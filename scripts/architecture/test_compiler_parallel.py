"""Bounded compiler concurrency, exact engine readback and cancellation checks."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import linux_job_isolation
import check
from native_confinement import CompilerPool, Execution, canonical
from test_native_confinement import Fixture


class ParallelSelection(unittest.TestCase):
    def test_normal_core_selects_only_the_measured_aggregate_budget(self):
        baseline = {'resources': {'cpus': 4, 'memory_bytes': 6 * 1024**3, 'pids': 1024},
                    'isolation': {'storage_kind': 'loop-ext4', 'storage_bytes': 24 * 1024**3}}
        configurations = [(baseline, True)]
        for section, key, value in [('resources', 'cpus', 2),
                                    ('resources', 'memory_bytes', 6 * 1024**3 - 1),
                                    ('resources', 'pids', 1023),
                                    ('isolation', 'storage_kind', 'tmpfs'),
                                    ('isolation', 'storage_bytes', 24 * 1024**3 - 1)]:
            config = {name: dict(values) for name, values in baseline.items()}
            config[section][key] = value
            configurations.append((config, False))
        larger = {name: dict(values) for name, values in baseline.items()}
        larger['resources'].update(cpus=8, memory_bytes=12 * 1024**3, pids=2048)
        configurations.append((larger, True))
        for config, expected in configurations:
            with self.subTest(config=config), patch.object(check, 'EXECUTION', SimpleNamespace(config=config)):
                self.assertEqual(check.compiler_witness_parallel(), expected)
        with patch.object(check, 'EXECUTION', None):
            self.assertFalse(check.compiler_witness_parallel())

    def test_parallel_dispatch_keeps_the_complete_trusted_case_inventory(self):
        # This exercises only inventory extraction and verdict dispatch. No Cargo
        # process runs; actual all-52 qualification remains the CI job's work.
        import tempfile
        root = Path(__file__).resolve().parents[2]
        policy = check.Policy(check.read(root / 'ci/architecture.toml'))
        commands, inventory, seeds = [], [], []
        def seed(argv, **kwargs):
            # The dependency seed runs once in the parent before the pool.
            seeds.append(argv[1])
            output = Path(argv[-1] if argv[1] == 'vendor' else argv[argv.index('--target-dir') + 1])
            (output / 'debug').mkdir(parents=True, exist_ok=True)
            config = '[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "/v"\n'
            return subprocess.CompletedProcess(argv, 0, config if argv[1] == 'vendor' else '', '')
        class Pool:
            def map(self, function, cases):
                inventory.extend(cases)
                self.expected = {name: codes for name, codes, _ in cases}
                for index, case in enumerate(cases):
                    child = Path(scratch) / f'isolate-{index}'
                    child.mkdir()
                    function(SimpleNamespace(roots={'candidate': child}), case)

            def run(self, child, argv, **kwargs):
                commands.append(argv)
                name = argv[argv.index('--example') + 1]
                codes = self.expected[name]
                message = {'reason': 'compiler-message', 'target': {'name': name},
                           'message': {'level': 'error', 'code': {'code': codes[0] if codes else None}}}
                built = {'reason': 'compiler-artifact', 'target': {'name': name}, 'fresh': False}
                return subprocess.CompletedProcess(argv, 101 if codes else 0,
                                                   stdout=json.dumps(message if codes else built), stderr='')
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as scratch:
            candidate = Path(scratch) / 'candidate'
            candidate.mkdir()
            execution = SimpleNamespace(compiler_pool=Pool, run=seed, roots={'checkout': root, 'candidate': candidate},
                                        config={'resources': {'cpus': 4, 'memory_bytes': 6 * 1024**3}})
            with patch.object(check, 'EXECUTION', execution), patch.object(check, 'architecture_progress'):
                receipt = check.check_compiler_witnesses(policy, root, root, Path(scratch), parallel=True)
        self.assertEqual(receipt['compiler_witnesses'], 52)
        self.assertEqual(sum(not codes for _, codes, _ in inventory), 16)
        self.assertEqual(sum(bool(codes) for _, codes, _ in inventory), 36)
        self.assertEqual(len(commands), 52)
        self.assertEqual(seeds, ['vendor', 'check', 'check'])
        self.assertEqual(receipt['compiler_dependency_seed']['configurations'], 2)
        self.assertTrue(all(argv[argv.index('--jobs') + 1] == '2' for argv in commands))
        self.assertEqual(sum('--features' in argv for argv in commands), 2)


class ParallelCompiler(Fixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.config['resources'] = {'cpus': 4, 'memory_bytes': 6 * 1024**3, 'pids': 256}
        self.parent = self.execution()
        self.manifest = self.roots['harness'] / 'Cargo.toml'
        self.manifest.write_text('[workspace]\n')
        self.argv = ['cargo', 'check', '--manifest-path', str(self.manifest)]
        self.created = {}
        self.removed = []
        self.mismatch = None
        self.fail_disposal = False
        self.engine_lock = threading.Lock()
        self.writable = []
        for name in ('validate_userns', 'validate_storage'):
            mock = patch.object(linux_job_isolation, name, return_value={})
            mock.start()
            self.addCleanup(mock.stop)
        mock = patch.object(linux_job_isolation, 'prepare_writable', side_effect=self.prepare)
        mock.start()
        self.addCleanup(mock.stop)
        mock = patch.object(Execution, '_client', side_effect=self.client)
        mock.start()
        self.addCleanup(mock.stop)

    def prepare(self, config, paths, uid, gid):
        self.assertEqual(config, self.config['isolation'])
        self.assertEqual(len(paths), 1)
        self.assertNotEqual(paths[0], self.roots['candidate'])
        self.writable.append(paths[0])
        return {'root': config['storage_root'], 'bytes': config['storage_bytes']}

    def client(self, argv, **kwargs):
        payload, code = '', 0
        if argv[0] == 'create':
            name = argv[argv.index('--name') + 1]
            with self.engine_lock:
                self.created[name] = argv
        elif argv[0] == 'info':
            payload = json.dumps({'SecurityOptions': ['name=userns'], 'SwapLimit': True})
        elif argv[:2] == ['inspect', '--format']:
            payload = json.dumps({'Status': 'exited', 'Running': False, 'ExitCode': 0,
                                  'OOMKilled': False})
        elif argv[0] == 'inspect':
            args = self.created[argv[1]]
            values = dict(arg[2:].split('=', 1) for arg in args if arg.startswith('--') and '=' in arg)
            mounts = []
            for index, value in enumerate(args):
                if value == '--mount':
                    fields = dict(part.split('=', 1) if '=' in part else (part, True)
                                  for part in args[index + 1].split(','))
                    mounts.append({'Type': fields['type'], 'Source': fields['src'],
                                   'Destination': fields['dst'], 'RW': 'readonly' not in fields})
            host = {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False,
                    'PidMode': '', 'IpcMode': 'private', 'CgroupnsMode': 'private',
                    'Runtime': 'runc', 'CapDrop': ['ALL'], 'CapAdd': [],
                    'PidsLimit': int(values['pids-limit']), 'Memory': int(values['memory']),
                    'MemorySwap': int(values['memory-swap']), 'NanoCpus': int(values['cpus']) * 10**9,
                    'Devices': [], 'DeviceRequests': [], 'ExtraHosts': [],
                    'ShmSize': 64 * 1024**2,
                    'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=1g,nr_inodes=65536,mode=1777'},
                    'SecurityOpt': ['no-new-privileges']}
            if self.mismatch:
                host[self.mismatch] += 1
            payload = json.dumps([{'Id': argv[1], 'Image': self.config['image'],
                                   'Config': {'User': '1000:1000'}, 'Mounts': mounts,
                                   'HostConfig': host}])
        elif argv[0] == 'rm':
            self.removed.append(argv[-1])
        elif argv[0] == 'container' and self.fail_disposal:
            code = 1
        return subprocess.CompletedProcess(argv, code, stdout=payload, stderr='')

    def test_two_isolates_enforce_aggregate_limits_and_merge_in_case_order(self):
        barrier = threading.Barrier(2)
        pool = CompilerPool(self.parent)
        def compile_case(child, index):
            with child.invocation(self.argv, self.roots['harness'], {}, discard_harness_target=True):
                barrier.wait(timeout=5)
                if index == 0:
                    time.sleep(0.03)  # Deliberately finish in the opposite order.
            return index
        self.assertEqual(pool.map(compile_case, [0, 1]), [0, 1])
        rows = self.parent.observations
        self.assertEqual([row['compiler_case_index'] for row in rows], [0, 1])
        self.assertEqual(len(set(self.writable)), 2)
        self.assertEqual(len(self.removed), 2)
        self.assertFalse(list(self.base.glob('compiler-isolate-*')))
        for key, maximum in self.config['resources'].items():
            self.assertLessEqual(sum(row['resources'][key] for row in rows), maximum)
        for row in rows:
            self.assertEqual(row['configuration_sha256'], hashlib.sha256(canonical(self.config)).hexdigest())
            self.assertEqual(row['aggregate_resources'], self.config['resources'])
            self.assertEqual(row['resources'], {'cpus': 2, 'memory_bytes': 3 * 1024**3, 'pids': 128})
            self.assertEqual(row['storage']['root'], str(self.base))
            self.assertEqual(row['storage']['bytes'], self.config['isolation']['storage_bytes'])
            self.assertEqual(row['storage']['tmp_bytes'], 1024**3)
            self.assertEqual(row['storage']['shm_bytes'], 64 * 1024**2)
            self.assertEqual(row['swap_bound']['effective_swap_bytes'], 0)
            self.assertTrue(row['disposed'] and row['harness_target_removed'])

    def test_engine_limit_mismatch_refuses_and_disposes(self):
        for field in ('PidsLimit', 'Memory', 'NanoCpus', 'MemorySwap'):
            with self.subTest(field=field):
                self.mismatch = field
                pool = CompilerPool(self.parent)
                def compile_case(child, _):
                    with child.invocation(self.argv, self.roots['harness'], {}, discard_harness_target=True):
                        self.fail('weakened engine limits were accepted')
                with self.assertRaises(ValueError):
                    pool.map(compile_case, [0])
                self.assertTrue(self.parent.observations[-1]['disposed'])
                self.assertFalse(list(self.base.glob('compiler-isolate-*')))

    def test_unconfirmed_disposal_retains_private_artifacts_and_fails(self):
        self.fail_disposal = True
        pool = CompilerPool(self.parent)
        def compile_case(child, _):
            with child.invocation(self.argv, self.roots['harness'], {}, discard_harness_target=True):
                pass
        with self.assertRaisesRegex(ValueError, 'disposal'):
            pool.map(compile_case, [0])
        self.assertEqual(len(list(self.base.glob('compiler-isolate-*'))), 1)
        self.assertFalse(self.parent.observations[-1]['disposed'])

    def cancellation(self, by_signal=False):
        pool = CompilerPool(self.parent)
        ready = self.base / 'ready'
        disposed = []
        @contextmanager
        def invocation(child, argv, cwd, env, **kwargs):
            row = {'disposed': False}
            child.observations.append(row)
            code = 'import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)'
            try:
                yield [sys.executable, '-c', code, str(ready)], os.environ, row
            finally:
                row['disposed'] = True
                disposed.append(True)
        handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        def compile_case(child, index):
            if index == 0:
                return pool.run(child, self.argv, cwd=self.roots['harness'])
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists(), 'attach client never started')
            if by_signal:
                os.kill(os.getpid(), signal.SIGTERM)
                while not pool.cancel.wait(0.01):
                    pass
                return None
            raise RuntimeError('wrong compiler diagnostic')
        with patch.object(Execution, 'invocation', invocation):
            with self.assertRaisesRegex(InterruptedError if by_signal else RuntimeError,
                                        'signal' if by_signal else 'wrong compiler'):
                pool.map(compile_case, [0, 1, 2, 3])
        with self.assertRaises(ProcessLookupError):
            os.kill(int(ready.read_text()), 0)
        self.assertEqual(disposed, [True])
        self.assertFalse(list(self.base.glob('compiler-isolate-*')))
        self.assertEqual({sig: signal.getsignal(sig) for sig in handlers}, handlers)

    def test_case_failure_cancels_and_reaps_other_attach_process(self):
        self.cancellation()

    def test_controller_term_cancels_and_restores_signal_handlers(self):
        self.cancellation(by_signal=True)

    def test_insufficient_budget_refuses_without_creating_isolates(self):
        for resources in ({'cpus': 2, 'memory_bytes': 6 * 1024**3, 'pids': 256},
                          {'cpus': 4, 'memory_bytes': 5 * 1024**3, 'pids': 256}):
            with self.subTest(resources=resources):
                self.parent.config = dict(self.config, resources=resources)
                with self.assertRaisesRegex(ValueError, 'resource budget'):
                    CompilerPool(self.parent)
        self.assertFalse(self.created)


if __name__ == '__main__':
    unittest.main()

"""Focused lifecycle checks for disposable, isolated compiler witness artifacts."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import check
import linux_job_isolation
from test_native_confinement import Fixture


class HarnessStorage(Fixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.execution_instance = self.execution()
        self.manifest = self.roots['harness'] / 'Cargo.toml'
        self.manifest.write_text('[workspace]\n')
        self.argv = ['cargo', 'check', '--manifest-path', str(self.manifest)]
        self.created = []
        self.targets = []
        self.daemon_available = True
        for name in ('prepare_writable', 'validate_userns', 'validate_storage'):
            mock = patch.object(linux_job_isolation, name, return_value={})
            mock.start()
            self.addCleanup(mock.stop)
        mock = patch.object(self.execution_instance, '_client', side_effect=self.client)
        mock.start()
        self.addCleanup(mock.stop)

    def client(self, argv, **kwargs):
        payload = ''
        if argv[0] == 'create':
            self.created = argv
            target = Path(next(value.split('=', 1)[1] for value in argv
                               if value.startswith('CARGO_TARGET_DIR=')))
            self.targets.append(target)
            (target / 'artifact').write_bytes(b'compiler output')
        elif argv[0] == 'info':
            payload = json.dumps({'SecurityOptions': ['name=userns'], 'SwapLimit': True})
        elif argv[:2] == ['inspect', '--format']:
            payload = json.dumps({'Status': 'exited', 'Running': False, 'ExitCode': 0,
                                  'OOMKilled': False})
        elif argv[0] == 'inspect':
            mounts = []
            for index, value in enumerate(self.created):
                if value == '--mount':
                    fields = dict(part.split('=', 1) if '=' in part else (part, True)
                                  for part in self.created[index + 1].split(','))
                    mounts.append({'Type': fields['type'], 'Source': fields['src'],
                                   'Destination': fields['dst'], 'RW': 'readonly' not in fields})
            memory = self.config['resources']['memory_bytes']
            payload = json.dumps([{'Id': 'fixture', 'Image': self.config['image'],
                'Config': {'User': '1000:1000'}, 'Mounts': mounts, 'HostConfig': {
                    'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False,
                    'PidMode': '', 'IpcMode': 'private', 'CgroupnsMode': 'private',
                    'Runtime': 'runc', 'CapDrop': ['ALL'], 'CapAdd': [], 'PidsLimit': 256,
                    'Memory': memory, 'MemorySwap': memory, 'NanoCpus': 2 * 10**9,
                    'Devices': [], 'DeviceRequests': [], 'ExtraHosts': [],
                    'ShmSize': 64 * 1024**2,
                    'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=1g,nr_inodes=65536,mode=1777'},
                    'SecurityOpt': ['no-new-privileges']}}])
        # Artifacts must still exist when the controller requests container removal.
        elif argv[0] == 'rm':
            self.assertTrue(self.targets[-1].exists())
        code = int(argv[0] == 'container' and not self.daemon_available)
        return subprocess.CompletedProcess(argv, code, stdout=payload, stderr='')

    def invoke(self, **kwargs):
        return self.execution_instance.invocation(self.argv, self.roots['checkout'], {}, **kwargs)

    def test_completed_cases_have_unique_targets_and_reclaim_each_one(self):
        for _ in range(3):
            with self.invoke(discard_harness_target=True):
                self.assertTrue(self.targets[-1].exists())
            self.assertFalse(self.targets[-1].exists())
            observation = self.execution_instance.observations[-1]
            self.assertTrue(observation['disposed'])
            self.assertTrue(observation['harness_target_removed'])
            self.assertEqual(observation['harness_target_path_sha256'],
                             hashlib.sha256(str(self.targets[-1]).encode()).hexdigest())
        self.assertEqual(len(set(self.targets)), 3)

    def test_default_retains_generated_build_output(self):
        with self.invoke():
            pass
        self.assertTrue((self.targets[-1] / 'artifact').exists())
        self.assertNotIn('harness_target_removed', self.execution_instance.observations[-1])

    def test_process_error_still_reclaims_after_confirmed_disposal(self):
        with patch('native_confinement.subprocess.run', side_effect=subprocess.CalledProcessError(1, self.argv)):
            with self.assertRaises(subprocess.CalledProcessError):
                self.execution_instance.run(self.argv, cwd=self.roots['checkout'],
                                            discard_harness_target=True, check=True)
        self.assertFalse(self.targets[-1].exists())

    def test_daemon_loss_retains_artifacts_and_refuses_disposal_claim(self):
        self.daemon_available = False
        with self.assertRaisesRegex(ValueError, 'disposal'):
            with self.invoke(discard_harness_target=True):
                pass
        self.assertTrue(self.targets[-1].exists())
        self.assertFalse(self.execution_instance.observations[-1]['disposed'])
        self.assertNotIn('harness_target_removed', self.execution_instance.observations[-1])

    def test_replaced_target_symlink_does_not_delete_its_destination(self):
        sentinel = self.control / 'preserve'
        sentinel.write_text('controller evidence')
        with self.invoke(discard_harness_target=True):
            target = self.targets[-1]
            shutil.rmtree(target)
            target.symlink_to(self.control, target_is_directory=True)
        self.assertFalse(target.is_symlink())
        self.assertEqual(sentinel.read_text(), 'controller evidence')

    def test_candidate_manifest_cannot_request_target_disposal(self):
        self.argv[-1] = str(self.roots['checkout'] / 'Cargo.toml')
        with self.assertRaisesRegex(ValueError, 'trusted harness'):
            with self.invoke(discard_harness_target=True):
                self.fail('candidate manifest accepted')
        self.assertFalse(self.created)


class CompilerWitnessStorage(unittest.TestCase):
    def test_check_jobs_are_bounded_by_candidate_cpu_and_existing_memory(self):
        for cpus, memory_gib, expected in [(4, 6, 4), (2, 6, 2), (16, 6, 4), (4, 3, 1)]:
            resources = {'cpus': cpus, 'memory_bytes': memory_gib * 1024**3}
            execution = SimpleNamespace(config={'resources': dict(resources)})
            with self.subTest(cpus=cpus, memory_gib=memory_gib), \
                    patch.object(check, 'EXECUTION', execution):
                self.assertEqual(check.compiler_check_jobs(), expected)
                self.assertEqual(execution.config['resources'], resources)
        with patch.object(check, 'EXECUTION', None):
            self.assertIsNone(check.compiler_check_jobs())

    def run_fixture(self, outcome):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            (root / 'Cargo.toml').write_text('[workspace]\n')
            (root / 'witness.rs').write_text('''/// ```rust
/// fn main() { /* marker */ }
/// ```
/// ```compile_fail,E0624
/// fn main() { /* marker */ }
/// ```
''')
            policy = SimpleNamespace(data={'core': {
                name: {'manifest': name + '/Cargo.toml'}
                for name in ('busbar-contract', 'busbar-plugin-loader')},
                'compiler_witnesses': [{'source': 'witness.rs', 'markers': ['marker'], 'count': 2}]})
            calls = []
            def run(argv, **kwargs):
                calls.append((argv, kwargs))
                name = argv[argv.index('--example') + 1]
                code, error_code, target = (0, None, name) if name == 'witness_00' else outcome
                message = {'reason': 'compiler-message', 'target': {'name': target},
                           'message': {'level': 'error', 'code': {'code': error_code},
                                       'rendered': 'retained diagnostic'}}
                return subprocess.CompletedProcess(argv, code,
                    stdout=json.dumps(message) if error_code else '', stderr='retained stderr')
            execution = SimpleNamespace(roots={'checkout': root}, run=run,
                config={'resources': {'cpus': 4, 'memory_bytes': 6 * 1024**3}})
            with patch.object(check, 'EXECUTION', execution), patch('check.print') as progress:
                try:
                    receipt = check.check_compiler_witnesses(policy, root, root, root / 'scratch')
                finally:
                    for argv, kwargs in calls:
                        self.assertTrue(kwargs['discard_harness_target'])
                        self.assertIn('--message-format=json', argv)
                        self.assertEqual(argv[:2], ['cargo', 'check'])
                        self.assertEqual(argv[argv.index('--jobs') + 1], '4')
                    self.assertEqual(len(calls), 2)
                    self.assertIn('retained stderr', (root / 'scratch/compiler-witnesses/witness_01.log').read_text())
                    rows = [json.loads(call.args[0].split(': ', 1)[1]) for call in progress.call_args_list]
                    self.assertEqual([row['event'] for row in rows], ['start', 'finish'] * 2)
                    self.assertEqual([row['case'] for row in rows], ['witness_00'] * 2 + ['witness_01'] * 2)
                    self.assertTrue(all(row['build_jobs'] == 4 for row in rows))
                    self.assertTrue(all(call.kwargs['flush'] for call in progress.call_args_list))
                    self.assertEqual(rows[-1]['passed'], outcome == (1, 'E0624', 'witness_01'))
                    self.assertEqual(len(rows[-1]['log_sha256']), 64)
            return receipt

    def test_positive_and_expected_negative_keep_their_verdicts_and_logs(self):
        self.assertEqual(self.run_fixture((1, 'E0624', 'witness_01')),
                         {'compiler_witnesses': 2, 'production_features': True})

    def test_wrong_negative_error_code_or_target_is_still_rejected(self):
        for outcome in [(1, 'E0001', 'witness_01'), (1, 'E0624', 'dependency'), (0, None, 'witness_01')]:
            with self.subTest(outcome=outcome), self.assertRaisesRegex(check.Violation, 'expected'):
                self.run_fixture(outcome)


if __name__ == '__main__':
    unittest.main()

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
                # Outer CI Git mappings belong to its candidate, not this fixture.
                self.execution_instance.run(self.argv, cwd=self.roots['checkout'], env={},
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
                    lines = [call.args[0] for call in progress.call_args_list]
                    rows = [json.loads(line.split(': ', 1)[1]) for line in lines if line.startswith('architecture-progress: ')]
                    # A failed case's own log reaches the job trace; a passing case prints none.
                    failed_logs = [line for line in lines if line.startswith('compiler-witness-log: ')]
                    passed_case = outcome == (1, 'E0624', 'witness_01')
                    self.assertEqual(failed_logs, [] if passed_case else
                                     ['compiler-witness-log: witness_01: retained stderr'] + (
                                         ['compiler-witness-log: witness_01: retained diagnostic'] if outcome[1] and outcome[2] == 'witness_01' else []))
                    self.assertEqual([row['event'] for row in rows], ['start', 'finish'] * 2)
                    self.assertEqual([row['case'] for row in rows], ['witness_00'] * 2 + ['witness_01'] * 2)
                    self.assertTrue(all(row['build_jobs'] == 4 for row in rows))
                    self.assertTrue(all(call.kwargs['flush'] for call in progress.call_args_list
                                        if call.args[0].startswith('architecture-progress: ')))
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


class SourceMaterialization(unittest.TestCase):
    def run_fixture(self, failure=None, repository='GetBusbar/busbar', cpus=4, memory_gib=6,
                    expected_jobs=4):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory).resolve()
            checkout, trusted, candidate, scratch = [root / name for name in
                                                     ('checkout', 'trusted', 'candidate', 'scratch')]
            crate = checkout / 'crates/core'
            crate.mkdir(parents=True)
            source = crate / 'custom-main.rs'
            source.write_text('include!(concat!(env!("OUT_DIR"), "/generated.rs"));')
            build_script = crate / 'build.rs'
            build_script.write_text('fn main() {}')
            (crate / 'Cargo.toml').write_text('[package]\nname="busbar-core"\n')
            trusted_test = trusted / 'crates/busbar-contract/tests/architecture_surface.rs'
            trusted_test.parent.mkdir(parents=True)
            trusted_test.write_text('// trusted source scan')
            (trusted / 'Cargo.toml').write_text('[workspace.dependencies]\nsyn="2"\nquote="1"\nproc-macro2="1"\nserde_json="1"\n')
            output = candidate / 'target/build/core/out'
            output.mkdir(parents=True)
            generated = output / 'generated.rs'
            generated.write_text('fn main() {}')
            reported_output = output
            if failure == 'escaping-output':
                reported_output = trusted
            elif failure == 'symlink-source':
                generated.unlink()
                generated.symlink_to(source)
            is_core = repository == 'GetBusbar/busbar'
            entry = {'manifest': 'crates/core/Cargo.toml', 'repository': repository,
                     'role': 'core' if is_core else 'implementation'}
            policy = SimpleNamespace(data={'core': {'busbar-core': entry}, 'repositories': {}},
                                     packages={'busbar-core': entry})
            metadata = {'packages': [{'id': 'core-id', 'name': 'busbar-core',
                'manifest_path': str(crate / 'Cargo.toml'),
                'targets': [{'kind': ['bin'] if is_core else ['lib'], 'src_path': str(source)},
                            {'kind': ['custom-build'], 'src_path': str(build_script)}]}]}
            commands = []
            def materialize(argv, **kwargs):
                commands.append(argv)
                if argv[:2] == ['cargo', 'metadata']:
                    return json.dumps(metadata)
                expected = (['cargo', 'check', '--workspace', '--manifest-path', str(checkout / 'Cargo.toml')]
                            if is_core else ['cargo', 'build', '--manifest-path', str(scratch / 'shipping-probe/Cargo.toml')])
                if is_core:
                    expected += ['--jobs', str(expected_jobs)]
                self.assertEqual(argv, expected + ['--message-format=json'])
                if failure == 'compiler-failure':
                    raise subprocess.CalledProcessError(1, argv)
                return json.dumps({'reason': 'build-script-executed', 'package_id': 'core-id',
                                   'out_dir': str(reported_output)}) + '\n'
            def source_scan(argv, **kwargs):
                self.assertEqual(argv[-2:], ['--test', 'architecture_surface'])
                env = kwargs['env']
                self.assertEqual(json.loads(Path(env['BUSBAR_ARCHITECTURE_GENERATED_DIRS']).read_text()),
                                 {str(crate): str(output)})
                if is_core:
                    inventory = json.loads(Path(env['BUSBAR_ARCHITECTURE_POLICY_SOURCES']).read_text())
                    self.assertEqual(set(inventory['roots']), {str(source), str(build_script)})
                    self.assertEqual(set(inventory['raw_paths']), {str(source), str(build_script)})
                    self.assertEqual(set(inventory['paths']), {str(source), str(build_script), str(generated)})
                else:
                    self.assertNotIn('BUSBAR_ARCHITECTURE_POLICY_SOURCES', env)
                    self.assertEqual(json.loads(Path(env['BUSBAR_ARCHITECTURE_SOURCES']).read_text()), [str(source)])
            execution = SimpleNamespace(roots={'candidate': candidate}, config={'resources': {
                'cpus': cpus, 'memory_bytes': memory_gib * 1024**3}})
            with patch.object(check, 'EXECUTION', execution), \
                    patch.object(check, 'candidate_output', side_effect=materialize), \
                    patch.object(check, 'candidate_run', side_effect=source_scan) as scan, \
                    patch('check.print') as progress:
                try:
                    result = check.check_sources(policy, repository, checkout, metadata, trusted, scratch)
                finally:
                    if failure:
                        scan.assert_not_called()
                self.assertEqual(result['core_source_files'], 3 if is_core else 0)
                self.assertTrue(result['trusted_source_check'])
                scan.assert_called_once()
                rows = [json.loads(call.args[0].split(': ', 1)[1]) for call in progress.call_args_list]
                self.assertEqual([row['event'] for row in rows], ['start', 'finish'])
                self.assertTrue(all(row['build_jobs'] == (expected_jobs if is_core else None)
                                    for row in rows))

    def test_core_check_materializes_generated_sources_and_retains_actual_target_inventory(self):
        self.run_fixture()

    def test_core_check_jobs_respect_cpu_and_memory_boundaries(self):
        for cpus, memory_gib, expected in [(2, 6, 2), (16, 6, 4), (4, 3, 1)]:
            with self.subTest(cpus=cpus, memory_gib=memory_gib):
                self.run_fixture(cpus=cpus, memory_gib=memory_gib, expected_jobs=expected)

    def test_plugin_source_materialization_still_builds_shipping_probe(self):
        self.run_fixture(repository='GetBusbar/busbar-auth-fixture')

    def test_generated_output_outside_candidate_is_still_rejected(self):
        with self.assertRaisesRegex(check.Violation, 'escapes its build output'):
            self.run_fixture('escaping-output')

    def test_indirect_generated_source_is_still_rejected(self):
        with self.assertRaisesRegex(check.Violation, 'indirect generated source'):
            self.run_fixture('symlink-source')

    def test_failed_check_cannot_produce_passing_source_receipt(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_fixture('compiler-failure')


if __name__ == '__main__':
    unittest.main()

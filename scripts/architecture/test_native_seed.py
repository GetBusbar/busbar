"""Actual per-job collector witness, opt-in on an existing public-tools image."""

import json
import hashlib
import io
import os
from contextlib import redirect_stdout
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_native_confinement import Fixture
from native_seed import prepare, manifest_snapshot, lock_inputs


class ManifestGraph(Fixture, unittest.TestCase):
    def test_all_four_subject_locks_stay_identical_and_only_core_adds_standalone_graphs(self):
        candidate, host, sdk = (self.roots[name] for name in ('checkout', 'trusted', 'harness'))
        (host / 'dist/default').mkdir(parents=True)
        expected = {}
        for label, directory in [('candidate', candidate), ('host', host),
                                 ('distribution', host / 'dist/default'), ('sdk', sdk)]:
            data = ('version=4\n[[package]]\nname="' + label + '"\nversion="1.0.0"\n'
                    'source="registry+https://github.com/rust-lang/crates.io-index"\n').encode()
            (directory / 'Cargo.lock').write_bytes(data)
            expected[label] = data
        # A required historical Git pin must stay even if a product lock also
        # mentions it. Selection is by actual workspace, never package names.
        expected['sdk'] += ('[[patch.unused]]\nname="required-codec"\nversion="1.0.0"\n'
            'source="git+https://github.com/GetBusbar/busbar-store-mysql?rev=' + 'b' * 40 + '#' + 'b' * 40 + '"\n').encode()
        (sdk / 'Cargo.lock').write_bytes(expected['sdk'])
        product_data = b'version=4\n[[package]]\nname="standalone-only"\nversion="1.0.0"\n'
        product = {'repo': 'busbar-store-mysql', 'commit': 'a' * 40,
                   'lock_sha256': hashlib.sha256(product_data).hexdigest()}
        for repository, evaluation, included in (
            ('GetBusbar/busbar', False, True), ('GetBusbar/busbar', True, False),
            ('GetBusbar/busbar-release', False, False), ('GetBusbar/busbar-plane-mcp', False, False),
        ):
            with self.subTest(repository=repository, evaluation=evaluation):
                q = SimpleNamespace(root=candidate, repository=repository, evaluation_only=evaluation)
                with patch('native_seed.subprocess.check_output', return_value=product_data) as fetch:
                    locks, inputs = lock_inputs(q, host, sdk, self.base / 'canonical', {'products': [product]})
                self.assertEqual({key: locks[key] for key in expected}, expected)
                self.assertEqual(set(inputs), set(locks))
                self.assertEqual(set(locks) - expected.keys(), {'product-busbar-store-mysql'} if included else set())
                self.assertEqual(fetch.call_count, int(included))
        q = SimpleNamespace(root=candidate, repository='GetBusbar/busbar', evaluation_only=False)
        with patch('native_seed.subprocess.check_output', return_value=b'changed lock'):
            with self.assertRaisesRegex(ValueError, 'lock differs'):
                lock_inputs(q, host, sdk, self.base / 'canonical', {'products': [product]})

    def test_original_graph_keeps_patches_without_staging_candidate_code_or_cargo_config(self):
        source = self.roots['checkout']
        manifest = '[workspace]\n[patch.crates-io]\nexample = { git = "https://github.com/example/crate", rev = "' + 'a' * 40 + '" }\n'
        (source / 'Cargo.toml').write_text(manifest)
        (source / '.cargo').mkdir()
        (source / '.cargo/config.toml').write_text('[build]\nrustc-wrapper="steal"\n')
        (source / 'build.rs').write_text('panic!("must not execute");')
        (source / 'src').mkdir()
        (source / 'src/lib.rs').write_text('compile_error!("not collector input");')
        output = self.control / 'graph'
        manifest_snapshot(source, output)
        self.assertEqual((output / 'Cargo.toml').read_text(), manifest)
        self.assertEqual((output / 'build.rs').read_bytes(), b'')
        self.assertEqual((output / 'src/lib.rs').read_bytes(), b'')
        self.assertFalse((output / '.cargo').exists())
        self.assertFalse((output / '.git').exists())


@unittest.skipUnless(os.environ.get('BUSBAR_NATIVE_TOOLS_TEST_CONFIG'), 'requires existing pinned public native tools')
class JobSeed(Fixture, unittest.TestCase):
    def test_seed_is_job_bound_and_does_not_copy_the_images_product_cache(self):
        self.config = json.loads(Path(os.environ['BUSBAR_NATIVE_TOOLS_TEST_CONFIG']).read_text())
        root, work = self.roots['checkout'], self.roots['candidate']
        (root / 'scripts').mkdir()
        (root / 'scripts/ci-product-pins.json').write_text('{"products":[]}\n')
        (root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel="1.98.0"\n')
        (root / 'Cargo.toml').write_text('[workspace]\n[package]\nname="private-job-fixture"\nversion="0.0.0"\nedition="2021"\n')
        (root / 'Cargo.lock').write_text('version=4\n[[package]]\nname="private-job-fixture"\nversion="0.0.0"\n')
        (root / 'src').mkdir()
        (root / 'src/lib.rs').write_text('#[test] fn actual() { assert_eq!(2 + 2, 4); }\n')
        evidence = self.control / 'evidence'
        evidence.mkdir()
        q = SimpleNamespace(execution=self.execution(), root=root, work=work, control=self.control,
            evidence=evidence, host=lambda: root, sdk=lambda: root, repository='BusbarInc/private-fixture',
            receipt={'source': 'a' * 40}, save=lambda: None, evaluation_only=False)
        prepare(q)
        self.assertEqual(q.receipt['dependency_seed']['repository'], q.repository)
        self.assertFalse(q.receipt['dependency_seed']['shared_image'])
        self.assertTrue((q.execution.dependency_seed / 'advisory-dbs').is_dir())
        self.assertFalse((q.execution.dependency_seed / 'git').exists())
        self.assertFalse((q.execution.dependency_seed / 'registry').exists())
        result = q.execution.run(['cargo', 'test', '--locked', '--offline'], cwd=root,
                                 env={'RUSTUP_TOOLCHAIN': '1.98.0'}, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(q.execution.observations[-1]['dependency_seed_sha256'],
                         q.receipt['dependency_seed']['manifest_sha256'])


class PreparationTiming(unittest.TestCase):
    def test_core_regressions_run_after_identity_validation_before_any_input_collection(self):
        import native
        for fail_regression in (False, True):
            with self.subTest(fail_regression=fail_regression):
                q = native.Qualification.__new__(native.Qualification)
                q.repository, q.evaluation_only = 'GetBusbar/busbar', False
                q.trusted = Path('/approved/controller')
                q.control = q.work = Path('/unused-test-work')
                q.receipt, q.policy = {'steps': []}, object()
                q.save, q.finish, q.host, q.architecture = Mock(), Mock(), Mock(), Mock()
                events = []
                def regression(name, argv, **kwargs):
                    self.assertEqual(kwargs['cwd'], q.trusted)
                    events.append(name)
                    if fail_regression:
                        raise RuntimeError('regression failed')
                q.run_controller = Mock(side_effect=regression)
                def validated(args):
                    events.append('validated-constructor')
                    return q
                def sources(*args):
                    events.append('canonical-inputs')
                    raise RuntimeError('stop before fetching')
                args = SimpleNamespace(external_conformance=False, conformance_only=False,
                                       conformance_capabilities=None, work=q.work)
                with patch.dict(os.environ, {'CI_JOB_ID': '1', 'CI_PIPELINE_ID': '2', 'CI_PROJECT_ID': '3',
                        'CI_PROJECT_PATH': q.repository, 'CI_CONFIG_REF_URI': 'immutable'}), \
                     patch('native.argparse.ArgumentParser.parse_args', return_value=args), \
                     patch('native.Qualification', side_effect=validated), \
                     patch('native.requires_native_oracle', return_value=False) as oracle, \
                     patch('native_sources.prepare', side_effect=sources) as collect, \
                     patch('native_seed.prepare') as seed, redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(RuntimeError, 'regression failed|stop before fetching'):
                        native.qualify()
                expected = ['validated-constructor', 'architecture-regressions']
                if not fail_regression:
                    expected += ['toolchain-regressions', 'conformance-capability-regressions',
                                 'conformance-confined-tools-regressions', 'canonical-inputs']
                self.assertEqual(events, expected)
                self.assertEqual(collect.call_count, int(not fail_regression))
                self.assertEqual(oracle.call_count, int(not fail_regression))
                seed.assert_not_called()
                q.architecture.assert_not_called()
                q.finish.assert_called_once()

    def test_monotonic_cost_is_recorded_for_success_and_failure_without_qualifying_checks(self):
        from native import Qualification
        for fails in (False, True):
            with self.subTest(fails=fails):
                q = Qualification.__new__(Qualification)
                q.receipt = {'steps': []}
                events = io.StringIO()
                with patch.object(q, 'save') as save, patch('native.time.monotonic', side_effect=[10, 12.25]), redirect_stdout(events):
                    if fails:
                        with self.assertRaisesRegex(RuntimeError, 'fixture failure'):
                            with q.preparation('dependency-seed'):
                                raise RuntimeError('fixture failure')
                    else:
                        with q.preparation('dependency-seed'):
                            pass
                row = q.receipt['preparation'][0]
                self.assertEqual(row['elapsed_seconds'], 2.25)
                self.assertEqual(row['status'], 'fail' if fails else 'pass')
                self.assertIn('started_at', row)
                self.assertIn('finished_at', row)
                self.assertEqual(q.receipt['steps'], [])
                self.assertEqual(save.call_count, 2)
                self.assertEqual(len(events.getvalue().splitlines()), 2)


if __name__ == '__main__':
    unittest.main()

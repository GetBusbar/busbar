"""A shared dependency seed never decides, shares or skips a compiler case verdict."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import check

VENDOR_CONFIG = '''[source.crates-io]
replace-with = "vendored-sources"

[source."git+https://github.com/GetBusbar/example?rev=abc"]
git = "https://github.com/GetBusbar/example"
rev = "abc"
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "/candidate/witness-vendor"
'''


def write_vendor_lock(argv):
    setting = next(arg for arg in argv if arg.startswith('resolver.lockfile-path='))
    lock = Path(json.loads(setting.split('=', 1)[1]))
    lock.parent.mkdir(parents=True)
    lock.write_text('version = 4\n')


def artifact(name, fresh):
    return {'reason': 'compiler-artifact', 'target': {'name': name, 'kind': ['example']}, 'fresh': fresh}


def error(name, code):
    return {'reason': 'compiler-message', 'target': {'name': name},
            'message': {'level': 'error', 'code': {'code': code}, 'rendered': 'diagnostic'}}


class Fixture:
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(directory.cleanup)
        self.root = root = Path(directory.name)
        (root / 'candidate').mkdir()
        (root / 'Cargo.toml').write_text('[workspace]\n')
        sources = [('crates/contract/src/positive.rs', '', 'fn main() { /* WITNESS */ }'),
                   ('crates/contract/src/private.rs', 'compile_fail,E0624', '// WITNESS'),
                   ('crates/loader/src/private.rs', 'compile_fail,E0603', '// WITNESS')]
        for source, flags, code in sources:
            path = root / source
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f'/// ```{flags}\n/// {code}\n/// ```\n')
        self.policy = SimpleNamespace(data={
            'core': {'busbar-contract': {'manifest': 'crates/contract/Cargo.toml'},
                     'busbar-plugin-loader': {'manifest': 'crates/loader/Cargo.toml'}},
            'compiler_witnesses': [{'source': source, 'markers': ['WITNESS'], 'count': 1}
                                   for source, _, _ in sources]})
        self.events, self.seed_calls, self.case_targets = [], [], {}
        self.vendor_returncode, self.seed_returncode = 0, 0
        self.case_outcome = {'witness_00': (0, [artifact('witness_00', False)]),
                             'witness_01': (101, [error('witness_01', 'E0624')]),
                             'witness_02': (101, [error('witness_02', 'E0603')])}

    def seed_run(self, argv, **kwargs):
        # The parent confined execution: vendor, then one check per feature set.
        self.assertTrue(kwargs['discard_harness_target'])
        self.events.append(('seed', argv[1]))
        self.seed_calls.append(argv)
        if argv[1] == 'vendor':
            output = Path(argv[-1])
            (output / 'dep-1.0.0').mkdir(parents=True)
            (output / 'dep-1.0.0' / 'lib.rs').write_text('pub fn dep() {}\n')
            write_vendor_lock(argv)
            return subprocess.CompletedProcess(argv, self.vendor_returncode, VENDOR_CONFIG, 'vendor log')
        self.assertEqual(argv[argv.index('--example') + 1], check.WITNESS_SEED)
        # Every seeded invocation receives the vendor resolution via the harness.
        self.assertEqual((self.root / 'scratch/compiler-witnesses/Cargo.lock').read_text(), 'version = 4\n')
        self.assertEqual(argv[argv.index('--jobs') + 1], '4')
        target = Path(argv[argv.index('--target-dir') + 1])
        self.assertTrue(target.is_relative_to(self.root / 'candidate'))
        profile = target / 'debug'
        for relative in ('deps/libdep-1.rmeta', '.fingerprint/dep-1/lib-dep',
                         # A forged harness fingerprint and cached example must not survive.
                         '.fingerprint/architecture-compiler-witnesses-1/example-witness_00',
                         'examples/witness_seed-1.rmeta', 'incremental/witness_seed-1/s'):
            (profile / relative).parent.mkdir(parents=True, exist_ok=True)
            (profile / relative).write_text(relative)
        return subprocess.CompletedProcess(argv, self.seed_returncode, '', 'seed log')

    def pool(self):
        test = self

        class Pool:
            def map(self, function, cases):
                test.events.append(('map', len(cases)))
                for index, case in enumerate(cases):
                    child = test.root / f'compiler-isolate-{index}' / 'candidate'
                    child.mkdir(parents=True)
                    function(SimpleNamespace(roots={'candidate': child}), case)

            def run(self, child, argv, **kwargs):
                name = argv[argv.index('--example') + 1]
                test.events.append(('case', name))
                harness = test.root / 'scratch/compiler-witnesses'
                if '--target-dir' not in argv:
                    # Unseeded fallback: exactly the original inputs and command.
                    test.assertNotIn('--config', argv)
                    test.assertFalse((harness / 'Cargo.lock').exists())
                    test.assertFalse((harness / 'examples' / (check.WITNESS_SEED + '.rs')).exists())
                    test.assertFalse(list((test.root / 'candidate').iterdir()))
                    returncode, messages = test.case_outcome[name]
                    return subprocess.CompletedProcess(argv, returncode, '\n'.join(map(json.dumps, messages)), '')
                test.assertTrue((harness / 'Cargo.lock').is_file())
                target = Path(argv[argv.index('--target-dir') + 1])
                config = Path(argv[argv.index('--config') + 1])
                test.assertTrue(target.is_relative_to(child.roots['candidate']))
                test.assertEqual((target / 'debug/deps/libdep-1.rmeta').read_text(), 'deps/libdep-1.rmeta')
                test.assertFalse((target / 'debug/examples').exists())
                test.assertFalse((target / 'debug/incremental').exists())
                test.assertFalse(list((target / 'debug/.fingerprint').glob('architecture-compiler-witnesses-*')))
                test.assertIn(str(test.root / 'scratch/compiler-witness-seed/vendor'), config.read_text())
                for other in test.case_targets.values():
                    test.assertNotEqual(other, target)
                    test.assertFalse(target.is_relative_to(other.parent))
                test.case_targets[name] = target
                # A case writing to its copy cannot reach the seed or later cases.
                (target / 'debug/deps/libdep-1.rmeta').write_text('poisoned by ' + name)
                returncode, messages = test.case_outcome[name]
                stdout = '\n'.join(json.dumps(row) for row in messages)
                return subprocess.CompletedProcess(argv, returncode, stdout, '')
        return Pool()

    def run_witnesses(self):
        execution = SimpleNamespace(roots={'checkout': self.root, 'candidate': self.root / 'candidate'},
                                    run=self.seed_run, compiler_pool=self.pool,
                                    config={'resources': {'cpus': 4, 'memory_bytes': 6 * 1024**3}})
        with patch.object(check, 'EXECUTION', execution), patch('check.print') as self.printed:
            return check.check_compiler_witnesses(self.policy, self.root, self.root, self.root / 'scratch',
                                                  parallel=True)


class CompilerSeed(Fixture, unittest.TestCase):
    def test_seed_is_built_once_before_cases_and_each_case_gets_a_private_copy(self):
        receipt = self.run_witnesses()
        self.assertEqual(receipt['compiler_witnesses'], 3)
        self.assertEqual(receipt['compiler_dependency_seed']['configurations'], 2)
        self.assertEqual(receipt['compiler_dependency_seed']['status'], 'seeded')
        self.assertEqual(self.events, [('seed', 'vendor'), ('seed', 'check'), ('seed', 'check'), ('map', 3),
                                       ('case', 'witness_00'), ('case', 'witness_01'), ('case', 'witness_02')])
        # Superset (loader) configuration first, then the contract-only one.
        self.assertIn('--features', self.seed_calls[1])
        self.assertNotIn('--features', self.seed_calls[2])
        seed = self.root / 'scratch/compiler-witness-seed'
        # Each later case saw unpoisoned content (checked in run); the seed is
        # released only after every case has finished.
        self.assertFalse((seed / 'target').exists() or (seed / 'vendor').exists())
        self.assertEqual(len(set(self.case_targets.values())), 3)
        # Candidate-side seed outputs are removed once snapshotted.
        self.assertEqual([path.name for path in (self.root / 'candidate').iterdir()], [])
        config = (seed / 'vendor.toml').read_text()
        self.assertIn('git+https://github.com/GetBusbar/example?rev=abc', config)
        self.assertNotIn('/candidate/witness-vendor', config)

    def test_a_seeded_positive_must_compile_its_own_crate(self):
        # Exit 0 with a cached (fresh) or absent own-crate artifact is not success.
        for messages in ([artifact('witness_00', True)], [], [artifact('witness_seed', False)]):
            with self.subTest(messages=messages):
                self.setUp()
                self.case_outcome['witness_00'] = (0, messages)
                with self.assertRaisesRegex(check.Violation, 'witness_00: expected successful positive control'):
                    self.run_witnesses()

    def test_negative_verdicts_are_unchanged(self):
        self.case_outcome['witness_01'] = (101, [error('witness_01', 'E0001')])
        with self.assertRaisesRegex(check.Violation, r"witness_01: expected \['E0624'\], received \['E0001'\]"):
            self.run_witnesses()
        self.setUp()
        self.case_outcome['witness_02'] = (0, [artifact('witness_02', False)])
        with self.assertRaisesRegex(check.Violation, 'witness_02: expected'):
            self.run_witnesses()

    def fail_seed(self, field, evidence):
        self.setUp()
        setattr(self, field, 101)
        with patch.object(check, 'EVIDENCE', evidence):
            return self.run_witnesses()

    def test_seed_failure_falls_back_to_unseeded_cases_with_the_same_verdicts(self):
        for field, log in (('vendor_returncode', 'vendor.log'), ('seed_returncode', 'seed-loader.log')):
            with self.subTest(field=field), tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as evidence:
                receipt = self.fail_seed(field, Path(evidence))
                self.assertEqual(receipt['compiler_witnesses'], 3)
                seed = receipt['compiler_dependency_seed']
                self.assertEqual((seed['status'], seed['fallback']), ('failed', 'unseeded'))
                self.assertIn('compiler dependency seed failed: ' + log.removesuffix('.log'), seed['reason'])
                # Every case still ran, each with its own (unseeded) verdict.
                self.assertEqual([event for event in self.events if event[0] == 'case'],
                                 [('case', 'witness_00'), ('case', 'witness_01'), ('case', 'witness_02')])
                lines = [call.args[0] for call in self.printed.call_args_list]
                self.assertIn('compiler-seed-log: ' + ('vendor log' if log == 'vendor.log' else 'seed log'), lines)
                self.assertEqual(seed['log'], 'architecture-compiler-seed-' + log)
                self.assertTrue((Path(evidence) / seed['log']).is_file())

    def test_unseeded_fallback_keeps_negative_and_positive_failures(self):
        for outcome in ((0, [artifact('witness_01', False)]), (101, [error('witness_01', 'E0001')])):
            with self.subTest(outcome=outcome):
                self.setUp()
                self.seed_returncode = 101
                self.case_outcome['witness_01'] = outcome
                with self.assertRaisesRegex(check.Violation, 'witness_01: expected'):
                    self.run_witnesses()
        # The strict own-artifact rule applies only to seeded cases.
        self.setUp()
        self.seed_returncode = 101
        self.case_outcome['witness_00'] = (0, [])
        self.assertEqual(self.run_witnesses()['compiler_witnesses'], 3)

    def test_candidate_seed_links_are_rejected(self):
        source = self.root / 'output'
        (source / 'debug').mkdir(parents=True)
        (source / 'debug' / 'escape').symlink_to(self.root / 'Cargo.toml')
        with self.assertRaisesRegex(check.Violation, 'non-regular'):
            check.copy_candidate_tree(source, self.root / 'copy')

    def test_vendor_configuration_cannot_add_other_settings(self):
        for text in ('[build]\nrustflags = ["-Zx"]\n' + VENDOR_CONFIG,
                     VENDOR_CONFIG.replace('rev = "abc"', 'rev = "abc"\nlocal-registry = "/x"'),
                     '[source.crates-io]\nreplace-with = "other"\n[source.vendored-sources]\ndirectory = "/x"\n',
                     '[source.crates-io]\nreplace-with = "vendored-sources"\n'):
            with self.subTest(text=text), self.assertRaises(check.Violation):
                check.vendor_source_config(text, Path('/seed/vendor'))


if __name__ == '__main__':
    unittest.main()

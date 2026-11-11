"""Keep witness dependencies minimal without accepting missing-crate failures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import check


class CompilerDependencies(unittest.TestCase):
    def run_fixture(self, negative_code='E0603'):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            (root / 'Cargo.toml').write_text('[workspace]\n')
            sources = [
                ('crates/contract/src/positive.rs', '', 'fn main() { /* WITNESS */ }'),
                ('crates/contract/src/private.rs', 'compile_fail,E0603',
                 'use busbar_plugin_loader::private; // WITNESS'),
                ('crates/loader/src/private.rs', 'compile_fail,E0603', '// WITNESS'),
                ('unknown.rs', 'compile_fail,E0603', '// WITNESS'),
            ]
            for source, flags, code in sources:
                path = root / source
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f'/// ```{flags}\n/// {code}\n/// ```\n')
            policy = SimpleNamespace(data={
                'core': {'busbar-contract': {'manifest': 'crates/contract/Cargo.toml'},
                         'busbar-plugin-loader': {'manifest': 'crates/loader/Cargo.toml'}},
                'compiler_witnesses': [{'source': source, 'markers': ['WITNESS'], 'count': 1}
                                       for source, _, _ in sources]})
            calls = []

            def run(argv, **kwargs):
                name = argv[argv.index('--example') + 1]
                calls.append(name)
                manifest = check.read(argv[argv.index('--manifest-path') + 1])
                self.assertEqual(manifest['dependencies']['busbar-contract'],
                                 {'path': str(root / 'crates/contract')})
                self.assertEqual(manifest['dependencies']['busbar-plugin-loader'],
                                 {'path': str(root / 'crates/loader'), 'optional': True})
                self.assertTrue(kwargs['discard_harness_target'])
                self.assertEqual(argv[argv.index('--jobs') + 1], '4')
                if name == 'witness_00':
                    self.assertNotIn('--features', argv)
                    return subprocess.CompletedProcess(argv, 0, stdout='', stderr='')
                self.assertEqual(argv[argv.index('--features') + 1], 'busbar-plugin-loader')
                message = {'reason': 'compiler-message', 'target': {'name': name},
                           'message': {'level': 'error', 'code': {'code': negative_code},
                                       'rendered': 'private item diagnostic'}}
                return subprocess.CompletedProcess(argv, 101, stdout=json.dumps(message), stderr='')

            execution = SimpleNamespace(roots={'checkout': root}, run=run,
                config={'resources': {'cpus': 4, 'memory_bytes': 6 * 1024**3}})
            with patch.object(check, 'EXECUTION', execution), patch('check.print'):
                result = check.check_compiler_witnesses(policy, root, root, root / 'scratch')
            self.assertEqual(calls, ['witness_00', 'witness_01', 'witness_02', 'witness_03'])
            return result

    def test_contract_only_checks_skip_loader_but_private_and_unknown_sources_keep_it(self):
        self.assertEqual(self.run_fixture(), {'compiler_witnesses': 4, 'production_features': True})

    def test_missing_crate_error_cannot_replace_the_intended_private_item_error(self):
        with self.assertRaisesRegex(check.Violation, 'expected.*E0603.*E0432'):
            self.run_fixture(negative_code='E0432')


if __name__ == '__main__':
    unittest.main()

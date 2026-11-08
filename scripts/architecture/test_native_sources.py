"""Candidate sources qualify before their public stage branches can advance."""
import tempfile
from pathlib import Path
import unittest

from native_sources import inputs


class Sources(unittest.TestCase):
    def test_collects_exact_public_commits_and_rejects_mutable_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = {'repositories': {'GetBusbar/busbar-store-memory': {'private': False},
                                       'BusbarInc/busbar-store-mssql': {'private': True}}}
            template = '[[package]]\nname="example"\nversion="1.0.0"\nsource="{}"\n'
            source = 'git+https://github.com/GetBusbar/busbar-store-memory?rev=' + 'a' * 40 + '#' + 'a' * 40
            (root / 'Cargo.lock').write_text(template.format(source))
            self.assertEqual(inputs(root, root, policy), {'GetBusbar/busbar-store-memory': {'a' * 40}})
            for wrong in (source.replace('rev=' + 'a' * 40, 'rev=dev'), source[:-1] + 'b'):
                (root / 'Cargo.lock').write_text(template.format(wrong))
                with self.assertRaisesRegex(ValueError, 'immutable'):
                    inputs(root, root, policy)

    def test_private_sources_never_enter_public_rewrite_map(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Cargo.lock').write_text('[[package]]\nname="private"\nversion="1.0.0"\n'
                'source="git+https://git.example/BusbarInc/private?rev=' + 'a' * 40 + '#' + 'a' * 40 + '"\n')
            self.assertEqual(inputs(root, root, {'repositories': {}}), {})


if __name__ == '__main__':
    unittest.main()

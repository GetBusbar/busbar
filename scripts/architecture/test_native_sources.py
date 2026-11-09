"""Candidate sources qualify before their public stage branches can advance."""
import tempfile
import hashlib
from pathlib import Path
import unittest

from native_sources import inputs, product_inputs


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

    def test_standalone_product_lock_adds_its_historical_codec_pin(self):
        from unittest.mock import patch
        head, codec = 'a' * 40, 'b' * 40
        repo = 'busbar-store-mysql'
        data = ('[[package]]\nname="mysql_common"\nversion="0.35.5"\n'
                'source="git+https://github.com/GetBusbar/' + repo + '?rev=' + codec + '#' + codec + '"\n').encode()
        product = {'repo':repo, 'commit':head, 'lock_sha256':hashlib.sha256(data).hexdigest()}
        policy = {'repositories':{'GetBusbar/'+repo:{'private':False}}}
        with tempfile.TemporaryDirectory() as directory, patch('native_sources.subprocess.check_output', return_value=data) as show:
            parent = Path(directory)
            self.assertEqual(product_inputs(parent, {'products':[product]}, policy), {'GetBusbar/'+repo:{codec}})
            show.assert_called_once_with(['git','-C',str(parent/repo),'show',head+':Cargo.lock'])
            product['lock_sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'lock differs'):
                product_inputs(parent, {'products':[product]}, policy)


if __name__ == '__main__':
    unittest.main()

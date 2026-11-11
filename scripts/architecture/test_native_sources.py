"""Candidate sources qualify before their public stage branches can advance."""
import tempfile
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from native_sources import inputs, product_inputs, prepare, standalone_products


class Sources(unittest.TestCase):
    def test_standalone_inputs_are_selected_by_controller_mode_only(self):
        oidc = {'repo': 'busbar-auth-oidc'}
        vector = {'products': [{'repo': 'busbar-store-mysql'}, oidc]}
        self.assertEqual(standalone_products('GetBusbar/busbar', False, vector), vector['products'])
        for repository, evaluation in [('GetBusbar/busbar', True),
                ('GetBusbar/busbar-release', False)]:
            self.assertEqual(standalone_products(repository, evaluation, vector), [oidc])
            for products in ([], [oidc, oidc]):
                with self.assertRaisesRegex(ValueError, 'absent or ambiguous'):
                    standalone_products(repository, evaluation, {'products': products})
        self.assertEqual(standalone_products('GetBusbar/busbar-plane-mcp', False, vector), [])
        for evaluation in (None, 'false', 0):
            with self.assertRaisesRegex(ValueError, 'controller job mode'):
                standalone_products('GetBusbar/busbar', evaluation, vector)

    def test_required_transitive_pins_survive_without_standalone_only_history(self):
        repository = 'GetBusbar/busbar-store-mysql'
        needed, extra, current, sdk = ('a' * 40, 'b' * 40, 'c' * 40, 'd' * 40)
        def data(revision):
            return ('[[package]]\nname="mysql_common"\nversion="1.0.0"\n'
                'source="git+https://github.com/' + repository + '?rev=' + revision + '#' + revision + '"\n').encode()
        product_data = data(extra)
        vector = {'sdk': sdk, 'products': [{'repo': 'busbar-auth-oidc', 'commit': current,
                                           'lock_sha256': hashlib.sha256(product_data).hexdigest()}]}
        for owner, evaluation, standalone in [('GetBusbar/busbar', False, True),
                ('GetBusbar/busbar', True, True), ('GetBusbar/busbar-release', False, True),
                ('GetBusbar/busbar-plane-mcp', False, False)]:
            with self.subTest(owner=owner, evaluation=evaluation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'scripts').mkdir()
                (root / 'scripts/ci-product-pins.json').write_text(json.dumps(vector))
                (root / 'Cargo.lock').write_bytes(data(needed))
                work = root / 'work'
                work.mkdir()
                q = SimpleNamespace(repository=owner, evaluation_only=evaluation, root=root,
                    work=work, sdk=lambda: root, policy=SimpleNamespace(data={'repositories': {
                        repository: {'private': False}, 'GetBusbar/busbar-auth-oidc': {'private': False}}}),
                    env={}, receipt={}, save=lambda: None)
                with patch('native.fetch_environment', return_value={'CI_SERVER_URL': 'https://github.com'}), \
                     patch('native.git', side_effect=lambda path, *args: args[-1].removeprefix('refs/heads/input-') if args[-1].startswith('refs/') else current), \
                     patch('native_sources.subprocess.run'), \
                     patch('native_sources.subprocess.check_output', return_value=product_data) as read:
                    prepare(q, root)
                self.assertEqual(q.receipt['canonical_inputs'][repository], sorted({needed} | ({extra} if standalone else set())))
                self.assertEqual(q.receipt['canonical_inputs']['GetBusbar/busbar-auth-oidc'], [current])
                self.assertEqual(read.call_count, int(standalone))
                self.assertEqual(q.receipt['canonical_inputs']['GetBusbar/busbar'], sorted({sdk, current}))

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

    def test_unused_sdk_patches_are_prefetched_with_the_same_identity_checks(self):
        # Cargo loads patched sources even when they do not enter the package
        # graph. The immutable SDK lock records these as [[patch.unused]].
        from native_sources import lock_inputs
        repository = 'GetBusbar/busbar-store-mysql'
        codec = '8407ab816c5606483549b13fc958054df837abd1'
        policy = {'repositories': {repository: {'private': False}}}
        source = 'git+https://github.com/' + repository + '?rev=' + codec + '#' + codec
        template = '[[patch.unused]]\nname="mysql_common"\nversion="0.35.5"\nsource="{}"\n'
        self.assertEqual(lock_inputs(template.format(source), policy), {repository: {codec}})
        self.assertEqual(lock_inputs(template.format(source),
                                     {'repositories': {repository: {'private': True}}}), {})
        for wrong in (source.replace('rev=' + codec, 'rev=dev'), source[:-1] + '0'):
            with self.assertRaisesRegex(ValueError, 'immutable'):
                lock_inputs(template.format(wrong), policy)

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

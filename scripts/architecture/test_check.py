"""Targeted mutation witnesses for the trusted architecture admission checker."""
import json
import copy
import os
from pathlib import Path
import tempfile
import unittest

from check import Policy, Violation, check_graph, check_declared, dependency, dependency_tables, resolve_shipping, vector_revisions, core_source_inventory

ROOT = Path('/candidate')


class CoreSourceInventoryTests(unittest.TestCase):
    def test_sdk_nested_sources_tests_and_build_scripts_are_all_in_scope(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            expected = ['crates/contract/src/lib.rs', 'crates/contract/src/abi/sdk/hidden.rs',
                        'crates/contract/tests/fixture.rs', 'crates/contract/build.rs',
                        'crates/kernel/src/lib.rs']
            for relative in expected:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fn fixture() {}')
            # Candidate/legacy file subsets cannot narrow the trusted member inventory.
            p = policy()
            p.data['policy_sources'] = ['crates/kernel/src/lib.rs']
            self.assertEqual(core_source_inventory(p, root), sorted(str((root / path).resolve()) for path in expected))

    def test_a_missing_core_member_is_not_silently_unchecked(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            with self.assertRaisesRegex(Violation, 'invalid core source root'):
                core_source_inventory(policy(), Path(directory))

    def test_symlinked_source_cannot_escape_the_candidate(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory) / 'candidate'
            for member in ['contract', 'kernel']:
                path = root / 'crates' / member / 'src'
                path.mkdir(parents=True)
                (path / 'lib.rs').write_text('fn fixture() {}')
            outside = Path(directory) / 'outside.rs'
            outside.write_text('fn fixture() {}')
            (root / 'crates/contract/src/escape.rs').symlink_to(outside)
            with self.assertRaisesRegex(Violation, 'escapes candidate'):
                core_source_inventory(policy(), root)


class VectorTests(unittest.TestCase):
    def test_complete_vector_binds_sdk_product_and_c_witness(self):
        p = policy()
        del p.data['repositories']['GetBusbar/busbar-store-beta']
        p.data['repositories']['GetBusbar/busbar-auth-alpha'].update(kind='auth', private=False)
        p.data['repositories']['GetBusbar/busbar-secret-c'] = dict(kind='secret', private=False, language='c')
        vector = dict(sdk='a' * 40, products=[dict(repo='busbar-auth-alpha', kind='auth',
            package='busbar-auth-alpha-plugin', url='https://github.com/GetBusbar/busbar-auth-alpha',
            commit='b' * 40, lock_sha256='c' * 64)], c_witness=dict(repo='busbar-secret-c',
            sdk='a' * 40, commit='d' * 40, url='https://github.com/GetBusbar/busbar-secret-c'))
        self.assertEqual(vector_revisions(p, vector)['GetBusbar/busbar-auth-alpha'], 'b' * 40)
        mutations = [lambda v: v.update(products=[]),
                     lambda v: v['products'].append(v['products'][0]),
                     lambda v: v['products'][0].update(commit='dev'),
                     lambda v: v['products'][0].update(package='busbar-auth-alpha'),
                     lambda v: v['c_witness'].update(sdk='e' * 40)]
        for mutate in mutations:
            changed = copy.deepcopy(vector)
            mutate(changed)
            with self.subTest(vector=changed), self.assertRaises(Violation):
                vector_revisions(p, changed)


def policy():
    return Policy({'version': 1, 'forbidden_shipping_features': ['test-support', 'test-seal'],
        'core': {'busbar-contract': {'manifest': 'crates/contract/Cargo.toml', 'allows': []},
                 'busbar-kernel': {'manifest': 'crates/kernel/Cargo.toml', 'allows': ['busbar-contract']}},
        'repositories': {'GetBusbar/busbar-auth-alpha': {'packages': [
            {'name': 'busbar-auth-alpha', 'manifest': 'auth-alpha/Cargo.toml', 'role': 'implementation'},
            {'name': 'busbar-auth-alpha-plugin', 'manifest': 'auth-alpha-plugin/Cargo.toml', 'role': 'wrapper'}]},
            'GetBusbar/busbar-store-beta': {'packages': [
                {'name': 'busbar-store-beta', 'manifest': 'store-beta/Cargo.toml', 'role': 'implementation'}]}},
        'assembly': {'package': 'busbar-default', 'repository': 'GetBusbar/busbar', 'manifest': 'dist/default/Cargo.toml'}})


def fixture():
    rows = [('impl', 'busbar-auth-alpha', None, '/candidate/auth-alpha/Cargo.toml'),
            ('wrapper', 'busbar-auth-alpha-plugin', None, '/candidate/auth-alpha-plugin/Cargo.toml'),
            ('sdk', 'busbar-contract', 'git+https://github.com/GetBusbar/busbar?rev=' + 'a'*40 + '#' + 'a'*40, '/cargo/sdk/Cargo.toml'),
            ('lib', 'ordinary-library', 'registry+https://github.com/rust-lang/crates.io-index', '/cargo/lib/Cargo.toml')]
    return {'packages': [dict(id=i, name=n, source=s, manifest_path=p) for i, n, s, p in rows],
            'resolve': {'nodes': [dict(id=i, features=[], deps=[]) for i, *_ in rows]}}


def edge(m, start, target, name='renamed', kind=None, cfg=None):
    next(n for n in m['resolve']['nodes'] if n['id'] == start)['deps'].append(
        {'name': name, 'pkg': target, 'dep_kinds': [{'kind': kind, 'target': cfg}]})


def sibling(m):
    m['packages'].append(dict(id='other', name='busbar-store-beta', source='git+https://github.com/GetBusbar/busbar-store-beta?rev='+'b'*40+'#'+'b'*40, manifest_path='/cargo/beta/Cargo.toml'))
    m['resolve']['nodes'].append(dict(id='other', features=[], deps=[]))


class GraphTests(unittest.TestCase):
    def check(self, m):
        return check_graph(m, policy(), 'GetBusbar/busbar-auth-alpha', ROOT)

    def test_own_wrapper_sdk_and_external_library_are_permitted(self):
        m = fixture(); edge(m, 'wrapper', 'impl'); edge(m, 'impl', 'sdk'); edge(m, 'impl', 'lib')
        self.assertEqual(self.check(m)['classified'], 3)

    def test_renamed_transitive_sibling_is_rejected(self):
        m = fixture(); sibling(m); edge(m, 'impl', 'lib'); edge(m, 'lib', 'other', name='ordinary_helper')
        with self.assertRaisesRegex(Violation, 'forbidden production/build edge'):
            self.check(m)

    def test_build_and_foreign_target_are_not_hidden(self):
        for kind, cfg in [('build', None), (None, 'cfg(windows)')]:
            m = fixture(); sibling(m); edge(m, 'impl', 'other', kind=kind, cfg=cfg)
            with self.assertRaisesRegex(Violation, 'forbidden production/build edge'):
                self.check(m)

    def test_dev_only_real_core_harness_does_not_enter_shipping_graph(self):
        m = fixture(); sibling(m); edge(m, 'impl', 'other', kind='dev')
        self.check(m)

    def test_transitive_shipping_authority_feature_is_rejected(self):
        m = fixture(); edge(m, 'impl', 'lib'); edge(m, 'lib', 'sdk')
        m['resolve']['nodes'][2]['features'] = ['test-seal']
        with self.assertRaisesRegex(Violation, 'shipping feature'):
            self.check(m)

    def test_relabelled_first_party_source_and_registry_substitution_are_rejected(self):
        for name, source in [('neutral', 'git+https://github.com/GetBusbar/unclassified#abc'),
                             ('busbar-contract', 'registry+https://github.com/rust-lang/crates.io-index')]:
            m = fixture(); m['packages'][2].update(name=name, source=source)
            with self.assertRaises(Violation):
                self.check(m)

    def test_wrong_checkout_cannot_impersonate_own_implementation(self):
        m = fixture(); m['packages'][0]['manifest_path'] = '/other/auth-alpha/Cargo.toml'
        with self.assertRaisesRegex(Violation, 'substitution'):
            self.check(m)

    def test_missing_resolve_is_not_evidence(self):
        m = fixture(); m['resolve'] = None
        with self.assertRaisesRegex(Violation, 'resolved cargo metadata'):
            self.check(m)

    def test_workspace_aliases_preserve_package_and_additive_features(self):
        name, cfg = dependency('neutral', {'workspace': True, 'features': ['extra']},
            {'dependencies': {'neutral': {'package': 'busbar-contract', 'features': ['test-support']}}})
        self.assertEqual(name, 'busbar-contract')
        self.assertEqual(cfg['features'], ['test-support', 'extra'])

    def test_declared_optional_target_and_build_tables_are_all_visited(self):
        manifest = {'target': {'cfg(windows)': {'build-dependencies': {'neutral': {'optional': True}}}}}
        self.assertIn(('build', {'neutral': {'optional': True}}), list(dependency_tables(manifest)))


class DeclarationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='architecture-', dir=os.environ.get('TMPDIR'))
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.repo = 'GetBusbar/busbar-auth-alpha'
        pin = 'a' * 40
        self.sdk = 'git = "https://github.com/GetBusbar/busbar", rev = "' + pin + '"'
        (self.root / '.busbar-ref').write_text(pin + ' 1.6.0\n')
        (self.root / 'Cargo.lock').write_text('[[package]]\nname="busbar-contract"\nversion="1.6.0"\nsource=' + json.dumps('git+https://github.com/GetBusbar/busbar?rev=' + pin + '#' + pin))
        (self.root / 'Cargo.toml').write_text('[workspace]\nmembers=["auth-alpha", "auth-alpha-plugin"]\n[workspace.dependencies]\nrenamed-sdk={package="busbar-contract", ' + self.sdk + '}\n')
        for name, deps in [('auth-alpha', '[dependencies]\nrenamed-sdk={workspace=true}\n'), ('auth-alpha-plugin', '[dependencies]\nbusbar-auth-alpha={path="../auth-alpha"}\n')]:
            directory = self.root / name
            directory.mkdir()
            (directory / 'Cargo.toml').write_text('[package]\nname="busbar-' + name + '"\nversion="1.6.0"\n' + deps)

    def check(self):
        return check_declared(policy(), self.repo, self.root)

    def test_exact_workspace_alias_and_wrapper_are_allowed(self):
        self.assertEqual(len(self.check()), 2)

    def test_inactive_optional_target_build_alias_cannot_hide_a_sibling(self):
        path = self.root / 'auth-alpha/Cargo.toml'
        with path.open('a') as stream:
            stream.write('[target.\'cfg(windows)\'.build-dependencies]\nneutral={package="busbar-store-beta",optional=true,git="https://github.com/GetBusbar/busbar-store-beta",rev="' + 'b'*40 + '"}\n')
        with self.assertRaisesRegex(Violation, 'forbidden declared build edge'):
            self.check()

    def test_workspace_feature_alias_cannot_enable_test_authority(self):
        path = self.root / 'auth-alpha/Cargo.toml'
        path.write_text(path.read_text().replace('workspace=true', 'workspace=true, features=["test-seal"]'))
        with self.assertRaisesRegex(Violation, 'shipping feature declaration'):
            self.check()

    def test_root_patch_and_config_replacement_are_rejected(self):
        path = self.root / 'Cargo.toml'
        original = path.read_text()
        path.write_text(original + '[patch.\'https://github.com/GetBusbar/busbar\']\nbusbar-contract={path="replacement"}\n')
        with self.assertRaisesRegex(Violation, 'patch substitution'):
            self.check()
        path.write_text(original)
        (self.root / '.cargo').mkdir()
        (self.root / '.cargo/config.toml').write_text('paths=["replacement"]\n')
        with self.assertRaisesRegex(Violation, 'Cargo source substitution'):
            self.check()

    def test_binary_only_root_retains_its_production_edges(self):
        directory = self.root / 'binary'
        (directory / 'src').mkdir(parents=True)
        (directory / 'src/main.rs').write_text('fn main() {}')
        (directory / 'Cargo.toml').write_text('[workspace]\n[package]\nname="product"\nversion="0.0.0"\n[dependencies]\nexternal={path="../external"}\n')
        (self.root / 'external/src').mkdir(parents=True)
        (self.root / 'external/src/lib.rs').write_text('')
        (self.root / 'external/Cargo.toml').write_text('[package]\nname="external"\nversion="0.0.0"\n')
        metadata = resolve_shipping(self.root, [('product', {'manifest': 'binary/Cargo.toml', 'role': 'core'})], self.root / 'scratch')
        product = next(p for p in metadata['packages'] if p['name'] == 'product')
        self.assertEqual(product['manifest_path'], str(directory / 'Cargo.toml'))
        node = next(n for n in metadata['resolve']['nodes'] if n['id'] == product['id'])
        self.assertEqual(len(node['deps']), 1)
        self.assertEqual(node['deps'][0]['name'], 'external')

    def test_unclassified_workspace_member_fails_closed(self):
        path = self.root / 'Cargo.toml'
        path.write_text(path.read_text().replace('"auth-alpha-plugin"]', '"auth-alpha-plugin", "extra"]'))
        (self.root / 'extra').mkdir()
        (self.root / 'extra/Cargo.toml').write_text('[package]\nname="innocent"\nversion="0.0.0"\n')
        with self.assertRaisesRegex(Violation, 'unclassified workspace member'):
            self.check()


if __name__ == '__main__':
    unittest.main()

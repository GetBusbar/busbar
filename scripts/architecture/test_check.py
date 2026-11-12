"""Vector binding witnesses for the Python policy model shared with native.py.

The architecture checks themselves are busbar-ci tests
(tools/ci/src/architecture/tests.rs)."""
import copy
import unittest

from check import Policy, Violation, vector_revisions


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


if __name__ == '__main__':
    unittest.main()

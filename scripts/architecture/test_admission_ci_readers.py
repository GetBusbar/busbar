"""New canonical inputs must be fetchable without opening unrestricted job-token access."""
import unittest

from admission import configure_ci_read_access


class Forge:
    def __init__(self, *, restricted=True, persist=True, wrong_group=False):
        self.restricted = restricted
        self.persist = persist
        self.wrong_group = wrong_group
        self.groups = set()
        self.writes = []

    def request(self, path, method='GET', data=None):
        if method != 'GET':
            self.writes.append((path, method, data))
            if self.persist:
                if method == 'PATCH':
                    self.restricted = data['enabled']
                elif method == 'POST':
                    self.groups.add(data['target_group_id'])
            return None
        if path.startswith('groups/'):
            name = path.split('/')[1]
            return {'id': 2 if name == 'GetBusbar' else 3,
                    'full_path': 'unexpected' if self.wrong_group else name}
        if path == 'projects/73/job_token_scope':
            return {'inbound_enabled': self.restricted}
        raise AssertionError(path)

    def all(self, path):
        if path != 'projects/73/job_token_scope/groups_allowlist':
            raise AssertionError(path)
        return [{'id': group} for group in sorted(self.groups)]


class CanonicalReaders(unittest.TestCase):
    project = {'id': 73, 'path_with_namespace': 'GetBusbar/new-input'}

    def test_new_input_gets_only_canonical_groups_and_reapply_is_idempotent(self):
        api = Forge()
        self.assertEqual(configure_ci_read_access(api, self.project), [{'id': 2}, {'id': 3}])
        self.assertTrue(api.restricted)
        writes = list(api.writes)
        self.assertEqual(len(writes), 2)
        self.assertTrue(all(method == 'POST' for _, method, _ in writes))
        configure_ci_read_access(api, self.project)
        self.assertEqual(api.writes, writes)

    def test_unrestricted_access_is_closed_before_readers_are_added(self):
        api = Forge(restricted=False)
        configure_ci_read_access(api, self.project)
        self.assertEqual(api.writes[0], ('projects/73/job_token_scope', 'PATCH', {'enabled': True}))
        self.assertTrue(api.restricted)

    def test_wrong_group_identity_cannot_authorize_readers(self):
        api = Forge(wrong_group=True)
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            configure_ci_read_access(api, self.project)
        self.assertEqual(api.writes, [])

    def test_outside_project_is_not_mutated(self):
        api = Forge()
        with self.assertRaisesRegex(ValueError, 'outside'):
            configure_ci_read_access(api, dict(self.project, path_with_namespace='Elsewhere/new-input'))
        self.assertEqual(api.writes, [])

    def test_failed_readback_cannot_report_success(self):
        for restricted in (True, False):
            with self.subTest(restricted=restricted):
                api = Forge(restricted=restricted, persist=False)
                with self.assertRaisesRegex(RuntimeError, 'did not hold'):
                    configure_ci_read_access(api, self.project)


if __name__ == '__main__':
    unittest.main()

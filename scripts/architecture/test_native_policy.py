"""Controller policy, never candidate omissions, selects required native work."""
import unittest

from check import Violation
from native import evaluation_job, requires_native_oracle
from native_policy import native_settings
from admission import required_conformance_job


class NativePolicy(unittest.TestCase):
    def test_new_owner_obligations_need_only_trusted_data(self):
        repository = 'GetBusbar/busbar-fixture-owner'
        settings = {'services': ['valkey'], 'server_binary': 'valkey', 'native_oracle': True,
                    'external_conformance': 'testing/conformance/external-fixture.sh',
                    'prepare_runtime': 'testing/native/prepare.sh'}
        policy = {'repositories': {repository: {'native': settings}}}
        self.assertEqual(native_settings(repository, policy), settings)
        self.assertEqual(evaluation_job(repository, False, True, policy), 'external-conformance')
        self.assertEqual(required_conformance_job(repository, policy), 'external-conformance')
        self.assertTrue(requires_native_oracle(repository, False, policy))
        self.assertFalse(requires_native_oracle(repository, True, policy))

    def test_unknown_services_commands_paths_and_inconsistent_server_refuse(self):
        for settings in [{'services': ['unknown']}, {'services': ['mysql', 'mysql']}, {'command': 'true'},
                         {'prepare_runtime': '../private.sh'}, {'prepare_runtime': 'testing/native/../private.sh'},
                         {'prepare_runtime': 'testing/conformance/run.sh'}, {'prepare_runtime': 'testing/native/run.py'},
                         {'external_conformance': '../private.sh'}, {'external_conformance': '/private.sh'},
                         {'server_binary': 'valkey'}, {'migration_fixture': 'arbitrary'}, {'native_oracle': 'false'},
                         {'required_conformance': 'false'}]:
            policy = {'repositories': {'fixture': {'native': settings}}}
            with self.subTest(settings=settings), self.assertRaises(Violation):
                native_settings('fixture', policy)

    def test_assembly_fixture_obligations_come_from_the_same_policy(self):
        settings = {'services': ['postgres'], 'migration_fixture': 'sqlite-1.5.5'}
        policy = {'assembly': {'repository': 'core', 'native': settings}, 'repositories': {}}
        self.assertEqual(native_settings('core', policy), settings)


if __name__ == '__main__':
    unittest.main()

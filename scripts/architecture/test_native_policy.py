"""Controller policy, never candidate omissions, selects required native work."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from check import Violation
from native import native_scheduling, evaluation_job, requires_native_oracle
from native_policy import native_settings
from admission import required_conformance_job


class NativePolicy(unittest.TestCase):
    def test_compiler_memory_budget_does_not_reduce_cpu_based_test_concurrency(self):
        execution = SimpleNamespace(config={'resources': {'cpus': 4, 'memory_bytes': 6 * 1024**3}})
        for host, expected in ((64, 4), (2, 2), (None, 4)):
            with self.subTest(host=host), patch('native.os.cpu_count', return_value=host):
                selected = native_scheduling(execution)
                self.assertEqual(selected['build_jobs'], 1)
                self.assertEqual(selected['test_threads'], expected)
                self.assertEqual(selected['candidate_memory_bytes'], 6 * 1024**3)
                self.assertEqual(selected['compiler_memory_bytes_per_slot'], 6 * 1024**3)
                self.assertIn('not-measured-peak-or-fit-guarantee', selected['memory_policy'])

    def test_compiler_fanout_respects_memory_cpu_and_sixteen_job_caps(self):
        for host, cpus, gib, expected in [(64, 4, 11, 1), (64, 4, 12, 2), (64, 4, 48, 4),
                (2, 4, 48, 2), (64, 32, 192, 16), (64, 1, 12, 1), (64, 4, 3, 1)]:
            with self.subTest(host=host, cpus=cpus, gib=gib), patch('native.os.cpu_count', return_value=host):
                resources = {'cpus': cpus, 'memory_bytes': gib * 1024**3}
                execution = SimpleNamespace(config={'resources': dict(resources)})
                self.assertEqual(native_scheduling(execution)['build_jobs'], expected)
                self.assertEqual(execution.config['resources'], resources)

    def test_unconfined_scheduling_preserves_existing_host_cpu_cap(self):
        with patch('native.os.cpu_count', return_value=64):
            selected = native_scheduling(None)
            self.assertEqual(selected['build_jobs'], 16)
            self.assertEqual(selected['test_threads'], 16)
            self.assertIsNone(selected['candidate_memory_bytes'])

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

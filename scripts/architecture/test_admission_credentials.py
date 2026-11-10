"""Group-protection lookup can use its authorized read credential without changing writes."""
import subprocess
import unittest
from unittest import mock

from admission import GitLab, group_protection_reader


class AdmissionCredentials(unittest.TestCase):
    def test_explicit_token_does_not_load_the_operator_credential(self):
        with mock.patch('admission.subprocess.run') as run:
            client = GitLab('https://git.example.invalid', token='group-reader')
        run.assert_not_called()
        self.assertEqual(client.token, 'group-reader')

    def test_distinct_reader_leaves_operator_credential_unchanged(self):
        operator = GitLab('https://git.example.invalid', token='operator')
        with mock.patch('admission.subprocess.run', return_value=subprocess.CompletedProcess(
                [], 0, stdout='group-reader\n', stderr='')) as run:
            reader = group_protection_reader(operator, 'group-read-service')
        run.assert_called_once_with(
            ['security', 'find-generic-password', '-s', 'group-read-service', '-w'],
            text=True, capture_output=True, check=False)
        self.assertIsNot(reader, operator)
        self.assertEqual(reader.server, operator.server)
        self.assertEqual(reader.token, 'group-reader')
        self.assertEqual(operator.token, 'operator')

    def test_default_keeps_existing_operator_lookup(self):
        operator = GitLab('https://git.example.invalid', token='operator')
        with mock.patch('admission.subprocess.run') as run:
            self.assertIs(group_protection_reader(operator, None), operator)
        run.assert_not_called()

    def test_keychain_failure_is_closed_and_does_not_echo_output(self):
        operator = GitLab('https://git.example.invalid', token='operator')
        for code, output in [(1, 'secret-canary'), (0, '')]:
            with self.subTest(code=code), mock.patch('admission.subprocess.run', return_value=
                    subprocess.CompletedProcess([], code, stdout=output, stderr='secret-canary')):
                with self.assertRaisesRegex(RuntimeError, '^group-protection read credential could not be loaded$'):
                    group_protection_reader(operator, 'group-read-service')
        self.assertEqual(operator.token, 'operator')


if __name__ == '__main__':
    unittest.main()

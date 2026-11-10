"""Exact-source witnesses for requalifying an already published development cohort."""
import unittest
from unittest.mock import patch

from check import Violation
from native import published_dev_target


class PublishedDevTests(unittest.TestCase):
    def invoke(self, output):
        with patch.dict('os.environ', {'CI_SERVER_URL': 'https://forge.example'}), \
             patch('native.fetch_environment', return_value={}), \
             patch('native.subprocess.check_output', return_value=output) as read:
            result = published_dev_target('GetBusbar/busbar', 'a' * 40)
            self.assertEqual(read.call_args.args[0], ['git', 'ls-remote',
                'https://forge.example/GetBusbar/busbar.git', 'refs/heads/dev'])
            return result

    def test_exact_published_source_is_bound(self):
        self.assertEqual(self.invoke('a' * 40 + '\trefs/heads/dev\n'), 'a' * 40)

    def test_moved_dev_requires_new_qualification(self):
        with self.assertRaisesRegex(Violation, 'published dev moved'):
            self.invoke('b' * 40 + '\trefs/heads/dev\n')

    def test_missing_ambiguous_or_wrong_ref_is_refused(self):
        for output in ['', 'a' * 40 + '\trefs/heads/main\n',
                       ('a' * 40 + '\trefs/heads/dev\n') * 2]:
            with self.subTest(output=output), self.assertRaises(Violation):
                self.invoke(output)

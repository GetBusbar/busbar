# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("ci_coverage", Path(__file__).with_name("ci_coverage.py"))
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


class RosterTests(unittest.TestCase):
    def test_valid_commands_and_comments(self):
        self.assertEqual(coverage.roster(b"# suite\nws\tbash testing/ws/run.sh\n"), {"ws": "bash testing/ws/run.sh"})

    def test_a_literal_backslash_t_is_not_a_delimiter(self):
        with self.assertRaises(ValueError):
            coverage.roster(b"ws\\tbash testing/ws/run.sh\n")

    def test_duplicate_suite_cannot_overwrite_an_execution(self):
        with self.assertRaises(ValueError):
            coverage.roster(b"ws\tbash testing/ws/run.sh\nws\tbash testing/other.sh\n")


if __name__ == "__main__":
    unittest.main()

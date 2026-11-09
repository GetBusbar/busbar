"""Native publication refuses machine-reported failures even after exit zero."""
import os
from pathlib import Path
import tempfile
import unittest

from native import validate_test_report, Violation


class TestReports(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'native.xml'

    def test_executed_passing_cases_are_accepted(self):
        self.path.write_text('<testsuites><testsuite failures="0" errors="0"><testcase name="real"/></testsuite></testsuites>')
        validate_test_report(self.path)

    def test_any_reported_failure_is_refused(self):
        for failing in ('<failure/>', '<error/>', '<rerunFailure/>', '<flakyFailure/>'):
            with self.subTest(failing=failing):
                self.path.write_text('<testsuite failures="0"><testcase>' + failing + '</testcase></testsuite>')
                with self.assertRaises(Violation):
                    validate_test_report(self.path)
        for field in ('failures', 'errors'):
            with self.subTest(field=field):
                self.path.write_text(f'<testsuite {field}="1"><testcase/></testsuite>')
                with self.assertRaises(Violation):
                    validate_test_report(self.path)

    def test_missing_empty_malformed_or_all_skipped_report_is_refused(self):
        with self.assertRaises(Violation):
            validate_test_report(self.path)
        for content in ('', '<testsuite/>', '<wrong><testcase/></wrong>',
                        '<testsuite><testcase><skipped/></testcase></testsuite>',
                        '<testsuite failures="unknown"><testcase/></testsuite>'):
            with self.subTest(content=content):
                self.path.write_text(content)
                with self.assertRaises(Violation):
                    validate_test_report(self.path)


if __name__ == '__main__':
    unittest.main()

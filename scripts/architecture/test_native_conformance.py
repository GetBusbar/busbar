"""Standalone evaluation failures remain failures and retain their real outputs."""
import json
import os
from pathlib import Path
import tempfile
import unittest

import native


class ConformanceEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.q = native.Qualification.__new__(native.Qualification)
        self.q.root = self.root
        self.q.evidence = self.root / 'evidence'
        self.q.evidence.mkdir()
        self.q.env = dict(os.environ)
        self.q.receipt = {'steps': []}
        scripts = self.root / 'testing/conformance'
        scripts.mkdir(parents=True)
        (scripts / 'suites.tsv').write_text('example\tbash example.sh\n')
        (scripts / 'run.sh').write_text('''mkdir -p target/conformance/verdicts
printf '{"exit_code":1}' > target/conformance/invocation.json
printf '{"status":"fail"}' > target/conformance/verdicts/example.json
exit 1
''')
        (scripts / 'sigstore.py').write_text('''import os, pathlib
pathlib.Path(os.environ['CONFORMANCE_OUT'], 'verdict.json').write_text('{"status":"not-run"}')
raise SystemExit(1)
''')

    def test_nonpassing_suites_and_release_check_both_run_and_keep_evidence(self):
        with self.assertRaisesRegex(native.Violation, 'evaluations did not pass'):
            self.q.core_conformance()
        self.assertEqual([step['exit_code'] for step in self.q.receipt['steps']], [1, 1])
        self.assertEqual(json.loads((self.q.evidence / 'conformance/verdicts/example.json').read_text())['status'], 'fail')
        self.assertEqual(json.loads((self.q.evidence / 'sigstore/verdict.json').read_text())['status'], 'not-run')

    def test_indirect_verdict_is_refused(self):
        output = self.root / 'target/conformance/verdicts'
        output.mkdir(parents=True)
        (output.parent / 'invocation.json').write_text('{}')
        other = self.root / 'other.json'
        other.write_text('{}')
        (output / 'example.json').symlink_to(other)
        with self.assertRaisesRegex(native.Violation, 'indirect conformance'):
            self.q.copy_conformance()


if __name__ == '__main__':
    unittest.main()

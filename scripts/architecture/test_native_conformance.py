"""Standalone evaluation failures remain failures and retain their real outputs."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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

    def test_external_failed_judge_keeps_hashed_output_without_admission(self):
        self.q.repository = 'GetBusbar/busbar-plane-llm'
        self.q.receipt['host_revision'] = 'a' * 40
        self.q.sdk = lambda: self.root
        self.q.architecture = lambda sdk: None
        entry = self.root / native.EXTERNAL_EVALUATIONS[self.q.repository]
        entry.write_text('''mkdir "$CONFORMANCE_OUT"
printf '{"status":"not-run","reason":"real model unavailable"}' > "$CONFORMANCE_OUT/evaluation.json"
printf 'upstream cases: 300 not run\n' > "$CONFORMANCE_OUT/results.txt"
exit 1
''')
        with patch.object(native, 'git', return_value='b' * 40):
            with self.assertRaisesRegex(native.Violation, 'failed; no automatic retry'):
                self.q.external_endpoint_conformance()
        self.assertEqual(self.q.receipt['steps'][-1]['exit_code'], 1)
        self.assertEqual(self.q.receipt['external_evidence'], {
            name: native.digest(self.q.evidence / 'external' / name)
            for name in ('evaluation.json', 'results.txt')})
        self.assertEqual(self.q.env['BUSBAR_PIN'], 'a' * 40)

    def test_external_job_cannot_substitute_for_other_repositories_or_modes(self):
        self.assertEqual(native.evaluation_job('GetBusbar/busbar-plane-llm', False, True),
                         'external-conformance')
        self.assertIsNone(native.evaluation_job('GetBusbar/busbar-plane-llm', False, False))
        for repository, core, external in [
                ('GetBusbar/busbar', False, True),
                ('GetBusbar/busbar-plane-llm', True, False),
                ('GetBusbar/busbar-plane-llm', True, True),
                ('GetBusbar/private-plugin', False, True)]:
            with self.assertRaises(native.Violation):
                native.evaluation_job(repository, core, external)


if __name__ == '__main__':
    unittest.main()

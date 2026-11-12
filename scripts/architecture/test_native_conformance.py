"""Standalone evaluation failures remain failures and retain their real outputs."""
import hashlib
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
        self.q.sdk = lambda: self.root
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
        subject = self.root / 'certified-busbar'
        subject.write_bytes(b'certified')
        staged = {'sha256': hashlib.sha256(b'certified').hexdigest()}
        with patch('native_release_stage.run_engineering', side_effect=native.Violation('engineering failed')), \
                patch('native_certified.stage', return_value=(subject, staged)) as stage, \
                patch('native_certified.verify_unchanged') as unchanged, \
                self.assertRaisesRegex(native.Violation, 'evaluations did not pass'):
            self.q.core_conformance()
        stage.assert_called_once_with(self.q)
        unchanged.assert_called_once_with(subject, staged)
        # Every suite resolves this subject: no conformance build of its own.
        self.assertEqual(self.q.env['BUSBAR_CONFORMANCE_SUBJECT'], str(subject))
        self.assertEqual(self.q.env['BUSBAR_CONFORMANCE_SUBJECT_SHA256'], staged['sha256'])
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

    def test_actual_judge_reports_survive_without_fixture_secrets_or_build_trees(self):
        output = self.root / 'target/conformance'
        (output / 'verdicts').mkdir(parents=True)
        (output / 'invocation.json').write_text('{}')
        (output / 'verdicts/h2.json').write_text('{"status":"fail"}')
        reports = {
            'h2/evidence/subject.xml': '<testsuite><testcase><failure>actual failure</failure></testcase></testsuite>',
            'otel-semconv-weaver/evidence/subject/live_check.json': '{"statistics":{"total_entities":1}}',
            'otlp/work/subject/traces.json': '{"resourceSpans":[]}',
            'oidf-run/subject/config.json': '{"client_secret":"do-not-retain"}',
            'oidf-run/record.json': json.dumps({'subject': {
                'exit': 1, 'modules': [['fapi2-module', 'FINISHED', 'REVIEW', 'token=do-not-retain']],
                'review_pages': {'fapi2-module': ['a' * 64]}}}),
            'h2/evidence/source.rs': 'do-not-retain',
        }
        for name, content in reports.items():
            path = output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.q.copy_conformance()
        destination = self.q.evidence / 'conformance'
        self.assertEqual((destination / 'h2/evidence/subject.xml').read_text(), reports['h2/evidence/subject.xml'])
        self.assertTrue((destination / 'otel-semconv-weaver/evidence/subject/live_check.json').is_file())
        self.assertFalse((destination / 'oidf-run').exists())
        self.assertFalse((destination / 'h2/evidence/source.rs').exists())
        summary = (destination / 'oidf-module-results.json').read_text()
        self.assertNotIn('do-not-retain', summary)
        self.assertEqual(json.loads(summary)['subject']['modules'], [['fapi2-module', 'FINISHED', 'REVIEW']])
        self.assertEqual(self.q.receipt['conformance_diagnostics']['h2/evidence/subject.xml'], native.digest(destination / 'h2/evidence/subject.xml'))

    def test_report_symlink_directory_cannot_escape_output_tree(self):
        output = self.root / 'target/conformance'
        (output / 'verdicts').mkdir(parents=True)
        (output / 'invocation.json').write_text('{}')
        outside = self.root / 'private'
        outside.mkdir()
        (outside / 'secret.xml').write_text('not evidence')
        (output / 'h2').mkdir()
        (output / 'h2/evidence').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(native.Violation, 'indirect conformance diagnostic'):
            self.q.copy_conformance()

    def test_external_failed_judge_keeps_hashed_output_without_admission(self):
        self.q.repository = 'GetBusbar/busbar-plane-llm'
        self.q.policy = {'repositories': {self.q.repository: {'native': {
            'external_conformance': 'testing/conformance/external-fixture.sh'}}}}
        self.q.receipt['host_revision'] = 'a' * 40
        self.q.sdk = lambda: self.root
        self.q.architecture = lambda sdk: None
        entry = self.root / native.native_settings(self.q.repository, self.q.policy)['external_conformance']
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
        self.assertTrue(native.requires_native_oracle('GetBusbar/busbar-plane-llm', False))
        self.assertFalse(native.requires_native_oracle('GetBusbar/busbar-plane-llm', True))
        self.assertIsNone(native.evaluation_job('GetBusbar/busbar-plane-llm', False, False))
        for repository, core, external in [
                ('GetBusbar/busbar', False, True),
                ('GetBusbar/busbar-plane-llm', False, True),
                ('GetBusbar/busbar-plane-decisions', False, True),
                ('GetBusbar/busbar-plane-llm', True, False),
                ('GetBusbar/busbar-plane-llm', True, True),
                ('GetBusbar/private-plugin', False, True)]:
            with self.assertRaises(native.Violation):
                native.evaluation_job(repository, core, external)


if __name__ == '__main__':
    unittest.main()

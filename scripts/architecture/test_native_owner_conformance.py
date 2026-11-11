"""Actual owner suites remain required when obsolete endpoint jobs are removed."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from check import Violation
from native import Qualification
from native_policy import conformance_rows

TRUSTED = Path(__file__).resolve().parents[2]


class OwnerConformance(unittest.TestCase):
    def qualification(self, directory, repository):
        q = Qualification.__new__(Qualification)
        q.root, q.trusted, q.repository = Path(directory), TRUSTED, repository
        q.receipt = {}
        q.run, q.copy_conformance = Mock(), Mock()
        rows = conformance_rows(repository, trusted=TRUSTED)
        roster = q.root / 'testing/conformance/suites.tsv'
        roster.parent.mkdir(parents=True)
        roster.write_text(''.join(name + '\t' + row['command'] + '\n' for name, row in rows.items()))
        return q, roster, rows

    def test_protected_inventory_retains_all_eight_llm_and_one_jev_suites(self):
        self.assertEqual(set(conformance_rows('GetBusbar/busbar-plane-llm')), {
            'llm-anthropic', 'llm-bedrock', 'llm-cohere', 'llm-gemini', 'llm-openai',
            'llm-responses', 'voice-transcribe', 'voice-tts'})
        self.assertEqual(set(conformance_rows('GetBusbar/busbar-plane-decisions')), {'jev'})
        pipeline = (TRUSTED / 'ci/architecture-pipeline.yml').read_text()
        self.assertNotIn('\nexternal-conformance:', pipeline)
        self.assertIn('\nnative-qualification:', pipeline)

    def test_each_required_suite_cannot_disappear_or_change_command(self):
        for repository in ('GetBusbar/busbar-plane-llm', 'GetBusbar/busbar-plane-decisions'):
            with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
                q, roster, rows = self.qualification(directory, repository)
                for missing in rows:
                    with self.subTest(repository=repository, suite=missing):
                        roster.write_text(''.join(name + '\t' + row['command'] + '\n'
                                                for name, row in rows.items() if name != missing))
                        with self.assertRaisesRegex(Violation, 'missing or its command differs'):
                            q.conformance('plugin-native-conformance')
                        roster.write_text(''.join(name + '\t' + ('true' if name == missing else row['command']) + '\n'
                                                for name, row in rows.items()))
                        with self.assertRaisesRegex(Violation, 'missing or its command differs'):
                            q.conformance('plugin-native-conformance')
                q.run.assert_not_called()

    def test_actual_command_failure_is_propagated_and_outputs_collected(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            q, _, rows = self.qualification(directory, 'GetBusbar/busbar-plane-llm')
            q.run.side_effect = Violation('real provider-spec suite failed')
            with self.assertRaisesRegex(Violation, 'real provider-spec suite failed'):
                q.conformance('plugin-native-conformance')
            self.assertEqual(q.receipt['required_conformance_suites'], sorted(rows))
            q.copy_conformance.assert_called_once()
            q.run.assert_called_once_with('plugin-native-conformance',
                ['bash', str(q.root / 'testing/conformance/run.sh')], timeout=10800)

    def test_duplicate_or_missing_roster_refuses_before_command(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            q, roster, _ = self.qualification(directory, 'GetBusbar/busbar-plane-decisions')
            roster.write_text(roster.read_text() * 2)
            with self.assertRaisesRegex(Violation, 'duplicate'):
                q.conformance('plugin-native-conformance')
            roster.unlink()
            with self.assertRaises(Violation):
                q.conformance('plugin-native-conformance')
            q.run.assert_not_called()


if __name__ == '__main__':
    unittest.main()

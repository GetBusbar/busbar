"""Exact public-fixture classification; different keys and locations remain findings."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from secret_fixtures import classify


class PublicFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name)
        self.path = 'fixtures/key.pem'
        self.content = b'public fixture bytes\n'
        self.file = self.source / self.path
        self.file.parent.mkdir()
        self.file.write_bytes(self.content)
        self.entry = dict(id='public-test-key', repository='test/repo', path=self.path,
            source_sha256=hashlib.sha256(self.content).hexdigest(), rule_id='private-key',
            start_line=1, end_line=1, reason='public test fixture', provenance='published fixture commit')
        self.policy = json.dumps(dict(schema='busbar.public-secret-fixtures/1', fixtures=[self.entry])).encode()
        self.finding = dict(RuleID='private-key', StartLine=1, EndLine=1, Match='NEVER_PRINT_THIS')
        self.report = dict(Results=[dict(Target=self.path, Secrets=[self.finding])])
        self.rows = [dict(path=self.path, mode='100644', sha256=self.entry['source_sha256'])]

    def classify(self):
        return classify(self.report, repository='test/repo', source=self.source,
                        source_rows=self.rows, policy=self.policy)

    def test_exact_public_fixture_preserves_safe_classification(self):
        result = self.classify()
        self.assertEqual(result['classified_public_fixtures'], 1)
        self.assertEqual(result['unresolved_findings'], 0)
        self.assertEqual(result['public_fixture_classifications'], [{'finding_index': 0, **self.entry}])
        self.assertNotIn('NEVER_PRINT_THIS', json.dumps(result))

    def test_different_key_at_same_path_remains_unresolved(self):
        # Model a new committed key: inventory updates, approved whole-file digest cannot.
        self.file.write_bytes(b'different private key bytes\n')
        self.rows[0]['sha256'] = hashlib.sha256(self.file.read_bytes()).hexdigest()
        result = self.classify()
        self.assertEqual(result['classified_public_fixtures'], 0)
        self.assertEqual(result['unresolved_findings'], 1)

    def test_same_fixture_at_different_path_remains_unresolved(self):
        self.file.rename(self.source / 'fixtures/elsewhere.pem')
        self.rows[0]['path'] = 'fixtures/elsewhere.pem'
        self.report['Results'][0]['Target'] = self.rows[0]['path']
        self.assertEqual(self.classify()['unresolved_findings'], 1)

    def test_unknown_rule_location_and_count_expansion_refuse(self):
        good = copy.deepcopy(self.report)
        for change in ({'RuleID': 'new-rule'}, {'StartLine': 2}, {'EndLine': 2}):
            with self.subTest(change=change):
                self.report = copy.deepcopy(good)
                self.report['Results'][0]['Secrets'][0].update(change)
                self.assertEqual(self.classify()['unresolved_findings'], 1)
        self.report = good
        self.report['Results'][0]['Secrets'].append(copy.deepcopy(self.finding))
        result = self.classify()
        self.assertEqual(result['classified_public_fixtures'], 1)
        self.assertEqual(result['unresolved_findings'], 1)

    def test_traversal_symlink_git_link_and_post_export_mutation_refuse(self):
        for path in ('../fixtures/key.pem', '/fixtures/key.pem', './fixtures/key.pem', 'fixtures//key.pem'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.report['Results'][0]['Target'] = path
                self.classify()
        self.report['Results'][0]['Target'] = self.path
        self.rows[0]['mode'] = '120000'
        with self.assertRaises(ValueError):
            self.classify()
        self.rows[0]['mode'] = '100644'
        self.file.write_bytes(b'mutated after export')
        with self.assertRaises(ValueError):
            self.classify()
        self.file.unlink()
        actual = self.source / 'other'
        actual.write_bytes(self.content)
        self.file.symlink_to(actual)
        with self.assertRaises(ValueError):
            self.classify()


if __name__ == '__main__':
    unittest.main()

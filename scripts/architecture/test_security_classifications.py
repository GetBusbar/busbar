"""Admission accepts classified counts only against the immutable trusted manifest."""
import copy
import hashlib
import json
import unittest

from admission import validate_security_scans


class SecurityClassifications(unittest.TestCase):
    def setUp(self):
        self.repository = 'GetBusbar/busbar-release'
        self.entries = [dict(id=f'fixture-{i}', repository=self.repository, path=f'fixtures/{i}.pem',
            source_sha256=str(i) * 64, rule_id='private-key', start_line=1, end_line=1,
            reason='public fixture', provenance='published fixture commit') for i in (1, 2)]
        self.policy = json.dumps(dict(schema='busbar.public-secret-fixtures/1', fixtures=self.entries)).encode()
        digest = hashlib.sha256(self.policy).hexdigest()
        self.receipt = dict(policy_files={'public-secret-fixtures.json': digest}, steps=[
            dict(name='secrets', status='pass', exit_code=1, findings=2,
                classified_public_fixtures=2, unresolved_findings=0, classification_policy_sha256=digest,
                public_fixture_classifications=[dict(finding_index=i, **e) for i, e in enumerate(self.entries)]),
            dict(name='dependencies', status='pass', exit_code=0, findings=0),
            dict(name='sast', status='pass', exit_code=0, findings=0)])

    def validate(self):
        validate_security_scans(self.receipt, self.repository, self.policy)

    def test_trusted_exact_classification_accepts_raw_positive_count_and_exit_one(self):
        self.validate()
        self.assertEqual(self.receipt['steps'][0]['findings'], 2)
        self.assertEqual(self.receipt['steps'][0]['exit_code'], 1)

    def test_candidate_policy_cannot_replace_controller_policy(self):
        for policy in (None, self.policy.replace(b'published fixture commit', b'candidate approval')):
            with self.subTest(policy=bool(policy)), self.assertRaises(ValueError):
                validate_security_scans(self.receipt, self.repository, policy)
        self.receipt['policy_files']['public-secret-fixtures.json'] = '0' * 64
        with self.assertRaises(ValueError):
            self.validate()

    def test_unknown_duplicate_reordered_or_other_repository_entry_refuses(self):
        good = copy.deepcopy(self.receipt)
        originals = good['steps'][0]['public_fixture_classifications']
        bad = [list(reversed(originals)), [originals[0], dict(originals[0], finding_index=1)],
            [dict(originals[0], rule_id='unknown'), originals[1]],
            [dict(originals[0], repository='other/repo'), originals[1]],
            [dict(originals[0], finding_index=False), originals[1]],
            [dict(originals[0], start_line=True), originals[1]]]
        for entries in bad:
            self.receipt = copy.deepcopy(good)
            self.receipt['steps'][0]['public_fixture_classifications'] = entries
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.validate()

    def test_unknown_findings_bad_counts_status_and_nonsecret_classification_refuse(self):
        good = copy.deepcopy(self.receipt)
        for change in ({'findings': 3}, {'unresolved_findings': 1}, {'classified_public_fixtures': 1},
                       {'exit_code': 0}, {'exit_code': 2}, {'status': 'fail'}, {'findings': True},
                       {'unresolved_findings': False}, {'classification_policy_sha256': '0' * 64}):
            self.receipt = copy.deepcopy(good)
            self.receipt['steps'][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate()
        self.receipt = good
        self.receipt['steps'][0]['name'] = 'dependencies'
        self.receipt['steps'][1]['name'] = 'secrets'
        with self.assertRaises(ValueError):
            self.validate()


if __name__ == '__main__':
    unittest.main()

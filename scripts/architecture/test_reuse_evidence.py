"""Focused fail-closed tests; no live CI calls or candidate execution."""
import copy
import datetime as dt
import hashlib
import io
import json
import tempfile
import os
import unittest
from unittest.mock import patch
import zipfile

from reuse_evidence import Archive, Resolver, independent_qualification_job
from input_identity import (encoded, TRIVY_METADATA_CONTRACT_IMAGE,
                            TRIVY_METADATA_CONTRACT_SCANNER)


def archive(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as output:
        for path, raw in files.items():
            output.writestr('boundary-evidence/' + path, raw)
    return stream.getvalue()


class API:
    def __init__(self, rows, raw):
        self.rows, self.payloads = rows, raw

    def json(self, path):
        return copy.deepcopy(self.rows[path])

    def all(self, path):
        return self.json(path)

    def raw(self, path):
        return self.payloads[path]


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='reuse-auth-test-',
            dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.original = dict(repository='GetBusbar/busbar-secret-c', source='1' * 40,
                             policy='2' * 40, host='2' * 40, sdk='3' * 40,
                             job='native-qualification')
        self.receipt = dict(schema='busbar.protected-native-admission/1', status='pass',
            repository=self.original['repository'], source='1' * 40, target_revision='1' * 40,
            policy_revision='2' * 40, host_revision='2' * 40, sdk_revision='3' * 40,
            policy_sha256='a' * 64, job_id='12', pipeline_id='11',
            config_uri='github.com/GetBusbar/busbar-secret-c//'
                       'ci/architecture-pipeline.yml@GetBusbar/busbar:' + '2' * 40 + '@refs/heads/dev',
            steps=[dict(name='c-unit', status='pass', exit_code=0,
                        stdout_sha256=hashlib.sha256(b'tested').hexdigest(),
                        stderr_sha256=hashlib.sha256(b'').hexdigest())])
        self.receipt_bytes = json.dumps(self.receipt).encode()
        self.files = {'receipt.json': self.receipt_bytes, 'c-unit.stdout': b'tested',
                      'c-unit.stderr': b''}
        self.artifacts = archive(self.files)
        self.job = dict(id=12, name='native-qualification', status='success', allow_failure=False,
                        pipeline={'id': 11}, commit={'id': '1' * 40}, ref='dev', runner={'id': 7})
        self.rows = {'projects/GetBusbar%2Fbusbar-secret-c': dict(id=10,
            path_with_namespace='GetBusbar/busbar-secret-c', merge_method='ff',
            ci_pipeline_variables_minimum_override_role='no_one_allowed',
            only_allow_merge_if_pipeline_succeeds=True, allow_merge_on_skipped_pipeline=False,
            ci_config_path='ci/architecture-pipeline.yml@GetBusbar/busbar:' + '4' * 40),
            'projects/10/protected_branches': [], 'groups/GetBusbar/protected_branches': [],
            'projects/10/pipelines/11': dict(id=11, project_id=10, sha='1' * 40,
                status='success', ref='dev', source='api', user={'id': 6}),
            'projects/10/pipelines/11/jobs': [self.job, dict(id=13, name='security-scans',
                status='success', allow_failure=False)], 'projects/10/jobs/12': self.job}
        self.rows['projects/10/repository/branches'] = [
            dict(name=branch, protected=True) for branch in ('dev', 'qa', 'main')]
        self.raw = {'projects/10/jobs/12/artifacts/boundary-evidence/receipt.json': self.receipt_bytes,
                    'projects/10/jobs/12/artifacts': self.artifacts}
        self.api = API(self.rows, self.raw)
        self.calls = []

    def validator(self, original, receipt, artifact, context, policy):
        self.assertEqual(artifact('c-unit.stdout'), b'tested')
        self.calls.append(context)
        return True

    def resolver(self):
        result = Resolver(self.api, group_api=self.api, objects=None, current_policy='4' * 40,
            merge_users={6}, owner_users={6}, scratch=self.tmp.name, full_validator=self.validator,
            trusted_policies={'2' * 40, '4' * 40})
        result._policy = lambda *args: dict(required_external=None, owner_suites=[],
                                            files={'ci/architecture.toml': 'a' * 64})
        return result

    def verify(self):
        resolver = self.resolver()
        self.assertTrue(resolver.authenticate_original(self.original, self.receipt,
                                                       hashlib.sha256(self.artifacts).hexdigest()))
        return resolver.validate_original(self.original, self.receipt_bytes, self.artifacts)

    def test_success_preserves_original_selector_when_current_changed(self):
        self.assertTrue(self.verify())
        self.assertEqual(self.calls[0]['original']['policy'], '2' * 40)

    def test_explicit_mixed_installed_selectors(self):
        resolver = self.resolver()
        resolver.selector_policies = {self.original['repository']: '2' * 40}
        self.rows['projects/GetBusbar%2Fbusbar-secret-c']['ci_config_path'] = (
            'ci/architecture-pipeline.yml@GetBusbar/busbar:' + '2' * 40)
        self.assertTrue(resolver.authenticate_original(self.original, self.receipt,
                                                       hashlib.sha256(self.artifacts).hexdigest()))
        self.assertTrue(resolver.validate_original(self.original, self.receipt_bytes, self.artifacts))

    def test_failed_independent_sibling_does_not_relabel_parent_green(self):
        self.rows['projects/10/pipelines/11']['status'] = 'failed'
        self.rows['projects/10/pipelines/11/jobs'][1]['status'] = 'failed'
        self.assertTrue(self.verify())
        self.assertEqual(self.calls[0]['pipeline']['status'], 'failed')

    def test_unrecognized_prerequisite_graph_refuses(self):
        text = b'stages: [qualify, website]\nnative-qualification:\n  stage: qualify\nsecurity-scans:\n  extends: native-qualification\n'
        self.assertTrue(independent_qualification_job(text, 'security-scans'))
        for addition in (b'  needs: [other]\n', b'  dependencies: [other]\n', b'  stage: website\n'):
            with self.subTest(addition=addition), self.assertRaises(ValueError):
                independent_qualification_job(text + addition, 'security-scans')

    def test_unapproved_original_validator_never_executes(self):
        resolver = self.resolver()
        resolver.trusted_policies = {'4' * 40}
        with self.assertRaisesRegex(ValueError, 'controller-approved'):
            resolver.resolve(self.original, self.receipt)

    def test_security_source_policy_images_and_advisory_freshness(self):
        class Objects:
            def tree(self, *args):
                return {'src.rs': {'mode': '100644', 'blob': '5' * 40}}

            def blob(self, *args):
                return b'source'

            def git(self, *args):
                return ('6' * 40).encode()

        resolver = self.resolver()
        resolver.objects = Objects()
        resolver.now = lambda: dt.datetime(2026, 11, 11, 20, tzinfo=dt.timezone.utc)
        source_rows = [dict(path='src.rs', mode='100644',
                            sha256=hashlib.sha256(b'source').hexdigest())]
        receipt = dict(policy_files={'tools.json': '7' * 64},
            source_files_sha256=hashlib.sha256(encoded(source_rows)).hexdigest(), source_tree='6' * 40,
            database=dict(updated_at='2026-11-11T13:00:00Z', sha256='8' * 64, metadata_sha256='9' * 64),
            steps=[dict(name=name, tool_image=tool, report_sha256='a' * 64, stderr_sha256='b' * 64)
                   for name, tool in [('secrets', 'trivy'), ('dependencies', 'trivy'), ('sast', 'semgrep')]])
        context = {'policy': {'files': {'ci/security/tools.json': '7' * 64},
                             'tools': dict(trivy='trivy', semgrep='semgrep', database_max_age_hours=72)}}
        self.assertEqual(resolver._security(self.original, receipt, context), receipt['database'])
        for key, value in [('source_files_sha256', '0' * 64), ('source_tree', '0' * 40),
                           ('policy_files', {}), ('database', dict(receipt['database'],
                            updated_at='2026-11-01T13:00:00Z'))]:
            with self.subTest(key=key), patch.dict(receipt, {key: value}), self.assertRaises(ValueError):
                resolver._security(self.original, receipt, context)
        with patch.dict(receipt['steps'][0], {'tool_image': 'untrusted'}), self.assertRaises(ValueError):
            resolver._security(self.original, receipt, context)

    def test_authenticated_security_compares_semantics_and_preserves_metadata_hashes(self):
        original = dict(self.original, job='security-scans')
        database = dict(updated_at='2026-11-11T13:00:00Z', sha256='8' * 64,
                        metadata_sha256='9' * 64)
        receipt_bytes = json.dumps(dict(job_id='12', database=database)).encode()
        artifact_bytes = archive({'security.json': receipt_bytes})
        tools = dict(trivy=TRIVY_METADATA_CONTRACT_IMAGE, database_max_age_hours=72)
        context = dict(receipt_bytes=receipt_bytes, artifact_bytes=artifact_bytes,
                       policy=dict(tools=tools, files={
                           'scripts/security/scan.py': TRIVY_METADATA_CONTRACT_SCANNER}))
        resolver = self.resolver()
        resolver.now = lambda: dt.datetime(2026, 11, 11, 20, tzinfo=dt.timezone.utc)
        resolver._security = lambda request, receipt, context: receipt['database']
        witness = dict(database=dict(database, metadata_sha256='a' * 64), tools=tools,
                       scanner_sha256=TRIVY_METADATA_CONTRACT_SCANNER)
        resolver.database_witness = witness
        key = json.dumps(original, sort_keys=True), '12'
        resolver._authenticated[key] = context
        self.assertTrue(resolver.validate_original(original, receipt_bytes, artifact_bytes))
        self.assertEqual(json.loads(receipt_bytes)['database']['metadata_sha256'], '9' * 64)
        self.assertEqual(witness['database']['metadata_sha256'], 'a' * 64)
        for replacement in (dict(database, sha256='b' * 64),
                            dict(database, updated_at='2026-11-01T13:00:00Z')):
            resolver._authenticated[key] = context
            with patch.dict(witness, {'database': replacement}), self.assertRaises(ValueError):
                resolver.validate_original(original, receipt_bytes, artifact_bytes)
        resolver._authenticated[key] = context
        with patch.dict(witness, {'scanner_sha256': '0' * 64}), self.assertRaises(ValueError):
            resolver.validate_original(original, receipt_bytes, artifact_bytes)

    def test_wrong_job_policy_source_and_optional_job_refuse(self):
        for key, value in [('name', 'other'), ('allow_failure', True),
                           ('commit', {'id': '9' * 40}), ('runner', None)]:
            with self.subTest(key=key), patch.dict(self.job, {key: value}):
                with self.assertRaises(ValueError):
                    self.verify()
        for key in ('policy_revision', 'source', 'config_uri'):
            with self.subTest(key=key), patch.dict(self.receipt, {key: 'wrong'}):
                with self.assertRaises(ValueError):
                    self.verify()

    def test_wrong_hash_and_missing_artifact_refuse(self):
        with self.assertRaises(ValueError):
            self.resolver().authenticate_original(self.original, self.receipt, '0' * 64)
        del self.files['c-unit.stdout']
        self.artifacts = archive(self.files)
        self.raw['projects/10/jobs/12/artifacts'] = self.artifacts
        with self.assertRaisesRegex(ValueError, 'artifact missing'):
            self.verify()

    def test_mandatory_pipeline_and_ref_protection_refuse(self):
        for path, key, value in [('projects/10/pipelines/11', 'status', 'canceled'),
                                  ('projects/10/pipelines/11', 'source', 'web'),
                                  ('projects/10/pipelines/11', 'user', {'id': 99})]:
            with self.subTest(path=path, key=key), patch.dict(self.rows[path], {key: value}):
                with self.assertRaises(ValueError):
                    self.verify()
        with patch.dict(self.rows['projects/10/repository/branches'][2], {'protected': False}):
            with self.assertRaisesRegex(ValueError, 'not protected'):
                self.verify()

    def test_uncreated_release_refs_require_protection_rules_not_branch_creation(self):
        from admission import validate_protection

        self.rows['projects/10/repository/branches'] = [dict(name='dev', protected=True)]
        self.rows['projects/10/protected_branches'] = [dict(name=branch,
            allow_force_push=False, push_access_levels=[{'access_level': 0}],
            merge_access_levels=[{'user_id': 6}]) for branch in ('dev', 'qa', 'main')]
        resolver = self.resolver()
        info = resolver._policy

        def policy(original, project_rules, group_rules, receipt):
            validate_protection(project_rules, group_rules, {6})
            return info(original, project_rules, group_rules, receipt)

        resolver._policy = policy
        context = resolver.resolve(self.original, self.receipt)
        self.assertIsNone(context['protected_refs']['qa'])
        self.assertIsNone(context['protected_refs']['main'])
        self.rows['projects/10/protected_branches'].pop()
        with self.assertRaisesRegex(ValueError, 'unprotected branch: main'):
            resolver.resolve(self.original, self.receipt)
        self.rows['projects/10/repository/branches'] = []
        with self.assertRaisesRegex(ValueError, 'development ref missing'):
            resolver.resolve(self.original, self.receipt)

    def test_authenticated_bytes_and_mandatory_full_validation(self):
        resolver = self.resolver()
        with self.assertRaises(ValueError):
            resolver.validate_original(self.original, self.receipt_bytes, self.artifacts)
        resolver.authenticate_original(self.original, self.receipt, hashlib.sha256(self.artifacts).hexdigest())
        with self.assertRaises(ValueError):
            resolver.validate_original(self.original, self.receipt_bytes + b' ', self.artifacts)
        self.validator = lambda *args: False
        with self.assertRaisesRegex(ValueError, 'complete original'):
            self.verify()

    def test_archive_traversal_and_duplicate_refuse(self):
        with self.assertRaises(ValueError):
            Archive(archive({'../escape': b'x'}))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as output:
            output.writestr('boundary-evidence/a', b'a')
            output.writestr('boundary-evidence/a', b'b')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            Archive(buffer.getvalue())


if __name__ == '__main__':
    unittest.main()

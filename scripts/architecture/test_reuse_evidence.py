"""Focused fail-closed tests; no live CI calls or candidate execution."""
import copy
import datetime as dt
import hashlib
import io
import json
import tempfile
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from admission import CORE_BUILD_STEPS
from reuse_evidence import (Archive, Resolver, dev_required_jobs, independent_qualification_job,
                            OwnerRuntime, ReleaseValidator, pipeline_tier, validate_core_build,
                            verify_release_dispatch, expected_loader)
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
                                            files={'ci/architecture.toml': 'a' * 64},
                                            tier=getattr(self, 'tier', 'single'))
        return result

    def verify(self):
        resolver = self.resolver()
        self.assertTrue(resolver.authenticate_original(self.original, self.receipt,
                                                       hashlib.sha256(self.artifacts).hexdigest()))
        return resolver.validate_original(self.original, self.receipt_bytes, self.artifacts)

    def test_success_preserves_original_selector_when_current_changed(self):
        self.assertTrue(self.verify())
        self.assertEqual(self.calls[0]['original']['policy'], '2' * 40)

    def test_permanent_release_dispatch_uses_actual_immutable_driver_shape(self):
        from pathlib import Path
        raw = (Path(__file__).resolve().parent / 'native.py').read_bytes()
        self.assertEqual(verify_release_dispatch(raw), hashlib.sha256(raw).hexdigest())
        with self.assertRaisesRegex(ValueError, 'dispatch'):
            verify_release_dispatch(raw.replace(b'qualify_generator(qualification)', b'qualification.run_unchecked()'))

    def test_complete_release_validator_cannot_accept_another_owner(self):
        with self.assertRaisesRegex(ValueError, 'release native validator scope differs'):
            ReleaseValidator(None)(self.original, self.receipt, lambda path: b'', {}, {})

    def test_old_validator_code_is_rejected_before_any_execution(self):
        runtime = OwnerRuntime.__new__(OwnerRuntime)
        runtime.policy, runtime.approved = 'b' * 40, {'b' * 40}
        runtime.ensure = lambda *args: None
        class Objects:
            def blob(self, repository, revision, path):
                return b'approved' if revision == 'b' * 40 else b'unapproved executable code'
        runtime.objects = Objects()
        with patch('reuse_evidence.subprocess.run') as process, self.assertRaisesRegex(ValueError, 'validator differs'):
            runtime.approve_policy('a' * 40)
        process.assert_not_called()

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

    def test_tiered_prerequisite_graph_is_exact(self):
        text = (Path(__file__).resolve().parents[2] / 'ci/architecture-pipeline.yml').read_bytes()
        self.assertEqual(pipeline_tier(text), 'tiered')
        self.assertTrue(independent_qualification_job(text, 'core-conformance'))
        build = b'core-build:\n  extends: .controller\n  stage: build\n'
        self.assertIn(build, text)
        changes = [
            (b'  stage: build\n', b'  stage: build\n  needs: [other]\n'),
            (build, build.replace(b'stage: build', b'stage: qualify')),
            (build, build + b'  when: always\n'),
            (build, build.replace(b'.controller', b'native-qualification')),
            (b'core-conformance:\n  extends: .controller\n  stage: qualify\n',
             b'core-conformance:\n  extends: .controller\n  stage: website\n'),
            (b'    - !reference [.rules, core-dev]\n', b'    - !reference [.rules, core-dev]\n    - when: always\n'),
            (b'stages: [build, qualify, website, release]', b'stages: [build, qualify, extra, website, release]'),
            (b'.controller:\n', b'.controller:\n  stage: qualify\n'),
            (b'website-dev:\n  stage: website\n', b'website-dev:\n  stage: build\n'),
            (b'core-dev:\n', b'core-dev:\n    - when: on_success\n'),
            # Only the shared controller's empty download list is recognized; it adds no edge.
            (b'  dependencies: []\n', b'  dependencies: [core-build]\n'),
            (b'  dependencies: []\n', b'  needs: []\n'),
            (b'  dependencies: []\n', b'  dependencies: []\n  dependencies: []\n'),
            (build, build + b'  dependencies: []\n'),
        ]
        for old, new in changes:
            with self.subTest(change=new), self.assertRaises(ValueError):
                self.assertIn(old, text)
                independent_qualification_job(text.replace(old, new, 1), 'core-conformance')

    def tiered_core(self):
        """The same original pipeline as a tiered core dev push: core-build -> core-conformance."""
        from native_certified import BUILD
        binary, development = b'certified-binary', b'{"development": true}'
        self.original = dict(self.original, repository='GetBusbar/busbar', host='1' * 40,
                             job='core-build')
        steps = [dict(name=name, status='pass', exit_code=0,
                      stdout_sha256=hashlib.sha256(b'tested').hexdigest(),
                      stderr_sha256=hashlib.sha256(b'').hexdigest()) for name in CORE_BUILD_STEPS]
        record = dict(sha256=hashlib.sha256(binary).hexdigest(), bytes=len(binary), path='busbar',
                      command=['cargo', *BUILD], rustc_wrapper='', clippy_args=[],
                      profile_use=None, development_artifact_receipt_sha256=hashlib.sha256(development).hexdigest())
        uri = ('github.com/GetBusbar/busbar//ci/architecture-pipeline.yml@GetBusbar/busbar:'
               + '2' * 40 + '@refs/heads/dev')
        self.receipt = dict(self.receipt, schema='busbar.core-build/1', repository='GetBusbar/busbar',
            host_revision='1' * 40, config_uri=uri, steps=steps, certified_binary=record,
            binary_sha256=record['sha256'], development_artifact=dict(sha256=record[
                'development_artifact_receipt_sha256'], path='development-artifact/receipt.json'))
        self.receipt_bytes = json.dumps(self.receipt).encode()
        self.files = {'receipt.json': self.receipt_bytes, 'busbar': binary,
                      'development-artifact/receipt.json': development,
                      **{step['name'] + '.' + stream: (b'tested' if stream == 'stdout' else b'')
                         for step in steps for stream in ('stdout', 'stderr')}}
        self.artifacts = archive(self.files)
        self.job.update(name='core-build')
        conformance_job = dict(self.job, id=14, name='core-conformance')
        self.conformance = dict(self.receipt, schema='busbar.protected-conformance/1', job_id='14',
            certified_binary=dict(sha256=record['sha256'], bytes=len(binary), core_build_job_id=12,
                                  pipeline_id=11),
            steps=[dict(name='core-native-conformance', status='pass', exit_code=0,
                        stdout_sha256=hashlib.sha256(b'judged').hexdigest(),
                        stderr_sha256=hashlib.sha256(b'').hexdigest())])
        self.store_conformance()
        project = dict(self.rows.pop('projects/GetBusbar%2Fbusbar-secret-c'), path_with_namespace='GetBusbar/busbar')
        self.rows['projects/GetBusbar%2Fbusbar'] = project
        self.rows['projects/10/pipelines/11/jobs'] = [self.job, conformance_job]
        self.rows['projects/10/jobs/14'] = conformance_job
        self.raw.update({'projects/10/jobs/12/artifacts/boundary-evidence/receipt.json': self.receipt_bytes,
                         'projects/10/jobs/12/artifacts': self.artifacts})
        self.store_conformance()
        self.tier = 'tiered'
        self.validator = validate_core_build

    def store_conformance(self):
        self.conformance_bytes = json.dumps(self.conformance).encode()
        self.conformance_artifacts = archive({'receipt.json': self.conformance_bytes,
            'core-native-conformance.stdout': b'judged', 'core-native-conformance.stderr': b''})
        self.raw.update({'projects/10/jobs/14/artifacts/boundary-evidence/receipt.json': self.conformance_bytes,
                         'projects/10/jobs/14/artifacts': self.conformance_artifacts})

    def verify_conformance(self):
        self.validator = lambda *args: True  # The marketing normalizer is covered elsewhere.
        resolver = self.resolver()
        original = dict(self.original, job='core-conformance')
        self.assertTrue(resolver.authenticate_original(original, self.conformance,
                                                       hashlib.sha256(self.conformance_artifacts).hexdigest()))
        return resolver.validate_original(original, self.conformance_bytes, self.conformance_artifacts)

    def test_tiered_core_dev_jobs_are_the_required_reusable_pair(self):
        self.tiered_core()
        self.assertTrue(self.verify())
        self.assertTrue(self.verify_conformance())
        self.assertEqual(dev_required_jobs('GetBusbar/busbar', 'tiered'), {'core-build', 'core-clippy', 'core-conformance'})
        self.assertEqual(dev_required_jobs('GetBusbar/busbar', 'single', 'core-conformance'),
                         {'native-qualification', 'security-scans', 'core-conformance'})
        self.assertEqual(dev_required_jobs('GetBusbar/busbar-x', 'tiered'),
                         {'native-qualification', 'security-scans'})
        # Under the tiered policy core-native is a QA-tier job: never dev reuse evidence.
        self.original['job'] = 'native-qualification'
        self.job['name'] = 'native-qualification'
        with self.assertRaisesRegex(ValueError, 'not required'):
            self.resolver().resolve(self.original, dict(self.receipt, schema='busbar.protected-native-admission/1'))

    def test_tiered_core_build_refuses_other_bytes_or_failed_checks(self):
        self.tiered_core()
        good = copy.deepcopy(self.receipt)
        for change in (dict(binary_sha256='0' * 64), dict(schema='busbar.protected-native-admission/1'),
                       dict(certified_binary=dict(good['certified_binary'], rustc_wrapper='clippy-driver')),
                       dict(certified_binary=dict(good['certified_binary'], command=['cargo', 'build'])),
                       dict(certified_binary=dict(good['certified_binary'], sha256='0' * 64)),
                       dict(certified_binary=dict(good['certified_binary'], bytes=1)),
                       dict(steps=good['steps'][1:]),
                       dict(steps=[dict(good['steps'][0], status='fail', exit_code=1), *good['steps'][1:]])):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.receipt = dict(good, **change)
                self.receipt_bytes = json.dumps(self.receipt).encode()
                self.artifacts = archive(dict(self.files, **{'receipt.json': self.receipt_bytes}))
                self.raw['projects/10/jobs/12/artifacts/boundary-evidence/receipt.json'] = self.receipt_bytes
                self.raw['projects/10/jobs/12/artifacts'] = self.artifacts
                self.verify()

    def test_tiered_core_conformance_must_judge_its_own_pipeline_build(self):
        self.tiered_core()
        good = copy.deepcopy(self.conformance)
        for change in (dict(binary_sha256='0' * 64),
                       dict(certified_binary=dict(good['certified_binary'], sha256='0' * 64)),
                       dict(certified_binary=dict(good['certified_binary'], core_build_job_id=99)),
                       dict(certified_binary=dict(good['certified_binary'], pipeline_id=99)),
                       dict(certified_binary=None)):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'certified core-build'):
                self.conformance = dict(good, **change)
                self.store_conformance()
                self.verify_conformance()
        self.conformance = good
        self.store_conformance()
        for status in ('failed', 'skipped'):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, 'core-build'):
                self.rows['projects/10/pipelines/11/jobs'][0]['status'] = status
                self.verify_conformance()
        self.rows['projects/10/pipelines/11/jobs'][0]['status'] = 'success'
        self.rows['projects/10/pipelines/11/jobs'].pop(0)
        with self.assertRaisesRegex(ValueError, 'core-build'):
            self.verify_conformance()

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


class NormalizerLayoutTests(unittest.TestCase):
    def test_original_conformance_inputs_include_capability_validator(self):
        source, sdk = 'a' * 40, 'b' * 40
        files = {'ci/architecture.toml': b'[repositories]\n',
                 'scripts/ci-product-pins.json': json.dumps({'sdk': sdk}).encode(),
                 'Cargo.lock': b'root-lock', 'dist/default/Cargo.lock': b'product-lock',
                 'testing/conformance/suites.tsv': b'h2\tfixture\n',
                 'testing/conformance/capabilities.py': b'capability-validation',
                 'conformance/ci-coverage.json': b'{"schema":"busbar.conformance.ci-coverage/1","suites":{}}'}
        objects = SimpleNamespace(tree=lambda *args: files, blob=lambda repo, ref, path: files[path])
        request = dict(repository='GetBusbar/busbar', source=source, host=source,
                       policy=source, sdk=sdk, job='core-conformance')
        load = expected_loader(objects, SimpleNamespace(RELEASE_INPUTS=()))
        path = 'testing/conformance/capabilities.py'
        self.assertEqual(load(request)['conformance_inputs'][path], hashlib.sha256(files[path]).hexdigest())
        previous = load(request)['conformance_inputs']
        files[path] += b'-changed'
        self.assertNotEqual(load(request)['conformance_inputs'], previous)

    def test_authenticated_validator_keeps_same_revision_relative_helper(self):
        revision = 'a' * 40
        source = b'''import importlib.util
from pathlib import Path
root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fixture_publisher', root / 'scripts/publish-check-results.py')
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
'''
        files = {'ci/scripts/collect-native-results.py': source,
                 'scripts/publish-check-results.py': b'VALUE = 42\n'}
        reads = []

        def blob(repository, ref, path):
            self.assertEqual((repository, ref), ('BusbarInc/marketing', revision))
            reads.append(path)
            return files[path]

        api = API({'projects/BusbarInc%2Fmarketing': dict(id=52,
            path_with_namespace='BusbarInc/marketing', visibility='private'),
            'projects/52/protected_branches': [], 'groups/BusbarInc/protected_branches': [],
            'projects/52/repository/branches/dev': dict(protected=True, commit=dict(id=revision))}, {})
        api.request = api.json
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            runtime = OwnerRuntime.__new__(OwnerRuntime)
            runtime.reads = runtime.groups = api
            runtime.principals = {6, 8}
            runtime.session = Path(directory)
            runtime.ensure = lambda repository, ref: self.assertEqual(
                (repository, ref), ('BusbarInc/marketing', revision))
            runtime.objects = SimpleNamespace(blob=blob)
            with patch('admission.validate_protection'):
                module, origin = runtime.load_normalizer()
                self.assertEqual(module.publisher.VALUE, 42)
                self.assertEqual(set(reads), set(files))
                self.assertEqual(origin['files'], {path: hashlib.sha256(raw).hexdigest()
                                                  for path, raw in files.items()})
                del files['scripts/publish-check-results.py']
                with self.assertRaises(KeyError):
                    runtime.load_normalizer()


if __name__ == '__main__':
    unittest.main()

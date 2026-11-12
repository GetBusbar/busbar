"""Bounded selector regressions with real identities and canonical API fixtures."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import input_identity as identity
from qualification_selection import (execute_plan, plan_cohort, proof_context, launch_fresh,
                                     parse_args, incremental_plan, apply_incremental, canonical_observation)
from reuse_evidence import Resolver
from test_input_identity import Objects, CORE, OWNER, SOURCE, HOST, SDK, NEW, NOW, DATABASE
from test_reuse_evidence import API, archive


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class SelectionFixture:
    CORE_JOBS = ('native-qualification', 'security-scans', 'core-conformance')
    TIER = 'single'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='selection-tests-', dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.objects = Objects()
        self.objects.git = lambda *args: ('f' * 40).encode()
        self.names = [CORE, 'GetBusbar/busbar-release', OWNER] + [
            'GetBusbar/busbar-owner-' + str(index) for index in range(47)]
        core = self.objects.files[CORE, HOST]
        core['ci/architecture.toml'] = '[assembly]\nrepository="' + CORE + '"\n' + ''.join(
            '[repositories."' + name + '"]\n' +
            ('native={required_conformance=true}\n' if name == OWNER else '')
            for name in self.names if name != CORE)
        coverage = json.loads(core['conformance/ci-coverage.json'])
        coverage['suites']['owner']['command'] = 'bash testing/conformance/owner.sh'
        core['conformance/ci-coverage.json'] = json.dumps(coverage)
        core['scripts/architecture/test_cleanup.py'] = 'original standalone test'
        self.objects.files[CORE, NEW] = dict(core)
        self.objects.files[CORE, NEW]['scripts/architecture/test_cleanup.py'] = 'fixed standalone test'
        for name in self.names[1:]:
            self.objects.files[name, SOURCE] = dict(self.objects.files[OWNER, SOURCE])
        self.rows, self.originals, self.api_rows, self.raw = [], {}, {}, {}
        self.validations = []
        for index, name in enumerate(self.names):
            project, pipeline = index + 1, index + 100
            source = HOST if name == CORE else SOURCE
            self.rows.append(dict(repository=name, project=project, source=NEW if name == CORE else source,
                                 host=NEW, policy=NEW, sdk=SDK))
            from urllib.parse import quote
            self.api_rows['projects/' + quote(name, safe='')] = dict(id=project,
                path_with_namespace=name, visibility='private', merge_method='ff',
                ci_pipeline_variables_minimum_override_role='no_one_allowed',
                only_allow_merge_if_pipeline_succeeds=True, allow_merge_on_skipped_pipeline=False,
                ci_config_path='ci/architecture-pipeline.yml@GetBusbar/busbar:' + HOST)
            base = 'projects/' + str(project)
            self.api_rows[base + '/protected_branches'] = []
            self.api_rows['groups/GetBusbar/protected_branches'] = []
            for branch in ('dev', 'qa', 'main'):
                self.api_rows[base + '/repository/branches/' + branch] = dict(name=branch, protected=True)
            self.api_rows[base + '/repository/branches'] = [dict(name=branch, protected=True)
                                                           for branch in ('dev', 'qa', 'main')]
            self.api_rows[base + '/pipelines/' + str(pipeline)] = dict(id=pipeline, project_id=project,
                sha=source, ref='dev', source='api', status='success', user={'id': 6})
            jobs = list(self.CORE_JOBS) if name == CORE else ['native-qualification', 'security-scans']
            self.originals[name] = []
            job_rows = []
            for offset, jobname in enumerate(jobs):
                job_id = 1000 + index * 3 + offset
                request = dict(repository=name, source=source, host=HOST, policy=HOST, sdk=SDK, job=jobname)
                files, receipt = self.fixture(request, pipeline, job_id)
                receipt_bytes = identity.encoded(receipt)
                filename = 'security.json' if jobname == 'security-scans' else 'receipt.json'
                files[filename] = receipt_bytes
                job = dict(id=job_id, name=jobname, status='success', allow_failure=False,
                           pipeline={'id': pipeline}, commit={'id': source}, ref='dev', runner={'id': 7})
                self.api_rows[base + '/jobs/' + str(job_id)] = job
                self.raw[base + '/jobs/' + str(job_id) + '/artifacts'] = archive(files)
                self.raw[base + '/jobs/' + str(job_id) + '/artifacts/boundary-evidence/' + filename] = receipt_bytes
                self.raw[base + '/jobs/' + str(job_id) + '/trace'] = b'* branch ' + HOST.encode() + b' -> FETCH_HEAD'
                job_rows.append(job)
                self.originals[name].append(dict(request=request, project=project, pipeline=pipeline,
                                                job=job_id, receipt=receipt))
            self.api_rows[base + '/pipelines/' + str(pipeline) + '/jobs'] = job_rows
        self.api = API(self.api_rows, self.raw)
        self.resolver = Resolver(self.api, group_api=self.api, objects=self.objects,
            current_policy=HOST, merge_users={6}, owner_users={6}, scratch=self.temp.name,
            full_validator=self.validate, trusted_policies={HOST, NEW}, now=lambda: NOW)
        # Fixture policies are controller-owned byte fixtures, not proof data.
        # The separate resolver suite covers immutable policy subprocess loading.
        self.resolver._policy = self.policy
        witness = self.originals[OWNER][1]
        self.database = self.resolver.authenticate_database(witness['request'], witness['receipt'])

    def policy(self, request, *args):
        files = {path: digest(self.objects.blob(CORE, request['policy'], path))
                 for path in ('ci/architecture.toml', 'ci/security/tools.json', 'scripts/security/scan.py')}
        return dict(files=files, tools=json.loads(self.objects.blob(CORE, request['policy'],
            'ci/security/tools.json')), owner_suites=['owner'] if request['repository'] == OWNER else [],
            required_external='core-conformance' if request['repository'] == CORE else None,
            independent_job=True, tier=self.TIER)

    def fixture(self, request, pipeline, job):
        security = request['job'] == 'security-scans'
        receipt = dict(repository=request['repository'], source=request['source'],
            policy_revision=HOST, status='pass', pipeline_id=str(pipeline), job_id=str(job))
        if security:
            tools = json.loads(self.objects.blob(CORE, HOST, 'ci/security/tools.json'))
            receipt.update(schema='busbar.security-scans/1', database=DATABASE,
                policy_files={'tools.json': digest(self.objects.blob(CORE, HOST, 'ci/security/tools.json'))},
                source_tree='f' * 40,
                source_files_sha256=digest(identity.encoded([dict(path=path, mode=entry['mode'],
                    sha256=digest(self.objects.blob(request['repository'], request['source'], path)))
                    for path, entry in self.objects.tree(request['repository'], request['source']).items()])),
                steps=[dict(name=name, tool_image=tools['semgrep' if name == 'sast' else 'trivy'],
                    report_sha256=digest(b'{}'), stderr_sha256=digest(b'')) for name in ('sast', 'secret', 'dependency')])
            return {}, receipt
        suite = request['repository'] == OWNER and request['job'] == 'native-qualification'
        name = 'plugin-native-conformance' if suite else 'unit'
        receipt.update(schema='busbar.protected-native-admission/1' if request['job'] ==
            'native-qualification' else 'busbar.protected-conformance/1', target_revision=request['source'],
            host_revision=HOST, sdk_revision=SDK,
            policy_sha256=digest(self.objects.blob(CORE, HOST, 'ci/architecture.toml')),
            config_uri='github.com/' + request['repository'] +
            '//ci/architecture-pipeline.yml@GetBusbar/busbar:' + HOST + '@refs/heads/dev',
            required_conformance_suites=['owner'] if suite else [],
            steps=[dict(name=name, status='pass', exit_code=0,
                        stdout_sha256=digest(b'checked'), stderr_sha256=digest(b''))])
        files = {name + '.stdout': b'checked', name + '.stderr': b''}
        if suite:
            verdict = identity.encoded(dict(status='pass', armed=True))
            files['conformance/verdicts/owner.json'] = verdict
            files['conformance/invocation.json'] = identity.encoded(dict(verdicts={'owner.json': digest(verdict)}))
        return files, receipt

    def validate(self, original, receipt, artifact, context, policy):
        self.assertEqual(context['job']['id'], int(receipt['job_id']))
        self.assertEqual(artifact(receipt['steps'][0]['name'] + '.stdout'), b'checked')
        self.validations.append(original)
        return True

    def plan(self, rows=None):
        return plan_cohort(rows or self.rows, self.originals, self.objects, self.resolver,
                           self.temp.name, database=self.database, now=NOW)

    def runtime(self):
        return SimpleNamespace(rows=self.rows, originals=self.originals, objects=self.objects,
            resolver=self.resolver, database=self.database, session=Path(self.temp.name), live={},
            observe=lambda candidate: canonical_observation(self.resolver, candidate))


class Selection(SelectionFixture, unittest.TestCase):
    def test_maintained_cli_defaults_to_read_only_and_requires_deliberate_fleet_override(self):
        args = parse_args(['--work-dir', self.temp.name])
        self.assertFalse(args.apply)
        self.assertFalse(args.full_fleet)
        self.assertEqual(args.limit, 20)
        for options in (['--apply'], ['--full-fleet'], ['--full-fleet', '--reason', ''],
                        ['--limit', '21'], ['--factory', '/candidate/factory.py']):
            with self.subTest(options=options), patch('sys.stderr', new=io.StringIO()), self.assertRaises(SystemExit):
                parse_args(['--work-dir', self.temp.name, *options])
        explicit = parse_args(['--work-dir', self.temp.name, '--full-fleet', '--reason', 'Required policy migration'])
        self.assertTrue(explicit.full_fleet)

    def test_default_maintained_plan_reuses_49_and_cannot_post(self):
        runtime = self.runtime()
        # Use an authenticated fixture clock, as the real resolver supplies.
        real_datetime = __import__('datetime').datetime
        with patch('input_identity.dt.datetime') as clock:
            clock.now.return_value = NOW
            clock.fromisoformat.side_effect = real_datetime.fromisoformat
            planned = incremental_plan(runtime, self.rows)
        self.assertEqual([row['repository'] for row in planned if row['fresh_kinds']], [CORE])
        self.assertEqual(sum(row['state'] == 'retained' for row in planned), 49)
        apply_incremental(parse_args(['--work-dir', self.temp.name]), planned, runtime,
                          lambda: self.fail('read-only planning attempted a mutation save'))

    def test_live_same_source_pipeline_blocks_fresh_and_explicit_fleet_duplicates(self):
        runtime = self.runtime()
        runtime.live[CORE] = [dict(project=1, pipeline=9999, source=NEW, status='running',
                                   host=None, policy=None, sdk=None)]
        planned = incremental_plan(runtime, self.rows[:1], full_fleet=True)
        self.assertEqual(planned[0]['state'], 'pending')
        self.assertEqual(planned[0]['fresh_kinds'], [])
        for entry in planned[0]['qualifications'].values():
            self.assertEqual(entry['origin']['pipeline'], 9999)
            self.assertIsNone(entry['origin']['host'])
            self.assertEqual(entry['mode'], 'pending')

    def test_whole_fleet_apply_cannot_be_disguised_as_normal_affected_selection(self):
        runtime = self.runtime()
        planned = [dict(repository=row['repository'], state='selected', fresh_kinds=['native'])
                   for row in self.rows]
        args = SimpleNamespace(apply=True, full_fleet=False, launch_repository=self.names)
        with self.assertRaisesRegex(ValueError, 'whole-fleet launch requires'):
            apply_incremental(args, planned, runtime, lambda: self.fail('unexpected write'))

    def test_regression_only_fix_selects_one_of_fifty_and_persists_original_evidence(self):
        rows = self.plan()
        self.assertEqual([row['repository'] for row in rows if row['state'] == 'selected'], [CORE])
        self.assertEqual(sum(row['state'] == 'retained' for row in rows), 49)
        self.assertEqual(rows[0]['fresh_kinds'], ['native', 'security'])
        self.assertEqual(rows[0]['qualifications']['conformance']['mode'], 'retained')
        native = rows[2]['qualifications']['native']
        self.assertEqual(native['scope'], 'retained-check')
        self.assertEqual(native['origin']['host'], HOST)
        self.assertEqual(json.loads(Path(native['receipt_path']).read_bytes())['host_revision'], HOST)
        self.assertGreater(len(self.validations), 49)

    def test_running_original_is_pending_and_exact_post_set_is_core_only(self):
        row = self.rows[2]
        base = 'projects/3/pipelines/102'
        self.api_rows[base]['status'] = 'running'
        self.api_rows[base + '/jobs'][0]['status'] = 'running'
        rows = self.plan()
        self.assertEqual(rows[2]['state'], 'pending')
        posts = []
        def launch(selected):
            posts.append(selected['repository'])
            return dict(id=9999, sha=selected['source'], status='created')
        execute_plan(rows, launch, fresh_repositories=[CORE])
        self.assertEqual(posts, [CORE])
        self.assertNotIn('pipeline', rows[2])
        self.assertEqual(rows[0]['qualifications']['conformance']['origin']['pipeline'], 100)
        self.assertEqual(rows[0]['qualifications']['native']['pipeline'], 9999)
        self.assertNotEqual(row['source'], NEW)

    def test_unknown_stale_forged_or_missing_evidence_never_retains(self):
        row = self.rows[2]
        candidate = self.originals[OWNER][0]
        candidate['receipt']['status'] = 'invented pass'
        result = self.plan([row])[0]
        self.assertEqual(result['qualifications']['native']['mode'], 'fresh')
        self.database = dict(DATABASE, updated_at='2020-01-01T00:00:00Z')
        result = self.plan([row])[0]
        self.assertEqual(result['qualifications']['security']['mode'], 'fresh')
        self.originals[OWNER] = []
        self.assertEqual(self.plan([row])[0]['state'], 'selected')
        self.objects.files[CORE, NEW]['ci/architecture.toml'] = '[repositories]\n'
        with self.assertRaisesRegex(ValueError, 'unknown qualification owner'):
            self.plan([row])

    def test_saved_proof_is_reverified_not_accepted_as_a_success_flag(self):
        row = self.plan([self.rows[2]])[0]
        entry = row['qualifications']['native']
        context = proof_context(entry, self.resolver, self.objects, database=self.database, now=NOW)
        proof = context.pop('proof')
        context.pop('verifier')
        objects = context.pop('objects')
        proof['identity_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'claimed identity differs'):
            identity.verify_reuse(proof, proof['requested'], objects, **context)

    def test_plugin_change_selects_owner_and_assembly_but_component_cannot_cover_protocol(self):
        owner_row = self.rows[3]
        owner = owner_row['repository']
        self.objects.changed(owner, SOURCE, 'testing/fixture.py', 'changed fixture')
        owner_row['source'] = NEW
        self.objects.files[CORE, NEW]['scripts/ci-product-pins.json'] = json.dumps(
            dict(sdk=SDK, products=[dict(repository=owner, commit=NEW)]))
        self.objects.files[CORE, NEW]['dist/default/Cargo.lock'] = 'new assembly lock'
        rows = self.plan()
        selected = {row['repository'] for row in rows if row['state'] == 'selected'}
        self.assertEqual(selected, {CORE, OWNER, owner})
        self.assertEqual(rows[2]['qualifications']['native']['mode'], 'fresh')
        self.assertIn('protocol requirements', rows[2]['qualifications']['native']['reason'])
        self.assertEqual(rows[4]['qualifications']['native']['scope'], 'retained-component')

    def test_policy_contract_change_invalidates_affected_native_jobs(self):
        self.objects.files[CORE, NEW]['scripts/architecture/native.py'] = 'changed assertion'
        row = self.plan([self.rows[2]])[0]
        self.assertEqual(row['qualifications']['native']['mode'], 'fresh')
        self.assertEqual(row['qualifications']['security']['mode'], 'retained')

    def test_successful_independent_kind_survives_failed_parent(self):
        self.api_rows['projects/3/pipelines/102']['status'] = 'failed'
        self.api_rows['projects/3/pipelines/102/jobs'][1]['status'] = 'failed'
        row = self.plan([self.rows[2]])[0]
        self.assertEqual(row['qualifications']['native']['mode'], 'retained')
        self.assertEqual(row['qualifications']['security']['mode'], 'fresh')

    def test_wrong_explicit_launch_set_performs_zero_posts(self):
        rows = self.plan()
        calls = []
        with self.assertRaisesRegex(ValueError, 'explicit fresh repositories'):
            execute_plan(rows, calls.append, fresh_repositories=self.names)
        self.assertEqual(calls, [])

    def test_new_pipeline_without_jobs_is_pending_and_never_duplicate(self):
        row = self.rows[2]
        self.api_rows['projects/3/pipelines/102']['status'] = 'created'
        self.api_rows['projects/3/pipelines/102/jobs'] = []
        result = self.plan([row])[0]
        self.assertEqual(result['state'], 'pending')
        self.assertTrue(all(value['mode'] == 'pending' for value in result['qualifications'].values()))

    def test_actual_launcher_posts_only_planned_repository_and_never_cancels(self):
        rows = self.plan()
        mutations = []
        project = dict(self.api_rows['projects/GetBusbar%2Fbusbar'])
        class LaunchAPI:
            def request(inner, path, method='GET', body=None):
                if method != 'GET':
                    mutations.append((path, method, body))
                if path == 'projects/GetBusbar%2Fbusbar':
                    if method == 'PUT':
                        project.update(body)
                    return dict(project)
                if path == 'projects/GetBusbar%2Fbusbar/repository/branches/dev':
                    return dict(commit=dict(id=NEW), protected=True)
                if path == 'projects/GetBusbar%2Fbusbar/pipeline' and method == 'POST':
                    return dict(id=9000, sha=NEW, status='created')
                if path == 'projects/GetBusbar%2Fbusbar/pipelines?ref=dev&sha=' + NEW + '&per_page=20':
                    return []
                raise AssertionError('unexpected API call: ' + path)

            def all(inner, path):
                self.assertEqual(path, 'projects/GetBusbar%2Fbusbar/protected_branches')
                return ['unchanged-rules']
        with patch('admission.validate_protection') as protection:
            apply_incremental(SimpleNamespace(apply=True, full_fleet=False, launch_repository=[CORE]), rows,
                SimpleNamespace(api=LaunchAPI(), group_rules={'GetBusbar': []}, rows=self.rows), lambda: None)
        protection.assert_called_once_with(['unchanged-rules'], [], {6, 8})
        self.assertEqual([path for path, method, _ in mutations if method == 'POST'],
                         ['projects/GetBusbar%2Fbusbar/pipeline'])
        self.assertFalse(any('/cancel' in path for path, _, _ in mutations))
        self.assertEqual(project['merge_method'], 'ff')
        self.assertEqual(project['ci_pipeline_variables_minimum_override_role'], 'no_one_allowed')


TIERED_PIPELINE = (Path(__file__).resolve().parents[2] / 'ci/architecture-pipeline.yml').read_text()
BINARY, DEVELOPMENT = b'certified-binary', b'{"development": true}'


class TieredCoreSelection(SelectionFixture, unittest.TestCase):
    """Core's tiered policy: dev evidence is core-build + core-conformance of its bytes."""
    CORE_JOBS = ('core-build', 'core-conformance')
    TIER = 'tiered'

    def setUp(self):
        self.build_jobs = {}
        super().setUp()

    def fixture(self, request, pipeline, job):
        if request['repository'] != CORE:
            return super().fixture(request, pipeline, job)
        for revision in (HOST, NEW):
            self.objects.files[CORE, revision]['ci/architecture-pipeline.yml'] = TIERED_PIPELINE
        from admission import CORE_BUILD_STEPS
        from native_certified import BUILD
        files, receipt = super().fixture(dict(request, job='core-conformance'), pipeline, job)
        record = dict(sha256=digest(BINARY), bytes=len(BINARY), path='busbar', command=['cargo', *BUILD],
                      rustc_wrapper='clippy-driver', clippy_args=['-D', 'warnings'], profile_use=None,
                      development_artifact_receipt_sha256=digest(DEVELOPMENT))
        if request['job'] == 'core-build':
            self.build_jobs[pipeline] = job
            receipt.update(schema='busbar.core-build/1', certified_binary=record, binary_sha256=record['sha256'],
                development_artifact=dict(sha256=record['development_artifact_receipt_sha256']),
                steps=[dict(receipt['steps'][0], name=name) for name in CORE_BUILD_STEPS])
            files = {name + '.' + stream: (b'checked' if stream == 'stdout' else b'')
                     for name in CORE_BUILD_STEPS for stream in ('stdout', 'stderr')}
            files.update({'busbar': BINARY, 'development-artifact/receipt.json': DEVELOPMENT})
        else:
            receipt.update(binary_sha256=record['sha256'], certified_binary=dict(
                sha256=record['sha256'], bytes=len(BINARY), core_build_job_id=self.build_jobs[pipeline],
                pipeline_id=pipeline))
        return files, receipt

    def validate(self, original, receipt, artifact, context, policy):
        if original['job'] == 'core-build':
            from reuse_evidence import validate_core_build
            self.assertTrue(validate_core_build(original, receipt, artifact, context, policy))
        return super().validate(original, receipt, artifact, context, policy)

    def core_row(self, **inputs):
        return [dict(self.rows[0], **inputs)]

    def test_identical_inputs_retain_both_dev_tier_jobs_and_launch_nothing(self):
        row = self.plan(self.core_row(source=HOST, host=HOST, policy=HOST))[0]
        self.assertEqual(set(row['required']), {'build', 'conformance'})
        self.assertEqual(row['state'], 'retained')
        self.assertEqual(row['fresh_kinds'], [])
        for kind in ('build', 'conformance'):
            self.assertEqual(row['qualifications'][kind]['scope'], 'execution-equivalent')
            self.assertEqual(row['qualifications'][kind]['origin']['pipeline'], 100)

    def test_changed_source_rebuilds_the_certified_binary(self):
        # Only a regression test changed: conformance may be retained, the build never is.
        row = self.plan(self.core_row())[0]
        self.assertEqual(row['state'], 'selected')
        self.assertEqual(row['fresh_kinds'], ['build'])
        self.assertEqual(row['qualifications']['conformance']['scope'], 'retained-check')

    def test_forged_binary_or_conformance_of_other_bytes_is_never_retained(self):
        base = 'projects/1/jobs/'
        build, conformance = (self.originals[CORE][index]['job'] for index in (0, 1))
        members = dict(zipfile_members(self.raw[base + str(build) + '/artifacts']), busbar=b'other bytes')
        self.raw[base + str(build) + '/artifacts'] = archive(members)
        row = self.plan(self.core_row(source=HOST, host=HOST, policy=HOST))[0]
        self.assertEqual(row['qualifications']['build']['mode'], 'fresh')
        self.assertEqual(row['qualifications']['conformance']['mode'], 'retained')
        self.setUp()
        candidate = self.originals[CORE][1]
        candidate['receipt']['certified_binary']['sha256'] = '0' * 64
        receipt_bytes = identity.encoded(candidate['receipt'])
        members = dict(zipfile_members(self.raw[base + str(conformance) + '/artifacts']),
                       **{'receipt.json': receipt_bytes})
        self.raw[base + str(conformance) + '/artifacts'] = archive(members)
        self.raw[base + str(conformance) + '/artifacts/boundary-evidence/receipt.json'] = receipt_bytes
        row = self.plan(self.core_row(source=HOST, host=HOST, policy=HOST))[0]
        self.assertEqual(row['qualifications']['build']['mode'], 'retained')
        self.assertEqual(row['qualifications']['conformance']['mode'], 'fresh')
        self.assertIn('certified core-build', row['qualifications']['conformance']['reason'])

    def test_qa_tier_jobs_are_not_dev_requirements(self):
        row = self.plan(self.core_row(source=HOST, host=HOST, policy=HOST))[0]
        self.assertNotIn('native', row['required'])
        self.assertNotIn('security', row['required'])


def zipfile_members(raw):
    import zipfile
    with zipfile.ZipFile(io.BytesIO(raw)) as source:
        return {name.removeprefix('boundary-evidence/'): source.read(name) for name in source.namelist()}


if __name__ == '__main__':
    unittest.main()

"""Bounded selector regressions with real identities and canonical API fixtures."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import input_identity as identity
from qualification_selection import execute_plan, plan_cohort, proof_context, launch_fresh
from reuse_evidence import Resolver
from test_input_identity import Objects, CORE, OWNER, SOURCE, HOST, SDK, NEW, NOW, DATABASE
from test_reuse_evidence import API, archive


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Selection(unittest.TestCase):
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
            jobs = ['native-qualification', 'security-scans'] + (['core-conformance'] if name == CORE else [])
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
            independent_job=True)

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
                raise AssertionError('unexpected API call: ' + path)

            def all(inner, path):
                self.assertEqual(path, 'projects/GetBusbar%2Fbusbar/protected_branches')
                return ['unchanged-rules']
        with patch('admission.validate_protection') as protection:
            execute_plan(rows, lambda row: launch_fresh(LaunchAPI(), {'GetBusbar': []}, row),
                         fresh_repositories=[CORE])
        protection.assert_called_once_with(['unchanged-rules'], [], {6, 8})
        self.assertEqual([path for path, method, _ in mutations if method == 'POST'],
                         ['projects/GetBusbar%2Fbusbar/pipeline'])
        self.assertFalse(any('/cancel' in path for path, _, _ in mutations))
        self.assertEqual(project['merge_method'], 'ff')
        self.assertEqual(project['ci_pipeline_variables_minimum_override_role'], 'no_one_allowed')


if __name__ == '__main__':
    unittest.main()

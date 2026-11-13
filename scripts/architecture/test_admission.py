"""Admission regression cases: successful current native proof is mandatory."""
import copy
import base64
import json
import unittest
from unittest.mock import patch

import admission
from admission import (CORE_BUILD_STEPS, CORE_CLIPPY_SCHEMA, CORE_CLIPPY_STEPS, CORE_TEST_SCHEMA, CORE_TEST_STEPS, expected_inputs, required_conformance_job, validate_merge,
                       validate_protection)

# Native admission (plugins and the release generator). Its conformance branch is
# exercised through a plugin that declares a same-pipeline external judge.
PLUGIN = 'GetBusbar/busbar-store-memory'
REAL_REQUIRED = admission.required_conformance_job


class Admission(unittest.TestCase):
    def setUp(self):
        self.revision, self.source, self.target = 'a' * 40, 'b' * 40, 'c' * 40
        self.host, self.sdk = 'e' * 40, 'd' * 40
        required = patch('admission.required_conformance_job', side_effect=lambda repository, policy=None:
                         'core-conformance' if repository == PLUGIN else REAL_REQUIRED(repository, policy))
        required.start()
        self.addCleanup(required.stop)
        self.project = dict(id=3, path_with_namespace=PLUGIN,
            ci_config_path='ci/architecture-pipeline.yml@GetBusbar/busbar:' + self.revision,
            merge_method='ff', only_allow_merge_if_pipeline_succeeds=True, allow_merge_on_skipped_pipeline=False)
        self.mr = dict(source_project_id=3, target_project_id=3, target_branch='dev', sha=self.source)
        self.pipeline = dict(id=100, project_id=3, source='merge_request_event', sha=self.source, status='success')
        self.jobs = [dict(id=101, name='native-qualification', status='success', allow_failure=False, runner={'id': 9})]
        self.receipt = dict(status='pass', repository=PLUGIN, source=self.source,
            policy_revision=self.revision, pipeline_id='100', job_id='101', target_revision=self.target,
            host_revision=self.host, sdk_revision=self.sdk,
            steps=[dict(name='architecture', status='pass', exit_code=0)])
        self.jobs.append(dict(self.jobs[0], id=102, name='core-conformance'))
        self.conformance = dict(copy.deepcopy(self.receipt), job_id='102', schema='busbar.protected-conformance/1')
        self.jobs.append(dict(self.jobs[0], id=103, name='security-scans'))
        self.security = dict(schema='busbar.security-scans/1', status='pass',
            repository=PLUGIN, source=self.source, policy_revision=self.revision,
            pipeline_id='100', job_id='103', steps=[dict(name=name, status='pass', exit_code=0, findings=0)
                for name in ('secrets', 'dependencies', 'sast')])

    def validate(self):
        validate_merge(self.project, self.mr, self.pipeline, self.jobs, self.receipt, self.revision, self.target, self.host, self.sdk,
                       self.conformance, self.security)

    def test_security_cannot_be_omitted_forged_or_reused(self):
        good = copy.deepcopy(self.security)
        for key in ('source', 'policy_revision', 'pipeline_id', 'job_id', 'schema'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.security = dict(good, **{key: 'wrong'})
                self.validate()
        self.security = good
        for broken in ([], good['steps'][:2], [dict(good['steps'][0], findings=1), *good['steps'][1:]]):
            with self.subTest(steps=broken), self.assertRaises(ValueError):
                self.security = dict(good, steps=broken)
                self.validate()

    def test_current_native_proof_admits(self):
        self.validate()

    def test_missing_or_optional_conformance_never_admits(self):
        good = copy.deepcopy(self.jobs)
        for jobs in ([good[0], good[2]], good + [good[1]], [good[0], dict(good[1], runner=None), good[2]],
                     [good[0], dict(good[1], allow_failure=True), good[2]]):
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                self.jobs = jobs
                self.validate()

    def test_nonpassing_jobs_cannot_hide_behind_successful_pipeline(self):
        good = copy.deepcopy(self.jobs)
        for status in ('failed', 'skipped', 'manual', 'canceled', 'pending', 'running'):
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.jobs = [good[0], dict(good[1], status=status), good[2]]
                self.validate()

    def test_conformance_receipt_must_bind_every_input_and_contain_only_passing_steps(self):
        good = copy.deepcopy(self.conformance)
        for key in ('source', 'target_revision', 'host_revision', 'sdk_revision', 'policy_revision',
                    'pipeline_id', 'job_id', 'repository', 'schema', 'status'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.conformance = dict(good, **{key: 'stale'})
                self.validate()
        for receipt in (None, dict(good, steps=[]), dict(good, steps=[dict(status='not-run', exit_code=0)]),
                        dict(good, steps=[dict(status='pass', exit_code=1)])):
            with self.subTest(receipt=receipt), self.assertRaises(ValueError):
                self.conformance = receipt
                self.validate()

    def test_owner_conformance_is_required_inside_native_job_for_both_planes(self):
        from native_policy import conformance_rows
        for repository in ('GetBusbar/busbar-plane-llm', 'GetBusbar/busbar-plane-decisions'):
            with self.subTest(repository=repository):
                self.assertIsNone(required_conformance_job(repository))
                self.project['path_with_namespace'] = repository
                self.receipt['repository'] = repository
                self.security['repository'] = repository
                self.jobs = [job for job in self.jobs if job['name'] != 'core-conformance']
                self.conformance = None
                self.receipt['steps'] = [dict(name='plugin-native-conformance', status='pass', exit_code=0)]
                self.receipt['required_conformance_suites'] = sorted(conformance_rows(repository))
                self.validate()
                self.receipt['required_conformance_suites'] = []
                with self.assertRaisesRegex(ValueError, 'omits required owner conformance'):
                    self.validate()
                self.receipt['required_conformance_suites'] = sorted(conformance_rows(repository))
                self.receipt['steps'] = [dict(name='architecture', status='pass', exit_code=0)]
                with self.assertRaisesRegex(ValueError, 'omits required owner conformance'):
                    self.validate()
        self.assertIsNone(required_conformance_job('GetBusbar/busbar-store-memory'))

    def test_nonpassing_pipeline_never_admits(self):
        for status in ('pending', 'running', 'skipped', 'failed', 'canceled', 'manual'):
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.pipeline['status'] = status
                self.validate()

    def test_missing_or_external_native_job_never_admits(self):
        good = copy.deepcopy(self.jobs)
        for jobs in ([], [dict(good[0], runner=None)], [dict(good[0], allow_failure=True)],
                     [dict(good[0], status='skipped')], good * 2):
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                self.jobs = jobs
                self.validate()

    def test_source_target_policy_and_receipt_must_match(self):
        for key in ('source', 'target_revision', 'host_revision', 'sdk_revision', 'policy_revision', 'pipeline_id', 'job_id', 'repository'):
            with self.subTest(key=key):
                old = self.receipt[key]
                self.receipt[key] = 'stale'
                with self.assertRaises(ValueError):
                    self.validate()
                self.receipt[key] = old

    def test_fork_or_branch_pipeline_cannot_replace_current_mr(self):
        self.mr['source_project_id'] = 99
        with self.assertRaises(ValueError):
            self.validate()
        self.mr['source_project_id'] = 3
        for source in ('push', 'api'):
            self.pipeline['source'] = source
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.validate()

    def test_changed_server_gate_or_missing_checks_refuse(self):
        self.project['allow_merge_on_skipped_pipeline'] = True
        with self.assertRaises(ValueError):
            self.validate()
        self.project['allow_merge_on_skipped_pipeline'] = False
        self.receipt['steps'] = []
        with self.assertRaises(ValueError):
            self.validate()

    def test_expected_inputs_use_core_source_or_owner_cohort_and_that_hosts_vector(self):
        from unittest.mock import Mock
        api = Mock()
        vector = {'content': base64.b64encode(json.dumps({'sdk': self.sdk}).encode()).decode()}
        api.request.return_value = vector
        core = dict(self.project, path_with_namespace='GetBusbar/busbar')
        self.assertEqual(expected_inputs(api, core, self.source), (self.source, self.sdk))
        api.all.assert_not_called()
        self.assertIn('?ref=' + self.source, api.request.call_args.args[0])
        project = dict(self.project, path_with_namespace='GetBusbar/busbar-auth-header')
        for variables, ref in [([], 'dev'), ([{'key': 'BUSBAR_ADMISSION_CORE_REVISION', 'value': self.host}], self.host)]:
            api.reset_mock()
            api.all.return_value = variables
            api.request.side_effect = [{'id': self.host}, vector]
            self.assertEqual(expected_inputs(api, project, self.source), (self.host, self.sdk))
            self.assertTrue(api.request.call_args_list[0].args[0].endswith('/commits/' + ref))
            self.assertTrue(api.request.call_args_list[1].args[0].endswith('?ref=' + self.host))


class CoreDevTierAdmission(unittest.TestCase):
    """Core MRs to dev are admitted on core-build + core-conformance of the MR pipeline."""

    def setUp(self):
        from native_certified import BUILD
        self.revision, self.source, self.target, self.sdk = 'a' * 40, 'b' * 40, 'c' * 40, 'd' * 40
        self.host = self.source
        self.digest = '5' * 64
        self.project = dict(id=3, path_with_namespace='GetBusbar/busbar',
            ci_config_path='ci/architecture-pipeline.yml@GetBusbar/busbar:' + self.revision,
            merge_method='ff', only_allow_merge_if_pipeline_succeeds=True, allow_merge_on_skipped_pipeline=False)
        self.mr = dict(source_project_id=3, target_project_id=3, target_branch='dev', sha=self.source)
        self.pipeline = dict(id=100, project_id=3, source='merge_request_event', sha=self.source, status='success')
        self.jobs = [dict(id=101, name='core-build', status='success', allow_failure=False, runner={'id': 9}),
                     dict(id=102, name='core-conformance', status='success', allow_failure=False, runner={'id': 9}),
                     dict(id=103, name='core-clippy', status='success', allow_failure=False, runner={'id': 9}),
                     dict(id=104, name='core-test', status='success', allow_failure=False, runner={'id': 9})]
        identity = dict(status='pass', repository='GetBusbar/busbar', source=self.source,
                        policy_revision=self.revision, pipeline_id='100', target_revision=self.target,
                        host_revision=self.host, sdk_revision=self.sdk)
        self.build = dict(identity, schema='busbar.core-build/1', job_id='101', binary_sha256=self.digest,
            certified_binary=dict(sha256=self.digest, bytes=4096, path='busbar', command=['cargo', *BUILD],
                                  rustc_wrapper='', clippy_args=[]),
            steps=[dict(name=name, status='pass', exit_code=0) for name in CORE_BUILD_STEPS])
        self.conformance = dict(identity, schema='busbar.protected-conformance/1', job_id='102',
            binary_sha256=self.digest,
            certified_binary=dict(sha256=self.digest, bytes=4096, core_build_job_id=101, pipeline_id=100),
            steps=[dict(name='core-native-conformance', status='pass', exit_code=0)])
        self.clippy = dict(identity, schema=CORE_CLIPPY_SCHEMA, job_id='103',
            steps=[dict(name=name, status='pass', exit_code=0) for name in CORE_CLIPPY_STEPS])
        self.tests = dict(identity, schema=CORE_TEST_SCHEMA, job_id='104',
            steps=[dict(name=name, status='pass', exit_code=0) for name in CORE_TEST_STEPS])

    def validate(self):
        validate_merge(self.project, self.mr, self.pipeline, self.jobs, self.build, self.revision,
                       self.target, self.host, self.sdk, self.conformance, clippy_receipt=self.clippy,
                       test_receipt=self.tests)

    def test_workspace_tests_are_their_own_required_job(self):
        good = copy.deepcopy(self.tests)
        for change in (dict(schema=CORE_CLIPPY_SCHEMA), dict(job_id='103'), dict(status='fail'),
                       dict(source='e' * 40), dict(pipeline_id='99'), dict(sdk_revision='e' * 40),
                       dict(steps=[step for step in good['steps'] if step['name'] != 'root-runtime']),
                       dict(steps=[step for step in good['steps'] if step['name'] != 'workspace-doctests']),
                       dict(steps=[*good['steps'], good['steps'][0]]),
                       dict(steps=[dict(good['steps'][0], status='fail', exit_code=100), *good['steps'][1:]])):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.tests = dict(good, **change)
                self.validate()
        self.tests = None
        with self.assertRaisesRegex(ValueError, 'core-test receipt is missing'):
            self.validate()
        self.tests = good
        self.jobs = [job for job in self.jobs if job['name'] != 'core-test']
        with self.assertRaisesRegex(ValueError, 'core-test'):
            self.validate()

    def test_lints_are_their_own_required_job(self):
        good = copy.deepcopy(self.clippy)
        for change in (dict(schema='busbar.core-build/1'), dict(job_id='101'), dict(status='fail'),
                       dict(steps=good['steps'][:1]),
                       dict(steps=[dict(good['steps'][0], status='fail', exit_code=101), good['steps'][1]])):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.clippy = dict(good, **change)
                self.validate()
        self.clippy = None
        with self.assertRaisesRegex(ValueError, 'core-clippy receipt is missing'):
            self.validate()
        self.clippy = good
        self.jobs = self.jobs[:2]
        with self.assertRaisesRegex(ValueError, 'core-clippy'):
            self.validate()

    def test_merge_reads_every_dev_tier_receipt_of_the_pipeline(self):
        from admission import core_dev_receipts

        class Api:
            def request(self, path):
                return {'path': path}
        receipts = core_dev_receipts(Api(), 'projects/3', self.jobs)
        self.assertEqual([receipt['path'] for receipt in receipts],
                         ['projects/3/jobs/%d/artifacts/boundary-evidence/receipt.json' % job
                          for job in (101, 102, 103, 104)])
        for jobs in ([job for job in self.jobs if job['name'] != 'core-test'],
                     [dict(job, status='failed') if job['name'] == 'core-test' else job for job in self.jobs]):
            with self.subTest(jobs=jobs), self.assertRaisesRegex(ValueError, 'core-test'):
                core_dev_receipts(Api(), 'projects/3', jobs)

    def test_a_clippy_driver_build_is_not_the_certified_binary(self):
        self.build['certified_binary']['rustc_wrapper'] = 'clippy-driver'
        with self.assertRaisesRegex(Exception, 'plain release build'):
            self.validate()

    def test_matching_dev_tier_receipts_admit_without_qa_tier_jobs(self):
        self.validate()

    def test_conformance_of_other_bytes_or_another_build_never_admits(self):
        good = copy.deepcopy(self.conformance)
        for change in (dict(binary_sha256='6' * 64),
                       dict(certified_binary=dict(good['certified_binary'], sha256='6' * 64)),
                       dict(binary_sha256='6' * 64, certified_binary=dict(good['certified_binary'], sha256='6' * 64)),
                       dict(certified_binary=dict(good['certified_binary'], bytes=4097)),
                       dict(certified_binary=dict(good['certified_binary'], core_build_job_id=99)),
                       dict(certified_binary=dict(good['certified_binary'], pipeline_id=99)),
                       dict(certified_binary=None)):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'certified core-build binary'):
                self.conformance = dict(good, **change)
                self.validate()

    def test_build_must_certify_its_binary(self):
        good = copy.deepcopy(self.build)
        for change in (dict(binary_sha256='6' * 64), dict(certified_binary=None),
                       dict(certified_binary=dict(good['certified_binary'], command=['cargo', 'build'])),
                       dict(certified_binary=dict(good['certified_binary'], sha256='short'))):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.build = dict(good, **change)
                self.validate()

    def test_missing_failed_or_ambiguous_receipts_and_jobs_never_admit(self):
        for receipts in ((None, self.conformance), (self.build, None)):
            with self.subTest(receipts=receipts), self.assertRaisesRegex(ValueError, 'receipt is missing'):
                self.build, self.conformance = (copy.deepcopy(r) for r in receipts)
                self.validate()
        self.setUp()
        good = copy.deepcopy(self.jobs)
        for jobs in ([good[0]], [good[1]], good + [good[0]], good + [good[1]],
                     [good[0], dict(good[1], runner=None)], [dict(good[0], runner=None), good[1]]):
            with self.subTest(jobs=jobs), self.assertRaisesRegex(ValueError, 'dev-tier job'):
                self.jobs = jobs
                self.validate()
        for index in (0, 1):
            for change in (dict(status='failed'), dict(status='skipped'), dict(allow_failure=True)):
                with self.subTest(index=index, change=change), self.assertRaises(ValueError):
                    self.jobs = copy.deepcopy(good)
                    self.jobs[index].update(change)
                    self.validate()

    def test_failed_or_incomplete_checks_never_admit(self):
        for receipt in ('build', 'conformance'):
            good = copy.deepcopy(getattr(self, receipt))
            for steps in ([], [dict(name='root-fmt', status='fail', exit_code=1)],
                          [*good['steps'][:-1], dict(good['steps'][-1], exit_code=101)]):
                with self.subTest(receipt=receipt, steps=steps), self.assertRaises(ValueError):
                    setattr(self, receipt, dict(good, steps=steps))
                    self.validate()
            with self.subTest(receipt=receipt, status='fail'), self.assertRaises(ValueError):
                setattr(self, receipt, dict(good, status='fail'))
                self.validate()
            setattr(self, receipt, good)
        for name in CORE_BUILD_STEPS:
            with self.subTest(omitted=name), self.assertRaisesRegex(ValueError, 'omits required checks'):
                self.build['steps'] = [dict(name=other, status='pass', exit_code=0)
                                       for other in CORE_BUILD_STEPS if other != name]
                self.validate()

    def test_receipts_from_another_pipeline_source_policy_or_target_never_admit(self):
        for receipt in ('build', 'conformance', 'clippy', 'tests'):
            good = copy.deepcopy(getattr(self, receipt))
            for key in ('source', 'policy_revision', 'pipeline_id', 'job_id', 'repository', 'schema',
                        'target_revision', 'host_revision', 'sdk_revision'):
                with self.subTest(receipt=receipt, key=key), self.assertRaises(ValueError):
                    setattr(self, receipt, dict(good, **{key: 'stale'}))
                    self.validate()
            setattr(self, receipt, good)

    def test_not_rebased_on_current_dev_never_admits(self):
        # Both jobs record the dev head they verified as an ancestor; dev has since moved.
        with self.assertRaisesRegex(ValueError, 'target_revision'):
            validate_merge(self.project, self.mr, self.pipeline, self.jobs, self.build, self.revision,
                           'f' * 40, self.host, self.sdk, self.conformance, clippy_receipt=self.clippy,
                           test_receipt=self.tests)

    def test_same_project_dev_mr_pipeline_and_server_gates_still_apply(self):
        for target, change in ((self.mr, dict(source_project_id=99)), (self.mr, dict(target_project_id=99)),
                               (self.mr, dict(target_branch='qa')), (self.pipeline, dict(source='push')),
                               (self.pipeline, dict(source='api')), (self.pipeline, dict(sha='f' * 40)),
                               (self.pipeline, dict(status='failed')), (self.pipeline, dict(project_id=99)),
                               (self.project, dict(allow_merge_on_skipped_pipeline=True)),
                               (self.project, dict(ci_config_path='ci/architecture-pipeline.yml@x:y'))):
            saved = copy.deepcopy(target)
            target.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate()
            target.clear()
            target.update(saved)
        self.validate()

    def test_step_names_follow_the_core_build_job(self):
        import native
        self.assertEqual(set(CORE_BUILD_STEPS), {'root-fmt', 'default-fmt', 'certified-build',
                         'development-artifact-evidence', *(name for name, _, _ in native.CORE_POLICY_COMMANDS)})
        self.assertEqual(CORE_CLIPPY_STEPS, tuple(name for name, _ in native.CORE_CLIPPY_COMMANDS))
        self.assertEqual(CORE_TEST_STEPS, tuple(name for name, _ in native.core_test_commands([])))

    def test_plugins_still_require_native_and_security(self):
        self.project['path_with_namespace'] = 'GetBusbar/busbar-store-memory'
        with self.assertRaisesRegex(ValueError, 'security'):
            self.validate()


class Protection(unittest.TestCase):
    def setUp(self):
        self.rules = [dict(name=branch, allow_force_push=False,
            push_access_levels=[dict(access_level=0)], merge_access_levels=[dict(access_level=40, user_id=8)])
            for branch in ('dev', 'qa', 'main')]

    def test_controlled_merge_and_no_push(self):
        validate_protection(self.rules, [], {8})

    def test_approved_operator_may_push_dev_but_never_stage_branches(self):
        self.rules[0]['push_access_levels'] = [dict(access_level=40, user_id=8)]
        validate_protection(self.rules, [], {8})
        for stage in self.rules[1:]:
            stage['push_access_levels'] = [dict(access_level=40, user_id=8)]
            with self.subTest(stage=stage['name']), self.assertRaisesRegex(ValueError, 'direct-push'):
                validate_protection(self.rules, [], {8})
            stage['push_access_levels'] = [dict(access_level=0)]

    def test_dev_does_not_allow_unknown_principals_or_wildcard_stage_access(self):
        self.rules[0]['push_access_levels'] = [dict(access_level=40, user_id=99)]
        with self.assertRaisesRegex(ValueError, 'direct-push'):
            validate_protection(self.rules, [], {8})
        self.rules[0]['push_access_levels'] = [dict(access_level=0)]
        group = dict(name='*', push_access_levels=[dict(access_level=40, user_id=8)], merge_access_levels=[])
        with self.assertRaisesRegex(ValueError, 'direct-push'):
            validate_protection(self.rules, [group], {8})

    def test_group_wildcard_overrides_stricter_project_rule(self):
        group = dict(name='d*', push_access_levels=[dict(access_level=40)], merge_access_levels=[])
        with self.assertRaisesRegex(ValueError, 'direct-push'):
            validate_protection(self.rules, [group], {8})

    def test_missing_rule_force_push_and_deploy_key_fail(self):
        with self.assertRaisesRegex(ValueError, 'unprotected'):
            validate_protection(self.rules[:2], [], {8})
        self.rules[0]['allow_force_push'] = True
        with self.assertRaisesRegex(ValueError, 'force-push'):
            validate_protection(self.rules, [], {8})
        self.rules[0]['allow_force_push'] = False
        self.rules[0]['push_access_levels'] = [dict(access_level=0, deploy_key_id=42)]
        with self.assertRaisesRegex(ValueError, 'direct-push'):
            validate_protection(self.rules, [], {8})

    def test_role_or_unapproved_user_cannot_merge(self):
        for access in (dict(access_level=40), dict(access_level=40, user_id=9), dict(access_level=40, group_id=2)):
            self.rules[0]['merge_access_levels'] = [access]
            with self.subTest(access=access), self.assertRaises(ValueError):
                validate_protection(self.rules, [], {8})


if __name__ == '__main__':
    unittest.main()

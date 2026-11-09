"""Admission regression cases: successful current native proof is mandatory."""
import copy
import base64
import json
import unittest

from admission import expected_inputs, validate_merge, validate_protection


class Admission(unittest.TestCase):
    def setUp(self):
        self.revision, self.source, self.target = 'a' * 40, 'b' * 40, 'c' * 40
        self.host, self.sdk = self.source, 'd' * 40
        self.project = dict(id=3, path_with_namespace='GetBusbar/busbar',
            ci_config_path='ci/architecture-pipeline.yml@GetBusbar/busbar:' + self.revision,
            merge_method='ff', only_allow_merge_if_pipeline_succeeds=True, allow_merge_on_skipped_pipeline=False)
        self.mr = dict(source_project_id=3, target_project_id=3, target_branch='dev', sha=self.source)
        self.pipeline = dict(id=100, project_id=3, source='merge_request_event', sha=self.source, status='success')
        self.jobs = [dict(id=101, name='native-qualification', status='success', allow_failure=False, runner={'id': 9})]
        self.receipt = dict(status='pass', repository='GetBusbar/busbar', source=self.source,
            policy_revision=self.revision, pipeline_id='100', job_id='101', target_revision=self.target,
            host_revision=self.host, sdk_revision=self.sdk,
            steps=[dict(name='architecture', status='pass', exit_code=0)])

    def validate(self):
        validate_merge(self.project, self.mr, self.pipeline, self.jobs, self.receipt, self.revision, self.target, self.host, self.sdk)

    def test_current_native_proof_admits(self):
        self.validate()

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
        self.pipeline['source'] = 'push'
        with self.assertRaises(ValueError):
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
        self.assertEqual(expected_inputs(api, self.project, self.source), (self.source, self.sdk))
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


class Protection(unittest.TestCase):
    def setUp(self):
        self.rules = [dict(name=branch, allow_force_push=False,
            push_access_levels=[dict(access_level=0)], merge_access_levels=[dict(access_level=40, user_id=8)])
            for branch in ('dev', 'qa', 'main')]

    def test_controlled_merge_and_no_push(self):
        validate_protection(self.rules, [], {8})

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

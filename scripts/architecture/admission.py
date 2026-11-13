#!/usr/bin/env python3
"""Owner-side protected admission. Never install this credential in candidate CI.

Approved operators may push development checkpoints directly to dev. QA/main reject
all direct pushes, and force pushes remain disabled everywhere. Qualified merges
still require successful pipelines and fast-forward history.
This controller additionally admits only the trusted native job for the exact source,
target, host, SDK and policy revision. Fork/external-status pipelines cannot impersonate it.

Core is admitted to dev on its DEV-tier receipts: the core-build job (fmt, deny/vet and
the one plain certified release build), the lint-only core-clippy job, the core-test
job (root workspace doctests and nextest run), and the core-conformance job that judged
exactly that binary by sha256, all from the current MR pipeline. Native qualification and security
are core's QA tier and are not dev admission inputs. Plugins keep native + security.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from check import read


class GitLab:
    def __init__(self, server, *, token=None):
        parsed = urllib.parse.urlsplit(server)
        if parsed.scheme != 'https' or parsed.path not in ('', '/'):
            raise ValueError('an HTTPS GitLab origin is required')
        self.server = server.rstrip('/')
        if token is not None:
            self.token = token
            return
        result = subprocess.run(['git', 'credential', 'fill'], input=f'protocol=https\nhost={parsed.netloc}\n\n',
                                text=True, capture_output=True, check=True)
        fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        self.token = fields['password']

    def request(self, path, method='GET', data=None):
        headers = {'PRIVATE-TOKEN': self.token}
        body = None
        if data is not None:
            headers['Content-Type'] = 'application/json'
            body = json.dumps(data).encode()
        request = urllib.request.Request(self.server + '/api/v4/' + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = response.read()
                return json.loads(payload) if payload else None
        except urllib.error.HTTPError as error:
            # Do not echo credentials, variable values, or a full API response.
            raise RuntimeError(f'{method} {path}: HTTP {error.code}') from None

    def all(self, path):
        result, page = [], 1
        while True:
            rows = self.request(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
            if not isinstance(rows, list):
                raise ValueError('paginated API did not return a list: ' + path)
            result.extend(rows)
            if len(rows) < 100:
                return result
            page += 1


def group_protection_reader(operator, keychain_service):
    """Use the separately authorized read credential only for group protection lookup."""
    if not keychain_service:
        return operator
    result = subprocess.run(['security', 'find-generic-password', '-s', keychain_service, '-w'],
                            text=True, capture_output=True, check=False)
    if result.returncode or not result.stdout.strip():
        raise RuntimeError('group-protection read credential could not be loaded')
    return GitLab(operator.server, token=result.stdout.strip())


def encoded(value):
    return urllib.parse.quote(str(value), safe='')


def matches(pattern, branch):
    # GitLab protected-branch names support '*', not shell '?' or character classes.
    return re.fullmatch(re.escape(pattern).replace(r'\*', '.*'), branch) is not None


def validate_protection(project_rules, group_rules, merge_users, *, branches=('dev', 'qa', 'main')):
    """GitLab combines matching rules permissively: examine every matching rule."""
    for branch in branches:
        rules = [row for row in [*project_rules, *group_rules] if matches(row['name'], branch)]
        if not rules:
            raise ValueError('unprotected branch: ' + branch)
        merge_allowed = False
        for rule in rules:
            if rule.get('allow_force_push'):
                raise ValueError('force-push allowance: ' + rule['name'])
            for row in rule['push_access_levels']:
                controlled_dev_push = (branch == 'dev' and row.get('user_id') in merge_users
                                       and not row.get('group_id') and not row.get('deploy_key_id'))
                if not controlled_dev_push and (row.get('access_level', 0) or any(
                        row.get(key) for key in ('user_id', 'group_id', 'deploy_key_id'))):
                    raise ValueError('direct-push allowance: ' + rule['name'])
            for row in rule['merge_access_levels']:
                if row.get('group_id') or row.get('deploy_key_id'):
                    raise ValueError('uncontrolled merge principal: ' + rule['name'])
                if row.get('user_id'):
                    if row['user_id'] not in merge_users:
                        raise ValueError('uncontrolled merge user: ' + rule['name'])
                    merge_allowed = True
                elif row.get('access_level', 0):
                    raise ValueError('role-wide merge allowance: ' + rule['name'])
        if not merge_allowed:
            raise ValueError('no controlled admission user can merge: ' + branch)


def configure_ci_read_access(api, project):
    """Allow the two canonical organizations to fetch inputs with bounded job tokens."""
    identity = 'projects/' + str(project['id'])
    approved = ('GetBusbar', 'BusbarInc')
    if project['path_with_namespace'].split('/')[0] not in approved:
        raise ValueError('CI input project is outside the canonical organizations')
    groups = []
    for name in approved:
        group = api.request('groups/' + encoded(name))
        if group.get('full_path') != name or type(group.get('id')) is not int:
            raise ValueError('canonical CI reader group identity mismatch')
        groups.append(group['id'])
    scope = identity + '/job_token_scope'
    if not api.request(scope).get('inbound_enabled'):
        api.request(scope, 'PATCH', {'enabled': True})
    existing = {row['id'] for row in api.all(scope + '/groups_allowlist')}
    for group_id in groups:
        if group_id not in existing:
            api.request(scope + '/groups_allowlist', 'POST', {'target_group_id': group_id})
    actual = api.all(scope + '/groups_allowlist')
    if (not api.request(scope).get('inbound_enabled')
            or not set(groups).issubset({row['id'] for row in actual})):
        raise RuntimeError('restricted canonical CI read access did not hold')
    return actual


def apply_project(api, project, policy_revision, merge_users, stage_owner=None):
    identity = 'projects/' + str(project['id'])
    expected = 'ci/architecture-pipeline.yml@GetBusbar/busbar:' + policy_revision
    settings = dict(ci_config_path=expected, merge_method='ff', only_allow_merge_if_pipeline_succeeds=True,
        allow_merge_on_skipped_pipeline=False, ci_pipeline_variables_minimum_override_role='no_one_allowed',
        ci_push_repository_for_job_token_allowed=False, remove_source_branch_after_merge=True)
    api.request(identity, 'PUT', settings)
    rules = api.all(identity + '/protected_branches')
    for branch in ('dev', 'qa', 'main'):
        rule = next((r for r in rules if r['name'] == branch and not r.get('inherited')), None)
        desired = {'allowed_to_push': ([{'user_id': user} for user in sorted(merge_users)]
                                       if branch == 'dev' else [{'access_level': 0}]),
                   'allowed_to_merge': [{'user_id': user} for user in sorted(merge_users)], 'allow_force_push': False}
        if rule:
            if branch != 'dev':
                # Preserve stricter owner-only QA/main admission; never give the dev
                # operator a new promotion permission as a side effect of this setup.
                desired.pop('allowed_to_merge')
            retained_push = {row['user_id'] for row in rule['push_access_levels']
                             if branch == 'dev' and row.get('user_id') in merge_users
                             and not row.get('group_id') and not row.get('deploy_key_id')}
            desired['allowed_to_push'] = [
                {'id': row['id'], '_destroy': True} for row in rule['push_access_levels']
                if row.get('user_id') not in retained_push
            ] + ([{'user_id': user} for user in sorted(merge_users - retained_push)]
                 if branch == 'dev' else [{'access_level': 0}])
            if 'allowed_to_merge' in desired:
                # Preserve existing approved records. Destroy/recreate of the same
                # user in one PATCH fails GitLab's unique access-record validation.
                retained = {row['user_id'] for row in rule['merge_access_levels']
                            if row.get('user_id') in merge_users and not row.get('group_id')}
                desired['allowed_to_merge'] = [
                    {'id': row['id'], '_destroy': True} for row in rule['merge_access_levels']
                    if row.get('user_id') not in retained
                ] + [{'user_id': user} for user in sorted(merge_users - retained)]
                if not desired['allowed_to_merge']:
                    desired.pop('allowed_to_merge')
            try:
                # Do not rewrite already-strict rules whose unprotect permission may
                # deliberately belong only to the instance owner (especially qa/main).
                validate_protection([rule], [], merge_users, branches=(branch,))
                if branch == 'dev' and retained_push != merge_users:
                    raise ValueError('approved development push permissions are missing')
            except ValueError:
                api.request(identity + '/protected_branches/' + encoded(branch), 'PATCH', desired)
        else:
            # Protect the name, without creating a qa/main branch or promoting code.
            if branch != 'dev':
                if stage_owner not in merge_users:
                    raise ValueError('new QA/main protection requires an explicit stage owner')
                desired['allowed_to_merge'] = [{'user_id': stage_owner}]
            api.request(identity + '/protected_branches', 'POST', dict(name=branch, **desired))
    actual = api.request(identity)
    for key, value in settings.items():
        if actual.get(key) != value:
            raise RuntimeError(f'{project["path_with_namespace"]}: setting did not hold: {key}')
    rules = api.all(identity + '/protected_branches')
    readers = configure_ci_read_access(api, project)
    return {'project': project['path_with_namespace'], 'id': project['id'],
            'settings': settings, 'rules': rules, 'ci_read_groups': readers}


def expected_inputs(api, project, source):
    """Resolve the same owner-controlled cohort input as native qualification."""
    core = 'projects/' + encoded('GetBusbar/busbar')
    if project['path_with_namespace'] == 'GetBusbar/busbar':
        host = source
    else:
        variables = api.all('projects/' + str(project['id']) + '/variables')
        cohort = [v for v in variables if v['key'] == 'BUSBAR_ADMISSION_CORE_REVISION']
        if len(cohort) > 1:
            raise ValueError('ambiguous host cohort input')
        ref = cohort[0]['value'] if cohort else 'dev'
        host = api.request(core + '/repository/commits/' + encoded(ref))['id']
    vector = api.request(core + '/repository/files/' + encoded('scripts/ci-product-pins.json') + '?ref=' + host)
    sdk = json.loads(base64.b64decode(vector['content']))['sdk']
    if not all(re.fullmatch('[0-9a-f]{40}', value) for value in (host, sdk)):
        raise ValueError('host and SDK must resolve to immutable commits')
    return host, sdk


def required_conformance_job(repository, policy=None):
    if repository == 'GetBusbar/busbar':
        return 'core-conformance'
    return None


def validate_security_scans(receipt, repository, fixture_policy=None):
    """Positive secret counts require exact entries from the approved policy commit."""
    scans = receipt.get('steps', [])
    if (not isinstance(scans, list) or len(scans) != 3
            or any(not isinstance(row, dict) for row in scans)
            or {row.get('name') for row in scans} != {'secrets', 'dependencies', 'sast'}):
        raise ValueError('security receipt contains missing scans')
    for row in scans:
        count, code = row.get('findings'), row.get('exit_code')
        if row.get('status') != 'pass' or type(count) is not int or type(code) is not int:
            raise ValueError('security receipt contains invalid scan status/count')
        if count == 0 and code == 0:
            if any(key in row for key in ('classification_policy_sha256', 'classified_public_fixtures',
                                          'unresolved_findings', 'public_fixture_classifications')):
                raise ValueError('empty scan carries unexpected fixture classifications')
            continue
        if row['name'] != 'secrets' or count <= 0 or code != 1 or not isinstance(fixture_policy, bytes):
            raise ValueError('security receipt contains nonpassing scans')
        digest = hashlib.sha256(fixture_policy).hexdigest()
        policy = json.loads(fixture_policy)
        if (not isinstance(policy, dict) or policy.get('schema') != 'busbar.public-secret-fixtures/1'
                or not isinstance(policy.get('fixtures'), list)):
            raise ValueError('invalid trusted public fixture policy')
        entries = {entry['id']: entry for entry in policy['fixtures']}
        classified = row.get('public_fixture_classifications')
        if (row.get('classification_policy_sha256') != digest
                or receipt.get('policy_files', {}).get('public-secret-fixtures.json') != digest
                or type(row.get('classified_public_fixtures')) is not int
                or row['classified_public_fixtures'] != count
                or type(row.get('unresolved_findings')) is not int or row['unresolved_findings'] != 0
                or not isinstance(classified, list) or len(classified) != count
                or len(entries) != len(policy['fixtures'])):
            raise ValueError('unbound or incomplete public fixture classification')
        used = set()
        for index, item in enumerate(classified):
            if not isinstance(item, dict):
                raise ValueError('invalid public fixture classification')
            entry = entries.get(item.get('id'))
            if (not entry or entry['repository'] != repository or entry['id'] in used
                    or type(item.get('finding_index')) is not int
                    or json.dumps(item, sort_keys=True) != json.dumps({'finding_index': index, **entry}, sort_keys=True)):
                raise ValueError('unknown, duplicated or reordered public fixture classification')
            used.add(entry['id'])


CORE = 'GetBusbar/busbar'
# Checks every passing core-build receipt must contain (native.core_formatting,
# native.CORE_POLICY_COMMANDS and native_certified.build).
CORE_BUILD_STEPS = ('root-fmt', 'default-fmt', 'dependency-policy', 'dependency-vet',
                    'default-dependency-policy', 'default-dependency-vet', 'certified-build',
                    'development-artifact-evidence')
# Checks every passing core-clippy receipt must contain (native.CORE_CLIPPY_COMMANDS).
CORE_CLIPPY_STEPS = ('root-clippy', 'default-clippy')
CORE_CLIPPY_SCHEMA = 'busbar.core-clippy/1'
# Checks every passing core-test receipt must contain (native.CORE_TEST_STEPS).
CORE_TEST_STEPS = ('workspace-doctests', 'root-runtime')
CORE_TEST_SCHEMA = 'busbar.core-test/1'


def passing_steps(receipt, label):
    steps = receipt.get('steps')
    if (not isinstance(steps, list) or not steps
            or any(not isinstance(step, dict) or step.get('status') != 'pass' or step.get('exit_code') != 0
                   for step in steps)):
        raise ValueError(label + ' receipt contains missing or nonpassing checks')
    names = [step.get('name') for step in steps]
    if len(names) != len(set(names)):
        raise ValueError(label + ' receipt contains duplicate checks')
    return set(names)


def validate_core_dev_tier(project, mr, pipeline, jobs, build_receipt, conformance_receipt,
                           revision, target, host, sdk, clippy_receipt=None, test_receipt=None):
    """Core's dev admission: this pipeline's certified build and the conformance of those bytes."""
    from native_certified import JOB, verify_receipt

    def required_job(name):
        rows = [job for job in jobs if job.get('name') == name]
        if len(rows) != 1 or not rows[0].get('runner') or type(rows[0].get('id')) is not int:
            raise ValueError('required same-pipeline dev-tier job is missing, ambiguous or external: ' + name)
        return rows[0]

    build, evaluation, lint = required_job(JOB), required_job('core-conformance'), required_job('core-clippy')
    tests = required_job('core-test')
    identity = {'status': 'pass', 'repository': project['path_with_namespace'], 'source': mr['sha'],
                'policy_revision': revision, 'pipeline_id': str(pipeline['id']),
                'target_revision': target, 'host_revision': host, 'sdk_revision': sdk}
    for label, receipt, job in (('core-build', build_receipt, build),
                                ('conformance', conformance_receipt, evaluation),
                                ('core-clippy', clippy_receipt, lint),
                                ('core-test', test_receipt, tests)):
        if not isinstance(receipt, dict):
            raise ValueError(label + ' receipt is missing')
        for key, value in dict(identity, job_id=str(job['id'])).items():
            if receipt.get(key) != value:
                raise ValueError(label + ' receipt mismatch: ' + key)
    # Schema, this pipeline/job/policy/source and the certified record of the one build.
    record = verify_receipt(build_receipt, job_id=build['id'], source=mr['sha'], policy=revision,
                            pipeline=pipeline['id'])
    missing = set(CORE_BUILD_STEPS) - passing_steps(build_receipt, 'core-build')
    if missing:
        raise ValueError('core-build receipt omits required checks: ' + ', '.join(sorted(missing)))
    if clippy_receipt.get('schema') != CORE_CLIPPY_SCHEMA:
        raise ValueError('core-clippy receipt mismatch: schema')
    missing = set(CORE_CLIPPY_STEPS) - passing_steps(clippy_receipt, 'core-clippy')
    if missing:
        raise ValueError('core-clippy receipt omits required checks: ' + ', '.join(sorted(missing)))
    if test_receipt.get('schema') != CORE_TEST_SCHEMA:
        raise ValueError('core-test receipt mismatch: schema')
    missing = set(CORE_TEST_STEPS) - passing_steps(test_receipt, 'core-test')
    if missing:
        raise ValueError('core-test receipt omits required checks: ' + ', '.join(sorted(missing)))
    if conformance_receipt.get('schema') != 'busbar.protected-conformance/1':
        raise ValueError('conformance receipt mismatch: schema')
    passing_steps(conformance_receipt, 'conformance')
    judged = conformance_receipt.get('certified_binary')
    if (not isinstance(judged, dict) or judged.get('sha256') != record['sha256']
            or conformance_receipt.get('binary_sha256') != record['sha256']
            or judged.get('bytes') != record.get('bytes')
            or judged.get('core_build_job_id') != build['id'] or judged.get('pipeline_id') != pipeline['id']):
        raise ValueError("conformance did not judge this pipeline's certified core-build binary")


def validate_merge(project, mr, pipeline, jobs, receipt, revision, target, host, sdk,
                   conformance_receipt=None, security_receipt=None, secret_fixture_policy=None,
                   clippy_receipt=None, test_receipt=None):
    """Finite admission predicate, shared by the controller and bypass regressions.

    For core, receipt is the core-build receipt, conformance_receipt the
    core-conformance receipt, clippy_receipt the core-clippy receipt and
    test_receipt the core-test receipt (DEV tier); security_receipt is not consulted.
    For every other project, receipt is the native-qualification receipt.
    """
    if project['ci_config_path'] != 'ci/architecture-pipeline.yml@GetBusbar/busbar:' + revision:
        raise ValueError('trusted CI setting changed')
    if not (project['merge_method'] == 'ff' and project['only_allow_merge_if_pipeline_succeeds'] and project['allow_merge_on_skipped_pipeline'] is False):
        raise ValueError('server admission settings changed')
    if mr['source_project_id'] != project['id'] or mr['target_project_id'] != project['id'] or mr['target_branch'] != 'dev':
        raise ValueError('admission requires a same-project candidate targeting dev')
    if pipeline.get('project_id') != project['id'] or pipeline.get('source') != 'merge_request_event' or pipeline.get('sha') != mr['sha'] or pipeline.get('status') != 'success':
        raise ValueError('missing, stale or unsuccessful current MR pipeline')
    if any(job.get('status') != 'success' or job.get('allow_failure') for job in jobs):
        raise ValueError('pipeline contains a nonpassing or optional job')
    if project['path_with_namespace'] == CORE:
        validate_core_dev_tier(project, mr, pipeline, jobs, receipt, conformance_receipt,
                               revision, target, host, sdk, clippy_receipt, test_receipt)
        return
    security = [job for job in jobs if job['name'] == 'security-scans']
    if len(security) != 1 or not security[0].get('runner'):
        raise ValueError('required independent security job missing or ambiguous')
    expected_security = dict(schema='busbar.security-scans/1', status='pass',
        repository=project['path_with_namespace'], source=mr['sha'], policy_revision=revision,
        pipeline_id=str(pipeline['id']), job_id=str(security[0]['id']))
    if not isinstance(security_receipt, dict) or any(
            security_receipt.get(key) != value for key, value in expected_security.items()):
        raise ValueError('security receipt missing, stale or for another source/policy/job')
    validate_security_scans(security_receipt, project['path_with_namespace'], secret_fixture_policy)
    native = [j for j in jobs if j['name'] == 'native-qualification']
    if len(native) != 1 or native[0]['status'] != 'success' or native[0].get('allow_failure'):
        raise ValueError('required native job missing or not passing')
    if not native[0].get('runner'):
        raise ValueError('external commit status is not a native job')
    expected = {'status': 'pass', 'repository': project['path_with_namespace'], 'source': mr['sha'],
                'policy_revision': revision, 'pipeline_id': str(pipeline['id']), 'job_id': str(native[0]['id']),
                'target_revision': target, 'host_revision': host, 'sdk_revision': sdk}
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise ValueError('native receipt mismatch: ' + key)
    if not receipt.get('steps') or any(step.get('status') != 'pass' or step.get('exit_code') != 0 for step in receipt['steps']):
        raise ValueError('native receipt contains missing or nonpassing checks')
    from native_policy import conformance_rows
    owner_suites = conformance_rows(project['path_with_namespace'])
    if owner_suites:
        selections = [step for step in receipt['steps'] if step.get('name') == 'plugin-native-conformance']
        if len(selections) != 1 or receipt.get('required_conformance_suites') != sorted(owner_suites):
            raise ValueError('native receipt omits required owner conformance suites or execution')
    required = required_conformance_job(project['path_with_namespace'])
    if required:
        evaluations = [job for job in jobs if job['name'] == required]
        if len(evaluations) != 1 or not evaluations[0].get('runner'):
            raise ValueError('required same-pipeline conformance job is missing or ambiguous')
        if not isinstance(conformance_receipt, dict):
            raise ValueError('required conformance receipt is missing')
        expected = dict(expected, job_id=str(evaluations[0]['id']), schema='busbar.protected-conformance/1')
        for key, value in expected.items():
            if conformance_receipt.get(key) != value:
                raise ValueError('conformance receipt mismatch: ' + key)
        if not conformance_receipt.get('steps') or any(
                step.get('status') != 'pass' or step.get('exit_code') != 0
                for step in conformance_receipt['steps']):
            raise ValueError('conformance receipt contains missing or nonpassing checks')


def job_receipt(api, identity, job, filename='receipt.json'):
    return api.request(identity + '/jobs/' + str(job['id']) + '/artifacts/boundary-evidence/' + filename)


def core_dev_receipts(api, identity, jobs):
    """Core DEV tier: this pipeline's core-build, core-conformance, core-clippy and core-test receipts."""
    receipts = []
    for job_name in ('core-build', 'core-conformance', 'core-clippy', 'core-test'):
        rows = [job for job in jobs if job['name'] == job_name and job['status'] == 'success']
        if len(rows) != 1:
            raise ValueError('current ' + job_name + ' is not successful')
        receipts.append(job_receipt(api, identity, rows[0]))
    return receipts


def native_receipts(api, identity, jobs, name, policy_revision):
    """Plugin/assembly admission inputs: native qualification, security and any conformance."""
    native = [job for job in jobs if job['name'] == 'native-qualification' and job['status'] == 'success']
    if len(native) != 1:
        raise ValueError('current native qualification is not successful')
    receipt = job_receipt(api, identity, native[0])
    conformance_receipt = None
    security_jobs = [job for job in jobs if job['name'] == 'security-scans']
    if len(security_jobs) != 1:
        raise ValueError('required security job missing or ambiguous')
    security_receipt = job_receipt(api, identity, security_jobs[0], 'security.json')
    secret_fixture_policy = None
    if any(row.get('findings') for row in security_receipt.get('steps', [])):
        # Read only the controller-approved immutable policy, never candidate files.
        manifest = api.request('projects/' + encoded('GetBusbar/busbar')
            + '/repository/files/' + encoded('ci/security/public-secret-fixtures.json')
            + '?ref=' + policy_revision)
        secret_fixture_policy = base64.b64decode(manifest['content'], validate=True)
    required = required_conformance_job(name)
    if required:
        evaluations = [job for job in jobs if job['name'] == required]
        if len(evaluations) != 1:
            raise ValueError('required same-pipeline conformance job is missing or ambiguous')
        conformance_receipt = job_receipt(api, identity, evaluations[0])
    return receipt, conformance_receipt, security_receipt, secret_fixture_policy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True)
    parser.add_argument('--policy-revision', required=True)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('action', choices=('inspect', 'apply', 'merge'))
    parser.add_argument('--group-read-keychain-service',
                        help='Optional macOS Keychain service for group-protection reads only')
    parser.add_argument('--repository')
    parser.add_argument('--merge-request', type=int)
    parser.add_argument('--merge-user-id', type=int, action='append', required=True,
                        help='Architecture owner/admission operator, never a candidate job identity')
    parser.add_argument('--stage-owner-id', type=int,
                        help='Owner-only merge permission when QA/main protection must be created')
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.policy_revision):
        raise ValueError('an immutable approved policy revision is required')
    policy = read(args.policy)
    repositories = ['GetBusbar/busbar', 'GetBusbar/busbar-release', *policy['repositories']]
    if args.repository:
        if args.repository not in repositories:
            raise ValueError('repository is outside this admission policy')
        repositories = [args.repository]
    api = GitLab(args.server)
    group_api = group_protection_reader(api, args.group_read_keychain_service)
    merge_users = set(args.merge_user_id)
    report = {'policy_revision': args.policy_revision, 'projects': [], 'groups': {}, 'owner_dependencies': []}
    for group in ('GetBusbar', 'BusbarInc'):
        try:
            report['groups'][group] = group_api.all('groups/' + encoded(group) + '/protected_branches')
        except RuntimeError as error:
            report['owner_dependencies'].append(str(error))
    if args.action in ('apply', 'merge'):
        # A policy revision cannot be invented or supplied solely as candidate file bytes.
        api.request('projects/' + encoded('GetBusbar/busbar') + '/repository/commits/' + args.policy_revision)
        api.request('projects/' + encoded('GetBusbar/busbar') + '/repository/files/' + encoded('ci/architecture-pipeline.yml') + '?ref=' + args.policy_revision)
        policy_file = api.request('projects/' + encoded('GetBusbar/busbar') + '/repository/files/' + encoded('ci/architecture.toml') + '?ref=' + args.policy_revision)
        if base64.b64decode(policy_file['content']) != args.policy.read_bytes():
            raise ValueError('local policy does not match the approved immutable revision')
    for name in repositories:
        project = api.request('projects/' + encoded(name))
        if name.startswith('BusbarInc/') and project['visibility'] != 'private':
            raise ValueError('enterprise project is not private: ' + name)
        identity = 'projects/' + str(project['id'])
        if args.action == 'apply':
            result = apply_project(api, project, args.policy_revision, merge_users, args.stage_owner_id)
            report['projects'].append(result)
            group = name.split('/')[0]
            if group in report['groups']:
                validate_protection(result['rules'], report['groups'][group], merge_users)
        elif args.action == 'inspect':
            report['projects'].append({'project': name, 'id': project['id'], 'ci_config_path': project['ci_config_path'],
                'rules': api.all(identity + '/protected_branches'), 'runners': api.all(identity + '/runners')})
        else:
            if not args.repository or not args.merge_request:
                raise ValueError('merge requires one repository and MR')
            if report['owner_dependencies']:
                raise ValueError('group protection rules remain unverified')
            validate_protection(api.all(identity + '/protected_branches'),
                                report['groups'][name.split('/')[0]], merge_users)
            mr = api.request(identity + '/merge_requests/' + str(args.merge_request))
            pipeline = mr.get('head_pipeline')
            if not pipeline:
                raise ValueError('current MR pipeline is missing')
            pipeline = api.request(identity + '/pipelines/' + str(pipeline['id']))
            jobs = api.all(identity + '/pipelines/' + str(pipeline['id']) + '/jobs')
            target = api.request(identity + '/repository/branches/dev')['commit']['id']
            host, sdk = expected_inputs(api, project, mr['sha'])
            clippy_receipt = test_receipt = None
            if name == CORE:
                receipt, conformance_receipt, clippy_receipt, test_receipt = core_dev_receipts(api, identity, jobs)
                security_receipt = secret_fixture_policy = None
            else:
                receipt, conformance_receipt, security_receipt, secret_fixture_policy = native_receipts(
                    api, identity, jobs, name, args.policy_revision)
            validate_merge(project, mr, pipeline, jobs, receipt, args.policy_revision, target, host, sdk,
                           conformance_receipt, security_receipt, secret_fixture_policy, clippy_receipt,
                           test_receipt)
            result = api.request(identity + '/merge_requests/' + str(args.merge_request) + '/merge', 'PUT', {'sha': mr['sha'], 'should_remove_source_branch': True, 'squash': False})
            report['projects'].append({'project': name, 'source': mr['sha'], 'target_before': target, 'merge_commit_sha': result.get('merge_commit_sha'), 'state': result['state']})
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'projects': len(report['projects']), 'owner_dependencies': report['owner_dependencies']}))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Owner-side protected admission. Never install this credential in candidate CI.

GitLab enforces protected branches, successful pipelines and fast-forward merging.
This controller additionally admits only the trusted native job for the exact source,
target and policy revision. Fork/external-status pipelines cannot impersonate it.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from check import read


class GitLab:
    def __init__(self, server):
        parsed = urllib.parse.urlsplit(server)
        if parsed.scheme != 'https' or parsed.path not in ('', '/'):
            raise ValueError('an HTTPS GitLab origin is required')
        self.server = server.rstrip('/')
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


def encoded(value):
    return urllib.parse.quote(str(value), safe='')


def matches(pattern, branch):
    # GitLab protected-branch names support '*', not shell '?' or character classes.
    return re.fullmatch(re.escape(pattern).replace(r'\*', '.*'), branch) is not None


def validate_protection(project_rules, group_rules, merge_users):
    """GitLab combines matching rules permissively: examine every matching rule."""
    for branch in ('dev', 'qa', 'main'):
        rules = [row for row in [*project_rules, *group_rules] if matches(row['name'], branch)]
        if not rules:
            raise ValueError('unprotected branch: ' + branch)
        merge_allowed = False
        for rule in rules:
            if rule.get('allow_force_push'):
                raise ValueError('force-push allowance: ' + rule['name'])
            for row in rule['push_access_levels']:
                if row.get('access_level', 0) or any(row.get(key) for key in ('user_id', 'group_id', 'deploy_key_id')):
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


def apply_project(api, project, policy_revision, merge_users):
    identity = 'projects/' + str(project['id'])
    expected = 'ci/architecture-pipeline.yml@GetBusbar/busbar:' + policy_revision
    settings = dict(ci_config_path=expected, merge_method='ff', only_allow_merge_if_pipeline_succeeds=True,
        allow_merge_on_skipped_pipeline=False, ci_pipeline_variables_minimum_override_role='no_one_allowed',
        ci_push_repository_for_job_token_allowed=False, remove_source_branch_after_merge=True)
    api.request(identity, 'PUT', settings)
    rules = api.all(identity + '/protected_branches')
    for branch in ('dev', 'qa', 'main'):
        rule = next((r for r in rules if r['name'] == branch and not r.get('inherited')), None)
        desired = {'allowed_to_push': [{'access_level': 0}],
                   'allowed_to_merge': [{'user_id': user} for user in sorted(merge_users)], 'allow_force_push': False}
        if rule:
            if branch != 'dev':
                # Preserve stricter owner-only QA/main admission; never give the dev
                # operator a new promotion permission as a side effect of this setup.
                desired.pop('allowed_to_merge')
            desired['allowed_to_push'] = [{'id': row['id'], '_destroy': True} for row in rule['push_access_levels']] + desired['allowed_to_push']
            if 'allowed_to_merge' in desired:
                desired['allowed_to_merge'] = [{'id': row['id'], '_destroy': True} for row in rule['merge_access_levels']] + desired['allowed_to_merge']
            try:
                # Do not rewrite already-strict rules whose unprotect permission may
                # deliberately belong only to the instance owner (especially qa/main).
                validate_protection([dict(rule, name='*')], [], merge_users)
            except ValueError:
                api.request(identity + '/protected_branches/' + encoded(branch), 'PATCH', desired)
        else:
            # Protect the name, without creating a qa/main branch or promoting code.
            api.request(identity + '/protected_branches', 'POST', dict(name=branch, **desired))
    actual = api.request(identity)
    for key, value in settings.items():
        if actual.get(key) != value:
            raise RuntimeError(f'{project["path_with_namespace"]}: setting did not hold: {key}')
    rules = api.all(identity + '/protected_branches')
    return {'project': project['path_with_namespace'], 'id': project['id'], 'settings': settings, 'rules': rules}


def validate_merge(project, mr, pipeline, jobs, receipt, revision, target):
    """Finite admission predicate, shared by the controller and bypass regressions."""
    if project['ci_config_path'] != 'ci/architecture-pipeline.yml@GetBusbar/busbar:' + revision:
        raise ValueError('trusted CI setting changed')
    if not (project['merge_method'] == 'ff' and project['only_allow_merge_if_pipeline_succeeds'] and project['allow_merge_on_skipped_pipeline'] is False):
        raise ValueError('server admission settings changed')
    if mr['source_project_id'] != project['id'] or mr['target_project_id'] != project['id'] or mr['target_branch'] != 'dev':
        raise ValueError('admission requires a same-project candidate targeting dev')
    if pipeline.get('project_id') != project['id'] or pipeline.get('source') != 'merge_request_event' or pipeline.get('sha') != mr['sha'] or pipeline.get('status') != 'success':
        raise ValueError('missing, stale or unsuccessful current MR pipeline')
    native = [j for j in jobs if j['name'] == 'native-qualification']
    if len(native) != 1 or native[0]['status'] != 'success' or native[0].get('allow_failure'):
        raise ValueError('required native job missing or not passing')
    if not native[0].get('runner'):
        raise ValueError('external commit status is not a native job')
    expected = {'status': 'pass', 'repository': project['path_with_namespace'], 'source': mr['sha'],
                'policy_revision': revision, 'pipeline_id': str(pipeline['id']), 'job_id': str(native[0]['id']),
                'target_revision': target}
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise ValueError('native receipt mismatch: ' + key)
    if not receipt.get('steps') or any(step.get('status') != 'pass' or step.get('exit_code') != 0 for step in receipt['steps']):
        raise ValueError('native receipt contains missing or nonpassing checks')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True)
    parser.add_argument('--policy-revision', required=True)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('action', choices=('inspect', 'apply', 'merge'))
    parser.add_argument('--repository')
    parser.add_argument('--merge-request', type=int)
    parser.add_argument('--merge-user-id', type=int, action='append', required=True,
                        help='Architecture owner/admission operator, never a candidate job identity')
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
    merge_users = set(args.merge_user_id)
    report = {'policy_revision': args.policy_revision, 'projects': [], 'groups': {}, 'owner_dependencies': []}
    for group in ('GetBusbar', 'BusbarInc'):
        try:
            report['groups'][group] = api.all('groups/' + encoded(group) + '/protected_branches')
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
            result = apply_project(api, project, args.policy_revision, merge_users)
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
            native = [job for job in jobs if job['name'] == 'native-qualification' and job['status'] == 'success']
            if len(native) != 1:
                raise ValueError('current native qualification is not successful')
            receipt = api.request(identity + '/jobs/' + str(native[0]['id']) + '/artifacts/boundary-evidence/receipt.json')
            target = api.request(identity + '/repository/branches/dev')['commit']['id']
            validate_merge(project, mr, pipeline, jobs, receipt, args.policy_revision, target)
            result = api.request(identity + '/merge_requests/' + str(args.merge_request) + '/merge', 'PUT', {'sha': mr['sha'], 'should_remove_source_branch': True, 'squash': False})
            report['projects'].append({'project': name, 'source': mr['sha'], 'target_before': target, 'merge_commit_sha': result.get('merge_commit_sha'), 'state': result['state']})
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'projects': len(report['projects']), 'owner_dependencies': report['owner_dependencies']}))


if __name__ == '__main__':
    main()

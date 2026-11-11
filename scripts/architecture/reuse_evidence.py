"""Authenticate retained evidence at its original protected GitLab execution.

The controller supplies canonical API clients, object stores and full validators.
No proof JSON, cached success flag or candidate checkout supplies authority. Only
original policy Python selected from the controller's core object store executes;
candidate binaries, scripts and archive members are never executed or extracted.
"""
from __future__ import annotations

import hashlib
import datetime as dt
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile

from input_identity import CORE, checked_request, database_identity, encoded as identity_encoded, require


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return urllib.parse.quote(str(value), safe='')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Archive:
    """Bounded, duplicate-free regular ZIP members, read without extraction."""

    def __init__(self, raw):
        require(isinstance(raw, bytes) and len(raw) <= 1024**3, 'invalid archive size')
        self.zip = zipfile.ZipFile(io.BytesIO(raw))
        members = self.zip.infolist()
        require(len(members) <= 10000, 'too many archive members')
        self.members = {}
        total = 0
        for item in members:
            path = PurePosixPath(item.filename)
            require(not path.is_absolute() and '..' not in path.parts
                    and '\\' not in item.filename and '\x00' not in item.filename
                    and str(path) == item.filename.rstrip('/'), 'unsafe archive path')
            require(item.filename not in self.members, 'duplicate archive member')
            mode = item.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR),
                    'nonregular archive member')
            require(not item.flag_bits & 1, 'encrypted archive member')
            total += item.file_size
            require(total <= 2 * 1024**3 and item.file_size <= 1024**3,
                    'expanded archive exceeds bounds')
            self.members[item.filename] = item

    def read(self, path):
        require(isinstance(path, str) and re.fullmatch(r'[A-Za-z0-9_./-]+', path)
                and '..' not in path.split('/') and not path.startswith('/'),
                'invalid evidence path')
        name = 'boundary-evidence/' + path
        require(name in self.members and not self.members[name].is_dir(),
                'required artifact missing: ' + path)
        return self.zip.read(self.members[name])


POLICY_FILES = ('scripts/architecture/admission.py', 'scripts/architecture/native_policy.py',
                'scripts/architecture/check.py', 'scripts/architecture/product_artifacts.py',
                'ci/architecture.toml', 'conformance/ci-coverage.json',
                'ci/security/public-secret-fixtures.json', 'ci/architecture-pipeline.yml')


def independent_qualification_job(raw, job):
    """Recognize only the approved simple first-stage job inheritance grammar.

    Unknown DAG/include/default syntax fails closed, requiring fresh execution or
    an explicit controller implementation of that new prerequisite contract.
    """
    text = raw.decode('utf-8')
    require(re.search(r'^stages: \[qualify, website\]$', text, re.M)
            and not re.search(r'^(?:include|default|workflow_defaults):', text, re.M)
            and not re.search(r'^\s*(?:needs|dependencies|<<):', text, re.M)
            and not re.search(r'^[^#\n]*[&*][A-Za-z_]', text, re.M),
            'unrecognized original job prerequisite graph')
    blocks = re.split(r'^([A-Za-z][A-Za-z0-9_-]*):\s*$', text, flags=re.M)
    jobs = dict(zip(blocks[1::2], blocks[2::2]))
    require(job in jobs and 'native-qualification' in jobs, 'original job definition missing')
    base = jobs['native-qualification']
    require(re.search(r'^  stage: qualify$', base, re.M)
            and not re.search(r'^  extends:', base, re.M), 'native prerequisite graph changed')
    if job != 'native-qualification':
        block = jobs[job]
        require(re.search(r'^  extends: native-qualification$', block, re.M)
                and not re.search(r'^  stage:', block, re.M), 'job prerequisite inheritance changed')
    return True
POLICY_CODE = """
import json, sys, tomllib
from pathlib import Path
base=Path(sys.argv[1]); sys.path.insert(0,str(base/'scripts/architecture'))
import admission, native_policy, check, product_artifacts
assert all(Path(m.__file__).resolve().is_relative_to(base.resolve()) for m in
           (admission,native_policy,check,product_artifacts))
data=json.load(sys.stdin)
admission.validate_protection(data['project_rules'],data['group_rules'],set(data['merge_users']))
p=tomllib.loads((base/'ci/architecture.toml').read_text())
repo=data['repository']
assert repo==p.get('assembly',{}).get('repository') or repo in p['repositories']
if data.get('security') is not None:
 admission.validate_security_scans(data['security'], repo,
  (base/'ci/security/public-secret-fixtures.json').read_bytes())
print(json.dumps({'required_external':admission.required_conformance_job(repo,p),
 'owner_suites':sorted(native_policy.conformance_rows(repo,p,trusted=base)),
 'native_settings':native_policy.native_settings(repo,p)}))
"""


class Resolver:
    def __init__(self, api, *, group_api, objects, current_policy, merge_users,
                 owner_users, scratch, full_validator, trusted_policies=None, now=None,
                 selector_policies=None):
        require(re.fullmatch('[0-9a-f]{40}', current_policy or ''), 'current immutable policy required')
        require(callable(full_validator), 'full original artifact validator required')
        require(merge_users and owner_users, 'controller-owned principal sets required')
        self.api, self.group_api, self.objects = api, group_api, objects
        self.current_policy = current_policy
        # Incremental selection can legitimately leave retained-only projects on
        # their earlier selector. This map is controller state, never API-derived
        # self-authorization or a field accepted from a reuse proof.
        self.selector_policies = dict(selector_policies or {})
        self.trusted_policies = set(trusted_policies or {current_policy})
        require(current_policy in self.trusted_policies and all(
            re.fullmatch('[0-9a-f]{40}', value) for value in self.trusted_policies),
            'controller-approved immutable policy revisions required')
        require(set(self.selector_policies.values()) <= self.trusted_policies,
                'installed selector map must use approved immutable policies')
        self.now = now or (lambda: dt.datetime.now(dt.timezone.utc))
        self.database_witness = None
        self.merge_users, self.owner_users = set(merge_users), set(owner_users)
        self.scratch = Path(scratch)
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.full_validator = full_validator
        self._authenticated = {}

    @staticmethod
    def _json(api, path):
        return api.json(path) if hasattr(api, 'json') else api.request(path)

    @classmethod
    def _all(cls, api, path):
        if hasattr(api, 'all'):
            return api.all(path)
        rows = []
        for page in range(1, 101):
            batch = cls._json(api, path + ('&' if '?' in path else '?')
                              + f'per_page=100&page={page}')
            require(isinstance(batch, list), 'invalid paginated API response')
            rows.extend(batch)
            if len(batch) < 100:
                return rows
        raise ValueError('API pagination exceeds bound')

    def _raw(self, path):
        if hasattr(self.api, 'raw'):
            return self.api.raw(path)
        require(self.api.server == 'https://github.com', 'canonical forge required')
        request = urllib.request.Request(self.api.server + '/api/v4/' + path,
                                        headers={'PRIVATE-TOKEN': self.api.token})
        with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
            raw = response.read(1024**3 + 1)
        require(len(raw) <= 1024**3, 'artifact download exceeds bound')
        return raw

    def _policy(self, request, project_rules, group_rules, receipt):
        # A local bundle manifest alone is not authentication: read every byte
        # directly from the controller's immutable canonical core Git objects.
        with tempfile.TemporaryDirectory(prefix='original-policy-', dir=self.scratch) as name:
            base = Path(name)
            hashes = {}
            paths = set(POLICY_FILES)
            security = request['job'] == 'security-scans'
            if security:
                paths.update(path for path in self.objects.tree(CORE, request['policy'])
                             if path.startswith('ci/security/') and path.count('/') == 2)
            for path in sorted(paths):
                raw = self.objects.blob(CORE, request['policy'], path)
                target = base / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                hashes[path] = digest(raw)
            result = subprocess.run([sys.executable, '-I', '-B', '-c', POLICY_CODE, str(base)],
                                    input=json.dumps(dict(repository=request['repository'],
                                        project_rules=project_rules, group_rules=group_rules,
                                        merge_users=sorted(self.merge_users),
                                        security=receipt if security else None)),
                                    capture_output=True, text=True, timeout=60)
            require(result.returncode == 0, 'immutable original policy rejected evidence context')
            info = json.loads(result.stdout)
            info['files'] = hashes
            independent_qualification_job((base / 'ci/architecture-pipeline.yml').read_bytes(), request['job'])
            info['independent_job'] = True
            if security:
                info['tools'] = json.loads((base / 'ci/security/tools.json').read_bytes())
            return info

    def resolve(self, original, receipt):
        original = checked_request(original)
        require(original['policy'] in self.trusted_policies,
                'original policy is not controller-approved executable validator code')
        security = original['job'] == 'security-scans'
        require(isinstance(receipt, dict), 'original receipt required')
        require(all(re.fullmatch('[1-9][0-9]*', str(receipt.get(k, '')))
                    for k in ('job_id', 'pipeline_id')), 'immutable original job IDs required')
        project = self._json(self.api, 'projects/' + encoded(original['repository']))
        require(project.get('path_with_namespace') == original['repository']
                and type(project.get('id')) is int, 'canonical original project mismatch')
        require(not original['repository'].startswith('BusbarInc/')
                or project.get('visibility') == 'private', 'private repository visibility changed')
        require(project.get('ci_config_path') ==
                'ci/architecture-pipeline.yml@GetBusbar/busbar:'
                + self.selector_policies.get(original['repository'], self.current_policy),
                'current protected project selector changed')
        require(project.get('merge_method') == 'ff'
                and project.get('only_allow_merge_if_pipeline_succeeds') is True
                and project.get('allow_merge_on_skipped_pipeline') is False
                and project.get('ci_pipeline_variables_minimum_override_role') == 'no_one_allowed',
                'current protected admission settings changed')
        base = 'projects/' + str(project['id'])
        project_rules = self._all(self.api, base + '/protected_branches')
        group_rules = self._all(self.group_api, 'groups/'
                               + encoded(original['repository'].split('/')[0]) + '/protected_branches')
        # Protection rules must cover all three names even before a release
        # branch is created. Enumerate refs so an authenticated absence is not
        # confused with an authorization failure from a single-ref endpoint.
        branches = self._all(self.api, base + '/repository/branches')
        require(all(isinstance(ref, dict) and isinstance(ref.get('name'), str)
                    for ref in branches), 'invalid canonical branch inventory')
        branch_map = {ref['name']: ref for ref in branches}
        require(len(branch_map) == len(branches), 'duplicate canonical branch name')
        require('dev' in branch_map, 'current development ref missing')
        protected_refs = {branch: branch_map.get(branch) for branch in ('dev', 'qa', 'main')}
        for ref in protected_refs.values():
            require(ref is None or ref.get('protected') is True,
                    'existing required ref is not protected')
        policy = self._policy(original, project_rules, group_rules, receipt)
        pipeline = self._json(self.api, base + '/pipelines/' + receipt['pipeline_id'])
        require(pipeline.get('id') == int(receipt['pipeline_id'])
                and pipeline.get('project_id') == project['id']
                and pipeline.get('sha') == original['source']
                and pipeline.get('status') in ('success', 'failed')
                and pipeline.get('ref') == 'dev'
                and pipeline.get('source') in ('api', 'push')
                and (pipeline.get('user') or {}).get('id') in self.owner_users,
                'original owner pipeline/source/ref is not successful and authentic')
        jobs = self._all(self.api, base + '/pipelines/' + receipt['pipeline_id'] + '/jobs')
        required = {'native-qualification', 'security-scans'}
        if policy['required_external']:
            required.add(policy['required_external'])
        require(original['job'] in required, 'original job not required by its immutable policy')
        # Other first-stage jobs are independent requirements. Their failure or
        # intentional absence cannot turn this successful job into a failure;
        # the aggregate selector must separately prove each required kind.
        matches = [j for j in jobs if j.get('name') == original['job']]
        require(len(matches) == 1 and matches[0].get('status') == 'success'
                and matches[0].get('allow_failure') is False,
                'original pipeline missing selected mandatory successful job')
        job = self._json(self.api, base + '/jobs/' + receipt['job_id'])
        require(job.get('id') == int(receipt['job_id']) and job.get('name') == original['job']
                and job.get('status') == 'success' and job.get('allow_failure') is False
                and (job.get('pipeline') or {}).get('id') == pipeline['id']
                and (job.get('commit') or {}).get('id') == original['source']
                and job.get('ref') == 'dev' and (job.get('runner') or {}).get('id')
                and any(j.get('id') == job['id'] and j.get('name') == original['job'] for j in jobs),
                'original mandatory runner job identity mismatch')
        expected = dict(repository=original['repository'], source=original['source'],
                        target_revision=original['source'], policy_revision=original['policy'],
                        host_revision=original['host'], sdk_revision=original['sdk'], status='pass',
                        policy_sha256=policy['files']['ci/architecture.toml'],
                        schema='busbar.protected-native-admission/1' if original['job'] ==
                        'native-qualification' else 'busbar.protected-conformance/1')
        if security:
            expected = dict(repository=original['repository'], source=original['source'],
                            policy_revision=original['policy'], status='pass',
                            schema='busbar.security-scans/1')
        require(all(receipt.get(k) == v for k, v in expected.items()), 'original receipt identity mismatch')
        uri = ('github.com/' + original['repository']
               + '//ci/architecture-pipeline.yml@GetBusbar/busbar:'
               + original['policy'] + '@refs/heads/dev')
        require(security or receipt.get('config_uri') == uri,
                'original source-bound configuration mismatch')
        job_base = base + '/jobs/' + receipt['job_id']
        if security:
            # Security receipts predate config_uri. The canonical original trace
            # must show the immutable policy Git fetch used by its bootstrap.
            trace = self._raw(job_base + '/trace')
            require(re.search(rb'\* branch\s+' + original['policy'].encode()
                              + rb'\s+-> FETCH_HEAD', trace) is not None,
                    'original security trace does not bind trusted policy checkout')
        filename = 'security.json' if security else 'receipt.json'
        receipt_bytes = self._raw(job_base + '/artifacts/boundary-evidence/' + filename)
        artifact_bytes = self._raw(job_base + '/artifacts')
        archive = Archive(artifact_bytes)
        require(archive.read(filename) == receipt_bytes and json.loads(receipt_bytes) == receipt,
                'receipt bytes are not from the original full archive/job')
        context = dict(original=original, project=project, pipeline=pipeline, job=job,
                       protected_refs=protected_refs,
                       policy=policy, receipt_bytes=receipt_bytes, artifact_bytes=artifact_bytes,
                       artifact_sha256=digest(artifact_bytes), receipt_sha256=digest(receipt_bytes))
        return context

    def _security(self, original, receipt, context):
        policy = context['policy']
        expected_files = {Path(path).name: value for path, value in policy['files'].items()
                          if path.startswith('ci/security/')}
        require(receipt.get('policy_files') == expected_files,
                'security artifact does not bind all immutable policy files')
        rows = [dict(path=path, mode=entry['mode'], sha256=digest(
                    self.objects.blob(original['repository'], original['source'], path)))
                for path, entry in self.objects.tree(original['repository'], original['source']).items()]
        require(receipt.get('source_files_sha256') == digest(identity_encoded(rows)),
                'security source export differs from original immutable source')
        tree = self.objects.git(original['repository'], 'rev-parse',
                                original['source'] + '^{tree}').decode().strip()
        require(receipt.get('source_tree') == tree, 'security original source tree mismatch')
        for step in receipt['steps']:
            tool = 'semgrep' if step['name'] == 'sast' else 'trivy'
            require(step.get('tool_image') == policy['tools'][tool]
                    and all(re.fullmatch('[0-9a-f]{64}', step.get(k, ''))
                            for k in ('report_sha256', 'stderr_sha256')),
                    'security scanner image or report identity mismatch')
        return database_identity(receipt.get('database'), policy['tools'], self.now())

    def authenticate_database(self, original, receipt):
        """Authenticate a fresh successful current-policy job as advisory witness.

        The witness is an original real job, not a claimed current database JSON.
        This reads only the explicitly selected completed job, never polls CI.
        """
        self.database_witness = None
        require(original['job'] == 'security-scans' and original['policy'] ==
                self.selector_policies.get(original['repository'], self.current_policy),
                'database witness must use current protected scanner policy')
        context = self.resolve(original, receipt)
        database = self._security(original, receipt, context)
        self.database_witness = dict(database=database, original=dict(original),
                                     receipt_sha256=context['receipt_sha256'],
                                     artifact_sha256=context['artifact_sha256'],
                                     database_max_age_hours=context['policy']['tools']['database_max_age_hours'])
        return dict(database)

    def authenticate_original(self, original, receipt, artifact_sha256):
        key = json.dumps(original, sort_keys=True), receipt.get('job_id')
        self._authenticated.pop(key, None)
        context = self.resolve(original, receipt)
        require(context['artifact_sha256'] == artifact_sha256,
                'archive digest differs from canonical original job')
        self._authenticated[key] = context
        return True

    def validate_original(self, original, receipt_bytes, artifact_bytes):
        original = checked_request(original)
        receipt = json.loads(receipt_bytes)
        key = json.dumps(original, sort_keys=True), receipt.get('job_id')
        context = self._authenticated.pop(key, None)
        require(context is not None and context['receipt_bytes'] == receipt_bytes
                and context['artifact_bytes'] == artifact_bytes,
                'original bytes have not been authenticated in this verification')
        artifact = Archive(artifact_bytes).read
        if original['job'] == 'security-scans':
            database = self._security(original, receipt, context)
            require(self.database_witness is not None and
                    database == self.database_witness['database'],
                    'original security database differs from authenticated fresh witness')
            database_identity(database, self.database_witness, self.now())
            return True
        steps = receipt.get('steps')
        require(isinstance(steps, list) and steps, 'original receipt has no checks')
        names = []
        for step in steps:
            name = step.get('name', '')
            require(re.fullmatch('[A-Za-z0-9_.-]+', name), 'invalid original check name')
            names.append(name)
            for stream in ('stdout', 'stderr'):
                require(digest(artifact(name + '.' + stream)) == step.get(stream + '_sha256'),
                        'original check stream missing or modified')
        require(len(names) == len(set(names)), 'duplicate original checks')
        if original['job'] == 'native-qualification':
            require(all(s.get('status') == 'pass' and s.get('exit_code') == 0 for s in steps),
                    'original native checks did not pass')
            suites = context['policy']['owner_suites']
            require(receipt.get('required_conformance_suites', []) == suites,
                    'original owner suites differ from immutable policy')
            require(not suites or 'plugin-native-conformance' in names,
                    'original owner conformance execution missing')
            if suites:
                invocation = json.loads(artifact('conformance/invocation.json'))
                require(set(invocation.get('verdicts', {})) == {suite + '.json' for suite in suites},
                        'original conformance artifacts omit immutable required suites')
                for suite in suites:
                    raw = artifact('conformance/verdicts/' + suite + '.json')
                    verdict = json.loads(raw)
                    require(digest(raw) == invocation['verdicts'][suite + '.json']
                            and verdict.get('status') == 'pass' and verdict.get('armed') is True,
                            'original required owner conformance verdict did not pass')
        require(self.full_validator(original, receipt, artifact, context, context['policy']) is True,
                'complete original artifact validation failed')
        return True


class MarketingValidator:
    """Adapt existing complete normalizers with controller-built original inputs.

    expected_loader(original) must derive the ORIGINAL lock/vector/conformance
    expectations from pinned objects, never from receipt/proof declarations.
    Private repositories need a controller validator that supports private input;
    the public marketing normalizer intentionally refuses them.
    """

    def __init__(self, module, expected_loader):
        self.module, self.expected_loader = module, expected_loader

    def __call__(self, original, receipt, artifact, context, policy):
        expected = self.expected_loader(original)
        require(all(expected.get(k) == original[k] for k in ('source', 'host', 'sdk')),
                'original normalizer expectations mismatch')
        # Explicitly describe the authenticated original selector. This is not
        # the current project setting and no synthetic merge-request is created.
        project = dict(context['project'], ci_config_path=
                       'ci/architecture-pipeline.yml@GetBusbar/busbar:' + original['policy'])
        if original['job'] == 'native-qualification':
            options = {}
            private = original['repository'].startswith('BusbarInc/')
            if private:
                options['authenticated_private_origin'] = True
            if context['pipeline']['status'] == 'failed':
                require(policy['independent_job'] is True, 'original job prerequisites unproven')
                options['authenticated_independent_parent'] = True
            result = self.module.normalize(receipt, project, context['pipeline'], context['job'],
                                           expected, artifact, **options)
            protocol_options = {'publish': False} if private else {}
            self.module.protocol_rows(receipt, result, artifact, policy['owner_suites'], **protocol_options)
        elif original['job'] == 'core-conformance':
            self.module.conformance_results(receipt, project, context['pipeline'], context['job'],
                                            expected, artifact)
        else:
            raise ValueError('full original validator unavailable for this job; run fresh')
        return True

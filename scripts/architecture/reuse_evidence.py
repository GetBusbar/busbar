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
import tomllib
import urllib.parse
import urllib.request
import zipfile

from input_identity import (CORE, checked_request, database_identity,
                            encoded as identity_encoded, require, semantic_database_identity)


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


LEGACY_STAGES = re.compile(r'^stages: \[qualify, website\]$', re.M)
TIERED_STAGES = re.compile(r'^stages: \[build, qualify, website, release\]$', re.M)
# Core's DEV tier: the certified build, then conformance of exactly its bytes.
CORE_DEV_JOBS = ('core-build', 'core-conformance')
TIERED_JOBS = {'core-build': 'build', 'core-conformance': 'qualify',
               'native-qualification': 'qualify', 'security-scans': 'qualify'}


def pipeline_blocks(text):
    blocks = re.split(r'^(\.?[A-Za-z][A-Za-z0-9_-]*):[ \t]*$', text, flags=re.M)
    names = blocks[1::2]
    require(len(names) == len(set(names)), 'duplicate original job definition')
    return dict(zip(names, blocks[2::2]))


def pipeline_tier(raw):
    """'single' (one qualify stage) or 'tiered' (build -> qualify); anything else fails closed."""
    text = raw.decode('utf-8')
    require(not re.search(r'^(?:include|default|workflow_defaults):', text, re.M)
            and not re.search(r'^\s*(?:needs|dependencies|<<):', text, re.M)
            and not re.search(r'^[^#\n]*[&*][A-Za-z_]', text, re.M),
            'unrecognized original job prerequisite graph')
    if LEGACY_STAGES.search(text):
        return 'single'
    require(TIERED_STAGES.search(text), 'unrecognized original job prerequisite graph')
    return 'tiered'


def plain_rules(block):
    """Rules may only select (or exclude with `when: never`); never run after failures."""
    require(not re.search(r'^  when:', block, re.M), 'job-level when changes prerequisites')
    match = re.search(r'^  rules:\n((?:(?:    .*)?\n)*)', block, re.M)
    rules = match[1] if match else ''
    require(all(value == 'never' for value in re.findall(r'^\s*(?:- )?when:\s*(\S+)', rules, re.M)),
            'rule-level when changes prerequisites')


def independent_qualification_job(raw, job):
    """Recognize only the approved job inheritance grammars.

    single: one qualify stage, jobs extend native-qualification.
    tiered: every job extends the shared .controller template; core-build alone
    occupies the build stage, so a qualify job's prerequisite is exactly a
    successful core-build of the same pipeline (core) or nothing (plugins).
    Unknown DAG/include/default syntax fails closed, requiring fresh execution or
    an explicit controller implementation of that new prerequisite contract.
    """
    text = raw.decode('utf-8')
    tier = pipeline_tier(raw)
    if tier == 'single':
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
    blocks = pipeline_blocks(text)
    require(job in TIERED_JOBS and job in blocks and '.controller' in blocks, 'original job definition missing')
    template = blocks['.controller']
    require(not re.search(r'^  (?:stage|extends|rules|when):', template, re.M),
            'controller template prerequisite graph changed')
    stages = {}
    for name, block in blocks.items():
        stage = re.findall(r'^  stage: (\S+)$', block, re.M)
        require(len(stage) <= 1 and not re.search(r'^  stage:(?! \S+$)', block, re.M),
                'ambiguous job stage')
        if stage:
            stages[name] = stage[0]
    require(stages.get(job) == TIERED_JOBS[job], 'job prerequisite stage changed')
    prerequisites = [name for name, stage in stages.items() if stage == 'build']
    require(prerequisites == ['core-build'], 'build-stage prerequisite set changed')
    for name in {job, *prerequisites}:
        block = blocks[name]
        require(re.findall(r'^  extends: (.*)$', block, re.M) == ['.controller'],
                'job prerequisite inheritance changed')
        plain_rules(block)
    # Shared rule sets are spliced into job rules with !reference.
    require(all(value == 'never' for value in re.findall(r'^\s*(?:- )?when:\s*(\S+)',
                                                         blocks.get('.rules', ''), re.M)),
            'shared rule-level when changes prerequisites')
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


RECEIPT_SCHEMAS = {'native-qualification': 'busbar.protected-native-admission/1',
                   'core-build': 'busbar.core-build/1',
                   'core-conformance': 'busbar.protected-conformance/1',
                   'external-conformance': 'busbar.protected-conformance/1'}


def dev_required_jobs(repository, tier, required_external=None):
    """Jobs a protected dev execution of this repository must pass under its policy."""
    if repository == CORE and tier == 'tiered':
        return set(CORE_DEV_JOBS)
    required = {'native-qualification', 'security-scans'}
    if required_external:
        required.add(required_external)
    return required


def validate_core_build(original, receipt, artifact, context, policy):
    """Complete core-build validation: the retained binary is the certified record's bytes."""
    from native_certified import BUILD, LINT_ARGS, LINTER, SCHEMA
    require(original['repository'] == CORE and original['job'] == 'core-build'
            and receipt.get('schema') == SCHEMA, 'core-build validator scope differs')
    record = receipt.get('certified_binary')
    require(isinstance(record, dict) and re.fullmatch('[0-9a-f]{64}', str(record.get('sha256')))
            and receipt.get('binary_sha256') == record['sha256']
            and record.get('command') == ['cargo', *BUILD] and record.get('rustc_wrapper') == LINTER
            and record.get('clippy_args') == LINT_ARGS and record.get('path') == 'busbar',
            'original core-build certifies no binary')
    binary = artifact('busbar')
    require(digest(binary) == record['sha256'] and len(binary) == record.get('bytes'),
            'original certified binary differs from its receipt')
    development = receipt.get('development_artifact') or {}
    require(digest(artifact('development-artifact/receipt.json'))
            == record.get('development_artifact_receipt_sha256') == development.get('sha256'),
            'original development artifact receipt differs')
    return True


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
                paths.add('scripts/security/scan.py')
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
            pipeline_yaml = (base / 'ci/architecture-pipeline.yml').read_bytes()
            independent_qualification_job(pipeline_yaml, request['job'])
            info['independent_job'] = True
            info['tier'] = pipeline_tier(pipeline_yaml)
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
        required = dev_required_jobs(original['repository'], policy.get('tier', 'single'),
                                     policy['required_external'])
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
                        schema=RECEIPT_SCHEMAS.get(original['job'], 'busbar.protected-conformance/1'))
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
        if original['job'] == 'core-conformance' and policy.get('tier') == 'tiered':
            self._judged_build(base, pipeline, jobs, receipt)
        context = dict(original=original, project=project, pipeline=pipeline, job=job,
                       protected_refs=protected_refs,
                       policy=policy, receipt_bytes=receipt_bytes, artifact_bytes=artifact_bytes,
                       artifact_sha256=digest(artifact_bytes), receipt_sha256=digest(receipt_bytes))
        return context

    def _judged_build(self, base, pipeline, jobs, receipt):
        """Tiered core conformance credits only the certified build of its own pipeline."""
        builds = [j for j in jobs if j.get('name') == 'core-build']
        require(len(builds) == 1 and builds[0].get('status') == 'success'
                and builds[0].get('allow_failure') is False and type(builds[0].get('id')) is int,
                'original conformance pipeline has no single successful core-build')
        build = json.loads(self._raw(base + '/jobs/' + str(builds[0]['id'])
                                     + '/artifacts/boundary-evidence/receipt.json'))
        record = (build.get('certified_binary') if isinstance(build, dict) else None) or {}
        judged = receipt.get('certified_binary') or {}
        require(isinstance(judged, dict) and build.get('schema') == RECEIPT_SCHEMAS['core-build']
                and build.get('status') == 'pass' and build.get('job_id') == str(builds[0]['id'])
                and build.get('pipeline_id') == str(pipeline['id']) and build.get('source') == pipeline['sha']
                and re.fullmatch('[0-9a-f]{64}', str(record.get('sha256')))
                and build.get('binary_sha256') == record['sha256'] == receipt.get('binary_sha256')
                == judged.get('sha256') and judged.get('bytes') == record.get('bytes')
                and judged.get('core_build_job_id') == builds[0]['id']
                and judged.get('pipeline_id') == pipeline['id'],
                "original conformance did not judge its pipeline's certified core-build binary")

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
        tools = context['policy']['tools']
        scanner_sha256 = context['policy']['files']['scripts/security/scan.py']
        semantic_database_identity(database, tools, self.now(), scanner_sha256=scanner_sha256)
        self.database_witness = dict(database=database, original=dict(original),
                                     receipt_sha256=context['receipt_sha256'],
                                     artifact_sha256=context['artifact_sha256'],
                                     tools=tools, scanner_sha256=scanner_sha256)
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
            require(self.database_witness is not None,
                    'authenticated current security database witness missing')
            # Preserve both raw metadata hashes in their authenticated receipts.
            # Only the known pinned offline scanner contract may compare actual
            # advisory bytes/freshness independently of download-local metadata.
            original_semantics = semantic_database_identity(database, context['policy']['tools'],
                self.now(), scanner_sha256=context['policy']['files']['scripts/security/scan.py'])
            witness_semantics = semantic_database_identity(self.database_witness['database'],
                self.database_witness['tools'], self.now(),
                scanner_sha256=self.database_witness['scanner_sha256'])
            require(original_semantics == witness_semantics,
                    'original security database differs from authenticated fresh witness')
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
        if original['job'] == 'core-build':
            require(all(s.get('status') == 'pass' and s.get('exit_code') == 0 for s in steps),
                    'original core-build checks did not pass')
            from admission import CORE_BUILD_STEPS
            require(set(CORE_BUILD_STEPS) <= set(names), 'original core-build omits required checks')
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


# Complete owner runtime and release validation; never installed in candidate CI.

import ast
import itertools
import importlib.util
import xml.etree.ElementTree as ET
import input_identity as identity

REPOSITORY = "GetBusbar/busbar-release"

def verify_release_dispatch(raw):
    """Recognize the existing direct native driver branch; no candidate imports."""
    tree = ast.parse(raw)
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    require('qualify' in functions and 'main' in functions, 'native driver entry points missing')
    shape = lambda node: ast.dump(node, include_attributes=False)
    expected_main = ast.parse('def main():\n with interruption_signals():\n  qualify()').body[0]
    require(shape(functions['main']) == shape(expected_main), 'native main dispatch changed')
    tries = [node for node in functions['qualify'].body if isinstance(node, ast.Try)]
    require(len(tries) == 1, 'native qualification control flow changed')
    starts = [node for node in tries[0].body if isinstance(node, ast.If)
              and shape(node.test) == shape(ast.parse('args.external_conformance', mode='eval').body)]
    require(len(starts) == 1, 'native qualification dispatch missing')
    branch = starts[0]
    for expression in ('args.external_conformance', 'args.conformance_only',
                       "qualification.repository == 'GetBusbar/busbar'",
                       "qualification.repository == 'GetBusbar/busbar-release'"):
        require(shape(branch.test) == shape(ast.parse(expression, mode='eval').body),
                'native release dispatch condition changed')
        if expression.endswith("'GetBusbar/busbar-release'"):
            expected = ast.parse('from native_plugins import qualify_generator\nqualify_generator(qualification)').body
            require([shape(node) for node in branch.body] == [shape(node) for node in expected],
                    'native release qualification dispatch missing')
        else:
            require(len(branch.orelse) == 1 and isinstance(branch.orelse[0], ast.If),
                    'native release dispatch chain changed')
            branch = branch.orelse[0]
    return sha(raw)


RELEASE_POLICY_CODE = """
import hashlib, json, sys, tomllib
from pathlib import Path
base=Path(sys.argv[1]); sys.path.insert(0,str(base/'scripts/architecture'))
import admission, native_policy, check, product_artifacts
assert all(Path(m.__file__).resolve().is_relative_to(base.resolve()) for m in
           (admission,native_policy,check,product_artifacts))
data=json.load(sys.stdin)
admission.validate_protection(data['project_rules'],data['group_rules'],set(data['merge_users']))
p=tomllib.loads((base/'ci/architecture.toml').read_text())
repo=data['repository']
assert repo=='GetBusbar/busbar-release'
assert hashlib.sha256((base/'scripts/architecture/native.py').read_bytes()).hexdigest()==data['release_dispatch_sha256']
if data.get('security') is not None:
 admission.validate_security_scans(data['security'],repo,
  (base/'ci/security/public-secret-fixtures.json').read_bytes())
print(json.dumps({'required_external':admission.required_conformance_job(repo,p),
 'owner_suites':sorted(native_policy.conformance_rows(repo,p,trusted=base)),
 'native_settings':native_policy.native_settings(repo,p)}))
"""


class ReleaseResolver(Resolver):
    """Only the existing release dispatch supplements original policy membership."""
    def _policy(self, request, project_rules, group_rules, receipt):
        if request['repository'] != REPOSITORY:
            return super()._policy(request, project_rules, group_rules, receipt)
        require(request['policy'] in self.trusted_policies,
                'release original policy is not controller approved')
        require(request['job'] in ('native-qualification', 'security-scans'),
                'unknown release qualification job')
        with tempfile.TemporaryDirectory(prefix='original-release-policy-', dir=self.scratch) as name:
            base = Path(name)
            hashes = {}
            paths = set(POLICY_FILES) | {'scripts/architecture/native.py'}
            security = request['job'] == 'security-scans'
            if security:
                paths.add('scripts/security/scan.py')
                paths.update(path for path in self.objects.tree(CORE, request['policy'])
                             if path.startswith('ci/security/') and path.count('/') == 2)
            for path in sorted(paths):
                raw = self.objects.blob(CORE, request['policy'], path)
                target = base / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                hashes[path] = sha(raw)
            dispatch = verify_release_dispatch((base / 'scripts/architecture/native.py').read_bytes())
            result = subprocess.run([sys.executable, '-I', '-B', '-c', RELEASE_POLICY_CODE, str(base)],
                                    input=json.dumps(dict(repository=request['repository'],
                                        project_rules=project_rules, group_rules=group_rules,
                                        merge_users=sorted(self.merge_users),
                                        release_dispatch_sha256=dispatch,
                                        security=receipt if security else None)),
                                    capture_output=True, text=True, timeout=60)
            require(result.returncode == 0, 'immutable original release policy rejected evidence context')
            info = json.loads(result.stdout)
            info['files'] = hashes
            independent_qualification_job((base / 'ci/architecture-pipeline.yml').read_bytes(), request['job'])
            info['independent_job'] = True
            if security:
                info['tools'] = json.loads((base / 'ci/security/tools.json').read_bytes())
            return info

def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def summary(raw):
    return [dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'), map(int, row)))
            for row in re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', raw.decode())]



def verify_confinement(parent, bootstrap, policy):
    boundary = parent['execution_boundary']
    require(boundary['mode'] == 'docker-confined' and boundary['isolated'] is True
            and boundary['confinement_configured'] is True
            and boundary['observer'] == 'protected-controller'
            and boundary['release_eligible'] is False, 'development confinement differs')
    rows = boundary['observations']
    require(rows and all(row['inspected'] is True and row['disposed'] is True
            and row['network'] == 'none' and row['storage'] and row['user_namespace']
            and row['configuration_sha256'] == boundary['configuration_sha256']
            and row.get('swap_bound') and row['state_before_disposal']['Running'] is False
            and row['state_before_disposal']['OOMKilled'] is False for row in rows),
            'candidate confinement/disposal observation missing or failed')
    for row in rows:
        swap = row['swap_bound']
        require(swap['effective_swap_bytes'] == 0
                and swap['requested_memory_swap_bytes'] == row['resources']['memory_bytes']
                and ((swap['mechanism'] == 'docker-memory-swap-limit'
                      and swap['observed_memory_swap_bytes'] == row['resources']['memory_bytes'])
                     or (swap['mechanism'] == 'kernel-zero-swap-capacity'
                         and swap['after_disposal']['effective_swap_bytes'] == 0)),
                'candidate zero-swap observation differs')
    require(bootstrap['schema'] == 'busbar.native-ci-root-bootstrap/1'
            and bootstrap['policy_revision'] == policy and bootstrap['status'] == 'pass'
            and bootstrap['runtime_sha256'] == boundary['approved_configuration_sha256']
            and bootstrap['root_controller'] is True and bootstrap['candidate_privileged'] is False
            and bootstrap['private_daemon_mount_and_network_namespaces'] is True
            and bootstrap['candidate_containers_disposed'] is True
            and bootstrap['storage_disposed'] is True, 'bootstrap confinement/disposal differs')
    return {'candidate_observations': len(rows), 'all_inspected_and_disposed': True,
            'candidate_containers_disposed': True, 'storage_disposed': True,
            'observer': boundary['observer'], 'release_producer_attestation': False}


class ReleaseValidator:
    def __init__(self, objects):
        self.objects = objects

    def __call__(self, original, receipt, artifact, context, policy):
        self.validate(original, receipt, artifact, context, policy)
        return True

    def validate(self, original, receipt, artifact, context, policy):
        require(original['repository'] == REPOSITORY
                and original['job'] == 'native-qualification', 'release native validator scope differs')
        SOURCE, POLICY, SDK = (original[key] for key in ('source', 'policy', 'sdk'))
        require(original['host'] == POLICY, 'original release host/policy differs')
        require(context['original'] == original and context['policy'] == policy,
                'authenticated original context differs')
        job = context['job']
        require(job['name'] == 'native-qualification' and job['allow_failure'] is False,
                'original native job is not mandatory')
        require(context['project']['id'] == 29
                and context['project']['path_with_namespace'] == REPOSITORY,
                'original release project differs')
        archive_bytes = context['artifact_bytes']
        require(sha(archive_bytes) == context['artifact_sha256']
                and sha(context['receipt_bytes']) == context['receipt_sha256'],
                'authenticated archive/receipt digest differs')
        ROOT_URL = 'https://github.com/GetBusbar/busbar-release/-/jobs/' + str(job['id'])
        require(job['id'] == int(receipt['job_id']) and job['status'] == 'success' and job['pipeline']['id'] == int(receipt['pipeline_id'])
                and job['pipeline']['project_id'] == 29 and job['commit']['id'] == SOURCE
                and job['pipeline']['sha'] == SOURCE, 'server job identity/status differs')
        require(len(archive_bytes) == job['artifacts_file']['size'], 'archive byte count differs')
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zipped:
            entries = zipped.infolist()
            names = [entry.filename for entry in entries]
            require(len(names) == len(set(names)) and len(names) < 10000
                    and sum(entry.file_size for entry in entries) < 64 * 1024**2, 'archive bounds or uniqueness differ')
            def read(name):
                raw = zipped.read('boundary-evidence/' + name)
                require(raw == artifact(name), 'artifact reader differs from authenticated full archive')
                return raw
            receipt_bytes = read('receipt.json')
            require(receipt_bytes == context['receipt_bytes'] and json.loads(receipt_bytes) == receipt, 'original receipt bytes differ')
            require(receipt['schema'] == 'busbar.protected-native-admission/1'
                    and receipt['repository'] == 'GetBusbar/busbar-release'
                    and receipt['source'] == SOURCE and receipt['policy_revision'] == POLICY
                    and receipt['sdk_revision'] == SDK and receipt['host_revision'] == POLICY
                    and receipt['status'] == 'pass' and receipt['source_unchanged'] is True
                    and str(receipt['job_id']) == str(job['id']) and str(receipt['pipeline_id']) == str(context['pipeline']['id']),
                    'protected parent identity/status differs')
            require(receipt['config_uri'] == 'github.com/GetBusbar/busbar-release//ci/architecture-pipeline.yml@GetBusbar/busbar:' + POLICY + '@refs/heads/dev',
                    'protected configuration binding differs')
            require(receipt['source_tree'] == self.objects.git(REPOSITORY, 'rev-parse', SOURCE + '^{tree}').decode().strip(), 'source tree differs')
            require(receipt['policy_sha256'] == sha(self.objects.blob(CORE, POLICY, 'ci/architecture.toml')), 'policy bytes differ')
            require(json.loads(self.objects.blob(CORE, POLICY, 'scripts/ci-product-pins.json'))['sdk'] == SDK, 'policy SDK differs')
            source_hash = sha(self.objects.git(REPOSITORY, 'archive', '--format=tar', SOURCE))
            require(source_hash == receipt['source_archive_sha256'], 'exact release source archive differs')
            kinds = ('auth', 'secret', 'store', 'hook', 'export', 'plane', 'transport')
            variants = ('open-source', 'enterprise')
            stages = ('fmt', 'metadata', 'clippy', 'build', 'native-doors', 'architecture')
            expected_steps = {'fmt', 'clippy', 'tooling-runtime', 'tooling-doctests', 'render-canonical'}
            expected_steps.update('-'.join((variant, kind, stage)) for variant, kind, stage in itertools.product(variants, kinds, stages))
            steps = {step['name']: step for step in receipt['steps']}
            require(len(steps) == len(receipt['steps']) == 89 and set(steps) == expected_steps, 'stage roster differs')
            hash_checks = []
            for name, step in steps.items():
                require(step['status'] == 'pass' and step['exit_code'] == 0, 'nonpassing stage: ' + name)
                for stream in ('stdout', 'stderr'):
                    filename = name + '.' + stream
                    require(sha(read(filename)) == step[stream + '_sha256'], 'retained log differs: ' + filename)
                    hash_checks.append(filename)
            runtime_xml = read('tooling-runtime.xml')
            require(sha(runtime_xml) == steps['tooling-runtime']['junit_sha256'], 'tooling JUnit digest differs')
            xml = ET.fromstring(runtime_xml)
            cases = list(xml.iter('testcase'))
            require(len(cases) == 1212 and not list(xml.iter('failure')) and not list(xml.iter('error'))
                    and not list(xml.iter('skipped')), 'executed tooling test outcome differs')
            runtime_log = read('tooling-runtime.stderr').decode()
            require(re.search(r'1212 tests run: 1212 passed, 2 skipped', runtime_log), 'runner summary differs')
            generated = {(row['distribution'], row['kind']): row for row in receipt['generated_plugins']}
            require(len(generated) == len(receipt['generated_plugins']) == 14
                    and set(generated) == set(itertools.product(variants, kinds)), 'generated fixture roster differs')
            fixtures = []
            for (variant, kind), result in generated.items():
                label = variant + '-' + kind
                architecture = json.loads(read(label + '-architecture.json'))
                require({key: value for key, value in result.items() if key not in ('kind', 'distribution')} == architecture,
                        'generated architecture artifact differs from parent: ' + label)
                owner = 'GetBusbar' if variant == 'open-source' else 'BusbarInc'
                require(architecture['repository'] == owner + '/busbar-' + kind + '-boundary-example'
                        and re.fullmatch('generated-sha256:[0-9a-f]{64}', architecture['source'])
                        and architecture['trusted_source_check'] is True and architecture['source_roots'] == 2
                        and architecture['release_eligible'] is False, 'generated subject/architecture result differs')
                observations = architecture['candidate_execution']
                require(observations and all(row['inspected'] is True and row['disposed'] is True
                    and row['network'] == 'none' and row['configuration_sha256'] == receipt['execution_boundary']['configuration_sha256']
                    and row['state_before_disposal']['ExitCode'] == 0 and not row['state_before_disposal']['OOMKilled']
                    for row in observations), 'generated confined execution evidence differs')
                doors = summary(read(label + '-native-doors.stdout'))
                require(doors == [{'passed': 3, 'failed': 0, 'ignored': 0, 'measured': 0, 'filtered_out': 0}], 'native-door test roster differs')
                fixtures.append({'distribution': variant, 'kind': kind, 'repository': architecture['repository'],
                    'generated_source': architecture['source'], 'architecture_policy_sha256': architecture['policy_sha256'],
                    'architecture_receipt_sha256': sha(read(label + '-architecture.json')),
                    'native_door_tests_passed': 3, 'native_door_tests_failed': 0,
                    'architecture_guard_test_summaries': summary(read(label + '-architecture.stdout')),
                    'confined_architecture_invocations': len(observations),
                    'artifact_link': ROOT_URL + '/artifacts/file/boundary-evidence/' + label + '-architecture.json',
                    'native_doors_link': ROOT_URL + '/artifacts/file/boundary-evidence/' + label + '-native-doors.stdout'})
            require(summary(read('render-canonical.stdout')) == [{'passed': 1, 'failed': 0, 'ignored': 0, 'measured': 0, 'filtered_out': 0}],
                    'explicit canonical scaffold test differs')
            doc = summary(read('tooling-doctests.stdout'))
            require(doc and all(row['failed'] == 0 for row in doc), 'doctest command outcome differs')
            require(receipt['execution_boundary']['release_eligible'] is False, 'unexpected release eligibility claim')
            bootstrap_bytes = read('bootstrap.json')
            confinement = verify_confinement(receipt, json.loads(bootstrap_bytes), POLICY)
            result = {'status': 'verified-development-tooling-checkpoint', 'project': 29, 'pipeline': job['pipeline']['id'], 'job': job['id'],
                'source': SOURCE, 'policy': POLICY, 'host': POLICY, 'sdk': SDK, 'source_unchanged': True,
                'source_tree': receipt['source_tree'], 'source_archive_sha256': source_hash,
                'parent_receipt_sha256': sha(receipt_bytes), 'artifact_archive_sha256': sha(archive_bytes),
                'artifact_archive_bytes': len(archive_bytes), 'artifacts_expire_at': job['artifacts_expire_at'],
                'finished_at': job['finished_at'], 'duration_seconds': job['duration'],
                'stage_count': 89, 'all_stages_passed': True, 'retained_step_log_hashes_verified': len(hash_checks),
                'confinement': confinement, 'bootstrap_sha256': sha(bootstrap_bytes),
                'tooling_tests': {'executed': 1212, 'passed': 1212, 'failed': 0, 'runner_reported_skipped': 2,
                                 'junit_sha256': sha(runtime_xml)},
                'canonical_render_tests_passed': 1, 'native_door_tests_passed': 42,
                'doctests': {'command_passed': True, 'executed': sum(row['passed'] for row in doc)},
                'generated_fixtures': fixtures,
                'links': {'job': ROOT_URL, 'archive_download': ROOT_URL + '/artifacts/download',
                          'parent_receipt': ROOT_URL + '/artifacts/file/boundary-evidence/receipt.json',
                          'tooling_junit': ROOT_URL + '/artifacts/file/boundary-evidence/tooling-runtime.xml'},
                'limits': {'release_eligible': False, 'production_signing': False, 'supported_lifetime_retention_verified': False,
                           'core_binary_sbom_proof': False, 'current_release_source_qualified': True},
                'scope': 'Original release native tooling and14 generated Rust scaffold fixtures only; no current-policy equivalence or core binary/SBOM claim.'}
            return result


class CanonicalObjects(identity.GitObjects):
    """Batch immutable blob reads without Git checkout/filter/candidate execution."""
    def blob(self, repository, revision, path):
        key = repository, revision, path
        if key not in self._blobs:
            tree = self.tree(repository, revision)
            identity.require(path in tree, 'required immutable object path missing: ' + path)
            rows = list(tree.items())
            for offset in range(0, len(rows), 512):
                batch = rows[offset:offset + 512]
                payload = ''.join(row['blob'] + '\n' for _, row in batch).encode()
                result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null',
                    '-c', 'core.fsmonitor=false', '-C', str(self.repositories[repository]),
                    'cat-file', '--batch'], input=payload, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, check=True)
                cursor = 0
                for name, entry in batch:
                    end = result.stdout.index(b'\n', cursor)
                    oid, kind, size = result.stdout[cursor:end].decode().split()
                    identity.require(oid == entry['blob'] and kind == 'blob', 'immutable blob response differs')
                    cursor = end + 1
                    raw = result.stdout[cursor:cursor + int(size)]
                    identity.require(len(raw) == int(size) and result.stdout[cursor + int(size):
                                     cursor + int(size) + 1] == b'\n', 'truncated immutable blob')
                    self._blobs[repository, revision, name] = raw
                    cursor += int(size) + 1
                identity.require(cursor == len(result.stdout), 'unexpected immutable blob response')
        return self._blobs[key]


class CanonicalReads:
    """Read once per owner session, retaining exact response bytes for its proof.

    This cache is deliberately empty on every construction. Existing disk files
    are overwritten after canonical reads, never treated as authenticated input.
    No method can mutate the forge. Live status comes exclusively from D's file.
    """
    def __init__(self, api, directory):
        self.api, self.directory = api, Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.records = {}

    def _read(self, kind, path, fetch):
        key = kind + ':' + path
        if key not in self.records:
            data = fetch()
            raw = data if kind == 'raw' else identity.encoded(data)
            target = self.directory / digest(key.encode())
            target.write_bytes(raw)
            self.records[key] = dict(path=str(target), sha256=digest(raw), bytes=len(raw))
        record = self.records[key]
        raw = Path(record['path']).read_bytes()
        identity.require(digest(raw) == record['sha256'], 'canonical session response bytes changed')
        return raw if kind == 'raw' else json.loads(raw)

    def request(self, path, method='GET', body=None):
        identity.require(method == 'GET' and body is None, 'owner context is read-only')
        return self._read('json', path, lambda: self.api.request(path))

    json = request

    def all(self, path):
        return self._read('all', path, lambda: self.api.all(path))

    def raw(self, path):
        def fetch():
            identity.require(self.api.server == 'https://github.com', 'canonical forge required')
            request = urllib.request.Request(self.api.server + '/api/v4/' + path,
                                            headers={'PRIVATE-TOKEN': self.api.token})
            with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
                raw = response.read(1024**3 + 1)
            identity.require(len(raw) <= 1024**3, 'canonical artifact exceeds bound')
            return raw
        return self._read('raw', path, fetch)



def expected_loader(objects, normalizer):
    """Build original validation expectations from immutable Git objects only."""
    def load(original):
        original = identity.checked_request(original)
        repository, source, policy, host = (original[key] for key in ('repository', 'source', 'policy', 'host'))
        identity.require(repository != 'GetBusbar/busbar-release',
                         'dedicated complete release tooling validator unavailable; fresh required')
        configuration = tomllib.loads(objects.blob(identity.CORE, policy, 'ci/architecture.toml').decode())
        source_tree = objects.tree(repository, source)
        vector = json.loads(objects.blob(identity.CORE, host, 'scripts/ci-product-pins.json'))
        identity.require(vector['sdk'] == original['sdk'], 'original SDK differs from original host')
        result = {key: original[key] for key in ('source', 'host', 'sdk')}
        if repository != identity.CORE:
            identity.require(repository in configuration['repositories'], 'original owner absent from policy')
            is_c = configuration['repositories'][repository].get('language') == 'c'
            result['c'] = is_c
            if not is_c:
                identity.require('Cargo.lock' in source_tree, 'original owner lock missing')
                result['lock'] = digest(objects.blob(repository, source, 'Cargo.lock'))
            return result
        identity.require(source == host, 'original core source and host differ')
        result.update(vector=vector, root_lock=digest(objects.blob(identity.CORE, source, 'Cargo.lock')),
                      distribution_lock=digest(objects.blob(identity.CORE, source, 'dist/default/Cargo.lock')))
        suites = objects.blob(identity.CORE, source, 'testing/conformance/suites.tsv').decode()
        result['conformance_suites'] = [line.split('\t', 1)[0] for line in suites.splitlines()
                                        if line.strip() and not line.lstrip().startswith('#')]
        inputs = ('testing/conformance/run.sh', 'testing/conformance/tools.sh',
                  'testing/conformance/suites.tsv', 'testing/conformance/capabilities.py', '.busbar-ref', 'Cargo.toml',
                  'Cargo.lock', 'rust-toolchain', 'rust-toolchain.toml')
        result['conformance_inputs'] = {path: digest(objects.blob(identity.CORE, source, path))
                                        for path in inputs if path in source_tree}
        coverage_bytes = objects.blob(identity.CORE, source, 'conformance/ci-coverage.json')
        coverage = json.loads(coverage_bytes)
        identity.require(coverage['schema'] == 'busbar.conformance.ci-coverage/1', 'original coverage unknown')
        result['coverage_sha256'] = digest(coverage_bytes)
        result['release_stages'] = {name: coverage['suites'].get(name, {}).get('stage')
                                    for name in ('slsa-verifier', 'sigstore')}
        engineering = {path for path in source_tree if Path(path).parent.as_posix() in
                       ('scripts/release', 'scripts/security') and path.endswith('.py')}
        engineering.update(path for path in normalizer.RELEASE_INPUTS if path in source_tree)
        result['release_engineering_inputs'] = {path: digest(objects.blob(identity.CORE, source, path))
                                               for path in sorted(engineering)}
        return result
    return load


class OwnerRuntime:
    """Portable owner discovery and authentication for the maintained selector.

    Credentials stay in the existing Git credential helper and optional group
    reader. Only immutable canonical Git objects are materialized; candidate
    checkouts, hooks, build scripts and candidate-provided proof code never run.
    """
    def __init__(self, api, group_api, work_dir, *, policy=None, limit=20):
        from admission import encoded as urlquote, validate_protection
        require(api.server == 'https://github.com', 'canonical forge required')
        require(type(limit) is int and 1 <= limit <= 20, 'discovery limit must be between 1 and 20')
        self.api, self.limit, self.principals = api, limit, {6, 8}
        self.work = Path(work_dir).resolve()
        self.work.mkdir(parents=True, exist_ok=True)
        self.session = Path(tempfile.mkdtemp(prefix='qualification-', dir=self.work))
        self.reads = CanonicalReads(api, self.session / 'api')
        self.groups = CanonicalReads(group_api, self.session / 'groups')
        self.objects = CanonicalObjects({})
        self.fetched, self.approved = set(), set()
        self.projects, self.rows, self.originals, self.observations = {}, [], {}, {}
        self.live, self.rejections = {}, []
        core = self.reads.request('projects/' + urlquote(CORE))
        branch = self.reads.request('projects/' + str(core['id']) + '/repository/branches/dev')
        require(core.get('path_with_namespace') == CORE and branch.get('protected') is True,
                'canonical core development branch is not protected')
        self.host = branch['commit']['id']
        self.policy = policy or self.host
        self.ensure(CORE, self.policy)
        self.ensure(CORE, self.host)
        self.approved.add(self.policy)
        configuration = tomllib.loads(self.objects.blob(CORE, self.policy, 'ci/architecture.toml').decode())
        vector = json.loads(self.objects.blob(CORE, self.host, 'scripts/ci-product-pins.json'))
        self.sdk = vector['sdk']
        self.ensure(CORE, self.sdk)
        names = set(configuration['repositories']) | {CORE, REPOSITORY}
        self.group_rules = {name: self.groups.all('groups/' + urlquote(name) + '/protected_branches')
                            for name in {repository.split('/')[0] for repository in names}}
        for name in sorted(names, key=lambda value: (value != CORE, value != REPOSITORY, value)):
            identity.checked_request(dict(repository=name, source=self.host, host=self.host,
                policy=self.policy, sdk=self.sdk, job='native-qualification'))
            project = self.reads.request('projects/' + urlquote(name))
            require(project.get('path_with_namespace') == name and type(project.get('id')) is int,
                    'canonical owner identity differs')
            require(not name.startswith('BusbarInc/') or project.get('visibility') == 'private',
                    'private owner visibility differs')
            base = 'projects/' + str(project['id'])
            validate_protection(self.reads.all(base + '/protected_branches'),
                                self.group_rules[name.split('/')[0]], self.principals)
            head = self.reads.request(base + '/repository/branches/dev')
            require(head.get('protected') is True, 'owner dev branch is not protected')
            require(project.get('merge_method') == 'ff'
                    and project.get('only_allow_merge_if_pipeline_succeeds') is True
                    and project.get('allow_merge_on_skipped_pipeline') is False
                    and project.get('ci_pipeline_variables_minimum_override_role') == 'no_one_allowed',
                    'protected admission settings differ')
            source = head['commit']['id']
            require(name != CORE or source == self.host, 'core moved during owner discovery')
            self.ensure(name, source)
            self.projects[name] = project
            self.rows.append(dict(repository=name, source=source, project=project['id'],
                                  host=self.host, sdk=self.sdk, policy=self.policy))
        # A changed assembled owner must first be included in the committed
        # assembly. Otherwise a green old core cannot qualify its new component.
        heads = {row['repository']: row['source'] for row in self.rows}
        for pin in [*vector['products'], vector['c_witness']]:
            require(heads.get('GetBusbar/' + pin['repo']) == pin['commit'],
                    'canonical owner head differs from assembly pins; refresh the assembly before qualification')
        self.normalizer, self.normalizer_origin = self.load_normalizer()
        marketing = MarketingValidator(self.normalizer, expected_loader(self.objects, self.normalizer))
        release = ReleaseValidator(self.objects)
        def validate(original, receipt, artifact, context, original_policy):
            validator = (release if original['repository'] == REPOSITORY else
                         validate_core_build if original['job'] == 'core-build' else marketing)
            return validator(original, receipt, artifact, context, original_policy)
        self.resolver = ReleaseResolver(self.reads, group_api=self.groups, objects=self.objects,
            current_policy=self.policy, merge_users=self.principals, owner_users=self.principals,
            scratch=self.session / 'validators', full_validator=validate,
            trusted_policies={self.policy}, selector_policies={})

    def ensure(self, repository, revision):
        require(re.fullmatch(r'(?:GetBusbar|BusbarInc)/[A-Za-z0-9_.-]+', repository or '')
                and re.fullmatch('[0-9a-f]{40}', revision or ''), 'immutable canonical object required')
        if repository not in self.objects.repositories:
            store = self.work / 'objects' / repository
            store.mkdir(parents=True, exist_ok=True)
            if not (store / 'HEAD').exists():
                subprocess.run(['git', 'init', '--bare', '--quiet', str(store)], check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.objects.repositories[repository] = store
        if (repository, revision) not in self.fetched:
            result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                '-C', str(self.objects.repositories[repository]), 'fetch', '--quiet', '--no-tags',
                '--depth=128', self.api.server + '/' + repository + '.git', revision],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            require(result.returncode == 0, 'canonical immutable object fetch failed: ' + repository)
            require(self.objects.git(repository, 'rev-parse', revision + '^{commit}').decode().strip() == revision,
                    'canonical fetched commit differs')
            self.fetched.add((repository, revision))

    def approve_policy(self, revision):
        """Old executable validators must be approved before subprocess loading."""
        if revision in self.approved:
            return
        self.ensure(CORE, revision)
        for name in ('admission.py', 'native_policy.py', 'check.py', 'product_artifacts.py'):
            path = 'scripts/architecture/' + name
            before, after = (self.objects.blob(CORE, ref, path) for ref in (revision, self.policy))
            equal = before == after
            if not equal and name == 'product_artifacts.py':
                project = getattr(identity, 'default_artifact_reader_identity', None)
                equal = callable(project) and isinstance(project(before), dict) and project(before) == project(after)
            require(equal, 'original executable validator differs from approved current policy')
        result = subprocess.run(['git', '-C', str(self.objects.repositories[CORE]), 'merge-base',
                                 '--is-ancestor', revision, self.policy],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(result.returncode == 0, 'original policy ancestry is unproven within bounded canonical history')
        self.approved.add(revision)

    def load_normalizer(self):
        from admission import encoded as urlquote, validate_protection
        name = 'BusbarInc/marketing'
        project = self.reads.request('projects/' + urlquote(name))
        require(project.get('path_with_namespace') == name and project.get('visibility') == 'private',
                'canonical validation controller identity differs')
        base = 'projects/' + str(project['id'])
        groups = self.groups.all('groups/BusbarInc/protected_branches')
        validate_protection(self.reads.all(base + '/protected_branches'), groups, self.principals)
        branch = self.reads.request(base + '/repository/branches/dev')
        require(branch.get('protected') is True, 'validation controller dev is not protected')
        revision = branch['commit']['id']
        self.ensure(name, revision)
        path = 'ci/scripts/collect-native-results.py'
        # Preserve the validator's repository-relative import layout. Its
        # publisher is executable validation code too, so bind both files to
        # the same authenticated immutable marketing revision.
        root = self.session / 'normalizer'
        files = {}
        for relative in (path, 'scripts/publish-check-results.py'):
            raw = self.objects.blob(name, revision, relative)
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            files[relative] = digest(raw)
        target = root / path
        spec = importlib.util.spec_from_file_location('protected_original_normalizer', target)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, dict(repository=name, source=revision, path=path,
                            sha256=files[path], files=files)

    def discover(self, rows):
        """One bounded snapshot; live jobs defer work and never count as passes."""
        from qualification_selection import LIVE, requirements
        witnesses = []
        for row in rows:
            name, base = row['repository'], 'projects/' + str(row['project'])
            self.originals[name] = []
            required = requirements(row, self.objects)
            listed = self.reads.request(base + '/pipelines?ref=dev&per_page=' + str(self.limit))
            require(isinstance(listed, list) and len(listed) <= self.limit, 'unbounded pipeline discovery response')
            selector = re.fullmatch(r'ci/architecture-pipeline\.yml@GetBusbar/busbar:([0-9a-f]{40})',
                                    self.projects[name].get('ci_config_path') or '')
            require(selector is not None, 'owner protected selector is not immutable')
            self.approve_policy(selector[1])
            self.resolver.trusted_policies.update(self.approved)
            self.resolver.selector_policies[name] = selector[1]
            covered = set()
            for listed_pipeline in listed:
                try:
                    pipeline = self.reads.request(base + '/pipelines/' + str(listed_pipeline['id']))
                    require(pipeline.get('project_id') == row['project'] and pipeline.get('ref') == 'dev'
                            and pipeline.get('source') in ('api', 'push')
                            and (pipeline.get('user') or {}).get('id') in self.principals,
                            'pipeline is not an authenticated owner execution')
                    if pipeline['status'] in LIVE:
                        if pipeline.get('sha') == row['source']:
                            self.live.setdefault(name, []).append(dict(project=row['project'],
                                pipeline=pipeline['id'], source=pipeline['sha'], status=pipeline['status'],
                                policy=None, host=None, sdk=None))
                        continue
                    if pipeline['status'] not in ('success', 'failed'):
                        continue
                    jobs = self.reads.all(base + '/pipelines/' + str(pipeline['id']) + '/jobs')
                    native = [job for job in jobs if job.get('name') == 'native-qualification']
                    native_receipt = None
                    if len(native) == 1:
                        try:
                            native_receipt = json.loads(self.reads.raw(base + '/jobs/' + str(native[0]['id'])
                                                       + '/artifacts/boundary-evidence/receipt.json'))
                        except (ValueError, OSError, RuntimeError):
                            pass
                    for kind, needed in required.items():
                        matches = [job for job in jobs if job.get('name') == needed['job']
                                   and job.get('status') == 'success' and job.get('allow_failure') is False]
                        if len(matches) != 1:
                            continue
                        job = matches[0]
                        filename = 'security.json' if kind == 'security' else 'receipt.json'
                        receipt = json.loads(self.reads.raw(base + '/jobs/' + str(job['id'])
                                                          + '/artifacts/boundary-evidence/' + filename))
                        if kind == 'security' and not native_receipt:
                            continue  # Original host/SDK cannot be invented from a current selector.
                        original = identity.receipt_request(receipt, needed['job'],
                            host=(native_receipt or {}).get('host_revision'),
                            sdk=(native_receipt or {}).get('sdk_revision'))
                        require(original['repository'] == name and original['source'] == pipeline['sha']
                                and receipt.get('job_id') == str(job['id'])
                                and receipt.get('pipeline_id') == str(pipeline['id']), 'original receipt locator differs')
                        for repository, revision in ((name, original['source']), (CORE, original['host']),
                                                      (CORE, original['sdk'])):
                            self.ensure(repository, revision)
                        self.approve_policy(original['policy'])
                        self.resolver.trusted_policies.update(self.approved)
                        candidate = dict(request=original, project=row['project'], pipeline=pipeline['id'],
                                         job=job['id'], receipt=receipt)
                        self.originals[name].append(candidate)
                        self.observations[row['project'], pipeline['id'], job['id']] = dict(
                            project=row['project'], pipeline=pipeline['id'], job=job['id'],
                            status='success', pipeline_status=pipeline['status'])
                        if kind == 'security' and original['policy'] == selector[1]:
                            witnesses.append(candidate)
                        requested = identity.checked_request({**{key: row[key] for key in
                            ('repository', 'source', 'host', 'policy', 'sdk')}, 'job': needed['job']})
                        proposal = identity.plan_reuse(original, requested, self.objects,
                                                       database=receipt.get('database'))
                        if (proposal['action'] != 'run' and not
                                (proposal['action'] == 'verify-component-retention' and needed['suites'])):
                            covered.add(kind)
                    if covered == set(required):
                        break  # Authenticate these candidates below; do not download an owner's unused history.
                except (ValueError, KeyError, TypeError, OSError, RuntimeError) as error:
                    self.rejections.append(dict(repository=name, pipeline=listed_pipeline.get('id'), reason=str(error)))
        self.database = None
        for candidate in sorted(witnesses, key=lambda value: value['job'], reverse=True):
            try:
                self.database = self.resolver.authenticate_database(candidate['request'], candidate['receipt'])
                break
            except (ValueError, KeyError, TypeError, OSError, RuntimeError) as error:
                self.rejections.append(dict(repository=candidate['request']['repository'],
                                            job=candidate['job'], reason=str(error)))
        return self

    def observe(self, candidate):
        return dict(self.observations[candidate['project'], candidate['pipeline'], candidate['job']])

    def finish(self):
        path = self.session / 'canonical-read-manifest.json'
        path.write_bytes(identity.encoded(dict(canonical=self.reads.records, groups=self.groups.records)))
        return dict(schema='busbar.owner-qualification-discovery/1', normalizer=self.normalizer_origin,
            policy=self.policy, host=self.host, sdk=self.sdk, pipeline_discovery_limit=self.limit,
            canonical_read_manifest=str(path), canonical_read_manifest_sha256=digest(path.read_bytes()),
            approved_policies=sorted(self.approved), database_witness=self.resolver.database_witness,
            rejections=self.rejections, owner_principals=sorted(self.principals))

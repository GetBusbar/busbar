"""In-CI retention decision for expensive check kinds, made before bootstrap.

Runs from the server-selected trusted policy checkout inside the protected job,
using only CI-provided identity (CI_JOB_TOKEN, CI_* variables) and the runner's
clone of the job's own project. For each retainable kind it decides:

  retained(original job N): a successful job of the same kind in the same
      project on protected dev, under the same approved policy revision, whose
      archive and per-step log digests verify and whose input identity equals
      the current input identity. A receipt referencing that job is written to
      boundary-evidence/retained.json and the expensive bootstrap is skipped.
  fresh(reason): anything else, including missing API access, malformed or
      forged evidence and any internal error. Nothing is written; the caller
      runs the full qualification.

The receipt never copies the original's pass flag; it carries the verified
original job/pipeline ids, archive and receipt digests and the identity.

Input identity (no Python AST, no interpreter-dependent data):
  * every tracked path and mode of the candidate commit tree, and the Git blob
    id of every path except a small content-excluded set (see excluded_paths);
  * the approved policy revision (the whole trusted controller tree: pipeline
    YAML, toolchain/image pins, fixtures, nextest config and controller code);
  * job kind, project, protected ref; for non-core projects also the resolved
    core host revision the job would assemble against.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile

CORE = 'GetBusbar/busbar'
SCHEMA = 'busbar.ci-retained-check/1'
IDENTITY_SCHEMA = 'busbar.ci-input-identity/1'
RECEIPT_SCHEMAS = {'native-qualification': 'busbar.protected-native-admission/1',
                   'core-conformance': 'busbar.protected-conformance/1'}
RETAINED = 0
FRESH = 3
SHA1 = re.compile(r'[0-9a-f]{40}')
MAX_PAGES = 5
MAX_VERIFIED = 3
ARCHIVE_LIMIT = 1024**3

# Content-excluded candidates: community/forge metadata that no qualification
# step reads. Paths and modes stay in the identity (directory walkers can see
# them); only their bytes are dropped. docs/** and README.md are NOT candidates:
# dist/default/tests/docs_examples.rs walks docs/**/*.md and README.md, and
# several tests include_str!/read docs/*.md (audit digests, admin-api.md,
# diagnostics.md). CHANGELOG.md and RELEASE.md are candidates but are named by
# the release gate (tools/publish-gate), so the reference guard keeps them hashed.
EXCLUDED_PREFIXES = ('.gitlab/issue_templates/', '.gitlab/merge_request_templates/', 'org-profile/')
# A markdown-walking marker in code could read excluded files without naming
# them. Each reviewed occurrence is pinned to its exact blob; any other marker
# disables the exclusion (fresh, never smaller key) until it is reviewed here.
MARKDOWN_WALKER = re.compile(rb'\x2a\.md\b|["\']\.?md["\']')
# Core's candidate scripts/architecture/** never executes in these jobs: the
# pipeline runs only the trusted policy checkout's copy (its header contract).
TRUSTED_ONLY = 'scripts/architecture/'
REVIEWED_MARKDOWN_WALKERS = {
    CORE: {
        # Walks docs/**/*.md and reads README.md only; neither is excluded.
        'dist/default/tests/docs_examples.rs': '661fe271e0a234598aa218237db1b465bd2a09ee',
        # Editor settings ([*.md] section); no qualification tool reads it.
        '.editorconfig': 'a6bd4c53f6ee346474321cabba0f37bbc986a987',
        # Audit prose quoting a shell loop over docs/design/inventory/*.md; unread data.
        'docs/evidence/1.6.0-audit-evidence.json': '7dd95dc226fad90ad925f6c2a1b78178f713757e',
    },
}


class Fresh(Exception):
    """Retention is unproven; run fresh with this reason."""


class Rejected(Fresh):
    """Evidence was malformed or forged; never retained."""


def require(condition, reason, error=Rejected):
    if not condition:
        raise error(reason)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


class Git:
    """Read immutable objects from the runner's clone; no checkout, hooks or filters."""

    def __init__(self, root):
        self.root = Path(root)
        self._trees = {}

    def _git(self, *args, data=None):
        return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                               '-c', 'safe.directory=' + str(self.root), '-C', str(self.root), *args],
                              input=data, capture_output=True, check=True).stdout

    def has_commit(self, revision):
        if not SHA1.fullmatch(revision or ''):
            return False
        try:
            return self._git('rev-parse', '--verify', '--quiet', revision + '^{commit}').decode().strip() == revision
        except subprocess.CalledProcessError:
            return False

    def tree(self, revision):
        if revision not in self._trees:
            require(self.has_commit(revision), 'commit ' + str(revision) + ' is not in the protected clone', Fresh)
            rows = {}
            for record in self._git('ls-tree', '-r', '-z', '--full-tree', revision).split(b'\0'):
                if not record:
                    continue
                header, path = record.split(b'\t', 1)
                mode, kind, oid = header.decode().split()
                path = path.decode('utf-8')
                require(kind == 'blob' and mode in ('100644', '100755', '120000'),
                        'submodule or unsupported tree entry ' + path, Fresh)
                rows[path] = (mode, oid)
            self._trees[revision] = rows
        return self._trees[revision]

    def blobs(self, oids):
        """Map each blob id to its bytes using one batch reader."""
        oids = sorted(set(oids))
        if not oids:
            return {}
        out = self._git('cat-file', '--batch', data=''.join(oid + '\n' for oid in oids).encode())
        result, offset = {}, 0
        for oid in oids:
            end = out.index(b'\n', offset)
            name, kind, size = out[offset:end].decode().split()
            require(name == oid and kind == 'blob', 'unexpected object in batch read', Fresh)
            start = end + 1
            result[oid] = out[start:start + int(size)]
            offset = start + int(size) + 1
        return result


def excluded_candidate(path, mode):
    if mode != '100644':
        return False
    if '/' not in path:
        return path.endswith('.md') and path != 'README.md'
    return path.startswith(EXCLUDED_PREFIXES)


def excluded_paths(repository, tree, git):
    """Return (content-excluded paths, notes); the guard is evaluated on this tree.

    A candidate stays hashed when any other non-markdown blob names its file
    name (include_str!, open(), read_to_string, scripts...). If code contains an
    unreviewed markdown-walking marker, nothing is excluded.
    """
    candidates = {path for path, (mode, _) in tree.items() if excluded_candidate(path, mode)}
    scanned = {path: oid for path, (_, oid) in tree.items()
               if path not in candidates and not path.endswith('.md')}
    contents = git.blobs(scanned.values())
    reviewed = REVIEWED_MARKDOWN_WALKERS.get(repository, {})
    for path, oid in sorted(scanned.items()):
        if repository == CORE and path.startswith(TRUSTED_ONLY):
            continue
        if MARKDOWN_WALKER.search(contents[oid]) and reviewed.get(path) != oid:
            return set(), ['content exclusion disabled: unreviewed markdown walker in ' + path]
    notes, excluded = [], set()
    for path in sorted(candidates):
        name = PurePosixPath(path).name.encode()
        readers = [other for other, oid in scanned.items() if name in contents[oid]]
        if readers:
            notes.append(path + ' stays hashed: named by ' + sorted(readers)[0])
        else:
            excluded.add(path)
    return excluded, notes


def tree_identity(tree, excluded):
    rows = [[path, mode, 'content-excluded' if path in excluded else oid]
            for path, (mode, oid) in sorted(tree.items())]
    return sha256(canonical(rows))


def identity(context, tree, excluded, host):
    value = {'schema': IDENTITY_SCHEMA, 'kind': context['kind'], 'project': context['project'],
             'project_id': context['project_id'], 'ref': 'dev', 'policy_revision': context['policy'],
             'tree_sha256': tree_identity(tree, excluded), 'content_excluded': sorted(excluded)}
    if context['project'] != CORE:
        value['host_revision'] = host
    return value


def changed_paths(before, after, excluded):
    paths = sorted(path for path in set(before) | set(after)
                   if (path in excluded and (path in before) != (path in after))
                   or (path not in excluded and before.get(path) != after.get(path)))
    return paths[:5] + (['... ' + str(len(paths) - 5) + ' more'] if len(paths) > 5 else [])


class Api:
    """GET-only GitLab API client authenticated by the job's own CI_JOB_TOKEN."""

    def __init__(self, env):
        server = env['CI_SERVER_URL'].rstrip('/')
        require(re.fullmatch(r'https://[A-Za-z0-9.-]+(?::[0-9]+)?', server)
                and env.get('CI_API_V4_URL', '').rstrip('/') == server + '/api/v4',
                'non-canonical CI API origin', Fresh)
        self.base, self.token = server + '/api/v4/', env['CI_JOB_TOKEN']

    def raw(self, path, limit=32 * 1024**2):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        request = urllib.request.Request(self.base + path, headers={'JOB-TOKEN': self.token})
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=120) as response:
                raw = response.read(limit + 1)
        except urllib.error.HTTPError as error:
            raise Fresh('CI_JOB_TOKEN read of ' + path.split('?')[0] + ' refused (HTTP '
                        + str(error.code) + '); job token needs read_jobs on its own project') from None
        except (urllib.error.URLError, OSError) as error:
            raise Fresh('GitLab API unavailable: ' + type(error).__name__) from None
        require(len(raw) <= limit, 'API response exceeds bound', Fresh)
        return raw

    def json(self, path):
        try:
            return json.loads(self.raw(path))
        except ValueError:
            raise Fresh('malformed GitLab API response') from None


def read_archive(raw):
    require(len(raw) <= ARCHIVE_LIMIT, 'archive exceeds bound')
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
        members, total = {}, 0
        for item in archive.infolist():
            path = PurePosixPath(item.filename)
            require(not path.is_absolute() and '..' not in path.parts and '\\' not in item.filename
                    and str(path) == item.filename.rstrip('/') and item.filename not in members
                    and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG, stat.S_IFDIR)
                    and not item.flag_bits & 1, 'unsafe archive member ' + item.filename)
            total += item.file_size
            require(total <= 2 * ARCHIVE_LIMIT, 'expanded archive exceeds bound')
            members[item.filename] = item
        require(len(members) <= 10000, 'too many archive members')
        return {name: archive.read(item) for name, item in members.items()
                if not item.is_dir() and name.startswith('boundary-evidence/')}
    except (zipfile.BadZipFile, OSError, EOFError, ValueError):
        raise Rejected('unreadable artifact archive') from None


def eligible(job, context):
    pipeline = job.get('pipeline') or {}
    return (job.get('name') == context['kind'] and job.get('status') == 'success'
            and job.get('ref') == 'dev' and job.get('tag') is False and job.get('allow_failure') is False
            and type(job.get('id')) is int and job['id'] != context['job_id']
            and pipeline.get('project_id') == context['project_id'] and pipeline.get('ref') == 'dev'
            and pipeline.get('source') in ('push', 'api')
            and SHA1.fullmatch((job.get('commit') or {}).get('id') or '') is not None
            and pipeline.get('sha') == job['commit']['id'])


def download(api, context, job):
    size = (job.get('artifacts_file') or {}).get('size')
    require(type(size) is int and 0 < size <= ARCHIVE_LIMIT, 'job ' + str(job['id']) + ' has no archive')
    raw = api.raw('projects/' + str(context['project_id']) + '/jobs/' + str(job['id']) + '/artifacts',
                  limit=ARCHIVE_LIMIT)
    require(len(raw) == size, 'job ' + str(job['id']) + ' archive size differs from server record')
    return raw


def verify_original(context, job, raw):
    """Verify an original fresh job's own archive; return its receipt and digests."""
    members = read_archive(raw)
    label = 'job ' + str(job['id'])
    require('boundary-evidence/retained.json' not in members, label + ' is not a fresh original')
    receipt_raw = members.get('boundary-evidence/receipt.json')
    require(receipt_raw is not None, label + ' archive has no receipt')
    receipt = json.loads(receipt_raw)
    uri = (context['server_host'] + '/' + context['project'] + '//ci/architecture-pipeline.yml@'
           + CORE + ':' + context['policy'] + '@refs/heads/dev')
    expected = {'schema': RECEIPT_SCHEMAS[context['kind']], 'status': 'pass',
                'repository': context['project'], 'source': job['commit']['id'],
                'job_id': str(job['id']), 'pipeline_id': str(job['pipeline']['id']),
                'policy_revision': context['policy'], 'config_uri': uri}
    for key, value in expected.items():
        require(isinstance(receipt, dict) and receipt.get(key) == value,
                label + ' receipt ' + key + ' differs from server/policy identity')
    steps = receipt.get('steps')
    require(isinstance(steps, list) and steps, label + ' receipt has no checks')
    names = set()
    for step in steps:
        name = step.get('name') if isinstance(step, dict) else None
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.-]+', name) and name not in names,
                label + ' has an invalid or duplicate check name')
        names.add(name)
        for stream in ('stdout', 'stderr'):
            log = members.get('boundary-evidence/' + name + '.' + stream)
            require(log is not None and sha256(log) == step.get(stream + '_sha256'),
                    label + ' check log ' + name + '.' + stream + ' missing or altered')
        if context['kind'] == 'native-qualification':
            require(step.get('status') == 'pass' and step.get('exit_code') == 0,
                    label + ' check ' + name + ' did not pass')
    if context['project'] != CORE:
        require(SHA1.fullmatch(receipt.get('host_revision') or ''), label + ' receipt has no host revision')
    return receipt, {'archive_sha256': sha256(raw), 'archive_size': len(raw), 'receipt_sha256': sha256(receipt_raw)}


def follow_retained(api, context, job, raw):
    """A retained job names its fresh original; re-authenticate that original."""
    members = read_archive(raw)
    label = 'retained job ' + str(job['id'])
    receipt = json.loads(members['boundary-evidence/retained.json'])
    require(isinstance(receipt, dict) and receipt.get('schema') == SCHEMA
            and receipt.get('decision') == 'retained' and receipt.get('kind') == context['kind']
            and receipt.get('project') == context['project'] and receipt.get('job_id') == job['id']
            and receipt.get('source') == job['commit']['id'], label + ' receipt differs from server identity')
    original = receipt.get('original')
    require(isinstance(original, dict) and type(original.get('job_id')) is int
            and type(original.get('pipeline_id')) is int, label + ' names no original')
    jobs = api.json('projects/' + str(context['project_id']) + '/pipelines/'
                    + str(original['pipeline_id']) + '/jobs?per_page=100')
    found = [row for row in jobs if isinstance(row, dict) and row.get('id') == original['job_id']]
    require(len(found) == 1 and eligible(found[0], context)
            and found[0]['pipeline']['id'] == original['pipeline_id'],
            label + ' original is not a successful same-kind protected dev job')
    original_raw = download(api, context, found[0])
    require(sha256(original_raw) == original.get('archive_sha256'),
            label + ' original archive digest differs from its receipt')
    return found[0], original_raw


def current_host(context, env):
    if context['project'] == CORE:
        return None
    pinned = env.get('BUSBAR_ADMISSION_CORE_REVISION', 'dev')
    if SHA1.fullmatch(pinned):
        return pinned
    require(pinned == 'dev', 'unrecognized host revision selector', Fresh)
    server = env['CI_SERVER_URL'].rstrip('/')
    auth = base64.b64encode(('gitlab-ci-token:' + env['CI_JOB_TOKEN']).encode()).decode()
    git_env = {key: value for key, value in env.items() if key in ('PATH', 'HOME')}
    git_env.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.' + server + '/.extraheader',
                   GIT_CONFIG_VALUE_0='Authorization: Basic ' + auth, GIT_TERMINAL_PROMPT='0')
    try:
        line = subprocess.run(['git', 'ls-remote', server + '/' + CORE + '.git', 'refs/heads/dev'], env=git_env,
                              capture_output=True, text=True, check=True, timeout=60, cwd='/').stdout.split()
    except (subprocess.SubprocessError, OSError):
        raise Fresh('could not resolve current core host revision') from None
    require(line and SHA1.fullmatch(line[0]), 'could not resolve current core host revision', Fresh)
    return line[0]


def context_from(env, policy):
    require(env.get('CI_PIPELINE_SOURCE') == 'push', 'pipeline source ' + str(env.get('CI_PIPELINE_SOURCE'))
            + ' is not an ordinary dev push', Fresh)
    require(env.get('CI_COMMIT_BRANCH') == 'dev' and env.get('CI_COMMIT_REF_PROTECTED') == 'true',
            'ref is not the protected dev branch', Fresh)
    kind = env.get('CI_JOB_NAME')
    require(kind in RECEIPT_SCHEMAS and (kind != 'core-conformance' or env.get('CI_PROJECT_PATH') == CORE),
            'kind ' + str(kind) + ' is not retainable', Fresh)
    require(SHA1.fullmatch(policy or '') and SHA1.fullmatch(env.get('CI_COMMIT_SHA', '')),
            'immutable policy and commit required', Fresh)
    return {'kind': kind, 'project': env['CI_PROJECT_PATH'], 'project_id': int(env['CI_PROJECT_ID']),
            'job_id': int(env['CI_JOB_ID']), 'pipeline_id': int(env['CI_PIPELINE_ID']),
            'source': env['CI_COMMIT_SHA'], 'policy': policy, 'server_host': env['CI_SERVER_HOST']}


def decide(env, policy, git, api, *, now=None):
    """Return ('retained', receipt) or ('fresh', reasons). Never raises for evidence."""
    reasons = []
    try:
        context = context_from(env, policy)
        tree = git.tree(context['source'])
        excluded, notes = excluded_paths(context['project'], tree, git)
        reasons.extend(notes)
        host = current_host(context, env)
        current = identity(context, tree, excluded, host)
        verified = 0
        for page in range(1, MAX_PAGES + 1):
            jobs = api.json('projects/' + str(context['project_id'])
                            + '/jobs?scope[]=success&per_page=100&page=' + str(page))
            require(isinstance(jobs, list), 'malformed job listing', Fresh)
            for job in jobs:
                if not (isinstance(job, dict) and eligible(job, context)):
                    continue
                if not git.has_commit(job['commit']['id']):
                    continue
                before = git.tree(job['commit']['id'])
                if tree_identity(before, excluded) != current['tree_sha256']:
                    if len(reasons) < 8:
                        reasons.append('job ' + str(job['id']) + ' inputs differ: '
                                       + ', '.join(changed_paths(before, tree, excluded)))
                    continue
                if verified >= MAX_VERIFIED:
                    reasons.append('verification bound reached')
                    return 'fresh', reasons
                verified += 1
                try:
                    raw = download(api, context, job)
                    original = job
                    if 'boundary-evidence/retained.json' in read_archive(raw):
                        original, raw = follow_retained(api, context, job, raw)
                    receipt, digests = verify_original(context, original, raw)
                    original_identity = identity(context, git.tree(original['commit']['id']), excluded,
                                                 receipt.get('host_revision'))
                    if original_identity != current:
                        reasons.append('job ' + str(original['id']) + ' identity differs (host/policy/tree)')
                        continue
                except (Rejected, ValueError, KeyError, TypeError, AttributeError) as error:
                    reasons.append('rejected evidence: ' + str(error)[:200])
                    continue
                stamp = (now or dt.datetime.now(dt.timezone.utc)).isoformat()
                return 'retained', {
                    'schema': SCHEMA, 'decision': 'retained', 'kind': context['kind'],
                    'project': context['project'], 'project_id': context['project_id'],
                    'job_id': context['job_id'], 'pipeline_id': context['pipeline_id'],
                    'source': context['source'], 'ref': 'dev', 'policy_revision': context['policy'],
                    'identity': current, 'identity_sha256': sha256(canonical(current)), 'decided_at': stamp,
                    'original': {'job_id': original['id'], 'pipeline_id': original['pipeline']['id'],
                                 'source': original['commit']['id'],
                                 'pipeline_source': original['pipeline']['source'],
                                 'runner_id': (original.get('runner') or {}).get('id'),
                                 'finished_at': original.get('finished_at'),
                                 'via_retained_job_id': job['id'] if job is not original else None,
                                 **digests},
                    'notes': reasons}
            if len(jobs) < 100:
                break
        reasons.append('no authenticated successful ' + context['kind'] + ' job with equal inputs')
    except Fresh as error:
        reasons.append(str(error))
    except Exception as error:  # Unknown failures are never success.
        reasons.append('internal error: ' + type(error).__name__ + ': ' + str(error)[:200])
    return 'fresh', reasons


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    kind = os.environ.get('CI_JOB_NAME', '?')
    try:
        evidence = args.output.parent
        if evidence.exists() or evidence.is_symlink():
            raise Fresh('checkout already contains ' + evidence.name)
        decision, detail = decide(os.environ, args.policy, Git(args.checkout), Api(os.environ))
    except Fresh as error:
        decision, detail = 'fresh', [str(error)]
    except Exception as error:
        decision, detail = 'fresh', ['internal error: ' + type(error).__name__]
    if decision == 'retained':
        evidence.mkdir()
        args.output.write_bytes(json.dumps(detail, indent=2, sort_keys=True).encode() + b'\n')
        print('busbar-retention: ' + kind + ': retained(original job ' + str(detail['original']['job_id'])
              + ', pipeline ' + str(detail['original']['pipeline_id']) + ', identity '
              + detail['identity_sha256'][:16] + ')', flush=True)
        for note in detail['notes']:
            print('busbar-retention:   note: ' + note, flush=True)
        return RETAINED
    print('busbar-retention: ' + kind + ': fresh(' + (detail[-1] if detail else 'unknown') + ')', flush=True)
    for reason in detail[:-1]:
        print('busbar-retention:   ' + reason, flush=True)
    return FRESH


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Plugin host identity: the exact core inputs a non-core native qualification reads.

A plugin (and busbar-release) qualification reads core through exactly two trees:

  * the trusted policy checkout (ci_config_path ``...@GetBusbar/busbar:<policy>``):
    the controller that runs and judges every step, its pipeline YAML, admission
    policy, fixtures, nextest config, conformance controls, plugins.yaml, and every
    other file the controller or the candidate (through the read-only mount) can read;
  * the assembled host checkout (BUSBAR_ADMISSION_CORE_REVISION, else core dev),
    exported to candidate code as BUSBAR_CHECKOUT: plugin tests build the real
    dist/default binary from it, read its goldens, SDK headers and product pins.

The identity hashes both trees, path by path (path, mode, Git blob id), with only
these reviewed reductions. Everything else is in; when unsure, it is in.

  1. Host-unread controller paths (HOST_UNREAD: scripts/architecture/, ci/, .gitlab/).
     Plugin jobs execute and read the *policy* checkout's copy of these, never the
     host's. This is enforced, not assumed: restrict_host_view() removes them from
     the host working tree before any candidate code runs (sparse checkout; the
     checkout stays clean at its exact commit) and verify_host_view() fails the job
     if they reappear. The policy copy of the same paths stays in the identity.
  2. Controller unit-test module contents (scripts/architecture/**/test_*.py in the
     policy tree). Only core's own job discovers and runs them. Each stays hashed
     when any non-markdown blob of the policy tree names its module (import, -m,
     file name), transitively, and all of them stay hashed when an unreviewed test
     walker (test_* glob, unittest discover, a TestLoader) appears in controller-
     reachable code. Their paths and modes always stay in the identity.
  3. ci/native-judge-inputs.json is replaced by this repository's projection: the
     plan shape native_ci_bootstrap.judge_selection validates plus the owner rows it
     selects for this repository. Other repositories' judge archives are never
     staged for this job. An invalid plan has no identity (fail closed).

Excluded by design: the policy/host commit ids and commit metadata themselves.
Plugin scripts use BUSBAR_PIN only as a label or cache key, never as a verdict
input (a2a, decisions, llm, mcp conformance were reviewed); the receipt still
records both exact revisions.

The digest binds schema, repository, the reduced host tree and the reduced policy
tree. Two (policy, host) pairs with equal identities give a plugin qualification
byte-identical core inputs, so its evidence stays valid across them. This module
is itself in the policy tree, so a change to this definition changes every identity.

Fleet use (never launches anything): exit 0 when a repoint is unnecessary.
  python3 -B scripts/architecture/plugin_host_identity.py compare --git-dir CORE_CLONE \\
      --repository GetBusbar/busbar-secret-c --policy OLD_POLICY --host OLD_HOST --to NEW_CORE
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

SCHEMA = 'busbar.plugin-host-identity/1'
CORE = 'GetBusbar/busbar'
HOST_UNREAD = ('scripts/architecture/', 'ci/', '.gitlab/')
JUDGE_PLAN = 'ci/native-judge-inputs.json'
JUDGE_SCHEMA = 'busbar.native-judge-inputs/1'
TEST_MODULE = re.compile(r'scripts/architecture/(?:[A-Za-z0-9_]+/)*(test_[A-Za-z0-9_]+)\.py')
# Code that can enumerate and run Python test modules without naming them.
TEST_WALKER = re.compile(rb'test_?\*|unittest\W{1,6}discover|[\'"]discover[\'"]|loadTestsFrom|TestLoader\b')
WALKER_CODE = ('.py', '.sh', '.bash', '.yml', '.yaml')
# Reviewed walkers: path -> (enclosing definition or None, exact stripped lines).
# native.py's discover calls are core_regressions(), which only GetBusbar/busbar runs;
# sdk-pipeline.yml discovers the SDK repository's tests/; development_checks.py loads
# the named scripts/release modules of core's release-engineering evidence.
REVIEWED_TEST_WALKERS = {
    'scripts/architecture/native.py': (b'    def core_regressions(self):', frozenset({
        b"self.run_controller('architecture-regressions', [sys.executable, '-m', 'unittest', 'discover',",
        b"'-s', str(self.trusted / 'scripts/architecture'), '-p', 'test_*.py'], cwd=self.trusted)",
        b"self.run_controller('toolchain-regressions', [sys.executable, '-m', 'unittest', 'discover',",
        b"'-s', str(self.trusted / 'scripts/architecture/toolchain'), '-p', 'test_*.py'], cwd=self.trusted)",
    })),
    'ci/sdk-pipeline.yml': (None, frozenset({
        b"'python -m pip install -e .', 'python -m unittest discover -s tests'],",
    })),
    'scripts/release/development_checks.py': (None, frozenset({
        b'suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)',
    })),
}
FIELDS = {'schema', 'repository', 'policy_revision', 'host_revision', 'host_unread', 'host_tree_sha256',
          'controller_tree_sha256', 'content_excluded', 'judge_selection', 'notes', 'sha256'}
SHA1 = re.compile(r'[0-9a-f]{40}')
SHA256 = re.compile(r'[0-9a-f]{64}')


class Unavailable(Exception):
    """No identity can be established; evidence is accepted only on its exact host."""


def require(condition, reason):
    if not condition:
        raise Unavailable(reason)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


class GitTrees:
    """Immutable commits of one local repository: no checkout, hooks or filters."""

    def __init__(self, root, env=None):
        self.root, self.env, self._rows = Path(root), env, {}
        self.excluded = {}  # policy revision -> excluded_test_modules() result; trees are immutable

    def _git(self, *args, data=None):
        try:
            return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                                   '-c', 'safe.directory=' + str(self.root.resolve()), '-C', str(self.root), *args],
                                  input=data, capture_output=True, check=True, env=self.env).stdout
        except (subprocess.CalledProcessError, OSError) as error:
            raise Unavailable('git ' + args[0] + ' failed in ' + self.root.name + ': '
                              + type(error).__name__) from None

    def rows(self, revision):
        require(SHA1.fullmatch(revision or ''), 'revision must be an immutable commit id')
        if revision not in self._rows:
            rows = {}
            for record in self._git('ls-tree', '-r', '-z', '--full-tree', revision).split(b'\0'):
                if not record:
                    continue
                header, path = record.split(b'\t', 1)
                mode, kind, oid = header.decode().split()
                path = path.decode('utf-8')
                require(kind == 'blob' and mode in ('100644', '100755', '120000'),
                        'submodule or unsupported tree entry ' + path)
                rows[path] = (mode, oid)
            require(rows, 'empty tree at ' + revision)
            self._rows[revision] = rows
        return self._rows[revision]

    def blobs(self, oids):
        oids = sorted(set(oids))
        if not oids:
            return {}
        out = self._git('cat-file', '--batch', data=''.join(oid + '\n' for oid in oids).encode())
        result, offset = {}, 0
        for oid in oids:
            end = out.index(b'\n', offset)
            name, kind, size = out[offset:end].decode().split()
            require(name == oid and kind == 'blob', 'unexpected object in batch read')
            start = end + 1
            result[oid] = out[start:start + int(size)]
            offset = start + int(size) + 1
        return result


def host_unread(path):
    return path.startswith(HOST_UNREAD)


def reviewed_walker(path, raw):
    """True when every walker occurrence in raw is a reviewed line in its reviewed scope."""
    review = REVIEWED_TEST_WALKERS.get(path)
    if review is None:
        return False
    scope, allowed = review
    lines = raw.split(b'\n')
    start = end = None
    if scope is not None:
        indexes = [index for index, line in enumerate(lines) if line == scope]
        if len(indexes) != 1:
            return False
        start = indexes[0]
        indent = len(scope) - len(scope.lstrip())
        end = next((index for index in range(start + 1, len(lines))
                    if lines[index].strip() and len(lines[index]) - len(lines[index].lstrip()) <= indent),
                   len(lines))
    for index, line in enumerate(lines):
        if TEST_WALKER.search(line):
            if line.strip() not in allowed or (start is not None and not start < index < end):
                return False
    return True


def excluded_test_modules(rows, blobs):
    """Content-excluded controller test modules and the notes explaining every kept one."""
    candidates = {}
    for path, (mode, oid) in rows.items():
        match = TEST_MODULE.fullmatch(path)
        if match and mode == '100644':
            candidates[path] = match[1]
    if not candidates:
        return set(), []
    scanned = {path: oid for path, (mode, oid) in rows.items()
               if path not in candidates and not path.endswith('.md') and mode != '120000'}
    contents = blobs(scanned.values())
    for path, oid in sorted(scanned.items()):
        code = path.endswith(WALKER_CODE) or rows[path][0] == '100755'
        if code and TEST_WALKER.search(contents[oid]) and not reviewed_walker(path, contents[oid]):
            return set(), ['test-module exclusion disabled: unreviewed test walker in ' + path]
    pattern = re.compile(rb'(?<![A-Za-z0-9_])(' + b'|'.join(
        re.escape(stem.encode()) for stem in sorted(set(candidates.values()), key=len, reverse=True))
        + rb')(?![A-Za-z0-9_])')
    named = {}
    for path, oid in sorted(scanned.items()):
        for stem in set(pattern.findall(contents[oid])):
            named.setdefault(stem.decode(), path)
    kept, notes = {}, []
    frontier = [path for path, stem in candidates.items() if stem in named]
    for path in frontier:
        kept[path] = named[candidates[path]]
    while frontier:
        reader = frontier.pop()
        raw = blobs([rows[reader][1]])[rows[reader][1]]
        for stem in set(pattern.findall(raw)):
            for path, other in candidates.items():
                if other == stem.decode() and path not in kept:
                    kept[path] = reader
                    frontier.append(path)
    for path in sorted(kept):
        notes.append(path + ' stays hashed: named by ' + kept[path])
    return set(candidates) - set(kept), notes


def judge_projection(repository, raw):
    """The part of the judge plan judge_selection() reads for this repository."""
    try:
        plan = json.loads(raw)
    except ValueError:
        raise Unavailable('invalid protected judge input plan') from None
    require(isinstance(plan, dict) and set(plan) == {'schema', 'owners', 'repositories'}
            and plan['schema'] == JUDGE_SCHEMA and isinstance(plan['owners'], dict)
            and len(plan['owners']) <= 16 and isinstance(plan['repositories'], dict),
            'invalid protected judge input plan')
    selected = plan['repositories'].get(repository, [])
    require(isinstance(selected, list) and len(selected) == len(set(selected))
            and all(isinstance(owner, str) and owner in plan['owners'] for owner in selected),
            'unapproved judge owner selection')
    return {'schema': plan['schema'], 'repository': repository, 'selected': selected,
            'owners': {owner: plan['owners'][owner] for owner in selected}}


def compute(repository, controller, policy, host_trees, host):
    """The identity record of `repository` qualified under `policy` against `host`."""
    require(isinstance(repository, str) and re.fullmatch(r'(GetBusbar|Busbar[I]nc)/[A-Za-z0-9._-]+', repository),
            'unknown repository')
    require(repository != CORE, 'core qualifies itself; it has no plugin host identity')
    policy_rows = controller.rows(policy)
    host_rows = host_trees.rows(host)
    memo = getattr(controller, 'excluded', None)
    if isinstance(memo, dict) and policy in memo:
        excluded, notes = memo[policy]
    else:
        excluded, notes = excluded_test_modules(policy_rows, controller.blobs)
        if isinstance(memo, dict):
            memo[policy] = (excluded, notes)
    notes = list(notes)
    selection = None
    controller_rows = []
    for path, (mode, oid) in sorted(policy_rows.items()):
        value = oid
        if path in excluded:
            value = 'content-excluded'
        elif path == JUDGE_PLAN:
            projection = judge_projection(repository, controller.blobs([oid])[oid])
            selection = projection['selected']
            value = 'projection:' + sha256(canonical(projection))
        controller_rows.append([path, mode, value])
    reduced_host = [[path, mode, oid] for path, (mode, oid) in sorted(host_rows.items()) if not host_unread(path)]
    record = {'schema': SCHEMA, 'repository': repository, 'policy_revision': policy, 'host_revision': host,
              'host_unread': list(HOST_UNREAD), 'host_tree_sha256': sha256(canonical(reduced_host)),
              'controller_tree_sha256': sha256(canonical(controller_rows)),
              'content_excluded': sorted(excluded), 'judge_selection': selection, 'notes': notes}
    record['sha256'] = digest_of(record)
    return record


def digest_of(record):
    """Only the reduced trees and their definition; never the commit ids."""
    return sha256(canonical({key: record[key] for key in
                             ('schema', 'repository', 'host_unread', 'host_tree_sha256', 'controller_tree_sha256')}))


def verify_record(record, *, repository, policy, host):
    """Return the identity of an authenticated receipt's record bound to its own revisions."""
    require(isinstance(record, dict), 'receipt records no plugin host identity')
    require('unavailable' not in record, 'plugin host identity was unavailable at qualification: '
            + str(record.get('unavailable'))[:200])
    require(set(record) == FIELDS and record.get('schema') == SCHEMA, 'unknown plugin host identity record')
    for key, value in (('repository', repository), ('policy_revision', policy), ('host_revision', host)):
        require(record[key] == value, 'plugin host identity ' + key + ' differs from its receipt')
    require(record['host_unread'] == list(HOST_UNREAD), 'plugin host identity definition differs')
    require(all(isinstance(record[key], str) and SHA256.fullmatch(record[key])
                for key in ('host_tree_sha256', 'controller_tree_sha256', 'sha256')),
            'malformed plugin host identity')
    require(digest_of(record) == record['sha256'], 'plugin host identity digest is not self-consistent')
    return record['sha256']


def accept(receipt, current):
    """Accept an authenticated plugin receipt for another host/policy only on an equal identity.

    Raises Unavailable with the explicit refusal reason otherwise.
    """
    require(isinstance(current, str) and SHA256.fullmatch(current),
            'no current plugin host identity to compare against')
    for key in ('policy_revision', 'host_revision'):
        require(isinstance(receipt.get(key), str) and SHA1.fullmatch(receipt[key]),
                'receipt ' + key + ' is not an immutable commit')
    record = receipt.get('plugin_host_identity')
    if record is None:
        raise Unavailable('receipt records no plugin host identity (qualified before identities were recorded)')
    recorded = verify_record(record, repository=receipt.get('repository'),
                             policy=receipt['policy_revision'], host=receipt['host_revision'])
    require(recorded == current, 'plugin host identity ' + recorded[:16] + ' (policy '
            + receipt['policy_revision'][:10] + ', host ' + receipt['host_revision'][:10]
            + ') differs from the current ' + current[:16])
    return recorded


def restrict_host_view(host):
    """Remove host-unread controller paths from a host checkout; the commit stays exact and clean."""
    host = Path(host)
    trees = GitTrees(host)
    head = trees._git('rev-parse', 'HEAD').decode().strip()
    info = host / '.git' / 'info'
    info.mkdir(exist_ok=True)
    (info / 'sparse-checkout').write_text('/*\n' + ''.join('!/' + prefix + '\n' for prefix in HOST_UNREAD))
    trees._git('config', 'core.sparseCheckout', 'true')
    trees._git('config', 'core.sparseCheckoutCone', 'false')
    trees._git('read-tree', '-mu', 'HEAD')
    require(trees._git('rev-parse', 'HEAD').decode().strip() == head, 'host view moved its commit')
    verify_host_view(host)
    return head


def verify_host_view(host):
    host = Path(host)
    for prefix in HOST_UNREAD:
        path = host / prefix.rstrip('/')
        require(not path.exists() and not path.is_symlink(), 'host view exposes ' + prefix)
    require(not GitTrees(host)._git('status', '--porcelain', '--untracked-files=no'),
            'host view has modified tracked source')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    show = sub.add_parser('show', help='print the identity record of one (policy, host) pair')
    compare = sub.add_parser('compare', help='exit 0 when NEW_CORE needs no repoint of this plugin')
    for command in (show, compare):
        command.add_argument('--git-dir', required=True, type=Path, help='local core clone holding the commits')
        command.add_argument('--repository', required=True)
        command.add_argument('--policy', required=True)
        command.add_argument('--host')
    compare.add_argument('--to', required=True, help='candidate core commit (policy and host)')
    args = parser.parse_args(argv)
    trees = GitTrees(args.git_dir)
    try:
        before = compute(args.repository, trees, args.policy, trees, args.host or args.policy)
        if args.command == 'show':
            print(json.dumps(before, indent=2, sort_keys=True))
            return 0
        after = compute(args.repository, trees, args.to, trees, args.to)
    except Unavailable as error:
        print('plugin-host-identity: unavailable: ' + str(error), file=sys.stderr)
        return 2
    same = before['sha256'] == after['sha256']
    print(json.dumps({'repository': args.repository, 'unchanged': same,
                      'before': {'policy': args.policy, 'host': args.host or args.policy, 'sha256': before['sha256']},
                      'after': {'policy': args.to, 'host': args.to, 'sha256': after['sha256']}}, sort_keys=True))
    return 0 if same else 1


if __name__ == '__main__':
    sys.exit(main())

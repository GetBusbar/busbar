#!/usr/bin/env python3
"""Trusted, read-only scans. Candidate code/configuration never executes here.

Run on a dedicated ephemeral scanner worker, never alongside native candidate jobs.
Docker is a local trusted service. Source-bearing containers have no network, host
credentials, Docker socket, writable policy, or writable evidence mount.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import uuid

from secret_fixtures import classify


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args])


def export_source(checkout, revision, destination):
    """Export Git blobs, ignoring export-ignore/filter attributes and worktree bytes."""
    require(re.fullmatch('[0-9a-f]{40}', revision), 'immutable source required')
    destination.mkdir()
    rows = []
    for record in git(checkout, 'ls-tree', '-rz', revision).split(b'\0'):
        if not record:
            continue
        header, name = record.split(b'\t', 1)
        mode, kind, oid = header.decode().split()
        path = name.decode('utf-8')
        require(not PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts,
                'invalid source path')
        require(kind == 'blob' and mode in ('100644', '100755', '120000'),
                'submodules and unknown Git entries need independent source qualification')
        data = git(checkout, 'cat-file', 'blob', oid)
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        # Symlinks become their literal target text; no host file can be followed.
        target.write_bytes(data)
        rows.append(dict(path=path, mode=mode, sha256=hashlib.sha256(data).hexdigest()))
    require(rows, 'empty source tree')
    return rows


def inspect_report(kind, report):
    """Return only safe counts; no source lines or matches enter the public receipt."""
    require(isinstance(report, dict), 'scanner report is not an object')
    if kind == 'sast':
        require(isinstance(report.get('results'), list) and isinstance(report.get('errors'), list),
                'invalid SAST report')
        require(not report['errors'], 'SAST had parse, timeout or analysis errors')
        paths = report.get('paths', {})
        require(isinstance(paths, dict) and isinstance(paths.get('scanned'), list)
                and paths['scanned'], 'SAST scanned no files')
        return len(report['results'])
    require(report.get('SchemaVersion') == 2, 'unsupported vulnerability/secret report')
    require(isinstance(report.get('Results', []), list), 'invalid scanner results')
    field = 'Secrets' if kind == 'secrets' else 'Vulnerabilities'
    count = 0
    for row in report.get('Results', []):
        require(isinstance(row, dict), 'invalid scanner result')
        findings = row.get(field) or []
        require(isinstance(findings, list), 'invalid scanner findings')
        count += len(findings)
    return count


def database_identity(cache, max_age, now=None):
    metadata = json.loads((cache / 'db/metadata.json').read_text())
    updated = dt.datetime.fromisoformat(metadata['UpdatedAt'].replace('Z', '+00:00'))
    now = now or dt.datetime.now(dt.timezone.utc)
    require(updated.tzinfo is not None and dt.timedelta() <= now - updated <= dt.timedelta(hours=max_age),
            'vulnerability database is stale or future-dated')
    return dict(updated_at=metadata['UpdatedAt'], sha256=digest(cache / 'db/trivy.db'),
                metadata_sha256=digest(cache / 'db/metadata.json'))


class Scanner:
    def __init__(self, trusted, work):
        self.policy = trusted / 'ci/security'
        self.work = work
        self.tools = json.loads((self.policy / 'tools.json').read_text())
        for name in ('trivy', 'semgrep'):
            require(re.fullmatch(r'[a-z0-9./:-]+@sha256:[0-9a-f]{64}', self.tools[name]),
                    'scanner image must be digest pinned')
        self.home = work / 'scanner-home'
        self.home.mkdir()
        # Do not inherit registry/cloud credentials, plugins, candidate config or CI tokens.
        self.env = dict(PATH=os.environ['PATH'], HOME=str(self.home), DOCKER_CONFIG=str(self.home))
        self.docker = ['docker', '--host', 'unix:///var/run/docker.sock']
        self.cache = work / 'database'
        self.cache.mkdir()
        self.steps = []
        self.repository = None
        self.source_rows = []

    def container(self, tool, argv, mounts=(), network='none'):
        name = 'busbar-scan-' + uuid.uuid4().hex
        command = [*self.docker, 'run', '--rm', '--name', name, '--pull=never', '--read-only',
                   '--cap-drop=ALL', '--security-opt=no-new-privileges', '--network=' + network,
                   '--pids-limit=256', '--memory=3g', '--cpus=2', '--user', f'{os.getuid()}:{os.getgid()}',
                   '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m,mode=1777', '-e', 'HOME=/tmp',
                   '--workdir', '/tmp', '--entrypoint', tool]
        for source, target, writable in mounts:
            require(',' not in str(source), 'comma in mount source')
            command += ['--mount', f'type=bind,src={source},dst={target}' + ('' if writable else ',readonly')]
        command += [self.tools[tool], *argv]
        # Reports may contain secrets; never stream them to job logs.
        with tempfile.TemporaryFile(dir=self.work) as out, tempfile.TemporaryFile(dir=self.work) as err:
            try:
                process = subprocess.run(command, env=self.env, stdout=out, stderr=err, timeout=1200)
                require(out.tell() <= 128 * 1024 * 1024, 'scanner report exceeds limit')
                out.seek(0)
                data = out.read()
                err.seek(0)
                stderr_hash = hashlib.file_digest(err, 'sha256').hexdigest()
            finally:
                subprocess.run([*self.docker, 'rm', '-f', name], env=self.env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        return process.returncode, data, stderr_hash

    def prepare(self):
        for tool in ('trivy', 'semgrep'):
            subprocess.run([*self.docker, 'pull', self.tools[tool]], env=self.env,
                           check=True, stdout=subprocess.DEVNULL, timeout=600)
        # Only this source-free container has network access. Scan containers cannot
        # contact registries, SaaS scanners, secret validation APIs or package servers.
        code, _, _ = self.container('trivy', ['image', '--download-db-only', '--disable-telemetry',
                                    '--skip-version-check', '--cache-dir', '/cache'],
                                    [(self.cache, '/cache', True)], network='bridge')
        require(code == 0, 'vulnerability database download failed')
        return database_identity(self.cache, self.tools['database_max_age_hours'])

    def scan(self, name, kind, source, argv, tool='trivy'):
        mounts = [(source, '/input', False), (self.policy, '/policy', False), (self.cache, '/cache', False)]
        code, data, stderr_hash = self.container(tool, argv, mounts)
        row = dict(name=name, tool_image=self.tools[tool], exit_code=code, status='fail',
                   report_sha256=hashlib.sha256(data).hexdigest(), stderr_sha256=stderr_hash)
        self.steps.append(row)
        try:
            report = json.loads(data)
            count = inspect_report(kind, report)
            row['findings'] = count  # Raw count, including classified public fixtures.
            if kind == 'secrets':
                private = self.work / 'private-scanner-reports'
                private.mkdir(mode=0o700, exist_ok=True)
                require(not private.is_symlink(), 'indirect private scanner output')
                private.chmod(0o700)
                fd = os.open(private / ('secrets-' + uuid.uuid4().hex + '.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data)
            if kind == 'secrets' and count and self.repository:
                row.update(classify(report, repository=self.repository, source=source,
                                    source_rows=self.source_rows,
                                    policy=(self.policy / 'public-secret-fixtures.json').read_bytes()))
                require(code == 1 and row['unresolved_findings'] == 0,
                        'unresolved secrets or scanner execution failure')
            else:
                require(code == 0 and count == 0, 'scanner findings or execution failure: ' + name)
            row['status'] = 'pass'
        except (ValueError, KeyError, TypeError):
            raise ValueError('security scan refused: ' + name) from None

    def trivy(self, mode, scanners, extra=()):
        return [mode, '--config', '/policy/trivy.yaml', '--ignorefile', '/policy/trivy.ignore',
                *(['--secret-config', '/policy/trivy-secret.yaml'] if mode != 'sbom' else []),
                '--disable-telemetry', '--skip-version-check', '--cache-dir', '/cache',
                '--cache-backend', 'memory', '--skip-db-update', '--skip-java-db-update', '--offline-scan',
                '--scanners', scanners, '--severity', 'HIGH,CRITICAL' if scanners == 'vuln' else
                'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', *extra]


def run_source(trusted, checkout, work, output):
    require(os.environ.get('CI_JOB_NAME') == 'security-scans', 'dedicated security-scans CI job required')
    require(os.environ.get('GITLAB_CI') == 'true', 'security qualification runs in GitLab')
    source = os.environ['CI_COMMIT_SHA']
    policy = git(trusted, 'rev-parse', 'HEAD').decode().strip()
    receipt = dict(schema='busbar.security-scans/1', status='fail', repository=os.environ['CI_PROJECT_PATH'],
                   source=source, policy_revision=policy, pipeline_id=os.environ['CI_PIPELINE_ID'],
                   job_id=os.environ['CI_JOB_ID'], steps=[])
    scanner = None
    try:
        snapshot = work / 'scan-source'
        rows = export_source(checkout, source, snapshot)
        receipt['source_files_sha256'] = hashlib.sha256(encoded(rows)).hexdigest()
        receipt['source_tree'] = git(checkout, 'rev-parse', source + '^{tree}').decode().strip()
        scanner = Scanner(trusted, work)
        scanner.repository = os.environ['CI_PROJECT_PATH']
        scanner.source_rows = rows
        receipt['policy_files'] = {p.name: digest(p) for p in sorted(scanner.policy.iterdir()) if p.is_file()}
        receipt['database'] = scanner.prepare()
        failures = []
        for name, kind in [('secrets', 'secret'), ('dependencies', 'vuln')]:
            try:
                scanner.scan(name, name, snapshot, scanner.trivy('filesystem', kind, ['/input']))
            except ValueError as error:
                failures.append(str(error))
        # Root and nested candidate ignore files cannot weaken SAST. Secrets were
        # scanned before these control-only files are replaced; no source code changes.
        for path in snapshot.rglob('.semgrepignore'):
            path.write_text('')
        (snapshot / '.semgrepignore').write_text('')
        try:
            scanner.scan('sast', 'sast', snapshot,
                         ['scan', '--config', '/policy/semgrep.yaml', '--json', '--error', '--strict',
                          '--metrics=off', '--disable-version-check', '--disable-nosem', '--no-git-ignore',
                          '--max-target-bytes=0', '--optimizations=none', '--oss-only', '--jobs=2', '/input'], tool='semgrep')
        except ValueError as error:
            failures.append(str(error))
        require(not failures, '; '.join(failures))
        receipt['status'] = 'pass'
    finally:
        if scanner is not None:
            receipt['steps'] = scanner.steps
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(encoded(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ('trusted', 'checkout', 'work', 'output'):
        parser.add_argument('--' + argument, type=Path, required=True)
    args = parser.parse_args()
    run_source(args.trusted.resolve(), args.checkout.resolve(), args.work.resolve(), args.output.resolve())
    print('security scans passed; source-bound receipt retained')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        # Exception text from source/tool output is deliberately not printed.
        print('security scans failed or could not run; inspect the safe receipt and worker prerequisites', file=sys.stderr)
        sys.exit(1)

"""The certified core binary: one release build of dist/default `busbar` per pipeline.

core-build runs the one product build of the dev tier,

    cargo build --release --locked --manifest-path dist/default/Cargo.toml --bin busbar

with clippy-driver as RUSTC_WRAPPER and `-D warnings`, so the same compiler pass
lints every local crate it compiles (dist/default and every core path crate under
crates/*; registry and Git crates keep Cargo's --cap-lints allow, which disables
clippy) and produces the binary. Its sha256 is the certified subject: core
conformance judges exactly these bytes, and native qualification verifies and
records the same digest instead of building another release binary.

Consumers never trust a file placed in their checkout. They read the core-build
job of their own pipeline through the GitLab API with their own job token: the
job must be the server's successful core-build job of this pipeline, its receipt
must name this source, policy, pipeline and job, and the downloaded binary must
have the receipt's digest. The verified copy sits in a controller-owned directory
that candidate invocations mount read-only.

A profile for profile-guided optimisation is a later, digest-pinned input
(profile_environment); it changes RUSTFLAGS for the one build and is recorded in
the receipt, so the job shape and the certification stay the same.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request

from check import Violation

JOB = 'core-build'
SCHEMA = 'busbar.core-build/1'
BUILD = ['build', '--release', '--locked', '--manifest-path', 'dist/default/Cargo.toml', '--bin', 'busbar']
LINTER = 'clippy-driver'
# What `cargo clippy -- -D warnings` hands clippy-driver (Cargo's own encoding).
LINT_ARGS = ['-D', 'warnings']
PACKAGE = 'busbar-default'
MAX_BINARY_BYTES = 512 * 1024**2
MAX_RECEIPT_BYTES = 64 * 1024**2
SUBJECT = 'certified-subject'


def clippy_args(args=LINT_ARGS):
    return ''.join(arg + '__CLIPPY_HACKERY__' for arg in args)


def lint_environment(env):
    """The compile identity of the one build: clippy-driver wraps rustc for every unit."""
    return dict(env, RUSTC_WRAPPER=LINTER, RUSTC_WORKSPACE_WRAPPER='', CLIPPY_ARGS=clippy_args())


def profile_environment(env, profile=None):
    """Optional digest-pinned profile-use input; None (today) changes nothing."""
    if profile is None:
        return env, None
    path, expected = Path(profile['path']), profile['sha256']
    if path.is_symlink() or not path.is_file() or not re.fullmatch('[0-9a-f]{64}', expected or ''):
        raise Violation('profile input is missing, indirect or unpinned')
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != expected:
        raise Violation('profile input digest differs from its pin')
    flags = [flag for flag in env.get('CARGO_ENCODED_RUSTFLAGS', '').split('\x1f') if flag]
    flags.append('-Cprofile-use=' + str(path))
    return dict(env, CARGO_ENCODED_RUSTFLAGS='\x1f'.join(flags)), {'sha256': actual}


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def build(q, *, profile=None):
    """Run the one build, finalize its development evidence, return the certified record."""
    from native import collect_output
    host = q.host()
    pins = json.loads((host / 'scripts/ci-product-pins.json').read_text())
    capture = q.work / 'certified-build-capture'
    tool = q.trusted / 'scripts/release/development_artifact.py'
    saved = q.env
    environment, profile_record = profile_environment(lint_environment(q.env), profile)
    q.env = environment
    try:
        q.run('certified-build', ['python3', '-I', str(tool), 'capture', '--directory', str(capture), '--', *BUILD])
    except Violation:
        diagnostics(q, capture / 'cargo-messages.jsonl')
        raise
    finally:
        q.env = saved
    binary = Path(q.env['CARGO_TARGET_DIR']) / 'release/busbar'
    collected = collect_output(q, binary, q.evidence / 'busbar', compiler_output=True)
    evidence = q.evidence / 'development-artifact'
    (evidence / 'build').mkdir(parents=True)
    for name in ('cargo-metadata.json', 'Cargo.lock', 'cargo-messages.jsonl', 'build-context.json'):
        collect_output(q, capture / name, evidence / 'build' / name, limit=64 * 1024**2)
    q.run_controller('development-artifact-evidence', [sys.executable, '-I', str(tool),
        'finalize', '--directory', str(evidence), '--binary', str(collected),
        '--source', q.receipt['source'], '--policy', q.receipt['policy_revision'], '--sdk', pins['sdk'],
        '--vector', str(host / 'scripts/ci-product-pins.json'), '--package', PACKAGE,
        '--compiler-output', str(binary), '--command-json', json.dumps(BUILD),
        '--retention-policy-sha256', digest(q.trusted / 'ci/architecture-pipeline.yml')])
    record = {'sha256': digest(collected), 'bytes': collected.stat().st_size, 'path': 'busbar',
              'command': ['cargo', *BUILD], 'rustc_wrapper': LINTER, 'clippy_args': LINT_ARGS,
              'profile_use': profile_record,
              'development_artifact_receipt_sha256': digest(evidence / 'receipt.json')}
    q.receipt['binary_sha256'] = record['sha256']
    q.receipt['certified_binary'] = record
    q.receipt['development_artifact'] = {
        'path': 'development-artifact/receipt.json', 'sha256': record['development_artifact_receipt_sha256'],
        'signed': False, 'release_eligible': False, 'supported_lifetime_retention_verified': False}
    q.receipt['sdk_revision'] = pins['sdk']
    q.receipt['dependency_vector'] = pins
    q.receipt['root_lock_sha256'] = digest(host / 'Cargo.lock')
    q.receipt['distribution_lock_sha256'] = digest(host / 'dist/default/Cargo.lock')
    q.save()
    return record


def diagnostics(q, messages, limit=4 * 1024**2):
    """A failed build's rendered compiler errors (capture keeps them as JSON)."""
    out = q.evidence / 'certified-build.diagnostics.txt'
    try:
        if messages.is_symlink() or not messages.is_file() or messages.stat().st_size > 512 * 1024**2:
            return
        rendered = []
        with messages.open('rb') as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                message = row.get('message') if isinstance(row, dict) else None
                if row.get('reason') == 'compiler-message' and isinstance(message, dict) \
                        and message.get('level') in ('error', 'warning'):
                    rendered.append(str(message.get('rendered') or ''))
        text = '\n'.join(rendered).encode()[:limit]
        out.write_bytes(text)
        sys.stderr.write(text.decode(errors='replace')[-65536:])
    except OSError:
        pass


# --- consumers --------------------------------------------------------------------------

class Api:
    """GET-only GitLab API client with this job's own CI_JOB_TOKEN."""

    def __init__(self, env=None, opener=None):
        env = os.environ if env is None else env
        server = env['CI_SERVER_URL'].rstrip('/')
        if not re.fullmatch(r'https://[A-Za-z0-9.-]+', server):
            raise Violation('non-canonical CI server')
        self.base, self.token = server + '/api/v4/', env['CI_JOB_TOKEN']
        self.opener = opener or urllib.request.build_opener()

    def raw(self, path, limit):
        request = urllib.request.Request(self.base + path, headers={'JOB-TOKEN': self.token})
        try:
            with self.opener.open(request, timeout=600) as response:
                data = response.read(limit + 1)
        except (urllib.error.URLError, OSError) as error:
            raise Violation('certified binary unavailable: ' + type(error).__name__) from None
        if len(data) > limit:
            raise Violation('certified binary response exceeds its bound')
        return data

    def json(self, path):
        try:
            return json.loads(self.raw(path, MAX_RECEIPT_BYTES))
        except ValueError:
            raise Violation('malformed GitLab API response') from None


def find_job(api, project, pipeline):
    jobs = []
    for page in range(1, 6):
        rows = api.json(f'projects/{project}/pipelines/{pipeline}/jobs?per_page=100&page={page}')
        jobs.extend(rows)
        if len(rows) < 100:
            break
    rows = [job for job in jobs if job.get('name') == JOB]
    if len(rows) != 1 or rows[0].get('status') != 'success' or type(rows[0].get('id')) is not int:
        raise Violation('this pipeline has no single successful core-build job')
    if (rows[0].get('pipeline') or {}).get('id') not in (None, int(pipeline)):
        raise Violation('core-build job belongs to another pipeline')
    return rows[0]


def verify_receipt(receipt, *, job_id, source, policy, pipeline):
    expected = {'schema': SCHEMA, 'status': 'pass', 'source': source, 'policy_revision': policy,
                'pipeline_id': str(pipeline), 'job_id': str(job_id), 'repository': 'GetBusbar/busbar'}
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise Violation('core-build receipt differs: ' + key)
    record = receipt.get('certified_binary')
    if not isinstance(record, dict) or not re.fullmatch('[0-9a-f]{64}', str(record.get('sha256'))) \
            or record.get('command') != ['cargo', *BUILD] or receipt.get('binary_sha256') != record['sha256']:
        raise Violation('core-build receipt has no certified binary')
    return record


def stage(q, api=None):
    """Fetch, verify and stage this pipeline's certified binary read-only; return its record."""
    api = api or Api()
    project, pipeline = os.environ['CI_PROJECT_ID'], os.environ['CI_PIPELINE_ID']
    job = find_job(api, project, pipeline)
    base = f'projects/{project}/jobs/{job["id"]}/artifacts/boundary-evidence/'
    receipt = json.loads(api.raw(base + 'receipt.json', MAX_RECEIPT_BYTES))
    record = verify_receipt(receipt, job_id=job['id'], source=q.receipt['source'],
                            policy=q.receipt['policy_revision'], pipeline=pipeline)
    data = api.raw(base + 'busbar', MAX_BINARY_BYTES)
    if hashlib.sha256(data).hexdigest() != record['sha256'] or len(data) != record.get('bytes'):
        raise Violation('downloaded certified binary differs from its core-build receipt')
    directory = q.control / SUBJECT
    if directory.exists() or directory.is_symlink():
        raise Violation('certified subject directory already exists')
    directory.mkdir(mode=0o755)
    binary = directory / 'busbar'
    with binary.open('xb') as stream:
        stream.write(data)
    binary.chmod(0o555)
    directory.chmod(0o555)
    if q.execution is not None:
        for name, root in q.execution.roots.items():
            if directory.is_relative_to(root) or Path(root).is_relative_to(directory):
                raise Violation('certified subject would be candidate-writable: ' + name)
        q.execution.extra_readonly.append(directory)
    staged = {'sha256': record['sha256'], 'bytes': record['bytes'], 'core_build_job_id': job['id'],
              'pipeline_id': int(pipeline), 'profile_use': record.get('profile_use'),
              'development_artifact_receipt_sha256': record.get('development_artifact_receipt_sha256')}
    q.receipt['certified_binary'] = staged
    q.receipt['binary_sha256'] = record['sha256']
    q.save()
    return binary, staged


def verify_unchanged(binary, staged):
    if Path(binary).is_symlink() or digest(binary) != staged['sha256']:
        raise Violation('certified subject changed during evaluation')


def discard(q):
    directory = q.control / SUBJECT
    if directory.is_dir() and not directory.is_symlink():
        directory.chmod(0o755)
        shutil.rmtree(directory)

#!/usr/bin/env python3
"""Trusted native admission entry. Full suites run only inside a GitLab job.

The project setting chooses this file's immutable checkout. Candidate code supplies
the product, never the policy, compiler witnesses, command list or merge credential.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from check import Policy, Violation, read

EXTERNAL_EVALUATIONS = {
    'GetBusbar/busbar-plane-llm': 'testing/conformance/external-openai.sh',
    'GetBusbar/busbar-plane-decisions': 'testing/conformance/external-jev.sh',
}


def validate_test_report(path):
    """A successful process exit cannot contradict a failing machine report."""
    try:
        root = ET.parse(path).getroot()
        cases = list(root.iter('testcase'))
        if root.tag not in ('testsuites', 'testsuite') or not cases:
            raise ValueError('empty or unrecognized JUnit report')
        for element in root.iter():
            if element.tag in ('failure', 'error', 'rerunFailure', 'rerunError', 'flakyFailure', 'flakyError'):
                raise ValueError('reported test failure')
            for attribute in ('failures', 'errors'):
                if attribute in element.attrib and int(element.attrib[attribute]) != 0:
                    raise ValueError('nonzero failure/error count')
        if all(case.find('skipped') is not None for case in cases):
            raise ValueError('no executed test cases')
    except (ET.ParseError, OSError, ValueError) as error:
        raise Violation('native test report is not passing: ' + str(error)) from error


def evaluation_job(repository, conformance_only, external_conformance):
    if conformance_only and external_conformance:
        raise Violation('evaluation modes are mutually exclusive')
    if conformance_only and repository == 'GetBusbar/busbar':
        return 'core-conformance'
    if external_conformance and repository in EXTERNAL_EVALUATIONS:
        return 'external-conformance'
    if conformance_only or external_conformance:
        raise Violation('no trusted evaluation command for this repository')
    return None


def requires_native_oracle(repository, external_conformance):
    # The independent endpoint job builds and judges its own actual subject.
    # Native admission still requires the signed shipping oracle, unchanged.
    return repository == 'GetBusbar/busbar-plane-llm' and not external_conformance


class Interrupted(BaseException):
    def __init__(self, signum):
        self.signum = signum
        super().__init__(f'native qualification interrupted by signal {signum}')


class Interruptions:
    def __init__(self):
        self.pending = None
        self.deferred = False

    def handle(self, signum, _frame):
        self.pending = signum
        # A second cancellation must not interrupt command, service or receipt cleanup.
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, signal.SIG_IGN)
        if not self.deferred:
            self.check()

    def check(self):
        if self.pending is not None:
            raise Interrupted(self.pending)


INTERRUPTIONS = None


@contextmanager
def interruption_signals():
    global INTERRUPTIONS
    previous = INTERRUPTIONS
    state = INTERRUPTIONS = Interruptions()
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        for sig in handlers:
            signal.signal(sig, state.handle)
        yield
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        INTERRUPTIONS = previous


@contextmanager
def deferred_interruptions():
    state = INTERRUPTIONS
    previous = state.deferred if state is not None else False
    if state is not None:
        state.deferred = True
    try:
        yield
    finally:
        if state is not None:
            state.deferred = previous
    if state is not None and not previous:
        state.check()


def stop_process_group(process, grace=10):
    """Let nested supervisors finish their TERM/finally cleanup before forcing the group."""
    with deferred_interruptions():
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            process.wait()
            return
        deadline = time.monotonic() + grace
        while True:
            process.poll()  # Reap the group leader when it exits.
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break
            time.sleep(min(0.05, remaining))
        process.wait(timeout=1)


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def fetch_environment():
    env = dict(os.environ)
    token = env['CI_JOB_TOKEN']
    auth = base64.b64encode(('gitlab-ci-token:' + token).encode()).decode()
    server = env['CI_SERVER_URL'].rstrip('/')
    env.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.' + server + '/.extraheader',
               GIT_CONFIG_VALUE_0='Authorization: Basic ' + auth, GIT_TERMINAL_PROMPT='0')
    return env


def checkout(repository, revision, destination):
    destination.mkdir(parents=True, exist_ok=False)
    env = fetch_environment()
    server = env['CI_SERVER_URL'].rstrip('/')
    subprocess.run(['git', '-C', str(destination), 'init', '-q'], check=True)
    subprocess.run(['git', '-C', str(destination), 'fetch', '--depth', '1',
                    server + '/' + repository + '.git', revision], env=env, check=True)
    subprocess.run(['git', '-C', str(destination), 'checkout', '--detach', 'FETCH_HEAD'], check=True)
    if re.fullmatch(r'[0-9a-f]{40}', revision) and git(destination, 'rev-parse', 'HEAD') != revision:
        raise Violation('fetched source revision mismatch')
    return destination


class Qualification:
    def __init__(self, args):
        self.conformance_only = args.conformance_only
        self.external_conformance = getattr(args, 'external_conformance', False)
        self.evaluation_only = self.conformance_only or self.external_conformance
        self.root, self.trusted, self.work = args.checkout.resolve(), args.trusted.resolve(), args.work.resolve()
        self.evidence = self.work / 'evidence'
        self.evidence.mkdir()
        self.repository = os.environ['CI_PROJECT_PATH']
        self.policy = Policy(read(self.trusted / 'ci/architecture.toml'))
        self.receipt = dict(schema='busbar.protected-native-admission/1', status='running', started_at=now(),
            repository=self.repository, source=git(self.root, 'rev-parse', 'HEAD'),
            source_tree=git(self.root, 'rev-parse', 'HEAD^{tree}'),
            policy_revision=git(self.trusted, 'rev-parse', 'HEAD'),
            policy_sha256=digest(self.trusted / 'ci/architecture.toml'),
            config_uri=os.environ['CI_CONFIG_REF_URI'], pipeline_id=os.environ['CI_PIPELINE_ID'],
            job_id=os.environ['CI_JOB_ID'], job_url=os.environ['CI_JOB_URL'], steps=[])
        if self.evaluation_only:
            expected_job = evaluation_job(self.repository, self.conformance_only, self.external_conformance)
            if (os.environ.get('CI_JOB_NAME') != expected_job
                    or os.environ.get('CI_PIPELINE_SOURCE') not in ('api', 'merge_request_event', 'push')):
                raise Violation('conformance requires its trusted job and pipeline source')
            # This receipt supplements, and never replaces, native qualification.
            self.receipt['schema'] = 'busbar.protected-conformance/1'
        if self.receipt['source'] != os.environ['CI_COMMIT_SHA']:
            raise Violation('candidate checkout is not the pipeline commit')
        if git(self.root, 'status', '--porcelain'):
            raise Violation('candidate checkout is dirty before qualification')
        if os.environ['CI_PIPELINE_SOURCE'] == 'merge_request_event':
            if (os.environ['CI_MERGE_REQUEST_TARGET_BRANCH_NAME'] != 'dev'
                    or os.environ['CI_MERGE_REQUEST_SOURCE_PROJECT_ID'] != os.environ['CI_PROJECT_ID']):
                raise Violation('qualification requires a same-project candidate targeting dev')
            remote = os.environ['CI_SERVER_URL'].rstrip('/') + '/' + self.repository + '.git'
            line = subprocess.check_output(['git', 'ls-remote', remote, 'refs/heads/dev'], env=fetch_environment(), text=True)
            target = line.split()[0]
            if not re.fullmatch('[0-9a-f]{40}', target):
                raise Violation('target branch revision is unavailable')
            subprocess.run(['git', '-C', str(self.root), 'fetch', '--no-tags', remote, target], env=fetch_environment(), check=True)
            if subprocess.run(['git', '-C', str(self.root), 'merge-base', '--is-ancestor', target, self.receipt['source']]).returncode:
                raise Violation('candidate must be rebased on current dev and qualified again')
            self.receipt['target_revision'] = target
        elif self.evaluation_only and os.environ['CI_PIPELINE_SOURCE'] == 'api':
            self.receipt['target_revision'] = None
        elif os.environ['CI_PIPELINE_SOURCE'] == 'push' and os.environ.get('CI_COMMIT_BRANCH') == 'dev':
            self.receipt['target_revision'] = self.receipt['source']
        else:
            raise Violation('qualification requires a dev MR or published dev commit')
        # Build/test children receive no project tokens, cloud credentials or merge/settings
        # credentials. The short-lived job token is used only by the trusted source fetcher.
        self.env = {key: value for key, value in os.environ.items() if key in
            ('PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'CARGO_HOME', 'RUSTUP_HOME')}
        # Keep native test libraries free of embedded debug-symbol bulk. Rust assertions
        # and optimization settings are unchanged; archive admission still hashes the
        # actual complete library used by every runtime and custody witness.
        self.env.update(CI='1', RUSTUP_TOOLCHAIN='1.98.0', CARGO_TARGET_DIR=str(self.work / 'target'),
            RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='',
            CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
            CARGO_BUILD_JOBS=str(min(os.cpu_count() or 4, 16)), CARGO_TERM_COLOR='never',
            TMPDIR=str(self.work / 'tmp'), BUSBAR_TEST_TMP_ROOT=str(self.work / 'tmp/tests'),
            MODERNCI_CACHE_DIR=str(self.work / 'cache'), XDG_CACHE_HOME=str(self.work / 'cache'),
            PYTHONDONTWRITEBYTECODE='1', CARGO_NET_GIT_FETCH_WITH_CLI='true', GIT_TERMINAL_PROMPT='0')
        self.env['CI_SERVER_HOST'] = os.environ['CI_SERVER_HOST']
        # Runner umasks can permit group/world writes. Custody requires a private
        # temporary directory, independent of the runner's checkout permissions.
        Path(self.env['TMPDIR']).mkdir(mode=0o700)
        self.save()

    def save(self):
        (self.evidence / 'receipt.json').write_text(json.dumps(self.receipt, indent=2) + '\n')

    def run(self, name, argv, cwd=None, timeout=3600):
        row = dict(name=name, argv=list(map(str, argv)), status='running', started_at=now())
        self.receipt['steps'].append(row)
        self.save()
        is_nextest = list(argv[:3]) == ['cargo', 'nextest', 'run']
        if is_nextest:
            locate = ['cargo', 'locate-project', '--workspace', '--message-format', 'plain']
            if '--manifest-path' in argv:
                locate += ['--manifest-path', argv[argv.index('--manifest-path') + 1]]
            workspace = Path(subprocess.check_output(locate, cwd=cwd or self.root, env=self.env, text=True).strip()).parent
            # Nextest's default store is workspace-relative, independent of Cargo's
            # target-dir. The distribution workspace therefore has its own report.
            junit = workspace / 'target/nextest/default/native.xml'
            junit.unlink(missing_ok=True)
        with (self.evidence / (name + '.stdout')).open('wb') as out, (self.evidence / (name + '.stderr')).open('wb') as err:
            process = None
            try:
                with deferred_interruptions():
                    process = subprocess.Popen(argv, cwd=cwd or self.root, env=self.env, stdout=out, stderr=err, start_new_session=True)
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row.update(status='timeout', finished_at=now())
                self.save()
                raise
            except Interrupted as error:
                row.update(status='interrupted', signal=error.signum, finished_at=now())
                self.save()
                raise
            finally:
                # TERM gives nested conformance supervisors time to reap their own
                # independent sessions; KILL remains bounded for unresponsive commands.
                if process is not None:
                    try:
                        stop_process_group(process)
                    except Interrupted as error:
                        row.update(status='interrupted', signal=error.signum, finished_at=now())
                        self.save()
                        raise
        row.update(status='pass' if code == 0 else 'fail', exit_code=code, finished_at=now())
        for stream in ('stdout', 'stderr'):
            row[stream + '_sha256'] = digest(self.evidence / (name + '.' + stream))
        if is_nextest and code == 0:
            if not junit.is_file():
                raise Violation('nextest did not produce its current machine-readable report')
            shutil.copyfile(junit, self.evidence / (name + '.xml'))
            row['junit_sha256'] = digest(junit)
            try:
                validate_test_report(junit)
            except Violation:
                row.update(status='fail', exit_code=1)
                self.save()
                raise
        self.save()
        print(json.dumps(row), flush=True)
        if code:
            raise Violation(f'{name} failed; no automatic retry')
        return self.evidence / (name + '.stdout')

    def host(self):
        if hasattr(self, '_host'):
            return self._host
        if self.repository == 'GetBusbar/busbar':
            host = self.root
        else:
            # Owner-controlled cohort input during an SDK cutover; ordinary candidates
            # cannot supply pipeline variable overrides. Afterwards current dev is resolved
            # once and the exact resulting revision is retained in the receipt.
            revision = os.environ.get('BUSBAR_ADMISSION_CORE_REVISION', 'dev')
            host = checkout('GetBusbar/busbar', revision, self.work / 'host')
            if self.repository != 'GetBusbar/busbar-release':
                sdk = (self.root / '.busbar-ref').read_text().split()[0]
                if json.loads((host / 'scripts/ci-product-pins.json').read_text())['sdk'] != sdk:
                    raise Violation('assembled host and plugin SDK differ; submit a coherent cohort')
        self.receipt['host_revision'] = git(host, 'rev-parse', 'HEAD')
        self.env['BUSBAR_CHECKOUT'] = str(host)
        self.env['BUSBAR_ADMISSION_CORE_REVISION'] = self.receipt['host_revision']
        self.save()
        self._host = host
        return host

    def sdk(self):
        if not hasattr(self, '_sdk'):
            pin = json.loads((self.host() / 'scripts/ci-product-pins.json').read_text())['sdk']
            self._sdk = checkout('GetBusbar/busbar', pin, self.work / 'sdk')
            self.receipt['sdk_revision'] = pin
            self.save()
        return self._sdk

    def architecture(self, sdk=None):
        command = ['python3', str(self.trusted / 'scripts/architecture/check.py'), '--policy', str(self.trusted / 'ci/architecture.toml'),
            '--repository', self.repository, '--checkout', str(self.root), '--trusted', str(self.trusted),
            '--scratch', str(self.work / 'architecture'), '--output', str(self.evidence / 'architecture.json')]
        if sdk:
            command += ['--sdk', str(sdk)]
        self.run('architecture', command)

    def core(self):
        self.architecture()
        self.run('architecture-regressions', [sys.executable, '-m', 'unittest', 'discover',
            '-s', str(self.trusted / 'scripts/architecture'), '-p', 'test_*.py'], cwd=self.trusted)
        host = self.host()
        sdk = json.loads((host / 'scripts/ci-product-pins.json').read_text())['sdk']
        self.sdk()
        # A local assembly patch must not hide SDK source drift behind an old pin.
        self.run('sdk-source-identity', ['git', 'diff', '--exit-code', sdk, 'HEAD', '--',
            'crates/busbar-contract/src', 'crates/busbar-contract/include', 'crates/busbar-contract/Cargo.toml'])
        self.receipt['sdk_revision'] = sdk
        from native_fixtures import Services
        with Services(self, host, all_services=True):
            envfile = self.run('product-inputs', ['bash', str(self.trusted / 'scripts/ci-product-inputs.sh')])
            path = envfile.read_text().strip()
            raw = subprocess.check_output(['bash', '-c', 'source "$1"; env -0', 'product-inputs', path], env=self.env)
            self.env.update(dict(value.decode().split('=', 1) for value in raw.split(b'\0') if value))
            self.receipt['product_input_bytes'] = {
                key: Path(value).stat().st_size for key, value in self.env.items()
                if key.startswith('BUSBAR_') and key.endswith(('_CDYLIB', '_PLUGIN'))
                and Path(value).is_file()
            }
            self.save()
            vector = json.loads((host / 'scripts/ci-product-pins.json').read_text())
            witness = vector['c_witness']
            if witness['sdk'] != vector['sdk']:
                raise Violation('C witness and assembled SDK pins differ')
            c_source = checkout('GetBusbar/' + witness['repo'], witness['commit'], self.work / 'c-witness')
            library = self.work / ('c-witness.dylib' if sys.platform == 'darwin' else 'c-witness.so')
            self.run('c-witness-build', ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
                '-shared', '-fPIC', '-fvisibility=hidden', '-I', str(host / Path(witness['header']).parent),
                str(c_source / 'secret-c/busbar_secret_c.c'), '-o', str(library)])
            self.env.update(BUSBAR_C_ABI_SOURCES=str(c_source / 'secret-c'), BUSBAR_C_ABI_LIBRARY=str(library))
            nextest = ['--no-fail-fast', '--test-threads', self.env['CARGO_BUILD_JOBS'], '--tool-config-file',
                       'admission:' + str(self.trusted / 'ci/native-nextest.toml')]
            selected = 'binary(mcp_stdio_serve) | binary(hook_parity_driver) | (package(busbar-default) & test(/^distribution::admin_cross_plane::/)) | (package(busbar-default) & test(/(serve_tests|secret_source|connector|boot)::/))'
            features = 'test-harness,transport-webrtc,openapi-schema'
            commands = [
                ('root-fmt', ['cargo', 'fmt', '--all', '--check']),
                ('default-fmt', ['cargo', 'fmt', '--manifest-path', 'dist/default/Cargo.toml', '--all', '--check']),
                ('workspace-doctests', ['cargo', 'test', '--workspace', '--doc', '--locked', '--no-fail-fast']),
                ('loader-witnesses', ['cargo', 'build', '--locked', '-p', 'busbar-plugin-loader', '--examples']),
                ('root-runtime', ['cargo', 'nextest', 'run', '--workspace', '--locked', *nextest]),
                ('default-runtime', ['cargo', 'nextest', 'run', '--locked', '--manifest-path', 'dist/default/Cargo.toml', '--workspace', *nextest]),
                ('root-clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings']),
                ('default-clippy', ['cargo', 'clippy', '--manifest-path', 'dist/default/Cargo.toml', '--workspace', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings']),
                ('root-clippy-nodefault', ['cargo', 'clippy', '--workspace', '--all-targets', '--no-default-features', '--locked', '--', '-D', 'warnings']),
                ('selected-default', ['cargo', 'nextest', 'run', '--locked', '--manifest-path', 'dist/default/Cargo.toml', '--features', features, '-E', selected, *nextest]),
                ('selected-errors', ['cargo', 'nextest', 'run', '--locked', '--manifest-path', 'dist/default/Cargo.toml', '--features', features, '-E', 'test(keys_error_surface_is_byte_stable) | test(every_admin_error_surface_answers_its_declared_status)', *nextest]),
                ('timing-admin', ['cargo', 'nextest', 'run', '--locked', '-p', 'busbar-kernel', '-p', 'busbar-core-admin', '--features', 'busbar-kernel/timing,busbar-kernel/openapi-schema,busbar-core-admin/openapi-schema', '-E', 'binary(timing_smoke) | package(busbar-core-admin) | (package(busbar-kernel) & test(/timing::/))', *nextest]),
                ('bounded-loom', ['cargo', 'test', '--release', '--locked', '-p', 'busbar-kernel', '--features', 'loom-model', 'txn_loom']),
                ('dependency-policy', ['cargo', 'deny', 'check']),
                ('dependency-vet', ['cargo', 'vet']),
                ('default-dependency-policy', ['cargo', 'deny', '--manifest-path', 'dist/default/Cargo.toml', 'check']),
                ('final-binary', ['cargo', 'build', '--release', '--locked', '--manifest-path', 'dist/default/Cargo.toml', '--bin', 'busbar']),
            ]
            for name, command in commands:
                self.run(name, command)
            self.run('default-dependency-vet', ['cargo', 'vet'], cwd=host / 'dist/default')
            binary = Path(self.env['CARGO_TARGET_DIR']) / 'release/busbar'
            shutil.copyfile(binary, self.evidence / 'busbar')
            self.receipt['binary_sha256'] = digest(binary)
            self.receipt['dependency_vector'] = json.loads((host / 'scripts/ci-product-pins.json').read_text())
            self.receipt['root_lock_sha256'] = digest(host / 'Cargo.lock')
            self.receipt['distribution_lock_sha256'] = digest(host / 'dist/default/Cargo.lock')
            self.env['BUSBAR_BIN'] = str(binary)
            # Section 15 qualifies the native product and its boundary. Core's
            # separate certification launcher includes the unimplemented ModernCI
            # attestation producer; this cutover does not commission that project.

    def plugin(self):
        host = self.host()
        sdk_pin = (self.root / '.busbar-ref').read_text().split()[0]
        sdk = self.sdk()
        self.receipt['sdk_revision'] = sdk_pin
        self.architecture(sdk)
        from native_fixtures import Services
        with Services(self, host):
            from native_plugins import qualify_plugin
            qualify_plugin(self, host, sdk)

    def conformance(self, name):
        suites = self.root / 'testing/conformance/suites.tsv'
        if suites.is_file() and any(line.strip() and not line.lstrip().startswith('#') for line in suites.read_text().splitlines()):
            try:
                self.run(name, ['bash', str(self.root / 'testing/conformance/run.sh')], timeout=10800)
            finally:
                # Failed and blocked evaluations are evidence too. Preserve their
                # actual verdicts without changing the command or job's failure.
                self.copy_conformance()

    def copy_conformance(self):
        source = self.root / 'target/conformance'
        if not source.is_dir():
            raise Violation('missing conformance output')
        destination = self.evidence / 'conformance'
        destination.mkdir(exist_ok=True)
        for relative in ('invocation.json', *[str(p.relative_to(source)) for p in sorted((source / 'verdicts').glob('*.json'))]):
            path = source / relative
            if path.is_symlink() or not path.is_file():
                raise Violation('missing or indirect conformance evidence')
            out = destination / relative
            out.parent.mkdir(exist_ok=True)
            shutil.copyfile(path, out)

    def core_conformance(self):
        """Evaluate required core suites, retaining failures and release-input gaps."""
        self.sdk()
        # The full applicable upstream mTLS signature roster contains thousands
        # of handshakes. Keep its three bounded legs inside this per-suite cap;
        # the enclosing command retains its three-hour bound.
        self.env['CONFORMANCE_TIMEOUT_SECONDS'] = '3600'
        failed = False
        try:
            self.conformance('core-native-conformance')
        except Violation:
            failed = True
        out = self.evidence / 'sigstore'
        out.mkdir()
        self.env['CONFORMANCE_OUT'] = str(out)
        try:
            self.run('sigstore-release-verification', ['python3', '-I',
                str(self.root / 'testing/conformance/sigstore.py'), '--require'])
        except Violation:
            failed = True
        if failed:
            raise Violation('one or more conformance evaluations did not pass; inspect actual verdicts')

    def external_endpoint_conformance(self):
        """Retain external judges' results without granting native admission."""
        sdk = self.sdk()
        self.receipt['sdk_revision'] = git(sdk, 'rev-parse', 'HEAD')
        self.architecture(sdk)
        self.env['BUSBAR_PIN'] = self.receipt['host_revision']
        self.env['CONFORMANCE_OUT'] = str(self.evidence / 'external')
        command = self.root / EXTERNAL_EVALUATIONS[self.repository]
        if not command.is_file() or command.is_symlink():
            raise Violation('missing external evaluation entry point')
        try:
            self.run('external-endpoint-conformance', ['bash', str(command)], timeout=10800)
        finally:
            output = self.evidence / 'external'
            files = {}
            for path in sorted(output.rglob('*')):
                if path.is_symlink():
                    raise Violation('indirect external evaluation evidence')
                if path.is_file():
                    files[str(path.relative_to(output))] = digest(path)
            self.receipt['external_evidence'] = files
            self.save()
            if 'evaluation.json' not in files:
                raise Violation('external judge produced no evaluation record')

    def finish(self, status, error=None):
        self.receipt.update(status=status, finished_at=now())
        if error:
            self.receipt['error'] = str(error)
        self.save()
        destination = self.root / 'boundary-evidence'
        if destination.exists():
            raise Violation('candidate supplied the evidence output directory')
        shutil.copytree(self.evidence, destination)


def qualify():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted', required=True, type=Path)
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--conformance-only', action='store_true')
    modes.add_argument('--external-conformance', action='store_true')
    args = parser.parse_args()
    if not all(os.environ.get(key) for key in ('CI_JOB_ID', 'CI_PIPELINE_ID', 'CI_PROJECT_PATH', 'CI_CONFIG_REF_URI')):
        raise Violation('full native qualification runs in GitLab CI only')
    qualification = None
    try:
        with deferred_interruptions():
            qualification = Qualification(args)
        if requires_native_oracle(qualification.repository, args.external_conformance):
            from native_oracle import prepare as prepare_oracle
            prepare_oracle(qualification)
        from native_sources import prepare
        prepare(qualification, qualification.host())
        evaluation_error = None
        if args.external_conformance:
            try:
                qualification.external_endpoint_conformance()
            except Violation as error:
                evaluation_error = error
        elif args.conformance_only:
            try:
                qualification.core_conformance()
            except Violation as error:
                evaluation_error = error
        elif qualification.repository == 'GetBusbar/busbar':
            qualification.core()
        elif qualification.repository == 'GetBusbar/busbar-release':
            from native_plugins import qualify_generator
            qualify_generator(qualification)
        elif qualification.repository in qualification.policy.data['repositories']:
            qualification.plugin()
        else:
            raise Violation('unclassified native project')
        if git(qualification.root, 'rev-parse', 'HEAD') != qualification.receipt['source']:
            raise Violation('source revision changed during qualification')
        if git(qualification.root, 'diff', 'HEAD', '--'):
            raise Violation('tracked source changed during qualification')
        qualification.receipt['source_unchanged'] = True
        archive = subprocess.Popen(['git', '-C', str(qualification.root), 'archive', '--format=tar', 'HEAD'], stdout=subprocess.PIPE)
        qualification.receipt['source_archive_sha256'] = hashlib.file_digest(archive.stdout, 'sha256').hexdigest()
        archive.stdout.close()
        if archive.wait():
            raise Violation('could not bind the qualified source archive')
        if evaluation_error is not None:
            raise evaluation_error
        qualification.finish('pass')
    except BaseException as error:
        if qualification is not None:
            qualification.finish('fail', error)
        raise
    finally:
        # Only the unique job workspace created by the trusted bootstrap is disposable.
        work = qualification.work if qualification is not None else args.work.resolve()
        if work.name == 'boundary-' + os.environ['CI_PROJECT_ID'] + '-' + os.environ['CI_JOB_ID']:
            shutil.rmtree(work)


def main():
    with interruption_signals():
        qualify()


if __name__ == '__main__':
    main()

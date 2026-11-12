#!/usr/bin/env python3
"""Trusted native admission entry. Full suites run only inside a GitLab job.

The project setting chooses this file's immutable checkout. Candidate code supplies
the product, never the policy, compiler witnesses, command list or merge credential.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager, ExitStack, nullcontext
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from check import Policy, Violation, read
from native_policy import native_settings


def native_scheduling(execution):
    # The trusted controller sees host CPUs, but rustc runs inside the candidate's
    # smaller CPU/memory boundary. Do not fan out to the controller's CPU count.
    available = os.cpu_count() or 4
    memory = None
    if execution is not None:
        available = min(available, execution.config['resources']['cpus'])
        memory = execution.config['resources']['memory_bytes']
    test_threads = max(1, min(available, 16))
    # Conservative scheduling after concurrent optimized compilers exhausted the
    # 6 GiB boundary. This is not a measured peak or a guarantee that one fits.
    memory_per_slot = 6 * 1024**3
    build_jobs = (test_threads if memory is None else
                  max(1, min(test_threads, memory // memory_per_slot)))
    # Unoptimized (dev/test-profile) compilers need far less memory than the
    # optimized ones that exhausted the boundary; one job left 3 of 4 CPUs idle
    # for every check and test build. Optimized steps keep the slot budget above.
    # Each step records its cgroup peak, so this budget is checked by evidence
    # and a too-small boundary fails visibly (OOMKilled) rather than silently.
    unoptimized_memory_per_slot = 2 * 1024**3
    unoptimized_build_jobs = (test_threads if memory is None else
                              max(1, min(test_threads, memory // unoptimized_memory_per_slot)))
    return {'build_jobs': build_jobs, 'test_threads': test_threads,
            'unoptimized_build_jobs': unoptimized_build_jobs,
            'candidate_memory_bytes': memory, 'compiler_memory_bytes_per_slot': memory_per_slot,
            'unoptimized_compiler_memory_bytes_per_slot': unoptimized_memory_per_slot,
            'memory_policy': 'conservative-slot-budget-not-measured-peak-or-fit-guarantee'}


OPTIMIZED_STEPS = frozenset({'product-inputs', 'bounded-loom', 'final-binary'})


def step_build_jobs(name, argv, scheduling):
    """Optimized builds keep the conservative slot budget; unoptimized ones use the CPUs."""
    if name in OPTIMIZED_STEPS or '--release' in argv or 'unoptimized_build_jobs' not in scheduling:
        return scheduling['build_jobs']
    return scheduling['unoptimized_build_jobs']


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


def evaluation_job(repository, conformance_only, external_conformance, policy=None):
    if conformance_only and external_conformance:
        raise Violation('evaluation modes are mutually exclusive')
    if conformance_only and repository == 'GetBusbar/busbar':
        return 'core-conformance'
    if external_conformance and native_settings(repository, policy).get('external_conformance'):
        return 'external-conformance'
    if conformance_only or external_conformance:
        raise Violation('no trusted evaluation command for this repository')
    return None


def requires_native_oracle(repository, external_conformance, policy=None):
    # The independent endpoint job builds and judges its own actual subject.
    # Native admission still requires the signed shipping oracle, unchanged.
    return native_settings(repository, policy).get('native_oracle', False) and not external_conformance


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
    return subprocess.check_output(['git', '-c', 'safe.directory=' + str(Path(root).resolve()), '-C', str(root), *args], text=True).strip()


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


@contextmanager
def candidate_output(q, source, limit, *, compiler_output=False):
    """Open each component without following links, including during rename races."""
    source = Path(source)
    roots = [q.root.resolve() / 'target', q.root.resolve() / 'dist/default/target']
    if getattr(q, 'work', None) is not None:
        roots.append(q.work.resolve())
    if (not source.is_absolute() or source != Path(os.path.abspath(source))
            or not any(source.is_relative_to(root) for root in roots)):
        raise Violation('collected output escapes candidate build roots')
    descriptors = []
    try:
        parent = os.open(source.anchor, os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(parent)
        for part in source.parts[1:-1]:
            parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(parent)
        fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            execution = getattr(q, 'execution', None)
            owner = (execution.config['isolation']['uid_map'][1] + execution.config['uid']
                     if execution is not None else os.geteuid())
            linked_compiler_output = compiler_output and before.st_uid == owner and before.st_nlink > 0
            if (not stat.S_ISREG(before.st_mode) or before.st_size > limit
                    or (before.st_nlink != 1 and not linked_compiler_output)):
                raise Violation('candidate output is nonregular, linked or exceeds limit')
            yield stream, before
            after = os.fstat(stream.fileno())
            fields = ('st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
            if any(getattr(before, key) != getattr(after, key) for key in fields):
                raise Violation('candidate output changed during collection')
    except OSError as error:
        raise Violation('missing or indirect candidate output: ' + str(error)) from error
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def collect_output(q, source, destination, limit=2 * 1024**3, *, compiler_output=False):
    """Copy only regular candidate outputs after execution has ended; never follow links."""
    source, destination = Path(source), Path(destination)
    created = False
    try:
        with candidate_output(q, source, limit, compiler_output=compiler_output) as (stream, before):
            with destination.open('xb') as output:
                created = True
                remaining = limit
                while chunk := stream.read(min(1024**2, remaining + 1)):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise Violation('candidate output grew beyond limit')
                    output.write(chunk)
                if limit - remaining != before.st_size:
                    raise Violation('candidate output changed during collection')
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise
    if hasattr(q, 'receipt'):
        q.receipt.setdefault('collected_outputs', []).append({
            'source': str(source), 'destination': str(destination),
            'sha256': digest(destination), 'bytes': before.st_size,
            'regular_file': True, 'single_link': True, 'source_link_count': before.st_nlink,
            'compiler_output': compiler_output, 'mutation_checked': True,
        })
    return destination


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


def published_dev_target(repository, source):
    """Requalification must bind to the current published dev, never an arbitrary ref."""
    remote = os.environ['CI_SERVER_URL'].rstrip('/') + '/' + repository + '.git'
    lines = subprocess.check_output(['git', 'ls-remote', remote, 'refs/heads/dev'],
                                    env=fetch_environment(), text=True, cwd='/').splitlines()
    if len(lines) != 1 or lines[0].split() != [source, 'refs/heads/dev']:
        raise Violation('published dev moved; qualify its current revision')
    return source


CORE_LINT_COMMANDS = (
    ('root-clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings']),
    ('default-clippy', ['cargo', 'clippy', '--manifest-path', 'dist/default/Cargo.toml', '--workspace', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings']),
    ('root-clippy-nodefault', ['cargo', 'clippy', '--workspace', '--all-targets', '--no-default-features', '--locked', '--', '-D', 'warnings']),
)


class Qualification:
    def __init__(self, args):
        self.conformance_only = args.conformance_only
        self.external_conformance = getattr(args, 'external_conformance', False)
        self.evaluation_only = self.conformance_only or self.external_conformance
        self.root, self.trusted, self.work = args.checkout.resolve(), args.trusted.resolve(), args.work.resolve()
        self.control = self.work
        self.execution = None
        if getattr(args, 'confinement', None):
            from native_confinement import Execution
            if not args.confinement_sha256 or digest(args.confinement) != args.confinement_sha256:
                raise Violation('protected confinement configuration digest differs')
            self.work = self.control / 'candidate'
            self.work.mkdir(mode=0o700)
            self.harness = self.control / 'harness'
            self.harness.mkdir(mode=0o700)
            # Controller-owned source is bind-mounted read-only, but the
            # remapped compiler must be able to traverse its mount root.
            self.harness.chmod(0o755)
            self.execution = Execution(json.loads(args.confinement.read_text()),
                {'checkout': self.root, 'candidate': self.work, 'trusted': self.trusted, 'harness': self.harness}, self.control)
        elif getattr(args, 'confinement_sha256', None):
            raise Violation('confinement digest requires its configuration')
        self.evidence = self.control / 'evidence'
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
        # A fresh job VM does not separate candidate code from this controller.
        # This development receipt must never substitute for independent host
        # observation required by the protected release producer.
        self.receipt['execution_boundary'] = {
            'mode': 'host-subprocess', 'isolated': False, 'release_eligible': False,
        }
        if self.execution is not None:
            self.receipt['execution_boundary'] = {
                'mode': 'docker-confined', 'isolated': False, 'release_eligible': False,
                'confinement_configured': True,
                'approved_configuration_sha256': args.confinement_sha256,
                'observations': self.execution.observations,
                'observer': 'protected-controller',
                'limitation': 'development execution evidence; not a release-producer attestation',
            }
            capability_path = getattr(args, 'conformance_capabilities', None)
            capability_digest = getattr(args, 'conformance_capabilities_sha256', None)
            if bool(capability_path) != bool(capability_digest):
                raise Violation('conformance capabilities require an independently approved digest')
            self.receipt['conformance_capabilities_sha256'] = self.execution.set_conformance_capabilities(
                capability_path, self.repository, self.receipt['source'], capability_digest)
        elif getattr(args, 'conformance_capabilities', None) or getattr(args, 'conformance_capabilities_sha256', None):
            raise Violation('conformance capabilities require confined execution')
        if self.evaluation_only:
            expected_job = evaluation_job(self.repository, self.conformance_only, self.external_conformance, self.policy)
            if (os.environ.get('CI_JOB_NAME') != expected_job
                    or os.environ.get('CI_PIPELINE_SOURCE') not in ('api', 'merge_request_event', 'push')):
                raise Violation('conformance requires its trusted job and pipeline source')
            # This receipt supplements, and never replaces, native qualification.
            self.receipt['schema'] = 'busbar.protected-conformance/1'
        if self.receipt['source'] != os.environ['CI_COMMIT_SHA']:
            raise Violation('candidate checkout is not the pipeline commit')
        tools_path = getattr(args, 'conformance_inputs', None)
        tools_digest = getattr(args, 'conformance_inputs_sha256', None)
        if tools_path or tools_digest:
            if not self.execution or not tools_path or not tools_digest:
                raise Violation('conformance instruments require confined execution and a protected plan digest')
            from native_conformance_inputs import stage as stage_instruments
            stage_instruments(self, tools_path, tools_digest)
        self.staged_fixtures = {}
        fixture_path = getattr(args, 'fixture_inputs', None)
        fixture_digest = getattr(args, 'fixture_inputs_sha256', None)
        if bool(fixture_path) != bool(fixture_digest) or (fixture_path and self.execution is None):
            raise Violation('staged fixture inputs require confinement and a protected digest')
        if fixture_path:
            from native_staged_fixtures import stage
            self.staged_fixtures = stage(self, fixture_path, fixture_digest)
        if git(self.root, 'status', '--porcelain'):
            raise Violation('candidate checkout is dirty before qualification')
        if os.environ['CI_PIPELINE_SOURCE'] == 'merge_request_event':
            if (os.environ['CI_MERGE_REQUEST_TARGET_BRANCH_NAME'] != 'dev'
                    or os.environ['CI_MERGE_REQUEST_SOURCE_PROJECT_ID'] != os.environ['CI_PROJECT_ID']):
                raise Violation('qualification requires a same-project candidate targeting dev')
            remote = os.environ['CI_SERVER_URL'].rstrip('/') + '/' + self.repository + '.git'
            line = subprocess.check_output(['git', 'ls-remote', remote, 'refs/heads/dev'],
                                           env=fetch_environment(), text=True, cwd='/')
            target = line.split()[0]
            if not re.fullmatch('[0-9a-f]{40}', target):
                raise Violation('target branch revision is unavailable')
            subprocess.run(['git', '-C', str(self.root), 'fetch', '--no-tags', remote, target], env=fetch_environment(), check=True)
            if subprocess.run(['git', '-C', str(self.root), 'merge-base', '--is-ancestor', target, self.receipt['source']]).returncode:
                raise Violation('candidate must be rebased on current dev and qualified again')
            self.receipt['target_revision'] = target
        elif os.environ['CI_PIPELINE_SOURCE'] in ('push', 'api') and os.environ.get('CI_COMMIT_BRANCH') == 'dev':
            self.receipt['target_revision'] = (published_dev_target(self.repository, self.receipt['source'])
                if os.environ['CI_PIPELINE_SOURCE'] == 'api' else self.receipt['source'])
            # Server-provided; consumers require a protected dev ref for push/api credit.
            self.receipt['commit_ref_protected'] = os.environ.get('CI_COMMIT_REF_PROTECTED') == 'true'
        elif self.evaluation_only and os.environ['CI_PIPELINE_SOURCE'] == 'api':
            self.receipt['target_revision'] = None
        else:
            raise Violation('qualification requires a dev MR or published dev commit')
        # Build/test children receive no project tokens, cloud credentials or merge/settings
        # credentials. The short-lived job token is used only by the trusted source fetcher.
        self.env = {key: value for key, value in os.environ.items() if key in
            ('PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'CARGO_HOME', 'RUSTUP_HOME')}
        # Keep native test libraries free of embedded debug-symbol bulk. Rust assertions
        # and optimization settings are unchanged; archive admission still hashes the
        # actual complete library used by every runtime and custody witness.
        self.receipt['native_scheduling'] = native_scheduling(self.execution)
        self.env.update(CI='1', RUSTUP_TOOLCHAIN='1.98.0', CARGO_TARGET_DIR=str(self.work / 'target'),
            RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='',
            CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
            CARGO_BUILD_JOBS=str(self.receipt['native_scheduling']['build_jobs']), CARGO_TERM_COLOR='never',
            TMPDIR=str(self.work / 'tmp'), BUSBAR_TEST_TMP_ROOT=str(self.work / 'tmp/tests'),
            MODERNCI_CACHE_DIR=str(self.work / 'cache'), XDG_CACHE_HOME=str(self.work / 'cache'),
            PYTHONDONTWRITEBYTECODE='1', CARGO_NET_GIT_FETCH_WITH_CLI='true', GIT_TERMINAL_PROMPT='0')
        self.env['CI_SERVER_HOST'] = os.environ['CI_SERVER_HOST']
        # Evidence links name the real native job; these fields contain no credentials.
        for key in ('CI_JOB_URL', 'CI_JOB_ID', 'CI_PIPELINE_ID'):
            if key in os.environ:
                self.env[key] = os.environ[key]
        # Runner umasks can permit group/world writes. Custody requires a private
        # temporary directory, independent of the runner's checkout permissions.
        Path(self.env['TMPDIR']).mkdir(mode=0o700)
        self.save()

    @contextmanager
    def preparation(self, name):
        """Retain controller preparation cost separately from qualification checks."""
        row = {'name': name, 'started_at': now(), 'status': 'running'}
        self.receipt.setdefault('preparation', []).append(row)
        started = time.monotonic()
        self.save()
        print(json.dumps({'native_preparation': row}), flush=True)
        try:
            yield
        except BaseException:
            row['status'] = 'fail'
            raise
        else:
            row['status'] = 'pass'
        finally:
            row.update(finished_at=now(), elapsed_seconds=round(time.monotonic() - started, 3))
            self.save()
            print(json.dumps({'native_preparation': row}), flush=True)

    def save(self):
        execution = getattr(self, 'execution', None)
        if execution and 'execution_boundary' in self.receipt:
            from native_confinement import canonical
            configuration = hashlib.sha256(canonical(execution.config)).hexdigest()
            rows = execution.observations
            if any(row.get('configuration_sha256') != configuration for row in rows):
                raise Violation('execution configuration differs from retained observations')
            # Approval binds the original input bytes; observations bind the
            # canonical runtime after measured, protected instrument additions.
            self.receipt['execution_boundary']['configuration_sha256'] = configuration
            self.receipt['execution_boundary']['isolated'] = bool(rows) and all(
                row.get('inspected') and row.get('disposed') and row.get('storage')
                and row.get('user_namespace') for row in rows)
        (self.evidence / 'receipt.json').write_text(json.dumps(self.receipt, indent=2) + '\n')

    def run(self, name, argv, cwd=None, timeout=3600):
        return self._run(name, argv, cwd, timeout, controller=False)

    def run_controller(self, name, argv, cwd=None, timeout=3600):
        return self._run(name, argv, cwd, timeout, controller=True)

    def _run(self, name, argv, cwd=None, timeout=3600, controller=False):
        execution = None if controller else getattr(self, 'execution', None)
        argv = list(argv)
        if execution and argv[:2] == ['cargo', 'deny']:
            argv.insert(2, '--frozen')
        if execution and argv[:2] == ['cargo', 'vet']:
            argv[2:2] = ['--locked', '--frozen']
        row = dict(name=name, argv=list(map(str, argv)), status='running', started_at=now(),
                   authority='controller' if controller else 'candidate')
        self.receipt['steps'].append(row)
        self.save()
        is_nextest = list(argv[:3]) == ['cargo', 'nextest', 'run']
        if is_nextest:
            locate = ['cargo', 'locate-project', '--workspace', '--message-format', 'plain']
            if '--manifest-path' in argv:
                locate += ['--manifest-path', argv[argv.index('--manifest-path') + 1]]
            workspace = Path((execution.check_output if execution else subprocess.check_output)(
                locate, cwd=cwd or self.root, env=self.env, text=True).strip()).parent
            if execution and not any(workspace.is_relative_to(p) for p in (self.root, self.work)):
                raise Violation('candidate workspace report escapes writable output roots')
            # Nextest's default store is workspace-relative, independent of Cargo's
            # target-dir. The distribution workspace therefore has its own report.
            junit = workspace / 'target/nextest/default/native.xml'
            if execution and (junit.is_symlink() or not junit.resolve().is_relative_to(workspace.resolve())):
                raise Violation('indirect candidate report path')
            junit.unlink(missing_ok=True)
        with (self.evidence / (name + '.stdout')).open('wb') as out, (self.evidence / (name + '.stderr')).open('wb') as err:
            process = None
            boundary = ExitStack()
            try:
                with deferred_interruptions():
                    command, environment = argv, self.env
                    scheduling = self.receipt.get('native_scheduling')
                    if scheduling and 'CARGO_BUILD_JOBS' in environment:
                        jobs = step_build_jobs(name, argv, scheduling)
                        environment = dict(environment, CARGO_BUILD_JOBS=str(jobs))
                        row['build_jobs'] = jobs
                    if execution:
                        command, environment, observation = boundary.enter_context(execution.invocation(argv, cwd or self.root, environment))
                        row['container'] = observation
                    elif controller and getattr(self, 'execution', None):
                        environment = dict(self.env, DOCKER_HOST=self.execution.config['docker_host'])
                    process = subprocess.Popen(command, cwd=cwd or self.root, env=environment, stdout=out, stderr=err, start_new_session=True)
                from native_resources import StepObserver, wait_observed
                observer = StepObserver(name, (row.get('container') or {}).get('container_id'))
                try:
                    code = wait_observed(process, timeout, observer)
                finally:
                    row['resources'] = observer.summary()
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
                try:
                    if process is not None:
                        stop_process_group(process)
                except Interrupted as error:
                    row.update(status='interrupted', signal=error.signum, finished_at=now())
                    self.save()
                    raise
                finally:
                    with deferred_interruptions():
                        boundary.close()
        row.update(status='pass' if code == 0 else 'fail', exit_code=code, finished_at=now())
        for stream in ('stdout', 'stderr'):
            row[stream + '_sha256'] = digest(self.evidence / (name + '.' + stream))
        if is_nextest and code == 0:
            if not junit.is_file():
                raise Violation('nextest did not produce its current machine-readable report')
            collected = collect_output(self, junit, self.evidence / (name + '.xml'), limit=64 * 1024**2)
            row['junit_sha256'] = digest(collected)
            try:
                validate_test_report(collected)
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
        scratch = self.harness / 'architecture' if self.execution else self.work / 'architecture'
        command = ['python3', str(self.trusted / 'scripts/architecture/check.py'), '--policy', str(self.trusted / 'ci/architecture.toml'),
            '--repository', self.repository, '--checkout', str(self.root), '--trusted', str(self.trusted),
            '--scratch', str(scratch), '--output', str(self.evidence / 'architecture.json')]
        if sdk:
            command += ['--sdk', str(sdk)]
        if self.execution:
            context, expected = self.execution.write_context()
            command += ['--execution-context', str(context), '--execution-context-sha256', expected]
        self.run_controller('architecture', command)
        if self.execution:
            observed = json.loads((self.evidence / 'architecture.json').read_text())
            self.execution.observations.extend(observed['candidate_execution'])
            self.save()

    def core_regressions(self):
        # Fixed controller tests need neither fetched subject dependencies nor
        # compiler witnesses. Fail here before paying either preparation cost.
        self.run_controller('architecture-regressions', [sys.executable, '-m', 'unittest', 'discover',
            '-s', str(self.trusted / 'scripts/architecture'), '-p', 'test_*.py'], cwd=self.trusted)
        self.run_controller('toolchain-regressions', [sys.executable, '-m', 'unittest', 'discover',
            '-s', str(self.trusted / 'scripts/architecture/toolchain'), '-p', 'test_*.py'], cwd=self.trusted)
        for name, relative in (
                ('conformance-capability-regressions', 'testing/conformance/test_capabilities.py'),
                ('conformance-confined-tools-regressions', 'testing/h2-conformance/test_confined_tools.py')):
            self.run_controller(name, [sys.executable, '-B', '-I', str(self.trusted / relative)], cwd=self.trusted)

    def core_formatting(self):
        # Formatting only needs the checked-out sources and pinned toolchain.
        # Keep candidate execution and the ordinary hashed step evidence.
        self.run('root-fmt', ['cargo', 'fmt', '--all', '--check'])
        self.run('default-fmt', ['cargo', 'fmt', '--manifest-path', 'dist/default/Cargo.toml', '--all', '--check'])

    def core_compilation(self):
        # Type-check and lint every target, tests included, before the compiler
        # witnesses and product preparation. These are the same clippy steps
        # that previously ran last, so the work moves earlier rather than being
        # added; a compile or lint error now fails in minutes.
        for name, command in CORE_LINT_COMMANDS:
            self.run(name, command)

    def core(self):
        self.core_compilation()
        self.architecture()
        host = self.host()
        sdk = json.loads((host / 'scripts/ci-product-pins.json').read_text())['sdk']
        self.sdk()
        # A local assembly patch must not hide SDK source drift behind an old pin.
        self.run('sdk-source-identity', ['git', 'diff', '--exit-code', sdk, 'HEAD', '--',
            'crates/busbar-contract/src', 'crates/busbar-contract/include', 'crates/busbar-contract/Cargo.toml'])
        self.receipt['sdk_revision'] = sdk
        from native_fixtures import Services
        with Services(self, host):
            envfile = self.run('product-inputs', ['bash', str(self.trusted / 'scripts/ci-product-inputs.sh')])
            from native_product_inputs import load_product_inputs
            vector = json.loads((host / 'scripts/ci-product-pins.json').read_text())
            product_inputs = load_product_inputs(envfile, self.work, self.policy, vector, self.receipt['host_revision'])
            if self.execution is not None:
                self.execution.allow_product_inputs(product_inputs)
            self.env.update(product_inputs)
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
            from check import load_c_recipe, PUBLIC_C_HEADER
            recipe = load_c_recipe(self.policy, 'GetBusbar/' + witness['repo'], c_source, witness['commit'])
            library = self.work / ('c-witness.dylib' if sys.platform == 'darwin' else 'c-witness.so')
            self.run('c-witness-build', ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
                '-shared', '-fPIC', '-fvisibility=hidden', '-I', str(host / Path(PUBLIC_C_HEADER).parent),
                *[str(c_source / source) for source in recipe['sources']], '-o', str(library)])
            self.env.update(BUSBAR_C_ABI_SOURCES=str(c_source / recipe['test-root']), BUSBAR_C_ABI_LIBRARY=str(library))
            nextest = ['--no-fail-fast', '--test-threads', str(self.receipt['native_scheduling']['test_threads']), '--tool-config-file',
                       'admission:' + str(self.trusted / 'ci/native-nextest.toml')]
            selected = 'binary(mcp_stdio_serve) | binary(hook_parity_driver) | (package(busbar-default) & test(/^distribution::admin_cross_plane::/)) | (package(busbar-default) & test(/(serve_tests|secret_source|connector|boot)::/))'
            features = 'test-harness,transport-webrtc,openapi-schema'
            final_build = ['build', '--release', '--locked', '--manifest-path', 'dist/default/Cargo.toml', '--bin', 'busbar']
            build_capture = self.work / 'final-build-capture'
            artifact_tool = self.trusted / 'scripts/release/development_artifact.py'
            commands = [
                ('workspace-doctests', ['cargo', 'test', '--workspace', '--doc', '--locked', '--no-fail-fast']),
                ('loader-witnesses', ['cargo', 'build', '--locked', '-p', 'busbar-plugin-loader', '--examples']),
                ('root-runtime', ['cargo', 'nextest', 'run', '--workspace', '--locked', *nextest]),
                ('default-runtime', ['cargo', 'nextest', 'run', '--locked', '--manifest-path', 'dist/default/Cargo.toml', '--workspace', *nextest]),
                ('selected-default', ['cargo', 'nextest', 'run', '--locked', '--manifest-path', 'dist/default/Cargo.toml', '--features', features, '-E', selected, *nextest]),
                ('selected-errors', ['cargo', 'nextest', 'run', '--locked', '--manifest-path', 'dist/default/Cargo.toml', '--features', features, '-E', 'test(keys_error_surface_is_byte_stable) | test(every_admin_error_surface_answers_its_declared_status)', *nextest]),
                ('timing-admin', ['cargo', 'nextest', 'run', '--locked', '-p', 'busbar-kernel', '-p', 'busbar-core-admin', '--features', 'busbar-kernel/timing,busbar-kernel/openapi-schema,busbar-core-admin/openapi-schema', '-E', 'binary(timing_smoke) | package(busbar-core-admin) | (package(busbar-kernel) & test(/timing::/))', *nextest]),
                ('bounded-loom', ['cargo', 'test', '--release', '--locked', '-p', 'busbar-kernel', '--features', 'loom-model', 'txn_loom']),
                ('dependency-policy', ['cargo', 'deny', 'check']),
                ('dependency-vet', ['cargo', 'vet']),
                ('default-dependency-policy', ['cargo', 'deny', '--manifest-path', 'dist/default/Cargo.toml', 'check']),
                ('final-binary', ['python3', '-I', str(artifact_tool), 'capture', '--directory', str(build_capture), '--', *final_build]),
            ]
            for name, command in commands:
                self.run(name, command)
            self.run('default-dependency-vet', ['cargo', 'vet'], cwd=host / 'dist/default')
            binary = Path(self.env['CARGO_TARGET_DIR']) / 'release/busbar'
            collected = collect_output(self, binary, self.evidence / 'busbar', compiler_output=True)
            self.receipt['binary_sha256'] = digest(collected)
            artifact_evidence = self.evidence / 'development-artifact'
            (artifact_evidence / 'build').mkdir(parents=True)
            for name in ('cargo-metadata.json', 'Cargo.lock', 'cargo-messages.jsonl', 'build-context.json'):
                collect_output(self, build_capture / name, artifact_evidence / 'build' / name, limit=64 * 1024**2)
            self.run_controller('development-artifact-evidence', [sys.executable, '-I', str(artifact_tool),
                'finalize', '--directory', str(artifact_evidence), '--binary', str(collected),
                '--source', self.receipt['source'], '--policy', self.receipt['policy_revision'], '--sdk', sdk,
                '--vector', str(host / 'scripts/ci-product-pins.json'), '--package', 'busbar-default',
                '--compiler-output', str(binary), '--command-json', json.dumps(final_build),
                '--retention-policy-sha256', digest(self.trusted / 'ci/architecture-pipeline.yml')])
            self.receipt['development_artifact'] = {
                'path': 'development-artifact/receipt.json',
                'sha256': digest(artifact_evidence / 'receipt.json'),
                'signed': False, 'release_eligible': False,
                'supported_lifetime_retention_verified': False,
            }
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
        from native_policy import conformance_rows, validate_conformance_roster
        required = conformance_rows(getattr(self, 'repository', None),
                                    getattr(self, 'policy', None), getattr(self, 'trusted', None))
        validate_conformance_roster(self.root, required)
        if required:
            self.receipt['required_conformance_suites'] = sorted(required)
        if getattr(self, 'execution', None) and self.execution.conformance_capabilities is None:
            raise Violation('confined conformance requires controller-owned capability manifest')
        suites = self.root / 'testing/conformance/suites.tsv'
        if suites.is_file() and any(line.strip() and not line.lstrip().startswith('#') for line in suites.read_text().splitlines()):
            if getattr(self, 'execution', None):
                for relative in ('testing/conformance/run.sh', 'testing/conformance/capabilities.py'):
                    path = self.root / relative
                    if path.is_symlink() or not path.is_file() or digest(path) != digest(self.trusted / relative):
                        raise Violation('confined conformance requires the published capability-aware controls: ' + relative)
            try:
                self.run(name, ['bash', str(self.root / 'testing/conformance/run.sh')], timeout=10800)
            finally:
                # Failed and blocked evaluations are evidence too. Preserve their
                # actual verdicts without changing the command or job's failure.
                self.copy_conformance()

    def copy_conformance(self):
        source = self.root / 'target/conformance'
        if source.is_symlink() or source.parent.is_symlink() or not source.is_dir():
            raise Violation('missing conformance output')
        destination = self.evidence / 'conformance'
        destination.mkdir(exist_ok=True)
        for relative in ('invocation.json', *[str(p.relative_to(source)) for p in sorted((source / 'verdicts').glob('*.json'))]):
            path = source / relative
            if path.is_symlink() or path.parent.is_symlink() or not path.is_file():
                raise Violation('missing or indirect conformance evidence')
            out = destination / relative
            out.parent.mkdir(exist_ok=True)
            collect_output(self, path, out, limit=64 * 1024**2)
        # Preserve the external judge's diagnostic evidence, not its tool/source
        # trees, fixture credentials or arbitrary candidate-selected paths.
        # These reports contain only dedicated synthetic protocol fixtures.
        patterns = (
            'h2/evidence/*.xml',
            'tls/evidence/*.json',
            'otlp/work/subject/traces.json',
            'otel-semconv-weaver/evidence/assessment.json',
            'otel-semconv-weaver/evidence/*-samples.json',
            'otel-semconv-weaver/evidence/*/live_check.json',
        )
        reports = sorted({path for pattern in patterns for path in source.glob(pattern)})
        total = 0
        retained = {}

        def bounded_report(path):
            nonlocal total
            relative = path.relative_to(source)
            # glob can traverse a symlink directory. Check every component before
            # reading anything, including the output root itself.
            if any(p.is_symlink() for p in (source, path, *path.parents) if p == source or source in p.parents):
                raise Violation('indirect conformance diagnostic evidence')
            with candidate_output(self, path, 64 * 1024**2) as (stream, before):
                payload = stream.read(64 * 1024**2 + 1)
                if len(payload) != before.st_size:
                    raise Violation('conformance diagnostic changed during collection')
            total += len(payload)
            if len(payload) > 64 * 1024 * 1024 or total > 256 * 1024 * 1024:
                raise Violation('conformance diagnostic evidence exceeds its byte budget')
            return relative, payload

        for path in reports:
            relative, payload = bounded_report(path)
            out = destination / relative
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(payload)
            retained[str(relative)] = hashlib.sha256(payload).hexdigest()

        # OIDF's raw exports/review HTML can carry generated credentials and
        # browser session tokens. Retain terminal module results and page hashes
        # only; never publish those raw pages, screenshots, configs or ZIPs.
        record = source / 'oidf-run/record.json'
        if record.exists() or record.is_symlink():
            _, payload = bounded_report(record)
            raw = json.loads(payload)
            summary = {'source_record_sha256': hashlib.sha256(payload).hexdigest(),
                       'scope': 'Terminal module outcomes and review page hashes; credential-bearing raw exports omitted'}
            for leg in ('control', 'negative', 'subject'):
                entry = raw.get(leg)
                if not isinstance(entry, dict):
                    continue
                safe = {'modules': []}
                for row in entry.get('modules', []):
                    if (not isinstance(row, list) or len(row) < 3 or
                            not isinstance(row[0], str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,240}', row[0]) or
                            any(not isinstance(v, str) or not re.fullmatch(r'[A-Z_-]{0,40}', v) for v in row[1:3])):
                        raise Violation('invalid OIDF terminal module identity/result')
                    safe['modules'].append(row[:3])
                pages = entry.get('review_pages', {})
                if (not isinstance(pages, dict) or any(
                        not re.fullmatch(r'[A-Za-z0-9_.:-]{1,240}', name) or not isinstance(hashes, list) or
                        any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value) for value in hashes)
                        for name, hashes in pages.items())):
                    raise Violation('invalid OIDF review page identity')
                safe['review_pages'] = pages
                if isinstance(entry.get('ok'), bool):
                    safe['ok'] = entry['ok']
                if type(entry.get('exit')) is int:
                    safe['exit'] = entry['exit']
                summary[leg] = safe
            out = destination / 'oidf-module-results.json'
            out.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
            retained[out.name] = digest(out)
        self.receipt['conformance_diagnostics'] = retained

    def core_conformance(self):
        """Evaluate required core suites, retaining failures and release-input gaps."""
        self.sdk()
        # The full applicable upstream mTLS signature roster contains thousands
        # of handshakes. Keep its three bounded legs inside this per-suite cap;
        # the enclosing command retains its three-hour bound.
        self.env['CONFORMANCE_TIMEOUT_SECONDS'] = '3600'
        from native_release_stage import run_engineering, classify, stage_context
        context = stage_context(os.environ)
        self.receipt['conformance_stage'] = context
        development = context['stage'] == 'dev'
        failed = False
        engineering_report = self.evidence / 'release-engineering/result.json'
        try:
            engineering_report = run_engineering(self, collect_output)
        except (Violation, OSError, ValueError, KeyError):
            failed = True
        try:
            self.conformance('core-native-conformance')
        except Violation as conformance_error:
            try:
                if str(conformance_error) != 'core-native-conformance failed; no automatic retry':
                    raise conformance_error
                if not development:
                    raise Violation('release-stage conformance remains required')
                self.receipt['development_conformance'] = classify(self, engineering_report)
            except (Violation, OSError, ValueError, KeyError) as error:
                self.receipt['development_conformance_error'] = str(error)
                failed = True
        out = (self.work if getattr(self, 'execution', None) else self.evidence) / 'sigstore'
        out.mkdir()
        self.env['CONFORMANCE_OUT'] = str(out)
        try:
            # Coverage declares this artifact-readiness check at main. Development
            # records missing inputs honestly; supplied invalid evidence still fails.
            self.receipt['sigstore_requirement'] = {'stage': context['stage'], 'required_at': 'main', 'required': not development, 'missing_result': 'not-run'}
            self.run('sigstore-release-evidence-observation', ['python3', '-I',
                str(self.root / 'testing/conformance/sigstore.py'), *([] if development else ['--require'])])
        except Violation:
            failed = True
        finally:
            if getattr(self, 'execution', None):
                destination = self.evidence / 'sigstore'
                destination.mkdir()
                for path in sorted(out.iterdir()):
                    collect_output(self, path, destination / path.name, limit=64 * 1024**2)
        if failed:
            raise Violation('one or more conformance evaluations did not pass; inspect actual verdicts')

    def external_endpoint_conformance(self):
        """Retain external judges' results without granting native admission."""
        if getattr(self, 'execution', None):
            raise Violation('external judges require a fixed-destination confined network broker')
        sdk = self.sdk()
        self.receipt['sdk_revision'] = git(sdk, 'rev-parse', 'HEAD')
        self.architecture(sdk)
        self.env['BUSBAR_PIN'] = self.receipt['host_revision']
        self.env['CONFORMANCE_OUT'] = str(self.evidence / 'external')
        from product_artifacts import regular_under
        script = native_settings(self.repository, getattr(self, 'policy', None)).get('external_conformance')
        if script is None:
            raise Violation('no required external evaluation entry point')
        command = regular_under(self.root / script, self.root)
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
    parser.add_argument('--confinement', type=Path, help='Protected pinned runtime configuration; never falls back to host')
    parser.add_argument('--confinement-sha256')
    parser.add_argument('--conformance-capabilities', type=Path)
    parser.add_argument('--conformance-capabilities-sha256')
    parser.add_argument('--conformance-inputs', type=Path)
    parser.add_argument('--conformance-inputs-sha256')
    parser.add_argument('--fixture-inputs', type=Path)
    parser.add_argument('--fixture-inputs-sha256')
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
        # Constructor validation establishes the immutable controller, exact
        # candidate and execution boundary before any regression command runs.
        if qualification.repository == 'GetBusbar/busbar' and not qualification.evaluation_only:
            qualification.core_regressions()
            qualification.core_formatting()
        if requires_native_oracle(qualification.repository, args.external_conformance, qualification.policy):
            from native_oracle import prepare as prepare_oracle
            with qualification.preparation('oracle-inputs'):
                prepare_oracle(qualification)
        from native_sources import prepare
        with qualification.preparation('canonical-inputs'):
            prepare(qualification, qualification.host())
        if qualification.execution is not None:
            from native_seed import prepare as prepare_seed
            with qualification.preparation('dependency-seed'):
                prepare_seed(qualification)
            from native_staged_fixtures import collect_required
            with qualification.preparation('staged-fixtures'):
                collect_required(qualification)
            if not args.conformance_capabilities:
                from native_conformance_capabilities import prepare as prepare_capabilities
                with qualification.preparation('conformance-capabilities'):
                    prepare_capabilities(qualification)
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
        work = getattr(qualification, 'control', qualification.work) if qualification is not None else args.work.resolve()
        if work.name == 'boundary-' + os.environ['CI_PROJECT_ID'] + '-' + os.environ['CI_JOB_ID']:
            shutil.rmtree(work)


def main():
    with interruption_signals():
        qualify()


if __name__ == '__main__':
    main()

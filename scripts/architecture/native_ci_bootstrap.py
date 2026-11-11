"""Protected, fixed-source root controller on an existing one-use native worker.

The runner's existing Docker group supplies administrator authority only for this
verified controller. Candidate commands never enter the bootstrap container or
receive its host namespaces, socket, environment, or credentials. A separate
userns daemon starts in private mount AND network namespaces before any daemon
process exists. This changes neither the runner manager nor the default daemon.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

PACKAGE = 'https://github.com/api/v4/projects/3/packages/generic/busbar-native-public-tools/20261110-78dea35890609955/image.tar'
ARCHIVE_SHA256 = '2b0ba52edc6f3bb198f2fcf9afc2c7edd75f3111f93f8b5afcbb3125eb813873'
ARCHIVE_BYTES = 938926592
MANIFEST = '78dea3589060995560aada47e190bf8d7c3f7d1e9ed6eb843ceffe5c13a81383'
DOCKER = '/usr/bin/docker'
DOCKER_SHA256 = '7ed12b00293d64742419a6601ae97960a367a0ce97c88b06e3278cc0a409557b'
SUBID = 524288
SUBCOUNT = 65536
REMAP = 'busbar-ci-remap'
ROOT = Path('/srv/busbar-native-ci')
CI_KEYS = frozenset(('CI_JOB_ID CI_PIPELINE_ID CI_PROJECT_ID CI_PROJECT_PATH CI_JOB_NAME '
    'CI_JOB_URL CI_PIPELINE_SOURCE CI_COMMIT_SHA CI_COMMIT_BRANCH CI_CONFIG_REF_URI '
    'CI_SERVER_HOST CI_SERVER_URL CI_MERGE_REQUEST_TARGET_BRANCH_NAME '
    'CI_MERGE_REQUEST_SOURCE_PROJECT_ID CI_JOB_TOKEN').split())
JOBS = {'native-qualification', 'core-conformance', 'external-conformance', 'native-isolation-diagnostic'}
HOST_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'
BASE_ENV = {'PATH': HOST_PATH,
            'PYTHONDONTWRITEBYTECODE': '1', 'LC_ALL': 'C.UTF-8', 'GIT_CONFIG_NOSYSTEM': '1',
            'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def host_program(name):
    path = shutil.which(name, path=HOST_PATH)
    require(path, 'required host tool is absent: ' + name)
    return path


def run(argv, **kwargs):
    return subprocess.run(list(map(str, argv)), check=True, **kwargs)


def ci_environment(env):
    result = {key: env[key] for key in CI_KEYS if key in env}
    require(result.get('CI_SERVER_URL') == 'https://github.com'
            and result.get('CI_SERVER_HOST') == 'github.com', 'unexpected CI authority')
    for key in ('CI_JOB_ID', 'CI_PIPELINE_ID', 'CI_PROJECT_ID'):
        require(re.fullmatch(r'[1-9][0-9]*', result.get(key, '')), 'invalid CI identity')
    require(result.get('CI_JOB_NAME') in JOBS, 'unrecognized protected bootstrap job')
    require(re.fullmatch(r'(?:GetBusbar|BusbarInc)/[A-Za-z0-9_.-]+', result.get('CI_PROJECT_PATH', '')),
            'invalid CI project')
    require(re.fullmatch(r'[0-9a-f]{40}', result.get('CI_COMMIT_SHA', '')), 'invalid source revision')
    require(result.get('CI_JOB_TOKEN'), 'controller job token is missing')
    return result


def approved_revision(env):
    match = re.fullmatch(r'(?:https://)?git\.getbusbar\.dev/' + re.escape(env['CI_PROJECT_PATH'])
        + r'//ci/architecture-pipeline\.yml@GetBusbar/busbar:([0-9a-f]{40})@refs/heads/[^\s]+',
        env['CI_CONFIG_REF_URI'])
    require(match is not None, 'bootstrap must come from the immutable server-selected configuration')
    return match[1]


def git(path, *args):
    return subprocess.check_output(['/usr/bin/git', '-c', 'safe.directory=' + str(path),
        '-c', 'core.hooksPath=/dev/null',
        '-c', 'core.fsmonitor=false', '-C', str(path), *args], env=BASE_ENV)


def verify_trusted(path, revision):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve() and path.is_dir(), 'indirect trusted checkout')
    require(git(path, 'rev-parse', 'HEAD').decode().strip() == revision, 'trusted source revision differs')
    require(not git(path, 'diff', '--no-ext-diff', 'HEAD', '--'), 'trusted source has modifications')
    require(not git(path, 'ls-files', '--others', '--exclude-standard'), 'untracked controller source')
    helper = path / 'scripts/architecture/native_ci_bootstrap.py'
    require(hashlib.sha256(git(path, 'show', 'HEAD:scripts/architecture/native_ci_bootstrap.py')).hexdigest()
            == digest(helper), 'bootstrap differs from approved Git object')
    return helper


class SameOrigin(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        old, new = urllib.parse.urlsplit(request.full_url), urllib.parse.urlsplit(url)
        require((old.scheme, old.netloc) == (new.scheme, new.netloc), 'credential download changed origin')
        return super().redirect_request(request, response, code, message, headers, url)


def fetch_archive(destination, token):
    request = urllib.request.Request(PACKAGE, headers={'JOB-TOKEN': token})
    opener = urllib.request.build_opener(SameOrigin())
    with opener.open(request, timeout=90) as source, destination.open('xb') as output:
        remaining = ARCHIVE_BYTES
        while chunk := source.read(min(1024**2, remaining + 1)):
            remaining -= len(chunk)
            require(remaining >= 0, 'public tooling archive exceeds its protected size')
            output.write(chunk)
    require(destination.stat().st_size == ARCHIVE_BYTES and digest(destination) == ARCHIVE_SHA256,
            'public tooling archive differs from its protected pin')
    destination.chmod(0o444)


class Registry:
    """Serve exact public OCI blobs only; no proxy, credentials or filesystem API."""
    def __init__(self, archive, port=0):
        self.archive = Path(archive)
        self.blobs = {}
        with tarfile.open(self.archive, 'r:') as source:
            for member in source:
                match = re.fullmatch(r'blobs/sha256/([0-9a-f]{64})', member.name)
                if match:
                    require(member.isfile() and match[1] not in self.blobs, 'invalid OCI blob member')
                    self.blobs[match[1]] = (member.offset_data, member.size)
        require(MANIFEST in self.blobs, 'pinned OCI manifest is absent')
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.respond(False)

            def do_GET(self):
                self.respond(True)

            def respond(self, body):
                if self.path in ('/v2', '/v2/'):
                    self.send_response(200)
                    self.send_header('Content-Length', '2')
                    self.end_headers()
                    if body:
                        self.wfile.write(b'{}')
                    return
                match = re.fullmatch(r'/v2/busbar-native-tools/(manifests|blobs)/sha256:([0-9a-f]{64})', self.path)
                if not match or match[2] not in owner.blobs:
                    self.send_error(404)
                    return
                offset, size = owner.blobs[match[2]]
                with owner.archive.open('rb') as stream:
                    stream.seek(offset)
                    media = 'application/octet-stream'
                    if match[1] == 'manifests':
                        require(size < 1024**2, 'oversized OCI manifest')
                        data = stream.read(size)
                        require(hashlib.sha256(data).hexdigest() == match[2], 'OCI manifest digest differs')
                        media = json.loads(data)['mediaType']
                        stream.seek(offset)
                    self.send_response(200)
                    self.send_header('Content-Type', media)
                    self.send_header('Content-Length', str(size))
                    self.send_header('Docker-Content-Digest', 'sha256:' + match[2])
                    self.end_headers()
                    if body:
                        remaining = size
                        while remaining:
                            chunk = stream.read(min(1024**2, remaining))
                            require(chunk, 'truncated OCI blob')
                            self.wfile.write(chunk)
                            remaining -= len(chunk)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port
        self.reference = f'127.0.0.1:{self.port}/busbar-native-tools@sha256:{MANIFEST}'

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)


def entry_command(helper, expected, image, name):
    # No candidate entrypoint, shell, arbitrary command, environment or writable
    # source mount. nsenter changes to the actual host root before host Python runs.
    code = ('import hashlib,pathlib,runpy,sys; p=pathlib.Path(' + repr(str(helper)) + '); '
            'assert hashlib.sha256(p.read_bytes()).hexdigest()==' + repr(expected) + '; '
            'sys.argv=[str(p),"--root"]; runpy.run_path(str(p),run_name="__main__")')
    return [DOCKER, '--host', 'unix:///var/run/docker.sock', 'run', '--name', name,
        '--pull=never', '--rm', '--interactive', '--privileged', '--userns=host',
        '--pid=host', '--network=none', '--entrypoint', '/usr/bin/nsenter', image,
        '--target', '1', '--mount', '--net', '--uts', '--ipc', '--root', '--wd=/',
        '--no-fork', '/usr/bin/python3', '-I', '-B', '-c', code]


def bootstrap(trusted, checkout, work):
    env = ci_environment(os.environ)
    revision = approved_revision(env)
    helper = verify_trusted(trusted, revision)
    require(digest(DOCKER) == DOCKER_SHA256, 'native Docker client differs')
    work, checkout = Path(work), Path(checkout)
    expected_work = Path('/var/lib/busbar-native') / ('boundary-' + env['CI_PROJECT_ID'] + '-' + env['CI_JOB_ID'])
    require(work == work.resolve() == expected_work and trusted == work / 'trusted', 'unexpected bootstrap staging root')
    require(checkout.is_dir() and checkout == checkout.resolve()
            and checkout.is_relative_to('/home/fleeting/builds'), 'unexpected runner checkout')
    archive = work / 'public-tools.tar'
    fetch_archive(archive, env['CI_JOB_TOKEN'])
    registry = Registry(archive)
    name = 'busbar-root-controller-' + env['CI_JOB_ID']
    client_env = dict(BASE_ENV, HOME=str(work), DOCKER_CONFIG=str(work / 'docker-client'))
    Path(client_env['DOCKER_CONFIG']).mkdir(mode=0o700)
    try:
        run([DOCKER, '--host', 'unix:///var/run/docker.sock', 'pull', registry.reference], env=client_env)
        payload = {'environment': env, 'trusted': str(trusted), 'checkout': str(checkout),
                   'work': str(work), 'archive': str(archive), 'port': registry.port,
                   'revision': revision, 'image': registry.reference}
        # The token crosses only stdin into the verified root controller. It is
        # absent from Docker's inspectable environment and the invoking process.
        os.environ.pop('CI_JOB_TOKEN', None)
        run(entry_command(helper, digest(helper), registry.reference, name),
            input=json.dumps(payload), text=True, env=client_env)
    finally:
        registry.close()
        subprocess.run([DOCKER, '--host', 'unix:///var/run/docker.sock', 'stop', '--time', '30', name],
                       env=client_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([DOCKER, '--host', 'unix:///var/run/docker.sock', 'rm', '--force', name],
                       env=client_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def root_directory(path, fresh=False):
    path = Path(path)
    for parent in reversed((path, *path.parents)):
        if not parent.exists():
            parent.mkdir(mode=0o755)
        metadata = parent.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                and not metadata.st_mode & 0o022, 'controller path is not root-owned')
    if fresh:
        require(not any(path.iterdir()), 'controller workspace is not fresh')
    return path


@contextlib.contextmanager
def subordinate_ids():
    paths = [Path('/etc/subuid'), Path('/etc/subgid')]
    originals = {path: path.read_bytes() if path.exists() else None for path in paths}
    for payload in originals.values():
        for line in (payload or b'').decode().splitlines():
            name, start, count = line.split(':')
            require(name != REMAP and (int(start) + int(count) <= SUBID or int(start) >= SUBID + SUBCOUNT),
                    'protected subordinate range overlaps an existing mapping')
    require(subprocess.run(['getent', 'passwd', REMAP], capture_output=True).returncode != 0,
            'remapped controller identity already exists')
    created = False
    try:
        run(['/usr/sbin/useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', REMAP])
        created = True
        for path, payload in originals.items():
            path.write_bytes((payload or b'').rstrip(b'\n') + (b'\n' if payload else b'')
                             + f'{REMAP}:{SUBID}:{SUBCOUNT}\n'.encode())
        yield
    finally:
        if created:
            run(['/usr/sbin/userdel', REMAP])
        for path, payload in originals.items():
            if payload is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(payload)


def runtime_configuration(control, endpoint, image, diagnostic):
    isolation = {'storage_kind': 'tmpfs' if diagnostic else 'loop-ext4',
        'storage_root': str(control / 'store'),
        'storage_bytes': 512 * 1024**2 if diagnostic else 24 * 1024**3,
        'storage_inodes': 65536 if diagnostic else 1048576,
        'storage_reserve_bytes': 0 if diagnostic else 6 * 1024**3,
        'uid_map': [0, SUBID, SUBCOUNT], 'gid_map': [0, SUBID, SUBCOUNT]}
    if not diagnostic:
        isolation['storage_image'] = str(control / 'job.ext4')
    return {'schema': 'busbar.native-confinement/2', 'docker': DOCKER,
        'docker_sha256': DOCKER_SHA256, 'docker_host': endpoint, 'image': image,
        'runtime': 'runc', 'uid': 1001, 'gid': 1002, 'python': '/usr/bin/python3',
        'environment': {'PATH': '/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin',
                        'CARGO_HOME': '/opt/busbar-native/cargo-seed', 'RUSTUP_HOME': '/usr/local/rustup'},
        'resources': {'cpus': 2 if diagnostic else 4, 'memory_bytes': (1 if diagnostic else 6) * 1024**3,
                      'pids': 256 if diagnostic else 1024},
        'isolation': isolation,
        'collector': {'docker_host': 'unix:///var/run/docker.sock', 'uid': SUBID + 1001, 'gid': SUBID + 1002}}


def daemon_main(control):
    require(os.geteuid() == 0, 'daemon supervisor requires root')
    for kind in ('mnt', 'net'):
        require(os.stat('/proc/self/ns/' + kind).st_ino != os.stat('/proc/1/ns/' + kind).st_ino,
                'secondary daemon requires private mount and network namespaces from startup')
    config = json.loads((control / 'daemon-inputs.json').read_text())
    data = control / 'daemon'
    root_directory(data)
    run([host_program('ip'), 'link', 'set', 'lo', 'up'])
    processes = []
    registry = Registry(control / 'image.tar', config['port'])
    def interrupted(signum, frame):
        raise KeyboardInterrupt('daemon supervisor interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        processes.append(subprocess.Popen([host_program('containerd'), '--address', str(data / 'containerd.sock'),
            '--root', str(data / 'containerd-root'), '--state', str(data / 'containerd-state'), '--config', '/dev/null'], env=BASE_ENV))
        daemon_config = {'hosts': [config['endpoint']], 'data-root': str(data / 'data'),
            'exec-root': str(data / 'exec'), 'pidfile': str(data / 'docker.pid'),
            'containerd': str(data / 'containerd.sock'), 'userns-remap': REMAP + ':' + REMAP,
            'storage-driver': 'overlay2', 'bridge': 'none', 'iptables': False, 'ip6tables': False,
            'ip-forward': False, 'ip-masq': False, 'features': {'containerd-snapshotter': False}}
        (data / 'daemon.json').write_text(json.dumps(daemon_config))
        processes.append(subprocess.Popen([host_program('dockerd'), '--config-file', str(data / 'daemon.json')], env=BASE_ENV))
        while all(process.poll() is None for process in processes):
            time.sleep(.5)
        raise RuntimeError('private daemon exited unexpectedly')
    finally:
        registry.close()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


def collector_mount_witness(config, store, evidence):
    import linux_job_isolation
    output = store / 'collector-witness'
    output.mkdir()
    linux_job_isolation.prepare_writable(config['isolation'], [output], config['uid'], config['gid'])
    client = [DOCKER, '--host', config['collector']['docker_host']]
    name = 'busbar-collector-proof-' + os.environ['CI_JOB_ID']
    code = "import os,pathlib; pathlib.Path('/output/proof').write_text(str(os.getuid())+':'+str(os.getgid()))"
    try:
        run([*client, 'run', '--name', name, '--pull=never', '--read-only', '--userns=host',
             '--user', str(config['collector']['uid']) + ':' + str(config['collector']['gid']),
             '--cap-drop=ALL', '--security-opt=no-new-privileges', '--network=bridge',
             '--pids-limit=32', '--memory=64m', '--cpus=1',
             '--mount', 'type=bind,src=' + str(output) + ',dst=/output',
             '--entrypoint', config['python'], config['image'], '-I', '-B', '-c', code], env=BASE_ENV)
        expected = str(config['collector']['uid']) + ':' + str(config['collector']['gid'])
        require((output / 'proof').read_text() == expected, 'default collector did not see the bounded host mount')
        (evidence / 'collector-mount.json').write_text(json.dumps({'mapped_identity': expected,
            'same_host_mount_visible': True, 'candidate_execution': False}) + '\n')
    finally:
        run([*client, 'rm', '--force', name], env=BASE_ENV, stdout=subprocess.DEVNULL)
        require(not subprocess.check_output([*client, 'ps', '--all', '--quiet', '--filter', 'name=^/' + name + '$'],
                env=BASE_ENV).strip(), 'collector witness disposal failed')


def diagnostic_steps(trusted, config, config_path, store, evidence):
    collector_mount_witness(config, store, evidence)
    env = dict(BASE_ENV, HOME=str(evidence), TMPDIR=str(store),
               BUSBAR_CONFINEMENT_TEST_CONFIG=str(config_path))
    with (evidence / 'confinement-tests.log').open('w') as output:
        run(['/usr/bin/python3', '-B', '-m', 'unittest', 'test_native_confinement.ExistingRuntime', '-v'],
            cwd=trusted / 'scripts/architecture', env=env, stdout=output, stderr=subprocess.STDOUT, timeout=240)
    pins = json.loads((trusted / 'scripts/architecture/toolchain/tsan-linux29-pins.json').read_text())
    baseline = evidence / 'tsan-baseline.json'
    with urllib.request.urlopen(pins['baseline_url'], timeout=60) as response:
        baseline.write_bytes(response.read(1024**2))
    require(digest(baseline) == pins['baseline_sha256'], 'TSan baseline differs from protected pin')
    with (evidence / 'tsan.log').open('w') as output:
        try:
            run(['/usr/bin/python3', '-B', trusted / 'scripts/architecture/toolchain/tsan_linux29_probe.py',
                '--config', config_path, '--config-sha256', digest(config_path), '--baseline', baseline,
                '--work', store / 'tsan-probe'], env=env, stdout=output, stderr=subprocess.STDOUT, timeout=300)
        finally:
            result = store / 'tsan-probe/result.json'
            if result.is_file():
                shutil.copy2(result, evidence / 'tsan-result.json')


def diagnostic(trusted, config, config_path, store, evidence):
    def measured():
        current = os.statvfs(store)
        return {'capacity_bytes': current.f_blocks * current.f_frsize,
                'available_bytes': current.f_bavail * current.f_frsize,
                'capacity_inodes': current.f_files, 'available_inodes': current.f_favail}
    record = {'before': measured(), 'configured_bytes': config['isolation']['storage_bytes']}
    try:
        diagnostic_steps(trusted, config, config_path, store, evidence)
    finally:
        record['after'] = measured()
        (evidence / 'diagnostic-storage.json').write_text(json.dumps(record, indent=2) + '\n')


def root_main():
    require(os.geteuid() == 0 and os.stat('/proc/self/ns/mnt').st_ino == os.stat('/proc/1/ns/mnt').st_ino,
            'controller must execute as host root')
    payload = json.loads(sys.stdin.read(1024**2))
    require(set(payload) == {'environment', 'trusted', 'checkout', 'work', 'archive', 'port', 'revision', 'image'},
            'unknown root bootstrap input')
    env = ci_environment(payload['environment'])
    require(set(payload['environment']) <= CI_KEYS and approved_revision(env) == payload['revision'],
            'unapproved controller environment')
    original_trusted, original_checkout = Path(payload['trusted']), Path(payload['checkout'])
    verify_trusted(original_trusted, payload['revision'])
    expected_work = Path('/var/lib/busbar-native') / ('boundary-' + env['CI_PROJECT_ID'] + '-' + env['CI_JOB_ID'])
    require(Path(payload['work']) == expected_work and original_trusted == expected_work / 'trusted'
            and Path(payload['archive']) == expected_work / 'public-tools.tar'
            and original_checkout == original_checkout.resolve()
            and original_checkout.is_relative_to('/home/fleeting/builds'), 'root bootstrap paths differ')
    require(type(payload['port']) is int and 1024 < payload['port'] < 65536
            and payload['image'] == f"127.0.0.1:{payload['port']}/busbar-native-tools@sha256:{MANIFEST}",
            'unapproved tool image reference')
    require(digest(DOCKER) == DOCKER_SHA256 and digest(payload['archive']) == ARCHIVE_SHA256,
            'administrator bootstrap inputs changed')
    os.environ.clear()
    os.environ.update(BASE_ENV | env)
    control = root_directory(ROOT / ('job-' + env['CI_JOB_ID']), fresh=True)
    control.chmod(0o700)
    os.environ['HOME'] = str(control / 'home')
    os.environ['PATH'] = '/opt/cargo/bin:' + HOST_PATH
    os.environ['RUSTUP_HOME'] = '/opt/rustup'
    os.environ['CARGO_HOME'] = str(control / 'home/.cargo')
    Path(os.environ['HOME']).mkdir(mode=0o700)
    trusted = control / 'trusted'
    shutil.copytree(original_trusted, trusted, symlinks=True)
    verify_trusted(trusted, payload['revision'])
    shutil.copyfile(payload['archive'], control / 'image.tar')
    (control / 'image.tar').chmod(0o444)
    require(digest(control / 'image.tar') == ARCHIVE_SHA256, 'copied public tooling archive differs')
    endpoint = 'unix://' + str(control / 'docker.sock')
    is_diagnostic = env['CI_JOB_NAME'] == 'native-isolation-diagnostic'
    config = runtime_configuration(control, endpoint, payload['image'], is_diagnostic)
    config_path = control / 'runtime.json'
    config_path.write_text(json.dumps(config, sort_keys=True) + '\n')
    (control / 'daemon-inputs.json').write_text(json.dumps({'port': payload['port'], 'endpoint': endpoint}))
    evidence = control / 'evidence'
    evidence.mkdir()
    receipt = {'schema': 'busbar.native-ci-root-bootstrap/1', 'policy_revision': payload['revision'],
        'image_manifest_sha256': MANIFEST, 'archive_sha256': ARCHIVE_SHA256,
        'runtime_sha256': digest(config_path), 'root_controller': True, 'bootstrap_admin_entry_privileged': True, 'candidate_privileged': False,
        'private_daemon_mount_and_network_namespaces': True, 'status': 'running'}
    supervisor = None
    mounted = False
    success = False
    disposal = False
    sys.path.insert(0, str(trusted / 'scripts/architecture'))
    import linux_job_isolation
    def interrupted(signum, frame):
        raise KeyboardInterrupt('protected controller interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        with subordinate_ids():
            capacity = os.statvfs(control)
            receipt['host_available_bytes_before_storage'] = capacity.f_bavail * capacity.f_frsize
            receipt['storage'] = linux_job_isolation.prepare(config['isolation'])
            mounted = True
            store = Path(config['isolation']['storage_root'])
            # Both candidate daemon and its containerd inherit this mounted root.
            log = (evidence / 'bootstrap-daemon.log').open('w')
            supervisor = subprocess.Popen([host_program('unshare'), '--mount', '--net', '--propagation', 'private',
                '/usr/bin/python3', '-I', '-B', trusted / 'scripts/architecture/native_ci_bootstrap.py',
                '--daemon', str(control)], env=BASE_ENV, stdout=log, stderr=subprocess.STDOUT)
            client = [DOCKER, '--host', endpoint]
            try:
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    require(supervisor.poll() is None, 'private daemon supervisor exited; see daemon.log')
                    status = subprocess.run([*client, 'info', '--format', '{{json .}}'], env=BASE_ENV, capture_output=True, text=True)
                    if status.returncode == 0:
                        break
                    time.sleep(.25)
                else:
                    raise RuntimeError('private Docker daemon did not become ready')
                info = json.loads(status.stdout)
                linux_job_isolation.validate_userns(config['isolation'], info)
                run([*client, 'pull', payload['image']], env=BASE_ENV)
                capacity = os.statvfs(control)
                receipt['host_available_bytes_after_image_import'] = capacity.f_bavail * capacity.f_frsize
                require(capacity.f_bavail * capacity.f_frsize >= config['isolation']['storage_reserve_bytes'],
                        'public tooling import would consume the protected host disk reserve')
                if is_diagnostic:
                    diagnostic(trusted, config, config_path, store, evidence)
                else:
                    checkout = store / 'checkout'
                    shutil.copytree(original_checkout, checkout, symlinks=True)
                    work = store / ('boundary-' + env['CI_PROJECT_ID'] + '-' + env['CI_JOB_ID'])
                    work.mkdir()
                    command = ['/usr/bin/python3', '-B', str(trusted / 'scripts/architecture/native.py'),
                        '--trusted', str(trusted), '--checkout', str(checkout), '--work', str(work),
                        '--confinement', str(config_path), '--confinement-sha256', digest(config_path)]
                    if env['CI_JOB_NAME'] == 'core-conformance':
                        command.append('--conformance-only')
                    elif env['CI_JOB_NAME'] == 'external-conformance':
                        command.append('--external-conformance')
                    try:
                        run(command, env=dict(os.environ))
                    finally:
                        if (checkout / 'boundary-evidence').is_dir():
                            shutil.copytree(checkout / 'boundary-evidence', evidence, dirs_exist_ok=True)
                success = True
            finally:
                listing = subprocess.run([*client, 'ps', '--all', '--quiet'], env=BASE_ENV, capture_output=True, text=True)
                if listing.returncode == 0:
                    ids = listing.stdout.split()
                    if ids:
                        run([*client, 'rm', '--force', *ids], env=BASE_ENV)
                    disposal = not subprocess.check_output([*client, 'ps', '--all', '--quiet'], env=BASE_ENV).strip()
                require(disposal, 'candidate disposal could not be confirmed')
                supervisor.terminate()
                supervisor.wait(timeout=70)
                supervisor = None
                log.close()
                if mounted:
                    linux_job_isolation.dispose(config['isolation'])
                    mounted = False
    finally:
        receipt.update(status='pass' if success and disposal and not mounted else 'failed',
                       candidate_containers_disposed=disposal, storage_disposed=not mounted)
        (evidence / 'bootstrap.json').write_text(json.dumps(receipt, indent=2) + '\n')
        destination = original_checkout / 'boundary-evidence'
        require(not destination.exists() and not destination.is_symlink(), 'candidate supplied artifact destination')
        shutil.copytree(evidence, destination)
        for path in [destination, *destination.rglob('*')]:
            require(not path.is_symlink(), 'indirect controller evidence')
            path.chmod(0o755 if path.is_dir() else 0o644)
        if supervisor is not None:
            supervisor.terminate()
            supervisor.wait(timeout=70)
        if not mounted:
            shutil.rmtree(control)
        os.environ.pop('CI_JOB_TOKEN', None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', action='store_true')
    parser.add_argument('--daemon', type=Path)
    parser.add_argument('--trusted', type=Path)
    parser.add_argument('--checkout', type=Path)
    parser.add_argument('--work', type=Path)
    args = parser.parse_args()
    if args.root:
        root_main()
    elif args.daemon:
        daemon_main(args.daemon)
    else:
        require(args.trusted and args.checkout and args.work, 'bootstrap paths required')
        bootstrap(args.trusted, args.checkout, args.work)


if __name__ == '__main__':
    main()

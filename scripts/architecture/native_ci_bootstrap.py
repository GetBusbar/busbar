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
    'CI_JOB_URL CI_PIPELINE_SOURCE CI_COMMIT_SHA CI_COMMIT_BRANCH CI_COMMIT_REF_PROTECTED CI_CONFIG_REF_URI '
    'CI_SERVER_HOST CI_SERVER_URL CI_MERGE_REQUEST_TARGET_BRANCH_NAME '
    'CI_MERGE_REQUEST_SOURCE_PROJECT_ID CI_JOB_TOKEN BUSBAR_ADMISSION_CORE_REVISION').split())
JOBS = {'native-qualification', 'core-conformance', 'external-conformance', 'native-isolation-diagnostic'}
# Server-assigned names of the `parallel: 8` dependency-unit producer
# (native_dep_cache.PRODUCER_JOB_NAME; tests pin that the two agree).
DEPENDENCY_UNITS_JOB = re.compile(r'plugin-dependency-units [1-8]/8')


def dependency_units_job(name):
    return DEPENDENCY_UNITS_JOB.fullmatch(name or '') is not None
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
    require(result.get('CI_JOB_NAME') in JOBS or dependency_units_job(result.get('CI_JOB_NAME')),
            'unrecognized protected bootstrap job')
    require(re.fullmatch(r'(?:GetBusbar|BusbarInc)/[A-Za-z0-9_.-]+', result.get('CI_PROJECT_PATH', '')),
            'invalid CI project')
    require(re.fullmatch(r'[0-9a-f]{40}', result.get('CI_COMMIT_SHA', '')), 'invalid source revision')
    require(result.get('CI_JOB_TOKEN'), 'controller job token is missing')
    host = result.get('BUSBAR_ADMISSION_CORE_REVISION')
    require(host is None or re.fullmatch(r'[0-9a-f]{40}', host), 'protected host revision must be immutable')
    require(result.get('CI_COMMIT_REF_PROTECTED') in (None, 'true', 'false'), 'invalid ref protection')
    require(result['CI_PROJECT_PATH'] == 'GetBusbar/busbar' or host is not None,
            'plugin qualification requires its protected immutable host revision')
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


def import_failure(error):
    detail = str(error.stderr or error.stdout or 'no daemon detail')
    for token in (os.environ.get('CI_JOB_TOKEN'),):
        if token:
            detail = detail.replace(token, '[redacted]')
    detail = re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', detail)[-4096:]
    return RuntimeError('offline image import failed (exit ' + str(error.returncode) + '): ' + detail)


def tool_image_config(archive):
    """The pinned manifest's verified image configuration and its digest."""
    with tarfile.open(archive, 'r:') as source:
        def blob(checksum):
            member = source.getmember('blobs/sha256/' + checksum)
            require(member.isfile() and member.size < 1024**2, 'invalid tool image metadata')
            raw = source.extractfile(member).read()
            require(hashlib.sha256(raw).hexdigest() == checksum, 'tool image metadata digest differs')
            return json.loads(raw)
        manifest = blob(MANIFEST)
        config_sha = manifest['config']['digest'].removeprefix('sha256:')
        config = blob(config_sha)
    require(config['architecture'] == 'amd64' and config['os'] == 'linux', 'tool image platform differs')
    return config, config_sha


def verify_loaded(actual, config, config_sha):
    """Bind a daemon's image record to the verified execution configuration."""
    require(actual['Id'] in ('sha256:' + MANIFEST, 'sha256:' + config_sha), 'loaded tool identity differs')
    require(actual.get('Os') == config['os'] and actual.get('Architecture') == config['architecture']
            and actual.get('RootFS') == {'Type': config['rootfs']['type'], 'Layers': config['rootfs']['diff_ids']}
            and all(actual.get('Config', {}).get(key) == value for key, value in config['config'].items()),
            'loaded tool execution content differs')
    return actual['Id']


def verify_imported_tool_image(archive, endpoint, env, image):
    """Re-verify an image this job's administrator entry already imported.

    The host daemon loaded and verified these exact bytes in bootstrap()
    before the root controller started; inspect and re-check the execution
    identity instead of importing the same archive a second time there.
    """
    config, config_sha = tool_image_config(archive)
    actual = json.loads(run([DOCKER, '--host', endpoint, 'image', 'inspect', image], env=env,
                            capture_output=True, text=True).stdout)[0]
    return verify_loaded(actual, config, config_sha)


def load_tool_image(archive, endpoint, env, source_image=None):
    """Import offline and bind the daemon's identity to verified execution bytes."""
    config, config_sha = tool_image_config(archive)
    client = [DOCKER, '--host', endpoint]
    try:
        if source_image is None:
            loaded = run([*client, 'image', 'load', '--input', str(archive)], env=env,
                         capture_output=True, text=True, timeout=300)
        else:
            require(source_image in ('sha256:' + MANIFEST, 'sha256:' + config_sha),
                    'unverified image selected for compatibility export')
            # Docker save supplies manifest.json for the classic overlay store.
            # Stream it directly: no second archive, registry or unpacked host tree.
            producer = subprocess.Popen([DOCKER, '--host', 'unix:///var/run/docker.sock',
                'image', 'save', '--platform', 'linux/amd64', source_image], env=env,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                loaded = run([*client, 'image', 'load'], stdin=producer.stdout, env=env,
                             capture_output=True, text=True, timeout=300)
                producer.stdout.close()
                require(producer.wait(timeout=30) == 0, 'verified tool image compatibility export failed')
            finally:
                if producer.stdout is not None:
                    producer.stdout.close()
                if producer.poll() is None:
                    producer.kill()
                    producer.wait(timeout=10)
    except subprocess.CalledProcessError as error:
        raise import_failure(error) from None
    names = re.findall(r'^Loaded image(?: ID)?: (.+)$', loaded.stdout, re.MULTILINE)
    require(len(names) == 1, 'tool archive must import exactly one image')
    actual = json.loads(run([*client, 'image', 'inspect', names[0]], env=env,
                           capture_output=True, text=True).stdout)[0]
    return verify_loaded(actual, config, config_sha)


def entry_command(helper, expected, image, name):
    # No candidate entrypoint, shell, arbitrary command, environment or writable
    # source mount. Bare --wd selects target PID 1's cwd; --wd=/ would open
    # the old container root before namespace entry, leaving Git without a
    # reachable cwd after --root. Python also enters the retained host root.
    code = ('import hashlib,os,pathlib,runpy,sys; os.chdir("/"); p=pathlib.Path(' + repr(str(helper)) + '); '
            'assert hashlib.sha256(p.read_bytes()).hexdigest()==' + repr(expected) + '; '
            'sys.argv=[str(p),"--root"]; runpy.run_path(str(p),run_name="__main__")')
    return [DOCKER, '--host', 'unix:///var/run/docker.sock', 'run', '--name', name,
        '--pull=never', '--rm', '--interactive', '--privileged', '--userns=host',
        '--pid=host', '--network=none', '--entrypoint', '/usr/bin/nsenter', image,
        '--target', '1', '--mount', '--net', '--uts', '--ipc', '--cgroup', '--root', '--wd',
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
    name = 'busbar-root-controller-' + env['CI_JOB_ID']
    client_env = dict(BASE_ENV, HOME=str(work), DOCKER_CONFIG=str(work / 'docker-client'))
    Path(client_env['DOCKER_CONFIG']).mkdir(mode=0o700)
    try:
        image = load_tool_image(archive, 'unix:///var/run/docker.sock', client_env)
        payload = {'environment': env, 'trusted': str(trusted), 'checkout': str(checkout),
                   'work': str(work), 'archive': str(archive),
                   'revision': revision, 'image': image}
        # The token crosses only stdin into the verified root controller. It is
        # absent from Docker's inspectable environment and the invoking process.
        os.environ.pop('CI_JOB_TOKEN', None)
        run(entry_command(helper, digest(helper), image, name),
            input=json.dumps(payload), text=True, env=client_env)
    finally:
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


def job_directory(path):
    control = root_directory(path, fresh=True)
    # Remapped graphroot must be traversable, but never listable or writable.
    # Private controller children retain their own root-only permissions.
    control.chmod(0o711)
    return control


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
        'collector': {'docker_host': 'unix:///var/run/docker.sock', 'image': image, 'uid': SUBID + 1001, 'gid': SUBID + 1002}}


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
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


def judge_selection(plan, repository, job):
    require(isinstance(plan, dict) and set(plan) == {'schema', 'owners', 'repositories'}
            and plan['schema'] == 'busbar.native-judge-inputs/1'
            and isinstance(plan['owners'], dict) and len(plan['owners']) <= 16
            and isinstance(plan['repositories'], dict), 'invalid protected judge input plan')
    if job == 'external-conformance' or (repository == 'GetBusbar/busbar' and job != 'core-conformance'):
        return []
    selected = plan['repositories'].get(repository, [])
    require(isinstance(selected, list) and len(selected) == len(set(selected))
            and all(isinstance(owner, str) and owner in plan['owners'] for owner in selected),
            'unapproved judge owner selection')
    total = 0
    seen = set()
    for owner in selected:
        row = plan['owners'][owner]
        verify_judge_record(owner, row)
        total += row['expanded_bytes']
        require(not seen.intersection(row['bundles']), 'duplicate judge bundle name')
        seen.update(row['bundles'])
    require(total <= 4 * 1024**3, 'selected judge inputs exceed the aggregate byte budget')
    return selected


def verify_judge_record(owner, row):
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,31}', owner)
            and isinstance(row, dict) and set(row) == {'archive_url', 'archive_sha256',
                'portable_manifest_sha256', 'bundles', 'bytes', 'expanded_bytes'},
            'invalid protected judge archive')
    for key in ('archive_sha256', 'portable_manifest_sha256'):
        require(isinstance(row[key], str) and re.fullmatch(r'[0-9a-f]{64}', row[key]),
                'invalid protected judge digest')
    require(type(row['bytes']) is int and 0 < row['bytes'] <= 2 * 1024**3
            and type(row['expanded_bytes']) is int and 0 < row['expanded_bytes'] <= 4 * 1024**3,
            'invalid protected judge size')
    require(isinstance(row['bundles'], list) and 0 < len(row['bundles']) <= 32
            and all(isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', name) for name in row['bundles'])
            and len(row['bundles']) == len(set(row['bundles'])), 'invalid protected judge bundle names')
    prefix = 'https://github.com/api/v4/projects/3/packages/generic/busbar-native-conformance-' + owner
    require(re.fullmatch(re.escape(prefix) + r'/[0-9]{8}-' + row['archive_sha256']
                        + '/' + re.escape(owner) + r'\.tar\.gz', row['archive_url']),
            'judge package is outside its credential origin or immutable package identity')


def fetch_judge_archive(row, destination, token):
    opener = urllib.request.build_opener(SameOrigin())
    request = urllib.request.Request(row['archive_url'], headers={'JOB-TOKEN': token})
    with opener.open(request, timeout=90) as source, destination.open('xb') as output:
        remaining = row['bytes']
        while chunk := source.read(min(1024**2, remaining + 1)):
            remaining -= len(chunk)
            require(remaining >= 0, 'judge archive exceeds its protected byte count')
            output.write(chunk)
    require(destination.stat().st_size == row['bytes'] and digest(destination) == row['archive_sha256'],
            'judge archive differs from the protected input plan')


def stage_judges(trusted, repository, job, store, token):
    from native_conformance_inputs import unpack
    plan_path = trusted / 'ci/native-judge-inputs.json'
    plan = json.loads(plan_path.read_text())
    owners = judge_selection(plan, repository, job)
    if not owners:
        return None
    private = store / 'judge-inputs'
    private.mkdir(mode=0o700)
    merged = {'schema': 'busbar.native-conformance-inputs/1', 'bundles': {}}
    retained = []
    for owner in owners:
        row = plan['owners'][owner]
        archive = private / (owner + '.tar.gz')
        fetch_judge_archive(row, archive, token)
        result = unpack(archive, row['archive_sha256'], row['portable_manifest_sha256'], private / owner)
        archive.unlink()
        portable_path = Path(result['manifest'])
        portable = json.loads(portable_path.read_text())
        require(set(portable) == {'schema', 'bundles'} and portable['schema'] == merged['schema']
                and sorted(portable['bundles']) == sorted(row['bundles']), 'published judge bundle set differs')
        actual_bytes = 0
        for name, bundle in portable['bundles'].items():
            require(name not in merged['bundles'] and bundle.get('path') == 'bundles/' + name,
                    'portable judge path or ownership differs')
            source = portable_path.parent / 'bundles' / name
            actual_bytes += sum(path.stat().st_size for path in source.rglob('*') if path.is_file())
            merged['bundles'][name] = dict(bundle, path=str(source))
        require(actual_bytes == row['expanded_bytes'],
                f"expanded judge size differs for {owner} ({owner}.tar.gz): expected {row['expanded_bytes']}, actual {actual_bytes}")
        retained.append({'owner': owner, 'archive_sha256': row['archive_sha256'],
                         'portable_manifest_sha256': row['portable_manifest_sha256'],
                         'expanded_bytes': actual_bytes, 'bundles': row['bundles']})
    manifest = private / 'combined.json'
    manifest.write_text(json.dumps(merged, sort_keys=True) + '\n')
    manifest.chmod(0o444)
    return {'manifest': str(manifest), 'sha256': digest(manifest),
            'protected_plan_sha256': digest(plan_path), 'archives': retained,
            'suite_verdict': 'not implied by input staging'}


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
             '--entrypoint', config['python'], config['collector']['image'], '-I', '-B', '-c', code], env=BASE_ENV)
        expected = str(config['collector']['uid']) + ':' + str(config['collector']['gid'])
        require((output / 'proof').read_text() == expected, 'default collector did not see the bounded host mount')
        (evidence / 'collector-mount.json').write_text(json.dumps({'mapped_identity': expected,
            'same_host_mount_visible': True, 'candidate_execution': False}) + '\n')
    finally:
        run([*client, 'rm', '--force', name], env=BASE_ENV, stdout=subprocess.DEVNULL)
        require(not subprocess.check_output([*client, 'ps', '--all', '--quiet', '--filter', 'name=^/' + name + '$'],
                env=BASE_ENV).strip(), 'collector witness disposal failed')


def diagnostic_steps(trusted, config, config_path, store, evidence):
    from native_service_peers import runtime_controls_probe
    runtime_controls_probe(config, evidence)
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


def require_host_controller():
    require(os.geteuid() == 0, 'controller must execute as host root')
    # The administrator bridge starts in Docker's private cgroup namespace.
    # Keeping it after entering host mounts makes sibling service cgroups appear
    # parent-relative to runc exec. Only the controller joins the host namespace;
    # candidates and fixture peers retain their private cgroup namespaces.
    for kind in ('mnt', 'cgroup'):
        require(os.stat('/proc/self/ns/' + kind).st_ino == os.stat('/proc/1/ns/' + kind).st_ino,
                'controller must execute in the host ' + kind + ' namespace')


def root_main():
    require_host_controller()
    payload = json.loads(sys.stdin.read(1024**2))
    require(set(payload) == {'environment', 'trusted', 'checkout', 'work', 'archive', 'revision', 'image'},
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
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', payload['image']), 'unapproved tool image identity')
    require(digest(DOCKER) == DOCKER_SHA256 and digest(payload['archive']) == ARCHIVE_SHA256,
            'administrator bootstrap inputs changed')
    os.environ.clear()
    os.environ.update(BASE_ENV | env)
    control = job_directory(ROOT / ('job-' + env['CI_JOB_ID']))
    os.environ['HOME'] = str(control / 'home')
    os.environ['PATH'] = '/opt/cargo/bin:' + HOST_PATH
    os.environ['RUSTUP_HOME'] = '/opt/rustup'
    os.environ['CARGO_HOME'] = str(control / 'home/.cargo')
    Path(os.environ['HOME']).mkdir(mode=0o700)
    trusted = control / 'trusted'
    shutil.copytree(original_trusted, trusted, symlinks=True)
    trusted.chmod(0o755)  # Published source is mounted read-only in candidate invocations.
    verify_trusted(trusted, payload['revision'])
    shutil.copyfile(payload['archive'], control / 'image.tar')
    (control / 'image.tar').chmod(0o444)
    require(digest(control / 'image.tar') == ARCHIVE_SHA256, 'copied public tooling archive differs')
    endpoint = 'unix://' + str(control / 'docker.sock')
    is_diagnostic = env['CI_JOB_NAME'] == 'native-isolation-diagnostic'
    config = runtime_configuration(control, endpoint, payload['image'], is_diagnostic)
    config_path = control / 'runtime.json'
    config_path.write_text(json.dumps(config, sort_keys=True) + '\n')
    (control / 'daemon-inputs.json').write_text(json.dumps({'endpoint': endpoint}))
    evidence = control / 'evidence'
    evidence.mkdir(mode=0o700)
    receipt = {'schema': 'busbar.native-ci-root-bootstrap/1', 'policy_revision': payload['revision'],
        'image_manifest_sha256': MANIFEST, 'archive_sha256': ARCHIVE_SHA256,
        'runtime_sha256': digest(config_path), 'root_controller': True, 'bootstrap_admin_entry_privileged': True, 'candidate_privileged': False,
        'private_daemon_mount_and_network_namespaces': True, 'status': 'running'}
    supervisor = None
    mounted = False
    success = False
    disposal = False
    workload_started = False
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
                config['image'] = load_tool_image(control / 'image.tar', endpoint, BASE_ENV,
                                                  source_image=payload['image'])
                # The administrator entry already imported and verified this
                # image on the host daemon; re-verify instead of a second import.
                config['collector']['image'] = verify_imported_tool_image(
                    control / 'image.tar', 'unix:///var/run/docker.sock', BASE_ENV, payload['image'])
                require(config['collector']['image'] == payload['image'], 'administrator image identity changed')
                config_path.write_text(json.dumps(config, sort_keys=True) + '\n')
                receipt['runtime_sha256'] = digest(config_path)
                receipt['candidate_image_id'] = config['image']
                receipt['collector_image_id'] = config['collector']['image']
                capacity = os.statvfs(control)
                receipt['host_available_bytes_after_image_import'] = capacity.f_bavail * capacity.f_frsize
                require(capacity.f_bavail * capacity.f_frsize >= config['isolation']['storage_reserve_bytes'],
                        'public tooling import would consume the protected host disk reserve')
                workload_started = True
                if is_diagnostic:
                    diagnostic(trusted, config, config_path, store, evidence)
                else:
                    import native_service_inputs
                    # The dependency-unit producer starts no service peer.
                    receipt['service_inputs'] = {} if dependency_units_job(env['CI_JOB_NAME']) else \
                        native_service_inputs.stage(trusted, env['CI_PROJECT_PATH'], store, env['CI_JOB_TOKEN'])
                    capacity = os.statvfs(control)
                    require(capacity.f_bavail * capacity.f_frsize >= config['isolation']['storage_reserve_bytes'],
                            'service image imports would consume the protected host disk reserve')
                    checkout = store / 'checkout'
                    shutil.copytree(original_checkout, checkout, symlinks=True)
                    work = store / ('boundary-' + env['CI_PROJECT_ID'] + '-' + env['CI_JOB_ID'])
                    work.mkdir()
                    command = ['/usr/bin/python3', '-B', str(trusted / 'scripts/architecture/native.py'),
                        '--trusted', str(trusted), '--checkout', str(checkout), '--work', str(work),
                        '--confinement', str(config_path), '--confinement-sha256', digest(config_path)]
                    judges = stage_judges(trusted, env['CI_PROJECT_PATH'], env['CI_JOB_NAME'], store, env['CI_JOB_TOKEN'])
                    if judges is not None:
                        command.extend(['--conformance-inputs', judges['manifest'], '--conformance-inputs-sha256', judges['sha256']])
                        receipt['judge_inputs'] = judges
                    if env['CI_JOB_NAME'] == 'core-conformance':
                        command.append('--conformance-only')
                    elif env['CI_JOB_NAME'] == 'external-conformance':
                        command.append('--external-conformance')
                    elif dependency_units_job(env['CI_JOB_NAME']):
                        command.append('--dependency-units')
                    try:
                        run(command, env=dict(os.environ), cwd=trusted)
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
                # Before any workload, a failed daemon cannot have accepted a
                # candidate. Stop its namespace before disposing the job mount.
                if not workload_started:
                    disposal = True
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

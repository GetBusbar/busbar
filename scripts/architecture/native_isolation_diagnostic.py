"""Fixed-source runtime witnesses for the API-only native-isolation-diagnostic job.

The compiled root controller (tools/ci, ``busbar-ci native-root``) prepares the
bounded storage and private userns daemon, then runs this module as a step,
exactly as it runs native.py for qualification. It never qualifies candidates.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request

DOCKER = '/usr/bin/docker'
BASE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'PYTHONDONTWRITEBYTECODE': '1', 'LC_ALL': 'C.UTF-8',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(argv, **kwargs):
    return subprocess.run(list(map(str, argv)), check=True, **kwargs)


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('--trusted', '--config', '--store', '--evidence'):
        parser.add_argument(name, type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get('CI_JOB_NAME') == 'native-isolation-diagnostic', 'diagnostic witnesses only')
    config = json.loads(args.config.read_text())
    diagnostic(args.trusted, config, args.config, args.store, args.evidence)


if __name__ == '__main__':
    main()

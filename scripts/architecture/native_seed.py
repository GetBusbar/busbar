"""Collect an offline Cargo seed for this job only, before executing candidate code.

The reusable image holds public tools. This transient collector sees generated
exact manifest graphs, inert source placeholders and exact local Git objects,
no executable candidate source, host sockets, tokens, or other jobs' caches. Cargo fetch never builds.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tomllib
import uuid

from check import Violation


def manifest_snapshot(source, destination, *, revision=None):
    """Preserve Cargo's graph without executing or staging candidate source code.

    Cargo fetch parses manifests and discovers target filenames, but does not
    compile build.rs or other targets. Original patches/features/workspace roots
    are necessary: making every locked dependency a new root changes that graph.
    Cargo configuration, hooks, object stores and source contents are excluded.
    """
    destination.mkdir(parents=True)
    if revision is None:
        paths = []
        for directory, dirs, files in os.walk(source, followlinks=False):
            dirs[:] = [name for name in dirs if name not in
                       ('.git', '.cargo', 'target', 'node_modules', '__pycache__')]
            for name in files:
                path = Path(directory) / name
                if path.is_symlink():
                    raise Violation('indirect manifest graph input')
                paths.append(path.relative_to(source))
        def read(relative):
            return (source / relative).read_bytes()
    else:
        output = subprocess.check_output(['git', '-C', str(source), 'ls-tree',
                                          '-r', '-z', revision])
        paths = []
        for row in output.split(b'\0'):
            if not row:
                continue
            header, name = row.split(b'\t', 1)
            mode, kind, _ = header.split()
            if kind != b'blob' or mode not in (b'100644', b'100755'):
                raise Violation('indirect manifest graph object')
            relative = Path(os.fsdecode(name))
            if not any(part in ('.git', '.cargo', 'target', 'node_modules') for part in relative.parts):
                paths.append(relative)
        def read(relative):
            return subprocess.check_output(['git', '-C', str(source), 'show', revision + ':' + str(relative)])
    for relative in paths:
        if relative.is_absolute() or '..' in relative.parts:
            raise Violation('manifest graph path escapes source')
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        # Non-manifest bytes cannot affect dependency collection. Empty files
        # preserve explicit target/build/readme names, including unusual suffixes.
        target.write_bytes(read(relative) if relative.name in ('Cargo.toml', 'Cargo.lock') else b'')


def prepare(q):
    execution = q.execution
    if execution is None:
        return
    sys.path.insert(0, str(Path(__file__).resolve().parent / 'toolchain'))
    from prepare import GIT, REGISTRY, packages
    from native import git
    root = q.control / 'dependency-collector'
    root.mkdir(mode=0o700)
    context, output = root / 'inputs', root / 'output'
    context.mkdir()
    output.mkdir()
    (context / 'seed-payload').mkdir()
    locks = {}
    inputs = {}
    host = q.host()
    sdk = q.sdk()
    for label, directory, relative in (
            ('candidate', q.root, 'Cargo.lock'), ('host', host, 'Cargo.lock'),
            ('distribution', host, 'dist/default/Cargo.lock'), ('sdk', sdk, 'Cargo.lock')):
        path = directory / relative
        if path.is_file():
            locks[label] = path.read_bytes()
            inputs[label] = (directory, None, str(Path(relative).parent))
    # The native commands build exactly this assembled public host vector. Each
    # standalone product has its own lock, already independently bound by it.
    vector = json.loads((host / 'scripts/ci-product-pins.json').read_text())
    canonical = q.work / 'canonical-inputs'
    for product in vector['products']:
        data = subprocess.check_output(['git', '-C', str(canonical / product['repo']),
                                        'show', product['commit'] + ':Cargo.lock'])
        if hashlib.sha256(data).hexdigest() != product['lock_sha256']:
            raise Violation('job seed product lock differs from admitted vector')
        label = 'product-' + product['repo']
        locks[label] = data
        inputs[label] = (canonical / product['repo'], product['commit'], '.')
    if not locks:
        raise Violation('job dependency seed has no exact locks')
    git_revisions = {}
    recipe = {'schema': 'busbar.native-seed-recipe/1', 'rust': '1.98.0',
              'vector_sha256': hashlib.sha256((host / 'scripts/ci-product-pins.json').read_bytes()).hexdigest(),
              'toolchain_sha256': hashlib.sha256((host / 'rust-toolchain.toml').read_bytes()).hexdigest(),
              'locks': {}, 'expected_packages': {}, 'git': {}, 'native_tools': {}, 'advisory_db': None,
              'copy_image_advisories': True, 'exact_manifest_graphs': True}
    for index, (label, data) in enumerate(sorted(locks.items())):
        rows = packages(tomllib.loads(data.decode()))
        source, revision, relative = inputs[label]
        destination = context / 'locks' / str(index)
        manifest_snapshot(source, destination, revision=revision)
        name = str(index) + ('/' + relative if relative != '.' else '')
        directory = context / 'locks' / name
        if not (directory / 'Cargo.toml').is_file():
            raise Violation('job seed input has no exact Cargo manifest')
        (directory / 'Cargo.lock').write_bytes(data)
        recipe['locks'][label] = hashlib.sha256(data).hexdigest()
        recipe['expected_packages'][name] = rows
        for row in rows:
            if row['source'] != REGISTRY:
                match = GIT.fullmatch(row['source'])
                git_revisions.setdefault(match[1], set()).add(match[2])
    for index, (url, revisions) in enumerate(sorted(git_revisions.items())):
        destination = context / 'git' / str(index)
        destination.parent.mkdir(exist_ok=True)
        subprocess.run(['git', 'init', '--bare', '--quiet', str(destination)], check=True)
        name = url.rsplit('/', 1)[1].removesuffix('.git')
        known = canonical / name
        if url.startswith('https://github.com/GetBusbar/') and known.is_dir():
            remote = str(known)
        else:
            # No job token or credential helper is available to public GitHub
            # fetches, and the lock parser permits only exact GitHub commit URLs.
            remote = url
        environment = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'GIT_TERMINAL_PROMPT': '0',
                       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        for revision in sorted(revisions):
            subprocess.run(['git', '-c', 'credential.helper=', '-C', str(destination),
                'fetch', '--quiet', '--no-tags', '--depth', '1', remote,
                revision + ':refs/heads/input-' + revision], env=environment, check=True, timeout=300)
            if git(destination, 'rev-parse', 'refs/heads/input-' + revision) != revision:
                raise Violation('job seed Git revision differs')
        (destination / 'config').write_text('[core]\nrepositoryformatversion=0\nbare=true\n')
        shutil.rmtree(destination / 'hooks', ignore_errors=True)
        (destination / 'FETCH_HEAD').unlink(missing_ok=True)
        recipe['git'][url] = '/inputs/git/' + str(index)
    binding = {'schema': 'busbar.native-job-seed/1', 'repository': q.repository,
               'source': q.receipt['source'], 'vector_sha256': recipe['vector_sha256'],
               'locks': recipe['locks'], 'git': {k: sorted(v) for k, v in git_revisions.items()}}
    recipe['plan_sha256'] = hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()
    (context / 'recipe.json').write_text(json.dumps(recipe, sort_keys=True) + '\n')
    for name in ('seed.py', 'prepare.py'):
        shutil.copyfile(Path(__file__).resolve().parent / 'toolchain' / name, context / name)
    config = execution.config
    from linux_job_isolation import prepare_writable
    storage = prepare_writable(config['isolation'], [context, output], config['uid'], config['gid'])
    client = execution.collector_client
    daemon = client(['info', '--format', '{{json .}}'], capture_output=True, text=True)
    if daemon.returncode:
        raise Violation('dependency collector daemon identity unavailable')
    if 'name=userns' in json.loads(daemon.stdout).get('SecurityOptions', []):
        raise Violation('trusted collector endpoint must be the separate unremapped daemon')
    namespace = {'mode': 'host', 'uid': config['collector']['uid'], 'gid': config['collector']['gid'],
                 'scope': 'trusted fetch only; no candidate execution'}
    name = 'busbar-job-seed-' + uuid.uuid4().hex
    try:
        created = client(['create', '--name', name, '--pull=never', '--read-only',
            '--network=bridge', '--runtime', config['runtime'], '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--userns=host', '--user', f"{config['collector']['uid']}:{config['collector']['gid']}",
            '--memory=' + str(config['resources']['memory_bytes']), '--cpus=' + str(config['resources']['cpus']),
            '--pids-limit=' + str(config['resources']['pids']), '--init',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=1g,nr_inodes=65536,mode=1777', '--shm-size=64m',
            '--mount', f'type=bind,src={context},dst=/inputs',
            '--mount', f'type=bind,src={output},dst=/__busbar_collected',
            '--entrypoint', '/usr/bin/env', config['collector'].get('image', config['image']), '-i',
            'PATH=/usr/local/cargo/bin:/usr/bin:/bin', 'BUSBAR_NATIVE_SEED_ROOT=/__busbar_collected',
            config['python'], '-I', '-B', '/inputs/seed.py'],
            capture_output=True)
        if created.returncode:
            raise Violation('private dependency collector container creation failed')
        inspected = client(['inspect', name], capture_output=True, text=True)
        if inspected.returncode:
            raise Violation('trusted collector inspection unavailable')
        actual = json.loads(inspected.stdout)[0]
        settings = actual['HostConfig']
        if not (settings['NetworkMode'] == 'bridge' and settings['ReadonlyRootfs']
                and not settings['Privileged'] and settings.get('UsernsMode') == 'host'
                and settings['CapDrop'] == ['ALL'] and not settings.get('CapAdd')
                and settings['Memory'] == config['resources']['memory_bytes']
                and settings['PidsLimit'] == config['resources']['pids']
                and actual['Config']['User'] == f"{config['collector']['uid']}:{config['collector']['gid']}"):
            raise Violation('trusted dependency collector controls differ')
        expected_mounts = {(str(context), '/inputs', True), (str(output), '/__busbar_collected', True)}
        if {(m['Source'], m['Destination'], m['RW']) for m in actual['Mounts'] if m['Type'] == 'bind'} != expected_mounts:
            raise Violation('trusted dependency collector mounts differ')
        with (q.evidence / 'dependency-seed.stdout').open('wb') as out, (q.evidence / 'dependency-seed.stderr').open('wb') as err:
            collected = client(['start', '--attach', name], stdout=out, stderr=err, timeout=1800)
        if collected.returncode:
            raise Violation('private dependency collection failed; no candidate network fallback')
    finally:
        client(['rm', '--force', name], capture_output=True)
        absent = client(['container', 'ls', '--all', '--quiet', '--filter', 'name=^/' + name + '$'], capture_output=True)
        if absent.returncode or absent.stdout.strip():
            raise Violation('private dependency collector disposal was not confirmed')
    seed = json.loads((output / 'seed.json').read_text())
    if seed['plan_sha256'] != recipe['plan_sha256'] or seed['packages'] != recipe['expected_packages']:
        raise Violation('private dependency seed binding differs')
    directory = output / 'cargo-seed'
    actual = {}
    for path in directory.rglob('*'):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Violation('private dependency seed contains indirect or special files')
        with path.open('rb') as stream:
            actual[str(path.relative_to(directory))] = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != seed['files']:
        raise Violation('private dependency seed file inventory differs')
    execution.dependency_seed = directory
    execution.dependency_seed_sha256 = hashlib.sha256((output / 'seed.json').read_bytes()).hexdigest()
    q.receipt['dependency_seed'] = dict(binding, manifest_sha256=execution.dependency_seed_sha256,
                                       collector_disposed=True, shared_image=False, storage=storage, user_namespace=namespace)
    q.save()

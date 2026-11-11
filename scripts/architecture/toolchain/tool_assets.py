"""Stage checksum-pinned native tools without running installers or candidate code."""

from pathlib import Path
import shutil
import stat
import sys
import tarfile
import urllib.request
import zipfile

from prepare import pinned, relative, require, sha


def download(item, downloads):
    url = item['url']
    require(url.startswith(('https://github.com/', 'https://nodejs.org/dist/',
                           'https://static.crates.io/crates/', 'https://files.pythonhosted.org/packages/')),
            'unexpected pinned tool origin')
    path = Path(downloads) / url.rsplit('/', 1)[1]
    if not path.exists():
        partial = path.with_name(path.name + '.partial')
        try:
            with urllib.request.urlopen(url, timeout=60) as incoming, partial.open('xb') as outgoing:
                remaining = 512 * 1024**2
                while data := incoming.read(min(1024**2, remaining + 1)):
                    remaining -= len(data)
                    require(remaining >= 0, 'tool archive exceeds byte limit')
                    outgoing.write(data)
            require(sha(partial) == item['sha256'], 'tool archive digest differs')
            partial.rename(path)
        finally:
            partial.unlink(missing_ok=True)
    require(not path.is_symlink() and sha(path) == item['sha256'], 'tool archive digest differs')
    return path


def unpack_source(archive, destination, root):
    with tarfile.open(archive) as source:
        members = source.getmembers()
        require(len(members) <= 100000 and sum(p.size for p in members) <= 512 * 1024**2,
                'tool source exceeds byte limit')
        seen = set()
        for entry in members:
            path = relative(entry.name)
            require(path.parts[0] == root and (entry.isdir() or entry.isfile()),
                    'unsafe tool source member')
            require(entry.name not in seen, 'duplicate tool source member')
            seen.add(entry.name)
            target = destination / path
            if entry.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(entry) as incoming, target.open('xb') as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
                target.chmod(0o755 if entry.mode & 0o111 else 0o644)


def stage(pins, platform, output, downloads, payload, source, oracle=None):
    tools = {}
    directory = output / 'tool-payload'
    directory.mkdir()
    (output / 'tool-sources').mkdir()
    for name, item in sorted(platform.get('tools', {}).items()):
        archive = download(item, downloads)
        with tarfile.open(archive) as source_archive:
            matches = [p for p in source_archive.getmembers() if p.name == item['member']]
            require(len(matches) == 1 and matches[0].isfile() and matches[0].size <= 256 * 1024**2,
                    'missing or unsafe native tool member')
            path = directory / 'usr/local/bin' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with source_archive.extractfile(matches[0]) as incoming, path.open('xb') as outgoing:
                shutil.copyfileobj(incoming, outgoing)
            path.chmod(0o755)
        tools[name] = dict(item, installed='/usr/local/bin/' + name, installed_sha256=sha(path))
    wheels = []
    for item in platform.get('wheels', []):
        archive = download(item, downloads)
        with zipfile.ZipFile(archive) as wheel:
            seen = set()
            require(sum(p.file_size for p in wheel.infolist()) <= 128 * 1024**2,
                    'Python wheel exceeds byte limit')
            for entry in wheel.infolist():
                name = entry.filename.rstrip('/')
                path = relative(name)
                mode = entry.external_attr >> 16
                require(not stat.S_ISLNK(mode) and name not in seen
                        and not any(p.endswith('.data') for p in path.parts),
                        'unsupported Python wheel member')
                seen.add(name)
                target = directory / 'usr/local/lib/python3.11/dist-packages' / path
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with wheel.open(entry) as incoming, target.open('xb') as outgoing:
                        shutil.copyfileobj(incoming, outgoing)
                    target.chmod(0o644)
        wheels.append(item)
    cargo_tools = {}
    for name, item in sorted(pins.get('cargo_tools', {}).items()):
        archive = download(item, downloads)
        unpack_source(archive, output / 'tool-sources', item['root'])
        lock = output / 'tool-sources' / item['root'] / 'Cargo.lock'
        require(lock.is_file(), 'native Cargo tool requires a bundled lockfile')
        cargo_tools[name] = dict(item, lock_sha256=sha(lock))
    for name, item in payload.items():
        destination = relative(name)
        require(destination.is_relative_to('opt/busbar-conformance')
                and len(destination.parts) > 2 and set(item) == {'path', 'sha256', 'executable'}
                and type(item['executable']) is bool, 'invalid supplemental tool payload')
        path = pinned(source, item['path'], item['sha256'])
        target = directory / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        target.chmod(0o755 if item['executable'] else 0o644)
    oracle_record = None
    if oracle is not None:
        require(set(oracle) == {'pin', 'artifact'} and all(
            isinstance(item, dict) and set(item) == {'path', 'sha256'}
            for item in oracle.values()), 'invalid signed oracle input')
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from native_oracle import load_pin, verify
        policy = pinned(source, oracle['pin']['path'], oracle['pin']['sha256'])
        pin = load_pin(policy, oracle['pin']['sha256'])
        artifact = pinned(source, oracle['artifact']['path'], oracle['artifact']['sha256'])
        arch = platform['triple'].split('-')[0]
        expected = pin['platforms'][arch]['sha256']
        verify(artifact, pin, arch, output / 'oracle-verification')
        target = directory / 'opt/busbar-native/oracle' / expected / pin['bin']
        target.parent.mkdir(parents=True)
        shutil.copyfile(artifact, target)
        target.chmod(0o555)
        oracle_record = {'source': pin['source'], 'sha256': expected,
                         'pin_sha256': oracle['pin']['sha256'], 'signature_verified': True}
    inventory = {str(p.relative_to(directory)): sha(p)
                 for p in sorted(directory.rglob('*')) if p.is_file()}
    return {'tools': tools, 'wheels': wheels, 'cargo_tools': cargo_tools,
            'payload': payload, 'oracle': oracle_record, 'files': inventory}

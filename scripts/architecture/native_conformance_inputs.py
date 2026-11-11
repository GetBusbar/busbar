"""Protected, measured public instruments mounted read-only for one native job."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
from types import SimpleNamespace
import urllib.parse

from native_staged_fixtures import regular, require


def stage(q, manifest, expected):
    payload = regular(Path(manifest), 16 * 1024**2)
    require(hashlib.sha256(payload).hexdigest() == expected, 'conformance input plan digest differs')
    data = json.loads(payload)
    require(set(data) == {'schema', 'bundles'} and data['schema'] == 'busbar.native-conformance-inputs/1'
            and isinstance(data['bundles'], dict) and len(data['bundles']) <= 32,
            'invalid conformance input plan')
    mounted = []
    inventory = {}
    total = 0
    for name, bundle in data['bundles'].items():
        require(re.fullmatch('[a-z][a-z0-9-]{0,63}', name)
                and isinstance(bundle, dict) and set(bundle) == {'path', 'files', 'provenance'}
                and isinstance(bundle['files'], dict) and 0 < len(bundle['files']) <= 100000
                and isinstance(bundle['provenance'], list) and bundle['provenance'],
                'invalid conformance tool bundle')
        for origin in bundle['provenance']:
            require(isinstance(origin, dict) and set(origin) == {'uri', 'sha256'},
                    'invalid instrument provenance')
            url = urllib.parse.urlsplit(origin['uri'])
            immutable_archive_query = (url.netloc == 'github.com'
                and re.fullmatch(r'/api/v4/projects/[^/]+/repository/archive\.tar\.gz', url.path)
                and re.fullmatch(r'sha=[0-9a-f]{40}', url.query))
            require(url.scheme == 'https' and url.netloc and not url.username and not url.password
                    and (not url.query or immutable_archive_query) and not url.fragment
                    and re.fullmatch('[0-9a-f]{64}', origin['sha256']),
                    'instrument provenance must be a credential-free pinned HTTPS source')
        source = Path(bundle['path'])
        if not source.is_absolute():
            require(source.parts and all(part not in ('.', '..') for part in source.parts),
                    'portable conformance bundle escapes its package')
            source = Path(manifest).resolve().parent / source
        require(source.is_absolute() and source.is_dir() and source == source.resolve()
                and not any(source.is_relative_to(path) for path in (q.root.resolve(), q.work.resolve())),
                'conformance bundle is candidate writable')
        destination = q.control / ('conformance-tools-' + name)
        destination.mkdir(mode=0o755)
        actual = set()
        try:
            for path in source.rglob('*'):
                require(not path.is_symlink(), 'indirect conformance bundle input')
                if path.is_dir():
                    continue
                relative = str(path.relative_to(source))
                require(relative in bundle['files'], 'unlisted conformance instrument')
                spec = bundle['files'][relative]
                require(isinstance(spec, dict) and set(spec) == {'sha256', 'executable'}
                        and re.fullmatch('[0-9a-f]{64}', spec['sha256'])
                        and type(spec['executable']) is bool, 'invalid instrument file identity')
                content = regular(path, 512 * 1024**2)
                total += len(content)
                require(total <= 4 * 1024**3, 'conformance instruments exceed byte budget')
                require(hashlib.sha256(content).hexdigest() == spec['sha256'],
                        'conformance instrument digest differs')
                output = destination / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(content)
                output.chmod(0o555 if spec['executable'] else 0o444)
                actual.add(relative)
            require(actual == set(bundle['files']), 'conformance instrument file set differs')
        except BaseException:
            shutil.rmtree(destination)
            raise
        target = '/opt/busbar-conformance/' + name
        mounted.append((destination, Path(target)))
        inventory[name] = {'path': target, 'files': bundle['files'], 'provenance': bundle['provenance']}
    published = q.control / 'conformance-inputs.json'
    published.write_text(json.dumps({'schema': data['schema'], 'bundles': inventory}, sort_keys=True) + '\n')
    published.chmod(0o444)
    q.execution.conformance_mounts.extend(mounted)
    q.execution.conformance_mounts.append((published, Path('/__busbar_conformance_inputs.json')))
    q.execution.conformance_inputs_manifest = published
    q.receipt['conformance_inputs'] = {'plan_sha256': expected,
        'mounted_manifest_sha256': hashlib.sha256(published.read_bytes()).hexdigest(), 'bundles': inventory}
    from native_python_runtime import bind
    bind(q)


def pack(manifest, expected, output):
    """Make a deterministic transport archive from already approved instruments."""
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='conformance-pack-', dir=output.parent) as directory:
        root = Path(directory)
        control = root / 'control'
        control.mkdir()
        execution = SimpleNamespace(conformance_mounts=[], conformance_inputs_manifest=None)
        q = SimpleNamespace(root=root / 'candidate-checkout', work=root / 'candidate-work',
                            control=control, execution=execution, receipt={})
        stage(q, manifest, expected)
        portable = json.loads(execution.conformance_inputs_manifest.read_text())
        for name, bundle in portable['bundles'].items():
            bundle['path'] = 'bundles/' + name
        manifest_bytes = (json.dumps(portable, sort_keys=True, indent=2) + '\n').encode()
        with output.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                def append(name, content, mode):
                    header = tarfile.TarInfo(name)
                    header.size, header.mode, header.mtime = len(content), mode, 0
                    archive.addfile(header, io.BytesIO(content))
                append('manifest.json', manifest_bytes, 0o444)
                for name, bundle in sorted(portable['bundles'].items()):
                    source = control / ('conformance-tools-' + name)
                    for relative, spec in sorted(bundle['files'].items()):
                        append('bundles/' + name + '/' + relative,
                               regular(source / relative, 512 * 1024**2),
                               0o555 if spec['executable'] else 0o444)
        with output.open('rb') as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        return {'archive': str(output), 'archive_sha256': checksum, 'bytes': output.stat().st_size,
                'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
                'bundles': sorted(portable['bundles'])}


def unpack(archive, expected, manifest_sha256, output):
    """Verify the protected archive, then extract only bounded regular files."""
    archive, output = Path(archive), Path(output)
    with archive.open('rb') as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == expected,
                'conformance archive digest differs')
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    seen, total = set(), 0
    try:
        with tarfile.open(archive, 'r:gz') as source:
            for member in source:
                name = Path(member.name)
                require(member.isfile() and not name.is_absolute()
                        and name.parts and all(part not in ('.', '..') for part in name.parts)
                        and (member.name == 'manifest.json' or name.parts[0] == 'bundles')
                        and member.name not in seen and len(seen) < 400000,
                        'unsafe conformance archive member')
                limit = 16 * 1024**2 if member.name == 'manifest.json' else 512 * 1024**2
                total += member.size
                require(0 <= member.size <= limit and total <= 4 * 1024**3 + 16 * 1024**2,
                        'conformance archive exceeds byte budget')
                path = output / name
                path.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as incoming, path.open('xb') as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
                path.chmod(member.mode & 0o555)
                seen.add(member.name)
        manifest = output / 'manifest.json'
        require(hashlib.sha256(regular(manifest, 16 * 1024**2)).hexdigest() == manifest_sha256,
                'portable conformance manifest differs')
        return {'manifest': str(manifest), 'manifest_sha256': manifest_sha256}
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    make = sub.add_parser('pack')
    make.add_argument('--manifest', type=Path, required=True)
    make.add_argument('--manifest-sha256', required=True)
    make.add_argument('--output', type=Path, required=True)
    extract = sub.add_parser('unpack')
    extract.add_argument('--archive', type=Path, required=True)
    extract.add_argument('--archive-sha256', required=True)
    extract.add_argument('--manifest-sha256', required=True)
    extract.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.operation == 'pack':
        result = pack(args.manifest, args.manifest_sha256, args.output)
    else:
        result = unpack(args.archive, args.archive_sha256, args.manifest_sha256, args.output)
    print(json.dumps(result))


if __name__ == '__main__':
    main()

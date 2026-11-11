"""Controller intake of pre-recorded, independently pinned legacy fixtures."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

from check import Violation


def require(value, message):
    if not value:
        raise Violation(message)


def regular(path, limit=64 * 1024**2):
    require(not any(part.is_symlink() for part in (path, *path.parents)), 'indirect staged fixture file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
                'staged fixture file is not a bounded regular file')
        payload = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        require(len(payload) == before.st_size and len(payload) <= limit
                and (before.st_mtime_ns, before.st_ctime_ns) == (after.st_mtime_ns, after.st_ctime_ns),
                'staged fixture changed during intake')
        return payload


def validate_manifest(files, trusted):
    rows = {}
    listed = {}
    for line in files['MANIFEST.tsv'].decode().splitlines():
        if not line or line.startswith('#'):
            continue
        key, value = line.split('\t', 1)
        if key == 'file':
            name, digest = value.split()
            require(name not in listed and name in files, 'duplicate or missing migration file')
            listed[name] = digest
        else:
            require(key in {'busbar', 'plugin', 'backend', 'recorder', 'requests'} and key not in rows,
                    'invalid migration manifest field')
            rows[key] = value
    require(set(rows) == {'busbar', 'plugin', 'backend', 'recorder', 'requests'}
            and rows['backend'] == 'sqlite' and re.fullmatch('[0-9a-f]{40}', rows['recorder'])
            and rows['requests'].split() == ['200', '200', '200', '503', '200', '200'],
            'migration fixture is not the fixed published SQLite recording')
    require(set(listed) == set(files) - {'MANIFEST.tsv'} and {'governance.db', 'rows.json'} <= set(listed),
            'migration manifest does not cover its complete fixture')
    for name, expected in listed.items():
        require(hashlib.sha256(files[name]).hexdigest() == expected, 'migration manifest file digest differs')
    version, binary, digest = rows['busbar'].split()
    require(version == 'v1.5.5', 'migration fixture did not use published 1.5.5')
    golden = [line.split('\t') for line in (trusted / 'testing/shadow-oracle/golden-digests.tsv').read_text().splitlines()
              if line and not line.startswith('#')]
    require(any(row[0] == '1.5.5' and row[1] == binary and row[-1] == digest for row in golden),
            'migration writer is not a protected published binary')
    tag, artifact, digest = rows['plugin'].split()
    plugins = [line.split('\t') for line in (trusted / 'testing/shadow-oracle/plugin-digests.tsv').read_text().splitlines()
               if line and not line.startswith('#')]
    require(any(row[:4] == ['store-sqlite', tag, artifact, digest] for row in plugins),
            'migration plugin is not a protected published SQLite asset')
    return rows


def stage(q, path, expected):
    payload = regular(Path(path), 4 * 1024**2)
    require(hashlib.sha256(payload).hexdigest() == expected, 'protected fixture input plan digest differs')
    data = json.loads(payload)
    require(set(data) == {'schema', 'fixtures'} and data['schema'] == 'busbar.native-staged-fixtures/1'
            and set(data['fixtures']) <= {'sqlite-1.5.5'}, 'unknown staged fixture plan')
    staged = {}
    evidence = {}
    for name, entry in data['fixtures'].items():
        require(set(entry) == {'path', 'files', 'origin'} and isinstance(entry['files'], dict)
                and set(entry['origin']) == {'repository', 'revision', 'path'}
                and entry['origin']['repository'] == 'GetBusbar/busbar-store-sqlite'
                and re.fullmatch('[0-9a-f]{40}', entry['origin']['revision'])
                and entry['origin']['path'] == 'store-sqlite/tests/fixtures/1.5.5',
                'invalid staged SQLite fixture identity')
        source = Path(entry['path'])
        require(source.is_absolute() and source == source.resolve() and source.is_dir()
                and not any(source.is_relative_to(root) for root in (q.root.resolve(), q.work.resolve())),
                'staged fixture source is candidate writable')
        files = {}
        total = 0
        for item in sorted(source.rglob('*')):
            require(not item.is_symlink(), 'indirect staged fixture input')
            if item.is_dir():
                continue
            relative = str(item.relative_to(source))
            require(relative in entry['files'], 'unlisted staged fixture file')
            content = regular(item)
            total += len(content)
            require(total <= 128 * 1024**2, 'staged fixture exceeds byte budget')
            require(hashlib.sha256(content).hexdigest() == entry['files'][relative],
                    'staged fixture file digest differs')
            files[relative] = content
        require(set(files) == set(entry['files']) and 'MANIFEST.tsv' in files,
                'staged fixture file set differs')
        recorded = validate_manifest(files, q.trusted)
        destination = q.control / ('staged-' + name)
        destination.mkdir(mode=0o755)
        try:
            for relative, content in files.items():
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                target.chmod(0o444)
            q.execution.extra_readonly.append(destination)
        except BaseException:
            shutil.rmtree(destination)
            raise
        staged[name] = destination
        evidence[name] = {'origin': entry['origin'], 'files': entry['files'], 'recorded': recorded}
    q.receipt['staged_fixture_inputs'] = {'plan_sha256': expected, 'fixtures': evidence}
    return staged


def collect_required(q):
    """Resolve the policy-owned historical fixture, never record a new golden."""
    from native_policy import native_settings
    from native import fetch_environment, git
    name = native_settings(q.repository, q.policy).get('migration_fixture')
    if name is None or name in q.staged_fixtures:
        return
    catalog_path = q.trusted / 'ci/native-fixtures.json'
    payload = regular(catalog_path, 4 * 1024**2)
    catalog = json.loads(payload)
    require(set(catalog) == {'schema', 'fixtures'} and catalog['schema'] == 'busbar.native-fixture-catalog/1'
            and name in catalog['fixtures'], 'required migration fixture is absent from protected catalog')
    entry = catalog['fixtures'][name]
    require(set(entry) == {'origin', 'files'} and isinstance(entry['files'], dict), 'invalid fixture catalog entry')
    origin = entry['origin']
    require(set(origin) == {'repository', 'revision', 'path'}
            and origin['repository'] == 'GetBusbar/busbar-store-sqlite'
            and re.fullmatch('[0-9a-f]{40}', origin['revision'])
            and origin['path'] == 'store-sqlite/tests/fixtures/1.5.5', 'unapproved migration source')
    directory = q.control / 'migration-source'
    directory.mkdir(mode=0o700)
    objects = directory / 'objects.git'
    subprocess.run(['git', 'init', '--bare', '--quiet', str(objects)], check=True)
    environment = fetch_environment()
    remote = environment['CI_SERVER_URL'].rstrip('/') + '/' + origin['repository'] + '.git'
    subprocess.run(['git', '-C', str(objects), 'fetch', '--quiet', '--depth', '1', remote,
                    origin['revision'] + ':refs/heads/fixture'], env=environment, check=True, timeout=300)
    require(git(objects, 'rev-parse', 'refs/heads/fixture') == origin['revision'], 'migration source revision differs')
    source = directory / 'files'
    source.mkdir()
    for relative, expected in entry['files'].items():
        require(re.fullmatch(r'[A-Za-z0-9_./-]+', relative)
                and not relative.startswith('/') and all(p not in ('', '.', '..') for p in relative.split('/')),
                'invalid migration source file')
        value = subprocess.check_output(['git', '-C', str(objects), 'show',
            origin['revision'] + ':' + origin['path'] + '/' + relative], timeout=30)
        require(len(value) <= 64 * 1024**2 and hashlib.sha256(value).hexdigest() == expected,
                'historical migration source digest differs')
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
    plan = {'schema': 'busbar.native-staged-fixtures/1',
            'fixtures': {name: dict(entry, path=str(source))}}
    path = directory / 'plan.json'
    path.write_text(json.dumps(plan, sort_keys=True) + '\n')
    q.staged_fixtures.update(stage(q, path, hashlib.sha256(path.read_bytes()).hexdigest()))
    q.receipt['staged_fixture_inputs']['catalog_sha256'] = hashlib.sha256(payload).hexdigest()
    shutil.rmtree(objects)

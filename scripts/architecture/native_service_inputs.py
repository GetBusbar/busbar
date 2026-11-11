"""Stage only protected policy's pinned AMD64 peers through private packages."""
import hashlib
import json
from pathlib import Path
import re
import tarfile

from check import read
from native_ci_bootstrap import BASE_ENV, DOCKER, fetch_judge_archive, require, run
from native_policy import native_settings


def selection(trusted, repository):
    plan = json.loads((trusted / 'ci/native-service-images.json').read_text())
    require(set(plan) == {'schema', 'services'} and plan['schema'] == 'busbar.native-service-images/1',
            'unknown protected service input schema')
    names = native_settings(repository, read(trusted / 'ci/architecture.toml')).get('services', [])
    catalog = {}
    for line in (trusted / 'testing/fleet-fixtures/service-images.tsv').read_text().splitlines():
        if line and not line.startswith('#'):
            fields = line.split('\t')
            catalog[fields[0]] = fields[1] + '@' + fields[2]
    result = {}
    for name in names:
        row = plan['services'].get(name, {})
        require(set(row) == {'reference', 'archive_url', 'archive_sha256', 'bytes', 'manifest_sha256', 'config_sha256'},
                'incomplete protected service archive')
        require(row['reference'] == catalog.get(name), 'service archive differs from protected catalog')
        for key in ('archive_sha256', 'manifest_sha256', 'config_sha256'):
            require(isinstance(row[key], str) and re.fullmatch(r'[0-9a-f]{64}', row[key]), 'invalid service digest')
        require(type(row['bytes']) is int and 0 < row['bytes'] <= 1024**3, 'invalid service archive size')
        prefix = 'https://github.com/api/v4/projects/3/packages/generic/busbar-native-service-' + name
        require(re.fullmatch(re.escape(prefix) + r'/[0-9]{8}-' + row['archive_sha256'] + r'/linux-amd64\.tar',
                             row['archive_url']), 'service package origin or identity differs')
        result[name] = row
    return result


def metadata(archive, row):
    with tarfile.open(archive, 'r:') as source:
        def blob(checksum):
            item = source.getmember('blobs/sha256/' + checksum)
            require(item.isfile() and item.size < 1024**2, 'invalid service OCI metadata')
            raw = source.extractfile(item).read()
            require(hashlib.sha256(raw).hexdigest() == checksum, 'service OCI metadata digest differs')
            return json.loads(raw)
        index = blob(row['reference'].rsplit('@sha256:', 1)[1])
        selected = [item for item in index['manifests'] if item.get('platform', {}).get('os') == 'linux'
                    and item.get('platform', {}).get('architecture') == 'amd64']
        require(len(selected) == 1 and selected[0]['digest'] == 'sha256:' + row['manifest_sha256'],
                'service platform is not anchored to the catalog index')
        manifest = blob(row['manifest_sha256'])
        require(manifest['config']['digest'] == 'sha256:' + row['config_sha256'], 'service config identity differs')
        config = blob(row['config_sha256'])
        require(config['os'] == 'linux' and config['architecture'] == 'amd64', 'service config platform differs')
        return config


def verify_import(actual, row, config):
    require(any(value.endswith('@' + row['reference'].rsplit('@', 1)[1]) for value in actual.get('RepoDigests', [])),
            'loaded service has lost its catalog index identity')
    require(actual.get('Os') == 'linux' and actual.get('Architecture') == 'amd64'
            and actual.get('RootFS') == {'Type': config['rootfs']['type'], 'Layers': config['rootfs']['diff_ids']}
            and all(actual.get('Config', {}).get(key) == value for key, value in config['config'].items()),
            'loaded service execution bytes differ')


def stage(trusted, repository, store, token):
    rows = selection(trusted, repository)
    if not rows:
        return {}
    root = Path(store) / 'service-inputs'
    root.mkdir(mode=0o700)
    client = [DOCKER, '--host', 'unix:///var/run/docker.sock']
    receipts = {}
    for name, row in rows.items():
        archive = root / (name + '.tar')
        try:
            fetch_judge_archive(row, archive, token)
            config = metadata(archive, row)
            run([*client, 'image', 'load', '--platform', 'linux/amd64', '--input', archive], env=BASE_ENV,
                capture_output=True, text=True, timeout=300)
            actual = json.loads(run([*client, 'image', 'inspect', '--platform', 'linux/amd64', row['reference']],
                                    env=BASE_ENV, capture_output=True, text=True).stdout)[0]
            verify_import(actual, row, config)
            receipts[name] = {'reference': row['reference'], 'archive_sha256': row['archive_sha256'],
                              'manifest_sha256': row['manifest_sha256'], 'config_sha256': row['config_sha256'],
                              'platform': 'linux/amd64', 'candidate_execution': False}
        finally:
            archive.unlink(missing_ok=True)
    return receipts

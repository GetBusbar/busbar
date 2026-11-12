"""Shared architecture policy model for the Python step runner.

The architecture step itself (shipping/assembly graph, declared edges, source
scan, C plugin checks and the compiler witnesses) runs as the pinned
`busbar-ci architecture` controller (tools/ci/src/architecture). These are the
pieces native.py and its helpers still import until the step runner is ported:
the policy classification model, the assembly vector binding, the C witness
recipe loader and the generated-subject fingerprint (which the controller
recomputes byte-for-byte when it validates a generated execution context).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib
from urllib.parse import urlsplit


class Violation(ValueError):
    pass


def read(path):
    with Path(path).open('rb') as stream:
        return tomllib.load(stream)


def git_repository(source):
    """Canonical owner/repository, retaining host and rejecting other source types."""
    if not source or not source.startswith('git+'):
        return None
    parsed = urlsplit(source[4:])
    path = parsed.path.strip('/').removesuffix('.git')
    return parsed.hostname, path


class Policy:
    def __init__(self, data):
        if data.get('version') != 1:
            raise Violation('unsupported architecture policy')
        self.data = data
        self.packages = {}
        for name, entry in data['core'].items():
            self.packages[name] = dict(entry, repository='GetBusbar/busbar', role='core')
        for repository, repo in data['repositories'].items():
            own = [p['name'] for p in repo.get('packages', []) if p['role'] == 'implementation']
            for p in repo.get('packages', []):
                allows = ['busbar-contract'] + (own if p['role'] == 'wrapper' else [])
                self.packages[p['name']] = dict(p, repository=repository, allows=allows)
        assembly = data['assembly']
        self.packages[assembly['package']] = dict(assembly, role='assembly', allows=list(self.packages))
        for host in data.get('test_hosts', []):
            if host.get('package'):
                self.packages[host['package']] = dict(host, role='test_host', dev_allows=host['allows'])

    def classify(self, package, repository, checkout, development_paths=None):
        name, source = package['name'], package.get('source')
        identity = git_repository(source)
        entry = self.packages.get(name)
        if entry is None:
            if identity and any(e['name'] == name and identity == ('github.com', e['repository']) for e in self.data.get('external_sources', [])):
                return None
            if name.startswith('busbar-') or (identity and identity[1].split('/')[0] in ('GetBusbar', 'BusbarInc')):
                raise Violation(f'unclassified first-party package: {name} ({source})')
            return None
        if source:
            canonical_host = os.environ.get('CI_SERVER_HOST')
            expected_host = canonical_host if entry['repository'].startswith('BusbarInc/') else 'github.com'
            if identity != (expected_host, entry['repository']) and identity != (canonical_host, entry['repository']):
                raise Violation(f'noncanonical source for {name}: {source}')
        else:
            actual = Path(package['manifest_path']).resolve()
            expected = (checkout / entry['manifest']).resolve()
            local = development_paths or {}
            if not (entry['repository'] == repository and actual == expected) and actual != local.get(name):
                raise Violation(f'unapproved path/source substitution for {name}: {actual}')
        return entry


def vector_revisions(policy, vector):
    sdk = vector['sdk']
    if not re.fullmatch('[0-9a-f]{40}', sdk):
        raise Violation('assembled SDK pin is not immutable')
    expected = {name for name, entry in policy.data['repositories'].items()
                if not entry['private'] and not entry.get('standalone') and entry.get('language') != 'c'}
    revisions = {'GetBusbar/busbar': sdk}
    for row in vector['products']:
        repo = 'GetBusbar/' + row['repo']
        if repo not in expected or repo in revisions:
            raise Violation('unclassified or duplicate assembly product: ' + repo)
        entry = policy.data['repositories'][repo]
        packages = {p['name'] for p in entry['packages'] if p['role'] == 'wrapper'}
        if (row['package'] not in packages or row['kind'] != entry['kind']
                or row['url'].removesuffix('.git') != 'https://github.com/' + repo
                or not re.fullmatch('[0-9a-f]{40}', row['commit'])
                or not re.fullmatch('[0-9a-f]{64}', row['lock_sha256'])):
            raise Violation('assembly product identity mismatch: ' + repo)
        revisions[repo] = row['commit']
    if set(revisions) != expected | {'GetBusbar/busbar'}:
        raise Violation('assembly product vector is incomplete')
    witness = vector['c_witness']
    if (not isinstance(witness, dict) or not {'repo', 'url', 'commit', 'sdk'} <= set(witness)
            or set(witness) - {'repo', 'url', 'commit', 'sdk', 'kind', 'language', 'header'}
            or any(not isinstance(value, str) for value in witness.values())):
        raise Violation('C witness vector has missing or unknown keys')
    repo = 'GetBusbar/' + witness['repo']
    c_owner = policy.data['repositories'].get(repo, {})
    if (c_owner.get('language') != 'c' or c_owner.get('private', False)
            or witness['sdk'] != sdk or not re.fullmatch('[0-9a-f]{40}', witness['commit'])
            or witness['url'].removesuffix('.git') != 'https://github.com/' + repo
            or witness.get('language', 'c') != 'c'
            or witness.get('kind', c_owner.get('kind')) != c_owner.get('kind')
            or witness.get('header', PUBLIC_C_HEADER) != PUBLIC_C_HEADER):
        raise Violation('C witness source/SDK mismatch')
    return revisions


PUBLIC_C_HEADER = 'crates/busbar-contract/include/busbar_plugin.h'


def validate_c_recipe(recipe, entry):
    from product_artifacts import relative_path
    if not isinstance(recipe, dict) or set(recipe) != {'sources', 'test-root', 'unit', 'schema'}:
        raise Violation('C witness recipe has missing or unknown keys')
    unit, schema = recipe['unit'], recipe['schema']
    if (not isinstance(unit, dict) or set(unit) != {'sources', 'defines'}
            or not isinstance(schema, dict) or set(schema) != {'source', 'driver'}):
        raise Violation('C witness requires bounded unit and schema recipes')
    def sources(values):
        if (not isinstance(values, list) or not 1 <= len(values) <= 16
                or any(not isinstance(value, str) for value in values) or len(set(values)) != len(values)):
            raise Violation('C witness source count or duplicates')
        for value in values:
            if not relative_path(value).endswith('.c'):
                raise Violation('C witness source must be a relative C file')
        return values
    sources(recipe['sources'])
    sources(unit['sources'])
    sources([schema['source']])
    if sorted(recipe['sources']) != sorted(entry.get('sources', [])):
        raise Violation('C witness sources differ from trusted classification')
    if not relative_path(schema['driver']).endswith('.py'):
        raise Violation('C schema driver must be a relative Python file')
    test_root = Path(relative_path(recipe['test-root']))
    if (any(Path(source).parent != test_root for source in recipe['sources'])
            or any(not Path(source).is_relative_to(test_root)
                   for source in [*unit['sources'], schema['source'], schema['driver']])):
        raise Violation('C witness test paths leave their declared source root')
    defines = unit['defines']
    if (not isinstance(defines, list) or len(defines) > 8
            or any(not isinstance(d, str) or not re.fullmatch(r'BUSBAR_[A-Z0-9_]{1,96}', d) for d in defines)
            or len(set(defines)) != len(defines)):
        raise Violation('C witness permits bounded macro names, never compiler arguments')
    return recipe


def load_c_recipe(policy, repository, checkout, revision=None):
    from product_artifacts import blob, git, pairs, regular_under
    checkout = Path(checkout)
    entry = policy.data['repositories'].get(repository, {})
    if entry.get('language') != 'c':
        raise Violation('C witness owner is not classified as C')
    head = git(checkout, 'rev-parse', 'HEAD').decode().strip()
    if revision is not None and head != revision:
        raise Violation('C witness checkout differs from admitted commit')
    revision = revision or head
    relative = 'testing/c-witness.json'
    data = blob(checkout, revision, relative, 16 * 1024)
    if regular_under(checkout / relative, checkout).read_bytes() != data:
        raise Violation('C witness recipe differs from its committed bytes')
    recipe = validate_c_recipe(json.loads(data, object_pairs_hook=pairs), entry)
    paths = [*recipe['sources'], *recipe['unit']['sources'],
             recipe['schema']['source'], recipe['schema']['driver']]
    for relative in paths:
        expected = blob(checkout, revision, relative, 2 * 1024 * 1024)
        if regular_under(checkout / relative, checkout).read_bytes() != expected:
            raise Violation('C witness source differs from its committed bytes')
    return recipe


def generated_revision(checkout):
    """Bound the exact controller-registered generated source, without Git fallback."""
    from native_confinement import checked_directory
    checkout = checked_directory(checkout)
    inventory, total = [], 0
    for count, path in enumerate(checkout.rglob('*'), start=1):
        if count > 10000:
            raise Violation('generated architecture source exceeds entry count')
        info = path.lstat()
        relative = path.relative_to(checkout)
        if (not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
                or '.git' in relative.parts):
            raise Violation('generated architecture source contains indirect or Git control files')
        row = {'path': relative.as_posix(), 'permissions': stat.S_IMODE(info.st_mode),
               'kind': 'directory', 'size': 0, 'sha256': None}
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
            if info.st_nlink != 1 or info.st_size > 16 * 1024**2 or total > 128 * 1024**2:
                raise Violation('generated architecture source exceeds collection bounds')
            payload = path.read_bytes()
            if len(payload) != info.st_size:
                raise Violation('generated architecture source changed while fingerprinting')
            row.update(kind='file', size=info.st_size, sha256=hashlib.sha256(payload).hexdigest())
        inventory.append(row)
    encoded = json.dumps(sorted(inventory, key=lambda row: row['path']),
                         sort_keys=True, separators=(',', ':')).encode()
    return 'generated-sha256:' + hashlib.sha256(encoded).hexdigest()

"""Shared architecture policy model for the owner Python tooling.

The architecture step (shipping/assembly graph, declared edges, source scan,
C plugin checks, compiler witnesses) and the native step runner are the pinned
`busbar-ci` controller (tools/ci/src/architecture, tools/ci/src/native, with the
shared readers in tools/ci/src/product.rs). These are the policy classification
model and assembly vector binding that admission, product_artifacts,
native_policy and the retained-evidence verifiers still import.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
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

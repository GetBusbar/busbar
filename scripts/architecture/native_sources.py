"""Read immutable public inputs from the canonical forge before admission.

Public mirrors contain admitted stage branches only. A coherent SDK cutover must
qualify candidate commits before those branches move. Fetch credentials stay in the
trusted collector; Cargo receives only credential-free local Git URL mappings.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import re
import subprocess
import tomllib


SOURCE = re.compile(r'git\+https://github.com/(GetBusbar/[^/?#]+?)(?:\.git)?\?rev=([0-9a-f]{40})#([0-9a-f]{40})')


def standalone_products(repository, evaluation_only, vector):
    """Select the exact standalone graphs needed by the trusted job's callers.

    Core native builds all declared product artifacts. Core conformance also
    builds the pinned OIDC workspace. Release scaffolds need the SDK as a Git
    dependency, which the local SDK workspace lock cannot materialize; the same
    admitted OIDC graph supplies both SDK contract and loader Git dependencies.
    """
    if type(evaluation_only) is not bool:
        raise ValueError('standalone product selection requires the controller job mode')
    if repository == 'GetBusbar/busbar' and not evaluation_only:
        return vector['products']
    if repository in ('GetBusbar/busbar', 'GetBusbar/busbar-release'):
        selected = [row for row in vector['products'] if row['repo'] == 'busbar-auth-oidc']
        if len(selected) != 1:
            raise ValueError('required OIDC SDK consumer graph is absent or ambiguous')
        return selected
    return []


def lock_inputs(text, policy):
    allowed = {'GetBusbar/busbar'} | {name for name, row in policy['repositories'].items() if not row['private']}
    sources = defaultdict(set)
    lock = tomllib.loads(text)
    # Cargo fetches unused patches while loading the workspace too. These exact
    # revisions belong to this lock's inputs even without a resolved package.
    for package in lock.get('package', []) + lock.get('patch', {}).get('unused', []):
        source = package.get('source', '')
        if not source.startswith('git+https://github.com/GetBusbar/'):
            continue
        match = SOURCE.fullmatch(source)
        if not match or match[2] != match[3]:
            raise ValueError('first-party source must be an exact immutable Git commit')
        repository, revision = match[1], match[2]
        if repository in allowed:
            sources[repository].add(revision)
        # Existing public third-party forks are governed by the dependency policy,
        # not treated as unpublished first-party plugin candidates.
    return sources


def inputs(host, candidate, policy):
    sources = defaultdict(set)
    for root, relative in ((host, 'Cargo.lock'), (host, 'dist/default/Cargo.lock'), (candidate, 'Cargo.lock')):
        lock = root / relative
        if not lock.is_file():
            continue
        for repository, revisions in lock_inputs(lock.read_text(), policy).items():
            sources[repository].update(revisions)
    return sources


def product_inputs(parent, vector, policy):
    """Standalone product builds use their own lockfiles, including codec forks.

    Read only the explicit assembled products, not historical dependency lockfiles:
    a Git dependency's own lockfile does not govern its consumer's resolution.
    """
    sources = defaultdict(set)
    for product in vector['products']:
        data = subprocess.check_output(['git', '-C', str(parent / product['repo']),
                                        'show', product['commit'] + ':Cargo.lock'])
        if hashlib.sha256(data).hexdigest() != product['lock_sha256']:
            raise ValueError('standalone product lock differs from assembled vector')
        for repository, revisions in lock_inputs(data.decode(), policy).items():
            sources[repository].update(revisions)
    return sources


def prepare(q, host):
    from native import fetch_environment, git
    sources = inputs(host, q.root, q.policy.data)
    for repository, revisions in inputs(q.sdk(), q.root, q.policy.data).items():
        sources[repository].update(revisions)
    vector = json.loads((host / 'scripts/ci-product-pins.json').read_text())
    sources['GetBusbar/busbar'].update((vector['sdk'], git(host, 'rev-parse', 'HEAD')))
    for product in vector['products']:
        sources['GetBusbar/' + product['repo']].add(product['commit'])
    # All listed products are public; private candidates never enter a public map.
    allowed = {'GetBusbar/busbar'} | {name for name, row in q.policy.data['repositories'].items() if not row['private']}
    if set(sources) - allowed:
        raise ValueError('unclassified or private repository in public product inputs')
    parent = q.work / 'canonical-inputs'
    parent.mkdir()
    env = fetch_environment()
    server = env['CI_SERVER_URL'].rstrip('/')
    fetched = defaultdict(set)
    def fetch(repository, revisions):
        if any(not re.fullmatch('[0-9a-f]{40}', revision) for revision in revisions):
            raise ValueError('immutable source revision required')
        cache = parent / repository.rsplit('/', 1)[1]
        if not cache.exists():
            subprocess.run(['git', 'init', '--bare', '--quiet', str(cache)], check=True)
        for revision in sorted(revisions - fetched[repository]):
            subprocess.run(['git', '-C', str(cache), 'fetch', '--quiet', '--depth', '1',
                server + '/' + repository + '.git', revision + ':refs/heads/input-' + revision], env=env, check=True)
            if git(cache, 'rev-parse', 'refs/heads/input-' + revision) != revision:
                raise ValueError('canonical input revision mismatch')
            fetched[repository].add(revision)
    for repository, revisions in sorted(sources.items()):
        fetch(repository, revisions)
    standalone = standalone_products(q.repository, q.evaluation_only, vector)
    for repository, revisions in product_inputs(parent, {'products': standalone}, q.policy.data).items():
        sources[repository].update(revisions)
        fetch(repository, revisions)
    settings = []
    for repository in sorted(sources):
        cache = parent / repository.rsplit('/', 1)[1]
        for suffix in ('', '.git'):
            settings.append(('url.' + cache.as_uri() + '.insteadOf', 'https://github.com/' + repository + suffix))
    q.env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_COUNT=str(len(settings)))
    for index, (key, value) in enumerate(settings):
        q.env['GIT_CONFIG_KEY_' + str(index)] = key
        q.env['GIT_CONFIG_VALUE_' + str(index)] = value
    q.receipt['canonical_inputs'] = {name: sorted(revisions) for name, revisions in sorted(sources.items())}
    q.save()

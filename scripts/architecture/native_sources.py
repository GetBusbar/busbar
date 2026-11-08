"""Read immutable public inputs from the canonical forge before admission.

Public mirrors contain admitted stage branches only. A coherent SDK cutover must
qualify candidate commits before those branches move. Fetch credentials stay in the
trusted collector; Cargo receives only credential-free local Git URL mappings.
"""
from __future__ import annotations

from collections import defaultdict
import json
import re
import subprocess
import tomllib


SOURCE = re.compile(r'git\+https://github.com/(GetBusbar/[^/?#]+?)(?:\.git)?\?rev=([0-9a-f]{40})#([0-9a-f]{40})')


def inputs(host, candidate, policy):
    allowed = {'GetBusbar/busbar'} | {name for name, row in policy['repositories'].items() if not row['private']}
    sources = defaultdict(set)
    for root, relative in ((host, 'Cargo.lock'), (host, 'dist/default/Cargo.lock'), (candidate, 'Cargo.lock')):
        lock = root / relative
        if not lock.is_file():
            continue
        for package in tomllib.loads(lock.read_text()).get('package', []):
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
    settings = []
    for repository, revisions in sorted(sources.items()):
        if any(not re.fullmatch('[0-9a-f]{40}', revision) for revision in revisions):
            raise ValueError('immutable source revision required')
        cache = parent / repository.rsplit('/', 1)[1]
        subprocess.run(['git', 'init', '--bare', '--quiet', str(cache)], check=True)
        for revision in sorted(revisions):
            subprocess.run(['git', '-C', str(cache), 'fetch', '--quiet', '--depth', '1',
                server + '/' + repository + '.git', revision + ':refs/heads/input-' + revision], env=env, check=True)
            if git(cache, 'rev-parse', 'refs/heads/input-' + revision) != revision:
                raise ValueError('canonical input revision mismatch')
        for suffix in ('', '.git'):
            settings.append(('url.' + cache.as_uri() + '.insteadOf', 'https://github.com/' + repository + suffix))
    q.env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_COUNT=str(len(settings)))
    for index, (key, value) in enumerate(settings):
        q.env['GIT_CONFIG_KEY_' + str(index)] = key
        q.env['GIT_CONFIG_VALUE_' + str(index)] = value
    q.receipt['canonical_inputs'] = {name: sorted(revisions) for name, revisions in sorted(sources.items())}
    q.save()

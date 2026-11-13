"""Read immutable public inputs from the canonical forge before admission.

Public mirrors contain admitted stage branches only. A coherent SDK cutover must
qualify candidate commits before those branches move. Fetch credentials stay in the
trusted collector; Cargo receives only credential-free local Git URL mappings.
"""
from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import re
from pathlib import Path
import subprocess
import tomllib
from urllib.parse import urlsplit


SOURCE = re.compile(r'git\+https://github.com/(GetBusbar/[^/?#]+?)(?:\.git)?\?rev=([0-9a-f]{40})#([0-9a-f]{40})')
# Each forge fetch is latency-bound (several HTTP round trips, tiny packs).
# Bounded concurrency keeps one job from monopolizing the forge.
FETCH_WORKERS = 8
FETCH_TIMEOUT = 300
CORE = 'GetBusbar/busbar'
PUBLIC = 'https://github.com/'
# Reviewed: the public read-only replica is never a build source. Each public fork
# pinned by core's [patch.crates-io] has an exact private-forge copy; the public
# URL in Cargo.toml/Cargo.lock is only a name, the locked commit pins the bytes.
# No wildcard: any other github.com Git source refuses.
UPSTREAM_FORKS = {
    PUBLIC + 'MattJackson/aws-lc-sys': 'GetBusbar/upstream-forks/aws-lc-sys',
    PUBLIC + 'MattJackson/jobserver-rs': 'GetBusbar/upstream-forks/jobserver-rs',
    PUBLIC + 'MattJackson/rust-stringprep': 'GetBusbar/upstream-forks/rust-stringprep',
    PUBLIC + 'MattJackson/dunce': 'GetBusbar/upstream-forks/dunce',
    PUBLIC + 'MattJackson/fs_extra': 'GetBusbar/upstream-forks/fs_extra',
    PUBLIC + 'MattJackson/h2': 'GetBusbar/upstream-forks/h2',
    PUBLIC + 'MattJackson/tungstenite-rs': 'GetBusbar/upstream-forks/tungstenite-rs',
}
FORK_URLS = {repository: url for url, repository in UPSTREAM_FORKS.items()}
FORK_CACHE = 'upstream-forks--'
FORK_SOURCE = re.compile(r'git\+(https://github\.com/[^/?#]+/[^/?#]+?)(?:\.git)?\?rev=([0-9a-f]{40})#([0-9a-f]{40})')
# Every other public URL is rewritten to an unroutable host so a stray fetch fails
# loudly. Git applies the longest matching insteadOf, so exact mappings still win.
REFUSED = 'https://public-replica-refused.invalid/'
REFUSAL = ('url.' + REFUSED + '.insteadOf', PUBLIC)


def cache_name(repository):
    """canonical-inputs directory; fork caches cannot collide with first-party names."""
    if repository in FORK_URLS:
        return FORK_CACHE + repository.rsplit('/', 1)[1]
    owner, _, name = repository.partition('/')
    if owner != 'GetBusbar' or not re.fullmatch('[A-Za-z0-9_.-]+', name) or name.startswith(FORK_CACHE):
        raise ValueError('not a canonical input repository: ' + repository)
    return name


def forge_repository(url):
    """Private-forge repository for a public Git URL, or None if unreviewed."""
    url = url.removesuffix('.git')
    if url in UPSTREAM_FORKS:
        return UPSTREAM_FORKS[url]
    name = url.removeprefix(PUBLIC + 'GetBusbar/')
    if name != url and re.fullmatch('[A-Za-z0-9_.-]+', name) and not name.startswith(FORK_CACHE):
        return 'GetBusbar/' + name
    return None


def public_urls(repository):
    base = FORK_URLS.get(repository, PUBLIC + repository)
    return (base, base + '.git')


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
        if not source.startswith('git+'):
            continue
        host = (urlsplit(source[4:]).hostname or '').rstrip('.')
        if host != 'github.com' and not host.endswith('.github.com'):
            continue
        if not source.startswith('git+https://github.com/GetBusbar/'):
            if re.split('[?#]', source[4:], maxsplit=1)[0].removesuffix('.git') not in UPSTREAM_FORKS:
                raise ValueError('unreviewed public replica Git source; build sources come only from '
                                 'the private forge: ' + source)
            match = FORK_SOURCE.fullmatch(source)
            if not match or match[2] != match[3]:
                raise ValueError('upstream fork source must be an exact immutable Git commit')
            sources[UPSTREAM_FORKS[match[1]]].add(match[2])
            continue
        match = SOURCE.fullmatch(source)
        if not match or match[2] != match[3]:
            raise ValueError('first-party source must be an exact immutable Git commit')
        repository, revision = match[1], match[2]
        if repository in allowed:
            sources[repository].add(revision)
        # Private or unclassified first-party repositories never enter a public
        # map; the job seed then refuses them rather than fetching publicly.
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


def subject_locks(candidate, host, sdk):
    """Exact subject closures that every confined job's dependency seed covers.

    The dependency seed (native_seed.lock_inputs) reads exactly these locks and
    resolves their first-party Git sources from canonical-inputs, so a plugin
    job consumes no other canonical revision.
    """
    return (('candidate', candidate, 'Cargo.lock'), ('host', host, 'Cargo.lock'),
            ('distribution', host, 'dist/default/Cargo.lock'), ('sdk', sdk, 'Cargo.lock'))


def plugin_job(q):
    return (q.repository not in (CORE, 'GetBusbar/busbar-release')
            and q.repository in q.policy.data['repositories'])


def required_sources(q, host, vector):
    """First-party revisions this job's consumers read from canonical-inputs.

    Plugin jobs build only their own workspace against the seeded subject
    closures; they never build the SDK's distribution or standalone products,
    so only the subject locks contribute. Core jobs read the same subject
    closures (dependency seed, Cargo's Git mappings, the OIDF suite's shipped
    OIDC pin in the distribution lock) plus every vector product commit
    (product-inputs and the standalone product seeds). Neither ever reads the
    SDK checkout's own distribution lock or core's HEAD from canonical-inputs:
    a lock cannot name its own commit, and core's host is its checkout. The
    release job keeps the full historical set.
    """
    if plugin_job(q) or q.repository == CORE:
        sources = defaultdict(set)
        for _, root, relative in subject_locks(q.root, host, q.sdk()):
            lock = root / relative
            if lock.is_file():
                for repository, revisions in lock_inputs(lock.read_text(), q.policy.data).items():
                    sources[repository].update(revisions)
        sources[CORE].add(vector['sdk'])
        if q.repository == CORE:
            for product in vector['products']:
                sources['GetBusbar/' + product['repo']].add(product['commit'])
        return sources
    from native import git
    sources = inputs(host, q.root, q.policy.data)
    for repository, revisions in inputs(q.sdk(), q.root, q.policy.data).items():
        sources[repository].update(revisions)
    sources[CORE].update((vector['sdk'], git(host, 'rev-parse', 'HEAD')))
    for product in vector['products']:
        sources['GetBusbar/' + product['repo']].add(product['commit'])
    return sources


def local_core_stores(q, host):
    """Controller-fetched core checkouts already verified at an exact revision.

    Only trusted stores under the controller work root qualify: the plugin host
    and SDK checkouts. A core job's host is its runner checkout, never reused.
    """
    from native import git
    stores = {}
    work = q.work.resolve()
    for root in (host, q.sdk()):
        root = Path(root).resolve()
        if root.parent == work and root.name in ('host', 'sdk'):
            stores.setdefault(git(root, 'rev-parse', 'HEAD'), root)
    return stores


def prepare(q, host):
    from native import fetch_environment, git
    vector = json.loads((host / 'scripts/ci-product-pins.json').read_text())
    sources = required_sources(q, host, vector)
    # All listed products are public; private candidates never enter a public map.
    allowed = {CORE} | {name for name, row in q.policy.data['repositories'].items() if not row['private']}
    listed = {'GetBusbar/' + product['repo'] for product in vector['products']}
    if (set(sources) - set(FORK_URLS) | listed) - allowed:
        raise ValueError('unclassified or private repository in public product inputs')
    parent = q.work / 'canonical-inputs'
    parent.mkdir()
    env = fetch_environment()
    server = env['CI_SERVER_URL'].rstrip('/')
    local = local_core_stores(q, host)
    fetched = defaultdict(set)
    def fetch_one(repository, revisions):
        cache = parent / cache_name(repository)
        if not cache.exists():
            subprocess.run(['git', 'init', '--bare', '--quiet', str(cache)], check=True)
        # Group by source: one shallow fetch carries every exact revision.
        remotes = defaultdict(list)
        for revision in revisions:
            store = local.get(revision) if repository == CORE else None
            remotes[str(store) if store else server + '/' + repository + '.git'].append(revision)
        for remote, wanted in sorted(remotes.items()):
            subprocess.run(['git', '-C', str(cache), 'fetch', '--quiet', '--no-tags', '--depth', '1', remote,
                *[revision + ':refs/heads/input-' + revision for revision in wanted]],
                env=env, check=True, timeout=FETCH_TIMEOUT)
        for revision in revisions:
            if git(cache, 'rev-parse', 'refs/heads/input-' + revision) != revision:
                raise ValueError('canonical input revision mismatch')
        return repository, revisions
    def fetch(selected):
        pending = {}
        for repository, revisions in sorted(selected.items()):
            if any(not re.fullmatch('[0-9a-f]{40}', revision) for revision in revisions):
                raise ValueError('immutable source revision required')
            missing = sorted(set(revisions) - fetched[repository])
            if missing:
                pending[repository] = missing
        if not pending:
            return
        with ThreadPoolExecutor(max_workers=min(FETCH_WORKERS, len(pending))) as pool:
            for repository, revisions in pool.map(lambda item: fetch_one(*item), sorted(pending.items())):
                fetched[repository].update(revisions)
    fetch(sources)
    standalone = standalone_products(q.repository, q.evaluation_only, vector)
    products = product_inputs(parent, {'products': standalone}, q.policy.data)
    for repository, revisions in products.items():
        sources[repository].update(revisions)
    fetch(products)
    settings = []
    for repository in sorted(sources):
        cache = parent / cache_name(repository)
        for url in public_urls(repository):
            settings.append(('url.' + cache.as_uri() + '.insteadOf', url))
    settings.append(REFUSAL)
    q.env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_COUNT=str(len(settings)))
    for index, (key, value) in enumerate(settings):
        q.env['GIT_CONFIG_KEY_' + str(index)] = key
        q.env['GIT_CONFIG_VALUE_' + str(index)] = value
    q.receipt['canonical_inputs'] = {name: sorted(revisions) for name, revisions in sorted(sources.items())
                                     if name not in FORK_URLS}
    q.receipt['upstream_forks'] = {name: sorted(revisions) for name, revisions in sorted(sources.items())
                                   if name in FORK_URLS}
    q.save()

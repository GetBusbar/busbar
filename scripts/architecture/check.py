#!/usr/bin/env python3
"""Check the shipping Cargo graph against an admission-owned kind boundary policy.

The caller supplies the repository identity and policy from the trusted CI checkout.
Candidate metadata never grants a role. A separate probe resolves production roots
without unifying their dev features; declared inactive edges are checked as well.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import tomllib
from urllib.parse import urlsplit
import uuid


EXECUTION = None
# Controller-owned read-only dependency units (native_dep_cache), or None.
DEPENDENCY_UNITS = None


def candidate_run(argv, *, discard_harness_target=False, **kwargs):
    if EXECUTION is None:
        return subprocess.run(argv, **kwargs)
    kwargs.setdefault('cwd', EXECUTION.roots['checkout'])
    if discard_harness_target:
        kwargs['discard_harness_target'] = True
    return EXECUTION.run(argv, **kwargs)


def candidate_output(argv, **kwargs):
    if EXECUTION is None:
        return subprocess.check_output(argv, **kwargs)
    kwargs.setdefault('cwd', EXECUTION.roots['checkout'])
    return EXECUTION.check_output(argv, **kwargs)


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


def check_graph(metadata, policy, repository, checkout, development_paths=None):
    if not metadata.get('resolve'):
        raise Violation('resolved cargo metadata is required; --no-deps is not evidence')
    packages = {p['id']: p for p in metadata['packages']}
    nodes = {n['id']: n for n in metadata['resolve']['nodes']}
    roles = {key: policy.classify(p, repository, checkout, development_paths) for key, p in packages.items()}
    forbidden = set(policy.data['forbidden_shipping_features'])
    for key, entry in roles.items():
        if entry is None:
            continue
        package = packages[key]
        if entry['role'] == 'test_host':
            raise Violation(f'test host entered shipping graph: {package["name"]}')
        enabled = forbidden.intersection(nodes.get(key, {}).get('features', []))
        if enabled:
            raise Violation(f'shipping feature on {package["name"]}: {sorted(enabled)}')
        # Traverse through external libraries, but compare each first-party hop to
        # the graph for the first-party package that actually owns that hop.
        pending = [e['pkg'] for e in nodes[key]['deps'] if any(d.get('kind') != 'dev' for d in e['dep_kinds'])]
        seen = set()
        while pending:
            target = pending.pop()
            if target in seen:
                continue
            seen.add(target)
            target_entry = roles[target]
            if target_entry is not None:
                if packages[target]['name'] not in entry['allows']:
                    raise Violation(f'forbidden production/build edge: {package["name"]} -> {packages[target]["name"]}')
                continue
            pending.extend(e['pkg'] for e in nodes[target]['deps'] if any(d.get('kind') != 'dev' for d in e['dep_kinds']))
    core_sources = {p.get('source') for p in packages.values() if p['name'] in policy.data['core'] and p.get('source')}
    if len(core_sources) > 1:
        raise Violation(f'SDK source/revision mismatch: {sorted(core_sources)}')
    return {'packages': len(packages), 'classified': sum(e is not None for e in roles.values())}


def dependency_tables(manifest):
    for section, kind in [('dependencies', 'normal'), ('build-dependencies', 'build'), ('dev-dependencies', 'dev')]:
        yield kind, manifest.get(section, {})
    for target in manifest.get('target', {}).values():
        for section, kind in [('dependencies', 'normal'), ('build-dependencies', 'build'), ('dev-dependencies', 'dev')]:
            yield kind, target.get(section, {})


def dependency(alias, value, workspace):
    value = {'version': value} if isinstance(value, str) else dict(value)
    if value.pop('workspace', False):
        inherited = workspace.get('dependencies', {}).get(alias)
        if inherited is None:
            raise Violation(f'unresolved workspace dependency {alias}')
        inherited = {'version': inherited} if isinstance(inherited, str) else dict(inherited)
        features = inherited.get('features', []) + value.get('features', [])
        value = dict(inherited, **value)
        value['features'] = features
    return value.get('package', alias), value


def check_substitutions(manifest, directory, policy, repository, checkout):
    for replacement in ('patch', 'replace'):
        groups = manifest.get(replacement, {})
        tables = groups.values() if replacement == 'patch' else [groups]
        for table in tables:
            for alias, cfg in table.items():
                actual = cfg.get('package', alias) if isinstance(cfg, dict) else alias
                actual = actual.split(':')[0]
                if actual in policy.packages or actual.startswith('busbar-'):
                    entry = policy.packages.get(actual, {})
                    # Core's own assembly uses its checked-out core, never a second SDK.
                    local_core = repository == 'GetBusbar/busbar' and actual in policy.data['core']
                    path = cfg.get('path') if isinstance(cfg, dict) else None
                    if not (local_core and path and
                            (directory / path / 'Cargo.toml').resolve() ==
                            (checkout / entry['manifest']).resolve() and set(cfg) <= {'path', 'package'}):
                        raise Violation(f'first-party {replacement} substitution: {actual}')


def check_declared(policy, repository, checkout):
    """Inspect all declarations, including cfg-disabled optional/build dependencies."""
    root = read(checkout / 'Cargo.toml')
    check_substitutions(root, checkout, policy, repository, checkout)
    # Cargo configuration can otherwise silently replace the checked manifest graph.
    for config in (checkout / '.cargo/config', checkout / '.cargo/config.toml'):
        if config.is_file():
            data = read(config)
            if any(key in data for key in ('patch', 'paths', 'source')):
                raise Violation(f'candidate Cargo source substitution in {config}')
    entries = [(name, e) for name, e in policy.packages.items() if e['repository'] == repository]
    refs = set()
    expected_paths = set()
    for name, entry in entries:
        path = checkout / entry['manifest']
        expected_paths.add(path.resolve())
        if entry.get('generated_by'):
            if not (checkout / entry['generated_by']).is_file():
                raise Violation(f'missing conformance generator: {entry["generated_by"]}')
            continue  # Generated host is verified separately by its native conformance job.
        if not path.is_file():
            raise Violation(f'missing classified manifest: {entry["manifest"]}')
        manifest = read(path)
        if manifest.get('package', {}).get('name') != name:
            raise Violation(f'package identity changed at {path}')
        workspace, workspace_dir = root.get('workspace', {}), checkout
        if 'workspace' in manifest:
            workspace, workspace_dir = manifest['workspace'], path.parent
        for kind, table in dependency_tables(manifest):
            for alias, value in table.items():
                actual, cfg = dependency(alias, value, workspace)
                known = policy.packages.get(actual)
                git = git_repository('git+' + cfg['git']) if cfg.get('git') else None
                external = git and any(e['name'] == actual and git == ('github.com', e['repository']) for e in policy.data.get('external_sources', []))
                if known is None and not external and (actual.startswith('busbar-') or (git and git[1].split('/')[0] in ('GetBusbar', 'BusbarInc'))):
                    raise Violation(f'unclassified declared first-party package: {actual}')
                if known:
                    allowed = entry.get('dev_allows', entry['allows']) if kind == 'dev' else entry['allows']
                    if actual not in allowed:
                        raise Violation(f'forbidden declared {kind} edge: {name} -> {actual}')
                    if kind != 'dev' and set(cfg.get('features', [])).intersection(policy.data['forbidden_shipping_features']):
                        raise Violation(f'forbidden shipping feature declaration: {name} -> {actual}')
                    if cfg.get('git'):
                        if git[1] != known['repository'] or git[0] not in ('github.com', os.environ.get('CI_SERVER_HOST')):
                            raise Violation(f'declared source mismatch: {name} -> {actual}')
                        rev = cfg.get('rev', '')
                        if not re.fullmatch(r'[0-9a-f]{40}', rev) or 'branch' in cfg or 'tag' in cfg:
                            raise Violation(f'first-party dependency must have an immutable full revision: {actual}')
                        if actual in policy.data['core']:
                            refs.add(rev)
                    elif 'path' in cfg:
                        base = workspace_dir if isinstance(value, dict) and value.get('workspace') else path.parent
                        resolved = (base / cfg['path'] / 'Cargo.toml').resolve()
                        if known['repository'] != repository or resolved != (checkout / known['manifest']).resolve():
                            raise Violation(f'cross-repository path dependency: {name} -> {actual}')
                    else:
                        raise Violation(f'first-party package cannot come from a registry: {actual}')
        if entry['role'] in ('implementation', 'wrapper') and set(manifest.get('features', {})).intersection(policy.data['forbidden_shipping_features']):
            raise Violation(f'plugin exposes a test authority feature: {name}')
        check_substitutions(manifest, path.parent, policy, repository, checkout)
    # A new workspace member cannot disappear merely because it was omitted from policy.
    for member in root.get('workspace', {}).get('members', []):
        for path in checkout.glob(member + '/Cargo.toml'):
            if path.resolve() not in expected_paths:
                raise Violation(f'unclassified workspace member: {path.relative_to(checkout)}')
    if repository != 'GetBusbar/busbar':
        pin_fields = (checkout / '.busbar-ref').read_text().split()
        if len(pin_fields) != 2 or pin_fields[1] != '1.6.0':
            raise Violation('expected SDK revision and product 1.6.0 in .busbar-ref')
        pin = pin_fields[0]
        if refs != {pin} or not re.fullmatch(r'[0-9a-f]{40}', pin):
            raise Violation(f'SDK manifest/.busbar-ref mismatch: {sorted(refs)} vs {pin}')
        lock = read(checkout / 'Cargo.lock')
        for p in lock['package']:
            if p['name'] in policy.data['core']:
                source = p.get('source', '')
                if not source.endswith('#' + pin) or git_repository(source) not in [('github.com', 'GetBusbar/busbar'), (os.environ.get('CI_SERVER_HOST'), 'GetBusbar/busbar')]:
                    raise Violation(f'SDK lock source mismatch: {p["name"]}: {source}')
    return entries


def inline(value):
    if isinstance(value, dict):
        return '{ ' + ', '.join(f'{json.dumps(k)} = {inline(v)}' for k, v in value.items()) + ' }'
    return json.dumps(value)


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


def check_vector(policy, checkout, entries):
    """Bind every declared/locked first-party source to the assembled product vector."""
    vector = json.loads((checkout / 'scripts/ci-product-pins.json').read_text())
    revisions = vector_revisions(policy, vector)
    workspace = read(checkout / 'Cargo.toml').get('workspace', {})
    manifests = {checkout / e['manifest'] for _, e in entries}
    manifests.add(checkout / 'Cargo.toml')
    for path in manifests:
        manifest = read(path)
        own_workspace = manifest.get('workspace', workspace)
        tables = [*dependency_tables(manifest), ('workspace', own_workspace.get('dependencies', {}))]
        for _, table in tables:
            for alias, cfg in table.items():
                name, value = dependency(alias, cfg, own_workspace)
                known = policy.packages.get(name)
                if known and value.get('git') and value['rev'] != revisions.get(known['repository']):
                    raise Violation(f'assembly manifest/vector mismatch: {path}: {name}')
    for path in (checkout / 'Cargo.lock', checkout / 'dist/default/Cargo.lock'):
        for package in read(path)['package']:
            known = policy.packages.get(package['name'])
            if known and package.get('source'):
                if not package['source'].endswith('#' + revisions.get(known['repository'], 'unclassified')):
                    raise Violation(f'assembly lock/vector mismatch: {path}: {package["name"]}')
    shared = check_shared_core_resolution(read(checkout / 'Cargo.lock'), read(checkout / 'dist/default/Cargo.lock'))
    return {'sdk_revision': vector['sdk'], 'products': len(vector['products']), 'shared_core_packages': shared,
            'vector_sha256': hashlib.sha256((checkout / 'scripts/ci-product-pins.json').read_bytes()).hexdigest()}


def check_shared_core_resolution(root_lock, distribution_lock):
    """Every core path crate dist/default links resolves exactly as in the root lock.

    The distribution lock records a non-member path crate's normal and build
    dependencies; the root lock records them too (plus dev-dependencies). If each
    one's whole closure in dist/default is a subset of its root closure, the two
    workspaces compile the same core crate from the same dependency versions and
    sources, so one shared target can reuse identical units. Returns the count.
    """
    def graph(lock):
        packages = lock.get('package', [])
        by_name = {}
        for package in packages:
            by_name.setdefault(package['name'], []).append(package)

        def resolve(entry):
            name, *rest = entry.split(' ')
            rows = by_name.get(name, [])
            if rest:
                rows = [row for row in rows if row['version'] == rest[0]]
            if len(rest) > 1:
                rows = [row for row in rows if '(' + row.get('source', '') + ')' == rest[1]]
            if len(rows) != 1:
                raise Violation('unresolvable lock dependency: ' + entry)
            return rows[0]

        def closure(package):
            seen, stack = {}, [package]
            while stack:
                row = stack.pop()
                identity = (row['name'], row['version'], row.get('source'))
                if identity not in seen:
                    seen[identity] = row
                    stack.extend(resolve(entry) for entry in row.get('dependencies', []))
            return set(seen)
        return {p['name']: p for p in packages if p.get('source') is None}, closure

    root_paths, root_closure = graph(root_lock)
    distribution_paths, distribution_closure = graph(distribution_lock)
    shared = sorted(set(root_paths) & set(distribution_paths))
    for name in shared:
        extra = distribution_closure(distribution_paths[name]) - root_closure(root_paths[name])
        if extra:
            sample = ', '.join(f'{n} {v}' for n, v, _ in sorted(extra)[:5])
            raise Violation(f'dist/default resolves core crate {name} differently from the root lock: {sample}')
    return len(shared)


def binary_resolution_root(checkout, entry, probe):
    """Cargo ignores binary-only dependencies. Resolve their actual normal/build edges
    in a manifest with an empty library; no fixture/dev feature can contaminate it."""
    original = checkout / entry['manifest']
    manifest = read(original)
    root_dir = original.parent if 'workspace' in manifest else checkout
    workspace = read(root_dir / 'Cargo.toml').get('workspace', {})
    binary = probe.parent / (probe.name + '-' + manifest['package']['name'])
    (binary / 'src').mkdir(parents=True, exist_ok=True)
    (binary / 'src/lib.rs').write_text('// Dependency resolution only; native CI builds the actual binary.\n')
    lines = ['[workspace]', '[package]', f'name={inline(manifest["package"]["name"])}', f'version={inline(manifest["package"]["version"])}', 'edition="2021"']
    groups = [('', manifest)] + [(f'target.{inline(target)}.', table) for target, table in manifest.get('target', {}).items()]
    for prefix, tables in groups:
        for section in ('dependencies', 'build-dependencies'):
            lines.append(f'[{prefix}{section}]')
            for alias, value in tables.get(section, {}).items():
                _, cfg = dependency(alias, value, workspace)
                if 'path' in cfg:
                    base = root_dir if isinstance(value, dict) and value.get('workspace') else original.parent
                    cfg['path'] = str((base / cfg['path']).resolve())
                lines.append(f'{inline(alias)}={inline(cfg)}')
    lines.append('[features]')
    for name, values in manifest.get('features', {}).items():
        if name not in ('test-support', 'test-seal'):
            lines.append(f'{inline(name)}={inline(values)}')
    (binary / 'Cargo.toml').write_text('\n'.join(lines) + '\n')
    return binary


def resolve_shipping(checkout, entries, scratch, cargo_config=None, assembly=False):
    """A disposable consumer has no dependency dev edges or workspace feature unification."""
    probe = scratch / ('assembly-probe' if assembly else 'shipping-probe')
    probe.mkdir(parents=True, exist_ok=True)
    (probe / 'src').mkdir(exist_ok=True)
    (probe / 'src/lib.rs').write_text('// Admission-only resolution root.\n')
    lines = ['[workspace]', '[package]', 'name = "architecture-shipping-probe"', 'version = "0.0.0"', 'edition = "2021"', '[dependencies]']
    binary_roots = {}
    for index, (name, entry) in enumerate(entries):
        if entry['role'] == 'test_host' or (entry['role'] == 'assembly') != assembly:
            continue  # the assembly owns a separate workspace and is resolved separately
        manifest = read(checkout / entry['manifest'])
        features = sorted(set(manifest.get('features', {})) - {'default', 'test-support', 'test-seal'})
        directory = (checkout / entry['manifest']).parent
        if 'lib' not in manifest and not (directory / 'src/lib.rs').is_file():
            directory = binary_resolution_root(checkout, entry, probe)
            binary_roots[name] = str((checkout / entry['manifest']).resolve())
        lines.append(f'root_{index} = {{ package = {json.dumps(name)}, path = {json.dumps(str(directory))}, features = {json.dumps(features)} }}')
    root_dir = checkout / 'dist/default' if assembly else checkout
    root = read(root_dir / 'Cargo.toml')
    for source, table in root.get('patch', {}).items():
        lines.append(f'[patch.{json.dumps(source)}]')
        for name, cfg in table.items():
            cfg = dict(cfg)
            if 'path' in cfg:
                cfg['path'] = str((root_dir / cfg['path']).resolve())
            values = ', '.join(f'{k} = {json.dumps(v)}' for k, v in cfg.items())
            lines.append(f'{json.dumps(name)} = {{ {values} }}')
    (probe / 'Cargo.toml').write_text('\n'.join(lines) + '\n')
    committed_lock = root_dir / 'Cargo.lock'
    if committed_lock.is_file():
        (probe / 'Cargo.lock').write_bytes(committed_lock.read_bytes())
    cmd = ['cargo', 'metadata', '--format-version', '1', '--manifest-path', str(probe / 'Cargo.toml')]
    if cargo_config:
        cmd += ['--config', str(cargo_config)]
    metadata = json.loads(candidate_output(cmd, cwd=scratch, text=True))
    for package in metadata['packages']:
        if package['name'] in binary_roots:
            package['manifest_path'] = binary_roots[package['name']]
    if committed_lock.is_file():
        locked = {(p['name'], p['version'], p.get('source')) for p in read(committed_lock)['package']}
        for package in metadata['packages']:
            if package.get('source') and (package['name'], package['version'], package['source']) not in locked:
                raise Violation(f'shipping resolver drifted from committed lock: {package["name"]} {package["version"]}')
    return metadata


def core_source_inventory(policy, checkout):
    """Every Rust source in each trusted core member, including SDK, tests and build scripts.

    A short hand-maintained list of policy files cannot establish core neutrality.
    The candidate cannot remove a member from this inventory by editing its own policy.
    """
    checkout = checkout.resolve()
    paths = set()
    for entry in policy.data['core'].values():
        root = (checkout / entry['manifest']).parent.resolve()
        if not root.is_relative_to(checkout) or not root.is_dir():
            raise Violation(f'invalid core source root: {root}')
        member = set()
        for path in root.rglob('*.rs'):
            resolved = path.resolve()
            if not resolved.is_relative_to(checkout):
                raise Violation(f'core source escapes candidate checkout: {path}')
            member.add(str(resolved))
        if not member:
            raise Violation(f'core member has no Rust sources: {root}')
        paths.update(member)
    return sorted(paths)


def core_target_roots(policy, checkout, metadata):
    """Use the actual workspace targets, never binary-only resolution stubs."""
    checkout = checkout.resolve()
    roots = set()
    found = set()
    for package in metadata['packages']:
        name = package['name']
        if name not in policy.data['core']:
            continue
        expected = (checkout / policy.data['core'][name]['manifest']).resolve()
        if Path(package['manifest_path']).resolve() != expected:
            raise Violation(f'core target metadata does not name its actual manifest: {name}')
        found.add(name)
        for target in package['targets']:
            path = Path(target['src_path']).resolve()
            if not path.is_relative_to(checkout) or not path.is_file():
                raise Violation(f'core target source escapes or is missing: {path}')
            roots.add(str(path))
    if found != set(policy.data['core']):
        raise Violation(f'missing actual core target metadata: {sorted(set(policy.data["core"]) - found)}')
    return sorted(roots)


def check_sources(policy, repository, checkout, metadata, trusted, scratch):
    """Run trusted syn checks as a small test harness, independent of candidate tests."""
    roots = []
    for package in metadata['packages']:
        entry = policy.packages.get(package['name'])
        if entry and entry['repository'] == repository and entry['role'] in ('implementation', 'wrapper'):
            roots.extend(t['src_path'] for t in package['targets'] if any(k in ('lib', 'rlib', 'cdylib') for k in t['kind']))
    if repository != 'GetBusbar/busbar' and not roots:
        raise Violation('no classified plugin source roots')
    harness = scratch / 'source-check'
    (harness / 'tests').mkdir(parents=True, exist_ok=True)
    (harness / 'tests/architecture_surface.rs').write_bytes(
        (trusted / 'crates/busbar-contract/tests/architecture_surface.rs').read_bytes())
    deps = read(trusted / 'Cargo.toml')['workspace']['dependencies']
    lines = ['[workspace]', '[package]', 'name="architecture-source-check"', 'version="0.0.0"', 'edition="2021"', '[dev-dependencies]']
    for name in ('syn', 'quote', 'proc-macro2', 'serde_json'):
        cfg = deps[name]
        cfg = {'version': cfg} if isinstance(cfg, str) else dict(cfg)
        if name == 'syn':
            cfg['features'] = sorted(set(cfg.get('features', []) + ['full', 'visit']))
        lines.append(f'{name} = {{ ' + ', '.join(f'{k} = {json.dumps(v)}' for k, v in cfg.items()) + ' }')
    (harness / 'Cargo.toml').write_text('\n'.join(lines) + '\n')
    env = dict(os.environ)
    env.pop('BUSBAR_ARCHITECTURE_SOURCES', None)
    env.pop('BUSBAR_ARCHITECTURE_POLICY_SOURCES', None)
    env.pop('BUSBAR_ARCHITECTURE_GENERATED', None)
    env.pop('BUSBAR_ARCHITECTURE_GENERATED_DIRS', None)
    if roots:
        inventory = scratch / 'source-roots.json'
        inventory.write_text(json.dumps(sorted(set(roots))))
        env['BUSBAR_ARCHITECTURE_SOURCES'] = str(inventory)
    mapping = {}
    source_metadata = metadata
    if repository == 'GetBusbar/busbar':
        # Shipping resolution substitutes empty libraries for binary-only crates. Those
        # stubs cannot identify real custom binary roots or produce their generated Rust.
        source_metadata = json.loads(candidate_output(
            ['cargo', 'metadata', '--no-deps', '--format-version', '1',
             '--manifest-path', str(checkout / 'Cargo.toml')], cwd=checkout, text=True))
        crate_roots = core_target_roots(policy, checkout, source_metadata)
    if roots or repository == 'GetBusbar/busbar':
        # Resolve generated OUT_DIR includes from this exact candidate invocation.
        # Checking the real core workspace executes its build scripts and checks
        # its actual targets; this source scan needs no linked core binaries.
        # Never use a candidate-supplied map or filename search for stale output.
        build_command = (['cargo', 'check', '--workspace', '--manifest-path', str(checkout / 'Cargo.toml')]
            if repository == 'GetBusbar/busbar' else
            ['cargo', 'build', '--manifest-path', str(scratch / 'shipping-probe/Cargo.toml')])
        # The global one-job limit protects optimized builds. This workspace
        # check, like the witnesses, can use the existing bounded check budget.
        jobs = compiler_check_jobs() if build_command[1] == 'check' else None
        if jobs is not None:
            build_command += ['--jobs', str(jobs)]
        if DEPENDENCY_UNITS is not None and EXECUTION is not None and repository != 'GetBusbar/busbar':
            # A private writable copy of trusted dependency units; the seed itself
            # is never mounted. Every candidate unit still compiles here.
            # Any failure leaves the probe on its own fresh target, as before.
            import native_dep_cache
            probe_target = EXECUTION.roots['candidate'] / ('probe-target-' + uuid.uuid4().hex)
            try:
                native_dep_cache.install(native_dep_cache.readonly_seed(DEPENDENCY_UNITS, EXECUTION), probe_target)
            except (native_dep_cache.Unavailable, OSError) as error:
                architecture_progress('dependency-units', 'fallback', reason=str(error)[:500])
                shutil.rmtree(probe_target, ignore_errors=True)
            else:
                build_command += ['--target-dir', str(probe_target)]
        architecture_progress('source-materialization', 'start', cargo_command=build_command[1],
                              build_jobs=jobs)
        started = time.monotonic()
        build = candidate_output(build_command + ['--message-format=json'], cwd=checkout, text=True)
        architecture_progress('source-materialization', 'finish', cargo_command=build_command[1],
                              elapsed_seconds=round(time.monotonic() - started, 3), build_jobs=jobs)
        for line in build.splitlines():
            row = json.loads(line)
            if row.get('reason') == 'build-script-executed':
                for package in source_metadata['packages']:
                    if package['id'] == row['package_id'] and package['name'] in policy.packages:
                        output = Path(row['out_dir'])
                        if EXECUTION and (not output.is_absolute() or output != output.resolve()
                                or not output.is_relative_to(EXECUTION.roots['candidate'])):
                            raise Violation('candidate generated source path escapes its build output')
                        mapping[str(Path(package['manifest_path']).parent)] = str(output)
        generated = scratch / 'generated-directories.json'
        generated.write_text(json.dumps(mapping))
        env['BUSBAR_ARCHITECTURE_GENERATED_DIRS'] = str(generated)
    if repository == 'GetBusbar/busbar':
        inventory = scratch / 'policy-sources.json'
        raw_paths = core_source_inventory(policy, checkout)
        paths = set(raw_paths)
        for output in mapping.values():
            for path in Path(output).rglob('*.rs'):
                if EXECUTION and (path.is_symlink() or not path.resolve().is_relative_to(EXECUTION.roots['candidate'])):
                    raise Violation('indirect generated source file')
                paths.add(str(path.resolve()))
        # Handwritten core must not know concrete owners. Generated assembly may
        # link those owners, but remains subject to the short-name selector check.
        plugin_packages = sorted(name for name, entry in policy.packages.items()
            if entry['role'] in ('implementation', 'wrapper'))
        inventory.write_text(json.dumps({'paths': sorted(paths), 'raw_paths': raw_paths,
            'roots': crate_roots, 'plugin_packages': plugin_packages,
            'names': sorted({r.split('/', 1)[1].split('-', 2)[2] for r in policy.data['repositories']})}))
        env['BUSBAR_ARCHITECTURE_POLICY_SOURCES'] = str(inventory)
    candidate_run(['cargo', 'test', '--manifest-path', str(harness / 'Cargo.toml'), '--test', 'architecture_surface'], cwd=scratch, env=env, check=True)
    return {'source_roots': len(set(roots)), 'core_source_files': len(paths) if repository == 'GetBusbar/busbar' else 0,
            'trusted_source_check': True}


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


def check_c(policy, repository, checkout, sdk, scratch):
    fields = (checkout / '.busbar-ref').read_text().split()
    revision = subprocess.check_output(['git', '-C', str(sdk), 'rev-parse', 'HEAD'], text=True).strip()
    if fields != [revision, '1.6.0']:
        raise Violation('C plugin/header SDK pin mismatch')
    recipe = load_c_recipe(policy, repository, checkout)
    sources = [checkout / path for path in recipe['sources']]
    for source in sources:
        includes = re.findall(r'^\s*#\s*include\s+(.+)$', source.read_text(), re.MULTILINE)
        if includes != ['"busbar_plugin.h"']:
            raise Violation(f'C plugin must include only the public ABI header: {source}')
    platform = 'linux' if EXECUTION else sys.platform
    output_directory = EXECUTION.roots['candidate'] / 'architecture' if EXECUTION else scratch
    output_directory.mkdir(exist_ok=True)
    library = output_directory / ('plugin.dylib' if platform == 'darwin' else 'plugin.so')
    candidate_run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fvisibility=hidden', '-fPIC',
        '-dynamiclib' if platform == 'darwin' else '-shared', '-I', str(sdk / Path(PUBLIC_C_HEADER).parent),
        *map(str, sources), '-o', str(library)], check=True)
    output = candidate_output(['nm', '-gU' if platform == 'darwin' else '--defined-only', str(library)], text=True)
    exported = {line.split()[-1].removeprefix('_') for line in output.splitlines() if len(line.split()) >= 3 and line.split()[-2].isupper()}
    if exported != {'busbar_plugin_door'}:
        raise Violation(f'C runtime exports are not the sole ABI door: {sorted(exported)}')
    return {'source_roots': len(sources), 'c_header_revision': revision, 'c_exports': sorted(exported)}


def architecture_progress(stage, event, **details):
    # The parent retains stderr even if its bounded controller timeout interrupts
    # this process before the final receipt can be written.
    print('architecture-progress: ' + json.dumps(dict(stage=stage, event=event, **details)),
          file=sys.stderr, flush=True)


def compiler_check_jobs():
    if EXECUTION is None:
        return None  # Preserve the caller's local scheduling policy.
    resources = EXECUTION.config['resources']
    # These compiler checks completed all 52 cases under the 4 CPU / 6 GiB
    # boundary before optimized-build scheduling was reduced to one job. Keep
    # that conservative global policy for builds; only checks may use CPUs.
    # Smaller memory boundaries have no such execution evidence.
    return min(4, resources['cpus']) if resources['memory_bytes'] >= 6 * 1024**3 else 1


def compiler_witness_parallel():
    """Select only the disk-backed aggregate budget exercised by job 5374."""
    if EXECUTION is None:
        return False
    resources = EXECUTION.config['resources']
    storage = EXECUTION.config['isolation']
    # Four representative controls preserved their verdicts with two 2 CPU /
    # 3 GiB isolates: 237.007s serial -> 209.916s parallel. CPU increased 4.2%;
    # this is a latency improvement, not a reduction in compiler work. The
    # pool now splits the same aggregate into COMPILER_POOL_WIDTH isolates.
    # Keep smaller and unmeasured storage boundaries on the existing serial path.
    return (resources['cpus'] >= 4 and resources['memory_bytes'] >= 6 * 1024**3
            and resources['pids'] >= 1024 and storage['storage_kind'] == 'loop-ext4'
            and storage['storage_bytes'] >= 24 * 1024**3)


WITNESS_SEED = 'witness_seed'
SEED_LOG_TAIL_LINES = 200
EVIDENCE = None  # The --output directory; failed seed logs are retained there.


class CompilerSeedFailure(Violation):
    """The optional dependency seed failed; cases fall back to fresh targets."""
    def __init__(self, message, log=None):
        super().__init__(message)
        self.log = log
HARNESS_UNIT_PREFIXES = ('architecture-compiler-witnesses-', 'architecture_compiler_witnesses-', 'witness_')


def is_harness_unit(name):
    """Whether a build-directory entry is a harness unit, in either Cargo layout.

    Before Cargo 1.100 entries are `<package>-<hash>` under deps/, .fingerprint/ and
    build/. Cargo 1.100 uses build/<package>/<hash>/, so the entry is the bare package name."""
    return name.startswith(HARNESS_UNIT_PREFIXES) or name in {prefix.rstrip('-') for prefix in HARNESS_UNIT_PREFIXES}


def copy_candidate_tree(source, destination):
    """Snapshot disposed candidate output into a new controller-owned tree.
    Only directories and regular files are accepted. Contents are copied, so no
    link or inode is shared with anything a later candidate can write."""
    if not stat.S_ISDIR(os.lstat(source).st_mode):
        raise CompilerSeedFailure(f'compiler dependency seed output is not a directory: {source.name}')
    destination.mkdir(mode=0o755)
    for directory, names, files in os.walk(source):
        relative = Path(directory).relative_to(source)
        for name in names + files:
            path, mode = Path(directory) / name, os.lstat(Path(directory) / name).st_mode
            if stat.S_ISDIR(mode) and name in names:
                (destination / relative / name).mkdir(mode=0o755)
            elif stat.S_ISREG(mode) and name in files:
                shutil.copy2(path, destination / relative / name, follow_symlinks=False)
            else:
                raise CompilerSeedFailure(f'compiler dependency seed contains a non-regular entry: {relative / name}')


def vendor_source_config(text, directory):
    """Re-emit Cargo's vendor replacement table with the controller-owned directory."""
    try:
        sources = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise CompilerSeedFailure(f'unreadable cargo vendor configuration: {error}') from None
    if set(sources) != {'source'} or not isinstance(sources['source'], dict):
        raise CompilerSeedFailure('unexpected cargo vendor configuration')
    lines = []
    for name, table in sources['source'].items():
        if name == 'vendored-sources':
            if set(table) != {'directory'}:
                raise CompilerSeedFailure('unexpected vendored source table')
            continue
        if (table.get('replace-with') != 'vendored-sources'
                or not set(table) <= {'replace-with', 'git', 'rev', 'branch', 'tag', 'registry'}
                or not all(isinstance(value, str) for value in table.values())):
            raise CompilerSeedFailure(f'unexpected cargo vendor replacement: {name}')
        lines += [f'[source.{json.dumps(name)}]', *(f'{json.dumps(k)} = {json.dumps(v)}' for k, v in table.items())]
    if 'vendored-sources' not in sources['source']:
        raise CompilerSeedFailure('cargo vendor emitted no vendored source')
    lines += ['[source.vendored-sources]', f'directory = {json.dumps(str(directory))}']
    return '\n'.join(lines) + '\n'


def prune_unused_patches(manifest, lock):
    """Omit the [patch] git entries Cargo itself reports unused; return what was omitted.

    Cargo loads every patch source, used or not, but `cargo vendor` copies only the
    used ones, so an unused git patch sends an offline seeded case to the network.
    Only Cargo's own `[[patch.unused]]` record may remove one: a URL spelled unlike
    Cargo's normalised form is kept, which fails closed (seed failure, unseeded run).
    Path and registry patches always stay."""
    rows = (lock.get('patch') or {}).get('unused', [])
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise CompilerSeedFailure('unreadable [[patch.unused]] in the vendor lockfile')
    unused = {(row.get('name'), row.get('source', '')) for row in rows}
    lines, section, pruned = [], None, []
    for line in manifest.read_text().splitlines():
        if line.startswith('['):
            section = line[len('[patch.'):-1] if line.startswith('[patch.') else None
        elif section is not None and line.strip():
            try:
                ((name, cfg),) = tomllib.loads(line).items()
                source_key = tomllib.loads('k = ' + section)['k'] if section[:1] in '\'"' else section
            except (tomllib.TOMLDecodeError, ValueError) as error:
                raise CompilerSeedFailure(f'unreadable harness patch entry: {error}') from None
            git = cfg.get('git') if isinstance(cfg, dict) else None
            package = cfg.get('package', name) if isinstance(cfg, dict) else name
            if isinstance(git, str) and any(found == package and isinstance(source, str)
                                            and (source.startswith('git+' + git + '?')
                                                 or source.startswith('git+' + git + '#'))
                                            for found, source in unused):
                pruned.append(source_key + ':' + name)
                continue
        lines.append(line)
    manifest.write_text('\n'.join(lines) + '\n')
    return pruned

def seed_compiler_dependencies(harness, scratch, cases):
    """Build the witness harness's dependency closure once, before any case runs.

    The seed is a trusted harness example with no candidate-selected code of its
    own, compiled from the same manifest, features and toolchain as every case.
    Its outputs are snapshotted into the read-only harness mount after the seed
    container is disposed. Cases receive a private copy; none can alter it.
    Dependency sources are vendored to one stable path because each isolate's
    private CARGO_HOME path differs, and Cargo fingerprints registry source paths.
    """
    started = time.monotonic()
    architecture_progress('compiler-seed', 'start')
    root = scratch / 'compiler-witness-seed'
    if root.exists():
        raise Violation('compiler dependency seed must be fresh')
    root.mkdir()
    (harness / 'examples' / (WITNESS_SEED + '.rs')).write_text('fn main() {}\n')
    manifest = str(harness / 'Cargo.toml')
    candidate = EXECUTION.roots['candidate']

    def confined(name, command):
        result = candidate_run(command, cwd=scratch, text=True, capture_output=True,
                               discard_harness_target=True)
        # rustc diagnostics arrive as JSON on stdout; Cargo's own errors on stderr.
        rendered = []
        for line in result.stdout.splitlines():
            try:
                row = json.loads(line) if line.startswith('{') else {}
            except ValueError:
                continue
            if isinstance(row, dict) and row.get('reason') == 'compiler-message':
                rendered.append(str((row.get('message') or {}).get('rendered') or ''))
        log = root / (name + '.log')
        log.write_text(result.stderr + '\n' + '\n'.join(rendered))
        if result.returncode != 0:
            # No case has run yet; the caller falls back to the unseeded path.
            raise CompilerSeedFailure(f'compiler dependency seed failed: {name}', log)
        return result

    output = candidate / ('witness-vendor-' + uuid.uuid4().hex)
    # Directory sources need a lockfile for git (patched) dependencies, but each
    # confined invocation otherwise resolves into a private, discarded lockfile.
    # Keep the vendor resolution and give it to every later seeded invocation:
    # the controller copies a harness Cargo.lock into each private lockfile.
    lock = candidate / ('witness-lock-' + uuid.uuid4().hex) / 'Cargo.lock'
    vendored = confined('vendor', ['cargo', 'vendor', '--manifest-path', manifest, '--versioned-dirs',
                                   '--config', 'resolver.lockfile-path=' + json.dumps(str(lock)), str(output)])
    if lock.is_symlink() or not lock.is_file() or lock.parent.is_symlink():
        raise CompilerSeedFailure('cargo vendor produced no regular lockfile')
    try:
        tomllib.loads(lock.read_text())
    except tomllib.TOMLDecodeError as error:
        raise CompilerSeedFailure(f'unreadable cargo vendor lockfile: {error}') from None
    shutil.copyfile(lock, harness / 'Cargo.lock', follow_symlinks=False)
    # Keep the original manifest so an unseeded fallback sees exactly its inputs.
    shutil.copyfile(harness / 'Cargo.toml', root / 'Cargo.toml.unpruned')
    pruned = prune_unused_patches(harness / 'Cargo.toml', tomllib.loads(lock.read_text()))
    shutil.rmtree(lock.parent)
    copy_candidate_tree(output, root / 'vendor')
    shutil.rmtree(output)
    config = root / 'vendor.toml'
    config.write_text(vendor_source_config(vendored.stdout, root / 'vendor'))
    output = candidate / ('witness-seed-target-' + uuid.uuid4().hex)
    # Superset first; the contract-only resolution may unify fewer features.
    configurations = sorted({needs_loader for _, _, needs_loader in cases}, reverse=True)
    for needs_loader in configurations:
        command = ['cargo', 'check', '--manifest-path', manifest, '--example', WITNESS_SEED,
                   '--message-format=json', '--config', str(config), '--target-dir', str(output)]
        if needs_loader:
            command += ['--features', 'busbar-plugin-loader']
        jobs = compiler_check_jobs()
        if jobs is not None:
            command += ['--jobs', str(jobs)]
        confined('seed-loader' if needs_loader else 'seed-contract', command)
    target = root / 'target'
    copy_candidate_tree(output, target)
    shutil.rmtree(output)
    # Never ship a cached result for any harness unit: each case's own crate is
    # always compiled by its own rustc invocation.
    for profile in [path for path in target.iterdir() if path.is_dir()]:
        for name in ('examples', 'incremental'):
            if (profile / name).exists():
                shutil.rmtree(profile / name)
        for name in ('.fingerprint', 'deps', 'build'):
            for path in (profile / name).iterdir() if (profile / name).is_dir() else ():
                if is_harness_unit(path.name):
                    shutil.rmtree(path) if path.is_dir() else path.unlink()
    files = [path for path in target.rglob('*') if path.is_file()]
    receipt = {'configurations': len(configurations), 'pruned_patches': pruned, 'target_files': len(files),
               'target_bytes': sum(path.stat().st_size for path in files),
               'vendor_config_sha256': hashlib.sha256(config.read_bytes()).hexdigest()}
    architecture_progress('compiler-seed', 'finish', elapsed_seconds=round(time.monotonic() - started, 3), **receipt)
    return {'target': target, 'config': config, 'receipt': receipt}


def abandon_compiler_seed(harness, scratch, failure):
    """Report a failed seed and remove everything it added before any case runs."""
    record = {'status': 'failed', 'reason': str(failure), 'fallback': 'unseeded'}
    if failure.log is not None and failure.log.is_file():
        lines = failure.log.read_text(errors='replace').splitlines()[-SEED_LOG_TAIL_LINES:]
        for line in lines:
            print('compiler-seed-log: ' + line[:4000], file=sys.stderr)
        sys.stderr.flush()
        record['log_tail_lines'] = len(lines)
        record['log_sha256'] = hashlib.sha256(failure.log.read_bytes()).hexdigest()
        if EVIDENCE is not None:
            retained = Path(EVIDENCE) / ('architecture-compiler-seed-' + failure.log.name)
            shutil.copyfile(failure.log, retained)
            record['log'] = retained.name
    architecture_progress('compiler-seed', 'fallback', **record)
    # Seed containers are disposed (candidate_run returned). Unseeded cases must
    # see the original harness: no lockfile, seed example, vendor or target.
    for path in (harness / 'Cargo.lock', harness / 'examples' / (WITNESS_SEED + '.rs')):
        path.unlink(missing_ok=True)
    root = scratch / 'compiler-witness-seed'
    if (root / 'Cargo.toml.unpruned').is_file():
        shutil.copyfile(root / 'Cargo.toml.unpruned', harness / 'Cargo.toml')
    for name in ('vendor', 'target'):
        if (root / name).exists():
            shutil.rmtree(root / name)
    for pattern in ('witness-vendor-*', 'witness-lock-*', 'witness-seed-target-*'):
        for path in EXECUTION.roots['candidate'].glob(pattern):
            path.unlink() if path.is_symlink() or not path.is_dir() else shutil.rmtree(path)
    return record


def check_compiler_witnesses(policy, candidate, trusted, scratch, *, parallel=False):
    """Compile approved positive/negative SDK examples against the candidate APIs.
    Unlike a bare compile_fail result, require the intended rustc error category."""
    harness = scratch / 'compiler-witnesses'
    (harness / 'examples').mkdir(parents=True, exist_ok=True)
    lines = ['[workspace]', '[package]', 'name="architecture-compiler-witnesses"', 'version="0.0.0"', 'edition="2021"', '[dependencies]']
    for name in ('busbar-contract', 'busbar-plugin-loader'):
        directory = (candidate / policy.data['core'][name]['manifest']).parent
        optional = ', optional=true' if name == 'busbar-plugin-loader' else ''
        lines.append(f'{name}={{path={inline(str(directory))}{optional}}}')
    root = read(candidate / 'Cargo.toml')
    for source, table in root.get('patch', {}).items():
        lines.append(f'[patch.{inline(source)}]')
        for name, cfg in table.items():
            cfg = dict(cfg)
            if 'path' in cfg:
                cfg['path'] = str((candidate / cfg['path']).resolve())
            lines.append(f'{inline(name)}={inline(cfg)}')
    (harness / 'Cargo.toml').write_text('\n'.join(lines) + '\n')
    cases = []
    contract_root = Path(policy.data['core']['busbar-contract']['manifest']).parent
    for row in policy.data['compiler_witnesses']:
        source = (trusted / row['source']).read_text()
        docs = '\n'.join(re.sub(r'^\s*//[/!] ?', '', line) for line in source.splitlines() if re.match(r'^\s*//[/!]', line))
        blocks = re.findall(r'```([^\n]*)\n(.*?)```', docs, re.DOTALL)
        selected = [(flags, code) for flags, code in blocks if any(marker in code for marker in row['markers'])]
        if len(selected) != row['count']:
            raise Violation(f'trusted compiler witness inventory changed: {row["source"]}')
        for flags, code in selected:
            code = '\n'.join(line[2:] if line.startswith('# ') else line for line in code.splitlines())
            if not re.search(r'\bfn\s+main\s*\(', code):
                code = 'fn main() {\n' + code + '\n}\n'
            expected = re.findall(r'E[0-9]{4}', flags)
            if 'compile_fail' in flags and not expected:
                raise Violation('negative witness must name its expected compiler error')
            name = f'witness_{len(cases):02}'
            (harness / 'examples' / (name + '.rs')).write_text(code)
            # Contract-only witnesses need no loader build. Keep the loader for
            # every other source owner and any explicit reference, including
            # forbidden/private imports whose intended error needs its presence.
            needs_loader = (not Path(row['source']).is_relative_to(contract_root)
                            or 'busbar_plugin_loader' in code)
            cases.append((name, expected, needs_loader))
    if not cases or not any(not expected for _, expected, _ in cases):
        raise Violation('compiler witnesses require a positive control')
    if parallel and EXECUTION is None:
        raise Violation('parallel compiler witnesses require confinement')
    pool = EXECUTION.compiler_pool() if parallel else None
    jobs = pool.jobs if pool else compiler_check_jobs()
    # Only the isolated pool path is seeded; the serial fallback is unchanged.
    seed = None
    if pool:
        try:
            seed = seed_compiler_dependencies(harness, scratch, cases)
        except CompilerSeedFailure as failure:
            # The seed is an optimisation only: restore exactly the unseeded
            # inputs and run every case on its own fresh target as before.
            fallback = abandon_compiler_seed(harness, scratch, failure)

    def compile_case(execution, case):
        name, expected, needs_loader = case
        # Each confined case still gets fresh artifacts. They are no longer needed
        # once its process exits; retaining all cases exhausts the bounded job disk.
        command = ['cargo', 'check', '--manifest-path', str(harness / 'Cargo.toml'), '--example', name, '--message-format=json']
        if needs_loader:
            command += ['--features', 'busbar-plugin-loader']
        if jobs is not None:
            command += ['--jobs', str(jobs)]
        if seed is not None:
            # A private copy inside this case's own isolate root, never the seed
            # itself. The pool removes it with the isolate after disposal.
            target = execution.roots['candidate'] / ('witness-target-' + uuid.uuid4().hex)
            shutil.copytree(seed['target'], target, symlinks=True)
            command += ['--config', str(seed['config']), '--target-dir', str(target)]
        architecture_progress('compiler-witnesses', 'start', case=name, total=len(cases),
                              expected=expected, build_jobs=jobs)
        started = time.monotonic()
        result = (pool.run(execution, command, cwd=scratch, vendored_sources=seed is not None) if pool else
                  candidate_run(command, cwd=scratch, text=True, capture_output=True,
                                discard_harness_target=True))
        messages = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
        errors = [row['message'] for row in messages if row.get('reason') == 'compiler-message' and row.get('target', {}).get('name') == name and row['message']['level'] == 'error']
        codes = {error['code']['code'] for error in errors if error.get('code')}
        log = result.stderr + '\n' + '\n'.join(e.get('rendered', '') for e in errors)
        (harness / (name + '.log')).write_text(log)
        passed = ((not expected and result.returncode == 0) or
                  (bool(expected) and result.returncode != 0 and bool(set(expected).intersection(codes))))
        details = {}
        if seed is not None:
            artifacts = [row for row in messages if row.get('reason') == 'compiler-artifact']
            # A seeded positive must prove rustc checked this case's own crate now;
            # a fresh (cached) result for it is never accepted as success.
            compiled = any(row.get('target', {}).get('name') == name and row.get('fresh') is False
                           for row in artifacts)
            passed = passed and (bool(expected) or compiled)
            details['dependency_units_rebuilt'] = sum(
                row.get('fresh') is False and row.get('target', {}).get('name') != name for row in artifacts)
        architecture_progress('compiler-witnesses', 'finish', case=name, total=len(cases),
                              expected=expected, received=sorted(codes), build_jobs=jobs,
                              passed=passed, exit_code=result.returncode,
                              elapsed_seconds=round(time.monotonic() - started, 3),
                              log_sha256=hashlib.sha256(log.encode()).hexdigest(), **details)
        if not passed:
            # The case log lives in the disposed harness; put its tail in the job trace.
            for line in [line for line in log.splitlines() if line.strip()][-SEED_LOG_TAIL_LINES:]:
                print('compiler-witness-log: ' + name + ': ' + line[:4000], file=sys.stderr)
            sys.stderr.flush()
            raise Violation(f'{name}: expected {expected or "successful positive control"}, received {sorted(codes)}; see {harness / (name + ".log")}')
    if pool:
        pool.map(compile_case, cases)
    else:
        for case in cases:
            compile_case(EXECUTION, case)
    receipt = {'compiler_witnesses': len(cases), 'production_features': True}
    if seed is not None:
        receipt['compiler_dependency_seed'] = dict(seed['receipt'], status='seeded')
        # Every case container is disposed; release the bounded job disk.
        shutil.rmtree(seed['target'])
        shutil.rmtree(seed['config'].parent / 'vendor')
    elif pool:
        receipt['compiler_dependency_seed'] = fallback
    return receipt


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


def validate_execution_paths(args, execution, context):
    checkout = execution.roots['checkout']
    generated = context.get('architecture_checkout')
    if generated is not None:
        if not isinstance(generated, dict) or set(generated) != {'path', 'source'}:
            raise Violation('invalid generated architecture checkout context')
        checkout = Path(generated['path'])
        if (not checkout.is_absolute() or checkout != checkout.resolve()
                or checkout not in execution.extra_readonly
                or not checkout.is_relative_to(execution.roots['candidate'] / 'generated')
                or generated_revision(checkout) != generated['source']):
            raise Violation('generated architecture checkout differs from protected context')
    if (args.checkout.resolve() != checkout
            or args.trusted.resolve() != execution.roots['trusted']
            or not args.scratch.resolve().is_relative_to(execution.roots['harness'])
            or not args.output.resolve().is_relative_to(execution.control)
            or any(args.output.resolve().is_relative_to(p) for p in execution.roots.values())):
        raise Violation('architecture controller paths differ from confined execution context')
    return generated['source'] if generated else None


def source_revision(checkout):
    result = subprocess.run(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True, capture_output=True)
    if result.returncode:
        # The native generator job retains its own source/SDK revisions and content hashes.
        return generated_revision(checkout)
    return result.stdout.strip()


def main():
    global EXECUTION, EVIDENCE, DEPENDENCY_UNITS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--scratch', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--trusted', required=True, type=Path)
    parser.add_argument('--sdk', type=Path, help='Exact pinned SDK checkout for a C plugin')
    parser.add_argument('--execution-context', type=Path)
    parser.add_argument('--execution-context-sha256')
    parser.add_argument('--dependency-units', type=Path, help='Controller-owned read-only dependency units')
    args = parser.parse_args()
    EXECUTION = None
    EVIDENCE = args.output.resolve().parent
    generated_source = None
    if args.execution_context:
        from native_confinement import Execution
        EXECUTION = Execution.from_context(args.execution_context, args.execution_context_sha256)
        generated_source = validate_execution_paths(args, EXECUTION, json.loads(args.execution_context.read_text()))
    elif args.execution_context_sha256:
        raise Violation('execution context digest requires its context')
    DEPENDENCY_UNITS = None
    if args.dependency_units is not None:
        if EXECUTION is None:
            raise Violation('dependency units require confined execution')
        DEPENDENCY_UNITS = args.dependency_units
    policy = Policy(read(args.policy))
    checkout = args.checkout.resolve()
    if args.repository != 'GetBusbar/busbar' and args.repository not in policy.data['repositories']:
        raise Violation(f'unclassified repository {args.repository}')
    args.scratch.mkdir(parents=True, exist_ok=True)
    if policy.data['repositories'].get(args.repository, {}).get('language') == 'c':
        if args.sdk is None:
            raise Violation('C verification requires the pinned SDK checkout')
        receipt = check_c(policy, args.repository, checkout, args.sdk.resolve(), args.scratch.resolve())
    else:
        architecture_progress('shipping-graph', 'start')
        entries = check_declared(policy, args.repository, checkout)
        metadata = resolve_shipping(checkout, entries, args.scratch.resolve())
        receipt = check_graph(metadata, policy, args.repository, checkout)
        architecture_progress('shipping-graph', 'finish')
        if args.repository == 'GetBusbar/busbar':
            architecture_progress('assembly-graph', 'start')
            receipt['dependency_vector'] = check_vector(policy, checkout, entries)
            assembled = resolve_shipping(checkout, entries, args.scratch.resolve(), assembly=True)
            receipt['assembly'] = check_graph(assembled, policy, args.repository, checkout)
            architecture_progress('assembly-graph', 'finish')
            receipt.update(check_compiler_witnesses(policy, checkout, args.trusted.resolve(),
                                                   args.scratch.resolve(), parallel=compiler_witness_parallel()))
        architecture_progress('source-check', 'start')
        receipt.update(check_sources(policy, args.repository, checkout, metadata, args.trusted.resolve(), args.scratch.resolve()))
        architecture_progress('source-check', 'finish')
    source = generated_revision(checkout) if generated_source else source_revision(checkout)
    if generated_source and source != generated_source:
        raise Violation('generated architecture source changed during qualification')
    receipt.update(repository=args.repository, policy_sha256=hashlib.sha256(args.policy.read_bytes()).hexdigest(), source=source)
    if EXECUTION:
        receipt['candidate_execution'] = EXECUTION.observations
        receipt['release_eligible'] = False
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    try:
        main()
    except (Violation, ValueError, OSError, subprocess.CalledProcessError, tomllib.TOMLDecodeError) as error:
        print(f'architecture: {error}', file=sys.stderr)
        sys.exit(1)

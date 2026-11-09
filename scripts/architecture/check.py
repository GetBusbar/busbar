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
import subprocess
import sys
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
    repo = 'GetBusbar/' + witness['repo']
    if (policy.data['repositories'].get(repo, {}).get('language') != 'c'
            or witness['sdk'] != sdk or not re.fullmatch('[0-9a-f]{40}', witness['commit'])
            or witness['url'].removesuffix('.git') != 'https://github.com/' + repo):
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
    return {'sdk_revision': vector['sdk'], 'products': len(vector['products']),
            'vector_sha256': hashlib.sha256((checkout / 'scripts/ci-product-pins.json').read_bytes()).hexdigest()}


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
    metadata = json.loads(subprocess.check_output(cmd, cwd=scratch, text=True))
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
        source_metadata = json.loads(subprocess.check_output(
            ['cargo', 'metadata', '--no-deps', '--format-version', '1',
             '--manifest-path', str(checkout / 'Cargo.toml')], cwd=checkout, text=True))
        crate_roots = core_target_roots(policy, checkout, source_metadata)
    if roots or repository == 'GetBusbar/busbar':
        # Resolve generated OUT_DIR includes from this exact candidate build. Never use
        # a candidate-supplied map or a stale build output selected by filename search.
        build_command = (['cargo', 'build', '--workspace', '--manifest-path', str(checkout / 'Cargo.toml')]
            if repository == 'GetBusbar/busbar' else
            ['cargo', 'build', '--manifest-path', str(scratch / 'shipping-probe/Cargo.toml')])
        build = subprocess.check_output(build_command + ['--message-format=json'], cwd=checkout, text=True)
        for line in build.splitlines():
            row = json.loads(line)
            if row.get('reason') == 'build-script-executed':
                for package in source_metadata['packages']:
                    if package['id'] == row['package_id'] and package['name'] in policy.packages:
                        mapping[str(Path(package['manifest_path']).parent)] = row['out_dir']
        generated = scratch / 'generated-directories.json'
        generated.write_text(json.dumps(mapping))
        env['BUSBAR_ARCHITECTURE_GENERATED_DIRS'] = str(generated)
    if repository == 'GetBusbar/busbar':
        inventory = scratch / 'policy-sources.json'
        paths = set(core_source_inventory(policy, checkout))
        for output in mapping.values():
            paths.update(str(path.resolve()) for path in Path(output).rglob('*.rs'))
        inventory.write_text(json.dumps({'paths': sorted(paths), 'roots': crate_roots,
            'names': sorted({r.split('/', 1)[1].split('-', 2)[2] for r in policy.data['repositories']})}))
        env['BUSBAR_ARCHITECTURE_POLICY_SOURCES'] = str(inventory)
    subprocess.run(['cargo', 'test', '--manifest-path', str(harness / 'Cargo.toml'), '--test', 'architecture_surface'], cwd=scratch, env=env, check=True)
    return {'source_roots': len(set(roots)), 'core_source_files': len(paths) if repository == 'GetBusbar/busbar' else 0,
            'trusted_source_check': True}


def check_c(policy, repository, checkout, sdk, scratch):
    entry = policy.data['repositories'][repository]
    fields = (checkout / '.busbar-ref').read_text().split()
    revision = subprocess.check_output(['git', '-C', str(sdk), 'rev-parse', 'HEAD'], text=True).strip()
    if fields != [revision, '1.6.0']:
        raise Violation('C plugin/header SDK pin mismatch')
    sources = [checkout / path for path in entry['sources']]
    for source in sources:
        includes = re.findall(r'^\s*#\s*include\s+(.+)$', source.read_text(), re.MULTILINE)
        if includes != ['"busbar_plugin.h"']:
            raise Violation(f'C plugin must include only the public ABI header: {source}')
    library = scratch / ('plugin.dylib' if sys.platform == 'darwin' else 'plugin.so')
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fvisibility=hidden', '-fPIC',
        '-dynamiclib' if sys.platform == 'darwin' else '-shared', '-I', str(sdk / 'crates/busbar-contract/include'),
        *map(str, sources), '-o', str(library)], check=True)
    output = subprocess.check_output(['nm', '-gU' if sys.platform == 'darwin' else '--defined-only', str(library)], text=True)
    exported = {line.split()[-1].removeprefix('_') for line in output.splitlines() if len(line.split()) >= 3 and line.split()[-2].isupper()}
    if exported != {'busbar_plugin_door'}:
        raise Violation(f'C runtime exports are not the sole ABI door: {sorted(exported)}')
    return {'source_roots': len(sources), 'c_header_revision': revision, 'c_exports': sorted(exported)}


def check_compiler_witnesses(policy, candidate, trusted, scratch):
    """Compile approved positive/negative SDK examples against the candidate APIs.
    Unlike a bare compile_fail result, require the intended rustc error category."""
    harness = scratch / 'compiler-witnesses'
    (harness / 'examples').mkdir(parents=True, exist_ok=True)
    lines = ['[workspace]', '[package]', 'name="architecture-compiler-witnesses"', 'version="0.0.0"', 'edition="2021"', '[dependencies]']
    for name in ('busbar-contract', 'busbar-plugin-loader'):
        directory = (candidate / policy.data['core'][name]['manifest']).parent
        lines.append(f'{name}={{path={inline(str(directory))}}}')
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
            cases.append((name, expected))
    if not cases or not any(not expected for _, expected in cases):
        raise Violation('compiler witnesses require a positive control')
    for name, expected in cases:
        result = subprocess.run(['cargo', 'check', '--manifest-path', str(harness / 'Cargo.toml'), '--example', name, '--message-format=json'], cwd=scratch, text=True, capture_output=True)
        messages = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
        errors = [row['message'] for row in messages if row.get('reason') == 'compiler-message' and row.get('target', {}).get('name') == name and row['message']['level'] == 'error']
        codes = {error['code']['code'] for error in errors if error.get('code')}
        (harness / (name + '.log')).write_text(result.stderr + '\n' + '\n'.join(e.get('rendered', '') for e in errors))
        if (not expected and result.returncode != 0) or (expected and (result.returncode == 0 or not set(expected).intersection(codes))):
            raise Violation(f'{name}: expected {expected or "successful positive control"}, received {sorted(codes)}; see {harness / (name + ".log")}')
    return {'compiler_witnesses': len(cases), 'production_features': True}


def source_revision(checkout):
    result = subprocess.run(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True, capture_output=True)
    if result.returncode:
        # The native generator job retains its own source/SDK revisions and content hashes.
        files = sorted(p for p in checkout.rglob('*') if p.is_file())
        return 'generated-sha256:' + hashlib.sha256(b''.join(str(p.relative_to(checkout)).encode() + b'\0' + p.read_bytes() for p in files)).hexdigest()
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--scratch', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--trusted', required=True, type=Path)
    parser.add_argument('--sdk', type=Path, help='Exact pinned SDK checkout for a C plugin')
    args = parser.parse_args()
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
        entries = check_declared(policy, args.repository, checkout)
        metadata = resolve_shipping(checkout, entries, args.scratch.resolve())
        receipt = check_graph(metadata, policy, args.repository, checkout)
        if args.repository == 'GetBusbar/busbar':
            receipt['dependency_vector'] = check_vector(policy, checkout, entries)
            assembled = resolve_shipping(checkout, entries, args.scratch.resolve(), assembly=True)
            receipt['assembly'] = check_graph(assembled, policy, args.repository, checkout)
            receipt.update(check_compiler_witnesses(policy, checkout, args.trusted.resolve(), args.scratch.resolve()))
        receipt.update(check_sources(policy, args.repository, checkout, metadata, args.trusted.resolve(), args.scratch.resolve()))
    receipt.update(repository=args.repository, policy_sha256=hashlib.sha256(args.policy.read_bytes()).hexdigest(), source=source_revision(checkout))
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    try:
        main()
    except (Violation, OSError, subprocess.CalledProcessError, tomllib.TOMLDecodeError) as error:
        print(f'architecture: {error}', file=sys.stderr)
        sys.exit(1)

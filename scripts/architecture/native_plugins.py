"""Existing plugin checks and canonical scaffolding under trusted native admission."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys

from native import digest, git


def qualify_plugin(q, host, sdk):
    entry = q.policy.data['repositories'][q.repository]
    if entry.get('language') == 'c':
        library = q.work / 'architecture' / ('plugin.dylib' if sys.platform == 'darwin' else 'plugin.so')
        q.env.update(BUSBAR_C_ABI_SOURCES=str(q.root / 'secret-c'), BUSBAR_C_ABI_LIBRARY=str(library))
        q.run('c-native-loader', ['cargo', 'test', '--locked', '--manifest-path', str(sdk / 'Cargo.toml'),
            '-p', 'busbar-plugin-loader', '--test', 'c_abi'])
        # The existing C witness includes ownership, secret wiping and threaded cases.
        include = sdk / 'crates/busbar-contract/include'
        sources = [str(q.root / 'secret-c/tests/unit.c'), str(q.root / 'secret-c/busbar_secret_c.c')]
        common = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-pthread',
                  '-DBUSBAR_SECRET_C_UNIT', '-I', str(include), *sources]
        for name, flags in [('unit', []), ('unit-tsan', ['-fsanitize=thread', '-g'])]:
            binary = q.work / name
            q.run('c-build-' + name, [*common, *flags, '-o', str(binary)])
            q.env['TSAN_OPTIONS'] = 'halt_on_error=1'
            q.run('c-' + name, [str(binary)])
        schema = q.work / 'settings-schema'
        q.run('c-build-schema', ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-I', str(include), str(q.root / 'secret-c/tests/settings_schema.c'),
            str(q.root / 'secret-c/busbar_secret_c.c'), '-o', str(schema)])
        q.run('c-schema', ['python3', str(q.root / 'secret-c/tests/settings_schema.py'), str(schema)])
        q.receipt.update(library_sha256=digest(library), private=False)
        shutil.copyfile(library, q.evidence / library.name)
        return
    q.run('fmt', ['cargo', 'fmt', '--all', '--check'])
    q.run('clippy', ['cargo', 'clippy', '--locked', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'])
    meta_file = q.run('metadata', ['cargo', 'metadata', '--locked', '--format-version', '1'])
    metadata = json.loads(meta_file.read_text())
    wrappers = [p for p in entry['packages'] if p['role'] in ('wrapper', 'combined')]
    if not wrappers:
        wrappers = [p for p in entry['packages'] if any('cdylib' in t['kind'] for package in metadata['packages'] if package['name'] == p['name'] for t in package['targets'])]
    if len(wrappers) != 1:
        raise RuntimeError('exactly one native plugin export package is required')
    package = next(p for p in metadata['packages'] if p['name'] == wrappers[0]['name'])
    target = next(t for t in package['targets'] if 'cdylib' in t['kind'])
    q.run('native-library', ['cargo', 'build', '--locked', '-p', package['name'], '--all-features', '--lib'])
    library = Path(q.env['CARGO_TARGET_DIR']) / 'debug' / ('lib' + target['name'] + ('.dylib' if sys.platform == 'darwin' else '.so'))
    if not library.is_file():
        raise RuntimeError('native library was not produced')
    q.env['BUSBAR_PLUGIN_CDYLIB'] = str(library)
    q.run('plugin-runtime', ['cargo', 'nextest', 'run', '--locked', '--workspace', '--all-features', '--no-fail-fast',
        '--tool-config-file', 'admission:' + str(q.trusted / 'ci/native-nextest.toml')])
    q.run('plugin-doctests', ['cargo', 'test', '--locked', '--workspace', '--all-features', '--doc', '--no-fail-fast'])
    if (q.root / 'deny.toml').is_file():
        q.run('dependency-policy', ['cargo', 'deny', 'check'])
    if (q.root / 'supply-chain/config.toml').is_file():
        q.run('dependency-vet', ['cargo', 'vet'])
    # Preserve repository-owned required extra selections; read the command from
    # the trusted fleet registry, not a candidate-controlled CI script.
    import yaml
    registry = yaml.safe_load((q.trusted / 'plugins.yaml').read_text())
    registered = next((p for p in registry['plugins'] if p['repo'] == q.repository.rsplit('/', 1)[1]), {})
    if registered.get('extra_test'):
        q.run('plugin-required-extra', ['bash', '-euo', 'pipefail', '-c', registered['extra_test']])
    q.conformance('plugin-native-conformance')
    q.receipt['library_sha256'] = digest(library)
    q.receipt['lock_sha256'] = digest(q.root / 'Cargo.lock')
    q.receipt['private'] = entry['private']
    shutil.copyfile(library, q.evidence / library.name)


def qualify_generator(q):
    """One generator, with all fourteen kind/distribution combinations checked by
    the same trusted role graph, source guard and native door fixtures."""
    host = q.host()
    pin = json.loads((host / 'scripts/ci-product-pins.json').read_text())['sdk']
    sdk = q.sdk()
    q.env.update(BUSBAR_SDK_CHECKOUT=str(sdk), BUSBAR_SDK_REVISION=pin,
                 BUSBAR_SCAFFOLD_OUTPUT=str(q.work / 'generated'))
    q.receipt.update(host_revision=git(host, 'rev-parse', 'HEAD'), sdk_revision=pin)
    q.run('fmt', ['cargo', 'fmt', '--all', '--check'])
    q.run('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings'])
    q.run('tooling-runtime', ['cargo', 'nextest', 'run', '--workspace', '--locked', '--no-fail-fast',
        '--tool-config-file', 'admission:' + str(q.trusted / 'ci/native-nextest.toml')])
    q.run('tooling-doctests', ['cargo', 'test', '--workspace', '--doc', '--locked'])
    q.run('render-canonical', ['cargo', 'test', '--locked', '-p', 'busbar-release-plugin', '--test', 'boundary_scaffold',
        'canonical_seven_kind_skeletons', '--', '--ignored', '--exact'])
    results = []
    for variant, owner in [('open-source', 'GetBusbar'), ('enterprise', 'BusbarInc')]:
        for kind in ('auth', 'secret', 'store', 'hook', 'export', 'plane', 'transport'):
            name = f'busbar-{kind}-boundary-example'
            stem = name.removeprefix('busbar-')
            root = q.work / 'generated' / variant / name
            repo = owner + '/' + name
            label = variant + '-' + kind
            q.run(label + '-fmt', ['cargo', 'fmt', '--all'], cwd=root)
            q.run(label + '-metadata', ['cargo', 'metadata', '--format-version', '1'], cwd=root)
            q.run(label + '-clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings'], cwd=root)
            q.run(label + '-build', ['cargo', 'build', '--locked', '-p', name + '-plugin', '--lib'], cwd=root)
            library = Path(q.env['CARGO_TARGET_DIR']) / 'debug' / ('lib' + name.replace('-', '_') + '_plugin' + ('.dylib' if sys.platform == 'darwin' else '.so'))
            q.env['BUSBAR_PLUGIN_CDYLIB'] = str(library)
            q.run(label + '-native-doors', ['cargo', 'test', '--locked', '-p', name + '-plugin', '--test', 'conformance'], cwd=root)
            scratch = q.work / ('generated-guard-' + label)
            scratch.mkdir()
            policy_file = scratch / 'policy.toml'
            policy_file.write_text((q.trusted / 'ci/architecture.toml').read_text() + f"""
[repositories.{json.dumps(repo)}]
kind = {json.dumps(kind)}
private = {str(variant == 'enterprise').lower()}
[[repositories.{json.dumps(repo)}.packages]]
name = {json.dumps(name)}
manifest = {json.dumps(stem + '/Cargo.toml')}
role = "implementation"
dev_allows = []
[[repositories.{json.dumps(repo)}.packages]]
name = {json.dumps(name + '-plugin')}
manifest = {json.dumps(stem + '-plugin/Cargo.toml')}
role = "wrapper"
dev_allows = ["busbar-contract", "busbar-plugin-loader"]
""")
            output = q.evidence / (label + '-architecture.json')
            q.run(label + '-architecture', ['python3', str(q.trusted / 'scripts/architecture/check.py'),
                '--policy', str(policy_file), '--repository', repo, '--checkout', str(root),
                '--trusted', str(q.trusted), '--scratch', str(scratch), '--output', str(output)])
            result = json.loads(output.read_text())
            results.append(dict(kind=kind, distribution=variant, **result))
    q.receipt['generated_plugins'] = results

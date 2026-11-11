"""Existing plugin checks and canonical scaffolding under trusted native admission."""
from __future__ import annotations

import json
from pathlib import Path
import sys

from native import collect_output, digest, git


def qualify_plugin(q, host, sdk):
    entry = q.policy.data['repositories'][q.repository]
    if entry.get('language') == 'c':
        from check import load_c_recipe, PUBLIC_C_HEADER
        recipe = load_c_recipe(q.policy, q.repository, q.root)
        library = q.work / 'architecture' / ('plugin.dylib' if sys.platform == 'darwin' else 'plugin.so')
        q.env.update(BUSBAR_C_ABI_SOURCES=str(q.root / recipe['test-root']), BUSBAR_C_ABI_LIBRARY=str(library))
        q.run('c-native-loader', ['cargo', 'test', '--locked', '--manifest-path', str(sdk / 'Cargo.toml'),
            '-p', 'busbar-plugin-loader', '--test', 'c_abi'])
        # Owner test locations are data; required instrumentation and stages are fixed.
        include = sdk / Path(PUBLIC_C_HEADER).parent
        sources = [str(q.root / path) for path in [*recipe['unit']['sources'], *recipe['sources']]]
        common = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-pthread',
                  *['-D' + name for name in recipe['unit']['defines']], '-I', str(include), *sources]
        for name, flags in [('unit', []), ('unit-tsan', ['-fsanitize=thread', '-g'])]:
            binary = q.work / name
            q.run('c-build-' + name, [*common, *flags, '-o', str(binary)])
            q.env['TSAN_OPTIONS'] = 'halt_on_error=1'
            command = [str(binary)]
            if name == 'unit-tsan' and sys.platform == 'linux':
                from native_sanitizer import run_c_unit_tsan
                run_c_unit_tsan(q)
            else:
                q.run('c-' + name, command)
        schema = q.work / 'settings-schema'
        q.run('c-build-schema', ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
            '-I', str(include), str(q.root / recipe['schema']['source']),
            *[str(q.root / path) for path in recipe['sources']], '-o', str(schema)])
        q.run('c-schema', ['python3', str(q.root / recipe['schema']['driver']), str(schema)])
        collected = collect_output(q, library, q.evidence / library.name, compiler_output=True)
        q.receipt.update(library_sha256=digest(collected), private=False)
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
    prepare_runtime(q)
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
    collected = collect_output(q, library, q.evidence / library.name, compiler_output=True)
    q.receipt['library_sha256'] = digest(collected)
    q.receipt['lock_sha256'] = digest(q.root / 'Cargo.lock')
    q.receipt['private'] = entry['private']


def prepare_runtime(q):
    """Prepare owner test subjects outside nextest's per-test runtime deadline."""
    from native_policy import native_settings
    from product_artifacts import regular_under
    script = native_settings(q.repository, q.policy).get('prepare_runtime')
    if script is not None:
        command = regular_under(q.root / script, q.root)
        q.run('plugin-runtime-prepare', ['bash', '-euo', 'pipefail', str(command)])


def generated_architecture_context(execution, checkout, label):
    """Select one already registered readonly tree without changing execution roots."""
    from check import generated_revision, Violation
    checkout = Path(checkout).resolve()
    if (checkout not in execution.extra_readonly
            or not checkout.is_relative_to(execution.roots['candidate'] / 'generated')):
        raise Violation('generated architecture checkout is not registered readonly')
    parent, expected = execution.write_context()
    if digest(parent) != expected:
        raise Violation('parent execution context changed')
    context = json.loads(parent.read_text())
    context['architecture_checkout'] = {'path': str(checkout), 'source': generated_revision(checkout)}
    path = execution.control / ('generated-' + label + '-execution-context.json')
    path.write_text(json.dumps(context, sort_keys=True) + '\n')
    return path, digest(path)


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
            if q.execution is not None:
                q.execution.register_generated(root)
            scratch = (q.harness if q.execution is not None else q.work) / ('generated-guard-' + label)
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
            command = ['python3', str(q.trusted / 'scripts/architecture/check.py'),
                '--policy', str(policy_file), '--repository', repo, '--checkout', str(root),
                '--trusted', str(q.trusted), '--scratch', str(scratch), '--output', str(output)]
            if q.execution is not None:
                context, expected = generated_architecture_context(q.execution, root, label)
                command += ['--execution-context', str(context), '--execution-context-sha256', expected]
            q.run_controller(label + '-architecture', command)
            result = json.loads(output.read_text())
            if q.execution is not None:
                q.execution.observations.extend(result['candidate_execution'])
            results.append(dict(kind=kind, distribution=variant, **result))
    q.receipt['generated_plugins'] = results

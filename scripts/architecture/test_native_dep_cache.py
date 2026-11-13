"""Trusted dependency units can only skip work: any doubt builds from scratch."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
import unittest.mock

import confinement_entry
import native_confinement
import native_dep_cache as cache

REPO = 'GetBusbar/busbar-transport-example'
IMAGE = 'sha256:' + 'a' * 64
ENV = {'RUSTUP_TOOLCHAIN': '1.98.0', 'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0',
       'RUSTC_WRAPPER': '', 'RUSTC_WORKSPACE_WRAPPER': ''}
PIPELINE = {'id': 77, 'ref': 'dev', 'sha': 'c' * 40, 'source': 'push'}
HOST = 'e' * 40
PINNED_PIPELINE = {'id': 88, 'ref': cache.PINNED_REF, 'sha': HOST, 'source': 'api'}
PINNED_PRODUCER = {'pipeline_id': 88, 'commit': HOST, 'ref': cache.PINNED_REF, 'source': 'api',
                   'protected': True, 'dev_revision': 'f' * 40}


def write_target(root):
    """A target dir holding two dependency units and one workspace member."""
    debug = root / 'debug'
    for relative, data in {
            'deps/libserde-0123456789abcdef.rlib': b'serde',
            'deps/libserde-0123456789abcdef.rmeta': b'serde-meta',
            'deps/serde-0123456789abcdef.d': b'dep-info',
            '.fingerprint/serde-0123456789abcdef/lib-serde': b'fp',
            'build/ring-fedcba9876543210/output': b'cargo:rustc-link-lib=ring',
            'deps/libbusbar_transport_example-1111111111111111.rlib': b'member',
            'deps/libbusbar_transport_example_plugin.so': b'member-cdylib',
            '.fingerprint/busbar-transport-example-1111111111111111/lib': b'member-fp',
            'build/busbar-transport-example-2222222222222222/output': b'member-build',
            'libbusbar_transport_example_plugin.so': b'profile-root output',
            'incremental/busbar_transport_example-x/s': b'incremental',
            'examples/demo': b'example'}.items():
        path = debug / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (root / '.rustc_info.json').write_text('{}')
    return root


class FakeRegistry:
    def __init__(self, files, package_files=None, packages=None):
        self.files, self.package_files, self.packages = files, package_files, packages
        self.downloads = 0

    def read(self, version, name, limit):
        if (version, name) not in self.files:
            raise FileNotFoundError(name)
        return self.files[version, name]

    def download(self, version, name, destination, size, digest):
        self.downloads += 1
        data = self.files[version, name]
        destination.write_bytes(data)
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise cache.Unavailable('dependency archive digest differs from its manifest')

    def json(self, path):
        if path.startswith('/packages?'):
            return self.packages
        return self.package_files


class Fixture(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(directory.cleanup)
        self.addCleanup(self.unseal, Path(directory.name))
        self.base = base = Path(directory.name)
        control = base / 'boundary-1-2'
        roots = {name: control / name for name in ('candidate', 'harness')}
        roots.update(checkout=base / 'checkout', trusted=base / 'trusted')
        for path in roots.values():
            path.mkdir(parents=True)
        (roots['checkout'] / 'Cargo.lock').write_text('version = 4\n')
        self.evidence = control / 'evidence'
        self.evidence.mkdir()
        policy = SimpleNamespace(data={'repositories': {REPO: {'packages': [
            {'name': 'busbar-transport-example', 'role': 'implementation'},
            {'name': 'busbar-transport-example-plugin', 'role': 'wrapper'}]}}})
        self.q = SimpleNamespace(receipt={}, policy=policy, repository=REPO, control=control,
                                 root=roots['checkout'], env=dict(ENV, CARGO_TARGET_DIR=str(roots['candidate'] / 'target')),
                                 evidence=self.evidence, save=lambda: None,
                                 execution=SimpleNamespace(config={'image': IMAGE}, roots=roots))
        self.identity = cache.consumer_identity(self.q, 'busbar-transport-example-plugin')
        self.version = cache.key(self.identity)

    @staticmethod
    def unseal(root):
        for directory, _, files in os.walk(root):
            os.chmod(directory, 0o755)

    def published(self, *, tamper=None, identity=None, pipelines=None, duplicate=False, producer=None):
        work = Path(tempfile.mkdtemp(dir=self.base))
        target = write_target(work / 'producer-target')
        cache.strip_path_units(target, {'busbar-transport-example', 'busbar-transport-example-plugin'})
        archive = work / 'units.tar.gz'
        files = cache.pack(target, archive)
        data = archive.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        name = 'units-' + digest + '.tar.gz'
        version = cache.key(identity) if identity and 'pinned_producer' in identity else self.version
        manifest = {'schema': cache.SCHEMA, 'key': version, 'identity': identity or self.identity,
                    'archive': {'name': name, 'sha256': digest, 'bytes': len(data)}, 'files': files,
                    'product': {'repo': REPO.split('/')[1], 'commit': 'd' * 40},
                    'producer': producer or {'pipeline_id': PIPELINE['id'], 'commit': PIPELINE['sha'], 'ref': 'dev'}}
        rows = [{'file_name': cache.MANIFEST, 'pipelines': pipelines or [PIPELINE]},
                {'file_name': name, 'file_sha256': digest, 'pipelines': pipelines or [PIPELINE]}]
        if duplicate:
            rows.append(dict(rows[1]))
        stored = tamper(data) if tamper else data
        return FakeRegistry({(version, cache.MANIFEST): cache.canonical(manifest), (version, name): stored},
                            package_files=rows, packages=[{'id': 9, 'name': cache.PACKAGE, 'version': version}])

    def pinned(self, commit=HOST, **kwargs):
        identity = dict(self.identity, pinned_producer={'ref': cache.PINNED_REF, 'commit': commit})
        kwargs.setdefault('pipelines', [dict(PINNED_PIPELINE, sha=commit)])
        kwargs.setdefault('producer', dict(PINNED_PRODUCER, commit=commit))
        return self.published(identity=identity, **kwargs)


class Restore(Fixture):
    def test_hit_restores_verified_seed_outside_every_candidate_mount(self):
        seed = cache.restore(self.q, self.published())
        self.assertEqual(self.q.receipt['dependency_units']['status'], 'hit')
        self.assertEqual(seed, (self.q.control / 'dependency-units').resolve())
        for root in self.q.execution.roots.values():
            self.assertFalse(seed.is_relative_to(root.resolve()))
        self.assertTrue((seed / 'debug/deps/libserde-0123456789abcdef.rlib').is_file())
        self.assertFalse(any(seed.rglob('*busbar_transport_example*')))
        self.assertFalse(any(seed.rglob('*busbar-transport-example*')))
        self.assertEqual(os.stat(seed).st_mode & 0o222, 0)
        cache.install_job_target(self.q, seed)
        target = Path(self.q.env['CARGO_TARGET_DIR'])
        self.assertEqual((target / 'debug/deps/libserde-0123456789abcdef.rlib').read_bytes(), b'serde')
        self.assertFalse((self.q.control / 'dependency-units.tar.gz').exists())

    def test_miss_builds_from_scratch(self):
        registry = FakeRegistry({})
        self.assertIsNone(cache.restore(self.q, registry))
        self.assertEqual(self.q.receipt['dependency_units'], {'status': 'miss', 'key': self.version})
        cache.install_job_target(self.q, None)
        self.assertFalse(Path(self.q.env['CARGO_TARGET_DIR']).exists())

    def test_archive_digest_mismatch_builds_from_scratch_and_leaves_nothing(self):
        registry = self.published(tamper=lambda data: data[:-1] + bytes([data[-1] ^ 1]))
        self.assertIsNone(cache.restore(self.q, registry))
        record = self.q.receipt['dependency_units']
        self.assertEqual(record['status'], 'fallback')
        self.assertIn('digest', record['reason'])
        self.assertFalse((self.q.control / 'dependency-units').exists())
        self.assertFalse((self.q.control / 'dependency-units.tar.gz').exists())

    def test_file_digest_mismatch_inside_a_valid_archive_builds_from_scratch(self):
        registry = self.published()
        manifest = json.loads(registry.files[self.version, cache.MANIFEST])
        manifest['files']['debug/deps/libserde-0123456789abcdef.rlib'] = '0' * 64
        registry.files[self.version, cache.MANIFEST] = cache.canonical(manifest)
        self.assertIsNone(cache.restore(self.q, registry))
        self.assertIn('inventory', self.q.receipt['dependency_units']['reason'])
        self.assertFalse((self.q.control / 'dependency-units').exists())

    def test_identity_mismatch_never_downloads(self):
        other = dict(self.identity, image='sha256:' + 'b' * 64)
        registry = self.published(identity=other)
        self.assertIsNone(cache.restore(self.q, registry))
        self.assertIn('identity', self.q.receipt['dependency_units']['reason'])
        self.assertEqual(registry.downloads, 0)

    def test_identity_covers_lock_image_environment_and_cargo_home(self):
        base = cache.key(self.identity)
        variants = [dict(self.identity, lock_sha256='0' * 64), dict(self.identity, image='sha256:' + 'b' * 64),
                    dict(self.identity, cargo_home='/elsewhere'),
                    cache.identity(REPO, self.identity['lock_sha256'], IMAGE, dict(ENV, RUSTFLAGS='-Cfoo'),
                                   wrapper='busbar-transport-example-plugin')]
        self.assertEqual(len({base, *map(cache.key, variants)}), len(variants) + 1)

    def test_upload_outside_the_protected_producer_pipeline_is_rejected(self):
        for pipelines in ([dict(PIPELINE, id=78)], [dict(PIPELINE, ref='feature')], [{}]):
            with self.subTest(pipelines=pipelines):
                self.q.receipt.clear()
                registry = self.published(pipelines=pipelines)
                self.assertIsNone(cache.restore(self.q, registry))
                self.assertEqual(self.q.receipt['dependency_units']['status'], 'fallback')
                self.assertEqual(registry.downloads, 0)

    def test_pinned_producer_files_hit_only_for_their_exact_host_revision(self):
        self.q.receipt['host_revision'] = HOST
        seed = cache.restore(self.q, self.pinned())
        record = self.q.receipt['dependency_units']
        self.assertIsNotNone(seed)
        self.assertEqual(record['status'], 'hit')
        self.assertEqual(record['provenance']['ref'], cache.PINNED_REF)
        self.assertEqual(record['pinned_key'], cache.key(dict(self.identity, pinned_producer={
            'ref': cache.PINNED_REF, 'commit': HOST})))
        self.assertNotEqual(record['pinned_key'], self.version)
        cache.discard(seed)
        # Another host revision (or none recorded) never looks at them.
        for host in ('d' * 40, None):
            with self.subTest(host=host):
                self.q.receipt.clear()
                if host:
                    self.q.receipt['host_revision'] = host
                registry = self.pinned()
                self.assertIsNone(cache.restore(self.q, registry))
                self.assertEqual(self.q.receipt['dependency_units']['status'], 'miss')
                self.assertEqual(registry.downloads, 0)

    def test_pinned_files_need_the_protected_owner_api_pipeline_on_the_exact_ref(self):
        bad = [dict(pipelines=[dict(PINNED_PIPELINE, ref='dev')]),
               dict(pipelines=[dict(PINNED_PIPELINE, ref=cache.PINNED_REF + '-x')]),
               dict(pipelines=[dict(PINNED_PIPELINE, source='push')]),
               dict(pipelines=[dict(PINNED_PIPELINE, source='schedule')]),
               dict(pipelines=[dict(PINNED_PIPELINE, sha='d' * 40)]),
               dict(pipelines=[dict(PINNED_PIPELINE, id=89)]),
               dict(producer=dict(PINNED_PRODUCER, protected=False)),
               dict(producer=dict(PINNED_PRODUCER, source='push')),
               dict(producer=dict(PINNED_PRODUCER, ref='dev')),
               dict(producer=dict(PINNED_PRODUCER, commit='d' * 40))]
        for kwargs in bad:
            with self.subTest(**{k: str(v) for k, v in kwargs.items()}):
                self.q.receipt.clear()
                self.q.receipt['host_revision'] = HOST
                registry = self.pinned(**kwargs)
                self.assertIsNone(cache.restore(self.q, registry))
                self.assertEqual(self.q.receipt['dependency_units']['status'], 'fallback')
                self.assertEqual(registry.downloads, 0)

    def test_dev_key_files_never_accept_a_pinned_pipeline(self):
        registry = self.published(pipelines=[dict(PINNED_PIPELINE, sha=PIPELINE['sha'])])
        self.assertIsNone(cache.restore(self.q, registry))
        self.assertEqual(self.q.receipt['dependency_units']['status'], 'fallback')

    def test_duplicated_archive_is_rejected(self):
        registry = self.published(duplicate=True)
        self.assertIsNone(cache.restore(self.q, registry))
        self.assertIn('duplicated', self.q.receipt['dependency_units']['reason'])

    def test_c_plugins_and_unconfined_runs_are_not_seeded(self):
        self.q.execution = None
        self.assertIsNone(cache.restore(self.q, FakeRegistry({})))
        self.assertEqual(self.q.receipt['dependency_units']['status'], 'not-applicable')


class Boundary(Fixture):
    def test_candidate_copy_cannot_write_the_seed(self):
        seed = cache.restore(self.q, self.published())
        before = cache.inventory(seed)
        copy = self.q.execution.roots['candidate'] / 'probe-target'
        cache.install(seed, copy)
        (copy / 'debug/deps/libserde-0123456789abcdef.rlib').write_bytes(b'candidate poison')
        (copy / 'debug/deps/new').write_bytes(b'added')
        self.assertEqual(cache.inventory(seed), before)
        sealed = seed / 'debug/deps/libserde-0123456789abcdef.rlib'
        # The seal is the mode bits; root (the native controller) bypasses them,
        # so assert the bits for every user and the refusal where it applies.
        for path in (sealed, sealed.parent, seed):
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o222, 0, path)
        if os.geteuid() != 0:
            with self.assertRaises(PermissionError):
                sealed.write_bytes(b'x')

    def test_seed_inside_a_candidate_mounted_root_is_refused(self):
        for name in ('candidate', 'checkout', 'harness', 'trusted'):
            inside = self.q.execution.roots[name] / 'units'
            inside.mkdir()
            with self.subTest(root=name), self.assertRaisesRegex(cache.Unavailable, name):
                cache.readonly_seed(inside, self.q.execution)

    def test_install_refuses_an_existing_destination(self):
        seed = cache.restore(self.q, self.published())
        destination = self.q.execution.roots['candidate'] / 'target'
        destination.mkdir()
        with self.assertRaises(cache.Unavailable):
            cache.install(seed, destination)

    def test_installed_copy_has_one_current_timestamp(self):
        seed = cache.restore(self.q, self.published())
        copy = cache.install(seed, self.base / 'copy', now=2_000_000_000)
        stamps = {path.stat().st_mtime for path in copy.rglob('*') if path.is_file()}
        self.assertEqual(stamps, {2_000_000_000})

    def test_installed_build_scripts_stay_executable(self):
        seed = self.base / 'exec-seed'
        (seed / 'debug/build/ring-0123456789abcdef').mkdir(parents=True)
        (seed / 'debug/build/ring-0123456789abcdef/build-script-build').write_bytes(b'#!')
        (seed / 'debug/build/ring-0123456789abcdef/build-script-build.d').write_bytes(b'dep')
        (seed / 'debug/build/ring-0123456789abcdef/build_script_build-0123456789abcdef').write_bytes(b'#!')
        copy = cache.install(seed, self.base / 'exec-copy')
        unit = copy / 'debug/build/ring-0123456789abcdef'
        self.assertTrue(os.access(unit / 'build-script-build', os.X_OK))
        self.assertTrue(os.access(unit / 'build_script_build-0123456789abcdef', os.X_OK))
        self.assertFalse(os.access(unit / 'build-script-build.d', os.X_OK))

    def test_unpack_rejects_escaping_and_unlisted_entries(self):
        for name, kind in (('../escape', tarfile.REGTYPE), ('debug/link', tarfile.SYMTYPE),
                           ('/abs', tarfile.REGTYPE), ('debug/unlisted', tarfile.REGTYPE)):
            with self.subTest(name=name):
                archive = self.base / ('bad-' + str(abs(hash(name))) + '.tar.gz')
                with tarfile.open(archive, 'w:gz') as tar:
                    info = tarfile.TarInfo(name)
                    info.type = kind
                    if kind == tarfile.SYMTYPE:
                        info.linkname = '/etc/passwd'
                    tar.addfile(info, io.BytesIO(b'') if kind == tarfile.REGTYPE else None)
                with self.assertRaises(cache.Unavailable):
                    cache.unpack(archive, self.base / ('out-' + str(abs(hash(name)))), {})

    def test_strip_keeps_only_registry_and_git_units(self):
        target = cache.strip_path_units(write_target(self.base / 't'), {'busbar-transport-example',
                                                                       'busbar-transport-example-plugin'})
        self.assertEqual(sorted(cache.inventory(target)), [
            'debug/.fingerprint/serde-0123456789abcdef/lib-serde',
            'debug/build/ring-fedcba9876543210/output',
            'debug/deps/libserde-0123456789abcdef.rlib',
            'debug/deps/libserde-0123456789abcdef.rmeta',
            'debug/deps/serde-0123456789abcdef.d'])

    def test_pack_is_deterministic(self):
        target = write_target(self.base / 't')
        cache.pack(target, self.base / 'a.tar.gz')
        cache.pack(target, self.base / 'b.tar.gz')
        self.assertEqual((self.base / 'a.tar.gz').read_bytes(), (self.base / 'b.tar.gz').read_bytes())


class Portability(unittest.TestCase):
    def test_every_confined_cargo_home_has_one_fixed_path(self):
        self.assertEqual(native_confinement.INVOCATION_CARGO_HOME, cache.CARGO_HOME_PATH)
        self.assertEqual(str(confinement_entry.INVOCATION_CARGO_HOME), cache.CARGO_HOME_PATH)

    def test_producer_commands_are_the_plugin_steps(self):
        source = (Path(__file__).with_name('native_plugins.py')).read_text()
        for name, argv in cache.plugin_commands('NAME'):
            if name == 'plugin-runtime':
                # The build half of nextest: same selection, no test execution.
                self.assertIn("'cargo', 'nextest', 'run', '--locked', '--workspace', '--all-features'", source)
                continue
            literal = ', '.join(repr(arg) for arg in argv).replace("'NAME'", "package['name']")
            self.assertIn(f"q.run({name!r}, [{literal}]", source)

    def test_stub_workspace_keeps_manifests_and_neutralises_code(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            source, stub = Path(directory) / 'src', Path(directory) / 'stub'
            (source / 'crate/src').mkdir(parents=True)
            (source / 'Cargo.toml').write_text('[workspace]\nmembers = ["crate"]\n')
            (source / 'Cargo.lock').write_text('version = 4\n')
            (source / 'crate/Cargo.toml').write_text('[package]\nname = "crate"\n')
            (source / 'crate/build.rs').write_text('fn main() { std::process::exit(1) }')
            (source / 'crate/src/lib.rs').write_text('compile_error!("candidate");')
            (source / 'crate/data.json').write_text('{"secret": 1}')
            (source / '.cargo').mkdir()
            (source / '.cargo/config.toml').write_text('[build]\nrustflags = ["-Cfoo"]\n')
            cache.stub_workspace(source, stub)
            self.assertEqual((stub / 'crate/Cargo.toml').read_text(), '[package]\nname = "crate"\n')
            self.assertEqual((stub / 'crate/build.rs').read_bytes(), cache.STUB)
            self.assertEqual((stub / 'crate/src/lib.rs').read_bytes(), cache.STUB)
            self.assertEqual((stub / 'crate/data.json').read_bytes(), b'')
            self.assertFalse((stub / '.cargo').exists())

    def test_stub_workspace_keeps_real_source_of_patched_path_crates(self):
        # busbar-store-postgres patches postgres-protocol from vendor/; stubbing it broke
        # postgres-types (registry) in fill 3003.
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            source, stub = Path(directory) / 'src', Path(directory) / 'stub'
            (source / 'crate/src').mkdir(parents=True)
            (source / 'vendor/proto/src').mkdir(parents=True)
            (source / 'Cargo.toml').write_text('[workspace]\nmembers = ["crate"]\nexclude = ["vendor/proto"]\n'
                                               '[patch.crates-io]\nproto = { path = "vendor/proto" }\n')
            (source / 'Cargo.lock').write_text('version = 4\n')
            (source / 'crate/Cargo.toml').write_text('[package]\nname = "crate"\n')
            (source / 'crate/src/lib.rs').write_text('compile_error!("candidate");')
            (source / 'vendor/proto/Cargo.toml').write_text('[package]\nname = "proto"\n')
            (source / 'vendor/proto/src/lib.rs').write_text('pub mod types {}')
            (source / 'vendor/proto/src/data.bin').write_bytes(b'real')
            cache.stub_workspace(source, stub)
            self.assertEqual((stub / 'crate/src/lib.rs').read_bytes(), cache.STUB)
            self.assertEqual((stub / 'vendor/proto/src/lib.rs').read_text(), 'pub mod types {}')
            self.assertEqual((stub / 'vendor/proto/src/data.bin').read_bytes(), b'real')
            for bad in ('../outside', '/abs', '.cargo/x'):
                with self.subTest(path=bad), tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as other:
                    (source / 'Cargo.toml').write_text('[patch.crates-io]\nproto = { path = "%s" }\n' % bad)
                    with self.assertRaisesRegex(Exception, 'patched path escapes'):
                        cache.stub_workspace(source, Path(other) / 'stub')

    def test_rebuilt_dependency_units_ignore_members(self):
        text = ('   Compiling serde v1.0.0\n   Checking busbar-x v1.6.0 (/w/x)\n'
                '    Finished `dev` profile\n   Compiling busbar-contract v1.6.0 (https://github.com/GetBusbar/busbar?rev=a#a)\n')
        self.assertEqual(cache.rebuilt_dependency_units(text, {'busbar-x'}),
                         ['serde v1.0.0', 'busbar-contract v1.6.0'])



class ProducerShards(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[2]

    def test_only_server_named_parallel_instances_are_producers(self):
        for index in range(1, cache.PRODUCER_SHARDS + 1):
            self.assertEqual(cache.producer_shard(f'plugin-dependency-units {index}/{cache.PRODUCER_SHARDS}'),
                             index - 1)
        for name in (None, '', 'plugin-dependency-units', 'plugin-dependency-units 0/8',
                     'plugin-dependency-units 9/8', 'plugin-dependency-units 1/4',
                     'plugin-dependency-units 1/8 ', 'native-qualification', 'plugin-dependency-units: [1]'):
            with self.subTest(name=name):
                self.assertIsNone(cache.producer_shard(name))

    def test_every_pinned_product_has_exactly_one_stable_shard(self):
        products = json.loads((self.ROOT / 'scripts/ci-product-pins.json').read_text())['products']
        shards = {}
        for product in products:
            shard = cache.product_shard(product['repo'])
            self.assertIn(shard, range(cache.PRODUCER_SHARDS))
            self.assertEqual(shard, cache.product_shard(product['repo']))
            shards.setdefault(shard, []).append(product['repo'])
        self.assertEqual(sum(map(len, shards.values())), len(products))
        # A first fill stays bounded: no instance owns more than six products.
        self.assertLessEqual(max(map(len, shards.values())), 6)

    def test_pipeline_bootstrap_and_module_agree_on_producer_names(self):
        import native_ci_bootstrap
        yaml = (self.ROOT / 'ci/architecture-pipeline.yml').read_text()
        job = yaml.split('\nplugin-dependency-units:\n', 1)[1].split('\n\n', 1)[0]
        self.assertIn(f'\n  parallel: {cache.PRODUCER_SHARDS}\n', job)
        self.assertIn('\n  resource_group: plugin-dependency-units-$CI_NODE_INDEX\n', job)
        # One definition: the YAML names no job pattern; the bootstrap uses the module's.
        self.assertNotIn('plugin-dependency-units [1-8]', yaml)
        for name in ('plugin-dependency-units 1/8', 'plugin-dependency-units 8/8', 'plugin-dependency-units',
                     'plugin-dependency-units 9/8', 'plugin-dependency-units 1/7'):
            with self.subTest(name=name):
                self.assertEqual(native_ci_bootstrap.dependency_units_job(name),
                                 cache.producer_shard(name) is not None)

    def test_producer_builds_only_its_own_shard(self):
        products = [{'repo': 'busbar-plane-%02d' % index} for index in range(24)]
        seen = []
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            (root / 'scripts/ci-product-pins.json').write_text(json.dumps({'products': products}))
            q = SimpleNamespace(repository='GetBusbar/busbar', execution=SimpleNamespace(config={'image': IMAGE}),
                                receipt={'commit_ref_protected': True}, root=root, save=lambda: None,
                                policy=SimpleNamespace(data={'repositories': {
                                    'GetBusbar/' + p['repo']: {'language': 'rust'} for p in products}}))
            original = cache.produce_product
            cache.produce_product = lambda q, product, *a, **k: seen.append(product['repo']) or {}
            env = {'CI_JOB_NAME': 'plugin-dependency-units 3/8', 'CI_PIPELINE_SOURCE': 'push',
                   'CI_COMMIT_BRANCH': 'dev', 'CI_COMMIT_REF_PROTECTED': 'true'}
            try:
                with unittest.mock.patch.dict(os.environ, env):
                    cache.produce(q, registry=object())
                with unittest.mock.patch.dict(os.environ, env | {'CI_JOB_NAME': 'plugin-dependency-units'}):
                    with self.assertRaisesRegex(Exception, 'protected core dev push producer'):
                        cache.produce(q, registry=object())
                # An unprotected dev ref never produces.
                with unittest.mock.patch.dict(os.environ, env | {'CI_COMMIT_REF_PROTECTED': 'false'}):
                    with self.assertRaisesRegex(Exception, 'protected core dev push producer'):
                        cache.produce(q, registry=object())
            finally:
                cache.produce_product = original
        self.assertEqual(seen, [p['repo'] for p in products if cache.product_shard(p['repo']) == 2])
        self.assertEqual(q.receipt['dependency_units_shard'], {'index': 2, 'total': cache.PRODUCER_SHARDS})

    def test_a_producer_with_any_failed_product_fails_after_trying_all(self):
        # Fill 3002 reported pass while every product failed and nothing was published.
        products = [{'repo': 'busbar-plane-%02d' % index} for index in range(24)]
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            (root / 'scripts/ci-product-pins.json').write_text(json.dumps({'products': products}))
            q = SimpleNamespace(repository='GetBusbar/busbar', execution=SimpleNamespace(config={'image': IMAGE}),
                                receipt={'commit_ref_protected': True}, root=root, save=lambda: None,
                                policy=SimpleNamespace(data={'repositories': {
                                    'GetBusbar/' + p['repo']: {'language': 'rust'} for p in products}}))
            mine = [p['repo'] for p in products if cache.product_shard(p['repo']) == 2]
            seen = []
            def build(q, product, *a, **k):
                seen.append(product['repo'])
                if product['repo'] == mine[0]:
                    raise RuntimeError('dubious ownership')
                return {'repo': product['repo'], 'status': 'published'}
            env = {'CI_JOB_NAME': 'plugin-dependency-units 3/8', 'CI_PIPELINE_SOURCE': 'push',
                   'CI_COMMIT_BRANCH': 'dev', 'CI_COMMIT_REF_PROTECTED': 'true'}
            with unittest.mock.patch.object(cache, 'produce_product', build), \
                    unittest.mock.patch.dict(os.environ, env):
                with self.assertRaisesRegex(Exception, 'dependency units failed for ' + mine[0]):
                    cache.produce(q, registry=object())
        self.assertEqual(seen, mine)
        self.assertEqual(q.receipt['dependency_units_produced'][0]['status'], 'failed')

    def test_producer_kinds_are_exact(self):
        good = {'CI_PIPELINE_SOURCE': 'api', 'CI_COMMIT_BRANCH': cache.PINNED_REF, 'CI_COMMIT_REF_PROTECTED': 'true'}
        self.assertEqual(cache.producer_kind(good), 'pinned')
        self.assertEqual(cache.producer_kind({'CI_PIPELINE_SOURCE': 'push', 'CI_COMMIT_BRANCH': 'dev',
                                              'CI_COMMIT_REF_PROTECTED': 'true'}), 'dev')
        self.assertIsNone(cache.producer_kind({'CI_PIPELINE_SOURCE': 'push', 'CI_COMMIT_BRANCH': 'dev'}))
        for env in (dict(good, CI_COMMIT_REF_PROTECTED='false'), dict(good, CI_COMMIT_BRANCH='dev'),
                    dict(good, CI_COMMIT_BRANCH=cache.PINNED_REF + '/x'), dict(good, CI_PIPELINE_SOURCE='push'),
                    dict(good, CI_PIPELINE_SOURCE='schedule'), {'CI_PIPELINE_SOURCE': 'api', 'CI_COMMIT_BRANCH': 'dev'},
                    {'CI_PIPELINE_SOURCE': 'merge_request_event', 'CI_COMMIT_BRANCH': 'dev'}):
            with self.subTest(env=env):
                self.assertIsNone(cache.producer_kind(env))

    def test_pinned_producer_needs_the_constructor_dev_ancestry_proof(self):
        products = [{'repo': 'busbar-plane-%02d' % index} for index in range(24)]
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            (root / 'scripts/ci-product-pins.json').write_text(json.dumps({'products': products}))
            q = SimpleNamespace(repository='GetBusbar/busbar', execution=SimpleNamespace(config={'image': IMAGE}),
                                receipt={}, root=root, save=lambda: None,
                                policy=SimpleNamespace(data={'repositories': {
                                    'GetBusbar/' + p['repo']: {'language': 'rust'} for p in products}}))
            seen = []
            env = {'CI_JOB_NAME': 'plugin-dependency-units 3/8', 'CI_PIPELINE_SOURCE': 'api',
                   'CI_COMMIT_BRANCH': cache.PINNED_REF, 'CI_COMMIT_REF_PROTECTED': 'true'}
            with unittest.mock.patch.object(cache, 'produce_product',
                                            lambda q, product, *a, **k: seen.append(k['pinned']) or {}), \
                    unittest.mock.patch.dict(os.environ, env):
                with self.assertRaisesRegex(Exception, 'protected core dev push producer'):
                    cache.produce(q, registry=object())
                q.receipt.update(target_revision='f' * 40, commit_ref_protected=True)
                cache.produce(q, registry=object())
        self.assertTrue(seen and all(seen))
        self.assertEqual(q.receipt['dependency_units_producer_kind'], 'pinned')

    def test_pinned_identity_differs_from_dev_identity(self):
        dev = cache.identity(REPO, '0' * 64, IMAGE, ENV, wrapper='w')
        self.assertNotIn('pinned_producer', dev)
        pinned = cache.identity(REPO, '0' * 64, IMAGE, ENV, wrapper='w', pinned_commit=HOST)
        self.assertEqual(pinned, dict(dev, pinned_producer={'ref': cache.PINNED_REF, 'commit': HOST}))


class PipelineRules(unittest.TestCase):
    """Evaluate the actual YAML rules for the pipelines that matter here."""
    ROOT = Path(__file__).resolve().parents[2]

    @staticmethod
    def evaluate(expression, env):
        def value(match):
            return repr(env.get(match[1]))
        python = re.sub(r'=~ /((?:[^/\\]|\\.)*)/', lambda m: '=~ ' + repr(m[1]), expression)
        python = re.sub(r'\$([A-Z_]+)', value, python)
        python = re.sub(r"(\S+) =~ ('(?:[^'\\]|\\.)*')",
                        lambda m: f'(__import__("re").search({m[2]}, {m[1]} or "") is not None)', python)
        python = python.replace('&&', ' and ').replace('||', ' or ')
        return eval(python, {})

    @classmethod
    def text(cls):
        """The YAML with every `!reference [.rules, name]` spliced in, as GitLab does."""
        text = (cls.ROOT / 'ci/architecture-pipeline.yml').read_text()
        shared = text.split('\n.rules:\n', 1)[1].split('\n\n', 1)[0]
        sets = dict(re.findall(r'^  ([a-z-]+):\n((?:    .*\n?)*)', shared, re.M))

        def splice(match):
            return sets[match[1]].rstrip('\n')
        # GitLab resolves nested references (a set may reference another set).
        while True:
            spliced = re.sub(r'^    - !reference \[\.rules, ([a-z-]+)\]$', splice, text, flags=re.M)
            if spliced == text:
                return text
            text = spliced

    def jobs(self, env):
        text = self.text()
        blocks = re.split(r'^([A-Za-z][A-Za-z0-9_-]*):\s*$', text, flags=re.M)
        selected = set()
        for name, block in zip(blocks[1::2], blocks[2::2]):
            if name in ('workflow', 'stages') or '\n  rules:\n' not in block:
                continue
            rules = block.split('\n  rules:\n', 1)[1]
            rules = re.split(r'\n  [a-z]', rules, maxsplit=1)[0]
            for rule in re.findall(r"    - (?:if: '([^']*)'(?:\n      when: (\w+))?|when: (\w+))", rules):
                expression, when, bare = rule
                if expression and not self.evaluate(expression, env):
                    continue
                if (when or bare or 'on_success') != 'never':
                    selected.add(name)
                break
        return selected

    def test_owner_pinned_api_pipeline_runs_only_the_producer(self):
        env = {'CI_PIPELINE_SOURCE': 'api', 'CI_COMMIT_BRANCH': cache.PINNED_REF, 'CI_COMMIT_REF_PROTECTED': 'true',
               'CI_PROJECT_PATH': 'GetBusbar/busbar', 'CI_PROJECT_NAMESPACE': 'GetBusbar', 'CI_PROJECT_NAME': 'busbar'}
        self.assertEqual(self.jobs(env), {'plugin-dependency-units'})
        self.assertEqual(self.jobs(dict(env, CI_COMMIT_REF_PROTECTED='false')), set())
        self.assertNotIn('plugin-dependency-units', self.jobs(dict(env, CI_PROJECT_PATH='GetBusbar/busbar-x',
                                                                     CI_PROJECT_NAME='busbar-x')))

    CORE = {'CI_PROJECT_PATH': 'GetBusbar/busbar', 'CI_PROJECT_NAMESPACE': 'GetBusbar', 'CI_PROJECT_NAME': 'busbar'}
    PLUGIN = {'CI_PROJECT_PATH': 'GetBusbar/busbar-store-sqlite', 'CI_PROJECT_NAMESPACE': 'GetBusbar',
              'CI_PROJECT_NAME': 'busbar-store-sqlite'}

    def workflow(self, env):
        rules = self.text().split('\nworkflow:\n', 1)[1].split('\n\n', 1)[0]
        for expression, when, bare in re.findall(
                r"    - (?:if: '([^']*)'(?:\n      when: (\w+))?|when: (\w+))", rules):
            if not expression or self.evaluate(expression, env):
                return (when or bare or 'always') != 'never'
        return False

    def test_dev_pipelines_keep_their_jobs(self):
        env = dict(self.CORE, CI_PIPELINE_SOURCE='push', CI_COMMIT_BRANCH='dev', CI_COMMIT_REF_PROTECTED='true')
        dev = {'core-build', 'core-clippy', 'core-conformance'}
        self.assertEqual(self.jobs(env), dev | {'plugin-dependency-units', 'website-dev'})
        self.assertEqual(self.jobs(dict(env, CI_PIPELINE_SOURCE='api')), dev)
        self.assertEqual(self.jobs(dict(env, CI_PIPELINE_SOURCE='schedule')), {'security-scans'})
        # The dependency-unit producer needs the server's protected-ref marker.
        self.assertEqual(self.jobs(dict(env, CI_COMMIT_REF_PROTECTED='false')), dev | {'website-dev'})

    def test_core_tiers(self):
        mr = dict(self.CORE, CI_PIPELINE_SOURCE='merge_request_event', CI_MERGE_REQUEST_TARGET_BRANCH_NAME='dev',
                  CI_COMMIT_REF_PROTECTED='false')
        self.assertTrue(self.workflow(mr))
        self.assertEqual(self.jobs(mr), {'core-build', 'core-clippy', 'core-conformance'})
        qa = dict(self.CORE, CI_PIPELINE_SOURCE='push', CI_COMMIT_BRANCH='qa', CI_COMMIT_REF_PROTECTED='true')
        everything = {'core-build', 'core-clippy', 'core-conformance', 'core-conformance-debug',
                      'native-qualification', 'security-scans'}
        self.assertTrue(self.workflow(qa))
        # Only a qa push retains the certified evidence for main.
        self.assertEqual(self.jobs(qa), everything | {'qa-certification'})
        nightly = dict(self.CORE, CI_PIPELINE_SOURCE='schedule', CI_COMMIT_BRANCH='dev',
                       CI_COMMIT_REF_PROTECTED='true', CI_PIPELINE_SCHEDULE_DESCRIPTION='qa-nightly')
        self.assertEqual(self.jobs(nightly), everything)
        main = dict(qa, CI_COMMIT_BRANCH='main')
        self.assertTrue(self.workflow(main))
        self.assertEqual(self.jobs(main), {'release-certification'})
        # Unprotected qa/main refs run nothing; other branches start no pipeline.
        for env in (dict(qa, CI_COMMIT_REF_PROTECTED='false'), dict(main, CI_COMMIT_REF_PROTECTED='false')):
            self.assertFalse(self.workflow(env))
            self.assertEqual(self.jobs(env), set())
        self.assertFalse(self.workflow(dict(qa, CI_COMMIT_BRANCH='feature')))

    def test_plugins_keep_one_tier(self):
        for source in ('push', 'merge_request_event', 'api'):
            env = dict(self.PLUGIN, CI_PIPELINE_SOURCE=source, CI_COMMIT_BRANCH='dev',
                       CI_MERGE_REQUEST_TARGET_BRANCH_NAME='dev')
            expected = {'native-qualification', 'security-scans'} | ({'website-dev'} if source == 'push' else set())
            self.assertEqual(self.jobs(env), expected, source)
        self.assertEqual(self.jobs(dict(self.PLUGIN, CI_PIPELINE_SOURCE='push', CI_COMMIT_BRANCH='qa',
                                        CI_COMMIT_REF_PROTECTED='true')), set())


if __name__ == '__main__':
    unittest.main()

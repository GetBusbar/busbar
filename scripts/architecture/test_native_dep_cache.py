"""Trusted dependency units can only skip work: any doubt builds from scratch."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile
from types import SimpleNamespace
import unittest

import confinement_entry
import native_confinement
import native_dep_cache as cache

REPO = 'GetBusbar/busbar-transport-example'
IMAGE = 'sha256:' + 'a' * 64
ENV = {'RUSTUP_TOOLCHAIN': '1.98.0', 'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0',
       'RUSTC_WRAPPER': '', 'RUSTC_WORKSPACE_WRAPPER': ''}
PIPELINE = {'id': 77, 'ref': 'dev', 'sha': 'c' * 40, 'source': 'push'}


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

    def published(self, *, tamper=None, identity=None, pipelines=None, duplicate=False):
        work = Path(tempfile.mkdtemp(dir=self.base))
        target = write_target(work / 'producer-target')
        cache.strip_path_units(target, {'busbar-transport-example', 'busbar-transport-example-plugin'})
        archive = work / 'units.tar.gz'
        files = cache.pack(target, archive)
        data = archive.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        name = 'units-' + digest + '.tar.gz'
        manifest = {'schema': cache.SCHEMA, 'key': self.version, 'identity': identity or self.identity,
                    'archive': {'name': name, 'sha256': digest, 'bytes': len(data)}, 'files': files,
                    'product': {'repo': REPO.split('/')[1], 'commit': 'd' * 40},
                    'producer': {'pipeline_id': PIPELINE['id'], 'commit': PIPELINE['sha'], 'ref': 'dev'}}
        rows = [{'file_name': cache.MANIFEST, 'pipelines': pipelines or [PIPELINE]},
                {'file_name': name, 'file_sha256': digest, 'pipelines': pipelines or [PIPELINE]}]
        if duplicate:
            rows.append(dict(rows[1]))
        stored = tamper(data) if tamper else data
        return FakeRegistry({(self.version, cache.MANIFEST): cache.canonical(manifest), (self.version, name): stored},
                            package_files=rows, packages=[{'id': 9, 'name': cache.PACKAGE, 'version': self.version}])


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
        with self.assertRaises(PermissionError):
            (seed / 'debug/deps/libserde-0123456789abcdef.rlib').write_bytes(b'x')

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

    def test_rebuilt_dependency_units_ignore_members(self):
        text = ('   Compiling serde v1.0.0\n   Checking busbar-x v1.6.0 (/w/x)\n'
                '    Finished `dev` profile\n   Compiling busbar-contract v1.6.0 (https://github.com/GetBusbar/busbar?rev=a#a)\n')
        self.assertEqual(cache.rebuilt_dependency_units(text, {'busbar-x'}),
                         ['serde v1.0.0', 'busbar-contract v1.6.0'])


if __name__ == '__main__':
    unittest.main()

"""Trusted product test images can only skip a build: any doubt builds as before."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from check import Violation
import native
import native_dep_cache as units
import native_product_images as images
import product_artifacts

IMAGE = 'sha256:' + 'a' * 64
ENV = {'RUSTUP_TOOLCHAIN': '1.98.0', 'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0',
       'RUSTC_WRAPPER': '', 'RUSTC_WORKSPACE_WRAPPER': '', 'CARGO_INCREMENTAL': '0', 'CI': '1'}
PIPELINE = {'id': 77, 'ref': 'dev', 'sha': 'c' * 40, 'source': 'push'}
ROW = {'repo': 'busbar-hook-fixture', 'package': 'busbar-hook-fixture-plugin', 'commit': 'd' * 40,
       'image': 'libbusbar_hook_fixture_plugin.so', 'lock_sha256': 'e' * 64, 'declares': 'declares.json',
       'kind': 'hook', 'alias': 'fixture', 'url': 'https://github.com/GetBusbar/busbar-hook-fixture'}
VECTOR = {'sdk': 'b' * 40, 'products': [ROW]}
BYTES = b'\x7fELF trusted fixture image'


class Registry:
    package = images.PACKAGE

    def __init__(self):
        self.files, self.rows, self.uploads = {}, {}, []

    def read(self, version, name, limit):
        if (version, name) not in self.files:
            raise FileNotFoundError(name)
        return self.files[version, name]

    def download(self, version, name, destination, size, digest):
        data = self.files[version, name]
        destination.write_bytes(data)
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise units.Unavailable('dependency archive digest differs from its manifest')

    def json(self, path):
        version = [part.split('=')[1] for part in path.split('&') if part.startswith('package_version=')]
        if path.startswith('/packages?'):
            return [{'id': 5, 'name': images.PACKAGE, 'version': version[0]}] if version else []
        return self.rows.get('last', [])

    def upload(self, version, name, path):
        self.uploads.append(name)
        self.files[version, name] = path.read_bytes()
        rows = self.rows.setdefault('last', [])
        rows.append({'file_name': name, 'file_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                     'pipelines': [PIPELINE]})


class Fixture(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(directory.cleanup)
        base = Path(directory.name).resolve()
        self.addCleanup(lambda: [os.chmod(d, 0o755) for d, _, _ in os.walk(base)])
        control = base / 'boundary-1-2'
        roots = {name: control / name for name in ('candidate', 'harness')}
        roots.update(checkout=base / 'checkout', trusted=base / 'trusted')
        for path in roots.values():
            path.mkdir(parents=True)
        (roots['checkout'] / '.cargo').mkdir()
        (roots['checkout'] / '.cargo/config.toml').write_text('[env]\nAWS_LC_SYS_STATIC = "1"\n')
        (roots['trusted'] / 'scripts/architecture').mkdir(parents=True)
        (roots['trusted'] / 'scripts/architecture/product_artifacts.py').write_text('# builder\n')
        self.target = roots['candidate'] / 'target'
        self.image_path = self.target / 'debug' / ROW['image']
        self.q = SimpleNamespace(receipt={'source': 'c' * 40}, control=control, root=roots['checkout'],
                                 trusted=roots['trusted'], work=roots['candidate'],
                                 env=dict(ENV, CARGO_TARGET_DIR=str(self.target),
                                          MODERNCI_CACHE_DIR=str(roots['candidate'] / 'cache')), save=lambda: None,
                                 execution=SimpleNamespace(config={'image': IMAGE, 'uid': os.geteuid(),
                                                                   'isolation': {'uid_map': [0, 0, 1]}}, roots=roots,
                                                           dependency_seed=None, product_images=None))
        self.items = [{'product': ROW, 'image': str(self.image_path)}]
        patcher = patch('native_product_images.planned', return_value=self.items)
        patcher.start()
        self.addCleanup(patcher.stop)

    def publish(self, registry, data=BYTES):
        """What a producer shard uploads, built by the fake confined step."""
        built = self.q.work / 'product-images-target/debug' / ROW['image']
        def run(name, argv, cwd=None):
            self.assertEqual(cwd, self.q.root)
            self.assertIn('--image-only', argv)
            built.parent.mkdir(parents=True, exist_ok=True)
            built.write_bytes(data)
            out = self.q.control / (name + '.stdout')
            out.write_text(str(built) + '\n')
            return out
        self.q.run = run
        with patch.dict(os.environ, {'CI_PIPELINE_ID': '77', 'CI_JOB_ID': '9', 'CI_COMMIT_SHA': 'c' * 40,
                                     'CI_COMMIT_BRANCH': 'dev'}):
            return images.produce_image(self.q, ROW, VECTOR, registry)


class Identity(Fixture):
    def test_key_covers_every_build_input(self):
        base = images.job_identity(self.q, ROW, VECTOR['sdk'])
        variants = [dict(ROW, commit='f' * 40), dict(ROW, lock_sha256='0' * 64), dict(ROW, image='libother.so')]
        keys = {units.key(base)} | {units.key(images.job_identity(self.q, row, VECTOR['sdk'])) for row in variants}
        keys.add(units.key(images.job_identity(self.q, ROW, '1' * 40)))
        self.q.env['RUSTFLAGS'] = '-Cdebuginfo=1'
        keys.add(units.key(images.job_identity(self.q, ROW, VECTOR['sdk'])))
        del self.q.env['RUSTFLAGS']
        (self.q.root / '.cargo/config.toml').write_text('[build]\nrustflags = ["-Copt-level=1"]\n')
        keys.add(units.key(images.job_identity(self.q, ROW, VECTOR['sdk'])))
        (self.q.trusted / 'scripts/architecture/product_artifacts.py').write_text('# other builder\n')
        keys.add(units.key(images.job_identity(self.q, ROW, VECTOR['sdk'])))
        self.q.execution.config['image'] = 'sha256:' + '9' * 64
        keys.add(units.key(images.job_identity(self.q, ROW, VECTOR['sdk'])))
        self.assertEqual(len(keys), 9)

    def test_indirect_or_ancestor_cargo_configuration_is_a_miss(self):
        config = self.q.root / '.cargo/config.toml'
        config.unlink()
        config.symlink_to(self.q.root / 'elsewhere.toml')
        with self.assertRaises(units.Unavailable):
            images.cargo_configuration(self.q.root)
        nested = self.q.root / 'nested'
        nested.mkdir()
        with self.assertRaisesRegex(units.Unavailable, 'above the build root'):
            images.cargo_configuration(nested)

    def test_producer_step_gets_the_unoptimized_budget(self):
        scheduling = {'build_jobs': 1, 'unoptimized_build_jobs': 3}
        argv = ['python3', '/t/scripts/architecture/product_artifacts.py', '--root', '/r', '--image-only', 'x']
        self.assertEqual(native.step_build_jobs('product-image-x', argv, scheduling), 3)
        self.assertEqual(native.step_build_jobs('product-image-x', argv[:-2], scheduling), 1)
        self.assertEqual(native.step_build_jobs('other', argv, scheduling), 1)


class Restore(Fixture):
    def test_published_image_restores_read_only_and_verifies_after_the_step(self):
        registry = Registry()
        self.assertEqual(self.publish(registry)['status'], 'published')
        self.assertEqual(registry.uploads[-1], units.MANIFEST)
        index = images.restore(self.q, VECTOR, 'c' * 40, registry=registry)
        entry = index[ROW['repo']]
        self.assertEqual(entry['sha256'], hashlib.sha256(BYTES).hexdigest())
        staged = self.q.execution.product_images
        self.assertEqual((staged / entry['file']).read_bytes(), BYTES)
        self.assertFalse(os.access(staged / entry['file'], os.W_OK))
        self.assertEqual(json.loads((staged / 'index.json').read_text()), index)
        self.assertEqual(self.q.receipt['product_images']['status'], 'hit')
        # The trusted script copies it to Cargo's own output path.
        product_artifacts.install_prebuilt(entry, ROW, self.image_path, root=staged)
        self.assertEqual(self.image_path.read_bytes(), BYTES)
        images.discard(self.q)
        self.assertIsNone(self.q.execution.product_images)
        images.verify(self.q, index, self.items)
        self.image_path.write_bytes(b'tampered')
        with self.assertRaisesRegex(Violation, 'changed during product preparation'):
            images.verify(self.q, index, self.items)

    def test_absent_image_builds(self):
        index = images.restore(self.q, VECTOR, 'c' * 40, registry=Registry())
        self.assertEqual(index, {})
        self.assertEqual(self.q.receipt['product_images']['products'][ROW['repo']]['status'], 'miss')
        self.assertEqual(self.q.receipt['product_images']['status'], 'miss')

    def test_changed_input_identity_never_downloads(self):
        registry = Registry()
        self.publish(registry)
        self.q.env['CARGO_PROFILE_DEV_DEBUG'] = '1'
        self.assertEqual(images.restore(self.q, VECTOR, 'c' * 40, registry=registry), {})
        self.assertEqual(self.q.receipt['product_images']['products'][ROW['repo']]['status'], 'miss')

    def test_tampered_archive_or_foreign_pipeline_builds(self):
        for tamper in ('archive', 'pipeline'):
            with self.subTest(tamper=tamper):
                registry = Registry()
                self.publish(registry)
                if tamper == 'archive':
                    name = next(n for (_, n) in registry.files if n.startswith('image-'))
                    version = next(v for (v, n) in registry.files if n == name)
                    registry.files[version, name] = registry.files[version, name][:-1] + b'x'
                else:
                    for row in registry.rows['last']:
                        row['pipelines'] = [dict(PIPELINE, ref='feature')]
                self.assertEqual(images.restore(self.q, VECTOR, 'c' * 40, registry=registry), {})
                self.assertEqual(self.q.receipt['product_images']['products'][ROW['repo']]['status'], 'fallback')
                images.discard(self.q)

    def test_unconfined_runs_restore_nothing(self):
        self.q.execution = None
        self.assertEqual(images.restore(self.q, VECTOR, 'c' * 40, registry=Registry()), {})


class TrustedScript(Fixture):
    def staged(self, data=BYTES, **changes):
        root = self.q.control / 'staged'
        (root / ROW['repo']).mkdir(parents=True)
        (root / ROW['repo'] / ROW['image']).write_bytes(data)
        entry = {'commit': ROW['commit'], 'image': ROW['image'], 'lock_sha256': ROW['lock_sha256'],
                 'file': ROW['repo'] + '/' + ROW['image'], 'sha256': hashlib.sha256(BYTES).hexdigest()}
        entry.update(changes)
        return root, entry

    def test_digest_pin_or_path_mismatch_refuses(self):
        for data, changes in ((b'other', {}), (BYTES, {'commit': 'f' * 40}), (BYTES, {'lock_sha256': '1' * 64}),
                              (BYTES, {'file': '../escape'})):
            with self.subTest(changes=changes):
                root, entry = self.staged(data, **changes)
                with self.assertRaises(Violation):
                    product_artifacts.install_prebuilt(entry, ROW, self.image_path, root=root)
                os.system('rm -rf ' + str(root))

    def test_build_skips_cargo_only_for_indexed_products(self):
        root, entry = self.staged()
        (root / 'index.json').write_text(json.dumps({ROW['repo']: entry}))
        self.assertEqual(product_artifacts.prebuilt_images(root), {ROW['repo']: entry})
        self.assertEqual(product_artifacts.prebuilt_images(root / 'absent'), {})
        item = {'product': ROW, 'checkout': Path('/src'), 'dropped_in': True}
        self.assertEqual(product_artifacts.image_argv(item, Path('/t')),
                         ['cargo', '+1.98.0', 'build', '--locked', '--manifest-path', '/src/Cargo.toml',
                          '-p', ROW['package'], '--lib', '--target-dir', '/t', '--features', 'dropped-in'])


if __name__ == '__main__':
    unittest.main()

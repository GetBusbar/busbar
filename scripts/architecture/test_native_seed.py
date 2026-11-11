"""Actual per-job collector witness, opt-in on an existing public-tools image."""

import json
import os
from types import SimpleNamespace
import unittest
from pathlib import Path

from test_native_confinement import Fixture
from native_seed import prepare, manifest_snapshot


class ManifestGraph(Fixture, unittest.TestCase):
    def test_original_graph_keeps_patches_without_staging_candidate_code_or_cargo_config(self):
        source = self.roots['checkout']
        manifest = '[workspace]\n[patch.crates-io]\nexample = { git = "https://github.com/example/crate", rev = "' + 'a' * 40 + '" }\n'
        (source / 'Cargo.toml').write_text(manifest)
        (source / '.cargo').mkdir()
        (source / '.cargo/config.toml').write_text('[build]\nrustc-wrapper="steal"\n')
        (source / 'build.rs').write_text('panic!("must not execute");')
        (source / 'src').mkdir()
        (source / 'src/lib.rs').write_text('compile_error!("not collector input");')
        output = self.control / 'graph'
        manifest_snapshot(source, output)
        self.assertEqual((output / 'Cargo.toml').read_text(), manifest)
        self.assertEqual((output / 'build.rs').read_bytes(), b'')
        self.assertEqual((output / 'src/lib.rs').read_bytes(), b'')
        self.assertFalse((output / '.cargo').exists())
        self.assertFalse((output / '.git').exists())


@unittest.skipUnless(os.environ.get('BUSBAR_NATIVE_TOOLS_TEST_CONFIG'), 'requires existing pinned public native tools')
class JobSeed(Fixture, unittest.TestCase):
    def test_seed_is_job_bound_and_does_not_copy_the_images_product_cache(self):
        self.config = json.loads(Path(os.environ['BUSBAR_NATIVE_TOOLS_TEST_CONFIG']).read_text())
        root, work = self.roots['checkout'], self.roots['candidate']
        (root / 'scripts').mkdir()
        (root / 'scripts/ci-product-pins.json').write_text('{"products":[]}\n')
        (root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel="1.98.0"\n')
        (root / 'Cargo.toml').write_text('[workspace]\n[package]\nname="private-job-fixture"\nversion="0.0.0"\nedition="2021"\n')
        (root / 'Cargo.lock').write_text('version=4\n[[package]]\nname="private-job-fixture"\nversion="0.0.0"\n')
        (root / 'src').mkdir()
        (root / 'src/lib.rs').write_text('#[test] fn actual() { assert_eq!(2 + 2, 4); }\n')
        evidence = self.control / 'evidence'
        evidence.mkdir()
        q = SimpleNamespace(execution=self.execution(), root=root, work=work, control=self.control,
            evidence=evidence, host=lambda: root, sdk=lambda: root, repository='BusbarInc/private-fixture',
            receipt={'source': 'a' * 40}, save=lambda: None)
        prepare(q)
        self.assertEqual(q.receipt['dependency_seed']['repository'], q.repository)
        self.assertFalse(q.receipt['dependency_seed']['shared_image'])
        self.assertTrue((q.execution.dependency_seed / 'advisory-dbs').is_dir())
        self.assertFalse((q.execution.dependency_seed / 'git').exists())
        self.assertFalse((q.execution.dependency_seed / 'registry').exists())
        result = q.execution.run(['cargo', 'test', '--locked', '--offline'], cwd=root,
                                 env={'RUSTUP_TOOLCHAIN': '1.98.0'}, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(q.execution.observations[-1]['dependency_seed_sha256'],
                         q.receipt['dependency_seed']['manifest_sha256'])


if __name__ == '__main__':
    unittest.main()

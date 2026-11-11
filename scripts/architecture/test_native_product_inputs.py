import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from check import Violation
from native_product_inputs import ProductInputs, load_product_inputs
from product_artifacts import blob
from test_product_artifacts import ArtifactFixture


class ProductInputsTests(ArtifactFixture):
    def setUp(self):
        super().setUp()
        _, self.values = self.plan()
        for value in self.values.values():
            if value != "{}":
                path = Path(value)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture")
        self.file = Path(self.values["BUSBAR_TEST_FIXTURE_CDYLIB"])
        self.path = self.root / "cache/ci-product-inputs" / self.revision / "environment.json"
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps(self.values))
        self.stdout = self.root / "stdout"
        self.stdout.write_text(str(self.path) + "\n")

    def load(self):
        return load_product_inputs(self.stdout, self.root, self.policy, self.vector, self.revision)

    def test_exact_independently_declared_data_map_passes(self):
        result = self.load()
        self.assertIsInstance(result, ProductInputs)
        self.assertEqual(result, self.values)

    def test_controller_reads_remapped_canonical_bare_objects(self):
        row = self.vector['products'][0]
        source = self.canonical / row['repo']
        checkout = self.root / 'owner-checkout'
        source.rename(checkout)
        self.git(self.root, 'clone', '--bare', '--quiet', str(checkout), str(source))
        # Git's ownership test switch reaches the same check as a controller
        # reading a bare repository reowned to the remapped candidate UID.
        with patch.dict(os.environ, {'GIT_TEST_ASSUME_DIFFERENT_OWNER': '1',
                                    'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1'}):
            refusal = subprocess.run(['git', '-C', str(source), 'ls-tree', row['commit'], '--', 'Cargo.lock'],
                                     capture_output=True)
            self.assertEqual(refusal.returncode, 128)
            self.assertIn(b'dubious ownership', refusal.stderr)
            self.assertEqual(self.load(), self.values)
            with self.assertRaises(Violation):
                blob(source, row['commit'], 'Cargo.lock', 4096)
            lock_hash = row['lock_sha256']
            row['lock_sha256'] = '0' * 64
            with self.assertRaisesRegex(Violation, 'lock differs'):
                self.load()
            row['lock_sha256'] = lock_hash
            row['commit'] = '0' * 40
            with self.assertRaises(Violation):
                self.load()
        self.assertEqual(self.git(source, 'config', '--local', '--get-regexp', 'core.bare'), 'core.bare true')
        setting = subprocess.run(['git', '-C', str(source), 'config', '--local', '--get', 'safe.directory'],
                                 capture_output=True)
        self.assertEqual(setting.returncode, 1)

    def test_shell_and_undeclared_environment_refuse(self):
        self.path.write_text("export PATH=$(touch /must-not-execute)")
        with self.assertRaises(ValueError):
            self.load()
        for key in ("PATH", "HOME", "BUSBAR_CHECKOUT", "LD_PRELOAD", "GIT_CONFIG_COUNT",
                    "BUSBAR_TEST_UNDECLARED_CDYLIB"):
            self.path.write_text(json.dumps({**self.values, key: "untrusted"}))
            with self.subTest(key=key), self.assertRaises(Violation):
                self.load()

    def test_missing_duplicate_wrong_settings_or_other_output_paths_refuse(self):
        missing = dict(self.values)
        missing.pop("BUSBAR_TEST_FIXTURE_CDYLIB")
        other = self.root / "target/other.so"
        other.write_bytes(b"fixture")
        for data in [missing, {**self.values, "BUSBAR_FIXTURE_TEST_STORE_SETTINGS": '{"other":1}'},
                     {**self.values, "BUSBAR_TEST_FIXTURE_CDYLIB": str(other)},
                     {**self.values, "BUSBAR_TEST_FIXTURE_CDYLIB": "/etc/passwd"}]:
            self.path.write_text(json.dumps(data))
            with self.assertRaises(Violation):
                self.load()
        self.path.write_text('{"a":1,"a":2}')
        with self.assertRaises(Violation):
            self.load()

    def test_symlink_file_and_parent_refuse(self):
        self.file.unlink()
        self.file.symlink_to("/etc/passwd")
        with self.assertRaises(Violation):
            self.load()
        self.file.unlink()
        other = self.root / "alternate"
        self.file.parent.rename(other)
        self.file.parent.symlink_to(other, target_is_directory=True)
        with self.assertRaises(Violation):
            self.load()


if __name__ == "__main__":
    unittest.main()

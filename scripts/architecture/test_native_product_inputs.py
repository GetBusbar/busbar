import json
from pathlib import Path
import tempfile
import unittest

from check import Violation
from native_product_inputs import PATH_KEYS, SETTINGS, load_product_inputs


class ProductInputsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "target").mkdir()
        (self.root / "cache").mkdir()
        self.file = self.root / "target/plugin.so"
        self.file.write_bytes(b"fixture")
        self.path = self.root / "cache/environment.json"
        self.values = {key: str(self.file) for key in PATH_KEYS} | {SETTINGS: "{}"}
        self.path.write_text(json.dumps(self.values))
        self.stdout = self.root / "stdout"
        self.stdout.write_text(str(self.path) + "\n")

    def test_exact_data_only_input_map_passes(self):
        self.assertEqual(load_product_inputs(self.stdout, self.root), self.values)

    def test_shell_input_or_arbitrary_environment_override_refuses(self):
        self.path.write_text("export PATH=$(touch /must-not-execute)")
        with self.assertRaises(ValueError):
            load_product_inputs(self.stdout, self.root)
        for key in (
            "PATH",
            "HOME",
            "BUSBAR_CHECKOUT",
            "LD_PRELOAD",
            "GIT_CONFIG_COUNT",
        ):
            self.path.write_text(json.dumps({**self.values, key: "untrusted"}))
            with self.subTest(key=key), self.assertRaises(Violation):
                load_product_inputs(self.stdout, self.root)

    def test_missing_duplicate_and_external_paths_refuse(self):
        data = dict(self.values)
        data.pop(next(iter(PATH_KEYS)))
        self.path.write_text(json.dumps(data))
        with self.assertRaises(Violation):
            load_product_inputs(self.stdout, self.root)
        self.path.write_text('{"a":1,"a":2}')
        with self.assertRaises(Violation):
            load_product_inputs(self.stdout, self.root)
        self.path.write_text(
            json.dumps({**self.values, next(iter(PATH_KEYS)): "/etc/passwd"})
        )
        with self.assertRaises(Violation):
            load_product_inputs(self.stdout, self.root)

    def test_symlink_file_and_parent_refuse(self):
        self.file.unlink()
        self.file.symlink_to("/etc/passwd")
        with self.assertRaises(Violation):
            load_product_inputs(self.stdout, self.root)
        self.file.unlink()
        self.file.write_bytes(b"fixture")
        link = self.root / "target/link"
        link.symlink_to(self.root / "target", target_is_directory=True)
        self.values[next(iter(PATH_KEYS))] = str(link / self.file.name)
        self.path.write_text(json.dumps(self.values))
        with self.assertRaises(Violation):
            load_product_inputs(self.stdout, self.root)


if __name__ == "__main__":
    unittest.main()

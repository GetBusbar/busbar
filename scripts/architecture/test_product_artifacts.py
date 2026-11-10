"""Focused owner-metadata and exact-vector artifact regressions."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from check import Violation
from product_artifacts import blob, build, declarations, plan


class ArtifactFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.canonical = self.root / "canonical-inputs"
        self.canonical.mkdir()
        self.revision = "a" * 40
        self.policy = SimpleNamespace(data={"repositories": {
            "GetBusbar/busbar-fixture-c": {"private": False, "language": "c"}
        }})
        self.vector = {"sdk": "b" * 40, "products": [], "c_witness": {
            "repo": "busbar-fixture-c", "sdk": "b" * 40, "commit": "c" * 40,
            "url": "https://github.com/GetBusbar/busbar-fixture-c"}}
        self.owner({"cdylib": ["BUSBAR_TEST_FIXTURE_CDYLIB"],
                    "empty-settings": ["BUSBAR_FIXTURE_TEST_STORE_SETTINGS"]})

    def git(self, source, *args):
        return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "user.name=Fixture",
            "-c", "user.email=fixture@example.invalid", "-C", str(source), *args], stderr=subprocess.DEVNULL).decode().strip()

    def owner(self, metadata, name="fixture", image=None):
        repo = "busbar-hook-" + name
        source = self.canonical / repo
        source.mkdir()
        (source / "wrapper").mkdir()
        package = repo + "-plugin"
        library = image or package.replace("-", "_")
        text = '[package]\nname = ' + json.dumps(package) + '\nversion = "0.0.0"\n'
        text += '[lib]\ncrate-type = ["cdylib"]\nname = ' + json.dumps(library) + '\n'
        text += '[features]\ndropped-in = []\n[package.metadata.busbar.test-artifacts]\n'
        text += ''.join(key + ' = ' + json.dumps(value) + '\n' for key, value in metadata.items())
        (source / "wrapper/Cargo.toml").write_text(text)
        (source / "Cargo.lock").write_text('version = 4\n')
        (source / "declares.json").write_text('{}\n')
        self.git(source, "init", "-q")
        self.git(source, "add", ".")
        self.git(source, "commit", "-qm", "Fixture owner")
        row = {"repo": repo, "package": package, "commit": self.git(source, "rev-parse", "HEAD"),
               "url": "https://github.com/GetBusbar/" + repo, "kind": "hook", "alias": name,
               "image": "lib" + library + ".so", "declares": "declares.json",
               "lock_sha256": hashlib.sha256((source / "Cargo.lock").read_bytes()).hexdigest()}
        self.policy.data["repositories"]["GetBusbar/" + repo] = {
            "private": False, "kind": "hook", "packages": [
                {"name": package, "role": "wrapper", "manifest": "wrapper/Cargo.toml"}]}
        self.vector["products"].append(row)
        return source, row

    def plan(self):
        return plan(self.policy, self.vector, lambda row: self.canonical / row["repo"],
                    self.root / "target", self.root / "cache", self.revision)


class OwnerArtifacts(ArtifactFixture):
    def test_new_owner_is_data_and_uses_fixed_build_and_output_recipe(self):
        products, values = self.plan()
        self.assertEqual(set(values), {"BUSBAR_TEST_FIXTURE_CDYLIB", "BUSBAR_FIXTURE_TEST_STORE_SETTINGS"})
        self.assertTrue(products[0]["dropped_in"])
        self.assertEqual(values["BUSBAR_FIXTURE_TEST_STORE_SETTINGS"], "{}")
        self.assertTrue(values["BUSBAR_TEST_FIXTURE_CDYLIB"].endswith(products[0]["image"].split('/')[-1]))
        (self.root / "scripts").mkdir()
        (self.root / "scripts/ci-product-pins.json").write_text(json.dumps(self.vector))
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            image = Path(products[0]["image"])
            image.parent.mkdir(parents=True, exist_ok=True)
            image.write_bytes(b"fixture")
            return subprocess.CompletedProcess(argv, 0)
        def checkout(row, path):
            path.mkdir(parents=True)
        with patch("product_artifacts.git", return_value=self.revision.encode()), \
             patch("product_artifacts.plan", return_value=(products, values)), \
             patch("product_artifacts.checkout_product", side_effect=checkout), \
             patch("product_artifacts.subprocess.run", side_effect=run):
            output = build(self.root, self.root / "target", self.root / "cache", self.policy)
        self.assertEqual(json.loads(output.read_text()), values)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:4], ["cargo", "+1.98.0", "build", "--locked"])
        self.assertEqual(calls[0][-2:], ["--features", "dropped-in"])

    def test_unknown_keys_commands_paths_wrong_types_and_collisions_refuse(self):
        for value in [{"command": ["touch /bad"]}, {"path": ["/bad"]},
                      {"cdylib": ["LD_PRELOAD"]}, {"cdylib": ["BUSBAR_CHECKOUT"]},
                      {"cdylib": ["BUSBAR_TEST_FIXTURE_MANIFEST"]},
                      {"cdylib": ["BUSBAR_TEST_FIXTURE_CDYLIB"] * 2},
                      {"cdylib": "BUSBAR_TEST_FIXTURE_CDYLIB"},
                      {"cdylib": ["BUSBAR_TEST_FIXTURE_CDYLIB"] * 17}]:
            with self.subTest(value=value), self.assertRaises(Violation):
                declarations(value)
        self.owner({"cdylib": ["BUSBAR_TEST_FIXTURE_CDYLIB"]}, "second")
        with self.assertRaisesRegex(Violation, "collide"):
            self.plan()

    def test_output_image_collisions_refuse(self):
        self.owner({"cdylib": ["BUSBAR_TEST_SECOND_CDYLIB"]}, "second", "busbar_hook_fixture_plugin")
        with self.assertRaisesRegex(Violation, "image path"):
            self.plan()

    def test_unknown_repo_pin_wrapper_lock_and_declares_paths_refuse(self):
        original = copy.deepcopy(self.vector)
        for field, value in [("repo", "unknown"), ("commit", "dev"), ("commit", "0" * 40), ("package", "not-the-wrapper"),
                             ("lock_sha256", "0" * 64), ("declares", "../private.json"),
                             ("declares", "/private.json"), ("image", "../../elsewhere.so")]:
            self.vector = copy.deepcopy(original)
            self.vector["products"][0][field] = value
            with self.subTest(field=field), self.assertRaises(Violation):
                self.plan()

    def test_metadata_is_read_from_exact_commit_and_symlinks_refuse(self):
        row = self.vector["products"][0]
        source = self.canonical / row["repo"]
        path = source / "wrapper/Cargo.toml"
        path.write_text('candidate working-tree corruption')
        self.plan()  # The canonical commit, not the mutable working-tree bytes.
        path.unlink()
        path.symlink_to("../declares.json")
        self.git(source, "add", ".")
        self.git(source, "commit", "-qm", "Indirect metadata")
        row["commit"] = self.git(source, "rev-parse", "HEAD")
        with self.assertRaisesRegex(Violation, "regular Git blob"):
            self.plan()

    def test_packed_bindings_and_blob_bounds(self):
        _, row = self.owner({"manifest": ["BUSBAR_TEST_SECOND_MANIFEST"],
                             "declares": ["BUSBAR_TEST_SECOND_DECLARES"]}, "second")
        _, values = self.plan()
        self.assertTrue(values["BUSBAR_TEST_SECOND_DECLARES"].endswith(row["commit"] + "/declares.json"))
        with self.assertRaisesRegex(Violation, "exceeds limit"):
            blob(self.canonical / row["repo"], row["commit"], "wrapper/Cargo.toml", 1)

    def test_pack_recipe_extracts_only_one_regular_manifest_without_signing_credentials(self):
        self.owner({"manifest": ["BUSBAR_TEST_SECOND_MANIFEST"],
                    "declares": ["BUSBAR_TEST_SECOND_DECLARES"]}, "second")
        products, values = self.plan()
        (self.root / "scripts").mkdir()
        (self.root / "scripts/ci-product-pins.json").write_text(json.dumps(self.vector))
        for mode in ("regular", "symlink", "duplicate"):
            def run(argv, **kwargs):
                if argv[0].endswith("busbar-plugin-pack"):
                    self.assertNotIn("BUSBAR_SIGN_KEY", kwargs["env"])
                    archive = Path(argv[argv.index("--out") + 1])
                    with tarfile.open(archive, "w:gz") as bundle:
                        for _ in range(2 if mode == "duplicate" else 1):
                            info = tarfile.TarInfo("manifest.json")
                            if mode == "symlink":
                                info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
                                bundle.addfile(info)
                            else:
                                info.size = 2
                                bundle.addfile(info, io.BytesIO(b"{}"))
                else:
                    for item in products:
                        image = Path(item["image"])
                        image.parent.mkdir(parents=True, exist_ok=True)
                        image.write_bytes(b"fixture")
                return subprocess.CompletedProcess(argv, 0)
            def checkout(row, path):
                path.mkdir(parents=True, exist_ok=True)
                (path / row["declares"]).write_text("{}")
            with self.subTest(mode=mode), \
                 patch("product_artifacts.git", return_value=self.revision.encode()), \
                 patch("product_artifacts.plan", return_value=(products, values)), \
                 patch("product_artifacts.checkout_product", side_effect=checkout), \
                 patch("product_artifacts.subprocess.run", side_effect=run), \
                 patch.dict(os.environ, {"BUSBAR_SIGN_KEY": "fixture"}):
                if mode == "regular":
                    build(self.root, self.root / "target", self.root / "cache", self.policy)
                    self.assertEqual(Path(values["BUSBAR_TEST_SECOND_MANIFEST"]).read_text(), "{}")
                else:
                    with self.assertRaises(Violation):
                        build(self.root, self.root / "target", self.root / "cache", self.policy)


if __name__ == "__main__":
    unittest.main()

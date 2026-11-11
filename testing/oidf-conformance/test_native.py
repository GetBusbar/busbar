# SPDX-License-Identifier: Apache-2.0
"""Targeted native OIDF staging and process-adapter checks; no complete suite run."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import oidf

spec = importlib.util.spec_from_file_location("stage_oidf", Path(__file__).resolve().parents[2]
                                            / "scripts/architecture/stage_oidf_conformance.py")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class NativeAdapter(unittest.TestCase):
    def test_native_missing_bundle_never_fetches_or_invokes_docker(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.dict(os.environ, {"CONFORMANCE_CAPABILITIES": "/measured-capabilities",
                                            "MODERNCI_CACHE_DIR": directory}), \
                mock.patch.object(oidf, "NATIVE_BUNDLE", Path(directory) / "missing"), \
                mock.patch.object(oidf.shutil, "which", return_value="/tool"), \
                mock.patch.object(oidf, "suite_source") as source, \
                mock.patch.object(oidf, "compose_command") as compose, \
                mock.patch.object(oidf, "run") as run:
            with self.assertRaisesRegex(oidf.Refused, "native OIDF bundle is unavailable"):
                oidf.run_all(directory)
            source.assert_not_called()
            compose.assert_not_called()
            run.assert_not_called()

    def test_staged_plugin_must_match_distribution_revision(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(oidf, "OIDC_BUNDLE", Path(directory) / "source"):
            oidf.OIDC_BUNDLE.mkdir()
            pin = {"url": "https://github.com/GetBusbar/busbar-auth-oidc", "rev": "a" * 40}
            (oidf.OIDC_BUNDLE / "source-identity.json").write_text(json.dumps(pin))
            (oidf.OIDC_BUNDLE / "Cargo.toml").write_text("[package]\n")
            output = Path(directory) / "output"
            self.assertTrue(oidf.staged_oidc_source(pin, output))
            self.assertEqual((output / "Cargo.toml").read_text(), "[package]\n")
            with self.assertRaisesRegex(oidf.Refused, "revision differs"):
                oidf.staged_oidc_source({**pin, "rev": "b" * 40}, output)

    def test_native_runner_preserves_official_plan_and_exports(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(oidf, "native_command", side_effect=lambda *args: list(args)) as command, \
                mock.patch.object(oidf, "run", return_value=0) as run:
            suite = oidf.NativeSuite(directory, "pki", "official-source", "wheels", "rig.log")
            leg = Path(directory) / "subject"
            leg.mkdir()
            (leg / "runner.log").write_text("official output")
            rc, log = suite.runner(str(leg), [oidf.PLAN, "/work/subject/plan-config.json"])
            self.assertEqual((rc, log), (0, "official output"))
            args = command.call_args.args
            self.assertEqual(args[:3], ("python", "usr/local/bin/python3", "scripts/run-test-plan.py"))
            self.assertIn(oidf.PLAN, args)
            self.assertIn(str(leg / "export"), args)
            self.assertIn(str(leg / "plan-config.json"), args)
            self.assertEqual(run.call_args.kwargs["cwd"], "official-source")
            self.assertEqual(run.call_args.kwargs["env"]["CONFORMANCE_SERVER"], oidf.SUITE_BASE)

    def test_changed_wheel_is_refused_before_unpacking(self):
        with tempfile.TemporaryDirectory() as directory:
            url, _ = oidf.WHEELS[0]
            (Path(directory) / url.rsplit("/", 1)[1]).write_bytes(b"tampered")
            with self.assertRaisesRegex(oidf.Refused, "wheel digest differs"):
                oidf.native_wheels(directory, str(Path(directory) / "deps"))
            self.assertFalse((Path(directory) / "deps").exists())

    def test_stager_pins_match_adapter(self):
        self.assertEqual(stage.SUITE_COMMIT, oidf.SUITE_COMMIT)
        self.assertEqual(list(stage.IMAGES.values()), [oidf.SERVER_IMAGE, oidf.NGINX_IMAGE,
                                                      oidf.MONGO_IMAGE, oidf.PYTHON_IMAGE])
        self.assertEqual(stage.WHEELS, oidf.WHEELS)


class ImageFlattening(unittest.TestCase):
    def archive(self, path, entries):
        with tarfile.open(path, "w") as archive:
            for name, kind, value in entries:
                info = tarfile.TarInfo(name)
                info.mode = 0o755
                if kind == "file":
                    info.size = len(value)
                    archive.addfile(info, io.BytesIO(value))
                else:
                    info.type = {"dir": tarfile.DIRTYPE, "link": tarfile.SYMTYPE,
                                 "hard": tarfile.LNKTYPE}[kind]
                    info.linkname = value
                    archive.addfile(info)

    def test_absolute_image_links_are_resolved_inside_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.archive(root / "image.tar", [("usr", "dir", ""), ("usr/lib", "dir", ""),
                         ("usr/lib/real.so", "file", b"image library"),
                         ("usr/lib/alias.so", "link", "real.so"), ("lib", "link", "/usr/lib"),
                         ("copy.so", "hard", "usr/lib/real.so")])
            files = stage.ImageFiles(root / "image.tar")
            try:
                files.copy("lib", root / "out")
                files.copy("copy.so", root / "hard-copy")
            finally:
                files.close()
            self.assertEqual((root / "out/alias.so").read_bytes(), b"image library")
            self.assertFalse((root / "out/alias.so").is_symlink())
            self.assertEqual((root / "hard-copy").stat().st_nlink, 1)

    def test_oci_whiteouts_preserve_opaque_directory_and_new_layer_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.archive(root / "lower.tar", [("lib", "dir", ""), ("lib/old.so", "file", b"old"),
                         ("removed", "file", b"old")])
            self.archive(root / "upper.tar", [("lib/.wh..wh..opq", "file", b""),
                         ("lib/new.so", "file", b"new"), (".wh.removed", "file", b"")])
            files = stage.ImageFiles([root / "lower.tar", root / "upper.tar"])
            try:
                files.copy("lib", root / "out")
                self.assertNotIn("removed", files.members)
            finally:
                files.close()
            self.assertEqual([path.name for path in (root / "out").iterdir()], ["new.so"])
            self.assertEqual((root / "out/new.so").read_bytes(), b"new")

    def test_oci_digest_mismatch_is_not_published(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(stage.urllib.request, "urlopen", return_value=io.BytesIO(b"wrong")):
            registry = object.__new__(stage.PublicRegistry)
            registry.host, registry.repository, registry.token = "registry.invalid", "public", "anonymous"
            destination = Path(directory) / "blob"
            with self.assertRaisesRegex(ValueError, "digest or length differs"):
                registry.fetch("blobs", "sha256:" + "0" * 64, destination)
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_escape_and_cycle_are_refused(self):
        for target in ("../../outside", "alias"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.archive(root / "image.tar", [("alias", "link", target)])
                files = stage.ImageFiles(root / "image.tar")
                try:
                    with self.assertRaises(ValueError):
                        files.copy("alias", root / "out")
                finally:
                    files.close()


if __name__ == "__main__":
    unittest.main()

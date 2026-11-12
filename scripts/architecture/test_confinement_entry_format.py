"""Formatting reuses only the immutable seed; compilation keeps fresh copies."""

import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import confinement_entry as entry


class FormatSeed(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.seed = self.root / "seed"
        self.seed.mkdir()
        (self.seed / "source.rs").write_text("immutable dependency")
        (self.seed / ".package-cache").touch()
        self.fresh = self.root / "cargo-home-invocation"
        self.fresh.mkdir()
        env = patch.dict(os.environ, {
            "CARGO_HOME": str(self.seed),
            "HOME": str(self.root / "home"),
            "BUSBAR_INVOCATION_CARGO_HOME": str(self.fresh),
            "RUSTUP_TOOLCHAIN": "1.98.0",
            "RUSTUP_HOME": "/fixed/rustup",
            "PATH": "/fixed/tools:/usr/bin:/bin",
        })
        env.start()
        self.addCleanup(env.stop)
        fixed = patch.object(entry, "INVOCATION_CARGO_HOME", self.fresh)
        fixed.start()
        self.addCleanup(fixed.stop)

    def test_only_exact_controller_format_forms_select_readonly_seed(self):
        for argv in (
            ["cargo", "fmt", "--all"],
            ["cargo", "fmt", "--all", "--check"],
            ["cargo", "fmt", "--manifest-path", "dist/default/Cargo.toml", "--all", "--check"],
        ):
            with self.subTest(argv=argv):
                self.assertTrue(entry.readonly_format_command(argv))

    def test_compiler_alternate_command_and_extra_arguments_cannot_select_fast_path(self):
        for argv in (
            [], ["cargo", "fmt"], ["cargo", "fmt", "--check"],
            ["cargo", "build", "--all", "--check"],
            ["cargo", "test", "--all", "--check"],
            ["cargo", "check", "--all", "--check"],
            ["cargo", "clippy", "--all", "--check"],
            ["cargo", "+other", "fmt", "--all", "--check"],
            ["/candidate/cargo", "fmt", "--all", "--check"],
            ["sh", "-c", "cargo fmt --all --check"],
            ["cargo", "fmt", "--all", "--check", "--", "--emit=files"],
            ["cargo", "fmt", "--manifest-path", "other/Cargo.toml", "--all", "--check"],
            ["cargo", "fmt", "--all", "--check", "--config-path", "/candidate/config"],
        ):
            with self.subTest(argv=argv):
                self.assertFalse(entry.readonly_format_command(argv))

    def test_check_uses_readonly_seed_without_copy_or_toolchain_changes(self):
        before = dict(os.environ)
        with patch.object(entry.os, "statvfs", return_value=SimpleNamespace(f_flag=os.ST_RDONLY)) as mount:
            with patch.object(entry.shutil, "copytree") as copy:
                entry.prepare_cargo_home(["cargo", "fmt", "--all", "--check"])
        mount.assert_called_once_with(str(self.seed))
        copy.assert_not_called()
        before.pop("BUSBAR_INVOCATION_CARGO_HOME")
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(list(self.fresh.iterdir()), [])

    def test_readonly_permissions_do_not_substitute_for_readonly_mount(self):
        self.seed.chmod(0o555)
        self.addCleanup(self.seed.chmod, 0o755)
        with patch.object(entry.os, "statvfs", return_value=SimpleNamespace(f_flag=0)):
            with self.assertRaisesRegex(RuntimeError, "read-only Cargo seed"):
                entry.prepare_cargo_home(["cargo", "fmt", "--all", "--check"])

    def test_build_and_unrecognized_format_still_get_independent_copies(self):
        for argv in (["cargo", "build"], ["cargo", "fmt"]):
            with self.subTest(argv=argv):
                os.environ.update(CARGO_HOME=str(self.seed), BUSBAR_INVOCATION_CARGO_HOME=str(self.fresh))
                with patch.object(entry.os, "statvfs", side_effect=AssertionError("not a fast path")):
                    entry.prepare_cargo_home(argv)
                self.assertEqual(os.environ["CARGO_HOME"], str(self.fresh))
                self.assertEqual((self.fresh / "source.rs").read_text(), "immutable dependency")
                self.assertFalse((self.fresh / ".package-cache").exists())
                (self.fresh / "source.rs").write_text("candidate poison")
                self.assertEqual((self.seed / "source.rs").read_text(), "immutable dependency")
                shutil.rmtree(self.fresh)
                self.fresh.mkdir()

    def test_private_home_must_be_the_fixed_controller_mount(self):
        os.environ["BUSBAR_INVOCATION_CARGO_HOME"] = str(self.root / "elsewhere")
        (self.root / "elsewhere").mkdir()
        with self.assertRaisesRegex(RuntimeError, "prepared by the controller"):
            entry.prepare_cargo_home(["cargo", "build"])

    def test_fast_path_still_rejects_indirect_or_nonempty_private_home(self):
        for indirect in (False, True):
            with self.subTest(indirect=indirect):
                os.environ["BUSBAR_INVOCATION_CARGO_HOME"] = str(self.fresh)
                if indirect:
                    shutil.rmtree(self.fresh)
                    self.fresh.symlink_to(self.seed, target_is_directory=True)
                else:
                    (self.fresh / "poison").touch()
                with self.assertRaisesRegex(RuntimeError, "prepared by the controller"):
                    entry.prepare_cargo_home(["cargo", "fmt", "--all", "--check"])


if __name__ == "__main__":
    unittest.main()

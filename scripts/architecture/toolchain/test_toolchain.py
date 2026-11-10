"""Exact-vector and hostile-input preparation regressions; no image builds here."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build
import prepare


class Inputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source, self.tools, self.downloads = [
            self.root / p for p in ("source", "tools", "downloads")
        ]
        for path in (self.source, self.tools, self.downloads):
            path.mkdir()
        self.package = {
            "name": "fixture",
            "version": "1.0.0",
            "source": prepare.REGISTRY,
            "checksum": "a" * 64,
        }
        (self.source / "Cargo.lock").write_text(
            "version=4\n[[package]]\n"
            + "\n".join(k + "=" + json.dumps(v) for k, v in self.package.items())
        )
        (self.source / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel="1.98.0"\ncomponents=["clippy","rustfmt"]\n'
        )
        (self.source / "vector.json").write_text(
            '{"final":"independently approved fixture"}\n'
        )
        self.plan = {
            "schema": "busbar.native-toolchain-inputs/1",
            "platform": "linux/arm64",
            "source_date_epoch": 1,
            "toolchain": {
                "path": "rust-toolchain.toml",
                "sha256": prepare.sha(self.source / "rust-toolchain.toml"),
            },
            "vector": {
                "path": "vector.json",
                "sha256": prepare.sha(self.source / "vector.json"),
            },
            "locks": {"Cargo.lock": prepare.sha(self.source / "Cargo.lock")},
            "git": {},
        }
        components = {}
        for name in ("clippy", "rustfmt"):
            archive = self.downloads / (name + ".tar.xz")
            archive.write_bytes(b"cached unit fixture, never executed")
            components[name] = {
                "url": "https://static.rust-lang.org/dist/" + archive.name,
                "sha256": prepare.sha(archive),
            }
        pins = {
            "schema": "busbar.native-toolchain-pins/1",
            "rust": "1.98.0",
            "platforms": {
                "linux/arm64": {
                    "base": "rust@sha256:" + "b" * 64,
                    "triple": "aarch64-unknown-linux-gnu",
                    "components": components,
                }
            },
        }
        (self.tools / "pins.json").write_text(json.dumps(pins))
        for name in ("prepare.py", "seed.py", "install.py"):
            (self.tools / name).write_text("# trusted unit fixture\n")

    def run_prepare(self, name="output"):
        path = self.root / "plan.json"
        path.write_text(json.dumps(self.plan))
        with patch.object(prepare, "HERE", self.tools):
            return prepare.prepare(
                path, prepare.sha(path), self.source, self.root / name, self.downloads
            )

    def test_context_binds_exact_vector_locks_and_generated_manifests(self):
        (self.source / "build.rs").write_text(
            'panic!("must never be copied or executed");'
        )
        (self.source / ".cargo").mkdir()
        (self.source / ".cargo/config.toml").write_text(
            '[build]\nrustc-wrapper="host-command"\n'
        )
        result = self.run_prepare()
        self.assertEqual(result["vector_sha256"], self.plan["vector"]["sha256"])
        self.assertEqual(result["expected_packages"], {"0": [self.package]})
        output = self.root / "output"
        self.assertFalse(
            any(p.name in ("build.rs", "config.toml") for p in output.rglob("*"))
        )
        self.assertIn(
            "default-features=false", (output / "locks/0/Cargo.toml").read_text()
        )
        self.assertIn("RUN --network=none", (output / "Dockerfile").read_text())

    def test_vector_and_lock_mutation_refuse_before_context_creation(self):
        for name in ("vector.json", "Cargo.lock", "rust-toolchain.toml"):
            path = self.source / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValueError, "digest differs"):
                self.run_prepare()
            self.assertFalse((self.root / "output").exists())
            path.write_bytes(original)

    def test_unknown_plan_fields_and_unapproved_plan_digest_refuse(self):
        self.plan["candidate_override"] = True
        with self.assertRaisesRegex(ValueError, "closed native"):
            self.run_prepare()
        path = self.root / "plan.json"
        with self.assertRaisesRegex(ValueError, "plan digest"):
            prepare.prepare(
                path, "0" * 64, self.source, self.root / "output", self.downloads
            )

    def test_symlinks_traversal_unpinned_git_and_missing_checksums_refuse(self):
        indirect = self.source / "indirect"
        indirect.symlink_to(self.source / "Cargo.lock")
        with self.assertRaisesRegex(ValueError, "indirect"):
            prepare.pinned(self.source, "indirect", self.plan["locks"]["Cargo.lock"])
        with self.assertRaisesRegex(ValueError, "unsafe input"):
            prepare.relative("../outside")
        for source in (
            "git+https://github.com/example/repo?branch=main#" + "a" * 40,
            "git+https://github.com/example/repo?rev=" + "a" * 40 + "#" + "b" * 40,
            "registry+https://evil.invalid/index",
        ):
            with self.assertRaises(ValueError):
                prepare.packages({"package": [dict(self.package, source=source)]})
        with self.assertRaisesRegex(ValueError, "checksum"):
            prepare.packages(
                {
                    "package": [
                        {k: v for k, v in self.package.items() if k != "checksum"}
                    ]
                }
            )

    def test_git_cache_excludes_credentials_and_hooks(self):
        git = self.source / "git"
        (git / "objects").mkdir(parents=True)
        (git / "hooks").mkdir()
        (git / "HEAD").write_text("ref: refs/heads/main\n")
        (git / "config").write_text("credential-helper=secret-token\n")
        (git / "hooks/post-checkout").write_text("host-command\n")
        (git / "objects/object").write_bytes(b"unit object; not executed")
        url = "https://github.com/example/fixture"
        source = "git+" + url + "?rev=" + "a" * 40 + "#" + "a" * 40
        (self.source / "Cargo.lock").write_text(
            'version=4\n[[package]]\nname="fixture"\nversion="1.0.0"\nsource='
            + json.dumps(source)
        )
        self.plan["locks"]["Cargo.lock"] = prepare.sha(self.source / "Cargo.lock")
        self.plan["git"] = {
            url: {
                "path": "git",
                "files": {
                    str(p.relative_to(git)): prepare.sha(p)
                    for p in git.rglob("*")
                    if p.is_file()
                },
            }
        }
        self.run_prepare()
        output = self.root / "output/git/0"
        self.assertNotIn("secret-token", (output / "config").read_text())
        self.assertFalse((output / "hooks").exists())
        self.assertTrue((output / "objects").is_dir())
        self.assertTrue((output / "refs").is_dir())

    def test_prepared_context_mutation_never_starts_a_builder(self):
        self.run_prepare()
        context = self.root / "output"
        expected = prepare.sha(context / "context.sha256.json")
        (context / "recipe.json").write_text("{}")
        with patch.object(build.subprocess, "run") as execute:
            with self.assertRaisesRegex(ValueError, "digest differs"):
                build.build(
                    context,
                    expected,
                    "/bin/echo",
                    prepare.sha("/bin/echo"),
                    "/bin/echo",
                    prepare.sha("/bin/echo"),
                    "unix:///unused.sock",
                    "busbar-native-task:unit",
                    self.root / "build",
                )
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()

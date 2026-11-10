"""Small real Cargo build witness; no network, dependencies or repository build."""

from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

import build_closure
import cargo_capture
import native_provenance as p


class CargoCaptureTests(unittest.TestCase):
    def test_real_locked_native_build_and_exact_shipped_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text(
                '[package]\nname="capture-fixture"\nversion="1.0.0"\nedition="2021"\n[features]\nmeasured=[]\n'
            )
            (root / "src/main.rs").write_text('fn main() { println!("captured"); }\n')
            subprocess.run(
                [
                    "cargo",
                    "generate-lockfile",
                    "--offline",
                    "--manifest-path",
                    str(root / "Cargo.toml"),
                ],
                check=True,
                capture_output=True,
            )
            target = (
                subprocess.check_output(["rustc", "-vV"])
                .decode()
                .split("host: ")[1]
                .splitlines()[0]
            )
            capture = root / "capture"
            cargo_capture.capture(
                capture,
                [
                    "build",
                    "--locked",
                    "--offline",
                    "--manifest-path",
                    str(root / "Cargo.toml"),
                    "--target",
                    target,
                    "--features",
                    "measured",
                    "--target-dir",
                    str(root / "target"),
                ],
            )
            binary = root / "target" / target / "debug/capture-fixture"
            self.assertEqual(subprocess.check_output([binary]), b"captured\n")
            artifact = root / "fixture.tar.gz"
            with tarfile.open(artifact, "w:gz") as archive:
                archive.add(binary, arcname="capture-fixture")
            closure = build_closure.collect(
                artifact,
                capture / "cargo-metadata.json",
                capture / "Cargo.lock",
                capture / "cargo-messages.jsonl",
                binary,
                "capture-fixture",
                "capture-fixture",
                "a" * 40,
                target,
                "capture-fixture",
                "1.0.0",
            )
            self.assertEqual(len(closure["components"]), 1)
            self.assertEqual(
                closure["components"][0]["properties"][0]["value"], "measured"
            )
            self.assertEqual(
                closure["members"]["capture-fixture"]["sha256"], p.digest(binary)
            )
            # A failed actual compiler run must discard its complete capture, never reuse one.
            (root / "src/main.rs").write_text("invalid Rust\n")
            with self.assertRaises(ValueError):
                cargo_capture.capture(
                    root / "failed",
                    [
                        "build",
                        "--locked",
                        "--offline",
                        "--manifest-path",
                        str(root / "Cargo.toml"),
                        "--target-dir",
                        str(root / "target"),
                    ],
                )
            self.assertFalse((root / "failed").exists())


if __name__ == "__main__":
    unittest.main()

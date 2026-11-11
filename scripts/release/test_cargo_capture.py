"""Small real Cargo build witness; no network, dependencies or repository build."""

from pathlib import Path
import subprocess
import tarfile
import tempfile
import shutil
import json
import sys
import unittest

import build_closure
import cargo_capture
import development_artifact
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
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    development_artifact.__file__,
                    "capture",
                    "--directory",
                    str(capture),
                    "--",
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
                check=True,
                capture_output=True,
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
            # Replay from collected/relocated bytes, never from a different metadata pass.
            retained = root / "retained"
            retained.mkdir()
            shutil.copytree(capture, retained / "build")
            shipped = root / "collected-busbar"
            shutil.copyfile(binary, shipped)
            vector = root / "vector.json"
            vector.write_bytes(p.canonical({"sdk": "b" * 40, "products": []}))
            command = p.load(capture / "build-context.json")["command"]
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    development_artifact.__file__,
                    "finalize",
                    "--directory",
                    str(retained),
                    "--binary",
                    str(shipped),
                    "--source",
                    "a" * 40,
                    "--policy",
                    "c" * 40,
                    "--sdk",
                    "b" * 40,
                    "--vector",
                    str(vector),
                    "--package",
                    "capture-fixture",
                    "--compiler-output",
                    str(binary),
                    "--command-json",
                    json.dumps(command),
                    "--retention-policy-sha256",
                    "d" * 64,
                ],
                check=True,
                capture_output=True,
            )
            result = p.load(retained / "receipt.json")
            self.assertEqual(result["binary_sha256"], p.digest(binary))
            self.assertFalse(result["signed"])
            self.assertFalse(result["release_eligible"])
            self.assertFalse(result["supported_lifetime_retention_verified"])
            receipt_hash = p.digest(retained / "receipt.json")
            verify = lambda: development_artifact.verify(
                retained, shipped, "a" * 40, "c" * 40, "b" * 40, receipt_hash
            )
            verify()
            for name in development_artifact.FILES:
                path = retained / name
                original = path.read_bytes()
                path.write_bytes(original + b"tamper")
                with self.subTest(name=name), self.assertRaises(ValueError):
                    verify()
                path.write_bytes(original)
            shipped.write_bytes(b"different binary")
            with self.assertRaises(ValueError):
                verify()
            shutil.copyfile(binary, shipped)
            for source, policy, sdk in (
                ("e" * 40, "c" * 40, "b" * 40),
                ("a" * 40, "e" * 40, "b" * 40),
                ("a" * 40, "c" * 40, "e" * 40),
            ):
                with self.assertRaises(ValueError):
                    development_artifact.verify(
                        retained, shipped, source, policy, sdk, receipt_hash
                    )
            # Even a supplied self-consistent receipt digest cannot hide an invented SBOM.
            sbom_path = retained / "sbom.cdx.json"
            sbom_path.write_bytes(
                p.canonical({"bomFormat": "CycloneDX", "components": []})
            )
            result["files"]["sbom.cdx.json"] = {
                "sha256": p.digest(sbom_path),
                "size": sbom_path.stat().st_size,
            }
            (retained / "receipt.json").write_bytes(p.canonical(result))
            with self.assertRaisesRegex(ValueError, "SBOM does not describe"):
                development_artifact.verify(
                    retained,
                    shipped,
                    "a" * 40,
                    "c" * 40,
                    "b" * 40,
                    p.digest(retained / "receipt.json"),
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

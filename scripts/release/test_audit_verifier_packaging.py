#!/usr/bin/env python3
"""Behavioral coverage of the existing per-target producer and release asset contract."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SOURCE_EPOCH = 1700000000
CHANGED_SOURCE_EPOCH = SOURCE_EPOCH + 3600
FAILED_BUILD_EXIT = 7

sys.path.insert(0, str(Path(__file__).resolve().parent))
import publish_gate as pg
import candidate


class AuditVerifierPackaging(unittest.TestCase):
    def test_published_rows_owe_tool_archive_and_package_sbom(self):
        rows = [dict(target="fixture", kind="binary", published=True, archive="tar.gz"),
                dict(target="internal", kind="binary", published=False, archive="tar.gz")]
        with patch.object(pg, "release_targets", return_value=rows):
            files, sboms, internal, _ = pg.expected_files(type("Inputs", (), {"root": Path(".")})(), {"version": "1.6.0", "plugins": []})
        self.assertIn("busbar-audit-verify-fixture.tar.gz", files)
        self.assertIn("busbar-audit-verify-v1.6.0-fixture.cdx.json", sboms)
        self.assertNotIn("busbar-audit-verify-internal.tar.gz", internal)

    def test_candidate_produces_verifier_package_sbom_on_published_rows(self):
        row = dict(target="fixture", kind="binary", published=True, archive="tar.gz")
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(candidate, "target_row", return_value=row), \
                patch.object(candidate.pg, "commit_key_list", return_value="fixture"), \
                patch.object(candidate, "sh", return_value="0\n"), \
                patch.object(candidate, "version", return_value="1.6.0"), \
                patch.object(candidate, "sbom") as produce:
            candidate.cmd_core("fixture", Path(tmp))
            produce.assert_any_call("fixture", "busbar-audit-verify-v1.6.0-fixture.cdx.json", Path(tmp), package="busbar-kernel-audit")

    def test_actual_build_script_emits_separate_native_tool_and_documentation(self):
        script = Path(__file__).resolve().parents[1] / "release-build.sh"
        for triple, ext, exe in [("x86_64-unknown-linux-gnu", "tar.gz", "busbar"),
                                 ("x86_64-pc-windows-msvc", "zip", "busbar.exe")]:
            with self.subTest(triple=triple), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "scripts").mkdir()
                shutil.copy(script, root / "scripts/release-build.sh")
                (root / ".github").mkdir()
                (root / ".github/release-targets.json").write_text(json.dumps({"targets": [dict(target=triple, kind="binary", published=True, pgo=False, archive=ext, exe=exe)]}))
                (root / "docs").mkdir()
                (root / "docs/audit-verify.md").write_text("Offline verifier instructions.\n")
                guard = root / "scripts/release-key-guard.sh"
                guard.write_text("#!/usr/bin/env bash\nexit 0\n")
                guard.chmod(0o755)
                doubles = root / "doubles"
                doubles.mkdir()
                cargo = doubles / "cargo"
                cargo.write_text("#!" + sys.executable + "\n" + '''import json,os,pathlib,sys
args=sys.argv[1:]
def arg(key,default): return args[args.index(key)+1] if key in args else default
binary=arg('--bin','busbar-audit-verify')
triple=arg('--target','')
name=binary+('.exe' if 'windows' in triple else '')
output=pathlib.Path(arg('--target-dir','target'))/triple/'release'/name
output.parent.mkdir(parents=True,exist_ok=True)
output.write_bytes(binary.encode())
output.chmod(0o755)
with open('cargo-calls.jsonl','a') as f: f.write(json.dumps({'args':args,'flags':os.environ.get('CARGO_ENCODED_RUSTFLAGS',os.environ.get('RUSTFLAGS',''))})+'\\n')
''')
                cargo.chmod(0o755)
                command = ["bash", str(root / "scripts/release-build.sh"), triple, "--out-dir", str(root / "out")]
                env = {**os.environ, "PATH": str(doubles) + os.pathsep + os.environ["PATH"],
                       "BUSBAR_RELEASE_PUBKEY": "fixture", "SOURCE_DATE_EPOCH": str(SOURCE_EPOCH),
                       "CARGO_ENCODED_RUSTFLAGS": "-Cprofile-use=unrelated.profdata"}
                result = subprocess.run(command, env=env, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                archive = root / "out" / f"busbar-audit-verify-{triple}.{ext}"
                self.assertTrue(archive.is_file(), result.stdout.decode())
                tool = "busbar-audit-verify" + (".exe" if exe.endswith(".exe") else "")
                if ext == "zip":
                    with zipfile.ZipFile(archive) as opened:
                        self.assertEqual(set(opened.namelist()), {tool, "audit-verify.md"})
                        self.assertEqual(opened.read(tool), b"busbar-audit-verify")
                    with zipfile.ZipFile(root / "out" / f"busbar-{triple}.{ext}") as opened:
                        self.assertEqual(opened.namelist(), [exe])
                else:
                    with tarfile.open(archive) as opened:
                        self.assertEqual(set(opened.getnames()), {tool, "audit-verify.md"})
                        self.assertEqual(opened.extractfile(tool).read(), b"busbar-audit-verify")
                        self.assertEqual(opened.getmember(tool).mode, 0o755)
                    with tarfile.open(root / "out" / f"busbar-{triple}.{ext}") as opened:
                        self.assertEqual(opened.getnames(), [exe])
                calls = [json.loads(line) for line in (root / "cargo-calls.jsonl").read_text().splitlines()]
                verifier = next(call for call in calls if "busbar-audit-verify" in call["args"])
                self.assertIn("busbar-kernel-audit", verifier["args"])
                self.assertIn("--locked", verifier["args"])
                self.assertNotIn("profile-use", verifier["flags"])
                if "windows" in triple:
                    self.assertIn("+crt-static", verifier["flags"])
                original = archive.read_bytes()
                os.utime(root / "docs/audit-verify.md", (CHANGED_SOURCE_EPOCH, CHANGED_SOURCE_EPOCH))
                rebuilt = subprocess.run(command, env=env, capture_output=True)
                self.assertEqual(rebuilt.returncode, 0, rebuilt.stderr.decode())
                self.assertEqual(archive.read_bytes(), original, "source timestamps cannot change a release archive")
                # A failed or interrupted retry must remove the preceding attempt's archives
                # and success marker, rather than leave a stale downloadable verifier.
                for failure in (f"exit {FAILED_BUILD_EXIT}", 'kill -TERM "$PPID"; exit 143'):
                    cargo.write_text("#!/bin/sh\n" + failure + "\n")
                    archive.write_bytes(original)
                    failed = subprocess.run(command, env=env, capture_output=True)
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertFalse(archive.exists())
                    self.assertFalse((root / "out" / f"busbar-{triple}.{ext}").exists())
                    self.assertFalse((root / "build-evidence/artifact.sha256").exists())


if __name__ == "__main__":
    unittest.main()

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
import candidate


class AuditVerifierPackaging(unittest.TestCase):
    def test_candidate_produces_verifier_package_sbom_on_published_rows(self):
        row = dict(target="fixture", kind="binary", published=True, archive="tar.gz")
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(candidate, "target_row", return_value=row), \
                patch.object(candidate, "commit_key_list", return_value="fixture"), \
                patch.object(candidate, "sh", return_value="0\n"), \
                patch.object(candidate, "version", return_value="1.6.0"), \
                patch.object(candidate, "sbom") as produce:
            candidate.cmd_core("fixture", Path(tmp))
            produce.assert_any_call("fixture", "busbar-audit-verify-v1.6.0-fixture.cdx.json", Path(tmp), package="busbar-kernel-audit")

    def test_image_candidate_uses_published_native_archive_and_pinned_dockerfile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "artifacts").mkdir()
            row = dict(target="x86_64-unknown-linux-gnu", kind="binary", published=True,
                       archive="tar.gz", packaged_into="image-linux-amd64")
            archive = root / "artifacts/busbar-x86_64-unknown-linux-gnu.tar.gz"
            import io
            with tarfile.open(archive, "w:gz") as opened:
                member = tarfile.TarInfo("busbar")
                member.size = len(b"published native bytes")
                opened.addfile(member, io.BytesIO(b"published native bytes"))
            calls = []
            def command(args, **kwargs):
                calls.append(args)
                if args[:3] == ["docker", "buildx", "build"]:
                    context = Path(args[-1])
                    self.assertEqual((context / "binaries/amd64/busbar").read_bytes(), b"published native bytes")
                    self.assertIn("FROM gcr.io/distroless/cc-debian12:nonroot@sha256:", (context / "Dockerfile").read_text())
                return "1700000000"
            with patch.object(candidate, "release_targets", return_value=[row]), \
                 patch.object(candidate, "cmd_core") as core, \
                 patch.object(candidate, "require_buildkit"), patch.object(candidate, "sh", side_effect=command):
                candidate.cmd_image("amd64", root)
            core.assert_called_once_with(row["target"], root)
            self.assertFalse(any(args[:2] == ["docker", "run"] for args in calls))

    def test_actual_build_script_emits_separate_native_tool_and_documentation(self):
        script = Path(__file__).resolve().parents[1] / "release-build.sh"
        for triple, ext, exe in [("x86_64-unknown-linux-gnu", "tar.gz", "busbar"),
                                 ("x86_64-pc-windows-msvc", "zip", "busbar.exe")]:
            with self.subTest(triple=triple), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "scripts").mkdir()
                shutil.copy(script, root / "scripts/release-build.sh")
                (root / "scripts/release").mkdir()
                for name in ("cargo_capture.py", "build_closure.py", "native_provenance.py"):
                    shutil.copy(script.parent / "release" / name, root / "scripts/release" / name)
                (root / "dist/default").mkdir(parents=True)
                (root / "dist/default/Cargo.toml").write_text('[package]\nname="busbar-default"\nversion="1.6.0"\n')
                (root / "Cargo.lock").write_text('[[package]]\nname="busbar-default"\nversion="1.6.0"\n[[package]]\nname="busbar-kernel-audit"\nversion="1.6.0"\n')
                (root / "release").mkdir()
                (root / "release/release-targets.json").write_text(json.dumps({"targets": [dict(target=triple, kind="binary", published=True, pgo=False, archive=ext, exe=exe)]}))
                (root / "docs").mkdir()
                (root / "docs/audit-verify.md").write_text("Offline verifier instructions.\n")
                guard = root / "scripts/release-key-guard.sh"
                guard.write_text("#!/usr/bin/env bash\nexit 0\n")
                guard.chmod(0o755)
                provenance = root / "scripts/build-provenance-gate.sh"
                provenance.write_text("#!/usr/bin/env bash\nexit 0\n")
                provenance.chmod(0o755)
                subprocess.run(["git", "init", "-q", str(root)], check=True)
                subprocess.run(["git", "-C", str(root), "-c", "user.name=Matthew Jackson", "-c", "user.email=1085847+MattJackson@users.noreply.github.com", "commit", "--allow-empty", "-qm", "Packaging fixture"], check=True)

                doubles = root / "doubles"
                doubles.mkdir()
                cargo = doubles / "cargo"
                cargo.write_text("#!" + sys.executable + "\n" + '''import json,os,pathlib,sys
args=sys.argv[1:]
def arg(key,default): return args[args.index(key)+1] if key in args else default
if args[0] == 'metadata':
    packages = [{'id': name, 'name': name, 'version': '1.6.0', 'source': None} for name in ('busbar-default', 'busbar-kernel-audit')]
    print(json.dumps({'packages': packages, 'workspace_root': str(pathlib.Path.cwd()),
                      'resolve': {'nodes': [{'id': row['id'], 'features': [], 'deps': []} for row in packages]}}))
    sys.exit(0)
binary=arg('--bin','busbar-audit-verify')
triple=arg('--target','')
name=binary+('.exe' if 'windows' in triple else '')
output=pathlib.Path(arg('--target-dir','target'))/triple/'release'/name
output.parent.mkdir(parents=True,exist_ok=True)
output.write_bytes(binary.encode())
output.chmod(0o755)
print(json.dumps({'reason':'compiler-artifact','package_id':'busbar-default' if binary == 'busbar' else 'busbar-kernel-audit', 'filenames':[str(output.absolute())], 'features':[]}))
print(json.dumps({'reason':'build-finished','success':True}))
with open('cargo-calls.jsonl','a') as f: f.write(json.dumps({'args':args,'flags':os.environ.get('CARGO_ENCODED_RUSTFLAGS',os.environ.get('RUSTFLAGS',''))})+'\\n')
''')
                cargo.chmod(0o755)
                cargo_source = cargo.read_text()
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
                for failure in (f"sys.exit({FAILED_BUILD_EXIT})",
                                f"os.kill(os.getppid(), signal.SIGTERM); sys.exit({FAILED_BUILD_EXIT})"):
                    cargo.write_text(cargo_source.replace(
                        "args=sys.argv[1:]", "import signal\nargs=sys.argv[1:]\n"
                        + "if 'busbar-audit-verify' in args:\n    " + failure))
                    archive.write_bytes(original)
                    failed = subprocess.run(command, env=env, capture_output=True)
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertFalse(archive.exists())
                    self.assertFalse((root / "out" / f"busbar-{triple}.{ext}").exists())
                    self.assertFalse((root / "build-evidence/artifact.sha256").exists())
                cargo.write_text(cargo_source)
                (root / "docs/audit-verify.md").unlink()
                failed_package = subprocess.run(command, env=env, capture_output=True)
                self.assertNotEqual(failed_package.returncode, 0)
                self.assertFalse(archive.exists())
                self.assertFalse((root / "out" / f"busbar-{triple}.{ext}").exists())
                self.assertFalse((root / "build-evidence/artifact.sha256").exists())


if __name__ == "__main__":
    unittest.main()

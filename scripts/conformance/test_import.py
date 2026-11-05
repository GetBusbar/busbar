"""Run the actual driver, importer and release reader across a same-head failure."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import sync


class ActualImport(unittest.TestCase):
    def fixture(self, root):
        driver = root / "testing/conformance/run.sh"
        driver.parent.mkdir(parents=True)
        source = Path(os.environ.get("CONFORMANCE_DRIVER", HERE.parents[1] / "testing/conformance/run.sh"))
        shutil.copyfile(source, driver)
        (driver.parent / "tools.sh").write_text("return 0\n")
        (driver.parent / "suites.tsv").write_text(
            "sample\tprintf '%s' '{\"suite\":\"sample\",\"status\":\"pass\",\"armed\":true}' > \"$CONFORMANCE_OUT/verdict.json\"\n")
        (root / "crates/busbar-contract").mkdir(parents=True)
        (root / "crates/busbar-contract/Cargo.toml").touch()
        helpers = root / "scripts/conformance"
        helpers.mkdir(parents=True)
        for name in ("import.sh", "invocation.py", "sync.py"):
            shutil.copyfile(HERE / name, helpers / name)
        (root / "conformance/verdicts").mkdir(parents=True)
        (root / "conformance/registry.toml").write_text('''[[suite]]
id = "sample"
repo = "GetBusbar/busbar-transport-test"
standard = "fixture"
plan = "fixture"
tier = "conformant"
label = "fixture"
verdict = "conformance-verdict-sample"
public = "true"
''')
        subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "fixture"], check=True)
        head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        mci = root / "modernci"
        mci.write_text('#!/usr/bin/env python3\nimport os\nprint(open(os.environ["ARTIFACT_RESPONSE"]).read())\n')
        mci.chmod(0o755)
        env = dict(os.environ, MODERNCI=str(mci), MODERNCI_REPO="GetBusbar/busbar-transport-test", MODERNCI_COMMIT=head,
                   ARTIFACT_RESPONSE=str(root / "response.json"))
        return driver, head, env

    def publish_artifact(self, root, head, data, state):
        (root / "response.json").write_text(json.dumps({"repo": "GetBusbar/busbar-transport-test", "head": head, "state": state,
            "sha": hashlib.sha256(data).hexdigest(), "data": base64.b64encode(data).decode()}))
        generation = root / "fetched/GetBusbar/busbar-transport-test/generation-fixture"
        generation.mkdir(parents=True, exist_ok=True)
        (generation / "artifact.tar").write_bytes(data)
        (generation.parent / "receipt.json").write_text(json.dumps({"repo": "GetBusbar/busbar-transport-test", "head": head,
            "check": "conformance", "state": state, "sha": hashlib.sha256(data).hexdigest(), "generation": generation.name}))

    def import_result(self, root, head, env):
        return subprocess.run(["bash", str(root / "scripts/conformance/import.sh"), "GetBusbar/busbar-transport-test", "dev", head],
                              env=env, capture_output=True, text=True)

    def test_actual_pass_then_failed_same_head_rejects_reused_artifact(self):
        for failure in ("duplicate", "provision"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                driver, head, env = self.fixture(root)
                good = subprocess.run(["bash", str(driver)], env=env, capture_output=True, text=True)
                self.assertEqual(good.returncode, 0, good.stderr)
                buf = io.BytesIO()
                with tarfile.open(fileobj=buf, mode="w:gz") as archive:
                    archive.add(root / "target/conformance", arcname="target/conformance")
                data = buf.getvalue()
                self.publish_artifact(root, head, data, "green")
                imported = self.import_result(root, head, env)
                self.assertEqual(imported.returncode, 0, imported.stdout + imported.stderr)
                self.assertEqual(sync.load_fetched(root / "fetched")["GetBusbar/busbar-transport-test"]["verdicts"]["sample"]["status"], "pass")
                if failure == "duplicate":
                    (driver.parent / "suites.tsv").write_text("sample\ttrue\nsample\ttrue\n")
                else:
                    (driver.parent / "tools.sh").write_text("return 1\n")
                failed = subprocess.run(["bash", str(driver)], env=env, capture_output=True, text=True)
                self.assertEqual(failed.returncode, 2, failed.stderr)
                self.assertFalse((root / "target/conformance/invocation.json").exists())
                self.assertFalse(list((root / "target/conformance/verdicts").glob("*.json")))
                self.publish_artifact(root, head, data, "red")
                refused = self.import_result(root, head, env)
                self.assertNotEqual(refused.returncode, 0, refused.stdout + refused.stderr)
                self.assertIn("did not finish green", refused.stderr)
                fetched = sync.load_fetched(root / "fetched")["GetBusbar/busbar-transport-test"]
                self.assertEqual(fetched["verdicts"], {})
                self.assertIn("exit does not match", fetched["receipt"]["missing"])
                rendered = json.loads(sync.render_release(root / "conformance/registry.toml", root / "fetched",
                    release="fixture", commit=head, pins={"GetBusbar/busbar-transport-test": head}, exceptions={}))
                self.assertIsNone(rendered["suites"][0]["claim"])
                self.assertNotEqual(rendered["suites"][0]["status"], "pass")

    def test_actual_red_invocation_preserves_failure_and_suppresses_pass_siblings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            driver, head, env = self.fixture(root)
            with (driver.parent / "suites.tsv").open("a") as stream:
                stream.write("broken\tprintf '%s' '{\"suite\":\"broken\",\"status\":\"fail\",\"armed\":true}' > \"$CONFORMANCE_OUT/verdict.json\"; exit 1\n")
            failed = subprocess.run(["bash", str(driver)], env=env, capture_output=True, text=True)
            self.assertEqual(failed.returncode, 1, failed.stderr)
            receipt = json.loads((root / "target/conformance/invocation.json").read_text())
            self.assertEqual(receipt["exit_code"], 1)
            self.assertEqual(set(receipt["verdicts"]), {"sample.json", "broken.json"})
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as archive:
                archive.add(root / "target/conformance", arcname="target/conformance")
            self.publish_artifact(root, head, buf.getvalue(), "red")
            self.assertNotEqual(self.import_result(root, head, env).returncode, 0)
            verdicts = sync.load_fetched(root / "fetched")["GetBusbar/busbar-transport-test"]["verdicts"]
            self.assertEqual(set(verdicts), {"broken"})
            self.assertEqual(verdicts["broken"]["status"], "fail")
            self.publish_artifact(root, head, buf.getvalue(), "green")
            self.assertNotEqual(self.import_result(root, head, env).returncode, 0)
            self.assertEqual(sync.load_fetched(root / "fetched")["GetBusbar/busbar-transport-test"]["verdicts"], {})

    def test_legacy_or_modified_archive_cannot_be_imported_as_green(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            driver, head, env = self.fixture(root)
            good = subprocess.run(["bash", str(driver)], env=env, capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            for mutation in ("verdict", "missing-receipt"):
                if mutation == "verdict":
                    with (root / "target/conformance/verdicts/sample.json").open("a") as stream:
                        stream.write(" ")
                else:
                    (root / "target/conformance/invocation.json").unlink()
                buf = io.BytesIO()
                with tarfile.open(fileobj=buf, mode="w:gz") as archive:
                    archive.add(root / "target/conformance", arcname="target/conformance")
                self.publish_artifact(root, head, buf.getvalue(), "green")
                result = self.import_result(root, head, env)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertFalse((root / "conformance/verdicts/sample.json").exists())


if __name__ == "__main__":
    unittest.main()

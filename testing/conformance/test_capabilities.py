"""Targeted confined dispatch checks; no product or external suite execution."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(os.environ.get("BUSBAR_CAPABILITY_TEMPLATE", Path(__file__).resolve().parent))
spec = importlib.util.spec_from_file_location("capabilities", HERE / "capabilities.py")
capabilities = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capabilities)


class Capabilities(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "capabilities.json"
        self.record = dict(schema=capabilities.SCHEMA, repo="GetBusbar/busbar",
                           source="a" * 40, toolchain_ready=True,
                           suites={"h2": {"available": True}})

    def check(self):
        self.path.write_text(json.dumps(self.record))
        return capabilities.unavailable(self.path, "GetBusbar/busbar", "a" * 40, "h2")

    def test_only_explicit_current_ready_capability_runs(self):
        self.assertIsNone(self.check())
        self.record["source"] = "b" * 40
        self.assertIn("admitted repository and source", self.check())
        self.record["source"] = "a" * 40
        self.record["repo"] = "other/repository"
        self.assertIn("admitted repository and source", self.check())

    def test_missing_or_unready_capability_fails_with_limitation(self):
        self.record["toolchain_ready"] = False
        self.assertIn("offline toolchain", self.check())
        self.record["toolchain_ready"] = True
        self.record["suites"] = {}
        self.assertIn("isolated runtime", self.check())
        self.record["suites"]["h2"] = {"available": False, "reason": "no pinned Caddy fixture"}
        self.assertEqual(self.check(), "no pinned Caddy fixture")

    def test_unknown_or_nonboolean_authority_fails(self):
        for value in (1, "true", None, [], {}):
            self.record["suites"]["h2"]["available"] = value
            self.assertIn("refused", self.check())
        self.record["suites"]["h2"] = {"available": True, "endpoint": "https://example.com"}
        self.assertIn("refused", self.check())

    def test_unreadable_or_invalid_manifest_never_falls_back(self):
        for payload in ("{", "[]", "null", " " * 65537):
            self.path.write_text(payload)
            self.assertIn("refused", capabilities.unavailable(
                self.path, "GetBusbar/busbar", "a" * 40, "h2"))
        self.path.unlink()
        self.assertIn("FileNotFoundError", capabilities.unavailable(
            self.path, "GetBusbar/busbar", "a" * 40, "h2"))

    def test_missing_or_unbounded_limitation_is_refused(self):
        for row in ({"available": False}, {"available": False, "reason": ""},
                    {"available": False, "reason": "x" * 2001},
                    {"available": False, "reason": "bad\nline"}):
            self.record["suites"]["h2"] = row
            self.assertIn("refused", self.check())


class ConfinedDriver(unittest.TestCase):
    def test_unavailable_suite_is_red_without_running_or_downloading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "testing/conformance"
            harness.mkdir(parents=True)
            for name in ("run.sh", "capabilities.py"):
                shutil.copyfile(HERE / name, harness / name)
            (harness / "tools.sh").write_text("touch provisioned; return 1\n")
            # A denied command would forge PASS if it were accidentally run.
            command = 'touch executed; printf \'{"suite":"h2","status":"pass","armed":true}\' > "$CONFORMANCE_OUT/verdict.json"'
            (harness / "suites.tsv").write_text("h2\t" + command + "\n")
            (root / "crates/busbar-contract").mkdir(parents=True)
            (root / "crates/busbar-contract/Cargo.toml").write_text("")
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
            git("init", "-q")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "core.hooksPath", "/dev/null")
            git("add", ".")
            git("commit", "-qm", "Fixture")
            source = git("rev-parse", "HEAD")
            manifest = root / "capabilities.json"
            manifest.write_text(json.dumps(dict(schema=capabilities.SCHEMA,
                repo="GetBusbar/busbar", source=source, toolchain_ready=True,
                suites={"h2": {"available": False, "reason": "Caddy not staged"}})))
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CI_", "MODERNCI_", "BUSBAR_", "CONF_", "CONFORMANCE_"))}
            env.update(CONFORMANCE_CAPABILITIES=str(manifest), MODERNCI_REPO="GetBusbar/busbar")
            result = subprocess.run(["bash", str(harness / "run.sh")], env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse((root / "executed").exists())
            self.assertFalse((root / "provisioned").exists())
            verdict = json.loads((root / "target/conformance/verdicts/h2.json").read_text())
            self.assertEqual(verdict["status"], "fail")
            self.assertIn("Caddy not staged", verdict["reason"])
            receipt = json.loads((root / "target/conformance/invocation.json").read_text())
            self.assertEqual(receipt["exit_code"], 1)
            self.assertEqual(receipt["commit"], source)
            self.assertIn("h2.json", receipt["verdicts"])


if __name__ == "__main__":
    unittest.main()

"""Exercise only staged SBOM tool intake; no Cargo graph or suite execution."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).parent / "sbom.sh").read_text()
TOOLS = SOURCE.split('CX=""; CLI=""\n', 1)[1].split('\n# validate <file>', 1)[0]


class StagedTools(unittest.TestCase):
    def preflight(self, missing=None, changed=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("cargo-cyclonedx", "cyclonedx"):
                path = root / name
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(0o700)
            for name in ("spec-valid-bom-1.5.json", "spec-invalid-empty-component-1.5.json"):
                (root / name).write_text(name)
            if missing:
                (root / missing).unlink()
            if changed:
                (root / changed).write_text("changed")
            script = '''set -uo pipefail
why=(); CX_VER=0.5.9; CLI_VER=v0.33.1; CX=""; CLI=""
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
fetch() { echo forbidden-network-fetch >&2; exit 99; }
'''
            for variable, fixture in (("SPEC_VALID_SHA", "spec-valid-bom-1.5.json"),
                                      ("SPEC_INVALID_SHA", "spec-invalid-empty-component-1.5.json")):
                script += variable + "=" + hashlib.sha256(fixture.encode()).hexdigest() + "\n"
            script += TOOLS.replace("/opt/busbar-conformance/sbom", str(root))
            script += '\n[ "$CARGO_NET_OFFLINE" = true ] || exit 98\nprintf "%s\\n" "${why[@]}"\n[ "${#why[@]}" = 0 ]\n'
            return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                                  env=dict(os.environ, CONFORMANCE_CAPABILITIES="controller-manifest"), timeout=5)

    def test_staged_tools_and_controls_require_no_fetch(self):
        result = self.preflight()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("forbidden-network", result.stderr)

    def test_missing_tool_or_upstream_control_remains_failure(self):
        for name in ("cargo-cyclonedx", "cyclonedx", "spec-valid-bom-1.5.json", "spec-invalid-empty-component-1.5.json"):
            with self.subTest(name=name):
                result = self.preflight(missing=name)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn("forbidden-network", result.stderr)

    def test_altered_upstream_control_remains_failure(self):
        result = self.preflight(changed="spec-invalid-empty-component-1.5.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing or changed", result.stdout)


if __name__ == "__main__":
    unittest.main()

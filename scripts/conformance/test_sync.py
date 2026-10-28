# SPDX-License-Identifier: Apache-2.0
"""python3 -I scripts/conformance/test_sync.py: the manifest render refuses every bad verdict and
renders a claim only for an armed pass."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sync  # noqa: E402

REG = '''
[[suite]]
id = "ws"
standard = "WebSocket (RFC 6455)"
plan = "Autobahn|Testsuite against busbar-transport-ws"
tier = "conformant"
label = "WebSocket"
verdict = "conformance-verdict-ws"
public = "true"

[[suite]]
id = "otlp"
standard = "OTLP"
plan = "collector"
tier = "capable"
label = "OTLP"
verdict = "conformance-verdict-otlp"
public = "true"
'''

GOOD = {"schema": "busbar.conformance.verdict/1", "suite": "ws", "status": "pass", "armed": True,
        "commit": "a" * 40, "repo": "GetBusbar/busbar-transport-ws", "core_pin": "b" * 40,
        "evidence": "https://eu-central.modernci.dev/move?repo=x&from=dev&head=" + "a" * 40,
        "generated_at": "2026-10-26T12:00:00Z"}


class Render(unittest.TestCase):
    def run_with(self, verdicts):
        d = Path(tempfile.mkdtemp())
        (d / "registry.toml").write_text(REG)
        (d / "v").mkdir()
        for name, v in verdicts.items():
            (d / "v" / f"{name}.json").write_text(json.dumps(v) if isinstance(v, dict) else v)
        return json.loads(sync.render(d / "registry.toml", d / "v"))

    def test_an_armed_pass_claims_at_its_tier_and_carries_its_stamp(self):
        m = self.run_with({"ws": GOOD})
        ws = next(s for s in m["suites"] if s["suite"] == "ws")
        self.assertEqual(ws["status"], "pass")
        self.assertEqual(ws["claim"], "Conformant — passes Autobahn|Testsuite against busbar-transport-ws")
        self.assertEqual((ws["repo"], ws["commit"], ws["core_pin"]), (GOOD["repo"], GOOD["commit"], GOOD["core_pin"]))
        self.assertEqual(ws["verified_at"], GOOD["generated_at"])
        self.assertEqual(m["commit"], "")
        self.assertEqual(m["generated_at"], GOOD["generated_at"])

    def test_a_suite_with_no_verdict_is_not_run_and_claims_nothing(self):
        m = self.run_with({"ws": GOOD})
        otlp = next(s for s in m["suites"] if s["suite"] == "otlp")
        self.assertEqual((otlp["status"], otlp["claim"]), ("not-run", None))

    def test_a_fail_claims_nothing_and_keeps_its_reason(self):
        m = self.run_with({"ws": dict(GOOD, status="fail", reason="case 9.1.6 failed")})
        ws = next(s for s in m["suites"] if s["suite"] == "ws")
        self.assertEqual((ws["status"], ws["claim"], ws["reason"]), ("fail", None, "case 9.1.6 failed"))

    def test_bad_verdicts_are_refused(self):
        for name, bad in {
            "another suite's verdict": {"ws": dict(GOOD, suite="otlp")},
            "an unregistered suite": {"nope": dict(GOOD, suite="nope")},
            "an unarmed pass": {"ws": dict(GOOD, armed=False)},
            "an unknown field": {"ws": dict(GOOD, extra=1)},
            "a wrong schema": {"ws": dict(GOOD, schema="x")},
            "an unknown status": {"ws": dict(GOOD, status="green")},
            "no commit": {"ws": {k: v for k, v in GOOD.items() if k != "commit"}},
        }.items():
            with self.subTest(name), self.assertRaises(sync.Refused):
                self.run_with(bad)

    def test_the_render_is_deterministic(self):
        d = Path(tempfile.mkdtemp())
        (d / "registry.toml").write_text(REG)
        (d / "v").mkdir()
        (d / "v" / "ws.json").write_text(json.dumps(GOOD))
        self.assertEqual(sync.render(d / "registry.toml", d / "v"), sync.render(d / "registry.toml", d / "v"))


if __name__ == "__main__":
    unittest.main()

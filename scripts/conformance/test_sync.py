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
repo = "GetBusbar/busbar-transport-ws"
standard = "WebSocket (RFC 6455)"
plan = "Autobahn|Testsuite against busbar-transport-ws"
tier = "conformant"
label = "WebSocket"
verdict = "conformance-verdict-ws"
public = "true"

[[suite]]
id = "otlp"
repo = "GetBusbar/busbar-export-otlp"
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


T = "1" * 40          # the release commit
P_WS = "a" * 40       # transport-ws's shipped pin
P_OTLP = "e" * 40     # export-otlp's shipped pin
MCI = "https://eu-central.modernci.dev"


def stamped(suite, repo, commit, core, **kw):
    v = {"schema": "busbar.conformance.verdict/1", "suite": suite, "status": "pass", "armed": True,
         "repo": repo, "commit": commit, "core_pin": core,
         "run_id": f"modernci:{repo}@{commit}:conformance",
         "evidence": f"{MCI}/move?repo={repo.replace('/', '%2F')}&from=dev&head={commit}",
         "generated_at": "2026-10-28T10:00:00Z"}
    v.update(kw)
    return v


def fetched(d, repo, head, verdicts, missing=None):
    r = Path(d) / repo
    (r / "verdicts").mkdir(parents=True, exist_ok=True)
    rec = {"repo": repo, "check": "conformance", "from": "dev", "head": head, "sha": "0" * 64}
    if missing:
        rec["missing"] = missing
    (r / "receipt.json").write_text(json.dumps(rec))
    for v in verdicts:
        (r / "verdicts" / f"{v['suite']}.json").write_text(json.dumps(v))


class Registry(unittest.TestCase):
    def test_a_registry_suite_without_a_repo_is_refused(self):
        d = Path(tempfile.mkdtemp())
        (d / "registry.toml").write_text(REG.replace('repo = "GetBusbar/busbar-export-otlp"\n', ""))
        with self.assertRaises(sync.Refused):
            sync.read_registry(d / "registry.toml")

    def test_the_real_registry_names_each_suites_owning_repo(self):
        real = Path(__file__).resolve().parents[2] / "conformance" / "registry.toml"
        for s in sync.read_registry(real):
            with self.subTest(s["id"]):
                self.assertRegex(s["repo"], r"^GetBusbar/busbar(-[a-z0-9-]+)?$")


class ReleaseRender(unittest.TestCase):
    """sync.py --release V --commit T --from-modernci DIR: only ModernCI's fetched verdicts count, each
    held to its stamp."""

    def render(self, build, pins=None, exceptions=None):
        d = Path(tempfile.mkdtemp())
        (d / "registry.toml").write_text(REG)
        (d / "f").mkdir()
        build(d / "f")
        pins = pins if pins is not None else {"GetBusbar/busbar-transport-ws": P_WS, "GetBusbar/busbar-export-otlp": P_OTLP}
        text = sync.render_release(d / "registry.toml", d / "f", release="1.6.0", commit=T, pins=pins,
                                   exceptions=exceptions or {})
        return text, json.loads(text)

    def suite(self, m, sid):
        return next(s for s in m["suites"] if s["suite"] == sid)

    def test_a_stamped_pass_for_the_shipped_pin_and_core_counts(self):
        _, m = self.render(lambda f: fetched(f, "GetBusbar/busbar-transport-ws", P_WS,
                                             [stamped("ws", "GetBusbar/busbar-transport-ws", P_WS, T)]))
        ws = self.suite(m, "ws")
        self.assertEqual((m["commit"], m["release"]), (T, "1.6.0"))
        self.assertEqual((ws["status"], ws["repo"], ws["commit"], ws["core_pin"]),
                         ("pass", "GetBusbar/busbar-transport-ws", P_WS, T))
        self.assertTrue(ws["evidence"].endswith("head=" + P_WS))
        self.assertEqual(ws["verified_at"], "2026-10-28T10:00:00Z")

    def test_a_suite_with_no_fetched_output_is_not_run_never_omitted(self):
        _, m = self.render(lambda f: None)
        self.assertEqual([s["suite"] for s in m["suites"]], ["otlp", "ws"])
        for s in m["suites"]:
            self.assertEqual((s["status"], s["claim"]), ("not-run", None))

    def test_each_stamp_mismatch_is_not_run_with_its_reason(self):
        repo = "GetBusbar/busbar-transport-ws"
        for name, v in {
            "another commit": stamped("ws", repo, "9" * 40, T),
            "another core pin": stamped("ws", repo, P_WS, "8" * 40),
            "another repo": stamped("ws", "GetBusbar/busbar-plane-mcp", P_WS, T),
            "a forged run id": stamped("ws", repo, P_WS, T, run_id="hand-written"),
            "evidence for another head": stamped("ws", repo, P_WS, T, evidence=f"{MCI}/move?repo=x&head={'9' * 40}"),
            "no schema": {k: x for k, x in stamped("ws", repo, P_WS, T).items() if k != "schema"},
        }.items():
            with self.subTest(name):
                _, m = self.render(lambda f, v=v: fetched(f, repo, P_WS, [v]))
                ws = self.suite(m, "ws")
                self.assertEqual((ws["status"], ws["claim"]), ("not-run", None))
                self.assertTrue(ws["reason"])

    def test_a_receipt_for_another_head_than_the_shipped_pin_is_not_used(self):
        repo = "GetBusbar/busbar-transport-ws"
        _, m = self.render(lambda f: fetched(f, repo, "9" * 40, [stamped("ws", repo, "9" * 40, T)]))
        self.assertEqual(self.suite(m, "ws")["status"], "not-run")

    def test_a_suite_whose_repo_ships_no_pin_is_not_run(self):
        repo = "GetBusbar/busbar-transport-ws"
        _, m = self.render(lambda f: fetched(f, repo, P_WS, [stamped("ws", repo, P_WS, T)]),
                           pins={"GetBusbar/busbar-export-otlp": P_OTLP})
        self.assertEqual(self.suite(m, "ws")["status"], "not-run")
        self.assertIn("ships no pin", self.suite(m, "ws")["reason"])

    def test_a_signed_exception_is_recorded_and_never_a_pass(self):
        _, m = self.render(lambda f: None, exceptions={"otlp": {"status": "not-run", "reason": "collector rig pending"}})
        otlp = self.suite(m, "otlp")
        self.assertEqual((otlp["status"], otlp["claim"]), ("not-run", None))
        self.assertTrue(otlp["reason"].startswith("owner exception (signed): collector rig pending"))

    def test_the_release_render_is_canonical_bytes(self):
        build = lambda f: fetched(f, "GetBusbar/busbar-transport-ws", P_WS, [stamped("ws", "GetBusbar/busbar-transport-ws", P_WS, T)])
        a, m = self.render(build)
        b, _ = self.render(build)
        self.assertEqual(a, b)
        self.assertEqual(a, json.dumps(m, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        self.assertNotIn("\r", a)

    def test_the_cli_needs_release_commit_and_from_modernci_together(self):
        self.assertEqual(sync.main(["--release", "1.6.0"]), 2)
        self.assertEqual(sync.main(["--release", "1.6.0", "--commit", T]), 2)
        self.assertEqual(sync.main(["--commit", "nothex", "--release", "1.6.0", "--from-modernci", "/nonexistent"]), 2)


if __name__ == "__main__":
    unittest.main()

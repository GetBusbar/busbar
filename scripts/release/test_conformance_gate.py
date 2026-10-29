#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Offline proof of G-C (docs/design/conformance-release.md): a tag is refused unless every public
registry suite has a real ModernCI `pass` for the release commit T (core) or the shipped pin P judged
against T (plugin).

  python3 -I scripts/release/test_conformance_gate.py

ModernCI is a fake that serves `conformance` check outputs as ModernCI's `artifact` operation does.
Needs ssh-keygen (the signed owner exceptions).
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conformance_gate as cg  # noqa: E402

T = "1" * 40  # the release commit (the tag target)
OLD_CORE = "2" * 40  # an older core the plugin pins in .busbar-ref
P = "a" * 40  # busbar-transport-ws's shipped pin
CORE = "GetBusbar/busbar"
WS = "GetBusbar/busbar-transport-ws"
MCI = "https://eu-central.modernci.dev"

REG = """
[[suite]]
id = "tls"
repo = "GetBusbar/busbar"
standard = "TLS"
plan = "testssl.sh"
tier = "conformant"
label = "TLS"
verdict = "conformance-verdict-tls"
public = "true"

[[suite]]
id = "ws"
repo = "GetBusbar/busbar-transport-ws"
standard = "WebSocket (RFC 6455)"
plan = "Autobahn|Testsuite"
tier = "conformant"
label = "WebSocket"
verdict = "conformance-verdict-ws"
public = "true"

[[suite]]
id = "sigstore"
repo = "GetBusbar/busbar"
standard = "Sigstore"
plan = "cosign verify"
tier = "capable"
label = "Sigstore"
verdict = "conformance-verdict-sigstore"
public = "false"
"""


def verdict(suite, repo, commit, core, status="pass", **kw):
    v = {"schema": "busbar.conformance.verdict/1", "suite": suite, "status": status, "armed": True,
         "repo": repo, "commit": commit, "core_pin": core,
         "run_id": f"modernci:{repo}@{commit}:conformance",
         "evidence": f"{MCI}/move?repo={repo.replace('/', '%2F')}&from=dev&head={commit}",
         "generated_at": "2026-10-28T10:00:00Z"}
    v.update(kw)
    return v


def archive(verdicts) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for v in verdicts:
            data = json.dumps(v).encode()
            ti = tarfile.TarInfo(f"target/conformance/verdicts/{v['suite']}.json")
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class FakeMCI(cg.ModernCI):
    """`outputs[(repo, head)]` is the list of verdicts the check kept; absent means ModernCI has none."""

    def __init__(self):
        self.outputs = {}
        self.reruns = {}  # (repo, head, core) -> verdicts; absent: ModernCI cannot re-run
        self.rerun_calls = []
        self.heads = {WS: P}

    def artifact(self, repo, head):
        if (repo, head) not in self.outputs:
            raise cg.NoOutput(f"no check result or measurement of conformance at {head} kept outputs")
        return {"repo": repo, "from": "dev", "head": head, "state": "green"}, archive(self.outputs[(repo, head)])

    def rerun(self, repo, head, core):
        self.rerun_calls.append((repo, head, core))
        if (repo, head, core) not in self.reruns:
            raise cg.CannotRerun("ModernCI measure has no core-pin override")
        return {"repo": repo, "from": "dev", "head": head, "state": "green"}, archive(self.reruns[(repo, head, core)])

    def dev_head(self, repo):
        return self.heads[repo]


class World:
    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gc-test-"))
        self.root, self.cand = self.tmp / "repo", self.tmp / "cand"
        (self.root / "conformance").mkdir(parents=True)
        (self.root / "conformance" / "registry.toml").write_text(REG)
        (self.root / "dist" / "default").mkdir(parents=True)
        (self.root / "dist" / "default" / "Cargo.lock").write_text(
            '[[package]]\nname = "busbar-transport-ws"\n'
            f'source = "git+https://github.com/GetBusbar/busbar-transport-ws?rev={P}#{P}"\n')
        (self.root / "release").mkdir()
        self.mci = FakeMCI()
        self.mci.outputs[(CORE, T)] = [verdict("tls", CORE, T, T), verdict("sigstore", CORE, T, T, status="not-run", armed=False)]
        self.mci.outputs[(WS, P)] = [verdict("ws", WS, P, T)]
        # K2 stand-in: a software ssh key under the file namespace.
        self.key = self.tmp / "k2"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)], check=True)
        kt, kb = (self.tmp / "k2.pub").read_text().split()[:2]
        self.signers = [f'busbar-release namespaces="busbar-release" {kt} {kb}']

    def build(self, testkit=None):
        if self.cand.exists():
            shutil.rmtree(self.cand)
        cg.build_manifest(self.mci, self.root, commit=T, release="1.6.0", out=self.cand, testkit=testkit)
        return json.loads((self.cand / "conformance-manifest.json").read_text())

    def gate(self, testkit=None):
        return cg.gate_c(self.root, self.cand, commit=T, release="1.6.0", allowed_signers=self.signers, client=self.mci,
                         testkit=testkit)

    def except_(self, doc, sign=True):
        f = self.root / "release" / "conformance-exceptions.json"
        f.write_text(json.dumps(doc))
        Path(str(f) + ".sig").unlink(missing_ok=True)  # ssh-keygen asks before overwriting one
        if sign:
            subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(self.key), "-n", "busbar-release", str(f)],
                           check=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=30)


def status(m, sid):
    return next(s for s in m["suites"] if s["suite"] == sid)["status"]


@unittest.skipUnless(shutil.which("ssh-keygen"), "needs ssh-keygen")
class GateC(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def tearDown(self):
        shutil.rmtree(self.w.tmp, ignore_errors=True)

    def assertRefused(self, refusals, *needles):
        self.assertTrue(refusals, "expected G-C to refuse the tag")
        text = "\n".join(refusals)
        for n in needles:
            self.assertIn(n, text)
        for r in refusals:
            self.assertTrue(r.startswith("REFUSED G-C "), r)

    def test_every_public_suite_passing_at_T_and_P_is_admitted(self):
        m = self.w.build()
        self.assertEqual((m["commit"], m["release"]), (T, "1.6.0"))
        self.assertEqual((status(m, "tls"), status(m, "ws")), ("pass", "pass"))
        self.assertEqual(self.w.gate(), [])

    def test_a_registered_public_suite_without_a_pass_refuses_the_tag(self):
        for name, verdicts in {
            "no verdict": [],
            "a fail": [verdict("ws", WS, P, T, status="fail", reason="case 9.1.6")],
            "not-run": [verdict("ws", WS, P, T, status="not-run", armed=False)],
        }.items():
            with self.subTest(name):
                self.w.mci.outputs[(WS, P)] = verdicts
                m = self.w.build()
                self.assertNotEqual(status(m, "ws"), "pass")
                self.assertRefused(self.w.gate(), "ws")
        # A non-public suite that does not pass never blocks the tag.
        self.w.mci.outputs[(WS, P)] = [verdict("ws", WS, P, T)]
        m = self.w.build()
        self.assertEqual(status(m, "sigstore"), "not-run")
        self.assertEqual(self.w.gate(), [])

    def test_a_verdict_stamped_for_another_commit_is_not_used(self):
        other = "9" * 40
        # The plugin's check output at P carries a verdict stamped for another plugin commit.
        self.w.mci.outputs[(WS, P)] = [verdict("ws", WS, other, T)]
        # The core output at T carries a verdict stamped for another core commit.
        self.w.mci.outputs[(CORE, T)] = [verdict("tls", CORE, other, other)]
        m = self.w.build()
        self.assertEqual((status(m, "ws"), status(m, "tls")), ("not-run", "not-run"))
        self.assertRefused(self.w.gate(), "ws", "tls")

    def test_a_hand_placed_verdict_is_ignored(self):
        self.w.mci.outputs.pop((WS, P))  # ModernCI kept no output for the shipped pin
        good = json.dumps(verdict("ws", WS, P, T))
        # In the tree (what import.sh used to fill) ...
        (self.w.root / "conformance" / "verdicts").mkdir()
        (self.w.root / "conformance" / "verdicts" / "ws.json").write_text(good)
        m = self.w.build()
        self.assertEqual(status(m, "ws"), "not-run")
        self.assertRefused(self.w.gate(), "ws")
        # ... and dropped into the candidate's fetch directory next to the receipts.
        stray = self.w.cand / "conformance" / "GetBusbar" / "busbar-transport-ws" / "verdicts"
        stray.mkdir(parents=True, exist_ok=True)
        (stray / "ws.json").write_text(good)
        self.assertRefused(self.w.gate(), "ws")

    def test_a_hand_edited_manifest_is_refused(self):
        self.w.mci.outputs[(WS, P)] = []
        self.w.build()
        f = self.w.cand / "conformance-manifest.json"
        m = json.loads(f.read_text())
        for s in m["suites"]:
            s["status"] = "pass"
        f.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
        self.assertRefused(self.w.gate(), "conformance-manifest.json")

    def test_a_plugin_verdict_judged_against_another_core_pin_is_rerun_or_refused(self):
        self.w.mci.outputs[(WS, P)] = [verdict("ws", WS, P, OLD_CORE)]
        # ModernCI cannot re-run against T: the suite is not-run and the tag is refused.
        m = self.w.build()
        self.assertIn((WS, P, T), self.w.mci.rerun_calls)
        ws = next(s for s in m["suites"] if s["suite"] == "ws")
        self.assertEqual(ws["status"], "not-run")
        self.assertIn(OLD_CORE[:12], ws["reason"])
        self.assertRefused(self.w.gate(), "ws")
        # ModernCI re-runs P against T: that verdict is the one used.
        self.w.mci.reruns[(WS, P, T)] = [verdict("ws", WS, P, T)]
        m = self.w.build()
        self.assertEqual(status(m, "ws"), "pass")
        self.assertEqual(next(s for s in m["suites"] if s["suite"] == "ws")["core_pin"], T)
        self.assertEqual(self.w.gate(), [])
        # A re-run that comes back stamped for another core still does not count.
        self.w.mci.reruns[(WS, P, T)] = [verdict("ws", WS, P, OLD_CORE)]
        self.assertEqual(status(self.w.build(), "ws"), "not-run")
        self.assertRefused(self.w.gate(), "ws")

    def test_a_plugin_verdict_on_the_released_test_kit_counts(self):
        # Lead's ruling (KICKOFF: plugins test against a released core test kit): a plugin's verdict
        # counts when its core pin is the released test-kit commit the release names (the plugins'
        # .busbar-ref), not T. Core suites still need T.
        kit = "7" * 40
        self.w.mci.outputs[(WS, P)] = [verdict("ws", WS, P, kit)]
        m = self.w.build(testkit=kit)
        ws = next(s for s in m["suites"] if s["suite"] == "ws")
        self.assertEqual((ws["status"], ws["core_pin"]), ("pass", kit))
        self.assertEqual(self.w.mci.rerun_calls, [])
        self.assertEqual(self.w.gate(testkit=kit), [])
        # The test-kit commit not named: the T rule holds and the tag is refused.
        self.assertEqual(status(self.w.build(), "ws"), "not-run")
        self.assertRefused(self.w.gate(), "ws")
        # Named, a plugin verdict on any other core still does not count.
        self.w.mci.outputs[(WS, P)] = [verdict("ws", WS, P, OLD_CORE)]
        self.assertEqual(status(self.w.build(testkit=kit), "ws"), "not-run")
        self.assertIn((WS, P, kit), self.w.mci.rerun_calls)
        self.assertRefused(self.w.gate(testkit=kit), "ws")
        # Core suites are never judged on the test kit: tls stamped on it is not used.
        self.w.mci.outputs[(WS, P)] = [verdict("ws", WS, P, kit)]
        self.w.mci.outputs[(CORE, T)] = [verdict("tls", CORE, T, kit)]
        self.assertEqual(status(self.w.build(testkit=kit), "tls"), "not-run")
        self.assertRefused(self.w.gate(testkit=kit), "tls")

    def test_a_stale_plugin_pin_is_refused(self):
        self.w.build()
        self.w.mci.heads[WS] = "b" * 40  # dev moved on after the pin
        self.assertRefused(self.w.gate(), WS, "dev head")
        # A signed, listed pin exception for exactly that commit admits it.
        self.w.except_({"schema": "busbar.conformance.exceptions/1", "release": "1.6.0", "suites": [],
                        "pins": [{"repo": "busbar-transport-ws", "commit": P, "reason": "dev holds an unreleased ABI change"}]})
        self.assertEqual(self.w.gate(), [])
        # One for another commit does not.
        self.w.except_({"schema": "busbar.conformance.exceptions/1", "release": "1.6.0", "suites": [],
                        "pins": [{"repo": "busbar-transport-ws", "commit": "c" * 40, "reason": "x"}]})
        self.assertRefused(self.w.gate(), WS)

    def test_a_dist_pin_that_is_not_the_judged_commit_is_refused(self):
        self.w.build()
        lock = self.w.root / "dist" / "default" / "Cargo.lock"
        lock.write_text(lock.read_text().replace(P, "d" * 40))
        self.w.mci.heads[WS] = "d" * 40
        self.assertRefused(self.w.gate(), WS)

    def test_a_signed_suite_exception_admits_and_records_not_run_never_pass(self):
        self.w.mci.outputs[(WS, P)] = []
        self.w.except_({"schema": "busbar.conformance.exceptions/1", "release": "1.6.0", "pins": [],
                        "suites": [{"suite": "ws", "status": "not-run", "reason": "Autobahn rig moves to 1.6.1"}]})
        m = self.w.build()
        ws = next(s for s in m["suites"] if s["suite"] == "ws")
        self.assertEqual((ws["status"], ws["claim"]), ("not-run", None))
        self.assertTrue(ws["reason"].startswith("owner exception (signed): Autobahn rig moves to 1.6.1"))
        self.assertEqual(self.w.gate(), [])
        # The exception covers only the status the owner signed: a fail is not covered.
        self.w.mci.outputs[(WS, P)] = [verdict("ws", WS, P, T, status="fail", reason="9.1.6")]
        self.w.build()
        self.assertRefused(self.w.gate(), "ws")

    def test_an_exception_that_claims_pass_is_refused(self):
        self.w.mci.outputs[(WS, P)] = []
        self.w.except_({"schema": "busbar.conformance.exceptions/1", "release": "1.6.0", "pins": [],
                        "suites": [{"suite": "ws", "status": "pass", "reason": "trust me"}]})
        self.w.build()
        self.assertRefused(self.w.gate(), "pass")

    def test_an_unsigned_or_tampered_exception_is_refused(self):
        self.w.mci.outputs[(WS, P)] = []
        doc = {"schema": "busbar.conformance.exceptions/1", "release": "1.6.0", "pins": [],
               "suites": [{"suite": "ws", "status": "not-run", "reason": "later"}]}
        self.w.except_(doc, sign=False)
        self.w.build()
        self.assertRefused(self.w.gate(), "conformance-exceptions.json")
        self.w.except_(doc)
        f = self.w.root / "release" / "conformance-exceptions.json"
        f.write_text(f.read_text().replace("later", "later!"))
        self.assertRefused(self.w.gate(), "conformance-exceptions.json")

    def test_an_exception_for_another_release_does_not_cover(self):
        self.w.mci.outputs[(WS, P)] = []
        self.w.except_({"schema": "busbar.conformance.exceptions/1", "release": "1.5.5", "pins": [],
                        "suites": [{"suite": "ws", "status": "not-run", "reason": "old"}]})
        self.w.build()
        self.assertRefused(self.w.gate(), "ws")


if __name__ == "__main__":
    unittest.main()

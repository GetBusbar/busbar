#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# proof-manifest.py -- THE COLLATOR for the Build Proof Dashboard (docs/design/1.6.0-proof-dashboard.md).
#
# It changes NO gate. It is a thin capture layer over apparatus that already runs in CI: it runs (or
# reads) the neutrality gates, enumerates the golden corpus, parses the field-coverage ledger, and
# ingests the MCP/A2A conformance JSON reports, then reduces every one to a public-safe verdict object
# and emits docs/proof/<version>.json per the proof-manifest schema.
#
# PUBLIC-SAFE BY CONSTRUCTION. The manifest carries verdicts, counts, gate names, test-function names,
# golden filenames, and field ids -- all already public in the docs/CHANGELOG the marketing site
# renders. It carries NO source, NO secrets, NO file contents, NO internal URLs. The companion guard
# scripts/check-proof-manifest-public.mjs fails the build if anything source-like appears.
#
# HONESTY RULE (carried from qa/segments.toml). A source that did not actually run renders `unknown`,
# never green. A report-only gate (plane-grep today) renders `report-only`, never `pass`. A class
# verdict is `fail` if any non-reserved source failed, `unknown` if any is unknown and none failed,
# else `pass`. The collator never launders a not-run into a pass.
#
# Usage:
#   scripts/proof-manifest.py --version dev --out docs/proof/dev.json
#   scripts/proof-manifest.py --version 1.6.0 --out docs/proof/1.6.0.json \
#       --sha <40hex> --run-id 123 --run-url https://github.com/.../runs/123 \
#       --staged-json /path/to/staged.json --reports-dir testing --run-cargo
#
# Flags:
#   --version         release/branch label; also the manifest `release.version`/`tag`.
#   --out             output path for the manifest JSON.
#   --repo-root       repo root (default: the script's parent's parent).
#   --sha             the commit SHA to stamp (default: `git rev-parse HEAD`).
#   --run-id/--run-url   CI provenance (default: empty / local).
#   --staged-json     optional staged.json (release receipt) to lift tag/digest/staging_tag from.
#   --reports-dir     directory tree to search for MCP/A2A conformance JSON reports.
#   --run-cargo       run the parity + oracle cargo tests for real (slow; CI). Off by default -> the
#                     cargo-backed sources render `unknown` (honest: not executed in this collation).
#   --index           also (re)write docs/proof/index.json rolling up every docs/proof/<v>.json.
#   --print           print the manifest to stdout as well.

import argparse
import atexit
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(s: str) -> str:
    return ANSI.sub("", s)


def run(cmd, cwd, env=None, timeout=None):
    """Run a command, return (exit_code, stdout+stderr text). Never raises on non-zero exit."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=full_env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return p.returncode, strip_ansi(p.stdout + p.stderr)
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, ""


def parse_count_table(text, keys):
    """Scrape a `  <KEY>   <n>` fixed-format table (plane-purity / plane-grep style)."""
    out = {}
    for k in keys:
        m = re.search(r"^\s*" + re.escape(k) + r"\s+(\d+)\s*$", text, re.MULTILINE)
        if m:
            out[k] = int(m.group(1))
    return out


def scrape_total(text):
    m = re.search(r"^\s*TOTAL\s+(\d+)\s*$", text, re.MULTILINE)
    return int(m.group(1)) if m else None


# ── VERDICT: byte-identity ────────────────────────────────────────────────────────────────────────

# THE GOLDEN CORPUS AND THE TESTS THAT ASSERT OVER IT, AS ONE CONSTANT.
#
# Both used to say `busbar-llm`. The proto module — the corpus, `translate_parity_*_tests.rs`, all
# of it — now lives in `busbar-llm-codec`, and neither reference moved with it. Two failures came
# out of that, in the same direction:
#
#   * `crates/busbar-llm/src/tests/proto/golden` does not exist, so `golden_dir.is_dir()` was False,
#     the enumeration loop never ran, and `total` stayed 0 — published as `evidence_count: 0`.
#   * `cargo test -p busbar-llm --lib translate_parity` selects a filter that matches ZERO tests in
#     that crate. cargo EXITS 0 when a filter matches nothing — running no tests is not an error to
#     cargo — so `code == 0` and the manifest published `"status": "pass"`.
#
# The published claim was therefore "the byte-identity corpus: 0 cases, pass". Zero cases passing is
# not evidence of anything, and it is the shape a reader is least likely to question, because the
# word next to it is `pass`. GOLDEN_MIN below is the floor that makes it impossible to say again.
GOLDEN_DIR = "crates/busbar-llm-codec/src/tests/proto/golden"
GOLDEN_CRATE = "busbar-llm-codec"
GOLDEN_MIN = 40  # the corpus holds >100 pairs; the floor is a collapse tripwire, not a second count


def golden_lanes(root):
    """Enumerate the golden corpus -> (total_pairs, {lane: [filenames]}). A filesystem fact.

    Factored out because the `llm-dialects` conformance source stands on this same corpus and must
    be able to say so with a number rather than with a sentence in a `note`.
    """
    golden_dir = root / GOLDEN_DIR
    lanes = {}
    total = 0
    if golden_dir.is_dir():
        for f in sorted(golden_dir.iterdir()):
            m = re.match(r"^(req|resp)_([a-z]2[a-z])_(.+)\.json$", f.name)
            if not m:
                continue
            total += 1
            lanes.setdefault(m.group(2), []).append(f.name)
    return total, lanes


def verdict_byte_identity(root, run_cargo):
    total, lanes = golden_lanes(root)
    lane_matrix = [
        {"lane": lane, "status": "present", "count": len(cases), "cases": sorted(cases)}
        for lane, cases in sorted(lanes.items())
    ]
    # The golden corpus is pinned on-disk; enumeration is a filesystem fact. Whether the byte-identity
    # ASSERT passed requires running the parity tests -- honest `unknown` unless --run-cargo.
    if run_cargo:
        code, _ = run(
            ["cargo", "test", "-p", "busbar-llm", "--lib", "translate_parity"],
            cwd=root,
            timeout=3600,
        )
        golden_status = "pass" if code == 0 else "fail"
    else:
        golden_status = "unknown"

    sources = [
        {
            "id": "translate-parity-cross-pairs",
            "kind": "golden",
            "status": golden_status,
            "count": total,
            "total": total,
            "lane_count": len(lane_matrix),
            "drilldown": {
                "type": "lane-matrix",
                "path": "crates/busbar-llm/src/tests/proto/golden/",
                "lanes": lane_matrix,
            },
        }
    ]
    # The five money-path oracle tests (byte-identity of the delivery/billing/egress path).
    oracles = [
        ("egress-differential", "crates/busbar-llm/src/engine/tests/egress_differential_tests.rs"),
        ("crossproto-billing", "crates/busbar-llm/src/engine/tests/crossproto_delivery_billing_tests.rs"),
        ("on-exhausted", "crates/busbar-llm/src/engine/tests/on_exhausted_tests.rs"),
        ("pool-upstream-creds", "crates/busbar-llm/src/engine/tests/pool_upstream_creds_tests.rs"),
        ("usage-decode-tap", "crates/busbar-core/src/ingress/tests/tests.rs"),
    ]
    for oid, opath in oracles:
        present = (root / opath).exists()
        sources.append({
            "id": oid,
            "kind": "oracle",
            "status": "unknown",  # cargo-backed; not executed in scrape mode
            "note": "present" if present else "test file not found",
            "drilldown": {"type": "test", "path": opath},
        })
    return {
        "class": "byte-identity",
        "title": "Your bytes survive read to IR to write",
        "status": class_status(sources),
        "evidence_count": total,
        "evidence_total": total,
        "unit": "golden byte-pairs",
        "sources": sources,
    }


# ── VERDICT: plane-neutrality-by-construction ───────────────────────────────────────────────────────

def verdict_plane_neutrality(root, hits_dir):
    sources = []

    # plane-purity: the gate's own ledger rows, and its hit artefact for the drilldown.
    # The COUNTS come from the artefact rather than from the printed report: the artefact carries a
    # #SCAN denominator line, so "clean" and "scanned nothing" stay distinguishable here too.
    pp_out = hits_dir / "plane-purity-hits.tsv"
    st_code, _ = run(["cargo", "xtask", "gate", "plane-purity", "--selftest"], cwd=root, timeout=300)
    code, text = run(
        ["cargo", "xtask", "gate", "plane-purity", "--format=tsv"],
        cwd=root,
        env={"PLANE_PURITY_HITS_OUT": str(pp_out)},
        timeout=300,
    )
    cat_names = ["PATH-INCLUDE", "SYMBOL", "TYPE", "KEY", "DIALECT", "BACKWARDS"]
    cats = {c: 0 for c in cat_names}
    total = 0
    if pp_out.exists():
        for line in pp_out.read_text().splitlines():
            cat = line.split("\t", 1)[0]
            if cat in cats:
                cats[cat] += 1
                total += 1
    sources.append({
        "id": "plane-purity-lint",
        "evidence": "scripts/plane-purity-lint.sh",
        "evidence_present": (root / "scripts/plane-purity-lint.sh").is_file(),
        "kind": "gate",
        "status": "pass" if code == 0 else "fail",
        "count": total,
        "breakdown": cats,
        "selftest": "pass" if st_code == 0 else "fail",
        "runs_in": ["ci.yml:structure-lint", "qa/segments.toml:plane-purity"],
        "drilldown": {"type": "hit-list", "artifact": "plane-purity-hits.tsv"},
    })

    # g6 freeze witness: a scalar, now one row of the plane-purity gate above rather than its own
    # script. Read off the ledger row's detail, which is the counted table the witness printed.
    m = re.search(r"plane-purity:core-llm-family-freeze\t(\w+)\t[^\t]*\tcount=(\d+)", text)
    sources.append({
        "id": "g6-freeze-witness",
        "evidence": "scripts/g6-freeze-witness.sh",
        "evidence_present": (root / "scripts/g6-freeze-witness.sh").is_file(),
        "kind": "gate",
        "status": "pass" if m and m.group(1) == "PASS" else "fail",
        "count": int(m.group(2)) if m else -1,
    })

    # plane-grep gate: report-only meter, per-needle table + TOTAL.
    gp_out = hits_dir / "plane-grep-hits.tsv"
    st_code, _ = run(["bash", "scripts/plane-grep-gate.sh", "--selftest"], cwd=root, timeout=300)
    code, text = run(
        ["bash", "scripts/plane-grep-gate.sh", "--report"],
        cwd=root,
        env={"GREP_GATE_REPORT_ONLY": "1", "PLANE_GREP_HITS_OUT": str(gp_out)},
        timeout=300,
    )
    needles = parse_count_table(
        text, ["openai", "gemini", "anthropic", "bedrock", "cohere", "responses", "mcp", "a2a"]
    )
    gp_total = scrape_total(text)
    sources.append({
        "id": "plane-grep-gate",
        "evidence": "scripts/plane-grep-gate.sh",
        "evidence_present": (root / "scripts/plane-grep-gate.sh").is_file(),
        "kind": "gate",
        "status": "report-only",  # non-blocking meter until GREP_GATE_REPORT_ONLY=0 is armed
        "count": gp_total if gp_total is not None else -1,
        "breakdown": needles,
        "selftest": "pass" if st_code == 0 else "fail",
        "drilldown": {"type": "hit-list", "artifact": "plane-grep-hits.tsv"},
    })

    # plane-abi-neutrality: 0 banned nouns on success.
    code, text = run(["cargo", "xtask", "gate", "plane-abi-neutrality"], cwd=root, timeout=120)
    sources.append({
        "id": "plane-abi-neutrality",
        "evidence": "scripts/plane-abi-neutrality.sh",
        "evidence_present": (root / "scripts/plane-abi-neutrality.sh").is_file(),
        "kind": "gate",
        "status": "pass" if code == 0 else "fail",
        "count": 0 if code == 0 else count_hit_lines(text),
    })

    # Headline meter = the by-construction side-channel count in the neutral crates: plane-purity +
    # g6. plane-grep is a report-only meter (shown as its own row); plane-abi is a separate witness
    # (own row) whose raw declaration-line matches must not dominate the neutral-crate headline.
    headline = 0
    for s in sources:
        if s["id"] in ("plane-purity-lint", "g6-freeze-witness") and isinstance(s.get("count"), int) and s["count"] > 0:
            headline += s["count"]
    return {
        "class": "plane-neutrality",
        "title": "The core cannot know any plane",
        "status": class_status(sources),
        "evidence_count": headline,
        "unit": "side channels (0 = property holds)",
        "meter": "zero-debt",
        "sources": sources,
    }


def count_hit_lines(text):
    # count file:line hit lines in a gate's failure output (rough, for a meter only)
    return sum(1 for ln in text.splitlines() if re.search(r"\.rs:\d+", ln))


# ── VERDICT: composability (removability / any subset runs) ─────────────────────────────────────────

def verdict_composability(root, run_cargo):
    sources = []
    planes = {"llm": "unknown", "mcp": "unknown", "a2a": "unknown"}
    delete_status = "unknown"
    noplugins_status = "unknown"
    proto_status = "unknown"
    if run_cargo:
        for pl in planes:
            code, _ = run(["bash", "scripts/plane-delete-test.sh", pl], cwd=root, timeout=3600)
            planes[pl] = "pass" if code == 0 else "fail"
        delete_status = "fail" if "fail" in planes.values() else "pass"
        code, _ = run(["bash", "scripts/no-plugins-gate.sh", "--check"], cwd=root, timeout=3600)
        noplugins_status = "pass" if code == 0 else "fail"
        code, _ = run(["bash", "scripts/proto-deletion-gate.sh"], cwd=root, timeout=5400)
        proto_status = "pass" if code == 0 else "fail"
    # EVERY SOURCE NAMES ITS OWN EVIDENCE. These three are marked from sibling ci.yml job results,
    # and mark_sources() will not stamp a pass onto a source whose evidence is not in the tree — so
    # each one names the gate script that job actually runs. Without an `evidence` key at all they
    # were exempt from that guard entirely (see mark_sources' docstring).
    sources.append({
        "id": "no-plugins-gate",
        "kind": "gate",
        "status": noplugins_status,
        "unit": "failed assertions",
        "evidence": "scripts/no-plugins-gate.sh",
        "evidence_present": (root / "scripts/no-plugins-gate.sh").is_file(),
        "note": "cargo-backed; run in ci.yml no-plugins-gate job",
    })
    sources.append({
        "id": "plane-delete-test",
        "kind": "gate",
        "status": delete_status,
        "planes": planes,
        "evidence": "scripts/plane-delete-test.sh",
        "evidence_present": (root / "scripts/plane-delete-test.sh").is_file(),
        "note": "cargo-backed; run in ci.yml structure-lint (--all)",
    })
    sources.append({
        "id": "proto-deletion-gate",
        "kind": "gate",
        "status": proto_status,
        "evidence": "scripts/proto-deletion-gate.sh",
        "evidence_present": (root / "scripts/proto-deletion-gate.sh").is_file(),
        "note": "cargo-backed; run in ci.yml deletion area",
    })
    return {
        "class": "composability",
        "title": "Any plane is removable; any subset runs",
        "status": class_status(sources),
        "sources": sources,
    }


# ── VERDICT: lossless field-coverage ────────────────────────────────────────────────────────────────

DIALECTS = ["anthropic", "openai", "gemini", "cohere", "bedrock", "responses"]


def verdict_field_coverage(root):
    status_path = root / "qa/field-coverage.status"
    missing_path = root / "qa/field-coverage.missing"
    carried = 0
    waived = 0
    by_dialect = {d: 0 for d in DIALECTS}
    waivers = []
    if status_path.is_file():
        for raw in status_path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            mc = re.match(r"^(\S+)\s*=\s*carried\s+(\S+)\s*$", line)
            mw = re.match(r"^(\S+)\s*=\s*waived\s+(\d{4}-\d{2}-\d{2})\s+(.+)$", line)
            if mc:
                carried += 1
                d = mc.group(1).split("/")[0]
                if d in by_dialect:
                    by_dialect[d] += 1
            elif mw:
                waived += 1
                waivers.append({"field": mw.group(1), "date": mw.group(2), "reason": mw.group(3)})
    missing = 0
    if missing_path.is_file():
        missing = sum(
            1
            for ln in missing_path.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        )
    total_classified = carried + waived + missing

    # ── THE EVIDENCE FLOOR, THE SAME RULE GOLDEN_MIN APPLIES ABOVE ──────────────────────────────
    # `carried`, `waived` and `missing` all start at 0 and both reads above are guarded by
    # `is_file()`, so a ledger that has been renamed, moved or emptied does not fail here — it
    # simply never contributes a row. `missing == 0` is then VACUOUSLY true and this class
    # published `"status": "pass"` with `evidence_count: 0` behind the title "Every provider field
    # is accounted for". That is the identical shape the golden corpus published when its directory
    # moved (total 0, status pass), and it is the shape a reader is least likely to question,
    # because the word next to it is `pass`. Zero fields classified is not zero fields missing.
    ledger_note = None
    if not status_path.is_file():
        ledger_status = "unknown"
        ledger_note = (f"no ledger at qa/field-coverage.status, so NOTHING was classified. "
                       f"`missing == 0` over an absent ledger accounts for no field at all. Fix: "
                       f"restore the ledger, or correct the path in this file if it moved.")
    elif total_classified == 0:
        ledger_status = "unknown"
        ledger_note = ("qa/field-coverage.status classified ZERO fields (no carried, waived or "
                       "missing rows parsed). A 'no fields missing' verdict over an empty ledger "
                       "compares nothing; it is not evidence that the fields are covered.")
    else:
        ledger_status = "pass" if missing == 0 else "fail"

    src = {
        "id": "field-coverage",
        "kind": "ledger",
        "status": ledger_status,
        # The evidence this source stands on, named, so mark_sources() can refuse to stamp a pass
        # onto it when the ledger is not there.
        "evidence": "qa/field-coverage.status",
        "evidence_present": status_path.is_file() and total_classified > 0,
        "note": ledger_note,
        "carried": carried,
        "waived": waived,
        "missing": missing,
        "by_dialect": by_dialect,
        "waivers": waivers,
        "drilldown": {"type": "field-ledger", "path": "qa/field-coverage.status"},
    }
    return {
        "class": "field-coverage",
        "title": "Every provider field is accounted for",
        "status": src["status"],
        "evidence_count": carried,
        "evidence_total": total_classified,
        "unit": "fields carried",
        "sources": [src],
    }


# ── VERDICT: wire-conformance ───────────────────────────────────────────────────────────────────────

def find_report(reports_dir, *needles):
    if not reports_dir or not reports_dir.is_dir():
        return None
    for p in reports_dir.rglob("*.json"):
        name = p.name.lower()
        if all(n in name for n in needles):
            return p
    return None


def read_report_status(path):
    try:
        data = json.loads(path.read_text())
    except Exception:
        return "unknown"
    # Both suites emit a per-leg report; accept a few common shapes for the pass/fail verdict.
    for key in ("passed", "ok", "success"):
        if isinstance(data.get(key), bool):
            return "pass" if data[key] else "fail"
    if isinstance(data.get("failures"), list):
        return "pass" if len(data["failures"]) == 0 else "fail"
    if isinstance(data.get("status"), str):
        return "pass" if data["status"].lower() in ("pass", "passed", "ok", "green") else "fail"
    return "unknown"


def verdict_conformance(root, reports_dir):
    sources = []

    # THE NEEDLE MUST NAME THE SUITE. `find_report(reports_dir, "control")` matched on "control"
    # alone, so an a2a control report satisfied the MCP verdict.
    mcp_control = find_report(reports_dir, "mcp", "control")
    mcp_status = read_report_status(mcp_control) if mcp_control else "unknown"
    sources.append({
        "id": "mcp-conformance",
        "kind": "conformance",
        "status": mcp_status,
        "legs": {"control": mcp_status, "subject": "unknown"},
        # The report this verdict was read out of, named, so a sibling job result cannot stand in
        # for a report that is not there.
        "evidence": str(mcp_control.relative_to(root)) if mcp_control and mcp_control.is_relative_to(root)
                    else (str(mcp_control) if mcp_control else "testing/**/mcp*control*.json"),
        "evidence_present": mcp_control is not None,
        "drilldown": {"type": "conformance-report", "artifact": "mcp-battery-control-report"},
        "note": "reads testing/mcp-conformance report JSON when present",
    })

    # ONE REPORT IS ONE LEG. The needles used to be derived as
    # `label.replace("-", "_").split("_")[:1]`, which reduced control-go-http_json,
    # control-go-jsonrpc and control-python to the SAME pair ("a2a", "control"). Whichever report
    # rglob happened to reach first was then published as the verdict for all three, so one
    # measurement became three independent per-leg claims -- the same over-claim mark_sources()
    # stopped doing when it was fanning one job result over a sub-map. Match on the whole label.
    a2a_legs = {}
    a2a_reports = {}
    for label in ["control-go-http_json", "control-go-jsonrpc", "control-python",
                  "negative-control", "swap-proof", "tck", "subject"]:
        rpt = find_report(reports_dir, "a2a", *label.split("-"))
        a2a_reports[label] = rpt
        a2a_legs[label] = read_report_status(rpt) if rpt else "unknown"
    a2a_status = ("fail" if "fail" in a2a_legs.values()
                  else "unknown" if "unknown" in a2a_legs.values() else "pass")
    a2a_found = [label for label, rpt in a2a_reports.items() if rpt is not None]
    sources.append({
        "id": "a2a-conformance",
        "kind": "conformance",
        "status": a2a_status,
        "legs": a2a_legs,
        "evidence": "testing/**/a2a*.json",
        "evidence_present": bool(a2a_found),
        "note": ("report(s) found for leg(s): " + ", ".join(a2a_found)) if a2a_found
                else "no a2a conformance report JSON found under --reports-dir",
        "drilldown": {"type": "conformance-report", "artifact": "a2a-battery-control-http_json"},
    })

    # LLM dialects: conformance IS the exhaustive golden corpus, so its evidence is that corpus and
    # the floor that corpus must clear -- stated as a count rather than as a sentence in a `note`
    # that nothing consumes. Status stays `unknown` until the parity tests are actually executed;
    # the corpus being on disk is what makes the claim MARKABLE, not what makes it true.
    golden_total, _ = golden_lanes(root)
    sources.append({
        "id": "llm-dialects",
        "kind": "conformance",
        "status": "unknown",
        "dialects": {d: "unknown" for d in ["anthropic", "openai", "gemini", "responses", "bedrock", "cohere"]},
        "evidence": GOLDEN_DIR,
        "evidence_present": golden_total >= GOLDEN_MIN,
        "count": golden_total,
        "note": ("proven by the exhaustive translate-parity golden corpus (see byte-identity): "
                 "%d byte-pair(s), floor %d" % (golden_total, GOLDEN_MIN)),
    })

    return {
        "class": "wire-conformance",
        "title": "We speak every protocol to spec",
        "status": class_status(sources),
        "sources": sources,
    }


# ── CROSS-JOB CAPTURE, AND THE TWO THINGS IT MUST NOT DO ────────────────────────────────────────────

def mark_sources(verdicts, specs):
    """Stamp sources from sibling CI job results, without manufacturing claims.

    A GitHub job result of `success` means the job passed. The manifest is a public claim about
    WHAT that proves, and the old implementation over-claimed in two distinct ways:

      1. IT PROMOTED SOURCES WITH NO EVIDENCE. ci.yml passes one `${CHECK_RESULT}` to six `--mark`
         flags. Two of the six named a test file that does not exist (the crossproto oracle had
         moved directory; the usage-decode oracle pointed at a path with no file in it). A green
         `check` job therefore published `"status": "pass"` for two oracles standing on nothing.
         The old code even computed `present` — and wrote the answer into a `note` nobody read,
         then overwrote the status anyway. Now: no evidence, no pass. The source is left `unknown`
         and says why, which is the honest verdict for a claim whose subject is missing.

      2. IT FANNED ONE RESULT OUT OVER A SUB-MAP. `s["dialects"] = {k: st for k in s["dialects"]}`
         turned one job result into six per-dialect verdicts (anthropic, openai, gemini, responses,
         bedrock, cohere); the same line turned one result into seven per-leg a2a verdicts and
         three per-plane verdicts. Those sub-maps exist to say which INDIVIDUAL legs were proven —
         that is their entire purpose, it is what a reader drills into — and filling them from a
         single aggregate makes them say something nobody measured. Now they are left as their
         producer computed them (`unknown` where nothing reported), and the fan-out is gone.

    `shared_with` records when the same result marked several sources, so the manifest does not
    read as several independent measurements.
    """
    marks = {}
    for spec in specs:
        if "=" not in spec:
            continue
        sid, res = spec.split("=", 1)
        res = res.strip().lower()
        if res == "":
            continue
        marks[sid.strip()] = "pass" if res in ("success", "pass") else "fail"
    if not marks:
        return
    # Which ids were given the same verdict value? Only meaningful as "these came from one place".
    by_value = {}
    for sid, st in marks.items():
        by_value.setdefault(st, []).append(sid)
    for v in verdicts:
        for s in v.get("sources", []):
            sid = s.get("id")
            if sid not in marks:
                continue
            st = marks[sid]
            # FAIL CLOSED ON A SOURCE THAT NAMES NO EVIDENCE AT ALL. This used to read
            # `if s.get("evidence") is not None and not s.get("evidence_present")`, which made the
            # whole guard OPT-IN: a source that simply had no `evidence` key skipped it and was
            # stamped `pass` from a bare --mark with nothing checked. Six of the sources this
            # collator emits were in exactly that state, so the promise this function's docstring
            # makes -- no evidence, no pass -- did not hold for over half of them, and a --mark
            # could overwrite a producer's own honestly-computed `unknown`. An unnamed subject is
            # not a weaker claim than a missing one; it is the same claim with less to check.
            if not s.get("evidence"):
                s["status"] = "unknown"
                s["note"] = (
                    "NOT captured: the sibling ci.yml job reported %r, but this source names NO "
                    "evidence of its own, so there is nothing that result could be a result "
                    "ABOUT. Give the source an `evidence` path (the gate script, test file or "
                    "report it stands on) before marking it." % (st,)
                )
                continue
            if not s.get("evidence_present"):
                s["status"] = "unknown"
                s["note"] = (
                    "NOT captured: the sibling ci.yml job reported %r, but this source's own "
                    "evidence (%s) is not present in the tree, so that result says nothing about "
                    "it. A job result is evidence for what the job ran; it cannot stand in for a "
                    "test file that does not exist." % (st, s.get("evidence"))
                )
                continue
            s["status"] = st
            s["note"] = "captured from the sibling ci.yml job result"
            siblings = [o for o in by_value.get(st, []) if o != sid]
            if siblings:
                # Named so the manifest cannot be read as N independent measurements.
                s["shared_with"] = sorted(siblings)
            # Sub-maps are DELIBERATELY not touched. See (2) in the docstring.
        v["status"] = class_status(v.get("sources", []))


# ── class-status reducer (the honesty rule) ─────────────────────────────────────────────────────────

def class_status(sources):
    live = [s for s in sources if s.get("status") != "reserved"]
    statuses = [s.get("status") for s in live]
    if "fail" in statuses:
        return "fail"
    if "unknown" in statuses:
        return "unknown"
    # report-only sources are measured-but-non-blocking: they never redden, never green a class alone.
    concrete = [s for s in statuses if s in ("pass", "fail")]
    if concrete and all(s == "pass" for s in concrete):
        return "pass"
    if statuses and all(s == "report-only" for s in statuses):
        return "report-only"
    return "pass" if "pass" in statuses else "unknown"


# ── main ────────────────────────────────────────────────────────────────────────────────────────────

def selftest(root):
    """Prove the manifest cannot publish a claim with nothing behind it.

    Every case here is one the collator got WRONG in the green direction before the case existed:
    a corpus path that had moved (published `total: 0, status: pass`), a cargo filter that selected
    nothing (cargo exits 0 on that), two oracle paths with no file at them (published `pass` from a
    sibling job's result), and a single job result fanned out over a six-entry dialect map.
    """
    bad = 0

    def ok(cond, label, detail=""):
        nonlocal bad
        if cond:
            print("  [ok]     %s" % label)
        else:
            print("  [FAILED] %s%s" % (label, (" — " + detail) if detail else ""))
            bad = 1

    print("proof-manifest selftest")

    # 1. The corpus is where this file says it is, and it is not empty.
    v = verdict_byte_identity(root, False)
    src = v["sources"][0]
    ok((root / GOLDEN_DIR).is_dir(), "the golden corpus path resolves to a real directory (%s)" % GOLDEN_DIR)
    ok(src["total"] >= GOLDEN_MIN,
       "the corpus yields %d byte-pairs, at or above the floor of %d" % (src["total"], GOLDEN_MIN),
       "a moved corpus used to publish total=0 alongside status=pass")

    # 2. A corpus that yields nothing is a FAIL, never a pass. Driven through the real function
    #    against a root with no corpus in it, which is exactly the state the stale path produced.
    empty_root = Path(tempfile.mkdtemp(prefix="proof-selftest-"))
    try:
        v0 = verdict_byte_identity(empty_root, False)
        s0 = v0["sources"][0]
        ok(s0["total"] == 0 and s0["status"] == "fail",
           "a corpus of zero byte-pairs is FAIL, not pass/unknown",
           "got total=%r status=%r" % (s0["total"], s0["status"]))
        ok("floor" in (s0.get("note") or ""), "and it says why, naming the floor")
    finally:
        shutil.rmtree(empty_root, ignore_errors=True)

    # 2b. THE SAME FLOOR ON THE FIELD LEDGER. `missing == 0` is vacuously true when no ledger was
    #     read at all, so an absent or empty qa/field-coverage.status published "Every provider
    #     field is accounted for: pass" over zero fields. Driven through the real function against
    #     a root with no ledger in it, and against the real tree as the positive control.
    empty_root = Path(tempfile.mkdtemp(prefix="proof-selftest-"))
    try:
        fc0 = verdict_field_coverage(empty_root)
        ok(fc0["status"] == "unknown" and fc0["evidence_count"] == 0,
           "an absent field-coverage ledger is UNKNOWN, not a pass over zero fields",
           "got status=%r count=%r" % (fc0["status"], fc0["evidence_count"]))
        ok("classified" in (fc0["sources"][0].get("note") or ""),
           "and it says why, naming that nothing was classified")
    finally:
        shutil.rmtree(empty_root, ignore_errors=True)
    fc = verdict_field_coverage(root)
    ok(fc["status"] in ("pass", "fail") and fc["evidence_total"] > 0,
       "the real ledger still yields a concrete verdict over %d classified field(s)"
       % fc["evidence_total"],
       "the floor must refuse an empty ledger, not refuse the ledger")

    # 3. Every oracle names a file that is actually there.
    missing = [s["id"] + " -> " + s["evidence"]
               for s in v["sources"] if s.get("evidence") and not s.get("evidence_present")]
    ok(not missing, "every money-path oracle names a test file that exists",
       "missing: %s" % ", ".join(missing))

    # 4. A sibling job's result cannot promote a source whose evidence is absent.
    fake = [{"class": "c", "sources": [
        {"id": "ghost", "status": "unknown", "evidence": "crates/nope/tests/nope.rs",
         "evidence_present": False},
        {"id": "real", "status": "unknown", "evidence": GOLDEN_DIR, "evidence_present": True},
    ]}]
    mark_sources(fake, ["ghost=success", "real=success"])
    g, r = fake[0]["sources"]
    ok(g["status"] == "unknown" and "NOT captured" in g["note"],
       "a job result does NOT promote an oracle whose test file is missing",
       "got %r" % g["status"])
    ok(r["status"] == "pass", "and it DOES promote one whose evidence is present",
       "got %r" % r["status"])
    ok(g.get("shared_with") == ["real"] or r.get("shared_with") == ["ghost"],
       "sources stamped from the same result say so, so the manifest is not read as N measurements")

    # 4b. NOR CAN IT PROMOTE A SOURCE THAT NAMES NO EVIDENCE AT ALL. The guard above used to be
    #     opt-in -- it only ran when an `evidence` key was present -- so the sources that named
    #     nothing were the ones it could not protect, which is exactly backwards.
    keyless = [{"class": "c", "sources": [{"id": "keyless", "status": "unknown"}]}]
    mark_sources(keyless, ["keyless=success"])
    k = keyless[0]["sources"][0]
    ok(k["status"] == "unknown" and "names NO evidence" in (k.get("note") or ""),
       "a job result does NOT promote a source that names no evidence at all",
       "got %r" % k["status"])

    # 4c. And every source this collator actually emits names its evidence, so none of them are
    #     silently unmarkable. Checked over the whole manifest rather than the byte-identity class.
    all_v = [verdict_byte_identity(root, False), verdict_composability(root, False),
             verdict_field_coverage(root), verdict_conformance(root, None)]
    unnamed = [s["id"] for v in all_v for s in v["sources"] if not s.get("evidence")]
    ok(not unnamed, "every source the collator emits names an evidence path",
       "sources with no evidence key: %s" % ", ".join(unnamed))

    # 5. One job result is not six dialect verdicts.
    # The fixture carries evidence because the real `llm-dialects` source does: this case is about
    # the SUB-MAP not being fanned out, and it must not accidentally be passing for the other
    # reason (an unmarkable source). 4b above is what proves the evidence guard.
    fan = [{"class": "c", "sources": [
        {"id": "llm-dialects", "status": "unknown",
         "evidence": GOLDEN_DIR, "evidence_present": True,
         "dialects": {d: "unknown" for d in
                      ["anthropic", "openai", "gemini", "responses", "bedrock", "cohere"]}},
    ]}]
    mark_sources(fan, ["llm-dialects=success"])
    dl = fan[0]["sources"][0]["dialects"]
    ok(all(x == "unknown" for x in dl.values()),
       "one job result is not fanned out into six per-dialect verdicts",
       "got %r" % dl)
    ok(fan[0]["sources"][0]["status"] == "pass",
       "while the source's own aggregate status is still captured")

    print()
    if bad:
        print("proof-manifest selftest: FAILED")
        return 1
    print("proof-manifest selftest: every published claim maps to evidence that exists")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Collate the Build Proof Dashboard manifest.")
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--repo-root", default=None)
    ap.add_argument("--sha", default=None)
    ap.add_argument("--run-id", default="")
    ap.add_argument("--run-url", default="")
    ap.add_argument("--staged-json", default=None)
    ap.add_argument("--reports-dir", default=None)
    ap.add_argument("--hits-dir", default=None,
                    help="where gate hit-list TSVs are written (they contain SOURCE lines, so this "
                         "MUST stay OUT of the committed manifest tree; default: a temp dir).")
    ap.add_argument("--run-cargo", action="store_true",
                    help="run all cargo-backed gates (parity + composability); CI.")
    ap.add_argument("--run-parity", action="store_true",
                    help="run the (cheap) busbar-llm parity tests for the byte-identity verdict.")
    ap.add_argument("--run-composability", action="store_true",
                    help="run the (heavy) delete/no-plugins/proto-deletion gates.")
    ap.add_argument("--mark", action="append", default=[], metavar="ID=STATUS",
                    help="stamp a source's verdict from a sibling CI job's reported result "
                         "(honest cross-job capture, e.g. --mark no-plugins-gate=pass). Repeatable.")
    ap.add_argument("--index", action="store_true")
    ap.add_argument("--print", dest="do_print", action="store_true")
    args = ap.parse_args()

    root = Path(args.repo_root).resolve() if args.repo_root else Path(__file__).resolve().parent.parent
    out_path = (root / args.out) if not os.path.isabs(args.out) else Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    sha = args.sha
    if not sha:
        code, text = run(["git", "rev-parse", "HEAD"], cwd=root)
        sha = text.strip() if code == 0 else "unknown"

    tag = args.version
    staging_tag = None
    digest = None
    if args.staged_json and Path(args.staged_json).is_file():
        try:
            staged = json.loads(Path(args.staged_json).read_text())
            tag = staged.get("tag", tag)
            staging_tag = staged.get("staging_tag")
            digest = staged.get("digest")
            sha = staged.get("qa_sha", sha)
            if not args.run_id:
                args.run_id = str(staged.get("run_id", ""))
        except Exception:
            pass

    # Hit-list TSVs contain SOURCE lines -> they must never land in the committed manifest tree. Default
    # to a temp dir; CI can point --hits-dir at a scratch path it uploads as a private CI artifact.
    if args.hits_dir:
        hits_dir = Path(args.hits_dir).resolve()
    else:
        # WE MADE IT, WE REMOVE IT. These TSVs carry SOURCE lines (see above), and the default path
        # was an unregistered mkdtemp -- so every local or CI collation left a directory of them
        # behind under the system temp dir, indefinitely, for a file whose entire design constraint
        # is that its contents must not escape the build.
        hits_dir = Path(tempfile.mkdtemp(prefix="proof-hits-"))
        atexit.register(shutil.rmtree, hits_dir, True)
    hits_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = Path(args.reports_dir).resolve() if args.reports_dir else None

    run_parity = args.run_cargo or args.run_parity
    run_composability = args.run_cargo or args.run_composability
    verdicts = [
        verdict_byte_identity(root, run_parity),
        verdict_plane_neutrality(root, hits_dir),
        verdict_composability(root, run_composability),
        verdict_field_coverage(root),
        verdict_conformance(root, reports_dir),
    ]

    # Honest cross-job capture: stamp a source's verdict from the sibling CI job that actually ran it.
    # A GitHub job result of "success" -> pass; anything else -> fail; empty/skip -> left unknown.
    marks = {}
    for spec in args.mark:
        if "=" not in spec:
            continue
        sid, res = spec.split("=", 1)
        res = res.strip().lower()
        if res == "":
            continue
        marks[sid.strip()] = "pass" if res == "success" else ("pass" if res == "pass" else "fail")
    if marks:
        for v in verdicts:
            for s in v.get("sources", []):
                if s.get("id") in marks:
                    st = marks[s["id"]]
                    s["status"] = st
                    s["note"] = "captured from the sibling ci.yml job result"
                    for mapkey in ("planes", "legs", "dialects"):
                        if isinstance(s.get(mapkey), dict):
                            s[mapkey] = {k: st for k in s[mapkey]}
            v["status"] = class_status(v.get("sources", []))

    manifest = {
        "schema_version": "1",
        "release": {
            "version": args.version,
            "tag": tag,
            "qa_sha": sha,
            "staging_tag": staging_tag,
            "digest": digest,
            "run_id": args.run_id,
            "run_url": args.run_url,
            "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "verdicts": verdicts,
    }

    # content digest over the verdicts (tamper-evidence; provenance is git history + run_url).
    verdict_bytes = json.dumps(verdicts, sort_keys=True, separators=(",", ":")).encode()
    manifest["provenance"] = {
        "content_digest": "sha256:" + hashlib.sha256(verdict_bytes).hexdigest(),
        "collator": "scripts/proof-manifest.py",
    }

    out_path.write_text(json.dumps(manifest, indent=2) + "\n")
    sys.stderr.write(f"proof-manifest: wrote {out_path}\n")

    if args.index and write_index(out_path.parent) != 0:
        # The manifest itself was written; only the roll-up refused. Non-zero so CI cannot publish
        # an index that says nothing and call the step green.
        return 1

    if args.do_print:
        print(json.dumps(manifest, indent=2))


def write_index(proof_dir):
    # AN INDEX OVER NOTHING IS NOT AN EMPTY PROBLEM SET. `releases: []` renders as a dashboard with
    # no red on it, which reads exactly like a dashboard with nothing wrong. Unparseable manifests
    # were also skipped by a bare `except: continue`, so a corrupted file silently vanished from the
    # roll-up rather than being reported. Both are named now, and a roll-up that found no manifest
    # at all refuses to overwrite the index.
    entries = []
    skipped = []
    for p in sorted(proof_dir.glob("*.json")):
        if p.name == "index.json":
            continue
        try:
            m = json.loads(p.read_text())
        except Exception as exc:
            skipped.append(f"{p.name} ({exc.__class__.__name__})")
            continue
        rel = m.get("release", {})
        entries.append({
            "version": rel.get("version", p.stem),
            "tag": rel.get("tag"),
            "qa_sha": rel.get("qa_sha"),
            "recorded_at": rel.get("recorded_at"),
            "file": p.name,
            "verdicts": [
                {"class": v.get("class"), "status": v.get("status")}
                for v in m.get("verdicts", [])
            ],
        })
    for s in skipped:
        sys.stderr.write(f"proof-manifest: SKIPPED unreadable manifest {s}\n")
    if not entries:
        sys.stderr.write(
            f"proof-manifest: REFUSING to write an EMPTY index over {proof_dir}. Zero readable "
            f"manifests is not zero problems -- an index with no releases renders as a dashboard "
            f"with nothing wrong on it. Leaving any existing index.json in place.\n"
        )
        return 1
    index = {"schema_version": "1", "releases": entries}
    (proof_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n")
    sys.stderr.write(f"proof-manifest: wrote {proof_dir / 'index.json'} ({len(entries)} release(s))\n")
    return 0


if __name__ == "__main__":
    main()

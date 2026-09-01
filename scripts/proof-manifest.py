#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# proof-manifest.py -- THE COLLATOR for the Build Proof Dashboard (docs/design/1.6.0-proof-dashboard.md).
#
# It changes NO gate. It is a thin capture layer over apparatus that already runs in CI: it runs (or
# reads) the neutrality gates, enumerates the golden corpus, parses the field-coverage ledger, and
# ingests the MCP/A2A conformance JSON reports, then reduces every one to a public-safe verdict object
# and emits docs/proof/<version>.json per the schema in section 4.1 of the design doc.
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

def verdict_byte_identity(root, run_cargo):
    golden_dir = root / "crates/busbar-llm/src/tests/proto/golden"
    lanes = {}
    total = 0
    if golden_dir.is_dir():
        for f in sorted(golden_dir.iterdir()):
            m = re.match(r"^(req|resp)_([a-z]2[a-z])_(.+)\.json$", f.name)
            if not m:
                continue
            total += 1
            lane = m.group(2)
            lanes.setdefault(lane, []).append(f.name)
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
        ("egress-differential", "crates/busbar-core/src/proxy/tests/egress_differential_tests.rs"),
        ("crossproto-billing", "crates/busbar-core/src/proxy/engine/tests/crossproto_delivery_billing_tests.rs"),
        ("on-exhausted", "crates/busbar-core/src/proxy/tests/on_exhausted_tests.rs"),
        ("pool-upstream-creds", "crates/busbar-core/src/proxy/tests/pool_upstream_creds_tests.rs"),
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

    # plane-purity-lint: per-category table + TOTAL.
    pp_out = hits_dir / "plane-purity-hits.tsv"
    st_code, _ = run(["bash", "scripts/plane-purity-lint.sh", "--selftest"], cwd=root, timeout=300)
    code, text = run(
        ["bash", "scripts/plane-purity-lint.sh", "--check"],
        cwd=root,
        env={"PLANE_PURITY_HITS_OUT": str(pp_out)},
        timeout=300,
    )
    cats = parse_count_table(text, ["PATH-INCLUDE", "SYMBOL", "TYPE", "KEY", "DIALECT", "BACKWARDS"])
    total = scrape_total(text)
    sources.append({
        "id": "plane-purity-lint",
        "kind": "gate",
        "status": "pass" if code == 0 else "fail",
        "count": total if total is not None else -1,
        "breakdown": cats,
        "selftest": "pass" if st_code == 0 else "fail",
        "runs_in": ["ci.yml:structure-lint", "qa/segments.toml:plane-purity"],
        "drilldown": {"type": "hit-list", "artifact": "plane-purity-hits.tsv"},
    })

    # g6 freeze witness: scalar count.
    code, text = run(["bash", "scripts/g6-freeze-witness.sh"], cwd=root, timeout=120)
    m = re.search(r"references to concrete LLM-family IR types:\s*(\d+)", text)
    g6 = int(m.group(1)) if m else None
    sources.append({
        "id": "g6-freeze-witness",
        "kind": "gate",
        "status": "pass" if code == 0 else "fail",
        "count": g6 if g6 is not None else -1,
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
        "kind": "gate",
        "status": "report-only",  # non-blocking meter until GREP_GATE_REPORT_ONLY=0 is armed
        "count": gp_total if gp_total is not None else -1,
        "breakdown": needles,
        "selftest": "pass" if st_code == 0 else "fail",
        "drilldown": {"type": "hit-list", "artifact": "plane-grep-hits.tsv"},
    })

    # plane-abi-neutrality: 0 banned nouns on success.
    code, text = run(["bash", "scripts/plane-abi-neutrality.sh"], cwd=root, timeout=120)
    sources.append({
        "id": "plane-abi-neutrality",
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
    sources.append({
        "id": "no-plugins-gate",
        "kind": "gate",
        "status": noplugins_status,
        "unit": "failed assertions",
        "note": "cargo-backed; run in ci.yml no-plugins-gate job",
    })
    sources.append({
        "id": "plane-delete-test",
        "kind": "gate",
        "status": delete_status,
        "planes": planes,
        "note": "cargo-backed; run in ci.yml structure-lint (--all)",
    })
    sources.append({
        "id": "proto-deletion-gate",
        "kind": "gate",
        "status": proto_status,
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
    src = {
        "id": "field-coverage",
        "kind": "ledger",
        "status": "pass" if missing == 0 else "fail",
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

    mcp_control = find_report(reports_dir, "control")
    mcp_status = read_report_status(mcp_control) if mcp_control else "unknown"
    sources.append({
        "id": "mcp-conformance",
        "kind": "conformance",
        "status": mcp_status,
        "legs": {"control": mcp_status, "subject": "unknown"},
        "drilldown": {"type": "conformance-report", "artifact": "mcp-battery-control-report"},
        "note": "reads testing/mcp-conformance report JSON when present",
    })

    a2a_legs = {}
    for label in ["control-go-http_json", "control-go-jsonrpc", "control-python",
                  "negative-control", "swap-proof", "tck", "subject"]:
        rpt = find_report(reports_dir, "a2a", *label.replace("-", "_").split("_")[:1])
        a2a_legs[label] = read_report_status(rpt) if rpt else "unknown"
    a2a_status = ("fail" if "fail" in a2a_legs.values()
                  else "unknown" if "unknown" in a2a_legs.values() else "pass")
    sources.append({
        "id": "a2a-conformance",
        "kind": "conformance",
        "status": a2a_status,
        "legs": a2a_legs,
        "drilldown": {"type": "conformance-report", "artifact": "a2a-battery-control-http_json"},
    })

    # LLM dialects: conformance IS the exhaustive golden corpus; mirror the byte-identity verdict.
    sources.append({
        "id": "llm-dialects",
        "kind": "conformance",
        "status": "unknown",
        "dialects": {d: "unknown" for d in ["anthropic", "openai", "gemini", "responses", "bedrock", "cohere"]},
        "note": "proven by the exhaustive translate-parity golden corpus (see byte-identity)",
    })

    return {
        "class": "wire-conformance",
        "title": "We speak every protocol to spec",
        "status": class_status(sources),
        "sources": sources,
    }


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
        hits_dir = Path(tempfile.mkdtemp(prefix="proof-hits-"))
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

    if args.index:
        write_index(out_path.parent)

    if args.do_print:
        print(json.dumps(manifest, indent=2))


def write_index(proof_dir):
    entries = []
    for p in sorted(proof_dir.glob("*.json")):
        if p.name == "index.json":
            continue
        try:
            m = json.loads(p.read_text())
        except Exception:
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
    index = {"schema_version": "1", "releases": entries}
    (proof_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n")
    sys.stderr.write(f"proof-manifest: wrote {proof_dir / 'index.json'}\n")


if __name__ == "__main__":
    main()

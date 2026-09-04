#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Render the Phase-0 parity baseline from a replay report.

  baseline-report.py <report.json> [--golden-meta meta.json] [--candidate-meta meta.json]
                     [--findings findings.md] > docs/design/PARITY-BASELINE-<date>.md

Applies the decision rule of the migration plan: weight 10 for money / refusal / admin / boot
divergences, 3 for wire bodies and audit, 1 for headers, metrics and scrape; KEEP HEAD iff
D/W <= 0.05 overall AND <= 0.20 in every weight-10 family AND every red cell is triaged.
"""
import json
import sys
from collections import Counter

HEAVY = {"admin.ops", "boot.refusal", "boot.warning", "billing", "plugins", "llm.wire", "route.failover", "config.migrate", "cli"}


def main() -> int:
    args = sys.argv[1:]
    rep = json.load(open(args[0]))
    findings = ""
    if "--findings" in args:
        findings = open(args[args.index("--findings") + 1]).read()
    t, fam = rep["totals"], rep["by_family"]
    overall = t["ratio"]
    heavy_bad = {f: s for f, s in fam.items() if f in HEAVY and s["ratio"] > 0.20}
    keep = overall <= 0.05 and not heavy_bad
    out = []
    out.append(f"# Parity baseline — {rep['meta'].get('candidate_version')} vs the published {rep['meta'].get('golden_version')}\n")
    out.append(f"Golden: `{rep['meta']['golden']}` · Candidate: `{rep['meta']['candidate']}` · cells: `{rep['meta']['cells_json']}`\n")
    out.append(f"**Owed {t['owed']} · diverging {t['diverging']} · golden gaps {t['gaps']} · weighted D/W = {overall:.4f}**\n")
    out.append(f"## Decision\n\n**{'KEEP HEAD' if keep else 'RE-CUT FROM THE TAG'}** — rule: D/W ≤ 0.05 overall ({overall:.4f}) and ≤ 0.20 in every weight-10 family"
               + (f"; violated by {', '.join(f'{f} ({s['ratio']:.2f})' for f, s in heavy_bad.items())}" if heavy_bad else "; every weight-10 family within bound")
               + ". Every red cell below must be triaged to a Phase-1 ticket before the decision is final.\n")
    out.append("## Per family\n\n| family | owed | diverging | D/W |\n|---|---|---|---|")
    for f, s in sorted(fam.items()):
        out.append(f"| {f} | {s['owed']} | {s['diverging']} | {s['ratio']:.3f} |")
    out.append("\n## Per divergence class\n\n| class | cells |\n|---|---|")
    for k, v in sorted(rep["by_class"].items(), key=lambda kv: -kv[1]):
        out.append(f"| {k} | {v} |")
    top = sorted((c for c in rep["cells"] if c["classes"]), key=lambda c: (-c["weight"], c["family"], c["id"]))
    out.append("\n## Divergences (heaviest first, top 40)\n")
    for c in top[:40]:
        out.append(f"- `{c['id']}` [{','.join(c['classes'])}] {c['first_diff']}")
    if len(top) > 40:
        out.append(f"- … {len(top) - 40} more in the report's diverging.txt")
    gaps = rep.get("gaps", [])
    by_reason = Counter((g["golden_status"], (g.get("detail") or "")[:70]) for g in gaps)
    out.append("\n## Golden gaps (cells the 1.5.5 recording could not produce — named, never owed)\n")
    for (st, d), n in by_reason.most_common(20):
        out.append(f"- {n} × {st}: {d}")
    if findings:
        out.append("\n## Findings\n")
        out.append(findings)
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())

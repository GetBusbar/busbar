#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Diff two shadow-oracle recordings cell by cell — the REPLAY half of the oracle.

  diff-cells.py --golden <dir> --candidate <dir> --out <dir> [--cells cells.json] [--family <regex>]

Reads <dir>/cells/<safe>.json (normalize.py output) from both recordings plus each side's
ledger.tsv. The OWED set is every cell id in cells.json (filtered) whose GOLDEN ledger row is PASS —
a cell the golden itself could not record is a named gap (owed-gaps.txt), never owed and never
green. For each owed id the candidate must have an identical normalized cell.

Divergence classes (a cell may carry several; the first names the earliest divergent layer):
  missing.golden      owed but the golden cell file is absent (recorder bug: red)
  missing.candidate   owed, golden present, candidate absent (the build did not serve it: red)
  status              HTTP status / exit code
  headers             header key set or value
  body                JSON: list of JSON-pointer paths with old/new; text/SSE: first differing line
  effects.usage       ledger delta differs (money)
  effects.metrics     metric delta differs
  effects.audit       audit delta differs
  effects.stderr      exec cells: the process's stderr (boot refusals, warnings, CLI errors)
  norm.rules          the set of normalizer rules that fired differs (a rule firing on ONE side is
                      itself a finding: something non-deterministic appeared or disappeared)

Writes <out>/report.json, <out>/report.md, <out>/owed.txt, <out>/owed-gaps.txt, <out>/diverging.txt
and prints one TSV row per owed id on stdout: <id> <TAB> PASS|FAIL <TAB> <classes> <TAB> <first-diff>
(the driver turns those into ledger rows via fleet-fixtures/lib.sh `record`).
Exit 0 always — the VERDICT is verdict.sh's job, not this file's.
"""
import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict

CLASS_ORDER = ["missing.golden", "missing.candidate", "status", "headers", "body", "effects.stderr",
               "effects.usage", "effects.metrics", "effects.audit", "norm.rules"]
# Weight per class; a cell's weight is its family's max class weight over the classes it diverged in.
# Money and refusal semantics dominate; cosmetics count but cannot outvote them.
CLASS_WEIGHT = {"missing.golden": 10, "missing.candidate": 10, "status": 10, "effects.usage": 10,
                "body": 3, "effects.stderr": 3, "effects.audit": 3, "headers": 1, "effects.metrics": 1, "norm.rules": 1}
# Families where BODY bytes are the contract itself (admin responses, boot messages, CLI output).
BODY_IS_CONTRACT = {"admin.ops", "boot.refusal", "boot.warning", "config.migrate", "cli", "ops.scrape"}


def safe_name(cell_id: str) -> str:
    return cell_id.replace("|", "__")


def load_ledger(d: str) -> dict:
    out = {}
    p = os.path.join(d, "ledger.tsv")
    if not os.path.exists(p):
        return out
    with open(p, encoding="utf-8", errors="replace") as f:
        for ln in f:
            parts = ln.rstrip("\n").split("\t")
            if len(parts) >= 2 and parts[0] not in out:
                out[parts[0]] = (parts[1], parts[3] if len(parts) > 3 else "")
    return out


def load_cell(d: str, cell_id: str):
    p = os.path.join(d, "cells", safe_name(cell_id) + ".json")
    if not os.path.exists(p):
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:  # a corrupt cell is a divergence, not a crash
        return {"__corrupt__": str(e)}


def json_paths_diff(a, b, path="", out=None, limit=50):
    """List JSON-pointer paths where a != b (first `limit`)."""
    if out is None:
        out = []
    if len(out) >= limit:
        return out
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                out.append({"path": f"{path}/{k}", "golden": None, "candidate": b[k]})
            elif k not in b:
                out.append({"path": f"{path}/{k}", "golden": a[k], "candidate": None})
            else:
                json_paths_diff(a[k], b[k], f"{path}/{k}", out, limit)
            if len(out) >= limit:
                break
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append({"path": f"{path}/len", "golden": len(a), "candidate": len(b)})
        for i, (x, y) in enumerate(zip(a, b)):
            json_paths_diff(x, y, f"{path}/{i}", out, limit)
            if len(out) >= limit:
                break
        return out
    if a != b:
        out.append({"path": path or "/", "golden": a, "candidate": b})
    return out


def text_diff(a: str, b: str):
    al, bl = a.split("\n"), b.split("\n")
    for i, (x, y) in enumerate(zip(al, bl)):
        if x != y:
            return {"line": i + 1, "golden": x[:300], "candidate": y[:300], "golden_lines": len(al), "candidate_lines": len(bl)}
    if len(al) != len(bl):
        i = min(len(al), len(bl))
        return {"line": i + 1, "golden": (al[i] if i < len(al) else "<EOF>")[:300],
                "candidate": (bl[i] if i < len(bl) else "<EOF>")[:300], "golden_lines": len(al), "candidate_lines": len(bl)}
    return None


def body_diff(g, c):
    if g == c:
        return None
    if isinstance(g, dict) and isinstance(c, dict):
        if "json" in g and "json" in c:
            return {"kind": "json", "paths": json_paths_diff(g["json"], c["json"])}
        if "text" in g and "text" in c:
            return {"kind": "text", **(text_diff(g["text"], c["text"]) or {})}
        return {"kind": "shape", "golden": sorted(g), "candidate": sorted(c)}
    return {"kind": "shape", "golden": type(g).__name__, "candidate": type(c).__name__}


def compare(g: dict, c: dict) -> tuple[list, dict]:
    classes, detail = [], {}
    if "__corrupt__" in g:
        return ["missing.golden"], {"missing.golden": g["__corrupt__"]}
    if "__corrupt__" in c:
        return ["missing.candidate"], {"missing.candidate": c["__corrupt__"]}
    if g.get("status") != c.get("status"):
        classes.append("status"); detail["status"] = {"golden": g.get("status"), "candidate": c.get("status")}
    gh, ch = g.get("headers", {}), c.get("headers", {})
    if gh != ch:
        classes.append("headers")
        detail["headers"] = {"only_golden": sorted(set(gh) - set(ch)), "only_candidate": sorted(set(ch) - set(gh)),
                             "changed": {k: {"golden": gh[k], "candidate": ch[k]} for k in sorted(set(gh) & set(ch)) if gh[k] != ch[k]}}
    bd = body_diff(g.get("body"), c.get("body"))
    if bd is not None:
        classes.append("body"); detail["body"] = bd
    ge, ce = g.get("effects", {}), c.get("effects", {})
    for k in ("usage", "metrics", "audit", "stderr"):
        if ge.get(k) != ce.get(k):
            classes.append(f"effects.{k}")
            if k == "stderr" and isinstance(ge.get(k), str) and isinstance(ce.get(k), str):
                detail["effects.stderr"] = {"kind": "text", **(text_diff(ge[k], ce[k]) or {})}
            else:
                detail[f"effects.{k}"] = {"paths": json_paths_diff(ge.get(k), ce.get(k))}
    if sorted(g.get("applied", [])) != sorted(c.get("applied", [])):
        classes.append("norm.rules")
        detail["norm.rules"] = {"only_golden": sorted(set(g.get("applied", [])) - set(c.get("applied", []))),
                                "only_candidate": sorted(set(c.get("applied", [])) - set(g.get("applied", [])))}
    classes.sort(key=CLASS_ORDER.index)
    return classes, detail


def first_diff_text(classes, detail) -> str:
    if not classes:
        return ""
    k = classes[0]
    d = detail.get(k)
    if k == "status":
        return f"status {d['golden']} -> {d['candidate']}"
    if k == "headers":
        parts = []
        if d["only_golden"]: parts.append("missing " + ",".join(d["only_golden"][:3]))
        if d["only_candidate"]: parts.append("added " + ",".join(d["only_candidate"][:3]))
        for hk, hv in list(d["changed"].items())[:2]:
            parts.append(f"{hk}: {hv['golden']!r} -> {hv['candidate']!r}")
        return "headers " + "; ".join(parts)
    if k == "body":
        if d.get("kind") == "json" and d.get("paths"):
            p = d["paths"][0]
            return f"body {p['path']}: {json.dumps(p['golden'])[:80]} -> {json.dumps(p['candidate'])[:80]}"
        if d.get("kind") == "text":
            return f"body line {d.get('line')}: {d.get('golden','')[:80]!r} -> {d.get('candidate','')[:80]!r}"
        return "body shape differs"
    if k == "effects.stderr":
        return f"stderr line {d.get('line')}: {d.get('golden','')[:80]!r} -> {d.get('candidate','')[:80]!r}"
    if k.startswith("effects."):
        ps = d.get("paths") or []
        if ps:
            p = ps[0]
            return f"{k} {p['path']}: {json.dumps(p['golden'])[:60]} -> {json.dumps(p['candidate'])[:60]}"
        return k
    if k == "norm.rules":
        return f"norm.rules only_golden={d['only_golden']} only_candidate={d['only_candidate']}"
    return k


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--golden", required=True)
    ap.add_argument("--candidate", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cells", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "cells.json"))
    ap.add_argument("--family", default="")
    ap.add_argument("--accepted", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "accepted-differences.json"))
    a = ap.parse_args()
    accepted = []
    if os.path.exists(a.accepted):
        for e in json.load(open(a.accepted, encoding="utf-8")).get("accepted", []):
            accepted.append({"rx": re.compile(e["cells"]), "classes": set(e.get("classes", [])), "kind": e.get("kind", "improvement"),
                             "id": e.get("id", e["cells"]), "rationale": e.get("rationale", ""), "by": e.get("by", "")})
    os.makedirs(a.out, exist_ok=True)

    with open(a.cells, encoding="utf-8") as f:
        cells_doc = json.load(f)
    fam_rx = re.compile(a.family) if a.family else None
    cells = [c for c in cells_doc["cells"] if not fam_rx or fam_rx.search(c.get("family", c.get("plane", "")))]
    by_id = {c["id"]: c for c in cells}
    gl, cl = load_ledger(a.golden), load_ledger(a.candidate)

    def family_of(c):  # legacy llm cells carry no `family`; treat plane as the family
        return c.get("family") or c.get("plane", "unknown")

    owed, gaps = [], []
    for c in cells:
        st = gl.get(c["id"], ("MISSING", "no golden ledger row"))
        if st[0] == "PASS":
            owed.append(c["id"])
        else:
            gaps.append((c["id"], st[0], st[1]))

    results, fam_stats, class_counts = [], defaultdict(lambda: Counter()), Counter()
    W = D = 0
    for cid in owed:
        c = by_id[cid]
        fam = family_of(c)
        g = load_cell(a.golden, cid)
        cc = load_cell(a.candidate, cid)
        if g is None:
            classes, detail = ["missing.golden"], {"missing.golden": "golden ledger PASS but cell file absent"}
        elif cc is None:
            classes, detail = ["missing.candidate"], {"missing.candidate": cl.get(cid, ("MISSING", "no candidate ledger row"))[1]}
        else:
            classes, detail = compare(g, cc)
            only = c.get("compare")  # a cell with inherently random output names the classes that ARE its contract
            if only:
                classes = [k for k in classes if k in only or k.startswith("missing.")]
                detail = {k: v for k, v in detail.items() if k in classes}
        # owner-accepted differences: the cell reports ACCEPTED (its own column), never a silent pass
        acc = None
        if classes:
            for e in accepted:
                if e["rx"].search(cid) and (not e["classes"] or set(classes) <= e["classes"]):
                    acc = e; break
        wt = c.get("weight")
        if wt is None:
            wt = 10 if fam in BODY_IS_CONTRACT else max([CLASS_WEIGHT[k] for k in classes] or [0])
            if fam in BODY_IS_CONTRACT and classes:
                wt = max(10 if k in ("status", "body", "missing.candidate", "missing.golden") else CLASS_WEIGHT[k] for k in classes)
        cell_w = max([CLASS_WEIGHT[k] for k in classes] or [0]) if not classes else max(wt, 1)
        owed_w = c.get("weight") or (10 if fam in BODY_IS_CONTRACT else 10)
        W += owed_w
        fam_stats[fam]["owed"] += 1
        fam_stats[fam]["owed_w"] += owed_w
        if classes and acc is None:
            D += min(cell_w, owed_w)
            fam_stats[fam]["diverging"] += 1
            fam_stats[fam]["div_w"] += min(cell_w, owed_w)
            for k in classes:
                class_counts[k] += 1
        elif classes:
            fam_stats[fam]["accepted"] += 1
        results.append({"id": cid, "family": fam, "plane": c.get("plane"), "weight": owed_w,
                        "classes": classes, "first_diff": first_diff_text(classes, detail), "detail": detail if classes else {},
                        **({"accepted": {"id": acc["id"], "kind": acc["kind"], "rationale": acc["rationale"], "by": acc["by"]}} if acc else {})})

    fam_table = {}
    for fam, s in sorted(fam_stats.items()):
        fam_table[fam] = {"owed": s["owed"], "diverging": s["diverging"], "accepted": s["accepted"], "owed_w": s["owed_w"], "div_w": s["div_w"],
                          "ratio": (s["div_w"] / s["owed_w"]) if s["owed_w"] else 0.0}
    gv = (a.golden, os.path.join(a.golden, "meta.json"))
    cv = (a.candidate, os.path.join(a.candidate, "meta.json"))

    def meta(p):
        try:
            return json.load(open(p))
        except Exception:
            return {}

    report = {
        "meta": {"golden": a.golden, "candidate": a.candidate, "golden_version": meta(gv[1]).get("version"),
                 "candidate_version": meta(cv[1]).get("version"), "cells_json": a.cells, "family_filter": a.family},
        "totals": {"cells_in_scope": len(cells), "owed": len(owed), "gaps": len(gaps),
                   "diverging": sum(1 for r in results if r["classes"] and "accepted" not in r),
                   "accepted": sum(1 for r in results if "accepted" in r), "W": W, "D": D,
                   "ratio": (D / W) if W else 0.0},
        "by_family": fam_table, "by_class": dict(class_counts),
        "gaps": [{"id": i, "golden_status": s, "detail": d} for i, s, d in gaps],
        "cells": results,
    }
    with open(os.path.join(a.out, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1, sort_keys=True)
    with open(os.path.join(a.out, "owed.txt"), "w") as f:
        f.write("\n".join(owed) + ("\n" if owed else ""))
    with open(os.path.join(a.out, "owed-gaps.txt"), "w") as f:
        for i, s, d in gaps:
            f.write(f"{i}\t{s}\t{d}\n")
    with open(os.path.join(a.out, "diverging.txt"), "w") as f:
        for r in results:
            if r["classes"]:
                f.write(f"{r['id']}\t{','.join(r['classes'])}\t{r['first_diff']}\n")

    # report.md
    lines = [f"# Shadow-oracle replay: {report['meta'].get('golden_version')} (golden) vs {report['meta'].get('candidate_version')} (candidate)", "",
             f"owed {len(owed)} · diverging {report['totals']['diverging']} · accepted {report['totals']['accepted']} · gaps {len(gaps)} · weighted D/W = {report['totals']['ratio']:.4f}", "",
             "| family | owed | diverging | accepted | D/W |", "|---|---|---|---|---|"]
    for fam, s in fam_table.items():
        lines.append(f"| {fam} | {s['owed']} | {s['diverging']} | {s['accepted']} | {s['ratio']:.3f} |")
    lines += ["", "| class | cells |", "|---|---|"] + [f"| {k} | {v} |" for k, v in sorted(class_counts.items(), key=lambda kv: -kv[1])]
    top = sorted((r for r in results if r["classes"] and "accepted" not in r), key=lambda r: (-r["weight"], r["id"]))[:25]
    if top:
        lines += ["", "## Top divergences", ""]
        for r in top:
            lines.append(f"- `{r['id']}` [{','.join(r['classes'])}] {r['first_diff']}")
    if gaps:
        lines += ["", "## Golden gaps (not owed)", ""] + [f"- `{i}` {s}: {d}" for i, s, d in gaps[:50]]
        if len(gaps) > 50:
            lines.append(f"- … {len(gaps) - 50} more in owed-gaps.txt")
    with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    for r in results:
        if "accepted" in r:
            sys.stdout.write(f"{r['id']}\tPASS\tACCEPTED {r['accepted']['kind']} ({r['accepted']['id']}): {','.join(r['classes'])}\t{r['first_diff']}\n")
            continue
        st = "FAIL" if r["classes"] else "PASS"
        sys.stdout.write(f"{r['id']}\t{st}\t{','.join(r['classes']) or 'identical'}\t{r['first_diff']}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

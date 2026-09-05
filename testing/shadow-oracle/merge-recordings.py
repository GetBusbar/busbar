#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Merge several record.sh outputs (recorded with disjoint --filter sets) into one recording.

    merge-recordings.py --out <dir> <part>...

A recording is a set of cells: `cells/<id>.json`, `raw/<id>/`, one ledger row each, and a
`meta.json` that names the binary, its digest, the harness revision and the host. Recording in
parts is how a full golden fits under a wall-clock cap or runs on several cores; the merge is
only honest when every part was made by the SAME binary, the SAME harness and the SAME host, so
that is refused otherwise. A cell id present in two parts is refused too: the parts must be
disjoint, or the merged ledger would carry two verdicts for one cell.
"""
import argparse
import json
import os
import shutil
import sys

PROVENANCE = ("binary", "version", "binary_sha256", "harness_rev", "host_triple")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("parts", nargs="+")
    a = ap.parse_args()
    if len(a.parts) < 1:
        sys.exit("merge-recordings: at least one part")
    metas = []
    for p in a.parts:
        mp = os.path.join(p, "meta.json")
        if not os.path.isfile(mp):
            sys.exit(f"merge-recordings: {p} has no meta.json (an unfinished or failed recording)")
        with open(mp) as f:
            metas.append((p, json.load(f)))
    base = metas[0][1]
    for p, m in metas[1:]:
        for k in PROVENANCE:
            if m.get(k) != base.get(k):
                sys.exit(f"merge-recordings: {p} {k}={m.get(k)!r} but {metas[0][0]} {k}={base.get(k)!r}; parts of one golden must share their provenance")
    if os.path.exists(a.out):
        sys.exit(f"merge-recordings: {a.out} exists; refusing to merge over it")
    os.makedirs(os.path.join(a.out, "cells"))
    os.makedirs(os.path.join(a.out, "raw"))
    seen = {}
    rows = []
    recorded = 0
    for p, m in metas:
        with open(os.path.join(p, "ledger.tsv")) as f:
            for line in f:
                if not line.strip():
                    continue
                cid = line.split("\t", 1)[0]
                if cid in seen:
                    sys.exit(f"merge-recordings: cell {cid!r} is in both {seen[cid]} and {p}; parts must be disjoint")
                seen[cid] = p
                rows.append(line if line.endswith("\n") else line + "\n")
        for sub in ("cells", "raw"):
            src = os.path.join(p, sub)
            if not os.path.isdir(src):
                continue
            for name in os.listdir(src):
                dst = os.path.join(a.out, sub, name)
                if os.path.exists(dst):
                    sys.exit(f"merge-recordings: {sub}/{name} is in two parts; parts must be disjoint")
                s = os.path.join(src, name)
                if os.path.isdir(s):
                    shutil.copytree(s, dst)
                else:
                    shutil.copy2(s, dst)
        recorded += int(m.get("recorded", 0))
    with open(os.path.join(a.out, "ledger.tsv"), "w") as f:
        f.writelines(rows)
    meta = dict(base)
    meta["recorded"] = recorded
    meta["merged_from"] = [{"part": os.path.basename(os.path.normpath(p)), "recorded": m.get("recorded", 0), "at": m.get("at")} for p, m in metas]
    meta["at"] = max(m.get("at", "") for _, m in metas)
    with open(os.path.join(a.out, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")
    print(f"merged {len(metas)} parts, {len(rows)} ledger rows, {recorded} recorded -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

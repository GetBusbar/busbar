#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""documented-claims-check.py -- assert the documented-behaviour claim register.

qa/documented-claims.json is the register behind the ARCHITECTURE.md Appendix B binding on
documented behaviour: the README and CHANGELOG claims cross-checked in
docs/design/inventory/1.5.5-ops-observability.md, each either pinned by a shadow-oracle cell
(`status: "cell"`) or written off as untestable prose with a stated reason (`status: "prose"`),
and the two rows the design calls CONTRADICTED carrying the CODE's behaviour as the parity target.

WHY THIS FILE EXISTS. The register was cited as a `gate` by the design-bindings ledger, and the
register's own header said "scripts/design-bindings.sh --check verifies the `cell` ids referenced
below still exist". Neither was true: nothing opened the file. A data file compares nothing --
it is an INPUT to a gate, never a gate -- so the claims it records were unasserted, and a cell id
could be renamed away or a claim silently dropped with every check in the tree still green.

WHAT IS ASSERTED, and why each arm is here:
  1. THE SHAPE OF THE REGISTER. Every claim carries an id, a quote and a status; a `cell` claim
     names at least one cell and no `reason`, a `prose` claim states a reason and names no cell.
     A claim that is neither pinned nor excused is the hole this register exists to make visible.
  2. THE CLAIM SET IS COMPLETE AND CONTIGUOUS. The claim ids are line addresses into the
     cross-check, so a dropped claim is a hole in the run. Both runs are checked for their exact
     span, count and contiguity: dropping the last claim of a run would otherwise read as a
     shorter, still-tidy register.
  3. THE `counts` BLOCK IS THE TRUTH. It is re-derived from `claims` and compared field by field.
     A summary maintained by hand beside the data it summarises drifts, and a drifted summary is
     how a register reports fifty-six claims while holding fifty-five.
  4. EVERY CITED CELL IS REAL AND WAS RECORDED. A cell id absent from cells.json names nothing.
     A cell id present but never recorded by the pinned golden is worse: it reads as a pin while
     the comparison behind it has never once run. Only a PASS row on the golden ledger is proof.
  5. THE CONTRADICTED ROWS STAY CONTRADICTED. Each names the documentation line it contradicts
     and the behaviour the code actually has, and is pinned by a cell like any other row. This is
     the register's sharpest claim -- the code, not the document, is the parity target -- and
     downgrading such a row to ordinary prose would quietly delete a known documentation defect.

Existence and content only; nothing is executed and no cell is recorded.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLAIMS = ROOT / "qa" / "documented-claims.json"
CELLS = ROOT / "testing" / "shadow-oracle" / "cells.json"
LEDGER = ROOT / "testing" / "shadow-oracle" / "golden" / "1.5.5" / "ledger.tsv"

# The two runs the binding names, as (prefix, first, last). These are line addresses into
# docs/design/inventory/1.5.5-ops-observability.md's two cross-check sections, so the span is part
# of the claim: a register that silently narrows its own range has stopped covering the document.
RUNS = (("README", 1047, 1073), ("CHANGELOG", 1087, 1115))
# The rows the design pins as code-wins. Named here so that demoting one to prose is RED.
CONTRADICTED = ("README:1061", "CHANGELOG:1099")

_ID = re.compile(r"^(README|CHANGELOG):([0-9]+)$")


def golden_recorded(ledger: Path) -> set[str]:
    """Cell ids the pinned golden actually recorded a comparable answer for (PASS rows only)."""
    out: set[str] = set()
    if not ledger.is_file():
        return out
    for line in ledger.read_text(encoding="utf-8", errors="replace").splitlines():
        p = line.split("\t")
        if len(p) >= 2 and p[1] == "PASS":
            out.add(p[0])
    return out


def check(claims_path: Path, cells_path: Path, ledger_path: Path) -> list[str]:
    """Every problem with the register, one human-readable line each. Empty means green."""
    bad: list[str] = []
    try:
        doc = json.loads(claims_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return [f"{claims_path}: unreadable claim register ({e})"]

    claims = doc.get("claims")
    if not isinstance(claims, list) or not claims:
        return [f"{claims_path}: no `claims` list -- a register with no claims asserts nothing"]

    cell_ids: set[str] = set()
    try:
        cell_ids = {c["id"] for c in json.loads(cells_path.read_text(encoding="utf-8")).get("cells", [])}
    except (OSError, ValueError, KeyError, TypeError) as e:
        bad.append(f"{cells_path}: unreadable cell list ({e})")
    recorded = golden_recorded(ledger_path)

    # 1. shape
    seen: dict[str, int] = {}
    for i, c in enumerate(claims):
        cid = c.get("id")
        where = cid or f"claims[{i}]"
        if not cid or not _ID.match(str(cid)):
            bad.append(f"{where}: id is not a <README|CHANGELOG>:<line> address")
            continue
        if cid in seen:
            bad.append(f"{cid}: listed twice (also at claims[{seen[cid]}])")
        seen[cid] = i
        if not str(c.get("quote", "")).strip():
            bad.append(f"{cid}: no quote -- a claim that does not say what was claimed")
        st = c.get("status")
        cells = c.get("cell") or []
        reason = str(c.get("reason", "")).strip()
        if st == "cell":
            if not isinstance(cells, list) or not cells:
                bad.append(f"{cid}: status 'cell' but names no cell -- nothing pins this claim")
            if reason:
                bad.append(f"{cid}: status 'cell' but also carries a prose `reason`; a claim is pinned or excused, never both")
        elif st == "prose":
            if not reason:
                bad.append(f"{cid}: status 'prose' with no reason -- a claim dropped without saying why")
            if cells:
                bad.append(f"{cid}: status 'prose' but names a cell; a pinned claim is `cell`")
        else:
            bad.append(f"{cid}: status {st!r} is neither 'cell' nor 'prose'")
        # 4. every cited cell is real and was recorded
        for ref in cells if isinstance(cells, list) else []:
            if cell_ids and ref not in cell_ids:
                bad.append(f"{cid}: cites {ref}, which is in no cell of {cells_path.name}")
            elif ref not in recorded:
                bad.append(f"{cid}: cites {ref}, which the pinned golden never recorded -- "
                           f"a pin whose comparison has never run")

    # 2. the claim set is complete and contiguous
    for prefix, first, last in RUNS:
        want = [f"{prefix}:{n}" for n in range(first, last + 1)]
        missing = [i for i in want if i not in seen]
        extra = sorted(i for i in seen if i.startswith(prefix + ":") and i not in set(want))
        if missing:
            bad.append(f"{prefix}: {len(missing)} claim(s) missing from the {first}-{last} run: "
                       + ", ".join(missing))
        if extra:
            bad.append(f"{prefix}: claim(s) outside the {first}-{last} run: " + ", ".join(extra))

    # 3. the counts block is the truth
    got = {
        "total": len(claims),
        "readme": sum(1 for c in claims if str(c.get("id", "")).startswith("README:")),
        "changelog": sum(1 for c in claims if str(c.get("id", "")).startswith("CHANGELOG:")),
        "cell": sum(1 for c in claims if c.get("status") == "cell"),
        "prose": sum(1 for c in claims if c.get("status") == "prose"),
        "contradicted": sum(1 for c in claims if c.get("contradicted") is True),
    }
    said = doc.get("counts") or {}
    for k, v in got.items():
        if k in said and said[k] != v:
            bad.append(f"counts.{k} says {said[k]}, the claims list holds {v}")
        elif k not in said:
            bad.append(f"counts.{k} is missing")

    # 5. the contradicted rows stay contradicted
    for cid in CONTRADICTED:
        c = claims[seen[cid]] if cid in seen else None
        if c is None:
            bad.append(f"{cid}: the register no longer carries this CONTRADICTED claim")
            continue
        if c.get("contradicted") is not True:
            bad.append(f"{cid}: is a CONTRADICTED row and is no longer flagged `contradicted`")
        if not str(c.get("code_wins", "")).strip():
            bad.append(f"{cid}: CONTRADICTED with no `code_wins` -- the parity target is the code's "
                       f"behaviour, and it is not written down")
        if not str(c.get("doc_line", "")).strip():
            bad.append(f"{cid}: CONTRADICTED with no `doc_line` naming the documentation it contradicts")
        if c.get("status") != "cell" or not (c.get("cell") or []):
            bad.append(f"{cid}: CONTRADICTED rows are pinned by a cell of their own; this one is not")
    for c in claims:
        cid = str(c.get("id", ""))
        if c.get("contradicted") is True and cid not in CONTRADICTED:
            bad.append(f"{cid}: flagged `contradicted`, but the design names only "
                       + " and ".join(CONTRADICTED))
    return bad


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--claims", default=str(CLAIMS))
    ap.add_argument("--cells", default=str(CELLS))
    ap.add_argument("--golden-ledger", default=str(LEDGER))
    ap.add_argument("--quiet", action="store_true", help="print problems only, no green line")
    a = ap.parse_args(argv)

    bad = check(Path(a.claims), Path(a.cells), Path(a.golden_ledger))
    if bad:
        print(f"documented claims: RED -- {len(bad)} problem(s) in {a.claims}:")
        for b in bad:
            print(f"  {b}")
        return 1
    if not a.quiet:
        doc = json.loads(Path(a.claims).read_text(encoding="utf-8"))
        c = doc.get("counts", {})
        print(f"documented claims: GREEN -- {c.get('total')} claims "
              f"({c.get('readme')} README + {c.get('changelog')} CHANGELOG), "
              f"{c.get('cell')} pinned by a recorded cell, {c.get('prose')} excused as prose, "
              f"{c.get('contradicted')} pinned code-wins")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""teller-steps-check.py — the H2 ledger printer: 'conformance rigs carry one cell per Teller step
per plane' (docs/design/1.6.0-TRACKER.md), matrix at qa/teller-steps.json.

    python3 scripts/teller-steps-check.py            # print the matrix, exit 0 or 1
    python3 scripts/teller-steps-check.py --check     # same as above (the flag CI wires in)
    python3 scripts/teller-steps-check.py --selftest  # prove a broken matrix is refused

RED RULE. For every plane and every GATING step (qa/teller-steps.json's steps.<step>.gating ==
true), the matrix's matrix.<plane>.<step>.cell must be something other than the literal string
"none". A gating step mapped to "none" anywhere is a named, printed gap and this script exits 1.
Non-gating steps (arrival/decode/approve) are printed for completeness but never fail the check —
they are mapped once, structurally, and are not what H2's own prose enumerates as load-bearing.

This mirrors scripts/capability-equality-summary.py's own doctrine exactly: a printer that RE-CHECKS
what it prints (parseable, every declared plane x step cell present, no unknown status), so a
missing/malformed ledger is a refusal (exit 1), never a lying green.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "qa" / "teller-steps.json"
STATUSES = {"mapped", "new", "none"}


def load():
    doc = json.loads(LEDGER.read_text())
    steps = doc.get("steps")
    matrix = doc.get("matrix")
    if not isinstance(steps, dict) or not steps:
        raise ValueError("qa/teller-steps.json: no non-empty 'steps' object")
    if not isinstance(matrix, dict) or not matrix:
        raise ValueError("qa/teller-steps.json: no non-empty 'matrix' object")
    for step, meta in steps.items():
        if not isinstance(meta, dict) or "gating" not in meta:
            raise ValueError(f"qa/teller-steps.json: steps.{step} has no 'gating' boolean")
    for plane, row in matrix.items():
        if not isinstance(row, dict):
            raise ValueError(f"qa/teller-steps.json: matrix.{plane} is not an object")
        missing_steps = set(steps) - set(row)
        if missing_steps:
            raise ValueError(f"qa/teller-steps.json: matrix.{plane} is missing step(s) {sorted(missing_steps)}")
        for step, cell in row.items():
            if step not in steps:
                raise ValueError(f"qa/teller-steps.json: matrix.{plane}.{step} names an undeclared step")
            if not isinstance(cell, dict) or "cell" not in cell or "status" not in cell:
                raise ValueError(f"qa/teller-steps.json: matrix.{plane}.{step} has no cell/status")
            if cell["status"] not in STATUSES:
                raise ValueError(f"qa/teller-steps.json: matrix.{plane}.{step}.status {cell['status']!r} "
                                  f"is not one of {sorted(STATUSES)}")
            if (cell["cell"] == "none") != (cell["status"] == "none"):
                raise ValueError(f"qa/teller-steps.json: matrix.{plane}.{step} cell/status disagree "
                                  f"on whether this is a gap (cell={cell['cell']!r} status={cell['status']!r})")
    return doc, steps, matrix


def render(steps: dict, matrix: dict) -> tuple[str, int, list[str]]:
    lines = []
    gaps = []
    planes = sorted(matrix)
    step_order = list(steps)  # dict insertion order from the JSON, i.e. the Teller loop's own order
    for plane in planes:
        lines.append(f"plane {plane}:")
        for step in step_order:
            gating = steps[step]["gating"]
            entry = matrix[plane][step]
            is_gap = entry["status"] == "none"
            mark = "NONE" if is_gap else entry["status"].upper()
            tag = "gating" if gating else "info  "
            lines.append(f"  [{tag}] {step:<13} {mark:<6} {entry['cell']}")
            if is_gap and gating:
                gaps.append(f"{plane}.{step}")
    return "\n".join(lines), len(gaps), gaps


def selftest() -> int:
    import tempfile

    failures = 0

    def expect_raises(doc, why):
        nonlocal failures
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(doc, f)
            path = f.name
        global LEDGER
        saved = LEDGER
        try:
            LEDGER = Path(path)
            load()
            print(f"  MISS: expected a refusal for {why}, got none")
            failures += 1
        except ValueError:
            print(f"  ok: refused a matrix with {why}")
        finally:
            LEDGER = saved

    expect_raises({"steps": {}, "matrix": {"llm": {}}}, "empty steps")
    expect_raises({"steps": {"a": {"gating": True}}, "matrix": {}}, "empty matrix")
    expect_raises({"steps": {"a": {"gating": True}}, "matrix": {"llm": {}}}, "a plane missing a declared step")
    expect_raises(
        {"steps": {"a": {"gating": True}}, "matrix": {"llm": {"a": {"cell": "x", "status": "bogus"}}}},
        "an unknown status",
    )
    expect_raises(
        {"steps": {"a": {"gating": True}}, "matrix": {"llm": {"a": {"cell": "none", "status": "mapped"}}}},
        "cell==none but status!=none",
    )

    # A gating gap must be counted and named; a non-gating gap must not fail the check.
    doc = {
        "steps": {"gate": {"gating": True}, "info": {"gating": False}},
        "matrix": {
            "p1": {"gate": {"cell": "none", "status": "none"}, "info": {"cell": "none", "status": "none"}},
        },
    }
    _, n_gaps, gaps = render(doc["steps"], doc["matrix"])
    if n_gaps == 1 and gaps == ["p1.gate"]:
        print("  ok: a gating gap is counted and a non-gating gap is not")
    else:
        print(f"  MISS: expected exactly 1 gap named p1.gate, got {n_gaps} ({gaps})")
        failures += 1

    if failures:
        print(f"teller-steps-check self-test: {failures} FAILURE(S)")
        return 1
    print("teller-steps-check self-test: PASS.")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    try:
        doc, steps, matrix = load()
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"FAIL: {LEDGER.relative_to(ROOT)} is not a valid teller-steps matrix: {e}", file=sys.stderr)
        return 1
    text, n_gaps, gaps = render(steps, matrix)
    print(text)
    print()
    if n_gaps:
        print(f"RED: {n_gaps} gating plane x step cell(s) are still \"none\": {', '.join(gaps)}")
        return 1
    print("GREEN: every gating plane x step cell in qa/teller-steps.json names a real scenario.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

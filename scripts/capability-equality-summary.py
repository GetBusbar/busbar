#!/usr/bin/env python3
"""Print the equality doctrine's ledger line -- the missing-cell count and list -- on EVERY run.

    python3 scripts/capability-equality-summary.py              # print the ledger, exit 0
    python3 scripts/capability-equality-summary.py --selftest   # prove a broken ledger is refused

WHY A PRINTER AND NOT ANOTHER GATE. The RED enforcement for `qa/capability-equality.json` lives in
`crates/busbar/tests/capability_equality.rs` (proven cells must name tests that exist; the cross
product is exact; n/a needs an argument) and runs on every `cargo test`. What a cargo test cannot
do is put the GAP in front of whoever reads a green umbrella run: its output is swallowed on
success. So `scripts/full-gate.sh` calls this printer in its result section, green or red, and the
missing cells are NAMED every single time -- the honest-ledger pattern (`qa/method-coverage.missing`,
the reserved qa segments): green means "the pin matches reality", never "no gap".

THE PRINTER RE-CHECKS WHAT IT PRINTS. A count computed from a file nobody validated is a number,
not a claim, so before printing this script re-verifies the cheap half of the gate's invariants
(parseable, declared axes, exact cross product, known states). If the ledger is unreadable or does
not tile, the printer REFUSES (exit 1) rather than printing a lying count -- and full-gate treats
that refusal as a failure, because a gap that can no longer be named is a gap on its way to being
forgotten. The owner has repeated this doctrine enough times.
"""

import json
import os
import sys
import tempfile

LEDGER = "qa/capability-equality.json"
STATES = {"proven", "missing", "not-applicable"}


def load(path):
    """Parse and cheaply re-verify the ledger. Returns (doc, error-string-or-None)."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return None, f"cannot read {path}: {e}"
    caps = doc.get("capabilities")
    planes = doc.get("planes")
    cells = doc.get("cells")
    if not isinstance(caps, dict) or not caps or not isinstance(planes, dict) or not planes:
        return None, f"{path}: `capabilities` and `planes` must be non-empty objects"
    if not isinstance(cells, list):
        return None, f"{path}: `cells` must be an array"
    seen = set()
    for c in cells:
        cap, plane, state = c.get("capability"), c.get("plane"), c.get("state")
        if cap not in caps or plane not in planes:
            return None, f"{path}: cell names undeclared axis: {cap!r} x {plane!r}"
        if state not in STATES:
            return None, f"{path}: cell {cap}×{plane} has state {state!r} (no fourth state)"
        if (cap, plane) in seen:
            return None, f"{path}: cell {cap}×{plane} appears twice"
        seen.add((cap, plane))
    for cap in caps:
        for plane in planes:
            if (cap, plane) not in seen:
                return None, (
                    f"{path}: cell {cap}×{plane} is ABSENT -- the matrix does not tile the "
                    f"cross product, so any count printed from it would lie"
                )
    return doc, None


def render(doc):
    planes = list(doc["planes"])
    missing = [
        f"{c['capability']}×{c['plane']}" for c in doc["cells"] if c["state"] == "missing"
    ]
    proven = sum(1 for c in doc["cells"] if c["state"] == "proven")
    na = sum(1 for c in doc["cells"] if c["state"] == "not-applicable")
    lines = [
        f"EQUALITY: {len(missing)} of {len(doc['cells'])} cells missing "
        f"({proven} proven, {na} n/a) -- LLM == MCP == A2A is not yet true, and this line "
        f"names where:"
    ]
    if missing:
        lines.append("  " + ", ".join(missing))
    per_plane = {
        p: sum(1 for c in doc["cells"] if c["state"] == "missing" and c["plane"] == p)
        for p in planes
    }
    lines.append(
        "  per plane: " + ", ".join(f"{p} {n}" for p, n in per_plane.items())
    )
    lines.append(
        "  (pin: qa/capability-equality.json; gate: crates/busbar/tests/capability_equality.rs -- "
        "close a cell by landing its test AND flipping the pin in the same commit)"
    )
    return "\n".join(lines)


def selftest():
    """A printer that would print a lying count must refuse instead. Three red fixtures, each run
    through the REAL load(), plus the real ledger accepted -- fixtures prove discrimination, the
    real file proves reach."""
    bad = 0

    def case(name, ok, why):
        nonlocal bad
        if ok:
            print(f"  [ok]     {name}")
        else:
            print(f"  [FAILED] {name} -- {why}")
            bad = 1

    with tempfile.TemporaryDirectory() as d:
        # (1) A missing ledger is refused, not printed as zero-gap.
        _, err = load(os.path.join(d, "absent.json"))
        case("an absent ledger is refused", err is not None, "printed from nothing")

        # (2) Malformed JSON is refused.
        p = os.path.join(d, "garbage.json")
        with open(p, "w", encoding="utf-8") as f:
            f.write("{ not json")
        _, err = load(p)
        case("a malformed ledger is refused", err is not None, "parsed garbage")

        # (3) A matrix with a HOLE is refused -- the count would lie by omission.
        p = os.path.join(d, "hole.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "capabilities": {"a": "x", "b": "x"},
                    "planes": {"p": "x"},
                    "cells": [{"capability": "a", "plane": "p", "state": "missing"}],
                },
                f,
            )
        _, err = load(p)
        case(
            "a matrix that does not tile the cross product is refused",
            err is not None and "ABSENT" in (err or ""),
            f"accepted a hole ({err})",
        )

        # (4) A fourth state is refused.
        p = os.path.join(d, "fourth.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "capabilities": {"a": "x"},
                    "planes": {"p": "x"},
                    "cells": [{"capability": "a", "plane": "p", "state": "partially"}],
                },
                f,
            )
        _, err = load(p)
        case("a fourth cell state is refused", err is not None, "accepted `partially`")

    # (5) The real ledger is accepted and yields a count -- the printer reaches its subject.
    doc, err = load(LEDGER)
    case(f"the real {LEDGER} is accepted", err is None, str(err))
    if doc is not None:
        out = render(doc)
        case("the rendered ledger names a count", out.startswith("EQUALITY: "), out[:60])

    # (6) The deep gate this printer fronts for actually exists and names the ledger -- a printer
    # outliving its gate would be the drift, one level up.
    gate = "crates/busbar/tests/capability_equality.rs"
    try:
        with open(gate, encoding="utf-8") as f:
            has = LEDGER in f.read()
    except OSError:
        has = False
    case("the enforcing cargo gate exists and reads the same ledger", has, gate)

    if bad:
        print("\ncapability-equality-summary selftest: FAILED")
        return 1
    print("\ncapability-equality-summary selftest: a broken ledger cannot print a clean line")
    return 0


def main():
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        return selftest()
    doc, err = load(LEDGER)
    if err:
        print(f"EQUALITY: UNREADABLE -- {err}", file=sys.stderr)
        print(
            "a gap that cannot be named is a gap on its way to being forgotten; fix the ledger",
            file=sys.stderr,
        )
        return 1
    print(render(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())

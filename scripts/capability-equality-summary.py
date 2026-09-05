#!/usr/bin/env python3
"""Print the equality doctrine's ledger line -- the missing-cell count and list -- on EVERY run.

    python3 scripts/capability-equality-summary.py              # print the ledger, exit 0
    python3 scripts/capability-equality-summary.py --root-legs  # RUN every root-leg proof cell
    python3 scripts/capability-equality-summary.py --selftest   # prove a broken ledger is refused

THE ROOT LEG COLUMN. Every cell carries a SECOND verdict (`root`), over the leg that runs its plane
through the composition root. `crates/busbar/tests/capability_equality.rs` verifies that column's
shape and that every named loop cell EXISTS. What a cargo test cannot do is run another crate's
tests, so `--root-legs` closes the other half: it builds the binary crate with all five `root-*`
features on and EXECUTES every root cell the ledger names, refusing a run in which a named cell did
not execute (a filter that selected nothing is a green that proves nothing). That is what makes
`proven` on the root column mean "watched over the loop" rather than "present on disk".

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
import re
import subprocess
import sys
import tempfile

LEDGER = "qa/capability-equality.json"
STATES = {"proven", "missing", "not-applicable"}
ROOT_STATES = {"proven", "none", "not-applicable"}
# The five legs the composition root carries, and the one cargo invocation that turns them all on.
ROOT_FEATURES = "root-admin,root-mcp,root-a2a,root-voice,root-llm"


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
    err = check_root_column(path, doc)
    if err:
        return None, err
    return doc, None


def check_root_column(path, doc):
    """The cheap half of the root-leg column's invariants, mirroring the cargo gate: every plane is
    answered by exactly one declared leg, every cell carries a second verdict naming that leg, and
    the two verdicts agree about `not-applicable`. Returns an error string or None."""
    legs = doc.get("root_legs")
    if not isinstance(legs, dict) or not legs:
        return f"{path}: `root_legs` must be a non-empty object of leg -> {{file, columns, note}}"
    plane_leg = {}
    for leg, meta in legs.items():
        if not isinstance(meta, dict) or not isinstance(meta.get("columns"), list):
            return f"{path}: root leg {leg!r} has no `columns` array"
        if not isinstance(meta.get("file"), str):
            return f"{path}: root leg {leg!r} names no `file`"
        for col in meta["columns"]:
            if col not in doc["planes"]:
                return f"{path}: root leg {leg!r} answers to undeclared column {col!r}"
            if col in plane_leg:
                return (
                    f"{path}: column {col!r} is claimed by both {plane_leg[col]!r} and {leg!r}; "
                    f"a plane runs through one leg, so two claims is no claim"
                )
            plane_leg[col] = leg
    unowned = sorted(p for p in doc["planes"] if p not in plane_leg)
    if unowned:
        return (
            f"{path}: ledger plane(s) {unowned} are answered by NO root leg -- a column with no "
            f"leg is a loop nobody is judging"
        )
    for c in doc["cells"]:
        cap, plane = c["capability"], c["plane"]
        r = c.get("root")
        if not isinstance(r, dict):
            return f"{path}: cell {cap}×{plane} carries no `root` verdict"
        if r.get("state") not in ROOT_STATES:
            return (
                f"{path}: cell {cap}×{plane} has root state {r.get('state')!r} "
                f"(no fourth state)"
            )
        if r.get("leg") != plane_leg[plane]:
            return (
                f"{path}: cell {cap}×{plane}'s root verdict names leg {r.get('leg')!r}, but that "
                f"plane runs through {plane_leg[plane]!r}"
            )
        if (r["state"] == "not-applicable") != (c["state"] == "not-applicable"):
            return (
                f"{path}: cell {cap}×{plane} is {c['state']!r} on the legacy path and "
                f"{r['state']!r} over the loop -- `not-applicable` is a statement about the PLANE "
                f"and cannot be true on one path and false on the other"
            )
        if r["state"] == "proven" and "::" not in str(r.get("test", "")):
            return (
                f"{path}: cell {cap}×{plane} is proven over the loop but names no "
                f"`<file>::<test fn>`"
            )
    return None


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
    lines.append(render_root(doc))
    return "\n".join(lines)


def render_root(doc):
    """The SECOND ledger line: the same matrix over the composition root's legs. A capability proven
    where the plane crate serves it and unwitnessed where the root drives it is the same silent
    half-answer, so the gap over the loop is named on every run too."""
    cells = doc["cells"]
    gaps = [
        f"{c['capability']}×{c['plane']}" for c in cells if c["root"]["state"] == "none"
    ]
    proven = sum(1 for c in cells if c["root"]["state"] == "proven")
    na = sum(1 for c in cells if c["root"]["state"] == "not-applicable")
    lines = [
        f"ROOT-EQUALITY: {len(gaps)} of {len(cells)} cells are still \"none\" over the composition "
        f"root's legs ({proven} proven over the loop, {na} n/a) -- this line names where:"
    ]
    if gaps:
        lines.append("  " + ", ".join(gaps))
    per_leg = []
    for leg in sorted(doc["root_legs"]):
        n = sum(1 for c in cells if c["root"]["leg"] == leg and c["root"]["state"] == "proven")
        g = sum(1 for c in cells if c["root"]["leg"] == leg and c["root"]["state"] == "none")
        per_leg.append(f"{leg} {n} proven / {g} none")
    lines.append("  per leg: " + ", ".join(per_leg))
    lines.append(
        "  (run them: scripts/capability-equality-summary.py --root-legs -- builds the binary "
        "crate with all five legs on and executes every named loop cell)"
    )
    return "\n".join(lines)


def root_cells(doc):
    """(leg, file, fn) for every root cell the ledger claims is proven, in ledger order."""
    out = []
    for c in doc["cells"]:
        r = c["root"]
        if r["state"] != "proven":
            continue
        f, fn = r["test"].split("::", 1)
        out.append((r["leg"], f, fn))
    return out


def libtest_path(file, fn):
    """`crates/busbar/src/root/units_mcp.rs::the_x` -> `root::units_mcp::tests::the_x`, the name the
    binary's own test harness knows it by. Derived rather than pinned, then CHECKED against the
    harness's own --list below, so a module that moved is a refusal and not a silent miss."""
    m = re.search(r"src/(.+)\.rs$", file)
    if not m:
        return None
    return m.group(1).replace("/", "::") + "::tests::" + fn


def run_named_root_cells(cells, label):
    """RUN a set of named root-leg cells. Build once with all five legs on, ask the harness what it
    carries, then execute exactly the cells the caller names -- and refuse a run where a named cell
    did not execute, because a filter that selected nothing is a green that proves nothing.

    `cells` is [(leg, repo-relative file, test fn)]. THE ONE RUNNER: `scripts/teller-steps-check.py`
    imports this rather than restating it, so "the cell RAN" has one definition in the tree.
    """
    if not cells:
        print(f"{label}: NO root cell was named to run", file=sys.stderr)
        return 1

    base = ["cargo", "test", "-p", "busbar", "--features", ROOT_FEATURES, "--bin", "busbar"]
    listed = subprocess.run(base + ["--", "--list"], capture_output=True, text=True)
    if listed.returncode != 0:
        print(f"{label}: the five-leg build did not compile:", file=sys.stderr)
        print(listed.stderr[-3000:], file=sys.stderr)
        return 1
    # `--list` prints `<full::test::path>: test` -- and the path itself is full of colons, so the
    # SUFFIX is what comes off, never a split on the first one.
    known = {
        ln[: -len(": test")] for ln in listed.stdout.splitlines() if ln.endswith(": test")
    }

    wanted, absent = [], []
    for leg, f, fn in cells:
        p = libtest_path(f, fn)
        if p is None or p not in known:
            absent.append(f"{leg}: {f}::{fn} (looked for {p})")
        elif p not in wanted:
            wanted.append(p)
    if absent:
        print(
            f"{label}: the five-leg build does NOT carry these named loop cells -- the ledger "
            f"claims a proof this binary cannot run:",
            file=sys.stderr,
        )
        for a in absent:
            print(f"  {a}", file=sys.stderr)
        return 1

    run = subprocess.run(base + ["--", "--exact"] + wanted, capture_output=True, text=True)
    out = run.stdout + run.stderr
    m = re.search(r"(\d+) passed; (\d+) failed", out)
    if run.returncode != 0 or not m:
        print(f"{label}: the root-leg cells did not pass:", file=sys.stderr)
        print(out[-3000:], file=sys.stderr)
        return 1
    passed, failed = int(m.group(1)), int(m.group(2))
    if failed or passed != len(wanted):
        print(
            f"{label}: expected {len(wanted)} named loop cell(s) to run and pass; the "
            f"harness reported {passed} passed / {failed} failed. A run that executed a different "
            f"set is not the run the ledger claims.",
            file=sys.stderr,
        )
        print(out[-3000:], file=sys.stderr)
        return 1
    per_leg = {}
    for leg, _, _ in cells:
        per_leg[leg] = per_leg.get(leg, 0) + 1
    print(
        f"{label}: {passed} named loop cell(s) RAN and passed with "
        f"--features {ROOT_FEATURES}"
    )
    for leg in sorted(per_leg):
        print(f"  {leg}: {per_leg[leg]} cell(s)")
    return 0


def run_root_legs():
    """The equality ledger's own root column, run."""
    doc, err = load(LEDGER)
    if err:
        print(f"ROOT-EQUALITY: UNREADABLE -- {err}", file=sys.stderr)
        return 1
    return run_named_root_cells(root_cells(doc), "ROOT-EQUALITY")


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

        # (4b) THE ROOT COLUMN. A cell with no second verdict, an n/a that disagrees across the two
        # paths, and a column no leg answers to must each be a refusal -- otherwise the ROOT-EQUALITY
        # line would print a count from a matrix nobody joined.
        base = {
            "capabilities": {"a": "x" * 30},
            "planes": {"p": "x"},
            "root_legs": {
                "leg": {"file": "crates/busbar/src/root/units_a.rs", "columns": ["p"], "note": "y" * 70}
            },
            "cells": [
                {
                    "capability": "a",
                    "plane": "p",
                    "state": "proven",
                    "test": "t",
                    "root": {
                        "state": "proven",
                        "leg": "leg",
                        "test": "crates/busbar/src/root/units_a.rs::the_loop_cell",
                    },
                }
            ],
        }

        def root_case(name, mutate, needle):
            d2 = json.loads(json.dumps(base))
            mutate(d2)
            p = os.path.join(d, re.sub(r"[^a-z0-9]+", "-", name) + ".json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump(d2, f)
            _, e = load(p)
            case(name, e is not None and needle in e, f"accepted it ({e})")

        # The unmutated fixture must PASS, or every red case below proves only that the base is bad.
        p = os.path.join(d, "root-green.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(base, f)
        _, e = load(p)
        case("a well-formed root column is accepted", e is None, str(e))

        root_case(
            "a cell with no root verdict is refused",
            lambda x: x["cells"][0].pop("root"),
            "carries no `root` verdict",
        )
        root_case(
            "a root verdict naming another leg is refused",
            lambda x: x["cells"][0]["root"].update({"leg": "other"}),
            "runs through",
        )
        root_case(
            "an n/a that disagrees across the two paths is refused",
            lambda x: x["cells"][0]["root"].update({"state": "not-applicable"}),
            "cannot be true on one path",
        )
        root_case(
            "a ledger column no leg answers to is refused",
            lambda x: x["root_legs"]["leg"].update({"columns": []}),
            "answered by NO root leg",
        )
        root_case(
            "a fourth root state is refused",
            lambda x: x["cells"][0]["root"].update({"state": "partially"}),
            "no fourth state",
        )

    # (5) The real ledger is accepted and yields a count -- the printer reaches its subject.
    doc, err = load(LEDGER)
    case(f"the real {LEDGER} is accepted", err is None, str(err))
    if doc is not None:
        out = render(doc)
        case("the rendered ledger names a count", out.startswith("EQUALITY: "), out[:60])
        case(
            "the rendered ledger names the loop's own gap set",
            "ROOT-EQUALITY: " in out,
            out[-80:],
        )
        # (5b) The derivation the runner uses must reach the file the ledger names, or --root-legs
        # would look for every cell under a path no harness knows and report a gap that is its own.
        leg_cells = root_cells(doc)
        case(
            "every root cell derives a libtest path under its own root module",
            leg_cells
            and all(
                (libtest_path(f, fn) or "").startswith("root::units_") for _, f, fn in leg_cells
            ),
            "a root cell derives no module path",
        )

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
    if len(sys.argv) > 1 and sys.argv[1] == "--root-legs":
        return run_root_legs()
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

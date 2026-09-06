#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""teller-steps-check.py — the H2 ledger printer: 'conformance rigs carry one cell per Teller step
per plane' (docs/design/1.6.0-TRACKER.md), matrix at qa/teller-steps.json.

    python3 scripts/teller-steps-check.py             # print the matrix, exit 0 or 1
    python3 scripts/teller-steps-check.py --check     # same as above (the flag CI wires in)
    python3 scripts/teller-steps-check.py --root-legs # RUN every root-leg proof cell the matrix names
    python3 scripts/teller-steps-check.py --root-legs-gating  # the SHIPPED legs owe every gating step
    python3 scripts/teller-steps-check.py --selftest  # prove a broken matrix is refused

RED RULE. For every plane and every GATING step (qa/teller-steps.json's steps.<step>.gating ==
true), the matrix's matrix.<plane>.<step>.cell must be something other than the literal string
"none". A gating step mapped to "none" anywhere is a named, printed gap and this script exits 1.
Non-gating steps (arrival/decode/approve) are printed for completeness but never fail the check —
they are mapped once, structurally, and are not what H2's own prose enumerates as load-bearing.

THE ROOT COLUMN. `cell` above is the SHIPPED path. Every cell now also carries a `root` verdict over
the leg that runs its plane through the composition root (root-llm / root-mcp / root-a2a /
root-voice / root-admin), naming a `crates/busbar/src/root/units_*.rs::<test fn>` cell that drives
the step through `run_unit`, or "none" with what the leg does instead. Structurally this column is
enforced the same way — every plane×step cell has one, a proven verdict names a fn that EXISTS in
its own leg's file, a "none" carries a real argument, and a leg with zero proven cells is red. Its
GAPS are printed and named but do not fail --check by themselves: the legs are default-OFF and are
being switched over plane by plane, so the gating rule is about the shipped path and the root gaps
are the switch-over queue. `--root-legs` goes the other way and EXECUTES every named cell (through
scripts/capability-equality-summary.py's one runner), so "proven" means watched, not merely present.

THE SHIPPED-LEG RULE (`--root-legs-gating`). "Default-off" is what makes a root gap a queue entry
rather than a hole, so the moment a leg enters `default` in crates/busbar/Cargo.toml that excuse
expires: the loop IS the shipped path for that plane, and a gating step nobody drives over it is the
same half-answer the rig column's gating rule exists to refuse. So this flag applies the rig
column's own RED RULE to the root column, for exactly the legs the binary ships on — read out of the
manifest rather than listed here, so a flip cannot turn the bar off by forgetting to update a second
list. `--check` is deliberately unchanged: it is the shipped-PATH ledger and its semantics are what
CI has been reading, so the new bar is its own flag and its own exit code.

This mirrors scripts/capability-equality-summary.py's own doctrine exactly: a printer that RE-CHECKS
what it prints (parseable, every declared plane x step cell present, no unknown status), so a
missing/malformed ledger is a refusal (exit 1), never a lying green.
"""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "qa" / "teller-steps.json"
STATUSES = {"mapped", "new", "none"}
ROOT_STATES = {"proven", "none"}
ROOT_DIR = "crates/busbar/src/root/"
# A root "none" shorter than this is a label; R-16 wants a sentence a reviewer could disagree with.
MIN_ROOT_NOTE = 60


def runner():
    """THE ONE RUNNER, borrowed rather than restated. `scripts/capability-equality-summary.py` owns
    the definition of "the named loop cell RAN and passed" (build the binary crate with all five
    legs on, ask the harness what it carries, execute exactly the named set, refuse a run that
    executed a different one). Two copies of that would be two definitions."""
    p = ROOT / "scripts" / "capability-equality-summary.py"
    spec = importlib.util.spec_from_file_location("capability_equality_summary", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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
    check_root_column(doc, steps, matrix)
    return doc, steps, matrix


def check_root_column(doc, steps, matrix):
    """The root column's own invariants. Raises ValueError; a matrix whose second verdict does not
    hold together cannot print an honest root line either."""
    legs = doc.get("root_legs")
    if not isinstance(legs, dict) or not legs:
        raise ValueError("qa/teller-steps.json: no non-empty 'root_legs' object")
    for leg, meta in legs.items():
        plane, file = meta.get("plane"), meta.get("file")
        if plane not in matrix:
            raise ValueError(f"qa/teller-steps.json: root leg {leg!r} names plane {plane!r}, "
                             f"which is not a row of the matrix")
        if not isinstance(file, str) or not file.startswith(ROOT_DIR):
            raise ValueError(f"qa/teller-steps.json: root leg {leg!r} names file {file!r}, which is "
                             f"not under {ROOT_DIR} -- a leg's evidence lives in the composition root")
        if not (ROOT / file).is_file():
            raise ValueError(f"qa/teller-steps.json: root leg {leg!r} names {file}, which does not exist")
    leg_of_plane = {m["plane"]: leg for leg, m in legs.items()}
    unowned = sorted(p for p in matrix if p not in leg_of_plane)
    if unowned:
        raise ValueError(f"qa/teller-steps.json: plane(s) {unowned} are answered by NO root leg -- "
                         f"a plane with no leg is a loop nobody is judging")
    proven_per_leg = {leg: 0 for leg in legs}
    for plane, row in matrix.items():
        leg = leg_of_plane[plane]
        for step, cell in row.items():
            r = cell.get("root")
            if not isinstance(r, dict):
                raise ValueError(f"qa/teller-steps.json: matrix.{plane}.{step} carries no 'root' "
                                 f"verdict -- an absent second verdict is indistinguishable from an "
                                 f"oversight")
            if r.get("state") not in ROOT_STATES:
                raise ValueError(f"qa/teller-steps.json: matrix.{plane}.{step}.root.state "
                                 f"{r.get('state')!r} is not one of {sorted(ROOT_STATES)}")
            if r.get("leg") != leg:
                raise ValueError(f"qa/teller-steps.json: matrix.{plane}.{step}.root names leg "
                                 f"{r.get('leg')!r}, but plane {plane!r} runs through {leg!r}")
            note = (r.get("note") or "").strip()
            if len(note) < MIN_ROOT_NOTE:
                raise ValueError(f"qa/teller-steps.json: matrix.{plane}.{step}.root has note "
                                 f"{note!r}: every root verdict owes a one-line argument "
                                 f"(>= {MIN_ROOT_NOTE} chars), a proof as much as a gap")
            if r["state"] == "none":
                continue
            test = r.get("test", "")
            want = legs[leg]["file"] + "::"
            if not isinstance(test, str) or not test.startswith(want):
                raise ValueError(f"qa/teller-steps.json: matrix.{plane}.{step}.root is proven by "
                                 f"{test!r}, which does not live in {leg!r}'s own file "
                                 f"{legs[leg]['file']} -- a leg is proven by its own cells")
            fn = test[len(want):]
            src = (ROOT / legs[leg]["file"]).read_text()
            if f"fn {fn}(" not in src:
                raise ValueError(f"qa/teller-steps.json: matrix.{plane}.{step}.root is proven by "
                                 f"{test}, but no `fn {fn}(` exists there. The named loop cell is "
                                 f"gone or renamed; a claim that outlives its evidence is the drift "
                                 f"this check exists to stop")
            proven_per_leg[leg] += 1
    empty = sorted(leg for leg, n in proven_per_leg.items() if n == 0)
    if empty:
        raise ValueError(f"qa/teller-steps.json: root leg(s) {empty} prove ZERO steps over the loop. "
                         f"A leg with no watched cell is a leg nobody drove")


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
            root = entry.get("root") or {}
            rmark = "NONE" if root.get("state") != "proven" else "LOOP"
            rcell = (
                root.get("test", "").rsplit("::", 1)[-1]
                if root.get("state") == "proven"
                else "--"
            )
            lines.append(
                f"  [{tag}] {step:<13} {mark:<6} {entry['cell']:<46} {rmark:<5} {rcell}"
            )
            if is_gap and gating:
                gaps.append(f"{plane}.{step}")
    return "\n".join(lines), len(gaps), gaps


def root_line(matrix):
    """The SECOND ledger line: the same plane x step matrix over the composition root's legs. Named
    on every run, green or red, for the same reason the rig gaps are."""
    gaps, proven, per_leg = [], 0, {}
    for plane, row in sorted(matrix.items()):
        for step, cell in row.items():
            r = cell.get("root") or {}
            leg = r.get("leg", "?")
            per_leg.setdefault(leg, [0, 0])
            if r.get("state") == "proven":
                proven += 1
                per_leg[leg][0] += 1
            else:
                gaps.append(f"{plane}.{step}")
                per_leg[leg][1] += 1
    total = proven + len(gaps)
    out = [
        f"ROOT-STEPS: {len(gaps)} of {total} plane x step cell(s) are still \"none\" over the "
        f"composition root's legs ({proven} driven through run_unit) -- this line names where:"
    ]
    if gaps:
        out.append("  " + ", ".join(gaps))
    out.append(
        "  per leg: "
        + ", ".join(f"{leg} {n} proven / {g} none" for leg, (n, g) in sorted(per_leg.items()))
    )
    out.append(
        "  (run them: scripts/teller-steps-check.py --root-legs -- builds the binary crate with "
        "all five legs on and executes every named loop cell)"
    )
    return "\n".join(out)


def root_cells(matrix):
    """(leg, file, fn) for every root cell the matrix claims is proven."""
    out = []
    for plane in sorted(matrix):
        for cell in matrix[plane].values():
            r = cell.get("root") or {}
            if r.get("state") != "proven":
                continue
            f, fn = r["test"].split("::", 1)
            out.append((r["leg"], f, fn))
    return out


def default_root_legs(manifest=None):
    """The root legs the shipped binary is BUILT with, read out of crates/busbar/Cargo.toml.

    Read rather than listed because a second list is a second answer: the `default = [...]` line IS
    the flip, so a leg that becomes default and a leg this bar applies to are the same fact, and a
    flip cannot quietly escape the bar by leaving a copy here un-updated.

    Deliberately a narrow parse of one line rather than a TOML dependency: this script runs anywhere
    python3 does, and the shape it reads is a single-line array the manifest has always written.
    """
    p = manifest or (ROOT / "crates" / "busbar" / "Cargo.toml")
    text = Path(p).read_text()
    in_features = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_features = stripped == "[features]"
            continue
        if not in_features or not stripped.startswith("default"):
            continue
        head, _, rest = stripped.partition("=")
        if head.strip() != "default":
            continue
        if "[" not in rest or "]" not in rest:
            raise ValueError("crates/busbar/Cargo.toml: `default` is not a single-line array")
        body = rest[rest.index("[") + 1 : rest.rindex("]")]
        feats = [f.strip().strip('"') for f in body.split(",") if f.strip()]
        return {f for f in feats if f.startswith("root-")}
    raise ValueError("crates/busbar/Cargo.toml: no `default` line under [features]")


def root_legs_gating(steps, matrix, shipped):
    """The shipped legs owe a driven cell for every gating step. Returns (text, red-cells)."""
    red, considered = [], 0
    for plane in sorted(matrix):
        for step, cell in matrix[plane].items():
            if not steps[step]["gating"]:
                continue
            r = cell.get("root") or {}
            if r.get("leg") not in shipped:
                continue
            considered += 1
            if r.get("state") != "proven":
                red.append(f"{plane}.{step} ({r.get('leg')})")
    legs = ", ".join(sorted(shipped)) if shipped else "(none)"
    out = [
        f"ROOT-GATING: the shipped legs are {legs}; {considered} gating plane x step cell(s) "
        "are theirs to drive."
    ]
    if red:
        out.append("  not driven: " + ", ".join(sorted(red)))
    return "\n".join(out), red


def run_root_legs_gating():
    try:
        _, steps, matrix = load()
        shipped = default_root_legs()
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"ROOT-GATING: cannot read the bar's two inputs: {e}", file=sys.stderr)
        return 1
    text, red = root_legs_gating(steps, matrix, shipped)
    print(text)
    if red:
        print(
            f"RED: {len(red)} gating step(s) on a leg the binary SHIPS have no cell over the loop. "
            "A default leg is the shipped path for its plane; a gating step nobody drives over it "
            "is a half-answer, not a queue entry."
        )
        return 1
    print("GREEN: every gating step on every shipped root leg is driven over the loop.")
    return 0


def run_root_legs():
    import os

    os.chdir(ROOT)
    try:
        _, _, matrix = load()
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"ROOT-STEPS: qa/teller-steps.json is not a valid matrix: {e}", file=sys.stderr)
        return 1
    return runner().run_named_root_cells(root_cells(matrix), "ROOT-STEPS")


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

    # THE ROOT COLUMN, on a fixture that is GREEN first -- otherwise every red case below would
    # prove only that the fixture is bad. The leg file and the fn are real, because "the named loop
    # cell exists" is exactly what this half checks and a planted file would not test the reach.
    leg_file = "crates/busbar/src/root/units_llm.rs"
    leg_fn = "the_switched_table_names_every_dialect_the_plane_names"
    note = "a fixture argument long enough to be an argument a reviewer could actually disagree with"

    def root_doc():
        return {
            "steps": {"gate": {"gating": True}},
            "root_legs": {"root-llm": {"plane": "llm", "file": leg_file}},
            "matrix": {
                "llm": {
                    "gate": {
                        "cell": "x",
                        "status": "mapped",
                        "root": {
                            "state": "proven",
                            "leg": "root-llm",
                            "test": f"{leg_file}::{leg_fn}",
                            "note": note,
                        },
                    }
                }
            },
        }

    def expect_ok(doc, why):
        nonlocal failures
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(doc, f)
            path = f.name
        global LEDGER
        saved = LEDGER
        try:
            LEDGER = Path(path)
            load()
            print(f"  ok: accepted {why}")
        except ValueError as e:
            print(f"  MISS: {why} was refused ({e})")
            failures += 1
        finally:
            LEDGER = saved

    expect_ok(root_doc(), "a well-formed root column")

    d = root_doc()
    d["matrix"]["llm"]["gate"].pop("root")
    expect_raises(d, "a cell carrying no root verdict")

    d = root_doc()
    d["matrix"]["llm"]["gate"]["root"]["test"] = f"{leg_file}::a_fn_that_was_renamed_away"
    expect_raises(d, "a root proof whose named loop cell vanished")

    d = root_doc()
    d["matrix"]["llm"]["gate"]["root"]["test"] = (
        f"crates/busbar/src/root/units_mcp.rs::{leg_fn}"
    )
    expect_raises(d, "root evidence taken from another leg's file")

    d = root_doc()
    d["matrix"]["llm"]["gate"]["root"]["note"] = "not yet"
    expect_raises(d, "a root verdict with a label instead of an argument")

    d = root_doc()
    d["root_legs"] = {"root-mcp": {"plane": "mcp", "file": leg_file}}
    expect_raises(d, "a plane no root leg answers to")

    d = root_doc()
    d["matrix"]["llm"]["gate"]["root"] = {"state": "none", "leg": "root-llm", "note": note}
    expect_raises(d, "a leg that proves zero steps over the loop")

    # And the root line itself must COUNT what it prints: one proven cell, no gap.
    text = root_line(root_doc()["matrix"])
    if "0 of 1" in text and "root-llm 1 proven / 0 none" in text:
        print("  ok: the root line counts the cells it prints")
    else:
        print(f"  MISS: the root line miscounted -- {text.splitlines()[0]}")
        failures += 1

    # THE SHIPPED-LEG BAR. Three properties, because the bar is worth exactly as much as its
    # ability to go red: a gating gap on a SHIPPED leg is red, the same gap on a leg the binary does
    # not ship is NOT (that is the switch-over queue the flag deliberately leaves alone), and the
    # shipped set is really read out of a manifest rather than assumed.
    steps = {"gate": {"gating": True}, "info": {"gating": False}}
    gap = {"state": "none", "leg": "root-llm", "note": note}
    driven = {"state": "proven", "leg": "root-llm", "test": "x::y", "note": note}
    matrix = {"llm": {"gate": {"root": gap}, "info": {"root": gap}}}

    _, red = root_legs_gating(steps, matrix, {"root-llm"})
    if [r.split(" ")[0] for r in red] == ["llm.gate"]:
        print("  ok: a gating gap on a shipped leg is red, and a non-gating one is not")
    else:
        print(f"  MISS: the shipped-leg bar named {red}")
        failures += 1

    _, red = root_legs_gating(steps, matrix, set())
    if not red:
        print("  ok: the same gap on a leg the binary does not ship is left to the queue")
    else:
        print(f"  MISS: the bar judged an unshipped leg -- {red}")
        failures += 1

    matrix_ok = {"llm": {"gate": {"root": driven}, "info": {"root": gap}}}
    _, red = root_legs_gating(steps, matrix_ok, {"root-llm"})
    if not red:
        print("  ok: a driven gating step on a shipped leg is green")
    else:
        print(f"  MISS: the bar refused a driven cell -- {red}")
        failures += 1

    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write('[features]\ndefault = ["proto-llm", "root-admin", "root-mcp"]\nroot-a2a = []\n')
        manifest = f.name
    if default_root_legs(manifest) == {"root-admin", "root-mcp"}:
        print("  ok: the shipped set is read out of the manifest's own default line")
    else:
        print(f"  MISS: read {default_root_legs(manifest)} out of the manifest")
        failures += 1

    if failures:
        print(f"teller-steps-check self-test: {failures} FAILURE(S)")
        return 1
    print("teller-steps-check self-test: PASS.")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    # The two root flags compose: `--root-legs --root-legs-gating` executes every named cell AND
    # applies the shipped-leg bar, and the run is red if either half is. Neither touches --check.
    if "--root-legs" in sys.argv or "--root-legs-gating" in sys.argv:
        rc = run_root_legs() if "--root-legs" in sys.argv else 0
        if "--root-legs-gating" in sys.argv:
            print()
            rc = run_root_legs_gating() or rc
        return rc
    try:
        doc, steps, matrix = load()
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"FAIL: {LEDGER.relative_to(ROOT)} is not a valid teller-steps matrix: {e}", file=sys.stderr)
        return 1
    text, n_gaps, gaps = render(steps, matrix)
    print(text)
    print()
    print(root_line(matrix))
    print()
    if n_gaps:
        print(f"RED: {n_gaps} gating plane x step cell(s) are still \"none\": {', '.join(gaps)}")
        return 1
    print("GREEN: every gating plane x step cell in qa/teller-steps.json names a real scenario.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

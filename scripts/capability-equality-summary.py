#!/usr/bin/env python3
"""Print the equality doctrine's ledger line -- the missing-cell count and list -- on EVERY run.

    python3 scripts/capability-equality-summary.py              # print the ledger, exit 0
    python3 scripts/capability-equality-summary.py --root-legs  # RUN every root-leg proof cell
    python3 scripts/capability-equality-summary.py --selftest   # prove a broken ledger is refused

THE ROOT LEG COLUMN. Every cell carries a SECOND verdict (`root`), over the leg that runs its plane
through the composition root. `crates/busbar/tests/capability_equality.rs` verifies that column's
shape and that every named loop cell EXISTS. What a cargo test cannot do is run another crate's
tests, so `--root-legs` closes the other half: it builds the binary crate with every leg's
feature on (ROOT_FEATURES below) and EXECUTES every root cell the ledger names, refusing a run in which a named cell did
not execute (a filter that selected nothing is a green that proves nothing). That is what makes
`proven` on the root column mean "watched over the loop" rather than "present on disk".

WHY A PRINTER AND NOT ANOTHER GATE. The RED enforcement for `qa/capability-equality.json` lives in
`crates/busbar/tests/capability_equality.rs` (proven cells must name tests that exist; the cross
product is exact; n/a needs an argument) and runs on every `cargo test`. What a cargo test cannot
do is put the GAP in front of whoever reads a green umbrella run: its output is swallowed on
success. So `cargo xtask full-gate` calls this printer in its result section, green or red, and the
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
# The six legs the composition root carries, and the one cargo invocation that turns them all on:
# the admin leg's own feature, for the mcp, a2a and voice legs (the kernel-loop rider those planes are
# served through) and the decisions leg (its door, served end to end) the feature that links the
# plane, and for the llm leg the feature that links the plane riding the `node` axis, which compiles
# the root's node (`root/plane_node.rs`).
ROOT_FEATURES = "root-admin,plane-mcp,plane-a2a,plane-streaming,plane-decisions,proto-llm"


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
        "crate with every leg on and executes every named loop cell)"
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


BUSBAR_MAIN = "crates/busbar/src/main.rs"


def _tokens(src):
    """The tokens the module reader needs: ("id", name), ("str", text) or ("p", char). Comments and
    literal bodies are skipped (a string's text is kept, for `#[path = ".."]`), and a char literal is
    told from a lifetime. The same scanner as xtask/src/libtest_path.rs."""
    c, n, i, out = src, len(src), 0, []
    ident0 = lambda ch: ch.isascii() and (ch.isalpha() or ch == "_")
    identc = lambda ch: ch.isascii() and (ch.isalnum() or ch == "_")
    while i < n:
        ch = c[i]
        if ch.isspace():
            i += 1
            continue
        if c.startswith("//", i):
            while i < n and c[i] != "\n":
                i += 1
            continue
        if c.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if c.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif c.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            continue
        raw_at = i + 1 if ch == "r" else (i + 2 if c.startswith("br", i) else None)
        if raw_at is not None:
            j, hashes = raw_at, 0
            while j < n and c[j] == "#":
                hashes, j = hashes + 1, j + 1
            if j < n and c[j] == '"':
                j += 1
                end = c.find('"' + "#" * hashes, j)
                end = n if end < 0 else end
                out.append(("str", c[j:end]))
                i = min(end + 1 + hashes, n)
                continue
            if ch == "r" and hashes == 1 and j < n and ident0(c[j]):
                k = j
                while k < n and identc(c[k]):
                    k += 1
                out.append(("id", c[j:k]))
                i = k
                continue
        if ch == '"' or c.startswith('b"', i):
            j, text = (i + 2 if ch == "b" else i + 1), []
            while j < n and c[j] != '"':
                if c[j] == "\\" and j + 1 < n:
                    text.append(c[j : j + 2])
                    j += 2
                    continue
                text.append(c[j])
                j += 1
            out.append(("str", "".join(text)))
            i = min(j + 1, n)
            continue
        if ch == "'" or c.startswith("b'", i):
            q = i + 1 if ch == "b" else i
            if q + 1 < n and c[q + 1] == "\\":
                j = q + 3
                while j < n and c[j] != "'":
                    j += 1
                i = min(j + 1, n)
                continue
            if q + 2 < n and c[q + 2] == "'":
                i = q + 3
                continue
            i = q + 1
            continue
        if ident0(ch):
            j = i
            while j < n and identc(c[j]):
                j += 1
            out.append(("id", c[i:j]))
            i = j
            continue
        if ch.isdigit():
            while i < n and (identc(c[i]) or c[i] == "."):
                i += 1
            continue
        out.append(("p", ch))
        i += 1
    return out


def _file_items(src):
    """(decls, fns) of one file: decls are (inline nesting, name, `#[path]` or None) for every
    `mod <name>;`; fns are (inline nesting, name) for every `fn <name>`."""
    t = _tokens(src)
    decls, fns, stack, depth, pending, i = [], [], [], 0, None, 0
    at = lambda k: t[k] if k < len(t) else (None, None)
    while i < len(t):
        kind, val = t[i]
        if (
            (kind, val) == ("p", "#")
            and at(i + 1) == ("p", "[")
            and at(i + 2) == ("id", "path")
            and at(i + 3) == ("p", "=")
            and at(i + 5) == ("p", "]")
        ):
            if at(i + 4)[0] == "str":
                pending = at(i + 4)[1]
            i += 6
            continue
        if (kind, val) == ("id", "mod") and at(i + 1)[0] == "id":
            name, nest = at(i + 1)[1], [m for m, _ in stack]
            if at(i + 2) == ("p", ";"):
                decls.append((nest, name, pending))
                pending = None
                i += 3
                continue
            if at(i + 2) == ("p", "{"):
                depth += 1
                stack.append((name, depth))
                pending = None
                i += 3
                continue
        if (kind, val) == ("id", "fn") and at(i + 1)[0] == "id":
            fns.append(([m for m, _ in stack], at(i + 1)[1]))
            i += 2
            continue
        if (kind, val) == ("p", "{"):
            depth += 1
            pending = None
        elif (kind, val) == ("p", "}"):
            while stack and stack[-1][1] == depth:
                stack.pop()
            depth = max(depth - 1, 0)
            pending = None
        elif (kind, val) == ("p", ";"):
            pending = None
        i += 1
    return decls, fns


def module_tree(read, root_file):
    """THE MODULE TREE of a crate, read the way rustc builds it: from `root_file`, every
    `mod <name>;` followed to its file (a `#[path]` relative to the declaring file's directory, or
    `<name>.rs` / `<name>/mod.rs` beside a mod-rs file and under `<stem>/` beside any other), every
    inline `mod <name> { .. }` part of the path. Returns (file -> set of module paths, file -> items).
    `read(path)` gives a repo-relative file's text or None."""
    norm = lambda p: os.path.normpath(p).replace(os.sep, "/")
    paths, items = {}, {}
    work = [(root_file, "", os.path.dirname(root_file), None)]
    while work:
        file, module, d, relative = work.pop()
        seen = paths.setdefault(file, set())
        if module in seen:
            continue
        seen.add(module)
        if file not in items:
            src = read(file)
            if src is None:
                continue
            items[file] = _file_items(src)
        for nest, name, path_attr in items[file][0]:
            child_module = "::".join([m for m in [module] if m] + nest + [name])
            inline_dir = d
            if nest:
                if relative:
                    inline_dir = os.path.join(inline_dir, relative)
                inline_dir = os.path.join(inline_dir, *nest)
            if path_attr is not None:
                child = norm(os.path.join(inline_dir, path_attr))
                work.append((child, child_module, os.path.dirname(child), None))
                continue
            base = inline_dir if nest else (os.path.join(d, relative) if relative else d)
            flat, nested = norm(os.path.join(base, f"{name}.rs")), norm(os.path.join(base, name, "mod.rs"))
            if read(flat) is not None:
                work.append((flat, child_module, norm(base), name))
            elif read(nested) is not None:
                work.append((nested, child_module, os.path.dirname(nested), None))
    return paths, items


def resolve(tree, file, fn):
    """(libtest path, None) for `fn` in `file`, or (None, why): the file is reached by no
    declaration, or the file or the fn is reached two ways (AMBIGUOUS, both named, never guessed)."""
    paths, items = tree
    reached = sorted(paths.get(file, set()))
    if not reached:
        return None, f"{file} is reached by no `mod` declaration from the crate root, so no test in it runs"
    if len(reached) > 1:
        return None, f"{file} is AMBIGUOUS: the crate reaches it as {' and '.join(reached)}; name one"
    nests = sorted({tuple(nest) for nest, name in items.get(file, ([], []))[1] if name == fn})
    if not nests:
        return None, f"no `fn {fn}` in {file}"
    if len(nests) > 1:
        return None, (
            f"`fn {fn}` in {file} is AMBIGUOUS: it is defined under "
            f"`{'::'.join(nests[0])}` and `{'::'.join(nests[1])}`"
        )
    return "::".join([m for m in [reached[0]] if m] + list(nests[0]) + [fn]), None


def _read_repo(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


_TREE = None


def libtest_path(file, fn):
    """`crates/busbar/src/root/tests/serve_tests.rs::the_x` -> `root::serve::door_tests::agent_door::the_x`,
    the name the binary's own test harness knows it by: READ off the module tree (`module_tree`), not
    guessed from the file's name, then CHECKED against the harness's own --list below. Returns
    (path, None) or (None, why)."""
    global _TREE
    if _TREE is None:
        _TREE = module_tree(_read_repo, BUSBAR_MAIN)
    return resolve(_TREE, file, fn)


def run_named_root_cells(cells, label):
    """RUN a set of named root-leg cells. Build once with all five legs on, ask the harness what it
    carries, then execute exactly the cells the caller names -- and refuse a run where a named cell
    did not execute, because a filter that selected nothing is a green that proves nothing.

    `cells` is [(leg, repo-relative file, test fn)].

    THIS IS NO LONGER THE ONE RUNNER. `scripts/teller-steps-check.py` used to import it; that check
    is now `cargo xtask teller-steps --root-legs`, which carries its own copy of this sequence
    (`xtask/src/gates/teller_steps.rs::run_root_legs`) including all three floors. Two copies is the
    cost of the conversion being incremental, and it is a NAMED cost: this printer folds into
    `cargo xtask full-gate`, and the second copy goes when it does. Until then, a change to the
    refusals here owes the same change there.
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
        p, why = libtest_path(f, fn)
        if p is None:
            absent.append(f"{leg}: {f}::{fn} ({why})")
        elif p not in known:
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

    # (4c) THE LIBTEST NAME IS READ OFF THE SOURCE. A body `serve.rs` carries under ANOTHER module
    # name (`#[path = "tests/serve_tests.rs"] mod door_tests`) and nests in an inline module resolves
    # to that module path; the file-NAME derivation this replaced gave `root::serve_tests::tests::<fn>`,
    # a module no build carries (RED: --root-legs reported every door cell absent). A file reached
    # two ways, or a fn defined under two nestings, is refused naming both; an unreached file is
    # refused naming it.
    def fixture_tree(files):
        return module_tree(lambda p: files.get(p), "c/src/main.rs")

    door = fixture_tree(
        {
            "c/src/main.rs": "mod root;\nfn main() {}\n",
            "c/src/root/mod.rs": "pub mod serve;\n",
            "c/src/root/serve.rs": (
                '#[cfg(test)]\n#[path = "tests/serve.rs"]\nmod tests;\n// mod not_a_module;\n'
                '#[cfg(all(test, linked_axis_node))]\n#[path = "tests/serve_tests.rs"]\nmod door_tests;\n'
            ),
            "c/src/root/tests/serve.rs": "#[test]\nfn plain_cell() {}\n",
            "c/src/root/tests/serve_tests.rs": (
                "mod decisions_door {\n    #[tokio::test]\n    async fn a_decisions_cell() {\n"
                '        let s = "mod fake { fn a_door_cell() }";\n        let c = \'}\';\n'
                "        let q = '\\'';\n    }\n}\n"
                "mod agent_door {\n    fn helper<'a>(x: &'a str) -> &'a str { x }\n"
                "    #[tokio::test]\n    async fn a_door_cell() {\n        /* } mod x { */\n"
                '        assert_eq!(helper(r#"}"#), "}");\n    }\n}\n'
            ),
        }
    )
    got, why = resolve(door, "c/src/root/tests/serve_tests.rs", "a_door_cell")
    case(
        "a #[path]-carried file resolves under its declared module and inline nesting",
        got == "root::serve::door_tests::agent_door::a_door_cell",
        f"resolved {got!r} ({why})",
    )
    case(
        "the file-name derivation `root::serve_tests::tests::<fn>` is not what resolves",
        got != "root::serve_tests::tests::a_door_cell",
        "the old derivation came back",
    )
    case(
        "a sibling inline module and a plain #[path] tests file resolve too",
        resolve(door, "c/src/root/tests/serve_tests.rs", "a_decisions_cell")[0]
        == "root::serve::door_tests::decisions_door::a_decisions_cell"
        and resolve(door, "c/src/root/tests/serve.rs", "plain_cell")[0]
        == "root::serve::tests::plain_cell",
        "a door sibling or the plain tests file did not resolve",
    )
    twice = fixture_tree(
        {
            "c/src/main.rs": "mod root;\n",
            "c/src/root/mod.rs": (
                '#[path = "tests/shared.rs"]\nmod one;\n#[path = "tests/shared.rs"]\nmod two;\n'
                '#[path = "tests/twice.rs"]\nmod twice;\n'
            ),
            "c/src/root/tests/shared.rs": "#[test]\nfn a_cell() {}\n",
            "c/src/root/tests/twice.rs": "mod a { #[test] fn a_cell() {} }\nmod b { #[test] fn a_cell() {} }\n",
        }
    )
    _, file_why = resolve(twice, "c/src/root/tests/shared.rs", "a_cell")
    _, fn_why = resolve(twice, "c/src/root/tests/twice.rs", "a_cell")
    case(
        "a file reached under two module paths is refused naming both",
        bool(file_why) and "AMBIGUOUS" in file_why and "root::one" in file_why and "root::two" in file_why,
        str(file_why),
    )
    case(
        "a fn defined under two inline modules is refused naming both",
        bool(fn_why) and "AMBIGUOUS" in fn_why and "`a`" in fn_why and "`b`" in fn_why,
        str(fn_why),
    )
    case(
        "an unreached file is refused naming it",
        "orphan.rs" in (resolve(door, "c/src/root/tests/orphan.rs", "a_cell")[1] or ""),
        "an unreached file resolved",
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
        unresolved = [
            f"{f}::{fn}: {libtest_path(f, fn)[1]}"
            for _, f, fn in leg_cells
            if libtest_path(f, fn)[0] is None
            or not libtest_path(f, fn)[0].startswith("root::")
            or not libtest_path(f, fn)[0].endswith(f"::{fn}")
        ]
        case(
            "every root cell resolves to a libtest path under its own root module",
            bool(leg_cells) and not unresolved,
            "; ".join(unresolved[:5]) or "no root cell",
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

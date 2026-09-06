#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# inventory-ref-lint.py -- every Appendix B binding's `inventory` column names a docs/design
# inventory file that actually exists (docs/design/inventory/1.5.5-*.md, or
# docs/design/1.5.5-BEHAVIOUR.md, or a bare backtick source path / `PB-N` self-reference, neither
# of which points at an inventory file at all).
#
# This is PB-72's binding made executable: "where a binding paraphrases its row, the row wins" only
# means anything if the row a binding cites actually exists; a reference to a file that was renamed
# or never existed is silently unfalsifiable otherwise. Deliberately does NOT try to resolve the
# finer-grained anchors (section numbers, `BOOT-172`-style row ids, source line numbers) inside that
# file: those drift with every refactor/renumbering and Appendix B's own free-text formatting for
# them is not consistent enough to parse without false positives; the file-level pointer is the
# part that is both load-bearing (PB-72 exists because PB-1's round-3 fix was to the ROW, i.e. the
# right FILE, not a within-file line) and reliably checkable.
#
# --check      exits non-zero and lists every dangling reference.
# --selftest   proves the scanner: a good binding set is clean; a bad file-prefix and a bad anchor
#              each fail, exactly one row apiece.

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINDINGS = ROOT / "qa" / "design-bindings.json"
INV_DIR = ROOT / "docs" / "design" / "inventory"
ARCH = ROOT / "docs" / "design" / "ARCHITECTURE.md"
BEHAVIOUR = ROOT / "docs" / "design" / "1.5.5-BEHAVIOUR.md"

# file-prefix word (as it appears in a binding's `inventory` column) -> inventory file it names.
ALIASES = {
    "auth-secrets": INV_DIR / "1.5.5-auth-secrets.md",
    "config": INV_DIR / "1.5.5-config.md",
    "dialects": INV_DIR / "1.5.5-dialects.md",
    "governance": INV_DIR / "1.5.5-governance-billing.md",
    "ops": INV_DIR / "1.5.5-ops-observability.md",
    "plugins-stores": INV_DIR / "1.5.5-plugins-stores.md",
    "proxy-hooks": INV_DIR / "1.5.5-proxy-hooks.md",
    "routes-admin": INV_DIR / "1.5.5-routes-admin.md",
    "1.5.5-behaviour": BEHAVIOUR,
}

# One inventory `inventory` column is `;`-separated segments, each headed by a file-prefix word.
PREFIX_RE = re.compile(r"^\s*`?([A-Za-z][A-Za-z.\-]*(?:\s[A-Za-z][A-Za-z\-]*)?)")

# One known Appendix-B table-parsing artifact: PB-20's binding text embeds the literal pipe-joined
# string `prev|seq|ts|action|resource|outcome|principal`, and the unescaped `|` characters inside a
# markdown table cell split it like any other column boundary, so the derived `inventory` field for
# that ONE row is a fragment of that string, not a pointer. Not a docs bug (the row itself, read in
# the rendered file, is unambiguous); a bug in nothing this lint owns fixing. Named here, not
# silently swallowed by the prefix heuristic.
KNOWN_PARSE_ARTIFACTS = {"PB-20"}


def load_bindings() -> list[dict]:
    doc = json.loads(BINDINGS.read_text())
    return doc.get("bindings", [])


def resolve_prefix(segment: str) -> tuple[str, Path] | None:
    m = PREFIX_RE.match(segment)
    if not m:
        return None
    words = segment.strip().strip("`")
    for alias, path in ALIASES.items():
        if words.lower().startswith(alias):
            return alias, path
    # A bare backtick code path (e.g. `config/mod.rs:1796-1799`) or a `PB-N` self-reference names
    # no inventory file at all -- not a dangling ref, just nothing to check here.
    if segment.strip().startswith("`") or segment.strip().startswith("PB-"):
        return None
    return ("?", Path("?"))  # unresolved prefix, flagged below


def check_binding(b: dict, cache: dict[Path, str]) -> list[str]:
    if b["id"] in KNOWN_PARSE_ARTIFACTS:
        return []
    inv = (b.get("inventory") or "").strip()
    if not inv or inv.startswith("every row of every inventory file"):
        return []  # PB-0's own row: a description, not a pointer.
    problems: list[str] = []
    for segment in inv.split(";"):
        segment = segment.strip()
        if not segment:
            continue
        resolved = resolve_prefix(segment)
        if resolved is None:
            continue
        alias, path = resolved
        if alias == "?":
            problems.append(f"{b['id']}: unrecognized inventory file prefix in segment '{segment}'")
            continue
        if path not in cache:
            cache[path] = path.is_file()
        if not cache[path]:
            problems.append(f"{b['id']}: inventory file missing for '{alias}': {path}")
    return problems


CELLS = ROOT / "testing" / "shadow-oracle" / "cells.json"


def check_cell_inventory_ids(cells_path: Path = CELLS) -> list[str]:
    """Every id in a CELL's `inventory` array must be a real inventory row id.

    This half of the lint was missing entirely. Everything above validates a BINDING's `inventory`
    column, which names an inventory FILE; nothing validated the `inventory` ID ARRAYS the oracle
    cells carry -- and those arrays are what scripts/inventory-coverage.py turns into the `citers`
    of a coverage row. A cell citing an id that does not exist is therefore worse than a dangling
    reference: the id it MEANT to cite gets no citer, so its coverage row silently becomes a gap,
    while the cell goes on claiming to cover something. That is how `CFG-220` -- a spelling left
    behind when the config inventory family was renamed to `CONF-` -- sat in three
    `admin.ops|PutHooksName|*` cells while `CONF-220` (`hooks.<h>.module`, REQUIRED) read as
    uncovered. No gate could see it: inventory-ref-lint reported GREEN, and inventory-coverage only
    noticed one commit later, as an unexplained id with no cell.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        from importlib import import_module

        known = set(import_module("inventory-coverage".replace("-", "_")).parse_inventory_ids())
    except Exception:  # pragma: no cover - import shape differs
        import importlib.util

        spec = importlib.util.spec_from_file_location("_invcov", ROOT / "scripts" / "inventory-coverage.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        known = set(mod.parse_inventory_ids())
    if not known:
        return ["inventory id universe parsed to ZERO ids -- nothing could be checked against it"]
    if not cells_path.exists():
        return []
    doc = json.loads(cells_path.read_text(encoding="utf-8"))
    problems: list[str] = []
    for cell in doc.get("cells", []):
        for cid in cell.get("inventory", []) or []:
            if cid not in known:
                problems.append(
                    f"cell {cell.get('id', '<unnamed>')}: inventory id '{cid}' is not an id in "
                    "docs/design/inventory/ (renamed away, or a typo -- either way it cites nothing)"
                )
    return problems


def check(bindings_path: Path = BINDINGS, cells_path: Path = CELLS) -> list[str]:
    global BINDINGS
    BINDINGS = bindings_path
    bindings = load_bindings()
    cache: dict[Path, str] = {}
    problems: list[str] = []
    for b in bindings:
        problems.extend(check_binding(b, cache))
    problems.extend(check_cell_inventory_ids(cells_path))
    return problems


def selftest() -> int:
    import tempfile

    print("== inventory-ref-lint SELF-TEST ==")
    fails = 0
    cases = 0

    def say(ok: bool, msg: str):
        nonlocal fails, cases
        cases += 1
        print(("PASS  " if ok else "FAIL  ") + msg)
        if not ok:
            fails += 1

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        good = {
            "bindings": [
                {"id": "PB-X1", "inventory": "routes-admin LST-001"},
            ]
        }
        bad_prefix = {
            "bindings": [
                {"id": "PB-X2", "inventory": "not-a-real-file ZZZ-001"},
            ]
        }
        no_pointer = {
            "bindings": [
                {"id": "PB-X3", "inventory": "`config/mod.rs:1796-1799`; PB-72"},
            ]
        }
        gp = tdp / "good.json"
        gp.write_text(json.dumps(good))
        problems = check(gp)
        say(problems == [], f"a real inventory file prefix is clean (got {problems})")

        bp = tdp / "bad_prefix.json"
        bp.write_text(json.dumps(bad_prefix))
        problems = check(bp)
        say(
            len(problems) == 1 and "unrecognized inventory file prefix" in problems[0],
            f"an unrecognized file prefix is exactly one problem (got {problems})",
        )

        np_ = tdp / "no_pointer.json"
        np_.write_text(json.dumps(no_pointer))
        problems = check(np_)
        say(
            problems == [],
            f"a bare source-file backtick and a PB-N self-reference name no inventory file, so neither is flagged (got {problems})",
        )

        # A CELL citing an inventory id that does not exist. This is the half of the lint that was
        # missing; before it, `CFG-220` in three real cells was invisible to every gate.
        cells_bad = tdp / "cells_bad.json"
        cells_bad.write_text(json.dumps({"cells": [
            {"id": "fam|op|slice", "inventory": ["CONF-220", "CFG-220"]},
        ]}))
        problems = check_cell_inventory_ids(cells_bad)
        say(
            len(problems) == 1 and "CFG-220" in problems[0] and "fam|op|slice" in problems[0],
            f"a cell citing a renamed-away inventory id is exactly one problem, naming cell and id (got {problems})",
        )

        cells_ok = tdp / "cells_ok.json"
        cells_ok.write_text(json.dumps({"cells": [
            {"id": "fam|op|slice", "inventory": ["CONF-220"]},
            {"id": "fam|op|other", "inventory": []},
        ]}))
        problems = check_cell_inventory_ids(cells_ok)
        say(problems == [], f"a cell citing only real inventory ids is clean (got {problems})")

        # And the shipped cells.json itself -- the check is worthless if it only ever sees fixtures.
        problems = check_cell_inventory_ids()
        say(problems == [], f"every id in the SHIPPED testing/shadow-oracle/cells.json resolves (got {problems})")

    print()
    if fails == 0:
        print(f"inventory-ref-lint selftest: GREEN ({cases} cases)")
        return 0
    print(f"inventory-ref-lint selftest: RED ({fails}/{cases} cases failed)")
    return 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    problems = check()
    if problems:
        print(f"inventory-ref-lint: RED -- {len(problems)} dangling inventory reference(s):")
        for p in problems:
            print(f"  {p}")
        return 1
    print("inventory-ref-lint: GREEN -- every binding's inventory column resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

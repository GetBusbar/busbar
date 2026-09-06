#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""The NAMED CONFORMANCE GAP register of the LLM spec conformance rig.

A named gap is a place where the product emits what the provider's own DOCUMENTATION describes and
the provider's PUBLISHED machine-readable spec does not admit, and the owner has decided the product
is right. It is the same kind of object as `testing/shadow-oracle/accepted-differences.json`, and it
obeys the same three rules:

  * NEVER A SILENT PASS. A gapped row is written to the ledger with the row class `gap`, printed in
    its own column, kept out of the owed set, and counted by the verdict. It is not a pass and it is
    never counted as one.
  * PINNED TO A SPEC DIGEST. Each entry names the digest of the published document it was confirmed
    against. When `spec-digests.tsv` moves, the entry goes STALE: it forgives nothing (the rows go
    back to FAIL) and it reports RED itself, until a human re-reads the new document and either
    re-confirms the entry against the new digest or deletes it.
  * AN UNUSED GAP IS A LIE. Every entry IN SCOPE for the run owes a `named-gap|<id>` ledger row.
    Fired at least once -> PASS; fired zero times -> FAIL, exactly like a probe that did not run.
    In scope means the run's cell universe actually contains a cell the entry names: a gate run over
    the whole of cells.json owes every entry, and a run over a three-cell fixture is not made red by
    an entry about cells it was never asked to judge. An entry no cell universe reaches at all is a
    dead entry, and `--check` says so.

Nothing here touches the validator's schema logic. The checker still produces the same violations
against the same pinned document; this register only decides what a failure is CALLED, and only when
every violation on the row is the exact one an entry names.

Usage as a script:
    named_gaps.py --check [--gaps <file>] [--digests <spec-digests.tsv>]   # register is well-formed
    named_gaps.py --ids   [--gaps <file>]                                  # the owed `named-gap|` ids
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_GAPS = os.path.join(HERE, "named-gaps.json")
DEFAULT_DIGESTS = os.path.join(HERE, "spec-digests.tsv")

# Every field is required. A gap that does not say WHO decided, WHY, against WHICH document and for
# WHICH exact violation is not a named gap, it is a silenced failure with a comment on it.
REQUIRED = ("id", "provider", "spec", "spec_digest", "review_at", "by", "dialect", "direction",
            "cells", "schema_path", "frame", "violation", "reason", "docs")
REQUIRED_VIOLATION = ("pointer", "rule", "detail_contains")
ROW_PREFIX = "named-gap|"


class Entry:
    """One registered gap: the rule it forgives, the pin it is confirmed against, and its firings."""

    def __init__(self, raw, pinned_digest):
        self.raw = raw
        self.id = raw["id"]
        self.dialect = raw["dialect"]
        self.direction = raw["direction"]
        self.schema_path = raw["schema_path"]
        self.cells = [re.compile(p) for p in raw["cells"]]
        v = raw["violation"]
        self.pointer = re.compile(v["pointer"])
        self.rule = v["rule"]
        self.detail_contains = v["detail_contains"]
        self.pinned_digest = pinned_digest
        self.fired = []
        # Set by Register.scope(): does the cell universe this run judges contain a cell this entry
        # names? Until it is scoped an entry answers for nothing.
        self.in_scope = False

    @property
    def stale(self):
        return self.pinned_digest != self.raw["spec_digest"]

    def row_id(self):
        return ROW_PREFIX + self.id

    def matches_row(self, cell_id, direction, dialect, schema_path):
        return (direction == self.direction and dialect == self.dialect
                and schema_path == self.schema_path
                and any(c.search(cell_id) for c in self.cells))

    def matches_violation(self, v):
        return (v.rule == self.rule and self.pointer.search(v.pointer)
                and self.detail_contains in str(v.detail))

    def detail(self):
        return (f"{self.raw['provider']} {self.raw['frame']} vs {self.schema_path} "
                f"@ spec {self.raw['spec']} {self.raw['spec_digest'][:12]} — {self.raw['reason']} "
                f"[{self.raw['docs']}] (by {self.raw['by']}; {self.raw['review_at']})")


class Register:
    def __init__(self, entries):
        self.entries = entries

    def scope(self, cells):
        """Mark the entries this run can answer for: the ones whose cells the universe contains."""
        for e in self.entries:
            e.in_scope = any(c.get("ingress_dialect") == e.dialect and any(r.search(c["id"]) for r in e.cells)
                             for c in cells)
        return self

    @property
    def scoped(self):
        return [e for e in self.entries if e.in_scope]

    def match(self, cell_id, direction, dialect, schema_path, violations):
        """The entry that names EVERY violation on this row, or None. A stale entry names nothing."""
        if not violations:
            return None
        for e in self.entries:
            if e.stale or not e.matches_row(cell_id, direction, dialect, schema_path):
                continue
            if all(e.matches_violation(v) for v in violations):
                e.fired.append(f"{cell_id}#{direction}")
                return e
        return None

    def owed_ids(self):
        return [e.row_id() for e in self.scoped]

    def ledger_rows(self):
        """One row per in-scope entry: a gap that is stale, or that never fired, is RED."""
        rows = []
        for e in self.scoped:
            title = f"named gap {e.id} ({e.raw['provider']} {e.schema_path})"
            if e.stale:
                rows.append((e.row_id(), "FAIL", title,
                             f"STALE: this gap was confirmed against {e.raw['spec']} spec digest "
                             f"{e.raw['spec_digest']}, and spec-digests.tsv now pins "
                             f"{e.pinned_digest}. A re-pinned document must be re-read: either "
                             f"the member arrived and this entry goes away, or re-confirm it "
                             f"against the new digest. Forgiving nothing until then."))
            elif not e.fired:
                rows.append((e.row_id(), "FAIL", title,
                             "registered but NEVER FIRED: no row produced the violation this entry "
                             "names. An unused gap is a lie — the product changed, the spec moved, "
                             "or the cells regex no longer selects anything. Delete it or fix it."))
            else:
                rows.append((e.row_id(), "PASS", title,
                             f"fired on {len(e.fired)} row(s): {', '.join(sorted(e.fired))}"))
        return rows


def load(path=DEFAULT_GAPS, pins=None, digests_path=DEFAULT_DIGESTS):
    """Read the register and REFUSE a malformed one (a bad entry is a bug, not a soft failure)."""
    if pins is None:
        pins = read_digests(digests_path)
    if not os.path.exists(path):
        raise SystemExit(f"named-gaps: register not found: {path}")
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    entries, seen = [], set()
    for raw in doc.get("gaps", []):
        missing = [k for k in REQUIRED if k not in raw]
        if missing:
            raise SystemExit(f"named-gaps: entry {raw.get('id', '(no id)')!r} is missing {missing}")
        for k in REQUIRED_VIOLATION:
            if k not in raw["violation"]:
                raise SystemExit(f"named-gaps: entry {raw['id']!r} violation is missing {k!r}")
        if raw["id"] in seen:
            raise SystemExit(f"named-gaps: duplicate entry id {raw['id']!r}")
        seen.add(raw["id"])
        if not raw["cells"]:
            raise SystemExit(f"named-gaps: entry {raw['id']!r} has no cells (a total blanket)")
        if raw["direction"] not in ("request", "response"):
            raise SystemExit(f"named-gaps: entry {raw['id']!r} direction must be request|response")
        if not str(raw["docs"]).startswith("http"):
            raise SystemExit(f"named-gaps: entry {raw['id']!r} must cite the provider's public "
                             f"documentation URL for the frame it keeps")
        # `review_at` restates the pin as the point of re-confirmation; the two disagreeing means the
        # entry was edited without deciding which document it now speaks for.
        want = "spec-digest:" + raw["spec_digest"]
        if raw["review_at"] != want:
            raise SystemExit(f"named-gaps: entry {raw['id']!r} review_at must be {want!r} "
                             f"(got {raw['review_at']!r})")
        if raw["spec"] not in pins:
            raise SystemExit(f"named-gaps: entry {raw['id']!r} names spec {raw['spec']!r}, which "
                             f"spec-digests.tsv does not pin")
        entries.append(Entry(raw, pins[raw["spec"]]["digest"]))
    return Register(entries)


def load_cells(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    cells = doc["cells"] if isinstance(doc, dict) else doc
    return [c for c in cells if c.get("plane") == "llm" or c.get("ingress_dialect")]


def read_digests(path):
    out = {}
    with open(path, encoding="utf-8") as f:
        for ln in f:
            if not ln.strip() or ln.startswith("#"):
                continue
            parts = ln.rstrip("\n").split("\t")
            if len(parts) >= 4:
                out[parts[0]] = dict(fmt=parts[1], digest=parts[2], url=parts[3])
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gaps", default=DEFAULT_GAPS)
    ap.add_argument("--digests", default=DEFAULT_DIGESTS)
    ap.add_argument("--cells", default=os.path.join(os.path.dirname(HERE), "shadow-oracle", "cells.json"),
                    help="the cell universe the run judges; an entry it does not reach is not owed")
    ap.add_argument("--check", action="store_true", help="the register is well-formed; print each entry and whether its pin is current")
    ap.add_argument("--ids", action="store_true", help="print the `named-gap|<id>` ids the run owes")
    a = ap.parse_args()
    reg = load(a.gaps, digests_path=a.digests).scope(load_cells(a.cells))
    if a.ids:
        for i in reg.owed_ids():
            print(i)
        return 0
    if a.check:
        dead = []
        for e in reg.entries:
            state = "STALE" if e.stale else ("pinned" if e.in_scope else "DEAD")
            if not e.in_scope:
                dead.append(e.id)
            print(f"{state:<7} {e.id:<28} {e.raw['spec']} {e.raw['spec_digest'][:12]} "
                  f"-> {e.schema_path}")
        if dead:
            # A staleness is reported through the ledger like everything else (the verdict stays the
            # only place anything is decided), but an entry NO cell in the universe reaches can never
            # fire and never be judged: it is dead text, and that is a defect of the register itself.
            sys.stderr.write(f"named-gaps: these entries name no cell in {a.cells}: {dead}\n")
            return 1
        return 0
    ap.error("one of --check or --ids")


if __name__ == "__main__":
    sys.exit(main())

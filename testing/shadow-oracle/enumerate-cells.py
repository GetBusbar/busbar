#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Enumerate the shadow-oracle golden-corpus cells — DERIVED, never hand-listed.

The oracle records the current binary's exact behavior (bytes + effects) per cell and replays it
against any later binary. Its cell list must be a function of what busbar claims to support, so a
new method, dialect or transport becomes a new cell automatically (an uncovered cell is RED), and
no one can forget one.

Sources (both GENERATED, both already gated):
  qa/method-inventory.json  -- MCP + A2A: method x originator x role x transport (230 cells, 10 N/A)
  qa/field-inventory.json   -- LLM: the dialects + directions + streaming flag

Each protocol cell is crossed with the OUTCOME CLASSES the governed path must reproduce
byte-for-byte: the happy path plus every refusal the core pipeline can emit before/around it.

Output: testing/shadow-oracle/cells.json  (stable ids, sorted; the recorder/replayer iterate it).
Usage:  enumerate-cells.py [--write] [--summary]
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
METHOD_INV = ROOT / "qa" / "method-inventory.json"
FIELD_INV = ROOT / "qa" / "field-inventory.json"
OUT = Path(__file__).resolve().parent / "cells.json"

# The outcome classes every plane's governed path must reproduce. Order is the pipeline order the
# refusal is produced at, so a diff names the earliest divergent step.
OUTCOMES = [
    ("ok", "happy path: authenticated, in-scope, under budget, upstream healthy"),
    ("unauthenticated", "no / bad credential -> refused at Authenticate (native 401)"),
    ("out_of_scope", "credential lacks the scope/grant -> refused at Approve (native 403)"),
    ("over_budget", "budget exhausted -> refused at Admit (native 429, names the bucket)"),
    ("malformed", "undecodable request -> refused at decode (native 400)"),
    ("upstream_down", "upstream refuses/times out -> Route failover / native upstream error"),
]
# Outcomes that only make sense for a request the plane actually forwards (not for refusals that
# never reach Route).
STREAMING_OUTCOMES = [("ok_stream", "happy path, streamed response (SSE / frames)")]


# Refusals are produced BEFORE Route, so they never depend on the egress dialect: enumerate them
# same-proto only (ingress == egress). Forwarded outcomes reach Route and exercise the cross-protocol
# translation the LLM plane exists for: enumerate EVERY ordered (ingress, egress) dialect pair.
PRE_ROUTE = {"unauthenticated", "out_of_scope", "over_budget", "malformed"}


def llm_cells(inv: dict) -> list[dict]:
    """LLM: refusal outcomes per dialect (same-proto); forwarded outcomes (ok, upstream_down, and a
    streamed happy path where the EGRESS dialect streams) for every ingress x egress dialect pair —
    the diagonal is the codec's own round trip, the off-diagonal is cross-protocol translation."""
    dialects = sorted(inv["dialects"]) if isinstance(inv["dialects"], list) else sorted(inv["dialects"].keys())
    streams = {f["dialect"] for f in inv["fields"] if f.get("streaming")}

    def cell(i: str, e: str, oc: str, why: str) -> dict:
        c = {
            "id": f"llm|{i}|{e}|request|{oc}",
            "plane": "llm", "family": "llm.wire", "ingress_dialect": i, "egress_dialect": e,
            "cross_protocol": i != e, "transport": "http", "op": "chat",
            "outcome": oc, "why": why,
        }
        # A 5xx from the upstream parks the lane's breaker; a later cell on that lane would then
        # record "overloaded" instead of its own outcome. `fresh` = the recorder boots a NEW busbar
        # (re-mints, re-primes) before this cell, so every cell is "from a fresh boot, do X".
        if oc == "upstream_down":
            c["fresh"] = True
        return c

    cells = []
    for d in dialects:
        for oc, why in OUTCOMES:
            if oc in PRE_ROUTE:
                cells.append(cell(d, d, oc, why))
    for i in dialects:
        for e in dialects:
            for oc, why in OUTCOMES:
                if oc not in PRE_ROUTE:
                    cells.append(cell(i, e, oc, why))
            if e in streams:
                for oc, why in STREAMING_OUTCOMES:
                    cells.append(cell(i, e, oc, why))
    return cells


def protocol_cells(inv: dict) -> list[dict]:
    """MCP / A2A: every non-N/A inventory cell x every outcome. The inventory cell already carries
    protocol, method, originator, role, transport and obligation; we add the outcome axis."""
    na = {c["id"] for c in inv.get("na_cells", [])} if isinstance(inv.get("na_cells"), list) else set()
    cells = []
    for c in inv["cells"]:
        if c["id"] in na or c.get("obligation") == "n/a":
            continue
        for oc, why in OUTCOMES:
            cells.append({
                "id": f"{c['id']}|{oc}",
                "plane": c["protocol"], "method": c["method"], "originator": c["originator"],
                "role": c["role"], "transport": c["transport"], "obligation": c["obligation"],
                "outcome": oc, "why": why,
            })
    return cells


def main() -> int:
    minv = json.loads(METHOD_INV.read_text())
    finv = json.loads(FIELD_INV.read_text())
    cells = sorted(llm_cells(finv) + protocol_cells(minv), key=lambda c: c["id"])
    ids = [c["id"] for c in cells]
    assert len(ids) == len(set(ids)), "cell ids must be unique"
    doc = {
        "_comment": [
            "GENERATED by testing/shadow-oracle/enumerate-cells.py. Do not edit by hand.",
            "Regenerate: testing/shadow-oracle/enumerate-cells.py --write",
            "One cell = one recorded (request, response, effects) triple the shadow oracle replays.",
        ],
        "derived_from": {"method_inventory": str(METHOD_INV.relative_to(ROOT)),
                          "field_inventory": str(FIELD_INV.relative_to(ROOT))},
        "outcomes": [{"outcome": o, "why": w} for o, w in OUTCOMES + STREAMING_OUTCOMES],
        "counts": {
            "total": len(cells),
            "by_plane": {p: sum(1 for c in cells if c["plane"] == p) for p in sorted({c["plane"] for c in cells})},
        },
        "cells": cells,
    }
    if "--summary" in sys.argv or "--write" not in sys.argv:
        print(json.dumps(doc["counts"], indent=2))
    if "--write" in sys.argv:
        OUT.write_text(json.dumps(doc, indent=2) + "\n")
        print(f"wrote {OUT.relative_to(ROOT)} ({len(cells)} cells)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

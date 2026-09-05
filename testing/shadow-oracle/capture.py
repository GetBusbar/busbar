#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Assemble one captured oracle cell from curl output + before/after EFFECT snapshots.

  capture.py <headers-file> <status> <body-file> <before-dir> <after-dir> [egress-file ...] > captured.json

The response half is the bytes busbar returned. The effects half is what busbar DID — the closed loop
("meters were metered, audits audited") — expressed as DELTAS between two snapshots taken around the
request, so absolute counters (which differ per run) never enter a golden:
  effects.usage    numeric fields of GET /api/v1/admin/keys/{id}/usage, after - before
  effects.metrics  prometheus samples (name + labels) whose value changed, after - before
  effects.audit    the admin-audit items added, plus the count: each added item as
                   {actor, action, resource, outcome, chain_ok} — chain_ok is computed here, against
                   the RAW (pre-normalization) hashes, before normalize.py ever sees them: an item's
                   chain_ok is true iff its prev_hash equals the preceding entry's hash (the previous
                   added item, or — for the oldest added item — the newest pre-existing entry), and,
                   for the very first entry the process ever wrote, iff prev_hash is empty (genesis)
  effects.egress   the request(s) busbar itself sent upstream, in order: each trailing argv is the
                   path to one JSON file written by mock-upstream.py's ORACLE_MOCK_CAPTURE_DIR
                   ({"path", "method", "headers", "body"} — see that script's docstring for how the
                   recorder finds these files for a given cell). A cell with none named just gets an
                   empty list — that itself is a contract for cells that must never reach upstream
                   (e.g. a refusal at Admit). A file that could not be read is recorded as
                   {"unavailable": true}, same convention as the other snapshot-derived effects.
A snapshot file that is missing or unparseable is recorded as {"unavailable": true} — visible in the
golden, never silently zero (a binary that cannot expose its ledger must not look like one that
metered nothing).
"""
import base64
import json
import os
import re
import sys

SAMPLE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([-+0-9.eE]+|NaN|[-+]Inf)\s*$")


def load_json(d: str, name: str):
    p = os.path.join(d, name)
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return None


def num_delta(a, b):
    """after - before over numeric leaves; non-numeric leaves are kept from `after` only if changed."""
    if isinstance(b, dict):
        a = a if isinstance(a, dict) else {}
        out = {}
        for k in sorted(set(a) | set(b)):
            d = num_delta(a.get(k), b.get(k))
            # `d in (..., 0)` uses `==`, and in Python False == 0, so a bool False delta (a genuine
            # true->false flip) would silently vanish here. Booleans are never "falsy zero": keep any
            # non-None bool, and otherwise fall back to the original empty/zero check.
            if isinstance(d, bool):
                out[k] = d
            elif d not in (None, {}, [], 0):
                out[k] = d
        return out
    if isinstance(b, list):
        return {"len": len(b) - (len(a) if isinstance(a, list) else 0)} if not isinstance(a, list) or len(a) != len(b) else {}
    if isinstance(b, bool):
        return b if a != b else None
    if isinstance(b, (int, float)):
        return b - (a if isinstance(a, (int, float)) and not isinstance(a, bool) else 0)
    return b if a != b else None


def parse_metrics(text: str) -> dict:
    out = {}
    for ln in text.splitlines():
        if not ln or ln.startswith("#"):
            continue
        m = SAMPLE.match(ln)
        if not m:
            continue
        try:
            out[m.group(1) + (m.group(2) or "")] = float(m.group(3))
        except ValueError:
            pass
    return out


def metrics_delta(before_dir: str, after_dir: str):
    try:
        b = parse_metrics(open(os.path.join(before_dir, "metrics.txt")).read())
        a = parse_metrics(open(os.path.join(after_dir, "metrics.txt")).read())
    except OSError:
        return {"unavailable": True}
    out = {}
    for k in sorted(set(a) | set(b)):
        d = a.get(k, 0.0) - b.get(k, 0.0)
        if d != 0:
            out[k] = int(d) if d == int(d) else d
    return out


def parse_headers(path: str) -> dict:
    h = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            ln = ln.rstrip("\r\n")
            if ":" in ln and not ln.startswith("HTTP/"):
                k, v = ln.split(":", 1)
                h[k.strip().lower()] = v.strip()
    return h


def audit_items(x) -> list:
    """The entry list out of a GET /api/v1/admin/audit snapshot, newest-first (matches the wire
    shape: {"items": [...], "next_cursor": ...}). A bare list or a missing/empty snapshot degrades
    to []."""
    if isinstance(x, dict):
        return x.get("items") or []
    return x if isinstance(x, list) else []


def audit_diff(before, after) -> dict:
    """The audit items THIS request added, plus the count. `before`/`after` are the raw (unnormalized)
    GET /api/v1/admin/audit snapshots — newest-first — taken around the request.

    The chain check has to happen here, on the raw hashes, because normalize.py turns every
    hash into "<HASH>" (they are per-run, content-derived, and not themselves the contract) — by the
    time a normalizer could look, prev_hash == hash would trivially hold for ANY two items. So each
    item's chain_ok is computed now and carried forward as a plain boolean; the raw hash/prev_hash
    values themselves are never put in the output (only actor/action/resource/outcome/chain_ok are)."""
    if after is None:
        return {"unavailable": True}
    items_before = audit_items(before)
    items_after = audit_items(after)
    added_n = len(items_after) - len(items_before)
    # The first `added_n` entries of `after` are the ones this request appended (still newest-first).
    added_desc = items_after[:added_n] if added_n > 0 else []
    # Walk oldest-added -> newest-added so each item's predecessor is well-defined: the oldest added
    # item's predecessor is the newest PRE-EXISTING entry (or, if there was no pre-existing entry at
    # all, the chain genesis — whose prev_hash must be "").
    prev_hash = items_before[0].get("hash", "") if items_before else ""
    items_out = []
    for it in reversed(added_desc):
        items_out.append({
            "actor": it.get("principal"),
            "action": it.get("action"),
            "resource": it.get("resource"),
            "outcome": it.get("outcome"),
            "chain_ok": it.get("prev_hash", "") == prev_hash,
        })
        prev_hash = it.get("hash", "")
    return {"added": added_n, "items": items_out}


def load_egress(paths: list) -> list:
    """Read the egress record files the recorder found for this cell, in the order given (the order
    the recorder discovered them, which — because mock-upstream.py names them so filenames sort in
    request order — is also the order the requests actually happened in)."""
    out = []
    for p in paths:
        try:
            with open(p) as f:
                out.append(json.load(f))
        except (OSError, ValueError):
            out.append({"unavailable": True})
    return out


def main() -> int:
    hdr_file, status, body_file, before, after = sys.argv[1:6]
    egress = load_egress(sys.argv[6:])
    raw = open(body_file, "rb").read()
    try:
        body = raw.decode("utf-8")
    except UnicodeDecodeError:
        body = "base64:" + base64.b64encode(raw).decode()

    ub, ua = load_json(before, "usage.json"), load_json(after, "usage.json")
    # `as_of` is the snapshot's own wall clock: its delta is 0 or 1 depending on the second boundary,
    # never a fact about the request. Drop it before the delta so its presence cannot flap.
    for snap in (ub, ua):
        if isinstance(snap, dict):
            snap.pop("as_of", None)
    usage = num_delta(ub, ua) if ua is not None else {"unavailable": True}
    ab, aa = load_json(before, "audit.json"), load_json(after, "audit.json")
    audit = audit_diff(ab, aa)

    cap = {
        "status": int(status) if status.isdigit() else 0,
        "headers": parse_headers(hdr_file),
        "body": body,
        "effects": {"usage": usage, "metrics": metrics_delta(before, after), "audit": audit, "egress": egress},
    }
    print(json.dumps(cap, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

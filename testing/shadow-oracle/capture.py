#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Assemble one captured oracle cell from curl output + before/after EFFECT snapshots.

  capture.py <headers-file> <status> <body-file> <before-dir> <after-dir> > captured.json

The response half is the bytes busbar returned. The effects half is what busbar DID — the closed loop
("meters were metered, audits audited") — expressed as DELTAS between two snapshots taken around the
request, so absolute counters (which differ per run) never enter a golden:
  effects.usage    numeric fields of GET /api/v1/admin/keys/{id}/usage, after - before
  effects.metrics  prometheus samples (name + labels) whose value changed, after - before
  effects.audit    count of admin-audit items added
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
            if d not in (None, {}, [], 0):
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


def main() -> int:
    hdr_file, status, body_file, before, after = sys.argv[1:6]
    raw = open(body_file, "rb").read()
    try:
        body = raw.decode("utf-8")
    except UnicodeDecodeError:
        body = "base64:" + base64.b64encode(raw).decode()

    ub, ua = load_json(before, "usage.json"), load_json(after, "usage.json")
    usage = num_delta(ub, ua) if ua is not None else {"unavailable": True}
    ab, aa = load_json(before, "audit.json"), load_json(after, "audit.json")

    def count(x):
        if isinstance(x, dict):
            return len(x.get("items") or [])
        return len(x) if isinstance(x, list) else 0

    audit = {"added": count(aa) - count(ab)} if aa is not None else {"unavailable": True}

    cap = {
        "status": int(status) if status.isdigit() else 0,
        "headers": parse_headers(hdr_file),
        "body": body,
        "effects": {"usage": usage, "metrics": metrics_delta(before, after), "audit": audit},
    }
    print(json.dumps(cap, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

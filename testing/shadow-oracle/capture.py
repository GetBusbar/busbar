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
                   for the very first entry the process ever wrote, iff prev_hash is empty (genesis).
                   The COUNT is the page-length difference only while the snapshot is a whole page;
                   once the log outgrows the recorder's `?limit=1000` the count comes from the
                   entries' own monotonic `seq` instead, because both capped pages hold exactly 1000
                   entries and their lengths stop moving
  effects.egress   the request(s) busbar itself sent upstream, in order: each trailing argv is the
                   path to one JSON file written by mock-upstream.py's ORACLE_MOCK_CAPTURE_DIR
                   ({"path", "method", "headers", "body"} — see that script's docstring for how the
                   recorder finds these files for a given cell). A cell with none named just gets an
                   empty list — that itself is a contract for cells that must never reach upstream
                   (e.g. a refusal at Admit). A file that could not be read is recorded as
                   {"unavailable": true}, same convention as the other snapshot-derived effects.
A snapshot file that is missing or unparseable is recorded as {"unavailable": true} — visible in the
golden, never silently zero (a binary that cannot expose its ledger must not look like one that
metered nothing). That holds for the BEFORE snapshot exactly as much as for the after one: the
recorder writes both with `curl ... -o <dir>/usage.json || rm -f <dir>/usage.json`, so a transient
admin-API failure leaves the file ABSENT, and a delta taken against an absent "before" is not a
delta at all — it is the running total. `after - 0` would put an absolute counter in a golden (the
one thing effects.* exists to keep out) and, for the audit log, would report every entry the process
has ever written as "added by this request". Both sides must be present, or the effect is
unavailable.

  capture.py --selftest    # prove the above; no busbar, no network
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
    # The recorder scrapes with `oracle_scrape_metrics ... || true`, so a scrape that failed after
    # creating (or part-writing) the file leaves a metrics.txt with no parseable samples. Subtracting
    # that from a healthy "after" reports every counter's RUNNING TOTAL as this request's delta.
    # EITHER SIDE, not just the before one: this guard used to read `not b and a`, so the mirror
    # failure — a healthy before against an empty AFTER — reported every counter's NEGATED lifetime
    # total instead, which is the same absolute-in-a-golden the docstring above refuses for usage and
    # audit ("Both sides must be present, or the effect is unavailable"). Two binaries whose scrape
    # fails the same way then produce the same fabricated numbers and compare equal, so the metrics
    # half of the closed loop proves nothing while looking measured.
    if bool(b) != bool(a):
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


def audit_seq(it):
    """An audit entry's monotonic 1-based sequence number, or None if the wire shape has none."""
    v = it.get("seq") if isinstance(it, dict) else None
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def audit_page_full(snap) -> bool:
    """True when the snapshot is only the FIRST PAGE of the audit log — the recorder asks for
    `?limit=1000` and the response says there is more behind a cursor. On a full page the entry
    COUNT stops moving (both sides pin at the limit), so `len(after) - len(before)` silently reports
    0 added for every cell recorded after the 1000th entry."""
    return bool(isinstance(snap, dict) and snap.get("next_cursor"))


def audit_diff(before, after) -> dict:
    """The audit items THIS request added, plus the count. `before`/`after` are the raw (unnormalized)
    GET /api/v1/admin/audit snapshots — newest-first — taken around the request.

    The chain check has to happen here, on the raw hashes, because normalize.py turns every
    hash into "<HASH>" (they are per-run, content-derived, and not themselves the contract) — by the
    time a normalizer could look, prev_hash == hash would trivially hold for ANY two items. So each
    item's chain_ok is computed now and carried forward as a plain boolean; the raw hash/prev_hash
    values themselves are never put in the output (only actor/action/resource/outcome/chain_ok are)."""
    # Either side missing means there is no delta to take. With `before` absent the subtraction below
    # would read as "this request added every entry in the log" (added_n = len(items_after), up to the
    # recorder's whole ?limit=1000 page) and would compute the oldest item's chain_ok against genesis
    # ("") rather than against the entry that really preceded it — a confidently wrong answer that
    # looks exactly like a right one in the golden.
    if after is None or before is None:
        return {"unavailable": True}
    items_before = audit_items(before)
    items_after = audit_items(after)
    added_n = len(items_after) - len(items_before)
    extra = {}
    # A snapshot that is only the first of several pages cannot be counted by length: the recorder
    # asks for ?limit=1000, so once the log passes 1000 entries BOTH pages hold exactly 1000 and the
    # subtraction reports 0 added for every cell from then on — a cell that audited nothing and a
    # cell that audited five look identical, and the golden freezes the wrong answer.
    # The entries carry their own monotonic 1-based `seq` (unique within a process lifetime), so the
    # newest sequence numbers give the count directly, independent of any page limit.
    if audit_page_full(before) or audit_page_full(after):
        sb = audit_seq(items_before[0]) if items_before else 0
        sa = audit_seq(items_after[0]) if items_after else None
        if sa is not None and sb is not None and sa >= sb:
            added_n = sa - sb
        else:
            # No seq on the wire, or the sequence went BACKWARDS (the process restarted mid-cell and
            # its counter reset to 1). Neither the length nor the sequence can be trusted here, and a
            # wrong count must not look like a right one.
            extra["paged"] = True
    # The first `added_n` entries of `after` are the ones this request appended (still newest-first).
    added_desc = items_after[:added_n] if added_n > 0 else []
    if added_n > len(items_after):
        # more were added than this page can show: the items list is partial, the count is not
        extra["items_truncated"] = added_n - len(items_after)
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
    return {"added": added_n, "items": items_out, **extra}


def usage_delta(before: str, after: str) -> dict:
    """The usage view's after-before delta, or {"unavailable": True} when EITHER snapshot is missing
    or unparseable. Shared with capture-concurrent.py so the two drivers cannot drift on what counts
    as a delta. `as_of` is the snapshot's own wall clock — its delta is 0 or 1 depending on which
    side of a second boundary each fetch landed, never a fact about the request — so it is dropped
    before the subtraction rather than allowed to flap."""
    ub, ua = load_json(before, "usage.json"), load_json(after, "usage.json")
    if ub is None or ua is None:
        return {"unavailable": True}
    for snap in (ub, ua):
        if isinstance(snap, dict):
            snap.pop("as_of", None)
    return num_delta(ub, ua)


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


def selftest() -> int:
    """Prove the missing-BEFORE guards, which is the only way a delta driver can put an ABSOLUTE in a
    golden while still looking like it worked. Each case is red without the guard it names.

    No busbar, no network, no ports: two directories and a handful of files.
    """
    import shutil
    import tempfile
    fails = 0

    def say(ok, what):
        nonlocal fails
        print(f"{'PASS' if ok else 'FAIL'}  {what}")
        if not ok:
            fails += 1

    w = tempfile.mkdtemp(prefix="capture-selftest.")
    try:
        b, a = os.path.join(w, "before"), os.path.join(w, "after")
        os.makedirs(b); os.makedirs(a)

        # usage: an after-snapshot showing a lifetime total of 41 requests, with the before-snapshot
        # ABSENT (the recorder's `|| rm -f` path). Without the guard this reports requests: 41 — the
        # running total, presented as this one request's delta.
        json.dump({"requests": 41, "tokens": 900, "spend_cents": 12}, open(os.path.join(a, "usage.json"), "w"))
        say(usage_delta(b, a) == {"unavailable": True}, "usage: before-snapshot absent -> unavailable, not the absolute")
        json.dump({"requests": 40, "tokens": 882, "spend_cents": 12}, open(os.path.join(b, "usage.json"), "w"))
        say(usage_delta(b, a) == {"requests": 1, "tokens": 18}, "usage: both snapshots present -> the real delta")
        os.remove(os.path.join(a, "usage.json"))
        say(usage_delta(b, a) == {"unavailable": True}, "usage: after-snapshot absent -> unavailable")

        # audit: a 3-entry log, none of it added by this request. Without the guard, an absent
        # before-snapshot makes added_n = 3 and the oldest item's chain_ok is judged against genesis.
        log = {"items": [{"seq": 3, "hash": "cc", "prev_hash": "bb", "principal": "p", "action": "x",
                          "resource": "r", "outcome": "ok"},
                         {"seq": 2, "hash": "bb", "prev_hash": "aa", "principal": "p", "action": "x",
                          "resource": "r", "outcome": "ok"},
                         {"seq": 1, "hash": "aa", "prev_hash": "", "principal": "p", "action": "x",
                          "resource": "r", "outcome": "ok"}]}
        say(audit_diff(None, log) == {"unavailable": True}, "audit: before-snapshot absent -> unavailable, not 'added 3'")
        say(audit_diff(log, None) == {"unavailable": True}, "audit: after-snapshot absent -> unavailable")
        d = audit_diff({"items": log["items"][1:]}, log)
        say(d.get("added") == 1 and len(d.get("items", [])) == 1 and d["items"][0]["chain_ok"] is True,
            "audit: both present -> exactly the one added entry, chained to its real predecessor")

        # metrics: an empty/part-written before scrape (the recorder's `|| true` path) against a
        # healthy after. Without the guard every counter's running total becomes this cell's delta.
        open(os.path.join(b, "metrics.txt"), "w").write("")
        open(os.path.join(a, "metrics.txt"), "w").write("busbar_requests_total{pool=\"p\"} 41\n")
        say(metrics_delta(b, a) == {"unavailable": True}, "metrics: unparseable before scrape -> unavailable, not the absolute")
        open(os.path.join(b, "metrics.txt"), "w").write("busbar_requests_total{pool=\"p\"} 40\n")
        say(metrics_delta(b, a) == {'busbar_requests_total{pool="p"}': 1}, "metrics: both scrapes present -> the real delta")
        # THE SAME FAILURE ON THE OTHER SIDE. The guard above was written for an empty BEFORE scrape
        # only, and the recorder's `oracle_scrape_metrics ... || true` can leave either file with no
        # parseable samples. An empty AFTER against a healthy before subtracted the running total the
        # wrong way round and reported every counter's NEGATED lifetime figure as this cell's delta —
        # an absolute in a golden, which is the one thing effects.* exists to keep out, and a value
        # both binaries reproduce identically when they fail the same way, so the differ sees a match.
        open(os.path.join(a, "metrics.txt"), "w").write("")
        say(metrics_delta(b, a) == {"unavailable": True}, "metrics: unparseable after scrape -> unavailable, not the negated absolute")
        open(os.path.join(a, "metrics.txt"), "w").write("busbar_requests_total{pool=\"p\"} 41\n")
        os.remove(os.path.join(b, "metrics.txt"))
        say(metrics_delta(b, a) == {"unavailable": True}, "metrics: before scrape absent -> unavailable")
    finally:
        shutil.rmtree(w, ignore_errors=True)
    print(f"\ncapture selftest: {'GREEN' if not fails else f'RED ({fails} failing)'}")
    return 1 if fails else 0


def main() -> int:
    if sys.argv[1:2] == ["--selftest"]:
        return selftest()
    hdr_file, status, body_file, before, after = sys.argv[1:6]
    egress = load_egress(sys.argv[6:])
    raw = open(body_file, "rb").read()
    try:
        body = raw.decode("utf-8")
    except UnicodeDecodeError:
        body = "base64:" + base64.b64encode(raw).decode()

    usage = usage_delta(before, after)
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

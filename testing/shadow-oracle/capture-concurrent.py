#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Assemble one captured oracle cell for a `concurrent` cell — N parallel requests, one recording.

Unlike capture.py (one request, one response), a concurrency/queue cell fires several requests at
once and its CONTRACT is the outcome as a SET, not a single HTTP transaction: the sorted multiset of
the N http statuses that came back (a shed 503 count, an admitted-and-served count, ...), plus the
same before/after usage-and-metrics deltas capture.py computes for every other driver, so a shed
request that bills nothing, or a queued request that ends up billed exactly once, shows up in the
golden the same way it would on any other cell.

  capture-concurrent.py '[200,200,503]' <before-dir> <after-dir> > captured.json

`status` is always 0 (there is no single response to report it for) and `headers` is always empty;
the multiset lives at body.statuses. Reuses capture.py's own usage/metrics/audit delta helpers so the
two drivers can never silently drift apart on what a "delta" means.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capture import audit_diff, load_json, metrics_delta, num_delta  # noqa: E402


def main() -> int:
    statuses = json.loads(sys.argv[1])
    before, after = sys.argv[2], sys.argv[3]
    ub, ua = load_json(before, "usage.json"), load_json(after, "usage.json")
    for snap in (ub, ua):
        if isinstance(snap, dict):
            snap.pop("as_of", None)
    usage = num_delta(ub, ua) if ua is not None else {"unavailable": True}
    ab, aa = load_json(before, "audit.json"), load_json(after, "audit.json")
    audit = audit_diff(ab, aa)
    cap = {
        "status": 0,
        "headers": {},
        "body": json.dumps({"statuses": sorted(statuses)}, separators=(",", ":"), sort_keys=True),
        "effects": {"usage": usage, "metrics": metrics_delta(before, after), "audit": audit, "egress": []},
    }
    print(json.dumps(cap, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

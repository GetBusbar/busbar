#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Normalize a captured oracle cell so a byte-diff is MEANINGFUL.

A response is only comparable across runs/binaries if the nondeterminism busbar legitimately emits
is stripped — and ONLY that. Every rule here is NAMED, and the normalizer records which rules fired,
so a change to the normalizer is itself reviewable (a rule that hides a real diff would show up as a
new rule firing where it did not before).

What is normalized (each rule is a named entry in `applied`):
  hdr.date            Date / Server / x-request-id / traceparent / busbar;dur timing header values
  id.wire             busbar-SYNTHESIZED wire ids: req_<hex>, resp_<hex>, msg_<hex>, chatcmpl-<hex>,
                      gemini/bedrock request ids (random bytes, hex) -> "<ID>"
  ts.unix             `created`/`timestamp`/`ts`/`at` integer unix seconds/millis -> 0
  audit.hash          audit-chain hashes / seals (hex >= 32) -> "<HASH>"; sealed timestamps -> 0
  metrics.absolute    metrics are captured as DELTAS by the recorder; absolutes never enter a golden
  metrics.timing      duration _sum / quantile / histogram-bucket samples DROPPED (the _count stays)
  hdr.retry-after     Retry-After value -> "<RETRY>" (presence is the contract; the value is clock/jitter)
  id.wire also maps v4 UUIDs -> "<UUID>"; header values get the same id rules as bodies
  key.id              the minted key id (differs per run) -> "<KEY>"  (recorder passes the real id)

Anything NOT listed is preserved byte-for-byte. Body JSON is re-serialized canonically (sorted keys,
no whitespace) so that key order — which is NOT semantically meaningful and which serializers may
vary — cannot masquerade as a diff. Non-JSON bodies (SSE) are normalized line-wise with the same
id/timestamp rules.

Usage: normalize.py <captured.json> [--key-id <id>] > normalized.json
  captured.json: {"status": int, "headers": {..}, "body": "<utf8 or base64:...>", "effects": {..}}
"""
import base64
import json
import re
import sys

HDR_STRIP = {"date", "server", "x-request-id", "traceparent", "tracestate", "x-trace-id"}
HDR_TIMING = {"server-timing"}  # busbar;dur=... carries a per-request latency; keep the KEY, blank the value
# Retry-After is a contract (present or absent, PB-4) but its VALUE is wall-clock / jitter dependent
# (seconds to the next window; breaker cooldown ±10 %). Keep the key, blank the value.
HDR_RETRY = {"retry-after"}

ID_RULES = [
    (re.compile(r"\b(req|resp|msg|run|call|task|sess|rtc)_[0-9A-Za-z]{8,}\b"), r"\1_<ID>"),  # hex OR base62 (1.5.5 synthesizes req_01<24 base62>)
    (re.compile(r"\bchatcmpl-[0-9A-Za-z]{8,}\b"), "chatcmpl-<ID>"),
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "<HASH>"),  # sha/hex seals, request ids as raw hex
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),  # v4 ids busbar synthesizes (cohere `id`, x-amzn-requestid)
]
TS_KEYS = {"created", "timestamp", "ts", "at", "sealed_at", "opened_at", "closed_at", "time", "as_of", "expires_at", "created_at", "updated_at", "last_used_at"}


def norm_headers(h: dict, applied: set) -> dict:
    out = {}
    for k, v in h.items():
        lk = k.lower()
        if lk in HDR_STRIP:
            applied.add("hdr.date"); continue
        if lk in HDR_TIMING:
            applied.add("hdr.date"); out[lk] = "<TIMING>"; continue
        if lk in HDR_RETRY:
            applied.add("hdr.retry-after"); out[lk] = "<RETRY>"; continue
        # header VALUES carry synthesized ids too (request-id: req_01<base62>): same id rules as bodies
        out[lk] = norm_scalar_str(v, applied)
    return dict(sorted(out.items()))


def norm_scalar_str(s: str, applied: set) -> str:
    for rx, rep in ID_RULES:
        if rx.search(s):
            applied.add("id.wire" if "<ID>" in rep else "audit.hash")
            s = rx.sub(rep, s)
    return s


METRIC_TIMING = re.compile(r"(_seconds_sum(\{|$))|(_seconds\{[^}]*quantile=)|(_bucket\{)|(_seconds$)")


def norm_json(v, applied: set, key_id: str | None, parent_key: str = ""):
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if k in TS_KEYS and isinstance(x, (int, float)):
                applied.add("ts.unix"); out[k] = 0; continue
            if parent_key == "metrics" and METRIC_TIMING.search(k):
                # a latency SUM / quantile sample is a measurement, never a contract, and a summary
                # emits its quantiles only once its window has samples — DROP the key; the COUNT stays
                applied.add("metrics.timing"); continue
            out[k] = norm_json(x, applied, key_id, k)
        return dict(sorted(out.items()))
    if isinstance(v, list):
        return [norm_json(x, applied, key_id, parent_key) for x in v]
    if isinstance(v, str):
        if key_id and v == key_id:
            applied.add("key.id"); return "<KEY>"
        return norm_scalar_str(v, applied)
    return v


def norm_body(body: str, applied: set, key_id: str | None):
    raw = body
    if body.startswith("base64:"):
        raw = base64.b64decode(body[7:]).decode("utf-8", "replace")
    stripped = raw.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return {"json": norm_json(json.loads(stripped), applied, key_id)}
        except Exception:
            pass
    # SSE / text: normalize line-wise; for `data: {json}` lines canonicalize the JSON payload too.
    lines = []
    for ln in raw.split("\n"):
        if ln.startswith("data: ") and ln[6:].lstrip().startswith("{"):
            try:
                j = norm_json(json.loads(ln[6:]), applied, key_id)
                lines.append("data: " + json.dumps(j, separators=(",", ":"), sort_keys=True)); continue
            except Exception:
                pass
        lines.append(norm_scalar_str(ln, applied) if key_id is None else norm_scalar_str(ln.replace(key_id, "<KEY>"), applied))
    return {"text": "\n".join(lines)}


def normalize(cap: dict, key_id: str | None) -> dict:
    applied: set = set()
    out = {
        "status": cap.get("status"),
        "headers": norm_headers(cap.get("headers", {}), applied),
        "body": norm_body(cap.get("body", ""), applied, key_id),
        "effects": norm_json(cap.get("effects", {}), applied, key_id),
    }
    out["applied"] = sorted(applied)
    return out


def main() -> int:
    args = sys.argv[1:]
    key_id = None
    if "--key-id" in args:
        i = args.index("--key-id"); key_id = args[i + 1]; del args[i:i + 2]
    cap = json.load(open(args[0])) if args else json.load(sys.stdin)
    print(json.dumps(normalize(cap, key_id), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

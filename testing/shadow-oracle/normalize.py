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
  hdr.etag            ETag values -> "<ETAG>" (content-derived; the content carries per-run ids)
  boot.pool-order     the boot banner's `pool /x = [...]` lines are emitted in map order, which is
                      nondeterministic on the SAME binary (measured on 1.5.5) -> sorted in place
  boot.error-order    `--validate` error bullets (`  - …`) come out in map order, nondeterministic on
                      the SAME binary (measured on 1.5.5: 3/6 runs each way) -> each run sorted in place
  keys.order          admin key listings (`items[]` whose ids are `vk_…`) are in creation-id order,
                      which is per-run -> sorted by name
  id.wire also maps minted bearer secrets `bbk_…` -> "bbk_<TOKEN>" (so no secret enters a golden)
  metrics.shape       a /metrics exposition body keeps its SHAPE (names, types, labels, counts):
                      latency samples (quantiles, _sum, _bucket, raw _seconds) are DROPPED, blank
                      separators dropped, and lines sorted (registry order is per-binary, not a contract)
  hdr.length          Content-Length -> "<LEN>" whenever a body rule fired (the length is the
                      shadow of a value that was just normalized, e.g. a latency or an id)
  boot.pair-order     "(A vs B)" conflict pairs in validation messages come out in map order,
                      nondeterministic on the SAME binary (measured on 1.5.5: 3/6 each way) -> sorted
  ver.string          `"version": "X.Y.Z"` of the binary -> "<VERSION>" (the diff of interest is
                      everything else; the version itself is expected to differ)

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
HDR_ETAG = {"etag"}

ID_RULES = [
    (re.compile(r"\b(req|resp|msg|run|call|task|sess|rtc)_[0-9A-Za-z]{8,}\b"), r"\1_<ID>"),  # hex OR base62 (1.5.5 synthesizes req_01<24 base62>)
    (re.compile(r"\bchatcmpl-[0-9A-Za-z]{8,}\b"), "chatcmpl-<ID>"),
    (re.compile(r"\bvk_[0-9a-f]{32}\b"), "vk_<KEY>"),  # every minted key id (audit resources, usage rows, labels)
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA<KEY>"),  # minted AWS access key ids
    (re.compile(r"\bbbk_[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{20,}\b"), "bbk_<TOKEN>"),  # minted bearer secrets (never stored)
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "<HASH>"),  # sha/hex seals, request ids as raw hex
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),  # v4 ids busbar synthesizes (cohere `id`, x-amzn-requestid)
    (re.compile(r"-(aarch64|x86_64)-(apple-darwin|unknown-linux-gnu|pc-windows-msvc)"), "-<TRIPLE>"),  # plugin tarball names carry the host triple
]
TS_KEYS = {"created", "timestamp", "ts", "at", "sealed_at", "opened_at", "closed_at", "time", "as_of", "expires_at", "created_at", "updated_at", "last_used_at", "started_at"}
# JSON keys whose value is a measured latency, never a contract (admin pool views)
TIMING_KEYS = {"latency_ms"}
VERSION_RX = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$")
POOL_LINE = re.compile(r"^\s+pool /\S+ = ")
ERROR_BULLET = re.compile(r"^  - ")
PAIR = re.compile(r"\((\d+) vs (\d+)")
EXPO_TIMING = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*(_seconds_sum|_seconds|_bucket)(\{|\s)|quantile=")


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
        if lk in HDR_ETAG:
            applied.add("hdr.etag"); out[lk] = "<ETAG>"; continue
        # header VALUES carry synthesized ids too (request-id: req_01<base62>): same id rules as bodies
        out[lk] = norm_scalar_str(v, applied)
    return dict(sorted(out.items()))


def norm_scalar_str(s: str, applied: set) -> str:
    for rx, rep in ID_RULES:
        if rx.search(s):
            applied.add("id.wire" if "<ID>" in rep else "audit.hash")
            s = rx.sub(rep, s)
    return s


METRIC_TIMING = re.compile(r"(_seconds_sum(\{|$))|(_seconds\{[^}]*quantile=)|(_bucket\{)|(_seconds$)|(recovery_hint_ms)|(cooldown)")
# JSON keys whose VALUE is a per-request synthesized id with no recognisable prefix (gemini responseId).
ID_KEYS = {"responseId", "request_id", "requestId"}


def norm_json(v, applied: set, key_id: str | None, parent_key: str = ""):
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if k in TS_KEYS and isinstance(x, (int, float)):
                applied.add("ts.unix"); out[k] = 0; continue
            if k in TIMING_KEYS and isinstance(x, (int, float)):
                applied.add("metrics.timing"); continue
            if k == "version" and isinstance(x, str) and VERSION_RX.match(x):
                applied.add("ver.string"); out[k] = "<VERSION>"; continue
            if k in ("items", "by_key") and isinstance(x, list) and x and all(isinstance(i, dict) and str(i.get("id", "")).startswith("vk_") and "name" in i for i in x):
                applied.add("keys.order"); x = sorted(x, key=lambda i: str(i["name"]))
            if parent_key == "metrics" and METRIC_TIMING.search(k):
                # a latency SUM / quantile sample is a measurement, never a contract, and a summary
                # emits its quantiles only once its window has samples — DROP the key; the COUNT stays
                applied.add("metrics.timing"); continue
            if parent_key == "metrics":
                # metric LABELS carry the minted key id (bucket="vk_…") and other per-run ids
                nk = k
                if key_id and key_id in nk:
                    applied.add("key.id"); nk = nk.replace(key_id, "<KEY>")
                nk = norm_scalar_str(nk, applied)
                out[nk] = norm_json(x, applied, key_id, k); continue
            if k in ID_KEYS and isinstance(x, str):
                applied.add("id.wire"); out[k] = "<ID>"; continue
            out[k] = norm_json(x, applied, key_id, k)
        return dict(sorted(out.items()))
    if isinstance(v, list):
        return [norm_json(x, applied, key_id, parent_key) for x in v]
    if isinstance(v, str):
        if key_id and v == key_id:
            applied.add("key.id"); return "<KEY>"
        return norm_scalar_str(v, applied)
    return v


def sort_runs(lines: list, rx, rule: str, applied: set) -> list:
    """Sort each run of consecutive lines matching rx (their order is map order, i.e. per-run)."""
    out, run = [], []
    for ln in lines + [None]:
        if ln is not None and rx.match(ln):
            run.append(ln); continue
        if run:
            if len(run) > 1:
                applied.add(rule)
            out.extend(sorted(run)); run = []
        if ln is not None:
            out.append(ln)
    return out


def sort_pool_lines(lines: list, applied: set) -> list:
    return sort_runs(sort_runs(lines, POOL_LINE, "boot.pool-order", applied), ERROR_BULLET, "boot.error-order", applied)


def norm_text(text: str, applied: set) -> str:
    if PAIR.search(text):
        def _sort_pair(m):
            a, b = sorted((int(m.group(1)), int(m.group(2))))
            return f"({a} vs {b}"
        new = PAIR.sub(_sort_pair, text)
        if new != text:
            applied.add("boot.pair-order"); text = new
    lines = text.split("\n")
    if lines and lines[0].startswith(("# HELP ", "# TYPE ")):
        applied.add("metrics.shape")
        keep = [ln for ln in lines if ln and not EXPO_TIMING.search(ln)]
        return "\n".join(sorted(keep))
    if len(lines) > 1 and lines[0].startswith("HTTP/"):
        # a raw response dump (HEAD cells): header lines get the header rules
        lines = ["" if ln.split(":", 1)[0].lower().strip() in HDR_STRIP and applied.add("hdr.date") is None else ln for ln in lines]
    return "\n".join(sort_pool_lines(lines, applied))


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
    return {"text": norm_text("\n".join(lines), applied)}


def normalize(cap: dict, key_id: str | None) -> dict:
    applied: set = set()
    body_rules: set = set()
    body = norm_body(cap.get("body", ""), body_rules, key_id)
    applied |= body_rules
    headers = norm_headers(cap.get("headers", {}), applied)
    if body_rules and "content-length" in headers:
        applied.add("hdr.length"); headers["content-length"] = "<LEN>"
    out = {
        "status": cap.get("status"),
        "headers": headers,
        "body": body,
        "effects": norm_json(cap.get("effects", {}), applied, key_id),
    }
    if isinstance(out["effects"].get("stderr"), str):
        out["effects"]["stderr"] = norm_text(out["effects"]["stderr"], applied)
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

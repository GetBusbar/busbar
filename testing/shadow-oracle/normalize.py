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
  ts.usage-window     a `/usage` body's `window.start` / `window.end` (the UTC day boundary the
                      window was computed against, not a contract of busbar's) -> 0; scoped to the
                      `window` object only, so no other `start`/`end` key in any other body is touched
  audit.hash          audit-chain hashes / seals (hex >= 32) -> "<HASH>"; sealed timestamps -> 0
  metrics.absolute    metrics are captured as DELTAS by the recorder; absolutes never enter a golden
  metrics.timing      duration _sum / quantile / histogram-bucket samples DROPPED (the _count stays)
  metrics.cooldown    a cooldown/breaker metric sample KEEPS its key (presence/absence is the
                      state-transition contract a cooldown-family cell proves) but its value — a
                      jittered base_cooldown_secs — is normalized to "<JITTER>"
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
  boot.exhaustion-order the boot banner's "pool exhaustion policy pool=<name> on_exhausted=<mode>"
                      lines (one per pool with an `on_exhausted:`) come out in map order, which is
                      nondeterministic on the SAME binary (measured on 1.5.5: two runs on the same
                      oracle config gave different orderings) -> each run sorted in place
  info.uptime         `uptime_seconds` (GET /api/v1/admin/info) -> 0: how long the process has been
                      up is a measurement of the recording, not of the binary — it read 0 or 1
                      depending on whether the cell was reached inside the first second of the boot.
                      Only the numeric VALUE; an openapi schema's `uptime_seconds` property is a
                      dict and stays exactly as documented.
  ver.string          `"version": "X.Y.Z"` of the binary -> "<VERSION>" (the diff of interest is
                      everything else; the version itself is expected to differ)
  body.keep-lines     a cell whose contract is the ABSENCE of something (`body_lines` on the cell)
                      keeps only the body lines matching that regex; an empty result is the
                      contract, and any surviving line is a diff
  keep.header-min     a cell's `keep.headers_min` pins a floor: the value becomes >=N when it clears N
  keep.header         a cell's `keep.headers` names a header that would otherwise be stripped/blanked
                      (Date, Retry-After, x-request-id, ...): its value is kept (still id-normalized)
                      instead, because for THIS cell the header's presence/value IS the contract
  keep.json_key       a cell's `keep.json_keys` names a dotted JSON path (list indices omitted, so
                      "items.digest" matches every element of an `items` array) whose value is kept
                      completely raw -- no id/ts/version scrubbing at or under that key -- because
                      for THIS cell that literal value IS the contract
  keep.text_regex     a cell's `keep.text_regex` names a line pattern in a /metrics exposition that
                      would otherwise be dropped by metrics.shape (a quantile/duration sample): the
                      line is kept with its trailing numeric sample value blanked to "<DUR>" (labels,
                      e.g. quantile="0.5", stay byte-exact) because for THIS cell the label SET is the
                      contract, not the timing value
  egress.cred         in effects.egress[].headers, the VALUE of an Authorization / x-api-key /
                      x-goog-api-key header, or of any header whose value is an AWS SigV4
                      "AWS4-HMAC-SHA256 Credential=..." string -> "<CRED>" (the credential differs
                      per run/environment; whether it rode upstream at all, and everything else
                      about the egress request, is deliberately left byte-exact so this cell can
                      catch a dropped tool list, a mangled system prompt, an injected max_tokens, or
                      a client header that leaked upstream when it should not have)
  text.port           127.0.0.1:<port> in any text body or stderr line: listen, admin and mock ports are the harness's
  egress.host         effects.egress[].headers.host: the mock's port becomes <PORT> (chosen per recording)
  eventstream.frames  a body whose Content-Type is `application/vnd.amazon.eventstream` (Bedrock's
                      binary framing for a streamed Converse) is DECODED rather than read as text.
                      Before this rule the bytes were run through `.decode("utf-8", "replace")`,
                      which is lossy in both directions: every non-UTF-8 framing byte — the two
                      big-endian lengths, the prelude CRC, the message CRC, the header block's
                      type/length bytes — collapsed to U+FFFD, so two DIFFERENT frame streams could
                      normalize to the same golden text, and the JSON payload inside each frame was
                      never seen by the JSON path at all (its `metrics.latencyMs`, a per-run
                      measurement, sat in the golden as a literal). The oracle was blind inside the
                      frames on exactly the five `llm|bedrock|*|ok_stream` cells.
                      The rule decodes the whole message stream: for each frame the 12-byte prelude
                      (total_length, headers_length, prelude CRC32), the header block (all nine AWS
                      header value types), the payload, and the trailing message CRC32 — and it
                      VERIFIES both CRCs, so a corrupted stream cannot decode into a clean-looking
                      list. Each payload is then normalized through the ordinary JSON path, so every
                      existing rule applies inside a frame exactly as it does to an unframed body
                      (`metrics.timing` on `latencyMs`, `ts.unix`, `id.wire`, ...).
                      The body is represented as the ordered list of `[event-type, payload]` pairs
                      with the framing DROPPED: lengths and CRCs are a re-encoding of the payload
                      and its headers, not a busbar contract, and keeping them would re-introduce
                      the per-run noise the payload rules just removed. Frame ORDER is kept, because
                      the order of a stream's events is a contract. The event-type is the frame's
                      `:event-type` header; a frame that carries none (an exception frame) is keyed
                      by its `:exception-type`/`:error-code`, else its `:message-type`, so an error
                      frame can never be mistaken for a nameless event.
                      A body that claims the content-type but does NOT decode (bad CRC, truncated
                      frame, unknown header type) does not silently fall back and disappear: the
                      rule records `eventstream.undecodable` instead and the old text path runs, and
                      because the applied-rule SET is itself a diff class (`norm.rules`), one side
                      decoding where the other does not is red on its own.
  egress.body         effects.egress[].body is parsed as JSON and re-serialized canonically (same
                      technique as a response body) so key order/whitespace cannot masquerade as a
                      diff; a non-JSON body is left untouched. No id/timestamp scrubbing rule from
                      the list above is applied to an egress body or to any non-credential egress
                      header — that is the point: this is the one place in the normalizer that must
                      stay maximally strict

Usage: normalize.py <captured.json> [--key-id <id>] [--keep-body-lines <regex>] [--keep <json>] > normalized.json
  --keep '<json>': per-cell opt-in that OVERRIDES the default stripping named above for named parts
    of THIS cell only: {"headers": ["retry-after", ...], "json_keys": ["info.version", ...],
    "text_regex": "..."}. Absent (the default): behavior is unchanged from before this flag existed.

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
import uuid as _uuid
import zlib

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
# The `/usage` body's `window` object: {start, end} are UTC-day-boundary unix seconds computed
# against "now", not a busbar contract -- scoped to the `window` key specifically (not every
# `start`/`end` anywhere) so a real `start`/`end` elsewhere (e.g. a pool/audit range) still diffs.
USAGE_WINDOW_KEYS = {"start", "end"}
# JSON keys whose value is a measured latency, never a contract (admin pool views; `latencyMs` is
# AWS Bedrock's own spelling on Converse's `metrics` member — S-3's "latencyMs is timing and
# normalized" decision, extended to every cell that carries it, not only the same-dialect one)
TIMING_KEYS = {"latency_ms", "latencyMs"}
VERSION_RX = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$")
POOL_LINE = re.compile(r"^\s+pool /\S+ = ")
ERROR_BULLET = re.compile(r"^  - ")
# The boot-time "pool exhaustion policy pool=<name> on_exhausted=<mode>" INFO line, one per pool that
# sets `on_exhausted:` — emitted from a walk over `cfg.pools` (a `HashMap`), so its relative order is
# per-process, not a contract (measured directly: two 1.5.5 runs on the same oracle config, same
# binary, produced oracle-lb/oracle-q/oracle-fb and oracle-fb/oracle-lb/oracle-q respectively). Same
# treatment as `POOL_LINE`/`ERROR_BULLET` above.
EXHAUSTION_LINE = re.compile(r".*\bpool exhaustion policy pool=")
PAIR = re.compile(r"\((\d+) vs (\d+)")
EXPO_TIMING = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*(_seconds_sum|_seconds|_bucket)(\{|\s)|quantile=")


def norm_headers(h: dict, applied: set, keep_headers: set | None = None, headers_min: dict | None = None) -> dict:
    keep_headers = keep_headers or set()
    headers_min = headers_min or {}
    out = {}
    for k, v in h.items():
        lk = k.lower()
        if lk in headers_min:
            # this cell pins a FLOOR, not the value: a jittered figure (Retry-After off a jittered
            # cooldown) is the harness's draw; whether it clears the floor is busbar's contract
            applied.add("keep.header-min")
            try:
                out[lk] = f">={headers_min[lk]}" if int(str(v).strip()) >= int(headers_min[lk]) else str(v)
            except ValueError:
                out[lk] = str(v)
            continue
        if lk in keep_headers:
            # this cell opted in: the value IS the contract -- keep it (still id-normalized, so a
            # wire id inside it does not become a spurious per-run diff), never stripped/blanked.
            applied.add("keep.header"); out[lk] = norm_scalar_str(v, applied); continue
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


METRIC_TIMING = re.compile(r"(_seconds_sum(\{|$))|(_seconds\{[^}]*quantile=)|(_bucket\{)|(_seconds$)|(recovery_hint_ms)")
# A cooldown/breaker-jitter sample is a real state signal (the metric line's PRESENCE is a contract —
# it is how a cooldown-family cell proves the breaker actually tripped/settled) but its exact seconds
# are base_cooldown_secs jittered +/-10%, so only the VALUE is normalized away, never the key.
METRIC_COOLDOWN = re.compile(r"cooldown")
# JSON keys whose VALUE is a per-request synthesized id with no recognisable prefix (gemini responseId).
ID_KEYS = {"responseId", "request_id", "requestId"}


def norm_json(v, applied: set, key_id: str | None, parent_key: str = "", path: str = "", keep_json_keys: set | None = None):
    keep_json_keys = keep_json_keys or set()
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            child_path = f"{path}.{k}" if path else k
            if child_path in keep_json_keys:
                # this cell opted in on this exact dotted path (list indices never appear in it, so
                # "items.digest" reaches every element of an `items` array): keep the value RAW, with
                # no further scrubbing at or under it -- for THIS cell that literal value IS the
                # contract (e.g. openapi info.version, a plugin digest).
                applied.add("keep.json_key"); out[k] = x; continue
            if parent_key == "window" and k in USAGE_WINDOW_KEYS and isinstance(x, (int, float)):
                applied.add("ts.usage-window"); out[k] = 0; continue
            if k in TS_KEYS and isinstance(x, (int, float)):
                applied.add("ts.unix"); out[k] = 0; continue
            if k == "uptime_seconds" and isinstance(x, (int, float)) and not isinstance(x, bool):
                # HOW LONG THE PROCESS HAS BEEN UP IS A MEASUREMENT, NOT A CONTRACT. `GET
                # /api/v1/admin/info` reports it, and nothing normalized it: a recording that reached
                # that cell inside the first second of the boot recorded 0 and one that took a second
                # longer recorded 1, so the cell diverged on how busy the machine was. Same treatment
                # (and same 0) the other clock-derived values get above, so the value the golden
                # already holds does not move — only its ability to say something else does.
                # The VALUE is what is rewritten, so the openapi SCHEMA cells that carry
                # `uptime_seconds` as a property description (a dict, not a number) are untouched:
                # there the key's documentation IS the contract.
                applied.add("info.uptime"); out[k] = 0; continue
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
            if parent_key == "metrics" and METRIC_COOLDOWN.search(k):
                # keep the key (a cooldown metric appearing/disappearing IS the state-transition
                # contract for the cooldown family) but blank the jittered value
                nk = k
                if key_id and key_id in nk:
                    applied.add("key.id"); nk = nk.replace(key_id, "<KEY>")
                nk = norm_scalar_str(nk, applied)
                applied.add("metrics.cooldown")
                out[nk] = "<JITTER>" if isinstance(x, (int, float)) else norm_json(x, applied, key_id, k, child_path, keep_json_keys)
                continue
            if parent_key == "metrics":
                # metric LABELS carry the minted key id (bucket="vk_…") and other per-run ids
                nk = k
                if key_id and key_id in nk:
                    applied.add("key.id"); nk = nk.replace(key_id, "<KEY>")
                nk = norm_scalar_str(nk, applied)
                out[nk] = norm_json(x, applied, key_id, k, child_path, keep_json_keys); continue
            if k in ID_KEYS and isinstance(x, str):
                applied.add("id.wire"); out[k] = "<ID>"; continue
            out[k] = norm_json(x, applied, key_id, k, child_path, keep_json_keys)
        return dict(sorted(out.items()))
    if isinstance(v, list):
        return [norm_json(x, applied, key_id, parent_key, path, keep_json_keys) for x in v]
    if isinstance(v, str):
        if key_id and v == key_id:
            applied.add("key.id"); return "<KEY>"
        return norm_scalar_str(v, applied)
    return v


CRED_HEADERS = {"authorization", "x-api-key", "x-goog-api-key"}
SIGV4_RX = re.compile(r"^AWS4-HMAC-SHA256\b")


def norm_egress_entry(entry, applied: set):
    """One recorded upstream request ({path, method, headers, body}). Deliberately NOT run through
    norm_json: only a credential value is scrubbed and only the body is re-serialized canonically —
    everything else (path, method, every other header value) stays byte-exact, because this is the
    seam that must catch a dropped/mangled egress request, not hide it."""
    if not isinstance(entry, dict):
        return entry
    out = dict(entry)
    headers = entry.get("headers")
    if isinstance(headers, dict):
        new_headers = {}
        for k, v in headers.items():
            lk = k.lower()
            if lk in CRED_HEADERS or (isinstance(v, str) and SIGV4_RX.match(v)):
                applied.add("egress.cred"); new_headers[lk] = "<CRED>"
            elif lk == "host" and isinstance(v, str) and re.search(r":\d+$", v):
                # the mock upstream's port is the harness's choice per recording, not busbar's
                applied.add("egress.host"); new_headers[lk] = re.sub(r":\d+$", ":<PORT>", v)
            else:
                new_headers[lk] = v
        out["headers"] = new_headers
    body = entry.get("body")
    if isinstance(body, str):
        stripped = body.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                out["body"] = json.loads(stripped)
                applied.add("egress.body")
            except Exception:
                pass
    return out


def norm_egress(egress, applied: set):
    if not isinstance(egress, list):
        return egress
    return [norm_egress_entry(e, applied) for e in egress]


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
    lines = sort_runs(lines, POOL_LINE, "boot.pool-order", applied)
    lines = sort_runs(lines, ERROR_BULLET, "boot.error-order", applied)
    lines = sort_runs(lines, EXHAUSTION_LINE, "boot.exhaustion-order", applied)
    return lines


VERSION_KV = re.compile(r'version="(\d+\.\d+\.\d+)(?:-[0-9A-Za-z.]+)?"')
LOOPBACK_PORT = re.compile(r"127\.0\.0\.1:\d{2,5}\b")


def norm_text(text: str, applied: set, keep_regex=None) -> str:
    # the binary's own version in key=value form (boot line) and every loopback port the harness
    # chose per recording (listen, admin, mock) are the harness's, not busbar's
    if VERSION_KV.search(text):
        applied.add("ver.string"); text = VERSION_KV.sub('version="<VERSION>"', text)
    if LOOPBACK_PORT.search(text):
        applied.add("text.port"); text = LOOPBACK_PORT.sub("127.0.0.1:<PORT>", text)
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
        keep = []
        for ln in lines:
            if not ln:
                continue
            if keep_regex and keep_regex.search(ln):
                # this cell opted in on this line pattern (e.g. a quantile sample that metrics.timing
                # would otherwise drop entirely): keep the line -- the label SET (quantile="0.5", ...)
                # is the contract -- but blank the trailing numeric sample value, which is not.
                head, sep, _val = ln.rpartition(" ")
                keep.append(head + " <DUR>" if sep else ln)
                applied.add("keep.text_regex")
                continue
            if not EXPO_TIMING.search(ln):
                keep.append(ln)
        return "\n".join(sorted(keep))
    if len(lines) > 1 and lines[0].startswith("HTTP/"):
        # a raw response dump (HEAD cells): header lines get the header rules
        lines = ["" if ln.split(":", 1)[0].lower().strip() in HDR_STRIP and applied.add("hdr.date") is None else ln for ln in lines]
    return "\n".join(sort_pool_lines(lines, applied))


EVENTSTREAM_CT = "application/vnd.amazon.eventstream"


def es_headers(buf: bytes) -> dict:
    """Decode one frame's header block. Raises ValueError on anything it does not fully understand —
    a header type this does not know is a header whose LENGTH this cannot compute, so every byte
    after it would be misread; refusing is the only honest answer."""
    out, i, n = {}, 0, len(buf)
    while i < n:
        nlen = buf[i]; i += 1
        if i + nlen > n:
            raise ValueError("header name runs past the block")
        name = buf[i:i + nlen].decode("utf-8"); i += nlen
        if i >= n:
            raise ValueError("header value type missing")
        htype = buf[i]; i += 1
        if htype == 0:
            val = True
        elif htype == 1:
            val = False
        elif htype in (2, 3, 4, 5, 8):
            width = {2: 1, 3: 2, 4: 4, 5: 8, 8: 8}[htype]
            if i + width > n:
                raise ValueError("header integer runs past the block")
            val = int.from_bytes(buf[i:i + width], "big", signed=True); i += width
        elif htype in (6, 7):
            if i + 2 > n:
                raise ValueError("header value length runs past the block")
            vlen = int.from_bytes(buf[i:i + 2], "big"); i += 2
            if i + vlen > n:
                raise ValueError("header value runs past the block")
            blob = buf[i:i + vlen]; i += vlen
            # 7 = STRING (every `:`-prefixed frame header Bedrock sends), 6 = BYTE_ARRAY (opaque:
            # rendered base64 so a non-UTF-8 value can never be lossily flattened here either)
            val = blob.decode("utf-8") if htype == 7 else "base64:" + base64.b64encode(blob).decode()
        elif htype == 9:
            if i + 16 > n:
                raise ValueError("header uuid runs past the block")
            val = str(_uuid.UUID(bytes=bytes(buf[i:i + 16]))); i += 16
        else:
            raise ValueError(f"unknown header value type {htype}")
        out[name] = val
    return out


def decode_eventstream(data: bytes) -> list:
    """Split an `application/vnd.amazon.eventstream` body into [(headers, payload_bytes), ...],
    VERIFYING the prelude CRC32 and the message CRC32 of every frame. Raises ValueError if the
    stream is not a well-formed, intact sequence of frames covering exactly the whole body."""
    frames, i, n = [], 0, len(data)
    while i < n:
        if n - i < 16:
            raise ValueError("truncated frame prelude")
        total = int.from_bytes(data[i:i + 4], "big")
        hlen = int.from_bytes(data[i + 4:i + 8], "big")
        pre_crc = int.from_bytes(data[i + 8:i + 12], "big")
        if zlib.crc32(data[i:i + 8]) & 0xFFFFFFFF != pre_crc:
            raise ValueError("prelude CRC32 mismatch")
        if total < 16 + hlen or i + total > n:
            raise ValueError("frame length runs past the body")
        msg_crc = int.from_bytes(data[i + total - 4:i + total], "big")
        if zlib.crc32(data[i:i + total - 4]) & 0xFFFFFFFF != msg_crc:
            raise ValueError("message CRC32 mismatch")
        frames.append((es_headers(data[i + 12:i + 12 + hlen]), data[i + 12 + hlen:i + total - 4]))
        i += total
    if not frames:
        raise ValueError("no frames")
    return frames


def es_event_type(hdrs: dict) -> str:
    """The name this frame is keyed by. `:event-type` for an ordinary event; for an exception frame
    (which carries no `:event-type`) the `:exception-type`/`:error-code`, else the `:message-type` —
    so an error frame is never recorded as a nameless event."""
    for k in (":event-type", ":exception-type", ":error-code", ":message-type"):
        v = hdrs.get(k)
        if isinstance(v, str) and v:
            return v
    return "<no-event-type>"


def norm_frame_payload(payload: bytes, applied: set, key_id: str | None, keep_json_keys: set | None):
    """One frame's payload through the ORDINARY body rules: JSON is parsed and run through norm_json
    (so metrics.timing fires on `latencyMs`, ts.unix on `created`, id.wire on a synthesized id — the
    same rules an unframed body gets), anything else through the scalar id rules."""
    text = payload.decode("utf-8", "replace")
    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return norm_json(json.loads(stripped), applied, key_id, keep_json_keys=keep_json_keys)
        except Exception:
            pass
    return norm_scalar_str(text if key_id is None else text.replace(key_id, "<KEY>"), applied)


def norm_body(body: str, applied: set, key_id: str | None, keep_json_keys: set | None = None, keep_regex=None, content_type: str | None = None):
    raw_bytes = base64.b64decode(body[7:]) if body.startswith("base64:") else body.encode("utf-8", "replace")
    raw = raw_bytes.decode("utf-8", "replace")
    if content_type and EVENTSTREAM_CT in content_type.lower():
        # Bedrock's binary framing. Decode it rather than read it as text: see `eventstream.frames`.
        try:
            frames = decode_eventstream(raw_bytes)
        except ValueError:
            # NOT a silent fallback: the rule name below is part of the `applied` set, which is
            # itself a diff class (norm.rules), so a body that stopped decoding is red on its own.
            applied.add("eventstream.undecodable")
        else:
            applied.add("eventstream.frames")
            return {"eventstream": [[es_event_type(h), norm_frame_payload(p, applied, key_id, keep_json_keys)] for h, p in frames]}
    stripped = raw.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return {"json": norm_json(json.loads(stripped), applied, key_id, keep_json_keys=keep_json_keys)}
        except Exception:
            pass
    # SSE / text: normalize line-wise; for `data: {json}` lines canonicalize the JSON payload too.
    lines = []
    for ln in raw.split("\n"):
        if ln.startswith("data: ") and ln[6:].lstrip().startswith("{"):
            try:
                j = norm_json(json.loads(ln[6:]), applied, key_id, keep_json_keys=keep_json_keys)
                lines.append("data: " + json.dumps(j, separators=(",", ":"), sort_keys=True)); continue
            except Exception:
                pass
        lines.append(norm_scalar_str(ln, applied) if key_id is None else norm_scalar_str(ln.replace(key_id, "<KEY>"), applied))
    return {"text": norm_text("\n".join(lines), applied, keep_regex)}


def normalize(cap: dict, key_id: str | None, keep_lines: str | None = None, keep: dict | None = None) -> dict:
    keep = keep or {}
    keep_headers = {h.lower() for h in keep.get("headers", [])}
    headers_min = {h.lower(): n for h, n in (keep.get("headers_min") or {}).items()}
    keep_json_keys = set(keep.get("json_keys", []))
    keep_regex = re.compile(keep["text_regex"]) if keep.get("text_regex") else None
    applied: set = set()
    body_rules: set = set()
    # The Content-Type decides whether the body is TEXT at all: an eventstream body is binary framing
    # and must be decoded, not read through `.decode(..., "replace")` (see `eventstream.frames`).
    content_type = next((v for k, v in cap.get("headers", {}).items() if k.lower() == "content-type"), None)
    body = norm_body(cap.get("body", ""), body_rules, key_id, keep_json_keys, keep_regex, content_type)
    if keep_lines is not None:
        # The cell's contract is what is NOT there: keep only the matching lines (a JSON body is
        # rendered canonically first so the filter sees one line per top-level entry).
        rx = re.compile(keep_lines)
        text = body["text"] if "text" in body else json.dumps(body.get("json", body.get("eventstream")), separators=(",", ":"), sort_keys=True, indent=0)
        body = {"text": "\n".join(ln for ln in text.split("\n") if rx.search(ln))}
        body_rules.add("body.keep-lines")
    applied |= body_rules
    headers = norm_headers(cap.get("headers", {}), applied, keep_headers, headers_min)
    if body_rules and "content-length" in headers:
        applied.add("hdr.length"); headers["content-length"] = "<LEN>"
    # `egress` is pulled out before the generic pass: norm_json's id/ts scrubbing rules must never
    # touch it (see the egress.* rule docs above) — it gets only its own, much stricter, treatment.
    effects_in = dict(cap.get("effects", {}))
    egress_in = effects_in.pop("egress", None)
    effects = norm_json(effects_in, applied, key_id)
    if egress_in is not None:
        effects["egress"] = norm_egress(egress_in, applied)
    out = {
        "status": cap.get("status"),
        "headers": headers,
        "body": body,
        "effects": effects,
    }
    if isinstance(out["effects"].get("stderr"), str):
        out["effects"]["stderr"] = norm_text(out["effects"]["stderr"], applied)
    out["applied"] = sorted(applied)
    return out


def main() -> int:
    args = sys.argv[1:]
    key_id = None
    keep_lines = None
    keep = None
    if "--key-id" in args:
        i = args.index("--key-id"); key_id = args[i + 1]; del args[i:i + 2]
    if "--keep-body-lines" in args:
        i = args.index("--keep-body-lines"); keep_lines = args[i + 1]; del args[i:i + 2]
    if "--keep" in args:
        i = args.index("--keep"); keep = json.loads(args[i + 1]); del args[i:i + 2]
    cap = json.load(open(args[0])) if args else json.load(sys.stdin)
    print(json.dumps(normalize(cap, key_id, keep_lines, keep), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

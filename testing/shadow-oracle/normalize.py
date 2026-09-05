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


def norm_body(body: str, applied: set, key_id: str | None, keep_json_keys: set | None = None, keep_regex=None):
    raw = body
    if body.startswith("base64:"):
        raw = base64.b64decode(body[7:]).decode("utf-8", "replace")
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
    body = norm_body(cap.get("body", ""), body_rules, key_id, keep_json_keys, keep_regex)
    if keep_lines is not None:
        # The cell's contract is what is NOT there: keep only the matching lines (a JSON body is
        # rendered canonically first so the filter sees one line per top-level entry).
        rx = re.compile(keep_lines)
        text = body["text"] if "text" in body else json.dumps(body["json"], separators=(",", ":"), sort_keys=True, indent=0)
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

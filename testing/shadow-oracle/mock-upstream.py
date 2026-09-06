#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""A DETERMINISTIC multi-dialect LLM upstream for the shadow oracle.

The oracle records busbar's exact bytes for every (ingress dialect, egress dialect, outcome) cell.
For that to be byte-stable across runs and binaries, the upstream must be a pure function of the
request: fixed ids, fixed usage (11 in / 7 out), a fixed marker text, no clocks, no randomness.

It answers in the dialect the REQUEST PATH selects (busbar's egress lane decides the path), so one
process serves all six egress dialects:

  anthropic         POST /v1/messages
  openai-chat       POST /v1/chat/completions
  openai-responses  POST /v1/responses
  gemini            POST /v1beta/models/<model>:generateContent | :streamGenerateContent
  bedrock           POST /model/<model>/converse | /converse-stream
  cohere            POST /v2/chat

Outcome controls (the recorder sets them per cell):
  header  X-Oracle-Upstream: down   -> 503 with a fixed body (drives busbar's failover / upstream-error path)
  header  X-Oracle-Upstream: slow   -> reserved (timeout cells), currently same as down
  header  X-Oracle-Upstream: 401    -> 401 with a fixed body (the member's credential is rejected: a hard-down)
  header  X-Oracle-Upstream: stream-error
                                    -> a 200 stream that FAILS PART WAY THROUGH: the dialect's normal
                                       events up to and including the text delta, then an IN-BAND error
                                       event in that dialect's own error shape, and no terminal usage /
                                       [DONE] frame. Distinct from `cut`, which kills the socket with no
                                       error at all: here the upstream says WHY, in band, after the
                                       response has already begun — so the door cannot answer with a
                                       status code and has to translate the failure into its own stream
  body    {"stream": true} (openai/anthropic/cohere) or the *stream* path (gemini/bedrock)
                                    -> a fixed SSE / streamed sequence in that dialect

Usage: mock-upstream.py <port> [marker] [control-file]

<control-file> is the third positional every caller in this tree actually passes (record.sh and the
script cells under scripts/): the path of a file the RECORDER writes between requests to select the
outcome for the next cell. It carries either a bare verb (down | 429 | 5xx | 401 | slow | cut,
applying to every model) or JSON {"<model>": "<verb>", ...} with "*" as the fallback — the same
vocabulary as the X-Oracle-Upstream header above, but chosen OUT OF BAND so busbar's own request is
byte-identical to the healthy cell it is being compared against. Absent file means a healthy
upstream; the recorder removes it again once the cell is captured. A FOREIGN mock answering on this
port would ignore the file entirely and serve every outage cell healthy, which is why record.sh
proves the port's owner is its own pid before it records anything.

Egress capture (opt-in, for proving what busbar actually SENT upstream — not just what came back):
  When the environment variable ORACLE_MOCK_CAPTURE_DIR is set, every handled request (whatever the
  outcome — 200, a control-file failure, a 404 for an unrouted path, all of it) is written as its own
  JSON file in that directory, named "<ns>-<pid>-<seq>.json" where <ns> is a nanosecond timestamp, so
  that filenames sort in request order. Each file holds exactly:
    {"path": <raw request path, unmodified>, "method": "POST",
     "headers": {<lowercased header name>: <value>, ...}, "body": <utf-8 str, or "base64:..." if not>}
  This lets a recorder that snapshots the directory's filename list immediately before issuing a
  request, and again immediately after, take "the filenames present after that weren't present
  before" (sorted, so ordering is preserved for cells that fire more than one egress request) as the
  egress record(s) for that one cell — no other coordination needed. When the env var is unset
  (the default), nothing is captured and this mock's behaviour is unchanged.
"""
import itertools
import json
import os
import sys
import threading
import time
from urllib.parse import unquote
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARKER = "oracle-marker"
IN_TOK, OUT_TOK = 11, 7
_capture_seq = itertools.count()


def j(obj) -> bytes:
    # Canonical, key-sorted, no whitespace variance -> byte-stable.
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


# Every member below that the published spec marks `required` but Anthropic defines as nullable is
# set to a fixed `None` (never omitted) so the body is both spec-complete and byte-stable; only the
# two token counts carry a real, deterministic value.
def anthropic_usage():
    return {"input_tokens": IN_TOK, "output_tokens": OUT_TOK, "cache_creation": None,
            "cache_creation_input_tokens": None, "cache_read_input_tokens": None,
            "inference_geo": None, "output_tokens_details": None, "server_tool_use": None,
            "service_tier": None}


def anthropic_delta_usage():
    return {"output_tokens": OUT_TOK, "input_tokens": IN_TOK, "cache_creation_input_tokens": None,
            "cache_read_input_tokens": None, "output_tokens_details": None, "server_tool_use": None}


def anthropic(model, marker):
    return j({"id": "msg_oracle", "type": "message", "role": "assistant", "model": model,
              "content": [{"type": "text", "text": marker, "citations": None}], "stop_reason": "end_turn",
              "stop_sequence": None, "stop_details": None, "container": None,
              "usage": anthropic_usage()})


def openai_chat(model, marker):
    return j({"id": "chatcmpl-oracle", "object": "chat.completion", "created": 0, "model": model,
              "choices": [{"index": 0, "message": {"role": "assistant", "content": marker, "refusal": None},
                           "finish_reason": "stop", "logprobs": None}],
              "usage": {"prompt_tokens": IN_TOK, "completion_tokens": OUT_TOK,
                        "total_tokens": IN_TOK + OUT_TOK}})


def openai_responses(model, marker):
    # Every member the published `Response` schema marks `required` (across its allOf merge) is
    # present here: the nullable ones fixed to `None`, the rest a fixed, deterministic value.
    return j({"id": "resp_oracle", "object": "response", "status": "completed", "model": model,
              "created_at": 0, "error": None, "incomplete_details": None, "instructions": None,
              "metadata": None, "parallel_tool_calls": True, "temperature": None, "top_p": None,
              "tool_choice": "auto", "tools": [],
              "output": [{"type": "message", "id": "msg_oracle", "role": "assistant", "status": "completed",
                          "content": [{"type": "output_text", "text": marker, "annotations": [], "logprobs": []}]}],
              "usage": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK, "total_tokens": IN_TOK + OUT_TOK,
                        "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                        "output_tokens_details": {"reasoning_tokens": 0}}})


def gemini(model, marker):
    return j({"candidates": [{"content": {"role": "model", "parts": [{"text": marker}]},
                              "finishReason": "STOP", "index": 0}],
              "usageMetadata": {"promptTokenCount": IN_TOK, "candidatesTokenCount": OUT_TOK,
                                "totalTokenCount": IN_TOK + OUT_TOK},
              "modelVersion": model})


def bedrock(model, marker):
    # `metrics.latencyMs` is a required member of ConverseResponse; fixed 0 keeps the body
    # deterministic (there is no real clock in this mock).
    return j({"output": {"message": {"role": "assistant", "content": [{"text": marker}]}},
              "stopReason": "end_turn",
              "usage": {"inputTokens": IN_TOK, "outputTokens": OUT_TOK, "totalTokens": IN_TOK + OUT_TOK},
              "metrics": {"latencyMs": 0}})


def cohere(model, marker):
    return j({"id": "cohere-oracle", "finish_reason": "COMPLETE",
              "message": {"role": "assistant", "content": [{"type": "text", "text": marker}]},
              "usage": {"billed_units": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK},
                        "tokens": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK}}})


# ── streamed variants: a fixed event sequence per dialect (one text delta + a terminal usage) ─────
def sse(events):
    return b"".join(f"data: {json.dumps(e, separators=(',', ':'), sort_keys=True)}\n\n".encode() for e in events)


def openai_chat_stream(model, marker):
    base = {"id": "chatcmpl-oracle", "object": "chat.completion.chunk", "created": 0, "model": model}
    return sse([
        {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": marker}, "finish_reason": None}]},
        {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
         "usage": {"prompt_tokens": IN_TOK, "completion_tokens": OUT_TOK, "total_tokens": IN_TOK + OUT_TOK}},
    ]) + b"data: [DONE]\n\n"


def anthropic_stream(model, marker):
    def ev(t, body):
        return f"event: {t}\ndata: {json.dumps(body, separators=(',', ':'), sort_keys=True)}\n\n".encode()
    return b"".join([
        ev("message_start", {"type": "message_start", "message": {
            "id": "msg_oracle", "type": "message", "role": "assistant", "model": model, "content": [],
            "stop_reason": None, "stop_sequence": None, "stop_details": None, "container": None,
            "usage": {**anthropic_usage(), "output_tokens": 0}}}),
        ev("content_block_start", {"type": "content_block_start", "index": 0,
                                    "content_block": {"type": "text", "text": "", "citations": None}}),
        ev("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": marker}}),
        ev("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ev("message_delta", {"type": "message_delta",
                             "delta": {"stop_reason": "end_turn", "stop_sequence": None,
                                       "stop_details": None, "container": None},
                             "usage": anthropic_delta_usage()}),
        ev("message_stop", {"type": "message_stop"}),
    ])


def gemini_stream(model, marker):
    return sse([json.loads(gemini(model, marker))])


def cohere_stream(model, marker):
    return sse([
        {"type": "message-start", "id": "cohere-oracle", "delta": {"message": {"role": "assistant", "content": []}}},
        {"type": "content-delta", "index": 0, "delta": {"message": {"content": {"type": "text", "text": marker}}}},
        {"type": "message-end", "delta": {"finish_reason": "COMPLETE",
                                          "usage": {"tokens": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK}}}},
    ])


# ── AWS event-stream (application/vnd.amazon.eventstream) framing for Bedrock ConverseStream ──────
# Mirrors crates/busbar-substrate/src/eventstream.rs `encode_frame` byte-for-byte: a real CRC32 (a
# native AWS SDK decoder validates both checksums), so the frames this mock emits are indistinguishable
# on the wire from a genuine Bedrock ConverseStream response.
import struct
import zlib


def _eventstream_header(name, value):
    v = value.encode("utf-8")
    return bytes([len(name)]) + name.encode("ascii") + b"\x07" + struct.pack(">H", len(v)) + v


def _eventstream_frame(event_type, payload):
    headers = (_eventstream_header(":event-type", event_type)
               + _eventstream_header(":content-type", "application/json")
               + _eventstream_header(":message-type", "event"))
    headers_len = len(headers)
    total_len = 12 + headers_len + len(payload) + 4
    prelude = struct.pack(">II", total_len, headers_len)
    prelude_crc = zlib.crc32(prelude) & 0xFFFFFFFF
    frame = prelude + struct.pack(">I", prelude_crc) + headers + payload
    message_crc = zlib.crc32(frame) & 0xFFFFFFFF
    return frame + struct.pack(">I", message_crc)


def bedrock_stream(model, marker):
    # The event sequence and payload shapes mirror crates/busbar-llm/src/bedrock/writer.rs
    # `write_response_event` exactly: no `contentBlockStart` for a plain text block (a real Bedrock
    # ConverseStream never sends one — the text block is implied by the first `contentBlockDelta`),
    # `messageStop` carries only `stopReason`, and token usage plus the required `metrics.latencyMs`
    # (`ConverseStreamMetadataEvent` — fixed 0, there is no real clock in this mock) trail in the
    # separate `metadata` frame.
    events = [
        ("messageStart", {"role": "assistant"}),
        ("contentBlockDelta", {"contentBlockIndex": 0, "delta": {"text": marker}}),
        ("contentBlockStop", {"contentBlockIndex": 0}),
        ("messageStop", {"stopReason": "end_turn"}),
        ("metadata", {"usage": {"inputTokens": IN_TOK, "outputTokens": OUT_TOK,
                                 "totalTokens": IN_TOK + OUT_TOK},
                      "metrics": {"latencyMs": 0}}),
    ]
    return b"".join(_eventstream_frame(et, j(body)) for et, body in events)


# ── the mid-stream failure: N good events, then an IN-BAND error in the dialect's own shape ───────
# The response has already been committed 200 with its first frames, so this is the one upstream
# failure a door cannot answer with a status code. Each dialect's error event below is the shape that
# dialect actually defines for it; the terminal usage/[DONE] frame is deliberately NOT sent, because
# a failed stream does not get one.
ERR_MSG = "oracle: upstream failed mid-stream"


def _sse_error_openai():
    return sse([{"error": {"type": "server_error", "code": None, "param": None, "message": ERR_MSG}}])


def openai_chat_stream_error(model, marker):
    base = {"id": "chatcmpl-oracle", "object": "chat.completion.chunk", "created": 0, "model": model}
    return sse([
        {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": marker}, "finish_reason": None}]},
    ]) + _sse_error_openai()


def anthropic_stream_error(model, marker):
    def ev(t, body):
        return f"event: {t}\ndata: {json.dumps(body, separators=(',', ':'), sort_keys=True)}\n\n".encode()
    return b"".join([
        ev("message_start", {"type": "message_start", "message": {
            "id": "msg_oracle", "type": "message", "role": "assistant", "model": model, "content": [],
            "stop_reason": None, "stop_sequence": None, "stop_details": None, "container": None,
            "usage": {**anthropic_usage(), "output_tokens": 0}}}),
        ev("content_block_start", {"type": "content_block_start", "index": 0,
                                   "content_block": {"type": "text", "text": "", "citations": None}}),
        ev("content_block_delta", {"type": "content_block_delta", "index": 0,
                                   "delta": {"type": "text_delta", "text": marker}}),
        # Anthropic's documented in-band stream failure: an `error` event, no message_stop.
        ev("error", {"type": "error", "error": {"type": "overloaded_error", "message": ERR_MSG}}),
    ])


def gemini_stream_error(model, marker):
    good = json.loads(gemini(model, marker))
    good.pop("usageMetadata", None)
    return sse([good, {"error": {"code": 500, "message": ERR_MSG, "status": "INTERNAL"}}])


def cohere_stream_error(model, marker):
    return sse([
        {"type": "message-start", "id": "cohere-oracle", "delta": {"message": {"role": "assistant", "content": []}}},
        {"type": "content-delta", "index": 0, "delta": {"message": {"content": {"type": "text", "text": marker}}}},
        {"type": "error", "id": "cohere-oracle", "message": ERR_MSG},
    ])


def responses_stream_error(model, marker):
    # /v1/responses answers buffered in every other cell; the ONLY streaming it does here is this
    # failure, so no recorded cell's bytes move by adding it.
    return sse([
        {"type": "response.created", "sequence_number": 0,
         "response": {"id": "resp_oracle", "object": "response", "status": "in_progress", "model": model}},
        {"type": "response.output_text.delta", "sequence_number": 1, "item_id": "msg_oracle",
         "output_index": 0, "content_index": 0, "delta": marker},
        {"type": "error", "sequence_number": 2, "code": "server_error", "param": None, "message": ERR_MSG},
    ])


def bedrock_stream_error(model, marker):
    # A real ConverseStream reports a mid-stream failure as an EXCEPTION frame: :message-type is
    # `exception`, not `event`, and :exception-type names the modelled error.
    def exception_frame(exc_type, payload):
        headers = (_eventstream_header(":exception-type", exc_type)
                   + _eventstream_header(":content-type", "application/json")
                   + _eventstream_header(":message-type", "exception"))
        headers_len = len(headers)
        total_len = 12 + headers_len + len(payload) + 4
        prelude = struct.pack(">II", total_len, headers_len)
        frame = prelude + struct.pack(">I", zlib.crc32(prelude) & 0xFFFFFFFF) + headers + payload
        return frame + struct.pack(">I", zlib.crc32(frame) & 0xFFFFFFFF)

    good = [
        ("messageStart", {"role": "assistant"}),
        ("contentBlockDelta", {"contentBlockIndex": 0, "delta": {"text": marker}}),
    ]
    return (b"".join(_eventstream_frame(et, j(body)) for et, body in good)
            + exception_frame("internalServerException", j({"message": ERR_MSG})))


class H(BaseHTTPRequestHandler):
    server_version = "oracle-upstream/1"
    sys_version = ""

    def _send(self, status, body, ctype="application/json"):
        if getattr(self, "cut", False) and status == 200:
            # `cut`: headers + the first frame (or half the body), then the socket dies — the
            # "upstream died mid-response" arm of the refund table (PB-27)
            first = body.split(b"\n\n", 1)[0] + b"\n\n" if b"\n\n" in body else body[: max(1, len(body) // 2)]
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(first); self.wfile.flush()
            try:
                self.connection.shutdown(1)
            except OSError:
                pass
            self.close_connection = True
            return
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _capture_egress(self, method, path, raw_body):
        # See the module docstring for the on-disk contract. Best-effort: a capture failure must
        # never take down the mock or change the response busbar gets.
        cap_dir = os.environ.get("ORACLE_MOCK_CAPTURE_DIR")
        if not cap_dir:
            return
        try:
            os.makedirs(cap_dir, exist_ok=True)
            headers = {k.lower(): v for k, v in self.headers.items()}
            try:
                body = raw_body.decode("utf-8")
            except UnicodeDecodeError:
                import base64
                body = "base64:" + base64.b64encode(raw_body).decode()
            record = {"path": path, "method": method, "headers": headers, "body": body}
            name = f"{time.time_ns()}-{os.getpid()}-{next(_capture_seq)}.json"
            tmp_path = os.path.join(cap_dir, f".{name}.tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(record, f, separators=(",", ":"), sort_keys=True)
            os.replace(tmp_path, os.path.join(cap_dir, name))  # atomic: no half-written file is ever "newest"
        except OSError:
            pass

    def do_GET(self):
        # Readiness only (fleet-fixtures wait_for_http probes with GET /). Every dialect is POST.
        p = self.path.split("?", 1)[0]
        if p == "/":
            return self._send(200, j({"ok": True, "mock": "oracle-upstream"}))
        if p == "/__control":
            # A diagnostic echo, never a dialect: a writer of the control file (record.sh,
            # cooldown-trip.sh, ...) polls this after an atomic rename to CONFIRM this mock has
            # actually seen the new bytes before it fires the cell's real request — otherwise a
            # writer has no way to know its write landed before the request that depends on it goes
            # out. Deliberately not wired into any dialect path or _capture_egress, so a cell can
            # never record it by accident.
            return self._send(200, j({"raw": self._read_control_file()}))
        return self._send(404, j({"error": f"oracle mock: no GET route {self.path}"}))

    def _read_control_file(self):
        """A single best-effort read of the control file's raw (whitespace-stripped) text, or None
        if there is no file / it could not be read. Used both by /__control and by the outage-verb
        resolution in do_POST below."""
        ctl_file = self.server.control_file  # type: ignore[attr-defined]
        if not ctl_file or not os.path.exists(ctl_file):
            return None
        try:
            with open(ctl_file, "r") as f:
                return f.read().strip()
        except OSError:
            return None

    @staticmethod
    def _verb_for_model(raw_ctl, model):
        """raw_ctl is either a bare verb (applies to every model) or JSON {"<model>": "<verb>"}.
        May raise ValueError on malformed JSON -- callers decide how to treat that."""
        if raw_ctl.startswith("{"):
            parsed = json.loads(raw_ctl)
            return (parsed.get(model) or parsed.get("*") or "").lower()
        return raw_ctl.lower()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        # Capture the egress request as busbar actually sent it, before any routing/outcome logic
        # below can short-circuit — a 503/404/control-file response is still a request that was made.
        self._capture_egress("POST", self.path, raw)
        try:
            req = json.loads(raw) if raw else {}
        except Exception:
            req = {}
        model = req.get("model") or "oracle-model"
        marker = self.server.marker  # type: ignore[attr-defined]

        # Two outage controls: a header (handy for curl-by-hand) and a CONTROL FILE the recorder
        # writes per cell — busbar must never see a control header, so the file is the one the
        # oracle actually uses.
        # busbar percent-encodes the gemini `:generateContent` colon on egress; decode before matching.
        p = unquote(self.path.split("?", 1)[0])
        # the egress model for path-addressed dialects (gemini / bedrock) lives in the path
        path_model = None
        if p.startswith("/v1beta/models/"):
            path_model = p[len("/v1beta/models/"):].split(":", 1)[0]
        elif p.startswith("/model/"):
            path_model = p[len("/model/"):].split("/", 1)[0]
        model = path_model or model

        # Control: a header (handy for curl-by-hand) or the CONTROL FILE the recorder writes per cell.
        # The file is either a bare verb (applies to every model) or JSON {"<model>": "<verb>"}.
        # Verbs: down (503) | 429 (Retry-After: 7) | 5xx (500) | 401 (credential rejected: a hard-down)
        #        | slow (sleep past busbar's attempt cap)
        #        | cut (close the socket after the first streamed event / mid-body)
        #        | stream-error (N good events, then an IN-BAND error event in the dialect's own
        #          error shape — the failure a 200 stream cannot report as a status code)
        ctl = (self.headers.get("X-Oracle-Upstream") or "").strip().lower()
        ctl_file = self.server.control_file  # type: ignore[attr-defined]
        if ctl_file:
            if os.path.exists(ctl_file):
                raw_ctl = self._read_control_file()
                if raw_ctl:
                    try:
                        ctl = self._verb_for_model(raw_ctl, model)
                    except ValueError:
                        raw_ctl = None  # malformed JSON: treat exactly like an empty/unreadable read
                    else:
                        with self.server.control_lock:  # type: ignore[attr-defined]
                            self.server.last_raw = raw_ctl  # type: ignore[attr-defined]
                if not raw_ctl:
                    # An EMPTY (or unreadable, or malformed-JSON) read means a writer's rename hadn't
                    # landed yet, or a transient OS hiccup -- NOT "no outage". Falling through to
                    # healthy here is exactly the bug this fix closes: a cell that ordered an outage
                    # would silently get served a 200. Hold the last verb this mock successfully read
                    # instead, and say so in mock.log so the condition is visible.
                    with self.server.control_lock:  # type: ignore[attr-defined]
                        last_raw = self.server.last_raw  # type: ignore[attr-defined]
                    try:
                        ctl = self._verb_for_model(last_raw, model) if last_raw else ""
                    except ValueError:
                        ctl = ""
                    sys.stderr.write(
                        f"[control] empty/unreadable/malformed read on {ctl_file} for model {model!r}; "
                        f"holding last verb (raw={last_raw!r}) -> {ctl!r}\n")
                    sys.stderr.flush()
            else:
                # No file at all is a real, intentional "no outage" (record.sh/cooldown-trip.sh clear
                # it with an atomic unlink between cells) -- not a torn read, so no verb survives it.
                with self.server.control_lock:  # type: ignore[attr-defined]
                    self.server.last_raw = None  # type: ignore[attr-defined]
                ctl = ""
        if ctl == "down":
            return self._send(503, j({"error": {"type": "upstream_unavailable", "message": "oracle: upstream down"}}))
        if ctl == "429":
            self.send_response(429); self.send_header("Content-Type", "application/json"); self.send_header("Retry-After", "7")
            body = j({"error": {"type": "rate_limit_error", "message": "oracle: upstream rate limited"}})
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        if ctl == "5xx":
            return self._send(500, j({"error": {"type": "server_error", "message": "oracle: upstream exploded"}}))
        if ctl == "401":
            return self._send(401, j({"error": {"type": "authentication_error", "message": "oracle: upstream rejected the credential"}}))
        if ctl == "slow":
            import time
            time.sleep(float(os.environ.get("ORACLE_MOCK_SLOW_SECS", "8")))
        # Per-request, not server-global: each accepted connection gets its own handler instance,
        # so storing this on `self` (not `self.server`) keeps concurrent requests from clobbering
        # each other's cut/no-cut decision once the server is threaded.
        self.cut = (ctl == "cut")

        want_stream = bool(req.get("stream"))
        # `stream-error` only ever applies to a request that IS a stream — a buffered request that
        # fails is already covered by `down`/`5xx`, and answering one with half a stream would be a
        # shape no upstream produces.
        stream_error = (ctl == "stream-error")
        if p == "/v1/messages":
            if want_stream and stream_error:
                return self._send(200, anthropic_stream_error(model, marker), "text/event-stream")
            body = anthropic_stream(model, marker) if want_stream else anthropic(model, marker)
            return self._send(200, body, "text/event-stream" if want_stream else "application/json")
        if p == "/v1/chat/completions":
            if want_stream and stream_error:
                return self._send(200, openai_chat_stream_error(model, marker), "text/event-stream")
            body = openai_chat_stream(model, marker) if want_stream else openai_chat(model, marker)
            return self._send(200, body, "text/event-stream" if want_stream else "application/json")
        if p == "/v1/responses":
            if want_stream and stream_error:
                return self._send(200, responses_stream_error(model, marker), "text/event-stream")
            return self._send(200, openai_responses(model, marker))
        if p.startswith("/v1beta/models/") and ":streamGenerateContent" in p:
            if stream_error:
                return self._send(200, gemini_stream_error(model, marker), "text/event-stream")
            return self._send(200, gemini_stream(model, marker), "text/event-stream")
        if p.startswith("/v1beta/models/") and ":generateContent" in p:
            return self._send(200, gemini(model, marker))
        if p.startswith("/model/") and p.endswith("/converse-stream"):
            if stream_error:
                return self._send(200, bedrock_stream_error(model, marker), "application/vnd.amazon.eventstream")
            return self._send(200, bedrock_stream(model, marker), "application/vnd.amazon.eventstream")
        if p.startswith("/model/") and p.endswith("/converse"):
            return self._send(200, bedrock(model, marker))
        if p == "/v2/chat":
            if want_stream and stream_error:
                return self._send(200, cohere_stream_error(model, marker), "text/event-stream")
            body = cohere_stream(model, marker) if want_stream else cohere(model, marker)
            return self._send(200, body, "text/event-stream" if want_stream else "application/json")
        return self._send(404, j({"error": f"oracle mock: no dialect for path {p}"}))

    def log_message(self, *_a):  # silent: byte-stable stdout for the recorder
        pass


def main():
    port = int(sys.argv[1])
    marker = sys.argv[2] if len(sys.argv) > 2 else MARKER
    control_file = sys.argv[3] if len(sys.argv) > 3 else ""
    # Threaded so concurrency/queue/breaker cells can hit this mock with several requests in
    # flight at once — a single-threaded HTTPServer would serialize them and make a "concurrent"
    # cell impossible to record honestly. daemon_threads so a stray "slow" sleeper doesn't block
    # process exit.
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.daemon_threads = True
    srv.marker = marker  # type: ignore[attr-defined]
    srv.control_file = control_file  # type: ignore[attr-defined]
    # Last successfully-read raw control-file text, shared across the threaded handlers so an empty
    # or unreadable read on one request can fall back to the last verb a DIFFERENT request actually
    # read, instead of "no outage". Guarded by a lock: ThreadingHTTPServer serves overlapping
    # requests on separate threads.
    srv.last_raw = None  # type: ignore[attr-defined]
    srv.control_lock = threading.Lock()  # type: ignore[attr-defined]
    srv.serve_forever()


if __name__ == "__main__":
    main()

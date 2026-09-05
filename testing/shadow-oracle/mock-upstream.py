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
  body    {"stream": true} (openai/anthropic/cohere) or the *stream* path (gemini/bedrock)
                                    -> a fixed SSE / streamed sequence in that dialect

Usage: mock-upstream.py <port> [marker]

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
import time
from urllib.parse import unquote
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARKER = "oracle-marker"
IN_TOK, OUT_TOK = 11, 7
_capture_seq = itertools.count()


def j(obj) -> bytes:
    # Canonical, key-sorted, no whitespace variance -> byte-stable.
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


def anthropic(model, marker):
    return j({"id": "msg_oracle", "type": "message", "role": "assistant", "model": model,
              "content": [{"type": "text", "text": marker}], "stop_reason": "end_turn",
              "stop_sequence": None, "usage": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK}})


def openai_chat(model, marker):
    return j({"id": "chatcmpl-oracle", "object": "chat.completion", "created": 0, "model": model,
              "choices": [{"index": 0, "message": {"role": "assistant", "content": marker},
                           "finish_reason": "stop"}],
              "usage": {"prompt_tokens": IN_TOK, "completion_tokens": OUT_TOK,
                        "total_tokens": IN_TOK + OUT_TOK}})


def openai_responses(model, marker):
    return j({"id": "resp_oracle", "object": "response", "status": "completed", "model": model,
              "output": [{"type": "message", "id": "msg_oracle", "role": "assistant", "status": "completed",
                          "content": [{"type": "output_text", "text": marker, "annotations": []}]}],
              "usage": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK, "total_tokens": IN_TOK + OUT_TOK}})


def gemini(model, marker):
    return j({"candidates": [{"content": {"role": "model", "parts": [{"text": marker}]},
                              "finishReason": "STOP", "index": 0}],
              "usageMetadata": {"promptTokenCount": IN_TOK, "candidatesTokenCount": OUT_TOK,
                                "totalTokenCount": IN_TOK + OUT_TOK},
              "modelVersion": model})


def bedrock(model, marker):
    return j({"output": {"message": {"role": "assistant", "content": [{"text": marker}]}},
              "stopReason": "end_turn",
              "usage": {"inputTokens": IN_TOK, "outputTokens": OUT_TOK, "totalTokens": IN_TOK + OUT_TOK}})


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
        ev("message_start", {"type": "message_start", "message": {"id": "msg_oracle", "type": "message", "role": "assistant",
                                                                     "model": model, "content": [], "stop_reason": None,
                                                                     "usage": {"input_tokens": IN_TOK, "output_tokens": 0}}}),
        ev("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ev("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": marker}}),
        ev("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ev("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                             "usage": {"output_tokens": OUT_TOK}}),
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


def bedrock_stream(model, marker):
    # Bedrock ConverseStream is an AWS event-stream binary framing; the oracle records whatever the
    # codec emits for it, but this mock does not synthesize the binary framing. Cells that need it
    # are recorded as MOCK-UNSUPPORTED (a named gap, never a silent pass).
    return None


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
        if self.path.split("?", 1)[0] == "/":
            return self._send(200, j({"ok": True, "mock": "oracle-upstream"}))
        return self._send(404, j({"error": f"oracle mock: no GET route {self.path}"}))

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
        ctl = (self.headers.get("X-Oracle-Upstream") or "").strip().lower()
        ctl_file = self.server.control_file  # type: ignore[attr-defined]
        if ctl_file and os.path.exists(ctl_file):
            try:
                raw_ctl = open(ctl_file).read().strip()
                if raw_ctl.startswith("{"):
                    ctl = (json.loads(raw_ctl).get(model) or json.loads(raw_ctl).get("*") or "").lower()
                else:
                    ctl = raw_ctl.lower() or ctl
            except (OSError, ValueError):
                pass
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
        if p == "/v1/messages":
            body = anthropic_stream(model, marker) if want_stream else anthropic(model, marker)
            return self._send(200, body, "text/event-stream" if want_stream else "application/json")
        if p == "/v1/chat/completions":
            body = openai_chat_stream(model, marker) if want_stream else openai_chat(model, marker)
            return self._send(200, body, "text/event-stream" if want_stream else "application/json")
        if p == "/v1/responses":
            return self._send(200, openai_responses(model, marker))
        if p.startswith("/v1beta/models/") and ":streamGenerateContent" in p:
            return self._send(200, gemini_stream(model, marker), "text/event-stream")
        if p.startswith("/v1beta/models/") and ":generateContent" in p:
            return self._send(200, gemini(model, marker))
        if p.startswith("/model/") and p.endswith("/converse-stream"):
            b = bedrock_stream(model, marker)
            return self._send(501, j({"error": "oracle mock: bedrock converse-stream framing unsupported (named gap)"}))
        if p.startswith("/model/") and p.endswith("/converse"):
            return self._send(200, bedrock(model, marker))
        if p == "/v2/chat":
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
    srv.serve_forever()


if __name__ == "__main__":
    main()

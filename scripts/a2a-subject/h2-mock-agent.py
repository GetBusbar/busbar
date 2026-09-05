#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""A MINIMAL A2A AGENT FOR THE H2 GATING SCENARIOS (tracker row H2, ARCHITECTURE.md #2.2).

The a2a-subject boot (scripts/a2a-subject/boot.sh) fronts a pinned reference agent behind a
signing vendor -- built for the official TCK/battery legs and not meant to be re-purposed for a
handful of throwaway budget/route/meter/audit fixtures. This is a standalone, dependency-free
fixture agent for the H2 scenario scripts (scripts/a2a-subject/h2-*.sh) instead: it serves an
honest AgentCard with NO `supportedInterfaces` (docs/a2a.md: "A card declaring no interfaces
defaults to JSON-RPC"), so Busbar dials it in plain JSON-RPC, and it answers `message/send` with a
single completed task.

EGRESS CAPTURE, the same on-disk contract testing/shadow-oracle/mock-upstream.py uses for the llm
plane: when A2A_MOCK_CAPTURE_DIR is set, every request this process receives (GET or POST) is
written as its own JSON file `{ts}-{pid}-{seq}.json` holding
`{"path": ..., "method": ..., "headers": {...}, "body": ...}` -- read the directory's file count
before/after a call to prove egress did or did not reach the fronted agent.

CONTROL: A2A_MOCK_CONTROL_FILE, if set and containing the literal `down`, answers every POST with a
502 (a "this agent is unreachable" response a live upstream would give under a hard failure) --
used by the route-failover scenario. Anything else in the file, or an absent/empty file, answers
normally. Checked per-request, so a scenario can flip it mid-run with no restart.

Usage: h2-mock-agent.py <port> [control-file]
"""
import itertools
import json
import os
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_capture_seq = itertools.count()


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z"


def _card(base_url):
    # Every REQUIRED AgentCard field except `supportedInterfaces` -- see the module docstring for
    # why omitting it is a deliberate, spec-legal choice rather than an incompleteness.
    return {
        "name": "H2 Fixture Agent",
        "description": "A minimal, fully-controlled A2A agent used by busbar's own H2 gating "
                        "scenarios (tracker row H2). Not a conformance control peer.",
        "url": base_url,
        "version": "1.0.0",
        "capabilities": {"streaming": False, "pushNotifications": False,
                          "extendedAgentCard": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{
            "id": "echo",
            "name": "Echo",
            "description": "Returns the text it was given, unchanged.",
            "tags": ["echo", "h2"],
        }],
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):
        pass

    def _capture(self, method, raw_body):
        cap_dir = os.environ.get("A2A_MOCK_CAPTURE_DIR")
        if not cap_dir:
            return
        try:
            os.makedirs(cap_dir, exist_ok=True)
            headers = {k.lower(): v for k, v in self.headers.items()}
            try:
                body = raw_body.decode("utf-8") if raw_body else ""
            except UnicodeDecodeError:
                import base64
                body = "base64:" + base64.b64encode(raw_body).decode()
            record = {"path": self.path, "method": method, "headers": headers, "body": body}
            name = f"{time.time_ns()}-{os.getpid()}-{next(_capture_seq)}.json"
            tmp = os.path.join(cap_dir, f".{name}.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(record, f)
            os.replace(tmp, os.path.join(cap_dir, name))
        except OSError:
            pass

    def _send(self, status, obj):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _down(self):
        control_file = self.server.control_file  # type: ignore[attr-defined]
        if not control_file or not os.path.exists(control_file):
            return False
        try:
            return open(control_file, encoding="utf-8").read().strip().lower() == "down"
        except OSError:
            return False

    def do_GET(self):
        self._capture("GET", None)
        if self.path.endswith("/.well-known/agent-card.json"):
            base = f"http://127.0.0.1:{self.server.server_address[1]}"  # type: ignore[attr-defined]
            return self._send(200, _card(base))
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        self._capture("POST", raw)
        if self._down():
            return self._send(502, {"error": {"code": -32603, "message": "h2 fixture agent: down"}})
        try:
            body = json.loads(raw) if raw else {}
        except Exception:
            body = {}
        method = body.get("method")
        rid = body.get("id")
        if method in ("SendMessage", "message/send") or self.path.endswith("message:send"):
            params = body.get("params") or {}
            message = params.get("message") or {}
            text = "".join(p.get("text", "") for p in message.get("parts") or [])
            task = {
                "id": str(uuid.uuid4()),
                "contextId": str(uuid.uuid4()),
                "status": {"state": "TASK_STATE_COMPLETED", "timestamp": _now()},
                "artifacts": [{
                    "artifactId": str(uuid.uuid4()),
                    "parts": [{"text": text or "ok"}],
                }],
            }
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {"task": task}})
        return self._send(404, {"jsonrpc": "2.0", "id": rid,
                                 "error": {"code": -32601, "message": f"unknown method {method}"}})


def main():
    port = int(sys.argv[1])
    control_file = sys.argv[2] if len(sys.argv) > 2 else ""
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    srv.control_file = control_file  # type: ignore[attr-defined]
    srv.serve_forever()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A stand-in Anthropic-protocol upstream for the functional probes.

It answers every POST with a fixed marker string in the assistant text and NONZERO usage
(input_tokens/output_tokens), because the store probe's whole point is that busbar records real
per-key usage counters and they SURVIVE a restart — a zero-usage response would make the durability
assertion vacuous. It never sleeps and never touches the network, so a probe spends no real provider
call and cannot hang on an upstream that is slow for reasons unrelated to the plugin under test.

Usage: mock-upstream.py <port> <marker> [require-upstream-key]

If a third argument is given, the mock REQUIRES it as the inbound `Authorization: Bearer <key>` (the
provider egress credential busbar sends) and answers 401 otherwise. The secret probe uses this: the
whole point there is that busbar RESOLVED the provider api_key from the secrets backend and actually
SENT it upstream, and only an upstream that rejects a wrong/absent key can prove the resolved value
was used rather than merely fetched.

Self-contained on purpose (fixtures live in the workflow's own tree, no external services): it is
the same shape scripts/release-check.sh's start_mock_upstream bakes inline, lifted into a file so
the probe scripts and the workflow share ONE mock rather than drifting copies.
"""
import http.server
import json
import sys

PORT = int(sys.argv[1])
MARKER = sys.argv[2]
REQUIRE_KEY = sys.argv[3] if len(sys.argv) > 3 else ""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if REQUIRE_KEY and self.headers.get("Authorization") != "Bearer " + REQUIRE_KEY:
            err = json.dumps({"error": "unauthorized: wrong or missing upstream key"}).encode()
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err)))
            self.end_headers()
            self.wfile.write(err)
            return
        body = json.dumps(
            {
                "id": "msg_fleet_fixture",
                "type": "message",
                "role": "assistant",
                "model": "test-model",
                "content": [{"type": "text", "text": MARKER}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 11, "output_tokens": 7},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

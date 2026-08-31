#!/usr/bin/env python3
"""A telemetry sink fixture for the export-plugin functional probe.

busbar's `export:` instances (request-log-webhook, otlp, ...) POST telemetry to a URL. This is that
URL: it records every POST it receives and exposes the count at GET /received, so the probe can
assert the exporter actually DELIVERED — not merely that busbar booted with it configured. A booted
exporter that never ships a byte is exactly the "it loaded" vs "it works" gap the whole exercise is
about, and only a receiver outside busbar can tell them apart.

Usage: export-sink.py <port>
  GET  /received  -> {"count": N, "last_bytes": B}   (what the probe polls)
  POST <anything> -> 200, increments the counter
Self-contained, no external services, stdlib only.
"""
import http.server
import json
import sys
import threading

PORT = int(sys.argv[1])
STATE = {"count": 0, "last_bytes": 0}
LOCK = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        with LOCK:
            STATE["count"] += 1
            STATE["last_bytes"] = length
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        with LOCK:
            body = json.dumps(dict(STATE)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

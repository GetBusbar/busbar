#!/usr/bin/env python3
"""A forwarding-hook sidecar fixture for the hook-plugin functional probe.

A forwarding hook (the first-party busbar-webrequest-hook) relays each tapped request to an external
sidecar over HTTP. This is that sidecar: it records every call and, for a `tap` (fire-and-forget),
that receipt IS the observable effect the probe asserts — the hook demonstrably FIRED on the request
path, which is the bar the audit sets ("an actual tap/gate effect on a request", above the log-line
floor).

For a `gate` it also returns an allow verdict so the request proceeds, so the same fixture serves
either wiring. The exact gate response envelope varies by hook ABI version; the probe that uses gate
mode asserts on receipt + the busbar-side log lines rather than on a specific verdict schema, so a
minor envelope drift never turns this into a false red about the fixture.

Usage: hook-sidecar.py <port>
  GET  /received -> {"count": N}
  POST <anything> -> 200 {"decision":"allow"}, increments the counter
Self-contained, stdlib only.
"""
import http.server
import json
import sys
import threading

PORT = int(sys.argv[1])
STATE = {"count": 0}
LOCK = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        with LOCK:
            STATE["count"] += 1
        body = json.dumps({"decision": "allow"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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

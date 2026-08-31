#!/usr/bin/env python3
"""A HashiCorp-Vault KV v2 fixture backend for the secret-plugin functional probe.

The first-party `vault` secret plugin (busbar-hashicorp-vault-plugin) resolves a config secret
reference by GET {addr}/v1/{path} with an X-Vault-Token header, expecting the KV v2 envelope
{"data":{"data":{<field>:<value>}}}. This is the smallest server that answers exactly that, so the
probe can prove the plugin RESOLVES a real value from a backend and busbar then USES it — not merely
that busbar booted with the plugin present.

It also enforces the token: a wrong X-Vault-Token gets 403. That matters — the probe's proof is that
the RESOLVED value flows into a working provider credential, and a fixture that returns the secret to
anyone would let a broken plugin (one that sends no token) pass.

Usage: vault-fixture.py <port> <expected-token> <field> <value>
  GET /v1/secret/data/busbar  (X-Vault-Token: <expected-token>) -> {"data":{"data":{<field>:<value>}}}
Self-contained, stdlib only.
"""
import http.server
import json
import sys

PORT = int(sys.argv[1])
EXPECTED_TOKEN = sys.argv[2]
FIELD = sys.argv[3]
VALUE = sys.argv[4]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("X-Vault-Token") != EXPECTED_TOKEN:
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps({"data": {"data": {FIELD: VALUE}}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

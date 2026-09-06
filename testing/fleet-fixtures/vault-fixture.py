#!/usr/bin/env python3
"""A HashiCorp-Vault KV v2 fixture backend for the secret-plugin functional probe.

The first-party `vault` secret plugin (busbar-hashicorp-vault-plugin) resolves a config secret
reference by GET {addr}/v1/{path} with an X-Vault-Token header, expecting the KV v2 envelope
{"data":{"data":{<field>:<value>}}}. This is the smallest server that answers exactly that, so the
probe can prove the plugin RESOLVES a real value from a backend and busbar then USES it — not merely
that busbar booted with the plugin present.

It also enforces the token: a wrong X-Vault-Token gets 403. That matters — the probe's proof is that
the RESOLVED value flows into a working provider credential, and a fixture that returns the secret to
anyone would let a broken plugin (one that sends no token) pass. A FIXTURE THAT CANNOT SAY NO MAKES
THE PROBE VACUOUS.

IT SAYS NO TO THREE THINGS, NOT ONE. The token was the only one it checked, and the other two matter
just as much because the probe's config names them:

  THE PATH. `self.path` was never read, so EVERY URL returned the secret. The provider's reference is
  `{ module: vault, settings: { path: "secret/data/busbar" } }` — a plugin that ignored that setting
  and asked for /v1/anything, or that hardcoded a path of its own, resolved the value anyway and the
  probe called the `path` setting proven. Only the configured path answers now; everything else is
  404, in Vault's own `{"errors":[...]}` shape.

  THE FIELD. The envelope held exactly one key, so "read the field the config names" and "return
  whichever value you find in there" are indistinguishable. The envelope now carries DECOYS — one
  before the real field and one after, so neither a first-value nor a last-value shortcut lands on
  the secret — and their values are wrong on purpose, which the mock upstream then rejects with a
  401. A multi-key envelope is also simply what a real KV v2 secret looks like.

Usage: vault-fixture.py <port> <expected-token> <field> <value> [path]
  GET /v1/<path>  (X-Vault-Token: <expected-token>) -> {"data":{"data":{...,<field>:<value>,...}}}
  <path> defaults to secret/data/busbar (what probe-secret.sh configures).
Self-contained, stdlib only.
"""
import http.server
import json
import sys

PORT = int(sys.argv[1])
EXPECTED_TOKEN = sys.argv[2]
FIELD = sys.argv[3]
VALUE = sys.argv[4]
PATH = "/v1/" + (sys.argv[5] if len(sys.argv) > 5 else "secret/data/busbar").strip("/")

# Wrong on purpose, and named so a probe failure reads as what it is rather than as a mystery string
# arriving upstream. A plugin that returns one of these instead of FIELD gets a 401 from the mock.
DECOY_BEFORE = "aaa_not_the_configured_field"
DECOY_AFTER = "zzz_not_the_configured_field"
DECOY_VALUE = "WRONG-FIELD-the-plugin-ignored-the-field-setting"


def envelope():
    # Insertion order is preserved by dict and by json.dumps, so the real field is neither first nor
    # last: a plugin that grabs "the one value in there" cannot accidentally be right.
    data = {DECOY_BEFORE: DECOY_VALUE, FIELD: VALUE, DECOY_AFTER: DECOY_VALUE}
    return {"data": {"data": data, "metadata": {"version": 1, "destroyed": False}}}


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Token first, then path: the same order a real Vault answers in, so a plugin sending a bad
        # token to a bad path still sees the 403 it would see in production.
        if self.headers.get("X-Vault-Token") != EXPECTED_TOKEN:
            self._send(403, {"errors": ["permission denied"]})
            return
        # EXACT match on the path, query stripped. A prefix match would answer
        # /v1/secret/data/busbar-something-else, which is not the path the config names.
        if self.path.split("?", 1)[0].rstrip("/") != PATH.rstrip("/"):
            self._send(404, {"errors": []})
            return
        self._send(200, envelope())

    def log_message(self, *_a):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

#!/usr/bin/env python3
"""A telemetry sink fixture for the export-plugin functional probe.

busbar's `export:` instances (request-log-webhook, otlp, ...) POST telemetry to a URL. This is that
URL: it records every POST it receives and exposes the count at GET /received, so the probe can
assert the exporter actually DELIVERED — not merely that busbar booted with it configured. A booted
exporter that never ships a byte is exactly the "it loaded" vs "it works" gap the whole exercise is
about, and only a receiver outside busbar can tell them apart.

A FIXTURE THAT CANNOT SAY NO MAKES THE PROBE VACUOUS (vault-fixture.py and mock-upstream.py state
the rule; it applies here too). The sink used to count ANY POST with no look at the body, so the
probe's claim degraded from "the exporter delivered a request log" to "something POSTed to this
port". An exporter that shipped `{}`, or an empty body, or somebody else's telemetry, or a stray
health check from a process that happened to find the port, all read as delivery — which is the
it-loaded-vs-it-works gap one layer further in.

So the sink VALIDATES THE SHAPE and counts only what conforms. The shape is busbar's request-log
record, one flat JSON object POSTed per completed request:

  {"ts": <uint>, "ingress_protocol": <str>, "pool": <str>, "outcome": <str>, "latency_ms": <uint>}

built by `build_request_log` in crates/busbar-core/src/export/mod.rs (the five ExportField tokens are
crates/busbar-plugin/src/cold/export.rs), delivered as one `application/json` POST per request by
crates/busbar-core/src/export/webhook.rs, documented in docs/configuration.md's `request-log-webhook`
row, and pinned by crates/busbar-core/src/export/tests/webhook_tests.rs. `outcome` is the closed
vocabulary of crates/busbar-substrate/src/telemetry.rs.

WHAT IS AND IS NOT REQUIRED. All five fields are required, because with no `fields:` key in config —
what probe-export.sh writes — the projection is the full produced set. Unknown keys are rejected:
this fixture is the *request-log* shape and nothing else, and silently tolerating extra keys is how a
sink stops being able to tell one exporter's payload from another's. `otlp` is deliberately NOT
accepted here — it is protobuf OTLP/HTTP, not this JSON, and a sink that accepted both would prove
nothing about either.

Malformed bodies are NOT counted, and are reported separately at /received so a probe failure says
"the exporter delivered N bodies, none of them a request log" rather than "nothing arrived".

Usage: export-sink.py <port>
  GET  /received  -> {"count": N, "last_bytes": B, "rejected": R, "last_reject": "<why>"}
  POST <anything> -> 200 and counted if it is a request-log record; 400 and REJECTED otherwise
Self-contained, no external services, stdlib only.
"""
import http.server
import json
import sys
import threading

PORT = int(sys.argv[1])
STATE = {"count": 0, "last_bytes": 0, "rejected": 0, "last_reject": ""}
LOCK = threading.Lock()

# name -> predicate on the decoded JSON value. bool is excluded from the integer fields on purpose:
# `True` is an int in Python, and a sink that accepted {"ts": true} would be validating nothing about
# ts at all.
def _uint(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _str(v):
    return isinstance(v, str)


# The closed outcome vocabulary (busbar-substrate/src/telemetry.rs). Pinned rather than "any string":
# a typo'd or renamed outcome is a real change in what the exporter ships.
OUTCOMES = ("ok", "exhausted", "client_error", "error")
FIELDS = {
    "ts": _uint,
    "ingress_protocol": _str,
    "pool": _str,
    "outcome": lambda v: _str(v) and v in OUTCOMES,
    "latency_ms": _uint,
}


def why_invalid(raw: bytes):
    """None if `raw` is a request-log record; otherwise a short reason naming what is wrong."""
    if not raw:
        return "empty body"
    try:
        rec = json.loads(raw)
    except Exception as exc:
        return f"not JSON ({exc.__class__.__name__})"
    if not isinstance(rec, dict):
        return f"not a JSON object (got {type(rec).__name__}); the request log is one flat object per request"
    missing = sorted(k for k in FIELDS if k not in rec)
    if missing:
        return "missing required field(s): " + ", ".join(missing)
    extra = sorted(k for k in rec if k not in FIELDS)
    if extra:
        return "unexpected field(s) for a request-log record: " + ", ".join(extra)
    wrong = sorted(k for k, ok in FIELDS.items() if not ok(rec[k]))
    if wrong:
        return "field(s) of the wrong type or outside the allowed values: " + ", ".join(wrong)
    return None


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        reason = why_invalid(raw)
        with LOCK:
            if reason is None:
                STATE["count"] += 1
                STATE["last_bytes"] = length
            else:
                STATE["rejected"] += 1
                STATE["last_reject"] = reason
        # 400, not 200: the exporter is told its payload was refused. A sink that answers 200 to a
        # malformed body and quietly drops it teaches the sender nothing.
        self.send_response(200 if reason is None else 400)
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

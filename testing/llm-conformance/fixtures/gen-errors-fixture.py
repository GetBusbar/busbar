#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""One-shot generator for testing/llm-conformance/fixtures/selftest-errors-recording.

Not part of the test run itself (selftest.sh never calls this) — it is the tool that produced the
tracked fixture below, kept so the fixture can be regenerated/extended by hand later instead of
hand-editing raw bytes. Run it and `git status` the fixture dir to see what changed.

This fixture proves two things the tracked fixtures/selftest-recording fixture does not exercise:

  1. gemini's `ok_stream_array` outcome (a request WITHOUT ?alt=sse, which per the Gemini API is
     served as a JSON ARRAY of GenerateContentResponse objects, not one object and not SSE) is
     validated element-by-element against GenerateContentResponse — not against the single-object
     schema, which would reject any array on sight.
  2. every error outcome (malformed, unauthenticated, out_of_scope, over_budget, upstream_down) is
     judged against the dialect's ERROR envelope, not its success schema. Proof: each error body
     here is deliberately something the SUCCESS schema (GenerateContentResponse, additionalProperties
     false, no "error" property) would reject outright — if the row PASSES, the checker used the
     error schema, not the success one.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "selftest-errors-recording")

REQUEST_BODY = json.dumps({"contents": [{"parts": [{"text": "ping"}], "role": "user"}]}, separators=(",", ":"))

# Two elements so the "malformed element" selftest case can mutate ONLY element [1] and prove the
# violation names that index, not just "somewhere in the array".
STREAM_ARRAY_BODY = json.dumps([
    {"candidates": [{"content": {"parts": [{"text": "oracle-marker-0"}], "role": "model"}, "finishReason": "STOP", "index": 0}],
     "modelVersion": "m-gemini", "usageMetadata": {"candidatesTokenCount": 7, "promptTokenCount": 11, "totalTokenCount": 18}},
    {"candidates": [{"content": {"parts": [{"text": "oracle-marker-1"}], "role": "model"}, "finishReason": "STOP", "index": 0}],
     "modelVersion": "m-gemini", "usageMetadata": {"candidatesTokenCount": 5, "promptTokenCount": 11, "totalTokenCount": 16}},
], separators=(",", ":"))

# google.rpc.Status envelopes (schemas/google-rpc-status.json). Each of these would fail
# GenerateContentResponse (additionalProperties: false, no "error" property declared) — that is the
# point: PASS here only happens if the checker picked the error schema.
ERROR_BODIES = {
    "malformed": (400, {"error": {"code": 400, "message": "request body could not be decoded", "status": "INVALID_ARGUMENT"}}),
    "unauthenticated": (400, {"error": {"code": 400, "message": "API key not valid", "status": "UNAUTHENTICATED"}}),
    "out_of_scope": (403, {"error": {"code": 403, "message": "the credential lacks a required scope", "status": "PERMISSION_DENIED"}}),
    "over_budget": (429, {"error": {"code": 429, "message": "bucket budget exhausted", "status": "RESOURCE_EXHAUSTED"}}),
    "upstream_down": (503, {"error": {"code": 503, "message": "upstream unavailable", "status": "UNAVAILABLE"}}),
}


def write_bytes(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))


def headers_block(status_line, ct):
    return (f"HTTP/1.1 {status_line}\r\ncontent-type: {ct}\r\n"
            "date: Fri, 04 Sep 2026 20:35:30 GMT\r\n\r\n")


STATUS_TEXT = {200: "200 OK", 400: "400 Bad Request", 403: "403 Forbidden", 429: "429 Too Many Requests", 503: "503 Service Unavailable"}


def cell_id(outcome):
    return f"llm|gemini|gemini|request|{outcome}"


def safe(cid):
    return cid.replace("|", "__")


def write_cell(outcome, status, body_obj, has_request):
    cid = cell_id(outcome)
    s = safe(cid)
    body_text = json.dumps(body_obj, separators=(",", ":")) if not isinstance(body_obj, str) else body_obj
    cell = {
        "body": {"json": body_obj} if not isinstance(body_obj, str) else {"text": body_obj},
        "headers": {"content-type": "application/json"},
        "status": status,
    }
    write_bytes(os.path.join(ROOT, "cells", s + ".json"), json.dumps(cell, separators=(",", ":")))
    write_bytes(os.path.join(ROOT, "raw", s, "body"), body_text)
    write_bytes(os.path.join(ROOT, "raw", s, "headers"), headers_block(STATUS_TEXT[status], "application/json"))
    if has_request:
        write_bytes(os.path.join(ROOT, "raw", s, "request.body"), REQUEST_BODY)
    return {
        "cross_protocol": False, "egress_dialect": "gemini", "family": "llm.wire", "id": cid,
        "ingress_dialect": "gemini", "op": "chat", "outcome": outcome, "plane": "llm", "transport": "http",
        "why": "selftest fixture: proves the ok_stream_array / error-outcome validator paths",
    }


def main():
    cells = []
    # 1. ok_stream_array: a valid array of two GenerateContentResponse objects.
    cells.append(write_cell("ok_stream_array", 200, json.loads(STREAM_ARRAY_BODY), has_request=True))
    # 2. every error outcome, each with a body that only passes if judged against the error schema.
    m_status, m_body = ERROR_BODIES["malformed"]
    cells.append(write_cell("malformed", m_status, m_body, has_request=False))
    for outcome in ("unauthenticated", "out_of_scope", "over_budget", "upstream_down"):
        status, body = ERROR_BODIES[outcome]
        cells.append(write_cell(outcome, status, body, has_request=True))

    write_bytes(os.path.join(ROOT, "cells.json"), json.dumps({"cells": cells}, indent=1))
    write_bytes(os.path.join(ROOT, "meta.json"), json.dumps({"binary": "fixture", "version": "busbar 1.5.5 (fixture cells)", "recorded": len(cells)}, indent=1))
    ledger_lines = "".join(f"{c['id']}\tPASS\tHTTP {ERROR_BODIES.get(c['outcome'], (200,))[0]} (fixture)\t\n" for c in cells)
    write_bytes(os.path.join(ROOT, "ledger.tsv"), ledger_lines)
    print(f"wrote {len(cells)} cells to {ROOT}")


if __name__ == "__main__":
    main()

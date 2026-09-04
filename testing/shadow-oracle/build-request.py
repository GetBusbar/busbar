#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Build the CLIENT-SIDE ingress request for one LLM oracle cell.

The request shape is fixed by each dialect's wire protocol (what a real client sends busbar), not by
our config — so this is independent of the oracle's busbar configuration. busbar's route table fixes
the INGRESS dialect by path; the `model` (`m-<egress_dialect>`) selects the lane and therefore the
EGRESS dialect. ingress != egress is a cross-protocol cell.

Reads a cell (JSON on stdin or --cell '<json>') and prints:
  {"method": "POST", "path": "...", "headers": {...}, "body": "<str>", "auth": "bearer"|"sigv4",
   "note": "..."}
The recorder adds the Authorization header for the cell's outcome (or omits it for
`unauthenticated`) and, for `upstream_down`, the X-Oracle-Upstream: down control the mock honors is
NOT sent by the client — the recorder flips the mock instead (busbar must not see a control header).

Named gap: bedrock INGRESS authenticates with SigV4 (busbar verifies AWS-style signatures on that
door), which a bearer key cannot satisfy. Such cells are emitted with auth="sigv4" so the recorder
records them as MOCK-UNSUPPORTED (a visible gap, never a silent pass) until a SigV4 signer is added.
"""
import json
import sys

PING = "ping"


def request_for(cell: dict) -> dict:
    ing = cell["ingress_dialect"]
    model = f"m-{cell['egress_dialect']}"
    oc = cell["outcome"]
    stream = oc == "ok_stream"
    hdr = {"Content-Type": "application/json"}
    auth = "bearer"
    note = ""

    if ing == "anthropic":
        path = "/v1/messages"
        body = {"model": model, "max_tokens": 64, "messages": [{"role": "user", "content": PING}]}
        if stream:
            body["stream"] = True
        hdr["anthropic-version"] = "2023-06-01"
    elif ing == "openai-chat":
        path = "/v1/chat/completions"
        body = {"model": model, "messages": [{"role": "user", "content": PING}]}
        if stream:
            body["stream"] = True
    elif ing == "openai-responses":
        path = "/v1/responses"
        body = {"model": model, "input": PING}
        if stream:
            body["stream"] = True
    elif ing == "gemini":
        verb = "streamGenerateContent?alt=sse" if stream else "generateContent"
        path = f"/v1beta/models/{model}:{verb}"
        body = {"contents": [{"role": "user", "parts": [{"text": PING}]}]}
    elif ing == "bedrock":
        path = f"/model/{model}/{'converse-stream' if stream else 'converse'}"
        body = {"messages": [{"role": "user", "content": [{"text": PING}]}]}
        auth = "sigv4"
        note = "bedrock ingress is SigV4-authenticated; needs a signer (named gap)"
    elif ing == "cohere":
        path = "/v2/chat"
        body = {"model": model, "messages": [{"role": "user", "content": PING}]}
        if stream:
            body["stream"] = True
    else:
        raise SystemExit(f"unknown ingress dialect {ing!r}")

    if oc == "malformed":
        raw = "{this is not json"
        note = (note + "; " if note else "") + "malformed body: decode must refuse with the dialect's native 400"
    else:
        raw = json.dumps(body, separators=(",", ":"), sort_keys=True)

    return {"method": "POST", "path": path, "headers": hdr, "body": raw, "auth": auth, "note": note}


def main() -> int:
    if "--cell" in sys.argv:
        cell = json.loads(sys.argv[sys.argv.index("--cell") + 1])
    else:
        cell = json.load(sys.stdin)
    print(json.dumps(request_for(cell), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

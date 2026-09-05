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
import os
import sys

PING = "ping"

# qa/field-inventory.json names the OpenAI dialects `openai` / `responses`; the oracle config
# (oracle-config.sh ORACLE_DIALECTS) and this builder use the fuller `openai-chat` / `openai-responses`.
# One map, applied to both axes, so a cell id never silently targets a model that does not exist.
DIALECT_ALIAS = {"openai": "openai-chat", "responses": "openai-responses"}


def canon(d: str) -> str:
    return DIALECT_ALIAS.get(d, d)


def request_for(cell: dict) -> dict:
    ing = canon(cell["ingress_dialect"])
    model = f"m-{canon(cell['egress_dialect'])}"
    oc = cell["outcome"]
    # `ok_stream_array` is gemini's JSON-array streaming (no `alt=sse`); every other dialect streams
    # one way only, so the array outcome is emitted for gemini ingress alone.
    stream = oc in ("ok_stream", "ok_stream_array")
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
        if stream:
            verb = "streamGenerateContent" if oc == "ok_stream_array" else "streamGenerateContent?alt=sse"
        else:
            verb = "generateContent"
        path = f"/v1beta/models/{model}:{verb}"
        body = {"contents": [{"role": "user", "parts": [{"text": PING}]}]}
    elif ing == "bedrock":
        path = f"/model/{model}/{'converse-stream' if stream else 'converse'}"
        body = {"messages": [{"role": "user", "content": [{"text": PING}]}]}
        auth = "sigv4"
        note = "bedrock ingress is SigV4-authenticated: signed with the cell principal's AWS credential (issue_aws_credential)"
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

    if auth == "sigv4":
        akid, secret, host = os.environ.get("ORACLE_AWS_AKID", ""), os.environ.get("ORACLE_AWS_SECRET", ""), os.environ.get("ORACLE_HOST", "")
        if oc == "unauthenticated" or not akid:
            # unauthenticated: a well-formed SigV4 header for an UNKNOWN AccessKeyId (the constant-time
            # DUMMY_SECRET reject path); an absent header would be the bearer arm's 401 instead
            akid, secret = "AKIAORACLEUNKNOWN000", "not-the-secret"
        hdr.update(sigv4_headers("POST", path, raw.encode(), host, akid, secret))
        auth = "sigv4-signed"

    return {"method": "POST", "path": path, "headers": hdr, "body": raw, "auth": auth, "note": note}


# ── inbound SigV4 (the Bedrock SDK's model): the verifier reads region/service from the Credential
# scope, requires x-amz-date within its skew window, refuses UNSIGNED-PAYLOAD and checks the body
# hash — so sign the real body with the current time.
def sigv4_headers(method: str, path: str, body: bytes, host: str, akid: str, secret: str,
                  region: str = "us-east-1", service: str = "bedrock") -> dict:
    import datetime, hashlib, hmac
    now = datetime.datetime.now(datetime.timezone.utc)
    amzdate, datestamp = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    signed = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amzdate}
    signed_headers = ";".join(sorted(signed))
    canonical_headers = "".join(f"{k}:{signed[k].strip()}\n" for k in sorted(signed))
    canonical = "\n".join([method, uri_encode_path(path), "", canonical_headers, signed_headers, payload_hash])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = hmac.new(("AWS4" + secret).encode(), datestamp.encode(), hashlib.sha256).digest()
    for part in (region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    return {"x-amz-date": amzdate, "x-amz-content-sha256": payload_hash,
            "Authorization": f"AWS4-HMAC-SHA256 Credential={akid}/{scope}, SignedHeaders={signed_headers}, Signature={sig}"}


def uri_encode_path(path: str) -> str:
    # SigV4 canonical URI: each segment percent-encoded except unreserved chars; '/' kept
    from urllib.parse import quote
    return "/".join(quote(seg, safe="-_.~") for seg in path.split("/"))


def main() -> int:
    if "--cell" in sys.argv:
        cell = json.loads(sys.argv[sys.argv.index("--cell") + 1])
    else:
        cell = json.load(sys.stdin)
    print(json.dumps(request_for(cell), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

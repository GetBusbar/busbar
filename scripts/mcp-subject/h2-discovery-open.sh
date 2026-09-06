#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `mcp.rig|h2-discovery-open` -- the MCP plane's DISCOVERY DOCUMENT, over HTTP,
# against the running server.
#
# THE CONTRACT. `crates/busbar-plane-mcp/src/claims.rs` declares
# `/.well-known/oauth-protected-resource/mcp` with `open(...)`: a claim with `scheme: None` and an
# EMPTY alternatives list. That is not "a scheme called anonymous" -- it is a surface whose claim
# declares no credential at all, and RFC 9728 requires exactly that, because this document is what a
# caller reads to find out HOW to authenticate. Requiring a credential to read it is a closed loop.
#
# So the served surface owes two things, and this scenario asserts both:
#   1. it ANSWERS -- with a real status and a real body. It used to answer with neither: the decode
#      step read the body before it read the target, so a fetch that carries no body at all read as
#      "nothing has arrived yet" on the one surface where nothing more ever arrives. The plane
#      claimed a route and then held every request to it open until the caller gave up. A hang is
#      not a refusal; it is the absence of a verdict, which is why the timeout below is short and
#      the timeout is itself a FAIL rather than an error.
#   2. it needs NO CREDENTIAL -- the same fetch, with no `authorization` header, is not a 401/403.
#
# WHY A RIG ROW AND NOT ONLY A CRATE TEST. `crates/busbar-plane-mcp/tests/conformance.rs` pins the
# plane's decode/authenticate steps in isolation. It cannot see whether the SHIPPING binary mounts
# the claim, whether the kernel routes an ExactPath selector to it, or whether some earlier layer
# takes the credential decision before the plane is consulted. Those are properties of the composed
# server and only a request to a real listener can tell you about them. That is this row's job.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/discovery-open.$$}"
trap 'h2_stop' EXIT

H2_GROUPS_YAML="groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }"

h2_boot "$WORK" "$H2_GROUPS_YAML" || { echo "FAIL	boot failed, see $WORK/busbar.log" ; exit 1; }

failures=0
detail=""

# The path is the plane's own constant (busbar-plane-mcp::claims::DEFAULT_METADATA), spelled here
# once. A rename in the crate that this rig did not follow should show up as a 404 on this row, not
# as a silently-skipped assertion.
META_PATH="/.well-known/oauth-protected-resource/mcp"
META_URL="http://127.0.0.1:${H2_DATA_PORT}${META_PATH}"

# --max-time is deliberately SHORT. The defect this row exists to catch is an open request that is
# never answered; a generous timeout would make that defect look like a slow pass on a loaded
# machine. curl exit 28 is the timeout, and it is reported as its own failure line below so a red
# here reads as "never answered" rather than an unexplained empty body.
body_file="${H2_WORKDIR}/meta.json"
status="$(curl -sS -m 10 -o "$body_file" -w '%{http_code}' "$META_URL")"
curl_rc=$?

if [ "$curl_rc" -eq 28 ]; then
  h2_verdict FAIL "the discovery document at ${META_PATH} never answered (curl timed out after 10s) \
-- the plane claims this route and then holds the request open, so a caller learns how to \
authenticate by waiting forever"
  exit 1
fi
if [ "$curl_rc" -ne 0 ]; then
  h2_verdict FAIL "curl failed (exit ${curl_rc}) fetching ${META_PATH}"
  exit 1
fi

# 1. IT ANSWERS. Any 2xx is an answer; a 401/403 is the credential defect (asserted separately
# below so the two failures never blur into one line), and anything else is not an answer at all.
case "$status" in
  2*) ;;
  401|403)
    failures=$((failures+1))
    detail="${detail}status=${status}: the open discovery document demanded a credential -- its \
claim declares no scheme, and a plane may narrow only within the alternatives its claim declares; "
    ;;
  *)
    failures=$((failures+1))
    detail="${detail}status=${status}(want 2xx) for an unauthenticated GET ${META_PATH}; "
    ;;
esac

# 2. IT ANSWERS WITH A BODY. An empty 200 is the same silence as a hang, one layer up: the caller
# still learns nothing about how to authenticate.
if [ ! -s "$body_file" ]; then
  failures=$((failures+1))
  detail="${detail}the document answered ${status} with an EMPTY body -- a caller reads this to \
discover the authorization server, and an empty document names none; "
else
  # It must be a JSON object, and it must carry the one member the whole document exists for: the
  # resource it describes. Parsed, not grepped -- a substring match would accept a 404 page that
  # happened to contain the word.
  resource="$(python3 -c '
import json,sys
try:
    d=json.load(open(sys.argv[1],encoding="utf-8"))
except Exception as e:
    print("UNPARSEABLE:%s"%e); raise SystemExit(0)
if not isinstance(d,dict):
    print("NOTANOBJECT"); raise SystemExit(0)
print(d.get("resource") or "MISSING")' "$body_file")"
  case "$resource" in
    UNPARSEABLE:*|NOTANOBJECT|MISSING)
      failures=$((failures+1))
      detail="${detail}the document is not a protected-resource metadata object (resource=${resource}); "
      ;;
  esac
fi

# 3. NO CREDENTIAL IS NEEDED -- and that is a property of the SURFACE, not of the caller happening
# to hold a good token. Proven by contrast: the same origin's REQUEST surface (the mount) still
# refuses an unauthenticated call. Without this second half, a server that had simply stopped
# authenticating anything at all would pass the assertions above.
mount_status="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -X POST "$H2_CANON" \
  -H 'content-type: application/json' -H 'mcp-method: tools/call' \
  -H 'mcp-protocol-version: 2026-07-28' -H 'Mcp-Name: probe_ping' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"probe_ping","arguments":{"label":"x"}}}')"
case "$mount_status" in
  401|403) ;;
  *)
    failures=$((failures+1))
    detail="${detail}the REQUEST mount answered ${mount_status} to an unauthenticated call (want \
401/403) -- the open document above proves nothing if the whole origin stopped asking; "
    ;;
esac

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "GET ${META_PATH} with no credential answered ${status} with a protected-resource \
metadata object; the request mount still answered ${mount_status} to an unauthenticated call"
else
  h2_verdict FAIL "$detail"
fi

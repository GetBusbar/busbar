#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `a2a.battery|h2-discovery-open` -- the A2A plane's TWO OPEN DISCOVERY DOCUMENTS,
# over HTTP, against the running server.
#
# THE CONTRACT. `crates/busbar-plane-a2a/src/claims.rs` declares exactly two paths with
# `open_http(...)` -- a claim whose `scheme` is None and whose alternatives list is EMPTY:
#
#     /.well-known/agent-card.json                  (the public agent card, A2A spec 5.3)
#     /.well-known/oauth-protected-resource/a2a     (protected-resource metadata, RFC 9728)
#
# and it declares a THIRD, adjacent surface with an ordinary closed claim:
#
#     /a2a/extendedAgentCard                        (the authenticated extended card, A2A spec 5.6)
#
# Both open documents exist to be read BEFORE the caller has a credential -- the card is how a client
# discovers which schemes this agent accepts, and the metadata document is how it discovers the
# authorization server. Demanding a credential for either is a closed loop. The extended card is the
# opposite: it is the one that may only be read WITH a credential, and it is asserted here in the
# same breath so this row proves a DISTINCTION rather than the absence of authentication.
#
# WHAT WENT WRONG, AND WHY IT NEEDS A SERVED-SURFACE ROW. The authenticate step used to decide
# openness from the OPERATION CLASS. Both open documents and the authenticated extended card all
# decode to the same class -- "read a card" -- so the class could not tell them apart. It answered
# for the push callback and for nothing else, and the two open documents were handed a scheme
# alternative their claim does not declare. A plane may narrow only WITHIN the set its claim
# declares, so naming one there is a refusal: a caller reading the card to find out how to
# authenticate was turned away for not having authenticated.
#
# A crate test can pin the plane's authenticate step in isolation. It cannot tell you whether the
# SHIPPING binary mounts these claims, whether the kernel routes an ExactPath selector to them, or
# whether a layer above the plane reaches the credential decision first. Those are properties of the
# composed server, and only a request to a real listener answers them.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/a2a-discovery-open.$$}"
trap 'h2_stop' EXIT

H2_GROUPS_YAML="groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }"

h2_boot "$WORK" "$H2_GROUPS_YAML" || { echo "FAIL	boot failed, see $WORK/busbar.log" ; exit 1; }

failures=0
detail=""
origin="http://127.0.0.1:${H2_DATA_PORT}"

# The paths are the plane's own constants (busbar-plane-a2a::claims P_CARD / P_METADATA /
# P_EXTENDED_CARD), spelled once here. A rename in the crate this rig did not follow shows up as a
# 404 on this row rather than as an assertion that quietly stopped applying.
P_CARD="/.well-known/agent-card.json"
P_METADATA="/.well-known/oauth-protected-resource/a2a"
P_EXTENDED_CARD="/a2a/extendedAgentCard"

# open_doc <path> <required-json-member>
# Fetches with NO authorization header and asserts: it answered (not a hang), it answered 2xx (not
# 401/403), and it answered with a JSON object carrying the member the document exists for. The
# timeout is short and its own failure line: the neighbouring MCP discovery defect presented as an
# unanswered request, and a hang must never read as a slow pass.
open_doc() {
  # Assigned in separate statements, not one `local a=… b=$a`: bash's `local` does not guarantee the
  # earlier name is visible to the later initialiser, and under `set -u` that reads as unbound.
  local path="$1"
  local member="$2"
  local url="${origin}${path}"
  local f status rc got
  f="${H2_WORKDIR}/$(basename "$path").body"
  status="$(curl -sS -m 10 -o "$f" -w '%{http_code}' "$url")"; rc=$?
  if [ "$rc" -eq 28 ]; then
    failures=$((failures+1))
    detail="${detail}${path}: never answered (curl timed out after 10s); "
    return
  fi
  if [ "$rc" -ne 0 ]; then
    failures=$((failures+1))
    detail="${detail}${path}: curl failed (exit ${rc}); "
    return
  fi
  case "$status" in
    2*) ;;
    401|403)
      failures=$((failures+1))
      detail="${detail}${path}: answered ${status} to an UNAUTHENTICATED read -- this claim declares \
no scheme, so a credential may not be demanded for it; "
      return
      ;;
    *)
      failures=$((failures+1))
      detail="${detail}${path}: status=${status} (want 2xx); "
      return
      ;;
  esac
  # Parsed, not grepped: a substring test would accept an error page that happened to contain the
  # member name.
  got="$(python3 -c '
import json,sys
try:
    d=json.load(open(sys.argv[1],encoding="utf-8"))
except Exception as e:
    print("UNPARSEABLE:%s"%e); raise SystemExit(0)
if not isinstance(d,dict):
    print("NOTANOBJECT"); raise SystemExit(0)
v=d.get(sys.argv[2])
print("MISSING" if v in (None,"",[],{}) else "OK")' "$f" "$member")"
  if [ "$got" != OK ]; then
    failures=$((failures+1))
    detail="${detail}${path}: answered ${status} but is not a document carrying '${member}' (${got}); "
  fi
}

# The public card must name the agent it describes; the metadata document must name the resource it
# protects. An empty 200 is the same silence as a hang, one layer up.
open_doc "$P_CARD" "name"
open_doc "$P_METADATA" "resource"

# THE OTHER HALF. The extended card is the adjacent surface whose claim IS closed. Without this,
# a server that had simply stopped authenticating everything would pass every assertion above.
ext_status="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' "${origin}${P_EXTENDED_CARD}")"
case "$ext_status" in
  401|403) ;;
  *)
    failures=$((failures+1))
    detail="${detail}${P_EXTENDED_CARD}: answered ${ext_status} to an UNAUTHENTICATED read (want \
401/403) -- the two open documents above prove a distinction only if this one still asks; "
    ;;
esac

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "both open discovery documents (${P_CARD}, ${P_METADATA}) answered 2xx with a \
real document and no credential; ${P_EXTENDED_CARD} still answered ${ext_status}"
else
  h2_verdict FAIL "$detail"
fi

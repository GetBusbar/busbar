#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `a2a.battery|h2-verify-refusal` -- H2 (ARCHITECTURE.md #2.2 step 2, VERIFY) for the
# A2A plane. Proves the Teller order at step 2: a credential that AUTHENTICATEs fine but holds no
# `agent` grant for the registered agent is refused BEFORE step 4 (ADMIT) ever draws a bucket -- no
# egress reaches the fronted agent, no usage delta.
#
# THE GRANT MECHANISM: as on the sibling MCP plane (scripts/mcp-subject/h2-verify-refusal.sh), the
# admin `POST /api/v1/admin/keys` mint has no per-kind `allowed_agents` field on this release --
# only `allowed_pools`. What it DOES expose is the documented C6 cross-kind rule
# (`busbar-api::VirtualKey::scope_allowed`): an OMITTED `allowed_pools` grants every scope kind: an
# EXPLICIT EMPTY list grants NONE of them, of any kind. `"allowed_pools": []` therefore mints a key
# that genuinely holds no `agent` grant, through the admin API exactly as an operator issuing a
# zero-entitlement key would.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/a2a-verify-refusal.$$}"
trap 'h2_stop' EXIT

H2_GROUPS_YAML="groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }"

h2_boot "$WORK" "$H2_GROUPS_YAML" || { echo "FAIL	boot failed, see $WORK/busbar.log" ; exit 1; }

failures=0
detail=""

mint_body="{\"name\":\"h2-noscope\",\"group\":\"h2-oracle\",\"allowed_pools\":[]}"
mint_resp="$(curl -sS -m 10 -X POST "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/keys" \
  -H "Authorization: Bearer $H2_ADMIN_TOKEN" -H 'Content-Type: application/json' -d "$mint_body")"
kid="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("id") or "")' <<<"$mint_resp")"
tok="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("token") or "")' <<<"$mint_resp")"
if [ -z "$kid" ] || [ -z "$tok" ]; then
  h2_verdict FAIL "mint with allowed_pools:[] failed: $mint_resp"
  exit 1
fi
bound="$(h2_bind "$tok")"

egress_before="$(h2_egress_count)"
usage_before="$(h2_usage "$kid")"

read -r verify_status verify_body <<<"$(h2_call "$bound" "verify-probe")"
[ "$verify_status" = "403" ] || { failures=$((failures+1)); detail="${detail}verify_status=${verify_status}(want 403, NotInScope's documented status); "; }
case "$verify_body" in
  *"not granted"*) ;;
  *) failures=$((failures+1)); detail="${detail}verify_body missing 'not granted': ${verify_body}; " ;;
esac

egress_after="$(h2_egress_count)"
[ "$egress_after" -eq "$egress_before" ] || { failures=$((failures+1)); detail="${detail}egress_delta=$((egress_after-egress_before))(want 0); "; }

usage_after="$(h2_usage "$kid")"
req_before="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("requests") or 0)' <<<"$usage_before")"
req_after="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("requests") or 0)' <<<"$usage_after")"
[ "$req_before" -eq "$req_after" ] || { failures=$((failures+1)); detail="${detail}usage_requests_delta=$((req_after-req_before))(want 0); "; }

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "no-grant key refused 403/not-granted before Admit; zero egress; zero usage delta"
else
  h2_verdict FAIL "$detail"
fi

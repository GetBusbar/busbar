#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `mcp.rig|h2-upstream-outage` -- H2 (ARCHITECTURE.md #2.2 step 5, ROUTE) for the MCP
# plane, and the sibling of `a2a.battery|h2-route-failover`. Proves the one fact the plane had no way
# to state: an ADMITTED call whose UPSTREAM is down is surfaced as an upstream failure, and it is
# surfaced as one because the upstream really did refuse.
#
# WHY THIS SCENARIO EXISTS AT ALL. scripts/mcp-subject/h2-mock-upstream.mjs honoured no fault control,
# so nothing in this rig could make the mcp upstream fail. Every h2 scenario here therefore ran
# against a permanently healthy backend, and the plane's `upstream_down` row was a NAMED GAP naming
# this file -- correctly, because the alternative is worse: a recorder that drove an outage cell
# against a healthy upstream would record a 200 and call it an outage, which is a green that asserts
# the opposite of what the cell is for. The a2a sibling has had the control since it was written
# (h2-mock-agent.mjs); this is the mcp half catching up, and the scenario that keeps it honest.
#
# WHAT IT ASSERTS, AND WHY EACH HALF IS LOAD-BEARING:
#   1. armed, a served tools/call does NOT come back a SUCCESS -- and "success" here is a fact about
#      the BODY, not the status line. MCP carries a tool failure IN BAND: busbar answers HTTP 200
#      with `isError: true` and the upstream's own error text, which is the protocol working, not
#      the fault being swallowed. Measured on this rig: armed, the body is
#      `isError:true` + "MCP upstream answered JSON-RPC error -32603: h2 fixture upstream: down";
#      healthy, it is `isError:false` + "ping: <label>". So the assertion is on those two, and a
#      scenario that asserted `status != 200` instead would be RED against a correct busbar --
#      which is how this one was first written, and what the first green run corrected.
#   2. armed, EGRESS GREW. An outage is a request that reached the upstream and was refused, not a
#      request busbar declined to send: without this, a refusal minted anywhere earlier in the chain
#      (admission, scope, budget) would pass step 1 while proving nothing about the upstream. This is
#      why h2-mock-upstream.mjs captures egress BEFORE consulting the control.
#   3. CLEARED, the SAME booted rig serves a healthy 200 again. The control is a per-request switch,
#      not a boot-time mode -- the recorder arms it around one cell and clears it after, and a mock
#      that latched would silently poison every cell recorded after an outage one.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/mcp-upstream-outage.$$}"
trap 'h2_stop' EXIT

H2_GROUPS_YAML="groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }"

h2_boot "$WORK" "$H2_GROUPS_YAML" || { echo "FAIL	boot failed, see $WORK/busbar.log"; exit 1; }

failures=0
detail=""

[ -n "${H2_CONTROL_FILE:-}" ] || { h2_verdict FAIL "h2_boot set no H2_CONTROL_FILE: this rig has no fault control, so the mcp plane cannot state an upstream outage at all"; exit 1; }
[ -f "$H2_CONTROL_FILE" ] || { h2_verdict FAIL "H2_CONTROL_FILE is ${H2_CONTROL_FILE}, which h2_boot did not create"; exit 1; }

read -r kid tok <<<"$(h2_mint h2-oracle)"
[ -n "$tok" ] || { h2_verdict FAIL "mint failed"; exit 1; }
bound="$(h2_bind "$tok")"
[ -n "$bound" ] || { h2_verdict FAIL "bind produced no audience-bound token"; exit 1; }

# ── armed ───────────────────────────────────────────────────────────────────────────────────────
printf 'down' >"$H2_CONTROL_FILE"
egress_before="$(h2_egress_count)"
read -r down_status down_body <<<"$(h2_call "$bound" "outage")"
egress_after="$(h2_egress_count)"

[ -n "$down_status" ] || { failures=$((failures+1)); detail="${detail}no status at all from the armed call; "; }
case "$down_body" in
  *'"isError":true'*) ;;
  *) failures=$((failures+1)); detail="${detail}a call against a DOWN upstream did not come back an error result — the control was not honoured: ${down_status} ${down_body}; " ;;
esac
case "$down_body" in
  *'h2 fixture upstream: down'*) ;;
  *) failures=$((failures+1)); detail="${detail}the error busbar surfaced does not name the upstream's own refusal, so it may have failed for some other reason: ${down_body}; " ;;
esac
[ "$egress_after" -gt "$egress_before" ] || { failures=$((failures+1)); detail="${detail}the armed call added no egress (${egress_before} -> ${egress_after}): the refusal was minted before the upstream was dialled, so it says nothing about an outage; "; }

# ── cleared: the same rig, the same key, a healthy answer ────────────────────────────────────────
: >"$H2_CONTROL_FILE"
read -r up_status up_body <<<"$(h2_call "$bound" "recovered")"
case "$up_body" in
  *'"isError":false'*'ping: recovered'*|*'ping: recovered'*'"isError":false'*) ;;
  *) failures=$((failures+1)); detail="${detail}after clearing the control the same rig did not serve the healthy echo — the fault latched: ${up_status} ${up_body}; " ;;
esac

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "armed, the served tools/call reached the upstream (egress ${egress_before} -> ${egress_after}) and came back an isError result naming the upstream's own refusal; cleared, the same rig served the healthy echo again"
else
  h2_verdict FAIL "$detail"
fi

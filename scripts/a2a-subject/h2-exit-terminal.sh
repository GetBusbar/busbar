#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `a2a.battery|h2-exit-terminal` -- H2 (ARCHITECTURE.md #2.2 step "exit") for the
# A2A plane. Proves the exit path settles EXACTLY ONCE per unit and never double-posts: two served
# `message/send` requests give exactly two usage-request deltas and exactly two new admin audit rows
# -- never zero (a step skipped), never more than two (a double post), never one (a settle merged
# across units).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/a2a-exit-terminal.$$}"
trap 'h2_stop' EXIT

H2_GROUPS_YAML="groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }"

h2_boot "$WORK" "$H2_GROUPS_YAML" || { echo "FAIL	boot failed, see $WORK/busbar.log" ; exit 1; }

failures=0
detail=""

read -r kid tok <<<"$(h2_mint h2-oracle)"
[ -n "$tok" ] || { h2_verdict FAIL "mint failed"; exit 1; }
bound="$(h2_bind "$tok")"

seq_before="$(h2_audit_max_seq)"
usage_before="$(h2_usage "$kid")"

read -r s1 _ <<<"$(h2_call "$bound" "exit-1")"
read -r s2 _ <<<"$(h2_call "$bound" "exit-2")"
[ "$s1" = "200" ] && [ "$s2" = "200" ] || { failures=$((failures+1)); detail="${detail}call statuses: ${s1} ${s2} (want 200 200); "; }

usage_after="$(h2_usage "$kid")"
req_before="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("requests") or 0)' <<<"$usage_before")"
req_after="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("requests") or 0)' <<<"$usage_after")"
req_delta="$((req_after - req_before))"
[ "$req_delta" -eq 2 ] || { failures=$((failures+1)); detail="${detail}usage_requests_delta=${req_delta}(want exactly 2 for two calls -- no double-post, no drop); "; }

audit_rows="$(h2_audit_rows_since "$seq_before" "agent.call" "agent:probe")"
[ "$audit_rows" -eq 2 ] || { failures=$((failures+1)); detail="${detail}new agent.call audit rows=${audit_rows}(want exactly 2, one settle per unit); "; }

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "two served message/send units settle to exactly two usage deltas and exactly two audit rows -- one terminal per unit, never doubled"
else
  h2_verdict FAIL "$detail"
fi

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `a2a.battery|h2-audit-record` -- H2 (ARCHITECTURE.md #2.2 step 7, AUDIT) for the
# A2A plane. Proves the Teller order at step 7: a served `message/send` seals exactly ONE new admin
# audit entry, action `agent.call`, outcome `applied`, resource `agent:<agent_id>` (docs/a2a.md: "The
# admin audit log records one row per admitted call under action `agent.call` / resource
# `agent:<agent_id>`" -- read here off the live chain).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/a2a-audit-record.$$}"
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

read -r call_status _ <<<"$(h2_call "$bound" "audit")"
[ "$call_status" = "200" ] || { failures=$((failures+1)); detail="${detail}call_status=${call_status}(want 200); "; }

new_rows="$(h2_audit_rows_since "$seq_before" "agent.call" "agent:probe")"
[ "$new_rows" -eq 1 ] || { failures=$((failures+1)); detail="${detail}new agent.call rows for agent:probe since seq ${seq_before} = ${new_rows} (want exactly 1); "; }

applied_check="$(curl -sS -m 10 -H "Authorization: Bearer $H2_ADMIN_TOKEN" \
  "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/audit?limit=5" \
  | python3 -c "import json,sys
d=json.load(sys.stdin)
since=$seq_before
items=[r for r in (d.get('items') or []) if r.get('seq',0) > since]
ok = any(r.get('action')=='agent.call' and r.get('outcome')=='applied' and r.get('resource')=='agent:probe' for r in items)
print('yes' if ok else 'no')")"
[ "$applied_check" = "yes" ] || { failures=$((failures+1)); detail="${detail}no new row carried outcome=applied; "; }

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "exactly one new admin audit entry, action agent.call, outcome applied, resource agent:probe"
else
  h2_verdict FAIL "$detail"
fi

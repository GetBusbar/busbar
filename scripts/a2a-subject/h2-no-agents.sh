#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `a2a.battery|h2-no-agents` -- H2 (ARCHITECTURE.md #2.2) for the A2A plane's
# AGENT-LESS deployment: busbar booted with no `agents:` section at all.
#
# WHY THIS SCENARIO EXISTS AT ALL. h2_boot always wrote the `agents:` block and then refused to
# return until the admin API reported `probe` approved, so every scenario in this rig -- and every
# recording driven through it -- ran against a deployment that fronts exactly one agent. The
# configuration where it fronts NONE was unreachable from here, which is why the plane's
# `no-agents-configured` row was a named gap naming h2_boot. h2_boot's third argument closes that,
# and this scenario is what keeps the argument honest: without it, `none` is a code path with no
# caller, and a code path with no caller is a claim.
#
# WHAT IT ASSERTS, AND WHY EACH HALF IS LOAD-BEARING:
#   1. busbar BOOTS. An agent-less deployment is a configuration busbar serves, not an error it
#      rejects -- `mounted_routes` in crates/busbar-a2a/src/a2a/receive.rs returns "an unchanged
#      router when this deployment fronts no agents". A boot that died here would mean the row is
#      about a config that cannot exist, which is a different finding and must not be silent.
#   2. a submission to the agent this deployment does not front is REFUSED, and specifically is not
#      a success.
#   3. ZERO EGRESS. The mock agent is still running and still capturing (see h2_boot's note on why
#      it is deliberately left up), so this is a real measurement rather than a tautology: busbar
#      refused without dialling anything, rather than dialling an agent it had no registration for.
#   4. the config really had no `agents:` key -- asserted against the file h2_boot wrote, because
#      every claim above is worthless if the deployment quietly had an agent after all.
#
# ── WHAT THIS SCENARIO DOES **NOT** ESTABLISH, STATED HERE SO NOTHING READS IT AS MORE ───────────
#
# It does NOT close `a2a|jsonrpc|client|client|SendMessage|no-agents-configured`, and it must not be
# cited as if it did. That cell's expected bytes are written into its own `why` in
# testing/shadow-oracle/cells/__init__.py: `effects.usage: {"requests": 1}` with no spend key -- a
# caller who DREW A SLOT and bought nothing, because the task "resolves to an upstream-shaped
# destination with no lane behind it". MEASURED on this configuration (1.6.0, aarch64-apple-darwin):
# a submission comes back 401 `invalid_api_key` and the key's usage reads `requests: 0`. Nothing is
# metered, because with no `agents:` key the plane MOUNTS NO ROUTES at all, so the audience-bound
# token for /a2a is not recognised and the refusal is minted in auth, upstream of the meter.
#
# So there are two different configurations wearing one name. This scenario pins the one h2_boot can
# now reach -- a deployment that fronts nothing -- and the cell is about a deployment that fronts
# something which resolves to no lane. The row stays a named gap, and it now names a SHARPER thing
# than "h2_boot always registers the probe agent": what is missing is a rig configuration with a
# registered agent whose lane is absent, reaching the meter and drawing one requests-only row.
# (Independently, that cell is `obligation: issue`, which the recorder's plane driver refuses before
# it ever reaches an outcome arm -- the rig observes that half as egress and cannot send it.)
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/a2a-no-agents.$$}"
trap 'h2_stop' EXIT

H2_GROUPS_YAML="groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }"

h2_boot "$WORK" "$H2_GROUPS_YAML" none || { echo "FAIL	the agent-less boot failed, see $WORK/busbar.log"; exit 1; }

failures=0
detail=""

# (4) first, because it is the premise of the other three.
if grep -qE '^agents:' "${H2_WORKDIR}/config.yaml"; then
  failures=$((failures+1))
  detail="${detail}h2_boot wrote an \`agents:\` key under 'none', so this is not the agent-less deployment; "
fi

read -r kid tok <<<"$(h2_mint h2-oracle)"
[ -n "$tok" ] || { h2_verdict FAIL "mint failed"; exit 1; }
bound="$(h2_bind "$tok")"
[ -n "$bound" ] || { h2_verdict FAIL "bind produced no audience-bound token"; exit 1; }

egress_before="$(h2_egress_count)"
read -r status body <<<"$(h2_call "$bound" "no-agents")"
egress_after="$(h2_egress_count)"

case "$status" in
  200) failures=$((failures+1)); detail="${detail}a submission to an agent this deployment does not front came back 200: ${body}; " ;;
  "")  failures=$((failures+1)); detail="${detail}no status at all from the submission; " ;;
  *)   ;;
esac

[ "$egress_after" -eq "$egress_before" ] || { failures=$((failures+1)); detail="${detail}egress grew by $((egress_after-egress_before)) — busbar dialled an upstream it has no registration for; "; }

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "booted with no \`agents:\` section; a submission to the unfronted agent was refused ${status} and dialled nothing (egress stayed ${egress_before}). NOT the no-agents-configured cell's expected {requests:1} — see this file's header"
else
  h2_verdict FAIL "$detail"
fi

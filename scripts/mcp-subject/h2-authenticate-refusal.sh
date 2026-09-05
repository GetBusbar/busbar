#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `mcp.rig|h2-authenticate-refusal` -- H2 (ARCHITECTURE.md #2.2 step 1, AUTHENTICATE)
# for the MCP plane. Proves the Teller order at step 1: a bearer that fails the RFC 8707 audience
# check (or is missing entirely) is refused with the plane's native 401 BEFORE step 2 (VERIFY) is
# ever reached, so no egress reaches the registered upstream and no admission slot is drawn.
#
# docs/mcp.md's own audience-boundary proof (scripts/mcp-subject/boot.sh::prove_the_boundary_is_intact)
# asserts this same contract as a boot-time check on every official-subject run; this script promotes
# it to a NAMED, LEDGERED scenario (see rigs-ledger.sh's run_mcp(), which folds this script's result
# into the `mcp.rig|*` row set) with its own egress-capture proof, independent of that boot path.
#
# RED PROOF (see the report, never executed here): point this script's `H2_CANON` at a busbar built
# from a commit where the audience check is bypassed and the no-credential / wrong-audience probes
# below answer 200 instead of 401 -- the script fails loudly rather than silently passing.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/authenticate-refusal.$$}"
trap 'h2_stop' EXIT

H2_GROUPS_YAML="groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }"

h2_boot "$WORK" "$H2_GROUPS_YAML" || { echo "FAIL	boot failed, see $WORK/busbar.log" ; exit 1; }

failures=0
detail=""

# A tools/call probe, never tools/list: tools/list is answered off busbar's cached catalogue and
# never dials the upstream even when admitted, so it cannot distinguish "refused before dispatch"
# from "admitted, but nothing was dispatched". tools/call is the step that actually reaches Route.
probe() {
  local bearer="$1"
  local -a auth=()
  [ -n "$bearer" ] && auth=(-H "authorization: Bearer $bearer")
  curl -sS -o /dev/null -w '%{http_code}' -m 15 -X POST "$H2_CANON" \
    -H 'content-type: application/json' -H 'mcp-method: tools/call' \
    -H 'mcp-protocol-version: 2026-07-28' -H 'Mcp-Name: probe_ping' "${auth[@]}" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"probe_ping","arguments":{"label":"probe"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
}

egress_before="$(h2_egress_count)"

got_none="$(probe "")"
[ "$got_none" = "401" ] || { failures=$((failures+1)); detail="${detail}no-credential->${got_none}(want 401); "; }

# A garbage bearer that decodes to nothing busbar minted.
got_garbage="$(probe "not-a-real-token")"
[ "$got_garbage" = "401" ] || { failures=$((failures+1)); detail="${detail}garbage-bearer->${got_garbage}(want 401); "; }

# A real key, bound to the WRONG audience.
read -r kid tok <<<"$(h2_mint h2-oracle)"
if [ -z "$tok" ]; then
  failures=$((failures+1)); detail="${detail}mint failed; "
else
  wrong_bound="$(node "${here}/mint-audience-token.mjs" "$H2_SIGNING_KEY" "$tok" "http://127.0.0.1:${H2_DATA_PORT}/mcp-not-this-resource")"
  got_wrong="$(probe "$wrong_bound")"
  [ "$got_wrong" = "401" ] || { failures=$((failures+1)); detail="${detail}wrong-audience->${got_wrong}(want 401); "; }

  # The control: the SAME key, bound to the RIGHT audience, must be admitted -- otherwise the three
  # refusals above are equally consistent with a busbar that refuses everything, which would make
  # this whole scenario vacuous.
  right_bound="$(h2_bind "$tok")"
  got_right="$(probe "$right_bound")"
  [ "$got_right" = "200" ] || { failures=$((failures+1)); detail="${detail}right-audience->${got_right}(want 200); "; }
fi

egress_after="$(h2_egress_count)"
egress_delta="$((egress_after - egress_before))"
# Exactly one egress request is expected: the ONE successful control probe above. Any egress beyond
# that means one of the three refused probes reached the upstream before being refused.
[ "$egress_delta" -eq 1 ] || { failures=$((failures+1)); detail="${detail}egress_delta=${egress_delta}(want 1, i.e. only the admitted control reached the upstream); "; }

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "no-credential, garbage-bearer and wrong-audience all 401; right-audience 200; egress delta 1 (only the admitted control)"
else
  h2_verdict FAIL "$detail"
fi

#!/usr/bin/env bash
# SCRATCH DIAGNOSTIC (draft PR, never to land): one MCP h2 call on a billing-ON node with every
# reading dumped, and the A2A subject's answer to the TCK's first send. Compact, at the end.
set -uo pipefail
cd "$(dirname "$0")/.."
R="$(pwd)"; D="$R/target/vd-diag"; rm -rf "$D"; mkdir -p "$D"
cargo build --release --locked -p busbar >"$D/build.out" 2>&1; brc=$?
export MCP_SUBJECT_BUSBAR_BIN="$R/target/release/busbar"
(
  source scripts/mcp-subject/h2-lib.sh
  trap 'h2_stop' EXIT
  H2_GROUPS='groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }'
  h2_boot "$D/mcp" "$H2_GROUPS" >"$D/mcp-boot.out" 2>&1 || { echo "MCP BOOT FAILED"; tail -n 8 "$D/mcp/busbar.log"; exit 0; }
  read -r kid tok <<<"$(h2_mint h2-oracle)"
  bound="$(h2_bind "$tok")"
  echo "USAGE before: $(h2_usage "$kid" | cut -c1-300)"
  echo "CALL: $(h2_call "$bound" meter | cut -c1-300)"
  sleep 3
  echo "USAGE after: $(h2_usage "$kid" | cut -c1-400)"
  echo "ADMIN usage: $(curl -sS -m 10 -H "Authorization: Bearer $H2_ADMIN_TOKEN" "http://127.0.0.1:${H2_ADMIN_PORT}/api/v1/admin/usage" | cut -c1-700)"
  echo "BUSBAR log:"; grep -viE "^\s*$" "$D/mcp/busbar.log" | tail -n 12 | cut -c1-260
) >"$D/mcp.diag" 2>&1
bash testing/shadow-oracle/rigs-ledger.sh --bin target/release/busbar --check >"$D/rigs.out" 2>&1
G=target/rigs-ledger
echo "######## SUMMARY ########"
echo "BUILD rc=$brc"
cat "$D/mcp.diag"
echo "== A2A subject logs"; ls "$G/a2a-tck-work" | tr '\n' ' '; echo
for f in $(find "$G/a2a-tck-work" -maxdepth 3 -name '*.log' 2>/dev/null | grep -v venv | head -n 6); do echo "-- $f"; grep -iE "decode|refus|400|error" "$f" | sort | uniq -c | sort -rn | head -n 4 | cut -c1-260; done
exit 1

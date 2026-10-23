#!/usr/bin/env bash
# SCRATCH DIAGNOSTIC (draft PR, never to land): the plane-rig ledger's reds, by family, and the
# MCP h2 money legs' own words. Compact output at the end of the log.
set -uo pipefail
cd "$(dirname "$0")/.."
R="$(pwd)"; D="$R/target/vd-diag"; rm -rf "$D"; mkdir -p "$D"
cargo build --release --locked -p busbar >"$D/build.out" 2>&1; brc=$?
bash testing/shadow-oracle/rigs-ledger.sh --bin target/release/busbar --check >"$D/rigs.out" 2>&1; rrc=$?
L=target/rigs-ledger/ledger.tsv
echo "######## SUMMARY ########"
echo "BUILD rc=$brc RIGS rc=$rrc"
awk -F'\t' '{split($1,a,"|"); k=a[1]; if (a[1]=="baseline") k="baseline:" a[2]; c[k" "$2]++} END{for (x in c) print c[x], x}' "$L" | sort -k2 | tr '\n' ';'; echo
echo "TCK FAIL ids: $(awk -F'\t' '$1 ~ /^a2a.tck\|/ && $2=="FAIL"{sub(/^a2a.tck\|/,"",$1); printf "%s ", $1}' "$L" | cut -c1-900)"
echo "BATTERY non-pass: $(awk -F'\t' '$1 ~ /^a2a.battery\|/ && $2!="PASS" && $2!="SKIP"{sub(/^a2a.battery\|/,"",$1); printf "%s(%s) ", $1, $4}' "$L" | cut -c1-400)"
echo "MCP non-pass: $(awk -F'\t' '$1 ~ /^mcp.rig\|/ && $2!="PASS" && $2!="SKIP"{sub(/^mcp.rig\|/,"",$1); printf "%s ", $1}' "$L" | cut -c1-300)"
awk -F'\t' '$1=="mcp.rig|h2-meter-row"||$1=="mcp.rig|h2-exit-terminal"{print $1": "substr($4,1,420)}' "$L"
grep -E "control-scenario|ceiling|MUST requirements|battery test ids|scenarios:" "$D/rigs.out" | head -n 5 | cut -c1-200
tail -n 30 target/rigs-ledger/a2a-tck.log 2>/dev/null | grep -iE "passed|failed|error" | tail -n 4 | cut -c1-200
exit 1

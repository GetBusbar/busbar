#!/usr/bin/env bash
# SCRATCH DIAGNOSTIC (draft PR, never to land): why each voice leg and each plane rig is red,
# compact, at the very end of the log (the measurement keeps only the tail).
set -uo pipefail
cd "$(dirname "$0")/.."
R="$(pwd)"; D="$R/target/vd-diag"; rm -rf "$D"; mkdir -p "$D"
bash testing/voice-conformance/voice-conformance.sh >"$D/voice.out" 2>&1; vrc=$?
cargo build --release --locked -p busbar >"$D/build.out" 2>&1; brc=$?
bash testing/shadow-oracle/rigs-ledger.sh --bin target/release/busbar --check >"$D/rigs.out" 2>&1; rrc=$?
L=target/rigs-ledger/ledger.tsv
echo "######## SUMMARY ########"
echo "VOICE rc=$vrc BUILD rc=$brc RIGS rc=$rrc"
echo "TCK FAIL count: $(awk -F'\t' '$1 ~ /^a2a.tck\|/ && $2=="FAIL"' "$L" | wc -l)"
for f in a2a-tck.log a2a-battery.log mcp-rig.log; do [ -f "target/rigs-ledger/$f" ] && { echo "== $f"; grep -iE "error|refused|connection|traceback|exception|E  " "target/rigs-ledger/$f" | sort | uniq -c | sort -rn | head -n 4 | cut -c1-200; }; done
ls target/rigs-ledger/ | tr '\n' ' '; echo
awk -F'\t' '$1 ~ /^mcp.rig\|h2-/ && $2!="PASS" && $2!="SKIP" {print $1": "substr($4,1,260)}' "$L"
awk -F'\t' '$1=="a2a.battery|adv.deep_nesting" || $1=="a2a.tck|CORE-SEND-001" {print $1": "substr($4,1,260)}' "$L"
echo "== VOICE"
grep -E "^RESULT " "$D/voice.out" | grep -v " PASS" | cut -c1-260 | head -n 20
grep -E "conformance failures|accounting problems" "$D/voice.out" | head -n 2
exit 1

#!/usr/bin/env bash
# SCRATCH DIAGNOSTIC (draft PR, never to land): every voice leg's verdict lines, and the plane-rig
# ledger's reds by family with their reasons. Compact output at the end of the log.
set -uo pipefail
cd "$(dirname "$0")/.."
R="$(pwd)"; D="$R/target/vd-diag"; rm -rf "$D"; mkdir -p "$D"
bash testing/voice-conformance/voice-conformance.sh >"$D/voice.out" 2>&1; vrc=$?
cargo build --release --locked -p busbar >"$D/build.out" 2>&1; brc=$?
bash testing/shadow-oracle/rigs-ledger.sh --bin target/release/busbar --check >"$D/rigs.out" 2>&1; rrc=$?
L=target/rigs-ledger/ledger.tsv
echo "######## SUMMARY ########"
echo "VOICE rc=$vrc BUILD rc=$brc RIGS rc=$rrc"
grep -E "^RESULT " "$D/voice.out" | grep -v " PASS" | cut -c1-300 | head -n 25
grep -E "conformance failures|accounting problems" "$D/voice.out" | head -n 3
awk -F'\t' '{split($1,a,"|"); k=a[1]; if (a[1]=="baseline") k="baseline:" a[2]; c[k" "$2]++} END{for (x in c) print c[x], x}' "$L" 2>/dev/null | sort -k2 | tr '\n' ';'; echo
awk -F'\t' '$2!="PASS" && $2!="SKIP" && $1 !~ /^baseline/ {print $1" "$2" "substr($4,1,220)}' "$L" 2>/dev/null | head -n 40
grep -E "control-scenario|ceiling|MUST requirements|battery test ids|scenarios:|RED|refus" "$D/rigs.out" | head -n 12 | cut -c1-240
tail -n 5 "$D/rigs.out" | cut -c1-240
exit 1

#!/usr/bin/env bash
# SCRATCH DIAGNOSTIC (draft PR, never to land): runs only the voice selftest and the plane rigs and
# prints why each is red, compactly, at the end of the log (a measure keeps only the log's tail).
set -uo pipefail
cd "$(dirname "$0")/.."
D=target/vd-diag; rm -rf "$D"; mkdir -p "$D"
echo "== voice selftest =="
bash testing/voice-conformance/voice-conformance.sh --selftest >"$D/voice.out" 2>&1; vrc=$?
echo "voice rc=$vrc"
echo "== release build =="
cargo build --release --locked -p busbar >"$D/build.out" 2>&1; brc=$?
echo "build rc=$brc"; tail -5 "$D/build.out"
echo "== rigs =="
bash testing/shadow-oracle/rigs-ledger.sh --bin target/release/busbar --check >"$D/rigs.out" 2>&1; rrc=$?
echo "rigs rc=$rrc"
L=target/rigs-ledger/ledger.tsv
echo "######## SUMMARY ########"
echo "RIGS rc=$rrc rows: $(wc -l <"$L" 2>/dev/null) notpass: $(awk -F'\t' '$2!="PASS"&&$2!="N/A"&&$2!="SKIP"' "$L" 2>/dev/null | wc -l)"
awk -F'\t' '$2!="PASS"&&$2!="N/A"&&$2!="SKIP"{printf "R %s %s %s\n",$2,$1,substr($4,1,150)}' "$L" 2>/dev/null | head -n 14
for f in mcp-subject a2a-battery a2a-tck voice; do
  [ -s "target/rigs-ledger/$f.log" ] || continue
  echo "-- $f.log tail"; grep -vE '^\s*$' "target/rigs-ledger/$f.log" | tail -n 4 | cut -c1-200
done
echo "VOICE rc=$vrc"
grep -E "^(error(\[E[0-9]+\])?:|thread '[^']*' panicked)" "$D/voice.out" | sort -u | head -n 4 | cut -c1-300
grep -E ' : (FAIL|NO RESULT)' "$D/voice.out" | sed -E 's/^ *· [^ ]+ : //' | sort | uniq -c | sort -rn | head -n 6 | cut -c1-400
exit 1

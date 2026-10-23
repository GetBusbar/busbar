#!/usr/bin/env bash
# SCRATCH DIAGNOSTIC (draft PR, never to land): the voice legs' remaining reds in full, and the
# whole plane-rig ledger with the fixes. Compact output at the end of the log.
set -uo pipefail
cd "$(dirname "$0")/.."
R="$(pwd)"; D="$R/target/vd-diag"; rm -rf "$D"; mkdir -p "$D"
bash testing/voice-conformance/voice-conformance.sh --selftest >"$D/voice.out" 2>&1; vrc=$?
cargo build --release --locked -p busbar >"$D/build.out" 2>&1; brc=$?
bash testing/shadow-oracle/rigs-ledger.sh --bin target/release/busbar --check >"$D/rigs.out" 2>&1; rrc=$?
L=target/rigs-ledger/ledger.tsv
echo "######## SUMMARY ########"
echo "VOICE rc=$vrc BUILD rc=$brc"
grep -E "^  [a-z-]+: " "$D/voice.out" | tail -n 17 | cut -c1-90
python3 - "$D/voice.out" <<'PY'
import sys,re,ast
t=open(sys.argv[1],encoding="utf-8",errors="replace").read()
m=re.search(r"the session reported (\[.*?\]); want (\[.*?\])", t)
if m:
    try:
        got,want=ast.literal_eval(m.group(1)),ast.literal_eval(m.group(2))
        for i,(g,w) in enumerate(zip(got,want)):
            if g!=w: print(f"METER[{i}] got {g[:150]} | want {w[:150]}")
        if len(got)!=len(want): print("METER len", len(got), len(want))
    except Exception as e: print("METER parse", e)
for pat in [r"a type-tagged frame: [^\n]{0,300}", r"the door answered `far tool call opens[^\n]{0,260}"]:
    m=re.search(pat,t)
    if m: print(m.group(0)[:300])
PY
echo "RIGS rc=$rrc rows=$(wc -l <"$L") notpass=$(awk -F'\t' '$2!="PASS"&&$2!="N/A"&&$2!="SKIP"' "$L" | wc -l)"
awk -F'\t' '$2!="PASS"&&$2!="N/A"&&$2!="SKIP"{printf "R %s %s\n",$1,substr($4,1,110)}' "$L" | head -n 16
exit 1

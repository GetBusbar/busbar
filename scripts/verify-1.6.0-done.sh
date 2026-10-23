#!/usr/bin/env bash
# SCRATCH DIAGNOSTIC (draft PR, never to land): the A2A TCK runner's own errors, the battery's
# deep-nesting case, and the MCP h2 meter leg's node log. Compact, at the very end of the log.
set -uo pipefail
cd "$(dirname "$0")/.."
R="$(pwd)"; D="$R/target/vd-diag"; rm -rf "$D"; mkdir -p "$D"
cargo build --release --locked -p busbar >"$D/build.out" 2>&1; brc=$?
bash testing/shadow-oracle/rigs-ledger.sh --bin target/release/busbar --check >"$D/rigs.out" 2>&1; rrc=$?
G=target/rigs-ledger
echo "######## SUMMARY ########"
echo "BUILD rc=$brc RIGS rc=$rrc"
echo "== TCK log tail"; grep -vE "^\s*ok:" "$G/a2a-tck.log" | grep -iE "fail|error|assert|refus|status|exception|E  " | sort | uniq -c | sort -rn | head -n 10 | cut -c1-230
echo "== TCK fold err"; tail -c 400 "$G/a2a-tck-fold.err" 2>/dev/null; echo
R2=$(ls "$G"/a2a-tck-work/out/*.json 2>/dev/null | head -n 1); echo "report: $R2"
[ -n "$R2" ] && python3 - "$R2" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
s=json.dumps(d)
i=s.find("CORE-SEND-001"); print(s[max(0,i-100):i+700])
PY
echo "== battery deep_nesting"; grep -n -A6 "deep_nesting" "$G/a2a-battery.log" | cut -c1-230 | head -n 10
echo "== mcp h2 meter-row log"; tail -n 14 "$G/mcp-h2-h2-meter-row.log" | cut -c1-230
echo "== mcp h2 meter-row work"; ls "$G/mcp-h2-h2-meter-row" | tr '\n' ' '; echo
f=$(ls "$G"/mcp-h2-h2-meter-row/*.yaml "$G"/mcp-h2-h2-meter-row/*/*.yaml 2>/dev/null | head -n 1); echo "config: $f"; [ -n "$f" ] && grep -nE "billing|rate_card|per_request|fee|ledger|mcp|server" "$f" | head -n 14 | cut -c1-200
exit 1

#!/usr/bin/env bash
# SCRATCH DIAGNOSTIC (draft PR, never to land): with the harness and node fixes, does the voice
# selftest pass, do the h2 busbars boot, and which pythons does the runner have.
set -uo pipefail
cd "$(dirname "$0")/.."
R="$(pwd)"; D="$R/target/vd-diag"; rm -rf "$D"; mkdir -p "$D"
bash testing/voice-conformance/voice-conformance.sh --selftest >"$D/voice.out" 2>&1; vrc=$?
cargo build --release --locked -p busbar >"$D/build.out" 2>&1; brc=$?
nd="$(bash scripts/mcp-conformance.sh --node-bin 2>"$D/node.err")"; nrc=$?
export PATH="$nd:$PATH"
MCP_SUBJECT_BUSBAR_BIN="$R/target/release/busbar" H2_WORK="$D/mh2" bash scripts/mcp-subject/h2-meter-row.sh >"$D/mh2.out" 2>"$D/mh2.err"
A2A_SUBJECT_BUSBAR_BIN="$R/target/release/busbar" H2_WORK="$D/ah2" bash scripts/a2a-subject/h2-meter-row.sh >"$D/ah2.out" 2>"$D/ah2.err"
echo "######## SUMMARY ########"
echo "VOICE rc=$vrc"; grep -E "self-test PASS|^FAIL" "$D/voice.out" | head -n 2 | cut -c1-200
grep -E "^(error(\[E[0-9]+\])?:|thread '[^']*' panicked)" "$D/voice.out" | sort -u | head -n 3 | cut -c1-250
grep -E ' : (FAIL|NO RESULT)' "$D/voice.out" | sed -E 's/^.* : (FAIL|NO RESULT)/\1/' | sort | uniq -c | sort -rn | head -n 4 | cut -c1-300
echo "BUILD rc=$brc NODE rc=$nrc nd=$nd $(node --version 2>&1)"
echo "MCP-H2: $(head -c 300 "$D/mh2.out" | tr '\t\n' '  ')"
grep -vE '^\s*$' "$D/mh2.err" | head -n 4 | cut -c1-220
f="$(find "$D/mh2" -name busbar.log 2>/dev/null | head -1)"; [ -n "$f" ] && grep -vE '^\s*$' "$f" | head -n 4 | cut -c1-220
echo "A2A-H2: $(head -c 300 "$D/ah2.out" | tr '\t\n' '  ')"
grep -vE '^\s*$' "$D/ah2.err" | head -n 4 | cut -c1-220
f="$(find "$D/ah2" -name busbar.log 2>/dev/null | head -1)"; [ -n "$f" ] && grep -vE '^\s*$' "$f" | head -n 4 | cut -c1-220
echo "PY: $(ls /usr/bin/python3* /usr/local/bin/python3* 2>/dev/null | tr '\n' ' ') uv=$(command -v uv) os=$(. /etc/os-release; echo $ID $VERSION_ID) arch=$(uname -m)"
for p in python3.13 python3.12 python3.11 python3.10; do command -v $p >/dev/null && echo "$p -> $($p --version 2>&1) venv=$($p -m venv --help >/dev/null 2>&1 && echo y || echo n)"; done
exit 1

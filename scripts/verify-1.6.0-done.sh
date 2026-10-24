#!/usr/bin/env bash
# SCRATCH DIAGNOSTIC (draft PR, never to land): the A2A subject held up, its card read, and the
# TCK's CORE-SEND-001 request replayed by hand through the shim, with the answers printed.
set -uo pipefail
cd "$(dirname "$0")/.."
R="$(pwd)"; D="$R/target/vd-diag"; rm -rf "$D"; mkdir -p "$D"
cargo build --release --locked -p busbar >"$D/build.out" 2>&1; brc=$?
node_dir="$(bash scripts/mcp-conformance.sh --node-bin 2>"$D/node-pin.log")" && export PATH="${node_dir}:${PATH}"
A2A_SUBJECT_BUSBAR_BIN="$R/target/release/busbar" A2A_SUBJECT_HOLD=1 \
  bash scripts/a2a-subject/boot.sh --probe shim >"$D/probe.log" 2>&1 &
P=$!
for i in $(seq 1 240); do grep -q HOLDING "$D/probe.log" && break; sleep 1; done
SUB=$(sed -n 's/^ *subject endpoint: //p' "$D/probe.log"); AG=$(sed -n 's/^ *fronted agent: *//p' "$D/probe.log")
echo "######## SUMMARY ########"
echo "BUILD rc=$brc subject=$SUB agent=$AG"; grep -E "FAIL|die" "$D/probe.log" | head -n 3
card=$(curl -sS -m 10 "$AG/.well-known/agent-card.json" 2>&1 | head -c 1500); echo "CARD(agent): ${card:0:900}"
card2=$(curl -sS -m 10 "$SUB/.well-known/agent-card.json" 2>&1 | head -c 1500); echo "CARD(root): ${card2:0:600}"
body='{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"ROLE_USER","parts":[{"text":"Hello from TCK"}],"messageId":"tck-complete-task-1"}}}'
for u in "$AG" "$AG/"; do
  echo "== POST $u"; curl -sS -m 15 -o "$D/r.out" -w '%{http_code}\n' -X POST "$u" -H 'content-type: application/json' -H 'A2A-Version: 1.0' -d "$body"; head -c 400 "$D/r.out"; echo
done
echo "== POST $AG/message:send"; curl -sS -m 15 -o "$D/r.out" -w '%{http_code}\n' -X POST "$AG/message:send" -H 'content-type: application/json' -H 'A2A-Version: 1.0' -d '{"message":{"role":"ROLE_USER","parts":[{"text":"Hello from TCK"}],"messageId":"tck-complete-task-2"}}'; head -c 400 "$D/r.out"; echo
kill $P 2>/dev/null; pkill -P $P 2>/dev/null
exit 1

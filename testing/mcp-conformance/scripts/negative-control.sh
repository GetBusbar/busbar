#!/usr/bin/env bash
# NEGATIVE CONTROL: prove the battery actually catches defects.
#
# A battery that only ever runs against a good implementation tells you nothing
# about its own sensitivity. This runs it against deliberately broken fake
# servers and shows which test catches which defect. If a row here goes green,
# the corresponding test has stopped working.
set -uo pipefail
cd "$(dirname "$0")/.."
NODE="$(command -v node)"
printf "%-18s %-36s %s\n" "MODE" "VERDICT" "TESTS THAT FAILED"
for mode in honest no-resulttype noise-on-stdout retired-code bad-icon no-cache-hints sub-no-ack; do
  OUT=$(MCP_FAKE_MODE="$mode" "$NODE" bin/mcp-battery.mjs run --name "fake-$mode" \
    --server-cmd "$NODE $(pwd)/fakepeer/fake-server.mjs" --tier push,pr --role server 2>&1)
  R=$(echo "$OUT" | grep "^results" | sed 's/results *: //')
  F=$(echo "$OUT" | grep -E "^  (FAIL|ERR )" | sed -E 's/^  (FAIL|ERR ) *\[[^]]*\] *//' | tr '\n' ' ')
  printf "%-18s %-36s %s\n" "$mode" "$R" "$F"
done

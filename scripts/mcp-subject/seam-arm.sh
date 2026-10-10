#!/usr/bin/env bash
# ARM ONE SEAM TEST, THEN BECOME THE FRONT-DOOR CLIENT.
#
# This is `MCP_SUBJECT_UPSTREAM_CONFIG_CMD`: the launch command the battery's seam suite substitutes
# for the ordinary server launch. Its contract, from `src/suites/seam.mjs`, is "a command that starts
# the subject as an MCP server with the fake server mounted as an upstream", and MCP standardises no
# way to derive that — which is exactly why the variable exists.
#
# WHAT IT DOES NOT DO IS THE INTERESTING HALF: IT DOES NOT BOOT A BUSBAR.
#
# The obvious reading of the contract is "boot a fresh busbar per test with this mode's fake server
# behind it". That reading cannot prove SEAM.ROLE-ISOLATION-UNDER-UPSTREAM-CRASH. "The front door
# still serves after an upstream died" is a claim about a process that was ALREADY SERVING when the
# upstream died; a busbar booted seconds earlier, for this test, with nothing else in flight, cannot
# demonstrate it — it would answer `server/discover` because it had never done anything else.
#
# So the busbar the seam runs against is THE SAME ONE the rest of the battery has been driving all
# run: same boot, same audience-bound credential, same registrations, same process. The hostile
# upstream is likewise one long-lived process, and the per-test ATTACK is selected by writing a
# control file it reads on every request (see `fakepeer/http-fake-server.mjs`). This script writes
# that file and then execs the ordinary stdio->HTTP adapter.
#
# The cost is stated rather than hidden: seam tests are NOT isolated from each other, because the
# subject is shared. That is the correct trade for these six clauses — every one of them is about
# what a long-lived gateway does when an upstream misbehaves — and a run in which test N's damage
# broke test N+1 is a finding this arrangement can see and a per-test boot could not. The ONE carry-
# over that is not a finding is busbar's verification window (below): reusing a failed verification
# for `verify_ttl` is the documented fail-closed behaviour, so each test waits it out.
#
# Usage: seam-arm.sh [--arm-only] <control-file> <subject-url>
#   --arm-only   arm and exit instead of becoming the client (client-arm.sh arms through this)
#   env: MCP_FAKE_MODE        the attack to arm (default: honest)
#        MCP_FAKE_TRANSCRIPT  where the fake server records every byte it is sent
set -euo pipefail

# NO APOSTROPHES IN THESE TWO MESSAGES, and that is not a style choice. Inside `${n:?word}` bash
# processes the word's quotes even when the whole expansion is itself inside double quotes, so
# `server's` opened a single-quoted region that closed on `subject's` — swallowing the SECOND
# assignment entirely. `url` was then never set, `exec node "$bridge" "$url"` died on `unbound
# variable` under `set -u`, and every seam test saw its peer exit 1 while the arming looked fine.
arm_only=0
[ "${1:-}" = --arm-only ] && { arm_only=1; shift; }
control="${1:?seam-arm.sh needs the fake server control file}"
url="${2:?seam-arm.sh needs the subject MCP endpoint URL}"
mode="${MCP_FAKE_MODE:-honest}"
transcript="${MCP_FAKE_TRANSCRIPT:-}"

here="$(cd "$(dirname "$0")/../.." && pwd)"
bridge="$here/testing/mcp-conformance/scripts/stdio-http-bridge.mjs"

# WRITTEN ATOMICALLY. The upstream reads this file on every request, and a half-written file would
# be read as "no mode armed", i.e. as the honest baseline — an attack silently downgraded to a
# control is the one failure mode here that produces a false GREEN.
arm() {
  local tmp="$control.$$"
  node -e '
    const fs = require("node:fs");
    fs.writeFileSync(process.argv[1], JSON.stringify({
      mode: process.argv[2],
      transcript: process.argv[3] || null,
    }));
  ' "$tmp" "$1" "$2"
  mv -f "$tmp" "$control"
}

# EACH SCENARIO MEETS ITS OWN ATTACK, THROUGH AN APPROVAL BUSBAR HAS JUST VERIFIED.
#
# busbar re-verifies the called upstream on the call path (verify-on-call: a `tools/list`, re-hashed
# against the operator's approved digest) once its last observation is `verify_ttl` old, and inside
# that window it reuses the last verdict, a FAILED verification included: the registration is
# `error` and serves nothing, fail closed (docs/tool-and-agent-trust.md, "Fail-closed"; THE DESIGN
# §11.12's trust lifecycle). That is busbar working as built. What it did to this leg is the defect
# this block removes: the CLI and SEAM scenarios run back to back against ONE shared peer,
# `half-answer` breaks the verification it meets, and every later scenario's call landed inside that
# window and was refused without a byte reaching the peer. Five CLI.HOSTILE scenarios scored
# VACUOUS on a verdict about the PREVIOUS scenario's attack, and a seam `stall` met on a
# VERIFICATION (busbar's own fetch, not the tool call its `timeout:` bounds) outlived the
# scenario's wait and left SEAM.ROLE-ISOLATION's half-answer unreached.
#
# None of these scenarios is named for busbar's trust gate; every one is named for what a CLIENT (or
# a gateway between two roles) does with a hostile server's bytes. busbar does not act on them: it
# relays what an approved tool answered to its caller, and answers nothing on the caller's behalf
# (THE DESIGN, Law 11). So the
# bytes must reach busbar on THIS scenario's own exchange, and where they land is read from the fake
# server's own table (`--mode-methods`), never from a copy:
#
#   * an attack shaped into the TOOL LISTING (an array naming `tools/list`: bad-icon, rugpull,
#     outputschema-lie, ...) is armed FIRST and the window waited out, so busbar's verification
#     fetches THAT listing before the call goes out;
#   * every other attack (`ANY`: a server-initiated request, an MRTR result, a stall, a torn frame)
#     is a defect of what the server ANSWERS, so the window is waited out against the HONEST peer,
#     with no transcript, and one honest call lets busbar verify the approved baseline afresh. The
#     attack is armed only then, and the call that follows passes through the tool the operator
#     approved and meets the attack on the relayed call itself.
#
# Nothing the suite judges is touched: the transcript is armed only with the attack, so the honest
# baseline call leaves no byte in it, and every assertion still reads only what crossed after.
# Skipped when the window is not in the environment (a subject that is not the booted busbar).
ttl="${MCP_SEAM_VERIFY_TTL_S:-0}"
if [ "$ttl" -gt 0 ] 2>/dev/null; then
  fires_on=$(node "$here/testing/mcp-conformance/fakepeer/fake-server.mjs" --mode-methods "$mode") \
    || { printf 'arm: the fake server names no mode %s\n' "$mode" >&2; exit 2; }
  wait_out() { sleep "$((ttl + 1))"; }
  case "$fires_on" in
    *'"tools/list"'*)
      arm "$mode" "$transcript"
      printf 'arm: %s is shaped into the listing; waiting out verify_ttl (%ss) so busbar re-verifies against it\n' "$mode" "$ttl" >&2
      wait_out ;;
    *)
      arm honest ""
      printf 'arm: waiting out verify_ttl (%ss) against the honest peer, then one honest call to verify the approved baseline\n' "$ttl" >&2
      wait_out
      curl -s --max-time 20 -X POST "$url" \
        -H 'content-type: application/json' \
        -H 'accept: application/json, text/event-stream' \
        -H 'mcp-method: tools/call' \
        -H 'mcp-protocol-version: 2026-07-28' \
        -H 'mcp-name: echo' \
        -d '{"jsonrpc":"2.0","id":0,"method":"tools/call","params":{"name":"echo","arguments":{"text":"baseline"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}' >&2 || true
      printf '\n' >&2
      arm "$mode" "$transcript" ;;
  esac
else
  arm "$mode" "$transcript"
fi

[ "$arm_only" = 1 ] && exit 0

# The FIRST request after a mode change respawns the fake server's child, so the attack is live
# before any byte of this test reaches busbar. Nothing here waits for that: the respawn happens
# inside the request that triggers it, so there is no window in which a request could be served by
# the previous mode.
exec node "$bridge" "$url"

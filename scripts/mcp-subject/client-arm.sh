#!/usr/bin/env bash
# ARM ONE CLIENT-ROLE TEST, THEN MAKE BUSBAR BE THE CLIENT.
#
# This is `MCP_SUBJECT_CLIENT_CMD`: the launch command `src/suites/client-role.mjs` substitutes for
# "the subject, running as an MCP client". Its contract, stated in that file's header, is exactly
# one sentence long:
#
#   it must be launchable with a command that connects to a stdio MCP server whose launch command
#   is supplied as the final argv element and in MCP_TARGET_SERVER_COMMAND, and it must then do
#   some ordinary work (discover, list tools, call a tool).
#
# THE HALF OF THAT CONTRACT BUSBAR CANNOT SATISFY, SAID OUT LOUD.
#
# busbar's MCP client direction speaks ONE transport — streamable HTTP, revision `2026-07-28` — and
# deliberately no other. `transport: stdio` is refused at config validation and there is no child
# supervisor in the build, so busbar cannot be handed a stdio launch command and told to run it.
# The final argv element and `MCP_TARGET_SERVER_COMMAND` are therefore READ AND IGNORED here, and
# the SAME fake server is reached over the SAME bytes through `fakepeer/http-fake-server.mjs` — the
# mirror the seam leg already uses. One source of hostility, two transports; the fake server's
# bytes are unchanged in both directions and busbar speaks only the transport it ships.
#
# That substitution is a fact about the subject, not a loosening of the test. Every assertion in
# `client-role.mjs` is read off the fake server's own transcript of what the client put on the
# wire, and the transcript is written by the same `fakepeer/fake-server.mjs` process either way.
#
# IT DOES NOT BOOT A BUSBAR, and that is the same ruling `seam-arm.sh` records. The busbar under
# test is the one `mcp-conformance.sh` booted for this whole run: built from THIS COMMIT, on
# loopback, behind a real audience-bound credential whose plane boundary was disproved before any
# verdict was believed. A gate that boots its subject per test would be slower and no more honest;
# a gate that pointed at a deployment would answer a question about that deployment.
#
# WHAT "ORDINARY WORK" IS FOR A GATEWAY. busbar has no interactive loop to drive: it is a client
# because a caller asked it to be one. So the work is driven through the front door — a `tools/list`
# (which busbar answers from its own catalogue and which therefore never reaches the peer, and that
# is a true statement about busbar's client direction rather than a shortcoming of this script) and
# then a `tools/call` for `echo`, the one front-door request whose whole purpose is to become a
# back-door request. What busbar then emits at the back door is what the suite judges.
#
# Usage: client-arm.sh <control-file> <subject-url> [<fake-server-launch, ignored>]
#   env: MCP_FAKE_MODE        the attack to arm (default: honest)
#        MCP_FAKE_TRANSCRIPT  where the fake server records every byte it is sent
set -euo pipefail

# NO APOSTROPHES IN THESE TWO MESSAGES. Inside `${n:?word}` bash processes the word's quotes even
# when the whole expansion is inside double quotes, so an apostrophe opens a single-quoted region
# that swallows the next assignment whole. `seam-arm.sh` lost an afternoon to exactly that.
control="${1:?client-arm.sh needs the fake server control file}"
url="${2:?client-arm.sh needs the subject MCP endpoint URL}"
mode="${MCP_FAKE_MODE:-honest}"
transcript="${MCP_FAKE_TRANSCRIPT:-}"

# WRITTEN ATOMICALLY, for the reason `seam-arm.sh` gives: the upstream reads this file on every
# request, and a half-written file reads as "no mode armed", i.e. as the honest baseline. An attack
# silently downgraded to a control is the one failure mode here that produces a false GREEN.
tmp="$control.$$"
node -e '
  const fs = require("node:fs");
  fs.writeFileSync(process.argv[1], JSON.stringify({
    mode: process.argv[2],
    transcript: process.argv[3] || null,
  }));
' "$tmp" "$mode" "$transcript"
mv -f "$tmp" "$control"

# THE REQUEST ENVELOPE THIS REVISION REQUIRES, IN FULL, AND EVERY LINE OF IT IS LOAD-BEARING.
#
# `2026-07-28` has no handshake, so `_meta` carries the protocol version and the caller's
# capabilities on EVERY request, and it REQUIRES the request's method and target to be MIRRORED into
# `Mcp-Method` and `Mcp-Name`. busbar enforces both MUSTs at ingress — `-32602` for the missing
# `_meta` members, `-32020` for a header that does not mirror the body — which is exactly what its
# own outbound `envelope()` is built to satisfy in the other direction.
#
# THE FIRST VERSION OF THIS SCRIPT OMITTED `Mcp-Name`, and the run it produced is worth recording
# because it is the failure mode this leg exists to make visible. busbar refused the `tools/call`
# at ingress, so nothing crossed the seam, so the fake server's transcript was EMPTY — and an empty
# transcript satisfies `CLI.NO-RESPONSES-SENT` and four of the hostile clauses VACUOUSLY, because
# every one of them is looking for something that must NOT be in it. What stopped that being read as
# a clean pass was `MCP_NO_SKIPS=1`: the four clauses that need a request to exist said "client sent
# no requests" by name and went red. The vacuity guard caught a defect in the DRIVER, first time out.
#
# The response body goes to STDERR, never stdout: the suite retains a client peer's stderr and this
# is the only place a reader can see whether the front door answered a result or an error.
post() {
  local body="$1" max="$2" method="$3" name="${4:-}"
  local -a namehdr=()
  [ -n "$name" ] && namehdr=(-H "mcp-name: $name")
  printf 'client-arm: POST %s %s\n' "$method" "$name" >&2
  curl -s --max-time "$max" -X POST "$url" \
    -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' \
    -H "mcp-method: $method" \
    -H 'mcp-protocol-version: 2026-07-28' \
    "${namehdr[@]}" \
    -d "$body" >&2 || true
  printf '\n' >&2
}

post '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}' \
  20 tools/list

# THE CALL THAT CROSSES. `echo` is the bare name `subject_write_config` publishes for the battery's
# hostile peer (`publish_as: echo`), because that is the tool `fakepeer/fake-server.mjs` has always
# exposed and busbar's routing key `{server}_{tool}` cannot compose a name with no separator in it.
#
# THE TIMEOUT IS THE SUITE'S, NOT A TUNED ONE. `stall` mode answers nothing at all and the point of
# `CLI.HOSTILE.STALLING-SERVER-DOES-NOT-HANG-FOREVER` is whether BUSBAR gives up; a `--max-time`
# shorter than busbar's own per-upstream deadline would answer that question with curl instead of
# with busbar. 45s is comfortably longer than the 10s deadline the seam registration configures and
# comfortably longer than any honest call, so what ends this request is always busbar.
post '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello from the client-role leg"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}' \
  45 tools/call echo

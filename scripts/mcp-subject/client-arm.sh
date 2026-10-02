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

# THE LIST THAT CROSSES. The front-door `tools/list` above never reaches the peer — busbar answers
# it from the operator's own catalogue, which is correct and is exactly why the CLI.* transcript
# used to contain no `tools/list` at all: `CLI.CACHE.TOLERATES-ABSENT-HINTS` read that silence as
# "client did not call tools/list even against an honest server" about a client that provably does.
# busbar's client direction sends one on exactly one path: the connect/refresh drift check
# (`mcp::connect::refresh`), which fetches the upstream's LIVE tool list to compare against the
# operator's approved digests. That is an OPERATOR's verb, so this script drives it as the operator
# — `POST /api/v1/admin/tools/probe/connect`, against the `probe` registration `boot.sh` points at
# the same fake peer. `probe` and not `seam`, deliberately: the refresh re-hashes what the peer
# serves and lands as DRIFT against the fixture digest, and a drift demotion on `seam` would
# quarantine the registration every SEAM.* clause dispatches through. The transcript the suite
# judges is written by the peer before busbar reaches any verdict about the answer.
#
# Skipped silently when the admin surface is not in the environment — an operator pointing this
# battery at something that is not the booted subject has no admin half to drive, and the scenario
# then reports the absence honestly instead of this script inventing a credential.
#
# RETRIED, up to three times, and the retry is the operator's own move rather than a soft gate.
# The shared hostile peer tears sockets down as a matter of course (`half-answer` kills each
# request; a mode change destroys the previous test's leftovers), and busbar's next send can ride
# a connection that died under it — one transient `error sending request` against a peer that is
# healthy again a moment later. An operator whose connect failed transiently presses the button
# again. Nothing here can fake the verdict: the transcript the scenario reads records only
# requests that genuinely ARRIVED at the peer, so a retry that still never reaches it leaves the
# same honest silence, and the scenario reports it.
# ONLY WHEN THE SUITE ASKS FOR IT (`MCP_ARM_LISTING=1`, set by the one scenario that reads a
# listing off the transcript), and the restraint is load-bearing: the admin plane RATE-LIMITS
# mutations per minute, `connect` is a mutation, and driving it on every one of the fourteen CLI
# arms (each with retries) exhausted the budget before CLI.CACHE.TOLERATES-ABSENT-HINTS -- the one
# scenario that needs the listing -- got its turn: rate_limited for the whole window, read as
# "client did not call tools/list even against an honest server". Gating on the MODE was the first
# attempt and was still wrong: three scenarios run the honest mode, and the two that do not read a
# listing burned the window and then their own 20-second failsafe waiting out a rate limit only
# the third needed to wait for. Every other scenario judges the `tools/call` below and never reads
# a listing.
if [ "${MCP_ARM_LISTING:-}" = "1" ] && [ -n "${MCP_SUBJECT_ADMIN_URL:-}" ] && [ -n "${MCP_SUBJECT_ADMIN_TOKEN:-}" ]; then
  # RETRIED AGAINST THE REAL ORACLE. What the scenario reads is the PEER'S TRANSCRIPT, and this
  # script holds the transcript's path ($transcript) — so the loop stops on the fact that matters
  # (a `tools/list` genuinely ARRIVED at the peer) rather than on a proxy for it. Falls back to the
  # trust view's `"failure":null` when no transcript was armed. Nothing here can fake the verdict:
  # the transcript is written by the peer on arrival, so a retry that never reaches it leaves the
  # same honest silence, and the scenario reports it.
  landed() {
    if [ -n "$transcript" ]; then
      [ -f "$transcript" ] && grep -q '"method":"tools/list"' "$transcript"
    else
      case "${view:-}" in *'"failure":null'*) return 0 ;; *) return 1 ;; esac
    fi
  }
  # UP TO ~75 SECONDS OF PATIENCE, and the number is the rate limiter's, not ours. `connect` sits
  # in the admin plane's CONFIG mutation class — a fixed 10-per-minute window — and the boot-time
  # arming legitimately spends exactly 10 on a fast machine less than a minute before this scenario
  # runs, so the honest first attempt can land in a spent window and be told "retry next minute".
  # An operator told that waits the minute; so does this script. The suite's failsafe for the cache
  # scenario is sized above this ceiling.
  for attempt in 1 2 3 4 5 6 7; do
    printf 'client-arm: POST admin tools/probe/connect, attempt %s (drives busbar'"'"'s own tools/list at the back door)\n' "$attempt" >&2
    view=$(curl -s --max-time 15 -X POST "$MCP_SUBJECT_ADMIN_URL/api/v1/admin/tools/probe/connect" \
             -H "authorization: Bearer $MCP_SUBJECT_ADMIN_TOKEN" || true)
    printf '%s\n' "$view" >&2
    landed && { printf 'client-arm: tools/list confirmed at the peer (attempt %s)\n' "$attempt" >&2; break; }
    case "$view" in
      *rate_limited*) sleep 12 ;;
      *) sleep 1 ;;
    esac
  done
fi

# THE CALL THAT CROSSES. `echo` is the bare name `subject_write_config` publishes for the battery's
# hostile peer (`publish_as: echo`), because that is the tool `fakepeer/fake-server.mjs` has always
# exposed and busbar's routing key `{server}_{tool}` cannot compose a name with no separator in it.
#
# THE TIMEOUT IS THE SUITE'S, NOT A TUNED ONE. `stall` mode answers nothing at all and the point of
# `CLI.HOSTILE.STALLING-SERVER-DOES-NOT-HANG-FOREVER` is whether BUSBAR gives up; a `--max-time`
# shorter than busbar's own per-upstream deadline would answer that question with curl instead of
# with busbar. 45s is comfortably longer than the 10s deadline the seam registration configures and
# comfortably longer than any honest call, so what ends this request is always busbar.
# RETRIED ON EXACTLY ONE SIGNATURE: busbar answering that its own upstream leg could not even be
# SENT (`error sending request`) -- the pooled-connection reuse race, in which nothing reached the
# peer at all. Every other answer, including every hostile mode's deliberate breakage, is taken as
# it stands: those scenarios judge what DID cross, and a stall or a torn socket is the crossing.
# A retry here can fake nothing -- the transcript the suite judges records only real arrivals.
#
# ...AND THE SIGNATURE DID NOT SAY WHAT THE PARAGRAPH ABOVE MEANT. `error sending request` is the
# PREFIX busbar puts on EVERY upstream transport error, so the guard matched the two hostile modes
# whose whole contract is that the request breaks: `stall` answers
# `error sending request: operation timed out` and `half-answer` answers `error sending request:
# client error (SendRequest): connection closed before message completed`. Both were retried three
# times. Two things followed, and both were read off one CI run rather than reasoned about:
#
#   1. THE FALSE OBSERVATION. `hostile.stall.clientExitedWithin25s` reported FALSE about a busbar
#      that gives up in ten seconds, every time -- because this script then did it twice more and
#      blew the suite's 25s failsafe. The scenario judges whether BUSBAR hangs; it was measuring
#      this loop.
#   2. THE TRIP. Each retry is a real dispatch and a real recorded upstream failure. Five failures
#      landed on the `seam` cell inside eighteen seconds -- three of them retries of two tests --
#      which is exactly ADR-0002's default trip predicate (`error_rate >= 0.5` over `min_requests:
#      5` in 30s). The breaker opened, correctly, and fast-failed every later scenario that
#      dispatched through the shared registration: one regression and five VACUOUS seam errors, the
#      red this branch exists to clear. Without the retries those same two tests record two
#      failures and nothing trips.
#
# So the retry is now gated on the MODE, which is what "every hostile mode's deliberate breakage is
# taken as it stands" always meant. In a mode contracted to break the request, a retry cannot tell
# the pooled-connection race from the attack -- it can only multiply the attack.
case "$mode" in
  stall|half-answer) call_attempt_limit=1 ;;
  *) call_attempt_limit=3 ;;
esac
for call_attempt in $(seq 1 "$call_attempt_limit"); do
  answer=$(curl -s --max-time 45 -X POST "$url" \
    -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' \
    -H 'mcp-method: tools/call' \
    -H 'mcp-protocol-version: 2026-07-28' \
    -H 'mcp-name: echo' \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello from the client-role leg"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}' || true)
  printf 'client-arm: POST tools/call echo (attempt %s)\n%s\n' "$call_attempt" "$answer" >&2
  case "$answer" in
    *'error sending request'*) sleep 1 ;;
    *) break ;;
  esac
done

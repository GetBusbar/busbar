#!/usr/bin/env bash
# INCOMPLETE — NOT WIRED, NOT RUN, NOT PROVEN. Stopped mid-build on an owner's change of plan.
# Nothing sets MCP_SUBJECT_UPSTREAM_CONFIG_CMD to this script yet, so the six `SEAM.*` clauses are
# still RED for the reason they were before: no upstream is mounted for the battery to observe.
# What is still missing to finish the job is listed at the foot of this file.
#
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
# broke test N+1 is a finding this arrangement can see and a per-test boot could not.
#
# Usage: seam-arm.sh <control-file> <subject-url>
#   env: MCP_FAKE_MODE        the attack to arm (default: honest)
#        MCP_FAKE_TRANSCRIPT  where the fake server records every byte it is sent
set -euo pipefail

# NO APOSTROPHES IN THESE TWO MESSAGES, and that is not a style choice. Inside `${n:?word}` bash
# processes the word's quotes even when the whole expansion is itself inside double quotes, so
# `server's` opened a single-quoted region that closed on `subject's` — swallowing the SECOND
# assignment entirely. `url` was then never set, `exec node "$bridge" "$url"` died on `unbound
# variable` under `set -u`, and every seam test saw its peer exit 1 while the arming looked fine.
control="${1:?seam-arm.sh needs the fake server control file}"
url="${2:?seam-arm.sh needs the subject MCP endpoint URL}"
mode="${MCP_FAKE_MODE:-honest}"
transcript="${MCP_FAKE_TRANSCRIPT:-}"

here="$(cd "$(dirname "$0")/../.." && pwd)"
bridge="$here/testing/mcp-conformance/scripts/stdio-http-bridge.mjs"

# WRITTEN ATOMICALLY. The upstream reads this file on every request, and a half-written file would
# be read as "no mode armed", i.e. as the honest baseline — an attack silently downgraded to a
# control is the one failure mode here that produces a false GREEN.
tmp="$control.$$"
node -e '
  const fs = require("node:fs");
  fs.writeFileSync(process.argv[1], JSON.stringify({
    mode: process.argv[2],
    transcript: process.argv[3] || null,
  }));
' "$tmp" "$mode" "$transcript"
mv -f "$tmp" "$control"

# The FIRST request after a mode change respawns the fake server's child, so the attack is live
# before any byte of this test reaches busbar. Nothing here waits for that: the respawn happens
# inside the request that triggers it, so there is no window in which a request could be served by
# the previous mode.
exec node "$bridge" "$url"

# ── WHAT IS STILL MISSING, STATED RATHER THAN LEFT TO BE REDISCOVERED ───────────────────────────
#
# 1. `boot.sh:subject_write_config` must gain an OPTIONAL `seam:` registration, written only when
#    `MCP_SEAM_UPSTREAM_URL` is set, exposing one tool with `publish_as: echo`. The `publish_as`
#    override already exists (it is how `greet` is published) and is REQUIRED here: the seam suite
#    calls the bare name `echo`, and busbar's routing key is `{server}_{tool}`, which cannot compose
#    a name with no separator in it. Without it every seam `tools/call` is answered "unknown tool",
#    nothing reaches an upstream, and five of the six clauses go GREEN VACUOUSLY — the exact false
#    green this whole leg exists to refuse.
# 2. `scripts/mcp-conformance.sh:battery_subject` must start `fakepeer/http-fake-server.mjs` on a
#    free port with a control file, export `MCP_SEAM_UPSTREAM_URL` BEFORE `boot_busbar_subject`, and
#    export `MCP_SUBJECT_UPSTREAM_CONFIG_CMD="bash <abs>/seam-arm.sh <control> $SUBJECT_URL"`.
# 3. `src/core/target.mjs:spawnServer()` takes no env, and `src/suites/seam.mjs` therefore never
#    delivers `seamEnv(mode, transcript)` to the launch it spawns — `seamEnv` is dead code and the
#    `upstreamMode` argument to `startSeam` is unused. So today the mode and the transcript path
#    cannot reach the peer AT ALL: every seam test would run against the honest baseline and read an
#    empty transcript. That is a defect in the battery, not in busbar, and it must be fixed before
#    any seam verdict means anything.
# 4. `upstream::UPSTREAM_TIMEOUT` is a hard-coded 30s and `SEAM.UPSTREAM-FAILURE-IS-TOOL-ERROR`
#    waits 20s, so `stall` mode is RED on arrival. The honest fix is a per-server deadline in the
#    `tools:` grammar (default unchanged at 30s), not a constant tuned to the battery.
# 5. RED BEFORE GREEN is UNDONE. Nothing in this branch has been run. In particular the battery's
#    `isResponse()` predicate is `'id' in msg`, which has previously mis-classified an illegal reply
#    as neither response nor notification; before any of these six clauses is believed, busbar must
#    be broken deliberately (relay the upstream's server-initiated request; forward the caller's
#    bearer upstream) and each clause watched going RED.

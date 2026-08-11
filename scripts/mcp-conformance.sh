#!/usr/bin/env bash
# MCP CONFORMANCE GATE — the official suite, and the in-house battery, run from busbar's own CI.
#
# WHY THIS RUNS HERE AND NOT WHERE THE BATTERIES LIVE.
#
# A conformance battery is a statement ABOUT BUSBAR, so it belongs where busbar is built and where a
# red blocks the release it is about. A previous attempt ran these in the private design repo, on a
# Gitea instance with no registered runners: eight jobs failed to schedule and stayed permanently
# red, and the only two that reported success ("negative control", "harness self-test") had executed
# nothing. That is the exact defect the batteries exist to catch, one level up — a gate reporting a
# state it never reached — and it is why every mode below ends with an ANTI-VACUITY assertion rather
# than with an exit code.
#
# THE TWO-LEG RULE, which is the whole design of this script.
#
#   CONTROL legs run ALWAYS. A battery that cannot judge a known-good third-party peer cannot be
#   trusted to judge ours. If the control leg is red, the finding is about the harness, the pin or
#   the environment — never about busbar — and it must be visible before any subject verdict is
#   believed.
#
#   SUBJECT legs are ARMED OR RED. They used to skip, and the reasoning for that was sound while
#   busbar answered no MCP method at all: a job red for a reason that is not a defect teaches
#   everyone to read red as noise. It stopped being sound the moment the release claim became "MCP
#   works". A disarmed subject leg proves the SUITE works and proves NOTHING about busbar, and it
#   renders as the same green tick as a leg that judged busbar and passed. So `NOT ARMED, SO NOT
#   RUN` is now a RED STATE — see `require_armed`, and see the `--selftest` fixtures that prove
#   that transition rather than asserting it.
#
#   The ARMED GUARD survives underneath: once armed, a run that produces fewer than the revision's
#   FULL required scenario set is a hard failure. Set equality, never a floor — a floor of 30 is
#   satisfied by any 30 of 37, which is precisely the defect the rule exists to prevent.
#
# MODES
#   --official-control   the official suite against a PINNED third-party SDK, in server mode
#   --official-subject   the official suite against busbar. ARMED OR RED.
#   --battery-control    the in-house adversarial/seam battery against its pinned python control
#   --battery-subject    the in-house battery against busbar. ARMED OR RED.
#   --selftest           prove the anti-vacuity assertions bite, before any verdict is trusted
#   --help
#
# ARMING
#   MCP_SUBJECT_BUSBAR_BIN        THE PRIMARY ARM for the official-suite subject leg: a busbar
#                                 binary built from THIS COMMIT. The leg boots it on loopback,
#                                 gives the suite a real audience-bound credential for it, and
#                                 proves the plane boundary is still intact before believing any
#                                 verdict. See scripts/mcp-subject/boot.sh.
#   MCP_CONFORMANCE_SUBJECT_URL   an EXTERNAL, already-deployed busbar endpoint. Kept as an optional
#                                 extra leg; it is deliberately no longer the primary arm, because a
#                                 release gate that depends on somebody's deployment being up
#                                 answers a question about that deployment, not about this commit.
#                                 IT ALSO ARMS THE IN-HOUSE BATTERY leg, which boots the same
#                                 binary and reaches it through the stdio→HTTP transport adapter in
#                                 testing/mcp-conformance/scripts/stdio-http-bridge.mjs. That leg
#                                 used to want a stdio launch command NOBODY COULD WRITE — busbar
#                                 has no stdio MCP surface — so it was never once armed.
#   MCP_SUBJECT_SERVER_CMD        a command that starts an MCP server on stdio. Still honoured, and
#                                 it takes precedence, for judging something that is not this build.
#   MCP_SUBJECT_CLIENT_CMD        ... or as an MCP client
#   MCP_BATTERY_DIR               the in-house battery. Defaults to testing/mcp-conformance IN THIS
#                                 REPOSITORY and is not expected to be set: the battery was moved
#                                 here (DECISION 2) precisely so no leg depends on a private host.
#
# PINS, and why each is exact:
#   CONFORMANCE_PIN  the suite version. A silent upgrade can never LOOSEN what a gate accepts, so it
#                    is pinned exactly, the same reasoning the plugin trust root uses for keys.
#   SDK_REF          the control peer's commit. An unpinned control leg goes red the day somebody
#                    else's main branch breaks, which trains everyone to ignore this workflow.
#   REVISION         the one MCP protocol revision busbar implements. Running the suite for a
#                    revision we do not implement would produce a failure list that is a to-do,
#                    not a defect.

set -euo pipefail
cd "$(dirname "$0")/.."

CONFORMANCE_PIN="@modelcontextprotocol/conformance@0.2.0-alpha.11"
REVISION="2026-07-28"

# The number of server scenarios revision REVISION freezes. Read from the suite at run time rather
# than hard-coded, so a suite bump that changes the set is caught by the comparison below instead of
# by nobody. The literal here is only a FLOOR against the degenerate case where `list` itself starts
# reporting nothing.
MIN_SERVER_SCENARIOS=30

# The in-house adversarial/seam battery. IN THIS REPOSITORY, and that is the whole of DECISION 2:
# it used to be fetched from a private repository on an internal Gitea host with no route
# from a GitHub-hosted runner. Reaching it needed a SECRET and a reachable private host, and the
# moment a control leg depends on a secret, "control legs run ALWAYS" is aspirational. A battery
# that contains no product knowledge by construction loses nothing by being readable, and gains a
# gate that cannot silently stop running. The A2A workflow settled this the same way first.
DEFAULT_BATTERY_DIR="testing/mcp-conformance"

say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# The subject-boot harness: build-from-this-commit, boot on loopback, obtain a real audience-bound
# credential, and PROVE the plane boundary is intact before any verdict is believed. Sourced rather
# than inlined because it is a substantial piece of reasoning of its own; sourced AFTER `say`/`die`
# because it uses both.
# shellcheck source=scripts/mcp-subject/boot.sh
. "$(dirname "$0")/mcp-subject/boot.sh"

usage() { sed -n '2,70p' "$0" | sed 's/^# \{0,1\}//'; }

# ARMED OR RED, in one place so it can be tested in one place.
#
# `require_armed <label> <VAR> [VAR...]` succeeds if ANY named variable is non-empty, and dies
# otherwise. The death is the point: it is what turns `NOT ARMED, SO NOT RUN` from a green tick
# into a failure. It is a function rather than an inline `if` in each leg so that `--selftest` can
# drive the transition itself — a rule whose enforcement is only ever exercised by the real thing
# is a rule nobody has watched work.
require_armed() {
  local label="$1"; shift
  local v
  for v in "$@"; do
    if [ -n "${!v:-}" ]; then
      say "   armed by $v"
      return 0
    fi
  done
  printf '%s\n' "" >&2
  printf 'FAIL: %s\n' "NOT ARMED, SO NOT RUN — and that is RED." >&2
  cat >&2 <<'BANNER'

  This leg judges BUSBAR. Disarmed, it judges nothing, and it reports the same
  green tick as a leg that judged busbar and passed. That is the false green
  this whole gate exists to refuse, so an unarmed subject leg FAILS.

  Arm it with any ONE of:
BANNER
  for v in "$@"; do printf '      %s=...\n' "$v" >&2; done
  cat >&2 <<'BANNER'

  In CI these are repository VARIABLES, never secrets: an endpoint URL is not a
  credential, and putting it in `secrets` would mask it out of the very logs
  someone debugging an armed run has to read.

BANNER
  exit 1
}

# Every scenario the pinned suite says REVISION requires of a server. This is the SET the runs below
# are compared against: "the suite exited 0" is satisfied by a suite that ran nothing.
required_server_scenarios() {
  npx --yes "$CONFORMANCE_PIN" list --server --requirements "$REVISION" 2>/dev/null \
    | awk '/^Server scenarios/{f=1;next} /^[A-Za-z]/{f=0} f && /^  - /{sub(/^  - /,""); sub(/ .*$/,""); print}'
}

# The scenarios a run actually EXECUTED, read off the results directory the suite writes. A run that
# reports success having produced no scenario directory executed nothing, and this is the only place
# that distinction is visible.
executed_scenarios() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  # The suite names each directory `server-<scenario>-<ISO-8601 stamp>`. The stamp is stripped by
  # its EXACT shape rather than by a loose character class: a class of `[0-9T:.Z-]` is greedy and
  # would eat the numeric tail of a scenario named `sep-2164`, silently reporting a scenario that
  # ran as one that did not — which turns this anti-vacuity check into a source of false reds.
  find "$dir" -maxdepth 1 -type d -name 'server-*' -print 2>/dev/null \
    | sed -E -e 's|.*/server-||' \
             -e 's/-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{3}Z$//' \
    | sort -u
}

# THE ANTI-VACUITY ASSERTION. Two halves, and both are needed:
#   (1) a FLOOR, so a run that produced nothing cannot pass;
#   (2) SET EQUALITY against what the revision requires, so a run that quietly stopped covering half
#       the surface cannot pass either. A floor alone is satisfied by any 30 of 37.
assert_covered() {
  local dir="$1" label="$2"
  local -a req exe
  local missing count
  req=$(required_server_scenarios)
  [ -n "$req" ] || die "$label: the pinned suite listed NO required server scenarios for $REVISION. \
The pin, the revision name, or the suite's own list command is wrong — believing a verdict computed \
against an empty requirement set is how a gate passes without executing."
  count=$(printf '%s\n' "$req" | grep -c . || true)
  [ "$count" -ge "$MIN_SERVER_SCENARIOS" ] || die "$label: the revision requires only $count server \
scenarios, below the floor of $MIN_SERVER_SCENARIOS. Either the suite changed shape or the \
requirement set is not being read."
  exe=$(executed_scenarios "$dir")
  [ -n "$exe" ] || die "$label: the run reported a verdict but produced NO scenario results in \
$dir. Exit code 0 from a suite that executed nothing is a false green."
  missing=$(comm -23 <(printf '%s\n' "$req" | sort -u) <(printf '%s\n' "$exe") || true)
  [ -z "$missing" ] || die "$label: $REVISION requires scenarios that this run never executed:
$missing
A verdict that skipped part of the required set is not a verdict about that set."
  say "  ok: $count required scenarios, all executed"
}

# The control peer: the spec authors' own TypeScript SDK, running its conformance fixture server.
#
# Driven DIRECTLY rather than through the suite's `sdk` subcommand, and the reason is a defect that
# subcommand has on a cold runner: it rebuilds the SDK (which invalidates tsx's compile cache) and
# then allows the fixture server 15 seconds to become ready. On a fresh runner that boot takes
# longer, so the control leg fails for a reason that is not a finding — the precise failure mode this
# whole script is arranged to avoid. Driving it here means the readiness wait is OURS and generous.
#
# The second, larger benefit: the control leg then runs the EXACT command the subject leg runs
# (`conformance server --url …`). A control that exercises a different code path from the subject
# proves less than it appears to.
#
# This does couple the control leg to a third party's file layout (`test/conformance/src/
# everythingServer.ts`, port 3000). That coupling is safe precisely because the checkout is pinned to
# a commit: a pinned tree's layout cannot move underneath us, and a deliberate pin bump is where a
# layout change should be discovered.
SDK_REPO="https://github.com/modelcontextprotocol/typescript-sdk.git"
SDK_REF="cc4b4161"
SDK_FIXTURE="test/conformance/src/everythingServer.ts"
SDK_URL="http://localhost:3000/mcp"
CONTROL_READY_TIMEOUT=240

official_control() {
  say "== OFFICIAL SUITE · CONTROL leg (pinned third-party peer: typescript-sdk@$SDK_REF) =="
  say "   A battery that cannot judge a known-good peer cannot judge ours. This leg runs ALWAYS."
  local dir=.mcp-conformance
  local sdk="$dir/sdk"
  mkdir -p "$dir"
  if [ ! -d "$sdk/.git" ]; then
    git clone --filter=blob:none "$SDK_REPO" "$sdk" >/dev/null 2>&1 \
      || die "could not clone the control peer. A finding about the runner's network, not busbar."
  fi
  git -C "$sdk" fetch --quiet origin "$SDK_REF" 2>/dev/null || git -C "$sdk" fetch --quiet origin
  git -C "$sdk" checkout --quiet "$SDK_REF" \
    || die "the pinned control-peer commit $SDK_REF is not reachable. Bump the pin deliberately; \
never float it to a branch, or this leg goes red the day somebody else's main breaks."
  say "   building the control peer at $(git -C "$sdk" rev-parse --short HEAD)"
  ( cd "$sdk" && pnpm install --frozen-lockfile && pnpm run build:all ) >"$dir/build.log" 2>&1 \
    || { tail -40 "$dir/build.log" >&2; die "the control peer would not build. Harness/runner \
finding, not a busbar finding."; }

  ( cd "$sdk" && npx tsx "$SDK_FIXTURE" ) >"$dir/control-server.log" 2>&1 &
  local server_pid=$!
  # shellcheck disable=SC2064
  trap "kill $server_pid 2>/dev/null || true" EXIT

  # READINESS BY OBSERVATION, not by sleeping. The wait ends when the endpoint answers ANYTHING —
  # a 4xx is a perfectly good proof that a server is listening, and waiting for a 2xx would make
  # readiness depend on the very behaviour under test.
  local waited=0
  until curl -s -o /dev/null --max-time 5 "$SDK_URL" -X POST -H 'content-type: application/json' -d '{}'; do
    waited=$((waited+2))
    [ "$waited" -lt "$CONTROL_READY_TIMEOUT" ] || {
      tail -30 "$dir/control-server.log" >&2
      die "the control peer did not become ready within ${CONTROL_READY_TIMEOUT}s."
    }
    sleep 2
  done
  say "   control peer ready after ${waited}s"

  rm -rf "$dir/control"
  mkdir -p "$dir/control"
  npx --yes "$CONFORMANCE_PIN" server --url "$SDK_URL" --requirements "$REVISION" \
      -o "$dir/control" \
    || die "the official suite could not judge the pinned reference SDK. This is a finding about \
the harness, the pin or the runner — NOT about busbar. Do not read any subject verdict until it is \
green."
  assert_covered "$dir/control" "official control"
  kill "$server_pid" 2>/dev/null || true
}

official_subject() {
  say "== OFFICIAL SUITE · SUBJECT leg (busbar) =="
  # ARMED BY A BINARY, and only secondarily by a URL. See scripts/mcp-subject/boot.sh for why the
  # subject is built from this commit and booted in this job rather than being an endpoint somebody
  # deployed: a release gate that depends on a live deployment produces two unreadable verdicts, a
  # green that means "the deployment was fine yesterday" and a red that means "somebody redeployed".
  # `MCP_CONFORMANCE_SUBJECT_URL` is kept as an OPTIONAL EXTRA leg for an operator who also wants a
  # real deployment judged; it is no longer how this gate gets armed.
  require_armed "official subject" MCP_SUBJECT_BUSBAR_BIN MCP_CONFORMANCE_SUBJECT_URL

  local target
  if [ -n "${MCP_SUBJECT_BUSBAR_BIN:-}" ]; then
    boot_busbar_subject
    # shellcheck disable=SC2064
    trap "kill $SUBJECT_PIDS 2>/dev/null || true" EXIT
    target="$SUBJECT_URL"
  else
    target="$MCP_CONFORMANCE_SUBJECT_URL"
    say "   armed by an EXTERNAL endpoint only: $target"
    say "   NOTE: this judges whatever is deployed there, which may not be this commit."
  fi

  # The results directory is a variable so the OPTIONAL external leg can run in the same job without
  # overwriting the booted subject's evidence. Two runs that both wrote here would leave one verdict
  # standing over the other's artifact, which is exactly the "reading a report from a previous run"
  # defect the battery leg already has a hard error for.
  local out="${MCP_SUBJECT_OUT:-.mcp-conformance/subject}"
  rm -rf "$out"
  mkdir -p "$out"
  local baseline=()
  [ -f qa/mcp-conformance-baseline.yml ] && baseline=(--expected-failures qa/mcp-conformance-baseline.yml)
  local rc=0
  npx --yes "$CONFORMANCE_PIN" server \
      --url "$target" --requirements "$REVISION" \
      "${baseline[@]}" -o "$out" || rc=$?
  # THE ARMED GUARD, and it runs BEFORE the exit code is honoured. An armed run that executed
  # nothing is the state the skip above would otherwise rot into: configured, green, and vacuous.
  assert_covered "$out" "official subject"
  [ "$rc" -eq 0 ] || die "busbar failed scenarios the $REVISION requirement set demands. If a \
failure is known and accepted, it belongs in qa/mcp-conformance-baseline.yml with a reason — never \
absorbed by loosening the gate."
}

battery_control() {
  say "== IN-HOUSE BATTERY · CONTROL leg (pinned python reference peer) =="
  # NO LONGER SKIPPABLE. The battery is in this repository (DECISION 2), so "not available" can no
  # longer mean "somebody did not set a secret" — it can only mean the tree was gutted. That is a
  # finding, so it is red.
  MCP_BATTERY_DIR="${MCP_BATTERY_DIR:-$DEFAULT_BATTERY_DIR}"
  [ -d "$MCP_BATTERY_DIR" ] || die "the in-house battery is not at $MCP_BATTERY_DIR. It lives in \
this repository so that this leg needs no secret and no reachable private host; if it is missing, \
the tree is wrong and no verdict from this script means anything."
  say "   battery: $MCP_BATTERY_DIR"
  # The battery writes `reports/control-<tier>.json`, with the tier's comma turned into a dash.
  # DELETED FIRST, and there is no fallback to any other report file. An earlier version of this
  # function fell back to `reports/control.json` when the exact name was not found, and on a repo
  # with committed report artifacts that fallback silently read a report from a PREVIOUS run — the
  # gate would have passed on evidence the current run never produced. A missing report is a hard
  # error precisely because the alternative is believing stale evidence.
  local report="$MCP_BATTERY_DIR/reports/control-push-pr.json"
  rm -f "$report"
  ( cd "$MCP_BATTERY_DIR" && ./scripts/setup-control.sh && ./scripts/run-control.sh push,pr ) \
    || die "the in-house battery could not judge its own pinned control peer. A finding about the \
harness, not about busbar."
  [ -f "$report" ] || die "the control run did not write $report. It cannot have executed, and no \
other report file is an acceptable substitute — reading one from a previous run is how a gate \
reports a state it never reached."
  python3 - "$report" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
tests = r.get("tests") or r.get("results") or []
ran = [t for t in tests if str(t.get("verdict", t.get("status", ""))).upper() not in ("SKIP", "SKIPPED")]
if len(ran) < 20:
    raise SystemExit(
        f"FAIL: the control report contains only {len(ran)} executed tests. A control leg that "
        f"skipped almost everything proves nothing about the harness."
    )
print(f"  ok: {len(ran)} control tests executed")
PY
}

battery_subject() {
  say "== IN-HOUSE BATTERY · SUBJECT leg (busbar) =="
  MCP_BATTERY_DIR="${MCP_BATTERY_DIR:-$DEFAULT_BATTERY_DIR}"
  [ -d "$MCP_BATTERY_DIR" ] || die "the in-house battery is not at $MCP_BATTERY_DIR."

  # ARMED BY A BINARY, exactly as the official subject leg is, and for the same reason: a gate armed
  # out of `vars.*` is a gate nobody has to arm, and this one nobody did — it spent the whole of
  # 1.5.5 reporting `NOT ARMED, SO NOT RUN`. The two arming variables survive underneath for an
  # operator pointing the battery at something else entirely, which is the harness's whole contract
  # (a target is a launch command and nothing more), but the RELEASE arm is the build.
  #
  # The battery drives a target over STDIO and busbar's MCP plane is HTTP; the transport adapter
  # that joins them is `testing/mcp-conformance/scripts/stdio-http-bridge.mjs`, and its header says
  # what it does and does not do. It is pointed at the SAME booted subject the official leg uses —
  # same boot, same real audience-bound credential, same disproof that the plane boundary is intact
  # before any verdict is believed — so the two legs cannot disagree about which busbar was judged.
  if [ -z "${MCP_SUBJECT_SERVER_CMD:-}${MCP_SUBJECT_CLIENT_CMD:-}" ] \
     && [ -n "${MCP_SUBJECT_BUSBAR_BIN:-}" ]; then
    # A workdir of its own: two legs writing one directory would leave each verdict standing over
    # the other's evidence, which is the defect `MCP_SUBJECT_OUT` exists to prevent on the official
    # leg.
    MCP_SUBJECT_WORKDIR="${MCP_SUBJECT_WORKDIR:-.mcp-conformance/battery-subject-run}" \
      boot_busbar_subject
    # shellcheck disable=SC2064
    trap "kill $SUBJECT_PIDS 2>/dev/null || true" EXIT
    MCP_SUBJECT_SERVER_CMD="node $(pwd)/$MCP_BATTERY_DIR/scripts/stdio-http-bridge.mjs $SUBJECT_URL"
    export MCP_SUBJECT_SERVER_CMD
  fi

  require_armed "battery subject" MCP_SUBJECT_BUSBAR_BIN MCP_SUBJECT_SERVER_CMD MCP_SUBJECT_CLIENT_CMD
  # MCP_NO_SKIPS: a skipping test is not a passing test. Set HERE and not on the control legs,
  # because on the control legs a skip is the harness telling the truth about a peer it was never
  # pointed at, whereas here it is a green tick over a surface of BUSBAR that nobody touched. It
  # makes the six `pr`-tier seam tests RED while busbar has no MCP CLIENT direction to mount the
  # battery's fake server as an upstream — which is the correct answer, because the seam is exactly
  # the one property that is meaningless with only one direction built.
  MCP_NO_SKIPS=1 \
  MCP_SUBJECT_SERVER_CMD="${MCP_SUBJECT_SERVER_CMD:-}" \
  MCP_SUBJECT_CLIENT_CMD="${MCP_SUBJECT_CLIENT_CMD:-}" \
    bash -c 'cd "$0" && ./scripts/run-subject.sh' "$MCP_BATTERY_DIR" \
    || die "the in-house battery found a defect in busbar."
}

# --selftest: prove the anti-vacuity assertions BITE, before any verdict from this script is
# believed. Same discipline as `no-plugins-gate.sh` and `structure-lint.sh`: fixtures the check MUST
# flag, plus one it must stay silent on. Without this, `assert_covered` could be silently broken and
# every leg would report a confident green.
selftest() {
  say "== mcp-conformance SELF-TEST (the coverage assertion cannot be lied to) =="
  local tmp failures=0
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # Each fixture runs in a SUBSHELL. `die` exits, and an exit inside an `if` condition would take
  # the whole self-test with it — a self-test that cannot observe its own REDs is the thing this
  # file exists to prevent, one level further in.
  probe() { ( assert_covered "$1" "$2" ) >/dev/null 2>&1; }

  # Stand in for the real suite so the self-test needs no network and no SDK build. It answers
  # `list` truthfully and writes whichever scenario directories the fixture asks for.
  required_server_scenarios() { printf 'alpha\nbeta\ngamma\ndelta\nepsilon\n'; }
  MIN_SERVER_SCENARIOS=5

  # A realistic result-directory name. The suite stamps every directory, and the fixtures must be
  # stamped too — a fixture that is easier to parse than the real thing tests a parser nobody runs.
  STAMP="2026-08-09T05-41-58-049Z"
  d() { mkdir -p "$1/server-$2-$STAMP"; }

  # RED 1: a run that exited 0 and produced NO results at all. The classic false green.
  mkdir -p "$tmp/empty"
  if probe "$tmp/empty" selftest-empty; then
    say "  MISS: an empty results directory was accepted"; failures=$((failures+1))
  else
    say "  ok: an empty results directory is refused"
  fi

  # RED 2: a run that executed SOME of the required set. A floor alone would accept this, which is
  # why the assertion is set equality and not a count.
  for n in alpha beta gamma delta; do d "$tmp/partial" "$n"; done
  if probe "$tmp/partial" selftest-partial; then
    say "  MISS: a run missing a required scenario was accepted"; failures=$((failures+1))
  else
    say "  ok: a run missing a required scenario is refused"
  fi

  # RED 3: the requirement set itself came back empty — a wrong pin or a renamed revision. Judging
  # against an empty set is the subtlest false green of the three, because everything "passes".
  required_server_scenarios() { printf ''; }
  d "$tmp/full" alpha
  if probe "$tmp/full" selftest-norequirements; then
    say "  MISS: an empty requirement set was accepted"; failures=$((failures+1))
  else
    say "  ok: an empty requirement set is refused"
  fi

  # GREEN: the complete set, which must pass — otherwise the three REDs above prove only that the
  # assertion refuses everything.
  required_server_scenarios() { printf 'alpha\nbeta\ngamma\ndelta\nepsilon\n'; }
  for n in beta gamma delta epsilon; do d "$tmp/full" "$n"; done
  if probe "$tmp/full" selftest-full; then
    say "  ok: a complete run is accepted"
  else
    say "  MISS: a complete run was refused — the assertion refuses everything and proves nothing"
    failures=$((failures+1))
  fi

  # GREEN 2, and it is the reason the timestamp is stripped by exact shape rather than by a
  # character class: a scenario whose own name ends in digits (`sep-2164-...`) must survive the
  # strip. A greedy class would turn it into `sep`, report the scenario as never executed, and make
  # this gate a source of false REDs — which is the same disease as a false green, wearing a
  # different coat.
  required_server_scenarios() { printf 'sep-2164\nsep-2164-resource-not-found\n'; }
  MIN_SERVER_SCENARIOS=2
  d "$tmp/numeric" sep-2164
  d "$tmp/numeric" sep-2164-resource-not-found
  if probe "$tmp/numeric" selftest-numeric; then
    say "  ok: a scenario name ending in digits survives the timestamp strip"
  else
    say "  MISS: a numeric-tailed scenario name was eaten by the timestamp strip"
    failures=$((failures+1))
  fi

  # ---------------------------------------------------------------------------------------------
  # THE ARM-STATE TRANSITION, TESTED RATHER THAN ASSERTED.
  #
  # `NOT ARMED, SO NOT RUN` used to be a green tick and is now a RED state. That change is worth
  # exactly nothing unless somebody watches it happen, and the only run that would otherwise
  # exercise it is a real CI run of a leg that is supposed to be armed — i.e. never, once the
  # variables are set. So the transition is driven here, in both directions, on the same function
  # the real legs call.
  #
  # Driven in a SUBSHELL with the environment scrubbed, for the same reason as `probe` above: a
  # `die` inside an `if` condition would take the whole self-test with it.
  armed_probe() { ( unset MCP_ARMTEST_A MCP_ARMTEST_B; "$@" >/dev/null 2>&1 ); }

  # RED 4: nothing set. This is the state the gate was in for the whole of 1.5.5, reporting green.
  if armed_probe require_armed "selftest" MCP_ARMTEST_A MCP_ARMTEST_B; then
    say "  MISS: an UNARMED subject leg was accepted — 'NOT ARMED, SO NOT RUN' is still green"
    failures=$((failures+1))
  else
    say "  ok: an unarmed subject leg is RED"
  fi

  # RED 5: set, but EMPTY. `vars.FOO` on a repository with no such variable expands to the empty
  # string, not to an unset name, so this is the shape an unarmed CI run actually has — and a
  # `[ -z ]` written as `[ -n "${FOO+x}" ]` would wave it through.
  if ( export MCP_ARMTEST_A=""; require_armed "selftest" MCP_ARMTEST_A MCP_ARMTEST_B ) >/dev/null 2>&1; then
    say "  MISS: an EMPTY arming variable was accepted as armed"
    failures=$((failures+1))
  else
    say "  ok: an empty arming variable is not armed"
  fi

  # GREEN 3: armed on the FIRST name, and GREEN 4 on the SECOND. Both, because a check that only
  # ever reads argument one would pass GREEN 3 and silently make `MCP_SUBJECT_CLIENT_CMD` — the
  # client half of the battery leg — unable to arm anything.
  if ( export MCP_ARMTEST_A="x"; require_armed "selftest" MCP_ARMTEST_A MCP_ARMTEST_B ) >/dev/null 2>&1; then
    say "  ok: the first arming variable arms the leg"
  else
    say "  MISS: a leg armed by its first variable was still refused"; failures=$((failures+1))
  fi
  if ( export MCP_ARMTEST_B="x"; require_armed "selftest" MCP_ARMTEST_A MCP_ARMTEST_B ) >/dev/null 2>&1; then
    say "  ok: the second arming variable also arms the leg"
  else
    say "  MISS: a leg armed by its second variable was refused"; failures=$((failures+1))
  fi

  # ---------------------------------------------------------------------------------------------
  # THE NON-WEAKENING DISPROOF MUST ITSELF BITE.
  #
  # The subject leg's whole claim to honesty is `prove_the_boundary_is_intact`: it presents four
  # tokens the booted busbar MUST refuse and one it MUST admit, and refuses to run the suite if any
  # of them behaves otherwise. If that function were broken — if it accepted every status, or
  # rejected every status — the leg would still report a confident verdict, and the verdict would be
  # about a busbar whose plane boundary nobody checked. So it is driven here against a stubbed
  # probe, in every direction that matters, exactly as `assert_covered` is.
  #
  # The stub replaces `subject_probe_status`, the ONE function that reaches the network, so no
  # busbar and no port are needed and the fixtures are about the LOGIC rather than about a boot.
  boundary_probe() (
    # $1 = the status to answer for the audience-bound token, $2 = for everything else.
    local ok="$1" other="$2"
    subject_probe_status() { [ "${2:-}" = "GOODTOKEN" ] && printf '%s' "$ok" || printf '%s' "$other"; }
    prove_the_boundary_is_intact "http://127.0.0.1:1/mcp" PLAIN GOODTOKEN WRONG >/dev/null 2>&1
  )

  # GREEN 5: the honest shape — refusals refused, the bound token admitted.
  if boundary_probe 200 401; then
    say "  ok: an intact audience boundary is accepted"
  else
    say "  MISS: an intact audience boundary was refused — the disproof refuses everything"
    failures=$((failures+1))
  fi

  # RED 7: a busbar that admits EVERYTHING. This is the shape a weakened audience check, a
  # conformance bypass or an accidentally-open auth chain would produce, and it is the exact false
  # green this leg must never report: 37 scenarios judged against a resource server that is not one.
  if boundary_probe 200 200; then
    say "  MISS: a busbar that admitted every token was accepted — the disproof proves nothing"
    failures=$((failures+1))
  else
    say "  ok: a busbar that admits an unbound/wrong-audience token is refused"
  fi

  # RED 8: a busbar that refuses everything, the bound token included. The four refusals alone are
  # equally consistent with this, which is why the disproof carries a positive control — without it
  # the leg would be "vacuous in the other direction" and every scenario would fail on auth.
  if boundary_probe 401 401; then
    say "  MISS: a busbar that refused even the valid token was accepted"
    failures=$((failures+1))
  else
    say "  ok: a busbar that refuses even the correctly-bound token is refused"
  fi

  # RED 9: the subject binary must EXIST and be executable. A missing build artifact must name
  # itself, not fail later as a connection error the reader has to trace back.
  if ( MCP_SUBJECT_BUSBAR_BIN="$tmp/there-is-no-such-binary" boot_busbar_subject ) >/dev/null 2>&1; then
    say "  MISS: a non-existent subject binary was accepted as an arm"
    failures=$((failures+1))
  else
    say "  ok: a non-existent subject binary is refused"
  fi

  # RED 6: the battery must be IN THIS REPOSITORY. It was moved here so no leg needs a secret or a
  # reachable private host; if the directory is gone, every battery verdict is vacuous, and the
  # honest report is red rather than a skip.
  [ -d "$DEFAULT_BATTERY_DIR" ] || {
    say "  MISS: the in-house battery is not at $DEFAULT_BATTERY_DIR"; failures=$((failures+1)); }
  [ -d "$DEFAULT_BATTERY_DIR" ] && say "  ok: the in-house battery is in-repo at $DEFAULT_BATTERY_DIR"

  [ "$failures" -eq 0 ] || die "$failures self-test fixture(s) did not behave as declared"
  say "  self-test: 14 fixture(s) passed"
}

case "${1:---help}" in
  --official-control) official_control ;;
  --official-subject) official_subject ;;
  --battery-control)  battery_control ;;
  --battery-subject)  battery_subject ;;
  --selftest)         selftest ;;
  --help|-h)          usage ;;
  *) die "unknown mode: $1 (try --help)" ;;
esac

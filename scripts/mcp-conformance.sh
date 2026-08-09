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
#   SUBJECT legs SKIP until ARMED by one variable naming busbar's endpoint. They do NOT fail. A job
#   that is red today for a reason that is not a defect is how red stops meaning defect: the first
#   REAL conformance failure would look exactly like the standing ones and be read as noise. The
#   counterweight is the ARMED GUARD — once armed, a run that produces zero executed scenarios is a
#   hard failure, because "armed but vacuous" is the state a skip would otherwise rot into.
#
# MODES
#   --official-control   the official suite against a PINNED third-party SDK, in server mode
#   --official-subject   the official suite against busbar, if armed
#   --battery-control    the in-house adversarial/seam battery against its pinned python control
#   --battery-subject    the in-house battery against busbar, if armed
#   --selftest           prove the anti-vacuity assertions bite, before any verdict is trusted
#   --help
#
# ARMING
#   MCP_CONFORMANCE_SUBJECT_URL   busbar's MCP endpoint, e.g. https://gw.example.com/mcp
#   MCP_BATTERY_DIR               a checkout of the in-house adversarial/seam battery, if you have
#                                 one; the legs that use it skip when it is unset
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

say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'; }

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
  if [ -z "${MCP_CONFORMANCE_SUBJECT_URL:-}" ]; then
    cat <<'BANNER'

  ┌──────────────────────────────────────────────────────────────────────────┐
  │  NOT ARMED, SO NOT RUN.                                                  │
  │                                                                          │
  │  This leg needs one variable naming a running busbar MCP endpoint:       │
  │      MCP_CONFORMANCE_SUBJECT_URL=https://<host>/mcp                      │
  │                                                                          │
  │  It SKIPS rather than failing, on purpose. A job that is red for a       │
  │  reason that is not a defect teaches everyone to ignore red, and the     │
  │  first real conformance failure would then look like noise.              │
  └──────────────────────────────────────────────────────────────────────────┘

BANNER
    return 0
  fi
  say "   armed: $MCP_CONFORMANCE_SUBJECT_URL"
  rm -rf .mcp-conformance/subject
  mkdir -p .mcp-conformance/subject
  local baseline=()
  [ -f qa/mcp-conformance-baseline.yml ] && baseline=(--expected-failures qa/mcp-conformance-baseline.yml)
  local rc=0
  npx --yes "$CONFORMANCE_PIN" server \
      --url "$MCP_CONFORMANCE_SUBJECT_URL" --requirements "$REVISION" \
      "${baseline[@]}" -o .mcp-conformance/subject || rc=$?
  # THE ARMED GUARD, and it runs BEFORE the exit code is honoured. An armed run that executed
  # nothing is the state the skip above would otherwise rot into: configured, green, and vacuous.
  assert_covered .mcp-conformance/subject "official subject"
  [ "$rc" -eq 0 ] || die "busbar failed scenarios the $REVISION requirement set demands. If a \
failure is known and accepted, it belongs in qa/mcp-conformance-baseline.yml with a reason — never \
absorbed by loosening the gate."
}

battery_control() {
  say "== IN-HOUSE BATTERY · CONTROL leg (pinned python reference peer) =="
  if [ -z "${MCP_BATTERY_DIR:-}" ] || [ ! -d "${MCP_BATTERY_DIR:-}" ]; then
    cat <<'BANNER'

  NOT AVAILABLE, SO NOT RUN.

  The in-house adversarial and seam battery is not part of this repository. Set MCP_BATTERY_DIR to
  a checkout of it to run these legs.

  This SKIPS rather than failing, for the same reason the subject legs do. Note that it is a WEAKER
  position than the official control leg above, which depends on nothing beyond this repository and
  therefore always runs.

BANNER
    return 0
  fi
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
  if [ -z "${MCP_BATTERY_DIR:-}" ] || [ ! -d "${MCP_BATTERY_DIR:-}" ]; then
    say "  battery not available (MCP_BATTERY_DIR unset); not run."
    return 0
  fi
  if [ -z "${MCP_SUBJECT_SERVER_CMD:-}${MCP_SUBJECT_CLIENT_CMD:-}" ]; then
    say "  NOT ARMED, SO NOT RUN. Set MCP_SUBJECT_SERVER_CMD or MCP_SUBJECT_CLIENT_CMD to arm."
    return 0
  fi
  ( cd "$MCP_BATTERY_DIR" && ./scripts/run-subject.sh ) \
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

  [ "$failures" -eq 0 ] || die "$failures self-test fixture(s) did not behave as declared"
  say "  self-test: 5 fixture(s) passed"
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

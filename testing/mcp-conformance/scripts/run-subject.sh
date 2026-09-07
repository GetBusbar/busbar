#!/usr/bin/env bash
# Run the battery against the SUBJECT, then diff it against the control.
#
# EXIT CODE POLICY, and it matters:
#
#   0   the subject was tested and passed.
#   1   something is genuinely wrong: a spec failure, a regression against the
#       control, a vacuous run -- OR NO SUBJECT WAS CONFIGURED AT ALL.
#
# THAT LAST CLAUSE IS A REVERSAL, AND IT IS DELIBERATE. This script used to exit
# 0 when unarmed, and the reasoning was good at the time: a job red by design is
# a standing red with permission to ignore it, which trains everyone to read red
# here as normal, so the first REAL failure looks identical to the expected one
# and gets scrolled past.
#
# It stopped being good when this battery became a RELEASE GATE for a product
# that claims to implement MCP. Unarmed, this script tests nothing and reports
# the same green tick as a run that tested everything and passed. "We never
# pointed the battery at busbar" then renders identically to "busbar passed the
# battery", and that is a strictly worse failure than a standing red, because a
# standing red is at least legible. So `NOT ARMED, SO NOT RUN` is RED.
#
# The protection against the opposite rot -- a configured subject that executes
# nothing -- is the ARMED GUARD further down: an armed run that executes zero
# tests fails.
#
# Point it at an implementation with ONE of these, no code change required:
#   MCP_SUBJECT_SERVER_CMD="<command that starts the subject as an MCP server on stdio>"
#   MCP_SUBJECT_CLIENT_CMD="<command that starts the subject as an MCP client>"
set -uo pipefail
cd "$(dirname "$0")/.."

TIER="${MCP_TIER:-push,pr}"
NAME="${MCP_SUBJECT_NAME:-subject}"
CONTROL_REPORT="reports/control-${TIER//,/-}.json"

if [ -z "${MCP_SUBJECT_SERVER_CMD:-}" ] && [ -z "${MCP_SUBJECT_CLIENT_CMD:-}" ]; then
  cat >&2 <<'MSG'
================================================================================
MCP CONFORMANCE (SUBJECT): NOT ARMED, SO NOT RUN -- AND THAT IS RED
================================================================================

Neither MCP_SUBJECT_SERVER_CMD nor MCP_SUBJECT_CLIENT_CMD is set, so there is no
implementation to drive. NOTHING WAS TESTED, and this exits 1.

WHAT IS PROVEN WITHOUT A SUBJECT, AND WHAT IS NOT
  * the CONTROL job runs this same battery against a pinned reference
    implementation and is green -- that proves the HARNESS and the TESTS work
  * the NEGATIVE-CONTROL job runs it against deliberately broken peers and
    proves it catches them
  * NEITHER of those is a statement about busbar. Not one.

So the only thing missing is the subject itself, and the subject is the only
reason this battery is in a release gate.

TO ARM IT, SET ONE VARIABLE. That is the entire change:

    MCP_SUBJECT_SERVER_CMD="/path/to/your-binary mcp serve --stdio"

  and optionally, for the client half:

    MCP_SUBJECT_CLIENT_CMD="/path/to/your-binary mcp connect"

  In CI, set it as a repository variable or pass it via workflow_dispatch.
  No code edit and no per-subject branch is ever required: the harness contains
  no knowledge of any particular implementation.

The moment that variable is set, this job starts gating for real.
================================================================================
MSG
  exit 1
fi

# ---------------------------------------------------------------------------
# ARMED. From here a failure is a real failure.
# ---------------------------------------------------------------------------
echo "subject armed: running the battery for real. A failure from here is an issue."
echo

mkdir -p reports
# THIS RUN'S REPORT, OR NONE. `scripts/mcp-conformance.sh` deletes the control
# report before its control leg for a reason it states in full -- "reading one
# from a previous run is how a gate reports a state it never reached" -- and the
# SUBJECT report got no such treatment. A battery that dies before writing left
# the previous run's `reports/subject.json` in place, the ARMED GUARD below
# counted ITS rows and printed `armed guard: N test(s) actually executed` about a
# run that did not happen, and `compare` wrote `reports/differential.json` -- the
# artifact CI uploads and a human reads -- out of stale evidence. The exit code
# stays red on `RUN_STATUS`, so this is a false ARTIFACT rather than a false
# verdict; a false artifact is what the verdict gets re-read from later.
rm -f reports/subject.json reports/differential.json

# PREFLIGHT. A wrong launch command is the commonest way to arm this job badly,
# and without this check every test waits out its failsafe timeout before the
# run fails, which turns a typo into a multi-minute red. Fail in seconds with a
# message that names the actual problem instead.
if [ -n "${MCP_SUBJECT_SERVER_CMD:-}" ]; then
  if ! node bin/mcp-battery.mjs run \
        --name preflight \
        --server-cmd "$MCP_SUBJECT_SERVER_CMD" \
        --only SRV.DISCOVER.IMPLEMENTED \
        --role server \
        --tier push --quiet \
        --out reports/preflight.json >/dev/null 2>&1; then
    cat >&2 <<MSG
PREFLIGHT FAILED: the configured subject did not answer server/discover.

  MCP_SUBJECT_SERVER_CMD=$MCP_SUBJECT_SERVER_CMD

The battery was NOT run, because a command that cannot answer the one RPC every
server MUST implement will fail every test for the same uninformative reason.

Check that the command starts a process which speaks MCP over stdio and stays
running. Common causes: wrong path, missing interpreter, the process exits
immediately, or it writes something other than MCP to stdout.
MSG
    exit 1
  fi
  echo "preflight: subject answers server/discover"
fi
node bin/mcp-battery.mjs run \
  --name "$NAME" \
  ${MCP_SUBJECT_SERVER_CMD:+--server-cmd "$MCP_SUBJECT_SERVER_CMD"} \
  ${MCP_SUBJECT_CLIENT_CMD:+--client-cmd "$MCP_SUBJECT_CLIENT_CMD"} \
  ${MCP_SUBJECT_FAILING_TOOL:+--failing-tool "$MCP_SUBJECT_FAILING_TOOL"} \
  ${MCP_ALLOW_UNARMED_ROLES:+--allow-unarmed-role "$MCP_ALLOW_UNARMED_ROLES"} \
  --tier "$TIER" \
  --out "reports/subject.json"
RUN_STATUS=$?

# BOTH DIRECTIONS OR SAY SO. No `--role` is passed above, deliberately: the default request is
# EVERY role, so a subject armed in only one direction now hits the battery's own
# `ROLE(S) REQUESTED BUT NOT ARMED` refusal (exit 2) instead of quietly shrinking the denominator.
# That refusal has already printed a message naming the roles and the scenario counts, and this
# branch exists so the ARMED GUARD below does not overwrite it with `no report was produced`, which
# names the symptom rather than the cause.
if [ "$RUN_STATUS" -eq 2 ] && [ ! -f reports/subject.json ]; then
  echo "the battery refused to run: see its message above. This is a CONFIGURATION fault in this" >&2
  echo "gate, not a verdict about the subject. Arm the missing role, narrow the run with --role," >&2
  echo "or declare it with MCP_ALLOW_UNARMED_ROLES." >&2
  exit 1
fi

# ARMED GUARD: a configured subject that tested nothing is a failure, not a
# pass. This is what stops the job rotting into a vacuous green once the
# implementation lands.
if [ ! -f reports/subject.json ]; then
  echo "ARMED GUARD: a subject was configured but no report was produced." >&2
  exit 1
fi
# THE COUNT MUST BE A NUMBER, AND A COUNT THAT COULD NOT BE READ IS ZERO.
#
# This reader used to be a bare command substitution whose failure was invisible. A report that is
# truncated, that is not JSON, or that simply has no `results` member makes `require(...).results`
# undefined, `.filter` throws, node exits non-zero and writes NOTHING — and `[ "" -eq 0 ]` is not
# false, it is a SYNTAX ERROR that bash reports as exit 2. `if` reads 2 as "not zero", takes the
# ELSE path, and the ARMED GUARD — the one check whose whole job is to refuse a run that executed
# nothing — steps aside and lets the run continue, printing `armed guard:  test(s) actually
# executed` with a hole where the number should be. A guard that fails OPEN on an unreadable report
# is the vacuous green it exists to refuse, arriving through the door nobody watches.
#
# So the node exit status is captured, and a count that is not a plain non-negative integer is
# treated as the failure it is rather than as an unreadable success.
EXECUTED=$(node -e '
  const r = require("./reports/subject.json").results;
  if (!Array.isArray(r)) throw new Error("the report has no `results` array");
  const ran = r.filter(x => x.verdict !== "SKIP").length;
  process.stdout.write(String(ran));
') || EXECUTED=""
case "$EXECUTED" in
  ''|*[!0-9]*)
    cat >&2 <<MSG
ARMED GUARD FAILED: reports/subject.json could not be read as a run at all --
no \`results\` array, or the file is truncated or not JSON. The executed-test
count is therefore UNKNOWN, and unknown is red: a run whose report cannot be
read is indistinguishable from a run that tested nothing.
MSG
    exit 1 ;;
esac
if [ "$EXECUTED" -eq 0 ]; then
  cat >&2 <<MSG
ARMED GUARD FAILED: a subject IS configured but ZERO tests actually executed
(every test skipped). That is a vacuous run, and a vacuous run must never be
reported as a pass.

Likely causes: the launch command is wrong, the process exits immediately, or
it does not speak MCP over stdio. Check reports/subject.json.
MSG
  exit 1
fi
echo "armed guard: $EXECUTED test(s) actually executed"

# A MISSING CONTROL IS AN UNRUN COMPARISON, NOT A DEFECT IN THE SUBJECT, and the exit code has to
# say which. Both used to leave here as 1, and the caller renders 1 as "the in-house battery found a
# defect in busbar" — so a CI job that had merely never been handed the control report accused
# busbar of failing, with `50 pass, 0 fail` printed four lines above it. That is the same
# misattribution class as a leg that exits 0 while unarmed: the number was right and the verdict
# was about something else entirely.
if [ ! -f "$CONTROL_REPORT" ]; then
  cat >&2 <<MSG
no control report at $CONTROL_REPORT, so the differential did not run.

THIS IS NOT A VERDICT ABOUT BUSBAR. The subject's own results are above and stand on their own;
what is missing is the control to compare them against. Run scripts/run-control.sh first, or, in
CI, check that the control leg's report reached this job — ordering a job with \`needs:\` does not
share its workspace.
MSG
  exit 2
fi

echo
node bin/mcp-battery.mjs compare \
  --control "$CONTROL_REPORT" \
  --subject reports/subject.json \
  --out reports/differential.json
DIFF_STATUS=$?

if [ "$DIFF_STATUS" -ne 0 ] || [ "$RUN_STATUS" -ne 0 ]; then
  exit 1
fi
exit 0

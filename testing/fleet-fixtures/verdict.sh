#!/usr/bin/env bash
# testing/fleet-fixtures/verdict.sh — THE single verdict of the plugin functional gate.
#
# Reads every ledger row every probe wrote, diffs it against the ids that were OWED (the kinds the
# caller asked to verify), and exits non-zero if anything failed, did not run, or if NOTHING ran.
# This is the ONLY place the gate decides anything; every probe merely reports. Same inversion as
# scripts/release-gate/gate.sh, and for the same three reasons:
#
#   * NO PROBE MASKS ANOTHER — probes do not control flow, so ordering cannot decide what runs.
#   * A PROBE THAT COULD NOT RUN IS NOT A PASS — an owed id with no ledger row is `did not run`, RED.
#   * ZERO ROWS IS RED — a functional gate that exercised nothing is the green-having-run-nothing
#     failure the audit is about, checked for by name rather than trusted not to happen.
#
# Usage: EXPECTED_IDS="store:sqlite hook:headroom" LEDGER=<tsv> verdict.sh
#        EXPECTED_IDS=$'a|b|GET /x|ok\nc|d'          LEDGER=<tsv> verdict.sh
#        (EXPECTED_IDS is the list of probe ids the run OWED, ONE PER LINE, or space-separated on a
#        single line when no id contains a space. It is derived by the caller from the plugin kind
#        or cell set under test, so a probe that silently did not fire is caught.)
set -uo pipefail
cd "$(dirname "$0")" || exit 1

LEDGER="${LEDGER:?LEDGER must point at the probe ledger tsv}"
EXPECTED_IDS="${EXPECTED_IDS:-}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
# The gate this verdict speaks for. The plugin functional gate is the default; the shadow oracle
# (testing/shadow-oracle/replay.sh) reuses this file unchanged by setting GATE_NAME.
GATE_NAME="${GATE_NAME:-plugin functional gate}"
GATE_UPPER="$(printf '%s' "$GATE_NAME" | tr '[:lower:]' '[:upper:]')"

# awk not `grep -c`: grep -c on an empty file prints 0 AND exits 1, which turns the vacuous-run
# guard's own input into a broken test — the exact trap release-gate/gate.sh documents.
rows="$(awk 'NF{n++} END{print n+0}' "$LEDGER" 2>/dev/null || echo 0)"

echo "═══ ${GATE_UPPER} ═══"
echo

if [ "$rows" -eq 0 ]; then
  echo "::error title=${GATE_NAME}::VACUOUS RUN: ZERO probes reported a result. Nothing was verified. RED by construction — a functional gate that passes because it exercised nothing is worse than none. Fix: look at the probe steps above; each owes a ledger row."
  {
    echo "## ${GATE_NAME}: RED — vacuous run"
    echo
    echo "**Zero probes reported a result.** Ledger: \`${LEDGER}\`."
  } >> "$SUMMARY"
  exit 1
fi

if [ -z "$EXPECTED_IDS" ]; then
  echo "::error title=${GATE_NAME}::no EXPECTED_IDS were declared, so 'did not run' cannot be detected and a probe that silently failed to fire would read as green. RED. Fix: the workflow must pass EXPECTED_IDS derived from the plugin kind."
  exit 1
fi

# AN ID IS A LINE, NOT A WORD, when the list carries newlines (the oracle owes ids with spaces in
# them); a one-line list is the space-separated shape. The count below and the split in awk use
# the same rule, so the reconciliation guard compares like with like.
case "$EXPECTED_IDS" in
  *$'\n'*) owed_n="$(printf '%s\n' "$EXPECTED_IDS" | awk 'NF{n++} END{print n+0}')" ;;
  *) owed_n="$(printf '%s' "$EXPECTED_IDS" | wc -w | tr -d ' ')" ;;
esac

fail_ids="" skip_ids="" missing_ids="" pass_n=0
report="$(mktemp)"
resolved="$(mktemp)"
trap 'rm -f "$report" "$resolved"' EXIT

# THE LAST ROW WINS. record() APPENDS, so an id can legitimately appear more than once — a probe
# that retried, or a later step that revised its own verdict. Taking the FIRST row froze the earliest
# (often optimistic) result and threw the correction away; a probe that recorded PASS and then FAIL
# read as PASS. `resolve` keeps the last row per id.
#
# One awk pass, not one per id: the previous loop re-read the whole ledger for every expected id,
# which is O(ids × rows) file reads on a ledger the oracle replay can fill with thousands of cells.
#
# EXPECTED_IDS REACHES awk THROUGH ENVIRON, NEVER THROUGH `-v`. A caller that builds the owed list
# from a file — `EXPECTED_IDS="$(cat expected-ids)"` — hands over a value containing NEWLINES, and
# the one-true-awk shipped as /usr/bin/awk on macOS rejects a newline inside a `-v` assignment
# ("awk: newline in string") and dies before its BEGIN block. A dead awk writes an EMPTY resolved
# file, the loop below reads nothing, every counter stays zero — and the verdict announced GREEN
# for a run whose ledger held a hundred rows, seven of them FAIL. ENVIRON carries the value byte
# for byte on every awk. The exit status is checked too: the resolver dying must never be silence.
EXPECTED_IDS="$EXPECTED_IDS" awk -F'\t' '
  BEGIN {
    ids = ENVIRON["EXPECTED_IDS"]
    # AN ID IS A LINE, NOT A WORD: the owed set of the oracle has ids that contain spaces, so a list
    # that carries newlines is split on newlines only; a one-line list is the space-separated shape.
    if (index(ids, "\n") > 0) n = split(ids, want, /\n/); else n = split(ids, want, /[ \t]+/)
    for (i = 1; i <= n; i++) if (want[i] != "") seen[want[i]] = 1
  }
  NF && ($1 in seen) { status[$1] = $2; detail[$1] = $4; got[$1] = 1 }
  END {
    # emitted in EXPECTED_IDS order, one line per owed id, so the shell loop below needs no lookup
    for (i = 1; i <= n; i++) {
      id = want[i]
      if (id == "") continue
      if (id in got) printf "%s\t%s\t%s\n", id, status[id], detail[id]
      else           printf "%s\t%s\t%s\n", id, "__NOROW__", ""
    }
  }
' "$LEDGER" > "$resolved"
resolver_rc=$?

# THE SECOND HALF OF "ZERO ROWS IS RED". The guard at the top counts rows in the LEDGER; this one
# counts the owed ids the resolver actually accounted for. They are different numbers and only the
# second one decides anything: if the resolver dies, or is fed a list it cannot split, the ledger
# is still full while the report is empty, and an empty report has no FAIL and no DID NOT RUN to
# turn the verdict red. So every owed id must come back resolved — as PASS, FAIL, SKIP or DID NOT
# RUN — and a count that does not reconcile is RED by construction, exactly like a vacuous run.
resolved_n="$(awk 'NF{n++} END{print n+0}' "$resolved" 2>/dev/null || echo 0)"
if [ "$resolver_rc" -ne 0 ] || [ "$resolved_n" -ne "$owed_n" ]; then
  echo "::error title=${GATE_NAME}::RED — the verdict could not account for what was owed: ${owed_n} ids were owed, ${resolved_n} came back resolved (resolver exit ${resolver_rc}). Nothing was decided, so nothing may be called green. Fix: the ledger is \`${LEDGER}\`; check that EXPECTED_IDS is a well-formed list and that the resolver above ran."
  {
    echo "## ${GATE_NAME}: RED — the verdict did not reconcile"
    echo
    echo "Owed **${owed_n}** ids, resolved **${resolved_n}** (resolver exit ${resolver_rc}). Ledger: \`${LEDGER}\`."
  } >> "$SUMMARY"
  echo; echo "${GATE_UPPER}: RED."
  exit 1
fi

while IFS=$'\t' read -r id status detail; do
  [ -n "$id" ] || continue
  case "$status" in
    __NOROW__) missing_ids="${missing_ids}${id} "; printf '%-12s %-40s\n' "DID NOT RUN" "$id" >> "$report" ;;
    PASS) pass_n=$((pass_n + 1)); printf '%-12s %-40s\n' "PASS" "$id" >> "$report" ;;
    SKIP) skip_ids="${skip_ids}${id} "; printf '%-12s %-40s %s\n' "SKIP" "$id" "$detail" >> "$report" ;;
    *)    fail_ids="${fail_ids}${id} "; printf '%-12s %-40s %s\n' "FAIL" "$id" "$detail" >> "$report" ;;
  esac
done < "$resolved"

cat "$report"
echo
# `owed` is counted BY THE LOOP, not re-derived with `wc -w`: a word count of the same string is the
# very miscount the loop was fixed for, and the two disagreeing is how the wrong number stayed
# plausible.
printf 'owed: %s   pass: %s   fail: %s   skip: %s   did not run: %s\n' \
  "$owed_n" "$pass_n" \
  "$(printf '%s' "$fail_ids"    | wc -w | tr -d ' ')" \
  "$(printf '%s' "$skip_ids"    | wc -w | tr -d ' ')" \
  "$(printf '%s' "$missing_ids" | wc -w | tr -d ' ')"

{
  echo "## ${GATE_NAME}"
  echo
  echo '```'
  cat "$report"
  echo '```'
} >> "$SUMMARY"

rc=0
if [ -n "$fail_ids" ]; then
  echo "::error title=${GATE_NAME}::RED — these probes FAILED: ${fail_ids}. Every probe ran; none was masked. Each has its own ::error:: above with expected vs observed."
  rc=1
fi
if [ -n "$missing_ids" ]; then
  echo "::error title=${GATE_NAME}::RED — these probes DID NOT RUN: ${missing_ids}. A probe that could not run is not a pass. Fix: find the step that owed the id and died before recording (a fixture that never came up, a step that errored in its preamble)."
  rc=1
fi
# A SKIP is never a pass. There is no allowlist here: a plugin functional probe that cannot run
# means the plugin could not be exercised, which is exactly the thing being gated.
if [ -n "$skip_ids" ]; then
  echo "::error title=${GATE_NAME}::RED — these probes SKIPPED: ${skip_ids}. A skip is never a pass; the plugin was not exercised. If a probe genuinely cannot apply, it must not be in EXPECTED_IDS."
  rc=1
fi

if [ "$rc" -ne 0 ]; then
  echo; echo "${GATE_UPPER}: RED."
  { echo; echo "### RED — the plugin was not proven functional."; } >> "$SUMMARY"
  exit 1
fi
echo; echo "${GATE_UPPER}: GREEN. All ${pass_n} owed probes ran and passed."
{ echo; echo "### GREEN — all ${pass_n} owed probes passed."; } >> "$SUMMARY"

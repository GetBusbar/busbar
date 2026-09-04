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
#        (EXPECTED_IDS is the space-separated list of probe ids the run OWED. It is derived by the
#        workflow from the plugin kind under test, so a probe that silently did not fire is caught.)
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

fail_ids="" skip_ids="" missing_ids="" pass_n=0
report="$(mktemp)"

for id in $EXPECTED_IDS; do
  row="$(awk -F'\t' -v i="$id" '$1==i{print; exit}' "$LEDGER")"
  if [ -z "$row" ]; then
    missing_ids="${missing_ids}${id} "
    printf '%-12s %-40s\n' "DID NOT RUN" "$id" >> "$report"
    continue
  fi
  status="$(printf '%s' "$row" | cut -f2)"
  detail="$(printf '%s' "$row" | cut -f4)"
  case "$status" in
    PASS) pass_n=$((pass_n + 1)); printf '%-12s %-40s\n' "PASS" "$id" >> "$report" ;;
    SKIP) skip_ids="${skip_ids}${id} "; printf '%-12s %-40s %s\n' "SKIP" "$id" "$detail" >> "$report" ;;
    *)    fail_ids="${fail_ids}${id} "; printf '%-12s %-40s %s\n' "FAIL" "$id" "$detail" >> "$report" ;;
  esac
done

cat "$report"
echo
printf 'owed: %s   pass: %s   fail: %s   skip: %s   did not run: %s\n' \
  "$(echo "$EXPECTED_IDS" | wc -w | tr -d ' ')" "$pass_n" \
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

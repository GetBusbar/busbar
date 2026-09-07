#!/usr/bin/env bash
# scripts/release-gate/ledger-selftest.sh — how ONE id's verdict is resolved out of the ledger,
# exercised offline against staged ledgers and against the real gate.sh.
#
# WHY THIS EXISTS. gate.sh read the ledger with
#
#     row="$(awk -F'\t' -v i="$id" '$1==i{print; exit}' "$ALL")"
#
# and its comment said duplicates were "flagged below". Nothing below flagged them: the `unexpected`
# scan finds ids the CONTRACT does not know about, never an id reported twice. And lib.sh opens the
# ledger with `[ -f "$LEDGER" ] || : > "$LEDGER"`, which does not truncate — so a step re-run against
# a persisted RUNNER_TEMP, or a leg that records on each retry attempt, leaves two rows for one id.
# With `exit` after the first match, a PASS written before a later FAIL was the only row the gate
# ever read, and the gate went GREEN over a check that had failed.
#
# Every case below is one the code got wrong in the green direction before the case existed.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
# shellcheck source=scripts/release-gate/lib.sh
. scripts/release-gate/lib.sh

bad=0
ok()   { printf '  [ok]     %s\n' "$1"; }
nope() { printf '  [FAILED] %s\n' "$1"; bad=1; }
tmp="$(mktemp -d "${TMPDIR:-/tmp}/relgate-ledger-XXXXXX")"
# shellcheck disable=SC2064
trap "rm -rf '$tmp'" EXIT

echo "release-gate ledger selftest"

# ── ledger_status_for, directly ─────────────────────────────────────────────────────────────────
led="$tmp/l.tsv"
{ printf 'a:one\tPASS\tfine\t\n'; } > "$led"
[ "$(ledger_status_for "$led" a:one)" = "PASS" ] \
  && ok "a single PASS row resolves PASS" || nope "a single PASS row resolved '$(ledger_status_for "$led" a:one)'"

[ -z "$(ledger_status_for "$led" a:absent)" ] \
  && ok "an id with no row resolves to nothing (did not run)" || nope "an absent id resolved to a status"

# THE DEFECT, PINNED: PASS first, FAIL second. First-row-wins read this as PASS.
{ printf 'a:one\tPASS\tthe first attempt\t\n'; printf 'a:one\tFAIL\tthe retry blew up\tboom\n'; } > "$led"
case "$(ledger_status_for "$led" a:one)" in
  CONFLICT) ok "PASS then FAIL for one id is CONFLICT, not the PASS that was written first" ;;
  PASS)     nope "PASS-then-FAIL resolved PASS — a failing check is being swallowed by an earlier row" ;;
  *)        nope "PASS-then-FAIL resolved '$(ledger_status_for "$led" a:one)'" ;;
esac

# And the other order, so the fix is not "the last row wins" either.
{ printf 'a:one\tFAIL\tboom\tboom\n'; printf 'a:one\tPASS\tthe retry was fine\t\n'; } > "$led"
[ "$(ledger_status_for "$led" a:one)" = "CONFLICT" ] \
  && ok "FAIL then PASS is CONFLICT too — the ledger has two answers either way" \
  || nope "FAIL-then-PASS resolved '$(ledger_status_for "$led" a:one)'"

# An honest retry that reports the SAME thing twice is unremarkable.
{ printf 'a:one\tPASS\tattempt 1\t\n'; printf 'a:one\tPASS\tattempt 2\t\n'; } > "$led"
[ "$(ledger_status_for "$led" a:one)" = "PASS" ] \
  && ok "two agreeing PASS rows still resolve PASS (a retry is not a conflict)" \
  || nope "two agreeing PASS rows resolved '$(ledger_status_for "$led" a:one)'"
{ printf 'a:one\tFAIL\tx\tx\n'; printf 'a:one\tFAIL\ty\ty\n'; } > "$led"
[ "$(ledger_status_for "$led" a:one)" = "FAIL" ] \
  && ok "two agreeing FAIL rows resolve FAIL" || nope "two agreeing FAIL rows resolved wrong"

# A status nobody defined is a FAILURE, never a pass and never silently ignored.
{ printf 'a:one\tWHATEVER\tsomething new\t\n'; } > "$led"
[ "$(ledger_status_for "$led" a:one)" = "FAIL" ] \
  && ok "an unrecognised status is FAIL, not a pass" || nope "an unrecognised status resolved '$(ledger_status_for "$led" a:one)'"

# One id's duplicates must not touch another id.
{ printf 'a:one\tPASS\tp\t\n'; printf 'a:two\tFAIL\tf\tf\n'; printf 'a:one\tPASS\tp\t\n'; } > "$led"
[ "$(ledger_status_for "$led" a:one)" = "PASS" ] && [ "$(ledger_status_for "$led" a:two)" = "FAIL" ] \
  && ok "ids are resolved independently" || nope "one id's rows leaked into another's verdict"

# ── gate.sh end to end, against a stubbed expected list ─────────────────────────────────────────
# Staged so the gate is driven by THE file, not by a copy of its loop.
mkdir -p "$tmp/fake/scripts/release-gate" "$tmp/fake/ledgers"
cp scripts/release-gate/gate.sh scripts/release-gate/lib.sh "$tmp/fake/scripts/release-gate/"
cat > "$tmp/fake/scripts/release-gate/expected-ids.sh" <<'STUB'
#!/usr/bin/env bash
printf 'a:one\tthe first check\n'
printf 'a:two\tthe second check\n'
printf 'a:three\tthe third check\n'
printf 'a:four\tthe fourth check\n'
printf 'a:five\tthe fifth check\n'
exit 0
STUB
chmod +x "$tmp/fake/scripts/release-gate/expected-ids.sh"

# The output goes to a FILE and the status into a variable set in THIS shell. Written as
# `out="$(run_gate)"` with the function assigning GATE_RC, the assignment happened inside the
# command substitution's subshell and never reached the caller, so every case read the previous
# run's status — four of them silently "passed" against a gate that had gone red. Which is the same
# dropped-status shape this file is about.
GATE_RC=0
GATE_OUT="$tmp/gate.out"
run_gate() {
  LEDGER_DIR="$tmp/fake/ledgers" RUNNER_TEMP="$tmp/fake" GITHUB_STEP_SUMMARY=/dev/null \
    "$tmp/fake/scripts/release-gate/gate.sh" 9.9.9 >"$GATE_OUT" 2>&1
  GATE_RC=$?
  out="$(cat "$GATE_OUT")"
}
all_pass() { for i in one two three four five; do printf 'a:%s\tPASS\tok\t\n' "$i"; done; }

# The pass path first: five agreeing PASS rows is GREEN, or every red below proves nothing.
all_pass > "$tmp/fake/ledgers/leg.tsv"
run_gate
if [ "$GATE_RC" -eq 0 ] && printf '%s' "$out" | grep -q 'GREEN'; then
  ok "five agreeing PASS rows is GREEN (the pass path still works)"
else
  nope "an all-green ledger did not go GREEN (rc=$GATE_RC): $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-200)"
fi
# And it counts the CHECKS, not the ledger lines.
if printf '%s' "$out" | grep -q 'Every one of the 5 contracted checks'; then
  ok "the GREEN line counts the contracted checks that passed"
else
  nope "the GREEN line does not count 5: $(printf '%s' "$out" | grep GREEN | head -1)"
fi

# THE DEFECT END TO END: a PASS row, then a FAIL row for the same id, in one ledger.
{ all_pass; printf 'a:three\tFAIL\tthe retry blew up\tboom\n'; } > "$tmp/fake/ledgers/leg.tsv"
run_gate
if [ "$GATE_RC" -eq 0 ]; then
  nope "gate.sh printed GREEN with a FAIL row present for a:three — the earlier PASS swallowed it"
elif printf '%s' "$out" | grep -q 'a:three'; then
  ok "a FAIL row after a PASS for the same id takes the gate RED, by name"
else
  nope "the gate went red but did not name a:three"
fi

# Across two ledger files, which is the real shape: one per matrix leg, concatenated.
all_pass > "$tmp/fake/ledgers/leg.tsv"
printf 'a:four\tFAIL\tthe second leg disagrees\tboom\n' > "$tmp/fake/ledgers/leg2.tsv"
run_gate
if [ "$GATE_RC" -ne 0 ] && printf '%s' "$out" | grep -q 'a:four'; then
  ok "two legs disagreeing about one id is RED, by name"
else
  nope "two legs disagreeing about a:four did not go red (rc=$GATE_RC)"
fi
rm -f "$tmp/fake/ledgers/leg2.tsv"

# A duplicated PASS must NOT be red — the fix must not make an ordinary retry a failure.
{ all_pass; printf 'a:three\tPASS\tthe retry was fine too\t\n'; } > "$tmp/fake/ledgers/leg.tsv"
run_gate
if [ "$GATE_RC" -eq 0 ]; then
  ok "a duplicated PASS row is not a conflict"
else
  nope "a duplicated PASS row took the gate red: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-200)"
fi
# Six ledger LINES over five contracted checks: the sentence a human reads must say five. It said
# `${rows}`, the raw line count, so a ledger polluted by re-runs or by rows nobody asked about
# inflated the one number anybody quotes.
if printf '%s' "$out" | grep -q 'Every one of the 5 contracted checks'; then
  ok "six ledger lines over five checks still reports five verified"
else
  nope "the GREEN line counted ledger lines, not checks: $(printf '%s' "$out" | grep GREEN | head -1)"
fi

# And the properties that were already right must stay right.
{ printf 'a:one\tPASS\tok\t\n'; } > "$tmp/fake/ledgers/leg.tsv"
run_gate
if [ "$GATE_RC" -ne 0 ] && printf '%s' "$out" | grep -q 'DID NOT RUN'; then
  ok "ids with no row at all are still DID NOT RUN and still red"
else
  nope "four unreported ids did not go red (rc=$GATE_RC)"
fi
: > "$tmp/fake/ledgers/leg.tsv"
run_gate
if [ "$GATE_RC" -ne 0 ] && printf '%s' "$out" | grep -q 'VACUOUS'; then
  ok "an empty ledger is still a vacuous run and still red"
else
  nope "an empty ledger did not report a vacuous run (rc=$GATE_RC)"
fi

echo
if [ "$bad" = 0 ]; then
  echo "release-gate ledger selftest: one id's verdict is resolved across every row that names it"
  exit 0
fi
echo "release-gate ledger selftest: FAILED"
exit 1

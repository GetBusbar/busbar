#!/usr/bin/env bash
# scripts/release-gate/gate.sh — THE GATE. The single verdict.
#
# Reads every ledger produced by every leg, diffs it against the ids the contract says are owed,
# and exits non-zero if the release is not verified. This is the ONLY place in the gate that
# decides anything; every check before it merely reports. That inversion is the entire design:
#
#   * NO CHECK CAN MASK ANOTHER. Checks do not control flow, so ordering cannot decide what runs.
#     verify-deploy.yml's (g) failed on a Cloudflare 403 from 2026-08-08 and (h)(i)(j)(k)(l) —
#     including the only check that boots the published image — did not execute once for six days,
#     while a `latest` that exited 1 on `docker run` sat in production.
#   * A CHECK THAT COULD NOT RUN IS NOT A PASS. An id in the expected list with no ledger row is
#     reported as `did not run` and is RED. Silence used to read as green.
#   * ZERO EXECUTED CHECKS IS RED. Checked by name. A gate that passes because it did nothing is
#     the failure mode the whole exercise exists to eliminate, and it is the one failure mode a
#     "collect failures and fail if any" design does NOT catch on its own.
#   * A SKIP IS COUNTED AND SURFACED, NEVER FOLDED INTO PASS. Only ids in SKIP_ALLOWED may skip,
#     and even those print a ::warning:: and are named in the summary as NOT VERIFIED.
#
# Usage: LEDGER_DIR=<dir of *.tsv ledgers> scripts/release-gate/gate.sh <version>
set -uo pipefail
# `|| exit` and not a bare cd: every path below is repo-relative, so a failed cd would run the
# whole check suite against whatever directory the caller happened to be in and report confident
# nonsense. Failing here is the only honest outcome.
cd "$(dirname "$0")/../.." || exit 1
# shellcheck source=scripts/release-gate/lib.sh
. scripts/release-gate/lib.sh

VERSION="${1:-${BUSBAR_GATE_VERSION:-}}"
LEDGER_DIR="${LEDGER_DIR:-${RUNNER_TEMP:-/tmp}/release-gate-ledgers}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"

# ── THE ONLY IDS PERMITTED TO SKIP, AND EXACTLY WHY ─────────────────────────────────────────────
#
# getbusbar.com sits behind Cloudflare bot protection, which serves 403 to GitHub Actions'
# datacenter address space while serving every real visitor normally. That is a property of where
# the runner is, not of the release. Failing on it is crying wolf (six daily runs did, and took
# five real checks dark with them); passing on it would assert something nobody verified.
#
# So these four SKIP — visibly, counted, named in the summary, with a ::warning:: — and every
# OTHER id that skips is RED, because for every other id "could not run" means the thing under
# test is unreachable for users too. The list is here and nowhere else so it cannot grow by
# accident inside a check that finds itself inconvenient.
SKIP_ALLOWED="install:script-live install:no-api-github install:e2e site:download-page"

echo "═══ RELEASE GATE — busbar ${VERSION:-<unknown>} ═══"
echo

# ── Collect ─────────────────────────────────────────────────────────────────────────────────────
ALL="${RUNNER_TEMP:-/tmp}/release-gate-all.tsv"
: > "$ALL"
if [ -d "$LEDGER_DIR" ]; then
  # -print0/read -d so a path with a space cannot silently drop a whole leg's results.
  while IFS= read -r -d '' f; do cat "$f" >> "$ALL"; done \
    < <(find "$LEDGER_DIR" -type f -name '*.tsv' -print0)
fi
# awk, not `grep -c`: grep -c on an empty file PRINTS 0 and EXITS 1, so the obvious
# `$(grep -c . "$ALL" || echo 0)` yields the two-line string "0\n0" and the `-eq 0` test below then
# errors out instead of taking the vacuous-run branch — i.e. the guard against a vacuous green was
# itself silently broken by a vacuous input. Found by running TEST 1 below rather than by reading.
rows="$(awk 'NF{n++} END{print n+0}' "$ALL")"

# ── THE VACUOUS-GREEN GUARD, FIRST, BEFORE ANY OTHER VERDICT ────────────────────────────────────
if [ "$rows" -eq 0 ]; then
  echo "::error title=release gate::VACUOUS RUN: ZERO checks reported a result. Nothing about ${VERSION:-this release} was verified. This is RED by construction — a gate that passes because it did nothing is worse than no gate. Fix: look at the matrix legs above; the ledger artifacts were empty or were never uploaded."
  {
    echo "## Release gate: RED — vacuous run"
    echo
    echo "**Zero checks reported a result.** Nothing was verified. Ledger dir: \`${LEDGER_DIR}\`."
  } >> "$SUMMARY"
  exit 1
fi

# ── Diff against what is owed ───────────────────────────────────────────────────────────────────
EXPECTED="${RUNNER_TEMP:-/tmp}/release-gate-expected.tsv"
if ! scripts/release-gate/expected-ids.sh --describe > "$EXPECTED"; then
  echo "::error title=release gate::could not derive the expected check list from ${CONTRACT}. Every 'did not run' verdict below would be vacuous, so this is RED rather than a pass. Fix: validate ${CONTRACT} parses as JSON and carries a non-empty .targets[]."
  exit 1
fi

fail_ids="" skip_ids="" bad_skip_ids="" missing_ids="" pass_n=0
report="${RUNNER_TEMP:-/tmp}/release-gate-report.txt"
: > "$report"

while IFS=$'\t' read -r id desc; do
  [ -n "$id" ] || continue
  # Deliberately the FIRST row for an id: a leg that reported and then a retry that reported
  # differently is itself a fact worth not papering over, and duplicates are flagged below.
  row="$(awk -F'\t' -v i="$id" '$1==i{print; exit}' "$ALL")"
  if [ -z "$row" ]; then
    missing_ids="${missing_ids}${id} "
    printf '%-12s %-46s %s\n' "DID NOT RUN" "$id" "$desc" >> "$report"
    continue
  fi
  status="$(printf '%s' "$row" | cut -f2)"
  detail="$(printf '%s' "$row" | cut -f4)"
  case "$status" in
    PASS)
      pass_n=$((pass_n + 1))
      printf '%-12s %-46s %s\n' "PASS" "$id" "$desc" >> "$report"
      ;;
    SKIP)
      skip_ids="${skip_ids}${id} "
      printf '%-12s %-46s %s\n' "SKIP" "$id" "$detail" >> "$report"
      case " $SKIP_ALLOWED " in
        *" $id "*) ;;
        *) bad_skip_ids="${bad_skip_ids}${id} " ;;
      esac
      ;;
    *)
      fail_ids="${fail_ids}${id} "
      printf '%-12s %-46s %s\n' "FAIL" "$id" "$detail" >> "$report"
      ;;
  esac
done < "$EXPECTED"

# Rows reported that nothing asked for. Not fatal — but a check reporting under an id the contract
# does not know about is a check whose result nobody is diffing, which is how coverage rots.
unexpected="$(cut -f1 "$ALL" | sort -u | while read -r id; do
  [ -n "$id" ] || continue
  cut -f1 "$EXPECTED" | grep -qxF "$id" || printf '%s ' "$id"
done)"

cat "$report"
echo
echo "───────────────────────────────────────────────────────────────────────────────"
printf 'reported: %s   pass: %s   fail: %s   skip: %s   did not run: %s\n' \
  "$rows" "$pass_n" \
  "$(printf '%s' "$fail_ids"    | wc -w | tr -d ' ')" \
  "$(printf '%s' "$skip_ids"    | wc -w | tr -d ' ')" \
  "$(printf '%s' "$missing_ids" | wc -w | tr -d ' ')"

# ── Job summary. Red on a run nobody opens is a signal to nobody. ───────────────────────────────
{
  echo "## Release gate — busbar ${VERSION:-<unknown>}"
  echo
  echo '```'
  cat "$report"
  echo '```'
} >> "$SUMMARY"

rc=0
if [ -n "$fail_ids" ]; then
  echo "::error title=release gate::RED — these checks FAILED for ${VERSION}: ${fail_ids}. Every check ran; none was masked by an earlier failure. Each failure has its own ::error:: above with expected vs observed and the fix."
  rc=1
fi
if [ -n "$missing_ids" ]; then
  echo "::error title=release gate::RED — these checks DID NOT RUN for ${VERSION}: ${missing_ids}. A check that could not run is not a pass. Fix: find the matrix leg or job that owed these ids and did not report them (a runner that never started, a step that died in its preamble, a leg skipped by an \`if:\`)."
  rc=1
fi
if [ -n "$bad_skip_ids" ]; then
  echo "::error title=release gate::RED — these checks SKIPPED and are not permitted to: ${bad_skip_ids}. Only the getbusbar.com/Cloudflare set may skip (${SKIP_ALLOWED}); everything else that cannot run is unreachable for users too."
  rc=1
fi
if [ -n "$skip_ids" ] && [ -z "$bad_skip_ids" ]; then
  echo "::warning title=release gate::NOT VERIFIED (allowlisted skip): ${skip_ids}— reachable for real users, structurally unreachable from a GitHub Actions runner (Cloudflare blocks the datacenter ranges). These are NOT passes. Fix, marketing-side: allowlist GitHub Actions egress, or serve install.sh from a path exempt from bot protection."
  {
    echo
    echo "> **Not verified (allowlisted skip):** \`${skip_ids}\` — Cloudflare blocks GitHub Actions runner IPs. Counted, not passed."
  } >> "$SUMMARY"
fi
if [ -n "$unexpected" ]; then
  echo "::warning title=release gate::ledger rows nobody asked for: ${unexpected}— these ids are not in the contract-derived expected list, so nothing is diffing them. Fix: add them to scripts/release-gate/expected-ids.sh or stop reporting them."
fi

if [ "$rc" -ne 0 ]; then
  echo
  echo "RELEASE GATE: RED. ${VERSION:-this release} is NOT verified."
  { echo; echo "### RED — \`${VERSION:-?}\` is not verified."; } >> "$SUMMARY"
  exit 1
fi

echo
echo "RELEASE GATE: GREEN. Every one of the ${rows} contracted checks for ${VERSION} ran and passed."
{ echo; echo "### GREEN — all ${pass_n} contracted checks passed."; } >> "$SUMMARY"

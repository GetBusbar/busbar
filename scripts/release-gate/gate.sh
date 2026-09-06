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
#        scripts/release-gate/gate.sh --selftest   # prove the gate's own floors, offline
set -uo pipefail
# `|| exit` and not a bare cd: every path below is repo-relative, so a failed cd would run the
# whole check suite against whatever directory the caller happened to be in and report confident
# nonsense. Failing here is the only honest outcome.
cd "$(dirname "$0")/../.." || exit 1
# shellcheck source=scripts/release-gate/lib.sh
. scripts/release-gate/lib.sh

# ── --selftest ──────────────────────────────────────────────────────────────────────────────────
#
# The gate's own machinery, exercised offline. Every case here is one that the code as it stood
# BEFORE the case existed got WRONG in the green direction — that is the entrance requirement, and
# it is why these are not "does expected-ids still print things" smoke tests. No network, no
# release, no runner: each case stages a contract or a ledger and reads the verdict.
selftest() {
  local rc_bad=0 tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/relgate-selftest-XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  local repo; repo="$PWD"

  ok()  { printf '  [ok]     %s\n' "$1"; }
  nope() { printf '  [FAILED] %s\n' "$1"; rc_bad=1; }

  echo "release-gate selftest"

  # ── CASE 1: a contract jq cannot read must not yield a SHORT list and exit 0 ──────────────────
  # Was: `done < <(published_targets)`. A process substitution's status is not the loop's and
  # `set -e` never sees it, so a failed jq dropped all 36 per-target ids and the script exited 0
  # with a well-formed 24-line answer. gate.sh checked only that exit code.
  printf 'this is not json\n' > "$tmp/broken.json"
  if CONTRACT="$tmp/broken.json" scripts/release-gate/expected-ids.sh >"$tmp/broken.out" 2>"$tmp/broken.err"; then
    nope "expected-ids EXITED 0 on an unparseable contract (printed $(awk 'END{print NR+0}' "$tmp/broken.out") ids) — a short list un-owes every check it dropped"
  else
    ok "expected-ids refuses an unparseable contract instead of printing a short list"
  fi

  # ── CASE 2: a contract that lost platforms trips the target floor ─────────────────────────────
  # The v1.5.3 defect in contract form: five assets where seven were owed. A count of targets that
  # quietly shrinks makes the gate owe fewer rows and go green having checked fewer platforms.
  jq '.targets = [(.targets[] | select(.published == true))][0:1]' .github/release-targets.json \
    > "$tmp/thin.json" 2>/dev/null || printf '{"targets":[]}\n' > "$tmp/thin.json"
  if CONTRACT="$tmp/thin.json" scripts/release-gate/expected-ids.sh >"$tmp/thin.out" 2>/dev/null; then
    nope "expected-ids accepted a contract with ONE published target — the other platforms are owed by nobody"
  else
    ok "expected-ids refuses a contract that collapsed to one published target"
  fi

  # ── CASE 3: the real contract still clears both floors and names every target ─────────────────
  # The floors must not be tripwires that only ever fire; this is the other half.
  if scripts/release-gate/expected-ids.sh > "$tmp/real.out" 2>/dev/null; then
    local n; n="$(awk 'NF{c++} END{print c+0}' "$tmp/real.out")"
    local ntgt; ntgt="$(grep -c '^plugin:' "$tmp/real.out" || true)"
    if [ "$n" -ge "$GATE_EXPECTED_FLOOR_DEFAULT" ] && [ "$ntgt" -ge 5 ]; then
      ok "the real contract yields ${n} ids over ${ntgt} published targets, clearing both floors"
    else
      nope "the real contract yields only ${n} ids over ${ntgt} targets — floors are set above reality"
    fi
  else
    nope "expected-ids FAILED on the real contract"
  fi

  # ── CASE 4: gate.sh floors the expected list on its own side ──────────────────────────────────
  # Staged with a stub expected-ids that exits 0 and prints three ids, which is precisely what a
  # jq failure used to look like from here. Before the floor, three passing ledger rows against a
  # three-id list printed "GREEN. Every one of the 3 contracted checks ran and passed."
  mkdir -p "$tmp/fake/scripts/release-gate" "$tmp/fake/ledgers"
  cp "$repo/scripts/release-gate/gate.sh" "$repo/scripts/release-gate/lib.sh" "$tmp/fake/scripts/release-gate/"
  cat > "$tmp/fake/scripts/release-gate/expected-ids.sh" <<'STUB'
#!/usr/bin/env bash
printf 'release:exists\tthe release exists\n'
printf 'meta:openapi\tthe openapi asset is there\n'
printf 'docker:label\tthe label matches\n'
exit 0
STUB
  chmod +x "$tmp/fake/scripts/release-gate/expected-ids.sh"
  {
    printf 'release:exists\tPASS\tok\t\n'
    printf 'meta:openapi\tPASS\tok\t\n'
    printf 'docker:label\tPASS\tok\t\n'
  } > "$tmp/fake/ledgers/leg.tsv"
  if LEDGER_DIR="$tmp/fake/ledgers" RUNNER_TEMP="$tmp/fake" GITHUB_STEP_SUMMARY=/dev/null \
     "$tmp/fake/scripts/release-gate/gate.sh" 9.9.9 >"$tmp/fake/out" 2>&1; then
    nope "gate.sh printed GREEN against a three-id expected list — a collapsed contract passes the gate"
  else
    if grep -q 'expected-check list came back with only 3' "$tmp/fake/out"; then
      ok "gate.sh goes RED, by name, when the expected-check list collapses"
    else
      nope "gate.sh went red against a three-id list but not for the short-list reason: $(tr '\n' ' ' < "$tmp/fake/out" | cut -c1-200)"
    fi
  fi

  echo
  if [ "$rc_bad" = 0 ]; then echo "release-gate selftest: the gate's floors and the plugin matcher all hold"; return 0; fi
  echo "release-gate selftest: FAILED"; return 1
}

# The floor the selftest measures the real contract against. Named separately from the runtime
# default below so raising one cannot silently un-check the other.
GATE_EXPECTED_FLOOR_DEFAULT=50

if [ "${1:-}" = "--selftest" ]; then selftest; exit $?; fi

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

# ── EVERY ROW MUST NAME THE VERSION IT IS ABOUT ────────────────────────────────────────────────
# The ledgers are downloaded artifacts merged by name pattern, and nothing in that path binds a row
# to the release under test. A leg that resolved a different version (release-fleet's `resolve`
# falls back to "the current latest release" when none is supplied), a re-run whose inputs changed
# between legs, or a stale ledger sitting in $RUNNER_TEMP from an earlier local run all contribute
# rows that read exactly like evidence for THIS release. So the version travels IN the row (lib.sh's
# fifth column) and only rows naming this version count. A row naming anything else — or nothing at
# all, which is what a row written by a check that never learned its version looks like — is named
# and is RED: it is a check that verified some other release, and counting it here would let a
# green verdict for 1.5.4 stand in for 1.6.0.
MINE="${RUNNER_TEMP:-/tmp}/release-gate-mine.tsv"
awk -F'\t' -v v="$VERSION" 'NF && $5 == v' "$ALL" > "$MINE"
foreign_ids="$(awk -F'\t' -v v="$VERSION" \
  'NF && $5 != v {printf "%s(%s) ", $1, ($5 == "" ? "<no version>" : $5)}' "$ALL")"
if [ -n "$foreign_ids" ]; then
  echo "::error title=release gate::RED — these ledger rows are about a DIFFERENT release than ${VERSION:-<unknown>}, and are NOT counted as evidence for it: ${foreign_ids}. Fix: find the leg that ran against another version (a stale workflow input, a resolve fallback to 'latest', or a ledger file left over from an earlier run in the same temp dir) and re-run it against ${VERSION:-this version}."
fi
ALL="$MINE"
rows="$(awk 'NF{n++} END{print n+0}' "$ALL")"

# ── THE VACUOUS-GREEN GUARD, FIRST, BEFORE ANY OTHER VERDICT ────────────────────────────────────
if [ "$rows" -eq 0 ]; then
  echo "::error title=release gate::VACUOUS RUN: ZERO checks reported a result. Nothing about ${VERSION:-this release} was verified. This is RED by construction — a gate that passes because it did nothing is worse than no gate. Fix: look at the matrix legs above; the ledger artifacts were empty or were never uploaded."
  {
    echo "## Release gate: RED — vacuous run"
    echo
    echo "**Zero checks reported a result for this version.** Nothing was verified. Ledger dir: \`${LEDGER_DIR}\`.${foreign_ids:+ Rows WERE present, but every one of them named a different release: \`${foreign_ids}\`.}"
  } >> "$SUMMARY"
  exit 1
fi

# ── Diff against what is owed ───────────────────────────────────────────────────────────────────
EXPECTED="${RUNNER_TEMP:-/tmp}/release-gate-expected.tsv"
if ! scripts/release-gate/expected-ids.sh --describe > "$EXPECTED"; then
  echo "::error title=release gate::could not derive the expected check list from ${CONTRACT}. Every 'did not run' verdict below would be vacuous, so this is RED rather than a pass. Fix: validate ${CONTRACT} parses as JSON and carries a non-empty .targets[]."
  exit 1
fi

# THE EXIT CODE IS NOT THE WHOLE STORY, AND USED NOT TO BE ANY OF IT. expected-ids.sh derived its
# per-target ids inside `while read; done < <(published_targets)`, whose process-substitution status
# `set -e` never sees — so a failed jq dropped all 36 per-target ids and the script still exited 0.
# The check above accepted that, and a gate that is owed fewer checks passes having verified fewer
# things while printing the same shape of green. expected-ids.sh now refuses to print a short list;
# this is the independent floor on the consuming side, because "the producer promises" is exactly
# the assumption the six-day defect was built on.
: "${GATE_EXPECTED_FLOOR:=50}"
expected_n="$(awk 'NF{n++} END{print n+0}' "$EXPECTED")"
if [ "$expected_n" -lt "$GATE_EXPECTED_FLOOR" ]; then
  echo "::error title=release gate::the expected-check list came back with only ${expected_n} ids (floor ${GATE_EXPECTED_FLOOR}). A short list means whole classes of check are owed by nobody, so their silence would read as green. RED by construction. Fix: run scripts/release-gate/expected-ids.sh --describe by hand and see what it stopped deriving from ${CONTRACT}."
  {
    echo "## Release gate: RED — the expected-check list is short"
    echo
    echo "Only \`${expected_n}\` ids were owed (floor \`${GATE_EXPECTED_FLOOR}\`)."
  } >> "$SUMMARY"
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
  [ -z "$foreign_ids" ] || {
    echo
    echo "> **Rows about a different release, not counted:** \`${foreign_ids}\`"
  }
} >> "$SUMMARY"

rc=0
if [ -n "$foreign_ids" ]; then
  # Re-stated here so it lands in the verdict block with everything else that makes the run red; the
  # ::error:: above fires before the vacuous guard so it is visible even on a run with no usable rows.
  rc=1
fi
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

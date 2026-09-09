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

  # CASE 2 (the target floor) and CASE 4 (the gate's own short-list floor) are not here:
  # both floors are introduced by 4a6fef385, which is not landing. The property they
  # guard -- a contract that quietly loses platforms must not make the gate owe fewer
  # rows -- is still worth having; it comes back with the commit that defines it.

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

  # ── CASE 5b: the published archive is bound to the STAGED record, or the row is red ───────────
  #
  # Before this, nothing downstream of the build ever compared a published byte to the record qa
  # wrote. Six per-target rows asserted properties the archive can have while being an archive
  # nobody staged. The case that proves it is the one no release can stage: two DIFFERENT archives
  # that both pass every other row.
  local sdir; sdir="$tmp/staged"
  mkdir -p "$sdir"
  printf 'the bytes qa staged\n'            > "$sdir/staged-archive"
  printf 'a different archive, uploaded later\n' > "$sdir/other-archive"
  local staged_hash other_hash
  staged_hash="$(sha256_file "$sdir/staged-archive")"
  other_hash="$(sha256_file "$sdir/other-archive")"
  jq -n --arg h "$staged_hash" \
    '{version:"9.9.9", assets:[{name:"busbar-x86_64-unknown-linux-gnu.tar.gz", size:19, sha256:$h}]}' \
    > "$sdir/staged.json"

  if [ "$staged_hash" = "$other_hash" ]; then
    nope "sha256_file returned the same digest for two different files — the whole row is decorative"
  else
    ok "sha256_file distinguishes two archives that differ by one line"
  fi
  local looked_up
  looked_up="$(STAGED_RECORD="$sdir/staged.json" staged_asset_sha256 busbar-x86_64-unknown-linux-gnu.tar.gz || true)"
  if [ "$looked_up" = "$staged_hash" ]; then
    ok "the staged record's digest for a named asset is read back out of it"
  else
    nope "staged_asset_sha256 did not return the recorded digest (got '${looked_up:-<none>}')"
  fi
  if digest_matches "$other_hash" "$looked_up"; then
    nope "an archive that is NOT the staged one compared EQUAL to the staged record — a rebuilt or hand-uploaded asset would ship green"
  else
    ok "an archive that is not the staged one does not match the staged record"
  fi
  if digest_matches "$staged_hash" "$looked_up"; then
    ok "and the genuinely staged archive still matches (the fix did not break the pass path)"
  else
    nope "the staged archive did not match its own recorded digest — the fix broke the pass path"
  fi
  # THE VACUOUS CASE, which is the reason digest_matches exists as a function rather than as `=`.
  # `[ "$got" = "$want" ]` is TRUE when both sides are empty, and both sides are empty in every
  # way this lookup can fail: no STAGED_RECORD on the runner, a record whose assets lost this name,
  # a jq that is not installed. A bare string compare would have called all of those a match.
  if [ -n "$(STAGED_RECORD="$sdir/staged.json" staged_asset_sha256 busbar-aarch64-apple-darwin.tar.gz || true)" ]; then
    nope "staged_asset_sha256 answered for an asset the record does not name"
  else
    ok "an asset the staged record does not name has no digest, rather than a blank one"
  fi
  if [ -n "$(STAGED_RECORD="$sdir/nonexistent.json" staged_asset_sha256 busbar-x86_64-unknown-linux-gnu.tar.gz || true)" ]; then
    nope "staged_asset_sha256 answered from a record file that does not exist"
  else
    ok "a missing staged record yields no digest at all"
  fi
  if digest_matches "" ""; then
    nope "two EMPTY digests compared equal — every way the lookup can fail would read as 'the bytes match'"
  else
    ok "two empty digests are not a match: a record that could not answer cannot bind anything"
  fi
  if digest_matches "$staged_hash" ""; then
    nope "a real archive matched an ABSENT expectation"
  else
    ok "a real archive does not match an absent expectation"
  fi
  printf '{"assets":[{"name":"a.tar.gz","sha256":"%s"},{"name":"a.tar.gz","sha256":"%s"}]}\n' \
    "$staged_hash" "$other_hash" > "$sdir/dup.json"
  if [ -n "$(STAGED_RECORD="$sdir/dup.json" staged_asset_sha256 a.tar.gz || true)" ]; then
    nope "a record naming one asset twice with two digests still produced AN answer — first-row-wins, in another file"
  else
    ok "a record that names one asset twice with different digests has no answer for it"
  fi

  # ── CASE 5c: the registry names are compared to the RECORD, not to each other ─────────────────
  #
  # docker-checks resolved `:<version>` on Docker Hub and then measured `:latest`, ghcr's
  # `:<version>` and ghcr's `:latest` against THAT digest — a value the same run had just fetched.
  # Four names agreeing with each other is what those rows proved, and four names all pointing at
  # bytes qa never staged satisfies every one of them: a promote that rebuilt instead of retagging
  # pushes one image under every name. The case below is exactly that release.
  local staged_img rebuilt_img
  staged_img="sha256:$(printf '%064d' 1 | tr 0 b)"
  rebuilt_img="sha256:$(printf '%064d' 1 | tr 0 c)"
  jq -n --arg d "$staged_img" --arg c "$rebuilt_img" '{digest:$d, compat_digest:$c}' > "$sdir/img.json"
  if digest_matches "$rebuilt_img" "$rebuilt_img"; then
    ok "two registry names agreeing with each other still compare equal — which is why that was never the question"
  else
    nope "the comparison no longer sees two identical digests as equal"
  fi
  if digest_matches "$rebuilt_img" "$(STAGED_RECORD="$sdir/img.json" staged_image_digest)"; then
    nope "a rebuilt image that every registry name agrees on matched the STAGED record — a promote that recompiled would ship green on all four docker rows"
  else
    ok "an image every registry name agrees on is still not the staged image"
  fi
  if digest_matches "$staged_img" "$(STAGED_RECORD="$sdir/img.json" staged_image_digest)"; then
    ok "and the genuinely staged image matches its recorded digest"
  else
    nope "the staged image did not match its own recorded digest — the fix broke the pass path"
  fi
  if [ "$(STAGED_RECORD="$sdir/img.json" staged_compat_digest)" = "$rebuilt_img" ]; then
    ok "the armv8.0-compat image is anchored on its OWN recorded digest, not the default manifest's"
  else
    nope "staged_compat_digest did not return .compat_digest"
  fi
  # An anchor that is not a digest is no anchor. A registry answers `sha256:<hex>`; a record that
  # lost the prefix, or carries a tag name, or is empty, must not become an expectation everything
  # is then compared to.
  local bogus
  for bogus in "" "latest" "1.5.4" "sha256:abc" "deadbeef"; do
    printf '{"digest":"%s"}\n' "$bogus" > "$sdir/bogus.json"
    if [ -n "$(STAGED_RECORD="$sdir/bogus.json" staged_image_digest || true)" ]; then
      nope "a staged record whose digest is '${bogus}' was accepted as an anchor"
    fi
  done
  ok "a record whose digest is empty, a tag, or a truncated hash yields no anchor at all"

  # ── CASE 6: a version match cannot be satisfied by a LONGER version ───────────────────────────
  # `grep -q "1.5.2"` matches "1.5.20". install:e2e (the row proving the documented first command
  # installs THIS release) and helm:render (the row proving the published chart deploys THIS image
  # tag) both used the unanchored form; site:download-page, in the same file, used the anchored one
  # and wrote down why. The failure only appears once the patch number reaches two digits, which is
  # to say it hides for years and then passes on exactly the release where it matters.
  if printf 'busbar 1.5.20' | grep -qE "$(version_re 1.5.2)"; then
    nope "the version matcher accepted 1.5.20 as 1.5.2 — the gate would pass on the wrong release"
  else
    ok "1.5.20 is not accepted as 1.5.2 (the right anchor holds)"
  fi
  if printf 'busbar 21.5.4' | grep -qE "$(version_re 1.5.4)"; then
    nope "the version matcher accepted 21.5.4 as 1.5.4 — the LEFT anchor is missing"
  else
    ok "21.5.4 is not accepted as 1.5.4 (the left anchor holds)"
  fi
  for good in "busbar 1.5.2" "v1.5.2" "busbar 1.5.2 (abcdef)" "1.5.2"; do
    if printf '%s' "$good" | grep -qE "$(version_re 1.5.2)"; then :; else
      nope "the version matcher REJECTED a genuine match: '${good}' — the fix broke the pass path"
    fi
  done
  ok "every genuine spelling of the version under test still matches"
  if printf 'image: "getbusbar/busbar:1.5.20"' | grep -qE "busbar:$(version_re_after 1.5.2)"; then
    nope "the after-a-prefix matcher accepted busbar:1.5.20 as busbar:1.5.2"
  else
    ok "busbar:1.5.20 is not accepted as busbar:1.5.2 after a literal prefix"
  fi
  if printf 'image: "getbusbar/busbar:1.5.2"' | grep -qE "busbar:$(version_re_after 1.5.2)"; then
    ok "and busbar:1.5.2 still matches after that prefix"
  else
    nope "version_re_after rejected a genuine busbar:1.5.2 — the left anchor was wrongly added"
  fi

  # CASE 7 (the container boot rows) is not here, for the same reason as CASE 5:
  # `start_container` and `is_running` are defined in 4a6fef385, which is not landing.

  echo
  if [ "$rc_bad" = 0 ]; then echo "release-gate selftest: the short-list refusal, the staged-record digests and the version anchors all hold"; return 0; fi
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

# ── THE ROWS MUST BE ABOUT THE RELEASE ON THE COMMAND LINE ─────────────────────────────────────
#
# Second, immediately after the vacuous-green guard and before a single verdict is read, because a
# ledger about another release is not a weaker answer than no ledger — it is a CONFIDENT one. A
# full set of green rows from the previous version reports "Every one of the 72 contracted checks
# for <this version> ran and passed", which is true about the count and false about the subject,
# and there is no later check that can notice.
#
# It gets here honestly: LEDGER is appended to and never truncated, download-artifact merges every
# ledger it is handed into one directory, and the fan-out can be dispatched at a second version on
# the same runner. Each row now stamps the version and the qa sha it was produced against, so this
# is a comparison and not an inference.
foreign="$(ledger_foreign_rows "$ALL" "${VERSION:-}")"
if [ -n "$foreign" ]; then
  echo "::error title=release gate::WRONG RELEASE: this gate was asked about '${VERSION:-<unknown>}' but the ledger carries rows about something else: ${foreign}. A row that names another version — or names none — cannot be counted toward this one, and a full set of stale green rows reads exactly like a verified release. RED by construction. Fix: the ledger is APPENDED to and never truncated, so a re-run on a persisted RUNNER_TEMP, a merged download-artifact directory, or a second dispatch on the same runner leaves the previous release's rows in place. Start from an empty LEDGER_DIR."
  {
    echo "## Release gate: RED — the ledger is about a different release"
    echo
    echo "Asked about \`${VERSION:-<unknown>}\`; these rows name something else: \`${foreign}\`"
  } >> "$SUMMARY"
  exit 1
fi
shas="$(ledger_sha_disagreements "$ALL")"
if [ -n "$shas" ]; then
  echo "::error title=release gate::TWO STAGINGS, ONE NAME: the ledger's rows were produced against more than one qa sha (${shas}). One version staged twice from two commits is two releases wearing one name — which is why the promote consumes a staged record and not a version. RED. Fix: verify every leg ran against the same staged record, and start from an empty LEDGER_DIR."
  { echo; echo "### RED — the ledger mixes qa shas: \`${shas}\`"; } >> "$SUMMARY"
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
  # EVERY row for the id, not the first one. The old `$1==i{print; exit}` meant a PASS written
  # before a later FAIL was the only row the gate ever read — and the ledger is appended to, never
  # truncated, so a re-run or a retrying leg produces exactly that pair. ledger_status_for (lib.sh)
  # resolves the id across all of its rows and says CONFLICT when they disagree.
  status="$(ledger_status_for "$ALL" "$id")"
  if [ -z "$status" ]; then
    missing_ids="${missing_ids}${id} "
    printf '%-12s %-46s %s\n' "DID NOT RUN" "$id" "$desc" >> "$report"
    continue
  fi
  # The detail comes from the WORST row present, so a conflicted or failed id shows the reason
  # rather than whichever row happened to be written first.
  detail="$(awk -F'\t' -v i="$id" '$1==i && $2!="PASS" {print $4; exit}' "$ALL")"
  [ -n "$detail" ] || detail="$(awk -F'\t' -v i="$id" '$1==i{print $4; exit}' "$ALL")"
  case "$status" in
    CONFLICT)
      fail_ids="${fail_ids}${id} "
      printf '%-12s %-46s %s\n' "CONFLICT" "$id" \
        "this id was reported more than once with DIFFERENT verdicts ($(ledger_rows_for "$ALL" "$id")) — the ledger does not say what happened, which is not a pass. ${detail}" >> "$report"
      ;;
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
# `pass_n`, not `rows`. `rows` is the raw ledger LINE count — it includes duplicate rows for one id
# and rows for ids the contract never asked about, so the one sentence a human reads was overstating
# how much was verified by exactly the amount the ledger had been polluted.
echo "RELEASE GATE: GREEN. Every one of the ${pass_n} contracted checks for ${VERSION} ran and passed."
{ echo; echo "### GREEN — all ${pass_n} contracted checks passed."; } >> "$SUMMARY"

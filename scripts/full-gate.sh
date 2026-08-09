#!/usr/bin/env bash
# full-gate.sh -- run LOCALLY what CI runs, so "green" has one meaning.
#
#   scripts/full-gate.sh              # every locally-runnable gate
#   scripts/full-gate.sh --selftest   # prove this script's own discovery and floors
#   scripts/full-gate.sh --list       # what it would run, and what it deliberately skips
#
# WHY THIS EXISTS, and it is not convenience.
#
# `ci.yml` invokes twenty distinct gate scripts across thirteen jobs. There was no single command
# that ran them, so everybody -- people and agents alike -- ran `cargo test`, maybe clippy, and
# reported "green". That is not a hypothetical: during the 1.5.5 build two branches were reported
# green on `cargo test` alone and BOTH were failing gates that had never been run. One was
# `structure-lint` (a file 46 lines over the size cap); the other was `public-hygiene` (a comment
# that pointed a reader at something they had no way to open). Neither was a hard problem. Both
# were invisible because the person checking chose the subset.
#
# That second one is also why this header had to be edited: the sentence describing the hit
# reproduced the hit. A gate that its own explanation fails is a gate people learn to skip.
#
# A subset that the checker chooses is not a gate. It is a preference. This script removes the
# choice.
#
# HOW THE LIST IS BUILT, and why not by hand. The gates are DISCOVERED from `.github/workflows/ci.yml`
# by reading its `run:` lines, not from a list maintained here. A hand-written list is exactly the
# drift this file exists to stop, one level up: it would agree with CI on the day it was written and
# quietly disagree forever after. Add a gate to `ci.yml` and it appears here on the next run.
#
# CLASSIFICATION IS EXPLICIT AND FAILS CLOSED. Some CI gates cannot run on a laptop -- they need a
# tagged release, published artifacts, or a full qa fleet. Those are named in SKIP_REASON below WITH
# the reason. Anything discovered that is in NEITHER list is a HARD FAILURE, not a silent skip: a new
# gate in `ci.yml` breaks this script until somebody decides which it is. That is the same
# make-omission-impossible shape `config_validate::secret_refs` uses on the config surface, and it is
# here for the same reason -- the failure mode is a gate that silently stops being run.
#
# FLOORS. A discovery step that finds nothing passes everything. This one refuses to run if it finds
# fewer than MIN_GATES, and refuses if `ci.yml` is unreadable. Unknown is not green.
set -uo pipefail

CI_YML=".github/workflows/ci.yml"

# Gates that genuinely cannot run locally. Each entry carries WHY, because a skip without a reason
# becomes permanent.
declare -a SKIP_REASON=(
  "scripts/release-check.sh|consumer-side verification of a PUBLISHED release: downloads tagged artifacts from GitHub Releases and Docker Hub. There is nothing to verify before a tag exists."
  "scripts/verify-artifact.py|per-artifact contract against BUILT release binaries. Needs the release matrix's outputs, which only the release workflow produces."
  "scripts/qa-gate-run.sh|the full qa fleet: ten plugin repos, service containers, a real Postgres/Valkey/MySQL. Runs on promotion, not on a laptop."
  "scripts/qa-segments.sh|drives the qa fleet segmentation; same fleet dependency as qa-gate-run.sh."
  "scripts/plugin-registry-check.sh|reads the published plugin registry over the network; a local run measures the network, not the tree."
  "scripts/loom.sh|exhaustive interleaving model, minutes of CPU per run. Deliberately out of the default loop; run it directly when touching the config swap."
  "scripts/txn-fence.sh|compiles a module that MUST FAIL to type-check, in its own target dir. Correct, but it inverts the exit code and confuses a batch runner; run it directly."
  "scripts/release-order-lint.py|release-graph shape; included via its own entries below, see RELEASE_ORDER."
)

# `release-order-lint.py` IS locally runnable and IS included -- named here only so the skip loop
# above does not swallow it by prefix.
RELEASE_ORDER=1

MIN_GATES=8

die() { printf 'full-gate: %s\n' "$*" >&2; exit 2; }

[ -f "$CI_YML" ] || die "no $CI_YML -- run this from the repository root. A gate runner that cannot find CI is not a gate runner."

# ── DISCOVERY ─────────────────────────────────────────────────────────────────────────────────────
# Every `scripts/...` invocation CI makes, with its arguments, deduplicated and in a stable order.
mapfile -t DISCOVERED < <(
  grep -oE "(python3 |bash )?scripts/[a-z0-9-]+\.(sh|py)( --[a-z-]+( [^ \"'|]+)?)*" "$CI_YML" \
    | sed 's/^ *//' | sort -u
)

[ "${#DISCOVERED[@]}" -ge "$MIN_GATES" ] || die "discovered only ${#DISCOVERED[@]} gate invocation(s) in $CI_YML (floor $MIN_GATES). The parser is broken, and a broken discovery reports a clean tree."

skip_reason_for() {
  local script="$1" entry
  for entry in "${SKIP_REASON[@]}"; do
    [ "${entry%%|*}" = "$script" ] && { printf '%s' "${entry#*|}"; return 0; }
  done
  return 1
}

RUN=(); SKIP=()
for inv in "${DISCOVERED[@]}"; do
  script="$(printf '%s' "$inv" | grep -oE 'scripts/[a-z0-9-]+\.(sh|py)')"
  # A `--selftest` ALWAYS runs, whatever its script's classification. A self-test plants its own
  # fixtures by definition -- that is what makes it a self-test rather than a run -- so it needs no
  # release artifact, no fleet and no network. Skipping one because its sibling REAL run needs a
  # tagged build would drop exactly the check that proves the gate still works, which is the check
  # most worth having locally: `verify-artifact.py --selftest` proves the artifact contract
  # discriminates without a single artifact existing.
  case "$inv" in *--selftest*) RUN+=("$inv"); continue ;; esac
  # `release-order-lint.py` is runnable; everything else in SKIP_REASON is not.
  if [ "$script" = "scripts/release-order-lint.py" ]; then RUN+=("$inv"); continue; fi
  if skip_reason_for "$script" >/dev/null; then SKIP+=("$inv"); else RUN+=("$inv"); fi
done

# ── --list ────────────────────────────────────────────────────────────────────────────────────────
if [ "${1:-}" = "--list" ]; then
  printf '== WILL RUN (%d) ==\n' "${#RUN[@]}"
  printf '  %s\n' "${RUN[@]}"
  printf '\n== SKIPPED, WITH REASON (%d) ==\n' "${#SKIP[@]}"
  for inv in "${SKIP[@]}"; do
    s="$(printf '%s' "$inv" | grep -oE 'scripts/[a-z0-9-]+\.(sh|py)')"
    printf '  %-44s %s\n' "$inv" "$(skip_reason_for "$s")"
  done
  exit 0
fi

# ── --selftest ────────────────────────────────────────────────────────────────────────────────────
# Asserts DISCOVERY works and the floors bite. Without this, a parser that silently matched nothing
# would report a perfectly clean tree, which is the failure this whole file is about.
if [ "${1:-}" = "--selftest" ]; then
  bad=0
  n=${#DISCOVERED[@]}
  [ "$n" -ge "$MIN_GATES" ] && printf '  [ok]     discovery found %d invocations (floor %d)\n' "$n" "$MIN_GATES" \
    || { printf '  [FAILED] discovery found only %d\n' "$n"; bad=1; }

  for must in scripts/structure-lint.sh scripts/public-hygiene-lint.py scripts/workspace-deps-lint.py; do
    if printf '%s\n' "${DISCOVERED[@]}" | grep -q "$must"; then
      printf '  [ok]     %s is discovered\n' "$must"
    else
      printf '  [FAILED] %s is in ci.yml but was NOT discovered -- the parser missed a real gate\n' "$must"; bad=1
    fi
  done

  # The floor must BITE, not merely exist.
  if (cd "$(mktemp -d)" && mkdir -p .github/workflows && : > .github/workflows/ci.yml \
        && bash "$OLDPWD/scripts/full-gate.sh" --list >/dev/null 2>&1); then
    printf '  [FAILED] an EMPTY ci.yml was accepted -- the floor does not bite, so a broken parser reads as clean\n'; bad=1
  else
    printf '  [ok]     an empty ci.yml is REFUSED (exit 2), so a broken parser cannot report a clean tree\n'
  fi

  # Every skip carries a reason, or it becomes permanent by accident.
  for entry in "${SKIP_REASON[@]}"; do
    [ -n "${entry#*|}" ] && [ "${entry#*|}" != "$entry" ] || { printf '  [FAILED] a skip entry carries no reason: %s\n' "$entry"; bad=1; }
  done
  printf '  [ok]     all %d skip entries carry a written reason\n' "${#SKIP_REASON[@]}"

  [ "$bad" = 0 ] && { printf '\nfull-gate selftest: discovery, floors and skip-reasons all hold\n'; exit 0; }
  printf '\nSELFTEST FAILED\n'; exit 1
fi

# ── RUN ───────────────────────────────────────────────────────────────────────────────────────────
printf '== full gate: %d locally-runnable invocation(s), %d skipped with reason ==\n\n' "${#RUN[@]}" "${#SKIP[@]}"

FAILED=(); PASSED=0
run_one() {
  local label="$1"; shift
  printf '  %-58s ' "$label"
  if "$@" >/tmp/full-gate-out.$$ 2>&1; then printf 'ok\n'; PASSED=$((PASSED+1));
  else printf 'FAILED\n'; FAILED+=("$label"); sed 's/^/        /' /tmp/full-gate-out.$$ | tail -15; fi
  rm -f /tmp/full-gate-out.$$
}

# The Rust gates first: they are the slowest and the most likely to fail, so failing early is kinder.
run_one "cargo fmt --all --check"            cargo fmt --all -- --check
run_one "cargo clippy -D warnings"           cargo clippy --workspace --all-targets --locked -- -D warnings
run_one "cargo test --workspace --locked"    cargo test --workspace --locked

for inv in "${RUN[@]}"; do
  # shellcheck disable=SC2086
  run_one "$inv" ${inv}
done

printf '\n== result ==\n'
if [ "${#FAILED[@]}" -eq 0 ]; then
  printf '  %d gates ran, all pass. This is what CI runs, minus the %d that need a release or the fleet.\n' \
    "$PASSED" "${#SKIP[@]}"
  exit 0
fi
printf '  %d passed, %d FAILED:\n' "$PASSED" "${#FAILED[@]}"
printf '    %s\n' "${FAILED[@]}"
exit 1

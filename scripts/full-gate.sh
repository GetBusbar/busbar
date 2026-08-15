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
#
# THE CARGO INVOCATIONS ARE DISCOVERED AND CLASSIFIED THE SAME WAY, and that is a repair, not a
# feature. This script used to hard-code three cargo lines -- fmt, clippy, test, all on the DEFAULT
# feature set, on this host. CI runs eleven, across FOUR build configurations, and the three that
# were missing are the three that have now taken the 1.6.0 build down in a row: a stale committed
# `openapi.json` (`--features openapi-schema`), a hook-resolution defect that only surfaced under
# `--no-default-features`, and an mTLS test reading a client-side error string that Windows words
# differently. Every one of them was reported 33/33 green here on the exact commit CI rejected.
#
# A local green that does not cover the configuration CI runs is not the same claim as a CI green,
# and it was being read as one. So the cargo lines are now read out of `ci.yml` like everything
# else, each is classified LOCAL or CI-only WITH A REASON, and an unclassified one is a hard
# failure -- the same fails-closed shape the script's rule already had. Windows genuinely cannot run
# here; that is named as such, and the final line says so rather than letting "all pass" imply it.
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

# ── THE CARGO GATES ───────────────────────────────────────────────────────────────────────────────
# CI's cargo invocations, normalised (spaces collapsed, `--verbose` dropped -- it changes output, not
# what is proven). LOCAL ones run here, in this order. CI-only ones carry their reason.
#
# Normalisation is what makes the two `--workspace` pairs distinguishable: the Linux job passes
# `--locked` and the Windows job does not, so "same command, different platform" does not collapse
# into one entry.
declare -a CARGO_LOCAL=(
  "cargo fmt --all -- --check"
  "cargo clippy --workspace --all-targets --locked -- -D warnings"
  "cargo build --workspace --locked"
  "cargo test --workspace --locked"
  "cargo clippy --no-default-features --locked -- -D warnings"
  "cargo build --no-default-features --locked"
  "cargo test --no-default-features --locked"
  "cargo clippy -p busbar -p busbar-core --all-targets --features openapi-schema --locked -- -D warnings"
  "cargo test -p busbar -p busbar-core --features openapi-schema --locked openapi -- --nocapture"
  "cargo build --locked --bin busbar"
  "cargo test -p busbar --test migration_corpus --locked -- --nocapture"
)

declare -a CARGO_CI_ONLY=(
  "cargo build --workspace|the WINDOWS job's build. There is no Windows host here, and the failures it catches are precisely the ones that do not reproduce on this one -- path separators, socket error wording, line endings. Nothing local substitutes for it."
  "cargo test --workspace|the WINDOWS job's test run; same reason. This is the one gap a local run genuinely cannot close: read a green here as 'green on this platform'."
  "cargo clippy --workspace --all-targets -- -D warnings|the WINDOWS job's clippy. It exists to catch the platform-gated code no local run compiles at all -- a #[cfg(unix)] item whose #[cfg(windows)] twin was never written is a warning THERE and nowhere here. A macOS/Linux clippy cannot substitute: it takes the other arm of every cfg. Approximated locally with 'cargo xwin clippy --target x86_64-pc-windows-msvc', which type-checks the Windows arms without a Windows host but still executes nothing."
  "cargo test --release --locked timing_gate -- --ignored|a RELEASE-profile wall-clock gate on a dedicated runner. A debug tree with a compiler and a browser competing for the CPU measures the laptop, not the engine; run it directly when touching the timing path."
)

# Normalise a cargo invocation for comparison: drop the shell plumbing CI wraps it in (`2>&1`),
# drop `--verbose` (it changes output, not what is proven), collapse whitespace.
cargo_norm() {
  printf '%s\n' "$1" | sed -e 's/2>&1//g' -e 's/--verbose//g' -e 's/[[:space:]]\{1,\}/ /g' -e 's/^ //' -e 's/ $//'
}

cargo_ci_only_reason() {
  local cmd="$1" entry
  for entry in "${CARGO_CI_ONLY[@]}"; do
    [ "${entry%%|*}" = "$cmd" ] && { printf '%s' "${entry#*|}"; return 0; }
  done
  return 1
}

die() { printf 'full-gate: %s\n' "$*" >&2; exit 2; }

[ -f "$CI_YML" ] || die "no $CI_YML -- run this from the repository root. A gate runner that cannot find CI is not a gate runner."

# ── DISCOVERY ─────────────────────────────────────────────────────────────────────────────────────
# Every `scripts/...` invocation CI makes, with its arguments, deduplicated and in a stable order.
mapfile -t DISCOVERED < <(
  grep -oE "(python3 |bash )?scripts/[a-z0-9-]+\.(sh|py)( --[a-z-]+( [^ \"'|]+)?)*" "$CI_YML" \
    | sed 's/^ *//' | sort -u
)

[ "${#DISCOVERED[@]}" -ge "$MIN_GATES" ] || die "discovered only ${#DISCOVERED[@]} gate invocation(s) in $CI_YML (floor $MIN_GATES). The parser is broken, and a broken discovery reports a clean tree."

# Every cargo invocation CI makes, normalised. COMMENT LINES ARE STRIPPED FIRST: `ci.yml` documents
# the openapi refresh command in a comment, and a documented command is not a gate.
mapfile -t CARGO_DISCOVERED < <(
  sed -e 's/^[[:space:]]*#.*$//' "$CI_YML" \
    | grep -v "^[[:space:]]*echo " \
    | grep -oE 'cargo (fmt|clippy|build|test|run)[^"|)]*' \
    | while IFS= read -r c; do cargo_norm "$c"; done \
    | grep -v '^$' | sort -u
)

# FAILS CLOSED, exactly as the script's rule does: a cargo invocation in `ci.yml` that is in NEITHER
# list breaks this script until somebody decides which it is. Silence here is how the openapi and
# no-default-features configurations went unrun for three releases.
CARGO_UNCLASSIFIED=()
for cmd in "${CARGO_DISCOVERED[@]}"; do
  known=0
  for l in "${CARGO_LOCAL[@]}"; do [ "$l" = "$cmd" ] && { known=1; break; }; done
  [ "$known" = 1 ] && continue
  cargo_ci_only_reason "$cmd" >/dev/null && continue
  CARGO_UNCLASSIFIED+=("$cmd")
done
if [ "${#CARGO_UNCLASSIFIED[@]}" -gt 0 ] && [ "${1:-}" != "--selftest" ]; then
  printf 'full-gate: %s\n' "$CI_YML runs cargo invocation(s) this script neither runs nor names as CI-only:" >&2
  printf '  %s\n' "${CARGO_UNCLASSIFIED[@]}" >&2
  die "add each to CARGO_LOCAL (it runs here) or CARGO_CI_ONLY with a reason (it cannot). An unrun configuration is how a local green stops meaning a CI green."
fi

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
  printf '== CARGO GATES, WILL RUN (%d) ==\n' "${#CARGO_LOCAL[@]}"
  printf '  %s\n' "${CARGO_LOCAL[@]}"
  printf '\n== CARGO GATES, CI-ONLY WITH REASON (%d) ==\n' "${#CARGO_CI_ONLY[@]}"
  for entry in "${CARGO_CI_ONLY[@]}"; do printf '  %-46s %s\n' "${entry%%|*}" "${entry#*|}"; done
  printf '\n== WILL RUN (%d) ==\n' "${#RUN[@]}"
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
  for entry in "${CARGO_CI_ONLY[@]}"; do
    [ -n "${entry#*|}" ] && [ "${entry#*|}" != "$entry" ] || { printf '  [FAILED] a CI-only cargo entry carries no reason: %s\n' "$entry"; bad=1; }
  done
  printf '  [ok]     all %d CI-only cargo entries carry a written reason\n' "${#CARGO_CI_ONLY[@]}"

  # THE CARGO HALF: discovery finds them, every one is classified, and the configurations that have
  # actually broken CI are among the ones that RUN here.
  n=${#CARGO_DISCOVERED[@]}
  [ "$n" -ge 10 ] && printf '  [ok]     cargo discovery found %d invocations (floor 10)\n' "$n" \
    || { printf '  [FAILED] cargo discovery found only %d -- the parser missed CI build configurations\n' "$n"; bad=1; }

  if [ "${#CARGO_UNCLASSIFIED[@]}" -eq 0 ]; then
    printf '  [ok]     every cargo invocation in ci.yml is classified LOCAL or CI-only\n'
  else
    printf '  [FAILED] unclassified cargo invocation(s) -- the script must refuse to run:\n'
    printf '           %s\n' "${CARGO_UNCLASSIFIED[@]}"; bad=1
  fi

  for must in "--no-default-features" "--features openapi-schema"; do
    if printf '%s\n' "${CARGO_LOCAL[@]}" | grep -q -- "$must"; then
      printf '  [ok]     the %s configuration is RUN locally\n' "$must"
    else
      printf '  [FAILED] %s is a CI build configuration that this script does not run -- a local green would not mean a CI green\n' "$must"; bad=1
    fi
  done

  # The equality-ledger printer this script calls in its result section must itself discriminate:
  # its own selftest proves a broken ledger is REFUSED rather than printed as a clean line.
  if python3 scripts/capability-equality-summary.py --selftest >/dev/null 2>&1; then
    printf '  [ok]     the equality-ledger printer refuses a broken ledger (its selftest holds)\n'
  else
    printf '  [FAILED] scripts/capability-equality-summary.py --selftest failed -- the ledger line this script prints could lie\n'; bad=1
  fi

  [ "$bad" = 0 ] && { printf '\nfull-gate selftest: discovery, floors and skip-reasons all hold\n'; exit 0; }
  printf '\nSELFTEST FAILED\n'; exit 1
fi

# ── RUN ───────────────────────────────────────────────────────────────────────────────────────────
printf '== full gate: %d cargo gate(s) + %d script gate(s), %d + %d skipped with reason ==\n\n' \
  "${#CARGO_LOCAL[@]}" "${#RUN[@]}" "${#CARGO_CI_ONLY[@]}" "${#SKIP[@]}"

FAILED=(); PASSED=0
run_one() {
  local label="$1"; shift
  printf '  %-58s ' "$label"
  if "$@" >/tmp/full-gate-out.$$ 2>&1; then printf 'ok\n'; PASSED=$((PASSED+1));
  else printf 'FAILED\n'; FAILED+=("$label"); sed 's/^/        /' /tmp/full-gate-out.$$ | tail -15; fi
  rm -f /tmp/full-gate-out.$$
}

# The Rust gates first: they are the slowest and the most likely to fail, so failing early is kinder.
# ALL FOUR locally-runnable build configurations, not just the default one -- see the header.
for cmd in "${CARGO_LOCAL[@]}"; do
  # shellcheck disable=SC2086
  run_one "$cmd" ${cmd}
done

for inv in "${RUN[@]}"; do
  # shellcheck disable=SC2086
  run_one "$inv" ${inv}
done

# ── THE EQUALITY LEDGER ───────────────────────────────────────────────────────────────────────────
# Owner: "LLM == MCP == A2A -- just different protocols not different pathway through engine at
# all." The RED enforcement is `crates/busbar/tests/capability_equality.rs` (already run by the
# cargo gates above); THIS line exists because a cargo test's output is swallowed on green, and the
# doctrine's gap must be NAMED on every umbrella run, green or red -- the honest-ledger pattern.
# A ledger that cannot be read is a failure, not a silence: a gap that can no longer be named is a
# gap on its way to being forgotten.
printf '\n== equality ledger ==\n'
if ! python3 scripts/capability-equality-summary.py; then
  FAILED+=("scripts/capability-equality-summary.py (qa/capability-equality.json is unreadable or does not tile -- the gap can no longer be named)")
fi

printf '\n== result ==\n'
if [ "${#FAILED[@]}" -eq 0 ]; then
  printf '  %d gates ran, all pass -- across %d build configurations, not just the default one.\n' \
    "$PASSED" "${#CARGO_LOCAL[@]}"
  printf '  NOT covered by this green (%d script gate(s) needing a release or the fleet, and):\n' "${#SKIP[@]}"
  for entry in "${CARGO_CI_ONLY[@]}"; do printf '    %s\n' "${entry%%|*}"; done
  printf '  Windows is the real gap: it runs the same tests on a platform this host cannot be.\n'
  exit 0
fi
printf '  %d passed, %d FAILED:\n' "$PASSED" "${#FAILED[@]}"
printf '    %s\n' "${FAILED[@]}"
exit 1

#!/usr/bin/env bash
# gate-mutants — THE GATES ARE THEMSELVES UNDER TEST.
#
# A gate is a program that says NO. The only way a gate can fail is by saying nothing: a check
# whose body is deleted, whose `ok` argument is forced true, whose `push` becomes a `drop`, still
# compiles, still prints PASS, and nothing in the tree notices. `cargo test` cannot notice either,
# because the thing that proves a gate is not a unit test — it is the gate's OWN `--selftest`,
# which plants a fault and demands the gate go red on it.
#
# So this script runs MUTATION TESTING over the gate sources with the gates' own self-proof as the
# test command. cargo-mutants takes each mutable expression in the changed code, stubs it, rebuilds,
# and runs the tests. A mutant that SURVIVES is a line of gate code that no self-test case holds
# down — a hole in the ratchet, found mechanically, before it is a hole somebody walks through.
#
# WHY `--in-diff` AND NOT THE WHOLE TREE. A full mutation run over the gate sources is thousands of
# mutants at ~one selftest each; that is a weekend, not a push. The ratchet law does not need it:
# it needs that NOTHING NEW ARRIVES UNHELD. Scoping to the merge-base diff makes the cost
# proportional to the change, which is what lets this run on every push instead of once a quarter.
# (Whole-tree runs are a separate, deliberate campaign — see docs/ci/gate-integrity.md.)
#
# WHY THE TEST COMMAND IS NOT `cargo test`. `cargo test -p xtask` proves the readers and the
# helpers. It does not prove that `construction`'s `one-pick-site` row still goes red on a second
# pick site — only `cargo xtask gate construction --selftest` does, because only it plants one.
# Mutating gate code and then asking `cargo test` about it measures the wrong suite and reports a
# comfortable number. The command below is the four gates' own proof, plus the library unit tests.
#
# USAGE
#   scripts/gate-mutants.sh --scope            print the in-scope changed files; exit 0 always
#   scripts/gate-mutants.sh --diff FILE        write the scoped merge-base..HEAD diff to FILE
#   scripts/gate-mutants.sh --shard K/N        run shard K of N; red if any mutant SURVIVES
#   scripts/gate-mutants.sh --selftest         prove the scoping, the base and the verdict
#
# ENVIRONMENT
#   GATE_MUTANTS_BASE      the line the branch is measured against
#                          (default: the ref `ceiling-rose` uses, so one branch has one base)
#   GATE_MUTANTS_JOBS      cargo-mutants --jobs (default 4)
#   GATE_MUTANTS_TIMEOUT   per-mutant test timeout in seconds (default 5400)
#   GATE_MUTANTS_BASELINE  `run` (default) or `skip`; the workflow skips it per-shard because the
#                          scope job runs the unmutated proof once for the whole commit
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# THE BASE. Spelled to match `xtask/src/gates/construction/ceilings.rs::INTEGRATION_REF`: a branch
# that is measured against one ref by the ceilings and another by the mutants can be green on both
# while being unheld on the difference between them.
GM_DEFAULT_BASE="origin/integration/oracle-phase0"

# THE SCOPE. The gate sources, their data, and the machinery that runs them. This list is the
# single source of truth: the workflow does not repeat it, it calls `--scope`.
#
# `qa/construction.toml` and `qa/kind-isolation.toml` produce no mutants (they are not Rust), and
# they are in the list anyway: a push that only moves a ceiling still has to prove the rule that
# reads it is held, because moving a number is exactly how a rule stops biting.
gm_scope_paths() {
  cat <<'PATHS'
xtask/src/gates
xtask/src/manifest.rs
xtask/src/scan.rs
xtask/src/ctx.rs
qa/construction.toml
qa/kind-isolation.toml
scripts/land.sh
scripts/gate-mutants.sh
.github/workflows
PATHS
}

# The subset cargo-mutants can actually mutate. Everything else in the scope is a TRIGGER (it makes
# the job run) but not a TARGET (there is no Rust in it to stub).
gm_target_paths() {
  cat <<'PATHS'
xtask/src/gates
xtask/src/manifest.rs
xtask/src/scan.rs
xtask/src/ctx.rs
PATHS
}

gm_log() { printf '[gate-mutants] %s\n' "$*"; }

# THE BASE MUST RESOLVE. A base that does not resolve is not "no changes" — it is a reader that
# cannot say anything, and the one thing this script must never do is report a clean scope because
# it could not find the ref. Exit 2 (a runner that cannot run), never 0.
gm_base() {
  local root="${1:-$here}" want="${GATE_MUTANTS_BASE:-$GM_DEFAULT_BASE}"
  if ! git -C "$root" rev-parse --verify --quiet "$want^{commit}" >/dev/null 2>&1; then
    echo "gate-mutants: base ref '$want' does not resolve in $root -- fetch it, or set \
GATE_MUTANTS_BASE. A scope computed against a ref that is not there is an empty scope for the \
wrong reason." >&2
    return 2
  fi
  local mb
  mb="$(git -C "$root" merge-base HEAD "$want" 2>/dev/null)" || {
    echo "gate-mutants: HEAD and '$want' have no merge-base in $root." >&2; return 2; }
  [ -n "$mb" ] || { echo "gate-mutants: empty merge-base against '$want'." >&2; return 2; }
  printf '%s\n' "$mb"
}

# THE SCOPE OF THIS PUSH: which in-scope files the branch actually touched since the base.
gm_scope() {
  local root="${1:-$here}" base
  base="$(gm_base "$root")" || return 2
  local paths=() p
  while IFS= read -r p; do [ -n "$p" ] && paths+=("$p"); done < <(gm_scope_paths)
  git -C "$root" diff --name-only "$base" HEAD -- "${paths[@]}" 2>/dev/null
}

# THE DIFF cargo-mutants reads. Scoped to the TARGET paths only: a diff carrying workflow YAML or a
# ceilings file would be ignored by cargo-mutants anyway, and carrying it makes the artefact lie
# about what was mutated.
gm_diff() {
  local out="$1" root="${2:-$here}" base
  base="$(gm_base "$root")" || return 2
  local paths=() p
  while IFS= read -r p; do [ -n "$p" ] && paths+=("$p"); done < <(gm_target_paths)
  git -C "$root" diff "$base" HEAD -- "${paths[@]}" >"$out" 2>/dev/null || return 2
  printf '%s\n' "$base"
}

gm_diff_files() { sed -n 's|^+++ b/||p' "$1"; }

# THE VERDICT. Separated from the run so it can be proven on fixtures by `--selftest` without
# spending an hour building mutants: given a cargo-mutants output directory and the tool's own exit
# status, is this shard green?
#
# SURVIVING = `missed.txt`. That is the whole claim of the job. `timeout.txt` is red as well and
# named separately, because a mutant whose tests hung is a mutant nothing CAUGHT — treating a
# timeout as "probably fine" is how a slow gate becomes an absent one. `unviable.txt` is NOT red: a
# mutant that does not compile was never a hole.
gm_verdict() {
  local outdir="$1" rc="$2" red=0
  local missed="$outdir/missed.txt" timedout="$outdir/timeout.txt"
  local unviable="$outdir/unviable.txt" caught="$outdir/caught.txt"

  # A shard that produced no output directory at all did not run. Green-by-absence is the exact
  # failure this whole file exists to refuse.
  if [ ! -d "$outdir" ]; then
    echo "gate-mutants: no output directory at $outdir -- the run did not happen. A shard that \
did not run is not a shard that found nothing." >&2
    return 1
  fi
  local n_caught=0 n_missed=0 n_timeout=0 n_unviable=0
  [ -f "$caught" ]   && n_caught=$(grep -c . "$caught" 2>/dev/null)
  [ -f "$missed" ]   && n_missed=$(grep -c . "$missed" 2>/dev/null)
  [ -f "$timedout" ] && n_timeout=$(grep -c . "$timedout" 2>/dev/null)
  [ -f "$unviable" ] && n_unviable=$(grep -c . "$unviable" 2>/dev/null)
  gm_log "caught=$n_caught surviving=$n_missed timeout=$n_timeout unviable=$n_unviable rc=$rc"

  if [ "$n_missed" != "0" ]; then
    red=1
    echo ""
    echo "SURVIVING MUTANT(S) -- gate code no self-test case holds down:"
    sed 's/^/  /' "$missed"
    echo ""
    echo "Each line above is a stub that made the gate sources DIFFERENT and left every gate"
    echo "self-test GREEN. Add the missing case to that gate's selftest, or delete the dead code."
  fi
  if [ "$n_timeout" != "0" ]; then
    red=1
    echo ""
    echo "TIMED-OUT MUTANT(S) -- not caught, just slow. Raise GATE_MUTANTS_TIMEOUT only if the"
    echo "unmutated selftest is genuinely near the ceiling; otherwise these are survivors:"
    sed 's/^/  /' "$timedout"
  fi
  # rc 4 is cargo-mutants' "the tests failed in the UNMUTATED tree" — a broken baseline, which says
  # nothing about mutants either way and must never read as a clean shard.
  if [ "$rc" = "4" ]; then
    red=1
    echo ""
    echo "BASELINE RED -- the gate self-tests do not pass on the unmutated tree. Nothing about"
    echo "mutation coverage was measured. Fix the tree first."
  fi
  return $red
}

gm_run_shard() {
  local shard="$1"
  case "$shard" in
    */*) : ;;
    *) echo "gate-mutants: --shard wants K/N, got '$shard'" >&2; return 2 ;;
  esac
  local diff="$here/target/gate-mutants.diff" base
  mkdir -p "$here/target"
  base="$(gm_diff "$diff")" || return 2
  gm_log "base $base"
  if [ ! -s "$diff" ]; then
    gm_log "no Rust in scope changed since the base -- nothing to mutate, and that is a real green."
    return 0
  fi
  gm_log "diff over: $(gm_diff_files "$diff" | tr '\n' ' ')"

  local outdir="$here/mutants.out"
  rm -rf "$outdir"
  # --cap-lints: the workspace builds under `-D warnings`, and a stub that leaves a variable unused
  #   would be reported UNVIABLE (a lint failure) rather than tested. A mutant hidden behind a lint
  #   is a mutant nobody measured.
  # --test-package xtask: the gates live in one package; mutating it must run ITS tests, not the
  #   workspace's.
  # --cargo-test-arg: THE TEST COMMAND. `--lib` is the unit suite; `--test gate_mutation_proof` is
  #   the harness that runs the four gates' own `--selftest`. Naming both, rather than letting
  #   `cargo test -p xtask` run everything, keeps the command the one this job claims to run.
  # --copy-vcs true: `ceiling-rose` and the kind-isolation base comparisons READ GIT (they diff the
  #   branch's ceilings against the merge-base blob). Without `.git` in the scratch copy those rows
  #   cannot run, the baseline goes red, and the shard measures nothing.
  # --baseline: `run` proves the command is green unmutated before believing any "caught". The
  #   workflow sets `skip` and runs that proof ONCE, in the scope job, because the baseline is a
  #   property of the COMMIT and not of the shard — paying for it in all N shards is the single
  #   biggest term in the wall clock. A hand run gets `run` by default.
  local jobs="${GATE_MUTANTS_JOBS:-4}" tmo="${GATE_MUTANTS_TIMEOUT:-5400}"
  local baseline="${GATE_MUTANTS_BASELINE:-run}"
  ( cd "$here" && XTASK_GATE_MUTATION_PROOF=1 XTASK_GATE_CEILING_SECS=3600 cargo mutants \
      --in-diff "$diff" \
      --shard "$shard" \
      --sharding round-robin \
      --test-package xtask \
      --cargo-test-arg --lib \
      --cargo-test-arg --test --cargo-test-arg gate_mutation_proof \
      --cap-lints true \
      --copy-vcs true \
      --baseline "$baseline" \
      --jobs "$jobs" \
      --timeout "$tmo" \
      --minimum-test-timeout 1200 \
      --output "$here" \
      --colors never \
      --caught )
  local rc=$?
  gm_verdict "$outdir" "$rc"
}

# ---------------------------------------------------------------------------------------------
# selftest — this script is a gate too, and a gate proves itself
# ---------------------------------------------------------------------------------------------
gm_selftest() {
  local fails=0 root base want; root="$(mktemp -d)"
  _c() { # name, expected-rc, command...
    local nm="$1" want="$2"; shift 2
    GM_OUT="$root/$(printf '%s' "$nm" | tr -c 'A-Za-z0-9._-' '_').out"
    "$@" >"$GM_OUT" 2>&1; local got=$?
    if [ "$got" = "$want" ]; then printf '  ok   %-58s (rc %s)\n' "$nm" "$got"
    else printf '  FAIL %-58s (rc %s, wanted %s; %s)\n' "$nm" "$got" "$want" "$GM_OUT"; fails=$((fails+1)); fi
  }
  _g() { # name, file, regex that must match
    if grep -qE "$3" "$2" 2>/dev/null; then printf '  ok   %-58s\n' "$1"
    else printf '  FAIL %-58s (no /%s/ in %s)\n' "$1" "$3" "$2"; fails=$((fails+1)); fi
  }

  echo "gate-mutants --selftest"

  # -- the scope list itself. A scope that lost a path is a gate source nothing mutates.
  local scope; scope="$(gm_scope_paths)"
  for want in xtask/src/gates xtask/src/manifest.rs xtask/src/scan.rs xtask/src/ctx.rs \
              qa/construction.toml qa/kind-isolation.toml scripts/land.sh .github/workflows; do
    if printf '%s\n' "$scope" | grep -qxF "$want"; then printf '  ok   %-58s\n' "scope carries $want"
    else printf '  FAIL %-58s\n' "scope carries $want"; fails=$((fails+1)); fi
  done

  # -- A BASE THAT DOES NOT RESOLVE IS A REFUSAL, NOT AN EMPTY SCOPE. This is the miss that would
  #    make the whole job silently vacuous on a runner with a shallow clone.
  # `env VAR=x f` cannot set a variable for a shell FUNCTION — `env` execs a binary and there is no
  # binary called `gm_base`. The wrapper is the only thing that puts the override in scope.
  _with_base() { local b="$1"; shift; GATE_MUTANTS_BASE="$b" "$@"; }
  _c "a base ref that does not resolve is refused" 2 \
      _with_base refs/heads/no-such-base-ever gm_base "$here"
  _g "the refusal names the ref" "$GM_OUT" "no-such-base-ever"
  _c "a base that does not resolve refuses the SCOPE too" 2 \
      _with_base refs/heads/no-such-base-ever gm_scope "$here"
  _c "a base that does not resolve refuses the DIFF too" 2 \
      _with_base refs/heads/no-such-base-ever gm_diff "$root/d.diff" "$here"

  # -- the real base resolves to a commit
  if base="$(gm_base "$here" 2>/dev/null)" && [ ${#base} -ge 7 ]; then
    printf '  ok   %-58s (%s)\n' "the default base resolves to a merge-base" "${base:0:12}"
  else
    printf '  FAIL %-58s\n' "the default base resolves to a merge-base"; fails=$((fails+1))
  fi

  # -- a shard that is not K/N is a runner error, not a green shard
  _c "a --shard that is not K/N is refused" 2 gm_run_shard "seven"

  # -- THE VERDICT, on fixtures. Each of the outcomes proven on its own: proving them together
  #    proves only that at least one of them reds.
  local o="$root/out"; mkdir -p "$o"
  : >"$o/caught.txt"; : >"$o/missed.txt"; : >"$o/timeout.txt"; : >"$o/unviable.txt"
  _c "an empty shard with rc 0 is green"             0 gm_verdict "$o" 0
  printf 'xtask/src/gates/construction/rules.rs:439: replace false with true\n' >"$o/missed.txt"
  _c "one surviving mutant is red"                   1 gm_verdict "$o" 0
  _g "the surviving mutant is PRINTED"               "$GM_OUT" "rules.rs:439"
  _g "the red says what a survivor means"            "$GM_OUT" "no self-test case holds down"
  : >"$o/missed.txt"
  printf 'xtask/src/gates/kind_isolation.rs:1845: replace usize with 0\n' >"$o/timeout.txt"
  _c "a timed-out mutant is red, not forgiven"       1 gm_verdict "$o" 2
  _g "the timeout is PRINTED"                        "$GM_OUT" "kind_isolation.rs:1845"
  : >"$o/timeout.txt"
  printf 'a mutant that does not compile\n' >"$o/unviable.txt"
  _c "an unviable mutant is NOT red"                 0 gm_verdict "$o" 0
  _c "a red baseline is red, and says so"            1 gm_verdict "$o" 4
  _g "the baseline red is named"                     "$GM_OUT" "BASELINE RED"
  _c "a shard that produced no output at all is red" 1 gm_verdict "$root/never-ran" 0
  _g "the missing-output red says it did not run"    "$GM_OUT" "did not run"

  rm -rf "$root"
  if [ "$fails" != "0" ]; then echo "gate-mutants --selftest: $fails FAILED"; return 1; fi
  echo "gate-mutants --selftest: all cases green"
  return 0
}

case "${1:---help}" in
  --scope)    gm_scope "$here" ;;
  --diff)     shift; [ $# -ge 1 ] || { echo "gate-mutants: --diff wants a FILE" >&2; exit 2; }
              gm_diff "$1" "$here" >/dev/null ;;
  --shard)    shift; [ $# -ge 1 ] || { echo "gate-mutants: --shard wants K/N" >&2; exit 2; }
              gm_run_shard "$1" ;;
  --selftest) gm_selftest ;;
  *) sed -n '/^# USAGE/,/^# ENVIRONMENT/p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac

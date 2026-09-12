#!/usr/bin/env bash
# Prove a hand-back ON LATCHKEY — a fresh managed runner per proof — with scripts/prove-remote.sh's
# contract, so the engine and a slot can swap one for the other without learning a second language.
#
#   ./scripts/prove-latchkey.sh                       # prove THIS worktree's tip
#   ./scripts/prove-latchkey.sh <branch>              # prove a local branch's tip
#   ./scripts/prove-latchkey.sh --posture ship        # …and the release-time gates as well
#   ./scripts/prove-latchkey.sh --preprove --batch <file>   # the engine's sweep pre-proof leg
#   ./scripts/prove-latchkey.sh --setup [host]        # a no-op: there is no box to prepare
#   ./scripts/prove-latchkey.sh --selftest
#
# ── WHY THIS EXISTS ─────────────────────────────────────────────────────────────────────────────
# The fleet is six EC2 boxes that are paid for whether or not a proof is running on them, and the
# owner's goal is to be 100% off them. Latchkey rents a 16-vCPU runner by the minute, packs the
# CURRENT DIRECTORY as the job's tree, runs one bash line on it and hands back a log. A slot's
# checkout IS the tree, which removes the whole push-a-ref/cherry-pick-on-the-box dance the fleet
# transport is — and replaces it with one problem, which the next block is about.
#
# ── THE ONE PROBLEM: `.git` NEVER SHIPS, AND THE GATES ARE RATCHETS ─────────────────────────────
# MEASURED (job cli-bfd4dc61, xlarge, this tree): the packed tree is byte-complete — 3,579 of the
# 3,581 files `git ls-files` names, the two missing being `.fix/*.orig`, which the packer drops as
# merge leftovers and which no gate reads — and `cargo xtask gate kind-isolation` STILL read RED on
# `deps`, `test-deps` and `matrix`, with one finding apiece and the same text in all three:
#
#     no-base  qa/kind-isolation.toml  no merge-base could be read, so no `not-allowed` edge could
#     be shown to pre-date this branch (git rev-parse HEAD exited 128: fatal: not a git repository).
#
# So it was never the deny-list, never a gitignored path, never Cargo feature unification and never
# the file count. It is that `xtask`'s ratchets are statements about HISTORY: `ceilings::base_ref`
# takes the merge-base with `origin/integration/oracle-phase0`, `kind_isolation::base` reads the
# BASE's own manifests out of `git show <base>:<crate>/Cargo.toml`, and `ceiling_rose` diffs every
# number in `qa/*.toml` against the base's copy. Latchkey never ships `.git`; a gate that cannot
# read its own history reports nothing, and — correctly — refuses to call that green.
#
# ── THE FIX: THE HISTORY TRAVELS AS A TREE OBJECT, NOT AS A DIRECTORY NAMED `.git` ──────────────
# `.latchkey/git` is a BARE repository staged into the tree before the pack. It is not called
# `.git`, so it ships; it carries the tip, the integration base under the very ref name the gate
# reads, the batch's picks and the audit pins; and the first thing the on-box script does is rename
# it into place. The result is the fleet box's state exactly — a real repository, with real history,
# whose HEAD is the tree that was packed — reached without an ssh transport.
#
# It is SHALLOW, because this laptop's clone is (a `git bundle` from a shallow repo is accepted on
# creation and then fails the fetch on the far side: "did not send all necessary objects", measured
# in job cli-21657406). A push into a bare repo with `receive.shallowUpdate` carries the shallow
# boundary with it and is 23 MB — a fifth of the 200 MB context bound, and 1.4 s to build.
#
# ── AND WHAT THE PACKER HELD BACK IS RESTORED FROM IT ───────────────────────────────────────────
# The credential deny-list is Latchkey's, not ours, and it will grow. Rather than chase it with
# `.latchkeyignore` re-includes — which would be a list of exactly the files a deny-list is for —
# the on-box script asks git: every path the reconstituted index reports as DELETED is a path the
# packer dropped, and `git checkout --` puts it back from the tip the bare repo carries. A file the
# deny-list adds tomorrow is restored tomorrow, with nothing to edit here, and NOTHING that is not
# in the tip's own tree can arrive this way.
#
# ── SELF-HEALING IS THE WORKSPACE'S SWITCH, SO IT IS DETECTED RATHER THAN DISABLED ──────────────
# Latchkey retries a failed job through a "self-heal" sidecar and a healed retry EXITS 0. That is a
# verdict about a tree somebody else edited, and recording it as GREEN would be the worst failure
# this harness has available. The switch is per workspace, not per job, so it cannot be turned off
# from here: the log is read instead — the wrapper prints `[latchkey-bash-wrapper] … sidecar POST`
# when it hands a failure over — and a job that exits 0 with that marker in its log is recorded
# `NONE:healed`, which is not a verdict and sends the line back to the queue.
#
# ── NO sccache, NO ACTIONS CACHE ────────────────────────────────────────────────────────────────
# Measured by LK-1 on the CI leg: GitHub's Actions cache backend is unreliable from Latchkey
# runners and the sccache install failed outright once. A cold `cargo build --workspace
# --all-targets` is 168 s on xlarge and that is the baseline this script is costed against; a proof
# that depends on a cache it may not get is a proof that reds for the cache's reasons.
#
# THE EXIT CODE IS THE JOB'S. Not "0 if the upload worked".
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# SCRATCH GOES UNDER $LAND_TMP, AND NEVER UNDER /tmp (owner rule, 2026-09-11) — same declaration,
# once, as every other script in this directory.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
LAND_TMP="${LAND_TMP:-$HOME/Developer/tmp}"
mkdir -p "$LAND_TMP" 2>/dev/null || true

LK_SIZE="${LATCHKEY_SIZE:-xlarge}"
LK_TIMEOUT="${LATCHKEY_TIMEOUT:-7200}"
LK_POLL_SECS="${LATCHKEY_POLL_SECS:-30}"
# The ceiling on how long this script will WAIT, distinct from the job's own timeout: a poller that
# outlives the job it watches is how a sweep slot is held by a job that has already been reaped.
LK_POLL_MAX="${LATCHKEY_POLL_MAX:-$(( LK_TIMEOUT + 1800 ))}"
LK_BIN="${LATCHKEY_BIN:-latchkey}"
LK_ENVFILE="${LATCHKEY_ENV_FILE:-$HOME/.busbar-engine/latchkey.env}"
# The integration line the ceilings are measured against — the same two names land-remote.sh uses,
# so "the base" means one thing across both transports.
LAND_BASE_REF="${LAND_BASE_REF:-refs/remotes/origin/integration/oracle-phase0}"
LAND_BASE_BRANCH="${LAND_BASE_BRANCH:-refs/heads/integration/oracle-phase0}"
# Where the full job log is kept for the 24 h Latchkey keeps its own copy, and after.
LK_LOGDIR="${LATCHKEY_LOG_DIR:-$(cd "$REPO/.." 2>/dev/null && pwd)/busbar-landq-state/gate/latchkey-logs}"

# THE DELIMITERS THE VERDICT FILE TRAVELS IN. Latchkey copies no files back — a log is the entire
# return channel — so the box prints `<batch>.result` between these two lines and this side parses
# it out. They are spelled ONCE, here, and both the emitter and the parser read them from these
# variables, so a selftest that drives the real parser over the real emitter cannot pass on a pair
# that have drifted apart.
LK_RES_BEGIN='===LATCHKEY-RESULT-BEGIN==='
LK_RES_END='===LATCHKEY-RESULT-END==='
# The sidecar's fingerprint in the log. A healed retry exits 0, so this string is the only evidence
# that the 0 is not the tree's.
LK_HEAL_MARK='[latchkey-bash-wrapper]'

lklog() { printf '[latchkey %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
lkdie() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

# dev (the default) or ship — prove-remote.sh's flag, with prove-remote.sh's words, because an
# operator who has learned one of these two scripts has learned both.
lk_validate_posture() { # $1 = the value
  case "${1:-}" in dev|ship) return 0 ;; esac
  echo "prove-latchkey: --posture takes 'dev' (the default, exactly what a --to dev landing proves)" >&2
  echo "prove-latchkey:   or 'ship' (that, plus the release-time gates). Got: '${1:-}'" >&2
  return 1
}

# THE BASE, RESOLVED HERE. `ceilings::base_ref` is the authority and it is Rust; this is the shell
# transcription of it — merge-base with the integration line, and the integration line as THIS
# repository holds it, never the tip being proven (land-remote.sh's note explains what pinning the
# tip under the base's name costs: every ceiling row compares a file against itself and passes).
lk_base_sha() { # $1 = repo
  local repo="${1:-$REPO}" head mb
  head="$(git -C "$repo" rev-parse HEAD 2>/dev/null)" || return 1
  mb="$(git -C "$repo" merge-base HEAD "$LAND_BASE_REF" 2>/dev/null || true)"
  if [ -n "$mb" ] && [ "$mb" != "$head" ]; then printf '%s\n' "$mb"; return 0; fi
  mb="$(git -C "$repo" rev-parse --verify --quiet "$LAND_BASE_BRANCH" 2>/dev/null || true)"
  if [ -n "$mb" ] && [ "$mb" != "$head" ]; then printf '%s\n' "$mb"; return 0; fi
  git -C "$repo" rev-parse --verify --quiet "HEAD~1" 2>/dev/null || return 1
}

# Every hash a batch file names, so the picks travel as objects. Same shape land.sh's own reader
# has: a line's payload is its hashes, `#`-comments and `#UNIT` markers are not lines.
lk_batch_hashes() { # $1 = batch file
  [ -f "${1:-}" ] || return 0
  sed 's/#.*//' "$1" | tr ' \t' '\n\n' | grep -E '^[0-9a-f]{7,40}$' | sort -u
}

# ── THE BARE REPOSITORY THAT TRAVELS AS A DIRECTORY ─────────────────────────────────────────────
# Built inside the tree that is about to be packed, because Latchkey packs the CURRENT DIRECTORY
# and nothing outside it. Removed again by the caller's trap whatever happens: a 23 MB repository
# left in a slot's checkout is the next proof's packed tree.
lk_stage_repo() { # $1 = repo  $2 = stage dir (inside the repo)  $3 = tip  $4 = base  $5.. = picks
  local repo="$1" stage="$2" tip="$3" base="$4"; shift 4
  local bare="$stage/git"
  rm -rf "$stage"; mkdir -p "$stage" || return 1
  git init -q --bare "$bare" || return 1
  # WITHOUT THIS THE PUSH IS REFUSED, and the refusal is the whole reason a `git bundle` could not
  # be used: this laptop's clone is shallow, and a receiver only accepts a shallow update when it
  # is told to carry the boundary.
  git -C "$bare" config receive.shallowUpdate true || return 1
  git -C "$bare" config gc.auto 0 || return 1
  local -a specs=( "+${tip}:refs/heads/tip" )
  local h
  for h in "$@"; do
    [ -n "$h" ] || continue
    specs+=( "+${h}:refs/proof/picks/$h" )
  done
  git -C "$repo" push -q "$bare" "${specs[@]}" 2>/dev/null || return 1
  # THE AUDIT PINS TRAVEL TOO, for the reason remote_push_tree names: qa/audit-ledger.json records
  # the commit each audit round read, the audit-ledger gate re-derives that tree, and a repository
  # that cannot resolve the pin reds for a reason that is not the tree's.
  #
  # ONE PUSH EACH, BEST-EFFORT, AND NOT IN THE SPEC LIST ABOVE. Measured: a single pin that sits on
  # the far side of this shallow clone's boundary fails the WHOLE push — `git push` is atomic over
  # its refspecs — and took the tip with it, so a proof was refused because an old audit round's
  # worktree commit is no longer fetchable. A pin that cannot travel costs one gate row; a pin that
  # cannot travel and takes the tip with it costs the proof.
  local pin npin=0
  for pin in $(git -C "$repo" for-each-ref --format='%(refname)' refs/audit-pins/ 2>/dev/null); do
    git -C "$repo" push -q "$bare" "+${pin}:${pin}" 2>/dev/null && npin=$(( npin + 1 ))
  done
  LK_PINS_SENT="$npin"
  # THE BASE UNDER THE NAME THE GATE READS. It is an ancestor of the tip, so its objects arrived
  # with the push above and this is a ref write, not a transfer. Both spellings, because
  # `ceilings::base_ref` reads the remote-tracking one and land.sh's own plumbing reads the branch.
  git -C "$bare" update-ref refs/remotes/origin/integration/oracle-phase0 "$base" || return 1
  git -C "$bare" update-ref refs/heads/integration/oracle-phase0 "$base" || return 1
  return 0
}

# ── THE SCRIPT THE RUNNER EXECUTES ──────────────────────────────────────────────────────────────
# Emitted from ONE function so `--selftest` drives the real text rather than a copy of it — the
# discipline prove-remote.sh's oracle_golden_path is written for. It is staged INTO the packed tree
# (the job's command line is one bash line, and a bash line cannot carry a script) and its whole
# job is: put the history back, put the deny-list's casualties back, hand the tree to the engine
# that already knows how to prove it, and print the verdict file where the log can carry it home.
lk_onbox_script() { # $1 = mode (preprove|tip)  $2 = branch name  $3 = posture
  cat <<'ONBOX'
#!/usr/bin/env bash
# Generated by scripts/prove-latchkey.sh — runs on a Latchkey runner, never on a fleet box.
set -uo pipefail
MODE="$1"; BR="$2"; POSTURE="$3"; TIP="$4"; BASE="$5"; FAMILIES="${6:-.}"; TESTS="${7:-}"
STAGE=".latchkey"
say() { printf '\n== %s  (%s)\n' "$1" "$(date -u +%H:%M:%S)"; }

say "reconstitute the history the ratchets read"
[ -d "$STAGE/git" ] || { echo "prove-latchkey: RED — no $STAGE/git in the packed tree; the history never shipped"; exit 2; }
[ -e .git ] && { echo "prove-latchkey: RED — this tree already has a .git; refusing to overwrite it"; exit 2; }
mv "$STAGE/git" .git || exit 2
git config core.bare false
git config advice.detachedHead false
git config user.name  "busbar latchkey prove"
git config user.email "ci@busbar.invalid"
git update-ref "refs/heads/$BR" "$TIP" || exit 2
git symbolic-ref HEAD "refs/heads/$BR" || exit 2
git reset -q --mixed || exit 2
BASE_SEEN="$(git merge-base HEAD origin/integration/oracle-phase0 2>/dev/null || true)"
[ "$BASE_SEEN" = "$BASE" ] || {
  echo "prove-latchkey: RED — the runner resolves the integration base as ${BASE_SEEN:-<nothing>}, the laptop resolved $BASE; refusing to judge"
  exit 2; }
echo "   HEAD $(git rev-parse --short HEAD) on $BR; integration base $(printf '%.9s' "$BASE")"

say "restore what the packer's deny-list held back"
DROPPED="$(git status --porcelain | awk '$1=="D"{print $2}')"
if [ -n "$DROPPED" ]; then
  printf '%s\n' "$DROPPED" | xargs git checkout -- || exit 2
  echo "   restored $(printf '%s\n' "$DROPPED" | grep -c .) path(s): $(printf '%s' "$DROPPED" | tr '\n' ' ')"
else
  echo "   nothing was held back"
fi
DIRT="$(git status --porcelain | grep -v "^?? $STAGE/" | grep -v '^?? \.lk-' || true)"
[ -z "$DIRT" ] || { echo "   NOTE: the packed tree differs from $TIP:"; printf '%s\n' "$DIRT" | head -20; }

# ── THE ENGINE'S ENVIRONMENT, MINUS THE FLEET'S ─────────────────────────────────────────────────
# land-remote.sh's RUN block, with three deliberate differences: no sccache and no Actions cache
# (measured unreliable from these runners, and a proof must not red for a cache's reasons); the
# whole machine for CARGO_BUILD_JOBS, because a Latchkey runner is not shared with four CI agents
# and two neighbouring proofs; and a FIXED oracle port block, because this runner is this job's
# alone and there is nothing here to collide with.
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TERM_COLOR=never CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$(nproc)}"
export XTASK_GATE_CEILING_SECS="${XTASK_GATE_CEILING_SECS:-3600}"
export LAND_REMOTE_INNER=1
export LAND_BASE_REF=origin/integration/oracle-phase0
export LAND_BASE_SHA="$BASE"
export BUSBAR_GATE_BASE_REF="$BASE" GATE_MUTANTS_BASE="$BASE"
export LAND_ORACLE_PORT_BASE="${LAND_ORACLE_PORT_BASE:-40000}"
export LAND_TMP="$HOME/latchkey-tmp"; mkdir -p "$LAND_TMP"
unset RUSTC_WRAPPER SCCACHE_DIR SCCACHE_CACHE_SIZE SCCACHE_SERVER_PORT

RC=0
if [ "$MODE" = preprove ]; then
  say "land.sh --preprove over the batch (the picks, the legs, the bisect — and it publishes nothing)"
  bash scripts/land.sh --preprove --batch "$STAGE/batch.txt"; RC=$?
  say "the per-line verdict file"
  # THE RETURN CHANNEL IS THE LOG. Latchkey copies no files back, so `<batch>.result` is printed
  # between two delimiters the laptop parses. An absent file is printed as an absent block, never
  # as an empty one: "no verdict" and "no lines were green" are different sentences.
  if [ -f "$STAGE/batch.txt.result" ]; then
    echo '===LATCHKEY-RESULT-BEGIN==='
    cat "$STAGE/batch.txt.result"
    echo '===LATCHKEY-RESULT-END==='
  else
    echo "prove-latchkey: no $STAGE/batch.txt.result — the batch did not reach its reporting stage"
  fi
else
  # ── THE TIP PLAN: prove-remote.sh's dev legs, in prove-remote.sh's order ──────────────────────
  say "build (workspace, locked)";      cargo build --workspace --locked || exit 1
  say "fmt";                            cargo fmt --all -- --check || exit 1
  say "clippy -D warnings";             RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --locked -- -D warnings || exit 1
  say "tests${TESTS:+ (packages: $TESTS)}"
  if [ -n "$TESTS" ]; then
    args=""; for p in $TESTS; do args="$args -p $p"; done
    # shellcheck disable=SC2086
    cargo test --locked $args || exit 1
  else
    cargo test --workspace --locked || exit 1
  fi
  say "gates: the legs a --to dev landing runs (posture: $POSTURE)"
  # land.sh's OWN verdict functions, read out of the tree under test and eval'd, exactly as
  # prove-remote.sh does it — so this leg and the landing engine's cannot disagree about what a red
  # means, and no copy of the standing-red list lives in this file.
  gsrc="$(sed -n '/^land_construction_standing_reds() {/,/^}/p;/^land_ceiling_verdict() {/,/^}/p;/^land_gate_verdict() {/,/^}/p' scripts/land.sh)"
  case "$gsrc" in
    *"land_gate_verdict()"*) ;;
    *) echo "prove-latchkey: RED — land.sh's gate verdict is not readable out of this tree"; exit 2 ;;
  esac
  eval "$gsrc" || exit 2
  cargo run -q -p xtask -- gate kind-isolation || exit 1
  glog=target/prove-gate-construction.log
  mkdir -p target
  cargo run -q -p xtask -- gate construction --report >"$glog" 2>&1 || true
  land_ceiling_verdict "$glog" || exit 1
  land_gate_verdict "$glog" '.' || exit 1
  if [ "$POSTURE" = ship ]; then
    say "cargo xtask gate --all (release-time rows: --posture ship)"
    cargo run -q -p xtask -- gate --all || exit 1
  fi
  say "cargo xtask selftest";           cargo run -q -p xtask -- selftest || exit 1
  say "shadow oracle (filter: $FAMILIES)"
  if [ -x ./bin/oracle ]; then
    cargo build -p busbar --release --locked || exit 1
    rm -rf target/oracle/recordings/candidate
    mkdir -p target/oracle/recordings/candidate
    ./bin/oracle record --plane all --bin target/release/busbar \
       --filter "$FAMILIES" --out target/oracle/recordings/candidate || exit 1
    ./bin/oracle replay --golden testing/shadow-oracle/golden/1.5.5 \
       --candidate target/oracle/recordings/candidate --out target/oracle/reports/prove || exit 1
  else
    echo "   (no ./bin/oracle in this tree — the oracle leg is NOT part of this verdict)"
  fi
  RC=0
  echo
  echo "PROVE-LATCHKEY: GREEN on $(uname -n) for $(git rev-parse --short HEAD)"
fi
echo "prove-latchkey: engine exit $RC"
exit $RC
ONBOX
}

# ── READING THE LOG BACK ────────────────────────────────────────────────────────────────────────
# One parser, driven by --selftest over fixtures, because every one of these three questions was a
# way for a harness to report a verdict it did not have.

# The verdict file, out of the delimited block. Prints nothing and returns 1 when there is no
# block: an absent verdict is not an empty one.
lk_parse_result() { # $1 = log file
  local log="${1:-}"
  [ -f "$log" ] || return 1
  awk -v b="$LK_RES_BEGIN" -v e="$LK_RES_END" '
    $0 == b { inb = 1; seen = 1; next }
    $0 == e { inb = 0; next }
    inb     { print }
    END     { exit seen ? 0 : 1 }
  ' "$log"
}

# Did the wrapper hand a failure to the self-heal sidecar? Self-healing is a WORKSPACE switch, so
# this is detection, not prevention — and a healed retry exits 0, which is why the exit code alone
# can never be trusted here.
lk_log_healed() { # $1 = log file
  local log="${1:-}"
  [ -f "$log" ] || return 1
  grep -qF -- "$LK_HEAL_MARK" "$log"
}

# THE ONE PLACE A JOB BECOMES A VERDICT. `GREEN` only when the job exited 0 AND nothing healed it;
# a healed zero is `NONE:healed`, which is not a verdict and which the sweep records as such so the
# line stays live rather than being scored on somebody's retry.
lk_job_verdict() { # $1 = log file  $2 = job exit code
  local log="${1:-}" rc="${2:-1}"
  if lk_log_healed "$log"; then
    if [ "$rc" = 0 ]; then echo "NONE:healed"; return 0; fi
    echo RED; return 0
  fi
  case "$rc" in
    0) echo GREEN ;;
    75) echo "NONE:no-verdict" ;;
    *) echo RED ;;
  esac
}

# ── THE JOB ─────────────────────────────────────────────────────────────────────────────────────
lk_load_token() {
  [ -n "${LATCHKEY_TOKEN:-}" ] && return 0
  [ -r "$LK_ENVFILE" ] || return 1
  # NEVER ECHOED, NEVER WRITTEN INTO THE REPO, NEVER PASSED AS --env: the CLI reads it out of the
  # environment and it goes no further. `set -a` is scoped to this subshell's caller by the two
  # lines around it and nothing here prints the value.
  set -a; . "$LK_ENVFILE"; set +a
  [ -n "${LATCHKEY_TOKEN:-}" ]
}

lk_submit() { # $1 = the bash line; prints the job id
  "$LK_BIN" run --size "$LK_SIZE" --timeout "$LK_TIMEOUT" --quiet --detach "$1" 2>/dev/null | tr -d '[:space:]'
}

lk_state() { # $1 = job id
  "$LK_BIN" status "$1" 2>/dev/null | awk '/^State:/{print $2}'
}

lk_exit_code() { # $1 = job id; prints the command's exit code, or nothing
  "$LK_BIN" status "$1" 2>/dev/null | awk '/^Exit code:/{print $3}' | grep -E '^[0-9]+$' || true
}

# BOUNDED. Every $LK_POLL_SECS, never a watcher process, and it gives up rather than waiting for a
# job that has been reaped — a poller that outlives its job holds a sweep slot for nothing.
lk_poll() { # $1 = job id; prints the terminal state, returns 1 on running out of patience
  local id="$1" waited=0 st
  while [ "$waited" -lt "$LK_POLL_MAX" ]; do
    st="$(lk_state "$id")"
    case "$st" in
      succeeded|failed|cancelled|expired) printf '%s\n' "$st"; return 0 ;;
    esac
    sleep "$LK_POLL_SECS"; waited=$(( waited + LK_POLL_SECS ))
  done
  printf 'timeout\n'; return 1
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# --selftest
# ──────────────────────────────────────────────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
  fails=0
  say() { if [ "$1" = PASS ]; then echo "  ok: $2"; else echo "  SELFTEST FAILED: $2"; fails=$((fails + 1)); fi; }
  root="$(mktemp -d "$LAND_TMP/prove-latchkey-selftest.XXXXXX")" || exit 2
  trap 'rm -rf "$root"' EXIT

  echo "== prove-latchkey SELF-TEST (prove-remote.sh's contract, argument for argument) =="
  lk_validate_posture dev  2>/dev/null && say PASS "the default posture is a value this script knows" \
    || say FAIL "dev is not an accepted posture"
  lk_validate_posture ship 2>/dev/null && say PASS "ship is the other one" \
    || say FAIL "ship is not an accepted posture"
  lk_validate_posture promote 2>/dev/null && say FAIL "an unknown posture was accepted" \
    || say PASS "an unknown posture is refused, not guessed"
  lk_validate_posture 2>/dev/null && say FAIL "an empty posture was accepted" \
    || say PASS "an empty posture is refused too"
  # THE SAME FLAGS prove-remote.sh TAKES. A backend the engine may swap in must not need a second
  # argv; --host and --setup are accepted and are no-ops here, which is a different thing from
  # being refused.
  # READ OUT OF THE PARSER ITSELF, not guessed at: `--host|--remote)` is one case arm for two
  # flags and `--selftest` is answered before the parser runs, so a check that demanded `<flag>)`
  # verbatim would fail on a script that handles every one of them.
  argv_src="$(sed -n '/^while \[ \$# -gt 0 \]; do/,/^done$/p' "${BASH_SOURCE[0]}")"
  for f in --setup --host --remote --posture --preprove --batch; do
    case "$argv_src" in
      *"$f"*) say PASS "the argument parser handles $f" ;;
      *) say FAIL "the argument parser does not handle $f" ;;
    esac
  done
  grep -qF -- '"${1:-}" = "--selftest"' "${BASH_SOURCE[0]}" \
    && say PASS "the argument parser handles --selftest" \
    || say FAIL "the argument parser does not handle --selftest"

  echo "== prove-latchkey SELF-TEST (the runner never sees the token, and never on the command line) =="
  # THE TOKEN IS AN ENVIRONMENT READ, NEVER AN --env. `latchkey run --env K=V` puts the value in the
  # job's environment where the job's own log can print it; the CLI reads LATCHKEY_TOKEN here.
  # THE INVOCATION, NOT THE WORDS. This file talks ABOUT `--env` in the comment that explains why
  # the token is not shipped that way, and a count that read prose would be satisfied by deleting a
  # comment. What is counted is a `$LK_BIN run` line carrying the flag.
  [ "$(grep -cE '"\$LK_BIN" run .*--env' "${BASH_SOURCE[0]}")" = 0 ] \
    && say PASS "no job environment is shipped by flag — the token is read, never handed over" \
    || say FAIL "this script passes --env to the runner"
  grep -qF -- 'LATCHKEY_TOKEN' "${BASH_SOURCE[0]}" \
    && say PASS "the token is read from the environment/the 600 env file" \
    || say FAIL "the token is not read from the environment"
  # THE PATTERN MUST NOT MATCH ITSELF — a grep for a variable name, written in the file it
  # searches, is its own hit, and this case failed on its own text the first time it ran.
  [ "$(grep -cE '(echo|printf) [^|]*LATCHKEY[_]TOKEN' "${BASH_SOURCE[0]}")" = 0 ] \
    && say PASS "  ...and is never printed" \
    || say FAIL "the token is printed somewhere in this script"

  echo "== prove-latchkey SELF-TEST (the verdict file travels in the log, and an absent one is absent) =="
  # THE REAL EMITTER AND THE REAL PARSER, against each other. The block the on-box script prints is
  # the block this side reads; a fixture that spelled the delimiters itself would still pass after
  # someone changed one of them.
  emit="$(lk_onbox_script preprove br dev)"
  case "$emit" in
    *"$LK_RES_BEGIN"*) say PASS "the on-box script emits the result block's opening delimiter" ;;
    *) say FAIL "the on-box script does not emit $LK_RES_BEGIN" ;;
  esac
  case "$emit" in
    *"$LK_RES_END"*) say PASS "  ...and its closing one" ;;
    *) say FAIL "the on-box script does not emit $LK_RES_END" ;;
  esac
  {
    echo "noise before"
    printf '%s\n' "$LK_RES_BEGIN"
    printf 'GREEN\t--prove --tests xtask aaaaaaa\n'
    printf 'RED\t--prove --tests xtask bbbbbbb\n'
    printf 'HELD\t--prove --tests xtask ccccccc\n'
    printf '%s\n' "$LK_RES_END"
    echo "noise after"
  } >"$root/with.log"
  got="$(lk_parse_result "$root/with.log")"
  [ "$(printf '%s\n' "$got" | grep -c .)" = 3 ] \
    && say PASS "the parser lifts exactly the block's rows out of a noisy log" \
    || say FAIL "the parser did not lift three rows (got: $(printf '%s' "$got" | tr '\n' '|'))"
  printf '%s\n' "$got" | grep -qP '^GREEN\t' 2>/dev/null || printf '%s\n' "$got" | grep -q "^GREEN	" \
    && say PASS "  ...tab-delimited, in land.sh's own row shape" \
    || say FAIL "the rows are not land.sh's STATUS<TAB>TEXT"
  echo "no block at all" >"$root/without.log"
  lk_parse_result "$root/without.log" >/dev/null 2>&1 \
    && say FAIL "a log with no result block was read as a verdict" \
    || say PASS "a log with NO result block is no verdict, not an empty one"

  echo "== prove-latchkey SELF-TEST (a healed retry is never GREEN) =="
  printf 'all fine\n' >"$root/clean.log"
  printf 'boom\n%s BEGIN sidecar POST (boot_wait=30s)\n%s END sidecar POST ok (attempts=1 http=200)\n' \
    "$LK_HEAL_MARK" "$LK_HEAL_MARK" >"$root/healed.log"
  [ "$(lk_job_verdict "$root/clean.log" 0)" = GREEN ] \
    && say PASS "a clean job that exited 0 is GREEN" \
    || say FAIL "a clean zero is not GREEN (got $(lk_job_verdict "$root/clean.log" 0))"
  [ "$(lk_job_verdict "$root/healed.log" 0)" = "NONE:healed" ] \
    && say PASS "a job the sidecar healed to zero is NONE:healed, never GREEN" \
    || say FAIL "a healed zero was scored $(lk_job_verdict "$root/healed.log" 0)"
  [ "$(lk_job_verdict "$root/clean.log" 1)" = RED ] \
    && say PASS "a clean job that exited 1 is RED" \
    || say FAIL "a clean 1 is not RED"
  [ "$(lk_job_verdict "$root/clean.log" 75)" = "NONE:no-verdict" ] \
    && say PASS "  ...and 75 is the queue's re-queue code, not a red" \
    || say FAIL "75 is not NONE:no-verdict"
  case "$(lk_job_verdict "$root/healed.log" 1)" in
    GREEN|NONE*) say FAIL "a healed job that still failed was not RED" ;;
    *) say PASS "a job the sidecar could NOT heal is RED" ;;
  esac

  echo "== prove-latchkey SELF-TEST (the history travels; \`.git\` never does) =="
  case "$emit" in
    *'mv "$STAGE/git" .git'*) say PASS "the on-box script renames the shipped bare repo into place" ;;
    *) say FAIL "the on-box script does not put the history back" ;;
  esac
  case "$emit" in
    *'$1=="D"{print $2}'*) say PASS "  ...and restores every path the packer's deny-list held back" ;;
    *) say FAIL "the deny-list's casualties are not restored" ;;
  esac
  case "$emit" in
    *'refusing to judge'*) say PASS "  ...and refuses to judge when the runner's base is not the laptop's" ;;
    *) say FAIL "a differing base is not refused on the box" ;;
  esac
  case "$emit" in
    *'unset RUSTC_WRAPPER'*) say PASS "  ...with no sccache: measured unreliable from these runners" ;;
    *) say FAIL "the on-box environment still reaches for sccache" ;;
  esac
  # THE BASE IS NEVER THE TIP. land-remote.sh's selftest keeps this line for the same reason: a base
  # pinned to the tip makes every ceiling row compare a file against itself and pass.
  grep -qE 'merge-base HEAD "\$LAND_BASE_REF"' "${BASH_SOURCE[0]}" \
    && say PASS "the base is the merge-base with the integration line, resolved here" \
    || say FAIL "the base is not the merge-base with the integration line"
  [ "$(grep -c 'LAND_BASE_REF="\${LAND_BASE_REF:-refs/remotes/origin/integration/oracle-phase0}"' "${BASH_SOURCE[0]}")" = 1 ] \
    && say PASS "  ...named once, the same name land-remote.sh uses" \
    || say FAIL "the integration ref is spelled more than once, or differently"

  echo "== prove-latchkey SELF-TEST (the bare repo is built for real, out of this repository) =="
  if git -C "$REPO" rev-parse HEAD >/dev/null 2>&1; then
    tip="$(git -C "$REPO" rev-parse HEAD)"
    base="$(lk_base_sha "$REPO")"
    [ -n "$base" ] && [ "$base" != "$tip" ] \
      && say PASS "the base resolves, and it is not the tip ($(printf '%.9s' "$base"))" \
      || say FAIL "the base did not resolve, or it is the tip"
    stage="$root/stage"
    if lk_stage_repo "$REPO" "$stage" "$tip" "$base"; then
      say PASS "a bare repository is staged out of this (shallow) clone"
      [ "$(git -C "$stage/git" rev-parse refs/heads/tip)" = "$tip" ] \
        && say PASS "  ...carrying the tip" || say FAIL "the staged repo's tip is wrong"
      [ "$(git -C "$stage/git" rev-parse refs/remotes/origin/integration/oracle-phase0)" = "$base" ] \
        && say PASS "  ...and the base under the ref name the gate reads" \
        || say FAIL "the staged repo has no origin/integration/oracle-phase0 at the base"
      [ "$(git -C "$stage/git" merge-base refs/heads/tip refs/remotes/origin/integration/oracle-phase0)" = "$base" ] \
        && say PASS "  ...so the merge-base the ratchets take is the one the laptop resolved" \
        || say FAIL "the staged repo's merge-base is not the base"
      git -C "$stage/git" cat-file -e "$base":qa/kind-isolation.toml 2>/dev/null \
        && say PASS "  ...and \`git show <base>:qa/kind-isolation.toml\` resolves in it" \
        || say FAIL "the base's ledger is not readable out of the staged repo"
    else
      say FAIL "the bare repository could not be staged"
    fi
  else
    say PASS "(not a git repository here — the staging cases are skipped)"
  fi

  echo "== prove-latchkey SELF-TEST (the batch's picks travel as objects) =="
  printf '#UNIT 1\n--prove --tests xtask deadbee cafebab  # a comment\n\n#a whole comment line\n' >"$root/b.txt"
  n="$(lk_batch_hashes "$root/b.txt" | grep -c .)"
  [ "$n" = 2 ] && say PASS "every hash a batch line names is read out of it ($n)" \
    || say FAIL "the batch reader found $n hashes, not 2"
  lk_batch_hashes "$root/b.txt" | grep -q '^deadbee$' \
    && say PASS "  ...by hash, not by position" || say FAIL "the batch reader lost a hash"
  lk_batch_hashes "$root/b.txt" | grep -q 'UNIT' \
    && say FAIL "the #UNIT marker was read as a hash" || say PASS "  ...and a #UNIT marker is not one"

  echo "== prove-latchkey SELF-TEST (scratch is never /tmp; the log is kept where the ledgers are) =="
  [ "$(grep -c '^LAND_TMP=' "${BASH_SOURCE[0]}")" = 1 ] \
    && say PASS "the scratch root is LAND_TMP, declared once" \
    || say FAIL "there is not exactly one LAND_TMP declaration"
  [ "$(grep -cE 'mktemp[^|]*\B/tmp/' "${BASH_SOURCE[0]}")" = 0 ] \
    && say PASS "  ...and nothing here names /tmp" \
    || say FAIL "something in this script names /tmp"
  grep -qF 'latchkey-logs' "${BASH_SOURCE[0]}" \
    && say PASS "the full job log is copied where it outlives Latchkey's 24 h" \
    || say FAIL "the job log is not kept past Latchkey's retention"

  if [ "$fails" -ne 0 ]; then
    echo "[selftest] FAILED: $fails case(s) did not hold." >&2
    exit 1
  fi
  echo "[selftest] PASS"
  exit 0
fi

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE ARGUMENTS — prove-remote.sh's, plus the engine's pre-proof leg.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
BRANCH=""; SETUP=0; POSTURE=dev; MODE=tip; BATCH=""; IGNORED_HOST=""
while [ $# -gt 0 ]; do
  case "$1" in
    --setup) SETUP=1; shift ;;
    # ACCEPTED AND IGNORED, ON PURPOSE. The engine's sweep hands its dispatch a box; a backend that
    # refused the flag would need the caller to know which backend it had, which is the coupling
    # BUSBAR_PROVE_BACKEND exists to remove.
    --host|--remote) IGNORED_HOST="${2:-}"; shift 2 ;;
    --posture) lk_validate_posture "${2:-}" || exit 2; POSTURE="$2"; shift 2 ;;
    --preprove) MODE=preprove; shift ;;
    --batch) BATCH="${2:-}"; MODE=preprove; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    -*) lkdie "unknown option $1" ;;
    *) BRANCH="$1"; shift ;;
  esac
done

# `--setup` HAS NOTHING TO DO. A fleet box is prepared once and reused; a Latchkey runner is fresh
# every time, which is the entire point. It exits 0 rather than refusing, so an operator's muscle
# memory and any script that calls it are answered.
if [ "$SETUP" = 1 ]; then
  echo "prove-latchkey: --setup is a no-op — a Latchkey runner is fresh per job; there is no box to prepare."
  echo "prove-latchkey: (the only preparation is an API key, read from $LK_ENVFILE)"
  exit 0
fi

command -v "$LK_BIN" >/dev/null 2>&1 || lkdie "no \`$LK_BIN\` on PATH — install the Latchkey CLI or set LATCHKEY_BIN"
lk_load_token || lkdie "no LATCHKEY_TOKEN in the environment and none readable in $LK_ENVFILE"

TIP="$(git -C "$REPO" rev-parse "${BRANCH:-HEAD}")" || lkdie "no such rev: ${BRANCH:-HEAD}"
BASE="$(lk_base_sha "$REPO")" || lkdie "no integration base to judge the ceilings against"
[ -n "$BASE" ] && [ "$BASE" != "$TIP" ] || lkdie "the base resolved to the tip — every ceiling row would compare a file against itself"
REF="latchkey-$(date -u +%Y%m%d-%H%M%S)-$$"
BRANCH_NAME="$(git -C "$REPO" rev-parse --abbrev-ref HEAD 2>/dev/null)"
case "$BRANCH_NAME" in HEAD|"") BRANCH_NAME="$REF" ;; esac

[ -n "$IGNORED_HOST" ] && lklog "note: --host/--remote '$IGNORED_HOST' is accepted and ignored; this backend rents a runner"

# The scope file is read LOCALLY as well as remotely, prove-remote.sh's reason verbatim: the
# operator should see the scope before the minutes start, not in the log afterwards.
SCOPE_FAM='.'; SCOPE_TESTS=''
if [ -f "$REPO/.keep-proof.toml" ]; then
  SCOPE_FAM="$(sed -n "s/^[[:space:]]*families[[:space:]]*=[[:space:]]*['\"]\(.*\)['\"][[:space:]]*\$/\1/p" "$REPO/.keep-proof.toml" | head -1)"
  [ -n "$SCOPE_FAM" ] || SCOPE_FAM='.'
  SCOPE_TESTS="$(sed -n 's/^[[:space:]]*tests[[:space:]]*=[[:space:]]*\[\(.*\)\].*/\1/p' "$REPO/.keep-proof.toml" \
                 | head -1 | tr -d '"'"'" | tr ',' ' ')"
fi

PICKS=""
if [ "$MODE" = preprove ]; then
  [ -n "$BATCH" ] || lkdie "--preprove needs --batch <file>"
  [ -f "$BATCH" ] || lkdie "no such batch file: $BATCH"
  PICKS="$(lk_batch_hashes "$BATCH")"
fi

lklog "tip $(git -C "$REPO" rev-parse --short "$TIP")   base $(printf '%.9s' "$BASE")   ref $REF"
lklog "mode:            $MODE${BATCH:+ (batch $BATCH, $(grep -c . "$BATCH" 2>/dev/null || echo 0) line(s))}"
lklog "posture:         --posture $POSTURE"
lklog "oracle families: $SCOPE_FAM"
lklog "test packages:   ${SCOPE_TESTS:-<the whole workspace>}"
lklog "runner:          $LK_SIZE, timeout ${LK_TIMEOUT}s, polled every ${LK_POLL_SECS}s"

# ── STAGE THE TREE ──────────────────────────────────────────────────────────────────────────────
# Everything the job needs goes INSIDE the directory being packed, and comes out again on the way
# out, whatever happens. A 23 MB bare repository left behind in a slot's checkout is the next
# proof's packed tree.
STAGE="$REPO/.latchkey"
RUNNER=".lk-run.sh"
cleanup() { rm -rf "$STAGE" "$REPO/$RUNNER"; }
trap cleanup EXIT INT TERM
lk_stage_repo "$REPO" "$STAGE" "$TIP" "$BASE" $PICKS || lkdie "could not stage the history into $STAGE"
lklog "history staged: $(du -sh "$STAGE/git" 2>/dev/null | cut -f1) ($(printf '%s' "$PICKS" | grep -c . || true) pick(s))"
[ -n "$BATCH" ] && cp "$BATCH" "$STAGE/batch.txt"
lk_onbox_script "$MODE" "$BRANCH_NAME" "$POSTURE" >"$REPO/$RUNNER"
chmod +x "$REPO/$RUNNER"

LOG="$REPO/target/land-latchkey-$REF.log"
mkdir -p "$(dirname "$LOG")"

START=$(date +%s)
JOB="$(cd "$REPO" && lk_submit "bash $RUNNER $MODE $BRANCH_NAME $POSTURE $TIP $BASE '$SCOPE_FAM' '$SCOPE_TESTS'")"
case "$JOB" in
  cli-*) ;;
  # NO JOB IS NOT A RED. The 20-runner workspace cap is shared with CI, and "the account was full"
  # is a statement about the account, not about the tree: exit 75 so the queue re-queues the line
  # instead of parking it on somebody else's build.
  *) lklog "no job was created (the workspace's runner cap is shared with CI) — exit 75, nothing was proven"; exit 75 ;;
esac
lklog "job $JOB submitted"

STATE="$(lk_poll "$JOB")" || { lklog "gave up waiting on $JOB after ${LK_POLL_MAX}s — exit 75, no verdict"; "$LK_BIN" cancel "$JOB" >/dev/null 2>&1 || true; exit 75; }
END=$(date +%s)
"$LK_BIN" logs "$JOB" >"$LOG" 2>&1 || true

# THE FULL LOG OUTLIVES LATCHKEY'S 24 HOURS. The ledgers cite logs by path months later.
mkdir -p "$LK_LOGDIR" 2>/dev/null && cp "$LOG" "$LK_LOGDIR/$JOB.log" 2>/dev/null \
  && lklog "log kept: $LK_LOGDIR/$JOB.log" \
  || lklog "WARNING: could not keep the log under $LK_LOGDIR — Latchkey drops it in 24 h"

RC=1
case "$STATE" in
  succeeded) RC="$(lk_exit_code "$JOB")"; [ -n "$RC" ] || RC=0 ;;
  failed)    RC="$(lk_exit_code "$JOB")"; [ -n "$RC" ] || RC=1 ;;
  cancelled) RC=130 ;;
  expired)   RC=124 ;;
esac
VERDICT="$(lk_job_verdict "$LOG" "$RC")"
MINUTES=$(( (END - START + 59) / 60 ))
lklog "job $JOB   state $STATE   exit $RC   verdict $VERDICT   wall $(( END - START ))s   ~${MINUTES} runner-minute(s)"

if [ "$MODE" = preprove ]; then
  # THE RESULT FILE COMES BACK TO THE PATH THE LOCAL RUNNER ALREADY READS. target/gate/landq*.sh
  # reads `<batch>.result` and nothing else.
  if lk_parse_result "$LOG" >"$BATCH.result.tmp" 2>/dev/null && [ -s "$BATCH.result.tmp" ]; then
    mv "$BATCH.result.tmp" "$BATCH.result"
    lklog "per-line outcomes: $BATCH.result"
    sed 's/^/  /' "$BATCH.result" >&2
  else
    rm -f "$BATCH.result.tmp"
    lklog "WARNING: no result block in $LOG — the batch did not reach its reporting stage"
  fi
fi

# A HEALED ZERO IS NOT A GREEN, AND IT IS NOT A RED EITHER. 75 is the queue's "prove this again"
# code — the same one land-remote.sh uses when a box vanishes mid-proof.
if [ "$VERDICT" = "NONE:healed" ]; then
  lklog "NONE:healed — Latchkey's self-heal sidecar retried this job to zero, so the 0 is not this tree's; exit 75"
  rm -f "$BATCH.result" 2>/dev/null || true
  exit 75
fi
exit "$RC"

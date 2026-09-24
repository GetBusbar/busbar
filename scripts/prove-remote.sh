#!/usr/bin/env bash
# Prove a hand-back ON THE FLEET, over ssh, and stream the whole thing back to this terminal.
#
#   ./scripts/prove-remote.sh --setup [host]        # prepare one box, or every box
#   ./scripts/prove-remote.sh                       # prove THIS worktree's tip
#   ./scripts/prove-remote.sh <branch>              # prove a local branch's tip
#   ./scripts/prove-remote.sh --host i-0abc <branch>
#   ./scripts/prove-remote.sh --selftest            # prove the scope resolver, offline, seconds
#
# ── WHY NOT GITHUB ACTIONS ──────────────────────────────────────────────────────────────────────
# During dev churn the owner's ruling is that Actions judges integration/qa/main and nothing else.
# For an agent hand-back, Actions is a queue, a checkout, a cold target/ and a verdict twenty
# minutes after the question — and, on a `keep-*` push, twelve jobs of it. The box is already warm:
# the toolchain the repo pins, an sccache with this workspace's objects in it, a target/ from the
# previous proof, and docker for the oracle's services. Pushing 200 KB of objects to it over ssh
# and running the SAME legs there is the same proof, minus the queue.
#
# ── WHAT IT PROVES, AND WHERE THAT LIST COMES FROM ──────────────────────────────────────────────
# Exactly the legs keep-proof.yml runs, in the same order, scoped by the SAME .keep-proof.toml the
# workflow reads off the branch root: workspace build, rustfmt, clippy -D warnings, the named test
# packages (or the whole suite when the branch names none), `cargo xtask gate --all`, `xtask
# selftest`, and the shadow oracle over `families` against the published 1.5.5 recording. A green
# here and a green there are the same sentence about the same tree; that is the whole point of
# reading the same scope file rather than inventing a second one.
#
# THE EXIT CODE IS THE REMOTE'S. Not "0 if the transport worked" — that is the failure mode where a
# proof harness reports success because it successfully failed to prove anything.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
# shellcheck source=scripts/ci-remote-lib.sh
. "$HERE/ci-remote-lib.sh"

HOST=""; BRANCH=""; SETUP=0; SELFTEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --setup) SETUP=1; shift ;;
    --selftest) SELFTEST=1; shift ;;
    --host)  HOST="$2"; shift 2 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    -*) rdie "unknown option $1" ;;
    *) if [ -z "$HOST" ] && [ "$SETUP" = 1 ]; then HOST="$1"; else BRANCH="$1"; fi; shift ;;
  esac
done

# ── THE SCOPE: resolved from the PROVEN TREE, and refused off a keep branch ─────────────────────
# `.keep-proof.toml` NARROWS the proof: `families` becomes the oracle's --filter and `tests` replaces
# the whole-workspace test run. That is the point of it on a `keep-*` branch and a silent hole
# everywhere else — once one was committed to the integration branch (item 13: 161 of 2,318 oracle
# cells, 6.9%, and three package names that do not exist), every proof after it quietly proved
# less while printing the same GREEN. So:
#   * the file is read from the TIP BEING PROVEN (`git show <tip>:.keep-proof.toml`), the same place
#     keep-proof.yml reads it — not from whatever the operator's working tree happens to hold;
#   * with no file, the fallback is logged as what it is: EVERY family, the WHOLE workspace;
#   * a file present on anything that is not a `keep-*` branch (detached HEAD included) is REFUSED,
#     exit 3, before a box is touched. There is no override: a hand-back that wants a scope is a
#     keep branch, and one that is not a keep branch gets the full proof.
# Sets SCOPE_FAM and SCOPE_TESTS. Returns 3 on the refusal.
resolve_scope() {
  local repo="$1" tip="$2" branch="$3" body short
  short="$(git -C "$repo" rev-parse --short "$tip" 2>/dev/null || echo "$tip")"
  SCOPE_FAM='.'; SCOPE_TESTS=''
  if ! body="$(git -C "$repo" show "$tip:.keep-proof.toml" 2>/dev/null)"; then
    rlog "SCOPE: no .keep-proof.toml in $short's tree — EVERY family (oracle filter '.'), the WHOLE workspace's tests"
    return 0
  fi
  case "$branch" in
    keep-*) ;;
    *)
      rlog "SCOPE REFUSED: $short carries .keep-proof.toml but '${branch:-<detached HEAD>}' is not a keep-* branch."
      rlog "  that file narrows the oracle and the test legs; off a keep branch it is a silent hole in the proof."
      rlog "  delete it from the branch (snapshot it first), or prove from a keep-* branch."
      return 3 ;;
  esac
  SCOPE_FAM="$(printf '%s\n' "$body" | sed -n "s/^[[:space:]]*families[[:space:]]*=[[:space:]]*['\"]\(.*\)['\"][[:space:]]*\$/\1/p" | head -1)"
  if [ -z "$SCOPE_FAM" ]; then
    SCOPE_FAM='.'
    rlog "SCOPE: .keep-proof.toml on $branch names no families — EVERY family (oracle filter '.')"
  else
    rlog "SCOPE: NARROWED by .keep-proof.toml on keep branch $branch"
  fi
  SCOPE_TESTS="$(printf '%s\n' "$body" | sed -n 's/^[[:space:]]*tests[[:space:]]*=[[:space:]]*\[\(.*\)\].*/\1/p' \
                 | head -1 | tr -d '"'"'" | tr ',' ' ')"
  return 0
}

# The branch NAME the proven tip goes by: the argument as given (a remote-tracking prefix stripped),
# or the checked-out branch; empty on a detached HEAD.
branch_name() {
  local repo="$1" given="$2"
  if [ -n "$given" ]; then
    given="${given#refs/heads/}"; given="${given#refs/remotes/}"; given="${given#origin/}"
    printf '%s' "$given"
  else
    git -C "$repo" symbolic-ref --short -q HEAD || true
  fi
}

# ── --selftest ──────────────────────────────────────────────────────────────────────────────────
# Offline, seconds, no fleet: throwaway repos built here, every case one where a broken resolver
# says the comfortable thing (a narrowed scope that looks like a full one, or no refusal).
if [ "$SELFTEST" = 1 ]; then
  st_bad=0
  ok()   { printf '  [ok]     %s\n' "$1"; }
  nope() { printf '  [FAILED] %s\n' "$1"; st_bad=1; }
  st_tmp="$(mktemp -d "${TMPDIR:-/tmp}/prove-remote-selftest-XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '$st_tmp'" EXIT
  echo "prove-remote selftest"
  # The throwaway repos carry no operator config and no hooks: an identity-policing global hook
  # would otherwise refuse the fixture commits and every case would pass or fail for that reason.
  stgit() { GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -c user.name=st -c user.email=st@invalid \
              -c core.hooksPath=/dev/null "$@"; }
  mkrepo() {  # mkrepo <dir> <branch> [scope-file-body]
    stgit init -q -b "$2" "$1" || exit 1
    stgit -C "$1" commit -q --no-verify --allow-empty -m base || exit 1
    if [ $# -ge 3 ]; then
      printf '%s\n' "$3" > "$1/.keep-proof.toml"
      stgit -C "$1" add .keep-proof.toml || exit 1
      stgit -C "$1" commit -q --no-verify -m scope || exit 1
    fi
  }
  NARROW="families = '^(llm|billing|ledger)([|.]|\$)'
tests = [\"busbar-llm\", \"busbar\"]"

  mkrepo "$st_tmp/none" predev
  log="$( { resolve_scope "$st_tmp/none" HEAD predev; echo "rc=$? fam=$SCOPE_FAM tests=$SCOPE_TESTS"; } 2>&1 )"
  case "$log" in
    *"EVERY family"*"rc=0 fam=. tests=") ok "no scope file: every family, whole workspace, and the fallback is LOGGED" ;;
    *) nope "no scope file did not resolve to a logged every-family proof: $log" ;;
  esac

  mkrepo "$st_tmp/integ" predev "$NARROW"
  if (resolve_scope "$st_tmp/integ" HEAD predev) 2>"$st_tmp/err"; then
    nope "a scope file on predev was ACCEPTED — the integration branch's proof is silently narrowed"
  else
    rc=$?; if [ "$rc" = 3 ] && grep -q 'SCOPE REFUSED' "$st_tmp/err"; then ok "scope file on predev: refused, exit 3"
    else nope "scope file on predev: exit $rc without the refusal line"; fi
  fi

  stgit -C "$st_tmp/integ" checkout -q --detach
  if (resolve_scope "$st_tmp/integ" HEAD "$(branch_name "$st_tmp/integ" '')") 2>/dev/null; then
    nope "a scope file on a DETACHED HEAD was accepted"
  else ok "scope file on a detached HEAD: refused"; fi

  mkrepo "$st_tmp/keep" keep-money "$NARROW"
  resolve_scope "$st_tmp/keep" HEAD "$(branch_name "$st_tmp/keep" '')" 2>/dev/null
  # shellcheck disable=SC2086
  if [ "$SCOPE_FAM" = '^(llm|billing|ledger)([|.]|$)' ] && [ "$(printf '%s ' $SCOPE_TESTS)" = "busbar-llm busbar " ]; then
    ok "scope file on keep-money: narrowed to its families and packages"
  else nope "scope file on keep-money resolved to fam='$SCOPE_FAM' tests='$SCOPE_TESTS'"; fi

  if [ "$(branch_name "$st_tmp/keep" origin/keep-x)" = keep-x ] && [ "$(branch_name "$st_tmp/keep" refs/heads/predev)" = predev ]; then
    ok "branch argument: origin/ and refs/heads/ prefixes stripped"
  else nope "branch argument prefixes not stripped"; fi

  mkrepo "$st_tmp/empty" keep-x "tests = [\"busbar\"]"
  log="$(resolve_scope "$st_tmp/empty" HEAD keep-x 2>&1; echo "fam=$SCOPE_FAM")"
  case "$log" in
    *"names no families"*"fam=.") ok "keep file without families: every family, and the fallback is LOGGED" ;;
    *) nope "keep file without families did not resolve to a logged every-family proof: $log" ;;
  esac

  # The WORKING TREE is not the authority: an untracked scope file must not narrow a tip without one.
  mkrepo "$st_tmp/wt" keep-y
  printf '%s\n' "$NARROW" > "$st_tmp/wt/.keep-proof.toml"
  resolve_scope "$st_tmp/wt" HEAD keep-y 2>/dev/null
  if [ "$SCOPE_FAM" = . ]; then ok "an untracked scope file does not narrow a tip that has none"
  else nope "an untracked working-tree scope file narrowed the proof to '$SCOPE_FAM'"; fi

  if [ "$st_bad" = 0 ]; then echo "prove-remote selftest: every case discriminates"; exit 0; fi
  echo "prove-remote selftest: FAILED"; exit 1
fi

remote_wrapper

if [ "$SETUP" = 1 ]; then
  rc=0
  if [ -n "$HOST" ]; then
    remote_setup "$HOST" || rc=1
  else
    for h in $(fleet_hosts); do remote_setup "$h" || rc=1; done
  fi
  exit "$rc"
fi

[ -n "$HOST" ] || HOST="$(fleet_pick_host)"
TIP="$(git -C "$REPO" rev-parse "${BRANCH:-HEAD}")" || rdie "no such rev: ${BRANCH:-HEAD}"
REF="prove-$(date -u +%Y%m%d-%H%M%S)-$$"
rlog "host $HOST   tip $(git -C "$REPO" rev-parse --short "$TIP")   ref $REF"

# The scope is resolved LOCALLY, before the push: the operator should see it (or its refusal)
# before the twenty minutes start, not in the log afterwards.
resolve_scope "$REPO" "$TIP" "$(branch_name "$REPO" "$BRANCH")" || exit $?
rlog "oracle families: $SCOPE_FAM"
rlog "test packages:   ${SCOPE_TESTS:-<the whole workspace>}"

remote_push_tree "$HOST" "$REPO" "$REF" "$TIP"

START=$(date +%s)
set +e
rsh_script "$HOST" "$REF" "$SCOPE_FAM" "$SCOPE_TESTS" <<'PROVE'
set -uo pipefail
REF="$1"; FAMILIES="$2"; TESTS="$3"
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TERM_COLOR=always CARGO_INCREMENTAL=0
export RUSTC_WRAPPER=sccache SCCACHE_DIR=/var/cache/sccache SCCACHE_CACHE_SIZE=60G
# A SERVER PORT OF ITS OWN. sccache's server is addressed by a TCP port that defaults to
# 4226 for every process on the box; the four runner agents each hold one of their own, and
# joining theirs would mean a neighbour's `sccache --stop-server` killing this proof
# mid-compile — seen once, as `Connection reset by peer` inside rustc.
export SCCACHE_SERVER_PORT="${SCCACHE_SERVER_PORT:-4300}"
export RUSTFLAGS="-D warnings"
# EIGHT, not nproc. A box runs up to four proofs at once (it also carries four runner agents); a
# cargo that takes all 32 cores makes every neighbour slower and itself no faster.
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}"
W="$HOME/busbar-prove"
cd "$W" || { echo "no $W — run: ./scripts/prove-remote.sh --setup $(hostname)"; exit 2; }

step() { printf '\n\033[1m══ %s\033[0m  (%s)\n' "$1" "$(date -u +%H:%M:%S)"; }
T0=$(date +%s); mark() { printf '   [%s] %ss\n' "$1" "$(( $(date +%s) - T0 ))"; T0=$(date +%s); }

step "checkout $REF"
git fetch -q prove "+refs/heads/$REF:refs/heads/$REF" || exit 2
git checkout -q -f "$REF" || exit 2
# target/ and the cargo registry are the warm state; everything else the last proof left is noise.
git clean -qffdx -e target -e .cargo -e node_modules
git --no-pager log --oneline -1
mark checkout

step "build (workspace, locked)"
cargo build --workspace --locked || exit 1
mark build

step "fmt"
cargo fmt --all -- --check || exit 1
mark fmt

step "clippy -D warnings"
cargo clippy --workspace --all-targets --locked -- -D warnings || exit 1
mark clippy

step "tests${TESTS:+ (packages: $TESTS)}"
if [ -n "$TESTS" ]; then
  args=""; for p in $TESTS; do args="$args -p $p"; done
  # shellcheck disable=SC2086
  cargo test --locked $args || exit 1
else
  cargo test --workspace --locked || exit 1
fi
mark tests

step "cargo xtask gate --all"
cargo run -q -p xtask -- gate --all || exit 1
mark gate

step "cargo xtask selftest"
cargo run -q -p xtask -- selftest || exit 1
mark selftest

step "shadow oracle (filter: $FAMILIES)"
if [ -x ./bin/oracle ]; then
  cargo build -p busbar --release --locked || exit 1
  rm -rf target/oracle/recordings/candidate
  mkdir -p target/oracle/recordings/candidate
  # THE BOX'S OWN PORTS. Four proofs may run here at once and the recorder binds a fixed block;
  # deriving the base from the shell pid keeps two concurrent proofs off each other's sockets, the
  # same knob land.sh documents for two worktrees on one laptop.
  export LAND_ORACLE_PORT_BASE=$(( 40000 + ( $$ % 40 ) * 200 ))
  ./bin/oracle record --plane all --bin target/release/busbar \
     --filter "$FAMILIES" --out target/oracle/recordings/candidate || exit 1
  ./bin/oracle replay --golden target/oracle/recordings/golden --strict \
     --candidate target/oracle/recordings/candidate --out target/oracle/reports/prove || exit 1
else
  echo "   (no ./bin/oracle in this tree — the oracle leg is NOT part of this verdict)"
fi
mark oracle

echo
echo "PROVE-REMOTE: GREEN on $(hostname) for $(git rev-parse --short HEAD)"
PROVE
RC=$?
set -e
END=$(date +%s)

rlog "host $HOST   exit $RC   wall $(( END - START ))s"
exit "$RC"

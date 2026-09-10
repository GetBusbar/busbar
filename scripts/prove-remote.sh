#!/usr/bin/env bash
# Prove a hand-back ON THE FLEET, over ssh, and stream the whole thing back to this terminal.
#
#   ./scripts/prove-remote.sh --setup [host]        # prepare one box, or every box
#   ./scripts/prove-remote.sh                       # prove THIS worktree's tip
#   ./scripts/prove-remote.sh <branch>              # prove a local branch's tip
#   ./scripts/prove-remote.sh --host i-0abc <branch>
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

# The oracle leg's --golden path, extracted from THIS FILE rather than duplicated as a string
# literal in the selftest below — a selftest that copies the path instead of reading it would still
# pass after someone reintroduces the bug in the real heredoc. Matches the "one function, so
# --selftest drives the REAL reader rather than a copy of it" discipline used elsewhere in scripts/
# (loom.sh, profile-lock.sh).
oracle_golden_path() {
  sed -n 's/.*oracle replay --golden[[:space:]][[:space:]]*\([^ ]*\).*/\1/p' "$HERE/prove-remote.sh" | head -1
}

if [ "${1:-}" = "--selftest" ]; then
  fails=0
  say() { if [ "$1" = PASS ]; then echo "  ok: $2"; else echo "  SELFTEST FAILED: $2"; fails=$((fails + 1)); fi; }
  echo "== prove-remote SELF-TEST (the oracle leg's --golden path) =="

  gp="$(oracle_golden_path)"
  echo "  --golden resolves to: $gp"

  # THE BUG THIS GUARDS: target/oracle/recordings/golden is a path no prove box ever populates (it
  # is a build-artifact directory, never checked in) — `oracle replay` against it always exits 2 on
  # its own usage line, so the oracle leg is red on every proof regardless of the tree under test.
  [ "$gp" != "target/oracle/recordings/golden" ] \
    && say PASS "the golden path is not the never-populated build-artifact path" \
    || say FAIL "the golden path is the never-populated build-artifact path ($gp)"

  # THE FIX: the published golden lives in-tree, same spelling land.sh's own oracle leg uses
  # ($here/testing/shadow-oracle/golden/1.5.5) — so it exists in every checkout a prove box pushes,
  # with nothing to populate first.
  [ -d "$REPO/$gp" ] \
    && say PASS "the golden path exists in-tree at $gp" \
    || say FAIL "the golden path does not exist in-tree at $gp"

  if [ "$fails" -ne 0 ]; then
    echo "[selftest] FAILED: $fails case(s) did not hold." >&2
    exit 1
  fi
  echo "[selftest] PASS"
  exit 0
fi

HOST=""; BRANCH=""; SETUP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --setup) SETUP=1; shift ;;
    --host)  HOST="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    -*) rdie "unknown option $1" ;;
    *) if [ -z "$HOST" ] && [ "$SETUP" = 1 ]; then HOST="$1"; else BRANCH="$1"; fi; shift ;;
  esac
done

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

# The scope file is read LOCALLY as well as remotely: the operator should see the scope before the
# twenty minutes start, not in the log afterwards.
SCOPE_FAM='.'; SCOPE_TESTS=''
if [ -f "$REPO/.keep-proof.toml" ]; then
  SCOPE_FAM="$(sed -n "s/^[[:space:]]*families[[:space:]]*=[[:space:]]*['\"]\(.*\)['\"][[:space:]]*\$/\1/p" "$REPO/.keep-proof.toml" | head -1)"
  [ -n "$SCOPE_FAM" ] || SCOPE_FAM='.'
  SCOPE_TESTS="$(sed -n 's/^[[:space:]]*tests[[:space:]]*=[[:space:]]*\[\(.*\)\].*/\1/p' "$REPO/.keep-proof.toml" \
                 | head -1 | tr -d '"'"'" | tr ',' ' ')"
else
  rlog "no .keep-proof.toml at the tree root — the oracle filter is '.' (every family)"
fi
rlog "oracle families: $SCOPE_FAM"
rlog "test packages:   ${SCOPE_TESTS:-<the whole workspace>}"

remote_push_tree "$HOST" "$REPO" "$REF" "$TIP"

# ── THE TREE THIS PROOF GETS IS ITS OWN ─────────────────────────────────────────────────────────
# Rail 14 is the record of what the shared `~/busbar-prove` costs: two slots proving two branches
# on one box, the second `git checkout -f` moving the tree under the first one's `cargo test`, and
# a verdict about neither branch. The slug is the BRANCH the operator named — or, when they named
# none, this worktree's tip — so two slots proving two branches get two directories by
# construction, and two slots proving the SAME branch share one, which is not a race but a queue.
SLUG="$(remote_branch_slug "${BRANCH:-$(git -C "$REPO" rev-parse --short "$TIP")}")" \
  || rdie "cannot make a checkout name out of '${BRANCH:-$TIP}'"
rlog "checkout on the box: ~/$(remote_work_dir "$SLUG")  (seed: $PROVE_SEED)"
WORK_DIR="$(rsh_script "$HOST" "$SLUG" "$PROVE_SEED" < <(remote_workdir_script) 2>/dev/null | tail -1)"
case "$WORK_DIR" in
  */busbar-prove-*) ;;
  *) rdie "the box did not make a per-branch checkout for '$SLUG' (got: ${WORK_DIR:-<nothing>}) — refusing to fall back to the shared tree" ;;
esac

START=$(date +%s)
set +e
rsh_script "$HOST" "$REF" "$SCOPE_FAM" "$SCOPE_TESTS" "$WORK_DIR" <<'PROVE'
set -uo pipefail
REF="$1"; FAMILIES="$2"; TESTS="$3"; WORK_DIR="$4"
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TERM_COLOR=always CARGO_INCREMENTAL=0
export RUSTC_WRAPPER=sccache SCCACHE_DIR=/var/cache/sccache SCCACHE_CACHE_SIZE=60G
# A SERVER PORT OF ITS OWN. sccache's server is addressed by a TCP port that defaults to
# 4226 for every process on the box; the four runner agents each hold one of their own, and
# joining theirs would mean a neighbour's `sccache --stop-server` killing this proof
# mid-compile — seen once, as `Connection reset by peer` inside rustc.
# …and derived from the CHECKOUT, not fixed at 4300, now that two branches can prove here at once:
# 4300 for both of them is the same neighbour problem one directory up.
if [ -z "${SCCACHE_SERVER_PORT:-}" ]; then
  _h=$(printf '%s' "$WORK_DIR" | cksum | cut -d' ' -f1)
  SCCACHE_SERVER_PORT=$(( 4300 + (_h % 60) ))
fi
export SCCACHE_SERVER_PORT
export RUSTFLAGS="-D warnings"
# EIGHT, not nproc. A box runs up to four proofs at once (it also carries four runner agents); a
# cargo that takes all 32 cores makes every neighbour slower and itself no faster.
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}"
W="$WORK_DIR"
cd "$W" || { echo "no $W — run: ./scripts/prove-remote.sh --setup $(hostname)"; exit 2; }
# THE PROOF ANNOUNCES ITSELF TO THE ALLOCATOR. `<checkout>/.proof.pid` is what ci-remote-lib.sh's
# probe counts per box, and the ceiling it enforces is only real if the file goes away when the
# proof does — including when it is killed. A pid whose process is gone is not counted, so a
# crashed proof degrades to "not running" rather than to a box nobody may use again.
echo $$ > "$W/.proof.pid"
trap 'rm -f "$W/.proof.pid"' EXIT INT TERM
echo "   proof pid $$ in $W (sccache port $SCCACHE_SERVER_PORT)"

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
  ./bin/oracle replay --golden testing/shadow-oracle/golden/1.5.5 \
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

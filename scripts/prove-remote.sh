#!/usr/bin/env bash
# Prove a hand-back ON THE FLEET, over ssh, and stream the whole thing back to this terminal.
#
#   ./scripts/prove-remote.sh --setup [host]        # prepare one box, or every box
#   ./scripts/prove-remote.sh                       # prove THIS worktree's tip
#   ./scripts/prove-remote.sh <branch>              # prove a local branch's tip
#   ./scripts/prove-remote.sh --host i-0abc <branch>
#   ./scripts/prove-remote.sh --posture ship        # …and the release-time gates as well
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
# ONE LEG IS NOT keep-proof.yml's, AND IT IS THE GATE LEG. `cargo xtask gate --all` includes the
# release-time gates, which are red on the dev line by design, so every slot pre-proof ended `RED in
# ship-ready` after a green build/test/clippy and told the slot nothing (measured: exit 1 at 815 s).
# The gate leg is now the one the LANDING ENGINE runs for a `--to dev` landing — kind-isolation,
# plus the construction row report judged by land.sh's own land_gate_verdict/land_ceiling_verdict —
# so a slot's verdict equals the engine's. `--posture ship` puts the release-time rows back.
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

# ── WHICH GATES A SLOT'S PROOF RUNS, AND WHY IT IS NOT `gate --all` ─────────────────────────────
# MEASURED (T0-S-TIP, 2026-09-10): a slot pre-proof exited 1 at 815 s with `RED in ship-ready`
# after a green build, fmt, clippy and test run, on a tree whose only reds were the tip's STANDING
# ones. `cargo xtask gate --all` runs the release-time gates — ship-ready, kind-isolation-ship, and
# design-bindings' PB-0 — and those are red on the dev line BY DESIGN: ship-ready's every row is a
# claim about a tree ready to promote, the ship twin's added rows are a claim about the ship SHA,
# and PB-0 cites a retired `scripts/inventory-coverage.sh`. A verdict that is red for all of those
# reasons tells the slot NOTHING about its own tree, and a red that means nothing is a red nobody
# reads — which is the exact signal-destroying shape xtask/src/gates/mod.rs's REPORT_ONLY header is
# itself a record of.
#
# SO A SLOT PROVES WHAT THE ENGINE PROVES. land.sh's dev-line plan runs `cargo xtask gate
# kind-isolation` (the owner's ship criterion, 84 s) and `cargo xtask gate construction --report`
# judged by land_gate_verdict — every row measured, the reds being EXACTLY the named standing list
# and no others, no stale name left on it — plus land_ceiling_verdict's proof that the ceiling
# ratchet was measured at all. A slot's green and the engine's green are then the same sentence.
#
# AND THE VERDICT IS land.sh's OWN CODE, NOT A COPY OF IT. The three functions are READ OUT OF
# scripts/land.sh IN THE TREE UNDER TEST and eval'd — the same "drive the REAL reader" discipline
# oracle_golden_path above is written for. A copy would drift from the engine silently, and a slot
# whose gate leg disagrees with the engine's is worse than no slot leg at all.
prove_gate_verdict_src() { # $1 = a tree; prints land.sh's gate-verdict functions
  sed -n '/^land_construction_standing_reds() {/,/^}/p;/^land_ceiling_verdict() {/,/^}/p;/^land_gate_verdict() {/,/^}/p' \
    "${1:-$REPO}/scripts/land.sh"
}
# dev (the default) or ship. `ship` is the operator saying "judge this as a promotion": the
# release-time rows run, and the verdict is `gate --all`'s as well as the dev plan's.
prove_validate_posture() { # $1 = the value
  case "${1:-}" in dev|ship) return 0 ;; esac
  echo "prove-remote: --posture takes 'dev' (the default, exactly what a --to dev landing proves)" >&2
  echo "prove-remote:   or 'ship' (that, plus the release-time gates). Got: '${1:-}'" >&2
  return 1
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

  echo "== prove-remote SELF-TEST (a slot proves what a --to dev landing proves) =="
  # THE POSTURE FLAG.
  prove_validate_posture dev  2>/dev/null && say PASS "the default posture is a value this script knows" \
    || say FAIL "dev is not an accepted posture"
  prove_validate_posture ship 2>/dev/null && say PASS "ship is the other one" \
    || say FAIL "ship is not an accepted posture"
  prove_validate_posture promote 2>/dev/null && say FAIL "an unknown posture was accepted" \
    || say PASS "an unknown posture is refused, not guessed"
  prove_validate_posture 2>/dev/null && say FAIL "an empty posture was accepted" \
    || say PASS "an empty posture is refused too"

  # THE LEGS. The dev plan is the engine's two gate legs; the release-time rows are ship's alone.
  body="$(sed -n "/^rsh_script \"\$HOST\" \"\$REF\"/,/^PROVE$/p" "$HERE/prove-remote.sh")"
  case "$body" in
    *"gate kind-isolation"*) say PASS "the dev plan runs the kind-isolation gate, as a landing does" ;;
    *) say FAIL "the kind-isolation gate is not in the remote plan" ;;
  esac
  case "$body" in
    *"gate construction --report"*) say PASS "  ...and the construction row report it judges" ;;
    *) say FAIL "the construction report is not in the remote plan" ;;
  esac
  shipblock="$(printf '%s\n' "$body" | sed -n '/POSTURE" = ship/,/^fi$/p')"
  case "$shipblock" in
    *"gate --all"*) say PASS "the release-time rows run under --posture ship" ;;
    *) say FAIL "--posture ship does not run the release-time gates" ;;
  esac
  # …AND NOWHERE ELSE. Measured: `gate --all` on the dev line exits 1 in ship-ready after a green
  # build/test/clippy, which is 815 s spent to tell the slot nothing about its own tree.
  # THE INVOCATION, not the words: this file talks ABOUT `gate --all` in the comment that explains
  # why it is not the dev leg, and a count that read prose would be satisfied by deleting a comment.
  n_all="$(printf '%s\n' "$body" | grep -c -- '-- gate --all' || true)"
  n_ship="$(printf '%s\n' "$shipblock" | grep -c -- '-- gate --all' || true)"
  [ "$n_all" = "$n_ship" ] && [ "$n_ship" -ge 1 ] \
    && say PASS "  ...and the DEFAULT posture never runs them ($n_all invocation(s), all of them ship's)" \
    || say FAIL "gate --all runs outside the ship posture ($n_all invocation(s), $n_ship of them ship's)"

  # THE VERDICT IS land.sh's, READ OUT OF THE TREE — driven here on fixtures, not described.
  src="$(prove_gate_verdict_src "$REPO")"
  case "$src" in
    *"land_gate_verdict()"*) say PASS "land.sh's gate verdict is readable out of the tree" ;;
    *) say FAIL "land.sh's gate verdict could not be read out of the tree" ;;
  esac
  case "$body" in
    *"prove_gate_verdict_src"*|*"land_gate_verdict"*) say PASS "  ...and the remote plan uses it" ;;
    *) say FAIL "the remote plan does not use land.sh's verdict" ;;
  esac
  # NO SECOND COPY OF THE STANDING LIST. A list spelled twice is a list that goes stale once.
  # THE PATTERN MUST NOT MATCH ITSELF — a grep for a row name, written in the file it searches, is
  # its own hit, and this case failed on its own text the first time it ran.
  [ "$(grep -c 'plane-no[-]money' "$HERE/prove-remote.sh" || true)" = 0 ] \
    && say PASS "  ...and this file keeps no copy of the standing-red list" \
    || say FAIL "this file carries its own copy of the standing-red rows"
  ( eval "$src"
    fx="$(mktemp -t prove-gate.XXXXXX)"
    land_construction_standing_reds | sed 's/^/FAIL  /;s/$/  x/' >"$fx"
    printf 'PASS  ceiling-rose  x\nPASS  ceiling-slack  x\nPASS  something-else  x\n' >>"$fx"
    land_ceiling_verdict "$fx" >/dev/null 2>&1 || exit 3
    land_gate_verdict "$fx" '.' >/dev/null 2>&1 || exit 4
    printf 'FAIL  a-brand-new-red  x\n' >>"$fx"
    land_gate_verdict "$fx" '.' >/dev/null 2>&1 && exit 5
    rm -f "$fx" ) ; rc=$?
  case "$rc" in
    0) say PASS "  ...and on a fixture it is green on the standing reds and red on a new one" ;;
    3) say FAIL "the ceiling ratchet read no rows on a fixture that has them" ;;
    4) say FAIL "the standing reds alone were scored RED (the slot would red on the tip's own rows)" ;;
    5) say FAIL "a NEW construction red was scored green" ;;
    *) say FAIL "the extracted verdict could not be driven (rc $rc)" ;;
  esac

  if [ "$fails" -ne 0 ]; then
    echo "[selftest] FAILED: $fails case(s) did not hold." >&2
    exit 1
  fi
  echo "[selftest] PASS"
  exit 0
fi

HOST=""; BRANCH=""; SETUP=0; POSTURE=dev
while [ $# -gt 0 ]; do
  case "$1" in
    --setup) SETUP=1; shift ;;
    --host)  HOST="$2"; shift 2 ;;
    --posture) prove_validate_posture "${2:-}" || exit 2; POSTURE="$2"; shift 2 ;;
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
rlog "posture:         --posture $POSTURE ($([ "$POSTURE" = ship ] && echo 'the dev plan PLUS the release-time gates' || echo 'exactly what a --to dev landing proves'))"
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
rsh_script "$HOST" "$REF" "$SCOPE_FAM" "$SCOPE_TESTS" "$WORK_DIR" "$POSTURE" <<'PROVE'
set -uo pipefail
REF="$1"; FAMILIES="$2"; TESTS="$3"; WORK_DIR="$4"; POSTURE="${5:-dev}"
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

step "gates: the legs a --to dev landing runs (posture: $POSTURE)"
# land.sh's OWN verdict functions, read out of the tree under test and eval'd — so this leg and the
# landing engine's cannot disagree about what a red means. `gate --all` is NOT this leg: it runs
# ship-ready, kind-isolation-ship and design-bindings' PB-0, which are red on the dev line by
# design, and a slot proof that exits 1 in ship-ready after a green build has measured nothing
# about its own tree (measured: exit 1 at 815 s, T0-S-TIP, on a tree with only standing reds).
gsrc="$(sed -n '/^land_construction_standing_reds() {/,/^}/p;/^land_ceiling_verdict() {/,/^}/p;/^land_gate_verdict() {/,/^}/p' scripts/land.sh)"
case "$gsrc" in
  *"land_gate_verdict()"*) ;;
  *) echo "prove-remote: RED — land.sh's gate verdict is not readable out of this tree; refusing to invent a second one"; exit 2 ;;
esac
eval "$gsrc" || exit 2
cargo run -q -p xtask -- gate kind-isolation || exit 1
glog=target/prove-gate-construction.log
mkdir -p target
cargo run -q -p xtask -- gate construction --report >"$glog" 2>&1 || true
land_ceiling_verdict "$glog" || exit 1
land_gate_verdict "$glog" '.' || exit 1
if [ "$POSTURE" = ship ]; then
  # THE RELEASE-TIME ROWS, ON THE OPERATOR'S WORD. ship-ready, kind-isolation-ship and
  # design-bindings are claims about a tree that is ready to promote; `--posture ship` is a slot
  # saying it is asking that question.
  step "cargo xtask gate --all (release-time rows: --posture ship)"
  cargo run -q -p xtask -- gate --all || exit 1
fi
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

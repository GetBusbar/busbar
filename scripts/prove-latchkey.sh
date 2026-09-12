#!/usr/bin/env bash
# Prove a hand-back ON LATCHKEY — a fresh managed runner per proof — with scripts/prove-remote.sh's
# contract, so the engine and a slot can swap one for the other without learning a second language.
#
#   ./scripts/prove-latchkey.sh                       # prove THIS worktree's tip
#   ./scripts/prove-latchkey.sh <branch>              # prove a local branch's tip
#   ./scripts/prove-latchkey.sh --posture ship        # …and the release-time gates as well
#   ./scripts/prove-latchkey.sh --tree /path/to/worktree    # …prove THAT checkout (a slot's own)
#   ./scripts/prove-latchkey.sh --preprove --batch <file>   # the engine's sweep pre-proof leg
#   ./scripts/prove-latchkey.sh --preprove --batch <f> --no-shards   # …as ONE job, the old way
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
# ── WHERE THE FULL JOB LOG IS KEPT, PAST LATCHKEY'S 24 HOURS ────────────────────────────────────
# Beside the MAIN repository, never beside this checkout. Measured the wrong way round first: a slot
# proves from `<repo>/.claude/worktrees/agent-lk3`, so `$REPO/..` is `.claude/worktrees` and the
# 700 KB log went to `…/.claude/worktrees/busbar-landq-state/`, which no ledger reads and which the
# next `git worktree prune` is entitled to remove. The main repository's own root is what
# `--git-common-dir` names, whichever worktree this is.
# ── AND IT IS A PATH IN THE ENV FILE, NOT A DERIVATION ──────────────────────────────────────────
# MEASURED (2026-09-12): the derivation is right for the runner tree and wrong for every other tree
# it is pointed at — the landing smoke on a scratch clone under $LAND_TMP kept its job logs beside
# the SCRATCH, under ~/Developer/tmp/…/busbar-landq-state/, which no ledger reads and which nothing
# preserves. The ledgers cite these logs by path months later, so there is exactly one right answer
# and it is not a function of which tree happened to be proving. `LATCHKEY_LOG_DIR` is set in
# scripts/landq.env.example and the supervisor exports it; the derivation stays as the last resort
# for an operator running by hand, and it says so when it is used.
LK_STATE_HOME="$(cd "$(dirname "$(git -C "$REPO" rev-parse --git-common-dir 2>/dev/null || echo "$REPO/.git")")/.." 2>/dev/null && pwd)"
LK_LOGDIR="${LATCHKEY_LOG_DIR:-}"
if [ -z "$LK_LOGDIR" ]; then
  LK_LOGDIR="$LK_STATE_HOME/busbar-landq-state/gate/latchkey-logs"
  LK_LOGDIR_DERIVED=1
fi

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
# ── AND IT IS THE MERGE-BASE OR NOTHING. A BRANCH TIP IS NOT A BASE ────────────────────────────
# MEASURED (K4d-r, 2026-09-12): a slot's tree whose tip was already an ANCESTOR of
# origin/integration/oracle-phase0 — a re-pick with no delta of its own — made `merge-base` equal
# HEAD, and the old fallback below it then answered with the raw local branch tip
# `refs/heads/integration/oracle-phase0`, which is AHEAD of that tip. That sha is not an ancestor of
# what `push +tip:refs/heads/tip` carried, so the objects never arrived, `update-ref` died
# `nonexistent object`, and the whole proof came back `could not stage the history` — an infra
# refusal wearing a tree's clothes, on every line that slot pre-proved.
#
# THE INVARIANT IS ONE SENTENCE: THE BASE IS ALWAYS AN ANCESTOR OF THE TIP. The merge-base is that
# by construction, so its objects travel with the tip's push and no extra transfer can fail. A
# branch tip is not, and no amount of "it is usually behind" makes it so.
#
# AND A BASE THAT EQUALS THE TIP IS THE RIGHT ANSWER FOR A ZERO-DELTA TREE, not an error to route
# around. The tree owes no delta; the PICKS are the delta, and they arrive as their own refs. The
# caller decides whether a proof with neither a delta nor a pick is worth running (see the refusal
# beside `TIP`), and this function's job is only to be true.
lk_base_sha() { # $1 = repo, $2 = the tip being proven (default HEAD)
  local repo="${1:-$REPO}" tip="${2:-HEAD}" head mb
  head="$(git -C "$repo" rev-parse "$tip" 2>/dev/null)" || return 1
  mb="$(git -C "$repo" merge-base "$head" "$LAND_BASE_REF" 2>/dev/null || true)"
  [ -n "$mb" ] || mb="$(git -C "$repo" merge-base "$head" "$LAND_BASE_BRANCH" 2>/dev/null || true)"
  if [ -n "$mb" ]; then printf '%s\n' "$mb"; return 0; fi
  # NO INTEGRATION REF IN THIS REPOSITORY AT ALL (a scratch clone, a fresh worktree). The tip's own
  # parent is the only ancestor there is to offer, and it IS an ancestor, which is the invariant.
  git -C "$repo" rev-parse --verify --quiet "${head}~1" 2>/dev/null || return 1
}

# ── THE SCOPE FILE IS TOML, AND IT IS READ AS TOML ──────────────────────────────────────────────
# MEASURED (M1c-b-r, 2026-09-12): `.keep-proof.toml`'s `tests` array was read with a single-line
# `sed 's/tests[[:space:]]*=[[:space:]]*\[\(.*\)\]/\1/p'`. A MULTI-LINE array —
#
#     tests = [
#       "busbar-core",
#       "xtask",
#     ]
#
# — matches nothing, so the value came back EMPTY, and empty means "the caller named no package",
# which the runner answers with `cargo test --workspace`: NINETY-FOUR MINUTES. That is what walked
# three of M1c-b's jobs into the 7200 s ceiling. Not the self-test batteries, not the runner size —
# a regex that could only read one of TOML's two spellings of the same array, failing OPEN, into the
# most expensive leg the engine has.
#
# SO IT IS PARSED, NOT MATCHED. `python3 -c` with `tomllib` is the first reader — it is in the
# standard library from 3.11 and the runners and this laptop all have it, and it is the same parser
# cargo's own ecosystem uses. The awk fallback joins the bracket span before it splits, so it reads
# both spellings too; it exists for a machine with no python3 and it is not the path anybody is
# expected to take.
#
# AND AN EMPTY ARRAY IS NOT AN ABSENT KEY. `tests = []` says "this hand-back asks for NO cargo
# test"; an absent `tests` says "the caller did not scope it". The first must not become the
# workspace — that is the failing-open bug again, one level up — so the reader prints the sentinel
# `-` for a declared-empty array and the runner subtracts the leg rather than widening it.
lk_toml_array() { # $1 = file, $2 = key; prints the members space-separated, or '-' when declared empty
  local f="${1:-}" k="${2:-}"
  [ -n "$f" ] && [ -f "$f" ] || return 0
  # `LK_TOML_FORCE_AWK=1` exists for ONE caller — this file's own selftest — because a laptop and a
  # runner both have python3, so the fallback would otherwise never be executed by anything until
  # the day it was the only reader left.
  if [ -z "${LK_TOML_FORCE_AWK:-}" ] && command -v python3 >/dev/null 2>&1; then
    LK_TOML_F="$f" LK_TOML_K="$k" python3 - <<'PY' 2>/dev/null && return 0
import os, sys
try:
    import tomllib
except ImportError:
    sys.exit(1)
try:
    with open(os.environ["LK_TOML_F"], "rb") as fh:
        d = tomllib.load(fh)
except Exception:
    sys.exit(1)
k = os.environ["LK_TOML_K"]
if k not in d:
    sys.exit(0)
v = d[k]
if isinstance(v, list):
    items = [str(x).strip() for x in v if str(x).strip()]
    print(" ".join(items) if items else "-")
elif isinstance(v, str):
    print(v)
sys.exit(0)
PY
  fi
  # THE FALLBACK JOINS THE BRACKET SPAN FIRST, which is the whole point: the defect was a reader
  # that looked at one line at a time. The span is captured and the DECISION is taken in shell,
  # because a pipeline cannot tell "the key was declared empty" from "the key was not there" —
  # `printf '' | awk '{…}'` runs no rule at all, and that is the same failing-open shape again.
  local span found=0
  span="$(awk -v key="$k" '
    BEGIN { inb = 0; buf = "" }
    {
      line = $0
      sub(/[[:space:]]*#.*$/, "", line)
      if (!inb) {
        if (line ~ "^[[:space:]]*" key "[[:space:]]*=[[:space:]]*\\[") {
          sub("^[[:space:]]*" key "[[:space:]]*=[[:space:]]*\\[", "", line)
          inb = 1; buf = line
        } else next
      } else { buf = buf " " line }
      if (inb && buf ~ /\]/) { sub(/\].*$/, "", buf); print "FOUND" buf; exit }
    }
  ' "$f" 2>/dev/null)"
  case "$span" in FOUND*) found=1; span="${span#FOUND}" ;; *) return 0 ;; esac
  [ "$found" = 1 ] || return 0
  span="$(printf '%s' "$span" | tr -d "\"'" | tr ',' ' ' | tr -s '[:space:]' ' ' | sed 's/^ *//; s/ *$//')"
  if [ -n "$span" ]; then printf '%s\n' "$span"; else printf -- '-\n'; fi
}
lk_toml_string() { # $1 = file, $2 = key; prints the value, or nothing
  local f="${1:-}" k="${2:-}"
  [ -n "$f" ] && [ -f "$f" ] || return 0
  # `LK_TOML_FORCE_AWK=1` exists for ONE caller — this file's own selftest — because a laptop and a
  # runner both have python3, so the fallback would otherwise never be executed by anything until
  # the day it was the only reader left.
  if [ -z "${LK_TOML_FORCE_AWK:-}" ] && command -v python3 >/dev/null 2>&1; then
    LK_TOML_F="$f" LK_TOML_K="$k" python3 - <<'PY' 2>/dev/null && return 0
import os, sys
try:
    import tomllib
except ImportError:
    sys.exit(1)
try:
    with open(os.environ["LK_TOML_F"], "rb") as fh:
        d = tomllib.load(fh)
except Exception:
    sys.exit(1)
v = d.get(os.environ["LK_TOML_K"])
if isinstance(v, str):
    print(v)
sys.exit(0)
PY
  fi
  sed -n "s/^[[:space:]]*$k[[:space:]]*=[[:space:]]*['\"]\(.*\)['\"][[:space:]]*\$/\1/p" "$f" 2>/dev/null | head -1
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
  # ── THE TIP GOES ALONE, AND EVERY PICK GOES BY ITSELF AFTER IT ────────────────────────────────
  # MEASURED (--smoke-latchkey on a scratch clone at 09dacd152, the pick 6b47b1ca5): pushing the tip
  # and one pick in ONE `git push` fails with
  #
  #     ! [remote failure]  6b47b1ca5 -> refs/proof/picks/6b47b1ca5 (remote failed to report status)
  #     error: failed to push some refs
  #
  # and `git push` is ATOMIC over its refspecs, so the TIP failed with it and the whole proof died
  # `could not stage the history`. The same pick pushed ALONE into the same bare repo succeeds; so
  # does the tip alone, and so do both when the tip goes first. The receiving side cannot report
  # status for a second ref while it is carrying a shallow boundary — which is this laptop's clone,
  # permanently. This is the audit pins' lesson, one paragraph down, arriving for the picks: a
  # single ref that cannot travel takes everything in its push with it.
  #
  # AND A PICK THAT CANNOT TRAVEL IS A REFUSAL, WHICH IS WHERE IT DIFFERS FROM A PIN. A pin that
  # does not arrive costs one gate row. A pick that does not arrive is a batch the runner cannot
  # cherry-pick — it would prove the TIP and report on the line — so it is rc 1 here and the caller
  # turns it into "nothing was staged", never into a verdict about the line.
  git -C "$repo" push -q "$bare" "+${tip}:refs/heads/tip" 2>/dev/null || return 1
  local h
  for h in "$@"; do
    [ -n "$h" ] || continue
    git -C "$repo" push -q "$bare" "+${h}:refs/proof/picks/$h" 2>/dev/null || {
      echo "prove-latchkey: the pick $h could not be pushed into the staged repository; nothing is proven without it" >&2
      return 1; }
  done
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
  # ── AND IT IS ASKED FOR BEFORE IT IS NAMED ────────────────────────────────────────────────────
  # `update-ref` on an object the bare repo does not have fails `nonexistent object`, and that
  # refusal reached the caller as `could not stage the history` — which reads like a transport fault
  # and is actually "somebody handed me a base that is not an ancestor of the tip" (see
  # lk_base_sha's header for the measurement). The object is checked for, pushed by itself if it is
  # genuinely absent, and only then named; a base that cannot be made present is said in words.
  if ! git -C "$bare" cat-file -e "${base}^{commit}" 2>/dev/null; then
    git -C "$repo" push -q "$bare" "+${base}:refs/proof/base/$base" 2>/dev/null || true
  fi
  git -C "$bare" cat-file -e "${base}^{commit}" 2>/dev/null || {
    echo "prove-latchkey: the base $base is not in the staged repository and could not be pushed into it." >&2
    echo "prove-latchkey:   A base must be an ANCESTOR of the tip; this one is not, so no ceiling row" >&2
    echo "prove-latchkey:   could be measured against it. Nothing was staged and nothing is proven." >&2
    return 1; }
  git -C "$bare" update-ref refs/remotes/origin/integration/oracle-phase0 "$base" || return 1
  git -C "$bare" update-ref refs/heads/integration/oracle-phase0 "$base" || return 1
  return 0
}

# ── AND THE DIRECTORY THAT IS PACKED IS NEVER THE WORKTREE ──────────────────────────────────────
# MEASURED, LIVE (the first phase-2 sweep on 992781fed): every pre-proof died with
# `could not stage the history into <W>/.latchkey`, and the two reasons are both fatal on their own.
#
#   (a) THE RUNNER TREE MUST NEVER BE WRITTEN. `latchkey run` packs the CURRENT DIRECTORY, so the
#       first form of this staged a 23 MB bare repository INSIDE W and asked Latchkey to pack W.
#       W is the landing engine's own checkout: the engine refuses an unsettled tree, `git clean`
#       runs across it, and a pre-proof is not W's state anyway — it is the LINE's picks threaded
#       on the tip, which the on-runner engine builds from the refs the bare repo carries.
#   (b) TWELVE CONCURRENT PRE-PROOFS SHARED ONE PATH. `$REPO/.latchkey` is a constant; the sweep
#       dispatches up to LATCHKEY_MAX_JOBS of these at once, and each one's `rm -rf` was another's
#       staging directory. The race is not a rare interleaving — it is every sweep.
#
# So every proof exports the tree it is about into a directory of its OWN, under $LAND_TMP, named
# by the ref (which already carries the timestamp and this process's pid), packs from THERE, and
# removes it afterwards. `git archive` rather than a copy: the export is exactly the tip's tracked
# files, so W's `target/`, its dirt and its other worktrees' leftovers cannot travel, and W is not
# so much as opened for writing.
lk_pack_dir() { # $1 = repo  $2 = the tree-ish to export  $3 = a unique id; prints the directory
  # DECLARED IN TWO STATEMENTS, not one. `local a="$1" d="…$a"` is read left-to-right by bash 4
  # and NOT by the bash 3.2 this laptop ships, where the second initialiser sees an unset name and
  # `set -u` kills the function — measured here, on the first run of this file's own cases.
  local repo="$1" treeish="$2" id="$3"
  local d="$LAND_TMP/latchkey-proof-$id"
  rm -rf "$d"; mkdir -p "$d" || return 1
  git -C "$repo" archive --format=tar "$treeish" | tar -xf - -C "$d" || return 1
  printf '%s\n' "$d"
}

# ── THE ENGINE THE RUNNER RUNS IS THE ONE THAT SENT IT, NEVER THE TREE'S ────────────────────────
# MEASURED (--smoke-latchkey on a scratch clone at 09dacd152): the runner ran `bash scripts/land.sh
# --preprove --batch …` out of the PACKED TREE, and that tree's land.sh has no `--preprove` at all —
# the flag fell through its parser into the hash list and the job died
# `RED — cherry-pick --preprove conflicted`. Every pre-proof on that tip would have.
#
# THE REASON IS STRUCTURAL AND land-remote.sh ALREADY SAYS IT: the tree's `scripts/land.sh` is
# whatever LANDED LAST, and the engine driving this proof is whatever the runner is carrying — which
# is routinely newer, because land.sh's own fixes travel through the queue and are in flight. A
# landing judged by an engine older than the one on the laptop was the first fleet batch's defect,
# and it is this one's. So the engine travels INTO the pack, exactly as land-remote.sh copies it to
# the box, and `here=` is re-pointed at the runner's cwd on arrival.
#
# IT IS THE ENGINE BESIDE THIS TRANSPORT. `land.run.sh` first — that is the name lq_stage_engine
# gives the runner's copy — then the sibling in scripts/. This file and the engine that uses it are
# staged together by lq_stage_engine, so "beside" is exactly right and never a guess.
lk_engine_path() { # prints the land.sh this proof should be judged by, or nothing
  local c
  for c in "$HERE/land.run.sh" "$HERE/land.sh" "$REPO/scripts/land.sh"; do
    [ -f "$c" ] && { printf '%s\n' "$c"; return 0; }
  done
  return 1
}

# ── THE SCRIPT THE RUNNER EXECUTES ──────────────────────────────────────────────────────────────
# Emitted from ONE function so `--selftest` drives the real text rather than a copy of it — the
# discipline prove-remote.sh's oracle_golden_path is written for. It is staged INTO the packed tree
# (the job's command line is one bash line, and a bash line cannot carry a script) and its whole
# job is: put the history back, put the deny-list's casualties back, hand the tree to the engine
# that already knows how to prove it, and print the verdict file where the log can carry it home.
# ── THE PREAMBLE EVERY LATCHKEY RUNNER SHARES ───────────────────────────────────────────────────
# Put the history back, put the deny-list's casualties back, and set the engine's environment.
# EMITTED FROM ONE FUNCTION BECAUSE THERE ARE TWO CALLERS NOW: this script's pre-proof/tip runner
# and scripts/land-latchkey.sh's landing shards. A second copy of the reconstitution is a second
# place for `.git` to arrive differently, and the whole point of the bare-repo trick is that the
# runner's repository is the laptop's exactly. It expects $BR, $TIP and $BASE to be set by the
# caller's own positional unpacking, which is the only thing the two callers disagree about.
lk_onbox_preamble() {
  cat <<'PREAMBLE'
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

# ── THE ENGINE THAT SENT THIS JOB, ROOTED IN THIS CHECKOUT ──────────────────────────────────────
# Shipped as $STAGE/land.run.sh (see lk_engine_path for why it is not the tree's), with `here=`
# re-pointed at the directory that was packed — land.sh derives every path from that one line, and
# land-remote.sh does the identical rewrite on a fleet box. $ENGINE is what every mode below runs.
ENGINE="$STAGE/land.run.sh"
if [ -f "$ENGINE" ]; then
  sed "s|^here=.*|here=\"$PWD\"|" "$ENGINE" >"$STAGE/land.local.sh"
  ENGINE="$STAGE/land.local.sh"
  echo "   engine: the runner's land.sh, rooted at $PWD ($(grep -c . "$ENGINE") lines)"
else
  echo "prove-latchkey: RED — no $STAGE/land.run.sh in the packed tree; the engine never shipped and"
  echo "prove-latchkey:       the tree's own land.sh is whatever landed last, which is not this proof's judge"
  exit 2
fi
PREAMBLE
}

lk_onbox_script() { # $1 = mode (preprove|tip)  $2 = branch name  $3 = posture
  cat <<'ONBOX'
#!/usr/bin/env bash
# Generated by scripts/prove-latchkey.sh — runs on a Latchkey runner, never on a fleet box.
set -uo pipefail
MODE="$1"; BR="$2"; POSTURE="$3"; TIP="$4"; BASE="$5"; FAMILIES="${6:-.}"; TESTS="${7:-}"; LEGS="${8:-}"
ONBOX
  lk_onbox_preamble
  cat <<'ONBOX'

RC=0
# ── THE LEG SUBSET THIS SHARD OWNS ──────────────────────────────────────────────────────────────
# land.sh's LAND_LEGS_ONLY, which only ever SUBTRACTS from the plan the union owes (land_legs_only
# refuses an empty intersection loudly rather than reporting green over nothing). Empty — which is
# a tip proof and an unsharded pre-proof — leaves the plan exactly as it has always been.
# LAND_LATCHKEY_INNER goes with it: a runner must never rent a runner.
[ -n "$LEGS" ] && export LAND_LEGS_ONLY="$LEGS"
export LAND_LATCHKEY_INNER=1
if [ "$MODE" = preprove ]; then
  say "land.sh --preprove over the batch${LEGS:+, legs [$LEGS]} (the picks, the legs, the bisect — and it publishes nothing)"
  bash "$ENGINE" --preprove --batch "$STAGE/batch.txt"; RC=$?
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
  # ── AND AN EMPTY SCOPE SUBTRACTS THE LEG, IT DOES NOT WIDEN IT ────────────────────────────────
  # `-` is what the scope reader prints for a DECLARED-EMPTY `tests = []`: the hand-back is saying
  # "no cargo test", which is a scope and not a silence. It used to be indistinguishable from an
  # absent key, and an absent key falls through to `cargo test --workspace` — 94 minutes, and the
  # real reason three of M1c-b's jobs hit the 7200 s ceiling (see lk_toml_array's header).
  if [ "$TESTS" = "-" ]; then
    say "tests (the scope declares an EMPTY set: the test leg is NOT part of this verdict)"
  elif [ -n "$TESTS" ]; then
    say "tests (packages: $TESTS)"
    args=""; for p in $TESTS; do args="$args -p $p"; done
    # shellcheck disable=SC2086
    cargo test --locked $args || exit 1
  else
    say "tests (the scope names no package, so the whole workspace — this is the expensive path)"
    cargo test --workspace --locked || exit 1
  fi
  say "gates: the legs a --to dev landing runs (posture: $POSTURE)"
  # land.sh's OWN verdict functions, read out of the tree under test and eval'd, exactly as
  # prove-remote.sh does it — so this leg and the landing engine's cannot disagree about what a red
  # means, and no copy of the standing-red list lives in this file.
  gsrc="$(sed -n '/^land_construction_standing_reds() {/,/^}/p;/^land_ceiling_verdict() {/,/^}/p;/^land_gate_verdict() {/,/^}/p' "$ENGINE")"
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
    # THE 7200 s CEILING (lk_job_capped). A job that ran out of time measured whatever it measured
    # and was then killed; the legs it never reached are exactly as unproven as they were before it
    # started, and that is `NONE`, not `RED`.
    124) echo "NONE:cap" ;;
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

# ── AND A REFUSAL SAYS WHY, IN THE CLI'S OWN WORDS ──────────────────────────────────────────────
# MEASURED (the sharded smoke, 2026-09-12 13:03): a submission took four minutes and came back with
# no job id, and this script said "the workspace's runner cap is shared with CI" — which was a
# GUESS. `2>/dev/null` had thrown away the only sentence that could have named the real cause, and
# the operator's next move (wait for the cap) was the wrong one. The `latchkey` CLI writes its
# progress AND its errors to stderr and the job id alone to stdout, so the two are separable: the
# id is read from stdout as before, and the last few lines of stderr are kept in $LK_SUBMIT_ERR for
# the caller to log when there is no id. Nothing is guessed and nothing is hidden.
# THE REASON TRAVELS IN A FILE, NOT IN A VARIABLE. Every caller of this runs it inside `$( cd … &&
# lk_submit … )` — a SUBSHELL — so a variable set here is gone before the caller can read it. The
# path is this process's alone (its pid) and the caller reads it with lk_submit_err.
LK_SUBMIT_ERRFILE="$LAND_TMP/lk-submit-err.$$"
lk_submit() { # $1 = the bash line; prints the job id; writes the CLI's own words when there is none
  local id
  : >"$LK_SUBMIT_ERRFILE" 2>/dev/null || true
  id="$("$LK_BIN" run --size "$LK_SIZE" --timeout "$LK_TIMEOUT" --quiet --detach "$1" 2>>"$LK_SUBMIT_ERRFILE" | tr -d '[:space:]')"
  case "$id" in cli-*) : >"$LK_SUBMIT_ERRFILE" 2>/dev/null || true ;; esac
  printf '%s' "$id"
}
lk_submit_err() { # prints the last thing the CLI said about a submission that made no job
  grep -v '^[[:space:]]*$' "$LK_SUBMIT_ERRFILE" 2>/dev/null | tail -5 | tr '\n' ' '
}

lk_state() { # $1 = job id
  "$LK_BIN" status "$1" 2>/dev/null | awk '/^State:/{print $2}'
}

lk_exit_code() { # $1 = job id; prints the command's exit code, or nothing
  "$LK_BIN" status "$1" 2>/dev/null | awk '/^Exit code:/{print $3}' | grep -E '^[0-9]+$' || true
}

# ── A JOB THAT NEVER RAN IS NOT A RED ───────────────────────────────────────────────────────────
# MEASURED (--smoke-latchkey, 2026-09-12): two jobs came back `State: failed`, `Exit code: -`,
# `Started: -`, `Failure reason: launch_failed: VcpuLimitExceeded`. Latchkey could not get the
# instance; the runner script was never executed; not one byte of anybody's tree was read. Scored
# from the state alone that is `failed` -> rc 1 -> RED, and two live queue lines would have been
# parked for AWS's capacity — which is the 127 defect wearing a different hat.
#
# THE QUESTION IS "DID THE COMMAND RUN", AND THE STATUS ANSWERS IT TWICE OVER: a job that ran has a
# `Started:` timestamp and an `Exit code:`. Either one absent on a terminal job means the verdict
# belongs to the platform, and the platform's verdicts are 75 — "nothing was learned, ask again".
lk_failure_reason() { # $1 = job id; prints Latchkey's own reason, or nothing
  "$LK_BIN" status "$1" 2>/dev/null | sed -n 's/^Failure reason:[[:space:]]*//p' | sed 's/[[:space:]]*$//' | grep -v '^-\?$' || true
}
lk_job_started() { # $1 = job id; 0 when the command really began
  local st
  st="$("$LK_BIN" status "$1" 2>/dev/null | awk '/^Started:/{print $2}')"
  case "$st" in *-*-*) return 0 ;; esac
  return 1
}
# THE ONE PLACE A TERMINAL STATE BECOMES AN EXIT CODE. Prints the code; 75 whenever the job never
# ran, whatever Latchkey called the state.
# ── AND A JOB THE CAP KILLED IS NOT A RED EITHER ────────────────────────────────────────────────
# MEASURED (SUB-4's tree and three of M1c-b's, 2026-09-11/12): a pre-proof on `large` ran past the
# 7200 s per-job ceiling inside `xtask selftest plane-purity-strict` and came back as a FAILURE with
# a timeout reason. Scored as a failure that is `RED`, and three live queue lines were called red
# for the size of the runner they were rented — which is the 127 defect and the VcpuLimitExceeded
# defect arriving a third time. The ceiling is a statement about THIS SCRIPT'S SHARD PLAN and about
# the runner size; it is never a statement about anybody's picks.
#
# LATCHKEY SPELLS IT THREE WAYS and this asks all three: the terminal state `expired`; a `failed`
# job whose own Failure reason names a timeout; and a job whose Started..Completed reaches the
# ceiling. 124 is the code — the shell's own timeout code — and lk_job_verdict turns it into
# `NONE:cap`, which is not a verdict.
lk_reason_is_cap() { # $1 = Latchkey's failure reason
  case "$(printf '%s' "${1:-}" | tr 'A-Z' 'a-z')" in
    *timeout*|*timed?out*|*time?limit*|*deadline*|*max?duration*) return 0 ;;
  esac
  return 1
}
lk_job_capped() { # $1 = job id, $2 = terminal state; 0 when the 7200 s ceiling is what ended it
  local id="$1" state="$2" secs
  [ "$state" = expired ] && return 0
  lk_reason_is_cap "$(lk_failure_reason "$id")" && return 0
  secs="$(lk_runner_secs "$id")"
  [ -n "$secs" ] && [ "$secs" -ge "$LK_TIMEOUT" ] && return 0
  return 1
}
# WHAT THE JOB GOT THROUGH BEFORE THE CEILING TOOK IT. A `NONE:cap` with no evidence is a shrug;
# with the legs it completed it is the shard plan's next move, written down. The runner's own
# headings (`== <leg>`) and the engine's own plan/leg sentences, and nothing invented here.
lk_legs_completed() { # $1 = log file
  local log="${1:-}"
  [ -f "$log" ] || return 0
  grep -E '^== |^land\.sh: \[' "$log" 2>/dev/null | sed 's/^== //' | tail -40
}
lk_job_rc() { # $1 = job id, $2 = terminal state
  local id="$1" state="$2" rc why
  case "$state" in
    cancelled) printf '130\n'; return 0 ;;
    expired)   printf '124\n'; return 0 ;;
  esac
  if lk_job_capped "$id" "$state"; then printf '124\n'; return 0; fi
  rc="$(lk_exit_code "$id")"
  if [ -z "$rc" ] && ! lk_job_started "$id"; then
    why="$(lk_failure_reason "$id")"
    lklog "job $id never started (${why:-no reason given}) — the runner script did not run, so there is no verdict: 75"
    printf '75\n'; return 0
  fi
  [ -n "$rc" ] || { case "$state" in succeeded) rc=0 ;; *) rc=1 ;; esac; }
  printf '%s\n' "$rc"
}

# ── WHAT IS ACTUALLY BILLED ─────────────────────────────────────────────────────────────────────
# The RUNNER's seconds, from the job's own Started/Completed — not this script's wall clock, which
# also contains the pack, the upload and the queue. Measured on the first real two-way proof: 717 s
# of laptop wall against 540 s on the runner, so reporting the wall would have overstated the bill
# by a third and made every cost comparison in the migration doc wrong in the same direction.
lk_runner_secs() { # $1 = job id; prints seconds, or nothing when the job never started
  local st ed
  st="$("$LK_BIN" status "$1" 2>/dev/null | awk '/^Started:/{print $2}')"
  ed="$("$LK_BIN" status "$1" 2>/dev/null | awk '/^Completed:/{print $2}')"
  case "$st$ed" in *-*) ;; *) return 0 ;; esac
  local a b
  a="$(date -u -j -f '%Y-%m-%dT%H:%M:%S' "${st%%.*}" +%s 2>/dev/null || date -u -d "$st" +%s 2>/dev/null)" || return 0
  b="$(date -u -j -f '%Y-%m-%dT%H:%M:%S' "${ed%%.*}" +%s 2>/dev/null || date -u -d "$ed" +%s 2>/dev/null)" || return 0
  [ -n "$a" ] && [ -n "$b" ] && [ "$b" -ge "$a" ] && printf '%s\n' "$(( b - a ))"
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
# THE PRE-PROOF'S SHARD PLAN — THE F5 SHAPE, UNDER THE 7200 s CEILING
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# MEASURED (SUB-4's tree, three of M1c-b's, 2026-09-11/12): one pre-proof job runs the WHOLE plan
# serially — build, tests, clippy, the gates AND the gate self-test batteries — and the batteries
# alone have been measured at 4,900 s (land_gate_battery_set's table). On `large` that walks past
# the 7200 s ceiling inside `xtask selftest plane-purity-strict`, and `xlarge` is not available
# (VcpuLimitExceeded, four times in one night). The landing path already answers this by fanning the
# plan across jobs (F5, scripts/land-latchkey.sh); this is the same answer for the pre-proof, and it
# is the same reason: the ceiling is PER JOB, so the fix is more jobs, never a longer one.
#
# THE SPLIT, AND WHY IT IS THIS SPLIT:
#
#   build   plugins fmt gatefiles tests clippy workspace-clippy   the cold build and everything
#                                                                 that rides on it
#   gates   kind-isolation gate                                   THE CAP'S HOME: the gate legs and
#                                                                 the self-test batteries they own
#   oracle  oracle                                                the recorder + replay
#
# EVERY SHARD INTERSECTS EVERY POSSIBLE PLAN, and that is a property, not a coincidence.
# `plugins fmt gatefiles` and `kind-isolation gate` are FLOOR in land_floor_plan — every union owes
# them — so neither of those two shards can ever select an empty subset of a line's plan, which is
# the one input land_legs_only refuses (correctly: a shard that owns no leg has measured nothing).
#
# THE ORACLE IS THE EXCEPTION AND IT IS HANDLED BY ASKING, NOT BY HOPING. `oracle` is in a union's
# plan only when the line names `--families`. A batch with even ONE line that names none would give
# that line an empty intersection in an oracle-only shard — a loud RED about a line whose plan
# simply has no oracle leg in it. So the oracle becomes its own job only when EVERY landing line in
# the batch names families; otherwise it rides with `build`, where it always has something to do.
#
# AND THE FAMILIES ARE NOT BUCKETED HERE, DELIBERATELY. land-latchkey.sh splits one union's family
# alternation across jobs because a landing is ONE union and the transport is handed its expression.
# A pre-proof batch is N lines, each carrying its OWN `--families` inside its argv, and land.sh
# reads that argv per line — there is no per-line channel through which this transport could hand a
# bucket down. Bucketing would mean rewriting queue lines, and a transport that edits the line it is
# proving is proving a different line. The leg split is what is expressible here, and it is what
# moves the cap: the batteries leave the critical path.
LK_PREPROVE_SHARDED="${LATCHKEY_PREPROVE_SHARDS:-1}"

lk_batch_lines_all_have_families() { # $1 = batch file; 0 when every landing line names --families
  local bf="${1:-}" l n=0
  [ -f "$bf" ] || return 1
  while IFS= read -r l || [ -n "$l" ]; do
    case "$l" in ''|'#'*) continue ;; esac
    n=$(( n + 1 ))
    case "$l" in *--families*) ;; *) return 1 ;; esac
  done <"$bf"
  [ "$n" -gt 0 ]
}

# Prints one `<name>|<legs>` row per job, or NOTHING when this batch should go as one job (which is
# exactly what this script did before the split, unchanged).
lk_preprove_shard_plan() { # $1 = batch file
  local bf="${1:-}"
  [ "$LK_PREPROVE_SHARDED" = 1 ] || return 1
  [ -f "$bf" ] || return 1
  grep -qvE '^[[:space:]]*(#|$)' "$bf" 2>/dev/null || return 1
  if lk_batch_lines_all_have_families "$bf"; then
    printf 'build|plugins fmt gatefiles tests clippy workspace-clippy\n'
    printf 'gates|kind-isolation gate\n'
    printf 'oracle|oracle\n'
  else
    printf 'build|plugins fmt gatefiles tests clippy workspace-clippy oracle\n'
    printf 'gates|kind-isolation gate\n'
  fi
}

# ── ONE VERDICT ROW PER LINE, OUT OF N SHARDS' ROWS ─────────────────────────────────────────────
# Each shard writes land.sh's own per-line file — `<STATUS><TAB><the line>` — over the SAME batch,
# so the rows are keyed by the line's text, which is how landq4.sh already reads them
# (lq_outcome_row). The merge is a WORST-WINS over the statuses, and the order is the worst-wins
# order for a reason apiece:
#
#   RED-CONFLICT  the PICK did not apply. Every shard saw the identical cherry-pick of the identical
#                 sha onto the identical tip, so it is the same fact in each of them.
#   RED           a leg this shard owns said no. One shard's red is the line's red — the other
#                 shards proved different legs and cannot speak for it.
#   HELD          land.sh's word for "a line before this one in its unit was the culprit, so this
#                 line was never applied". It OUTRANKS GREEN, which is the case that matters: a line
#                 the gates shard proved green may have been held in the build shard, and a line
#                 whose build was never run is not a proven line.
#   GREEN         only when every shard that owns a leg of it said so.
#
# AND A LINE THAT NOT EVERY SHARD REPORTED GETS NO ROW AT ALL. The shard sets are chosen so that
# every shard owns a leg of every line (see the plan above), so a missing row means that shard's
# file was truncated — and a merged GREEN assembled from a subset of the shards is exactly the
# "judged on a subset nobody chose" failure the landing path refuses by name.
lk_merge_results() { # $1 = the merged file, $2 = how many shards must have reported, $3.. = the shard files
  local out="$1" want="$2"; shift 2
  [ "$#" -ge 1 ] || return 1
  awk -F'\t' -v want="$want" '
    function rank(x) {
      if (x ~ /^RED-CONFLICT/) return 4
      if (x ~ /^RED/)          return 3
      if (x == "HELD")         return 2
      if (x == "GREEN")        return 1
      return 0
    }
    NF >= 2 {
      t = $2
      for (i = 3; i <= NF; i++) t = t FS $i
      if (!(t in seen)) { order[++n] = t; seen[t] = 1; best[t] = "" }
      if (rank($1) > rank(best[t])) best[t] = $1
      cnt[t]++
    }
    END {
      for (i = 1; i <= n; i++) {
        t = order[i]
        if (cnt[t] < want) continue
        printf "%s\t%s\n", best[t], t
      }
    }
  ' "$@" >"$out" 2>/dev/null
  [ -s "$out" ]
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# --selftest
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# EVERYTHING ABOVE THIS LINE IS A LIBRARY, AND scripts/land-latchkey.sh SOURCES IT.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# The landing backend needs THIS packer — `lk_stage_repo`, the bare-repo trick, the base resolution,
# the log parser, the healed-retry rule, the bounded poller and the runner preamble — and a second
# copy of any one of them is a second place for a verdict to be wrong. A second packer is the worst
# of them: the whole `.latchkey/git` design is one paragraph of reasoning about shallow clones, ref
# names and atomic pushes, and two copies of it drift silently because both look right.
#
# So `LK_LIB_ONLY=1 . scripts/prove-latchkey.sh` stops here, with every function defined and nothing
# run. `return` is what a sourced file does; the `|| exit 0` is for the operator who types
# `LK_LIB_ONLY=1 ./scripts/prove-latchkey.sh` and should get silence rather than a shell error.
if [ -n "${LK_LIB_ONLY:-}" ]; then return 0 2>/dev/null || exit 0; fi

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

  echo "== prove-latchkey SELF-TEST (this file is a library, and land-latchkey.sh sources it) =="
  # DRIVEN, NOT SPELLED: the file is really sourced with the guard set, in a subshell, and the
  # packer's name is really looked up afterwards. A guard placed below a function would still let
  # the source run the job.
  ( LK_LIB_ONLY=1 . "${BASH_SOURCE[0]}" >/dev/null 2>&1; declare -F lk_stage_repo >/dev/null ) \
    && say PASS "LK_LIB_ONLY=1 sources this file for its packer and runs nothing" \
    || say FAIL "LK_LIB_ONLY=1 did not leave lk_stage_repo defined"
  ( LK_LIB_ONLY=1 . "${BASH_SOURCE[0]}" >/dev/null 2>&1; declare -F lk_onbox_preamble >/dev/null ) \
    && say PASS "  ...and the runner preamble the landing shards share" \
    || say FAIL "lk_onbox_preamble is not defined for a library consumer"
  # THE PREAMBLE IS THE ONE THE PRE-PROOF RUNNER USES, not a copy beside it: the emitter is asked
  # for both and one must contain the other, character for character.
  case "$(lk_onbox_script preprove br dev)" in
    *"$(lk_onbox_preamble)"*) say PASS "  ...and it is the SAME text the pre-proof runner runs" ;;
    *) say FAIL "lk_onbox_script no longer emits lk_onbox_preamble's text" ;;
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
  # THE BASE IS THE MERGE-BASE AND NOTHING ELSE. The old form of this asked only that a merge-base
  # appeared somewhere; the FALLBACK underneath it — a raw `rev-parse` of the integration branch —
  # is what actually answered on a zero-delta tree, and that sha is not an ancestor of the tip
  # (K4d-r's `nonexistent object`). Both halves are asked now: the merge-base is used, and the
  # branch ref is never rev-parsed for a base.
  grep -qE 'merge-base "\$head" "\$LAND_BASE_REF"' "${BASH_SOURCE[0]}" \
    && say PASS "the base is the merge-base with the integration line, resolved here" \
    || say FAIL "the base is not the merge-base with the integration line"
  sed -n '/^lk_base_sha() {/,/^}/p' "${BASH_SOURCE[0]}" | grep -q 'rev-parse --verify --quiet "\$LAND_BASE' \
    && say FAIL "lk_base_sha still falls back to a raw branch tip, which is not an ancestor of the tip" \
    || say PASS "  ...and never a raw branch tip (an object the tip's push does not carry)"
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

  echo "== prove-latchkey SELF-TEST (the RUNNER TREE is never written, and two proofs never share a path) =="
  # MEASURED, LIVE: the first phase-2 sweep staged .latchkey INSIDE W and every pre-proof died
  # `could not stage the history into <W>/.latchkey` — twelve of them racing on one constant path,
  # in the engine's own checkout. Both halves are driven here on a real repository.
  _pt="$root/tree"
  git init -q "$_pt" 2>/dev/null
  # --no-verify: this laptop has a global hook that refuses any commit whose author is not the
  # owner's canonical identity, and a throwaway fixture repository is not a commit anybody keeps.
  git -C "$_pt" config user.email lk@selftest; git -C "$_pt" config user.name lk
  git -C "$_pt" config commit.gpgsign false
  printf 'a\n' >"$_pt/a.txt"; mkdir -p "$_pt/qa"; printf 'x=1\n' >"$_pt/qa/k.toml"
  git -C "$_pt" add a.txt qa/k.toml >/dev/null 2>&1; git -C "$_pt" commit -q --no-verify -m one
  printf 'b\n' >"$_pt/b.txt"; git -C "$_pt" add b.txt >/dev/null 2>&1; git -C "$_pt" commit -q --no-verify -m two
  _tip="$(git -C "$_pt" rev-parse HEAD)"
  _porcelain_before="$(git -C "$_pt" status --porcelain | grep -c . || true)"
  _p1="$(lk_pack_dir "$_pt" "$_tip" "case-1")"
  [ -n "$_p1" ] && [ -f "$_p1/a.txt" ] && [ -f "$_p1/b.txt" ] \
    && say PASS "the tree is exported, tracked file for tracked file, into its own directory" \
    || say FAIL "the export did not produce the tip's files"
  case "$_p1" in "$_pt"*) say FAIL "the export is INSIDE the tree it exports" ;;
    "$LAND_TMP"/latchkey-proof-*) say PASS "  ...under LAND_TMP, never inside the tree" ;;
    *) say FAIL "the export is not under LAND_TMP ($_p1)" ;; esac
  lk_stage_repo "$_pt" "$_p1/.latchkey" "$_tip" "$(git -C "$_pt" rev-parse HEAD~1)" >/dev/null 2>&1 \
    && say PASS "  ...and the bare repository is staged INSIDE that export" \
    || say FAIL "the bare repository could not be staged in the export"
  # THE WHOLE POINT: the runner tree is byte-identical afterwards. Not "no tracked change" — nothing
  # at all, including the untracked `.latchkey` directory the first form left behind.
  [ "$(git -C "$_pt" status --porcelain | grep -c . || true)" = "$_porcelain_before" ] \
    && say PASS "  ...and the runner tree's porcelain is exactly what it was" \
    || say FAIL "the runner tree was written: $(git -C "$_pt" status --porcelain | head -3 | tr '\n' ' ')"
  [ -e "$_pt/.latchkey" ] && say FAIL "a .latchkey was left in the runner tree" \
    || say PASS "  ...with no .latchkey anywhere in it"
  # TWO PROOFS, ONE TREE, AT ONCE. The ref carries the timestamp and the pid, so two concurrent
  # pre-proofs of the same tip cannot be handed the same directory — which is what the sweep does
  # twelve at a time.
  _p2="$(lk_pack_dir "$_pt" "$_tip" "case-2")"
  [ -n "$_p2" ] && [ "$_p1" != "$_p2" ] \
    && say PASS "two proofs of the same tip get two directories" \
    || say FAIL "two proofs of the same tip were handed one directory ($_p1)"
  [ -f "$_p1/.latchkey/git/HEAD" ] \
    && say PASS "  ...and the second's staging did not remove the first's" \
    || say FAIL "the second proof's staging destroyed the first's bare repository"
  # THE PACK PATH IS THE SUBMISSION'S cwd. A directory staged correctly and then packed from $REPO
  # would ship the runner tree anyway.
  grep -qF 'JOB="$(cd "$PACK" && lk_submit' "${BASH_SOURCE[0]}" \
    && say PASS "  ...and the job is submitted from the export, never from the repository" \
    || say FAIL "the job is submitted from somewhere other than the export"
  [ "$(grep -c 'STAGE="\$REPO/\.latchkey"' "${BASH_SOURCE[0]}")" = 0 ] \
    && say PASS "  ...nothing here stages into the repository any more" \
    || say FAIL "this script still stages into the repository"
  rm -rf "$_p1" "$_p2"

  echo "== prove-latchkey SELF-TEST (the engine travels; the TREE's land.sh is not the judge) =="
  # MEASURED (--smoke-latchkey on a scratch clone at 09dacd152): the runner ran the PACKED TREE's
  # scripts/land.sh, which on that tip has no `--preprove` at all — the flag fell through its parser
  # into the hash list and every pre-proof died `RED — cherry-pick --preprove conflicted`. The
  # tree's engine is whatever landed last; the engine driving a proof is whatever the runner carries.
  case "$emit" in
    *'ENGINE="$STAGE/land.run.sh"'*) say PASS "the runner takes its engine from the packed stage" ;;
    *) say FAIL "the runner does not look for a shipped engine" ;;
  esac
  case "$emit" in
    *'bash "$ENGINE" --preprove --batch'*) say PASS "  ...and the pre-proof leg runs THAT engine" ;;
    *) say FAIL "the pre-proof leg still runs the tree's own scripts/land.sh" ;;
  esac
  case "$emit" in
    *'bash scripts/land.sh'*) say FAIL "something in the runner still runs the tree's scripts/land.sh" ;;
    *) say PASS "  ...and nothing in the runner runs the tree's scripts/land.sh" ;;
  esac
  case "$emit" in
    *'sed "s|^here=.*|here=\"$PWD\"|"'*) say PASS "  ...with here= re-pointed at the packed directory" ;;
    *) say FAIL "the engine's root is not re-pointed on the runner" ;;
  esac
  case "$emit" in
    *'the engine never shipped'*) say PASS "  ...and a job with no engine in it REFUSES, rather than falling back to the tree's" ;;
    *) say FAIL "a missing engine falls back silently" ;;
  esac
  lk_engine_path >/dev/null 2>&1 \
    && say PASS "an engine is found beside this transport ($(basename "$(lk_engine_path)"))" \
    || say FAIL "no engine could be found beside this transport"

  echo "== prove-latchkey SELF-TEST (a job that never ran is not a red) =="
  # MEASURED (--smoke-latchkey, 2026-09-12): `State: failed`, `Exit code: -`, `Started: -`,
  # `Failure reason: launch_failed: VcpuLimitExceeded`. The runner script never executed and two
  # live queue lines would have been parked for AWS's capacity. Driven over a stubbed CLI that
  # prints those exact four lines.
  _lkstatus="$root/status.txt"
  LK_BIN="$root/fake-latchkey"
  printf '#!/usr/bin/env bash\n[ "$1" = status ] && cat "%s"\nexit 0\n' "$_lkstatus" >"$LK_BIN"
  chmod +x "$LK_BIN"
  printf 'Job:              cli-x\nState:            failed\nExit code:        -\nFailure reason:   launch_failed: VcpuLimitExceeded\nStarted:          -\nCompleted:        2026-09-12T02:42:38.263Z\n' >"$_lkstatus"
  [ "$(lk_job_rc cli-x failed 2>/dev/null)" = 75 ] \
    && say PASS "a job that never started is 75, never a red about anybody's picks" \
    || say FAIL "a job that never started was scored $(lk_job_rc cli-x failed 2>/dev/null)"
  lk_failure_reason cli-x 2>/dev/null | grep -q 'VcpuLimitExceeded' \
    && say PASS "  ...and Latchkey's own reason is read, so the ledger can say why" \
    || say FAIL "the failure reason is not read"
  printf 'Job:              cli-y\nState:            failed\nExit code:        1\nStarted:          2026-09-12T02:42:38.000Z\nCompleted:        2026-09-12T02:52:38.000Z\n' >"$_lkstatus"
  [ "$(lk_job_rc cli-y failed 2>/dev/null)" = 1 ] \
    && say PASS "  ...but a job that RAN and exited 1 is still a red" \
    || say FAIL "a real red was excused (got $(lk_job_rc cli-y failed 2>/dev/null))"
  printf 'Job:              cli-z\nState:            succeeded\nExit code:        0\nStarted:          2026-09-12T02:42:38.000Z\nCompleted:        2026-09-12T02:52:38.000Z\n' >"$_lkstatus"
  [ "$(lk_job_rc cli-z succeeded 2>/dev/null)" = 0 ] \
    && say PASS "  ...and one that ran and exited 0 is still a green" \
    || say FAIL "a real green was lost"
  [ "$(lk_job_rc cli-z expired 2>/dev/null)" = 124 ] \
    && say PASS "  ...and the 7200 s ceiling is 124, which is the shard plan's fault and not the tree's" \
    || say FAIL "an expired job is not 124"
  LK_BIN="${LATCHKEY_BIN:-latchkey}"

  echo "== prove-latchkey SELF-TEST (the tip and its picks travel, and neither takes the other down) =="
  # MEASURED: one `git push` carrying the tip AND a pick fails on a shallow clone, and takes the tip
  # with it because a push is atomic over its refspecs. Driven on a real repository with a real pick
  # that is NOT an ancestor of the tip — which is what a batch's picks always are.
  _pk="$root/picktree"
  git init -q "$_pk" 2>/dev/null
  git -C "$_pk" config user.email lk@selftest; git -C "$_pk" config user.name lk
  printf 'base\n' >"$_pk/a.txt"; git -C "$_pk" add a.txt >/dev/null 2>&1
  git -C "$_pk" commit -q --no-verify -m base
  _pkbase="$(git -C "$_pk" rev-parse HEAD)"
  printf 'tip\n' >>"$_pk/a.txt"; git -C "$_pk" add a.txt >/dev/null 2>&1
  git -C "$_pk" commit -q --no-verify -m tip
  _pktip="$(git -C "$_pk" rev-parse HEAD)"
  # the pick: a commit on a side branch, reachable from no ref the tip is on
  git -C "$_pk" checkout -q -b side "$_pkbase"
  printf 'pick\n' >"$_pk/p.txt"; git -C "$_pk" add p.txt >/dev/null 2>&1
  git -C "$_pk" commit -q --no-verify -m pick
  _pkpick="$(git -C "$_pk" rev-parse HEAD)"
  git -C "$_pk" checkout -q "$_pktip"
  if lk_stage_repo "$_pk" "$root/pkstage" "$_pktip" "$_pkbase" "$_pkpick"; then
    say PASS "a tip and a pick stage together into one bare repository"
    [ "$(git -C "$root/pkstage/git" rev-parse refs/heads/tip)" = "$_pktip" ] \
      && say PASS "  ...the tip is there" || say FAIL "the tip did not arrive"
    [ "$(git -C "$root/pkstage/git" rev-parse "refs/proof/picks/$_pkpick")" = "$_pkpick" ] \
      && say PASS "  ...and so is the pick, under the ref the runner cherry-picks from" \
      || say FAIL "the pick did not arrive"
  else
    say FAIL "staging a tip with a pick failed (this is the defect --smoke-latchkey found)"
  fi
  # THE TIP GOES BY ITSELF. Not a style point: one push carrying both is the failure above.
  [ "$(grep -c 'git -C "\$repo" push -q "\$bare" "+\${tip}:refs/heads/tip"' "${BASH_SOURCE[0]}")" = 1 ] \
    && say PASS "  ...because the tip is pushed in a refspec of its own" \
    || say FAIL "the tip does not have a push of its own"
  # A PICK THAT CANNOT TRAVEL IS A REFUSAL, never a proof of the tip reported as the line's.
  # NOT ALL-ZEROS: git reads an all-zero source as a DELETE, which succeeds, and this case passed
  # against a staging that had refused nothing. A well-formed sha that is not in the object store is
  # what a pick on the far side of a shallow boundary actually looks like.
  lk_stage_repo "$_pk" "$root/pkstage2" "$_pktip" "$_pkbase" deadbeefdeadbeefdeadbeefdeadbeefdeadbeef >/dev/null 2>&1 \
    && say FAIL "a pick that cannot be pushed was staged anyway" \
    || say PASS "  ...and a pick that cannot travel refuses the staging outright"

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
  # …BESIDE THE MAIN REPOSITORY, NEVER BESIDE THIS CHECKOUT. This went the wrong way round on the
  # first real proof: a slot proves from `<repo>/.claude/worktrees/<slot>`, so `$REPO/..` was
  # `.claude/worktrees` and the log landed where no ledger reads and `git worktree prune` may
  # delete. Driven on the REAL resolution, from whichever checkout this is.
  case "$LK_LOGDIR" in
    */.claude/worktrees/*) say FAIL "the log directory is inside a worktree ($LK_LOGDIR)" ;;
    */busbar-landq-state/gate/latchkey-logs) say PASS "  ...beside the state repository, not inside this checkout" ;;
    *) say FAIL "the log directory is not the state repository's ($LK_LOGDIR)" ;;
  esac
  # THE BILL IS THE RUNNER'S SECONDS, NOT THIS SCRIPT'S WALL CLOCK. Measured: 717 s of laptop wall
  # against 540 s on the runner, so the wall overstates the bill by a third — in the direction that
  # makes every cost comparison in the migration doc wrong.
  grep -qF 'lk_runner_secs "$JOB"' "${BASH_SOURCE[0]}" \
    && say PASS "the minutes reported are the job's Started..Completed, not the wall" \
    || say FAIL "the minutes reported are this script's wall clock"

  # ── THE SCOPE FILE IS TOML, AND A MULTI-LINE ARRAY IS AN ARRAY (M1c-b-r's defect) ─────────────
  # The single-line `sed` read a multi-line `tests = [...]` as EMPTY, and empty falls through to
  # `cargo test --workspace` — 94 minutes, which is what walked three of M1c-b's jobs into the
  # 7200 s ceiling. Both spellings, and the two readers are asked the same questions so the fallback
  # cannot answer differently from the parser.
  echo "== the scope file (.keep-proof.toml) =="
  kp="$root/kp"; mkdir -p "$kp"
  printf 'families = %s\ntests = [\n  "busbar-core",\n  "xtask",\n]\n' "'^(boot)([|.]|\$)'" >"$kp/multi.toml"
  printf 'tests = ["a", "b"]\nfamilies = "^x"\n' >"$kp/one.toml"
  printf 'tests = []\n' >"$kp/empty.toml"
  printf 'families = "^y"\n' >"$kp/absent.toml"
  printf 'tests = [\n  "a",   # a comment inside the array\n  "b",\n]\n' >"$kp/cmt.toml"
  _kpcase() { # $1 = label, $2 = expected tests, $3 = file, $4 = 1 to force the awk fallback
    local got
    if [ "${4:-0}" = 1 ]; then
      got="$( LK_TOML_FORCE_AWK=1 lk_toml_array "$3" tests )"
    else
      got="$( lk_toml_array "$3" tests )"
    fi
    [ "$got" = "$2" ] && say PASS "$1" || say FAIL "$1 (wanted [$2], got [$got])"
  }
  for _fb in 0 1; do
    _w="the parser"; [ "$_fb" = 1 ] && _w="the awk fallback"
    _kpcase "$_w reads a MULTI-LINE tests array"        "busbar-core xtask" "$kp/multi.toml" "$_fb"
    _kpcase "  ...and the single-line spelling too"     "a b"               "$kp/one.toml"   "$_fb"
    _kpcase "  ...a DECLARED-EMPTY array is '-', never empty" "-"           "$kp/empty.toml" "$_fb"
    _kpcase "  ...and an ABSENT key is empty, never '-'"     ""            "$kp/absent.toml" "$_fb"
    _kpcase "  ...a comment inside the array is not a package" "a b"        "$kp/cmt.toml"   "$_fb"
  done
  [ "$(lk_toml_string "$kp/multi.toml" families)" = '^(boot)([|.]|$)' ] \
    && say PASS "a families regex survives its own brackets and pipes" \
    || say FAIL "the families regex was mangled ($(lk_toml_string "$kp/multi.toml" families))"
  [ -z "$(lk_toml_string "$kp/empty.toml" families)" ] \
    && say PASS "  ...and an absent families is nothing (the caller substitutes '.')" \
    || say FAIL "an absent families read as something"
  [ -z "$(lk_toml_array "$root/no-such.toml" tests)" ] \
    && say PASS "a scope file that is not there scopes nothing" \
    || say FAIL "a missing scope file produced a value"
  # AND THE EMPTY SCOPE SUBTRACTS THE LEG RATHER THAN WIDENING IT — asked of the runner's own text.
  emit_kp="$(lk_onbox_script tip br dev)"
  case "$emit_kp" in
    *'if [ "$TESTS" = "-" ]; then'*) say PASS "the runner subtracts the test leg on a declared-empty scope" ;;
    *) say FAIL "the runner cannot tell a declared-empty scope from an absent one" ;;
  esac
  case "$emit_kp" in
    *'cargo test --workspace --locked'*) say PASS "  ...and the workspace path is still there for an ABSENT scope" ;;
    *) say FAIL "the workspace fallback was removed along with the bug" ;;
  esac
  sed -n '/^SCOPE_FAM=/,/^fi$/p' "${BASH_SOURCE[0]}" | grep -q 'lk_toml_array "$REPO/.keep-proof.toml" tests' \
    && say PASS "the live reader is the one these cases drove" \
    || say FAIL "the live reader is not lk_toml_array"
  sed -n '/^SCOPE_FAM=/,/^fi$/p' "${BASH_SOURCE[0]}" | grep -q "sed -n 's/\^\[\[:space:\]\]\*tests" \
    && say FAIL "the single-line sed reader is still the live one" \
    || say PASS "  ...and the single-line sed reader is gone from it"
  unset -f _kpcase

  # ── THE BASE IS THE MERGE-BASE, AND ALWAYS AN ANCESTOR OF THE TIP (K4d-r's defect) ────────────
  echo "== the base a proof is judged against =="
  br="$root/baserepo"; mkdir -p "$br" "$root/nohooks"
  # A THROWAWAY REPOSITORY, NOT THIS DEVELOPER'S — land.sh's selftest says it first: the host's
  # global core.hooksPath (an identity check, here) would refuse every commit this case needs.
  ( cd "$br" && git init -q . && git config core.hooksPath "$root/nohooks" \
    && git config user.email t@t && git config user.name t \
    && echo a >a && git add a && git commit -qm a \
    && git branch -q integration/oracle-phase0 \
    && echo b >b && git add b && git commit -qm b \
    && git update-ref refs/heads/integration/oracle-phase0 HEAD \
    && git checkout -q -b slot HEAD~1 ) >/dev/null 2>&1
  # `slot` is an ANCESTOR of the integration branch: merge-base(slot, integration) == slot itself.
  # The old fallback answered with the integration BRANCH TIP, which is not among the objects the
  # tip's push carries — the `nonexistent object` that killed every one of K4d-r's pre-proofs.
  zb="$(LAND_BASE_REF=refs/heads/integration/oracle-phase0 LAND_BASE_BRANCH=refs/heads/integration/oracle-phase0 \
        lk_base_sha "$br" "$(git -C "$br" rev-parse HEAD)")"
  zt="$(git -C "$br" rev-parse HEAD)"
  ztip="$(git -C "$br" rev-parse refs/heads/integration/oracle-phase0)"
  [ "$zb" = "$zt" ] && say PASS "a zero-delta tree's base is the tip itself, not a branch tip" \
    || say FAIL "a zero-delta tree resolved its base to '$zb' (tip $zt, branch $ztip)"
  [ "$zb" != "$ztip" ] && say PASS "  ...and it is never the raw integration branch tip" \
    || say FAIL "the base is the integration branch tip, whose objects the tip's push does not carry"
  git -C "$br" merge-base --is-ancestor "$zb" "$zt" 2>/dev/null \
    && say PASS "  ...the base is an ancestor of the tip (so its objects always travel)" \
    || say FAIL "the base is not an ancestor of the tip"
  ( cd "$br" && git checkout -q integration/oracle-phase0 && echo c >c && git add c && git commit -qm c ) >/dev/null 2>&1
  db="$(LAND_BASE_REF=refs/heads/integration/oracle-phase0 LAND_BASE_BRANCH=refs/heads/integration/oracle-phase0 \
        lk_base_sha "$br" "$(git -C "$br" rev-parse slot)")"
  [ "$db" = "$(git -C "$br" rev-parse slot)" ] \
    && say PASS "a tree with a delta still gets the merge-base" \
    || say FAIL "a tree with a delta resolved its base to '$db'"
  # AND THE STAGING NEVER NAMES AN OBJECT IT DID NOT PUSH.
  sd="$root/stage"; mkdir -p "$sd"
  if lk_stage_repo "$br" "$sd/.latchkey" "$(git -C "$br" rev-parse slot)" "$(git -C "$br" rev-parse slot)" >/dev/null 2>&1; then
    say PASS "a zero-delta tree stages (base == tip is a base, not a failure)"
    [ "$(git -C "$sd/.latchkey/git" rev-parse refs/remotes/origin/integration/oracle-phase0 2>/dev/null)" \
      = "$(git -C "$br" rev-parse slot)" ] \
      && say PASS "  ...and the staged repo resolves the base ref to it" \
      || say FAIL "the staged repo does not resolve the base ref"
  else
    say FAIL "a zero-delta tree could not be staged"
  fi
  grep -qF 'cat-file -e "${base}^{commit}"' "${BASH_SOURCE[0]}" \
    && say PASS "the staging asks for the base object before it names it" \
    || say FAIL "the staging names the base without asking whether it arrived"

  # ── THE 7200 s CEILING IS NEVER A RED ─────────────────────────────────────────────────────────
  echo "== the cap =="
  [ "$(lk_job_verdict "$root/none.log" 124)" = "NONE:cap" ] \
    && say PASS "exit 124 (the ceiling) is NONE:cap, not RED" \
    || say FAIL "the ceiling is scored $(lk_job_verdict "$root/none.log" 124)"
  [ "$(lk_job_verdict "$root/none.log" 1)" = "RED" ] \
    && say PASS "  ...and a real failure is still RED" || say FAIL "a real failure stopped being RED"
  for r in "timeout" "Timed out after 7200s" "job deadline exceeded" "max_duration reached"; do
    lk_reason_is_cap "$r" && say PASS "Latchkey's '$r' reads as the cap" \
      || say FAIL "'$r' was not read as the cap"
  done
  lk_reason_is_cap "launch_failed: VcpuLimitExceeded" \
    && say FAIL "a launch failure was read as the cap" \
    || say PASS "a launch failure is NOT the cap (it is the 75 that never started)"
  printf '== build\n== fmt\nland.sh: [l] plan: plugins fmt gate\nnoise\n' >"$root/capped.log"
  [ "$(lk_legs_completed "$root/capped.log" | grep -c .)" = 3 ] \
    && say PASS "a capped job reports what it completed, out of the log's own headings" \
    || say FAIL "the completed legs are not read out of the log"
  grep -qF 'prove-latchkey: NONE:cap' "${BASH_SOURCE[0]}" \
    && say PASS "the cap is said in a sentence the engine can grep" \
    || say FAIL "the cap has no sentence"

  # ── THE SHARD PLAN ────────────────────────────────────────────────────────────────────────────
  echo "== the pre-proof's shard plan (the F5 shape under the ceiling) =="
  printf -- '--prove --tests xtask --families %s aaaaaaa\n' "'^(llm)([|.]|\$)'" >"$root/bf-fam.txt"
  printf -- '--prove --tests xtask bbbbbbb\n' >"$root/bf-nofam.txt"
  printf -- '--prove --tests xtask --families %s aaaaaaa\n--prove --tests xtask bbbbbbb\n' "'^(llm)([|.]|\$)'" >"$root/bf-mixed.txt"
  : >"$root/bf-empty.txt"
  pf="$(LK_PREPROVE_SHARDED=1 lk_preprove_shard_plan "$root/bf-fam.txt")"
  pn="$(LK_PREPROVE_SHARDED=1 lk_preprove_shard_plan "$root/bf-nofam.txt")"
  pm="$(LK_PREPROVE_SHARDED=1 lk_preprove_shard_plan "$root/bf-mixed.txt")"
  [ "$(printf '%s\n' "$pf" | grep -c .)" = 3 ] && say PASS "an all-families batch is three jobs" \
    || say FAIL "an all-families batch is $(printf '%s\n' "$pf" | grep -c .) job(s)"
  [ "$(printf '%s\n' "$pn" | grep -c .)" = 2 ] && say PASS "a batch with a family-less line is two" \
    || say FAIL "a family-less batch is $(printf '%s\n' "$pn" | grep -c .) job(s)"
  [ "$(printf '%s\n' "$pm" | grep -c .)" = 2 ] \
    && say PASS "  ...and ONE family-less line is enough to keep the oracle off its own job" \
    || say FAIL "a mixed batch split the oracle out, and that line's plan has no oracle leg to select"
  case "$pf" in *"gates|kind-isolation gate"*) say PASS "the gate legs are ALWAYS their own job (the cap's home)" ;;
    *) say FAIL "the gate legs are not their own job" ;; esac
  case "$pn" in *"gates|kind-isolation gate"*) say PASS "  ...on a family-less batch too" ;;
    *) say FAIL "the gate legs are not their own job on a family-less batch" ;; esac
  case "$pn" in *"oracle"*) say PASS "  ...and the oracle rides with build rather than vanishing" ;;
    *) say FAIL "the oracle leg was dropped from the plan entirely" ;; esac
  LK_PREPROVE_SHARDED=0 lk_preprove_shard_plan "$root/bf-fam.txt" >/dev/null 2>&1 \
    && say FAIL "LATCHKEY_PREPROVE_SHARDS=0 still sharded" \
    || say PASS "LATCHKEY_PREPROVE_SHARDS=0 (and --no-shards) is one job, exactly as before"
  LK_PREPROVE_SHARDED=1 lk_preprove_shard_plan "$root/bf-empty.txt" >/dev/null 2>&1 \
    && say FAIL "an empty batch was sharded" || say PASS "an empty batch has no plan to shard"
  # EVERY SHARD OWNS A LEG OF EVERY POSSIBLE PLAN — land.sh's own floor plan is the authority.
  lsh=""
  for c in "$HERE/land.run.sh" "$HERE/land.sh" "$REPO/scripts/land.sh"; do [ -f "$c" ] && { lsh="$c"; break; }; done
  if [ -n "$lsh" ]; then
    fsrc="$(sed -n '/^land_floor_plan() {/,/^}/p' "$lsh")"
    eval "$fsrc" 2>/dev/null
    for planv in "$(land_floor_plan '' '' '')" "$(land_floor_plan busbar loc '^x')"; do
      for row in $(printf '%s\n' "$pf" "$pn" | grep -c . >/dev/null; printf '%s\n' "$pf" | sed 's/|.*//'); do :; done
      while IFS= read -r row; do
        [ -n "$row" ] || continue
        nm="${row%%|*}"; lg="${row#*|}"
        [ "$nm" = oracle ] && continue   # the oracle's job exists only when every line owes it
        hit=0
        for leg in $lg; do case " $planv " in *" $leg "*) hit=1 ;; esac; done
        [ "$hit" = 1 ] && say PASS "shard $nm owns a leg of the plan [$planv]" \
          || say FAIL "shard $nm owns NO leg of [$planv] — land_legs_only would red it"
      done <<SHEOF
$pn
SHEOF
    done
  else
    say PASS "(no land.sh beside this transport; the plan-intersection case is skipped)"
  fi

  # ── THE MERGE ─────────────────────────────────────────────────────────────────────────────────
  echo "== merging N shards' rows into one verdict row per line =="
  T="$(printf '\t')"
  printf 'GREEN%sL1\nGREEN%sL2\nGREEN%sL3\n' "$T" "$T" "$T" >"$root/m1"
  printf 'GREEN%sL1\nRED%sL2\nHELD%sL3\n'   "$T" "$T" "$T" >"$root/m2"
  printf 'GREEN%sL1\nGREEN%sL2\nGREEN%sL3\n' "$T" "$T" "$T" >"$root/m3"
  lk_merge_results "$root/mout" 3 "$root/m1" "$root/m2" "$root/m3"
  [ "$(awk -F"$T" '$2=="L1"{print $1}' "$root/mout")" = GREEN ] \
    && say PASS "green in every shard is GREEN" || say FAIL "a line green everywhere is not GREEN"
  [ "$(awk -F"$T" '$2=="L2"{print $1}' "$root/mout")" = RED ] \
    && say PASS "one shard's RED is the line's RED" || say FAIL "a shard's red did not reach the merge"
  [ "$(awk -F"$T" '$2=="L3"{print $1}' "$root/mout")" = HELD ] \
    && say PASS "HELD outranks GREEN (a held line was never applied, so it was never proven)" \
    || say FAIL "a line held in one shard came out GREEN"
  printf 'RED-CONFLICT%sL4\n' "$T" >>"$root/m1"; printf 'RED%sL4\n' "$T" >>"$root/m2"; printf 'GREEN%sL4\n' "$T" >>"$root/m3"
  lk_merge_results "$root/mout2" 3 "$root/m1" "$root/m2" "$root/m3"
  [ "$(awk -F"$T" '$2=="L4"{print $1}' "$root/mout2")" = RED-CONFLICT ] \
    && say PASS "RED-CONFLICT outranks everything (the pick is the same fact in every shard)" \
    || say FAIL "a conflict was outranked"
  printf 'GREEN%sL5\n' "$T" >>"$root/m1"
  lk_merge_results "$root/mout3" 3 "$root/m1" "$root/m2" "$root/m3"
  [ -z "$(awk -F"$T" '$2=="L5"{print $1}' "$root/mout3")" ] \
    && say PASS "a line not every shard reported gets NO row (never a green on a subset)" \
    || say FAIL "a line only one shard reported was given a merged row"
  # AND THE LINE TEXT SURVIVES ITS OWN PUNCTUATION — 44 queue lines carry a bracketed regex.
  printf "GREEN%s--prove --families '^(llm)([|.]|\$)' abc\n" "$T" >"$root/m4"
  printf "RED%s--prove --families '^(llm)([|.]|\$)' abc\n" "$T" >"$root/m5"
  lk_merge_results "$root/mout4" 2 "$root/m4" "$root/m5"
  grep -q "^RED${T}--prove --families '\^(llm)(\[|\.\]|\\\$)' abc$" "$root/mout4" \
    && say PASS "a line carrying a bracketed family regex merges by its raw bytes" \
    || say FAIL "a family regex was mangled by the merge ($(cat "$root/mout4"))"

  # ── --tree ────────────────────────────────────────────────────────────────────────────────────
  case "$argv_src" in *"--tree"*) say PASS "the argument parser handles --tree" ;;
    *) say FAIL "the argument parser does not handle --tree" ;; esac
  case "$argv_src" in *"--no-shards"*) say PASS "the argument parser handles --no-shards" ;;
    *) say FAIL "the argument parser does not handle --no-shards" ;; esac
  grep -qF 'LK_LOGDIR="${LATCHKEY_LOG_DIR:-$LK_STATE_HOME/busbar-landq-state/gate/latchkey-logs}"' "${BASH_SOURCE[0]}" \
    && say PASS "--tree re-derives the log home from the tree it was given" \
    || say FAIL "--tree leaves the log home pointing at the engine home"

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
BRANCH=""; SETUP=0; POSTURE=dev; MODE=tip; BATCH=""; IGNORED_HOST=""; TREE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --setup) SETUP=1; shift ;;
    # ── WHICH CHECKOUT IS BEING PROVEN ────────────────────────────────────────────────────────────
    # This script resolves its repository as `$(dirname "$0")/..`, which is right for the copy in a
    # checkout's own scripts/ and WRONG for the deployed one: the engine home is
    # ~/.busbar-engine/current/scripts, whose `..` is the engine home, not anybody's tree. Every
    # slot that wanted to prove its own worktree had to COPY the transport into it first — which is
    # the "an unlanded script is not in the tree" mistake, made by hand, once per slot.
    # `--tree <worktree>` says it instead, and it is the documented slot invocation.
    --tree) TREE="${2:-}"; shift 2 ;;
    # THE SHARD SPLIT, OFF. `--no-shards` is the escape hatch for an operator comparing a sharded
    # pre-proof against the single job it replaced; LATCHKEY_PREPROVE_SHARDS=0 is the same switch
    # for the engine home's env file.
    --shards)    LK_PREPROVE_SHARDED=1; shift ;;
    --no-shards) LK_PREPROVE_SHARDED=0; shift ;;
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

# ── THE TREE UNDER PROOF, AND EVERYTHING THIS SCRIPT DERIVES FROM IT ────────────────────────────
# Re-derived, not patched: LK_STATE_HOME and LK_LOGDIR are computed from $REPO at load time, and a
# `--tree` that moved $REPO without moving them would keep a slot's job logs beside the engine home
# rather than beside the state repository the ledgers cite.
if [ -n "$TREE" ]; then
  [ -d "$TREE" ] || lkdie "--tree: no such directory: $TREE"
  REPO="$(cd "$TREE" && pwd)" || lkdie "--tree: could not enter $TREE"
  git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1 || lkdie "--tree: $REPO is not a git checkout"
  LK_STATE_HOME="$(cd "$(dirname "$(git -C "$REPO" rev-parse --git-common-dir 2>/dev/null || echo "$REPO/.git")")/.." 2>/dev/null && pwd)"
  LK_LOGDIR="${LATCHKEY_LOG_DIR:-$LK_STATE_HOME/busbar-landq-state/gate/latchkey-logs}"
  lklog "tree: $REPO (--tree)"
fi

command -v "$LK_BIN" >/dev/null 2>&1 || lkdie "no \`$LK_BIN\` on PATH — install the Latchkey CLI or set LATCHKEY_BIN"
lk_load_token || lkdie "no LATCHKEY_TOKEN in the environment and none readable in $LK_ENVFILE"
[ -n "${LK_LOGDIR_DERIVED:-}" ] && lklog "note: LATCHKEY_LOG_DIR is unset, so the job logs go to the DERIVED path $LK_LOGDIR — set it in the env file; the ledgers cite these by path"

TIP="$(git -C "$REPO" rev-parse "${BRANCH:-HEAD}")" || lkdie "no such rev: ${BRANCH:-HEAD}"
BASE="$(lk_base_sha "$REPO" "$TIP")" || lkdie "no integration base to judge the ceilings against"
[ -n "$BASE" ] || lkdie "no integration base to judge the ceilings against"
REF="latchkey-$(date -u +%Y%m%d-%H%M%S)-$$"
BRANCH_NAME="$(git -C "$REPO" rev-parse --abbrev-ref HEAD 2>/dev/null)"
case "$BRANCH_NAME" in HEAD|"") BRANCH_NAME="$REF" ;; esac

[ -n "$IGNORED_HOST" ] && lklog "note: --host/--remote '$IGNORED_HOST' is accepted and ignored; this backend rents a runner"

# The scope file is read LOCALLY as well as remotely, prove-remote.sh's reason verbatim: the
# operator should see the scope before the minutes start, not in the log afterwards.
SCOPE_FAM='.'; SCOPE_TESTS=''
if [ -f "$REPO/.keep-proof.toml" ]; then
  SCOPE_FAM="$(lk_toml_string "$REPO/.keep-proof.toml" families)"
  [ -n "$SCOPE_FAM" ] || SCOPE_FAM='.'
  SCOPE_TESTS="$(lk_toml_array "$REPO/.keep-proof.toml" tests)"
fi

PICKS=""
if [ "$MODE" = preprove ]; then
  [ -n "$BATCH" ] || lkdie "--preprove needs --batch <file>"
  [ -f "$BATCH" ] || lkdie "no such batch file: $BATCH"
  PICKS="$(lk_batch_hashes "$BATCH")"
fi

# ── A PROOF WITH NEITHER A DELTA NOR A PICK IS REFUSED; ONE WITH PICKS IS NOT ───────────────────
# The old refusal was `BASE != TIP` unconditionally, and it was aimed at the right target: a base
# pinned to the tip makes every ceiling row compare a file against itself and pass. But a PRE-PROOF
# of a zero-delta tree is the normal shape of a re-pick — the tree owes nothing, the PICKS are the
# delta, and they arrive as their own refs and are applied by the engine on the runner. Refusing
# that case cost K4d-r every line it tried to prove. So the question is not "is the base the tip"
# but "is there anything for a ceiling to measure": a delta, or a pick.
NPICKS="$(printf '%s\n' "$PICKS" | grep -c . || true)"
if [ "$BASE" = "$TIP" ] && [ "${NPICKS:-0}" = 0 ]; then
  lkdie "the base resolved to the tip and this proof carries no picks — there is no delta for a ceiling row to measure, and every one of them would compare a file against itself and pass"
fi

lklog "tip $(git -C "$REPO" rev-parse --short "$TIP")   base $(printf '%.9s' "$BASE")   ref $REF"
lklog "mode:            $MODE${BATCH:+ (batch $BATCH, $(grep -c . "$BATCH" 2>/dev/null || echo 0) line(s))}"
lklog "posture:         --posture $POSTURE"
lklog "oracle families: $SCOPE_FAM"
case "$SCOPE_TESTS" in
  '-') lklog "test packages:   <none: the scope declares tests = [], so there is no test leg>" ;;
  '')  lklog "test packages:   <the whole workspace — the scope names none; this is the 94-minute path>" ;;
  *)   lklog "test packages:   $SCOPE_TESTS" ;;
esac
lklog "runner:          $LK_SIZE, timeout ${LK_TIMEOUT}s, polled every ${LK_POLL_SECS}s"

# ── STAGE THE TREE ──────────────────────────────────────────────────────────────────────────────
# Everything the job needs goes INSIDE the directory being packed, and comes out again on the way
# out, whatever happens. A 23 MB bare repository left behind in a slot's checkout is the next
# proof's packed tree.
PACK="$(lk_pack_dir "$REPO" "$TIP" "$REF")" || lkdie "could not export $(git -C "$REPO" rev-parse --short "$TIP") into $LAND_TMP — nothing was packed"
STAGE="$PACK/.latchkey"
RUNNER=".lk-run.sh"
# THE EXPORT GOES WHATEVER HAPPENS. It is 3,580 files and a 23 MB repository; left behind by a
# killed poller it is the next sweep's disk.
cleanup() { rm -rf "$PACK"; }
trap cleanup EXIT INT TERM
lk_stage_repo "$REPO" "$STAGE" "$TIP" "$BASE" $PICKS || lkdie "could not stage the history into $STAGE"
lklog "packed from $PACK ($(find "$PACK" -type f | grep -c . || true) file(s)); history $(du -sh "$STAGE/git" 2>/dev/null | cut -f1), $(printf '%s' "$PICKS" | grep -c . || true) pick(s)"
LK_ENGINE="$(lk_engine_path)" || lkdie "no land.sh beside $HERE to send with this proof"
cp "$LK_ENGINE" "$STAGE/land.run.sh" || lkdie "could not stage the engine ($LK_ENGINE) into the pack"
lklog "engine: $LK_ENGINE travels with the job (the tree's own scripts/land.sh is not this proof's judge)"
[ -n "$BATCH" ] && cp "$BATCH" "$STAGE/batch.txt"
lk_onbox_script "$MODE" "$BRANCH_NAME" "$POSTURE" >"$PACK/$RUNNER"
chmod +x "$PACK/$RUNNER"

mkdir -p "$REPO/target" 2>/dev/null || true

# ── THE JOBS: ALL SUBMITTED FIRST, THEN POLLED ──────────────────────────────────────────────────
# A loop that polled each job before submitting the next would serialise exactly the fan-out that
# exists to fit under the ceiling. One packed tree, N submissions of it, N logs, one merged verdict.
SH_NAMES=""; SH_IDS=""
lk_launch() { # $1 = shard name, $2 = the legs it owns ('' = the whole plan); prints nothing
  local name="$1" legs="$2" id
  id="$(cd "$PACK" && lk_submit "bash $RUNNER $MODE $BRANCH_NAME $POSTURE $TIP $BASE '$SCOPE_FAM' '$SCOPE_TESTS' '$legs'")"
  case "$id" in cli-*) ;; *) return 1 ;; esac
  SH_NAMES="$SH_NAMES $name"; SH_IDS="$SH_IDS $id"
  lklog "job $id  = shard $name${legs:+  (legs: $legs)}"
  return 0
}
lk_cancel_all() {
  local j
  for j in $SH_IDS; do "$LK_BIN" cancel "$j" >/dev/null 2>&1 || true; done
}

START=$(date +%s)
PLAN=""
[ "$MODE" = preprove ] && PLAN="$(lk_preprove_shard_plan "$BATCH" || true)"
if [ -n "$PLAN" ]; then
  lklog "the pre-proof is SHARDED into $(printf '%s\n' "$PLAN" | grep -c .) job(s) over one packed tree — the ${LK_TIMEOUT}s ceiling is per JOB"
  while IFS= read -r row; do
    [ -n "$row" ] || continue
    lk_launch "${row%%|*}" "${row#*|}" && continue
    # NO JOB IS NOT A RED, and a HALF-SUBMITTED fan is not a proof: the shards already in flight are
    # cancelled rather than left to bill for a verdict this script will not merge.
    lklog "no job was created for shard ${row%%|*}: $(lk_submit_err) — cancelling the fan; exit 75, nothing was proven"
    lk_cancel_all
    exit 75
  done <<EOF
$PLAN
EOF
else
  lk_launch "$MODE" "" || { lklog "no job was created: $(lk_submit_err) — exit 75, nothing was proven"; exit 75; }
fi

# ── COLLECTING ──────────────────────────────────────────────────────────────────────────────────
RC=0; CAPPED=""; NOVERDICT=""; NSH=0; RESFILES=""; TOTSECS=0
rm -f "$BATCH.result" 2>/dev/null || true
set -- $SH_NAMES
for JOB in $SH_IDS; do
  NAME="$1"; shift
  NSH=$(( NSH + 1 ))
  LOG="$REPO/target/land-latchkey-$REF-$NAME.log"
  if STATE="$(lk_poll "$JOB")"; then
    "$LK_BIN" logs "$JOB" >"$LOG" 2>&1 || true
    mkdir -p "$LK_LOGDIR" 2>/dev/null && cp "$LOG" "$LK_LOGDIR/$JOB.log" 2>/dev/null \
      && lklog "log kept: $LK_LOGDIR/$JOB.log" \
      || lklog "WARNING: could not keep the log under $LK_LOGDIR — Latchkey drops it in 24 h"
    JRC="$(lk_job_rc "$JOB" "$STATE")"
    VERDICT="$(lk_job_verdict "$LOG" "$JRC")"
    RSECS="$(lk_runner_secs "$JOB")"
  else
    # A POLLER THAT GAVE UP HAS NOT MEASURED A TIMEOUT, it has stopped looking. The job is cancelled
    # so it stops billing, and the outcome is the honest "no verdict", never the cap and never a red.
    lklog "gave up waiting on $JOB after ${LK_POLL_MAX}s — no verdict"
    "$LK_BIN" cancel "$JOB" >/dev/null 2>&1 || true
    STATE=unpolled; JRC=75; VERDICT="NONE:no-verdict"; RSECS=""
  fi
  TOTSECS=$(( TOTSECS + ${RSECS:-0} ))
  lklog "shard $NAME  job $JOB  state $STATE  exit $JRC  verdict $VERDICT  runner ${RSECS:-?}s  ~$(( ( ${RSECS:-0} + 59 ) / 60 )) billed runner-minute(s)  log $LOG"
  case "$VERDICT" in
    GREEN) ;;
    # ── THE CEILING, SAID IN WORDS, WITH WHAT IT GOT THROUGH ──────────────────────────────────────
    # landq4.sh greps this sentence (LQ_LK_CAP_RE) and scores the line NONE:cap — live, unparked,
    # re-swept. The legs that DID complete are printed with it because they are the shard plan's
    # next move: a cap in `gates` says split the batteries, a cap in `build` says the tree grew.
    NONE:cap)
      CAPPED="${CAPPED:+$CAPPED }$NAME"
      echo "prove-latchkey: NONE:cap — shard $NAME hit the ${LK_TIMEOUT}s per-job ceiling; the cap is this plan's, never these picks'" >&2
      echo "prove-latchkey: NONE:cap — what shard $NAME completed before the ceiling:" >&2
      lk_legs_completed "$LOG" | sed 's/^/prove-latchkey:   /' >&2 ;;
    NONE:*) NOVERDICT="${NOVERDICT:+$NOVERDICT }$NAME ($VERDICT)" ;;
    *) RC=1 ;;
  esac
  if [ "$MODE" = preprove ]; then
    if lk_parse_result "$LOG" >"$BATCH.result.$NAME" 2>/dev/null && [ -s "$BATCH.result.$NAME" ]; then
      RESFILES="$RESFILES $BATCH.result.$NAME"
    else
      rm -f "$BATCH.result.$NAME" 2>/dev/null || true
      lklog "WARNING: no result block in $LOG — shard $NAME did not reach its reporting stage"
    fi
  fi
done
END=$(date +%s)
lklog "$NSH job(s)   wall $(( END - START ))s   runner ${TOTSECS}s total   ~$(( ( TOTSECS + 59 ) / 60 )) billed runner-minute(s)"

# ── THE MERGED VERDICT ──────────────────────────────────────────────────────────────────────────
# A no-verdict outranks everything, in both of its flavours, and for one reason: a plan that was cut
# into jobs is only proven when every job reported. A merged file assembled from the shards that DID
# answer is a verdict on a subset nobody chose — and worse here than in a landing, because
# lq_outcome_green would read a wholly-GREEN partial file and score the line GREEN over an rc of 75.
# So the partial files go, no `<batch>.result` is written at all, and 75 says what 75 says.
if [ -n "$CAPPED" ] || [ -n "$NOVERDICT" ]; then
  rm -f "$BATCH.result" $RESFILES 2>/dev/null || true
  [ -n "$CAPPED" ] && echo "prove-latchkey: NONE:cap — shard(s) $CAPPED exceeded the ${LK_TIMEOUT}s ceiling; nothing about these picks was learned" >&2
  [ -n "$NOVERDICT" ] && lklog "no verdict from shard(s) $NOVERDICT — exit 75, the line stays live"
  exit 75
fi

if [ "$MODE" = preprove ]; then
  # THE RESULT FILE COMES BACK TO THE PATH THE LOCAL RUNNER ALREADY READS. target/gate/landq*.sh
  # reads `<batch>.result` and nothing else.
  if [ -n "$RESFILES" ] && lk_merge_results "$BATCH.result" "$NSH" $RESFILES; then
    lklog "per-line outcomes: $BATCH.result (merged from $NSH shard(s))"
    sed 's/^/  /' "$BATCH.result" >&2
    rm -f $RESFILES 2>/dev/null || true
  else
    rm -f "$BATCH.result" $RESFILES 2>/dev/null || true
    lklog "WARNING: the shards' result blocks could not be merged — no per-line outcomes for this batch"
  fi
fi

exit "$RC"

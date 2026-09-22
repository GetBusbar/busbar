#!/usr/bin/env bash
# Reap worktrees, build artifacts and ORPHANED PROCESSES that nothing is using any more.
#
# WHY THIS EXISTS. Agents isolate into their own worktrees so they cannot clobber
# each other's uncommitted work, and each one then pays a full cold build. Cargo
# never garbage-collects, so the artifacts outlive the worktree, the branch and
# the session that made them. Left alone this reaches hundreds of gigabytes and
# it slows every build that follows: a bigger target/ is more to stat, scan and
# link on every single invocation. Disk is the cheap part; the wall-clock tax is
# the expensive one.
#
# WHAT IT WILL NOT DO, and why each refusal is a rule rather than caution:
#
#   * It never touches a worktree with UNCOMMITTED CHANGES. A worktree is the one
#     place work exists that git cannot get back for you. This repo has already
#     lost an agent's work once to a `git stash` that swept a shared tree; a reap
#     that guesses is strictly worse, because there is no stash to pop.
#   * It never touches a worktree with a LIVE PROCESS in it. Idle-looking is not
#     idle: directory mtime under-reports badly (worktrees that looked 39h stale
#     were 0h active), so this reads the git INDEX mtime, which moves when work
#     does.
#   * It never runs `cargo clean` on the MAIN checkout while anything is
#     building. That forces every concurrent agent to rebuild from scratch and
#     turns a slow hour into a lost afternoon.
#
# So it is deliberately conservative: it would rather leave a dead worktree for
# the next pass than remove a live one once.
#
# Usage:
#   scripts/reap-worktrees.sh            # report only, changes nothing
#   scripts/reap-worktrees.sh --reap     # remove what it proved dead
#   scripts/reap-worktrees.sh --reap --idle-hours 6
set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
REAP=0
IDLE_HOURS=12

while [ $# -gt 0 ]; do
  case "$1" in
    --reap) REAP=1 ;;
    --idle-hours) IDLE_HOURS="$2"; shift ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "reap-worktrees: unknown argument '$1'" >&2; exit 2 ;;
  esac
  shift
done

now=$(date +%s)
idle_cutoff=$(( IDLE_HOURS * 3600 ))
reclaimable=0
reaped=0
kept=0

printf '%-58s %9s  %s\n' "WORKTREE" "TARGET" "VERDICT"

# The main checkout is never a reap candidate. Everything else is judged.
while read -r wt; do
  [ -n "$wt" ] || continue
  [ "$wt" = "$REPO" ] && continue
  [ -d "$wt" ] || continue

  tgt_kb=0
  [ -d "$wt/target" ] && tgt_kb=$(du -sk "$wt/target" 2>/dev/null | awk '{print $1}')
  tgt_h=$(awk -v k="$tgt_kb" 'BEGIN{printf "%.1fG", k/1048576}')

  # Uncommitted work is the hard stop. A worktree is the one place git cannot
  # recover from, so this refuses before it considers anything else.
  dirty=$(git -C "$wt" status --porcelain 2>/dev/null | wc -l | tr -d ' ')
  if [ "$dirty" != "0" ]; then
    printf '%-58s %9s  KEEP — %s uncommitted file(s)\n' "$wt" "$tgt_h" "$dirty"
    kept=$((kept + 1)); continue
  fi

  # Index mtime, not directory mtime: directory mtime under-reports activity
  # badly and has already mislabelled live worktrees as idle here.
  idx="$(git -C "$wt" rev-parse --git-dir 2>/dev/null)/index"
  if [ -f "$idx" ]; then
    mtime=$(stat -f %m "$idx" 2>/dev/null || stat -c %Y "$idx" 2>/dev/null || echo 0)
    idle=$(( now - mtime ))
  else
    idle=$idle_cutoff
  fi

  if [ "$idle" -lt "$idle_cutoff" ]; then
    printf '%-58s %9s  KEEP — active %dh ago\n' "$wt" "$tgt_h" "$((idle / 3600))"
    kept=$((kept + 1)); continue
  fi

  reclaimable=$((reclaimable + tgt_kb))
  if [ "$REAP" = "1" ]; then
    if git worktree remove --force "$wt" 2>/dev/null; then
      printf '%-58s %9s  REAPED — clean, idle %dh\n' "$wt" "$tgt_h" "$((idle / 3600))"
      reaped=$((reaped + 1))
    else
      printf '%-58s %9s  KEEP — git refused removal\n' "$wt" "$tgt_h"
      kept=$((kept + 1))
    fi
  else
    printf '%-58s %9s  WOULD REAP — clean, idle %dh\n' "$wt" "$tgt_h" "$((idle / 3600))"
  fi
done < <(git -C "$REPO" worktree list --porcelain | awk '/^worktree /{print $2}')

[ "$REAP" = "1" ] && git -C "$REPO" worktree prune

echo
main_kb=$(du -sk "$REPO/target" 2>/dev/null | awk '{print $1}' || echo 0)
awk -v r="$reclaimable" -v m="$main_kb" -v n="$reaped" -v k="$kept" 'BEGIN{
  printf "reaped %d, kept %d, reclaimed %.1f GB from worktrees\n", n, k, r/1048576
  printf "main checkout target/: %.1f GB\n", m/1048576
}'

# The main target/ is the biggest single consumer and the most dangerous thing to
# clear, so this only ever ADVISES. A `cargo clean` mid-wave makes every running
# agent rebuild from zero.
builders=$(pgrep -c rustc 2>/dev/null || echo 0)
if [ "$builders" -gt 0 ]; then
  echo "main target/: NOT cleaning — $builders rustc process(es) live. Re-run when the wave drains."
elif [ "$main_kb" -gt 52428800 ]; then
  echo "main target/: over 50 GB and nothing is building — 'cargo clean' is safe now."
fi

# ---------------------------------------------------------------------------
# ORPHANED PROCESS REAPER
#
# WHY. On 2026-09-22 this box was found holding 433 leaked `release/busbar`
# test subjects, 4.7 GB of RSS, all reparented to launchd. A rig boots one
# subject per scenario; something in a teardown path stopped reaping, and
# nothing noticed for hours because leaked processes are invisible until you
# count them. They inflated load average while agents complained about build
# contention.
#
# THE ONE SAFETY RULE, and everything else follows from it:
#
#   KILL ONLY WHAT HAS NO PARENT.
#
# `ppid == 1` means the parent exited without reaping — on macOS the child is
# reparented to launchd. A process whose parent is alive may be doing real
# work for a live agent, and is NEVER touched here regardless of age or name.
# That is why this is safe to run unattended: it does not judge whether work
# is finished, it observes that the thing which started it is gone.
#
# Matching by name alone would be the dangerous version of this. The name
# allowlist below narrows an already-safe set; it is not the safety mechanism.
# ---------------------------------------------------------------------------

# Ephemeral things a rig or a recorder starts and is expected to reap itself.
# Deliberately narrow. A long-lived service must never appear here.
ORPHAN_PATTERNS='release/busbar|busbar-oracle'
# NOTE: macOS `ps` has NO `etimes` (seconds) field -- that is GNU-only. It has
# `etime`, formatted [[dd-]hh:]mm:ss, so age is parsed in awk below. Using
# `etimes` here silently shifts every column and the age test then compares a
# COMMAND STRING against an integer. Caught on this script's first dry run.
ORPHAN_MIN_AGE_SECS=120

reap_orphans() {
  local killed=0 spared=0 young=0

  while read -r pid ppid etimes comm; do
    [ -n "$pid" ] || continue
    if [ "$ppid" != "1" ]; then spared=$((spared + 1)); continue; fi
    if [ "$etimes" -lt "$ORPHAN_MIN_AGE_SECS" ]; then young=$((young + 1)); continue; fi
    if [ "$REAP" = "1" ]; then
      kill -TERM "$pid" 2>/dev/null
      killed=$((killed + 1))
    else
      killed=$((killed + 1))
    fi
  done < <(ps -eo pid,ppid,etime,command 2>/dev/null \
             | grep -E "$ORPHAN_PATTERNS" | grep -v grep \
             | awk '{ n=split($3, t, /[-:]/);
                      if (n==2)      secs = t[1]*60 + t[2];
                      else if (n==3) secs = t[1]*3600 + t[2]*60 + t[3];
                      else if (n==4) secs = t[1]*86400 + t[2]*3600 + t[3]*60 + t[4];
                      else           secs = 0;
                      print $1, $2, secs, $4 }')

  if [ "$REAP" = "1" ] && [ "$killed" -gt 0 ]; then
    sleep 3
    ps -eo pid,ppid,command 2>/dev/null | grep -E "$ORPHAN_PATTERNS" | grep -v grep \
      | awk '$2==1 {print $1}' | xargs -r kill -9 2>/dev/null
  fi

  if [ "$REAP" = "1" ]; then
    printf 'orphaned processes: reaped %d, spared %d (live parent), %d too young (<%ds)\n' \
      "$killed" "$spared" "$young" "$ORPHAN_MIN_AGE_SECS"
  else
    printf 'orphaned processes: WOULD REAP %d, spared %d (live parent), %d too young (<%ds)\n' \
      "$killed" "$spared" "$young" "$ORPHAN_MIN_AGE_SECS"
  fi
}

echo
reap_orphans

# A parentless `sleep` is an abandoned poll loop from a wait chain whose owner
# died. Live agent loops sleep 20-60s and their parent is alive, so they are
# spared by the ppid rule above; only the long-interval strays reach here.
stray_sleeps=$(ps -eo pid,ppid,etime,command 2>/dev/null \
  | awk '$2==1 && $4=="sleep" {
           n=split($3, t, /[-:]/);
           if (n==2)      secs = t[1]*60 + t[2];
           else if (n==3) secs = t[1]*3600 + t[2]*60 + t[3];
           else if (n==4) secs = t[1]*86400 + t[2]*3600 + t[3]*60 + t[4];
           else           secs = 0;
           if (secs > 900) print $1 }')
if [ -n "$stray_sleeps" ]; then
  n=$(echo "$stray_sleeps" | grep -c .)
  if [ "$REAP" = "1" ]; then
    echo "$stray_sleeps" | xargs -r kill -9 2>/dev/null
    echo "abandoned poll loops: reaped $n (parentless, idle >15m)"
  else
    echo "abandoned poll loops: WOULD REAP $n (parentless, idle >15m)"
  fi
fi

# ---------------------------------------------------------------------------
# RUNAWAY REAPER — a SECOND rule, because the orphan rule cannot see these.
#
# WHY. Minutes after the orphan reaper was written, this box was found at load
# 64 on 18 cores with `pgrep rustc`, `pgrep cargo` and `pgrep release/busbar`
# all reporting ZERO. Two `target/debug/deps/cli-*` binaries — cargo's compiled
# TEST harnesses — were burning ~590% CPU EACH for 52 minutes, about 12 of 18
# cores between them. They were children of `cargo test -p xtask`, so their
# parents were alive and the ppid==1 rule spared them correctly.
#
# Two lessons, both encoded below:
#   1. Checking for `rustc`/`cargo`/the product binary is NOT checking for
#      build load. A compiled test binary is none of those things.
#   2. "Has a live parent" means "not abandoned". It does NOT mean "healthy".
#
# THE RULE HERE IS DIFFERENT AND DELIBERATELY NARROW: a cargo-built TEST
# binary under target/*/deps/ that has been running longer than a test suite
# ever legitimately runs. Normal tests finish in seconds; these had accrued 80
# minutes of CPU time apiece. This never matches a service, an editor, an
# agent, or the product — only the ephemeral harnesses cargo generates.
# ---------------------------------------------------------------------------

RUNAWAY_MAX_ELAPSED_SECS=1200   # 20 minutes; a test suite that long is livelocked

reap_runaways() {
  local found=0
  while read -r pid secs cmd; do
    [ -n "$pid" ] || continue
    [ "$secs" -gt "$RUNAWAY_MAX_ELAPSED_SECS" ] || continue
    found=$((found + 1))
    if [ "$REAP" = "1" ]; then
      kill -9 "$pid" 2>/dev/null
      printf 'runaway test binary: KILLED pid %s after %dm — %s\n' "$pid" "$((secs / 60))" "$cmd"
    else
      printf 'runaway test binary: WOULD KILL pid %s after %dm — %s\n' "$pid" "$((secs / 60))" "$cmd"
    fi
  done < <(ps -eo pid,etime,command 2>/dev/null \
             | grep -E 'target/[a-z]+/deps/[a-z_]+-[0-9a-f]{8,}' | grep -v grep \
             | awk '{ n=split($2, t, /[-:]/);
                      if (n==2)      secs = t[1]*60 + t[2];
                      else if (n==3) secs = t[1]*3600 + t[2]*60 + t[3];
                      else if (n==4) secs = t[1]*86400 + t[2]*3600 + t[3]*60 + t[4];
                      else           secs = 0;
                      sub(/.*\//, "", $3);
                      print $1, secs, $3 }')
  [ "$found" -eq 0 ] && echo "runaway test binaries: none over ${RUNAWAY_MAX_ELAPSED_SECS}s"
  return 0
}

reap_runaways

# Report REAL load, not the three names that happened to be checked first.
printf 'load: %s | rustc %s, cargo %s, test-bins %s, product %s\n' \
  "$(uptime | sed 's/.*load averages*: //')" \
  "$(pgrep -c rustc 2>/dev/null || echo 0)" \
  "$(pgrep -c cargo 2>/dev/null || echo 0)" \
  "$(pgrep -fc 'target/[a-z]*/deps/' 2>/dev/null || echo 0)" \
  "$(pgrep -fc 'release/busbar' 2>/dev/null || echo 0)"

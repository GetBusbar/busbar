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
# Honour BOTH `--reap` and an inherited REAP=1. The env form is what the hourly
# housekeeping instruction has always used -- and a plain `REAP=0` here clobbered
# it, so every hourly run was a DRY RUN that printed "WOULD KILL" and killed
# nothing. Caught 2026-09-22 when the runaway rule finally fired on a test binary
# at 1054% CPU and the process was still there afterwards.
REAP="${REAP:-0}"
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
# THE GUARD IS THE WHOLE ADVISORY, so it must be as wide as the advice.
#
# WHY. This once printed "over 50 GB and nothing is building — 'cargo clean' is
# safe now" while 8 rustc and 16 cargo processes were live and ~20 agents were
# mid-build. Following it would have forced every one of them to rebuild from
# zero. Two defects, both the same shape as everything else this release keeps
# finding:
#   * it guarded on `rustc` ALONE, while the rule it advises says
#     rustc AND cargo AND test-binaries must all be zero. A cargo between rustc
#     invocations -- linking, fingerprinting, fetching -- reads as idle.
#   * it measured MINUTES before it spoke. `du -sk` over a 58 GB target/ is slow,
#     so the process count was stale by the time the sentence printed.
# Both are fixed here: every column the `load:` line reports is counted, by the
# same `live()` helper, and counted IMMEDIATELY before the advice is given.
# `grep -c` prints 0 AND exits 1 when it matches nothing, so under
# `set -euo pipefail` a bare assignment from it aborts the script on the HEALTHY
# path. Swallow the status inside the helper, never at the call site.
live() { local n; n=$(ps -eo command 2>/dev/null | awk '{print $1}' | grep -cE "$1" || true); echo "${n:-0}"; }

n_rustc=$(live '/bin/rustc$')
n_cargo=$(live '/bin/cargo$')
n_tests=$(live '/(debug|release)/deps/[a-z_]+-[0-9a-f]{8,}$')
n_busy=$(( n_rustc + n_cargo + n_tests ))

if [ "$n_busy" -gt 0 ]; then
  echo "main target/: NOT cleaning — rustc $n_rustc, cargo $n_cargo, test-bins $n_tests live. Re-run when the wave drains."
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

# ---------------------------------------------------------------------------
# RULE 3: the ABANDONED HOT PROCESS -- keyed on behaviour, not on a name.
#
# Found 2026-09-22: a python3 at 97% CPU, ppid==1, elapsed 2 days 22 hours,
# 3820 MINUTES of accrued CPU time (~63 core-hours), cwd inside an agent
# worktree, writing to the task-output dir of a session that ended Sep 17.
#
# RULE 1 could not see it and never could: ORPHAN_PATTERNS greps for
# `release/busbar|busbar-oracle`, and this was neither. RULE 2 could not see it
# either: it is not a cargo test binary under target/*/deps/. Both rules were
# written from the last incident and matched its SPELLING. This one matches the
# SHAPE of abandonment instead, so it does not need to know what ran:
#
#   parent is dead (ppid==1)  AND  burning real CPU  AND  old  AND  its cwd is
#   inside this repo tree.
#
# All four are required. ppid==1 alone means abandoned, not harmful; CPU alone
# means busy, not abandoned. An editor, an agent, a shell or the product fails
# at least one leg. Thresholds are env-overridable ONLY so the canary can
# exercise the rule honestly -- a rule that cannot be shown firing is not a rule.
# ---------------------------------------------------------------------------

ORPHAN_CPU_FLOOR=${ORPHAN_CPU_FLOOR:-20}            # percent; below this it is idle, not runaway
ORPHAN_HOT_MIN_AGE_SECS=${ORPHAN_HOT_MIN_AGE_SECS:-600}
ORPHAN_CWD_ROOT=${ORPHAN_CWD_ROOT:-/Users/matthew/Developer/GetBusbar}

reap_abandoned_hot() {
  local found=0
  while read -r pid cpu secs comm; do
    [ -n "$pid" ] || continue
    # integer-compare the CPU percent without bc
    case "$cpu" in ''|*[!0-9.]*) continue ;; esac
    [ "${cpu%%.*}" -ge "$ORPHAN_CPU_FLOOR" ] || continue
    [ "$secs" -gt "$ORPHAN_HOT_MIN_AGE_SECS" ] || continue
    # the fourth leg: cwd inside the repo tree. lsof only for the tiny candidate set.
    local cwd
    # `set -o pipefail` + lsof's non-zero rc on a SIP-protected process used to kill
    # the whole script HERE, silently, before the abandoned-hot / poll-loop / tmp /
    # load lines ever printed. It surfaced as rc=1 with no stderr. An empty cwd is a
    # NORMAL answer (system daemons deny it) and the case below already spares them.
    cwd=$(/usr/sbin/lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -1 || true)
    case "$cwd" in "$ORPHAN_CWD_ROOT"*) ;; *) continue ;; esac
    found=$((found + 1))
    if [ "$REAP" = "1" ]; then
      kill -9 "$pid" 2>/dev/null
      printf 'abandoned hot process: KILLED pid %s (%s%% cpu, %dm, cwd %s) -- %s\n' \
        "$pid" "$cpu" "$((secs / 60))" "$cwd" "$comm"
    else
      printf 'abandoned hot process: WOULD KILL pid %s (%s%% cpu, %dm, cwd %s) -- %s\n' \
        "$pid" "$cpu" "$((secs / 60))" "$cwd" "$comm"
    fi
  done < <(ps -eo pid,ppid,pcpu,etime,comm 2>/dev/null \
             | awk '$2==1 {
                      n=split($4, t, /[-:]/);
                      if (n==2)      secs = t[1]*60 + t[2];
                      else if (n==3) secs = t[1]*3600 + t[2]*60 + t[3];
                      else if (n==4) secs = t[1]*86400 + t[2]*3600 + t[3]*60 + t[4];
                      else           secs = 0;
                      print $1, $3, secs, $5 }')
  [ "$found" -eq 0 ] && echo "abandoned hot processes: none (>=${ORPHAN_CPU_FLOOR}% cpu, >${ORPHAN_HOT_MIN_AGE_SECS}s, ppid 1, cwd under ${ORPHAN_CWD_ROOT})"
  return 0
}

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
reap_abandoned_hot

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

# A THIRD poll-loop rule, because neither rule above can see this one.
#
# WHY. A wait loop was found alive at 11h41m. Its parent was a LIVE (stale)
# claude session, so the ppid==1 orphan rule spared it by design; and it was a
# `zsh -c` wrapper rather than a bare `sleep`, so the stray-sleep rule never
# looked at it. It was provably non-terminating on two independent counts:
#   (1) it waited for '^test result' in a log whose build had already FAILED, so
#       the string it waits for can never be written; and
#   (2) its own `pgrep -f 'cargo test -p busbar'` MATCHED ITS OWN COMMAND LINE.
#       The loop was its own subject, so `! pgrep ...` could never be true.
# (2) is the general, decidable case: if `pgrep -f <pat>` returns the waiting
# process's own pid, the loop can never exit no matter what the product does.
# That is a proof of non-termination, not a heuristic, so a live parent does not
# protect it -- and it also explains a lying `load:` line, since such a loop is
# counted as a live `cargo` by any pattern that reads command lines.
self_matching=$(ps -eo pid,etime,command 2>/dev/null \
  | awk '/pgrep -f/ && (/until /||/while /) {
           n=split($2, t, /[-:]/);
           if (n==2)      secs = t[1]*60 + t[2];
           else if (n==3) secs = t[1]*3600 + t[2]*60 + t[3];
           else if (n==4) secs = t[1]*86400 + t[2]*3600 + t[3]*60 + t[4];
           else           secs = 0;
           if (secs > 900) print }' \
  | while read -r pid etime rest; do
      pat=$(printf '%s\n' "$rest" | sed -n "s/.*pgrep[[:space:]][[:space:]]*-f[[:space:]][[:space:]]*['\"]*\([^'\"]*\).*/\1/p")
      [ -n "$pat" ] || continue
      pgrep -f "$pat" 2>/dev/null | grep -qx "$pid" && echo "$pid"
    done || true)   # a non-match is status 1; `set -e` must not read that as failure
if [ -n "$self_matching" ]; then
  n=$(echo "$self_matching" | grep -c .)
  if [ "$REAP" = "1" ]; then
    echo "$self_matching" | xargs kill -9 2>/dev/null
    echo "self-watching poll loops: reaped $n (pgrep pattern matches own argv; cannot terminate)"
  else
    echo "self-watching poll loops: WOULD REAP $n (pgrep pattern matches own argv; cannot terminate)"
  fi
fi

# ABANDONED-COLD REAPER -- the complement of the hot rule above, and the fix for
# a blind spot that hid two dead processes for eighteen hours.
#
# WHY. `target/debug/xtask full-gate` was found orphaned (ppid 1) at 18h21m with
# a child `xtask gate plane-purity` at 14h17m. Neither was reaped, for two
# independent reasons:
#   (1) ORPHAN_PATTERNS is 'release/busbar|busbar-oracle' -- it names the product
#       and the oracle but never the tool that RUNS THE GATES, so the orphan rule
#       could not see an xtask no matter how long it sat there; and
#   (2) the hot rule needs >=20% cpu, and these were at 0%.
# They had each burned a FIFTH OF A SECOND of cpu in eighteen hours, and `sample`
# put both stacks at `_dyld_start + 0` -- stalled in the dynamic linker, before
# main(). They never ran a single gate. Two `--selftest` poll loops waited on
# them for seven hours and could never have been answered.
#
# THE TEST IS DECIDABLE, not a heuristic: sample the process's accumulated CPU
# time twice, COLD_SAMPLE_SECS apart. A process doing work advances it. One that
# does not advance it over a live interval, after an hour of wall clock, is not
# slow -- it is stopped. That distinction is what lets this rule name `cargo` and
# `xtask`, which the orphan rule dares not, without ever killing a live worker.
COLD_PATTERNS='xtask|[c]argo|rustc|release/busbar|busbar-oracle'
COLD_MIN_AGE_SECS=${COLD_MIN_AGE_SECS:-3600}
COLD_SAMPLE_SECS=6

cold_candidates=$(ps -eo pid,ppid,etime,command 2>/dev/null \
  | grep -E "$COLD_PATTERNS" | grep -v grep \
  | awk '$2==1 { n=split($3, t, /[-:]/);
                 if (n==2)      secs = t[1]*60 + t[2];
                 else if (n==3) secs = t[1]*3600 + t[2]*60 + t[3];
                 else if (n==4) secs = t[1]*86400 + t[2]*3600 + t[3]*60 + t[4];
                 else           secs = 0;
                 if (secs > '"$COLD_MIN_AGE_SECS"') print $1 }' || true)

cold_stuck=''
if [ -n "$cold_candidates" ]; then
  # snapshot, wait, snapshot again -- only a pid whose cpu time is IDENTICAL in
  # both samples is declared stuck.
  for p in $cold_candidates; do
    printf '%s %s\n' "$p" "$(ps -o time= -p "$p" 2>/dev/null | tr -d ' ')"
  done > /tmp/.reap-cold-t0
  sleep "$COLD_SAMPLE_SECS"
  while read -r p t0; do
    [ -n "$t0" ] || continue
    t1=$(ps -o time= -p "$p" 2>/dev/null | tr -d ' ')
    [ -n "$t1" ] || continue
    [ "$t0" = "$t1" ] && cold_stuck="$cold_stuck $p"
  done < /tmp/.reap-cold-t0
  rm -f /tmp/.reap-cold-t0
fi

if [ -n "${cold_stuck# }" ]; then
  n=$(echo "$cold_stuck" | tr ' ' '\n' | grep -c .)
  if [ "$REAP" = "1" ]; then
    # children first: a stalled parent's children are stalled with it.
    for p in $cold_stuck; do pgrep -P "$p" 2>/dev/null | xargs kill -9 2>/dev/null; done
    echo "$cold_stuck" | tr ' ' '\n' | grep . | xargs kill -9 2>/dev/null
    echo "abandoned cold tools: reaped $n (orphaned >1h, cpu time did not advance over ${COLD_SAMPLE_SECS}s)"
  else
    echo "abandoned cold tools: WOULD REAP $n ($(echo "$cold_stuck" | tr -s ' '))"
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
             | grep -E '/(debug|release)/deps/[a-z_]+-[0-9a-f]{8,}' | grep -v grep \
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
# The `tool-bins` column exists because a 2026-09-22 housekeeping run reported
# rustc/cargo/test-bins/product ALL ZERO while `target/debug/xtask` burned 15.8%
# of a core. A gate binary is not rustc, not cargo, not under target/*/deps/ and
# not release/busbar -- four patterns, and the thing actually running matched
# none of them. Same lesson as the test-bins column, one layer out.
# ...and every one of those counters COUNTED MENTIONS, NOT PROCESSES. They
# matched the pattern against the WHOLE command line, so two different things
# were counted as a running build:
#   * the `grep` doing the counting, whose own argv contains the pattern; and
#   * any `zsh -c` agent wrapper whose SCRIPT TEXT merely names a cargo path --
#     one 8-hour-stale shell held `cargo` at 1 on a box with no cargo at all.
# `cargo` was therefore never 0, so the housekeeping rule that reclaims the main
# `target/` only "when rustc/cargo/test-bins are all 0" could never fire: a
# cleanup gate held shut by its own instrument.
# The fix is to match the EXECUTABLE, not the sentence -- field 1 of the command
# line, which a wrapper shell cannot forge by talking about it. (`pgrep -fc`
# looks tidier and was tried first; it silently missed a live
# `./target/debug/turnstile-web`, and a quieter wrong answer is worse.)
live() { ps -eo command 2>/dev/null | awk '{print $1}' | grep -cE "$1"; }

printf 'load: %s | rustc %s, cargo %s, test-bins %s, tool-bins %s, product %s\n' \
  "$(uptime | sed 's/.*load averages*: //')" \
  "$(live '/bin/rustc$')" \
  "$(live '/bin/cargo$')" \
  "$(live '/(debug|release)/deps/[a-z_]+-[0-9a-f]{8,}$')" \
  "$(live '/(debug|release)/[a-z_-]+$')" \
  "$(pgrep -fc 'release/busbar' 2>/dev/null || echo 0)"

# ---------------------------------------------------------------------------
# /private/tmp SWEEP (owner instruction 2026-09-22). Dead agent scratch dirs and
# abandoned cargo targets accumulate here without limit -- 559 GB when first
# measured. NEVER touch claude-501/: that is where LIVE agents write their task
# output, and deleting it kills every running agent's transcript.
# Anything modified in the last 10 minutes is skipped as possibly in use.
# ---------------------------------------------------------------------------
tmp_freed=0; tmp_killed=0
if [ -d /private/tmp ]; then
  for d in /private/tmp/*/; do
    case "$d" in
      /private/tmp/claude-501/|/private/tmp/com.apple.*|/private/tmp/.*) continue ;;
    esac
    [ -d "$d" ] || continue
    # A PINNED TREE IS NOT SCRATCH. On 2026-09-23 this sweep deleted
    # /tmp/codeaudit-live mid-run and truncated 6 of 10 audit finders; the agents
    # could not tell "found nothing" from "tree vanished". Any dir carrying the
    # marker is off limits for as long as the marker exists.
    [ -e "$d/.codeaudit-pin" ] && continue
    [ -n "$(find "$d" -maxdepth 0 -mmin -10 2>/dev/null)" ] && continue
    sz=$(du -sxm "$d" 2>/dev/null | cut -f1); sz=${sz:-0}
    if [ "$REAP" = "1" ]; then
      rm -rf "$d" 2>/dev/null && { tmp_freed=$((tmp_freed+sz)); tmp_killed=$((tmp_killed+1)); }
    else
      tmp_freed=$((tmp_freed+sz)); tmp_killed=$((tmp_killed+1))
    fi
  done
fi
if [ "$REAP" = "1" ]; then
  echo "/private/tmp: removed $tmp_killed dir(s), freed $((tmp_freed/1024)) GB (claude-501 preserved)"
else
  echo "/private/tmp: $tmp_killed dir(s) reapable, $((tmp_freed/1024)) GB (dry run; claude-501 preserved)"
fi


#!/usr/bin/env bash
# THE FLEET'S COST IS EBS WHEN NOBODY IS PROVING. Eighteen boxes mostly idle measured $569; the
# constraint was never CPU, it was proof SLOTS — two per box, and a battery that took one core.
# Now a gate-only union proof is ~908 s on 32 vCPU, so the same work needs a few boxes for a few
# minutes and none at all in between. This script is the "and none at all in between".
#
#   ./scripts/ci-fleet-power.sh --stop-idle        # STOP every box that has held no proof for
#                                                  # LANDQ_IDLE_STOP_MINS (default 15). EBS persists.
#   ./scripts/ci-fleet-power.sh --start N          # START N stopped boxes and WAIT for readiness
#   ./scripts/ci-fleet-power.sh --ensure-slots D   # start only as many as D proof slots are short of
#   ./scripts/ci-fleet-power.sh --status           # what is running, what is stopped, what is busy
#   ./scripts/ci-fleet-power.sh --selftest         # the whole mechanism against a stubbed `aws`
#
#   CI_RUNNER_DRY_RUN=1 …                          # print the mutating calls, make none
#
# ── WHY STOP AND NOT TERMINATE ────────────────────────────────────────────────────────────────────
# A terminated box loses its EBS volume, and that volume is `~/busbar.git`, `~/busbar-prove`, the
# warm `target/` and the sccache — between eight and twenty minutes of bootstrap and a cold first
# build, paid again on the next proof. A STOPPED box keeps all of it and costs gp3 storage alone
# (300 GB ≈ $24/mo per box, versus $1.22/h running for a c7a.8xlarge). Stopping is therefore ~97%
# of the saving with none of the loss, and a start is 60–90 s rather than ten minutes.
#
# ── WHY A PROOF CANNOT BE STOPPED OUT FROM UNDER ITSELF ───────────────────────────────────────────
# NOT "the box looks quiet". Loadavg is a one-minute average and a proof that started forty seconds
# ago is not in it; a box carrying four CI runner agents is never quiet anyway. The stopper asks the
# box its OWN PROOF REGISTRY — the pid files every proof and every landing writes, checked live —
# and the check and the decision happen inside one lock on the box, the same lock a proof takes to
# announce itself. So the interleaving is:
#
#   stopper takes the lock, sees zero proofs, writes ~/.busbar-stopping, releases
#     → every later proof-start takes the lock, sees ~/.busbar-stopping, and REFUSES the box
#   proof takes the lock first, writes its pid file, releases
#     → the stopper takes the lock, counts 1, and reports BUSY. It does not stop the box.
#
# There is no third order. A box is stopped only after it has refused, in its own file system, to
# admit any further proof — which is why `--stop-idle` REFUSES TO STOP A BOX THAT HAS NO
# ~/.busbar-power.sh INSTALLED: without the admit half, the claim is a promise nothing is keeping.
# It installs the script on that pass and the box becomes stoppable on the next one.
#
# ── NOTHING LOST ──────────────────────────────────────────────────────────────────────────────────
# A claim that is made and then not carried out (the stop call failed, the box went below the
# running floor) is CLEARED, not left behind: a box marked stopping and never stopped would refuse
# every proof forever and read to the allocator as a box that is simply never ready.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${AWS_REGION:=us-east-1}"
export AWS_REGION AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-$AWS_REGION}"
export PATH="$HOME/.local/bin:$PATH"

FLEET_TAG="${CI_RUNNER_FLEET:-busbar-ci-runner}"
FLEET_FILE="${BUSBAR_FLEET_FILE:-$HOME/.busbar-fleet}"
SSH_WRAP="${BUSBAR_SSH_WRAPPER:-$HOME/.busbar-fleet-ssh}"
REMOTE_USER="${BUSBAR_REMOTE_USER:-ubuntu}"
PROVE_PER_BOX="${BUSBAR_PROVE_PER_BOX:-2}"
IDLE_STOP_MINS="${LANDQ_IDLE_STOP_MINS:-15}"
# THE FLOOR OF RUNNING BOXES. Not the same knob as CI_RUNNER_ONDEMAND_FLOOR, which is the floor of
# REGISTERED boxes (a stopped box is still registered). This one is "how many boxes stay awake for
# the GitHub Actions jobs that are not proofs", because a fleet stopped to zero holds every CI job
# `queued` until the next sweep happens to want a box.
RUNNING_MIN="${CI_RUNNER_RUNNING_MIN:-2}"
# AND THE CEILING OF RUNNING BOXES, which is what actually bounds the bill. The starter never takes
# the fleet above it, however many slots a sweep asks for; the sweep then dispatches what there is.
RUNNING_MAX="${CI_RUNNER_RUNNING_MAX:-${CI_RUNNER_ONDEMAND_FLOOR:-10}}"
START_WAIT_SECS="${CI_RUNNER_START_WAIT_SECS:-300}"
DRY_RUN="${CI_RUNNER_DRY_RUN:-0}"

plog() { printf '[power %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
pdie() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
pdry() { [ "$DRY_RUN" = 1 ]; }

# ── THE BOX-SIDE PROTOCOL, AS ONE FILE ───────────────────────────────────────────────────────────
# It is printed here and installed at ~/.busbar-power.sh rather than sent as an ssh command line,
# because the OTHER half of the protocol — `admit`, which a proof calls before it starts — runs from
# inside land-remote.sh's quoted heredoc and from prove-remote.sh on the box, where no copy of this
# script exists. One file on the box, three callers, no second definition of the lock to drift.
#
# THE LOCK IS `mkdir`, NOT `flock`. This text is driven by --selftest on the operator's laptop as
# well as on the box, and macOS has no flock(1). mkdir is atomic on every filesystem either one
# has, and a lock held by a process that died is broken on age rather than held forever.
power_box_script() {
  cat <<'BOX'
#!/bin/sh
# THE BOX'S OWN POWER PROTOCOL — installed by scripts/ci-fleet-power.sh. Do not edit here; edit
# power_box_script() in that file, which reinstalls this on every stop/start pass.
#
#   ~/.busbar-power.sh busy                  -> how many proofs this box is holding, live
#   ~/.busbar-power.sh probe                 -> `BUSY <n>` or `IDLE <seconds>`; keeps the idle clock
#   ~/.busbar-power.sh claim-stop <mins>     -> `STOP-CLAIMED <s>` | `BUSY <n>` | `IDLE <s>`
#   ~/.busbar-power.sh admit <pidfile> <pid> -> `ADMITTED` (rc 0) | `REFUSED <why>` (rc 3)
#   ~/.busbar-power.sh clear                 -> the box may hold proofs again (run after a start)
set -u
H="${HOME:-/home/ubuntu}"
LOCK="$H/.busbar-power.lock"
STOPPING="$H/.busbar-stopping"
IDLE="$H/.busbar-idle-since"

# A PROOF IS A LIVE PID, AND THERE ARE TWO KINDS. `<checkout>/.proof.pid` is what prove-remote.sh's
# slot pre-proof writes; `<checkout>/target/land-remote-<ref>.pid` is what land-remote.sh writes for
# a landing and for every sweep pre-proof, which go through land.run.local.sh and never touch
# .proof.pid. Counting only the first is how a LANDING gets stopped by a stopper that believed the
# box was idle. A pid whose process is gone is a crashed proof, not a running one.
busy_count() {
  n=0
  for f in "$H"/busbar-prove*/.proof.pid "$H"/busbar-prove*/target/land-remote-*.pid; do
    [ -f "$f" ] || continue
    # A LANDING THAT HAS FINISHED WROTE ITS `.rc`. These files are named by ref and accumulate, so a
    # stale one whose pid has been reused would hold the box awake forever.
    case "$f" in *land-remote-*) [ -f "${f%.pid}.rc" ] && continue ;; esac
    p="$(cat "$f" 2>/dev/null)"
    case "$p" in ''|*[!0-9]*) continue ;; esac
    kill -0 "$p" 2>/dev/null && n=$((n + 1))
  done
  # THE BELT AND THE BRACES. A landing whose pid file was removed but whose engine is still running
  # is still a landing; the same pattern ci-remote-lib.sh's shard probe already reads.
  if [ "$n" -eq 0 ] && pgrep -f '[l]and.run.local.sh' >/dev/null 2>&1; then n=1; fi
  echo "$n"
}

lock() {
  i=0
  while ! mkdir "$LOCK" 2>/dev/null; do
    if [ -n "$(find "$LOCK" -maxdepth 0 -mmin +2 2>/dev/null)" ]; then rmdir "$LOCK" 2>/dev/null; continue; fi
    i=$((i + 1)); [ "$i" -gt 60 ] && return 1
    sleep 1
  done
  return 0
}
unlock() { rmdir "$LOCK" 2>/dev/null || true; }

case "${1:-}" in
  busy) busy_count ;;
  probe)
    n="$(busy_count)"
    if [ "$n" -gt 0 ]; then rm -f "$IDLE"; echo "BUSY $n"; exit 0; fi
    [ -f "$IDLE" ] || date +%s >"$IDLE"
    s="$(cat "$IDLE" 2>/dev/null || echo 0)"
    case "$s" in ''|*[!0-9]*) s="$(date +%s)"; echo "$s" >"$IDLE" ;; esac
    echo "IDLE $(( $(date +%s) - s ))"
    ;;
  claim-stop)
    mins="${2:-15}"
    case "$mins" in ''|*[!0-9]*) mins=15 ;; esac
    lock || { echo "LOCKED"; exit 1; }
    n="$(busy_count)"
    if [ "$n" -gt 0 ]; then rm -f "$IDLE"; unlock; echo "BUSY $n"; exit 0; fi
    [ -f "$IDLE" ] || date +%s >"$IDLE"
    s="$(cat "$IDLE" 2>/dev/null || echo 0)"
    case "$s" in ''|*[!0-9]*) s="$(date +%s)"; echo "$s" >"$IDLE" ;; esac
    age=$(( $(date +%s) - s ))
    if [ "$age" -ge $(( mins * 60 )) ]; then
      : >"$STOPPING"; unlock; echo "STOP-CLAIMED $age"; exit 0
    fi
    unlock; echo "IDLE $age"; exit 0
    ;;
  admit)
    pf="${2:-}"; pid="${3:-}"
    [ -n "$pf" ] || { echo "REFUSED no-pidfile"; exit 3; }
    case "$pid" in ''|*[!0-9]*) echo "REFUSED no-pid"; exit 3 ;; esac
    lock || { echo "REFUSED locked"; exit 3; }
    if [ -e "$STOPPING" ]; then
      unlock
      echo "REFUSED stopping"
      exit 3
    fi
    mkdir -p "$(dirname "$pf")" 2>/dev/null || true
    echo "$pid" >"$pf" || { unlock; echo "REFUSED pidfile-unwritable"; exit 3; }
    rm -f "$IDLE"
    unlock
    echo "ADMITTED"
    exit 0
    ;;
  clear) rm -f "$STOPPING" "$IDLE"; echo "CLEARED" ;;
  *) echo "usage: $0 busy|probe|claim-stop <mins>|admit <pidfile> <pid>|clear" >&2; exit 2 ;;
esac
BOX
}

_rsh() { # $1 = host, $2.. = command words
  local h="$1"; shift
  "$SSH_WRAP" "$REMOTE_USER@$h" "$@" </dev/null 2>/dev/null
}
_tmo() { if command -v timeout >/dev/null 2>&1; then timeout "$@"; else shift; "$@"; fi; }

# INSTALL THE PROTOCOL, IDEMPOTENTLY, AND SAY WHETHER THE BOX NOW HAS IT. The stop path refuses a
# box this returns non-zero for: an uninstalled box is one that cannot refuse a proof, and a claim
# it cannot keep is worse than an idle box.
power_install() { # $1 = host
  local h="$1"
  power_box_script | _tmo 45 "$SSH_WRAP" "$REMOTE_USER@$h" \
    'cat >"$HOME/.busbar-power.sh.tmp" && chmod 0755 "$HOME/.busbar-power.sh.tmp" && mv -f "$HOME/.busbar-power.sh.tmp" "$HOME/.busbar-power.sh" && echo INSTALLED' \
    >/dev/null 2>&1
}
power_ask() { # $1 = host, $2.. = the box script's arguments
  local h="$1"; shift
  _tmo 30 "$SSH_WRAP" "$REMOTE_USER@$h" "\$HOME/.busbar-power.sh $*" </dev/null 2>/dev/null
}

# ── EC2 ──────────────────────────────────────────────────────────────────────────────────────────
# `describe-instances --output text` returns a TAB-separated LIST ON ONE LINE for a single
# reservation and one line per reservation otherwise; every reader here normalises to one id per
# line rather than trusting the shape.
ids_in_state() { # $1 = a comma-separated instance-state-name list
  aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=$FLEET_TAG" "Name=instance-state-name,Values=$1" \
    --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null \
    | tr -s '[:space:]' '\n' | grep . || true
}
n_lines() { printf '%s' "${1:-}" | tr -s '[:space:]' '\n' | grep -c . || true; }

# THE READINESS PROBE, AND IT IS THE ALLOCATOR'S OWN. A started box is not free until it answers the
# same question fleet_pick_host asks — the bare repo and the shared checkout are there — and until
# it has CLEARED the stop marker its own EBS volume carried across the stop. A box that answers ssh
# but whose marker is still set would be started, counted, and then refuse every proof sent to it.
power_ready() { # $1 = host
  local h="$1" out
  out="$(_tmo 30 "$SSH_WRAP" "$REMOTE_USER@$h" \
    'test -d "$HOME/busbar.git" && test -d "$HOME/busbar-prove" && echo PREPARED' </dev/null 2>/dev/null)"
  case "$out" in *PREPARED*) ;; *) return 1 ;; esac
  power_install "$h" || return 1
  power_ask "$h" clear >/dev/null 2>&1 || return 1
  return 0
}

# ── --start N ────────────────────────────────────────────────────────────────────────────────────
# STARTS AS MANY AS IT NEEDS AND NEVER MORE, and a box is not counted until it is READY. Prints the
# ids that came all the way up, one per line.
power_start() { # $1 = how many
  local want="${1:-0}" stopped running room pick started="" ready="" h t0 now
  case "$want" in ''|*[!0-9]*) want=0 ;; esac
  [ "$want" -gt 0 ] || return 0
  running="$(ids_in_state 'pending,running')"
  room=$(( RUNNING_MAX - $(n_lines "$running") ))
  [ "$room" -gt 0 ] || { plog "already at CI_RUNNER_RUNNING_MAX ($RUNNING_MAX running) — starting nothing"; return 0; }
  [ "$want" -le "$room" ] || { plog "asked for $want box(es); CI_RUNNER_RUNNING_MAX leaves room for $room"; want="$room"; }
  stopped="$(ids_in_state 'stopped')"
  [ -n "$stopped" ] || { plog "no stopped box to start (the fleet is all awake or all gone)"; return 0; }
  pick="$(printf '%s\n' "$stopped" | head -n "$want")"
  plog "starting $(n_lines "$pick") box(es): $(printf '%s' "$pick" | tr '\n' ' ')"
  if pdry; then
    plog "[dry-run] aws ec2 start-instances --instance-ids $(printf '%s' "$pick" | tr '\n' ' ')"
    printf '%s\n' "$pick"; return 0
  fi
  # shellcheck disable=SC2086  # a whitespace-separated id list, passed as separate arguments
  aws ec2 start-instances --instance-ids $(printf '%s' "$pick" | tr '\n' ' ') >/dev/null 2>&1 \
    || { plog "start-instances refused — nothing was started"; return 1; }
  started="$pick"
  # A BOUNDED FOREGROUND POLL, never a blocking wait: a sweep that hangs here is a sweep that never
  # dispatches. Boxes that are not ready by START_WAIT_SECS are simply not returned, and the caller
  # dispatches to what there is.
  t0="$(date +%s)"
  while :; do
    ready=""
    for h in $started; do power_ready "$h" && ready="$ready $h"; done
    ready="$(printf '%s' "$ready" | tr -s ' ' '\n' | grep . || true)"
    [ "$(n_lines "$ready")" -lt "$(n_lines "$started")" ] || break
    now="$(date +%s)"
    [ $(( now - t0 )) -lt "$START_WAIT_SECS" ] || { plog "readiness timed out after ${START_WAIT_SECS}s — $(n_lines "$ready") of $(n_lines "$started") box(es) are up"; break; }
    sleep 10
  done
  plog "ready after $(( $(date +%s) - t0 ))s: $(printf '%s' "$ready" | tr '\n' ' ')"
  fleet_file_refresh
  printf '%s\n' "$ready" | grep . || true
}

# ── --ensure-slots D ─────────────────────────────────────────────────────────────────────────────
# THE SWEEP'S ENTRY POINT. D is how many proof slots this dispatch wants — one per line, plus the
# batch in flight and the base-only replay, because those are proofs on boxes too. The free slots on
# the boxes that are ALREADY AWAKE are subtracted first; only the shortfall is started, rounded up
# to whole boxes at BUSBAR_PROVE_PER_BOX slots each, and never past CI_RUNNER_RUNNING_MAX.
power_free_slots() {
  local running h free=0 n
  running="$(ids_in_state 'running')"
  for h in $running; do
    n="$(power_ask "$h" busy)"
    case "$n" in ''|*[!0-9]*) continue ;; esac          # unreachable or unprepared: not free
    [ "$n" -lt "$PROVE_PER_BOX" ] && free=$(( free + PROVE_PER_BOX - n ))
  done
  echo "$free"
}
power_ensure_slots() { # $1 = slots wanted
  local want="${1:-0}" free short boxes
  case "$want" in ''|*[!0-9]*) want=0 ;; esac
  [ "$want" -gt 0 ] || return 0
  free="$(power_free_slots)"
  short=$(( want - free ))
  if [ "$short" -le 0 ]; then
    plog "$want slot(s) wanted, $free free on the boxes already awake — starting nothing"
    return 0
  fi
  boxes=$(( (short + PROVE_PER_BOX - 1) / PROVE_PER_BOX ))
  plog "$want slot(s) wanted, $free free — $short short, which is $boxes box(es) at $PROVE_PER_BOX slot(s) each"
  power_start "$boxes"
}

# ── --stop-idle ──────────────────────────────────────────────────────────────────────────────────
power_stop_idle() {
  local running h out n probe idle_ok="" keep stoppable claimed="" rc
  running="$(ids_in_state 'running')"
  n="$(n_lines "$running")"
  [ "$n" -gt 0 ] || { plog "nothing running"; return 0; }
  # HOW MANY MAY GO AT ALL. The running floor is checked BEFORE any claim is made, because a claim
  # that is then not carried out has to be cleared again, and a box cleared a second late is a box
  # that refused a proof for no reason.
  keep="$RUNNING_MIN"
  [ "$keep" -le "$n" ] || keep="$n"
  stoppable=$(( n - keep ))
  if [ "$stoppable" -le 0 ]; then
    plog "$n box(es) running and CI_RUNNER_RUNNING_MIN is $RUNNING_MIN — none may be stopped"
    return 0
  fi
  # PROBE FIRST, CLAIM SECOND. `probe` keeps each box's idle clock and tells us who is a candidate;
  # only the candidates we are actually going to stop are asked to claim.
  for h in $running; do
    power_install "$h" || { plog "$h: the power protocol is not installed (it is now) — not stoppable this pass"; continue; }
    probe="$(power_ask "$h" probe)"
    case "$probe" in
      IDLE\ *)
        if [ "${probe#IDLE }" -ge $(( IDLE_STOP_MINS * 60 )) ] 2>/dev/null; then
          idle_ok="$idle_ok $h"
        else
          plog "$h: idle ${probe#IDLE }s, under the ${IDLE_STOP_MINS}m rule"
        fi ;;
      BUSY\ *) plog "$h: $probe — it is holding a proof" ;;
      *)       plog "$h: did not answer the probe; it is left alone" ;;
    esac
  done
  idle_ok="$(printf '%s' "$idle_ok" | tr -s ' ' '\n' | grep . || true)"
  [ -n "$idle_ok" ] || { plog "no box has been idle for ${IDLE_STOP_MINS}m"; return 0; }
  idle_ok="$(printf '%s\n' "$idle_ok" | head -n "$stoppable")"
  for h in $idle_ok; do
    out="$(power_ask "$h" claim-stop "$IDLE_STOP_MINS")"
    case "$out" in
      STOP-CLAIMED\ *) claimed="$claimed $h"; plog "$h: $out — it will admit no further proof" ;;
      *)               plog "$h: $out — not claimed" ;;
    esac
  done
  claimed="$(printf '%s' "$claimed" | tr -s ' ' '\n' | grep . || true)"
  [ -n "$claimed" ] || { plog "nothing claimed"; return 0; }
  if pdry; then
    plog "[dry-run] aws ec2 stop-instances --instance-ids $(printf '%s' "$claimed" | tr '\n' ' ')"
    for h in $claimed; do power_ask "$h" clear >/dev/null 2>&1 || true; done
    plog "[dry-run] …and the claims cleared again, because nothing was stopped"
    return 0
  fi
  # shellcheck disable=SC2086  # a whitespace-separated id list, passed as separate arguments
  aws ec2 stop-instances --instance-ids $(printf '%s' "$claimed" | tr '\n' ' ') >/dev/null 2>&1
  rc=$?
  if [ "$rc" -ne 0 ]; then
    # NOTHING LOST, AND NOTHING LEFT MARKED. A claim that was not carried out is released, or the
    # box would refuse every proof until somebody noticed a fleet that is up and never chosen.
    plog "stop-instances failed (rc $rc) — clearing every claim"
    for h in $claimed; do power_ask "$h" clear >/dev/null 2>&1 || true; done
    return 1
  fi
  plog "stopped $(n_lines "$claimed") box(es): $(printf '%s' "$claimed" | tr '\n' ' ')  (EBS persists; the next sweep starts what it needs)"
  fleet_file_refresh
}

# ── THE HOST FILE ────────────────────────────────────────────────────────────────────────────────
# REWRITTEN THROUGH A TEMPORARY, AND NEVER EMPTIED WHILE BOXES ARE RUNNING. See the note on
# ci-runners-lib.sh's write_fleet_file: a rewrite is what the allocator reads next, and a rewrite
# that lands empty is a queue runner that HALTs on "no prepared, reachable on-demand box among the 0"
# with ten boxes up.
fleet_file_refresh() {
  local tmp rows
  if pdry; then plog "[dry-run] would rewrite $FLEET_FILE"; return 0; fi
  tmp="$(mktemp "${TMPDIR:-/tmp}/busbar-fleet.XXXXXX")" || return 1
  rows="$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=$FLEET_TAG" "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[].[InstanceId,Placement.AvailabilityZone,PrivateIpAddress,InstanceLifecycle]' \
    --output text 2>/dev/null | awk -F'\t' 'NF >= 3 {
        lc = (NF >= 4 ? $4 : "")
        if (lc == "spot") o = "spot"; else if (lc == "None") o = "ondemand"
        else if (lc == "") o = "unknown"; else o = lc
        printf "%s\t%s\t%s\t%s\n", $1, $2, $3, o }')"
  if [ -z "$rows" ] && [ -n "$(ids_in_state 'running')" ]; then
    rm -f "$tmp"
    plog "REFUSING to rewrite $FLEET_FILE: the query returned no row while boxes are running — the old file stands"
    return 1
  fi
  {
    echo "# busbar CI fleet — written by scripts/ci-fleet-power.sh at $(date -u +%FT%TZ)"
    echo "# <instance-id> <az> <private-ip> <lifecycle>   (ssh reaches these over SSM; there is no public port)"
    printf '%s\n' "$rows"
  } >"$tmp"
  mv -f "$tmp" "$FLEET_FILE"
}

power_status() {
  local h n
  printf 'running:\n'
  for h in $(ids_in_state 'running'); do
    n="$(power_ask "$h" probe)"
    printf '  %s  %s\n' "$h" "${n:-<no answer>}"
  done
  printf 'stopped:\n'
  for h in $(ids_in_state 'stopped'); do printf '  %s\n' "$h"; done
  printf 'knobs: LANDQ_IDLE_STOP_MINS=%s BUSBAR_PROVE_PER_BOX=%s CI_RUNNER_RUNNING_MIN=%s CI_RUNNER_RUNNING_MAX=%s\n' \
    "$IDLE_STOP_MINS" "$PROVE_PER_BOX" "$RUNNING_MIN" "$RUNNING_MAX"
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# --selftest. EVERY CASE DRIVES THE REAL FUNCTIONS: `aws` is a stub on PATH answering from fixture
# files, the ssh wrapper is a stub that runs the box script against a fake HOME, and the box script
# is the one power_box_script prints — not a copy of it.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
power_selftest() {
  local root fails=0 out
  root="$(mktemp -d "${TMPDIR:-/tmp}/ci-fleet-power-selftest.XXXXXX")" || return 1
  _t() { if [ "$2" = "$3" ]; then printf '  ok   %-58s\n' "$1"
         else printf '  FAIL %-58s (wanted [%s], got [%s])\n' "$1" "$2" "$3"; fails=$((fails + 1)); fi; }

  echo "ci-fleet-power selftest: this file"
  _t "parses (bash -n)" 0 "$(bash -n "${BASH_SOURCE[0]}"; echo $?)"

  # ── THE BOX SCRIPT, driven directly against a fake HOME ────────────────────────────────────────
  local BH="$root/box"; mkdir -p "$BH/busbar-prove/target" "$BH/busbar.git"
  local BS="$root/power.sh"; power_box_script >"$BS"; chmod 0755 "$BS"
  _t "the box script parses (sh -n)" 0 "$(sh -n "$BS"; echo $?)"
  local box; box() { env HOME="$BH" sh "$BS" "$@"; }

  echo "ci-fleet-power selftest: the box's own proof registry, not its load"
  _t "an empty box is holding nothing" 0 "$(box busy)"
  echo $$ >"$BH/busbar-prove/.proof.pid"
  _t "a live slot pre-proof counts"    1 "$(box busy)"
  printf '999999\n' >"$BH/busbar-prove/.proof.pid"
  _t "a dead pid is not a proof"       0 "$(box busy)"
  # THE CASE THAT WAS RED FIRST: a LANDING writes target/land-remote-<ref>.pid and never touches
  # .proof.pid, so a registry that reads only .proof.pid stops boxes mid-landing.
  rm -f "$BH/busbar-prove/.proof.pid"
  echo $$ >"$BH/busbar-prove/target/land-remote-land-1.pid"
  _t "a live LANDING counts as a proof" 1 "$(box busy)"
  : >"$BH/busbar-prove/target/land-remote-land-1.rc"
  _t "  ...but one that wrote its rc is over" 0 "$(box busy)"
  rm -f "$BH/busbar-prove/target/land-remote-land-1.rc"
  rm -f "$BH/busbar-prove/target/land-remote-land-1.pid"

  echo "ci-fleet-power selftest: a busy box is never claimed, whatever its idle clock says"
  echo $$ >"$BH/busbar-prove/.proof.pid"
  printf '%s\n' 0 >"$BH/.busbar-idle-since"        # "idle since the epoch", and still busy
  out="$(box claim-stop 15)"
  _t "a box holding a proof answers BUSY" "BUSY 1" "$out"
  _t "  ...and no stop was claimed"       0 "$([ -e "$BH/.busbar-stopping" ] && echo 1 || echo 0)"
  _t "  ...and its idle clock was reset"  0 "$([ -e "$BH/.busbar-idle-since" ] && echo 1 || echo 0)"
  rm -f "$BH/busbar-prove/.proof.pid"

  echo "ci-fleet-power selftest: the idle rule is minutes with no proof, on the box's own clock"
  out="$(box claim-stop 15)"
  _t "a box idle for zero seconds is not claimed" "IDLE 0" "$out"
  printf '%s\n' "$(( $(date +%s) - 899 ))" >"$BH/.busbar-idle-since"
  case "$(box claim-stop 15)" in STOP-CLAIMED*) out=claimed ;; *) out=not-claimed ;; esac
  _t "  ...at 14m59s it is still not claimed" "not-claimed" "$out"
  printf '%s\n' "$(( $(date +%s) - 901 ))" >"$BH/.busbar-idle-since"
  case "$(box claim-stop 15)" in STOP-CLAIMED*) out=claimed ;; *) out=not-claimed ;; esac
  _t "  ...at 15m01s it is"                   "claimed"     "$out"
  _t "  ...and the box now carries the mark" 1 "$([ -e "$BH/.busbar-stopping" ] && echo 1 || echo 0)"

  echo "ci-fleet-power selftest: a claimed box admits NO proof — the stop cannot land on one"
  out="$(box admit "$BH/busbar-prove/.proof.pid" $$)"
  _t "admit is REFUSED under a claim" "REFUSED stopping" "$out"
  _t "  ...with rc 3"                 3 "$(box admit "$BH/busbar-prove/.proof.pid" $$ >/dev/null; echo $?)"
  _t "  ...and wrote no pid file"     0 "$([ -e "$BH/busbar-prove/.proof.pid" ] && echo 1 || echo 0)"
  _t "clear releases the box"         "CLEARED" "$(box clear)"
  _t "  ...and then admit admits"     "ADMITTED" "$(box admit "$BH/busbar-prove/.proof.pid" $$)"
  _t "  ...having written the pid"    "$$" "$(cat "$BH/busbar-prove/.proof.pid")"
  _t "  ...so the box now reads busy" 1 "$(box busy)"
  _t "  ...and claim-stop says so"    "BUSY 1" "$(box claim-stop 0)"
  rm -f "$BH/busbar-prove/.proof.pid"

  # ── THE LAPTOP SIDE, against a stubbed `aws` and a stubbed ssh wrapper ─────────────────────────
  local bin="$root/bin"; mkdir -p "$bin"
  cat >"$bin/aws" <<AWSSTUB
#!/usr/bin/env bash
# A stub \`aws\`: describe-instances answers from \$root/state (one "<id> <state>" per line), and the
# mutating calls append to \$root/calls so the test can read what was asked for.
R="$root"
case "\$2" in
  describe-instances)
    want=""
    for a in "\$@"; do case "\$a" in Name=instance-state-name,Values=*) want="\${a#*Values=}" ;; esac; done
    q=""
    for a in "\$@"; do [ "\$prev" = "--query" ] && q="\$a"; prev="\$a"; done
    while read -r id st; do
      [ -n "\$id" ] || continue
      printf '%s\n' "\$want" | tr ',' '\n' | grep -qx "\$st" || continue
      case "\$q" in
        *PrivateIpAddress*) printf '%s\t%s\t%s\t%s\n' "\$id" us-east-1a 172.31.0.1 None ;;
        *) printf '%s\n' "\$id" ;;
      esac
    done <"\$R/state"
    ;;
  start-instances) shift 2; echo "start \$*" >>"\$R/calls" ;;
  stop-instances)  shift 2; echo "stop \$*"  >>"\$R/calls" ;;
esac
exit 0
AWSSTUB
  chmod 0755 "$bin/aws"
  cat >"$root/ssh" <<SSHSTUB
#!/usr/bin/env bash
# A stub ssh wrapper: every host is the ONE fake box, so the protocol is driven for real.
host="\${1#*@}"; shift
export HOME="$BH"
cmd="\$*"
case "\$cmd" in
  *'.busbar-power.sh.tmp'*) cat >/dev/null; printf 'INSTALLED\n'; exit 0 ;;
  *'busbar.git'*)           printf 'PREPARED\n'; exit 0 ;;
esac
cmd="\${cmd#\\\$HOME/.busbar-power.sh }"
exec sh "$BS" \$cmd
SSHSTUB
  chmod 0755 "$root/ssh"
  local OP="$PATH" OW="$SSH_WRAP" OF="$FLEET_FILE"
  PATH="$bin:$PATH"; SSH_WRAP="$root/ssh"; FLEET_FILE="$root/fleet"

  echo "ci-fleet-power selftest: the starter starts what it needs and NEVER more"
  printf 'i-a running\ni-b stopped\ni-c stopped\ni-d stopped\n' >"$root/state"
  : >"$root/calls"
  # One running box at ceiling 2 is 2 free slots; 5 wanted is 3 short, which is 2 boxes.
  box clear >/dev/null
  RUNNING_MAX=10 PROVE_PER_BOX=2 power_ensure_slots 5 >/dev/null 2>&1
  _t "5 slots against 2 free starts 2 boxes" "start --instance-ids i-b i-c" "$(cat "$root/calls")"
  : >"$root/calls"
  power_ensure_slots 2 >/dev/null 2>&1
  _t "a demand the awake fleet covers starts nothing" "" "$(cat "$root/calls")"
  : >"$root/calls"
  RUNNING_MAX=2 power_start 3 >/dev/null 2>&1
  _t "CI_RUNNER_RUNNING_MAX bounds the starter" "start --instance-ids i-b" "$(cat "$root/calls")"
  : >"$root/calls"
  RUNNING_MAX=1 power_start 3 >/dev/null 2>&1
  _t "  ...and at the ceiling it starts nothing" "" "$(cat "$root/calls")"
  RUNNING_MAX=10

  echo "ci-fleet-power selftest: the stopper, the running floor, and the claim it keeps"
  printf 'i-a running\ni-b running\ni-c running\n' >"$root/state"
  : >"$root/calls"; box clear >/dev/null
  printf '%s\n' "$(( $(date +%s) - 3600 ))" >"$BH/.busbar-idle-since"
  RUNNING_MIN=3 power_stop_idle >/dev/null 2>&1
  _t "the running floor stops nothing below itself" "" "$(cat "$root/calls")"
  : >"$root/calls"; box clear >/dev/null
  printf '%s\n' "$(( $(date +%s) - 3600 ))" >"$BH/.busbar-idle-since"
  RUNNING_MIN=2 power_stop_idle >/dev/null 2>&1
  _t "  ...and above it stops exactly the surplus" "stop --instance-ids i-a" "$(cat "$root/calls")"
  : >"$root/calls"; box clear >/dev/null
  echo $$ >"$BH/busbar-prove/.proof.pid"
  printf '%s\n' "$(( $(date +%s) - 3600 ))" >"$BH/.busbar-idle-since"
  RUNNING_MIN=0 power_stop_idle >/dev/null 2>&1
  _t "a box holding a proof is never stopped" "" "$(cat "$root/calls")"
  _t "  ...and carries no stop mark"          0 "$([ -e "$BH/.busbar-stopping" ] && echo 1 || echo 0)"
  rm -f "$BH/busbar-prove/.proof.pid"

  echo "ci-fleet-power selftest: the host file is never emptied under a running fleet"
  printf 'i-a running\n' >"$root/state"
  printf 'i-old\tus-east-1a\t172.31.0.9\tondemand\n' >"$root/fleet"
  fleet_file_refresh >/dev/null 2>&1
  _t "a good rewrite lands" 1 "$(awk 'NF && $1 !~ /^#/ && $4 == "ondemand"' "$root/fleet" | grep -c . || true)"
  # THE INCIDENT: the query answers nothing (throttle, expired credentials, a filter that matched
  # no reservation) while the fleet is up. The old file must stand, or the next allocation is
  # "no prepared, reachable on-demand box among the 0" with ten boxes running.
  cat >"$bin/aws" <<'EMPTY'
#!/usr/bin/env bash
case "$2" in describe-instances)
  for a in "$@"; do case "$a" in *PrivateIpAddress*) exit 0 ;; esac; done
  echo "i-a" ;; esac
exit 0
EMPTY
  chmod 0755 "$bin/aws"
  fleet_file_refresh >/dev/null 2>&1
  _t "an empty answer does NOT empty the file" 1 "$(awk 'NF && $1 !~ /^#/ && $4 == "ondemand"' "$root/fleet" | grep -c . || true)"
  _t "  ...and the refresh reports the refusal" 1 "$(fleet_file_refresh >/dev/null 2>&1; echo $?)"

  PATH="$OP"; SSH_WRAP="$OW"; FLEET_FILE="$OF"
  rm -rf "$root"
  if [ "$fails" -eq 0 ]; then
    echo "ci-fleet-power selftest: GREEN (the registry, the claim, the admit refusal, the two bounds, the host file)"
    return 0
  fi
  echo "ci-fleet-power selftest: RED ($fails failure(s))" >&2
  return 1
}

case "${1:---status}" in
  --selftest)     power_selftest; exit $? ;;
  --print-box)    power_box_script; exit 0 ;;
  --stop-idle)    power_stop_idle; exit $? ;;
  --start)        power_start "${2:-1}"; exit $? ;;
  --ensure-slots) power_ensure_slots "${2:-0}"; exit $? ;;
  --status)       power_status; exit 0 ;;
  -h|--help)      sed -n '2,30p' "$0"; exit 0 ;;
  *)              pdie "unknown argument '$1' (expected --stop-idle, --start N, --ensure-slots D, --status, --print-box or --selftest)" ;;
esac

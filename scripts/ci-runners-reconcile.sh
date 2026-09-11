#!/usr/bin/env bash
# THE RECONCILE IS THE TRUTH ABOUT THE FLEET. Run it every fifteen minutes and the fleet is what
# CI_RUNNER_COUNT + CI_RUNNER_ONDEMAND_FLOOR say it is, with no ghost registrations, no stale host
# list, and no box that came up an hour ago and never registered.
#
#   ./scripts/ci-runners-reconcile.sh                  # the 15-minute pass (idempotent, exit 0)
#   ./scripts/ci-runners-reconcile.sh --converge       # …and re-apply the bootstrap to every box
#   ./scripts/ci-runners-reconcile.sh --converge --restart   # …and restart the agents (KILLS JOBS)
#   ./scripts/ci-runners-reconcile.sh --no-remote      # skip the remote-prove checkout refresh
#   CI_RUNNER_DRY_RUN=1 ./scripts/ci-runners-reconcile.sh     # print the calls, make none
#
# WHY THIS SCRIPT IS THE ANSWER AND `up.sh` IS NOT. On 2026-09-09 the fleet hit zero twice inside
# one day. The first time was the nightly stop; the second was `instance-terminated-no-capacity`
# taking all eight c7a.8xlarge in us-east-1a at once. In BOTH cases the recovery required a human to
# notice — `ci-runners-up.sh` is a command someone runs, not a schedule — and in both cases the
# fleet left thirty-two offline registrations behind, each one a routing black hole that absorbs a
# job and holds it `queued` for twenty-four hours with no error anywhere.
#
# A fleet whose recovery depends on someone noticing is a fleet that is down for as long as nobody
# is looking. So this is written to be a TIMER: idempotent, a no-op when healthy, and exit 0 no
# matter which leg had nothing to do, because a cron that pages on a healthy run is a cron that gets
# muted. Every pass, in this order:
#
#   1. TOP UP.      Spot to CI_RUNNER_COUNT, on-demand to CI_RUNNER_ONDEMAND_FLOOR, counted
#                   separately off `InstanceLifecycle`. Diversified across every AZ and instance
#                   type the region offers (see launch_spot in ci-runners-lib.sh).
#   2. SWEEP.       Delete every OFFLINE org registration whose instance no longer exists.
#   3. REGISTER.    …and only then register the boxes that are short of agents.
#   4. REFRESH.     ~/.busbar-fleet and the remote-prove bare repo + checkout on every box.
#
# THE ORDER OF 2 AND 3 IS LOAD-BEARING. Registering first means the new box's agents join a pool
# that still contains the dead box's agents, and GitHub keeps routing jobs into the corpse — which
# is exactly the morning the nightly stop produced. Sweep the dead, then add the living.
#
# THE SWEEP CHECKS EXISTENCE, NOT OFFLINE-NESS. A box eight minutes into its bootstrap is offline
# and alive; deleting its registration on a 15-minute timer would make a real box unreachable and
# the next pass would "fix" it by registering it again, forever. sweep_ghost_runners maps the runner
# name back to the instance id the bootstrap minted it from and deletes only what EC2 no longer
# lists in any state.
#
# CONVERGENCE IS NOW OPT-IN (`--converge`). It is the same payload it always was — the way a fix
# found at 04:00 reaches the boxes at 04:01 without a ten-minute bootstrap per box that also throws
# away the warm target/ and sccache. But it is an apt install, a rustup check and a 900-second SSM
# window on every box, which is not a thing to do four times an hour on a healthy fleet.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci-runners-lib.sh
. "$HERE/ci-runners-lib.sh"

CONVERGE=0
RESTART=0
REMOTE=1
SELFTEST=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --converge)  CONVERGE=1 ;;
    --restart)   RESTART=1; CONVERGE=1 ;;   # a restart with no convergence is just an outage
    --no-remote) REMOTE=0 ;;
    --selftest)  SELFTEST=1 ;;
    *)           die "unknown argument '$1' (expected --converge, --restart, --no-remote or --selftest)" ;;
  esac
  shift
done

# ── --selftest: the one rule this script must never lose ────────────────────────────────────────
# It runs BEFORE require_aws, because a check on the text of the refresh command needs no fleet, no
# credentials and no `gh` — and a selftest that cannot be run on a laptop is a selftest nobody runs.
reconcile_selftest() {
  local fails=0
  _t() { if [ "$2" = "$3" ]; then printf '  ok   %-52s\n' "$1"
         else printf '  FAIL %-52s (wanted [%s], got [%s])\n' "$1" "$2" "$3"; fails=$((fails + 1)); fi; }
  echo "ci-runners-reconcile selftest: the SSM refresh never prunes a live run's refs"
  # THE PATTERNS ARE BRACKETED SO THEY DO NOT MATCH THEIR OWN SOURCE LINE. `grep`ing this file for
  # the string the check forbids finds the check itself, reads 1, and is red forever — or, worse,
  # is "fixed" by loosening it until it can never be red at all.
  _t "the refresh does not prune refs/heads" 0 \
     "$(grep -c 'fetch -q --prun[e] origin' "${BASH_SOURCE[0]}")"
  _t "  ...it mirrors origin plainly"        1 \
     "$(grep -c 'git -C busbar.git fetch -q ori[g]in' "${BASH_SOURCE[0]}")"
  _t "  ...and no other leg prunes heads"    0 \
     "$(grep -c -- '--prun[e] origin' "${BASH_SOURCE[0]}")"
  # ── THE FLOOR COUNTS A STOPPED BOX, AND THE PASS RUNS THE IDLE STOPPER ───────────────────────
  # Both are about the same arithmetic: what the fleet HAS versus what is AWAKE. Reading the floor
  # off `pending,running` would launch a replacement for every box the stopper just put to sleep.
  echo "ci-runners-reconcile selftest: the floor counts what the fleet HAS, not what is awake"
  _t "the top-up counts REGISTERED on-demand boxes" 1 \
     "$(grep -c 'have_od="\$(n_of "\$(fleet_registered_onde[m]and_ids)")"' "${BASH_SOURCE[0]}")"
  _t "  ...and the same for spot"                   1 \
     "$(grep -c 'have_spot="\$(n_of "\$(fleet_registered_sp[o]t_ids)")"' "${BASH_SOURCE[0]}")"
  # ── THE BAN IS ON EVERY SCRIPT, NOT JUST THIS ONE ────────────────────────────────────────────
  # A ban that greps only "${BASH_SOURCE[0]}" proves the one file it was fixed in and nothing
  # else — a scripted RE-INTRODUCTION of the awake-only pair one file over (ci-runners-up.sh,
  # ci-runners-down.sh, or a new caller) sails through GREEN. The awake-only names
  # (`fleet_ond[e]mand_ids`, `fleet_sp[o]t_ids`) were deleted from ci-runners-lib.sh entirely, so
  # their bare re-appearance anywhere under scripts/ci-runners-*.sh — a call, or the function
  # definition coming back — is itself the defect. `fleet_registered_ondemand_ids` /
  # `fleet_registered_spot_ids` do not contain either substring, so this cannot self-match the
  # fixed names.
  _t "no scripts/ci-runners-*.sh calls the awake-only on-demand query" 0 \
     "$(grep -hc 'fleet_onde[m]and_ids' "$HERE"/ci-runners-*.sh | awk '{s+=$1} END{print s+0}')"
  _t "  ...or the awake-only spot query"                              0 \
     "$(grep -hc 'fleet_sp[o]t_ids' "$HERE"/ci-runners-*.sh | awk '{s+=$1} END{print s+0}')"
  _t "the summary reports awake against the ceiling" 1 \
     "$(grep -c 'awake, online runn[e]rs' "${BASH_SOURCE[0]}")"
  echo "ci-runners-reconcile selftest: the idle stopper runs on the timer, not when someone remembers"
  _t "the pass calls the stopper"                   1 \
     "$(grep -c 'ci-fleet-po[w]er.sh" --stop-idle' "${BASH_SOURCE[0]}")"
  _t "  ...on the plain 15-minute path, not under --converge" 1 \
     "$([ "$(grep -n 'ci-fleet-po[w]er.sh" --stop-idle' "${BASH_SOURCE[0]}" | cut -d: -f1)" \
        -lt "$(grep -n '^if \[ "\$CONVERGE" = 1 \]; then' "${BASH_SOURCE[0]}" | cut -d: -f1)" ] && echo 1 || echo 0)"
  _t "  ...and an operator can turn it off"         1 \
     "$(grep -c 'CI_RUNNER_POW[E]R:-1' "${BASH_SOURCE[0]}")"
  _t "the stopper's own selftest is green"          0 \
     "$(bash "$HERE/ci-fleet-power.sh" --selftest >/dev/null 2>&1; echo $?)"

  if [ "$fails" -eq 0 ]; then echo "ci-runners-reconcile selftest: GREEN (the SSM refresh without --prune; the floor counts a stopped box; the idle stopper is on the timer)"; return 0; fi
  echo "ci-runners-reconcile selftest: RED ($fails failure(s))" >&2; return 1
}
[ "$SELFTEST" = 1 ] && { reconcile_selftest; exit $?; }

require_aws
command -v gh >/dev/null || die "gh is required (the sweep and the registration check both use it)"
dry && log "DRY RUN: read-only describes still run; nothing will be launched, deleted or registered"

# ── 1. Top up ───────────────────────────────────────────────────────────────────────────────────
# THE FLOOR IS A FLOOR OF *REGISTERED* BOXES, AND A STOPPED BOX IS REGISTERED. It keeps its EBS
# volume (the bare repo, the shared checkout, the warm target/, the sccache), its instance id and
# its runner registrations, and scripts/ci-fleet-power.sh has it proving again in 60-90 s. Counting
# only the awake ones here would launch a brand-new box for every box the idle stopper just put to
# sleep: the whole saving spent on replacements, each one ten minutes from being useful, and the
# stopped originals still on the bill for their EBS. What may be AWAKE at once is a separate knob,
# CI_RUNNER_RUNNING_MAX, and that is the one that bounds the hourly cost.
have_od="$(n_of "$(fleet_registered_ondemand_ids)")"
have_spot="$(n_of "$(fleet_registered_spot_ids)")"
awake="$(n_of "$(fleet_instance_ids)")"
log "fleet: spot $have_spot/$COUNT, on-demand $have_od/$FLOOR registered ($awake awake, max $RUNNING_MAX)"

launched=""
want_od=$(( FLOOR - have_od ))
if [ "$want_od" -gt 0 ]; then
  log "on-demand floor short by $want_od — launching"
  launched="$launched $(launch_ondemand "$want_od")"
fi
want_spot=$(( COUNT - have_spot ))
if [ "$want_spot" -gt 0 ]; then
  log "spot short by $want_spot — launching, diversified"
  launched="$launched $(launch_spot "$want_spot")"
fi
launched="$(printf '%s' "$launched" | tr -s ' ' ' ' | sed -e 's/^ //' -e 's/ $//')"
[ -n "$launched" ] && log "launched: $launched"

# A launched box is not a usable box for another 8-12 minutes (apt, rustup, the runner tarballs and
# the pre-warm build). It is deliberately NOT waited for: this pass records that capacity was asked
# for, and the pass fifteen minutes from now registers it. Blocking here is how a 15-minute timer
# becomes two overlapping 15-minute timers.
[ -n "$launched" ] && log "(new boxes bootstrap for ~8-12 min; the next pass registers them)"

# ── 1b. POWER: put the idle boxes to sleep, and never run more than the ceiling ─────────────────
# THIS IS THE TIMER THE STOPPER WANTED. $569 was measured for eighteen boxes that were mostly idle,
# and the constraint was never CPU — it was proof SLOTS, two per box, with a battery that took one
# core. A box that has held no proof for LANDQ_IDLE_STOP_MINS is STOPPED, not terminated: EBS
# persists, the bill falls to gp3 storage alone, and the next sweep starts what it needs.
#
# IT CANNOT STOP A PROOF. ci-fleet-power.sh asks each box its OWN PROOF REGISTRY under the box's own
# lock — the lock a proof takes to announce itself — and a box it claims refuses to admit any
# further proof before it is stopped. Nothing here needs to know that; what this pass must not do is
# skip it, because a stopper that only runs when someone remembers is the nightly-stop lesson again
# with the sign reversed.
POWER_STATUS="skipped"
if [ "${CI_RUNNER_POWER:-1}" = 1 ] && [ -x "$HERE/ci-fleet-power.sh" ]; then
  POWER_STATUS="$(bash "$HERE/ci-fleet-power.sh" --stop-idle 2>&1 | tail -1)"
  log "power: $POWER_STATUS"
  awake="$(n_of "$(fleet_instance_ids)")"
  if [ "$awake" -gt "$RUNNING_MAX" ]; then
    # Not an error and not something this pass forces: a box above the ceiling is a box holding a
    # proof (the stopper refused it) or a box inside its idle window. Both resolve themselves on
    # the next pass, and neither is worth killing work over.
    log "power: $awake box(es) awake, above CI_RUNNER_RUNNING_MAX=$RUNNING_MAX — the surplus is proving or still inside its idle window; the next pass re-asks"
  fi
fi

# ── 2. Sweep the ghosts, BEFORE registering anything ────────────────────────────────────────────
sweep_ghost_runners
[ "$SWEPT_GHOSTS" -gt 0 ] && log "swept $SWEPT_GHOSTS ghost registration(s)"

# ── 3. Register the boxes that are short of agents ──────────────────────────────────────────────
# CHEAPLY, AND ONLY THE BOXES THAT NEED IT. The bootstrap names every agent `ec2-<id-minus-i->-<n>`,
# so the org's runner list answers "is this box registered?" without an SSM round-trip and without
# minting a token for seven boxes that already hold GitHub-issued credentials. Minting one per pass
# regardless is also how the org's token API limit gets exhausted.
ONLINE_NAMES="$(gh api --paginate "/orgs/${ORG}/actions/runners?per_page=100" \
  --jq '.runners[] | select(.status=="online") | .name' 2>/dev/null)"
IDS="$(fleet_instance_ids)"
NEEDY=""
# THE AGENTS ARE NUMBERED FROM 1, not from 0. ci-runner-bootstrap.sh's loop is `i=1; while
# [ "$i" -le "$AGENTS" ]` and the directories are /opt/runner-1 through /opt/runner-$AGENTS, so the
# names GitHub holds are ec2-<short>-1 … ec2-<short>-4. Counting from 0 made every box look one
# agent short, and the first dry run of this pass proposed re-registering a healthy eight-box fleet.
for iid in $IDS; do
  short="${iid#i-}"
  n=1
  while [ "$n" -le "$AGENTS" ]; do
    printf '%s\n' "$ONLINE_NAMES" | grep -qx "ec2-${short}-${n}" || { NEEDY="$NEEDY $iid"; break; }
    n=$(( n + 1 ))
  done
done
NEEDY="$(printf '%s' "$NEEDY" | sed -e 's/^ //' -e 's/ $//')"

REGISTERED=""
if [ -n "$NEEDY" ]; then
  # Only the ones SSM can reach. The rest are still bootstrapping and are the next pass's problem.
  REACHABLE="$(ssm_online "$NEEDY")"
  if [ -n "$REACHABLE" ]; then
    log "registering: $REACHABLE"
    # shellcheck disable=SC2086  # a whitespace-separated id list, passed as separate arguments
    "$HERE/ci-runners-register.sh" $REACHABLE >/dev/null 2>&1 || true

    # THE COUNT IS RE-DERIVED FROM GITHUB, NOT FROM THE EXIT CODE. THE SSM AGENT COMES UP LONG
    # BEFORE THE RUNNERS DO — a box answered SSM roughly a minute after launch while it was still
    # eight minutes from having unpacked /opt/runner-1, so this dispatched a registration to a box
    # with nothing to register, and the SSM command "succeeded". Reporting `registered 2` on that
    # pass was a summary line that said the fleet was fixed when nothing had changed, which is the
    # one failure mode a fleet summary must not have. So: ask the org what is online NOW.
    #
    # Dispatching early is otherwise harmless (busbar-runner-register is idempotent and skips an
    # agent that already holds a .runner credential) and costs one extra token mint per pass while
    # a box bootstraps. Being loudly honest about the outcome is worth more than avoiding that.
    AFTER="$(gh api --paginate "/orgs/${ORG}/actions/runners?per_page=100" \
      --jq '.runners[] | select(.status=="online") | .name' 2>/dev/null)"
    for iid in $REACHABLE; do
      short="${iid#i-}"; n=1; ok=1
      while [ "$n" -le "$AGENTS" ]; do
        printf '%s\n' "$AFTER" | grep -qx "ec2-${short}-${n}" || { ok=0; break; }
        n=$(( n + 1 ))
      done
      [ "$ok" = 1 ] && REGISTERED="$REGISTERED $iid"
    done
    REGISTERED="$(printf '%s' "$REGISTERED" | sed -e 's/^ //' -e 's/ $//')"
    if [ -z "$REGISTERED" ]; then
      log "  (still no agents online on those boxes — bootstrap is not finished; the next pass retries)"
    fi
  else
    log "short of agents but not SSM-reachable yet: $NEEDY"
  fi
fi

# ── 4. Refresh the host list and the remote-prove checkouts ─────────────────────────────────────
# ~/.busbar-fleet goes stale the moment a spot box is reclaimed, and a stale entry makes the
# round-robin allocator in ci-remote-lib.sh hand an agent a host that no longer exists — which
# surfaces as a `prove-remote.sh` that hangs in the SSM tunnel rather than as "that box is gone".
write_fleet_file
log "refreshed ${BUSBAR_FLEET_FILE:-$HOME/.busbar-fleet} ($(n_of "$(fleet_instance_ids)") host(s))"

REMOTE_STATUS="skipped"
if [ "$REMOTE" = 1 ]; then
  ALIVE="$(ssm_online "$IDS")"
  if [ -z "$ALIVE" ]; then
    log "no SSM-reachable box; skipping the remote-prove refresh"
  else
    # OVER SSM, NOT OVER SSH. This runs unattended, and the ssh path needs session-manager-plugin,
    # the fleet key and an interactive-ish transport; SendCommand needs the instance profile that is
    # already there. A NEW box therefore gets a warm bare repo without anyone running
    # `prove-remote.sh --setup` by hand.
    PUB=""
    [ -f "${FLEET_SSH_KEY:-$HOME/.ssh/busbar-ci-fleet}.pub" ] \
      && PUB="$(cat "${FLEET_SSH_KEY:-$HOME/.ssh/busbar-ci-fleet}.pub")"
    T="$(mktemp)"
    {
      printf '{"commands":['
      if [ -n "$PUB" ]; then
        # The public half only. The private key never leaves this machine and is never printed.
        printf '"install -d -m 0700 -o ubuntu -g ubuntu /home/ubuntu/.ssh; touch /home/ubuntu/.ssh/authorized_keys; grep -qF %s%s%s /home/ubuntu/.ssh/authorized_keys || echo %s%s%s >> /home/ubuntu/.ssh/authorized_keys; chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys; chmod 0600 /home/ubuntu/.ssh/authorized_keys",' \
          "'" "$PUB" "'" "'" "$PUB" "'"
      fi
      # Idempotent by construction: clone only when absent, fetch always. `git clean` is NOT done
      # here — that is prove-remote.sh's job immediately before a proof, and doing it on a timer
      # would delete a running proof's working tree out from under it.
      #
      # AND NEITHER IS `--prune`, FOR EXACTLY THE SAME REASON, ONE LEVEL UP. `--prune` over
      # `+refs/heads/*:refs/heads/*` deletes every ref under refs/heads that origin does not have —
      # which is precisely the set a live landing owns: `land-<stamp>-<pid>`, its `-base`, and the
      # `-landed` tip the box publishes when land.sh returns. This watchdog runs on a ~10-minute
      # timer against EVERY box, so it lands inside other people's runs by construction, and it is
      # the SSM half: ci-remote-lib.sh's own refresh was fixed and this one still ran with --prune,
      # so the greens kept vanishing. Measured 09-10: gate-mutants-2's 2.2 h GREEN discarded at
      # 06:39, and tree-reds' per-line outcome file gone at 09:09 — both mid-run, both with
      # refs/proof/* (outside this refspec, and so outside the prune) intact, which is the
      # fingerprint. A stale mirror costs objects on the next push; a pruned ref costs a proof.
      # shellcheck disable=SC2016  # $HOME and $(…) are for the REMOTE shell, not this one
      printf '"su - ubuntu -c %scd $HOME; test -d busbar.git || git clone --bare -q https://github.com/GetBusbar/busbar.git busbar.git; git -C busbar.git config gc.auto 256; git -C busbar.git fetch -q origin \\"+refs/heads/*:refs/heads/*\\" 2>/dev/null; test -d busbar-prove/.git || git clone -q busbar.git busbar-prove; git -C busbar-prove remote get-url prove >/dev/null 2>&1 || git -C busbar-prove remote add prove $HOME/busbar.git; git -C busbar-prove config user.name \\"busbar remote prove\\"; git -C busbar-prove config user.email ci@busbar.invalid; git -C busbar-prove config advice.detachedHead false%s; echo prove=$(su - ubuntu -c %sgit -C $HOME/busbar-prove rev-parse --short HEAD 2>/dev/null || echo MISSING%s)"' \
        "'" "'" "'" "'"
      printf ']}'
    } > "$T"
    if dry; then
      log "[dry-run] aws ssm send-command --instance-ids $ALIVE  # refresh ~/busbar.git + ~/busbar-prove"
      [ -n "$PUB" ] && log "[dry-run]   …and re-deliver the fleet ssh PUBLIC key"
      REMOTE_STATUS="dry-run"
    else
      # shellcheck disable=SC2086  # $ALIVE is a whitespace-separated id list and must word-split
      C="$(aws ssm send-command --instance-ids $ALIVE --document-name AWS-RunShellScript \
        --comment "refresh busbar remote-prove checkouts" --parameters "file://$T" \
        --timeout-seconds 600 --query 'Command.CommandId' --output text 2>/dev/null)"
      if [ -n "$C" ]; then
        # ssm_wait returns ONE STATUS PER INSTANCE, tab-separated. Pasting that straight into the
        # summary made the "one line" eight words wide and unreadable at a glance, which is the one
        # thing the summary line exists to avoid. Collapse to `<succeeded>/<total>`.
        raw="$(ssm_wait "$C" 12 10)"
        REMOTE_STATUS="$(printf '%s' "$raw" | tr -s '[:space:]' '\n' | grep -c '^Success$' || true)/$(n_of "$raw")"
        log "remote-prove refresh: $REMOTE_STATUS box(es) Success  [$raw]"
      else
        REMOTE_STATUS="dispatch-failed"
        log "remote-prove refresh: could not dispatch (not fatal)"
      fi
    fi
    rm -f "$T"
  fi
fi

# ── 5. Convergence, opt-in ──────────────────────────────────────────────────────────────────────
# Every item below was found by a real run failing. It is unchanged from when this script was only
# a converger; what changed is that it no longer runs on the timer path. IT ALSO REMOVES THE
# NIGHTLY STOP, unconditionally: that timer terminated the entire fleet at 02:00 PT with nothing
# scheduled to bring it back, and a box born before the default changed must not keep it by
# accident. Re-enable it deliberately, per box, only alongside something that starts the fleet.
if [ "$CONVERGE" = 1 ]; then
  CONV="$(ssm_online "$IDS")"
  if [ -z "$CONV" ]; then
    log "--converge: no SSM-reachable box"
  elif dry; then
    log "[dry-run] aws ssm send-command --instance-ids $CONV  # converge on ci-runner-bootstrap.sh"
  else
    log "converging: $CONV"
    TMP="$(mktemp)"
    cat > "$TMP" <<'JSON'
{"commands":[
 "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv >/dev/null 2>&1; python3 -m venv /tmp/vp >/dev/null 2>&1 && echo venv=ok || echo venv=BROKEN; rm -rf /tmp/vp",
 "if ! command -v gh >/dev/null; then V=$(curl -fsSL https://api.github.com/repos/cli/cli/releases/latest | jq -r .tag_name | tr -d v); [ -n \"$V\" ] && [ \"$V\" != null ] || V=2.82.1; curl -fsSL \"https://github.com/cli/cli/releases/download/v${V}/gh_${V}_linux_amd64.tar.gz\" | tar -xz -C /tmp && install -m 0755 /tmp/gh_${V}_linux_amd64/bin/gh /usr/local/bin/gh; fi; echo gh=$(gh --version 2>/dev/null | head -1)",
 "printf '#!/usr/bin/env bash\\nset -uo pipefail\\nif [ -n \"${RUNNER_WORKSPACE:-}\" ] && [ -d \"${RUNNER_WORKSPACE}\" ]; then find \"${RUNNER_WORKSPACE}\" -maxdepth 1 -mindepth 1 -name %s_temp*%s -exec rm -rf {} + 2>/dev/null || true; fi\\ndocker container prune -f --filter until=1h >/dev/null 2>&1 || true\\ndocker network   prune -f --filter until=1h >/dev/null 2>&1 || true\\ndocker volume    prune -f                   >/dev/null 2>&1 || true\\ndf -h / | tail -1 || true\\nexit 0\\n' \"'\" \"'\" > /opt/job-started-hook.sh; chmod 0755 /opt/job-started-hook.sh; bash -e /opt/job-started-hook.sh >/dev/null 2>&1 && echo hook=ok || echo hook=STILL-FAILS",
 "su - ubuntu -c 'test -x ~/.cargo/bin/rustup || (curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal --default-toolchain 1.98.0 -c clippy -c rustfmt >/dev/null 2>&1)'; echo base-cargo=$(su - ubuntu -c '~/.cargo/bin/cargo --version' 2>&1 | head -1)",
 "for d in /opt/runner-*; do n=${d##*-}; install -d -o ubuntu -g ubuntu $d/.cargo $d/.rustup $d/sccache; cp -an /home/ubuntu/.rustup/. $d/.rustup/ 2>/dev/null; cp -an /home/ubuntu/.cargo/. $d/.cargo/ 2>/dev/null; chown -R ubuntu:ubuntu $d/.cargo $d/.rustup $d/sccache; sed -i -e '/^PATH=/d' -e '/^CARGO_HOME=/d' -e '/^RUSTUP_HOME=/d' -e '/^SCCACHE_DIR=/d' -e '/^SCCACHE_CACHE_SIZE=/d' -e '/^SCCACHE_SERVER_PORT=/d' -e '/^SCCACHE_BUCKET=/d' -e '/^SCCACHE_REGION=/d' -e '/^SCCACHE_S3_KEY_PREFIX=/d' -e '/^ACTIONS_RUNNER_HOOK_JOB_STARTED=/d' $d/.env; printf 'PATH=%s/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\\nCARGO_HOME=%s/.cargo\\nRUSTUP_HOME=%s/.rustup\\nSCCACHE_DIR=%s/sccache\\nSCCACHE_CACHE_SIZE=20G\\nSCCACHE_SERVER_PORT=%s\\nACTIONS_RUNNER_HOOK_JOB_STARTED=/opt/job-started-hook.sh\\n' $d $d $d $d $((4226+n)) >> $d/.env; done; echo envs=written",
 "systemctl disable --now busbar-runner-nightly-stop.timer >/dev/null 2>&1; rm -f /etc/systemd/system/busbar-runner-nightly-stop.timer /etc/systemd/system/busbar-runner-nightly-stop.service; systemctl daemon-reload; echo nightly-stop=$(systemctl is-enabled busbar-runner-nightly-stop.timer 2>&1 | head -1)",
 "echo agents=$(ls -d /opt/runner-* 2>/dev/null | wc -l) ready=$( [ -f /var/run/busbar-runner-ready ] && echo yes || echo NO )"
]}
JSON
    # shellcheck disable=SC2086  # $CONV is a whitespace-separated id list and must word-split
    CMD_ID="$(aws ssm send-command --instance-ids $CONV --document-name AWS-RunShellScript \
      --comment "converge busbar CI runner boxes" --parameters "file://$TMP" \
      --timeout-seconds 900 --query 'Command.CommandId' --output text)"
    rm -f "$TMP"
    if [ -n "$CMD_ID" ]; then
      log "converge: $(ssm_wait "$CMD_ID" 90 10)"
      for i in $CONV; do
        printf '  %s: ' "$i"
        aws ssm get-command-invocation --command-id "$CMD_ID" --instance-id "$i" \
          --query 'StandardOutputContent' --output text 2>/dev/null | tr '\n' ' ' | cut -c1-200
        echo
      done
    else
      log "converge: send-command failed"
    fi

    if [ "$RESTART" = 1 ]; then
      # `svc.sh stop` KILLS THE JOB IN FLIGHT, and the run then reports `failure` with NO failed
      # step, which is indistinguishable at a glance from a real red. Six jobs were lost this way.
      log "restarting the runner agents (THIS KILLS ANY JOB IN FLIGHT)"
      T2="$(mktemp)"
      cat > "$T2" <<'JSON'
{"commands":["for d in /opt/runner-*; do (cd $d && ./svc.sh stop >/dev/null 2>&1; ./svc.sh start >/dev/null 2>&1); done; sleep 2; systemctl list-units 'actions.runner.*' --no-legend | wc -l"]}
JSON
      # shellcheck disable=SC2086  # $CONV is a whitespace-separated id list and must word-split
      C2="$(aws ssm send-command --instance-ids $CONV --document-name AWS-RunShellScript \
        --parameters "file://$T2" --query 'Command.CommandId' --output text)"
      rm -f "$T2"
      [ -n "$C2" ] && log "restart: $(ssm_wait "$C2" 30 8)"
    fi
  fi
fi

# ── The one line ────────────────────────────────────────────────────────────────────────────────
# One line, because this runs on a timer and the thing an operator scrolls a log for is "was the
# fleet what it should have been". The counts are re-read from EC2 AFTER the pass rather than
# inferred from what was launched: a RunInstances that returned an id and then failed its capacity
# check is not a box.
now_od="$(n_of "$(fleet_registered_ondemand_ids)")"
now_spot="$(n_of "$(fleet_registered_spot_ids)")"
now_awake="$(n_of "$(fleet_instance_ids)")"
now_runners="$(n_of "$(gh api --paginate "/orgs/${ORG}/actions/runners?per_page=100" \
  --jq '.runners[] | select(.status=="online") | .name' 2>/dev/null)")"
printf 'reconcile: spot %s/%s, on-demand %s/%s registered, %s/%s awake, online runners %s, swept ghosts %s, registered %s, remote-prove %s\n' \
  "$now_spot" "$COUNT" "$now_od" "$FLOOR" "$now_awake" "$RUNNING_MAX" "$now_runners" "$SWEPT_GHOSTS" \
  "$(n_of "$REGISTERED")" "$REMOTE_STATUS"

# ALWAYS ZERO. A healthy pass, a pass that could not reach a bootstrapping box, and a pass that
# found nothing to do are all "the fleet is being kept" — and a timer that exits non-zero on any of
# them is a timer somebody disables by Thursday. Real breakage is visible in the summary line
# (spot 0/8 is not a healthy fleet) and in the log above it, not in the exit code.
exit 0

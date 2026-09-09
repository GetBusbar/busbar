#!/usr/bin/env bash
# Bring every RUNNING fleet box up to what ci-runner-bootstrap.sh says a box should be, without
# replacing it.
#
#   ./scripts/ci-runners-reconcile.sh              # every box, no service restart
#   ./scripts/ci-runners-reconcile.sh --restart    # …and restart the agents so .env takes effect
#
# WHY A RECONCILER AND NOT "JUST RELAUNCH". Two reasons, both observed.
#
# 1. A LAUNCH TEMPLATE VERSION CAN BE REFUSED WHILE THE FLEET SCALES ANYWAY. EC2 caps user-data at
#    16384 bytes; the version carrying a fix was rejected, the old version stayed default, and four
#    new boxes came up without the GitHub CLI, without python3-venv and without per-agent cargo
#    homes. ci-runners-up.sh now gzips and hard-fails on a refusal — but a fleet that is already in
#    that state needs a way out that is not "terminate everything mid-run".
# 2. A FIX FOUND AT 04:00 SHOULD REACH THE BOXES AT 04:01. Every item below was found by a real run
#    failing; a replacement cycle is ten minutes of bootstrap per box and throws away the warm
#    target/ and sccache that are the point of a persistent runner.
#
# Everything here is idempotent and safe to run against a box that is already correct. It does NOT
# restart the runner agents unless asked: `svc.sh stop` kills the job in flight, and the run then
# reports `failure` with NO failed step, which is indistinguishable at a glance from a real red.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci-runners-lib.sh
. "$HERE/ci-runners-lib.sh"

RESTART=0
[ "${1:-}" = "--restart" ] && RESTART=1

require_aws
IDS="$(fleet_instance_ids)"
[ -n "$IDS" ] || die "no running instances tagged Name=$FLEET"
log "reconciling: $IDS"

ONLINE="$(aws ssm describe-instance-information \
  --filters "Key=InstanceIds,Values=$(echo "$IDS" | tr -s ' \t' ',,' | sed 's/,$//')" \
  --query 'InstanceInformationList[?PingStatus==`Online`].InstanceId' --output text)"
[ -n "$ONLINE" ] || die "no fleet instance is reachable over SSM yet"
log "SSM-online: $ONLINE"

TMP="$(mktemp)"
cat > "$TMP" <<'JSON'
{"commands":[
 "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv >/dev/null 2>&1; python3 -m venv /tmp/vp >/dev/null 2>&1 && echo venv=ok || echo venv=BROKEN; rm -rf /tmp/vp",
 "if ! command -v gh >/dev/null; then V=$(curl -fsSL https://api.github.com/repos/cli/cli/releases/latest | jq -r .tag_name | tr -d v); [ -n \"$V\" ] && [ \"$V\" != null ] || V=2.82.1; curl -fsSL \"https://github.com/cli/cli/releases/download/v${V}/gh_${V}_linux_amd64.tar.gz\" | tar -xz -C /tmp && install -m 0755 /tmp/gh_${V}_linux_amd64/bin/gh /usr/local/bin/gh; fi; echo gh=$(gh --version 2>/dev/null | head -1)",
 "printf '#!/usr/bin/env bash\\nset -uo pipefail\\nif [ -n \"${RUNNER_WORKSPACE:-}\" ] && [ -d \"${RUNNER_WORKSPACE}\" ]; then find \"${RUNNER_WORKSPACE}\" -maxdepth 1 -mindepth 1 -name %s_temp*%s -exec rm -rf {} + 2>/dev/null || true; fi\\ndocker container prune -f --filter until=1h >/dev/null 2>&1 || true\\ndocker network   prune -f --filter until=1h >/dev/null 2>&1 || true\\ndocker volume    prune -f                   >/dev/null 2>&1 || true\\ndf -h / | tail -1 || true\\nexit 0\\n' \"'\" \"'\" > /opt/job-started-hook.sh; chmod 0755 /opt/job-started-hook.sh; bash -e /opt/job-started-hook.sh >/dev/null 2>&1 && echo hook=ok || echo hook=STILL-FAILS",
 "su - ubuntu -c 'test -x ~/.cargo/bin/rustup || (curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal --default-toolchain 1.98.0 -c clippy -c rustfmt >/dev/null 2>&1)'; echo base-cargo=$(su - ubuntu -c '~/.cargo/bin/cargo --version' 2>&1 | head -1)",
 "for d in /opt/runner-*; do n=${d##*-}; install -d -o ubuntu -g ubuntu $d/.cargo $d/.rustup $d/sccache; cp -an /home/ubuntu/.rustup/. $d/.rustup/ 2>/dev/null; cp -an /home/ubuntu/.cargo/. $d/.cargo/ 2>/dev/null; chown -R ubuntu:ubuntu $d/.cargo $d/.rustup $d/sccache; sed -i -e '/^PATH=/d' -e '/^CARGO_HOME=/d' -e '/^RUSTUP_HOME=/d' -e '/^SCCACHE_DIR=/d' -e '/^SCCACHE_CACHE_SIZE=/d' -e '/^SCCACHE_SERVER_PORT=/d' -e '/^SCCACHE_BUCKET=/d' -e '/^SCCACHE_REGION=/d' -e '/^SCCACHE_S3_KEY_PREFIX=/d' -e '/^ACTIONS_RUNNER_HOOK_JOB_STARTED=/d' $d/.env; printf 'PATH=%s/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\\nCARGO_HOME=%s/.cargo\\nRUSTUP_HOME=%s/.rustup\\nSCCACHE_DIR=%s/sccache\\nSCCACHE_CACHE_SIZE=20G\\nSCCACHE_SERVER_PORT=%s\\nACTIONS_RUNNER_HOOK_JOB_STARTED=/opt/job-started-hook.sh\\n' $d $d $d $d $((4226+n)) >> $d/.env; done; echo envs=written",
 "echo agents=$(ls -d /opt/runner-* 2>/dev/null | wc -l) ready=$( [ -f /var/run/busbar-runner-ready ] && echo yes || echo NO )"
]}
JSON
CMD_ID="$(aws ssm send-command --instance-ids $ONLINE --document-name AWS-RunShellScript \
  --comment "reconcile busbar CI runner boxes" --parameters "file://$TMP" \
  --timeout-seconds 900 --query 'Command.CommandId' --output text)" || die "send-command failed"
rm -f "$TMP"
for _ in $(seq 1 90); do
  sleep 10
  st="$(aws ssm list-command-invocations --command-id "$CMD_ID" --query 'CommandInvocations[].Status' --output text)"
  case "$st" in *Pending*|*InProgress*|*Delayed*) continue ;; *) log "ssm: $st"; break ;; esac
done
for i in $ONLINE; do
  printf '  %s: ' "$i"
  aws ssm get-command-invocation --command-id "$CMD_ID" --instance-id "$i" \
    --query 'StandardOutputContent' --output text 2>/dev/null | tr '\n' ' ' | cut -c1-200
  echo
done

if [ "$RESTART" = 1 ]; then
  log "restarting the runner agents (THIS KILLS ANY JOB IN FLIGHT)"
  T2="$(mktemp)"
  cat > "$T2" <<'JSON'
{"commands":["for d in /opt/runner-*; do (cd $d && ./svc.sh stop >/dev/null 2>&1; ./svc.sh start >/dev/null 2>&1); done; sleep 2; systemctl list-units 'actions.runner.*' --no-legend | wc -l"]}
JSON
  C2="$(aws ssm send-command --instance-ids $ONLINE --document-name AWS-RunShellScript \
    --parameters "file://$T2" --query 'Command.CommandId' --output text)"
  rm -f "$T2"
  for _ in $(seq 1 30); do
    sleep 8
    st="$(aws ssm list-command-invocations --command-id "$C2" --query 'CommandInvocations[].Status' --output text)"
    case "$st" in *Pending*|*InProgress*|*Delayed*) continue ;; *) log "restart: $st"; break ;; esac
  done
fi

log "done. Register any NEW box with: ./scripts/ci-runners-register.sh"

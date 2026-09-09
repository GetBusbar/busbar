#!/usr/bin/env bash
# Give the operator an SSH shell on every busbar CI box, WITHOUT opening a single inbound port.
#
#   ./scripts/ci-runners-ssh.sh
#
# WHY THIS EXISTS. ci-runners-up.sh deliberately builds an EGRESS-ONLY box: an Actions runner dials
# out and nothing ever dials in, so the security group opens nothing. That is the right shape for
# the Actions fleet and the wrong shape for the owner's ruling that during dev churn proofs run
# DIRECTLY on the boxes — `land.sh --remote` needs a git transport and a streaming stdout, and SSM
# SendCommand gives neither (fire-and-poll, 100 KB of captured output, no stdin).
#
# The first attempt was the obvious one: authorise tcp/22 from the operator's /32 and ssh to the
# public IP. It does not work from this network, and the failure is worth recording because it looks
# like a firewall bug and is not: a TCP connect "succeeds" against ANY address — 1.2.3.4:22 included
# — and then the stream is dropped, so ssh dies in `banner exchange` while sshd on the box is
# healthy and has logged nothing. That is a middlebox forging SYN-ACK. Port 443 behaves the same.
# The rule was revoked; it admitted an operator who could not connect, which is attack surface
# bought for nothing.
#
# So: ssh is tunnelled through SSM (ordinary HTTPS to the regional endpoint), the security group
# keeps its empty ingress list, and access is an IAM question rather than a CIDR question. This
# script installs the pieces that makes that work:
#   1. session-manager-plugin, into ~/.local/bin — the AWS installer wants root, the binary does not
#   2. a DEDICATED key pair (~/.ssh/busbar-ci-fleet), whose public half is delivered to each box
#      over SSM. The private half never leaves this machine and is never printed.
#   3. ~/.busbar-fleet — the INSTANCE IDS the host allocator round-robins over. Instance ids, not
#      public IPs: an id is stable for the life of the box and is what SSM addresses anyway.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci-runners-lib.sh
. "$HERE/ci-runners-lib.sh"

require_aws
export PATH="$HOME/.local/bin:$PATH"

# ── 1. session-manager-plugin, without root ─────────────────────────────────────────────────────
if ! command -v session-manager-plugin >/dev/null; then
  log "installing session-manager-plugin into ~/.local/bin (no sudo)"
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) URL=https://s3.amazonaws.com/session-manager-downloads/plugin/latest/mac_arm64/sessionmanager-bundle.zip ;;
    Darwin/*)     URL=https://s3.amazonaws.com/session-manager-downloads/plugin/latest/mac/sessionmanager-bundle.zip ;;
    Linux/aarch64)URL=https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_arm64/session-manager-plugin.deb ;;
    Linux/*)      URL=https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb ;;
    *) die "unknown platform $(uname -s)/$(uname -m); install session-manager-plugin by hand" ;;
  esac
  d="$(mktemp -d)"
  ( cd "$d" && curl -fsSL "$URL" -o bundle && { unzip -q bundle || ar x bundle 2>/dev/null; } ) \
    || die "could not fetch $URL"
  bin="$(find "$d" -type f -name session-manager-plugin | head -1)"
  [ -n "$bin" ] || die "no session-manager-plugin inside $URL"
  mkdir -p "$HOME/.local/bin"
  install -m 0755 "$bin" "$HOME/.local/bin/session-manager-plugin"
  rm -rf "$d"
fi
log "session-manager-plugin $(session-manager-plugin --version)"

# ── 2. The fleet key ────────────────────────────────────────────────────────────────────────────
KEY="${FLEET_SSH_KEY:-$HOME/.ssh/busbar-ci-fleet}"
if [ ! -f "$KEY" ]; then
  log "creating $KEY (ed25519, no passphrase — a fleet key, not a person's key)"
  ssh-keygen -t ed25519 -N '' -C busbar-ci-fleet -f "$KEY" -q || die "ssh-keygen failed"
fi
PUB="$(cat "$KEY.pub")" || die "no public half at $KEY.pub"

IDS="$(fleet_instance_ids)"
[ -n "$IDS" ] || die "no running instances tagged Name=$FLEET"

# Over SSM, so no box needs a KeyName at launch and rotating the key is this script again rather
# than a fleet replacement.
TMP="$(mktemp)"
cat > "$TMP" <<JSON
{"commands":[
 "install -d -m 0700 -o ubuntu -g ubuntu /home/ubuntu/.ssh",
 "touch /home/ubuntu/.ssh/authorized_keys",
 "grep -qF '$PUB' /home/ubuntu/.ssh/authorized_keys || echo '$PUB' >> /home/ubuntu/.ssh/authorized_keys",
 "chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys && chmod 0600 /home/ubuntu/.ssh/authorized_keys",
 "rm -f /etc/ssh/sshd_config.d/99-busbar-alt-port.conf",
 "systemctl enable --now ssh >/dev/null 2>&1 || true; systemctl restart ssh >/dev/null 2>&1 || true",
 "echo authorized_keys=\$(wc -l < /home/ubuntu/.ssh/authorized_keys)"
]}
JSON
CMD_ID="$(aws ssm send-command --instance-ids $IDS --document-name AWS-RunShellScript \
  --comment "install the busbar fleet ssh key" --parameters "file://$TMP" \
  --query 'Command.CommandId' --output text)" || die "send-command failed"
rm -f "$TMP"
for _ in $(seq 1 30); do
  sleep 6
  st="$(aws ssm list-command-invocations --command-id "$CMD_ID" --query 'CommandInvocations[].Status' --output text)"
  case "$st" in *Pending*|*InProgress*|*Delayed*) continue ;; *) log "ssm: $st"; break ;; esac
done

# ── THE INGRESS THAT IS NOT THERE ───────────────────────────────────────────────────────────────
# Revoked, not merely never added: an earlier iteration of this script opened 22 and 443 while the
# SSM route was being proven. Leaving them would be an open port on a box that executes arbitrary
# branch code, kept alive by nothing but forgetfulness.
SG_ID="$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" \
          --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)"
if [ -n "$SG_ID" ] && [ "$SG_ID" != None ]; then
  perms="$(aws ec2 describe-security-groups --group-ids "$SG_ID" \
            --query 'SecurityGroups[0].IpPermissions' --output json)"
  if [ "$perms" != "[]" ]; then
    log "revoking leftover ingress on $SG_ID (the fleet is reached over SSM, not over a port)"
    aws ec2 revoke-security-group-ingress --group-id "$SG_ID" \
      --ip-permissions "$perms" >/dev/null 2>&1 || log "  (revoke reported nothing to do)"
  fi
  log "ingress on $SG_ID: $(aws ec2 describe-security-groups --group-ids "$SG_ID" --query 'length(SecurityGroups[0].IpPermissions)' --output text) rule(s)"
fi

# ── 3. The host list every remote entry point reads ─────────────────────────────────────────────
FLEET_FILE="${BUSBAR_FLEET_FILE:-$HOME/.busbar-fleet}"
{
  echo "# busbar CI fleet — written by scripts/ci-runners-ssh.sh at $(date -u +%FT%TZ)"
  echo "# <instance-id> <az> <private-ip>   (ssh reaches these over SSM; there is no public port)"
  aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=$FLEET" "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[].[InstanceId,Placement.AvailabilityZone,PrivateIpAddress]' \
    --output text
} > "$FLEET_FILE"
log "wrote $FLEET_FILE:"
sed 's/^/  /' "$FLEET_FILE"

cat <<EOF

Optional ~/.ssh/config snippet (the scripts do not need it — they generate their own wrapper at
~/.busbar-fleet-ssh — but it makes a bare \`ssh i-0abc…\` work too). The private key is never
printed; only its path is named:

  Host i-* mi-*
    User ubuntu
    IdentityFile $KEY
    IdentitiesOnly yes
    StrictHostKeyChecking accept-new
    UserKnownHostsFile ~/.ssh/known_hosts_busbar_fleet
    ServerAliveInterval 30
    ServerAliveCountMax 6
    ControlMaster auto
    ControlPath ~/.ssh/cm-busbar-%r@%h
    ControlPersist 10m
    ProxyCommand aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p --region $AWS_REGION

Next:  ./scripts/prove-remote.sh --setup        # bare repo + warm checkout on every box
EOF

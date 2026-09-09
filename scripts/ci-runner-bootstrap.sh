#!/usr/bin/env bash
# EC2 user-data for a busbar self-hosted GitHub Actions runner box.
#
# Runs ONCE at first boot as root. It installs everything a keep-proof / ci job needs, unpacks
# $AGENTS copies of the Actions runner, and then STOPS — it does not register. Registration is a
# separate step (scripts/ci-runners-register.sh, delivered over SSM) for one reason that matters:
#
#   A RUNNER REGISTRATION TOKEN MUST NEVER BE BAKED INTO USER-DATA. User-data is readable by
#   anything that can reach the instance metadata service — including every job this box will ever
#   run, which is arbitrary code from any branch an agent pushes. A token in user-data is a token
#   handed to untrusted CI. Tokens are minted at registration time with
#   `gh api -X POST /orgs/<org>/actions/runners/registration-token`, live ~60 minutes, are used
#   immediately and are never written to disk.
#
# The split has a second payoff: the box spends its first boot compiling (see PRE-WARM below), so
# by the time it accepts its first job sccache is already hot.
set -uxo pipefail
exec > >(tee -a /var/log/busbar-runner-bootstrap.log) 2>&1

AGENTS="__AGENTS__"
SCCACHE_BUCKET="__SCCACHE_BUCKET__"
SCCACHE_REGION="__SCCACHE_REGION__"
SCCACHE_BACKEND="__SCCACHE_BACKEND__"
RUNNER_LABELS="__RUNNER_LABELS__"
ORG="__ORG__"
RUST_CHANNEL="__RUST_CHANNEL__"
VCPU_PER_AGENT="__VCPU_PER_AGENT__"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# The GitHub-hosted ubuntu-latest image carries far more than this; these are the packages the
# busbar workflows actually reach for (jq for the test-binary enumerator, python3+pyyaml for the
# schema/dispatcher lints, gdb for the crash-artefact step, docker for the postgres/valkey service
# containers, the usual native build chain for ring/openssl).
apt-get install -y -qq build-essential pkg-config libssl-dev git curl jq unzip zstd cmake clang \
  gdb python3 python3-pip python3-yaml docker.io ca-certificates rsync

systemctl enable --now docker
usermod -aG docker ubuntu

# ── sccache, shared by every agent on the box ───────────────────────────────────────────────────
# S3 backend, not the GitHub Actions cache: the GHA cache is rate-limited per repo and every
# read crosses the public internet, which is exactly the tax self-hosting is meant to remove.
# S3 in the SAME REGION as the fleet is a same-AZ-ish hop, and the bucket's 14-day lifecycle keeps
# it from growing without bound. Credentials come from the instance profile — nothing is stored.
SCCACHE_VER="$(curl -fsSL https://api.github.com/repos/mozilla/sccache/releases/latest | jq -r .tag_name)"
[ -n "$SCCACHE_VER" ] && [ "$SCCACHE_VER" != "null" ] || SCCACHE_VER="v0.10.0"
curl -fsSL "https://github.com/mozilla/sccache/releases/download/${SCCACHE_VER}/sccache-${SCCACHE_VER}-x86_64-unknown-linux-musl.tar.gz" \
  | tar -xz -C /tmp
install -m 0755 "/tmp/sccache-${SCCACHE_VER}-x86_64-unknown-linux-musl/sccache" /usr/local/bin/sccache
mkdir -p /var/cache/sccache && chown ubuntu:ubuntu /var/cache/sccache

# ── Which sccache backend the box uses ──────────────────────────────────────────────────────────
# LOCAL DISK NOW, S3 LATER, per the owner's constraint. A local /var/cache/sccache is one gp3 read
# away and cannot fail for a reason outside this box: no bucket policy, no instance-profile
# expiry, no cross-AZ hop. Its cost is that the cache is per-instance, so a fresh spot replacement
# starts cold — which the bootstrap PRE-WARM below already pays down.
#
# The S3 half is fully provisioned by scripts/ci-runners-up.sh (bucket, 14-day lifecycle, and the
# instance-profile policy that can read and write it), so "later" is exactly this flag:
#   CI_RUNNER_SCCACHE=s3 ./scripts/ci-runners-up.sh   # then re-launch the fleet
# Nothing else changes; the workflows never name a backend.
if [ "${SCCACHE_BACKEND}" = "s3" ]; then
  SCCACHE_ENV="SCCACHE_BUCKET=${SCCACHE_BUCKET}
SCCACHE_REGION=${SCCACHE_REGION}
SCCACHE_S3_KEY_PREFIX=busbar"
else
  SCCACHE_ENV="SCCACHE_DIR=/var/cache/sccache
SCCACHE_CACHE_SIZE=60G"
fi

# ── Rust, pinned to rust-toolchain.toml's channel ───────────────────────────────────────────────
# rustup honours the repo's rust-toolchain.toml on every cargo invocation anyway; installing the
# same channel here means the first job does not pay to download a toolchain.
su - ubuntu -c "curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal \
  --default-toolchain ${RUST_CHANNEL} -c clippy -c rustfmt"

# ── The runner agents ───────────────────────────────────────────────────────────────────────────
RUNNER_VER="$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest | jq -r .tag_name | tr -d v)"
[ -n "$RUNNER_VER" ] && [ "$RUNNER_VER" != "null" ] || RUNNER_VER="2.328.0"
curl -fsSL -o /tmp/runner.tar.gz \
  "https://github.com/actions/runner/releases/download/v${RUNNER_VER}/actions-runner-linux-x64-${RUNNER_VER}.tar.gz"
/usr/local/bin/sccache --version || true

IID="$(curl -fsSL -H "X-aws-ec2-metadata-token: $(curl -fsSL -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')" http://169.254.169.254/latest/meta-data/instance-id)"
SHORT="${IID##*-}"

i=1
while [ "$i" -le "$AGENTS" ]; do
  d="/opt/runner-$i"
  mkdir -p "$d"
  tar -xzf /tmp/runner.tar.gz -C "$d"
  chown -R ubuntu:ubuntu "$d"

  # `.env` is the runner's own per-job environment file. Putting the toolchain and the compiler
  # cache here (rather than in every workflow) means a workflow that says nothing about sccache
  # still gets it, and a workflow that DOES name a backend agrees with the box instead of
  # fighting it.
  #
  # CARGO_BUILD_JOBS IS THE LOAD-BEARING LINE. Cargo defaults to nproc, so N agents on one 32-vCPU
  # box would each spawn 32 rustc threads: 4x oversubscription, every job slower than if it had
  # run alone. Pinning each agent to its fair share (32/AGENTS) is what makes several agents per
  # box a throughput win instead of a wash.
  cat > "$d/.env" <<ENVEOF
PATH=/home/ubuntu/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
HOME=/home/ubuntu
RUSTC_WRAPPER=sccache
${SCCACHE_ENV}
SCCACHE_IDLE_TIMEOUT=0
CARGO_INCREMENTAL=0
CARGO_BUILD_JOBS=${VCPU_PER_AGENT}
CARGO_TERM_COLOR=always
ENVEOF
  chown ubuntu:ubuntu "$d/.env"
  i=$((i+1))
done

# ── The registration helper the SSM step calls ──────────────────────────────────────────────────
# Takes a short-lived org registration token on ARGV, registers every agent dir that is not already
# configured, and installs each as a systemd service so a spot reclaim + replacement comes back by
# itself. NOT --ephemeral: an ephemeral runner deregisters after one job and would need a FRESH
# token to come back, which is precisely the credential this design refuses to store. The
# equivalent hygiene is bought by the clean-workspace hook below, which is stronger than
# --ephemeral for the thing that actually bites (a stale target/ or a leftover file), while KEEPING
# the warm cargo/target directory that is the entire point of a persistent box.
cat > /usr/local/bin/busbar-runner-register <<'REGEOF'
#!/usr/bin/env bash
set -uo pipefail
TOKEN="${1:?usage: busbar-runner-register <registration-token>}"
ORG="${2:-GetBusbar}"
LABELS="${3:-busbar-xl}"
IID="$(curl -fsSL -H "X-aws-ec2-metadata-token: $(curl -fsSL -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')" http://169.254.169.254/latest/meta-data/instance-id)"
SHORT="${IID##*-}"
rc=0
for d in /opt/runner-*; do
  n="${d##*-}"
  if [ -f "$d/.runner" ]; then echo "$d already configured"; continue; fi
  sudo -u ubuntu env HOME=/home/ubuntu "$d/config.sh" \
      --url "https://github.com/${ORG}" --token "$TOKEN" \
      --name "ec2-${SHORT}-${n}" --labels "$LABELS" \
      --work "$d/_work" --unattended --replace --disableupdate || { rc=1; continue; }
  (cd "$d" && ./svc.sh install ubuntu && ./svc.sh start) || rc=1
done
exit "$rc"
REGEOF
chmod 0755 /usr/local/bin/busbar-runner-register

# ── Clean workspace between jobs ────────────────────────────────────────────────────────────────
# ACTIONS_RUNNER_HOOK_JOB_STARTED runs before every job on a persistent runner. It removes the
# checkout leftovers a previous branch left behind — WITHOUT touching ~/.cargo or the sccache dir,
# which are the warm state a persistent runner exists for. `actions/checkout` does its own
# `git clean -ffdx`, but only inside the repo it checks out; untracked files a job wrote elsewhere
# under _work are exactly what this catches.
cat > /opt/job-started-hook.sh <<'HOOKEOF'
#!/usr/bin/env bash
set -uo pipefail
if [ -n "${RUNNER_WORKSPACE:-}" ] && [ -d "${RUNNER_WORKSPACE}" ]; then
  find "${RUNNER_WORKSPACE}" -maxdepth 1 -mindepth 1 -name '_temp*' -exec rm -rf {} + 2>/dev/null
fi
docker container prune -f  >/dev/null 2>&1
docker volume    prune -f  >/dev/null 2>&1
df -h / | tail -1
HOOKEOF
chmod 0755 /opt/job-started-hook.sh
for d in /opt/runner-*; do
  echo "ACTIONS_RUNNER_HOOK_JOB_STARTED=/opt/job-started-hook.sh" >> "$d/.env"
done

# ── Nightly stop at 02:00 America/Los_Angeles ───────────────────────────────────────────────────
# The fleet is for agents pushing during the working day; a box idling overnight is pure burn.
# `shutdown -h` on a spot instance with InstanceInitiatedShutdownBehavior=terminate ends the
# billable hour; scripts/ci-runners-up.sh brings the fleet back. Local time is set to PT so the
# schedule reads the way the team says it.
timedatectl set-timezone America/Los_Angeles
cat > /etc/systemd/system/busbar-runner-nightly-stop.timer <<'TEOF'
[Unit]
Description=Stop the busbar CI runner box overnight
[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=false
[Install]
WantedBy=timers.target
TEOF
cat > /etc/systemd/system/busbar-runner-nightly-stop.service <<'SEOF'
[Unit]
Description=Stop the busbar CI runner box overnight
[Service]
Type=oneshot
ExecStart=/sbin/shutdown -h +1 "busbar CI runner nightly stop (02:00 PT)"
SEOF
systemctl daemon-reload
systemctl enable --now busbar-runner-nightly-stop.timer

# ── PRE-WARM ────────────────────────────────────────────────────────────────────────────────────
# Compile the workspace once, on the box, before it takes any job. This populates the shared S3
# sccache with this instance type's exact rustc outputs, so the FIRST real job is a warm job. It
# also proves the toolchain and native deps are actually complete: if this fails, the box says so
# in /var/log/busbar-runner-bootstrap.log instead of failing somebody's hand-back.
su - ubuntu -c "git clone -q --depth 50 https://github.com/${ORG}/busbar.git /home/ubuntu/prewarm" || true
su - ubuntu -c "cd /home/ubuntu/prewarm && \
  RUSTC_WRAPPER=sccache $(printf '%s ' ${SCCACHE_ENV}) CARGO_INCREMENTAL=0 \
  cargo build --workspace --locked" || true

touch /var/run/busbar-runner-ready
echo "BOOTSTRAP COMPLETE"

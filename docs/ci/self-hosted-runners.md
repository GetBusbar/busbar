# The busbar-xl runner fleet

Four EC2 spot boxes in `us-east-1`, sixteen GitHub Actions runner agents registered at the
**GetBusbar org** level with the labels `self-hosted, linux, x64, busbar-xl`, and two ways to reach
them: as Actions runners, and directly over ssh.

Everything below is reproducible from `scripts/`; nothing here is a one-off that lives only in a
console.

---

## 1. Why a fleet at all

The org is on the GitHub Team plan: **60 concurrent hosted jobs**, shared by every workflow in every
repository. One `keep-proof` run is about a dozen jobs (fmt/clippy/build, five test shards, the
shard total, the gate leg, design-bindings, the oracle, the construction gate, the verdict), so
**five concurrent hand-backs saturate the entire org allowance** and the sixth agent's push sits in
`queued` behind work it has nothing to do with. With 20–30 agents pushing, the queue — not the
compiler — is the wall clock. It was measured, not guessed: the repo's Actions queue was **691 runs
deep** the night this fleet was built.

## 2. Sizing, and the arithmetic behind it

    25 agents × 1 push / 30 min          =  50 pushes per hour
    50 pushes × ~10 jobs                 = 500 jobs per hour
    500 jobs × ~15 min                   = 125 job-hours of demand per wall-clock hour

125 job-hours per hour is not what a fleet must supply, because that number assumes every job pays
full cold cost. The two things that make it tractable are the two things a *persistent* box has and
a fresh container does not: a warm `sccache` and a warm `target/`. What the fleet must actually
absorb is the **burst** — several hand-backs landing inside the same five minutes — and the ceiling
that matters is concurrency, not throughput.

    4 instances × 4 runner agents        = 16 concurrent job slots
    c7a.8xlarge = 32 vCPU                → 8 vCPU per slot

**`CARGO_BUILD_JOBS` is the load-bearing line.** Cargo defaults to `nproc`, so four agents on one
32-vCPU box would each spawn 32 rustc threads: 4× oversubscription, and every job slower than if it
had run alone. Each agent's `.env` pins `CARGO_BUILD_JOBS=32/AGENTS`. That single pin is what makes
four agents per box a throughput win rather than a wash.

To scale, move either number:

    CI_RUNNER_COUNT=8 ./scripts/ci-runners-up.sh            # more boxes
    CI_RUNNER_ITYPE=c7a.16xlarge CI_RUNNER_AGENTS=8 ./scripts/ci-runners-up.sh

Autoscaling is deliberately **not** here yet. A fixed fleet with a nightly stop is a cost you can
read off a calendar; an autoscaler is a second system that fails in its own ways, and it should be
added when the fixed fleet is demonstrably the constraint.

## 3. What it costs

| line | measured |
|---|---|
| c7a.8xlarge on-demand, us-east-1 | **$1.6422 /hr** |
| c7a.8xlarge **spot**, us-east-1a (2026-09-08) | **$0.667 /hr** — 59% off |
| fleet of 4, spot | **$2.67 /hr** |
| EBS: 300 GB gp3 + 6000 IOPS + 500 MB/s, per box | ≈ $54 /month ≈ $0.074 /hr |
| fleet of 4, all-in while running | **≈ $2.97 /hr** |

With the nightly stop (below) and roughly ten working hours a day, twenty-two days a month, that is
**≈ $650/month**. The comparison is not "$650 versus $0": it is $650 versus twenty-five agents each
burning a laptop for thirty to sixty minutes per hand-back, on trees whose CI is red for reasons
that have nothing to do with the hand-back.

**Spot, with at most one on-demand box.** CI is interruption-tolerant by construction: a reclaimed
box loses at most the jobs in flight on it, and `concurrency: cancel-in-progress` means a re-push
would have killed them anyway. If spot capacity is refused outright, `ci-runners-up.sh` falls back
to **exactly one** on-demand instance — enough that a capacity refusal degrades throughput instead
of taking CI to zero, not so much that a bad spot day quietly triples the bill.

## 4. Start, stop, scale

```sh
./scripts/ci-runners-up.sh          # create/scale. Idempotent: tops the fleet up to CI_RUNNER_COUNT
./scripts/ci-runners-register.sh    # mint an org registration token and register every agent
./scripts/ci-runners-ssh.sh         # ssh key + session-manager-plugin + ~/.busbar-fleet
./scripts/prove-remote.sh --setup   # bare repo + warm checkout on every box
./scripts/ci-runners-down.sh        # deregister, terminate, sweep offline runners
```

`ci-runners-up.sh` is also the scale-up command: it leaves running boxes alone and launches the
difference. Bootstrap takes 8–12 minutes (apt, rustup, the runner tarballs, and a full pre-warm
build so the first real job is a warm job).

**The registration token is never stored.** `POST /orgs/GetBusbar/actions/runners/registration-token`
is called at registration time, travels to the boxes over SSM SendCommand, and is used within
seconds. It is never in user-data — user-data is readable from the instance metadata service by
every job the box will ever run, which is arbitrary code from any branch an agent pushes. A token in
user-data is a token handed to untrusted CI.

**Order matters in `down`.** Terminating first would leave the org's runner list full of entries
GitHub still believes are available, and a job routed to a dead runner sits `queued` until the 24h
timeout with no error anywhere. So: deregister (the boxes are still alive to be told), then
terminate, then sweep every `offline` org runner regardless.

**Nightly stop, 02:00 America/Los_Angeles.** A systemd timer on each box runs `shutdown -h`; the
launch template sets `InstanceInitiatedShutdownBehavior=terminate`, so the billable hour ends and
the EBS volume goes with it. `ci-runners-up.sh` brings the fleet back.

## 5. What is on a box

* Ubuntu 24.04, x86-64 (the `x64` label and the release artefacts both mean x86-64)
* Rust at the channel `rust-toolchain.toml` pins (1.98.0), with clippy and rustfmt
* Docker, for the oracle's postgres / mysql / valkey service containers
* `sccache` at **`/var/cache/sccache`, local disk, 60 G**. The S3 bucket, its 14-day lifecycle and
  the instance-profile policy that reads and writes it are provisioned anyway, so a fleet-shared
  cache is `CI_RUNNER_SCCACHE=s3 ./scripts/ci-runners-up.sh` and a relaunch. No workflow names a
  backend.
* Four unpacked runner agents under `/opt/runner-N`, each a systemd service, each with its own
  `_work` tree and `.env`
* **A clean-workspace hook, not `--ephemeral`.** An ephemeral runner deregisters after one job and
  needs a *fresh* token to come back — precisely the credential this design refuses to keep. The
  `ACTIONS_RUNNER_HOOK_JOB_STARTED` hook is stronger than `--ephemeral` for the thing that actually
  bites (a stale workspace, a leftover container) while keeping the warm cargo and sccache state
  that is the whole reason to run a persistent box. The hook is invoked by the runner as
  `bash -e <hook>`, so every line in it is forgiven explicitly and it ends in `exit 0`: a cleanup
  step must never be able to fail a job it was only meant to tidy up for.
* **No inbound ports.** The security group's ingress list is empty. A runner dials out and holds the
  connection; nothing ever dials in. Admin and ssh both travel over SSM.

### Service containers are addressed by container IP

`ports: - 5432:5432` is a statement about a machine the job owns. Four agents share a box, and the
host's 5432 is one resource: the second job to publish it dies in `Initialize containers` with
`Bind for 0.0.0.0:5432 failed: port is already allocated`, before a line of the job has run.

So nothing is published. The runner already puts every service container on a per-job bridge
network (`github_network_<uuid>`); `scripts/ci-service-endpoints.sh` reads each container's address
off that network and writes `BUSBAR_TEST_POSTGRES_URL` / `BUSBAR_TEST_MYSQL_URL` / `VALKEY_URL` into
`$GITHUB_ENV`. Two jobs on one box get two networks and two addresses. This holds at any
agents-per-box count.

---

## 6. Proving directly on the fleet (no GitHub Actions)

During dev churn, Actions judges `integration/*`, `qa` and `main`; a hand-back is proven **on the
boxes**, over ssh. Same legs, same scope file, no queue.

### ssh goes through SSM, and the security group still opens nothing

The obvious shape — authorise tcp/22 from the operator's `/32`, ssh to the public IP — was built,
tried and abandoned on evidence. From this network a TCP connect "succeeds" against *any* address,
`1.2.3.4:22` included, and the stream is then dropped: every session died in `banner exchange` while
`sshd` sat healthy on the box and logged nothing. That is a middlebox forging SYN-ACK; port 443
behaves identically. The rule was **revoked** — it admitted an operator who could not connect, which
is attack surface bought for nothing.

ssh is therefore tunnelled inside `aws ssm start-session`, which is ordinary HTTPS to the regional
SSM endpoint. Strictly better than the rule it replaces: the group keeps its empty ingress list,
there is no operator IP to keep current, access is IAM (revoked by policy, recorded in CloudTrail
against a named principal), and the host is the **instance id**, stable for the life of the box.

`./scripts/ci-runners-ssh.sh` installs `session-manager-plugin` into `~/.local/bin` without root,
creates and delivers `~/.ssh/busbar-ci-fleet`, writes `~/.busbar-fleet`, and revokes any leftover
ingress. The scripts generate their own ssh wrapper at `~/.busbar-fleet-ssh`; this snippet is only
needed if you also want a bare `ssh i-0abc…` to work:

```
Host i-* mi-*
  User ubuntu
  IdentityFile ~/.ssh/busbar-ci-fleet
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
  UserKnownHostsFile ~/.ssh/known_hosts_busbar_fleet
  ServerAliveInterval 30
  ServerAliveCountMax 6
  ControlMaster auto
  ControlPath ~/.ssh/cm-busbar-%r@%h
  ControlPersist 10m
  ProxyCommand aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p --region us-east-1
```

The private key is never printed by any script, and never leaves the operator's machine — only its
public half travels, over SSM.

### `prove-remote.sh` — an agent's hand-back

```sh
./scripts/prove-remote.sh                      # prove this worktree's tip on a round-robin box
./scripts/prove-remote.sh keep-my-branch       # prove a local branch's tip
./scripts/prove-remote.sh --host i-0abc… keep-my-branch
./scripts/prove-remote.sh --setup              # prepare every box (idempotent)
```

It runs exactly the legs `keep-proof.yml` runs, in the same order, scoped by **the same
`.keep-proof.toml`** the workflow reads off the branch root: workspace build, rustfmt,
`clippy -D warnings`, the named test packages (or the whole suite when the branch names none),
`cargo xtask gate --all`, `cargo xtask selftest`, and the shadow oracle over `families` against the
published 1.5.5 recording. Reading the same scope file rather than inventing a second one is what
makes a green here and a green there the same sentence about the same tree.

The log streams to your terminal as it happens, and **the exit code is the box's** — there is no
"the transport worked, so the landing is green" path.

### `land.sh --remote` — the integrator's batch

```sh
./scripts/land.sh --remote i-0abc… --batch target/gate/batch-17.txt
LAND_REMOTE=auto ./scripts/land.sh --batch target/gate/batch-17.txt      # round-robin a host
```

`land.sh` gained exactly one block in MAIN: if `--remote` (or `LAND_REMOTE`) is set and
`LAND_REMOTE_INNER` is not, it `exec`s `scripts/land-remote.sh`, which pushes the tree and the
batch's picks to a box, copies the batch file up, runs **the same `land.sh`** there with the same
arguments minus `--remote`, streams the log back, brings `<batch>.result` back to the path the local
queue runner reads, and exits with the remote's status. Nothing below that block changed, so the
engine, the bisect and the selftest are untouched.

**The picks are pushed separately from the tip.** A batch line names commits that live in an agent's
worktree: they are objects in the integrator's repository but are not reachable from `HEAD`, so a
plain `push HEAD` would leave the box with a batch it cannot cherry-pick. Every hash the batch
mentions goes up under `refs/proof/<ref>/<hash>`, which both transfers the object and keeps it alive
against the box's gc.

**A bare repo plus a checkout, not one non-bare repo.** `receive.denyCurrentBranch=false` buys off
git's refusal by letting a push desynchronise the index from HEAD, and that shows up later as a
proof run against a tree that is not the one that was pushed. `~/busbar.git` takes the push;
`~/busbar-prove` is reset to it explicitly, then cleaned with `git clean -ffdx -e target -e .cargo`
— the warm `target/` and warm sccache are the entire reason a persistent box beats a container.

### What the integrator exports for `target/gate/landq3.sh`

`landq3.sh` needs no edit. Export these and it lands on the fleet instead of the laptop:

```sh
export LAND_REMOTE=auto                   # or a specific instance id, e.g. i-011b75f393bf2da40
export AWS_REGION=us-east-1
export PATH="$HOME/.local/bin:$PATH"      # session-manager-plugin
# optional, all have working defaults:
export BUSBAR_FLEET_FILE="$HOME/.busbar-fleet"
export FLEET_SSH_KEY="$HOME/.ssh/busbar-ci-fleet"
export CARGO_BUILD_JOBS=8                 # the box's fair share; 4 proofs may share 32 vCPU
```

`LAND_REMOTE=auto` round-robins over `~/.busbar-fleet` with a cursor kept in a **file**, because the
callers are separate processes: `land.sh` invoked from four worktrees is four shells that share
nothing but the filesystem. A named host always wins.

---

## 7. When the fleet is down

Symptom: jobs sit in `queued` forever with no error. `runs-on` has **no hosted fallback** on purpose
— a fallback is a fleet outage nobody notices until the bill arrives — so a dead fleet is a stopped
queue, loudly.

1. **Are the runners there and online?**
   ```sh
   gh api /orgs/GetBusbar/actions/runners --jq '.runners[]|"\(.name) \(.status) busy=\(.busy)"'
   ```
   *All offline* → the boxes are gone (spot reclaim, or the nightly stop). Go to 3.
   *Nothing listed* → registration was lost. Go to 4.

2. **Are the boxes alive?**
   ```sh
   aws ec2 describe-instances --filters Name=tag:Name,Values=busbar-ci-runner \
     Name=instance-state-name,Values=running --query 'Reservations[].Instances[].InstanceId' --output text
   ```

3. **Bring the fleet back.** `./scripts/ci-runners-up.sh` then `./scripts/ci-runners-register.sh`.
   Boxes are ready in 8–12 minutes; the pre-warm build means the first job is not also the first
   cold compile. If spot is refused, the script says so and falls back to one on-demand box.

4. **Ghost runners.** An `offline` org runner is a routing black hole: GitHub will hand it a job
   that never runs. `./scripts/ci-runners-down.sh` sweeps every offline entry (it does this even
   when there are no instances left to terminate).

5. **A box is up but jobs fail immediately.** Look at `Set up runner` — that is the job hook. Then:
   ```sh
   ~/.busbar-fleet-ssh ubuntu@i-0abc… 'tail -50 /var/log/busbar-runner-bootstrap.log'
   ~/.busbar-fleet-ssh ubuntu@i-0abc… 'systemctl list-units "actions.runner.*"'
   ```

6. **Disk.** Four agents × their own `target/` on 300 GB. The hook prints `df -h /` at the top of
   every job; if it is tight, `./scripts/ci-runners-down.sh && ./scripts/ci-runners-up.sh` is a
   clean slate in ten minutes, or raise `CI_RUNNER_DISK_GB`.

7. **The escape hatch.** Actions is the judge for `integration/*`, `qa` and `main` regardless; for a
   hand-back, `./scripts/prove-remote.sh` needs only ONE box and no runner registration at all — it
   is ssh and a git push. A fleet with a broken Actions registration can still prove work.

### Known sharp edges

* **`~/.cargo` is shared between the Actions agents and the remote-prove checkout.** They are the
  same user on the same box. A `dtolnay/rust-toolchain` step re-installing rustup while a remote
  proof is running has been observed to leave `~/.cargo/bin/rustup` missing for a few seconds; a
  re-run fixes it. Isolating them is the obvious next change.
* **`allows_public_repositories` is enabled on the org's Default runner group.** It has to be —
  `GetBusbar/busbar` is public and self-hosted runners are blocked from public repos by default.
  That default exists because a fork's pull-request workflow could otherwise run on our hardware.
  The mitigation is the repository's fork-PR approval setting, not the runner group; check it before
  accepting outside contributions.

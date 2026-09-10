# The busbar-xl runner fleet

Ten EC2 boxes in `us-east-1` — **eight spot** plus an **on-demand floor of two** — with four
GitHub Actions runner agents each, registered at the **GetBusbar org** level with the labels
`self-hosted, linux, x64, busbar-xl`, and two ways to reach them: as Actions runners, and directly
over ssh.

The fleet is kept at that shape by `scripts/ci-runners-reconcile.sh` on a fifteen-minute timer, not
by someone noticing it is gone. See §7.

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

    8 instances × 4 runner agents        = 32 concurrent job slots
    c7a.8xlarge = 32 vCPU                → 8 vCPU per slot

It opened at four boxes / sixteen slots, and sixteen was not enough: within the first evening all
sixteen were busy, four keep-proof runs were queued, and one of them sat **47 minutes without a
single job starting**. Doubling to eight drained that queue in under a minute. Sixteen slots is
about four concurrent hand-backs; the arrival rate above is more than that whenever three agents
finish together.

**`CARGO_BUILD_JOBS` is the load-bearing line.** Cargo defaults to `nproc`, so four agents on one
32-vCPU box would each spawn 32 rustc threads: 4× oversubscription, and every job slower than if it
had run alone. Each agent's `.env` pins `CARGO_BUILD_JOBS=32/AGENTS`. That single pin is what makes
four agents per box a throughput win rather than a wash.

Those 32 slots are the **spot** capacity. The on-demand floor adds `CI_RUNNER_ONDEMAND_FLOOR × 4`
on top of it (§3, §4) — currently 8 more slots, and the only 8 that cannot be reclaimed.

To scale, move either number:

    CI_RUNNER_COUNT=12 ./scripts/ci-runners-up.sh           # more spot boxes
    CI_RUNNER_ONDEMAND_FLOOR=4 ./scripts/ci-runners-up.sh   # a deeper guaranteed floor
    CI_RUNNER_ITYPE=c7a.16xlarge CI_RUNNER_AGENTS=8 ./scripts/ci-runners-up.sh

Autoscaling is deliberately **not** here yet. A fixed fleet reconciled on a timer is a cost you can
read off a calendar and a shape you can read off one summary line; an autoscaler is a second system
that fails in its own ways, and it should be added when the fixed fleet is demonstrably the
constraint. Note what the floor is *not*: it is not a minimum an autoscaler scales up from, it is a
floor a **reclaim** cannot scale below.

## 3. What it costs

| line | measured |
|---|---|
| c7a.8xlarge on-demand, us-east-1 | **$1.6422 /hr** |
| c7a.8xlarge **spot**, us-east-1a (2026-09-08) | **$0.667 /hr** — 59% off |
| EBS: 300 GB gp3 + 6000 IOPS + 500 MB/s, per box | ≈ $54 /month ≈ $0.074 /hr |
| fleet of 4, all-in while running | ≈ $2.97 /hr |
| 8 spot boxes, all-in while running | ≈ $5.93 /hr — $5.34 spot + $0.59 EBS |
| **on-demand floor of 2 (`CI_RUNNER_ONDEMAND_FLOOR`)** | **≈ $3.28 /hr extra** — 2 × $1.6422 |
| the floor's EBS, 2 × 300 GB gp3 | ≈ $0.15 /hr |
| **current fleet: 8 spot + 2 on-demand, all-in** | **≈ $9.36 /hr** |

The floor is the single largest line here and it is bought deliberately. On 2026-09-09 the fleet hit
zero **twice in one day** — once from the nightly stop, once from `instance-terminated-no-capacity`
taking all eight `c7a.8xlarge` in `us-east-1a` at the same instant — and both times agents went on
pushing into a queue with nothing behind it. $3.28/hr is what it costs for that number to be two
instead of zero. The owner's ruling: *keep those EC2 boxes up, I don't want us pushing builds and
them not landing.*

Set `CI_RUNNER_ONDEMAND_FLOOR=0` to go back to spot-only. Nothing else needs to change.

**Spot is still where the throughput comes from,** and it is now spread rather than concentrated.
CI is interruption-tolerant by construction: a reclaimed box loses at most the jobs in flight on it,
and `concurrency: cancel-in-progress` means a re-push would have killed them anyway. What changed is
that "spot" no longer means one instance type in one AZ — see §4.

## 4. Start, stop, scale

```sh
./scripts/ci-runners-reconcile.sh   # THE ONE TO RUN. Top up, sweep ghosts, register, refresh
CI_RUNNER_COUNT=8 ./scripts/ci-runners-up.sh   # create/scale from nothing. Idempotent
./scripts/ci-runners-register.sh    # mint an org registration token and register every agent
./scripts/ci-runners-ssh.sh         # ssh key + session-manager-plugin + ~/.busbar-fleet
./scripts/ci-runners-down.sh        # deregister + terminate the SPOT boxes; the floor SURVIVES
./scripts/ci-runners-down.sh --all  # …everything, floor included
./scripts/ci-runners-lint.sh        # bash -n + shellcheck -x over all nine scripts
./scripts/ci-runners-selftest.sh    # the registration path, stubbed — no AWS, no gh auth, no fleet
CI_RUNNER_DRY_RUN=1 ./scripts/ci-runners-<anything>.sh   # print the AWS calls, make none
```

**`ci-runners-reconcile.sh` is the entry point, and `up.sh` is what it calls into.** Reconcile is
the only one of these that is safe on a timer, and §7 is written around it.

**`down` leaves the floor standing.** `down` is what you run to stop paying for a burst, to get a
clean slate after a disk-full box, or at the end of a long session — and every one of those is a
moment when the next agent's push must still land. Only `--all` takes the fleet to zero, and it says
so in its name.

`ci-runners-up.sh` is also the scale-up command: it leaves running boxes alone and launches the
difference. Bootstrap takes 8–12 minutes (apt, rustup, the runner tarballs, and a full pre-warm
build so the first real job is a warm job).

### Two kinds of capacity

`up.sh` launches the **on-demand floor first**, then the spot capacity. The floor goes first
deliberately: if the account is at an instance limit or the launch template is wrong, the thing that
fails is the spot top-up and the guaranteed capacity is already up. The reverse order gets you eight
spot boxes and no floor on exactly the day the floor is the point.

The two are counted **separately**, off EC2's own `InstanceLifecycle` field rather than a tag we
might have failed to write — because "the fleet has 8 boxes" is not the fact that matters after a
reclaim. "The fleet has 0 boxes that cannot be reclaimed" is.

Floor boxes are otherwise **identical**: same AMI, same bootstrap, same labels, same four agents.
A job cannot tell which kind it landed on, and nothing in any workflow names one.

### Spot goes across every pool, not into one

One instance type in one AZ is **one capacity pool**, and `instance-terminated-no-capacity` is a
statement about one pool. Eight boxes in it is not eight machines, it is one machine with eight
names — which is precisely how the fleet went to zero on 2026-09-09.

So `up.sh` asks EC2 which `(AZ, instance-type)` pairs actually exist and requests spot against all
of them at once:

    c7a.8xlarge  m7a.8xlarge  c6a.8xlarge  c7i.8xlarge     (CI_RUNNER_ITYPES)
    × every AZ of the default VPC that offers them          → 20 pools in us-east-1

All four types are **32 vCPU and x86-64**, so `CARGO_BUILD_JOBS=32/AGENTS` — the load-bearing pin
above — holds unchanged whichever one a box turns out to be.

The request is a single `create-fleet --type instant` with `AllocationStrategy=price-capacity-optimized`,
which picks the pools with the deepest capacity at the best price rather than the cheapest pool
outright. `instant` because this is a script a human or a timer runs: the instance ids come back
synchronously and **no durable fleet object is left behind** to drift, double-provision, or need
deleting. Whatever the fleet request cannot fill is then retried as per-AZ `RunInstances` against
the same pool list — a different *mechanism*, not a retry of the one that has just declined.

**The offerings lookup is not decoration.** `us-east-1e` offers none of these four types, so a naive
cross product would spend a fifth of its overrides on guaranteed `Unsupported` errors and produce a
request that only *looks* diversified. Ask EC2 which pools exist before asking it for capacity.

**User-data is capped at 16384 bytes, so it is gzipped.** The bootstrap outgrew the cap;
`CreateLaunchTemplateVersion` refused it — and refusing a *new* version leaves the OLD one as
default, so `run-instances --version $Latest` launched four boxes from a template that predated the
GitHub CLI, python3-venv and the per-agent cargo homes. A scale-up that "succeeds" into a stale
image is the worst failure available here: the boxes register, take jobs, and fail them for reasons
that were fixed hours earlier. cloud-init decompresses gzipped user-data before executing it
(16734 bytes raw → 6588 encoded), the encoded size is asserted against the cap before EC2 is asked,
and a refused version now **stops** the scale-up instead of being logged and ignored.

**`ci-runners-reconcile.sh --converge` is the way out of that state**, and the way a fix reaches the
boxes in a minute rather than a bootstrap cycle per box that also discards the warm `target/` and
sccache. It is idempotent, and it does not restart the agents unless given `--restart`.

Convergence is behind a flag because it is an apt install, a rustup check and a 900-second SSM
window on **every** box — not a thing to do four times an hour on a healthy fleet. The default
reconcile pass does not touch the insides of a box at all.

**The registration token is never stored.** `POST /orgs/GetBusbar/actions/runners/registration-token`
is called at registration time, travels to the boxes over SSM SendCommand, and is used within
seconds. It is never in user-data — user-data is readable from the instance metadata service by
every job the box will ever run, which is arbitrary code from any branch an agent pushes. A token in
user-data is a token handed to untrusted CI.

**Order matters in `down`.** Terminating first would leave the org's runner list full of entries
GitHub still believes are available, and a job routed to a dead runner sits `queued` until the 24h
timeout with no error anywhere. So: deregister (the boxes are still alive to be told), then
terminate, then sweep every `offline` org runner regardless.

**The nightly stop is OPT-IN, and off by default.** It used to be on: a systemd timer ran
`shutdown -h` at 02:00 PT, and with `InstanceInitiatedShutdownBehavior=terminate` that is a
terminate. It fired, and the failure was worse than the bill it was avoiding — there is no working
day here, agents push around the clock, and **nothing brings the fleet back**; `ci-runners-up.sh` is
a command someone runs, not a schedule. By morning: zero instances, **32 offline runner
registrations still absorbing jobs**, and keep-proof runs queued behind machines that had not
existed for seven hours, with no error anywhere saying so. A cost control that silently takes CI to
zero and needs a human to notice is not a cost control.

```sh
CI_RUNNER_NIGHTLY_STOP=1 ./scripts/ci-runners-up.sh   # only alongside something that restarts it
```

`ci-runners-reconcile.sh --converge` removes the timer from any box that still carries one, so a box
born before this default changed cannot keep it by accident. (It is on the `--converge` path, not
the timer path, because it is an SSM round-trip into every box — and a box launched today never had
the timer to begin with.)

Even so, the nightly stop is now the *second*-worst way this fleet has reached zero. See §7 for the
first, and for the loop that means neither one needs a human to notice.

## 5. What is on a box

* Ubuntu 24.04, x86-64 (the `x64` label and the release artefacts both mean x86-64)
* Rust at the channel `rust-toolchain.toml` pins (1.98.0), with clippy and rustfmt
* Docker, for the oracle's postgres / mysql / valkey service containers
* `sccache` **per agent**: `/opt/runner-N/sccache`, 20 G, on its own server port `4226+N`. Not
  shared, and that is not an oversight — see the table below. The S3 bucket, its 14-day lifecycle
  and the instance-profile policy that reads and writes it are provisioned anyway, so a genuinely
  fleet-shared cache (with no local server contention at all) is
  `CI_RUNNER_SCCACHE=s3 ./scripts/ci-runners-up.sh` and a relaunch. No workflow names a backend.
* Four unpacked runner agents under `/opt/runner-N`, each a systemd service, each with its own
  `_work` tree, `.env`, `CARGO_HOME` and `RUSTUP_HOME`
* **A clean-workspace hook, not `--ephemeral`.** An ephemeral runner deregisters after one job and
  needs a *fresh* token to come back — precisely the credential this design refuses to keep. The
  `ACTIONS_RUNNER_HOOK_JOB_STARTED` hook is stronger than `--ephemeral` for the thing that actually
  bites (a stale workspace, a leftover container) while keeping the warm cargo and sccache state
  that is the whole reason to run a persistent box. The hook is invoked by the runner as
  `bash -e <hook>`, so every line in it is forgiven explicitly and it ends in `exit 0`: a cleanup
  step must never be able to fail a job it was only meant to tidy up for.
* **No inbound ports.** The security group's ingress list is empty. A runner dials out and holds the
  connection; nothing ever dials in. Admin and ssh both travel over SSM.

### What the hosted image had that a bare Ubuntu box does not

Every one of these was found by a real run failing, and every one is now in the bootstrap so a
replacement spot box is born with it:

| missing | how it failed |
|---|---|
| `gh` | `gh: command not found`, exit 127 — on the *last* step of a six-minute oracle job that had already produced `18 owed, 0 diverging` |
| `python3-venv` | `bin/oracle` builds a venv; Ubuntu 24.04's `python3` has no ensurepip, so the pinned tool never installed and surfaced four steps later as `ModuleNotFoundError: No module named 'busbar_oracle'` |
| one sccache server per agent | four agents share port 4226 by default; one job's `sccache --stop-server` killed a neighbour mid-compile with `Connection reset by peer (os error 104)` **inside rustc** |
| one `CARGO_HOME` per agent | rustup is not concurrency-safe; two `dtolnay/rust-toolchain` steps racing left `~/.cargo/bin/rustup` missing and every `cargo` on the box "command not found" |
| an `-e`-safe job hook | the runner invokes the hook as `bash -e`, so a `find` returning 1 failed `Set up runner` and killed a shard in three seconds |

`node` is still absent from the box; `actions/setup-node` provides it for the one job that needs it,
and the runner bundles its own for actions. A `run:` step that calls `node` directly would fail.

**Do not restart the runner services while jobs are in flight.** `svc.sh stop` kills the job, and the
run reports `failure` with *no failed step*, which is indistinguishable at a glance from a real red.
Six jobs were lost this way while the fleet was being tuned. Drain first, or accept the re-run.

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

## 7. The fleet is at zero

Symptom: jobs sit in `queued` forever with no error. `runs-on` has **no hosted fallback** on purpose
— a fallback is a fleet outage nobody notices until the bill arrives — so a dead fleet is a stopped
queue, loudly.

### Run reconcile. That is the whole first step.

```sh
export AWS_REGION=us-east-1
export PATH="$HOME/.local/bin:$PATH"
./scripts/ci-runners-reconcile.sh
```

It is idempotent, it is a no-op when the fleet is healthy, and it **exits 0 whatever happened** — so
it is also the right thing to run when you are not sure there is a problem. One pass, in this order:

1. **Top up.** Spot to `CI_RUNNER_COUNT`, on-demand to `CI_RUNNER_ONDEMAND_FLOOR`, counted
   separately off `InstanceLifecycle` and launched across every pool (§4).
2. **Sweep the ghosts.** Every `offline` org registration whose instance no longer exists.
3. **Register** the boxes that are short of agents — and *only* those, through `register_agents`
   in `scripts/ci-runners-lib.sh` (§ *Registration is a library call*).
4. **Refresh** `~/.busbar-fleet` and the remote-prove bare repo + checkout on every box.

It ends in one line:

```
reconcile: spot 8/8, on-demand 2/2, online runners 32, swept ghosts 0, registered 0, remote-prove 10/10
```

`spot 0/8` is a fleet that is down. `online runners 0` alongside `spot 8/8` is a registration
problem, not a capacity problem. That line is the whole status report.

### Registration is a library call, not an exec of a sibling script

`register_agents` — the token mint and the SSM dispatch — lives in `scripts/ci-runners-lib.sh`, and
both `ci-runners-register.sh` (the operator's entry point) and the reconcile's step 3 call it. It
used to live only in `ci-runners-register.sh`, which the reconcile ran as
`"$HERE/ci-runners-register.sh" $REACHABLE >/dev/null 2>&1 || true`.

On 2026-09-10 a spot interruption wave replaced seven boxes and the fleet sat at **8 agents online
of 40 for over an hour**. Every replacement had finished its bootstrap and unpacked all four runner
trees; the AMI, the user-data, the labels and the egress were all fine. The reconcile was being run
from a *copied* scripts directory that contained everything it sources except that one sibling. The
exec failed 127 into `/dev/null`, `|| true` discarded it, and each pass printed

```
registering: i-0a51811c6fb5a08e6 i-06997fa8615add7ae …
  (still no agents online on those boxes — bootstrap is not finished; the next pass retries)
```

which is a true sentence about a fleet that had finished bootstrapping forty minutes earlier and
would never register, because nothing had been dispatched.

Two properties now hold, and `scripts/ci-runners-selftest.sh` checks both:

* **A partial `scripts/` copy cannot silently skip registration.** The reconcile cannot start
  without `ci-runners-lib.sh` — sourcing it is fatal when it is missing — so anything that can run
  the reconcile at all can register.
* **A failed registration is reported as itself.** `register_agents` returns non-zero on an empty
  token (the org API limit) or a rejected/failed SSM command, and the reconcile prints
  `REGISTRATION STEP FAILED (rc=…) — these boxes will NOT come online on their own` instead of the
  line about bootstrapping.

### Why the order of 2 and 3 is load-bearing

Register first and the new box's agents join a pool that **still contains the dead box's agents**,
and GitHub goes on routing jobs into the corpse. An `offline` org runner is a routing black hole:
GitHub hands it a job, the job never runs, and it sits `queued` until the 24h timeout with no error
anywhere. That is not hypothetical — it is exactly what the nightly stop left behind, **32 of them**,
absorbing work all night. Sweep the dead, then add the living.

### Why the sweep checks existence, not offline-ness

`ci-runners-down.sh --all` deletes every `offline` runner, and that is correct when the fleet is
being torn down: there is nothing left, so "offline" and "dead" are the same word.

On a fifteen-minute timer it is **wrong**. A box eight minutes into its bootstrap is offline and very
much alive, and deleting its registration would make a real box unreachable — after which the next
pass would "fix" it by registering it again, forever. So reconcile maps the runner name back to the
instance id the bootstrap minted it from (`ec2-<id-minus-i->-<agent>`) and removes only the
registrations whose instance EC2 no longer lists **in any state**. Names that do not match the
fleet's pattern belong to something else and are left strictly alone.

### Put it on a timer

The fleet went to zero twice on 2026-09-09 and both recoveries needed a human to notice.
`ci-runners-up.sh` is a command someone runs; this is the one that can be a schedule:

```sh
*/15 * * * * cd /path/to/busbar && AWS_REGION=us-east-1 PATH="$HOME/.local/bin:$PATH" \
  ./scripts/ci-runners-reconcile.sh >> /tmp/busbar-reconcile.log 2>&1
```

It exits 0 on a healthy pass, on a pass that could not reach a bootstrapping box, and on a pass that
found nothing to do — because a cron that pages on a healthy run is a cron that gets muted by
Thursday. Real breakage is visible in the summary line, not in the exit code.

### If reconcile is not enough

1. **See what it saw.**
   ```sh
   gh api /orgs/GetBusbar/actions/runners --jq '.runners[]|"\(.name) \(.status) busy=\(.busy)"'
   aws ec2 describe-instances --filters Name=tag:Name,Values=busbar-ci-runner \
     Name=instance-state-name,Values=running \
     --query 'Reservations[].Instances[].[InstanceId,InstanceLifecycle,Placement.AvailabilityZone]' \
     --output text
   ```
   A `None` in the lifecycle column is an on-demand floor box. If that column is all `spot`, the
   floor is missing and the next reconcile rebuilds it.

2. **Nothing exists at all** — the launch template, IAM role, security group or sccache bucket are
   gone. That is `up.sh`'s job, not reconcile's: `CI_RUNNER_COUNT=8 ./scripts/ci-runners-up.sh`.
   Reconcile launches capacity; it does not provision the account.

3. **See what it would do without doing it.** Every script honours it:
   ```sh
   CI_RUNNER_DRY_RUN=1 ./scripts/ci-runners-reconcile.sh
   ```
   Read-only describes still run, so this is a real report about the real fleet. It never mints a
   credential — a dry run of `down` used to print a live org remove-token, which is why it now
   refuses to request one at all.

4. **A box is up but jobs fail immediately.** Look at `Set up runner` — that is the job hook. Then:
   ```sh
   ~/.busbar-fleet-ssh ubuntu@i-0abc… 'tail -50 /var/log/busbar-runner-bootstrap.log'
   ~/.busbar-fleet-ssh ubuntu@i-0abc… 'systemctl list-units "actions.runner.*"'
   ```
   If several boxes are wrong the same way, the bootstrap changed under them:
   `./scripts/ci-runners-reconcile.sh --converge`.

5. **Disk.** Four agents × their own `target/` on 300 GB. The hook prints `df -h /` at the top of
   every job; if it is tight, `./scripts/ci-runners-down.sh` (which leaves the floor up) followed by
   a reconcile is a clean slate in ten minutes, or raise `CI_RUNNER_DISK_GB`.

6. **The escape hatch.** Actions is the judge for `integration/*`, `qa` and `main` regardless; for a
   hand-back, `./scripts/prove-remote.sh` needs only ONE box and no runner registration at all — it
   is ssh and a push. A fleet with a broken Actions registration can still prove work, and the
   on-demand floor means there is always a box for it to use.

### "The fleet is slow" is usually not the fleet

Before adding boxes or widening a timeout, look at CPU. A job that has burned 25 minutes at ~4% CPU
is not starved, it is blocked. The one that cost the most time here:

```
pid ...  xtask gate --all           wchan=anon_pipe_write  state=S  etime=43:25
pid ...  git ... cat-file --batch   wchan=anon_pipe_write  state=S  etime=41:22
```

Both ends blocked *writing*. `git cat-file --batch` is a request/response coprocess: the parent must
drain its stdout while feeding its stdin. Nobody drained, both pipe buffers filled, both sides
blocked forever — on an **idle** box, load average 0.02. `cargo xtask gate --all` deadlocks this way
on the current tree, which is why the `xtask` test leg cannot pass at any per-binary ceiling.

The per-binary watchdog (`BINARY_TIMEOUT_SECS=1500`) caught it correctly and said so. It was raised
to 3000s once, on the assumption that a shared box had merely made a 15-minute suite slower. That
was wrong and has been reverted. **A watchdog you widen every time it fires is a watchdog you have
turned off slowly.** Read `wchan` first:

```sh
~/.busbar-fleet-ssh ubuntu@i-0abc... 'ps -eo pid,etime,pcpu,wchan:20,args --sort=-etime | head -20'
```

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

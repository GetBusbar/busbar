# The fleet's cost

`docs/ci/self-hosted-runners.md` is how the fleet is built. This is what it costs, why the bill was
what it was, and the four knobs that decide it.

---

## 1. The measurement that started this

The owner measured **$569 for eighteen boxes that were mostly idle.**

The interesting word is *idle*. The fleet was not short of CPU; it was short of **proof slots**.
A proof slot is one landing or one pre-proof, `BUSBAR_PROVE_PER_BOX` of them per box (2), and every
self-test battery inside a proof ran its cases **one at a time on one core**. A 32-vCPU box holding
two proofs was therefore using two cores to do the work and paying for thirty-two. Eighteen boxes
were bought because eighteen boxes were the only way to get thirty-six slots; the CPU underneath
them was never the thing being bought.

Two things changed that, and this document is about spending the second one:

1. **The batteries went multi-core** (`--jobs N`; `docs/design/xtask-gates.md` §2.2). A battery now
   takes its cases across the box's cores, so a gate-only union proof is ~908 s of wall clock on 32
   vCPU instead of hours. One box now does in minutes what a slot used to hold for an hour.
2. **An idle box is now STOPPED, not left running** (`scripts/ci-fleet-power.sh`). The fleet's shape
   follows the work instead of standing by for it.

---

## 2. Stop, not terminate

A **terminated** box loses its EBS volume, and that volume is `~/busbar.git`, `~/busbar-prove`, the
warm `target/` and the sccache — between eight and twenty minutes of bootstrap plus a cold first
build, paid again on the next proof. A **stopped** box keeps all of it, keeps its instance id, keeps
its runner registrations, costs gp3 storage alone, and is proving again in 60–90 s.

| state | what it costs, c7a.8xlarge + 300 GB gp3 |
|---|---|
| running | **$1.6422 /hr** compute + **$0.074 /hr** storage |
| **stopped** | **$0.074 /hr** storage — 4.3% of the running box |
| terminated | $0, and the next proof pays a cold bootstrap and a cold build |

So stopping is ~96% of the saving with none of the loss. That is the whole argument.

### How a proof is never stopped out from under itself

Not "the box looks quiet". Loadavg is a one-minute average and a proof that started forty seconds
ago is not in it; a box carrying four CI runner agents is never quiet anyway.

The box carries its own protocol at `~/.busbar-power.sh` (printed by `power_box_script()` in
`scripts/ci-fleet-power.sh`, reinstalled on every pass). The stopper's check and the proof's
announcement take **the same lock on the box**, so there are only two interleavings:

| order | what happens |
|---|---|
| stopper first | it counts zero live proofs, writes `~/.busbar-stopping`, releases. Every later proof-start takes the lock, sees the mark, and **refuses the box** — `prove-remote.sh` exits 2, `land-remote.sh` exits 2 (a landing that did not happen, which the queue re-queues; never a red). |
| proof first | its pid file is written under the lock. The stopper takes the lock, counts 1, reports **BUSY**, and does not stop the box. |

There is no third order. Two supporting rules:

* **The registry is pid files, both kinds.** `<checkout>/.proof.pid` is what a slot pre-proof
  writes; `<checkout>/target/land-remote-<ref>.pid` is what a landing *and every sweep pre-proof*
  writes, because those go through `land.run.local.sh` and never touch `.proof.pid`. A registry that
  read only the first would stop boxes mid-landing. That case is red-first in the selftest.
* **A box with no `~/.busbar-power.sh` is never stopped.** Without the admit half, a claim is a
  promise nothing is keeping. The pass installs the script and the box becomes stoppable on the next
  one. A claim that is made and then *not* carried out is cleared, or the box would refuse every
  proof forever while reading to the allocator as simply never ready.

### How a sweep gets the boxes back

`scripts/landq4.sh`'s pre-prove sweep asks for what it is about to use, **before** it probes:

```
lq_sweep_slot_demand <live lines> <chained holds> <base replay?> <batch in flight?>
  -> ci-fleet-power.sh --ensure-slots D
```

`D` is one slot per live line, one per chained hold, one for the base-only replay (a proof of the
tip itself, on a box of its own) and one for the batch the runner is about to pop — but **not** for
a batch already in flight, which is holding a box that already reports itself busy.

`--ensure-slots` subtracts the free slots on the boxes already awake, starts only the whole boxes the
shortfall needs at `BUSBAR_PROVE_PER_BOX` slots each, and **waits for the same readiness probe the
allocator asks** (`test -d ~/busbar.git && test -d ~/busbar-prove`, then the stop mark cleared). A
box that is merely starting is not free; a box counted before it is ready is a line dispatched into a
bootstrap. It never goes past `CI_RUNNER_RUNNING_MAX`; when it cannot get there the sweep dispatches
to what there is and says so, exactly as it does when the fleet is short for any other reason.

---

## 3. The four knobs

| knob | default | what it decides |
|---|---|---|
| `LANDQ_IDLE_STOP_MINS` | 15 | minutes with **no proof** before a box is stopped. Measured on the box's own registry, not its load. |
| `CI_RUNNER_ONDEMAND_FLOOR` | 2 | the floor of **REGISTERED** boxes. **A stopped box counts.** It keeps its EBS, its id and its registrations and is 60–90 s from proving; counting only the awake ones would make the reconcile launch a replacement for every box the stopper just put to sleep — the whole saving spent on new boxes, each ten minutes from being useful, with the stopped originals still billed for storage. |
| `CI_RUNNER_RUNNING_MAX` | the floor | how many boxes may be **AWAKE** at once. This is the factor that multiplies the hourly rate; the floor only multiplies EBS. The starter never takes the fleet past it. |
| `CI_RUNNER_RUNNING_MIN` | 2 | how many boxes stay awake for the GitHub Actions jobs that are **not** proofs. A fleet stopped to zero holds every ordinary CI job `queued` until the next sweep happens to want a box. |
| `BUSBAR_PROVE_PER_BOX` | 2 | proof slots per box — see §4, which is about what that number may honestly be. |
| `CI_RUNNER_POWER` | 1 | `0` turns the idle stopper off in `ci-runners-reconcile.sh`. |

The stopper runs on the reconcile's fifteen-minute timer, before the ghost sweep, never under
`--converge`. A stopper that runs when somebody remembers is the nightly-stop lesson with the sign
reversed.

```
./scripts/ci-fleet-power.sh --status          # what is awake, what is asleep, what is busy
./scripts/ci-fleet-power.sh --stop-idle       # the 15-minute pass, by hand
./scripts/ci-fleet-power.sh --start 3         # start three and wait for readiness
./scripts/ci-fleet-power.sh --ensure-slots 8  # start only what 8 slots are short of
CI_RUNNER_DRY_RUN=1 ./scripts/ci-fleet-power.sh --stop-idle   # print the calls, make none
./scripts/ci-fleet-power.sh --selftest        # the whole mechanism against a stubbed `aws`
```

---

## 4. The per-box slot ceiling, measured

**The measurement.** One 32-vCPU fleet box (`c7a.8xlarge`-class, 61 GiB, the batteries at
`6222dd608`). N proof-slot-shaped battery sets run **at once**, each in its own seeded checkout with
its own sccache port and `CARGO_BUILD_JOBS=8` — which is what N concurrent proofs on one box
actually are. Each set is `kind-isolation --selftest` then `construction --selftest`, the two
batteries every landing pays for by design.

**The verdict that matters is not the wall-clock ceiling.** `DEFAULT_SELFTEST_CEILING` is 1800 s and
nothing came near it, even at N=4. The budget that decides the ceiling is the batteries' own
**work-unit budget** (`gates::SELFTEST_BUDGETS`) — a self-calibrating ruler, deliberately denominated
in arithmetic rather than seconds so that a slow or contended box does not turn a healthy gate red.
`construction`'s budget is **50 000** units; `kind-isolation`'s is **310 000**.

| N | gate | wall s (per slot) | work units | budget | verdict |
|---|---|---|---|---|---|
| 1 | kind-isolation | 112 | 162 351 | 310 000 | **INSIDE** (52%) |
| 1 | construction | 76 | 37 107 | 50 000 | **INSIDE** (74%) |
| 1 | **set** | **188** | | | **inside** |
| 2 | kind-isolation | 176, 178 | 180 570, 190 769 | 310 000 | INSIDE (58%, 62%) |
| 2 | construction | 659, 656 | 57 155, 62 931 | 50 000 | **OVER (114%, 126%) — RED** |
| 2 | **set** | **835** | | | **over budget** |
| 3 | kind-isolation | 284, 286, 286 | 211 577, 215 408, 197 905 | 310 000 | INSIDE (64–69%) |
| 3 | construction | 695, 699, 700 | 62 827, 104 255, 83 959 | 50 000 | **OVER (126–209%) — RED** |
| 3 | **set** | **986** | | | **over budget** |

**The ceiling is N = 1** for a battery set that contains `construction`, on a 32-vCPU box. Not
because anything hangs — every wall figure is inside the 1800 s ceiling with room to spare — but
because `construction` spends 14% to 109% more than its budget the moment it shares the box, and a
battery over its budget is a **RED landing**. The harness says so in its own words: at N=2 it
re-took the battery at `--jobs 1` and reported *"EVERY finding above went away at `--jobs 1` over 36
case(s)"*. The red is the budget, not the gate.

`kind-isolation` alone holds at N ≥ 3 (64–69% of budget at N=3), so the ceiling is a property of
**`construction`**, and specifically of its planting: 44–45 s of the run is one plant on one thread,
and the work-unit ruler under-corrects for a co-tenant on that shape.

**Read this as "how many cores a slot needs", not "how many slots a box holds".** What N=2 measures
is a slot with a ~16-core share; what N=1 measures is a slot with 32. Only the 32-core share is
inside budget, and that is the fact §5 sizes the fleet with.

**The cheaper fix, not taken here.** Raising `construction`'s budget would make the ceiling 2 or 3
on today's boxes and halve the fleet again. It is not this slot's call: the budget is a regression
guard against a rule that grows a whole-tree scan per plant, and raising it to accommodate
contention is exactly the *"budget somebody raises without reading it"* its own comment warns about.
The honest alternative is to make `construction`'s planting cheaper (its 45 s single-threaded plant
is the whole co-tenancy penalty) and re-measure.

---

## 5. What a proof costs on each size

Prices from `aws pricing get-products` (AmazonEC2, US East (N. Virginia), Linux, Shared tenancy,
`capacitystatus=Used`), read 2026-09-11; gp3 from the same API.

| type | vCPU | on-demand $/hr | gp3 |
|---|---|---|---|
| c7a.4xlarge | 16 | **0.8211** | $0.080 /GB-month |
| c7a.8xlarge | 32 | **1.6422** | (300 GB + 6000 IOPS + 500 MB/s ≈ **$54/mo ≈ $0.074/hr** per box) |
| c7a.16xlarge | 64 | **3.2845** | |
| m7a.8xlarge | 32 | 1.8547 | (the fleet's second type; 13% dearer for the same 32 vCPU) |

**The proof unit** is one gate-only union proof, ~908 s = 0.2522 h of wall clock on a 32-vCPU box.

| shape | core share per slot | inside budget? | $/proof |
|---|---|---|---|
| c7a.4xlarge, `PROVE_PER_BOX=1` | 16 | **no** — the N=2 condition, `construction` over budget | $0.326 |
| c7a.8xlarge, `PROVE_PER_BOX=2` (today) | 16 | **no** — measured RED at N=2 | $0.190 |
| **c7a.8xlarge, `PROVE_PER_BOX=1`** | **32** | **yes** | **$0.414** |
| **c7a.16xlarge, `PROVE_PER_BOX=2`** | **32** | **yes** | **$0.414** |
| c7a.16xlarge, `PROVE_PER_BOX=4` | 16 | no — the same 16-core share | $0.207 |

The two cheap rows are cheap because they are red. Cost per *proof* is meaningless if the proof is
a red landing that then bisects at the full price per half; the only honest comparison is between
the two rows that are inside budget, **and those two are the same price to four decimal places**
(1.6422 × 0.2522 = 0.4142; 3.2845 × 0.2522 ÷ 2 = 0.4142). Per slot-hour, a 32-core share costs
$1.6422 whichever box it is cut out of.

### The 12-line sweep + 1 batch + 4 RAIL-14 pre-proofs = 17 slots

| | c7a.8xlarge @ PER_BOX=1 | c7a.16xlarge @ PER_BOX=2 |
|---|---|---|
| boxes | **17** | **9** (18 slots, one spare) |
| all awake, compute | $27.92 /hr | $29.56 /hr |
| one 17-slot dispatch (908 s + ~90 s start = 0.277 h) | **$7.73** | **$8.19** |
| **standing cost, all stopped** (EBS only) | **$918 /mo** | **$486 /mo** |
| boxes to start, probe, register, reconcile and keep | 17 | 9 |

**Recommendation: `c7a.16xlarge` with `BUSBAR_PROVE_PER_BOX=2` and `CI_RUNNER_RUNNING_MAX=9`.**

The two shapes cost the same per proof and within 6% per dispatch. The difference is the term the
$569 was made of: a fleet that is mostly idle pays for **boxes**, not for proofs. Nine boxes stopped
cost **$432/month less** than seventeen stopped, halve the SSM/ssh fan-out every probe round makes,
halve the registrations the ghost sweep has to reason about, and halve the EBS that has to be
re-warmed after a terminate. The price is $0.46 more on each 17-slot dispatch and a coarser
granularity — a box is two slots, so a 13-slot sweep wakes seven boxes and idles one slot.

**Not applied.** Changing the instance type means relaunching boxes, which discards their warm
`target/` and sccache; it belongs in a deliberate resize alongside `CI_RUNNER_ITYPE`,
`CI_RUNNER_ITYPES` and the `CARGO_BUILD_JOBS=32/AGENTS` pin in
`docs/ci/self-hosted-runners.md` §2, not in the commit that measured it.

**Whatever shape is chosen, `BUSBAR_PROVE_PER_BOX=2` on a 32-vCPU box is the one setting §4 says is
wrong today** — it is the 16-core share that put `construction` 14–26% over budget. On the current
fleet the safe setting is `BUSBAR_PROVE_PER_BOX=1`, at the cost of halving the slots per box; that
is a `landq4`/`prove-remote` knob, not a relaunch, and it is the one change here an operator can
make today.

---

## 6. Two failures this document exists to prevent

**The fleet went to zero twice in one day** (2026-09-09) — the nightly stop, and
`instance-terminated-no-capacity` taking eight same-type same-AZ spot boxes at once. That is why
there is a floor at all, and why this mechanism **stops** rather than terminates and has a
`CI_RUNNER_RUNNING_MIN`.

**The queue runner HALTed on a fleet that was up** (11:5x) with

```
no prepared, reachable on-demand box among the 0
```

minutes after the fleet was resized 18 → 10 and the reconcile swept 32 ghost registrations — with
ten boxes running and `~/.busbar-fleet` naming all ten. "Prepared" is `test -d ~/busbar.git &&
test -d ~/busbar-prove` asked over the SSM tunnel inside a 15 s bound, and that one round landed in
the churn: every box timed out at once, and the **empty table was cached for the whole sweep**, so
every later allocation read zero rows and no box was ever asked again. Two fixes, both about the
difference between *no answer* and *no fleet*:

* `fleet_table_open` refuses to cache a round in which not one box answered, and says the **round**
  failed. The sweep falls back to one round per allocation.
* `fleet_pick_host`, with no table and not one box answering, re-asks once at 45 s
  (`FLEET_PROBE_RETRY_TIMEOUT`) before halting. Never *through* an open table, where a dropped box
  stopped answering and a taken box is at its ceiling.

And the other half of the same halt: `write_fleet_file` used `> "$f"`, which **truncates before the
query runs**. A describe that is throttled, mid-resize or unauthorised left the allocator's only
knowledge of the fleet as four comment lines. It is now a temporary, a refusal to install an empty
file while boxes are running, and an `mv`.

A file that is merely *stale* costs one skipped box on the next allocation, which the probe round
already handles. A file that is *empty* costs the queue.

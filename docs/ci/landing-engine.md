# The landing engine

`scripts/landq4.sh` lands the queue: it pops a batch, proves it on a fleet box, pushes what went
green and parks what did not. This page is about the **engine around it** — how it is started, how
it is adopted when a new version of itself lands, what its exit status means, and what an
integrator has to do (very nearly nothing).

The fleet it proves on is `docs/ci/fleet.md`. The queue commands are `scripts/landq-ctl.sh`.

---

## 1. The one command

```bash
bash scripts/landq-supervisor.sh          # from ANY directory that is not the runner tree
```

That is the whole restart procedure. No env line, no staged copy under `land-fanout-<sha>`, no
`nohup` incantation out of the ledger. The supervisor reads `~/.busbar-engine/env`, starts
`landq4.sh` with it, waits for it, and decides what to do next from the exit status alone.

Run it from outside the tree it lands into: started inside, it would be a stranger process in the
runner tree, and the census would kill it (one engine in the tree).

The runner recognises **its own chain by PID** — the holder of the host lock and every descendant of
it — never by what the command line says. A supervised start (`bash landq-supervisor.sh` → `bash
~/.busbar-engine/current/scripts/landq4.sh`, from a scratch cwd) names the tree in no argv and no
cwd; judged by text the census saw nothing at all, called itself broken, and refused every batch
with `NONE:census-empty` at every loop top (measured 2026-09-11). Strangers are still judged by the
three text forms — identity by pid exempts the runner's chain, not the host.

Useful arguments: `--selftest` (every decision, against a stub runner), `--once` (one start, one
decision, then return), `--help`.

---

## 2. The engine home

```
~/.busbar-engine/
  current/scripts/…   a `git archive` of the landed tip's scripts/ at the sha below
  sha                 the sha that archive was taken at — "which engine is running", as a fact
  env                 the restart line, as a file (template: scripts/landq.env.example)
  PAGED               present = a HALT is waiting for the integrator; nothing starts
  ADOPT               present = the STOP marker in the tree is the supervisor's, for an adoption
  PIN                 present = adopt nothing, whatever lands (an engine held on purpose)
  last-tip            the TIP as of the last boundary the supervisor saw
  engine-source       the engine BRANCH sha the running engine was cherry-picked from
  supervisor.log      what the supervisor did, one line each
```

`current` is an **archive of one sha**, never a `cp -r` (which carries whatever the source directory
happened to hold) and never a checkout (which anything running `git checkout` can move under the
running engine). `LAND_SH_SRC` is therefore not an operator's choice any more: the supervisor sets
it to `~/.busbar-engine/current/scripts` at every start.

### Adoption is an engine line landing

`landq4.sh` writes `target/gate/landq.boundary` — one line, `<epoch> <tip>` — at the end of every
batch and on its way out through the STOP marker. At each new boundary the supervisor looks at the
**range that just landed**, `last-tip..<new tip>`, and asks one question of it:

> does this range contain a commit that touches `scripts/` **and** carries
> `(cherry picked from commit X)` with `X` in the pinned engine's own branch history?

`X` qualifies when it *is* `engine-source`, or when one of the two contains the other
(`git merge-base --is-ancestor` either way) — an engine branch is cut from the engine branch before
it, so the next engine line always shares history with the last one, and somebody else's branch
never does. That trailer is the only link available: landings are `cherry-pick -x`, so the landed
commit never carries the branch sha, and an ancestry test on the landed sha answers nothing.

When the answer is yes, the supervisor archives **the landed tip's** `scripts/` (not the commit's),
records `X` as the new `engine-source`, and restarts — at the boundary, never mid-batch.

**Why it is provenance and not "the tip's newest `scripts/` commit moved".** Measured 2026-09-11
23:54Z: a batch landed a docs line and, beside it, an unrelated one-file fix to
`scripts/release-script-lint.sh`. `git log -1 <tip> -- scripts/` duly moved — to a commit whose tree
carries seventy scripts and **no `landq4.sh`**. The supervisor stopped a healthy runner, archived
that, and looped `No such file` with exit 127 for five minutes. A `scripts/` change is not an
engine; an engine line is a `scripts/` change with a proof and a provenance.

**An archive is checked before it is swapped in.** `LANDQ_SUP_REQUIRED` (default `landq4.sh
land.sh`) must exist in the archived `scripts/`, or the adoption is refused, logged, and the pinned
engine keeps running. Today's integration tip has no `landq4.sh` at all — the engine is unlanded by
construction while its line is in the queue — so this check alone would have held the line.

Four refusals, each logged by name:

* **no baseline yet** (a first start, or a fresh engine home) — the tip is recorded and nothing is
  adopted. The home is whatever the integrator pinned, and the tip is usually *behind* it.
* **the tip did not move.**
* **`scripts/` moved without an engine line** — a docs line that touches a script, somebody else's
  fix, a lint rule. Never adopted.
* **`~/.busbar-engine/PIN` exists** — nothing is adopted for as long as it is there. Landings are
  still tracked, so removing the pin does not then adopt a line that landed three batches ago.
  `rm ~/.busbar-engine/PIN` resumes.

If a STOP marker is **already** set when the supervisor wants to adopt, that STOP is the
integrator's: the supervisor leaves it alone, keeps the baseline where it is, and adopts at the next
boundary instead.

---

## 3. The exit-code contract

The runner's exit status is the only thing the supervisor reads. It is a contract, declared in
`landq4.sh` (`THE EXIT-CODE CONTRACT`) and proven by both selftests.

| code | meaning | who decided it | the supervisor |
|------|---------|----------------|----------------|
| `0`  | the STOP marker was seen at the loop top (or `--preprove-once`/`--selftest` finished) | an integrator | exits too — unless the STOP was its own adoption, in which case it adopts and restarts |
| `1`  | **HALT head-conflict-twice** — the first queue line would not apply twice in a row | the tree | **pages** and waits: the line needs re-picking by hand |
| `2`  | another runner already holds the host lock | another runner | exits quietly — it will not race a live runner |
| `3`  | **HALT tree-moved** — HEAD has not been the last landed tip (or the tree was modified) for `LANDQ_TREE_MOVED_HALT_AFTER` loops in a row (default 5, i.e. ~15 min of backoff) | the tree | **pages** and waits |
| any other | infrastructure: a crash, a kill, a signal, a driver that escaped its own taxonomy | nobody | **restarts** on the 60 / 120 / 240 / 480 / 900 s ladder, counted in the status file |

**Only the two HALTs are facts about the tree, and only they page.** Every infrastructure failure —
a box that stopped answering, an scp that closed, the base push failing, a probe round with nobody
home, a stale lock — is classed, counted, backed off and retried *inside* the loop and never exits
at all (`landq4.sh`, `THE FAULT TAXONOMY`). An infrastructure reason is never a HALT.

---

## 4. The env file

One file, `~/.busbar-engine/env`, versioned as `scripts/landq.env.example`:

```bash
cp scripts/landq.env.example ~/.busbar-engine/env      # then edit the values
```

Grammar: `NAME=value`, one per line; `#` comments and blank lines ignored. Nothing else — a line
that is not an assignment, or that carries a command substitution, a pipeline or a second command,
is **refused before anything is sourced** and the runner is not started. `$HOME` and `$PATH` expand.

It is read **once per start**, in the subshell that becomes the runner: an edit takes effect at the
next restart and never halfway through one. `LANDQ_ROOT` is required (the tree the runner lands
into); `LAND_SH_SRC` is not read — the supervisor owns it.

---

## 5. Paging and unpaging

A page is a file and a line, not an alert somebody has to be subscribed to:

* `~/.busbar-engine/PAGED` — one tab-separated line per page: `<UTC> <kind> <text>`.
* the status JSON's `supervisor` section (`fault`, `state: paged`) and its `pages` list, which
  `scripts/landq-ctl.sh status` renders as `PAGE: …`.
* the runner's own page ledger (`target/gate/landq4.page.txt`), so the page survives into the next
  runner's status file.

While `PAGED` exists the supervisor starts nothing: it polls and waits. **Unpage by fixing the tree
fact and then removing the file:**

```bash
rm ~/.busbar-engine/PAGED        # the supervisor starts the runner again within a minute
```

There is no other unpage, and there is no flag that makes a HALT restart: a head line that will not
apply is not going to apply on the third try.

---

## 6. First adoption — from the hand-started runner to the supervisor, once

Do this at a boundary, with the runner stopped. It costs one boundary and it is the last one the
engine costs.

1. **Prepare the home** (the runner may still be running):

   ```bash
   mkdir -p ~/.busbar-engine
   cp <repo>/scripts/landq.env.example ~/.busbar-engine/env
   ```
   Edit `~/.busbar-engine/env` so that every variable of the current hand-typed restart line is in
   it — `LANDQ_ROOT`, `LAND_BATCH`, `LAND_CHAIN_DEPTH`, `LAND_SELFTEST_SHARDS`, `LAND_REMOTE`,
   `XTASK_GATE_CEILING_SECS`, `LANDQ_PREPROVE_LINES`, `LANDQ_PREPROVE_HEAD`, `BUSBAR_PROVE_PER_BOX`,
   `BUSBAR_PROVE_SEED`, `LANDQ_IDLE_STOP_MINS`, the four `CI_RUNNER_*` knobs, `AWS_REGION`, `PATH`,
   `LAND_TMP` — and **drop `LAND_SH_SRC`**: it is the supervisor's now.

2. **Ask the running runner for a boundary:**

   ```bash
   touch "$LANDQ_ROOT/target/gate/STOP"
   ```
   It finishes the batch it is in, signals the boundary and exits 0.

3. **Pin the engine that is actually running.** This is the one step nothing can infer: the engine
   in production is usually *ahead* of the tip (its line has not landed yet), so the supervisor must
   be told what it is rather than reading it off the tip.

   ```bash
   ENG=<the engine sha the ledger's restart line names>     # e.g. the branch tip being run today
   git -C "$LANDQ_ROOT" fetch -q origin                     # so the sha is present in the tree
   rm -rf ~/.busbar-engine/current && mkdir -p ~/.busbar-engine/current
   git -C "$LANDQ_ROOT" archive "$ENG" scripts | tar -x -C ~/.busbar-engine/current
   printf '%s\n' "$ENG" > ~/.busbar-engine/sha
   printf '%s\n' "$ENG" > ~/.busbar-engine/engine-source    # the branch provenance is checked against
   rm -f ~/.busbar-engine/last-tip                          # no baseline: the first start adopts nothing
   ```
   The empty baseline is deliberate. The supervisor records the tip at its first start and adopts
   only an engine line that lands *after* it, so a tip that is behind the pinned engine — which is
   the normal state of affairs — can never pull the engine backwards.

4. **When it has exited** (`tail -n 3 "$LANDQ_ROOT/target/gate/landq.out"` says `STOP marker seen`):

   ```bash
   rm -f "$LANDQ_ROOT/target/gate/STOP"
   cd ~                                            # anywhere that is NOT the runner tree
   bash <repo>/scripts/landq-supervisor.sh         # or: nohup … >/dev/null 2>&1 &
   ```
   The supervisor starts the runner on the engine **pinned in step 3**, records the tip's engine as
   its baseline, and from then on adopts every landing that changes it.

5. **Check it once:** `scripts/landq-ctl.sh status` shows the tip, the engine sha and the
   supervisor's state; `cat ~/.busbar-engine/sha` is the engine that is running.

From then on the integrator's whole part in an engine change is queueing the line. There is no
staging directory, no STOP marker and no restart line to re-type.

---

## 7. What the supervisor may not do

* **It never writes the queue.** Not `land-queue.txt`, not the inbox, not a count of either. The
  runner is the only writer of the queue (`scripts/landq-ctl.sh`, F3); the supervisor does not even
  open it, and its selftest asserts that the file never appears in its source.
* **It never kills a batch to adopt.** Adoption goes through the STOP marker and the boundary.
* **It never turns an infrastructure failure into a HALT**, and it never restarts through a HALT.
* **It writes the status file's `supervisor` section only while no runner is alive**, so the
  "one writer, temp+mv" rule the status file was built on still holds.
* **It puts no scratch under `/tmp`** (owner rule): the archive is staged under `$LAND_TMP`.
* **It never adopts anything but an engine line.** A `scripts/` change with no cherry-pick
  provenance from the pinned engine's branch is logged and ignored, an archive without the entry
  points is refused before the swap, and `~/.busbar-engine/PIN` stops adoption altogether.

---

## 8. Proving it

```bash
bash scripts/landq-supervisor.sh --selftest     # the decisions, the ladder, the env file, adoption
bash scripts/landq4.sh --selftest               # the engine, including the exit-code contract
bash scripts/landq-ctl.sh --selftest            # the queue commands and the status rendering
```

The supervisor's selftest runs a **stub runner** that exits with each code of the contract in turn
and asserts the decision taken for each, the backoff ladder actually waited, that the env file is
read once per start, that a `PAGED` marker blocks every start until it is removed, that a boundary
that carried an engine line adopts (and the 23:54Z batch — a docs line beside somebody else's
script fix, reproduced as a fixture — does not), that an archive without `landq4.sh` is refused
before the swap, that a first start with no baseline adopts nothing, and that a `PIN` holds the
engine through an engine landing while still tracking the tip.

## 9. The adoption gates — no engine change reaches the home unproven

> **Owner's process rule, 2026-09-11 19:28:** *test piecemeal, never let a 2-hour run find it.*

The rule exists because of a measured cost. The first Latchkey sweep ran on an engine whose
dispatcher resolved one path wrongly, and **twelve real queue lines were parked before anybody read
a log**. The second died on a staging race that every sweep would have hit. Neither defect was in
the new backend; both were in the code path that had assumed there was only one.

So there are three gates, one per thing that can be wrong, and each of them **drives the real thing**
— the real CLI, the real queue, a real landing — on a scratch root, in minutes rather than in a
sweep. An engine change is not handed back until its gate is green **on the exact scripts the home
will carry**.

| gate | what it drives | what it would have caught |
|---|---|---|
| `landq4.sh --smoke-latchkey '<line>' …` | the pre-proof backend: one batch file per line, all dispatched at once, so the concurrency the sweep really has is the concurrency the gate has | the dispatcher's path resolution; the staging race; the tree's `land.sh` being shipped instead of the engine's |
| `landq4.sh --smoke-latchkey --landing` | **one real landing**: picks applied, the union proven as rented jobs, a tip published, the push taken | anything that publishes |
| `landq4.sh --smoke-bigbatch <queue file>` | the popper, against the **real queue** — 717 lines with every tag shape an integrator has ever written | a popper that loses a line |
| `landq4.sh --smoke-latchkey --sweep` | **`lq_preprove_sweep` itself**, over a one-line queue it cuts, with a recording stub standing in for `ci-fleet-power.sh` | a sweep that starts an EC2 box for work that never goes there (§13) |

```bash
LANDQ_ROOT=~/Developer/tmp/smoke/root LAND_SH_SRC=~/.busbar-engine/current/scripts \
BUSBAR_PROVE_BACKEND=latchkey LATCHKEY_SIZE=large \
  bash scripts/landq4.sh --smoke-latchkey '--prove --tests xtask <sha>'

LANDQ_ROOT=~/Developer/tmp/smoke/root LAND_SH_SRC=~/.busbar-engine/current/scripts \
BUSBAR_LAND_BACKEND=latchkey LATCHKEY_SIZE=large \
  bash scripts/landq4.sh --smoke-latchkey --landing

LANDQ_ROOT=~/Developer/tmp/smoke/root \
  bash scripts/landq4.sh --smoke-bigbatch <the runner's land-queue.txt>

LANDQ_ROOT=~/Developer/tmp/smoke/root LAND_SH_SRC=~/.busbar-engine/current/scripts \
BUSBAR_PROVE_BACKEND=latchkey BUSBAR_LAND_BACKEND=latchkey LATCHKEY_SIZE=large \
  bash scripts/landq4.sh --smoke-latchkey --sweep
```

The sweep gate's assertion nobody can fake is **an empty file**. `ci-fleet-power.sh` is replaced, in
the staged engine where the sweep really looks for it, by a stub that appends its argv to a file; a
sweep that started a box wrote in it. A green run is that file with nothing in it, plus four
sentences in the sweep's own log (§13).

**None of them takes the landing lock, and that is deliberate.** The lock is host-wide
(`$HOME/.busbar-landq4.lock`); a gate that could only run while the live runner is down is a gate
that is run once and then never again. The pre-proof gate is placed above the lock acquisition
entirely and lands nothing by construction (every line goes through the pre-proof leg, which
publishes nothing). The landing gate points `LANDQ_LOCK` at its own scratch path.

**The landing gate cannot reach the real remote.** It creates a **bare origin of its own** under
`$LAND_TMP`, repoints the clone's `origin` at it for the duration, and puts the URL back whatever
happens. It takes **its own pick**, cut in the clone off the clone's own tip — a queue line's picks
may or may not apply at whatever tip a scratch clone is sitting on, and a gate that can fail because
the scratch tree is a day old is a gate nobody trusts. A docs-only pick selects no cargo package and
names no family, so the union's plan is the floor and the landing is ONE job: the cheapest shape
that is still a whole landing.

And it **compares the landed tree with the fleet path's**, byte for byte. The two backends differ in
*where* `prove_tree` ran and in nothing else; `prove_tree` publishes nothing; and the picking code is
literally the same file, because `land-remote.sh` copies the engine to the box exactly as
`prove-latchkey.sh` packs it into the job. So the tip a latchkey landing publishes must be
tree-identical to the one the fleet path publishes for the same line — checked by taking the same
pick in a third checkout at the same base with the same `git cherry-pick -x`, and comparing tree
oids.

**A RED landing is not a failed gate.** The distinction the pre-proof gate already draws holds here:
a verdict about a TREE is the tree's, and the gate is about the transport. A `cap`, a `harness` or a
`box-unreachable` class is `NO VERDICT` (exit 75) — nothing was learned; any other red is reported
as the tree's, and the gate then checks the one thing a red landing owes: **that the tree was put
back where it started.**

## 10. Big-batch mode — what the runner pops, and what a red costs

> **Owner's ruling, 2026-09-11 21:0x:** every applicable line joins the union, chains as one unit,
> no pre-proof to join, `LAND_BATCH_MAX` 40, bisect by prefix.

The ruling is a trade taken deliberately, and it is worth writing down which way. Measured: **6
landings in 24 h** against **259 lines still to land** — 43 days. Every admission rule the popper
had was written to make ONE landing's red readable:

| rule | what it bought | what it cost |
|---|---|---|
| one file to one line | a red names one line unambiguously | two lines that touch one file are two batches |
| one gates-touching line per batch | the gate under test has one editor | the gates lines land one at a time |
| a raise never beside a lower | a ceiling move is attributable | two figure lines are two batches |
| a pre-proof green before joining | evidence before the serial proof | a line the sweep never reached cannot land |

Under a **prefix bisect** the thing they bought is bought differently: a red in a chained unit is
attributed to the first line that carries it, and every line after it comes back `HELD` — unproven,
unparked, and requeued exactly as it was popped. So the rules are dropped and the bisect does the
reading.

**What the pop does now.** In queue order, to `LAND_BATCH_MAX` (40): take every line whose picks
apply cleanly onto **the tip plus the batch so far**, and write the whole batch as ONE unit
(`#UNIT 1` on every line after the first), which is what `land.sh`'s existing `land_unit_prefix`
bisect keys on.

**"Applies cleanly" is `merge-tree`, and it writes nothing.** `lq_apply_probe` runs the same
three-way merge a cherry-pick runs — base = the pick's parent, ours = what the batch has
accumulated, theirs = the pick — and carries the result forward as a throwaway `commit-tree` so the
next pick merges onto it. No worktree, no index, no checkout, nothing written to the runner tree; the
object database is append-only and concurrent-safe, which is why this shape is available at all. A
scratch worktree and a real cherry-pick would be 3,580 files to create, metadata written into the
shared git directory, and forty chances for a half-finished `--abort` to leave state behind.

**A `#HOLD-after-<sha>` releases when the sha is landed *or* when a line already in this batch
carries it.** The second half is what turns a fourteen-deep chain from fourteen batches into one.
"Landed" means either of two facts and the engine now says which: the sha is an **ancestor** of
HEAD, or a landed commit carries its `(cherry picked from commit <sha>)` **trailer**. This tree lands
by cherry-pick, so the second is the arm that matters — and it had been searching **zero commits**
since it was written, because every rev range the engine tried (`landq4.tip..HEAD`,
`origin/<BR>..HEAD`) is empty on a healthy runner: both are written after every batch. It is a
bounded **depth** over HEAD now (`LANDQ_PROVENANCE_DEPTH`, 2000), and a depth cannot be empty.

**What does not apply is `NONE:no-apply`, not a red.** The line stays LIVE and unmarked and is
offered again at the next tip — which is usually all it needed, because the line it conflicted with
has just landed. The rows go to `landq.status.json`'s `no_apply`, because a queue of 250 with three
lines that never join any batch looks exactly like a queue of 250. **Nothing is parked by this
popper, ever.**

**A park and a word hold are never overturned**, however big the batch is allowed to be: `#RED…`,
`#MALFORMED`, `#HOLD-after-strike` and any non-hex remainder are the integrator's, and the popper
does not guess at a word. A *label* beside a hold is not a dependency — 36 of the queue's held lines
are written `#HOLD-after-<sha> #T0-B2-seam --prove …` and the second token names the slot.

Measured by `--smoke-bigbatch` on the real 717-line queue at tip `3236c8a2b`: **12 landing lines in
one batch**, 39 `NONE:no-apply` rows all still live, 12 batched + 705 kept = 717 read, the park count
unmoved, one unit, and every batched line re-verified to apply in the order the batch names.

`LAND_BIG_BATCH=0` is the way back to the admission-rule popper, in one variable. **The two are
never mixed** — a batch is all one shape.

## 11. Two more rules the live sweep asked for

### A crate-test red the base also has is the base's — `NONE:base-test`

The oracle has had this rule since 09-11: *an oracle red the base also has is the tip's standing
state, not these picks'* (`lq_line_red_is_base_oracle`, recorded `NONE:base`, requeued live, never
parked). A **crate test** is the same fact about the same tree and had no rule at all.

Measured 2026-09-12: LK-ALL landed with `--tests ''` and broke
`gates::release_order::tests::every_rule_and_the_graph_proof_are_proven_able_to_go_red` **on the
tip**. Two live lines then went RED on a test neither of them can have touched, and both were parked.

So there is a second ledger beside the oracle's, keyed by tip, with the same `#measured` row — and
the `#measured` row is the load-bearing part, because *"no test is red at this tip"* and *"nobody
has measured this tip"* are different sentences with different dispositions. The sweep's base replay
now carries `--tests xtask` so it writes that ledger; a landed wholly-green batch writes it too.
Neither learner records `#measured` for a leg that did not run — that is the `base-unmeasured`
lesson with the sign flipped, and recording it falsely would excuse every future test red at that
tip on no evidence.

**Every** failing test must be red at the base, not merely one of them: a line that broke one test
and happens to also trip a standing one is a line that broke a test.

### A union touching the workflows or `xtask/` tests `xtask`, whatever the line said

The other half of the same defect. LK-ALL's whole diff was `.github/workflows/**` and `xtask/**`,
and:

* the `gate` leg **runs** the gates — it does not test them;
* the per-gate self-test **batteries** (`land_gate_battery_set`) prove a gate against its own
  fixtures — they are not `cargo test -p xtask`, which is where a rule's red-before-green cells live;
* the packages a line contributes are derived from `^crates/[^/]*`, so a union whose diff is
  `.github/` and `xtask/` derives **no package** and runs no cargo test at all.

`land_tests_floor_xtask` closes it: `.github/workflows/`, `.github/actions/` or `xtask/` in the
union's diff and `xtask` is **added** to whatever the line named — never substituted for it, and
applied before the plan is taken so the `tests` and `clippy` legs are in it.

### And the job-log home is a path in the env file, not a derivation

The scripts walked from the tree being proved to the main repository's parent. That is right for the
runner tree and wrong for every other `LANDQ_ROOT`: the landing gate on a scratch clone kept its job
logs beside the **scratch**, under `~/Developer/tmp/…/busbar-landq-state/`, where no ledger reads
them and nothing preserves them. The ledgers cite these logs by path months later, so there is
exactly one right answer and it is not a function of which tree happened to be proving.
`LATCHKEY_LOG_DIR` is in `scripts/landq.env.example`; the derivation stays as the last resort for an
operator running by hand, and it says so in the log when it is used.

## 12. Two rulings the live runner paid for in landings

### A landing that needs a box HAS one before the pop — the precondition, not the retry

Measured 2026-09-12: five `NONE:probe-empty` faults between 07:49 and 14:31, no landing at all in
those seven hours, and in the end a runner restart ordered by hand.

`power_ensure_slots` was never wrong. It was never **asked**. `--ensure-slots` is called from
exactly one place — the pre-proof sweep — and the sweep is skipped on precisely the loops that still
land: a base fix at the head pops alone, and a queue with no live line has no sweep either. The
fleet idle-stops itself after `LANDQ_IDLE_STOP_MINS`, so after an hour of Latchkey pre-proofs it is
asleep by construction, and the batch was popped onto it anyway.

Waking **after** the fault does not close it. A box is 60–90 s from proving and the first backoff is
60 s, so the retry probes a box that is still booting and scores the same class again. And the retry
must **re-probe, not re-read**: the sweep caches one probe round for its whole dispatch
(`fleet_table_open`), and that table is by construction the fleet from before any box was started.

So the pop has a precondition (`lq_landing_slot_ready`). When `BUSBAR_LAND_BACKEND=fleet` and no
awake box has a free proof slot, the engine starts one and **waits** for it
(`CI_RUNNER_START_WAIT_SECS`), then asks the fleet **again**. The second ask is the whole point:
`ci-fleet-power.sh --ensure-slots` exits 0 for "starting nothing" and for "no stopped box to start
(the fleet is all awake or all gone)" alike, so a landing dispatched on that exit status is a
landing dispatched into nothing. A number can be checked; that exit status cannot — which is why
`--free-slots` exists, and why it is a fresh ssh round over the boxes and never a cached table.

It runs **before the queue lock** (waking a box can take five minutes, and the lock is what
`landq-ctl` needs to edit the queue at all) and before any popper. A fleet that will not wake is not
a fault of the queue's: **nothing is popped**, no line moves, no class is scored against anybody's
picks, and the loop is taken again on the class's backoff — where `probe-empty` popped lines, failed
them and put them back, five times over. On `BUSBAR_LAND_BACKEND=latchkey` it is a no-op by design:
that backend needs no box at all.

#### And a box under a stop claim is not a free box

The other half, found by reading the live runner at fault 5. A box the operator had just started by
hand was logged `skipped (unreachable or unprepared)` while running and idle. A hand start
(`aws ec2 start-instances`) runs none of `ci-fleet-power.sh`, so the `~/.busbar-stopping` the stopper
wrote before stopping that box is still there — and the landing's proof probe begins
`test -e ~/.busbar-stopping && exit 1`, so it gets no answer and the caller reads the silence as an
unreachable box. `power_start` clears it through `power_ready`; a hand start has nobody to do it.

`busy` cannot see this: a claimed box holds no proof — that is *why* it was claimed — so it answers
0 and the box counts as fully free. Without this, the precondition above passes and the landing
fails anyway. So the allocator asks the question the landing will ask (`~/.busbar-power.sh stopping`
-> `STOPPING` | `CLEAR`) and clears a claim it finds, rather than counting a box it knows the landing
cannot use. The verb is a question and writes nothing: `clear` also drops the idle clock, and a
fleet asked for free slots every loop would never idle out.

### Which tags carry an argument is one list, and every reader of the prefix walks it

A queue line is `<tag>… -- <payload>`, and almost every tag is one `#` token — so every reader of the
prefix was written, independently and correctly, as "drop the leading `#` tokens". The pre-proof
parks broke that and nothing else did: `#RED-preproof <log> …` and `#PARK-preproof <log> …` carry the
path to their evidence, and **a path does not begin with `#`**. A reader that stops at the first
non-`#` token stops on the log path, and everything behind it is invisible to it.

Five readers walk that prefix, and only `lq_line_unpark` knew:

| reader | what it did on a pre-proof-parked line |
|---|---|
| `lq_release_holds` | never reached the `#HOLD-after-<sha>` behind the path — the hold could **never** release, however long ago its sha landed |
| `lq_hold_after_sha` | saw no tags at all: the line was not chainable, and its hold was invisible to the chained-pre-proof arithmetic too |
| `lq_line_payload` | returned `<log path> #HOLD-after-… --prove …`, so a `RETAG` rebuilt the line with a **path** as the head of its payload |
| `lq_line_still_held` | escaped on `#RED-preproof` only by matching `#RED*` on the way past; on `#PARK-preproof` it walked into the path and reported "no payload" |
| `lq_line_unpark` | correct, and its comment warned about exactly this |

A warning is not a defence; the knowledge is. `LQ_ARG_TAGS` is that knowledge, read in one predicate
(`lq_tag_takes_arg`), walked in one place (`lq_line_tags`), and every reader is written over it. A
new argument-carrying tag is one word in one place. The selftest also asserts the closing property —
no function shifts a token off the prefix without asking the list — so a sixth reader is caught by
the suite and not by a queue that has quietly stopped moving.

Measured on the live queue at the time of the fix (722 lines, 17 pre-proof parks): `lq_line_payload`
returned a path for 17 of 17 before, and the line for 17 of 17 after.

## 13. Where the base-state replay runs — one shape, two homes

The sweep proves the LINES, and it proves one thing that is not a line: **the tip itself**. A batch
with no picks, over the union of the families the sweep's lines ask the oracle for, plus
`--tests xtask`. It is what makes every other verdict in the sweep readable — without it an oracle
row that was already red at the tip is scored as a line's own red (`lq_line_red_is_base_oracle` has
nothing to compare against), and a crate test that was already failing at the tip parks a line that
cannot have touched it (`lq_red_is_base_test`). Ruled 2026-09-11 after a line was parked `#RED` for
three hours on rows nobody had measured, and the answer is `NONE:base-unmeasured` / `NONE:base-test`:
live, unparked, at the **front** of the next sweep.

**Its shape does not change with the backend. Its home does.**

| `BUSBAR_PROVE_BACKEND` | where the replay runs | what the sweep reserves for it | log |
|---|---|---|---|
| `fleet` | an EC2 box, taken **before any line is dispatched** so measuring the base never costs a line its proof | one proof slot, held out of `hosts` from the start | `base state: <i-…> reserved for the base replay at <tip> BEFORE any line was dispatched` |
| `latchkey` | a **rented runner of its own** — the same `lq_dispatch_preprove` every line and every chained hold goes through | **no box at all**; it takes a Latchkey slot instead, still before any line, and counts against `lq_latchkey_proc_bound` like any other pre-proof | `base state: the base replay at <tip> is a LATCHKEY job — no EC2 box is reserved or started for it, …` |

Measured, live, 2026-09-12 16:15: with **both** backends on `latchkey`, every line's pre-proof went
to Latchkey and the sweep still logged `base state: i-063… reserved for the base replay` and
measured the tip on a box. That, and the slot demand below, were the last two EC2 dependencies in
the engine.

### The fleet is asked for what will run on the fleet

`lq_sweep_slot_demand` is the **work**: one slot per live line, one per chained hold, one for the
base replay, one for the batch the runner is about to pop. `lq_sweep_fleet_demand` is the part of
that work which still justifies **waking a box**, and it is the only number `--ensure-slots` is ever
given:

* the **proofs** justify a box only on the `fleet` pre-proof backend. On `latchkey` they are zero,
  all of them. A sweep with more lines than `lq_latchkey_proc_bound` dispatches what fits and leaves
  the rest for the next loop — exactly what it already does whenever the fleet is short. Counting
  the overflow and starting boxes for it was considered and refused: it puts the queue's depth back
  on the bill. A line beyond the bound still takes a box that is **already awake** if one is free;
  it simply never wakes one.
* the **batch** justifies a box only when `BUSBAR_LAND_BACKEND=fleet`. The Latchkey landing path
  rents its own runners, which is why `lq_landing_slot_ready` — the pop's own precondition (§12) —
  is already a no-op on that backend.

With both backends on `latchkey` the number is **zero**, and a zero is never put to the allocator at
all (`--ensure-slots 0` is a question with a box-shaped answer nobody wants). The sweep says so in
one line an operator can grep the bill against:

```
sweep: fleet demand 0 — no EC2 box is started or reserved (prove backend latchkey)
pre-prove: this sweep reaches no box, so it opens no ssh wrapper and probes no fleet table
```

### An empty fleet is not an error path

Ruled after the 17:28 double death (2026-09-12): the runner exited 2 because a line whose Latchkey
job was refused fell back to the fleet, and `ci-remote-lib`'s allocator treats a fleet file with no
on-demand box as a hard `ERROR` — on a fleet that is empty **by design**. The supervisor then read
that 2 as "another runner holds the host lock" and exited too. One refused job, and nothing was
running.

* On the `latchkey` pre-proof backend `lq_preprove_needs_box` answers **no box, unconditionally** —
  not "no box while a runner slot is free". The allocator is never asked, so its opinion about an
  empty fleet is never consulted.
* A `75` from `prove-latchkey.sh` ("no job was created; the workspace cap is shared with CI") is
  **no verdict**. The line stays LIVE and unmarked and is swept again on the next loop, exactly as a
  short fleet has always been handled. There is no fall-back to a box.
* `landq-supervisor.sh` classifies `locked` from the **lock file's live owner**, never from an exit
  code: `sup_lock_holder` asks the question `lq_lock_acquire` asks — a pid that is alive and is
  still the process that took the lock, and never the supervisor's own. An exit 2 with no live
  holder is an infrastructure exit and is restarted on the 60/120/240/480/900 s ladder.
  `HALT head-conflict-twice` (1) and `HALT tree-moved` (3) are untouched: those are facts about the
  tree and they still page.

The second line above is the same rule one step further out: `remote_wrapper` and `fleet_table_open`
are the fleet's transport — a generated ssh wrapper that *refuses outright* on a host without
`session-manager-plugin`, and an ssh round over every instance. A sweep with nothing to say to the
fleet opens neither. A runner that can no longer reach EC2 at all is precisely where the owner's
goal ends.

### The readers did not learn a second vocabulary

`lq_base_red_learn` and `lq_base_test_learn` read the replay's **log**, and so does every rule that
asks a question about a tree. A Latchkey dispatch's own stream is the transport's narration — the
legs' output is in the job logs, which it names by path. So each dispatch folds the shard logs it
names back into the proof's own log (`lq_absorb_shard_logs`) before anything is scored. Without it a
base replay on Latchkey would run perfectly and measure **nothing**, and `NONE:base-test` /
`NONE:base` would quietly stop being sayable. A fleet proof names no shard logs and it is a no-op.

And one thing the shard logs still do **not** carry: the per-test `test …::… FAILED` lines. On the
rented runner those live in `land.sh`'s own nested log, which does not travel — the job log says
`land.sh: RED — tests failed in: xtask` and no more. `lq_base_test_learn` therefore refuses to
record `#measured` for a test leg that went red and named no test. That refusal is the whole rule:
a tip declared **measured with an empty red set** is worse than an unmeasured one, because every
later line's identical test red is then scored as its own and a line is parked for a test it cannot
have touched — which is the defect `lq_red_is_base_test` exists to prevent, arrived at through the
front door. An unmeasured tip is an honest outcome; a measured-clean tip that is not clean is not.

## 14. `prove-latchkey.sh`'s own slot-side semaphore — bounding what a SLOT submits

**MEASURED 17:40:** twelve slots' `prove-latchkey.sh` were each running their own `latchkey run`
concurrently, against Latchkey's shared 20-job workspace cap — a cap CI's `keep-proof.yml` draws
from too. The engine's own sweep (`LATCHKEY_MAX_JOBS=12`) got `latchkey created no job` and its
sweep starved for twelve minutes. `lq_latchkey_proc_bound` (§13) already bounds how many jobs the
**engine's own sweep** dispatches at once; nothing on the laptop bounded how many jobs every
**slot**, each running its own `prove-latchkey.sh`, drew from the same cap at the same time. One
script bounding its own dispatch cannot protect a cap five other copies of the same script are
also drawing on.

`prove-latchkey.sh` now takes one of `LATCHKEY_SLOT_JOBS` (default 6) slots from a pool of
`mkdir`-locked directories under `LATCHKEY_SLOT_DIR` (default `~/.busbar-engine/latchkey-slots`)
**before every real `latchkey run`** — inside `lk_submit`, which every caller (a plain proof, and
every shard of a sharded pre-proof) goes through. `mkdir` is the lock: atomic across processes, no
lockfile to race. A slot's directory carries the PID that took it (this *script's* `$$`, not
`$BASHPID` — see below) and when it was taken.

* **A full pool waits, and never spins.** `prove-latchkey: waiting for a slot (N of M in use)` is
  logged once per wait, then a bounded backoff: 30 s, doubling, capped at 5 minutes.
* **A stale slot is taken, never waited behind.** A slot whose PID is no longer alive — its holder
  exited without releasing, a `kill -9` no trap catches — is reclaimed by the next acquirer at
  once.
* **The engine's own jobs bypass the pool entirely.** `LATCHKEY_ENGINE=1` is the marker (set by
  `land-latchkey.run.sh` / `landq4`, a separate line's work); its absence is *read* here, never
  assumed, so the marker is honoured the day it lands with no change on this side. The pool exists
  to protect the engine's own share of the cap from every slot — the engine is not another
  consumer of the thing it is being protected from.
* **Released on exit, however it happens** — a normal completion, a `kill`, an interrupted poll —
  from the same `trap … EXIT INT TERM` that already cleans up the packed tree. A sharded pre-proof
  fans out into several `latchkey run` calls, each inside its own `$(cd "$PACK" && lk_submit …)`
  *subshell*, whose writes to an ordinary variable never reach the caller; the slots a script
  holds are therefore never tracked in a variable, but found by the PID they carry — `$$` is
  unchanged across those subshells in bash (unlike `$BASHPID`), so a scan by PID from the exit
  trap finds every slot the process took, wherever in the run it took it.

Proven by `scripts/prove-latchkey.sh --selftest`, against the real pool functions over a scratch
`LATCHKEY_SLOT_DIR`: the engine bypass, a stale PID reclaimed, a full pool that waits (the log
sentence, not a spin) and proceeds the moment a slot frees, and a slot released on a real `SIGTERM`
to a real killed process.

### The oracle compare leg is scoped like the record leg, or a scoped slot can only read red

**MEASURED (K12g):** a slot's shadow-oracle leg — `./bin/oracle record --filter "$FAMILIES"` then
a compare — recorded a candidate scoped to `$FAMILIES` and then compared it against **every** one
of the golden's 915 cells. Every golden cell outside that scope has no matching candidate cell (a
scoped record leg never touched it) and reads as `missing.candidate`: 646 of 648 "failures" on one
run were exactly this, not a real divergence. `replay.sh` forwards only `--family` to the differ
(a regex over the cell's *family field*, not its id) and has no `--id-filter` of its own; land.sh's
own landing gate already asks the differ directly (`bin/oracle diff … --id-filter "$families"
--strict`, the same regex domain record.sh's own `--filter` uses) for exactly this reason, so
`prove-latchkey.sh`'s onbox oracle leg now makes the identical call rather than a second, narrower
reading of `replay.sh`'s one flag. The verdict line names its own scope:
`N of M in scope (families: <regex>), D diverging` — never a bare failure count against cells a
scoped run was never asked to prove.

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
  supervisor.log      what the supervisor did, one line each
```

`current` is an **archive of one sha**, never a `cp -r` (which carries whatever the source directory
happened to hold) and never a checkout (which anything running `git checkout` can move under the
running engine). `LAND_SH_SRC` is therefore not an operator's choice any more: the supervisor sets
it to `~/.busbar-engine/current/scripts` at every start.

### Adoption is a landing

`landq4.sh` writes `target/gate/landq.boundary` — one line, `<epoch> <tip>` — at the end of every
batch and on its way out through the STOP marker. The supervisor reads that signal while the runner
runs, and at each new boundary asks the landed tip one question:

```bash
git log -1 --format=%H <tip> -- scripts/       # the tip's engine sha
```

If that is not the sha in `~/.busbar-engine/sha`, a new engine has landed. The supervisor then:

1. writes `~/.busbar-engine/ADOPT` (the sha to adopt) and sets `target/gate/STOP`,
2. lets the runner finish the batch it is in and stop **at the boundary** — never mid-batch, because
   a batch is an hour of a fleet box,
3. re-archives `scripts/` at the new sha, removes the STOP marker **it** set, and starts the runner
   again.

Nobody types anything, and no boundary is lost. A landing that does not touch `scripts/` moves
nothing. If a STOP marker is **already** set when the supervisor wants to adopt, that STOP is the
integrator's: the supervisor leaves it alone and adopts at the next start instead.

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

3. **When it has exited** (`tail -n 3 "$LANDQ_ROOT/target/gate/landq.out"` says `STOP marker seen`):

   ```bash
   rm -f "$LANDQ_ROOT/target/gate/STOP"
   cd ~                                            # anywhere that is NOT the runner tree
   bash <repo>/scripts/landq-supervisor.sh         # or: nohup … >/dev/null 2>&1 &
   ```
   The supervisor archives `scripts/` at the landed tip's engine sha into `~/.busbar-engine/current`,
   starts the runner with the env file, and from then on adopts every engine that lands.

4. **Check it once:** `scripts/landq-ctl.sh status` shows the tip, the engine sha and the
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

---

## 8. Proving it

```bash
bash scripts/landq-supervisor.sh --selftest     # the decisions, the ladder, the env file, adoption
bash scripts/landq4.sh --selftest               # the engine, including the exit-code contract
bash scripts/landq-ctl.sh --selftest            # the queue commands and the status rendering
```

The supervisor's selftest runs a **stub runner** that exits with each code of the contract in turn
and asserts the decision taken for each, the backoff ladder actually waited, that the env file is
read once per start, that a `PAGED` marker blocks every start until it is removed, and that a
boundary carrying a new engine sha adopts (and one that does not, does not).

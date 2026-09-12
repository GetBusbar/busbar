# Off EC2, onto Latchkey

The owner's goal is 100% off EC2 onto [latchkey.dev](https://latchkey.dev), with a go/stop at every
step. The work is phased because the three workloads the fleet carries have very different costs of
being wrong:

| Phase | Workload | Where it runs after the phase | Status |
|-------|----------|-------------------------------|--------|
| 1 | The three self-hosted GitHub Actions workflows | Latchkey labels | landed on `keep-ci-latchkey` |
| 2 | The landing engine's **sweep pre-proofs** | Latchkey, `BUSBAR_PROVE_BACKEND=latchkey` | this section |
| 3 | The **landing** itself (`land-remote.sh`) | Latchkey | not started; go/stop below |

> Phase 1's section is written on `keep-ci-latchkey` and arrives at this file by landing, not by
> being restated here. If the queue pops that line after this one the two sections merge; they do
> not overlap.

---

## Phase 2 — the sweep's pre-proofs

`scripts/prove-latchkey.sh` implements `scripts/prove-remote.sh`'s contract over `latchkey run`, and
`scripts/landq4.sh` reads `BUSBAR_PROVE_BACKEND=fleet|latchkey` (default `fleet`) to choose which of
them a sweep's pre-proof leg uses. **The landing itself stays on the fleet in this phase**,
deliberately: a pre-proof that is wrong costs the queue an order, a landing that is wrong publishes.

### The delta, and why it was not what it looked like

The first measurement (jobs `cli-678df284`, `cli-edd061ac`, xlarge, 16 vCPU) read the packed runner
tree as **RED on `kind-isolation:deps`, `:test-deps` and `:matrix`**, on a tree the fleet reads
11/11 green. Four hypotheses were on the table: a file held back by the credential deny-list, a
gitignored path a gate reads, Cargo feature unification from a missing workspace member, and the
missing `.git`. They were separated by measurement, not by argument.

**The packed tree is byte-complete.** Job `cli-e36cb8c0` printed the runner's whole file list; a
`comm` against `git ls-files` on the same checkout differs by **two files in one direction and zero
in the other**: `.fix/kernel.rs.orig` and `.fix/units_llm.rs.orig`, which the packer drops as merge
leftovers and which no gate reads. 3,579 packed against 3,581 tracked. Nothing is added. So it is
not the deny-list, not a gitignored path, not a missing member and not the file count.

**It is the missing `.git`**, and the gate said so in its own detail, which the first measurement's
`tail` had cut off. Job `cli-bfd4dc61` printed it in full — the same finding on all three rows:

```
FAIL  kind-isolation:deps   a dependency edge is not the edge the ledger has written down
      … no-base  qa/kind-isolation.toml  no merge-base could be read, so no `not-allowed` edge
      could be shown to pre-date this branch (git rev-parse HEAD exited 128: fatal: not a git
      repository (or any of the parent directories): .git). A ratchet that cannot read its own
      history reports nothing, and reporting nothing is not passing.
```

Those three rows are **ratchets against history**. `construction::ceilings::base_ref` takes the
merge-base with `origin/integration/oracle-phase0`; `kind_isolation::base` reads the BASE's own
manifests out of `git show <base>:<crate>/Cargo.toml`; `ceiling_rose` diffs every number in
`qa/*.toml` against the base's copy. Latchkey never ships `.git`. The rows were right: no history,
no verdict, and a ratchet that switches itself off on the runner where it is cheapest to switch off
is not a ratchet.

### The fix: the history travels as a directory that is not called `.git`

`scripts/prove-latchkey.sh` stages `.latchkey/git` — a **bare repository** — into the tree before
the pack. It carries the tip, the integration base under the very ref name the gate reads, every
hash the batch names, and the audit pins. The first thing the on-box script does is rename it into
place, point `HEAD` at the branch, and `git reset --mixed`. The runner is then a fleet box's state
exactly: a real repository, with real history, whose HEAD is the tree that was packed.

It is **shallow**, because this laptop's clone is. A `git bundle` is the obvious answer and it does
not work: `git bundle create` from a shallow repo succeeds, and the fetch on the far side then fails
with `did not send all necessary objects` (measured, job `cli-21657406`). A push into a bare repo
with `receive.shallowUpdate` carries the boundary with it. **23 MB, 1.4 s to build** — against a
200 MB context bound and a 13 MB tree.

**And the deny-list's casualties are restored generically**, not chased with `.latchkeyignore`
re-includes, which would be a list of exactly the files a credential deny-list exists to remove.
The on-box script asks git: every path the reconstituted index reports as `D` is a path the packer
dropped, and `git checkout --` puts it back from the tip the bare repo already carries. A file the
deny-list adds next month is restored next month with nothing to edit, and nothing that is not in
the tip's own tree can arrive this way.

**PROVEN** (job `cli-fc20353b`, xlarge): `cargo xtask gate kind-isolation` reads **11/11 green** on
the runner, restoring the two `.orig` files on the way, with `merge-base HEAD
origin/integration/oracle-phase0` equal to the sha the laptop resolved. Same tree, same verdict as
the fleet and the laptop.

### The audit pins are pushed one at a time, and that is not fussiness

`git push` is atomic over its refspecs. One audit pin that sits on the far side of this shallow
clone's boundary failed the whole push **and took the tip with it**, so a proof was refused because
an old audit round's worktree commit is no longer fetchable. A pin that cannot travel costs one gate
row; a pin that cannot travel and takes the tip with it costs the proof.

### What sucks

Every one of these was worked around rather than wished away, and each is a fact about the product
rather than about this tree.

1. **`.git` never ships, and the gates are ratchets.** The whole of the delta above. The workaround
   is 23 MB of bare repository per job and an on-box prologue. It is the single largest difference
   between the two backends and it is load-bearing: without it three gate rows are red on every
   proof, for a reason that has nothing to do with the tree.
2. **No file comes back — a log is the entire return channel.** `land-remote.sh` copies
   `<batch>.result` off the box with `scp`. There is no equivalent, so the on-box script prints the
   verdict file between two delimiters and this side parses it out of the log. It works, and it
   means a verdict can be lost to a truncated log in a way it cannot be lost to a file copy.
3. **Self-healing cannot be disabled per job.** It is a workspace switch. A healed retry **exits
   zero**, so the exit code alone can never be trusted: a proof harness that read it would report
   GREEN for a tree somebody else's retry produced. The workaround is detection — the wrapper prints
   `[latchkey-bash-wrapper] … sidecar POST` when it hands a failure over, and a job that exits 0
   with that marker in its log is recorded `NONE:healed` and exits 75. It is never GREEN. This is
   the one item on this list that is a **correctness** risk rather than an inconvenience, and it is
   the reason phase 3's go/stop below is what it is.
4. **The 20-concurrent-runner cap is shared with CI, and it binds today.** `latchkey run` answered
   `Job creation blocked: concurrency_limit` on **seven consecutive submissions** while phase 1's CI
   push held the account. `LATCHKEY_MAX_JOBS` therefore defaults to **12, not 20**, and a line whose
   job cannot be created overflows onto a fleet box rather than being scored — nothing about a tree
   has been learned when the account is full.
5. **The GitHub Actions cache backend is unreliable from these runners** (measured by phase 1; one
   hard `sccache` install failure). Every proof is therefore a **cold build**. The fleet's whole
   advantage — a warm `target/`, an sccache with this workspace's objects in it — is gone, and there
   is no persistent disk to put it back on. This is the cost line, not a bug.
6. **Local shell quoting is lost.** The CLI joins the command tokens with single spaces into one
   bash line, so a `$( … )` that the local shell resolved arrives already resolved, and one that it
   did not arrives as a syntax error. Cost one job (`cli-74628a29`) to learn. The runner script is
   therefore **staged into the packed tree as a file** and the command line is `bash .lk-run.sh …`,
   which is also the only way to ship a script of any size.
7. **No ssh, so no `--cancel <host> <ref>`.** `latchkey cancel <id>` exists and is used, but the
   engine's ability to signal a process group on a box (a chain root proven RED under a rung that is
   still bisecting) has no equivalent; the job is cancelled whole.
8. **The batch file must live inside the repository.** `land.sh` refuses a `--batch` outside the
   tree, and Latchkey packs the current directory and nothing outside it, so the two agree — but it
   means a sweep's scratch has to be under `target/gate/`, not under `$LAND_TMP`.

### Minutes per proof

Measured on the same tree, one real slot pre-proof each way — a batch of one hashless line
(`--prove --tests xtask`), which is "the tip itself, proven":

Both proofs ran against the same tip (`1c6bc813f`) with the same base (`4197eb098`), and the
**verdict files are byte-identical** — `md5 423fe6243ffb85091e8a45b4c783c986` on both sides:

```
GREEN	--prove --tests xtask
```

The gate rows agree too, row for row: `kind-isolation: 11 row(s), green` on both, and the same
sentence of evidence behind the GREEN — `plugin cdylibs build; rustfmt on 0 picked .rs file(s);
cargo test (xtask); cargo clippy (xtask); kind-isolation --selftest not owed by this union;
kind-isolation green; construction rows (., standing reds named)`.

| | Fleet (`i-063846ce9e9fba91d`) | Latchkey `xlarge` (`cli-3f8735cb`) |
|---|---|---|
| driver wall, laptop | **488 s** | **717 s** |
| on the machine | 483 s | **540 s** (started 00:23:26 → completed 00:32:26) |
| pack + upload | 200 KB of git objects over ssh | 69 s for 29 MB of bare repo + 13 MB of tree |
| queue / provision | 0 (the box is awake) | 82 s |
| build state | warm `target/`, warm sccache | **cold, every time** |
| billed | standing EBS + instance-hours, proof or no proof | **9 runner-minutes ≈ $0.18** |
| verdict | GREEN (transport exited 2 — see below) | GREEN |
| self-heal markers in the log | n/a | **0** |

**So a pre-proof of this union costs 9 runner-minutes and runs 1.1× the fleet's on-machine time**
(540 s against 483 s) despite the cold build, because a Latchkey xlarge gives the whole 16 vCPU to
one proof where a fleet box gives a proof `CARGO_BUILD_JOBS=8` of 32 shared with four CI agents and
a neighbouring proof. The 229 s of laptop-wall difference is transport and queue, not compute.

> The fleet driver exited 2 on a transport check, not on the tree: this operator committed to the
> branch while the proof was in flight, so `land-remote.sh` compared the tip the box published
> (`1c6bc813f`) against the laptop's new HEAD and refused to move the tree — which is exactly what
> it is for. The per-line outcome file is the pre-proof's verdict and it came back GREEN, as
> land-remote.sh's own note says it must.

The cost shape, not the stopwatch, is the decision: a fleet box costs whether or not it is proving,
and a Latchkey runner costs only while it is. The gate-only union on xlarge measured 329 s cold
(build 168 s, xtask 25 s, kind-isolation 41 s, construction 51 s, contract battery 44 s), and the
construction gate's own budget **holds** at 16 vCPU — 39,607 of 50,000 work units, 79%.

### What the first live sweep found (2026-09-11 18:09)

Phase 2 went live and the first sweep failed on two defects in the seam, neither of them about
Latchkey and both of them worth writing down because they are the shape a *second* backend always
fails in.

1. **The transport was resolved from the tree being proven.** The dispatcher ran
   `bash "$tree/scripts/prove-latchkey.sh"`, and `$tree` is the runner's checkout at the **landed**
   tip — which does not carry an unlanded script. Every line came back `No such file or directory`,
   **exit 127**. The engine's own scripts come from the **engine home** (`$SCRIPTS` / `LAND_SH_SRC`,
   which the supervisor archives), never from the tree: *the tree is the subject of a proof, not its
   tooling.* `lq_stage_engine` now stages `prove-latchkey.sh` beside `land.run.sh` as
   `target/gate/prove-latchkey.run.sh`, with `REPO=` rewritten to the tree exactly as
   `land-remote.sh`'s is — because that script derives its `REPO` from its own path, and a copy run
   out of the scratch would have packed the **wrong tree, confidently**. An engine home archived
   before this landed simply has no latchkey transport; the dispatcher says so and takes a box.
2. **Exit 127 was scored as a pre-proof RED.** The rows went into `preproved.txt` as
   `RED <tip>@…` and the lines were parked `#RED-preproof` — the engine parked real work over its
   own missing file. Nothing had been built, picked or judged. `126`, `127` and `70` are now
   `NONE:harness` before every other rule, on all three paths (a single line, a chained rung, and a
   chain root, which empties every rung behind it when it is scored red). `1` is still RED and `2`
   is unchanged: a rule that swallowed a prover's own red would park nothing ever again, which is
   the more expensive failure. `75` is left exactly where it was — already a NONE, already never a
   park, and relabelling it would rewrite every reclaimed box in the ledger.

The general lesson for phase 3: **a second backend's first failure mode is not the backend, it is
the code path that assumed there was only one.** Both defects are in `landq4.sh`, not in
`prove-latchkey.sh`, and neither would have been caught by any amount of testing of the Latchkey
side alone.

### Go / stop for phase 3 (the landing engine)

**STOP**, on two conditions, both of them about the landing and not about this phase:

1. **Self-healing must be off workspace-wide, confirmed by an org owner.** A pre-proof that a retry
   healed to zero costs the queue an order and is caught by the `NONE:healed` detection above. A
   LANDING that a retry healed to zero **publishes a tree nobody proved**. Detection is the right
   answer for a pre-proof and is not an acceptable answer for a landing: the marker is a string in
   a log, and a product that can change that string can change it in a release note.
2. **The concurrency cap must be raised above 20, or the landing must be exempted from it.** The
   landing engine is serial by construction, so it needs one runner — but it needs that one runner
   *now*, and today a sweep and a CI push together can leave zero. A landing that waits behind a
   concurrency limit is the queue stalled, which is the one thing the engine is for.

A third item is a **measurement**, not a condition: a full batch landing is up to 2.2 h and
Latchkey's job timeout caps at **7200 s (2 h)**. A batch that would exceed the cap has to be split
before phase 3 can be anything other than a partial migration.

**GO for phase 2** stands on the measurement above: the packed tree is byte-complete, the history
delta has a fix that is proven green on the runner, the pre-proof's worst failure mode (a healed
retry) is detected and never scored green, and the overflow path is the fleet the engine already
has. The default stays `fleet`; the backend is a variable the operator sets.

## Phase 3 — the landing itself, and the pre-proof under the ceiling

Phase 2 moved the sweep's pre-proofs. Phase 3 is the last workload on the fleet and the last reason
any EC2 box is awake: **the landing's own proof**. It is `BUSBAR_LAND_BACKEND=fleet|latchkey`, a
variable separate from `BUSBAR_PROVE_BACKEND` on purpose — a pre-proof that is wrong costs the queue
an order; a landing that is wrong publishes — and the two move independently, in that order, and can
move back independently.

### The shape change: the tree travels, so the laptop is the box

`land-remote.sh` ships the whole batch to one fleet box: the box picks, the box proves, the box
bisects, the box publishes a tip and the laptop fast-forwards onto it. **That shape cannot shard.**
A Latchkey job is a packed directory and one bash line; the picks are a property of the TREE, so the
tree is what travels — and once the tree travels, the laptop is the box:

* `scripts/land.sh` runs **here**, in `$LANDQ_ROOT`, exactly as it runs on a fleet box. It applies
  the picks, it halves the batch on red, it writes `<batch>.result`, it fast-forwards nothing
  because the tree it proved is already HEAD, and the laptop pushes as it always did.
* `prove_tree` is the **only** thing that leaves. Each call becomes a fan of jobs over the tree as
  it stands at that moment, which is why **the bisect works unchanged**: `land.sh` resets to a
  smaller pick set and calls the prover again, and the prover packs whatever it is given.

The cost is one cold build per job and it is paid on purpose: `latchkey run` exposes no cache (Fast
Cache is a WORKFLOW feature only, measured by LK-5), so a shard is ~168 s of cold
`cargo build --workspace --all-targets` on xlarge before it measures anything. Four shards pay it
four times; four shards also turn a 2.2 h serial oracle into four jobs well under the ceiling, which
is the difference between a landing that can run here at all and one that cannot.

### The 7200 s ceiling is the reason for every shard plan in this phase

It is Latchkey's, it is per JOB, and it is not negotiable. Measured:

| workload | serial | fits under 7200 s? |
|---|---|---|
| gate-only union, cold, xlarge (LK-2) | 908 s | yes |
| full oracle, every family, fleet box | up to 2.2 h | no |
| gate self-test batteries (`land_gate_battery_set`'s table) | up to 4,900 s | with nothing else |
| **a pre-proof of a whole tree on `large`** | **hit the cap** | **no** |

The landing's plan:

```
job "union"   plugins, fmt, gatefiles, tests, clippy, kind-isolation, gate   (the oracle subtracted)
job "fam-k"   the oracle, over bucket k of the union's family alternation    (k = 1..N, default 4)
job "base"    the oracle at the BASE tip with NO picks, run alongside        (what makes a red readable)
```

The pre-proof's plan, added after the cap hit four real trees (SUB-4's and three of M1c-b's) inside
`xtask selftest plane-purity-strict`:

```
job "build"   plugins fmt gatefiles tests clippy workspace-clippy
job "gates"   kind-isolation gate      <- the cap's home: the gate legs and their self-test batteries
job "oracle"  oracle                   <- its own job ONLY when every line in the batch names --families
```

**Every shard intersects every possible plan, by construction.** `plugins fmt gatefiles` and
`kind-isolation gate` are FLOOR in `land_floor_plan` — every union owes them — so neither of those
shards can ever select the empty subset `land_legs_only` refuses (correctly: a shard that owns no
leg has measured nothing). The oracle is the exception and it is handled by **asking**: `oracle` is
in a plan only when the line names `--families`, so one family-less line in the batch and the oracle
rides with `build`, where it always has something to do.

**The pre-proof's families are not bucketed, and that is a limit rather than an oversight.**
`land-latchkey.sh` splits one union's family alternation because a landing is ONE union and the
transport is handed its expression. A pre-proof batch is N lines each carrying its own `--families`
*inside its argv*, and `land.sh` reads that argv per line — there is no per-line channel through
which the transport could hand a bucket down. Bucketing would mean rewriting queue lines, and a
transport that edits the line it is proving is proving a different line.

### A cap hit is `NONE:cap`, never a red

The cap took three pre-proofs on the night of 09-11 and **all three were recorded RED**: three live
queue lines called red for the size of the runner they were rented. Nothing about those picks had
been measured — the job was killed mid-leg.

Latchkey spells a capped job three ways and `lk_job_capped` asks all three: the terminal state
`expired`; a `failed` job whose own `Failure reason` names a timeout; and a job whose
`Started..Completed` reaches the ceiling. The code is 124, the verdict is `NONE:cap`, and in
`landq4.sh` it is a **fault class of its own** — not `harness` (a different disposition) and not
`box-unreachable`, which would send `lq_fault_wake` off to start EC2 boxes for a workload that has
left them. The line stays live, unparked, re-swept on the class's backoff. A capped shard prints
**what it completed** before the ceiling, because that is the shard plan's next move written down: a
cap in `gates` says split the batteries, a cap in `build` says the tree grew.

### The cap's real cause was a regex, not a battery

The sharding above was built because the batteries were measured at 4,900 s and the cap looked like
a capacity problem. It was partly one. The rest of it was this, found by M1c-b-r:

`.keep-proof.toml`'s `tests` array was read with a **single-line** `sed`:

```
sed -n 's/^[[:space:]]*tests[[:space:]]*=[[:space:]]*\[\(.*\)\].*/\1/p'
```

TOML has two spellings of the same array and that reads one of them. A multi-line

```toml
tests = [
  "busbar-core",
  "xtask",
]
```

matched nothing, so the value came back **empty** — and empty means "the caller named no package",
which the runner answers with `cargo test --workspace`: **94 minutes**. That is what walked three of
M1c-b's jobs into the ceiling. Not the batteries, not the runner size: a reader that could only see
one of two legal spellings, **failing open into the most expensive leg the engine has.**

It is parsed now, by `tomllib` through `python3 -c`, with an awk fallback that joins the bracket span
before it splits — and the fallback is exercised by the selftest through `LK_TOML_FORCE_AWK`,
because otherwise it would never run on any machine until the day it was the only reader left.

**And a declared-empty array is not an absent key.** `tests = []` says *this hand-back asks for no
cargo test*; an absent `tests` says *the caller did not scope it*. The first must not become the
workspace — that is the same failing-open shape one level up — so the reader prints the sentinel `-`
and the runner **subtracts** the leg.

The general rule, and it is the third time this migration has met it: **a reader that cannot
distinguish "absent" from "empty" will eventually choose the expensive answer for the wrong reason.**
The 127-as-a-verdict defect, the `VcpuLimitExceeded`-as-a-red defect and this one are all that shape.

### `LATCHKEY_MAX_JOBS` is a bound on jobs, and a pre-proof is no longer one job

Twelve pre-proofs over a fan of three is **thirty-six runners** on a twenty-runner workspace shared
with CI. The process bound is now the job bound divided by the fan
(`LATCHKEY_JOBS_PER_PROOF`, default 3). Under-dividing blows the cap; over-dividing leaves a runner
slot idle for a minute.

### Two defects the two-backend world produced, and both were ours

The general lesson of phase 2 repeated itself twice in phase 3, and it is worth stating as a rule:
**a second backend's first failure mode is not the backend, it is the code path that assumed there
was only one.**

1. **The base is the merge-base or nothing.** On a tree whose tip is already an ancestor of
   `origin/integration/oracle-phase0` — a re-pick with no delta of its own — `merge-base` equals
   HEAD, and the fallback beneath it answered with the raw local branch tip. That sha is **not an
   ancestor of what the tip's push carries**, so its objects never arrived, `update-ref` died
   `nonexistent object`, and every pre-proof that slot took came back `could not stage the history`
   — an infra refusal wearing a tree's clothes. The invariant is one sentence: **the base is always
   an ancestor of the tip.** A base that equals the tip is the *right* answer for a zero-delta tree,
   because the PICKS are the delta and they arrive as their own refs.
2. **A refused submission said the wrong thing.** `2>/dev/null` on `latchkey run` threw away the
   only sentence that could name the cause, so a four-minute refusal was reported as "the
   workspace's runner cap is shared with CI" — a guess — and the operator's next move (wait for the
   cap) was the wrong one. The id is read from stdout and the CLI's own stderr is kept for the log.

### The adoption gates

No backend is adopted without its gate passing **on the exact engine the home carries** (the
owner's process rule, 19:28: *test piecemeal, never let a 2-hour run find it*). There are three now,
one per thing that can be wrong:

| gate | what it drives | where |
|---|---|---|
| `landq4.sh --smoke-latchkey '<line>' …` | the pre-proof backend: N lines concurrently, the real CLI | a scratch `LANDQ_ROOT` |
| `landq4.sh --smoke-latchkey --landing` | **one real landing**: picks applied, union proven on rented jobs, tip published, push taken | a scratch clone with **its own bare origin** under `$LAND_TMP` |
| `landq4.sh --smoke-bigbatch <queue file>` | the popper, against the **real queue**, copied first | a scratch `LANDQ_ROOT` |

The landing gate is the harder one and it has to be, for the reason this document keeps repeating: a
landing publishes. So it drives a landing **where a publish cannot reach anybody** — a bare origin
created under `$LAND_TMP`, the clone's `origin` repointed at it for the duration and put back
whatever happens — and it takes **its own pick**, cut in the clone off the clone's own tip, because
a gate that can fail merely because the scratch tree is a day old is a gate nobody runs twice. It
sets `LANDQ_LOCK` to a scratch path for the same reason: a gate that can only run while the live
runner is down is a gate that is run once.

And it **compares the landed tree with the fleet path's**. The two backends differ in where
`prove_tree` ran and in nothing else; `prove_tree` publishes nothing; the picking code is the same
file, because `land-remote.sh` copies the engine to the box exactly as `prove-latchkey.sh` packs it
into the job. So the tip a latchkey landing publishes must be **tree-identical** to the one the
fleet path publishes for the same line — and that is checked rather than argued: a third checkout at
the same base takes the same pick with the same `git cherry-pick -x` the box runs, and the two tree
oids are compared.

### Go / stop for phase 3

The two phase-2 STOP conditions were about the landing and this is the landing, so they are answered
here:

1. **Self-healing is off workspace-wide** (the owner turned the sidecar off; it now only posts a
   diagnosis). That is a SETTING and a setting can be changed by somebody who is not reading this
   file, so `lk_job_verdict`'s healed-retry rule is unchanged and still runs on every job's log: a
   zero with `[latchkey-bash-wrapper]` in it is `NONE:healed`, which is not a verdict. **Detection
   is kept even though prevention is claimed.**
2. **The cap is not waited on, which is the answer instead of a raise.** 20 concurrent, shared with
   CI, 40 requested and still pending on their side. A landing whose submission is refused has
   learned NOTHING about its picks: `land-latchkey.sh` retries on a bounded backoff (30, 60, 120,
   240, 300 s) and then exits 75, which `landq4.sh` scores `harness` — the batch's lines go back on
   the queue LIVE and unchanged and the batch is re-taken on the class's backoff. Never a park,
   never a HALT, and **never a landing that holds the engine open until a slot appears**: that is
   the same outage as a landing that failed, taken slowly.
3. The third item was a **measurement**, and it is taken: a full batch is up to 2.2 h serial against
   a 7200 s per-job ceiling, and the shard plans above are the split it asked for.

**Zero EC2** is the two remaining boxes going when one landing has proven on Latchkey and the gate
above is green on the engine in the home. The boxes that remain are for landings and the base replay
only; the fleet watchdog retires with them.

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

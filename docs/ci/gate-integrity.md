# Gate integrity — who gates the gates

Every rule in this tree is held by a gate, and every gate is a program whose only job is to say NO.
That arrangement has one failure mode, and it is total: **a gate fails by saying nothing.** Delete a
check's body, force its `ok` argument to `true`, turn an `offenders.push` into a `drop` — the file
still compiles, the row still prints PASS, the umbrella still goes green, and the rule it was
enforcing is simply gone. Nothing is red. Nothing is missing. There is no diff to review that looks
like a rule being removed, because a rule being removed looks like a rule.

A hand audit of four gates found 53 checks in exactly that state — enforced by code no test could
distinguish from a stub. That audit took a week and produced a table. **A hand audit is not a gate.**

This document is what replaced it.

## The ratchet law

> Nothing new arrives unheld, and nothing already held quietly stops being held.

Two halves, and they are enforced by two different mechanisms.

*Nothing new arrives unheld* is [`gate-mutants`](../../.github/workflows/gate-mutants.yml). Every
push that changes gate code is mutated, and a stub that survives the gates' own self-proof is a
line of new gate code that nothing holds down. It is scoped to the diff, so its cost is proportional
to the change and it can therefore run on every push rather than once a quarter.

*Nothing already held stops being held* is the ratchets that were already here: the ceilings in
`qa/construction.toml` and `qa/kind-isolation.toml`, held exactly (not approximately) by
`ceiling-slack`, and held against the merge-base by `ceiling-rose`. A number that goes up is a
landing that grew the coupling; a number left above what it measures is slack, and slack is where
drift hides.

`ship-ready` is the row that says both halves are true at the same time, on a tree that is asking to
be promoted.

## What CI holds mechanically

| check | what it is | required on |
| --- | --- | --- |
| `ci umbrella` | every gating job in `ci.yml`, in one status | qa, main |
| `structure lint` | `kind-isolation`, structure-lint, release-order, duplex-ws | qa, main |
| `construction gate (…)` | how the tree is built vs `ARCHITECTURE.md`, on its posture | qa, main |
| `gate-mutants` | the gates themselves, under mutation | qa, main |
| `ship-ready` | the ship criterion, as five rows | qa, main |

The required-check list is not maintained by hand in a settings page. It is
[`scripts/ci-branch-protection.sh`](../../scripts/ci-branch-protection.sh): idempotent, `gh api`,
read-modify-write (it adds a floor to whatever a branch already requires, and never removes a
context somebody added for a reason this script does not know about). It also sets
`allow_force_pushes: false`, `allow_deletions: false` and `enforce_admins: true` — the last of which
is the point. A required check an administrator can click past is a required check that gets clicked
past at 2am, by the person best placed to know they should not.

`strict` is deliberately **false**: this repository lands by cherry-pick, and requiring branches to
be up to date with the base would wedge the landing queue behind its own merges without proving
anything the checks do not already prove.

## The mutation job

`scripts/gate-mutants.sh` runs `cargo-mutants` (pinned by version, cached) over the Rust this branch
changed in the gate sources, with a test command that is **not** `cargo test`:

```
cargo xtask gate kind-isolation      --selftest
cargo xtask gate kind-isolation-ship --selftest
cargo xtask gate construction        --selftest
cargo xtask gate design-bindings     --selftest
cargo test -p xtask --lib
```

The distinction matters more than it looks. `cargo test -p xtask --lib` proves the readers, the
parsers and the helpers. It does not prove that `construction`'s `one-pick-site` row still goes red
on a second pick site — only `cargo xtask gate construction --selftest` does, because only it plants
one. Mutating gate code and asking `cargo test` about it measures the wrong suite and reports a
comfortable number.

`cargo-mutants` can only drive `cargo test`, so `xtask/tests/gate_mutation_proof.rs` is the bridge:
one integration test that shells out to the four gates' own self-proof. Under the mutation harness
the binary it builds is the mutated one, so a stub no self-test case holds down leaves all four green
and the mutant SURVIVES.

**Scope.** `xtask/src/gates/**`, `xtask/src/manifest.rs`, `xtask/src/scan.rs`, `xtask/src/ctx.rs`,
`qa/construction.toml`, `qa/kind-isolation.toml`, `scripts/land.sh`, `scripts/gate-mutants.sh`,
`.github/workflows/**`. The two `.toml` files produce no mutants and are in the list anyway: a push
that only moves a ceiling still has to prove the rule reading it is held, because moving a number is
exactly how a rule stops biting.

**Sharding.** One full four-gate self-proof is roughly half an hour, so the mutants are fanned
across 24 shards, on Latchkey (`--shard k/n`, round-robin) — the EC2 `busbar-xl` fleet this used to
shard across is decommissioned (LK-5). Wall clock is one baseline plus however many mutants land on
the busiest shard; a landing-sized diff puts about one on each.

### The wall clock, measured

Everything about this job's cost is one number repeated: **the test command**, which a shard pays
once for its baseline and once for every mutant it holds. Measured on this tree
(`XTASK_GATE_CEILING_SECS=3600`, one gate at a time, nothing else running):

| leg of the test command | cases | measured |
| --- | --- | --- |
| `cargo xtask gate kind-isolation --selftest` | 107 | **975s** (16m15) |
| `cargo xtask gate kind-isolation-ship --selftest` | 86 | **975s** (16m15) |
| `cargo xtask gate construction --selftest` | 35 | **367s** (6m07) |
| `cargo xtask gate design-bindings --selftest` | 10 | **13s** |
| `cargo test -p xtask --lib` | 176 | **53s** |
| all four gates + the lib suite | | **2383s (39m43)** |

So a shard running the unnarrowed command over a diff that lands one mutant on it costs
`build + 39m43 + build + 39m43` — **over eighty minutes for one mutant**, and the job's original
55-minute shard timeout could not have held it. That is not a fan-out problem; twenty-four shards
do not make a single shard's baseline cheaper.

**The lever that works is not running proofs the stub could not fail.** `kind-isolation --selftest`
executes no line of `gates/construction/`, so against a construction mutant it is 16 minutes spent
establishing that the mutant is not somewhere it could not be. `scripts/gate-mutants.sh --gates`
computes the list from the diff and `XTASK_GATE_MUTATION_GATES` carries it into the harness; the
baseline job reads the same flag, because a baseline proving a wider command than the shards run is
a baseline about a different command.

| the diff touches | test command | one shard, one mutant |
| --- | --- | --- |
| `gates/design_bindings/**` only | 13s + 53s = **66s** | ~2m + builds |
| `gates/construction/**` only | 6m07 + 53s = **7m00** | **~14m** + builds |
| `gates/kind_isolation/**` only | 16m15 + 16m15 + 53s = **33m23** | **~67m** + builds |
| anything shared (`mod.rs`, `manifest.rs`, `scan.rs`, `ctx.rs`, an unmapped path) | **39m43** | ~80m + builds |

**Two of those four fit the 40-minute target and two do not, and pretending otherwise would be the
same kind of comfortable number this whole document exists to refuse.** A construction- or
design-bindings-scoped push now finishes well inside it. A kind-isolation-scoped push does not: its
two self-proofs are 32 minutes between them and the shard pays that twice. The shard timeout is
raised to 120 minutes so that case reports a verdict instead of a timeout — a timeout is red, but it
is red about the clock rather than about the tree, which is the least useful red there is.

**Levers considered and not taken.**

*A baseline cache keyed on the tree hash, shared inside the run.* The 24 shards start together, so
there is no first finisher for the others to wait on; a cache written by shard 3 at minute 40 is
read by nobody. Making them wait serialises the fan-out, which costs more than it saves.

*Hoisting the baseline out of the shards again.* Refused, and see the section above for what it cost
the last time — the baseline is the only observation of the environment a mutant is actually tested
in.

*More shards.* Wall clock is `baseline + (mutants on the busiest shard) x (test command)`. At a
landing-sized diff the busiest shard already holds one mutant, so the second term is already minimal
and every extra shard adds another whole baseline to the fleet's bill for nothing.

*A bare `cargo test -p xtask` as the command.* `xtask/tests/cli.rs` carries two cases —
`selftest_runs_every_registered_gates_red_proof` and
`the_registry_and_the_workflow_still_name_the_same_gates` — that re-run **every** registered gate's
self-proof, 45 minutes of it. Naming `--lib` and `--test gate_mutation_proof` explicitly is what
keeps that out of every baseline and every mutant. Adding a test target here adds its cost to every
mutant in the campaign.


That fan-out is why the trigger stops at `integration/**`, `dev`, `qa`, `main` and pull requests, and
no longer includes `keep-*`. The workflow's `concurrency:` cancels a branch's *own* superseded run,
which is no help when the load is ~15 distinct hand-back branches each claiming a shard at once: the
integration tip's proof queued behind slot work it had nothing to do with (`docs/ci/self-hosted-
runners.md`, the old EC2-fleet-sizing doc, predicted exactly this before it was retired with the
fleet itself — LK-5).
So for a slot branch the 24-shard proof runs in two places instead: **locally**, as
`scripts/gate-mutants.sh --shard 1/1` (one shard, every mutant, same script and same test command),
by any slot whose diff enters the mutation scope, stated in the hand-back; and **at landing**, on
the integration branch, where the required check is actually read from. `ship-ready:gate-mutants`
already falls back to the merge-base's verdict when a commit carries no run of its own.

**Two things the job refuses to treat as green.**

*A shard that did not run.* No output directory is not "no survivors found"; it is red.

*A skipped baseline.* The first version of this job ran the unmutated command once, in its own job,
and told the shards to skip theirs — the baseline being a property of the commit, and paying for it
24 times being the whole wall clock. That reasoning is wrong, and the first real run proved it wrong
in the worst direction: `cargo test -p xtask --lib` passes on the checkout and fails inside
`cargo-mutants`' scratch copy. Every mutant therefore "failed the tests" for a reason that had
nothing to do with the mutation, every mutant was reported CAUGHT, and the job was GREEN over a
campaign that had measured nothing at all. The baseline is not a property of the commit; it is a
property of the commit **in this environment**, and the environment is the scratch copy, which only
the shard can see. It runs in every shard now, and `--baseline skip` is reachable only by hand.

**Why the required check is not path-filtered.** A required status that a `paths:` filter can decline
to report is a required status that blocks every unrelated pull request forever, which is how
required checks come to be removed. So the workflow always runs and `gate-mutants` always reports;
the *work* is what the scope decides. A push with no gate Rust in it goes green in about a minute,
honestly, having measured that there was nothing to measure.

## The ship-ready row

`cargo xtask gate ship-ready` is the old ship checklist, as five rows that can each go red on their
own:

- `ship-ready:ship-twin` — `kind-isolation-ship` is green: the twin measures zero everywhere.
- `ship-ready:ceiling-slack` — every ceiling equals the thing it measures.
- `ship-ready:ceiling-rose` — no number in a `qa` ceilings file went up on this branch.
- `ship-ready:standing-reds` — the standing-red list is EMPTY, for a `qa`/`main` posture.
- `ship-ready:gate-mutants` — the mutation verdict for this commit is green.

The first three are read from the gates that own those rules rather than re-implemented here; a rule
implemented in two places is a rule two gates can disagree about while both stay green. If the
construction gate stops emitting `ceiling-slack` at all, this gate goes **red**, not quiet.

`ship-ready:standing-reds` is the one row that reads a posture. The standing-red list is a *dev-line
convenience*: construction rows that are known red, written down, and deliberately not blocking the
integration line while they are drained. That is reasonable to have and unreasonable to promote —
promoting it does not drain it, it promotes the breakage and retires the record of it. So the row is
green-with-the-list-printed on the dev line and red for `qa`/`main` while anything is on it.

### Why the mutation verdict is read from GitHub and not from a file in the tree

The obvious design is for the mutation job to commit `qa/gate-mutants.json` — `{tree, surviving,
run_url}` — and for the row to read it. That design cannot work.

**A committed file is a claim the claimant wrote.** Anyone who can push to the branch can write
`"surviving": 0` next to their own tree hash, and nothing in the repository can tell that file apart
from the one the job wrote: same branch, same permissions, no signature to check. The gate would be
asking the person being gated whether they passed. And it fails in the quiet direction — the forgery
is a one-line edit and the gate goes green.

The GitHub check for a commit is a record only GitHub can write. It is keyed to the commit SHA, it
cannot be produced by editing the tree, and re-running it requires actually re-running it. So the row
asks the checks API over `gh`, and **an answer it cannot get is red, never green**: a gate that
cannot reach its evidence has not been satisfied, it has been prevented from asking. `mutants.out/`
is still uploaded as a run artefact and the run URL is still printed — as a pointer for a human,
never as the verdict.

## The landing runner

`scripts/land.sh --to qa|main` is the promotion posture. In it:

- the standing-red allowance is **refused entirely** — `land_construction_standing_reds` returns
  nothing, so any construction FAIL row aborts the leg, and the refusal names the rows;
- every override that could let a red through (`LAND_PUSH_ANYWAY`, `LAND_CI_RED_OK`, `LAND_FORCE`,
  `LAND_SKIP_GATES`, `LAND_ALLOW_RED`) is refused up front, by name, before any work happens;
- the posture is printed at the top of the run, with the sentence that no override can turn a red
  into a land.

An override flag that survives into `qa`/`main` is the same thing as no gate at all — it is the
`--no-verify` of promotion, and it is always used on exactly the day it should not be.

## The sentence this all exists for

**There is no human step between a red and a fix.** Humans and agents write code and push it; the
gates go red on their own, in CI, on the fleet, with the offending line printed; the push to `qa` or
`main` is impossible until it is green — not discouraged, not reviewed, impossible, because branch
protection is code and the landing runner refuses its own overrides. Nobody has to remember to run
anything, nobody has to read a checklist, and nobody has the option of deciding this one is fine.

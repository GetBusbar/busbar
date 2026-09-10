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

### The base every ratchet is measured against

Every rule above is a comparison, and a comparison needs a left-hand side. That commit is **the
base**, and there is exactly one thing in `xtask` that decides what it is:
`xtask/src/gates/construction/ceilings.rs::base_ref`. `ceiling-rose` reads it (and `--write`'s
strike of the declared raises the base carries reads it with them), `kind-isolation`'s provenance
rules (`[[dep]]`, `minted-row`, `second-mint`) read it, and `ship-ready:gate-mutants` reads it — the
last of which used to compute its own merge-base in its own words, which is two answers to one
question in one binary.

By default the base is the **merge-base with `origin/integration/oracle-phase0`**, and `HEAD~1` when
that merge-base *is* `HEAD` (which is the state the integration line itself is in, where "what this
branch changed" is what the last commit changed).

**`BUSBAR_GATE_BASE_REF` moves it, everywhere, at once.**

| the variable | what the base is |
| --- | --- |
| unset (or empty) | the merge-base, exactly as before — nothing about the default path changes |
| set to a ref this repository resolves | **that commit**; no merge-base is computed and no `HEAD~1` is fallen back to |
| set to a ref this repository has not got | every rule that reads the base is **RED**, naming the variable and the ref |

The third row is the point. "The operator named a base and it is not here" is the state a shallow
clone or a missing fetch is in, and falling back to the merge-base there would measure the branch
against a commit nobody named and report the answer as though they had — a green, quietly, for the
wrong comparison. So it refuses, by name.

It exists for the landing runner, which proves a pick against the base it is actually being landed
on rather than against whatever the integration tip happens to be at that second, and for forks
whose integration line has another name. It is a **repointing** variable in exactly the sense
`CONFIG_SCHEMA_BASELINE_REF` is, so `scripts/verify-1.6.0-done.sh` refuses a DONE run that sets it:
a DONE run means "this tree was measured against something outside itself", and a base of the
operator's choosing is a different claim.

`scripts/gate-mutants.sh` keeps its own `GATE_MUTANTS_BASE`, because it computes a *merge-base with*
the ref it is given rather than taking the ref as the base; its default is spelled to match
`INTEGRATION_REF` so that one branch has one base.

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

**Sharding.** One full four-gate self-proof is roughly half an hour, so the mutants are fanned across
24 shards of the `busbar-xl` fleet (`--shard k/n`, round-robin). Wall clock is one baseline plus
however many mutants land on the busiest shard; a landing-sized diff puts about one on each.

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

### Whose mutation verdict is about this tree

`ship-ready:gate-mutants` asks the checks API about **HEAD**. When HEAD has no `gate-mutants` check
at all, there is exactly one commit that may answer for it and one condition under which it may:

> The base may answer for the tip only when the branch changed **nothing in the mutation job's
> scope** — because only then is the gate code at the tip the gate code at the base.

This used to be unconditional, and the rationale beside it was true of one case and applied to all
of them: a commit that only moved documentation carries no run of its own, so the branch point's
standing verdict is the honest answer for it. For a branch that moved documentation, yes. For a
branch that rewrote `xtask/src/gates` and was never pushed, the base is a commit that **carries none
of the picks** — its green says nothing about the gate code being shipped, and the row printed PASS
over it.

Which files count as "the scope" is not written down here, and not written down in `xtask` either.
`scripts/gate-mutants.sh` says of its own list *"this list is the single source of truth: the
workflow does not repeat it, it calls `--scope`"*, so the row reads `gm_scope_paths()` out of that
script. A copy in Rust would be the second source of truth, and a path added to the job but not to
the copy is a path this row believes the branch cannot have touched — the fallback going quiet
again, one file at a time. A scope that cannot be read, or that reads as **empty**, is RED: empty
means "this branch changed nothing the job measures", which is the answer that hands every
ancestor's verdict to every tip.

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

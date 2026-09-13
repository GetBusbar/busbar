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

### The `ceiling-rose` transition, and its closing line

`ceiling-rose` currently reads a declared raise in either of two shapes: the array form
(`[[gate.ceiling_raises]]`, keyed by a row's identity) and a retired `[gate.ceiling_raises."<key>"]
from`/`to` header, kept alive only because a queue of already-measured faces was cut against the
reader that took it. The same transition also lets an ordinal key (`cell.<N>.count`) resolve
against the base's row order, for the same reason — most of the queued declarations were written
against a position, not an identity. Neither of these is read from a clock: nothing in the gate
calls `now()`, reads a commit date, or compares against a stored one, so nothing turns red when a
date passes. The transition closes only when a specific commit lands.

That commit is **`gate ceiling-rose: the from/to transition closes — the retired header is refused
again`**, queued to land on **2026-09-18**. It deletes two arms in
`xtask/src/gates/construction/ceilings.rs`: `read_pair`'s acceptance of the retired `from`/`to`
header, and the ordinal-resolution arm inside `judged` that resolves a `cell.<N>.count` key against
the base's row order. After it lands, both shapes are refused exactly as they were before the
transition opened. A selftest case (`transition_arms_present_cases` in
`xtask/src/gates/construction/selftest.rs`) plants both shapes today and holds them to green by
name; the closing commit's own diff deletes that case along with the arms it was proving present,
so a reader can tell the transition is still open by that case still existing rather than by
reading a date in a comment.

### The minted-dep door

`ceiling-rose` admits a ceiling the base never carried through `[[minted]]` (a new crate) or
`[[minted_kind]]` (a new column) — but a brand new `[[dep]]` edge is usually between two crates
that already exist; neither mint row has anything to say about it, and until now that left it
unlandable: `kind-isolation:deps` requires the row for any new shipped edge, and `ceiling-rose`
refused the row's key (`dep.<from>.<to>.<half>.count`, absent at the base) because no `[[minted]]`
or `[[minted_kind]]` row admitted it either.

The row is now its own admission, in the same style `[[minted]]` uses: it must carry `ceiling` (the
count it is born at), and its `verdict` must be the class `kind-isolation`'s own grant table
(`ARCHITECTURE_ALLOWED` / `ARCHITECTURE_TCB`, read through `kind_isolation::dep_class_verdict`)
already implies for the (from-kind, to-kind) pair — never a class the row asserts for itself. A row
with no `ceiling` is refused by name; a row with `ceiling` but a class the architecture does not
grant is refused by its class; a row with both is admitted, and a rise above that `ceiling`
afterwards is an ordinary declared raise. This is the one place `xtask/src/gates/construction/
ceilings.rs` reads `xtask/src/gates/kind_isolation.rs` — a narrow, one-directional seam kept to two
functions so the two gates never carry two different answers about the same grant table.

**Two defects in that door, both measured before a real edge tried to use it.** First, `[[dep]]`'s
own row reader (`take_row` in `xtask/src/gates/kind_isolation.rs`) took every field it was given
POSITIONALLY and treated every one as mandatory, so a row carrying the door's new `ceiling` field was
either refused outright (`ceiling` was not in the wanted-field list, so it read as `unknown-field`
and the whole row was dropped) or, if `ceiling` were simply added to that list, silently reindexed
every row that does NOT carry it — `verdict` would read `count`'s old slot on every one of the
ledger's other 219 rows. The fix is `take_row_opt`, a sibling reader that keeps the mandatory fields
positional (so every row written before `ceiling` existed keeps reading byte-identically) and reads
the optional set BY NAME instead (so a field's absence cannot shift anything after it). `[[dep]]` is
its first user; a `ceiling`-less row reads exactly as before, a `ceiling`-bearing row's figure is
carried on `DepEdge` and surfaced in the `--report` debt printout, and an empty or non-numeric
`ceiling` is refused at load the same way every other malformed number in this table is.

Second, the door's own admission (`dep_admission`) checked a new row's `verdict` against ONLY the
architecture's ordinary grant table (`ARCHITECTURE_ALLOWED` / `ARCHITECTURE_TCB`), which has no arm
for a transitional exemption — so a pair the grant table implies `not-allowed` for was refused by
class even when a standing `[[transitional]]` row already carries it as a named drain exemption
(`busbar-core -> busbar-unit-*`, owner ruling 2026-09-08, which `kind-isolation:deps` already accepts
off the same table). `dep_admission` now asks `kind_isolation::transitional_covers` first: a pair a
`[[transitional]]` row names is admitted at the row's own `ceiling` without the class check — the
transitional table is a grant with an expiry, not the absence of one — and an uncovered pair is
refused exactly as before.

The selftest also carries two cases for E1b's own two rows (`busbar-plugin-loader` /
`busbar-plugin-sdk -> busbar-contract`, `tcb`) on the ordinary (non-transitional) `tcb` path — but
only once `ARCHITECTURE_TCB` actually grants that pair, which is E1b's own change and not this
door's. The cases are gated at construction time on `kind_isolation::dep_class_verdict` returning
`tcb` for the pair and push nothing when it does not, so they neither fail today nor need a second
change once E1b's grant lands beneath this branch.

### The minted-rule door

The minted-dep door above closes the hole for `qa/kind-isolation.toml`. `qa/construction.toml` has
the same hole in a different shape, and it was measured the same way — by a line that could not
land. `ceiling-rose` compares the branch's ceilings against the base's, and until GATES-6 it walked
the BASE's key map, so a key the base did not carry was never visited at all. GATES-6 turned the
walk around; what it then found is this: a whole **rule** born on the branch — a `[rules.<name>]`
table the base carries no key of — has no `before` anywhere, and no honest `0 -> N` declaration to
write for it either. A rule opens with several ceilings at once (a `loc-ceilings`-shaped rule opens
five in one commit), and declaring each as its own `[[gate.ceiling_raises]]` entry is paperwork
describing a birth as a sequence of raises it never had. Worse, such an entry can never be marked
*used* — `raises()` marks a declaration used only when the diff loop flagged its path as risen, and
a path the base has no value for is not a rise — so the entry sits in the file forever failing its
own expiry check, which is `ceiling-rose`'s stale-waiver refusal. That is the RED that struck TS-1's
declaration and parked its line.

So the rule table gets the admission the crate and the column already have. The ledger entry lives
in `qa/construction.toml` itself — the same document `ceiling-rose` ratchets, so the door reads no
second file — and its form is:

```toml
[[minted_rule]]
rule = "the-rule-name"          # the `[rules.<name>]` table this row admits, once
commit = "<sha>"                # the landing that minted the table (optional, and checked)
<ceiling_key> = "<figure>"      # one line per ceiling the table opens, at the figure it opens at
```

`rule` and `commit` are not ceilings (they are in `NOT_CEILINGS`, beside `[[minted]]`'s and
`[[minted_kind]]`'s own figures); **every other field of the row is one of the rule's opening
ceilings**, read as a bare TOML integer or a quoted one, exactly as `[[minted]]` reads its
`ceiling`. The door admits the declared opening value ONCE, base to tip — never a chain of deltas —
and a ceiling of the rule the row does not name is undeclared, and RED, exactly as an unadmitted
`[[cell]]` is. A rule table carrying two integer ceilings needs both lines; a rule whose table has
no integer in it needs no row at all, because there is nothing for `ceiling-rose` to ratchet.

A row admits nothing at all in three cases, each refused by name:

* **second mint** — the base already carries a key of `[rules.<name>]`. The table's opening was
  declared once and is history; every figure after that moves through `ceiling-rose`, in a commit
  that says which number went up.
* **unlanded rule mint** — this tree carries no ceiling under `[rules.<name>]`, so the row admits a
  table that does not exist.
* **mint mismatch** — the row names a key the table does not carry on this tree, or (when `commit`
  can be read) the figure it declares is not what that commit's own copy of `qa/construction.toml`
  actually carried at `rules.<name>.<key>`. A row may name the figure a rule was born at; it may not
  assert one of its own choosing, or the ledger becomes the authority on its own history instead of
  a record of it. A row with no readable `commit` is trusted on its keys' presence alone, the same
  as a `[[minted]]` row is trusted on its `ceiling`.

**The row is spent the moment its rule lands**, and `cargo xtask gate construction --write` strikes
it — the same discipline `--write` keeps for a declared raise the base has come to carry. This is
not tidying. From the landing onward every base carries `[rules.<name>]`, so the row is a second
mint by the rule above; left in the file it would red `ceiling-rose` on the next branch and every
branch after it. The strike and the refusal are one mechanism read from two sides.

One line of `--report` exists only for this door: `ceiling-rose` reports a *rise*, and a rule landing
at exactly what it is admitted for is not one, so a mint that stayed under its admission would
otherwise print nothing anywhere. The `N rule(s) BORN this branch` line is how the report says a
rule was minted at all.

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

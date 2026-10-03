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

*Nothing new arrives unheld* is every gate's own `--selftest`: each owed row has a planted case that
must go RED, and `cargo xtask selftest` refuses a gate with an unproven row. A manual mutation run is
described under *The mutation job* below.

*Nothing already held stops being held* is the ratchets that were already here: the zero-armed
tripwires and count ratchets in `qa/construction.toml`, the edges in `qa/kind-isolation.toml`, and
the census that refuses a rule table deleted together with its floor. A new edge or a rise in a
zero-armed tripwire is a landing that grew the coupling.

Size is NOT one of them. The line-count ceilings, `ceiling-rose`, `ceiling-slack` and the
kind-isolation figure counts are deleted: size is not a CI check (owner 2026-10-02), and it is
measured by hand at PERF with `cargo xtask loc`.

`ship-ready` is the row that says both halves are true at the same time, on a tree that is asking to
be promoted.

## What the pipeline holds mechanically

busbar has one pipeline workflow, `.github/workflows/promote.yml`: every same-repo pull request is one
hop up the branch ladder, and the release engine in busbar-release plans the hop from the PR's base
branch.

| check | what it is | required on |
| --- | --- | --- |
| `preflight` | formatting, `Cargo.lock` current, the generated C header current, on a free runner | qa, main |
| `hop` | the turnstile admits the candidate: EVERY registered `cargo xtask gate`, plus the oracle and conformance where the rung asks, then the fast-forward of the base | qa, main |

`ship-ready` is a registered gate like the rest: it runs on every hop, with `XTASK_SHIP_TARGET` set to
the hop's base branch, so it is strict for `qa` and `main` and carries the dev line's standing reds
for `predev` and `dev`.

### Which executable scenario runs on the dev push

Same question, one layer down. `qa/teller-steps.json` maps every Teller step of every gating plane to
the scenario that proves it, and `cargo xtask gate teller-steps` asserts each cell NAMES A REAL
SCRIPT. It does not run one. The twelve `scripts/mcp-subject/h2-*.sh` and `scripts/a2a-subject/h2-*.sh`
scenarios — the admission path end to end, authenticate through exit — are run by
`testing/shadow-oracle/rigs-ledger.sh`, driven from the TELLER-STEPS group of
`scripts/verify-1.6.0-done.sh`; no pipeline job runs them per hop. Eight of the twenty rigs are the
MONEY legs, one set per plane: `h2-class-price.sh`, `h2-card-epoch.sh`, `h2-unpriced-refuses.sh`
(added when the rigs' subject became a billing-ON deployment, #42) and `h2-ledger-unconditional.sh`
(the 2026-09-22 ruling that the metering write does not depend on the rate card at all). See
`docs/design/BUSBAR-1.6.0.md` Part 7 §12/§13.

### Which registered gate runs on a hop

Every gate in `xtask`'s registry runs on every hop: the turnstile discovers them with
`cargo xtask gate --list` and runs each by name, so a gate that runs on no job cannot exist here
quietly. `design-bindings` counts a gate module as invoked exactly when it is registered; a script it
cites counts only when something the pipeline runs invokes that script, and a script nothing runs
compares nothing, so the binding is reported unproven rather than waved through.

The required-check list is not maintained by hand in a settings page. It is
[`scripts/ci-branch-protection.sh`](../../scripts/ci-branch-protection.sh): idempotent, `gh api`,
read-modify-write (it adds a floor of two contexts, `preflight` and `hop`, to whatever a branch already requires, and never removes a
context somebody added for a reason this script does not know about). It also sets
`allow_force_pushes: false`, `allow_deletions: false` and `enforce_admins: true` — the last of which
is the point. A required check an administrator can click past is a required check that gets clicked
past at 2am, by the person best placed to know they should not.

`strict` is deliberately **false**: this repository lands by cherry-pick, and requiring branches to
be up to date with the base would wedge the landing queue behind its own merges without proving
anything the checks do not already prove.

## The mutation job

There is none. `scripts/gate-mutants.sh` and the workflow that ran it are deleted, and no required
check reads a mutation verdict. `xtask/tests/gate_mutation_proof.rs` stays as the bridge a manual
`cargo-mutants` run over `xtask/src/gates/**` drives (`XTASK_GATE_MUTATION_PROOF=1`): under mutation
the binary it builds is the mutated one, so a stub no self-test case holds down leaves every gate
green and the mutant SURVIVES. Naming `--lib` and `--test gate_mutation_proof` as the test command,
and never a bare `cargo test -p xtask` (whose `cli.rs` re-runs every gate's self-proof, 45 minutes of
it), keeps that cost out of every mutant.

## The ship-ready row

`cargo xtask gate ship-ready` is the old ship checklist, as two rows that can each go red on their
own:

- `ship-ready:ship-twin` — `kind-isolation-ship` is green: the twin measures zero everywhere.
- `ship-ready:standing-reds` — the standing-red list is EMPTY, for a `qa`/`main` posture.

(`ship-ready:ceiling-slack` and `ship-ready:ceiling-rose` are deleted with the construction rows they
read: size is not a CI check, owner 2026-10-02.)

(The `gate-mutants` mutation verdict was a fifth row here. Per owner ruling it is now manual-only
and optional — it tests the tests, it does not gate a release — so ship-ready no longer owes or
reads it, and branch protection no longer requires the `gate-mutants` check.)

The ship twin is read from the gate that owns it rather than re-implemented here; a rule
implemented in two places is a rule two gates can disagree about while both stay green.

`ship-ready:standing-reds` is the one row that reads a posture. The standing-red list is a *dev-line
convenience*: construction rows that are known red, written down, and deliberately not blocking the
integration line while they are drained. That is reasonable to have and unreasonable to promote —
promoting it does not drain it, it promotes the breakage and retires the record of it. So the row is
green-with-the-list-printed on the dev line and red for `qa`/`main` while anything is on it.

## The landing runner

Promotion is `promote.yml`'s hop (busbar-release `ci/promote/`): a pull request into `qa` or `main`
is admitted by the turnstile or not at all, and the hop has no override flag. A lane lands on
`predev` through `busbar-release ship`, which opens the pull request and stops; CI is the proof.

## The sentence this all exists for

**There is no human step between a red and a fix.** Humans and agents write code and push it; the
gates go red on their own, in CI, on the fleet, with the offending line printed; the push to `qa` or
`main` is impossible until it is green — not discouraged, not reviewed, impossible, because branch
protection is code and the hop has no override. Nobody has to remember to run
anything, nobody has to read a checklist, and nobody has the option of deciding this one is fine.

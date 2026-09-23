# S18-post-partition

The three files that entered the tree after the 17+6 slice partition was cut, and so belonged to
no slice. Swept directly. Each is a gate module — the instruments the rest of the sweep was
measured with, which makes an unfalsifiable one the worst kind of gap.

| FILE | VERDICT | EVIDENCE | ROWS |
|---|---|---|---|
| `xtask/src/gates/kind_abi_lane.rs` | FINDING | `grep -c 'fn selftest'` -> 1 but `grep -c 'prove_red'` -> **0**, against 8 `Row::fail` sites. Registered (`grep -c 'kind_abi_lane::' gates/mod.rs` -> 1) and invoked (`grep -c kind-abi-lane ci.yml` -> 2). So eight refusal arms ship with no case proving any of them can fire. | X-4000 |
| `xtask/src/gates/kind_isolation/closure.rs` | FINDING | 803 lines, 2 `Row::fail`, no `selftest` of its own; it is reached through the parent `kind-isolation` battery, whose own case for `:closure` reports IMPOSSIBLE because the row is standing red. So the rule is real and its falsification is blocked, not absent. | X-4001 |
| `xtask/src/gates/sweep_coverage.rs` | FINDING | 4 `prove_red` cases, all three planted arms proven GREEN->RED after the overlay fix. But `grep -c sweep-coverage ci.yml` -> **0**: the completeness instrument for this whole sweep runs nowhere automatically. Four of its six rows still carry no RED case. | X-4002 |

## ROWS RAISED

### X-4000 · kind-abi-lane ships eight refusal arms and no proof any of them can fire
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `grep -c 'prove_red' xtask/src/gates/kind_abi_lane.rs` -> 0, while `grep -c 'Row::fail'` -> 8.
           Control: `xtask/src/gates/sweep_coverage.rs` -> 4 prove_red / 9 Row::fail, so the grep
           finds prove_red where it exists. The gate IS registered and IS run on every push
           (`grep -c 'kind-abi-lane' .github/workflows/ci.yml` -> 2), which makes this worse, not
           better: it is a green that has never been shown able to go red, running on every commit.
ACTION:    Add one prove_red case per Row::fail arm, each planting the violation that arm names.
           Any arm that cannot be planted is itself the finding.

### X-4001 · the closure rule's falsification is blocked by its own standing red
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `closure.rs` has no `fn selftest`; it is exercised through `kind-isolation`, where the
           case covering `kind-isolation:closure` reports IMPOSSIBLE — prove_red requires
           GREEN->RED and the row is red on arrival. The rule's mechanics are covered by 11 unit
           tests that need no green baseline, so this is a lost falsifiability, not an absent rule.
           A standing red and a lost falsifiability are different facts.
ACTION:    Clear the standing red on `:closure` (the 60 real findings it reports), then the case
           can be asked. Do not weaken the rule to make the case pass.

### X-4002 · the sweep's own completeness gate runs nowhere, and four of its six rows have no RED case
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `grep -c 'sweep-coverage' .github/workflows/ci.yml` -> **0**. Same for `map-proof` -> 0
           and `unconstructed` -> 0. Control: `no-float-money` -> 2. Three registered gates are
           invoked by nothing automatic. Separately, `cargo xtask selftest sweep-coverage` names
           four owed rows — `:denominator`, `:swept`, `:reachability-axis`, `:compiles-and-tracked`
           — as covered by no RED case, so each could be deleted with the selftest still green.
ACTION:    Add the three gates to ci.yml, and a RED case per uncovered row. `:swept` and
           `:compiles-and-tracked` are standing red today, so those two will honestly report
           IMPOSSIBLE until the tree clears them.

## TALLY
files in slice:  3
verdict lines:   3
CLEAN:           0
FINDING:         3      rows raised: 3
DELETABLE:       0
UNREADABLE:      0

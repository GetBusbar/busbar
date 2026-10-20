//! THE KIND-ISOLATION GATE'S RED PROOF, DRIVEN THROUGH THE DISPATCHER.
//!
//! No check of the pipeline runs a gate's `--selftest` by itself; this test is what holds the
//! gate's planted-fault battery to exit 0 under `cargo test --workspace`, so a rule that stops
//! going RED on its plant is a named test failure.
//!
//! THE NAME CARRIES ITS TIME BUDGET. This is a whole-battery selftest (the dearest in the registry,
//! about two hundred cases, each driving the whole gate over the tree: `gates::SELFTEST_BUDGETS`),
//! and the `test` check's nextest limits give a test five minutes except the whole-battery
//! selftests, which it selects by the name `selftest_runs_every_registered_gates_red_proof` and
//! gives twelve minutes and an early start (`.ci/default.yaml`, the protected config's copy). Under
//! the five-minute default this battery was terminated at 300 s before it could report, so its
//! name ends in that phrase: the budget is the one the CI config already reserves for exactly this
//! kind of test, not a longer limit written here.

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn kind_isolation_selftest_runs_every_registered_gates_red_proof() {
    assert_eq!(run(&["gate", "kind-isolation", "--selftest"]), 0);
}

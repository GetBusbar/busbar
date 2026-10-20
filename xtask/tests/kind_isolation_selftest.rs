//! THE KIND-ISOLATION GATE'S RED PROOF, DRIVEN THROUGH THE DISPATCHER.
//!
//! No check of the pipeline runs a gate's `--selftest` by itself; this test is what holds the
//! gate's planted-fault battery to exit 0 under `cargo test --workspace`, so a rule that stops
//! going RED on its plant is a named test failure.

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn the_kind_isolation_gate_proves_red_in_its_selftest() {
    assert_eq!(run(&["gate", "kind-isolation", "--selftest"]), 0);
}

//! THE C1-LITERALS GATE'S SELF-TEST, DRIVEN THROUGH THE DISPATCHER.
//!
//! The gate's vocabulary is the plugin registry's (BUSBAR-1.6.0.md l.2068-2069: "Where a roster of
//! instances must exist, it is derived from the instances' own declarations"). Its self-test plants
//! an instance `plugins.yaml` gains, a registered auth plugin (`oauth`) and an ordinary-word
//! instance named as the instance a config selects, and proves each RED. This file pins that
//! self-test at exit 0 under `cargo test --workspace --locked`. It does not pin the gate's verdict.

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

/// The gate proves it reds on every registered instance, not on a hand-typed copy of the roster.
#[test]
fn the_c1_literals_gate_proves_red_in_its_selftest() {
    assert_eq!(run(&["gate", "c1-literals", "--selftest"]), 0);
}

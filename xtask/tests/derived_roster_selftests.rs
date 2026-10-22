//! THE DERIVED-ROSTER GATES PROVE THEIR REDS UNDER `cargo test` (audit XA2 HIGH 1, XF HIGH 12,
//! XG HIGH 2).
//!
//! `cargo xtask gate --all` judges the tree; it does not run a gate's selftest battery, so a plant
//! that would no longer bite is caught only where a test drives the battery. This file drives the two
//! batteries whose rosters are derived from the LLM plane's declarations: `dialect-map` (the dialect
//! roster: a deleted mapping file, a roster under its floor) and `kernel-token-wire-purity` (the
//! token wire-field set the dialect tables declare, and its floor).

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn the_dialect_map_gate_proves_every_red_in_its_selftest() {
    assert_eq!(run(&["gate", "dialect-map", "--selftest"]), 0);
}

#[test]
fn the_kernel_token_wire_purity_gate_proves_every_red_in_its_selftest() {
    assert_eq!(run(&["gate", "kernel-token-wire-purity", "--selftest"]), 0);
}

//! THE DENYLIST GATE'S RED PROOF, DRIVEN THROUGH THE DISPATCHER.
//!
//! It pins the registered gate's SELFTEST at exit 0: a pure crate `cargo metadata` does not
//! resolve is a red scan row, and a banned edge or a socket in a pinned plane, hook or auth
//! plugin is a red hits row (Q128 xtask #5).

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn the_denylist_gate_proves_red_in_its_selftest() {
    assert_eq!(run(&["gate", "denylist", "--selftest"]), 0);
}

//! THE DOOR-ONLY GATE'S RED PROOF, DRIVEN THROUGH THE DISPATCHER.
//!
//! It pins the SELFTEST at exit 0: a planted path around a plugin's door (a workspace plugin, and
//! a plugin the root pins from its own repo, Q128 xtask #29) and a planted static seam drive the
//! scan RED, and the tree itself is green against its drain-only ledger.

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn the_door_only_gate_proves_red_in_its_selftest() {
    assert_eq!(run(&["gate", "door-only", "--selftest"]), 0);
}

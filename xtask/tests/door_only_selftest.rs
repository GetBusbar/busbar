//! THE DOOR-ONLY GATE'S RED PROOF, DRIVEN THROUGH THE DISPATCHER.
//!
//! It pins the SELFTEST at exit 0: every planted path around a plugin's door (a workspace plugin,
//! a git-pinned one, one reached through a renamed edge, a path `linked_gen.rs` emits and an entry
//! module the root's manifest hands it) and every planted static seam (spelled out, through a type
//! alias, held in a struct's field) drives the scan RED, and the tree itself is green against its
//! drain-only ledger.

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn the_door_only_gate_proves_red_in_its_selftest() {
    assert_eq!(run(&["gate", "door-only", "--selftest"]), 0);
}

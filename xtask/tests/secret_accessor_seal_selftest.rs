//! THE SECRET-ACCESSOR-SEAL GATE'S RED PROOF, DRIVEN THROUGH THE DISPATCHER.
//!
//! It pins the SELFTEST at exit 0: every planted reach for the raw secret accessor or the kernel
//! seal is RED, in an in-tree plugin and in every plugin the root pins from its own repo, whatever
//! its kind (Q128 xtask #38).

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn the_secret_accessor_seal_gate_proves_red_in_its_selftest() {
    assert_eq!(run(&["gate", "secret-accessor-seal", "--selftest"]), 0);
}

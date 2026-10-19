//! THE PLUGIN-CLOSURE-DEPS GATE'S RED PROOF, DRIVEN THROUGH THE DISPATCHER.
//!
//! It pins the SELFTEST at exit 0: a plugin naming the kernel, the seal lender, or a busbar crate
//! the workspace does not hold (a git copy of a retired one, Q128 xtask #36) is RED.

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn the_plugin_closure_deps_gate_proves_red_in_its_selftest() {
    assert_eq!(run(&["gate", "plugin-closure-deps", "--selftest"]), 0);
}

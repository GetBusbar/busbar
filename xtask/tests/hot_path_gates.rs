//! THE HOT-PATH GATES, DRIVEN THROUGH THE DISPATCHER.
//!
//! `docs/design/1.6.0-plane-extraction-LOCKED.md` §8 owes a perf gate and an alloc gate; §11b counts
//! their criterion benches toward the core-engine tests/benches 8→9 rise. Both are registered but
//! deliberately NOT invoked by `ci.yml` yet (the keystone wave owns `.github`), so
//! `full_gate::REGISTRY_NOT_IN_CI` excuses them with `Excuse::XtaskTest` pointing HERE: this file is
//! the coverage route the excuse rests on, and it runs under `cargo test --workspace --locked` on
//! every push. The exact invocation strings below are the needles that excuse checks for — keep them
//! byte-identical to the entries in `xtask/src/full_gate.rs`.
//!
//! Driven through `cli::main` directly, like `xtask/tests/cli.rs`: exit 0 is green, and a gate that
//! could not run would not be able to return it.

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn the_hot_path_perf_gate_is_green_over_the_committed_instrument() {
    assert_eq!(run(&["gate", "hot-path-perf"]), 0);
}

#[test]
fn the_hot_path_alloc_gate_is_green_over_the_committed_instrument() {
    assert_eq!(run(&["gate", "hot-path-alloc"]), 0);
}

/// Both gates prove they can still go RED — the property `cargo xtask selftest` refuses a gate for
/// lacking. Driven here too so the whole hot-path witness pair has a home under `xtask/tests/`.
#[test]
fn both_hot_path_gates_prove_red_in_their_selftests() {
    assert_eq!(run(&["gate", "hot-path-perf", "--selftest"]), 0);
    assert_eq!(run(&["gate", "hot-path-alloc", "--selftest"]), 0);
}

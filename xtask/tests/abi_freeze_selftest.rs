//! ABI-FREEZE PROVES ITS REDS UNDER `cargo test` (row 159, audit XF HIGH 1).
//!
//! `cargo xtask gate --all` judges the tree; it does not run a gate's self-test battery, so a plant
//! that no longer bites is caught only where a test drives the battery. The battery holds the
//! condemned ABI lanes deleted with no size integer: a file under `abi/hot` or `abi/cold` is RED,
//! and a `[[frozen]]` row (a hand-kept line count, BUSBAR-1.6.0.md l.2102) is RED whatever it says.

#[test]
fn the_abi_freeze_gate_proves_every_red_in_its_selftest() {
    let args = vec![
        "gate".to_string(),
        "abi-freeze".to_string(),
        "--selftest".to_string(),
    ];
    assert_eq!(xtask::cli::main(&args), 0);
}

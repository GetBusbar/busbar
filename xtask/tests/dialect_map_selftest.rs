//! DIALECT-MAP PROVES ITS REDS UNDER `cargo test` (row 159, audit XF HIGH 12).
//!
//! `cargo xtask gate --all` judges the tree; it does not run a gate's self-test battery, so a plant
//! that no longer bites is caught only where a test drives the battery. The battery's roster cases
//! hold the mapping files to the dialects the LLM plane's codec modules declare: a deleted mapping
//! file whose table stays compiled in is RED, and so is a roster under its floor.

#[test]
fn the_dialect_map_gate_proves_every_red_in_its_selftest() {
    let args = vec![
        "gate".to_string(),
        "dialect-map".to_string(),
        "--selftest".to_string(),
    ];
    assert_eq!(xtask::cli::main(&args), 0);
}

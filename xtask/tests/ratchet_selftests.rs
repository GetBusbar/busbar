//! THE RATCHETS HELD AGAINST THE BASE, DRIVEN THROUGH THE DISPATCHER (row 159; Law 9, BUSBAR-1.6.0.md:
//! a ceiling "refuses every rise from that moment").
//!
//! Each gate below reads a drain-only list or a ceiling from the tree it judges, and its self-test
//! plants the edit that used to forgive a new violation in the same change: a ledger row, a
//! sanctioned site, a raised or deleted count, a raised rule ceiling, an added segment-debt row, and
//! (one-memory-abi) an export written in a pinned plugin's source. A gate's self-test exits 0 only
//! when every planted case went RED naming its plant and every control stayed green, so these pin
//! the proofs under `cargo test`, where no other check runs a gate's battery.
//!
//! One test per gate, so each battery has its own time budget and a red names its gate.

fn selftest(gate: &str) -> i32 {
    let args = vec![
        "gate".to_string(),
        gate.to_string(),
        "--selftest".to_string(),
    ];
    xtask::cli::main(&args)
}

#[test]
fn one_memory_abi_proves_its_ledger_against_the_base_and_reads_the_pinned_plugins() {
    assert_eq!(selftest("one-memory-abi"), 0);
}

#[test]
fn c1_literals_proves_its_ledger_against_the_base() {
    assert_eq!(selftest("c1-literals"), 0);
}

#[test]
fn contract_stateless_proves_its_ledger_against_the_base() {
    assert_eq!(selftest("contract-stateless"), 0);
}

#[test]
fn door_only_proves_its_ledger_against_the_base() {
    assert_eq!(selftest("door-only"), 0);
}

#[test]
fn door_cells_rig_proves_its_ledger_against_the_base() {
    assert_eq!(selftest("door-cells-rig"), 0);
}

#[test]
fn plane_secret_blindness_proves_its_ledger_against_the_base() {
    assert_eq!(selftest("plane-secret-blindness"), 0);
}

#[test]
fn plugin_closure_deps_proves_its_ledger_against_the_base() {
    assert_eq!(selftest("plugin-closure-deps"), 0);
}

#[test]
fn linked_dropped_features_proves_its_ledger_against_the_base() {
    assert_eq!(selftest("linked-dropped-features"), 0);
}

#[test]
fn abi_location_proves_its_ledger_against_the_base() {
    assert_eq!(selftest("abi-location"), 0);
}

#[test]
fn plane_purity_proves_its_segment_debt_list_against_the_base() {
    assert_eq!(selftest("plane-purity"), 0);
}

#[test]
fn construction_proves_its_rule_ceilings_against_the_base() {
    assert_eq!(selftest("construction"), 0);
}

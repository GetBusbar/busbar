// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE DOOR HOLDS ITS LEASES IN THE ONE SHARED LEASE HELPER (THE DESIGN, the one kind-neutral
//! SDK lifecycle: "KIND-SHARE's lifecycle module is the one lease and error helper; a kind's local
//! copy is deleted when it is ported").
//!
//! The store door answers its off-path results under leases. It holds them in
//! `abi::sdk::life::Leases`, the table every kind's door shares: one numbering, one release rule
//! (an unknown lease is REFUSED), one zeroization of secret bytes. A second table of its own, with
//! its own counter and its own zeroing loop, is the copy the rule deletes: it drifts from the shared
//! one (the unknown-lease answer already did once), and a plain store loop over bytes freed right
//! after is a dead store the optimiser may remove.
//!
//! The check is a source scan, because the property is "this second table exists nowhere", which no
//! behaviour of a correct copy shows.

/// `abi/sdk/store/door.rs`, as written.
fn store_door_source() -> String {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/abi/sdk/store/door.rs");
    std::fs::read_to_string(&path).expect("store/door.rs is readable")
}

/// The store door declares no lease table, lease counter or byte-zeroing loop of its own, and
/// holds its answers in the shared `life::Leases`.
#[test]
fn the_store_door_keeps_no_lease_table_of_its_own() {
    let source = store_door_source();
    let offenders: Vec<String> = source
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let code = line.split("//").next().unwrap_or_default();
            code.contains("HashMap<u64")
                || code.contains("next_lease")
                || code.contains("for_each(|x| *x = 0)")
        })
        .map(|(i, line)| format!("store/door.rs:{}: {}", i + 1, line.trim()))
        .collect();
    assert!(
        offenders.is_empty(),
        "the store door keeps a lease table of its own beside life::Leases: {offenders:#?}"
    );
    assert!(
        source.contains("life::Leases"),
        "the store door does not hold its leases in the shared life::Leases"
    );
}

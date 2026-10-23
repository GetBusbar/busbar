// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE DOOR SERVES ITS LIFECYCLE THROUGH THE ONE KIND-NEUTRAL SDK LIFECYCLE (THE DESIGN,
//! `docs/design/BUSBAR-1.6.0.md` l.1659-1664, KIND-SHARE: "KIND-SHARE's lifecycle module is the one
//! lease and error helper; a kind's local copy is deleted when it is ported").
//!
//! The store's instance state is a `Life` held in the SDK's `Held`, and every lifecycle slot but
//! `open` is the generic one in `abi::sdk::life`: one `validate` forwarding to the store's parse,
//! one `release` rule (an unknown lease is REFUSED), one `cancel` answering the kind's constant.
//! `open` stays the store's own because its connect step may pend on `open`'s ticket, which the
//! generic `open` cannot. The store's off-path answers are held in `abi::sdk::life::Leases`, the
//! table every kind's door shares: one numbering, one release rule, one zeroization of secret
//! bytes.
//!
//! RED before the port: the store door declared its own `validate`, `refresh`, `retire`, `tick`,
//! `drive`, `cancel`, `release` and `close` slots over its own state, kept its own lease map and
//! counter, and zeroed secret bytes with a plain store loop the optimiser may remove. Its own
//! `release` already drifted from the shared rule once (it accepted an unknown lease).
//!
//! The check is a source scan, because the property is "this second lifecycle exists nowhere",
//! which no behaviour of a correct copy shows. Its behavioural twin is
//! `store_door_allocations::the_store_door_refuses_a_release_of_a_lease_it_does_not_hold`, which
//! drives `release` through the door's table and now reaches the generic slot.

/// `abi/sdk/store/door.rs`, as written.
fn store_door_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/abi/sdk/store/door.rs");
    std::fs::read_to_string(&path).expect("store/door.rs is readable")
}

/// The lines of `source` that are code (a `//` comment cut off), numbered from 1.
fn code_lines(source: &str) -> impl Iterator<Item = (usize, &str)> {
    source
        .lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.split("//").next().unwrap_or_default()))
}

/// The store door declares no lease table, lease counter or byte-zeroing loop of its own, and
/// holds its answers in the shared `life::Leases`.
#[test]
fn the_store_door_keeps_no_lease_table_of_its_own() {
    let source = store_door_source();
    let offenders: Vec<String> = code_lines(&source)
        .filter(|(_, code)| {
            code.contains("HashMap<u64")
                || code.contains("next_lease")
                || code.contains("for_each(|x| *x = 0)")
        })
        .map(|(n, code)| format!("store/door.rs:{n}: {}", code.trim()))
        .collect();
    assert!(
        offenders.is_empty(),
        "the store door keeps a lease table of its own beside life::Leases: {offenders:#?}"
    );
    assert!(
        source.contains("leases().keep_new("),
        "the store door does not hold its answers in the instance's one life::Leases"
    );
}

/// The store door declares no lifecycle slot of its own but `open`: `store_door!` names the
/// generic `abi::sdk::life` slots over the store's `Served` life for the other eight.
#[test]
fn the_store_door_declares_no_lifecycle_slot_of_its_own_but_open() {
    let source = store_door_source();
    let own: Vec<String> = code_lines(&source)
        .filter(|(_, code)| {
            [
                "pub struct Validate<B>",
                "Refresh(RefreshIn,",
                "Retire(GenIn,",
                "Tick(TickIn,",
                "Drive(DriveIn,",
                "Cancel(CancelIn,",
                "Release(ReleaseIn,",
                "Close(InHead,",
            ]
            .iter()
            .any(|own| code.contains(own))
        })
        .map(|(n, code)| format!("store/door.rs:{n}: {}", code.trim()))
        .collect();
    assert!(
        own.is_empty(),
        "the store door keeps lifecycle slots of its own beside abi::sdk::life: {own:#?}"
    );
    for slot in [
        "validate", "refresh", "retire", "tick", "drive", "cancel", "release", "close",
    ] {
        let generic = format!("{slot}: $crate::abi::sdk::Safe<$crate::abi::sdk::life::");
        assert!(
            source.contains(&generic),
            "store_door! does not name the generic life slot for `{slot}`"
        );
    }
    assert!(
        source.contains("impl<B: StoreSlots> Life for Served<B>"),
        "the store's instance state is not a Life"
    );
}

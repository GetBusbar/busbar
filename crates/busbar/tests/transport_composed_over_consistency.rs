// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Every linked wire is built over nothing, as the boot seal records it. A transport is linked only
//! as its memory-ABI door (step 36), and the host serves a door over its own sockets: the door is
//! refused at its build if it names a transport it composes over (`HostWire::new`), so the seal's
//! rows record no layer (`composed_over: None`, which the registry's boot check,
//! `busbar_contract::transport::registry::check_composition`, holds against each declaration). This
//! is the witness that the linked wires agree with that — built by the same bottom-up fold the boot
//! seal (`busbar::root::registry::compose`) runs over the linked transport table, which build.rs
//! hands this test as data (`$OUT_DIR/linked_transports.rs`), and checked against the shipped fold
//! (`src/root/tests/fixtures/transport_fold.txt`, the same rows the root's own fold test reads). The
//! test names no transport: every key it holds is one a linked row declared.

use busbar_contract::transport::TransportSettings;

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

/// The shipped fold: `<wire key> <layer it was composed over, or ->`, in build order.
const TRANSPORT_FOLD: &str = include_str!("../src/root/tests/fixtures/transport_fold.txt");

fn shipped_fold() -> Vec<(&'static str, Option<&'static str>)> {
    TRANSPORT_FOLD
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_once(' ').expect("`<wire> <layer>` row"))
        .map(|(key, over)| (key, (over != "-").then_some(over)))
        .collect()
}

#[test]
fn every_real_transport_answers_composed_over_consistently_with_its_construction() {
    let shipped = shipped_fold();
    // Every linked transport row is built: the fold's rows plus the rows this build leaves unlinked
    // are the shipped table, so a row dropped from the manifest is a row missing here.
    // A row registers every scheme its entry claims (ONE ENTRY PER PLUGIN: an entry's second scheme
    // is its own claim, not a row), so the shipped fold has one row per CLAIM of a linked row.
    let claimed: usize = LINKED_TRANSPORTS.iter().map(|r| (r.claims)().len()).sum();
    assert_eq!(
        claimed + LINKED_TRANSPORTS_OFF,
        shipped.len(),
        "the linked transport table and the shipped fold disagree on how many wires there are"
    );

    let built = fold_linked_transports(&TransportSettings::default());
    assert_eq!(
        built.len(),
        LINKED_TRANSPORTS.len(),
        "every linked wire is built"
    );
    for (row, t) in &built {
        let key = row.key();
        assert_eq!(t.key(), key, "a wire answers the key its door states");
        let (_, expected) = shipped
            .iter()
            .find(|(shipped_key, _)| *shipped_key == key)
            .unwrap_or_else(|| panic!("`{key}` is linked but the shipped fold has no row"));
        assert_eq!(
            *expected, None,
            "{key} is served over the host's sockets and is built over nothing"
        );
    }
    // NO TRANSPORT NAMES ANOTHER (ARCHITECT ruling Q128 U7; TRANSPORT-STACK (2), :4721): the carrier
    // is the connector's choice from the target's scheme, so no shipped wire is built over another
    // and the shipped fold names no layer.
    assert!(
        shipped.iter().all(|(_, over)| over.is_none()),
        "the shipped fold names a layer"
    );
}

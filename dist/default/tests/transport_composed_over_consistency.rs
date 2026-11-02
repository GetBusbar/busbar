// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::transport::TransportSettings;

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

const TRANSPORT_FOLD: &str =
    include_str!("../../../crates/busbar/src/root/tests/fixtures/transport_fold.txt");

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
        assert_eq!(t.key(), row.key, "a wire answers the key its row declares");
        let (_, expected) = shipped
            .iter()
            .find(|(key, _)| *key == row.key)
            .unwrap_or_else(|| panic!("`{}` is linked but the shipped fold has no row", row.key));
        assert_eq!(
            *expected, None,
            "{} is served over the host's sockets and is built over nothing",
            row.key
        );
    }

    assert!(
        shipped.iter().all(|(_, over)| over.is_none()),
        "the shipped fold names a layer"
    );
}

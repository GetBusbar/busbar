// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::transport::TransportSettings;

use crate::root::linked::linked_transport;
use crate::root::registry::{compose, Dropped};
use busbar_core_connector::doors::{row_facts, stated_row, RowFacts};

#[test]
fn every_linked_transport_row_is_keyed_by_its_doors_statement() {
    let stated: Vec<RowFacts> = crate::LINKED_TRANSPORT_DOORS
        .iter()
        .map(|(key, door)| {
            let stated = stated_row(*door).unwrap_or_else(|e| panic!("`{key}`: {e}"));
            assert_eq!(
                stated.key, *key,
                "the connector keys `{key}` by its door's Statement"
            );
            stated
        })
        .collect();
    let rows: Vec<(&str, Vec<&str>)> = crate::LINKED
        .transports
        .iter()
        .map(|t| ((t.key)(), (t.composes_over)().to_vec()))
        .collect();
    assert_eq!(
        stated
            .into_iter()
            .map(|f| (f.key, f.composes_over))
            .collect::<Vec<_>>(),
        rows,
        "each linked row is keyed and layered by its door's Statement"
    );
}
include!(concat!(env!("OUT_DIR"), "/context_test_sources.rs"));
owner_test_sources!(linked_transport_rows);

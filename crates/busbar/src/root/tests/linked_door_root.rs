// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::linked::linked_transport;
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
    // The linked row no longer carries its claims and layers (040c52e0cc: never read); the boot seal
    // reads them off the same door through `row_facts`, which must agree with the connector's key.
    let rows: Vec<(&str, Vec<&str>)> = crate::LINKED_TRANSPORT_DOORS
        .iter()
        .map(|(_, door)| {
            let facts = row_facts(*door);
            (facts.key, facts.composes_over)
        })
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

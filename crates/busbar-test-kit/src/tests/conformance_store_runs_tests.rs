// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S ONE SUITE, RUN IN-TREE (audit loader-conformance #6: one conformance suite per
//! kind). The published store script (`conformance/store.rs`) over the build's store: its linked
//! door and its dropped-in image (the `store_v3_door` example `cdylib`), through the one loader,
//! with the inputs the store's own repo runs it over (`tests/fixtures/store_conformance.json`).
//! These replace the in-tree store suites that duplicated the script.

use crate::conformance::{both_ways, red_count, Subject};

fn subject() -> Subject {
    Subject::new(
        crate::both_ways::store_fixture::door,
        "store_v3_door",
        include_str!("../../tests/fixtures/store_conformance.json"),
    )
}

/// BOTH WAYS: linked vs dropped in, every step at its pin, the folds equal, the contract held.
#[test]
fn the_builds_store_is_one_store_linked_and_dropped_in() {
    both_ways(&subject());
}

/// RED: a moved crossing count on any step of the store's fold is refused.
#[test]
fn red_a_moved_count_on_the_store_fold_is_refused() {
    red_count(&subject());
}

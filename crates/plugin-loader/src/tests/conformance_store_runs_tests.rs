// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::conformance::{both_ways, red_count, Subject};

fn subject() -> Subject {
    Subject::new(
        crate::both_ways::store_fixture::door,
        "store_v3_door",
        include_str!("../../tests/fixtures/store_conformance.json"),
    )
}

#[test]
fn the_builds_store_is_one_store_linked_and_dropped_in() {
    both_ways(&subject());
}

#[test]
fn red_a_moved_count_on_the_store_fold_is_refused() {
    red_count(&subject());
}

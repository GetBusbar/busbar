// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The held cards: read only under the generation they were held under.

use serde_json::json;

use super::*;

#[test]
fn a_card_held_under_a_generation_is_read_under_it_only() {
    let cards = Cards::new();
    assert_eq!(cards.at("planner", 1), None);
    cards.hold("planner", 1, json!({ "name": "P" }));
    assert_eq!(
        cards.at("planner", 1).as_deref(),
        Some(&json!({ "name": "P" }))
    );
    assert_eq!(
        cards.at("planner", 2),
        None,
        "a stale generation is not read"
    );
    assert_eq!(cards.at("other", 1), None);
}

#[test]
fn a_newer_hold_replaces_the_card_and_retire_drops_its_generation() {
    let cards = Cards::new();
    cards.hold("planner", 1, json!({ "v": 1 }));
    cards.hold("planner", 2, json!({ "v": 2 }));
    assert_eq!(cards.at("planner", 1), None);
    assert_eq!(cards.at("planner", 2).as_deref(), Some(&json!({ "v": 2 })));
    cards.retire(1);
    assert!(cards.at("planner", 2).is_some());
    cards.retire(2);
    assert_eq!(cards.at("planner", 2), None);
}

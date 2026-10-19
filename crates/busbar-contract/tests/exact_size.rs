// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE SIZE PER STRUCT (owner ruling 21 and THE DESIGN's R9): every ABI struct has exactly one v1
//! size, and any other size, shorter or longer, is refused with a declared code. No older or
//! shorter size is published or accepted, and a field a short struct lacks never reads as "none".
//! Each item of the sweep keeps its own REDs here: a short size (and a long one) refused.

// ── item: every kind tail is exactly its kind's tail ─────────────────────────────────────────────

const DOOR: &str = include_str!("../src/abi/mechanism/door.rs");

/// RED (ruling 21): the mechanism states ONE size per kind tail, and no growth rule that reads an
/// older, shorter tail with its missing fields as absent.
#[test]
fn the_kind_tail_has_one_size() {
    assert!(
        DOOR.contains("THE KIND TAIL SIZE RULE"),
        "the rule is stated"
    );
    assert!(
        !DOOR.contains("GROWTH RULE") && !DOOR.contains("frozen"),
        "no older, frozen tail size is read"
    );
}

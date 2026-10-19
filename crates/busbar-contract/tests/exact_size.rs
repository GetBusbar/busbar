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

// ── item: the plane snapshot is exactly one size ─────────────────────────────────────────────────

/// RED (ruling 21): a plane's generation snapshot is checked at its one size; a snapshot published
/// at the size before `listed` or before `arrival_spans` is refused, never read as "lists none".
#[test]
fn a_plane_snapshot_of_any_other_size_is_refused() {
    use busbar_contract::abi::plane::check::check_snapshot;
    use busbar_contract::abi::plane::PlaneSnapshot;
    use std::mem::{offset_of, size_of};
    let at = |size: usize| {
        // SAFETY: an all-zero `PlaneSnapshot` is a valid value (integers, NULL pointers, absent
        // blobs and strings).
        let mut s: PlaneSnapshot = unsafe { std::mem::zeroed() };
        s.size = size as u32;
        s.generation = 7;
        s
    };
    let whole = size_of::<PlaneSnapshot>();
    assert_eq!(check_snapshot(&at(whole), 7), Ok(()));
    for size in [
        offset_of!(PlaneSnapshot, listed),
        offset_of!(PlaneSnapshot, arrival_spans),
        whole - 8,
        whole + 8,
    ] {
        assert!(
            check_snapshot(&at(size), 7).is_err(),
            "a {size}-byte snapshot (its one size is {whole}) is refused"
        );
    }
}

const PLANE: &str = include_str!("../src/abi/plane/mod.rs");

/// RED (ruling 21): the plane ABI publishes no shorter accepted size of its tail, snapshot, open
/// `in` or piece answer: no field is documented as read absent past a short `size`.
#[test]
fn the_plane_abi_states_no_shorter_size() {
    for needle in ["ends before it", "stops short of it", "absent tail field"] {
        assert!(
            !PLANE.contains(needle),
            "plane/mod.rs still states `{needle}`"
        );
    }
}

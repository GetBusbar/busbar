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

// ── item: the superseded connection-table lowering is gone ───────────────────────────────────────

const CONN: &str = include_str!("../src/abi/host/conn/mod.rs");

/// RED (ruling 21 and the u10 audit): the test-only `ConnSlots` lowering, which read a short
/// "headless" open descriptor as stating no head words, no longer ships; the connector table
/// (`abi::host::conn::connector`) is the one connection table.
#[test]
fn the_headless_connection_lowering_is_gone() {
    for needle in [
        "OPEN_DESC_HEADLESS",
        "ConnSlots",
        "HostConns",
        "ConnHost",
        "WireOpenDesc",
    ] {
        assert!(
            !CONN.contains(needle),
            "abi/host/conn/mod.rs still ships `{needle}`"
        );
    }
}

// ── item: the C header pins every structure's one size ───────────────────────────────────────────

const HEADER: &str = include_str!("../include/busbar_plugin.h");

/// RED (ruling 21): the C header carries a size assert for EVERY structure it declares, so a C
/// plugin is held to each struct's one size: "N of N structures are pinned by the golden".
#[test]
fn the_c_header_pins_every_structure() {
    let line = HEADER
        .lines()
        .find(|l| l.contains("structures are pinned by the golden"))
        .expect("the header states its layout proof");
    let words: Vec<&str> = line.split_whitespace().collect();
    let at = words.iter().position(|w| *w == "of").expect("`N of M`");
    assert_eq!(words[at - 1], words[at + 1], "{line}");
}

// ── item (LOW): the plane tail caps every list count ─────────────────────────────────────────────

/// RED (u11 LOW): `check_tail` caps EVERY list the plane tail states at `STATEMENT_LIST_MAX`, so no
/// caller (the loader's refusal-status read included) walks a plugin-stated count past its data.
#[test]
fn the_plane_tail_caps_every_list_count() {
    use busbar_contract::abi::mechanism::check::{Rule, STATEMENT_LIST_MAX};
    use busbar_contract::abi::plane::check::check_tail;
    use busbar_contract::abi::plane::{PlaneTail, INGRESS_REQUEST_RESPONSE};
    let base = PlaneTail {
        ingress: INGRESS_REQUEST_RESPONSE,
        ..PlaneTail::ZERO
    };
    assert_eq!(check_tail(&base), Ok(()));
    let over = STATEMENT_LIST_MAX + 1;
    // A non-NULL, aligned pointer to nothing: the cap is judged before any element is read.
    fn dangling<T>() -> *const T {
        std::ptr::NonNull::<T>::dangling().as_ptr().cast_const()
    }
    let at = |t: PlaneTail, field: &str| {
        let f = check_tail(&t).expect_err(field);
        assert_eq!((f.rule, f.field), (Rule::OverMax, field), "{field}");
    };
    macro_rules! over {
        ($ptr:ident, $len:ident, $field:literal) => {
            at(
                PlaneTail {
                    $ptr: dangling(),
                    $len: over,
                    ..base
                },
                $field,
            )
        };
    }
    over!(dialects, dialects_len, "tail.dialects");
    over!(dialect_auth, dialect_auth_len, "tail.dialect_auth");
    over!(scope_kinds, scope_kinds_len, "tail.scope_kinds");
    over!(op_classes, op_classes_len, "tail.op_classes");
    over!(
        billable_classes,
        billable_classes_len,
        "tail.billable_classes"
    );
    over!(route_cost, route_cost_len, "tail.route_cost");
    over!(fee_units, fee_units_len, "tail.fee_units");
    over!(record_kinds, record_kinds_len, "tail.record_kinds");
    over!(egress_targets, egress_targets_len, "tail.egress_targets");
    over!(record_chains, record_chains_len, "tail.record_chains");
    over!(trust_keys, trust_keys_len, "tail.trust_keys");
    over!(
        refusal_statuses,
        refusal_statuses_len,
        "tail.refusal_statuses"
    );
    over!(
        record_retentions,
        record_retentions_len,
        "tail.record_retentions"
    );
}

// ── item: the dead locate head-defaults and states-length words are gone ─────────────────────────

const TRANSPORT: &str = include_str!("../src/abi/transport/mod.rs");

/// RED (2d, after the framers took their head lines and body length, #1203): `LocateIn` lends no
/// head-defaults buffer and `LocateOut` states no `states_length`, so `LocateOut` is one exact size
/// again with no field nothing reads.
#[test]
fn locate_carries_no_dead_head_defaults() {
    for needle in [
        "pub defaults_buf",
        "pub defaults_cap",
        "pub defaults_written",
        "pub defaults_needed",
        "pub states_length",
    ] {
        assert!(
            !TRANSPORT.contains(needle),
            "abi/transport still states `{needle}`"
        );
    }
}

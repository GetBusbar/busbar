// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MECHANISM'S STATED RULES (ARCHITECT review of M0, rulings R1-R7): the four memory classes,
//! sizes, fixed element layouts, ticket uniqueness, concurrency and the NONE ticket, the slot
//! layout, the kind tail head and outcome authority are spec text on the types a plugin author
//! reads, and a rewrite that drops one drops it from the contract. This holds each where it was put.

const MOD: &str = include_str!("../src/abi/mechanism/mod.rs");
const CALL: &str = include_str!("../src/abi/mechanism/call.rs");
const LIFECYCLE: &str = include_str!("../src/abi/mechanism/lifecycle.rs");
const TICKET: &str = include_str!("../src/abi/mechanism/ticket.rs");
const DOOR: &str = include_str!("../src/abi/mechanism/door.rs");

#[test]
fn the_four_memory_classes_are_stated_on_the_mechanism_and_on_out_head() {
    for (file, text) in [("mechanism/mod.rs", MOD), ("mechanism/call.rs", CALL)] {
        for needle in [
            "MEMORY, FOUR CLASSES",
            "(i) REQUEST-PATH RESULTS go into HOST-owned buffers",
            "never hands back a pointer for a result",
            "(ii) GENERATION DATA",
            "only data a plugin PUBLISHES at `open`/`refresh`",
            "The Door and the Statement (the Door points to it) are `'static`",
            "`retire` of that generation",
            "(iii) PER-CALL `OutHead.error`",
            "NEXT op on the same",
            "valid only until the op returns",
            "(iv) OFF-PATH LISTS AND SECRETS",
            "SIZES: the plugin writes at most `min(out.size",
            "reads an absent tail field as zero",
            "FIXED ELEMENTS",
            "growing one is a mechanism bump",
        ] {
            assert!(text.contains(needle), "{file}: {needle}");
        }
    }
}

#[test]
fn a_ticket_is_unique_per_instance_and_its_slot_is_host_private() {
    assert!(TICKET.contains("UNIQUE PER INSTANCE across all workers"));
    assert!(TICKET.contains("HOST-PRIVATE"));
}

#[test]
fn the_concurrency_none_and_slot_layout_rules_are_stated_on_the_lifecycle() {
    for needle in [
        "CONCURRENCY.",
        "ops on ONE ticket are serialized by the host",
        "may run concurrently with request ops",
        "Serialization does not apply to a",
        "PENDING answered on one is FAULT",
        "SLOT LAYOUT.",
        "or the load is refused",
    ] {
        assert!(LIFECYCLE.contains(needle), "{needle}");
    }
}

#[test]
fn every_kind_tail_leads_with_a_kind_tail_head() {
    assert!(DOOR.contains("pub kind_tail: *const KindTailHead"));
    assert!(DOOR.contains("pub struct KindTailHead"));
}

#[test]
fn the_return_value_is_the_authoritative_outcome() {
    assert!(CALL.contains("The RETURN VALUE is authoritative"));
}

#[test]
fn the_host_zeroes_every_out_before_every_call() {
    assert!(CALL.contains("THE HOST ZEROES THE WHOLE `out` BEFORE EVERY"));
    assert!(CALL.contains("(no template)"));
}

/// THE KIND TAIL GROWTH RULE: append-only. A tail at the host's size reads whole; an OLDER tail (at
/// least the kind's frozen size, smaller than the host's) reads its own bytes and the host
/// zero-fills the rest; a NEWER tail reads only the host's bytes; a tail smaller than the frozen
/// size is refused. RED: the strict "smaller than this host's" rule refused the older tail.
#[test]
fn a_kind_tail_grows_append_only() {
    use busbar_contract::abi::mechanism::door::tail_read_len;
    assert_eq!(tail_read_len(56, 40, 56), Some(56), "the host's own size");
    assert_eq!(
        tail_read_len(40, 40, 56),
        Some(40),
        "an older tail: its own bytes"
    );
    assert_eq!(
        tail_read_len(72, 40, 56),
        Some(56),
        "a newer tail: the host's bytes"
    );
    assert_eq!(tail_read_len(32, 40, 56), None, "below the frozen size");
    assert!(DOOR.contains("THE KIND TAIL GROWTH RULE"));
}

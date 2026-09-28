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
            "valid until `retire` of that generation",
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

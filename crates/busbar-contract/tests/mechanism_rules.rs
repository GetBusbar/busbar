// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MECHANISM'S THREE STATED RULES (ARCHITECT review of M0): out-memory lifetime, concurrency and
//! outcome authority are spec text on the types a plugin author reads, and a rewrite that drops one
//! drops it from the contract. This holds each where it was put.

const MOD: &str = include_str!("../src/abi/mechanism/mod.rs");
const CALL: &str = include_str!("../src/abi/mechanism/call.rs");
const LIFECYCLE: &str = include_str!("../src/abi/mechanism/lifecycle.rs");

#[test]
fn the_out_memory_lifetime_rule_is_stated_on_the_mechanism_and_on_out_head() {
    for (file, text) in [("mechanism/mod.rs", MOD), ("mechanism/call.rs", CALL)] {
        assert!(text.contains("OUT-MEMORY LIFETIME"), "{file}");
        assert!(text.contains("NEXT op on the same ticket"), "{file}");
        assert!(text.contains("until `retire` of that generation"), "{file}");
    }
}

#[test]
fn the_concurrency_rule_is_stated_on_the_lifecycle() {
    assert!(LIFECYCLE.contains("CONCURRENCY."));
    assert!(LIFECYCLE.contains("ops on ONE ticket are serialized by the host"));
    assert!(LIFECYCLE.contains("may run concurrently with request ops"));
}

#[test]
fn the_return_value_is_the_authoritative_outcome() {
    assert!(CALL.contains("The RETURN VALUE is authoritative"));
}

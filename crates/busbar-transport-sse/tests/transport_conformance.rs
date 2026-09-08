// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Conformance: this crate is a well-formed `transport`.
//!
//! The kind's shared battery is `busbar_plugin_testkit::transport_conformance`. This file is THE
//! SAME FILE, modulo this crate's own type, in every one of the seven wires — which is the thing
//! `kind-isolation:testkit` found missing: three of the seven carry a `src/tests/battery.rs` of
//! their own and four carry nothing, so the kind had no battery even though 3,652 lines of wire
//! tests existed. Those stay where they are and remain the load-bearing ones; this file is the
//! shared half.

use busbar_contract::transport::TransportMeta;
use busbar_plugin_testkit::transport_conformance as conf;
use busbar_transport_sse::SseTransport;

#[test]
fn the_declaration_is_well_formed() {
    conf::assert_declaration(&conf::TransportDecl {
        key: <SseTransport as TransportMeta>::KEY,
        composes_over: <SseTransport as TransportMeta>::COMPOSES_OVER,
        upgrades_to: <SseTransport as TransportMeta>::UPGRADES_TO,
        transport_facts: <SseTransport as TransportMeta>::TRANSPORT_FACTS,
        session: <SseTransport as TransportMeta>::SESSION,
        session_bound: <SseTransport as TransportMeta>::SESSION_BOUND,
        selector_forms: <SseTransport as TransportMeta>::SELECTOR_FORMS.len(),
        egress_selector_forms: <SseTransport as TransportMeta>::EGRESS_SELECTOR_FORMS.len(),
    });
}

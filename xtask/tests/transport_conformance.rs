// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `transport` KIND'S SHARED CONFORMANCE BATTERY, AND THE SEVEN WIRES IT IS ASKED OF.
//!
//! One test binary, on the tooling side of the tree, for the reason
//! `tests/unit_conformance.rs`'s header states at length: a shared battery is TOOLING, and tooling
//! depends on the plugins it drives, never the reverse. A `transport -> plugin-tooling` edge is in
//! no table the architecture grants and in no trusted-base table either — so the seven wires are
//! UNCHANGED by this landing, and the subjects are named in `xtask`'s own `[dev-dependencies]`,
//! which are edges of the gate runner rather than of the tree.

#[path = "battery/transport.rs"]
mod conf;

mod grpc {
    //! Conformance: this crate is a well-formed `transport`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type, as every one of the seven wires — which is the thing
    //! `kind-isolation:testkit` found missing: three of the seven carry a `src/tests/battery.rs` of
    //! their own and four carry nothing, so the kind had no battery even though 3,652 lines of wire
    //! tests existed. Those stay where they are and remain the load-bearing ones; this block is the
    //! shared half.

    use crate::conf;
    use busbar_contract::transport::TransportMeta;
    use busbar_transport_grpc::GrpcTransport;

    #[test]
    fn the_declaration_is_well_formed() {
        conf::assert_declaration(&conf::TransportDecl {
            key: <GrpcTransport as TransportMeta>::KEY,
            composes_over: <GrpcTransport as TransportMeta>::COMPOSES_OVER,
            upgrades_to: <GrpcTransport as TransportMeta>::UPGRADES_TO,
            transport_facts: <GrpcTransport as TransportMeta>::TRANSPORT_FACTS,
            session: <GrpcTransport as TransportMeta>::SESSION,
            session_bound: <GrpcTransport as TransportMeta>::SESSION_BOUND,
            selector_forms: <GrpcTransport as TransportMeta>::SELECTOR_FORMS.len(),
            egress_selector_forms: <GrpcTransport as TransportMeta>::EGRESS_SELECTOR_FORMS.len(),
        });
    }
}

mod http {
    //! Conformance: this crate is a well-formed `transport`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type, as every one of the seven wires — which is the thing
    //! `kind-isolation:testkit` found missing: three of the seven carry a `src/tests/battery.rs` of
    //! their own and four carry nothing, so the kind had no battery even though 3,652 lines of wire
    //! tests existed. Those stay where they are and remain the load-bearing ones; this block is the
    //! shared half, and lifting the wire half into the testkit is the named next step.

    use crate::conf;
    use busbar_contract::transport::TransportMeta;
    use busbar_transport_http::HttpTransport;

    #[test]
    fn the_declaration_is_well_formed() {
        conf::assert_declaration(&conf::TransportDecl {
            key: <HttpTransport as TransportMeta>::KEY,
            composes_over: <HttpTransport as TransportMeta>::COMPOSES_OVER,
            upgrades_to: <HttpTransport as TransportMeta>::UPGRADES_TO,
            transport_facts: <HttpTransport as TransportMeta>::TRANSPORT_FACTS,
            session: <HttpTransport as TransportMeta>::SESSION,
            session_bound: <HttpTransport as TransportMeta>::SESSION_BOUND,
            selector_forms: <HttpTransport as TransportMeta>::SELECTOR_FORMS.len(),
            egress_selector_forms: <HttpTransport as TransportMeta>::EGRESS_SELECTOR_FORMS.len(),
        });
    }
}

mod sse {
    //! Conformance: this crate is a well-formed `transport`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type, as every one of the seven wires — which is the thing
    //! `kind-isolation:testkit` found missing: three of the seven carry a `src/tests/battery.rs` of
    //! their own and four carry nothing, so the kind had no battery even though 3,652 lines of wire
    //! tests existed. Those stay where they are and remain the load-bearing ones; this block is the
    //! shared half.

    use crate::conf;
    use busbar_contract::transport::TransportMeta;
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
}

mod stdio {
    //! Conformance: this crate is a well-formed `transport`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type, as every one of the seven wires — which is the thing
    //! `kind-isolation:testkit` found missing: three of the seven carry a `src/tests/battery.rs` of
    //! their own and four carry nothing, so the kind had no battery even though 3,652 lines of wire
    //! tests existed. Those stay where they are and remain the load-bearing ones; this block is the
    //! shared half.

    use crate::conf;
    use busbar_contract::transport::TransportMeta;
    use busbar_transport_stdio::StdioTransport;

    #[test]
    fn the_declaration_is_well_formed() {
        conf::assert_declaration(&conf::TransportDecl {
            key: <StdioTransport as TransportMeta>::KEY,
            composes_over: <StdioTransport as TransportMeta>::COMPOSES_OVER,
            upgrades_to: <StdioTransport as TransportMeta>::UPGRADES_TO,
            transport_facts: <StdioTransport as TransportMeta>::TRANSPORT_FACTS,
            session: <StdioTransport as TransportMeta>::SESSION,
            session_bound: <StdioTransport as TransportMeta>::SESSION_BOUND,
            selector_forms: <StdioTransport as TransportMeta>::SELECTOR_FORMS.len(),
            egress_selector_forms: <StdioTransport as TransportMeta>::EGRESS_SELECTOR_FORMS.len(),
        });
    }
}

mod tcp {
    //! Conformance: this crate is a well-formed `transport`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type, as every one of the seven wires — which is the thing
    //! `kind-isolation:testkit` found missing: three of the seven carry a `src/tests/battery.rs` of
    //! their own and four carry nothing, so the kind had no battery even though 3,652 lines of wire
    //! tests existed. Those stay where they are and remain the load-bearing ones; this block is the
    //! shared half.

    use crate::conf;
    use busbar_contract::transport::TransportMeta;
    use busbar_transport_tcp::TcpTransport;

    #[test]
    fn the_declaration_is_well_formed() {
        conf::assert_declaration(&conf::TransportDecl {
            key: <TcpTransport as TransportMeta>::KEY,
            composes_over: <TcpTransport as TransportMeta>::COMPOSES_OVER,
            upgrades_to: <TcpTransport as TransportMeta>::UPGRADES_TO,
            transport_facts: <TcpTransport as TransportMeta>::TRANSPORT_FACTS,
            session: <TcpTransport as TransportMeta>::SESSION,
            session_bound: <TcpTransport as TransportMeta>::SESSION_BOUND,
            selector_forms: <TcpTransport as TransportMeta>::SELECTOR_FORMS.len(),
            egress_selector_forms: <TcpTransport as TransportMeta>::EGRESS_SELECTOR_FORMS.len(),
        });
    }
}

mod tls {
    //! Conformance: this crate is a well-formed `transport`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type, as every one of the seven wires — which is the thing
    //! `kind-isolation:testkit` found missing: three of the seven carry a `src/tests/battery.rs` of
    //! their own and four carry nothing, so the kind had no battery even though 3,652 lines of wire
    //! tests existed. Those stay where they are and remain the load-bearing ones; this block is the
    //! shared half.

    use crate::conf;
    use busbar_contract::transport::TransportMeta;
    use busbar_transport_tls::TlsTransport;

    #[test]
    fn the_declaration_is_well_formed() {
        conf::assert_declaration(&conf::TransportDecl {
            key: <TlsTransport as TransportMeta>::KEY,
            composes_over: <TlsTransport as TransportMeta>::COMPOSES_OVER,
            upgrades_to: <TlsTransport as TransportMeta>::UPGRADES_TO,
            transport_facts: <TlsTransport as TransportMeta>::TRANSPORT_FACTS,
            session: <TlsTransport as TransportMeta>::SESSION,
            session_bound: <TlsTransport as TransportMeta>::SESSION_BOUND,
            selector_forms: <TlsTransport as TransportMeta>::SELECTOR_FORMS.len(),
            egress_selector_forms: <TlsTransport as TransportMeta>::EGRESS_SELECTOR_FORMS.len(),
        });
    }
}

mod ws {
    //! Conformance: this crate is a well-formed `transport`.
    //!
    //! The kind's shared battery is [`crate::conf`], one module over. This block is THE SAME BLOCK,
    //! modulo this crate's own type, as every one of the seven wires — which is the thing
    //! `kind-isolation:testkit` found missing: three of the seven carry a `src/tests/battery.rs` of
    //! their own and four carry nothing, so the kind had no battery even though 3,652 lines of wire
    //! tests existed. Those stay where they are and remain the load-bearing ones; this block is the
    //! shared half.

    use crate::conf;
    use busbar_contract::transport::TransportMeta;
    use busbar_transport_ws::WsTransport;

    #[test]
    fn the_declaration_is_well_formed() {
        conf::assert_declaration(&conf::TransportDecl {
            key: <WsTransport as TransportMeta>::KEY,
            composes_over: <WsTransport as TransportMeta>::COMPOSES_OVER,
            upgrades_to: <WsTransport as TransportMeta>::UPGRADES_TO,
            transport_facts: <WsTransport as TransportMeta>::TRANSPORT_FACTS,
            session: <WsTransport as TransportMeta>::SESSION,
            session_bound: <WsTransport as TransportMeta>::SESSION_BOUND,
            selector_forms: <WsTransport as TransportMeta>::SELECTOR_FORMS.len(),
            egress_selector_forms: <WsTransport as TransportMeta>::EGRESS_SELECTOR_FORMS.len(),
        });
    }
}

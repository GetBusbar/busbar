// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `Transport::composed_over` has no default body: every implementor answers it explicitly. This
//! is the witness that the seven in-tree transports' answers agree with how they are actually
//! built — the same construction [`busbar::root::registry`] uses to compose the real stack.
//!
//! A transport that opens its own socket (`tcp`, `tls`, `http`, `stdio`) answers `None` no matter
//! what it declares in `COMPOSES_OVER`; a transport that is only ever built by holding (or being
//! handed) another instance (`sse`, `ws`, `grpc`) names that instance's key. This test instantiates
//! all seven the way the composition root does and checks both halves: the answer is the one the
//! design's table expects, AND — for the composed three — it is one of the layers the transport
//! actually declares in `COMPOSES_OVER`, which is exactly what the registry's boot check
//! (`busbar_contract_transport::registry::check_composition`) relies on being true.

use std::sync::Arc;

use busbar_contract::{Transport, TransportMeta};
use busbar_transport_grpc::GrpcTransport;
use busbar_transport_http::{ClientSettings, HttpTransport};
use busbar_transport_sse::SseTransport;
use busbar_transport_stdio::StdioTransport;
use busbar_transport_tcp::TcpTransport;
use busbar_transport_tls::TlsTransport;
use busbar_transport_ws::WsTransport;

fn assert_root(t: &dyn Transport) {
    assert_eq!(
        t.composed_over(),
        None,
        "{} opens its own socket and must answer composed_over() = None",
        t.key()
    );
}

fn assert_composed(t: &dyn Transport, composes_over: &'static [&'static str]) {
    let over = t.composed_over().unwrap_or_else(|| {
        panic!(
            "{} is only ever built composed and must name its layer",
            t.key()
        )
    });
    assert!(
        composes_over.contains(&over),
        "{}.composed_over() = {over:?}, which is not in its own COMPOSES_OVER {composes_over:?}",
        t.key()
    );
}

#[test]
fn every_real_transport_answers_composed_over_consistently_with_its_construction() {
    let tcp = Arc::new(TcpTransport::new());
    let tls = Arc::new(TlsTransport::new());
    let http = Arc::new(HttpTransport::new(ClientSettings::default()));
    let sse = SseTransport::new(Arc::clone(&http));
    let ws = WsTransport::over(Arc::clone(&http) as Arc<dyn Transport>);
    let grpc = GrpcTransport::over(Arc::clone(&http) as Arc<dyn Transport>);
    let stdio = StdioTransport::new();

    // The three that open their own socket: `None`, regardless of what they declare.
    assert_root(tcp.as_ref());
    assert_root(tls.as_ref());
    assert_root(http.as_ref());
    assert_root(&stdio);

    // The three that are only ever built composed: the parent they were actually given, and that
    // parent must be one of the layers `COMPOSES_OVER` names.
    assert_composed(&sse, <SseTransport as TransportMeta>::COMPOSES_OVER);
    assert_composed(&ws, <WsTransport as TransportMeta>::COMPOSES_OVER);
    assert_composed(&grpc, <GrpcTransport as TransportMeta>::COMPOSES_OVER);

    // Named exactly, matching the design's own table (`tcp → tls → http → {sse, ws, grpc}`).
    assert_eq!(sse.composed_over(), Some("http"));
    assert_eq!(ws.composed_over(), Some("http"));
    assert_eq!(grpc.composed_over(), Some("http"));
}

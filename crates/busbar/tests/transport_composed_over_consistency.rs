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

use busbar_contract::{check_composition, Registered, Transport, TransportMeta};
use busbar_transport_grpc::GrpcTransport;
use busbar_transport_http::{ClientSettings, HttpTransport};
use busbar_transport_sse::SseTransport;
use busbar_transport_stdio::StdioTransport;
use busbar_transport_tcp::TcpTransport;
use busbar_transport_tls::TlsTransport;
// The WS transport is the voice plane's edge and is compiled only with it, so this witness names
// it only in a build that carries it.
#[cfg(feature = "plane-voice")]
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
    #[cfg(feature = "plane-voice")]
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
    #[cfg(feature = "plane-voice")]
    assert_composed(&ws, <WsTransport as TransportMeta>::COMPOSES_OVER);
    assert_composed(&grpc, <GrpcTransport as TransportMeta>::COMPOSES_OVER);

    // Named exactly, matching the design's own table (`tcp → tls → http → {sse, ws, grpc}`).
    assert_eq!(sse.composed_over(), Some("http"));
    #[cfg(feature = "plane-voice")]
    assert_eq!(ws.composed_over(), Some("http"));
    assert_eq!(grpc.composed_over(), Some("http"));
}

/// A row for the boot check, read off the live transport rather than typed out beside it.
fn row<T: TransportMeta>(t: &dyn Transport) -> Registered {
    Registered {
        key: T::KEY,
        composes_over: T::COMPOSES_OVER,
        composed_over: t.composed_over(),
    }
}

/// THE REAL STACK BOOTS.
///
/// This used to live in the contract crate as a hand-typed table of the seven transports' declared
/// layers, and a hand-typed table is a table that drifts: it had `ws` composing over `http, tcp`
/// long after the transport itself declared `http, tcp, tls`, and had `grpc` built over `tcp` when
/// the composition root builds it over `http`. Both wrong, both green, because nothing tied either
/// column to the thing it described.
///
/// It lives here instead, where the transport crates are reachable, and every column is READ:
/// `KEY` and `COMPOSES_OVER` off the type, `composed_over` off an instance built the way the
/// composition root builds it. There is nothing left to retype, so there is nothing left to drift —
/// a transport that changes what it declares changes this table in the same edit, and a transport
/// composed over a layer it does not declare is the boot refusal the node would give.
#[test]
fn the_real_stack_boots_as_the_transports_themselves_declare_it() {
    let tcp = Arc::new(TcpTransport::new());
    let tls = Arc::new(TlsTransport::new());
    let http = Arc::new(HttpTransport::new(ClientSettings::default()));
    let sse = SseTransport::new(Arc::clone(&http));
    #[cfg(feature = "plane-voice")]
    let ws = WsTransport::over(Arc::clone(&http) as Arc<dyn Transport>);
    let grpc = GrpcTransport::over(Arc::clone(&http) as Arc<dyn Transport>);
    let stdio = StdioTransport::new();

    let mut registry = vec![
        row::<TcpTransport>(tcp.as_ref()),
        row::<TlsTransport>(tls.as_ref()),
        row::<HttpTransport>(http.as_ref()),
        row::<SseTransport>(&sse),
    ];
    // WS is the voice plane's edge and is compiled with it: a row for a transport this build does
    // not carry would be a composition the node never made.
    #[cfg(feature = "plane-voice")]
    registry.push(row::<WsTransport>(&ws));
    registry.push(row::<GrpcTransport>(&grpc));
    registry.push(row::<StdioTransport>(&stdio));

    assert_eq!(check_composition(&registry), Ok(()));
}

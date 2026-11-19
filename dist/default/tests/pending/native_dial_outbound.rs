// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND SIDE THROUGH THE LINKED HTTP IMAGE, against real loopback sockets: a sealed
//! credential reaches the upstream once, in its place, and is never sent as metadata; a provider
//! keyed by a query pair gets its key in the URL; a sealed value is not written in the clear
//! without the destination's own acceptance; a request rides a tunnel through the operator's
//! proxy, whose password appears in the CONNECT only; a refusing proxy fails at the proxy and
//! reaches no provider; a kept connection sends no second CONNECT; and each request's delivery
//! state is its own.
//!
//! RED at the integration head: the native dial hands the transport the credential in the clear,
//! sends the sealing metadata upstream as headers, never puts a query key in the URL, and refuses
//! every destination the proxy choice selects. GREEN when the dial is on the outbound parts
//! (`busbar_core_connector::outbound`) and the image speaks transport 2.0.
//!
//! NOT YET A TEST TARGET: it lives in `tests/pending/` (not compiled) and moves to `tests/` in the
//! change that puts the dial on the outbound parts.
//!
//! The same file proves the parts at the boundary before the real image exists: built with the
//! reference transport fixture in place of `busbar_transport_http::PLUGIN` (the one line in
//! [`Rig::new`]), every assertion stands.

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::conn::PieceKind;
use busbar_contract::storage::{StorageAccount, StorageDenied, StorageSource};
use busbar_core_connector::native_dial::{
    locate, stage, NativeCarrier, NativeConnection, NativeDial, NativeFailure, NativeHead, Tunnel,
};
use busbar_core_connector::proxy::ProxyHop;
use busbar_core_connector::test_support_far_ends::{Behaviour, Provider, Proxy};
use busbar_plugin_abi::plane::CARRIER_HTTP;
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;

const KEY: &str = "sk-live-0123456789abcdef";

/// A storage account that admits everything (the accounting is another test's subject).
struct Open;

impl StorageAccount for Open {
    fn try_reserve(&self, _bytes: usize) -> Result<(), StorageDenied> {
        Ok(())
    }
    fn release(&self, _bytes: usize) {}
}

/// The linked image opened in its client role, and a runtime to drive dials on.
struct Rig {
    runtime: tokio::runtime::Runtime,
    carrier: NativeCarrier,
    // Held: dropping the harness closes the image.
    _harness: Harness,
}

impl Rig {
    fn new() -> Self {
        let harness = Harness::admit_linked(&busbar_transport_http::PLUGIN, FakeNeeds::new())
            .expect("the linked http image admits");
        let port = harness
            .open_transport("busbar-transport-http", b"{}")
            .expect("the linked http image opens");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        busbar_core_connector::io::install_process_reactor(runtime.handle().clone());
        Self {
            runtime,
            carrier: NativeCarrier {
                instance: Arc::from("busbar-transport-http"),
                port,
                carrier: CARRIER_HTTP,
                stall_ms: None,
            },
            _harness: harness,
        }
    }

    /// A dial of `provider`, straight or through `tunnel`.
    fn dial(&self, provider: &Provider, tunnel: Option<(&Proxy, Tunnel)>) -> NativeConnection {
        let located = locate(&format!("{}/v1/models", provider.url())).expect("located");
        let (addr, tunnel) = match tunnel {
            Some((proxy, tunnel)) => (proxy.addr(), Some(tunnel)),
            None => (provider.addr(), None),
        };
        let _entered = self.runtime.enter();
        NativeConnection::dial(
            self.carrier.clone(),
            NativeDial {
                located,
                addr,
                also: Vec::new(),
                tls: None,
                anchors: None,
                open_timeout: Duration::from_secs(10),
                storage: StorageSource::new(Arc::new(Open) as Arc<dyn StorageAccount>),
                tunnel,
            },
        )
        .expect("the dial begins")
    }

    /// One GET on `conn`: its status and its stream, or the failure.
    fn get(
        &self,
        conn: &mut NativeConnection,
        target: &str,
        fields: Vec<(String, Vec<u8>)>,
        sealed_in_clear: bool,
    ) -> Result<(u32, u64), NativeFailure> {
        self.runtime.block_on(async {
            let mut head = Some(NativeHead {
                method: b"GET".to_vec(),
                target: target.as_bytes().to_vec(),
                fields,
                body_len: None,
                budget: Some(Duration::from_secs(20)),
                sealed_in_clear,
            });
            let stream =
                std::future::poll_fn(|cx| conn.poll_send_head(cx, &mut head, false)).await?;
            let mut buf = vec![0_u8; 64 * 1024];
            let mut status = 0;
            loop {
                let piece = tokio::time::timeout(
                    Duration::from_secs(20),
                    std::future::poll_fn(|cx| conn.poll_read(cx, stream, &mut buf)),
                )
                .await
                .expect("an answer within 20 s")?;
                match piece.kind {
                    PieceKind::Fields => status = piece.status_code.unwrap_or(status),
                    PieceKind::Completion => break,
                    PieceKind::Body | PieceKind::HookReply => {}
                }
            }
            Ok((status, stream))
        })
    }
}

fn ok() -> Provider {
    Provider::start(vec![Behaviour::Answer {
        status: 200,
        lines: Vec::new(),
        body: b"{}".to_vec(),
    }])
}

fn sealed_header() -> Vec<(String, Vec<u8>)> {
    vec![
        ("accept".to_owned(), b"application/json".to_vec()),
        ("x-api-key".to_owned(), KEY.as_bytes().to_vec()),
        ("busbar-sealed-fields".to_owned(), b"x-api-key".to_vec()),
    ]
}

#[test]
fn a_sealed_header_reaches_the_upstream_once_in_its_place_and_no_metadata_does() {
    let (rig, provider) = (Rig::new(), ok());
    let mut conn = rig.dial(&provider, None);
    let (status, _) = rig
        .get(&mut conn, "/v1/models", sealed_header(), true)
        .expect("served");
    assert_eq!(status, 200);
    let seen = provider.seen();
    assert_eq!(seen.count(KEY.as_bytes()), 1);
    assert_eq!(seen.count(format!("x-api-key: {KEY}\r\n").as_bytes()), 1);
    assert_eq!(
        seen.count(b"busbar-sealed"),
        0,
        "the sealing metadata is the engine's own and never leaves it"
    );
}

#[test]
fn a_provider_keyed_by_a_query_pair_gets_its_key_in_the_url() {
    let (rig, provider) = (Rig::new(), ok());
    let mut conn = rig.dial(&provider, None);
    let fields = vec![(
        "busbar-sealed-query".to_owned(),
        b"key=AIzaSyExample".to_vec(),
    )];
    let (status, _) = rig
        .get(&mut conn, "/v1beta/models?alt=sse", fields, true)
        .expect("served");
    assert_eq!(status, 200);
    let seen = provider.seen();
    assert_eq!(
        seen.count(b"GET /v1beta/models?alt=sse&key=AIzaSyExample HTTP/1.1\r\n"),
        1,
        "{}",
        String::from_utf8_lossy(&seen.requests[0])
    );
    assert_eq!(seen.count(b"busbar-sealed"), 0);
}

#[test]
fn a_sealed_value_is_not_written_in_the_clear_without_the_destinations_own_acceptance() {
    let (rig, provider) = (Rig::new(), ok());
    let mut conn = rig.dial(&provider, None);
    let refused = rig
        .get(&mut conn, "/v1/models", sealed_header(), false)
        .expect_err("refused");
    assert!(
        refused.cause.outbound,
        "the engine's own refusal: no provider is charged for it"
    );
    assert!(!refused.cause.text.contains(KEY));
    assert_eq!(provider.seen().requests.len(), 0, "nothing was sent");
}

#[test]
fn a_request_rides_a_tunnel_and_the_proxys_password_is_in_the_connect_only() {
    let (rig, provider, proxy) = (Rig::new(), ok(), Proxy::start(None));
    let hop = Arc::new(ProxyHop::new(
        proxy.addr().ip().to_string(),
        proxy.addr().port(),
        Some("Basic dTpw".to_owned()),
    ));
    let tunnel = Tunnel::to_address(hop, provider.addr(), None);
    let mut conn = rig.dial(&provider, Some((&proxy, tunnel)));
    let (status, _) = rig
        .get(&mut conn, "/v1/models", sealed_header(), true)
        .expect("served through the tunnel");
    assert_eq!(status, 200);
    let at_proxy = proxy.seen();
    assert_eq!(at_proxy.requests.len(), 1);
    assert_eq!(
        at_proxy.count(format!("CONNECT {} HTTP/1.1\r\n", provider.addr()).as_bytes()),
        1,
        "the CONNECT names the judged address"
    );
    assert_eq!(at_proxy.count(b"Proxy-Authorization: Basic dTpw\r\n"), 1);
    assert_eq!(
        at_proxy.count(KEY.as_bytes()),
        0,
        "the request's head is never shown to the proxy"
    );
    let at_provider = provider.seen();
    assert_eq!(at_provider.count(b"Proxy-Authorization"), 0);
    assert_eq!(at_provider.count(KEY.as_bytes()), 1);

    // A kept connection was tunnelled when it was dialled: no second CONNECT.
    let (status, _) = rig
        .get(&mut conn, "/v1/models", sealed_header(), true)
        .expect("the kept connection serves the next exchange");
    assert_eq!(status, 200);
    assert_eq!(proxy.seen().requests.len(), 1);
    assert_eq!(provider.seen().connections, 1);
}

#[test]
fn a_refusing_proxy_fails_at_the_proxy_and_reaches_no_provider() {
    let (rig, provider, proxy) = (Rig::new(), ok(), Proxy::start(Some(403)));
    let hop = Arc::new(ProxyHop::new(
        proxy.addr().ip().to_string(),
        proxy.addr().port(),
        None,
    ));
    let tunnel = Tunnel::to_address(hop, provider.addr(), None);
    let mut conn = rig.dial(&provider, Some((&proxy, tunnel)));
    let failed = rig
        .get(&mut conn, "/v1/models", Vec::new(), true)
        .expect_err("no tunnel");
    assert_eq!(
        failed.cause.stage,
        stage::PROXY,
        "a proxy failure is the proxy's: no provider's breaker is charged"
    );
    assert!(failed.cause.text.contains("403"), "{}", failed.cause.text);
    assert_eq!(provider.seen().connections, 0);
}

#[test]
fn a_whole_request_is_recorded_whole_and_a_request_the_provider_cut_is_not() {
    let rig = Rig::new();
    let served = ok();
    let mut conn = rig.dial(&served, None);
    let (_, stream) = rig
        .get(&mut conn, "/v1/models", Vec::new(), true)
        .expect("served");
    assert_eq!(conn.sent_word(stream), "whole");

    let cut = Provider::start(vec![Behaviour::CloseOnRequest]);
    let mut conn = rig.dial(&cut, None);
    let failed = rig
        .get(&mut conn, "/v1/models", Vec::new(), true)
        .expect_err("the provider closed");
    assert_eq!(failed.cause.stage, stage::CONNECT);
    assert_eq!(
        cut.seen().requests.len(),
        1,
        "the provider received the request: it may have worked on it"
    );
}

#[test]
fn a_port_nothing_listens_on_fails_at_the_connect_with_nothing_sent() {
    let rig = Rig::new();
    let closed = Provider::closed_port();
    let located = locate(&format!("http://{closed}/v1/models")).expect("located");
    let _entered = rig.runtime.enter();
    let mut conn = NativeConnection::dial(
        rig.carrier.clone(),
        NativeDial {
            located,
            addr: closed,
            also: Vec::new(),
            tls: None,
            anchors: None,
            open_timeout: Duration::from_secs(10),
            storage: StorageSource::new(Arc::new(Open) as Arc<dyn StorageAccount>),
            tunnel: None,
        },
    )
    .expect("the dial begins");
    let failed = rig
        .get(&mut conn, "/v1/models", Vec::new(), true)
        .expect_err("refused connect");
    assert_eq!(failed.cause.stage, stage::CONNECT);
}

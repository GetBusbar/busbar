// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE EGRESS CLIENT, OR TWO — the posture cell.
//!
//! The `http` transport carried an egress client of its OWN: a second pooled client, built inside
//! the transport, beside the one this node's data path already dials through. Two clients are two
//! postures, and the difference is not a detail of construction — it is visible on the wire. The
//! composed client resolves a destination through the pin it was built with, so a name no
//! nameserver answers still reaches the address that was already judged; a client that keeps its
//! own connector resolves through the system and reaches nothing. Same request, same upstream,
//! two different answers, decided by which of the two pools the dial happened to land in.
//!
//! So the cell is written as the question the transport has to answer: does a request dialled
//! through this transport reach the upstream the COMPOSED client reaches, carrying the bytes the
//! caller wrote? A transport with a pool of its own answers no, and that is the whole finding.
//!
//! The second case is the other half of the same statement. A transport that was composed over no
//! egress client has nothing to dial through, and says so — it does not quietly build one.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use busbar_contract::plugin::KernelSeal;
use busbar_contract::{
    ArenaBytes, DestinationFacts, LaneId, StreamId, Transport, TransportKeyHandle, UpstreamAddress,
    VerifiedDestination,
};
use busbar_substrate::egress::engine::{build_client, EngineClient, EngineSpec};
use busbar_transport_http::{
    ClientSettings, EgressExchange, EgressFault, EgressFuture, EgressRequest, HttpTransport,
};
use futures::StreamExt;

/// The name no nameserver answers. The pin is what makes it reachable, so a client without the pin
/// cannot reach the upstream at all — which is the posture difference, made visible.
const PINNED_NAME: &str = "posture.invalid";

/// THE COMPOSITION, as the root will make it: the engine's client behind the transport's own face.
/// Nothing is decided here — the request goes over as it arrives and the answer comes back as it
/// arrives — which is the whole of what handing a client in means.
struct ComposedEngineClient(EngineClient);

impl EgressExchange for ComposedEngineClient {
    fn exchange(&self, req: EgressRequest) -> EgressFuture {
        let sent = self.0.request(req);
        Box::pin(async move { sent.await.map_err(|e| Box::new(e) as EgressFault) })
    }
}

struct CellSeal;
impl KernelSeal for CellSeal {
    fn seal_origin(&self) -> &'static str {
        "busbar root egress-posture cell"
    }
}

fn cell_key() -> TransportKeyHandle {
    TransportKeyHandle::issue(&CellSeal, 0, "cell")
}

fn upstream_dest(uri: &str) -> VerifiedDestination {
    let host: &'static str = Box::leak(uri.to_string().into_boxed_str());
    VerifiedDestination::seal(
        &CellSeal,
        DestinationFacts::Upstream {
            transport: "http",
            address: UpstreamAddress::socket(host),
            lane: LaneId::new("cell"),
        },
        "http",
        None,
    )
}

/// An upstream that answers with the request HEAD it actually received, so the cell asserts what
/// went out on the wire rather than what the caller meant to put there.
async fn head_echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                    .await
                    .unwrap_or(0);
                let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                let head = text.split("\r\n\r\n").next().unwrap_or("").to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    head.len(),
                    head
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, resp.as_bytes()).await;
            });
        }
    });
    port
}

/// THE POSTURE, ON THE WIRE. The engine's client is built with the destination pinned: the name is
/// answered by the address that was already judged and no lookup is made. A request dialled through
/// the transport must arrive at THAT upstream, with the head the caller wrote, and come back as the
/// same 200 the composed client would have read — because it IS the composed client that sent it.
#[tokio::test]
async fn the_transport_reaches_the_pinned_upstream_through_the_composed_client() {
    let port = head_echo_server().await;
    let client = build_client(&EngineSpec::pinned(
        Arc::from(PINNED_NAME),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        Vec::new(),
    ))
    .expect("the pinned posture builds");

    let transport = HttpTransport::over_egress(
        Arc::new(ComposedEngineClient(client)),
        ClientSettings::default(),
    );
    let uri = format!("http://{PINNED_NAME}:{port}/");
    let conn = transport
        .dial(&upstream_dest(&uri), &cell_key())
        .await
        .expect("the dial names an upstream this transport can express");
    let req = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: {PINNED_NAME}\r\nx-busbar-posture: pinned\r\n\
         content-length: 0\r\n\r\n"
    );
    transport
        .write(&conn, StreamId(0), ArenaBytes::new(req.as_bytes()))
        .await
        .expect("the exchange reaches the pinned upstream");

    let mut frames = transport.frames(conn);
    let (_s, head) = frames.next().await.unwrap().unwrap();
    let head_text = String::from_utf8_lossy(head.bytes.as_slice()).into_owned();
    assert!(
        head_text.starts_with("HTTP/1.1 200 "),
        "the pinned upstream answered {head_text:?}"
    );
    let (_s, body) = frames.next().await.unwrap().unwrap();
    let seen = String::from_utf8_lossy(body.bytes.as_slice()).into_owned();
    assert!(
        seen.starts_with("POST /v1/messages "),
        "the upstream saw {seen:?}, not the request the envelope named"
    );
    assert!(
        seen.to_ascii_lowercase()
            .contains("x-busbar-posture: pinned"),
        "the upstream saw {seen:?}, without the header the caller wrote"
    );
}

/// THE OTHER HALF. A transport handed no egress client has nothing to dial through and answers so.
/// A transport that builds one for itself answers the dial and opens a pool nobody composed.
#[tokio::test]
async fn a_transport_composed_over_no_egress_client_refuses_the_dial() {
    let transport = HttpTransport::new(ClientSettings::default());
    let refused = transport
        .dial(&upstream_dest("http://127.0.0.1:1/"), &cell_key())
        .await;
    assert!(
        refused.is_err(),
        "a transport composed over no egress client answered a dial, so it holds a client of its own"
    );
}

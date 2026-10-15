// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BYTE-IDENTITY CONFORMANCE for the hostless egress seam adapter (`egress::seam`).
//!
//! Ported from the deleted agent engine's `egress_seam_tests`. The adapter drives the host egress poll seam
//! (`drive_open` + `drive_poll`); the comparator is a direct pinned reqwest hop (`build_pinned_client`,
//! the codec every plane's own transport used). Against the SAME loopback fixture the two MUST agree,
//! field for field: status, location, body, the capped-read `ReadEnd`, and, over a stream, the
//! CONCATENATED body. A divergence would make a plane routed through the seam emit different bytes
//! than a direct hop does.
//!
//! The fixtures are PLAINTEXT loopback (the host's `open_http` connects with no extra trust anchors, so
//! a self-signed test CA cannot be reached through the seam). The peer-SPKI dimension is therefore
//! `None == None` here, and `client_identity_offered` is `false` on both sides (no identity).
//!
//! This module is a child of `seam`, so it drives the private `read_capped_over` cap loop and the
//! `buffered` / `stream_head` / `pump` functions directly over one hostless scope.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::sync::Arc;

use super::{buffered, with_hostless, HopSpec};
use crate::egress::{build_pinned_client, RefuseSecondLookup};
use crate::proxy::{read_capped, ReadEnd};

#[cfg(feature = "egress-stream")]
use super::{pump, stream_head, StreamOutcome};
#[cfg(feature = "egress-stream")]
use crate::egress::ChunkFlow;

const LOOPBACK: &str = "127.0.0.1";

/// The body cap the buffered equality tests read to (well above every fixture body).
const CAP: usize = 1024 * 1024;

/// A loopback HTTP/1.1 server that answers every connection with a fixed status line, headers, and
/// body. A plain std listener, so there is no ambient runtime.
fn spawn_mock(
    status_line: &'static str,
    headers: &'static [(&'static str, &'static str)],
    body: Vec<u8>,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let mut head = format!("HTTP/1.1 {status_line}\r\n");
            for (n, v) in headers {
                head.push_str(&format!("{n}: {v}\r\n"));
            }
            head.push_str(&format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            ));
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });
    port
}

/// A loopback server that PROMISES a large `Content-Length` and then sends a short body and closes,
/// so a body read fails mid-transfer (`ReadEnd::TransportError`).
fn spawn_truncating_mock(prefix: &'static [u8], promised_len: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {promised_len}\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(prefix);
            let _ = stream.flush();
            // Drop the connection with the promise unfulfilled: the client sees a mid-body failure.
        }
    });
    port
}

/// What a direct pinned hop observed.
struct Direct {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
    end: ReadEnd,
}

/// Run one direct pinned GET (the exact `build_pinned_client` codec the planes use) and `read_capped`
/// its body: the independent oracle the seam is compared against.
fn direct_read(url: &str, port: u16, cap: usize) -> Direct {
    let addr: IpAddr = LOOPBACK.parse().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let client = build_pinned_client(
            LOOPBACK,
            std::net::SocketAddr::new(addr, port),
            Arc::new(RefuseSecondLookup),
            None,
            &[],
        )
        .expect("pinned client");
        let resp = client.get(url).send().await.expect("hop");
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let (bytes, end) = read_capped(resp.bytes_stream(), cap).await;
        Direct {
            status,
            location,
            body: bytes.to_vec(),
            end,
        }
    })
}

fn hop<'a>(url: &'a str) -> HopSpec<'a> {
    HopSpec {
        verb: "GET",
        url,
        headers: &[],
        body: &[],
        allow_private: true,
        allow_plaintext: true,
        client_identity_ref: 0,
        trust_anchor_ref: 0,
        timeout: std::time::Duration::ZERO,
        resolved_addr: None,
    }
}

/// One seam buffered hop over a throw-away hostless scope.
fn seam_buffered(url: &str, cap: usize) -> super::Buffered {
    with_hostless(|scope| buffered(scope, &hop(url), cap)).expect("seam buffered")
}

/// THE CORE EQUALITY. Pins that the hostless seam's `buffered` and a direct pinned reqwest hop agree
/// field for field against the same fixture: status, location, body, peer key pin and
/// `client_identity_offered`, with a body under the cap reading `Complete`. Ported from the retired agent engine's
/// `egress_seam_tests` (`buffered_adapter_matches_the_..._transport_get_byte_for_byte`, renamed: the
/// kernel names no plane), with the old `ReqwestTransport::get` comparator replaced by the direct hop.
#[test]
fn buffered_adapter_matches_a_direct_pinned_get_byte_for_byte() {
    let body = b"the agent card bytes, exactly".to_vec();
    let port = spawn_mock(
        "200 OK",
        &[("content-type", "application/json")],
        body.clone(),
    );
    let url = format!("http://127.0.0.1:{port}/.well-known/agent-card.json");

    let direct = direct_read(&url, port, CAP);
    let seamed = seam_buffered(&url, CAP);

    assert_eq!(seamed.status, direct.status, "status matches");
    assert_eq!(seamed.location, direct.location, "location matches");
    assert_eq!(seamed.body, direct.body, "body is byte-identical");
    assert_eq!(seamed.body, body, "and equals what the upstream sent");
    assert_eq!(
        seamed.peer_spki, None,
        "no observed peer key pin on plaintext (the direct hop observes none either)"
    );
    assert!(
        !seamed.client_identity_offered,
        "client_identity_offered is false: no identity"
    );
    assert_eq!(
        seamed.end,
        ReadEnd::Complete,
        "a body under the cap reads Complete"
    );
    assert_eq!(seamed.end, direct.end, "the ReadEnd matches the direct hop");
}

/// THE REDIRECT HEAD. Pins that a 302 with a `Location` is surfaced (never followed) with the location
/// verbatim, exactly as a direct pinned hop reads it, so a plane's redirect loop can consume it. Ported
/// from the retired agent engine's `egress_seam_tests`.
#[test]
fn buffered_adapter_surfaces_a_redirect_location_like_the_transport() {
    let port = spawn_mock(
        "302 Found",
        &[("location", "https://elsewhere.example/card")],
        Vec::new(),
    );
    let url = format!("http://127.0.0.1:{port}/");

    let direct = direct_read(&url, port, CAP);
    let seamed = seam_buffered(&url, CAP);

    assert_eq!(seamed.status, 302);
    assert_eq!(seamed.status, direct.status);
    assert_eq!(
        seamed.location.as_deref(),
        Some("https://elsewhere.example/card")
    );
    assert_eq!(
        seamed.location, direct.location,
        "the redirect Location is byte-identical"
    );
}

/// ALL THREE `ReadEnd` STATES. Pins that the seam's cap loop (`read_capped_over`, reached through
/// `buffered`) reproduces `proxy::read_capped` exactly: `Complete` for a body under the cap,
/// `Truncated` (a cap-length prefix) for an over-cap body, `TransportError` for a mid-body failure.
/// Ported from the retired agent engine's `egress_seam_tests`.
#[test]
fn capped_read_reproduces_all_three_readend_states() {
    // (1) COMPLETE: a body under the cap.
    {
        let body = b"small complete body".to_vec();
        let cap = 4096usize;
        let port = spawn_mock("200 OK", &[], body.clone());
        let url = format!("http://127.0.0.1:{port}/");
        let direct = direct_read(&url, port, cap);
        // A second, independent hop for the seam (the mock answers each connection freshly).
        let port2 = spawn_mock("200 OK", &[], body.clone());
        let url2 = format!("http://127.0.0.1:{port2}/");
        let seamed = seam_buffered(&url2, cap);
        assert_eq!(direct.end, ReadEnd::Complete);
        assert_eq!(seamed.end, ReadEnd::Complete, "under-cap body is Complete");
        assert_eq!(seamed.body, direct.body, "Complete body byte-identical");
        assert_eq!(seamed.body, body);
    }

    // (2) TRUNCATED: a body that overruns the cap.
    {
        let body = vec![b'x'; 10_000];
        let cap = 100usize;
        let port = spawn_mock("200 OK", &[], body.clone());
        let url = format!("http://127.0.0.1:{port}/");
        let direct = direct_read(&url, port, cap);
        let port2 = spawn_mock("200 OK", &[], body.clone());
        let url2 = format!("http://127.0.0.1:{port2}/");
        let seamed = seam_buffered(&url2, cap);
        assert_eq!(direct.end, ReadEnd::Truncated);
        assert_eq!(seamed.end, ReadEnd::Truncated, "over-cap body is Truncated");
        assert_eq!(
            seamed.body.len(),
            cap,
            "Truncated body holds exactly cap bytes"
        );
        assert_eq!(seamed.body, direct.body, "Truncated prefix byte-identical");
    }

    // (3) TRANSPORT ERROR: a body that fails mid-transfer.
    {
        let cap = 4096usize;
        let port = spawn_truncating_mock(b"partial", 1000);
        let url = format!("http://127.0.0.1:{port}/");
        let direct = direct_read(&url, port, cap);
        let port2 = spawn_truncating_mock(b"partial", 1000);
        let url2 = format!("http://127.0.0.1:{port2}/");
        let seamed = seam_buffered(&url2, cap);
        assert_eq!(direct.end, ReadEnd::TransportError);
        assert_eq!(
            seamed.end,
            ReadEnd::TransportError,
            "a mid-body failure is TransportError"
        );
    }
}

/// THE STREAM RELAY. Pins that the seam's `stream_head` + `pump` deliver a byte-identical CONCATENATED
/// body for an event-stream reply versus a direct streamed pinned hop, and agree on the head (status,
/// lower-cased content-type). Per the adapter's documented nuance the per-chunk boundaries may differ;
/// the concatenation may not. Ported from the retired agent engine's `egress_seam_tests`, with the old
/// `ReqwestTransport::post_stream` comparator replaced by the direct hop.
#[cfg(feature = "egress-stream")]
#[test]
fn stream_adapter_concatenation_matches_post_stream() {
    use futures::StreamExt;

    let event_stream = b"event: message\ndata: {\"one\":1}\n\ndata: {\"two\":2}\n\n".to_vec();
    let addr: IpAddr = LOOPBACK.parse().unwrap();

    // The direct streamed hop, collecting the concatenated body.
    let port = spawn_mock(
        "200 OK",
        &[("content-type", "text/event-stream")],
        event_stream.clone(),
    );
    let url = format!("http://127.0.0.1:{port}/rpc");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (direct_status, direct_content_type, direct_body) = rt.block_on(async {
        let client = build_pinned_client(
            LOOPBACK,
            std::net::SocketAddr::new(addr, port),
            Arc::new(RefuseSecondLookup),
            None,
            &[],
        )
        .expect("pinned client");
        let resp = client
            .post(&url)
            .body(b"{}".to_vec())
            .send()
            .await
            .expect("direct hop");
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let mut stream = resp.bytes_stream();
        let mut collected = Vec::new();
        while let Some(chunk) = stream.next().await {
            collected.extend_from_slice(&chunk.expect("direct chunk"));
        }
        (status, content_type, collected)
    });

    // The seam: head then pump, under ONE hostless scope (the egress stays open between the two).
    let port2 = spawn_mock(
        "200 OK",
        &[("content-type", "text/event-stream")],
        event_stream.clone(),
    );
    let url2 = format!("http://127.0.0.1:{port2}/rpc");
    let spec = HopSpec {
        verb: "POST",
        url: &url2,
        headers: &[],
        body: b"{}",
        allow_private: true,
        allow_plaintext: true,
        client_identity_ref: 0,
        trust_anchor_ref: 0,
        timeout: std::time::Duration::ZERO,
        resolved_addr: None,
    };
    let mut seam_body: Vec<u8> = Vec::new();
    let seam_head =
        with_hostless(
            |scope| match stream_head(scope, &spec, CAP).expect("seam stream_head") {
                StreamOutcome::Streaming { head, id } => {
                    let mut on = |chunk: &[u8]| -> ChunkFlow {
                        seam_body.extend_from_slice(chunk);
                        ChunkFlow::Continue
                    };
                    match pump(scope, id, &mut on) {
                        super::PumpEnd::Done => head,
                        super::PumpEnd::Failed(f) => panic!("the pump failed mid-stream: {f:?}"),
                    }
                }
                StreamOutcome::Buffered(_) => panic!("an event-stream reply must be a live stream"),
            },
        );

    assert_eq!(
        seam_head.status, direct_status,
        "stream head status matches"
    );
    assert_eq!(
        seam_head.content_type, direct_content_type,
        "content-type matches (lower-cased)"
    );
    assert_eq!(
        seam_body, direct_body,
        "the concatenated event-stream body is byte-identical"
    );
    assert_eq!(seam_body, event_stream, "and equals what the upstream sent");
}

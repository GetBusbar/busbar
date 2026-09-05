// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BYTE-IDENTITY CONFORMANCE for the neutral fetch adapter.
//!
//! The adapter drives the host egress seam (`egress_open` + `egress_poll`); a plane's own transport
//! drives a direct pinned reqwest hop. Against the SAME loopback fixture the two MUST agree, field for
//! field: status, location, body, the capped-read `ReadEnd`, and — over a stream — the CONCATENATED
//! body. If they ever diverge, an extracted plane routed through the seam would emit different bytes
//! than the compiled-in one did, which is the exact regression LAW rule 5 forbids.
//!
//! The fixtures are PLAINTEXT loopback (the host's `open_http` connects with no extra trust anchors,
//! so a self-signed test CA cannot be reached through the seam — the same reason `egress_tests` uses
//! plaintext). The peer-SPKI dimension is therefore `None == None` here; its byte-identity over TLS is
//! by CONSTRUCTION — the host and the plane decode the pin through the one shared
//! `busbar_substrate::plane_host::spki::pin` (`a2a::spki::spki_pin` re-exports it), so there is no second spelling
//! to diverge. `client_identity_offered` is asserted directly (both compute `is_some()`).

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::sync::Arc;

use crate::a2a::fetch::{FetchPolicy, Transport};
use crate::a2a::relay::{ChunkFlow, RelayTransport};
use crate::a2a::transport::ReqwestTransport;
use busbar_substrate::egress::seam::{HopSpec, HostlessEgress};
use busbar_substrate::egress::{build_pinned_client, RefuseSecondLookup};
use busbar_substrate::proxy::{read_capped, ReadEnd};

/// The installed hostless-egress driver — the engine's, bound by the transport's own test boot
/// (`test_egress_boot`, the same binding the composition root makes) and read back through the ONE
/// neutral seam the plane's production transport reads. Each verb on it runs the engine's
/// buffered / streaming egress bodies whole over one hostless scope.
fn driver() -> &'static dyn HostlessEgress {
    super::test_egress_boot::install();
    busbar_substrate::egress::seam::hostless().expect("the hostless-egress driver is installed")
}

const LOOPBACK: &str = "127.0.0.1";

/// A loopback HTTP/1.1 server that answers every connection with a fixed status line, headers, and
/// body. Raw TCP so there is no ambient runtime — exactly the shape `egress_tests` runs in.
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

/// A loopback server that PROMISES a large `Content-Length` and then sends a short body and closes —
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
            // Drop the connection with the promise unfulfilled → the client sees a mid-body failure.
        }
    });
    port
}

/// Run one direct pinned hop (the exact `build_pinned_client` codec the planes use) and `read_capped`
/// its body — the independent oracle the seam is compared against.
fn direct_read(
    url: &str,
    addr: IpAddr,
    port: u16,
    cap: usize,
) -> (u16, Option<String>, Vec<u8>, ReadEnd) {
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
        (status, location, bytes.to_vec(), end)
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

/// THE CORE EQUALITY: the neutral buffered adapter and the A2A transport's own `get` agree field for
/// field against the same fixture — status, location, body, peer_spki, client_identity_offered.
#[test]
fn buffered_adapter_matches_the_a2a_transport_get_byte_for_byte() {
    let body = b"the agent card bytes, exactly".to_vec();
    let port = spawn_mock(
        "200 OK",
        &[("content-type", "application/json")],
        body.clone(),
    );
    let url = format!("http://127.0.0.1:{port}/.well-known/agent-card.json");
    let addr: IpAddr = LOOPBACK.parse().unwrap();

    // The A2A transport's own buffered hop (pins to addr, reqwest codec, read_capped inside).
    let policy = FetchPolicy::default();
    let transport = ReqwestTransport::new(&policy);
    let direct = transport
        .get(&url::Url::parse(&url).unwrap(), addr)
        .expect("direct get");

    // The neutral adapter over the host egress seam.
    let cap = policy.max_body_bytes.saturating_add(1);
    let seamed = driver().buffered(&hop(&url), cap).expect("seam buffered");

    assert_eq!(seamed.status, direct.status, "status matches");
    assert_eq!(seamed.location, direct.location, "location matches");
    assert_eq!(seamed.body, direct.body, "body is byte-identical");
    assert_eq!(
        seamed.peer_spki, direct.peer_spki,
        "peer_spki matches (None == None on plaintext)"
    );
    assert_eq!(
        seamed.client_identity_offered, direct.client_identity_offered,
        "client_identity_offered matches (both false: no identity)"
    );
    assert_eq!(
        seamed.end,
        ReadEnd::Complete,
        "a body under the cap reads Complete"
    );
}

/// THE REDIRECT HEAD: a 302 with a `Location` is surfaced (never followed) with the location verbatim,
/// exactly as the transport's own read does — the redirect loop stays plane-side and consumes this.
#[test]
fn buffered_adapter_surfaces_a_redirect_location_like_the_transport() {
    let port = spawn_mock(
        "302 Found",
        &[("location", "https://elsewhere.example/card")],
        Vec::new(),
    );
    let url = format!("http://127.0.0.1:{port}/");
    let addr: IpAddr = LOOPBACK.parse().unwrap();

    let policy = FetchPolicy::default();
    let transport = ReqwestTransport::new(&policy);
    let direct = transport
        .get(&url::Url::parse(&url).unwrap(), addr)
        .expect("direct get");

    let cap = policy.max_body_bytes.saturating_add(1);
    let seamed = driver().buffered(&hop(&url), cap).unwrap();

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

/// ALL THREE `ReadEnd` STATES reproduce `read_capped` exactly — the MCP dispatch reads this to keep a
/// truncated / failed body from being parsed as a clean one.
#[test]
fn capped_read_reproduces_all_three_readend_states() {
    let addr: IpAddr = LOOPBACK.parse().unwrap();

    // (1) COMPLETE: a body under the cap.
    {
        let body = b"small complete body".to_vec();
        let port = spawn_mock("200 OK", &[], body.clone());
        let url = format!("http://127.0.0.1:{port}/");
        let cap = 4096usize;
        let (_s, _l, dbytes, dend) = direct_read(&url, addr, port, cap);
        // A second, independent hop for the seam (the mock answers each connection freshly).
        let port2 = spawn_mock("200 OK", &[], body.clone());
        let url2 = format!("http://127.0.0.1:{port2}/");
        let seamed = driver().buffered(&hop(&url2), cap).unwrap();
        assert_eq!(dend, ReadEnd::Complete);
        assert_eq!(seamed.end, ReadEnd::Complete, "under-cap body is Complete");
        assert_eq!(seamed.body, dbytes, "Complete body byte-identical");
        assert_eq!(seamed.body, body);
    }

    // (2) TRUNCATED: a body that overruns the cap.
    {
        let body = vec![b'x'; 10_000];
        let cap = 100usize;
        let port = spawn_mock("200 OK", &[], body.clone());
        let url = format!("http://127.0.0.1:{port}/");
        let (_s, _l, dbytes, dend) = direct_read(&url, addr, port, cap);
        let port2 = spawn_mock("200 OK", &[], body.clone());
        let url2 = format!("http://127.0.0.1:{port2}/");
        let seamed = driver().buffered(&hop(&url2), cap).unwrap();
        assert_eq!(dend, ReadEnd::Truncated);
        assert_eq!(seamed.end, ReadEnd::Truncated, "over-cap body is Truncated");
        assert_eq!(
            seamed.body.len(),
            cap,
            "Truncated body holds exactly cap bytes"
        );
        assert_eq!(seamed.body, dbytes, "Truncated prefix byte-identical");
    }

    // (3) TRANSPORT ERROR: a body that fails mid-transfer.
    {
        let cap = 4096usize;
        let port = spawn_truncating_mock(b"partial", 1000);
        let url = format!("http://127.0.0.1:{port}/");
        let (_s, _l, _db, dend) = direct_read(&url, addr, port, cap);
        let port2 = spawn_truncating_mock(b"partial", 1000);
        let url2 = format!("http://127.0.0.1:{port2}/");
        let seamed = driver().buffered(&hop(&url2), cap).unwrap();
        assert_eq!(dend, ReadEnd::TransportError);
        assert_eq!(
            seamed.end,
            ReadEnd::TransportError,
            "a mid-body failure is TransportError"
        );
    }
}

/// THE STREAM RELAY: the neutral stream adapter and the A2A transport's own `post_stream` deliver a
/// byte-identical CONCATENATED body for an event-stream reply, and agree on the head. Per the adapter's
/// documented nuance the per-chunk boundaries may differ; the concatenation may not.
#[test]
fn stream_adapter_concatenation_matches_post_stream() {
    let sse = b"event: message\ndata: {\"one\":1}\n\ndata: {\"two\":2}\n\n".to_vec();
    let addr: IpAddr = LOOPBACK.parse().unwrap();

    // The A2A transport's own streaming relay, collecting the concatenated sink bytes.
    let port = spawn_mock(
        "200 OK",
        &[("content-type", "text/event-stream")],
        sse.clone(),
    );
    let url = format!("http://127.0.0.1:{port}/rpc");
    let policy = FetchPolicy::default();
    let transport = ReqwestTransport::new(&policy);
    let mut direct_body = Vec::new();
    let mut sink = |chunk: &[u8]| -> ChunkFlow {
        direct_body.extend_from_slice(chunk);
        ChunkFlow::Continue
    };
    let direct_head = transport
        .post_stream(&url::Url::parse(&url).unwrap(), addr, &[], b"{}", &mut sink)
        .expect("direct post_stream");

    // The neutral stream adapter.
    let cap = policy.max_body_bytes.saturating_add(1);
    let port2 = spawn_mock(
        "200 OK",
        &[("content-type", "text/event-stream")],
        sse.clone(),
    );
    let url2 = format!("http://127.0.0.1:{port2}/rpc");
    // The driver reads the head and, for an event-stream reply, pumps every chunk into the sink over
    // the same scope; a non-stream reply comes back as its head alone with nothing pumped.
    let mut seam_body = Vec::new();
    let seam_head = {
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
        let mut on = |chunk: &[u8]| -> ChunkFlow {
            seam_body.extend_from_slice(chunk);
            ChunkFlow::Continue
        };
        driver()
            .stream(&spec, cap, &mut on)
            .expect("seam stream_head")
    };

    assert_eq!(
        seam_head.status, direct_head.status,
        "stream head status matches"
    );
    assert_eq!(
        seam_head.content_type, direct_head.content_type,
        "content-type matches (lower-cased)"
    );
    assert_eq!(
        seam_body, direct_body,
        "the concatenated event-stream body is byte-identical"
    );
    assert_eq!(seam_body, sse, "and equals what the upstream sent");
}

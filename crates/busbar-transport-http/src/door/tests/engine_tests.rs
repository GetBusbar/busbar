// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The engine against hand-written far ends: what 1.5.5's client (reqwest 0.12) did with a
//! response's trailers and with its one request timeout.

use super::*;

const SEC: u64 = 1_000_000_000;

fn posture(timeout_secs: u64) -> Posture {
    Posture {
        keep_alive_interval: Some(Duration::from_secs(30)),
        keep_alive_timeout: Duration::from_secs(10),
        adaptive_window: true,
        request_timeout: Duration::from_secs(timeout_secs),
        max_body_bytes: 32 * 1024 * 1024,
    }
}

/// A framing with one GET sent on stream 1, the far end not yet heard from.
fn asked(proto: Proto, timeout_secs: u64) -> Framing {
    let mut f = Framing::dial("http://127.0.0.1:9", proto, posture(timeout_secs), 0).expect("dial");
    // `begin` drives the handshake in its own op, before any request exists (as the door does).
    f.drive(0, 0);
    f.emit(1, b"GET /x HTTP/1.1\r\n\r\n", 0, 0).expect("emit");
    f.drive(0, 0);
    let sent = f.take_wire(usize::MAX);
    assert!(!sent.is_empty(), "the request went out");
    f
}

/// Every body byte handed up on stream 1 (the head piece and failure pieces excluded), and whether
/// the stream ended whole.
fn body(f: &mut Framing) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut whole = false;
    for p in f.pieces().drain(..) {
        if p.stream != 1 || p.status.is_some() || p.failed {
            continue;
        }
        if p.bytes.is_empty() {
            whole = true;
        }
        out.extend_from_slice(&p.bytes);
    }
    (out, whole)
}

fn failed(f: &mut Framing) -> bool {
    f.failure().is_some() || f.pieces().iter().any(|p| p.failed)
}

/// One HTTP/2 frame.
fn h2(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut v = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, ty, flags];
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// A literal header field, new name, without indexing, no Huffman.
fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0x00, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v.push(value.len() as u8);
    v.extend_from_slice(value.as_bytes());
    v
}

/// 1.5.5 read a response body through reqwest, which yields data frames only: a chunked
/// response's trailer section never reached the body.
#[test]
fn an_h1_trailer_section_is_not_body() {
    let mut f = asked(Proto::H1, 300);
    f.ingest(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: x-t\r\n\r\n\
          5\r\nhello\r\n0\r\nx-t: 1\r\n\r\n",
        false,
    );
    f.drive(SEC, 0);
    let (b, whole) = body(&mut f);
    assert_eq!(
        String::from_utf8_lossy(&b),
        "hello",
        "the body is the payload only"
    );
    assert!(whole, "the response ended whole");
}

/// The same on HTTP/2: a trailing HEADERS frame is not body.
#[test]
fn an_h2_trailer_block_is_not_body() {
    let mut f = asked(Proto::H2, 300);
    let mut far = h2(4, 0, 0, &[]);
    far.extend(h2(1, 0x4, 1, &[0x88]));
    far.extend(h2(0, 0, 1, b"hello"));
    far.extend(h2(1, 0x4 | 0x1, 1, &literal("grpc-status", "0")));
    f.ingest(&far, false);
    f.drive(SEC, 0);
    let (b, whole) = body(&mut f);
    assert_eq!(
        String::from_utf8_lossy(&b),
        "hello",
        "the body is the payload only"
    );
    assert!(whole, "the response ended whole");
}

/// 1.5.5's `upstream_request_timeout_secs` was reqwest's TOTAL timeout: one clock from the send
/// to the body's end (reqwest 0.12 wraps the response body in the same sleep). A response still
/// streaming at the deadline is cut there, on HTTP/1.1 ...
#[test]
fn a_body_still_arriving_at_the_request_timeout_is_cut_h1() {
    let mut f = asked(Proto::H1, 5);
    f.ingest(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n",
        false,
    );
    f.drive(SEC, 0);
    assert_eq!(body(&mut f).0, b"hello");
    assert_eq!(
        f.next_deadline(),
        Some(5 * SEC),
        "the body wait is bounded by the one request clock"
    );
    f.drive(5 * SEC - 1, 0);
    assert!(!failed(&mut f), "not before the deadline");
    f.drive(5 * SEC, 0);
    assert!(failed(&mut f), "cut at the request timeout");
}

/// ... and on HTTP/2, where it ends that stream alone.
#[test]
fn a_body_still_arriving_at_the_request_timeout_is_cut_h2() {
    let mut f = asked(Proto::H2, 5);
    let mut far = h2(4, 0, 0, &[]);
    far.extend(h2(1, 0x4, 1, &[0x88]));
    far.extend(h2(0, 0, 1, b"hello"));
    f.ingest(&far, false);
    f.drive(SEC, 0);
    assert_eq!(body(&mut f).0, b"hello");
    f.drive(5 * SEC - 1, 0);
    assert!(!failed(&mut f), "not before the deadline");
    f.drive(5 * SEC, 0);
    assert!(
        f.pieces().iter().any(|p| p.stream == 1 && p.failed),
        "the stream is cut at the request timeout"
    );
}

/// 1.5.5 put no transport cap on a RESPONSE: a streamed body ran as long as the far end sent it
/// (the plane's own buffered reads were capped, the streaming path was not). One larger than
/// `limits.request_body_max_bytes` (32 MiB) passes through whole.
#[test]
fn a_streamed_response_past_the_request_body_cap_passes_through() {
    let mut f = asked(Proto::H1, 300);
    f.ingest(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n",
        false,
    );
    f.drive(SEC, 0);
    let chunk = vec![b'x'; 1024 * 1024];
    let mut seen = 0usize;
    for _ in 0..33 {
        let mut wire = format!("{:x}\r\n", chunk.len()).into_bytes();
        wire.extend_from_slice(&chunk);
        wire.extend_from_slice(b"\r\n");
        f.ingest(&wire, false);
        f.drive(SEC, 0);
        assert!(!failed(&mut f), "cut after {seen} bytes");
        seen += body(&mut f).0.len();
    }
    f.ingest(b"0\r\n\r\n", false);
    f.drive(SEC, 0);
    let (rest, whole) = body(&mut f);
    seen += rest.len();
    assert_eq!(seen, 33 * 1024 * 1024);
    assert!(whole);
}

/// The clock is the ATTEMPT's, stamped before the dial: a connect that took 200s leaves the
/// exchange 100s of a 300s timeout, so a body still streaming at 300s from the attempt's start is
/// cut there, not 300s after the request went out.
#[test]
fn a_slow_connect_and_a_slow_body_share_one_attempt_clock() {
    let connected = 200 * SEC;
    let mut f =
        Framing::dial("http://127.0.0.1:9", Proto::H1, posture(300), connected).expect("dial");
    f.drive(connected, 0);
    f.emit(1, b"GET /x HTTP/1.1\r\n\r\n", connected, 300 * SEC)
        .expect("emit");
    f.drive(connected, 0);
    assert!(!f.take_wire(usize::MAX).is_empty(), "the request went out");
    f.ingest(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n",
        false,
    );
    f.drive(connected + SEC, 0);
    assert_eq!(body(&mut f).0, b"hello");
    f.drive(300 * SEC - 1, 0);
    assert!(!failed(&mut f), "not before the attempt's deadline");
    f.drive(300 * SEC, 0);
    assert!(
        failed(&mut f),
        "cut at 300s from the attempt's start, not from the send"
    );
}

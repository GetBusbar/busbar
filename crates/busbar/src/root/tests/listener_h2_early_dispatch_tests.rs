// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A MALFORMED HTTP/2 REQUEST IS REFUSED, NOT ANSWERED (RFC 9113 8.1, 8.1.2.6; h2spec
//! `http2/8.1/1`, `http2/8.1.2.6/2`).
//!
//! hyper dispatches a request at its HEADERS frame. A handler that answers at once completes the
//! stream, h2 resets it (RST_STREAM NO_ERROR) and the frames that arrive afterwards are ignored, so
//! a request that turned out malformed in its LATER frames got a normal response where the RFC wants
//! the stream error PROTOCOL_ERROR. The delay between the frames below is what makes the failure
//! certain rather than a race. The serve loop now holds a request whose method carries no body
//! (GET, HEAD, OPTIONS, TRACE) until its stream is complete.
//!
//! NOT COVERED HERE, and not fixable here: h2spec `http2/8.1.2.1/3` (a pseudo-header field in
//! trailers, RFC 9113 8.1). h2 0.4.18 (and 0.4.20, the latest) drops the trailers' pseudo-header
//! fields without a check (`proto/streams/recv.rs` `recv_trailers`: `frame.into_fields()`), so the
//! request arrives as well-formed and nothing above h2 can see the violation.
//!
//! Each test drives the real plain listener (`serve_plain`, the same hardened builder and service
//! as the TLS one) over h2c with prior knowledge, with the frames written by hand.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const GOAWAY: u8 = 0x7;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PROTOCOL_ERROR: u32 = 1;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut v = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, kind, flags];
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// `GET http://localhost/` as an HPACK block (static table: :method GET, :scheme http, :path /,
/// then :authority localhost as a literal), with `extra` header bytes appended.
fn request_block(extra: &[u8]) -> Vec<u8> {
    request_block_at(&[0x84], extra)
}

/// The same with `path` as the HPACK bytes of the :path field (`[0x84]` is `/`).
fn request_block_at(path: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut b = vec![0x82, 0x86];
    b.extend_from_slice(path);
    b.extend_from_slice(&[0x01, 9]);
    b.extend_from_slice(b"localhost");
    b.extend_from_slice(extra);
    b
}

/// One decoded frame: (type, flags, stream, payload).
type Frame = (u8, u8, u32, Vec<u8>);

fn parse(mut acc: &[u8]) -> Vec<Frame> {
    let mut out = Vec::new();
    while acc.len() >= 9 {
        let len = ((acc[0] as usize) << 16) | ((acc[1] as usize) << 8) | acc[2] as usize;
        if acc.len() < 9 + len {
            break;
        }
        let sid = u32::from_be_bytes([acc[5], acc[6], acc[7], acc[8]]) & 0x7fff_ffff;
        out.push((acc[3], acc[4], sid, acc[9..9 + len].to_vec()));
        acc = &acc[9 + len..];
    }
    out
}

/// The router: `/` counts its dispatches and answers at once, never touching the request body (as
/// `/healthz` does); `/len` reads the whole body and answers with its length.
async fn listener() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let dispatched = Arc::new(AtomicUsize::new(0));
    let seen = dispatched.clone();
    let router = Router::new()
        .route(
            "/",
            get(move || {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    "ok"
                }
            }),
        )
        .route(
            "/len",
            get(|body: bytes::Bytes| async move { format!("body={}", body.len()) }),
        );
    let socket = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        super::serve_plain(socket, router, std::future::pending(), None)
            .await
            .expect("serve");
    });
    (addr, dispatched)
}

/// Send the connection preface, an empty SETTINGS, then each `(delay, bytes)` step; return every
/// frame the server wrote within `listen`.
async fn exchange(addr: std::net::SocketAddr, steps: &[(u64, Vec<u8>)]) -> Vec<Frame> {
    let mut c = TcpStream::connect(addr).await.expect("connect");
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    hello.extend(frame(4, 0, 0, &[]));
    c.write_all(&hello).await.expect("preface");
    for (delay, bytes) in steps {
        tokio::time::sleep(Duration::from_millis(*delay)).await;
        c.write_all(bytes).await.expect("write");
    }
    let mut acc = Vec::new();
    let mut buf = vec![0u8; 4096];
    let end = tokio::time::Instant::now() + Duration::from_millis(800);
    while let Ok(Ok(n)) = tokio::time::timeout_at(end, c.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
    }
    parse(&acc)
}

fn has(frames: &[Frame], kind: u8) -> bool {
    frames.iter().any(|f| f.0 == kind && f.2 == 1)
}

/// The stream is ended with PROTOCOL_ERROR (RST_STREAM on it, or GOAWAY), and nothing was answered.
fn assert_refused(frames: &[Frame], dispatched: &AtomicUsize, what: &str) {
    let refused = frames.iter().any(|f| {
        (f.0 == RST_STREAM && f.2 == 1 && f.3[..4] == PROTOCOL_ERROR.to_be_bytes())
            || (f.0 == GOAWAY && f.3[4..8] == PROTOCOL_ERROR.to_be_bytes())
    });
    assert!(refused, "{what}: want PROTOCOL_ERROR, got {frames:?}");
    assert!(
        !has(frames, DATA),
        "{what}: a response body was sent: {frames:?}"
    );
    assert_eq!(
        dispatched.load(Ordering::SeqCst),
        0,
        "{what}: the handler ran"
    );
}

#[tokio::test]
async fn a_second_headers_frame_without_end_stream_is_a_stream_error_not_a_response() {
    let (addr, dispatched) = listener().await;
    let frames = exchange(
        addr,
        &[
            (0, frame(HEADERS, END_HEADERS, 1, &request_block(&[]))),
            // the second HEADERS block: no END_STREAM, so not valid trailers (RFC 9113 8.1)
            (
                150,
                frame(HEADERS, END_HEADERS, 1, &[0x00, 1, b'x', 1, b'y']),
            ),
        ],
    )
    .await;
    assert_refused(&frames, &dispatched, "8.1");
}

#[tokio::test]
async fn data_that_does_not_add_up_to_content_length_is_a_stream_error_not_a_response() {
    let (addr, dispatched) = listener().await;
    // `content-length: 5` (static index 28, literal without indexing), then 2 + 2 body bytes.
    let frames = exchange(
        addr,
        &[
            (
                0,
                frame(
                    HEADERS,
                    END_HEADERS,
                    1,
                    &request_block(&[0x0f, 0x0d, 1, b'5']),
                ),
            ),
            (100, frame(DATA, 0, 1, b"ab")),
            (100, frame(DATA, END_STREAM, 1, b"cd")),
        ],
    )
    .await;
    assert_refused(&frames, &dispatched, "8.1.2.6");
}

#[tokio::test]
async fn a_well_formed_get_is_dispatched_at_its_headers_frame() {
    let (addr, dispatched) = listener().await;
    let frames = exchange(
        addr,
        &[(
            0,
            frame(HEADERS, END_HEADERS | END_STREAM, 1, &request_block(&[])),
        )],
    )
    .await;
    assert!(has(&frames, HEADERS) && has(&frames, DATA), "{frames:?}");
    assert_eq!(dispatched.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_well_formed_get_that_carries_a_body_is_dispatched_once_complete_and_sees_it() {
    let (addr, _) = listener().await;
    // `/len` as a literal :path (static name index 4), so the body is the handler's to read.
    let path = [&[0x04u8, 4][..], b"/len"].concat();
    let frames = exchange(
        addr,
        &[
            (
                0,
                frame(HEADERS, END_HEADERS, 1, &request_block_at(&path, &[])),
            ),
            (100, frame(DATA, 0, 1, b"abc")),
            (100, frame(DATA, END_STREAM, 1, b"de")),
        ],
    )
    .await;
    let body: Vec<u8> = frames
        .iter()
        .filter(|f| f.0 == DATA && f.2 == 1)
        .flat_map(|f| f.3.clone())
        .collect();
    assert_eq!(body, b"body=5", "{frames:?}");
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOWNSTREAM REPLY BUFFER (TRANSPORT-TLS T7b): one contiguous run per write, nothing the
//! peer took left readable, and a buffer that cannot grow fails the connection without writing a
//! partial reply.

use std::task::Context;

use busbar_core_connector::secure_vec::{refuse_growth, SecureVec};
use tokio::io::AsyncReadExt;

use super::{absorb_wire, write_some, OUT_KEEP};

const SENTINEL: &[u8] = b"set-cookie: session=SENTINEL-T7B-0123456789";

fn reply() -> Vec<u8> {
    let mut r = b"HTTP/1.1 200 OK\r\n".to_vec();
    r.extend_from_slice(SENTINEL);
    r.extend_from_slice(b"\r\ncontent-length: 2\r\n\r\nok");
    r
}

/// Write everything queued into `w`, counting the writes.
fn drain_into(out: &mut SecureVec, failed: &mut bool, w: &mut tokio::io::DuplexStream) -> usize {
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut writes = 0;
    while !out.is_empty() {
        match write_some(out, failed, std::pin::Pin::new(&mut *w), &mut cx) {
            std::task::Poll::Ready(true) => writes += 1,
            other => panic!("the peer has room: {other:?}"),
        }
    }
    writes
}

#[tokio::test]
async fn out_holds_no_token_after_flush_downstream() {
    let (mut near, mut far) = tokio::io::duplex(1 << 20);
    let mut out = SecureVec::new();
    let mut failed = false;
    absorb_wire(&mut out, &mut failed, &reply());
    drain_into(&mut out, &mut failed, &mut near);
    assert!(!failed);
    let mut got = vec![0_u8; reply().len()];
    far.read_exact(&mut got).await.unwrap();
    assert_eq!(got, reply(), "the reply reaches the peer byte-exact");
    assert!(
        !out.allocation()
            .windows(SENTINEL.len())
            .any(|w| w == SENTINEL),
        "the written reply is wiped from the buffer"
    );
}

#[tokio::test]
async fn downstream_out_wraps_single_write() {
    let (mut near, _far) = tokio::io::duplex(1 << 20);
    let mut out = SecureVec::new();
    let mut failed = false;
    absorb_wire(&mut out, &mut failed, &[1_u8; 3000]);
    // The peer took the first 2000 bytes; the next reply does not fit after the end.
    out.consume(2000);
    absorb_wire(&mut out, &mut failed, &[2_u8; 2500]);
    assert_eq!(out.len(), 3500);
    assert_eq!(
        drain_into(&mut out, &mut failed, &mut near),
        1,
        "one contiguous run, one write"
    );
}

/// RED against the rejected form, which drops a reply it cannot buffer and carries on.
#[tokio::test]
async fn downstream_out_overflow_fails_connection() {
    let mut out = SecureVec::new();
    let mut failed = false;
    absorb_wire(&mut out, &mut failed, b"HTTP/1.1 200 OK\r\n");
    refuse_growth(true);
    absorb_wire(&mut out, &mut failed, &[7_u8; 64 * 1024]);
    refuse_growth(false);
    assert!(
        failed,
        "a reply that cannot be buffered fails the connection"
    );
    assert!(out.is_empty(), "no partial reply is left to write");
    absorb_wire(&mut out, &mut failed, b"later");
    assert!(out.is_empty(), "nothing is queued after the failure");
}

#[tokio::test]
async fn downstream_out_shrinks_after_burst() {
    let (mut near, mut far) = tokio::io::duplex(8 << 20);
    let mut out = SecureVec::new();
    let mut failed = false;
    absorb_wire(&mut out, &mut failed, &vec![3_u8; 200 * 1024]);
    assert!(out.capacity() > OUT_KEEP);
    drain_into(&mut out, &mut failed, &mut near);
    assert!(out.capacity() <= OUT_KEEP);
    let mut got = vec![0_u8; 200 * 1024];
    far.read_exact(&mut got).await.unwrap();
}

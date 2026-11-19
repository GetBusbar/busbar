// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A `MemIo` conn releases everything it allocated when its last handle is dropped, and the far
//! end's bytes it held are wiped before they are released. Counted with the allocation watch on
//! this thread only: what the scope allocated and did not free is what a dropped conn leaves held.
#![cfg(feature = "memio")]
#![forbid(unsafe_code)]

use std::future::poll_fn;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::time::Duration;

use busbar_ffi::test_watch::{Freed, Watch};
use busbar_plugin_abi::memio::{MemIo, MemStream, Ran};
use busbar_plugin_abi::records::Fixed;
use hyper::rt::{Read, ReadBuf};

#[global_allocator]
static WATCH: Watch = Watch::new();

const MINUTE: u64 = 60_000_000_000;
const GET: &[u8] = b"GET / HTTP/1.1\r\nhost: peer.test\r\n\r\n";
/// Bytes the far end sent; the watch reports any freed block that still holds them.
const CANARY: &[u8; 32] = b"far-end-request-bytes-0123456789";

/// Bytes the scope allocated and did not free, and the blocks they are in.
fn held(freed: &Freed) -> (usize, usize) {
    (
        freed.alloc_bytes.saturating_sub(freed.bytes),
        freed.allocs.saturating_sub(freed.count),
    )
}

/// An HTTP/1.1 server conn over `m` with hyper's thirty-second header-read timeout.
fn http1_server(m: &mut MemIo) {
    let io = m.io();
    let timer = m.timer();
    m.spawn(async move {
        let mut b = hyper::server::conn::http1::Builder::new();
        b.timer(timer).header_read_timeout(Duration::from_secs(30));
        let service =
            hyper::service::service_fn(|_: hyper::Request<hyper::body::Incoming>| async {
                Ok::<_, std::convert::Infallible>(hyper::Response::new(String::from("ok")))
            });
        let _ = b.serve_connection(io, service).await;
    });
}

/// The `200` status lines in what `flush` wrote.
fn served(m: &mut MemIo) -> usize {
    let mut room = [0u8; 4096];
    let mut out = Fixed::new(&mut room);
    m.flush(&mut out).unwrap();
    let n = out.len();
    room[..n]
        .windows(12)
        .filter(|w| *w == b"HTTP/1.1 200")
        .count()
}

/// One request served on a kept-alive conn, which then waits for the next one.
fn served_once() -> MemIo {
    let mut m = MemIo::new();
    http1_server(&mut m);
    m.run(MINUTE, 256);
    m.feed(GET);
    m.run(MINUTE + 1_000, 256);
    assert_eq!(served(&mut m), 1, "the request was not served");
    m
}

/// A task that reads 8 bytes at a time until EOF, so it never holds more than 8 of them.
fn reader(m: &mut MemIo) {
    let mut io: MemStream = m.io();
    m.spawn(async move {
        let mut raw = [MaybeUninit::<u8>::uninit(); 8];
        loop {
            let mut rb = ReadBuf::uninit(&mut raw);
            let _ = poll_fn(|cx| Pin::new(&mut io).poll_read(cx, rb.unfilled())).await;
            if rb.filled().is_empty() {
                return;
            }
        }
    });
}

#[test]
fn a_conn_dropped_between_requests_holds_no_bytes() {
    // hyper's one-time per-thread state is made outside the counted scope.
    drop(served_once());
    let freed = WATCH.armed_here(b"", || drop(served_once()));
    eprintln!("MEMIO-HELD dropped-idle {:?}", held(&freed));
    assert_eq!(
        held(&freed),
        (0, 0),
        "a served conn dropped while it waits for its next request left bytes held"
    );
}

#[test]
fn a_conn_closed_by_eof_holds_no_bytes() {
    drop(served_once());
    let freed = WATCH.armed_here(b"", || {
        let mut m = served_once();
        m.feed(&[]);
        assert_eq!(m.run(MINUTE + 2_000, 256), Ran::Closed);
        drop(m);
    });
    eprintln!("MEMIO-HELD closed-eof {:?}", held(&freed));
    assert_eq!(held(&freed), (0, 0), "a conn closed by EOF left bytes held");
}

#[test]
fn an_attributed_conn_dropped_with_parked_wakers_holds_no_bytes() {
    let freed = WATCH.armed_here(b"", || {
        let mut m = MemIo::new();
        let plan = m.attributed_output(64, 1024, 64 * 1024);
        plan.admit(1, u64::MAX).unwrap();
        let gate = plan.clone();
        m.spawn(async move {
            let _ = poll_fn(|cx| gate.poll_release(1, cx)).await;
        });
        reader(&mut m);
        assert_eq!(m.run(0, 256), Ran::Idle);
        drop(plan);
        drop(m);
    });
    eprintln!("MEMIO-HELD attributed {:?}", held(&freed));
    assert_eq!(
        held(&freed),
        (0, 0),
        "an attributed conn and its plan were left held after the conn was dropped"
    );
}

#[test]
fn the_far_ends_bytes_are_wiped_before_the_conn_releases_them() {
    let freed = WATCH.armed_here(CANARY, || {
        let mut m = MemIo::new();
        reader(&mut m);
        m.run(0, 256);
        // Read through the pipe, 8 bytes at a time.
        m.feed(CANARY);
        m.run(1, 256);
        // Still in the pipe, unread, when the conn ends.
        m.feed(CANARY);
        drop(m);
    });
    eprintln!(
        "MEMIO-HELD wipe {:?} canary_blocks {}",
        held(&freed),
        freed.blocks_containing_canary
    );
    assert_eq!(
        held(&freed),
        (0, 0),
        "the conn's buffers were never released"
    );
    assert_eq!(
        freed.blocks_containing_canary, 0,
        "a buffer still held the far end's bytes when it was freed"
    );
}

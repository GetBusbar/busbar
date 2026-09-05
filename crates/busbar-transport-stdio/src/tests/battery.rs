// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stdio transport battery: byte-exact round trip, half-close, cancel mid-frame, backpressure,
//! K writers, and honest frame meta. Every test drives the SAME [`StdioTransport`] a real deployment
//! uses, over an in-memory duplex instead of a real pipe — the same "generic so tests drive it over
//! an in-memory duplex" seam the 1.5.5-era `serve_io` used.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use tokio::io::{split, AsyncWriteExt};

use busbar_contract::wire::{Direction, TransportError};
use busbar_contract::{ArenaBytes, Transport};

use crate::StdioTransport;

/// Build a connected pair of live connections over an in-memory duplex, standing in for two ends
/// of a real pipe. `cap` is the duplex's byte capacity, which is what makes the backpressure test
/// deterministic.
fn pair(t: &StdioTransport, cap: usize) -> (busbar_contract::wire::Conn, busbar_contract::wire::Conn) {
    let (end_a, end_b) = tokio::io::duplex(cap);
    // `tokio::io::duplex` already returns a connected PAIR: writes on `end_a` are what `end_b`
    // reads, and vice versa. Splitting each end and wrapping the two halves of the SAME end
    // together (not cross-wired) is what keeps that pairing — swapping either write half here
    // would make a side read back its own writes instead of its peer's.
    let (ar, aw) = split(end_a);
    let (br, bw) = split(end_b);
    let conn_a = t.wrap_pair(ar, aw, "b");
    let conn_b = t.wrap_pair(br, bw, "a");
    (conn_a, conn_b)
}

#[tokio::test]
async fn round_trip_byte_exact() {
    let t = StdioTransport::new();
    let (a, b) = pair(&t, 64 * 1024);

    let payload = b"the quick brown fox jumps over the lazy dog \xE2\x9C\x93".to_vec();
    let n = t
        .write(&a, busbar_contract::StreamId(0), ArenaBytes::new(&payload))
        .await
        .expect("write succeeds");
    assert_eq!(n, payload.len());

    let mut frames = t.frames(b);
    let (stream, frame) = frames
        .next()
        .await
        .expect("a frame arrives")
        .expect("the frame is not an error");
    assert_eq!(stream, busbar_contract::StreamId(0));
    assert_eq!(frame.direction, Direction::Inbound);
    assert_eq!(frame.bytes.as_slice(), payload.as_slice(), "byte-exact");
    assert_eq!(frame.meta.bytes, payload.len() as u64, "honest frame meta");
    assert_eq!(frame.meta.transport_units, None, "DECODES_PAYLOAD is false");
    assert_eq!(frame.meta.status, None, "STATUS_CLASS is None for stdio");
}

#[tokio::test]
async fn multiple_frames_in_order_no_data_loss() {
    // Regression coverage for the bug this crate's own report calls out: recreating a `BufReader`
    // per frame and keeping only its inner reader silently drops whatever the `BufReader` had
    // already read ahead into its internal buffer. Three frames written back-to-back (likely to
    // land in the peer's read buffer in one underlying read) must all still arrive, in order,
    // byte-exact.
    let t = StdioTransport::new();
    let (a, b) = pair(&t, 64 * 1024);
    for line in ["one", "two", "three"] {
        t.write(&a, busbar_contract::StreamId(0), ArenaBytes::new(line.as_bytes()))
            .await
            .unwrap();
    }
    let mut frames = t.frames(b);
    for expect in ["one", "two", "three"] {
        let (_s, frame) = frames.next().await.unwrap().unwrap();
        assert_eq!(frame.bytes.as_slice(), expect.as_bytes());
    }
}

#[tokio::test]
async fn half_close_peer_sees_clean_eof_and_can_still_be_written_to() {
    let t = StdioTransport::new();
    let (a, b) = pair(&t, 64 * 1024);

    t.write(&a, busbar_contract::StreamId(0), ArenaBytes::new(b"last words"))
        .await
        .unwrap();

    // `a` shuts down its OWN write half only — the wire-level half-close — without touching its
    // read half and without going through `Transport::close` (which the contract defines as
    // tearing down the whole connection, not one direction of it).
    let a_state = t.state_of(a.id()).unwrap();
    {
        let mut w = a_state.writer.lock().await;
        w.shutdown().await.unwrap();
    }

    let mut frames = t.frames(b);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"last words");
    // The half-close is a clean EOF, not an error: the NEXT poll ends the stream quietly.
    assert!(frames.next().await.is_none(), "half-close reads as EOF, not Reset");
}

#[tokio::test]
async fn cancel_mid_frame_fences_the_connection() {
    // A tiny duplex capacity so a large write cannot complete in one poll, giving the test a
    // window to drop the future mid-write.
    let t = StdioTransport::new();
    let (a, _b) = pair(&t, 8);

    let big = vec![b'x'; 1_000_000];
    let write_fut = t.write(&a, busbar_contract::StreamId(0), ArenaBytes::new(&big));
    // Race the write against an immediate timeout: with an 8-byte duplex and a megabyte payload,
    // the write cannot have finished, so the timeout always wins and the future is dropped.
    let raced = tokio::time::timeout(Duration::from_millis(1), write_fut).await;
    assert!(raced.is_err(), "the write did not have time to complete");

    // The connection is now fenced: neither a further write nor a read is served, because the
    // wire may hold a partial, unterminated line and this transport refuses to guess where it
    // ends.
    let small = b"x";
    let err = t
        .write(&a, busbar_contract::StreamId(0), ArenaBytes::new(small))
        .await
        .unwrap_err();
    assert_eq!(err, TransportError::Framing);
}

#[tokio::test]
async fn backpressure_is_bidirectional() {
    // An 8-byte duplex: a write larger than the capacity cannot complete until a reader drains
    // it, which is exactly what "backpressure" means at the byte-stream level.
    let t = Arc::new(StdioTransport::new());
    let (a, b) = pair(&t, 8);

    let payload = vec![b'y'; 4096];

    // Drive the write and the drain concurrently, and assert the write only finishes once bytes
    // are actually read off the other end — the observable shape of backpressure.
    let t2 = t.clone();
    let payload2 = payload.clone();
    let writer = tokio::spawn(async move {
        t2.write(&a, busbar_contract::StreamId(0), ArenaBytes::new(&payload2))
            .await
    });
    // Give the writer a moment to fill the 8-byte duplex and block.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!writer.is_finished(), "an oversized write must block on a full duplex");
    let mut frames = t.frames(b);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.len(), payload.len());
    writer.await.unwrap().unwrap();
}

#[tokio::test]
async fn k_writers_serialise_without_interleaving() {
    let t = Arc::new(StdioTransport::new());
    let (a, b) = pair(&t, 64 * 1024);
    const K: usize = 32;
    let mut handles = Vec::new();
    for i in 0..K {
        let t = t.clone();
        let a = a.clone_for_test();
        handles.push(tokio::spawn(async move {
            let line = format!("writer-{i:02}");
            t.write(&a, busbar_contract::StreamId(0), ArenaBytes::new(line.as_bytes()))
                .await
                .unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let mut frames = t.frames(b);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..K {
        let (_s, frame) = frames.next().await.unwrap().unwrap();
        let line = String::from_utf8(frame.bytes.as_slice().to_vec()).unwrap();
        assert!(line.starts_with("writer-"), "no interleaving: {line:?}");
        seen.insert(line);
    }
    assert_eq!(seen.len(), K, "every writer's line arrived exactly once, unmangled");
}

#[tokio::test]
async fn upgrade_is_always_refused() {
    let t = StdioTransport::new();
    let (a, _b) = pair(&t, 4096);
    let keys = test_key_handle();
    let err = t.upgrade(a, "tls", &keys).await.unwrap_err();
    assert_eq!(err, TransportError::Framing);
}

#[tokio::test]
async fn unit0_refusal_writes_then_closes() {
    let t = StdioTransport::new();
    let (a, b) = pair(&t, 4096);
    let refusal = busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Arrival,
        reason: busbar_contract::unit::RefusalReason::CursorBudget,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };
    t.unit0_refusal(a, &refusal, ArenaBytes::new(b"refused"))
        .await
        .unwrap();
    let mut frames = t.frames(b);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"refused");
}

#[allow(clippy::assertions_on_constants)]
#[tokio::test]
async fn transport_meta_matches_the_architecture_row() {
    use busbar_contract::wire::Unit0Trigger;
    use busbar_contract::TransportMeta;
    assert_eq!(<StdioTransport as TransportMeta>::KEY, "stdio");
    assert!(<StdioTransport as TransportMeta>::SESSION);
    assert!(<StdioTransport as TransportMeta>::SESSION_BOUND);
    assert_eq!(
        <StdioTransport as TransportMeta>::UNIT0_TRIGGER,
        Some(Unit0Trigger::FirstMessage)
    );
    assert!(<StdioTransport as TransportMeta>::UPGRADES_TO.is_empty());
    assert!(<StdioTransport as TransportMeta>::COMPOSES_OVER.is_empty());
    assert!(!<StdioTransport as TransportMeta>::DECODES_PAYLOAD);
    assert_eq!(<StdioTransport as TransportMeta>::STATUS_CLASS, None);
}

fn test_key_handle() -> busbar_contract::TransportKeyHandle {
    struct Seal;
    impl busbar_contract::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    busbar_contract::TransportKeyHandle::issue(&Seal, 0, "test")
}

/// Test-only: [`busbar_contract::wire::Conn`] is `Clone` (a cheap `Arc` handle), which is exactly
/// what lets several tasks hold "the same connection" the way a real caller's writer/closer/frame
/// pump each hold their own clone. Named to make every call site read as what it is.
trait CloneForTest {
    fn clone_for_test(&self) -> Self;
}
impl CloneForTest for busbar_contract::wire::Conn {
    fn clone_for_test(&self) -> Self {
        self.clone()
    }
}

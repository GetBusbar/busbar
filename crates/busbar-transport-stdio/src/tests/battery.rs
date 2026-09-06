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

use busbar_contract::{ArenaBytes, Transport};
use busbar_contract_transport::wire::Direction;
use busbar_contract_transport::wire::TransportError;

use crate::StdioTransport;

/// Build a connected pair of live connections over an in-memory duplex, standing in for two ends
/// of a real pipe. `cap` is the duplex's byte capacity, which is what makes the backpressure test
/// deterministic.
fn pair(
    t: &StdioTransport,
    cap: usize,
) -> (
    busbar_contract_transport::wire::Conn,
    busbar_contract_transport::wire::Conn,
) {
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
        t.write(
            &a,
            busbar_contract::StreamId(0),
            ArenaBytes::new(line.as_bytes()),
        )
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

    t.write(
        &a,
        busbar_contract::StreamId(0),
        ArenaBytes::new(b"last words"),
    )
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
    assert!(
        frames.next().await.is_none(),
        "half-close reads as EOF, not Reset"
    );
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

    // The read arm of the same cell. A `frames()` future dropped while suspended in `read_line`
    // must leave the connection readable: the reader (and its read-ahead) belongs to the
    // connection, not to the future that was polling it, so the next pump sees the line that
    // arrived rather than a silent end-of-stream indistinguishable from the peer closing.
    let t = StdioTransport::new();
    let (a, b) = pair(&t, 64 * 1024);
    {
        let mut frames = t.frames(b.clone());
        let first = frames.next();
        tokio::pin!(first);
        let raced = tokio::time::timeout(Duration::from_millis(1), first.as_mut()).await;
        assert!(
            raced.is_err(),
            "the read must still be suspended when dropped"
        );
    }
    t.write(
        &a,
        busbar_contract::StreamId(0),
        ArenaBytes::new(b"after the cancel"),
    )
    .await
    .unwrap();
    let mut frames = t.frames(b);
    let (_s, frame) = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("a cancelled read must not lose the reader")
        .expect("the stream must not end")
        .expect("and must not be a fenced error");
    assert_eq!(frame.bytes.as_slice(), b"after the cancel");
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
    assert!(
        !writer.is_finished(),
        "an oversized write must block on a full duplex"
    );
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
            t.write(
                &a,
                busbar_contract::StreamId(0),
                ArenaBytes::new(line.as_bytes()),
            )
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
    assert_eq!(
        seen.len(),
        K,
        "every writer's line arrived exactly once, unmangled"
    );
}

/// stdio composes over nothing, so a handoff offered to it is one neither leg declared. The refusal
/// is a mismatch and not a framing error, because the bytes were never the problem.
#[tokio::test]
async fn a_handoff_onto_stdio_is_a_mismatch() {
    let t = StdioTransport::new();
    let (a, _b) = pair(&t, 4096);
    let keys = test_key_handle();
    let err = t.adopt(&t, a, &keys).await.unwrap_err();
    assert_eq!(err, TransportError::HandoffMismatch);
    assert!(<StdioTransport as busbar_contract::TransportMeta>::COMPOSES_OVER.is_empty());
}

/// The refusal a unit-0 arrival is answered with, for the cells that send one.
fn a_refusal() -> busbar_contract::unit::Refusal<'static> {
    busbar_contract::unit::Refusal {
        step: busbar_contract::unit::Step::Arrival,
        reason: busbar_contract::unit::RefusalReason::CursorBudget,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    }
}

#[tokio::test]
async fn unit0_refusal_writes_then_closes() {
    let t = StdioTransport::new();
    let (a, b) = pair(&t, 4096);
    t.unit0_refusal(a, None, &a_refusal(), ArenaBytes::new(b"refused"))
        .await
        .unwrap();
    let mut frames = t.frames(b);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"refused");
}

/// A refusal the peer never received is not a refusal that was delivered. With the far end of the
/// pipe gone every write fails, and answering `Ok` there tells the caller a unit-0 arrival was
/// turned away in words the peer can read when nothing left this process at all.
#[tokio::test]
async fn a_refusal_that_never_reached_the_peer_is_reported() {
    let t = StdioTransport::new();
    let (end_a, end_b) = tokio::io::duplex(4096);
    let (br, bw) = split(end_b);
    let b = t.wrap_pair(br, bw, "a");
    let id = b.id();
    // The far end goes away, so the child's stdin is closed under this transport's feet.
    drop(end_a);

    let err = t
        .unit0_refusal(b, None, &a_refusal(), ArenaBytes::new(b"refused"))
        .await
        .expect_err("a refusal that could not be written is not a delivered refusal");
    assert_eq!(err, TransportError::Reset);
    // The connection still goes away: a refusal always ends the session, delivered or not.
    assert!(
        t.state_of(id).is_none(),
        "the failure path still closes the connection"
    );
}

/// A refusal on a connection the fence has already tripped, or one this transport no longer knows,
/// has no channel to reach the peer on at all.
#[tokio::test]
async fn a_refusal_on_a_fenced_connection_is_reported_closed() {
    let t = StdioTransport::new();
    let (a, _b) = pair(&t, 4096);
    t.state_of(a.id())
        .unwrap()
        .poisoned
        .store(true, std::sync::atomic::Ordering::Release);
    let err = t
        .unit0_refusal(a, None, &a_refusal(), ArenaBytes::new(b"refused"))
        .await
        .expect_err("a fenced connection cannot carry a refusal");
    assert_eq!(err, TransportError::Closed);
}

#[allow(clippy::assertions_on_constants)]
#[tokio::test]
async fn transport_meta_matches_the_architecture_row() {
    use busbar_contract::TransportMeta;
    use busbar_contract_transport::wire::Unit0Trigger;
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
    impl busbar_contract::plugin::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    busbar_contract::TransportKeyHandle::issue(&Seal, 0, "test")
}

/// Test-only: [`busbar_contract_transport::wire::Conn`] is `Clone` (a cheap `Arc` handle), which is exactly
/// what lets several tasks hold "the same connection" the way a real caller's writer/closer/frame
/// pump each hold their own clone. Named to make every call site read as what it is.
trait CloneForTest {
    fn clone_for_test(&self) -> Self;
}
impl CloneForTest for busbar_contract_transport::wire::Conn {
    fn clone_for_test(&self) -> Self {
        self.clone()
    }
}

/// The destination's argument vector and environment both reach the child. A single opaque path
/// could carry neither, so a deployment naming a program with arguments had no way to say so.
#[tokio::test]
async fn argv_and_env_reach_the_spawned_child() {
    // `sh -c SCRIPT NAME`: the script reads the environment this destination declared and the
    // argument vector it was spawned with, and writes both back as one line — one stdio frame.
    let dest = program_dest(
        &["-c", "printf '%s %s\\n' \"$MARK\" \"$0\""],
        &[("MARK", "declared")],
    );
    let t = StdioTransport::new();
    let conn = t.dial(&dest, &test_key_handle()).await.unwrap();
    let mut frames = t.frames(conn.clone_for_test());
    let (_, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"declared argzero");
    t.close(conn, busbar_contract_transport::wire::CloseReason::Normal);
}

/// The environment is cleared before anything the destination declared is set, so a child never
/// inherits a variable the deployment did not write down. `HOME` is set in this process and
/// must not survive into a child that was given an empty environment.
#[tokio::test]
async fn the_child_inherits_no_environment_it_was_not_given() {
    assert!(
        std::env::var_os("HOME").is_some(),
        "the parent has a HOME to leak"
    );
    let dest = program_dest(&["-c", "printf 'home=[%s]\\n' \"$HOME\""], &[]);
    let t = StdioTransport::new();
    let conn = t.dial(&dest, &test_key_handle()).await.unwrap();
    let mut frames = t.frames(conn.clone_for_test());
    let (_, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"home=[]");
    t.close(conn, busbar_contract_transport::wire::CloseReason::Normal);
}

/// A sealed destination naming `/bin/sh`, the given argument vector (with `argzero` appended to
/// stand in for the shell's own `$0`) and the given environment.
fn program_dest(
    args: &[&'static str],
    env: &'static [(&'static str, &'static str)],
) -> busbar_contract::VerifiedDestination {
    struct Seal;
    impl busbar_contract::plugin::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    let mut argv: Vec<&'static str> = args.to_vec();
    argv.push("argzero");
    let argv: &'static [&'static str] = Box::leak(argv.into_boxed_slice());
    busbar_contract::VerifiedDestination::seal(
        &Seal,
        busbar_contract::DestinationFacts::Upstream {
            transport: "stdio",
            address: busbar_contract_transport::dest::UpstreamAddress::Program {
                path: "/bin/sh",
                args: argv,
                env,
            },
            lane: busbar_contract::LaneId::new("test"),
        },
        "stdio",
        None,
    )
}

/// A child that dies mid-line has not sent a frame. `read_until` returns what it has when the peer
/// hits EOF without a newline, and handing that fragment up as a well-formed frame is the same
/// "guess where the body ended" this transport already refuses on the write side. The unterminated
/// tail is a framing error, and the clean EOF on a line boundary stays a clean end of stream.
#[tokio::test]
async fn an_unterminated_final_line_is_a_framing_error() {
    let t = StdioTransport::new();
    let (end_a, end_b) = tokio::io::duplex(64 * 1024);
    let (br, bw) = split(end_b);
    let b = t.wrap_pair(br, bw, "a");
    let (_ar, mut aw) = split(end_a);

    // One whole line, then half of another, then the peer goes away.
    aw.write_all(b"{\"id\":1}\n{\"jsonr").await.unwrap();
    aw.shutdown().await.unwrap();

    let mut frames = t.frames(b);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"{\"id\":1}");
    let err = frames
        .next()
        .await
        .expect("the fragment must be reported, not swallowed")
        .expect_err("a half-written line is not a frame");
    assert_eq!(err, TransportError::Framing);
}

/// The unterminated tail survives a cancelled read, so the answer to it must too. A pump dropped
/// mid-line leaves those bytes on the connection (that is the whole point of the reader slot), and
/// the next pump's own read returns nothing at all when the peer then goes away — so "this call read
/// zero bytes" is not the same question as "the peer stopped on a line boundary". Only the second
/// one is a clean end of session.
#[tokio::test]
async fn a_partial_line_carried_across_a_cancelled_read_is_still_a_framing_error() {
    let t = StdioTransport::new();
    let (end_a, end_b) = tokio::io::duplex(64 * 1024);
    let (br, bw) = split(end_b);
    let b = t.wrap_pair(br, bw, "a");
    let (_ar, mut aw) = split(end_a);

    // Half a line, and no newline is ever coming.
    aw.write_all(b"abc").await.unwrap();
    {
        let mut frames = t.frames(b.clone_for_test());
        let first = frames.next();
        tokio::pin!(first);
        let raced = tokio::time::timeout(Duration::from_millis(50), first.as_mut()).await;
        assert!(
            raced.is_err(),
            "the read must still be suspended, holding the partial line, when dropped"
        );
    }
    aw.shutdown().await.unwrap();

    let mut frames = t.frames(b);
    let err = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("the carried-over fragment must be answered")
        .expect("a fragment the peer abandoned is not a clean end of session")
        .expect_err("a half-written line is not a frame");
    assert_eq!(err, TransportError::Framing);
}

/// The fence answers a write that may have put bytes on the wire. A write dropped while it was still
/// waiting its turn for the write lock put none there — nothing was written, so nothing is in doubt,
/// and fencing the connection over it costs a caller every later write and read on a session that
/// was never damaged.
#[tokio::test]
async fn a_write_dropped_while_queued_for_the_lock_does_not_fence_the_connection() {
    let t = StdioTransport::new();
    let (a, b) = pair(&t, 64 * 1024);
    let state = t.state_of(a.id()).unwrap();

    // Stand in for another writer holding the lock: the queued write cannot even begin.
    let held = state.writer.lock().await;
    {
        let queued = t.write(&a, busbar_contract::StreamId(0), ArenaBytes::new(b"queued"));
        tokio::pin!(queued);
        let raced = tokio::time::timeout(Duration::from_millis(20), queued.as_mut()).await;
        assert!(raced.is_err(), "the write cannot have taken the lock");
    }
    drop(held);

    t.write(
        &a,
        busbar_contract::StreamId(0),
        ArenaBytes::new(b"after the queue"),
    )
    .await
    .expect("a write that never began leaves the connection usable");
    let mut frames = t.frames(b);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.as_slice(), b"after the queue");
}

/// A peer that never writes a newline must not be able to exhaust this process's memory. The child
/// is operator-launched, so it sits nearer the trusted side than a client does, but it is still a
/// process this transport does not control and no layer above caps what it sends.
#[tokio::test]
async fn a_line_past_the_maximum_is_a_framing_error() {
    let t = StdioTransport::new();
    let (end_a, end_b) = tokio::io::duplex(64 * 1024);
    let (br, bw) = split(end_b);
    let b = t.wrap_pair(br, bw, "a");
    let (_ar, mut aw) = split(end_a);

    let over = vec![b'x'; crate::transport::MAX_LINE_BYTES + 1];
    let flood = tokio::spawn(async move {
        // Never a newline: without a bound the reader would keep growing instead of answering.
        let _ = aw.write_all(&over).await;
        futures::future::pending::<()>().await;
    });

    let mut frames = t.frames(b);
    let err = tokio::time::timeout(Duration::from_secs(5), frames.next())
        .await
        .expect("an over-long line must be answered, not read forever")
        .expect("the stream must report it")
        .expect_err("a line past the maximum is not a frame");
    assert_eq!(err, TransportError::Framing);
    flood.abort();
}

/// The bound does not touch ordinary traffic: a line just under the maximum is still a frame,
/// byte-exact.
#[tokio::test]
async fn a_line_within_the_maximum_is_still_a_frame() {
    let t = Arc::new(StdioTransport::new());
    let (a, b) = pair(&t, 64 * 1024);
    let payload = vec![b'y'; crate::transport::MAX_LINE_BYTES - 1];
    let writer = tokio::spawn({
        let t = t.clone();
        let payload = payload.clone();
        async move {
            t.write(&a, busbar_contract::StreamId(0), ArenaBytes::new(&payload))
                .await
                .unwrap()
        }
    });
    let mut frames = t.frames(b);
    let (_s, frame) = frames.next().await.unwrap().unwrap();
    assert_eq!(frame.bytes.len(), payload.len());
    assert!(frame.bytes.as_slice().iter().all(|&c| c == b'y'));
    writer.await.unwrap();
}

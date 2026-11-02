// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A mirrored LINE stream relays PAYLOAD only. `busbar_contract::abi::transport`, "fields by

use super::{Across, Bridge, Leg, LegSink, Pairing};
use crate::framer::{Got, Yielded};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The caller's first line stream and its upstream counterpart (line position 0 of each leg).

const CALLER_LINE: u64 = 10;
const UPSTREAM_LINE: u64 = 20;
/// The caller's second line stream and its upstream counterpart (line position 1 of each leg):

const CALLER_ENDING: u64 = 11;
const UPSTREAM_ENDING: u64 = 21;

/// A whole binary payload frame on `stream`.
fn payload(stream: u64, bytes: &[u8]) -> Got {
    Got {
        stream,
        bytes: bytes.to_vec(),
        end_of_frame: true,
        status_code: None,
        handoff: false,
        status_class: 0,
        fault: 0,
        retry_after_secs: None,
        declared_len: None,
        fields: false,
        text: false,
        reason: None,
        failed: false,
        end: false,
    }
}

/// A payload piece that does NOT complete its frame.
fn partial(stream: u64, bytes: &[u8]) -> Got {
    Got {
        end_of_frame: false,
        ..payload(stream, bytes)
    }
}

/// A field block piece (a head, a continuation of one, or trailers).
fn fields(stream: u64, bytes: &[u8], end_of_frame: bool) -> Got {
    Got {
        fields: true,
        end_of_frame,
        ..payload(stream, bytes)
    }
}

/// A failed stream's last piece: the bytes are the reason, and `PIECE_END` is NOT set. Nothing

fn failed(stream: u64, reason: &[u8]) -> Got {
    Got {
        failed: true,
        ..payload(stream, reason)
    }
}

/// A stream's end: empty, with `PIECE_END`. Nothing follows it on its stream.
fn ended(stream: u64) -> Got {
    Got {
        end: true,
        ..payload(stream, b"")
    }
}

fn text(stream: u64, bytes: &[u8]) -> Got {
    Got {
        text: true,
        ..payload(stream, bytes)
    }
}

fn across(stream: u64, bytes: &[u8], end_of_frame: bool) -> Across {
    Across {
        stream,
        bytes: bytes.to_vec(),
        end_of_frame,
    }
}

/// A leg as a test sees it: the frames that crossed into it, and how often it was closed.
#[derive(Default)]
struct Sink {
    lines: Mutex<Vec<Across>>,
    closed: std::sync::atomic::AtomicU32,
}

impl Sink {
    fn lines(&self) -> Vec<Across> {
        self.lines.lock().unwrap().clone()
    }
    fn closes(&self) -> u32 {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl LegSink for Sink {
    fn line(&self, across: Across, _now: Instant) {
        self.lines.lock().unwrap().push(across);
    }
    fn close(&self) {
        self.closed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The head blocks naming a leg's two audio lines, in position order.
fn line_heads(first: u64, second: u64) -> Vec<Got> {
    vec![
        fields(first, b"kind: audio\r\n", true),
        fields(second, b"kind: audio\r\n", true),
    ]
}

/// A bridge whose caller lines `CALLER_LINE`/`CALLER_ENDING` mirror upstream lines

fn mirrored_bridge() -> Bridge {
    let mut b = Bridge::new();
    let (session, across) = b.sort(Leg::Caller, line_heads(CALLER_LINE, CALLER_ENDING));
    assert!(session.is_empty() && across.is_empty());
    let (session, across) = b.sort(Leg::Upstream, line_heads(UPSTREAM_LINE, UPSTREAM_ENDING));
    assert!(session.is_empty() && across.is_empty());
    assert_eq!(b.mirrored(), Ok(()));
    b
}

/// The rest of a known line's head, split by a small sink after the piece that named the line:

fn head_tail(stream: u64) -> Vec<Got> {
    vec![
        fields(stream, b"x-continued: tail\r\n", false),
        fields(stream, b"x-more: head\r\n", true),
    ]
}

/// A known line's fields after its body: trailers, and a field block with no field left in it.

fn trailers(stream: u64) -> Vec<Got> {
    vec![
        fields(stream, b"x-trailer: done\r\n", true),
        fields(stream, b"", true),
    ]
}

#[test]
fn a_known_lines_field_blocks_and_failure_reason_never_cross_but_its_frames_do() {
    let mut b = mirrored_bridge();
    let mut pieces = head_tail(CALLER_LINE);
    pieces.extend([
        partial(CALLER_LINE, b"fi"),
        payload(CALLER_LINE, b"rst"),
        text(CALLER_LINE, b""),
        text(CALLER_LINE, b"hi"),
        payload(CALLER_LINE, b"\x00\x01"),
    ]);
    pieces.extend(trailers(CALLER_LINE));

    pieces.push(failed(CALLER_LINE, b"peer reset the stream"));
    let (session, crossed) = b.sort(Leg::Caller, pieces);
    assert!(
        session.is_empty(),
        "a line's pieces are never the session's"
    );
    assert_eq!(
        crossed,
        vec![
            across(UPSTREAM_LINE, b"fi", false),
            across(UPSTREAM_LINE, b"rst", true),
            across(UPSTREAM_LINE, b"", true),
            across(UPSTREAM_LINE, b"hi", true),
            across(UPSTREAM_LINE, b"\x00\x01", true),
        ],
        "only the five payload pieces cross, in order, the empty frame included"
    );
}

#[test]
fn a_known_lines_ordinary_end_is_consumed_and_its_earlier_frames_and_trailers_are_not() {
    let mut b = mirrored_bridge();
    let (session, crossed) = b.sort(
        Leg::Caller,
        vec![
            payload(CALLER_LINE, b"z"),
            payload(CALLER_LINE, b""),
            fields(CALLER_LINE, b"x-trailer: done\r\n", true),
            ended(CALLER_LINE),
        ],
    );
    assert!(session.is_empty());
    assert_eq!(
        crossed,
        vec![
            across(UPSTREAM_LINE, b"z", true),
            across(UPSTREAM_LINE, b"", true),
        ],
        "the trailers and the end are consumed; both frames, the empty one too, cross"
    );
}

#[test]
fn the_upstream_legs_field_blocks_and_failure_reason_never_cross_back_to_the_caller() {
    let mut b = mirrored_bridge();
    let mut pieces = head_tail(UPSTREAM_LINE);
    pieces.push(payload(UPSTREAM_LINE, b"back"));
    pieces.extend(trailers(UPSTREAM_LINE));

    pieces.push(failed(UPSTREAM_LINE, b"upstream reset the stream"));
    let (session, crossed) = b.sort(Leg::Upstream, pieces);
    assert!(session.is_empty());
    assert_eq!(crossed, vec![across(CALLER_LINE, b"back", true)]);
}

#[test]
fn a_failed_reason_without_the_end_flag_is_not_media_on_its_own() {
    let mut b = mirrored_bridge();
    let reason = failed(CALLER_LINE, b"upstream timed out");
    assert!(!reason.end, "a failed piece never carries PIECE_END");
    let (session, crossed) = b.sort(Leg::Caller, vec![reason]);
    assert!(session.is_empty());
    assert!(crossed.is_empty());
}

/// A mirrored pairing over two recording legs, on an optional memory limit.
fn paired(limit: Option<usize>) -> (Arc<Pairing>, Arc<Sink>, Arc<Sink>) {
    let (caller, upstream) = (Arc::new(Sink::default()), Arc::new(Sink::default()));
    let pairing =
        Pairing::with_memory_limit(caller.clone(), "127.0.0.1:3478".parse().unwrap(), limit);
    let now = Instant::now();
    assert!(pairing
        .sort(Leg::Caller, line_heads(CALLER_LINE, CALLER_ENDING), now)
        .is_empty());
    assert!(pairing
        .sort(
            Leg::Upstream,
            line_heads(UPSTREAM_LINE, UPSTREAM_ENDING),
            now
        )
        .is_empty());
    pairing.attach(upstream.clone()).unwrap();
    (pairing, caller, upstream)
}

#[test]
fn published_line_metadata_is_neither_accepted_queued_nor_handed_and_frames_are_counted_exactly() {
    crate::support::worker().block_on(async {
        let (pairing, caller, upstream) = paired(None);
        let mut pieces = head_tail(CALLER_LINE);
        pieces.extend([
            payload(CALLER_LINE, b"a"),
            payload(CALLER_LINE, b""),
            text(CALLER_LINE, b"bcd"),
            payload(CALLER_ENDING, b"e"),
            ended(CALLER_ENDING),
        ]);
        pieces.extend(trailers(CALLER_LINE));

        pieces.push(failed(CALLER_LINE, b"peer reset the stream"));
        let batch = pairing.publish(
            Leg::Caller,
            {
                let mut yielded = Yielded::default();
                yielded.pieces = pieces;
                yielded
            },
            Instant::now(),
        );
        assert!(batch.pieces.is_empty(), "a line is never the session's");
        let outcome = pairing.published().await;
        assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
        assert_eq!(
            upstream.lines(),
            vec![
                across(UPSTREAM_LINE, b"a", true),
                across(UPSTREAM_LINE, b"", true),
                across(UPSTREAM_LINE, b"bcd", true),
                across(UPSTREAM_ENDING, b"e", true),
            ]
        );
        assert!(caller.lines().is_empty());

        assert_eq!(
            (
                outcome.accepted_frames,
                outcome.accepted_bytes,
                outcome.handed_frames,
                outcome.handed_bytes,
                outcome.cancelled_frames,
                outcome.cancelled_bytes,
                outcome.uncertain_frames,
                outcome.uncertain_bytes,
            ),
            (4, 5, 4, 5, 0, 0, 0, 0)
        );
        assert_eq!(
            (
                outcome.original_bytes,
                outcome.original_handed_bytes,
                outcome.original_cancelled_bytes,
                outcome.original_uncertain_bytes,
            ),
            (0, 0, 0, 0),
            "no application input was accepted"
        );

        let mut pieces = head_tail(UPSTREAM_LINE);
        pieces.extend(trailers(UPSTREAM_LINE));
        pieces.push(failed(UPSTREAM_LINE, b"upstream reset the stream"));
        let batch = pairing.publish(
            Leg::Upstream,
            {
                let mut yielded = Yielded::default();
                yielded.pieces = pieces;
                yielded
            },
            Instant::now(),
        );
        assert!(batch.pieces.is_empty());
        let outcome = pairing.published().await;
        assert!(caller.lines().is_empty());
        assert_eq!((outcome.accepted_frames, outcome.handed_frames), (4, 4));

        pairing.close();
        let outcome = pairing.publication_outcome();
        assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
        assert_eq!(
            (
                outcome.accepted_frames,
                outcome.handed_frames,
                outcome.cancelled_frames,
                outcome.cancelled_bytes,
            ),
            (4, 4, 0, 0)
        );
        assert_eq!((caller.closes(), upstream.closes()), (1, 1));
    });
}

#[test]
fn a_close_after_metadata_only_pieces_has_nothing_accepted_handed_or_cancelled() {
    crate::support::worker().block_on(async {
        let (pairing, caller, upstream) = paired(None);

        let mut pieces = head_tail(CALLER_LINE);
        pieces.extend(trailers(CALLER_LINE));
        pieces.push(failed(CALLER_LINE, b"peer reset the stream"));
        pieces.push(fields(CALLER_ENDING, b"x-trailer: done\r\n", true));
        pieces.push(ended(CALLER_ENDING));
        let batch = pairing.publish(
            Leg::Caller,
            {
                let mut yielded = Yielded::default();
                yielded.pieces = pieces;
                yielded
            },
            Instant::now(),
        );
        assert!(batch.pieces.is_empty());
        let outcome = pairing.published().await;
        assert!(outcome.failure.is_none(), "{:?}", outcome.failure);

        pairing.close();
        let outcome = pairing.publication_outcome();
        assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
        assert_eq!(
            (
                outcome.accepted_frames,
                outcome.accepted_bytes,
                outcome.handed_frames,
                outcome.handed_bytes,
                outcome.cancelled_frames,
                outcome.cancelled_bytes,
            ),
            (0, 0, 0, 0, 0, 0)
        );
        assert!(upstream.lines().is_empty() && caller.lines().is_empty());
        assert_eq!((caller.closes(), upstream.closes()), (1, 1));
    });
}

#[test]
fn metadata_pieces_release_the_batch_custody_with_the_frames_that_did_cross() {
    crate::support::worker().block_on(async {
        let (pairing, _caller, upstream) = paired(Some(1 << 20));
        let memory = pairing.memory_account();
        assert_eq!(memory.used(), 0);
        let custody = pairing.reserve_input(64).expect("room under the limit");
        assert!(memory.used() > 0, "the reservation is charged");
        let mut pieces = head_tail(CALLER_LINE);
        pieces.push(payload(CALLER_LINE, b"xy"));
        pieces.extend(trailers(CALLER_LINE));

        pieces.push(failed(CALLER_LINE, b"peer reset the stream"));
        let batch = pairing.publish(
            Leg::Caller,
            {
                let mut yielded = Yielded::default();
                yielded.pieces = pieces;
                yielded.custody = custody;
                yielded
            },
            Instant::now(),
        );
        assert!(batch.pieces.is_empty());
        let outcome = pairing.published().await;
        assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
        assert_eq!(upstream.lines(), vec![across(UPSTREAM_LINE, b"xy", true)]);
        assert_eq!(
            (
                outcome.accepted_frames,
                outcome.accepted_bytes,
                outcome.handed_frames,
                outcome.handed_bytes,
            ),
            (1, 2, 1, 2)
        );
        drop(batch);
        assert_eq!(
            memory.used(),
            0,
            "every queued job and retired metadata piece released its share"
        );
        pairing.close();
        assert_eq!(pairing.publication_outcome().cancelled_frames, 0);
    });
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Protocol producers keep custody of the bytes they own (Q24, UNSAFE-MIN §4.4): an SSE buffer's
//! growth, clones, cancellation, unwinding and error return, and every JSON-RPC producer's output in
//! its `SecureVec` owner. Each case plants a fresh canary, ends its owners, then scans this process's
//! memory: the canary must be gone, and wherever an owner is still alive part-way it must still be
//! found. The producers' allocation counts are `jsonrpc_producer_allocations.rs`. Linux only (A23).
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::cell::Cell;
use std::future::Future;
use std::task::{Context, Poll, Waker};

use busbar_contract::secure::SecureVec;
use busbar_contract::{jsonrpc, protocol::SseFrames};

use busbar_contract::canary_scan::{WipeProof, PAYLOAD_LEN};

/// The shipped allocator, so the scan reads what production would leave behind.
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// The SSE field prefix a pending frame starts with.
const DATA: &[u8] = b"data: ";

/// A buffer holding a pending (unterminated) frame `data: <secret>`, the secret's only copy.
fn pending_frame(secret: &[u8]) -> SseFrames {
    let mut frames = SseFrames::new();
    frames.push(DATA);
    frames.push(secret);
    frames
}

#[test]
fn the_scan_distinguishes_plain_and_wiping_owners() {
    let proof = WipeProof::new();
    let plain = proof.payload().to_vec();
    drop(plain);
    assert!(
        proof.canary_copies("a plain buffer") >= 1,
        "a plain buffer's freed bytes must be found"
    );

    let proof = WipeProof::new();
    let wiped = SecureVec::from(proof.payload().to_vec());
    drop(wiped);
    proof.assert_absent("a SecureVec");
}

/// Growth wipes the old allocation (else its freed copy is found at the end) and keeps the pending
/// bytes.
#[test]
fn sse_growth_wipes_the_registered_old_allocation_and_preserves_pending_bytes() {
    const LARGE_CHUNK: &[u8] = &[b'x'; 65536];
    let mut proof = WipeProof::text();
    let staging = proof.text_payload();
    let mut frames = pending_frame(staging.as_bytes());
    assert!(frames.next_frame().is_none());
    let seed = frames.buffer().len();
    assert_eq!(seed, DATA.len() + PAYLOAD_LEN);
    frames.push(LARGE_CHUNK);
    assert_eq!(&frames.buffer()[..DATA.len()], DATA);
    assert_eq!(&frames.buffer()[DATA.len()..seed], staging.as_bytes());
    assert_eq!(&frames.buffer()[seed..], LARGE_CHUNK);
    assert_eq!(frames.pending(), seed + LARGE_CHUNK.len());
    drop(staging);
    proof.assert_held("the grown buffer holds the pending frame");
    drop(frames);
    proof.assert_absent("the old allocation at growth, then the grown one at drop");
}

#[test]
fn sse_clones_pending_cancellation_and_unwind_wipe_their_final_owners() {
    let mut proof = WipeProof::text();
    let staging = proof.text_payload();
    let frames = pending_frame(staging.as_bytes());
    let clone = frames.clone();
    drop(frames);
    assert_eq!(&clone.buffer()[..DATA.len()], DATA);
    assert_eq!(&clone.buffer()[DATA.len()..], staging.as_bytes());
    drop(staging);
    let mut pending = Box::pin(async move {
        let frames = clone;
        std::future::pending::<()>().await;
        drop(frames);
    });
    assert_eq!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    );
    proof.assert_held("the pending future still owns the clone");
    drop(pending);
    proof.assert_absent("the original at drop, then the clone at cancellation");

    let proof = WipeProof::text();
    let staging = proof.text_payload();
    let frames = pending_frame(staging.as_bytes());
    drop(staging);
    let unwound = std::panic::catch_unwind(move || {
        let _owner = frames;
        panic!("SSE owner unwind fixture");
    });
    assert!(unwound.is_err());
    proof.assert_absent("an owner dropped by unwinding");
}

#[test]
fn every_jsonrpc_producer_output_is_wiped_by_its_secure_owner() {
    const ID: &[u8] = br#""private-id""#;
    const OPEN: &[u8] = br#"{"credential":""#;
    const CLOSE: &[u8] = br#""}"#;
    let text = "private\u{0}\n\r\t\"\\雪".repeat(4096);
    /// A producer's name and the producer itself.
    type Producer<'a> = (&'a str, &'a dyn Fn(&[u8]) -> Vec<u8>);
    let producers: [Producer<'_>; 4] = [
        ("result", &|body: &[u8]| jsonrpc::result_bytes(ID, body)),
        ("request", &|body: &[u8]| {
            jsonrpc::request_bytes(ID, &text, Some(body))
        }),
        ("notification", &|body: &[u8]| {
            jsonrpc::notification_bytes(&text, Some(body))
        }),
        ("error", &|body: &[u8]| {
            jsonrpc::error_bytes(ID, i64::MIN, &text, Some(body))
        }),
    ];
    for (name, produce) in producers {
        let proof = WipeProof::text();
        let staging = proof.text_payload();
        // `{"credential":"<secret>"}`, built at its final size in a wiping staging buffer.
        let mut body = SecureVec::with_capacity(OPEN.len() + PAYLOAD_LEN + CLOSE.len())
            .expect("bounded fixture");
        body.extend_from_slice(OPEN);
        body.extend_from_slice(staging.as_bytes());
        body.extend_from_slice(CLOSE);
        drop(staging);
        let owner = SecureVec::from(produce(body.as_slice()));
        drop(body);
        drop(owner);
        proof.assert_absent(name);
    }
}

#[test]
fn an_sse_owner_resumes_with_the_same_frame_then_wipes_on_error_return() {
    let proof = WipeProof::text();
    let staging = proof.text_payload();
    // The frame the resumed owner must yield, in a wiping buffer of its final size.
    let mut expected =
        SecureVec::with_capacity(DATA.len() + PAYLOAD_LEN + 2).expect("bounded fixture");
    expected.extend_from_slice(DATA);
    expected.extend_from_slice(staging.as_bytes());
    expected.extend_from_slice(b"\n\n");
    let ready = Cell::new(false);
    let mut frames = pending_frame(staging.as_bytes());
    frames.push(b"\n");
    drop(staging);
    assert!(frames.next_frame().is_none());
    let mut resumed = Box::pin(async {
        let mut frames = frames;
        std::future::poll_fn(|_| {
            if ready.get() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        frames.push(b"\n");
        assert_eq!(frames.next_frame(), Some(&expected[..]));
        Err::<(), ()>(())
    });
    assert_eq!(
        resumed
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    );
    ready.set(true);
    assert_eq!(
        resumed
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(()))
    );
    drop(resumed);
    drop(expected);
    proof.assert_absent("a resumed owner returning an error");
}

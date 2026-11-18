// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SSE compaction erases the tail it vacates before a later push can reuse those bytes (moved here
//! from the crate's `sse_frames_tests.rs`; Q24, UNSAFE-MIN §4.4). A yielded frame carries a fresh
//! canary; once a push compacts the buffer, the frame's bytes lie only in the live buffer's spare
//! capacity, and a scan of this process's memory must not find them there. Linux only (A23).
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use busbar_contract::protocol::SseFrames;
use busbar_contract::secure::SecureVec;

use busbar_contract::canary_scan::WipeProof;

/// The shipped allocator, so the scan reads what production would leave behind.
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// The complete frame `data: <secret>\n\n`, built at its final size in a wiping buffer.
fn frame(secret: &[u8]) -> SecureVec {
    let mut out =
        SecureVec::with_capacity(b"data: ".len() + secret.len() + 2).expect("bounded fixture");
    out.extend_from_slice(b"data: ");
    out.extend_from_slice(secret);
    out.extend_from_slice(b"\n\n");
    out
}

#[test]
fn compaction_wipes_only_the_known_initialized_vacated_tail_before_truncating() {
    const PENDING: &[u8] = b"data: tail";

    // A yielded frame, then a pending tail compacted over its start: the frame's canary lies in the
    // vacated tail, past the bytes the pending tail overwrote.
    let proof = WipeProof::text();
    let staging = proof.text_payload();
    let framed = frame(staging.as_bytes());
    drop(staging);
    let mut frames = SseFrames::new();
    frames.push(framed.as_slice());
    frames.push(PENDING);
    assert_eq!(frames.next_frame(), Some(&framed[..]));
    assert!(frames.next_frame().is_none());
    drop(framed);
    frames.push(b"");
    assert_eq!(frames.buffer(), PENDING);
    proof.assert_absent("the vacated tail after compaction");

    frames.push(b"\n\n");
    assert_eq!(frames.next_frame(), Some(&b"data: tail\n\n"[..]));
    frames.push(b"");
    assert!(frames.buffer().is_empty());

    // A fully consumed buffer: compaction wipes the whole initialized prefix the frame filled.
    let proof = WipeProof::text();
    let staging = proof.text_payload();
    let framed = frame(staging.as_bytes());
    drop(staging);
    frames.push(framed.as_slice());
    assert_eq!(frames.next_frame(), Some(&framed[..]));
    drop(framed);
    frames.push(b"");
    assert!(frames.buffer().is_empty());
    proof.assert_absent("the consumed prefix after compaction");
    drop(frames);
}

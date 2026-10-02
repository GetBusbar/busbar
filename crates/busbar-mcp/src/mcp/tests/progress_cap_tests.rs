// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An UNTRUSTED upstream progress stream is bounded: a peer that emits progress without end cannot
//! grow busbar's per-request channel without end. These cases pin the cap and the drop policy of
//! [`super::ProgressChannel`].

use super::ProgressChannel;

/// An UNTRUSTED upstream progress stream is bounded: past the cap frames are dropped, and the
/// ones KEPT are the earliest, in order. Without the bound a peer that emits progress without end
/// grows busbar's per-request channel without end (the two wire push sites append verbatim,
/// across every round of a multi-round call).
#[test]
fn push_frame_bounds_an_untrusted_progress_stream_at_the_cap() {
    let mut ch = ProgressChannel::default();
    for i in 0..(ProgressChannel::MAX_FRAMES + 50) {
        ch.push_frame(serde_json::json!({ "n": i }));
    }
    assert_eq!(
        ch.frames.len(),
        ProgressChannel::MAX_FRAMES,
        "an unbounded upstream progress stream must not grow the per-request channel past the cap"
    );
    assert_eq!(
        ch.frames.first().and_then(|f| f.get("n")),
        Some(&serde_json::json!(0)),
        "the earliest frame is retained"
    );
    assert_eq!(
        ch.frames.last().and_then(|f| f.get("n")),
        Some(&serde_json::json!(ProgressChannel::MAX_FRAMES - 1)),
        "the run kept is contiguous from the first frame"
    );
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The same-proto `StreamTranslate` A-tap unit checks RELOCATED HERE from `busbar-core`'s
//! `test_support/tests/tests.rs::test_stream_inspection_tap_usage_parsing`. They drive the
//! witnessed `StreamTranslate` directly — usage extraction and the
//! terminal-error abnormal-end signal — which names codec vocabulary a neutral crate's tests must
//! not, so they live beside the codec. The core-subject half (that `forward()` delivers a
//! byte-identical stream) stays in `busbar-core`. Byte-identical assertions.

use super::*;

/// Tests that the same-proto `StreamTranslate`:
/// (a) extracts billed usage from message_start/message_delta events (`translate.usage()`)
/// (b) sets `terminal_error()` on a genuine SSE error frame (the breaker abnormal-end signal)
#[test]
fn test_stream_inspection_tap_usage_parsing() {
    // Test 1: the A-tap extracts usage from Anthropic-style events (input on message_start, output
    // on message_delta — the start-usage backfill the A-tap reads AFTER).
    let mut t = StreamTranslate::new_same_proto("anthropic").expect("same-proto translator");
    let _ = t.feed(b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n");
    let _ = t.feed(b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n");
    let _ = t.feed(b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
    let _ = t.finish();
    let u = t.usage().expect("A-tap captured usage");
    assert_eq!(u.input_tokens, 10, "input_tokens should be 10");
    assert_eq!(u.output_tokens, 5, "output_tokens should be 5");
    // A clean stream (no error frame) must leave terminal_error None — the signal the stream-end
    // arm uses to distinguish a clean close from an aborted one.
    assert!(
        t.terminal_error().is_none(),
        "a clean stream (no error frame) must leave terminal_error None"
    );

    // Test 2: a genuine SSE error frame DOES set terminal_error (the abnormal-end signal).
    let mut err_t = StreamTranslate::new_same_proto("anthropic").expect("translator");
    let _ = err_t.feed(b"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"boom\"}}\n\n");
    assert!(
        err_t.terminal_error().is_some(),
        "an SSE error frame must populate terminal_error"
    );
}

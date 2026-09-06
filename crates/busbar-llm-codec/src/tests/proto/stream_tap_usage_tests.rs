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

/// The same-protocol A-tap must carry the usage DETAIL sub-buckets, not just the four totals. The
/// trailing `include_usage` chunk of an OpenAI stream carries the identical `usage` object the
/// buffered response does, and the reader decodes every sub-bucket off it; the A-tap that feeds
/// billing and the client-visible usage object must not drop them, or the same request reports its
/// attribution at `stream:false` and a hard absent at `stream:true`.
#[test]
fn same_proto_tap_carries_usage_detail_sub_buckets() {
    let mut t = StreamTranslate::new_same_proto("openai").expect("same-proto translator");
    let _ = t.feed(
        b"data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n",
    );
    let _ = t.feed(
        b"data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n",
    );
    let _ = t.feed(
        b"data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":40,\"total_tokens\":140,\"prompt_tokens_details\":{\"cached_tokens\":10,\"audio_tokens\":4},\"completion_tokens_details\":{\"reasoning_tokens\":25,\"audio_tokens\":6,\"accepted_prediction_tokens\":7,\"rejected_prediction_tokens\":3}}}\n\n",
    );
    let _ = t.feed(b"data: [DONE]\n\n");
    let _ = t.finish();
    let u = t.usage().expect("A-tap captured usage").clone();
    assert_eq!(u.input_tokens, 90, "uncached input total still carried");
    assert_eq!(u.output_tokens, 40, "output total still carried");
    assert_eq!(
        u.detail.reasoning_tokens,
        Some(25),
        "same-proto A-tap must carry reasoning_tokens"
    );
    assert_eq!(
        u.detail.input_audio_tokens,
        Some(4),
        "same-proto A-tap must carry input_audio_tokens"
    );
    assert_eq!(
        u.detail.output_audio_tokens,
        Some(6),
        "same-proto A-tap must carry output_audio_tokens"
    );
    assert_eq!(
        u.detail.accepted_prediction_tokens,
        Some(7),
        "same-proto A-tap must carry accepted_prediction_tokens"
    );
    assert_eq!(
        u.detail.rejected_prediction_tokens,
        Some(3),
        "same-proto A-tap must carry rejected_prediction_tokens"
    );
}

/// Cohere reports usage TWICE — a raw `tokens` bucket and a separately-metered `billed_units`
/// bucket, and the billed counts are what an operator is invoiced on (`to_token_usage` lets them
/// WIN over the raw totals). A same-protocol Cohere STREAM reports them only on the terminal
/// `message-end` usage, so an A-tap that folds only the four totals bills the streamed call off the
/// raw counts while its buffered twin bills off the billed counts.
#[test]
fn same_proto_tap_carries_cohere_billed_units() {
    let mut t = StreamTranslate::new_same_proto("cohere").expect("same-proto translator");
    let _ = t.feed(b"data: {\"type\":\"message-start\",\"id\":\"m\"}\n\n");
    let _ = t.feed(
        b"data: {\"type\":\"content-delta\",\"index\":0,\"delta\":{\"message\":{\"content\":{\"text\":\"hi\"}}}}\n\n",
    );
    let _ = t.feed(
        b"data: {\"type\":\"message-end\",\"delta\":{\"finish_reason\":\"COMPLETE\",\"usage\":{\"tokens\":{\"input_tokens\":100,\"output_tokens\":40},\"billed_units\":{\"input_tokens\":120,\"output_tokens\":50,\"search_units\":2,\"classifications\":3}}}}\n\n",
    );
    let _ = t.finish();
    let u = t.usage().expect("A-tap captured usage").clone();
    assert_eq!(
        u.detail.billed_input_tokens,
        Some(120),
        "streamed Cohere must carry billed_units.input_tokens"
    );
    assert_eq!(
        u.detail.billed_output_tokens,
        Some(50),
        "streamed Cohere must carry billed_units.output_tokens"
    );
    assert_eq!(
        u.detail.search_units,
        Some(2),
        "streamed Cohere must carry billed_units.search_units"
    );
    assert_eq!(
        u.detail.billed_classifications,
        Some(3),
        "streamed Cohere must carry billed_units.classifications"
    );
    // The billed counts are the ledgered ones (`to_token_usage` lets them win over the raw totals),
    // so a streamed Cohere call now meters the same figures its buffered twin does.
    let ledgered = u.to_token_usage();
    assert_eq!(
        (ledgered.input, ledgered.output),
        (120, 50),
        "streamed Cohere must ledger the billed counts, not the raw totals"
    );
}

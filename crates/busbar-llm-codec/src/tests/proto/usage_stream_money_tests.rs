// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STREAMED BILL EQUALS THE BUFFERED BILL — per dialect, for every usage member that becomes
//! money — plus the two disciplines that keep a stream's accumulators honest: the trailing-usage
//! fold REPLACES (it never adds), and every reassembly buffer is BOUNDED.
//!
//! WHY THIS FILE EXISTS. A streamed response reports its usage on a different frame, in a different
//! shape, through a different reader entry point (`read_response_events` + the terminal fold) than
//! the buffered one — so the two arms can and do drift, and the drift is invisible: both answers
//! reconcile internally, they just disagree with each other. The operator then pays a different
//! amount for the same completion depending on a `stream` flag. Each dialect's stream is driven
//! end-to-end here and its A-tap usage (the value production bills from) is compared against the
//! buffered read of the SAME numbers.
//!
//! SPEC ANCHOR — the streamed usage frames below are the ones the specifications PINNED BY DIGEST in
//! `testing/llm-conformance/spec-digests.tsv` declare:
//!
//! * `anthropic` (digest `d1d189d7…`) — `MessageStartEvent.message.usage` carries the input and
//!   cache counts; `MessageDeltaEvent.usage` carries the output count. The input side is reported
//!   ONCE, at start, so the terminal fold must backfill it or the prompt bills as zero.
//! * `openai` (digest `5f2358ee…`) — `CreateChatCompletionStreamResponse.usage`, present only on the
//!   trailing `stream_options.include_usage` chunk, with `prompt_tokens_details`; and the
//!   `/responses` `response.completed` event, whose usage is nested under `response`.
//! * `gemini` (digest `836bf6ea…`) — `GenerateContentResponse.usageMetadata` on the terminal chunk.
//! * `cohere` (digest `6f64ec87…`) — `StreamedChatResponseV2` `message-end.delta.usage`, with both
//!   the raw `tokens` bucket and the billed `billed_units` one.
//! * `bedrock` (digest `618bf3a6…`) — the `ConverseStreamMetadataEvent` `metadata` frame's
//!   `usage`, carried in a binary event-stream frame.

use super::*;

/// The four neutral counters a completion is priced on: uncached input, output, cache-read,
/// cache-write.
type Money = (u64, u64, Option<u64>, Option<u64>);

/// The neutral money four the billing path reads.
fn money(u: &busbar_substrate_values::billing::TokenUsage) -> Money {
    (u.input, u.output, u.cache_read, u.cache_creation)
}

/// Drive a SAME-PROTOCOL stream and project the A-tap usage — the exact value the streaming billing
/// arm ledgers — onto the billing carrier.
fn streamed_money(proto: &str, frames: &[&[u8]]) -> Money {
    let mut t = StreamTranslate::new_same_proto(proto).expect("same-proto translator");
    for f in frames {
        let _ = t.feed(f);
    }
    let _ = t.finish();
    let u = t
        .usage()
        .expect("the A-tap captured this stream's terminal usage")
        .clone();
    money(&u.to_token_usage())
}

/// The buffered arm over the same numbers.
fn buffered_money(proto: &str, body: &[u8]) -> Money {
    let v: serde_json::Value = busbar_substrate_values::json::parse(body).expect("json body");
    let ir = protocol_for(proto)
        .expect("known proto")
        .reader()
        .read_response(&v)
        .expect("read_response");
    money(&ir.usage.to_token_usage())
}

/// ANTHROPIC. Input and both cache counts are reported ONLY on `message_start`; the terminal
/// `message_delta` carries output alone. The streamed bill must still be the whole bill.
#[test]
fn anthropic_streamed_bill_equals_the_buffered_bill() {
    let streamed = streamed_money(
        "anthropic",
        &[
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":110,\"output_tokens\":1,\"cache_creation_input_tokens\":40,\"cache_read_input_tokens\":25}}}\n\n",
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":70}}\n\n",
            b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ],
    );
    assert_eq!(streamed, (110, 70, Some(25), Some(40)));
    assert_eq!(
        streamed,
        buffered_money(
            "anthropic",
            br#"{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":110,"output_tokens":70,"cache_creation_input_tokens":40,"cache_read_input_tokens":25}}"#,
        ),
        "the same completion must bill the same amount streamed and buffered",
    );
}

/// OPENAI CHAT. The trailing `include_usage` chunk is the ONLY frame of the stream that carries a
/// usage object at all — including both `prompt_tokens_details` cache slices, which the buffered
/// arm subtracts out of `prompt_tokens` and prices at their own tiers.
#[test]
fn openai_streamed_bill_equals_the_buffered_bill() {
    let streamed = streamed_money(
        "openai",
        &[
            b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n",
            b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":130,\"completion_tokens\":90,\"total_tokens\":220,\"prompt_tokens_details\":{\"cached_tokens\":30,\"cache_write_tokens\":20}}}\n\n",
            SSE_DONE_FRAME,
        ],
    );
    assert_eq!(streamed, (80, 90, Some(30), Some(20)));
    assert_eq!(
        streamed,
        buffered_money(
            "openai",
            br#"{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":130,"completion_tokens":90,"prompt_tokens_details":{"cached_tokens":30,"cache_write_tokens":20}}}"#,
        ),
    );
}

/// OPENAI RESPONSES. The usage is nested under `response` on the `response.completed` event.
#[test]
fn responses_streamed_bill_equals_the_buffered_bill() {
    let streamed = streamed_money(
        "responses",
        &[
            b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n",
            b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":210,\"output_tokens\":80,\"input_tokens_details\":{\"cached_tokens\":50,\"cache_write_tokens\":30}}}}\n\n",
        ],
    );
    assert_eq!(streamed, (130, 80, Some(50), Some(30)));
    assert_eq!(
        streamed,
        buffered_money(
            "responses",
            br#"{"id":"resp_1","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}],"usage":{"input_tokens":210,"output_tokens":80,"input_tokens_details":{"cached_tokens":50,"cache_write_tokens":30}}}"#,
        ),
    );
}

/// GEMINI. The terminal chunk's `usageMetadata` carries the cached-content slice and the thinking
/// tokens, both of which change the bill.
#[test]
fn gemini_streamed_bill_equals_the_buffered_bill() {
    let streamed = streamed_money(
        "gemini",
        &[
            b"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"hi\"}]}}]}\n\n",
            b"data: {\"candidates\":[{\"finishReason\":\"STOP\",\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"\"}]}}],\"usageMetadata\":{\"promptTokenCount\":150,\"candidatesTokenCount\":40,\"cachedContentTokenCount\":20,\"thoughtsTokenCount\":35,\"totalTokenCount\":225}}\n\n",
        ],
    );
    assert_eq!(streamed, (130, 75, Some(20), None));
    assert_eq!(
        streamed,
        buffered_money(
            "gemini",
            br#"{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":150,"candidatesTokenCount":40,"cachedContentTokenCount":20,"thoughtsTokenCount":35,"totalTokenCount":225}}"#,
        ),
    );
}

/// COHERE. `message-end.delta.usage` carries BOTH the raw `tokens` bucket and the separately
/// metered `billed_units` one — and the billed bucket is what the operator is invoiced on, so a
/// streamed call that folds only the raw totals under-reports (or over-reports) the bill.
#[test]
fn cohere_streamed_bill_equals_the_buffered_bill() {
    let streamed = streamed_money(
        "cohere",
        &[
            b"event: message-start\ndata: {\"type\":\"message-start\",\"id\":\"co_1\"}\n\n",
            b"event: message-end\ndata: {\"type\":\"message-end\",\"delta\":{\"finish_reason\":\"COMPLETE\",\"usage\":{\"tokens\":{\"input_tokens\":100,\"output_tokens\":40},\"billed_units\":{\"input_tokens\":120,\"output_tokens\":50}}}}\n\n",
        ],
    );
    assert_eq!(streamed, (120, 50, None, None));
    assert_eq!(
        streamed,
        buffered_money(
            "cohere",
            br#"{"id":"c1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]},"usage":{"tokens":{"input_tokens":100,"output_tokens":40},"billed_units":{"input_tokens":120,"output_tokens":50}}}"#,
        ),
    );
}

/// BEDROCK. The `metadata` event-stream frame carries the usage, cache counters included.
#[test]
fn bedrock_streamed_bill_equals_the_buffered_bill() {
    use busbar_substrate_values::eventstream::encode_frame;
    let start = encode_frame("messageStart", br#"{"role":"assistant"}"#);
    let stop = encode_frame("messageStop", br#"{"stopReason":"end_turn"}"#);
    let meta = encode_frame(
        "metadata",
        br#"{"usage":{"inputTokens":100,"outputTokens":50,"totalTokens":150,"cacheReadInputTokens":15,"cacheWriteInputTokens":22},"metrics":{"latencyMs":5}}"#,
    );
    let streamed = streamed_money("bedrock", &[&start, &stop, &meta]);
    assert_eq!(streamed, (100, 50, Some(15), Some(22)));
    assert_eq!(
        streamed,
        buffered_money(
            "bedrock",
            br#"{"output":{"message":{"role":"assistant","content":[{"text":"hi"}]}},"stopReason":"end_turn","usage":{"inputTokens":100,"outputTokens":50,"cacheReadInputTokens":15,"cacheWriteInputTokens":22}}"#,
        ),
    );
}

/// THE TRAILING-USAGE FOLD REPLACES, IT NEVER ADDS. Both the terminal delta and the trailing
/// usage-only chunk report the SAME cumulative totals (the provider restates them; they are not two
/// halves of one sum). Folding with `+=` instead of `=` would bill this completion TWICE — an exact
/// doubling, which is precisely the shape that looks plausible on an invoice.
#[test]
fn a_restated_trailing_usage_replaces_the_total_and_never_doubles_it() {
    // OpenAI: a finish chunk that ALREADY carried the usage, followed by the trailing usage-only
    // chunk restating it.
    assert_eq!(
        streamed_money(
            "openai",
            &[
                b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n",
                b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":130,\"completion_tokens\":90,\"total_tokens\":220}}\n\n",
                b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":130,\"completion_tokens\":90,\"total_tokens\":220}}\n\n",
                SSE_DONE_FRAME,
            ],
        ),
        (130, 90, None, None),
        "a restated trailing usage is the SAME total, not a second one to add",
    );

    // Anthropic: the start-usage backfill fills only what the terminal delta LEFT EMPTY. A delta
    // that carries its own input count must not have the start's added to it.
    assert_eq!(
        streamed_money(
            "anthropic",
            &[
                b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"role\":\"assistant\",\"usage\":{\"input_tokens\":110,\"output_tokens\":1,\"cache_read_input_tokens\":25}}}\n\n",
                b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"input_tokens\":110,\"output_tokens\":70,\"cache_read_input_tokens\":25}}\n\n",
                b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            ],
        ),
        (110, 70, Some(25), None),
        "the backfill FILLS an empty field; it never adds to one the delta already reported",
    );
}

/// A LATER usage-bearing frame's real count wins over an earlier zero, and a later ZERO never
/// clobbers a count already reported — the two halves of the fold's "non-zero wins" rule. Without
/// the first half a stream bills zero; without the second, one bills zero too, from the other end.
#[test]
fn a_zero_usage_frame_never_erases_a_count_already_reported() {
    // The terminal chunk reports the real numbers; a trailing all-zero usage chunk (some
    // OpenAI-compatible backends emit one) must not erase them.
    assert_eq!(
        streamed_money(
            "openai",
            &[
                b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n",
                b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":130,\"completion_tokens\":90,\"total_tokens\":220}}\n\n",
                b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":0,\"completion_tokens\":0,\"total_tokens\":0}}\n\n",
                SSE_DONE_FRAME,
            ],
        ),
        (130, 90, None, None),
        "an all-zero trailing usage chunk must not erase the counts already reported",
    );
}

// ── MAX_BUF discipline: every reassembly accumulator is bounded ─────────────────────────────────

/// THE SSE REASSEMBLY BUFFER IS BOUNDED. An upstream that never sends a frame terminator (a
/// wedged/hostile egress, or a frame larger than the transport's own limit) must not be able to
/// grow this translator's buffer without limit: past `MAX_BUF` the stream is ABANDONED, the buffer
/// released, and every subsequent `feed` is a no-op. Unbounded, one stream can exhaust the process.
#[test]
fn the_sse_reassembly_buffer_is_abandoned_past_max_buf() {
    let mut t = StreamTranslate::new_same_proto("openai").expect("same-proto translator");
    // A single `data:` frame that never terminates, fed in chunks past the cap.
    let chunk = vec![b'x'; 64 * 1024];
    let mut fed = 0usize;
    let _ = t.feed(b"data: {\"id\":\"chatcmpl-1\",\"padding\":\"");
    while fed <= StreamTranslate::MAX_BUF + (128 * 1024) {
        let _ = t.feed(&chunk);
        fed += chunk.len();
        if t.aborted() {
            break;
        }
    }
    assert!(
        t.aborted(),
        "a stream whose reassembly buffer grew past MAX_BUF ({}) must be abandoned, not buffered \
         without limit",
        StreamTranslate::MAX_BUF
    );
    // Post-abort, further bytes are a no-op: the translator neither buffers nor emits.
    assert!(
        t.feed(&chunk).is_empty(),
        "every feed after the abandonment is a no-op"
    );
    assert!(t.aborted(), "the abandonment latches");
}

/// The GEMINI JSON-ARRAY ingress framer owns a SECOND reassembly accumulator, on the path where the
/// client asked for a JSON array rather than SSE. It carries the same bound: an element that never
/// closes abandons the framer instead of growing.
#[test]
fn the_gemini_json_array_framer_is_bounded_by_the_same_cap() {
    let mut f = gemini::GeminiJsonArrayFramer::default();
    let chunk = vec![b'x'; 64 * 1024];
    let _ = f.feed(b"data: {\"candidates\":[{\"padding\":\"");
    let mut fed = 0usize;
    while fed <= gemini::GeminiJsonArrayFramer::MAX_BUF + (128 * 1024) {
        let _ = f.feed(&chunk);
        fed += chunk.len();
    }
    // The abandonment is observable at the close: an aborted framer terminates the array with a
    // native `google.rpc.Status` error element instead of the bare `]` that would make a silently
    // truncated array look like a complete one.
    let close = String::from_utf8(f.finish()).expect("the close is utf-8");
    assert!(
        close.contains("\"error\"") && close.contains("500"),
        "the gemini json-array framer must abandon past MAX_BUF ({}) and say so at the close, \
         rather than buffer without limit; got {close}",
        gemini::GeminiJsonArrayFramer::MAX_BUF
    );
}

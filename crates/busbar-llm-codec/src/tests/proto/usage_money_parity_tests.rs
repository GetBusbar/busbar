// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE COMPLETION, ONE BILL — the money invariant, per dialect, across the THREE paths that can
//! answer "what did this response cost": the buffered read (`read_response` → `IrUsage`), the
//! HEAD-TRUNCATED recovery (`recover_truncated_usage`), and the streamed A-tap
//! (`StreamTranslate::usage`).
//!
//! WHY THIS FILE EXISTS. Every one of those three paths maps the SAME provider usage object onto
//! the same neutral carrier, and each is written separately per dialect — so a member that becomes
//! money can be read by one and dropped by another, and the operator is then invoiced a different
//! amount for the same completion depending only on a `stream` flag or on whether the body happened
//! to fit the reassembly cap. That is a divergence no total reconciles, so it is pinned HERE, once
//! per dialect, rather than left to each dialect's own suite to remember.
//!
//! SPEC ANCHOR. The wire shapes are the ones the PROVIDER SPECIFICATIONS PINNED BY DIGEST in
//! `testing/llm-conformance/spec-digests.tsv` declare:
//!
//! * `anthropic` (digest `d1d189d7…`) — `Usage`: `input_tokens`, `output_tokens`,
//!   `cache_creation_input_tokens`, `cache_read_input_tokens`.
//! * `openai` (digest `5f2358ee…`) — `CompletionUsage`: `prompt_tokens`, `completion_tokens`,
//!   `prompt_tokens_details.cached_tokens`; and the `/responses` `ResponseUsage`: `input_tokens`,
//!   `output_tokens`, `input_tokens_details.cached_tokens`.
//! * `gemini` (digest `836bf6ea…`, generativelanguage v1beta discovery) — `UsageMetadata`:
//!   `promptTokenCount`, `candidatesTokenCount`, `cachedContentTokenCount`, `thoughtsTokenCount`,
//!   `toolUsePromptTokenCount`, `totalTokenCount`.
//! * `bedrock` (digest `618bf3a6…`, botocore bedrock-runtime) — `TokenUsage`: `inputTokens`,
//!   `outputTokens`, `cacheReadInputTokens`, `cacheWriteInputTokens`.
//! * `cohere` (digest `6f64ec87…`) — `Usage`: the raw `tokens` bucket and the separately-metered
//!   `billed_units` bucket, every count typed `number` (so a JSON double is spec-valid).

use super::*;

/// The neutral money four, as the billing path reads them.
fn money(u: &busbar_substrate_values::billing::TokenUsage) -> (u64, u64, Option<u64>, Option<u64>) {
    (u.input, u.output, u.cache_read, u.cache_creation)
}

/// The buffered arm: the whole body through `read_response`, projected onto the billing carrier.
fn buffered_money(proto: &str, body: &[u8]) -> (u64, u64, Option<u64>, Option<u64>) {
    let v: serde_json::Value = busbar_substrate_values::json::parse(body).expect("json body");
    let ir = protocol_for(proto)
        .expect("known proto")
        .reader()
        .read_response(&v)
        .expect("read_response");
    money(&ir.usage.to_token_usage())
}

/// The HEAD-TRUNCATED arm: the same body with its opening structure cut away (what the reassembly
/// cap leaves behind), recovered through the dialect's tail scan.
fn truncated_money(proto: &str, body: &[u8]) -> (u64, u64, Option<u64>, Option<u64>) {
    // Cut the head hard enough that the retained slice is NOT a well-formed document — the
    // condition this path exists for — while keeping the trailing usage member, which is what the
    // reassembly cap leaves behind. The cut lands a few bytes ahead of the usage key.
    let key = b"\"usage";
    let key_pos = (0..=body.len() - key.len())
        .rev()
        .find(|&i| &body[i..i + key.len()] == key)
        .expect("fixture carries a trailing usage member");
    let cut = key_pos - 12;
    assert!(cut > 0, "fixture must have a head to cut");
    let tail = &body[cut..];
    assert!(
        busbar_substrate_values::json::parse::<serde_json::Value>(tail).is_err(),
        "the fixture's retained tail must be a genuinely truncated (unparseable) document"
    );
    let u = protocol_for(proto)
        .expect("known proto")
        .reader()
        .recover_truncated_usage(tail)
        .expect("a truncated body still carries its trailing usage object");
    money(&u)
}

/// A HEAD-TRUNCATED body bills EXACTLY what the identical untruncated body bills — per dialect,
/// with every money-bearing usage member the pinned spec declares present on the wire.
///
/// A divergence here is one completion with two invoices, decided by whether the response happened
/// to fit `max_translated_body_bytes()`: a cap that is a memory bound, not a pricing input.
#[test]
fn a_truncated_body_bills_what_the_untruncated_body_bills() {
    // (protocol, body). Each body carries EVERY money member of that dialect's usage object.
    let cases: &[(&str, &[u8])] = &[
        (
            "anthropic",
            br#"{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"hello there, this is a reply long enough to truncate"}],"stop_reason":"end_turn","usage":{"input_tokens":110,"output_tokens":70,"cache_creation_input_tokens":40,"cache_read_input_tokens":25}}"#,
        ),
        (
            "openai",
            br#"{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hello there, this is a reply long enough to truncate"},"finish_reason":"stop"}],"usage":{"prompt_tokens":130,"completion_tokens":90,"total_tokens":220,"prompt_tokens_details":{"cached_tokens":30,"cache_write_tokens":20},"completion_tokens_details":{"reasoning_tokens":12}}}"#,
        ),
        (
            "responses",
            br#"{"id":"resp_1","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello there, this is a reply long enough to truncate"}]}],"usage":{"input_tokens":210,"output_tokens":80,"total_tokens":290,"input_tokens_details":{"cached_tokens":50,"cache_write_tokens":30},"output_tokens_details":{"reasoning_tokens":9}}}"#,
        ),
        (
            "gemini",
            br#"{"candidates":[{"content":{"role":"model","parts":[{"text":"hello there, this is a reply long enough to truncate"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":150,"candidatesTokenCount":40,"cachedContentTokenCount":20,"thoughtsTokenCount":35,"totalTokenCount":225}}"#,
        ),
        (
            "bedrock",
            br#"{"output":{"message":{"role":"assistant","content":[{"text":"hello there, this is a reply long enough to truncate"}]}},"stopReason":"end_turn","usage":{"inputTokens":100,"outputTokens":50,"totalTokens":150,"cacheReadInputTokens":15,"cacheWriteInputTokens":22}}"#,
        ),
        (
            "cohere",
            br#"{"id":"c1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"hello there, this is a reply long enough to truncate"}]},"usage":{"tokens":{"input_tokens":100,"output_tokens":40},"billed_units":{"input_tokens":120,"output_tokens":50,"search_units":3,"classifications":2}}}"#,
        ),
    ];

    for (proto, body) in cases {
        assert_eq!(
            truncated_money(proto, body),
            buffered_money(proto, body),
            "{proto}: a head-truncated body must bill exactly what the same untruncated body bills"
        );
    }
}

/// The money four are the REPORTED numbers, not zeros — the parity assertion above would also hold
/// if BOTH arms read nothing at all, so the values themselves are pinned here.
#[test]
fn every_money_member_the_spec_declares_reaches_the_bill() {
    // anthropic: additive cache convention — `input_tokens` is already the uncached input.
    assert_eq!(
        buffered_money(
            "anthropic",
            br#"{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":110,"output_tokens":70,"cache_creation_input_tokens":40,"cache_read_input_tokens":25}}"#,
        ),
        (110, 70, Some(25), Some(40)),
    );

    // openai chat: `prompt_tokens` is a TOTAL that already includes both cache slices, so the
    // uncached input is 130 - 30 (read) - 20 (write) = 80. Pricing the cache-write slice at the
    // plain input tier — or not subtracting it — misprices the request.
    assert_eq!(
        buffered_money(
            "openai",
            br#"{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":130,"completion_tokens":90,"prompt_tokens_details":{"cached_tokens":30,"cache_write_tokens":20}}}"#,
        ),
        (80, 90, Some(30), Some(20)),
    );

    // responses: same normalization against `input_tokens_details`.
    assert_eq!(
        buffered_money(
            "responses",
            br#"{"id":"resp_1","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}],"usage":{"input_tokens":210,"output_tokens":80,"input_tokens_details":{"cached_tokens":50,"cache_write_tokens":30},"output_tokens_details":{"reasoning_tokens":9}}}"#,
        ),
        (130, 80, Some(50), Some(30)),
    );

    // gemini: `promptTokenCount` includes the cached content (so subtract it), and the THINKING
    // tokens are billed at the output rate on top of the visible answer.
    assert_eq!(
        buffered_money(
            "gemini",
            br#"{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":150,"candidatesTokenCount":40,"cachedContentTokenCount":20,"thoughtsTokenCount":35,"totalTokenCount":225}}"#,
        ),
        (130, 75, Some(20), None),
    );

    // bedrock: both cache counters are their own members, additive to `inputTokens`.
    assert_eq!(
        buffered_money(
            "bedrock",
            br#"{"output":{"message":{"role":"assistant","content":[{"text":"hi"}]}},"stopReason":"end_turn","usage":{"inputTokens":100,"outputTokens":50,"cacheReadInputTokens":15,"cacheWriteInputTokens":22}}"#,
        ),
        (100, 50, Some(15), Some(22)),
    );

    // cohere: the separately-metered `billed_units` bucket is what the operator is invoiced on, so
    // it WINS over the raw `tokens` totals for the input/output tiers.
    assert_eq!(
        buffered_money(
            "cohere",
            br#"{"id":"c1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]},"usage":{"tokens":{"input_tokens":100,"output_tokens":40},"billed_units":{"input_tokens":120,"output_tokens":50}}}"#,
        ),
        (120, 50, None, None),
    );
}

/// COHERE'S COUNTS ARE `number`, NOT `integer`, in the pinned v2 document (digest `6f64ec87…`) — so
/// `100.0` is one hundred tokens on the wire, in the raw bucket AND in the billed one. An
/// integer-only read answers zero for every one of them: a complete, silent loss of the bill with
/// nothing malformed anywhere. Pinned on BOTH the buffered and the truncated arms.
#[test]
fn cohere_double_typed_counts_bill_the_count_they_state() {
    let body = br#"{"id":"c1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"hello there, this is a reply long enough to truncate"}]},"usage":{"tokens":{"input_tokens":100.0,"output_tokens":40.0},"billed_units":{"input_tokens":120.0,"output_tokens":50.0,"search_units":3.0,"classifications":2.0}}}"#;
    assert_eq!(
        buffered_money("cohere", body),
        (120, 50, None, None),
        "a double-typed billed count is the count it states, not zero"
    );
    assert_eq!(
        truncated_money("cohere", body),
        (120, 50, None, None),
        "the truncated arm reads the same double-typed counts"
    );

    // With no `billed_units` at all, the raw doubles are what is billed.
    let raw_only = br#"{"id":"c1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"hello there, this is a reply long enough to truncate"}]},"usage":{"tokens":{"input_tokens":100.0,"output_tokens":40.0}}}"#;
    assert_eq!(buffered_money("cohere", raw_only), (100, 40, None, None));
    assert_eq!(truncated_money("cohere", raw_only), (100, 40, None, None));
}

/// GEMINI'S TOOL-USE PROMPT CROSS-CHECK fires ONLY when the provider's own total CONTRADICTS the
/// parts. `toolUsePromptTokenCount` is its own `UsageMetadata` member in the pinned discovery
/// document (digest `836bf6ea…`) and is billed at the input rate, so it is ADDITIVE — except
/// against an upstream whose `totalTokenCount` leaves no room for it, which has already folded it
/// into `promptTokenCount` and would be DOUBLE-BILLED by the add.
///
/// Both directions are pinned: a guard that never fires double-bills every tool turn on such an
/// upstream, and a guard that always fires drops a real, billed bucket on every ordinary one.
#[test]
fn gemini_tool_use_prompt_is_added_unless_the_total_contradicts_the_parts() {
    let body = |extra: &str| -> Vec<u8> {
        format!(
            r#"{{"candidates":[{{"content":{{"role":"model","parts":[{{"text":"hello there, this is a reply long enough to truncate"}}]}},"finishReason":"STOP"}}],"usageMetadata":{{"promptTokenCount":100,"candidatesTokenCount":40,"toolUsePromptTokenCount":30{extra}}}}}"#
        )
        .into_bytes()
    };

    // The total CONFIRMS the split (100 + 40 + 30 = 170): the tool-use bucket is additive input.
    let confirmed = body(r#","totalTokenCount":170"#);
    assert_eq!(buffered_money("gemini", &confirmed), (130, 40, None, None));
    assert_eq!(truncated_money("gemini", &confirmed), (130, 40, None, None));

    // The total is LARGER than the parts: still no contradiction, still additive.
    let roomy = body(r#","totalTokenCount":500"#);
    assert_eq!(buffered_money("gemini", &roomy), (130, 40, None, None));
    assert_eq!(truncated_money("gemini", &roomy), (130, 40, None, None));

    // The total CONTRADICTS the split (140 < 170): the upstream already folded the tool-use prompt
    // into `promptTokenCount`, so adding it again would bill those 30 tokens twice.
    let contradicted = body(r#","totalTokenCount":140"#);
    assert_eq!(
        buffered_money("gemini", &contradicted),
        (100, 40, None, None),
        "the provider's own total is the authority; the add must not double-bill"
    );
    assert_eq!(
        truncated_money("gemini", &contradicted),
        (100, 40, None, None),
    );

    // NO total reported at all: nothing contradicts the split, so the bucket is billed.
    let no_total = body("");
    assert_eq!(buffered_money("gemini", &no_total), (130, 40, None, None));
    assert_eq!(truncated_money("gemini", &no_total), (130, 40, None, None));

    // The cross-check accounts for the THINKING tokens too — they are part of the parts it weighs.
    // 100 + 40 + 25 (thoughts) + 30 (tool-use) = 195; a total of 195 confirms, 194 contradicts.
    let with_thoughts_confirmed = body(r#","thoughtsTokenCount":25,"totalTokenCount":195"#);
    assert_eq!(
        buffered_money("gemini", &with_thoughts_confirmed),
        (130, 65, None, None),
    );
    let with_thoughts_contradicted = body(r#","thoughtsTokenCount":25,"totalTokenCount":194"#);
    assert_eq!(
        buffered_money("gemini", &with_thoughts_contradicted),
        (100, 65, None, None),
    );
}

/// A usage object that is ABSENT is billed as zero and never as an error: the readers all document
/// this tolerance (an OpenAI-compatible backend that omits `usage` on an otherwise valid 200 is a
/// response-format quirk, not a client mistake), and turning it into a `ClientError` would discard
/// a valid body.
#[test]
fn a_response_without_usage_bills_zero_rather_than_failing() {
    let cases: &[(&str, &[u8], (u64, u64, Option<u64>, Option<u64>))] = &[
        (
            "anthropic",
            br#"{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn"}"#,
            (0, 0, None, None),
        ),
        (
            "openai",
            br#"{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}"#,
            (0, 0, None, None),
        ),
        (
            "gemini",
            br#"{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}]}"#,
            (0, 0, None, None),
        ),
        (
            "cohere",
            br#"{"id":"c1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]}}"#,
            (0, 0, None, None),
        ),
        (
            "bedrock",
            br#"{"output":{"message":{"role":"assistant","content":[{"text":"hi"}]}},"stopReason":"end_turn"}"#,
            (0, 0, None, None),
        ),
        (
            "responses",
            br#"{"id":"resp_1","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}]}"#,
            (0, 0, None, None),
        ),
    ];
    for (proto, body, expect) in cases {
        assert_eq!(buffered_money(proto, body), *expect, "{proto}");
    }
}

/// A cache slice LARGER than the total it is a slice of (a malformed upstream) saturates to zero
/// uncached input rather than wrapping into an astronomically large bill.
#[test]
fn a_cache_slice_larger_than_its_total_saturates_instead_of_wrapping() {
    // openai: cached (500) exceeds prompt_tokens (100).
    assert_eq!(
        buffered_money(
            "openai",
            br#"{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":10,"prompt_tokens_details":{"cached_tokens":500}}}"#,
        ),
        (0, 10, Some(500), None),
    );
    // gemini: cachedContentTokenCount exceeds promptTokenCount.
    assert_eq!(
        buffered_money(
            "gemini",
            br#"{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":10,"cachedContentTokenCount":500,"totalTokenCount":110}}"#,
        ),
        (0, 10, Some(500), None),
    );
    // responses: both slices exceed the total together.
    assert_eq!(
        buffered_money(
            "responses",
            br#"{"id":"resp_1","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}],"usage":{"input_tokens":100,"output_tokens":10,"input_tokens_details":{"cached_tokens":80,"cache_write_tokens":80}}}"#,
        ),
        (0, 10, Some(80), Some(80)),
    );
}

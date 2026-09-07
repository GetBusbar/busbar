// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GEMINI USAGE IDENTITY, REPLAYED FROM REAL VENDOR BYTES.
//!
//! Every other Gemini usage test in this crate is built from a `json!` literal a busbar author
//! wrote, which means it can only ever confirm what that author already believed. The question
//! these tests exist to settle could not be answered that way: is `toolUsePromptTokenCount` counted
//! INSIDE `promptTokenCount`, or beside it? Is `thoughtsTokenCount` inside `candidatesTokenCount`?
//! The sum identity the billing cross-check leans on is a different equation for each answer, and a
//! hand-written fixture simply encodes the guess.
//!
//! So the fixtures here are not hand-written. They are seven real turns captured off Vertex AI
//! (`gemini-2.5-flash`, us-central1, 2026-09-07) and committed verbatim under
//! `src/tests/proto/golden/vendor/` — see that directory's README for provenance and the full
//! per-recording table. `include_str!` pins them at compile time, so these tests cannot drift from
//! the evidence and cannot be blessed into agreement with a future regression.
//!
//! WHAT THEY PROVE
//!
//! 1. The identity `total == prompt + candidates + thoughts + toolUse` holds on all seven.
//! 2. `toolUsePromptTokenCount` is NOT a slice of the prompt (32 tool-use tokens against an
//!    18-token prompt — a sub-bucket cannot exceed its bucket).
//! 3. The billed figures the real decoder produces for each recording, pinned exactly.
//! 4. The decoder REPORTS the resulting shortfall instead of reconciling silently, and reports it
//!    on the streaming path too.

use super::super::proto_codec::Protocol;

// The four non-streaming recordings, verbatim. Paths are relative to THIS source file so they
// resolve under every `#[path]`-compile shape this module is built in.
const RESP_TOOL_CALL: &str =
    include_str!("../../tests/proto/golden/vendor/resp_g2g_vertex_tool_call.json");
const RESP_TOOL_RESULT: &str =
    include_str!("../../tests/proto/golden/vendor/resp_g2g_vertex_tool_result.json");
const RESP_THINKING: &str =
    include_str!("../../tests/proto/golden/vendor/resp_g2g_vertex_thinking.json");
const RESP_GROUNDING: &str =
    include_str!("../../tests/proto/golden/vendor/resp_g2g_vertex_grounding.json");

// The three SSE recordings, verbatim.
const SSE_TOOL_CALL: &str =
    include_str!("../../tests/proto/golden/vendor/stream_g2g_vertex_tool_call.sse");
const SSE_GROUNDING: &str =
    include_str!("../../tests/proto/golden/vendor/stream_g2g_vertex_grounding.sse");
const SSE_GROUNDING_SEARCH: &str =
    include_str!("../../tests/proto/golden/vendor/stream_g2g_vertex_grounding_search.sse");

/// Parse a recording into its `usageMetadata` block.
fn usage_of(recording: &str) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(recording).expect("recording parses");
    v["usageMetadata"].clone()
}

/// The LAST SSE frame of a recording that actually carries token counters.
///
/// Deliberately not "the last frame": on a real Gemini stream the earlier frames carry a
/// `usageMetadata` object with NO counters inside it (see `sse_early_frame_usage_metadata_carries_no_counters`).
fn last_counted_sse_frame(recording: &str) -> serde_json::Value {
    let mut last = None;
    for line in recording.lines() {
        let Some(payload) = line.strip_prefix("data: ") else {
            continue;
        };
        let v: serde_json::Value = serde_json::from_str(payload.trim()).expect("frame parses");
        if v["usageMetadata"]["promptTokenCount"].as_u64().is_some() {
            last = Some(v);
        }
    }
    last.expect("some frame carries counters")
}

fn count(usage: &serde_json::Value, key: &str) -> u64 {
    usage[key].as_u64().unwrap_or(0)
}

/// Assert the identity on one recorded `usageMetadata` block, DRIVEN BY THE DIALECT'S OWN CONST
/// TABLE rather than by a list repeated here. Adding a term to `GEMINI_USAGE_ADDITIVE_TERMS`
/// without a recording that supports it turns this red, which is the point of the table being data.
fn assert_identity(name: &str, usage: &serde_json::Value) {
    let summed: u64 = super::GEMINI_USAGE_ADDITIVE_TERMS
        .iter()
        .map(|k| count(usage, k))
        .sum();
    let total = count(usage, "totalTokenCount");
    assert_eq!(
        summed,
        total,
        "{name}: Google's own totalTokenCount must equal the sum of \
         GEMINI_USAGE_ADDITIVE_TERMS. terms={:?} usage={usage}",
        super::GEMINI_USAGE_ADDITIVE_TERMS
    );
}

/// THE MEASUREMENT. All seven real recordings satisfy
/// `totalTokenCount == promptTokenCount + candidatesTokenCount + thoughtsTokenCount + toolUsePromptTokenCount`.
///
/// This is the rule `GEMINI_USAGE_ADDITIVE_TERMS` encodes. If a future recording is added that
/// breaks it, the const table is wrong and must be re-derived — not this assertion relaxed.
#[test]
fn the_four_term_usage_identity_holds_on_every_real_recording() {
    for (name, body) in [
        ("resp_tool_call", RESP_TOOL_CALL),
        ("resp_tool_result", RESP_TOOL_RESULT),
        ("resp_thinking", RESP_THINKING),
        ("resp_grounding", RESP_GROUNDING),
    ] {
        assert_identity(name, &usage_of(body));
    }
    for (name, sse) in [
        ("sse_tool_call", SSE_TOOL_CALL),
        ("sse_grounding", SSE_GROUNDING),
        ("sse_grounding_search", SSE_GROUNDING_SEARCH),
    ] {
        assert_identity(name, &last_counted_sse_frame(sse)["usageMetadata"]);
    }
}

/// THE FINDING THAT OVERTURNED THE DOCS, stated as arithmetic rather than opinion.
///
/// `IrUsageDetail::tool_use_prompt_tokens`, `docs/design/billing-usage-units.md` and
/// `docs/design/billing-unified.md` all described `toolUsePromptTokenCount` as `⊂ prompt`. On the
/// real grounding turn it is 32 against a `promptTokenCount` of 18. Nothing can be a slice of
/// something smaller than itself, so the question is settled without appeal to any spec.
#[test]
fn tool_use_prompt_tokens_cannot_be_a_slice_of_the_prompt() {
    let usage = usage_of(RESP_GROUNDING);
    let prompt = count(&usage, "promptTokenCount");
    let tool_use = count(&usage, "toolUsePromptTokenCount");
    assert_eq!(prompt, 18, "recording changed; re-derive the identity");
    assert_eq!(tool_use, 32, "recording changed; re-derive the identity");
    assert!(
        tool_use > prompt,
        "the whole finding rests on this: toolUse={tool_use} exceeds promptTokenCount={prompt}, so \
         it is an ADDITIVE term and not a sub-bucket"
    );
    // And the total only closes when it is added as a fourth term.
    let without =
        prompt + count(&usage, "candidatesTokenCount") + count(&usage, "thoughtsTokenCount");
    assert_eq!(without, 190, "the three-term sum");
    assert_eq!(
        count(&usage, "totalTokenCount"),
        222,
        "Google's stated total"
    );
    assert_eq!(
        222 - without,
        tool_use,
        "the shortfall IS the tool-use term"
    );
}

/// `thoughtsTokenCount` is additive too — confirmed, not overturned. If it were a slice of
/// `candidatesTokenCount` the three-term sum would overshoot Google's total on every thinking turn.
#[test]
fn thoughts_tokens_are_additive_not_a_slice_of_candidates() {
    let usage = usage_of(RESP_THINKING);
    let (prompt, candidates, thoughts) = (
        count(&usage, "promptTokenCount"),
        count(&usage, "candidatesTokenCount"),
        count(&usage, "thoughtsTokenCount"),
    );
    assert_eq!((prompt, candidates, thoughts), (42, 146, 372));
    assert_eq!(
        prompt + candidates + thoughts,
        count(&usage, "totalTokenCount"),
        "additive"
    );
    assert!(
        thoughts > candidates,
        "thoughts={thoughts} exceeds candidates={candidates}: it cannot be a subset of it either"
    );
}

/// THE MONEY PATH, pinned through the REAL decoder on the REAL bytes.
///
/// These are the figures busbar bills for each recorded turn today. They are asserted here so that
/// any future edit to the Gemini usage decode has to state, in a diff to this test, exactly which
/// bill it changed and by how much.
#[test]
fn billed_figures_for_every_recording_are_pinned() {
    let reader = Protocol::gemini();
    let reader = reader.reader();
    // (recording, input_tokens, output_tokens) — output folds thoughts in; input is uncached prompt.
    for (name, body, want_in, want_out) in [
        ("tool_call", RESP_TOOL_CALL, 47u64, 74u64), // 7 visible + 67 thinking
        ("tool_result", RESP_TOOL_RESULT, 137, 19),  // no thinking on this turn
        ("thinking", RESP_THINKING, 42, 518),        // 146 visible + 372 thinking
        ("grounding", RESP_GROUNDING, 18, 172),      // 89 visible + 83 thinking
    ] {
        let v: serde_json::Value = serde_json::from_str(body).expect("parses");
        let ir = reader.read_response(&v).expect("read");
        assert_eq!(ir.usage.input_tokens, want_in, "{name}: input_tokens");
        assert_eq!(ir.usage.output_tokens, want_out, "{name}: output_tokens");
        // No cache was involved in any of these captures.
        assert_eq!(
            ir.usage.cache_read_input_tokens, None,
            "{name}: no cache read"
        );
        assert_eq!(
            ir.usage.cache_creation_input_tokens, None,
            "{name}: gemini has no cache-creation analog"
        );
    }
}

/// The under-count, stated as money. busbar bills 18 + 172 = 190 tokens for the grounding turn.
/// Google counted 222. The 32-token difference is `toolUsePromptTokenCount`, which
/// `billable_tokens` still excludes.
///
/// This test does NOT assert that busbar bills 222 — folding the term in is a registered money
/// change with its own CHANGELOG line, and is not made here. It pins the size of the gap so that
/// closing it is a deliberate, visible edit.
#[test]
fn a_grounded_turn_is_under_counted_by_exactly_the_tool_use_term() {
    let v: serde_json::Value = serde_json::from_str(RESP_GROUNDING).expect("parses");
    let ir = Protocol::gemini().reader().read_response(&v).expect("read");
    assert_eq!(ir.usage.billable_tokens(), 190, "what busbar bills today");
    let note = ir
        .usage
        .detail
        .usage_identity_note
        .as_ref()
        .expect("the decoder must REPORT the discrepancy, not reconcile silently");
    assert_eq!(note.reported_total, 222, "what Google counted");
    assert_eq!(note.summed_total, 190, "what busbar decoded");
    assert_eq!(note.unaccounted, 32, "the shortfall, positive = unbilled");
    assert_eq!(note.identity, "gemini.usageMetadata");
    // The term itself is still carried as attribution, exactly as received. Nothing was zeroed.
    assert_eq!(ir.usage.detail.tool_use_prompt_tokens, Some(32));
}

/// The quiet case must stay quiet. A turn whose counters reconcile against Google's stated total
/// reports NO note — otherwise the signal is noise and nobody reads it.
#[test]
fn a_reconciling_turn_reports_no_discrepancy() {
    let reader = Protocol::gemini();
    let reader = reader.reader();
    for (name, body) in [
        ("tool_call", RESP_TOOL_CALL),
        ("tool_result", RESP_TOOL_RESULT),
        ("thinking", RESP_THINKING),
    ] {
        let v: serde_json::Value = serde_json::from_str(body).expect("parses");
        let ir = reader.read_response(&v).expect("read");
        assert_eq!(
            ir.usage.detail.usage_identity_note, None,
            "{name}: counters reconcile, so there is nothing to report"
        );
    }
}

/// SPEC DISCREPANCY, RECORDED: the streaming path never reports `toolUsePromptTokenCount`.
///
/// `proto_stream.rs` assumes a streamed Gemini egress reports it "only on the trailing usage-bearing
/// chunk". Both grounded SSE recordings carry `groundingMetadata` — the same server-side tool use
/// that produced 32 tool-use tokens on the buffered turn — yet neither reports the field on ANY
/// frame, trailing one included. A streamed grounded turn therefore cannot even be measured for the
/// under-count its buffered twin exhibits.
#[test]
fn streamed_grounded_turns_omit_the_tool_use_term_entirely() {
    for (name, sse) in [
        ("sse_grounding", SSE_GROUNDING),
        ("sse_grounding_search", SSE_GROUNDING_SEARCH),
    ] {
        assert!(
            sse.contains("groundingMetadata"),
            "{name}: this recording is supposed to be a grounded turn"
        );
        assert!(
            !sse.contains("toolUsePromptTokenCount"),
            "{name}: the recording no longer matches the documented discrepancy — if Vertex has \
             started reporting the field on streams, re-derive the note in the vendor README"
        );
        // And the identity still closes without it, i.e. no tool-use tokens were charged.
        assert_identity(name, &last_counted_sse_frame(sse)["usageMetadata"]);
    }
}

/// SPEC DISCREPANCY, RECORDED: an early SSE frame carries a `usageMetadata` object that is PRESENT
/// but has no counters in it (`{"trafficType": "ON_DEMAND"}`).
///
/// A decoder that reads "the key exists" as "usage has arrived" defaults every counter to zero and
/// can latch that as the turn's usage. This test pins the shape so the trap stays documented.
#[test]
fn sse_early_frame_usage_metadata_carries_no_counters() {
    let first = SSE_GROUNDING
        .lines()
        .find_map(|l| l.strip_prefix("data: "))
        .expect("a first frame");
    let v: serde_json::Value = serde_json::from_str(first.trim()).expect("parses");
    let usage = &v["usageMetadata"];
    assert!(
        usage.is_object(),
        "the object is PRESENT on the first frame"
    );
    assert!(
        usage.get("totalTokenCount").is_none() && usage.get("promptTokenCount").is_none(),
        "yet it carries no counters at all: {usage}"
    );
    // Which is exactly why the identity check treats an absent total as "nothing to check"
    // rather than as zero: this frame must not be reported as a discrepancy.
    let ir = Protocol::gemini().reader().read_response(&v).expect("read");
    assert_eq!(
        ir.usage.detail.usage_identity_note, None,
        "a counterless frame states no total, so there is no identity to violate"
    );
}

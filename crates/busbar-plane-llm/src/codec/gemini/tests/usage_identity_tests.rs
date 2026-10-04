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
//! 4. The decoder BILLS the fourth term (1.6.0 money change) — a grounded turn now reconciles
//!    against Google's own stated total instead of falling 14% short of it — and the identity
//!    cross-check stays as a DISCREPANCY METRIC for whatever the table does not model yet.

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
/// `IrUsageDetail::tool_use_prompt_tokens`, `docs/design/BUSBAR-1.6.0.md` THE DESIGN, §7 and
/// `docs/design/BUSBAR-1.6.0.md` THE DESIGN, §7 all described `toolUsePromptTokenCount` as `⊂ prompt`. On the
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
    // (recording, input_tokens, output_tokens) — output folds thoughts in; input is uncached prompt
    // PLUS the additive tool-use prompt term (Google charges it at the input rate).
    for (name, body, want_in, want_out) in [
        ("tool_call", RESP_TOOL_CALL, 47u64, 74u64), // 7 visible + 67 thinking
        ("tool_result", RESP_TOOL_RESULT, 137, 19),  // no thinking on this turn
        ("thinking", RESP_THINKING, 42, 518),        // 146 visible + 372 thinking
        ("grounding", RESP_GROUNDING, 50, 172),      // 18 prompt + 32 tool-use; 89 + 83 out
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

/// THE 1.6.0 MONEY CHANGE, stated as arithmetic. busbar used to bill 18 + 172 = 190 tokens for the
/// grounding turn while Google counted 222 — a 14% under-count on every grounded turn, and the
/// 32-token difference was exactly `toolUsePromptTokenCount`.
///
/// It is now BILLED: the term is an additive input-rate charge, so it lands in `input_tokens`
/// (18 uncached prompt + 32 tool-use = 50) and `billable_tokens` reaches Google's own stated total.
/// The identity cross-check therefore has nothing left to report on this recording — which is the
/// only honest end state, because a note that fires on every grounded turn forever is not a signal.
#[test]
fn a_grounded_turn_bills_the_tool_use_term() {
    let v: serde_json::Value = serde_json::from_str(RESP_GROUNDING).expect("parses");
    let ir = Protocol::gemini().reader().read_response(&v).expect("read");
    assert_eq!(
        ir.usage.input_tokens, 50,
        "18 uncached prompt + the 32-token additive tool-use term"
    );
    assert_eq!(
        ir.usage.billable_tokens(),
        222,
        "what busbar bills now == what Google counted (was 190)"
    );
    assert_eq!(
        ir.usage.detail.usage_identity_note, None,
        "every term Google stated is now billed, so there is no shortfall left to report"
    );
    // The term itself is still carried as attribution, exactly as received. Nothing was zeroed.
    assert_eq!(ir.usage.detail.tool_use_prompt_tokens, Some(32));
    // And the money projection the ledger reads carries it at the INPUT rate, not as a lost bucket.
    let billed = ir.usage.to_token_usage();
    assert_eq!(billed.input, 50, "the ledger's input tier carries the term");
    assert_eq!(billed.output, 172);
}

/// THE LEDGER HOLDS WHAT GOOGLE ITEMIZED, AND THE GAP IS REPORTED (owner 2026-10-02: ledger what
/// the plane reports; fix Gemini ledging). If Google states a `totalTokenCount` the itemized terms
/// cannot reach, no unit is invented for the gap: the buckets ledger exactly as sent and the note
/// (with its audit WARN) names the gap, which is what says a counter is unmodelled.
///
/// The term here (`someFutureTokenCount`) is deliberately one `GEMINI_USAGE_ADDITIVE_TERMS` does not
/// model.
#[test]
fn an_unmodelled_term_is_reported_never_ledgered() {
    let body = serde_json::json!({
        "candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": "STOP"}],
        "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 5,
            "someFutureTokenCount": 7,
            "totalTokenCount": 22
        }
    });
    let ir = Protocol::gemini()
        .reader()
        .read_response(&body)
        .expect("read");
    // The buckets exactly as sent; the 7 tokens no counter itemizes are folded into none of them.
    assert_eq!(ir.usage.input_tokens, 10);
    assert_eq!(ir.usage.output_tokens, 5);
    let ledgered = ir.usage.to_token_usage();
    assert_eq!((ledgered.input, ledgered.output), (10, 5));
    let note = ir
        .usage
        .detail
        .usage_identity_note
        .as_ref()
        .expect("a total the modelled terms cannot reach must be REPORTED");
    assert_eq!(note.reported_total, 22);
    assert_eq!(note.summed_total, 15);
    assert_eq!(
        note.unaccounted, 7,
        "positive = tokens busbar did not decode"
    );
    assert_eq!(note.identity, "gemini.usageMetadata");
}

/// THE ORACLE CELL `usage.gemini|tool-use|total-not-a-sum` (TODO 576): Google states 64 where its
/// named counters sum to 57 (18 prompt + 7 candidates + 32 tool-use). The ledger holds the itemized
/// 57, on every read path: 50 input (prompt + tool-use prompt) and 7 output. The 7-token gap is
/// reported, never ledgered.
#[test]
fn a_total_above_its_terms_ledgers_the_itemized_counts_on_every_path() {
    const RESP: &str = r#"{"candidates":[{"content":{"parts":[{"text":"pong"}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":18,"candidatesTokenCount":7,"toolUsePromptTokenCount":32,"totalTokenCount":64},"modelVersion":"m-cap"}"#;
    let body: serde_json::Value = serde_json::from_str(RESP).unwrap();
    let ir = Protocol::gemini()
        .reader()
        .read_response(&body)
        .expect("read");
    let ledgered = ir.usage.to_token_usage();
    assert_eq!((ledgered.input, ledgered.output), (50, 7));
    let note = ir
        .usage
        .detail
        .usage_identity_note
        .as_ref()
        .expect("the gap is reported");
    assert_eq!(
        (note.reported_total, note.summed_total, note.unaccounted),
        (64, 57, 7)
    );
    let recovered = Protocol::gemini()
        .reader()
        .recover_truncated_usage(RESP.as_bytes())
        .expect("the trailing usageMetadata is recoverable");
    assert_eq!((recovered.input, recovered.output), (50, 7));
}

/// A total at or below the sum of its terms adds nothing: an early stream frame states none, and a
/// turn whose terms close bills exactly them.
#[test]
fn a_total_that_closes_or_is_absent_adds_nothing() {
    for (usage, out) in [
        (
            serde_json::json!({"promptTokenCount": 10, "candidatesTokenCount": 5}),
            5,
        ),
        (
            serde_json::json!({"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15}),
            5,
        ),
        (
            serde_json::json!({"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 3}),
            5,
        ),
    ] {
        let body = serde_json::json!({
            "candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": "STOP"}],
            "usageMetadata": usage
        });
        let ir = Protocol::gemini()
            .reader()
            .read_response(&body)
            .expect("read");
        assert_eq!((ir.usage.input_tokens, ir.usage.output_tokens), (10, out));
    }
}

/// THE TRUNCATED PATH BILLS THE SAME. A response too large to reassemble is metered through
/// `recover_truncated_usage`, which parses the trailing `usageMetadata` on its own. It read three of
/// Google's four terms, so a grounded turn that overflowed the reassembly cap billed 32 tokens less
/// than the identical turn that did not — the under-count would have survived the fix on exactly the
/// responses nobody can inspect.
#[test]
fn a_truncated_grounded_turn_bills_the_tool_use_term_too() {
    let recovered = Protocol::gemini()
        .reader()
        .recover_truncated_usage(RESP_GROUNDING.as_bytes())
        .expect("the trailing usageMetadata is recoverable");
    assert_eq!(
        recovered.input, 50,
        "18 uncached prompt + the 32-token additive tool-use term — same as the buffered path"
    );
    assert_eq!(recovered.output, 172, "89 visible + 83 thinking");
}

/// THE WRITER IS THE READER'S INVERSE. `input_tokens` now carries the tool-use term, so a
/// cross-protocol Gemini egress must NOT re-emit that term inside `promptTokenCount` as well — the
/// wire shape puts it beside the prompt, and double-counting it would hand a native google-genai
/// client a `usageMetadata` that no longer reconciles with its own `totalTokenCount`.
#[test]
fn the_writer_reconstructs_the_recorded_wire_shape() {
    let v: serde_json::Value = serde_json::from_str(RESP_GROUNDING).expect("parses");
    let ir = Protocol::gemini().reader().read_response(&v).expect("read");
    let out = Protocol::gemini().writer().write_response(&ir);
    let meta = &out["usageMetadata"];
    assert_eq!(
        meta["promptTokenCount"], 18,
        "the prompt term, not 50: {out}"
    );
    assert_eq!(meta["toolUsePromptTokenCount"], 32, "beside it: {out}");
    assert_eq!(
        meta["totalTokenCount"], 222,
        "and Google's own total is reproduced exactly: {out}"
    );
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

/// The upstream body of the oracle cell `usage.gemini|stream-grounded|no-tool-use-count` (TODO
/// 605(a)), verbatim: a STREAMED grounded turn whose final frame states `totalTokenCount` 57
/// against prompt 18 + candidates 7, with no `toolUsePromptTokenCount` on any frame.
const GROUNDED_STREAM: &str = concat!(
    "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"po\"}],\"role\":\"model\"},\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":18,\"totalTokenCount\":18},\"modelVersion\":\"m-cap\"}\r\n\r\n",
    "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"ng\"}],\"role\":\"model\"},\"finishReason\":\"STOP\",\"index\":0,\"groundingMetadata\":{\"webSearchQueries\":[\"ping\"]}}],\"usageMetadata\":{\"promptTokenCount\":18,\"candidatesTokenCount\":7,\"totalTokenCount\":57},\"modelVersion\":\"m-cap\"}\r\n\r\n",
);

/// What 1.5.5 relayed for that cell to an OpenAI chat client that asked for
/// `stream_options.include_usage`, verbatim from `golden/1.5.5` (`/steps/0/body/text`; the oracle
/// masks the chunk id as `<ID>` and `created` as 0). The usage chunk reports the counters Google
/// itemized: 18 prompt, 7 completion, 25 total.
const GROUNDED_STREAM_155: &str = concat!(
    "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null,\"index\":0}],\"created\":0,\"id\":\"chatcmpl-<ID>\",\"model\":\"m-cap\",\"object\":\"chat.completion.chunk\"}\n\n",
    "data: {\"choices\":[{\"delta\":{\"content\":\"po\"},\"finish_reason\":null,\"index\":0}],\"created\":0,\"id\":\"chatcmpl-<ID>\",\"model\":\"m-cap\",\"object\":\"chat.completion.chunk\"}\n\n",
    "data: {\"choices\":[{\"delta\":{\"content\":\"ng\"},\"finish_reason\":null,\"index\":0}],\"created\":0,\"id\":\"chatcmpl-<ID>\",\"model\":\"m-cap\",\"object\":\"chat.completion.chunk\"}\n\n",
    "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\",\"index\":0}],\"created\":0,\"id\":\"chatcmpl-<ID>\",\"model\":\"m-cap\",\"object\":\"chat.completion.chunk\"}\n\n",
    "data: {\"choices\":[],\"created\":0,\"id\":\"chatcmpl-<ID>\",\"model\":\"m-cap\",\"object\":\"chat.completion.chunk\",\"usage\":{\"completion_tokens\":7,\"prompt_tokens\":18,\"total_tokens\":25}}\n\n",
    "data: [DONE]\n\n",
);

/// The oracle's two masks, and nothing else: every `"id":"chatcmpl-…"` value becomes `<ID>` and
/// every `"created":N` becomes 0. Every other byte is compared as relayed.
fn mask_chunk_identity(out: &str) -> String {
    fn mask_after(s: &str, key: &str, stop: fn(char) -> bool, with: &str) -> String {
        let mut rest = s;
        let mut masked = String::with_capacity(s.len());
        while let Some(at) = rest.find(key) {
            let (head, tail) = rest.split_at(at + key.len());
            masked.push_str(head);
            masked.push_str(with);
            rest = &tail[tail.find(stop).unwrap_or(tail.len())..];
        }
        masked.push_str(rest);
        masked
    }
    let ids = mask_after(out, "\"id\":\"chatcmpl-", |c| c == '"', "<ID>");
    mask_after(&ids, "\"created\":", |c| !c.is_ascii_digit(), "0")
}

/// Relay the grounded stream to an OpenAI chat client that opted into the usage chunk.
fn relay_grounded_stream() -> (String, busbar_contract::billing::TokenUsage) {
    let mut t = crate::codec::proto_stream::StreamTranslate::new("openai", "gemini")
        .expect("openai ingress over a gemini egress");
    t.set_client_include_usage(true);
    let mut out = t.feed(GROUNDED_STREAM.as_bytes());
    out.extend(t.finish());
    let billed = t
        .usage()
        .expect("the stream's usage is captured for billing")
        .to_token_usage();
    (
        mask_chunk_identity(&String::from_utf8(out).expect("utf8")),
        billed,
    )
}

/// THE LEDGER AND THE RELAYED BYTES BOTH CARRY WHAT GOOGLE ITEMIZED (oracle cell
/// `usage.gemini|stream-grounded|no-tool-use-count`). The final frame states `totalTokenCount` 57
/// against 18 prompt + 7 candidates; the 32-token gap is reported, never ledgered, so the turn
/// ledgers 18 in + 7 out (what 1.5.5 billed) and the client receives exactly the 1.5.5 stream: its
/// usage chunk reports 7 completion, 25 total.
#[test]
fn a_grounded_stream_relays_the_155_bytes_and_ledgers_the_itemized_counts() {
    let (relayed, ledgered) = relay_grounded_stream();
    assert_eq!(
        relayed, GROUNDED_STREAM_155,
        "the relayed stream is 1.5.5's"
    );
    assert_eq!((ledgered.input, ledgered.output), (18, 7));
}

/// THE RED ARM: the pin above is not vacuous. The stream b8605a388 relayed (the total's remainder
/// folded into the client's usage chunk: 39 completion, 57 total) differs from 1.5.5's after the
/// same masks, and the relay today does not produce it.
#[test]
fn a_grounded_stream_never_relays_the_totals_remainder() {
    let leaked = GROUNDED_STREAM_155.replace(
        "\"usage\":{\"completion_tokens\":7,\"prompt_tokens\":18,\"total_tokens\":25}",
        "\"usage\":{\"completion_tokens\":39,\"prompt_tokens\":18,\"total_tokens\":57}",
    );
    assert_ne!(
        leaked, GROUNDED_STREAM_155,
        "the fixture names the usage chunk"
    );
    assert_ne!(
        mask_chunk_identity(&leaked),
        GROUNDED_STREAM_155,
        "the masks never hide a usage count"
    );
    let (relayed, _) = relay_grounded_stream();
    assert_ne!(relayed, leaked, "the total's remainder reached the client");
    assert!(
        relayed.contains("\"completion_tokens\":7,")
            && !relayed.contains("\"completion_tokens\":39"),
        "{relayed}"
    );
}

/// What each `usageMetadata` count IS, per Google's own usage semantics, as the meter-class move
/// one more reported token makes: (input, cache read, output). Prompt and the tool-use prompt are
/// input; the cached slice moves a prompt token into the cache-read class; candidates and thoughts
/// are output. `totalTokenCount` is Google's sum of the others, never a unit of its own.
const GEMINI_COUNT_CLASSES: &[(&str, (i64, i64, i64))] = &[
    ("promptTokenCount", (1, 0, 0)),
    ("cachedContentTokenCount", (-1, 1, 0)),
    ("toolUsePromptTokenCount", (1, 0, 0)),
    ("candidatesTokenCount", (0, 0, 1)),
    ("thoughtsTokenCount", (0, 0, 1)),
];

/// EVERY COUNT GOOGLE REPORTS IS LEDGERED, IN ITS OWN CLASS (owner 2026-10-02: ledger what the plane
/// reports; fix Gemini ledging). The census is the pinned wire lock
/// (`testing/llm-conformance/wire/gemini.wire.json`): every integer member of `usageMetadata` must
/// have a declared class above, and reporting 7 more of it must move the ledgered units by exactly
/// that class on the buffered and the truncated-recovery read. RED when the reader drops a count
/// (a usage-table row removed), mis-classes one, or the lock gains a count nobody classed.
#[test]
fn every_usage_count_in_the_wire_lock_is_ledgered_in_its_class() {
    let lock_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/llm-conformance/wire/gemini.wire.json");
    let lock: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&lock_path).expect("the pinned gemini wire lock"),
    )
    .expect("wire lock json");
    let counts: Vec<&str> = lock["response"]
        .as_object()
        .expect("response paths")
        .iter()
        .filter(|(_, v)| v["type"] == "integer")
        .filter_map(|(k, _)| k.strip_prefix("usageMetadata."))
        .filter(|f| !f.contains('.') && !f.contains('['))
        .filter(|f| *f != "totalTokenCount")
        .collect();
    assert_eq!(
        counts.len(),
        GEMINI_COUNT_CLASSES.len(),
        "the lock's usageMetadata counts {counts:?} each need exactly one class"
    );
    let ledger = |usage: serde_json::Value| -> [(i64, i64, i64); 2] {
        let body = serde_json::json!({
            "candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": "STOP"}],
            "usageMetadata": usage
        });
        let units = |u: busbar_contract::billing::TokenUsage| {
            let n = |x: u64| i64::try_from(x).expect("small fixture");
            (n(u.input), n(u.cache_read.unwrap_or(0)), n(u.output))
        };
        let buffered = Protocol::gemini()
            .reader()
            .read_response(&body)
            .expect("read")
            .usage
            .to_token_usage();
        let recovered = Protocol::gemini()
            .reader()
            .recover_truncated_usage(body.to_string().as_bytes())
            .expect("the trailing usageMetadata is recoverable");
        [units(buffered), units(recovered)]
    };
    let base = serde_json::json!({"promptTokenCount": 1000, "candidatesTokenCount": 100});
    let before = ledger(base.clone());
    for field in counts {
        let (_, (di, dc, dout)) = GEMINI_COUNT_CLASSES
            .iter()
            .find(|(f, _)| *f == field)
            .unwrap_or_else(|| {
                panic!("`usageMetadata.{field}` is in the wire lock with no meter class")
            });
        let mut usage = base.clone();
        let was = usage[field].as_u64().unwrap_or(0);
        usage[field] = serde_json::json!(was + 7);
        let after = ledger(usage);
        for (path, (b, a)) in ["buffered", "truncated"]
            .iter()
            .zip(before.iter().zip(after.iter()))
        {
            assert_eq!(
                (a.0 - b.0, a.1 - b.1, a.2 - b.2),
                (7 * di, 7 * dc, 7 * dout),
                "{path}: 7 more `{field}` must move (input, cache read, output) by its class"
            );
        }
    }
}

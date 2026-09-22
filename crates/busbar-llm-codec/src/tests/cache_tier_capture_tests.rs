// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CACHE-TIER READ TESTS, ANCHORED TO REAL CAPTURED UPSTREAM BODIES.
//!
//! Every test in this file starts from a body that was RECORDED off a real upstream exchange and
//! is committed in this repo — the shadow oracle's signed-off 1.5.5 golden
//! (`testing/shadow-oracle/golden/1.5.5/cells/`) and the llm-conformance recordings
//! (`testing/llm-conformance/fixtures/`). Nothing here invents a `usage` shape.
//!
//! WHY THAT MATTERS MORE THAN USUAL HERE. The defect these tests pin was *not* "the reader
//! mis-parses a field": it was "the reader never looked at a field the provider really sends", and
//! a hand-written fixture cannot distinguish those two. If the field path in this file were wrong,
//! a hand-rolled JSON literal would still make the assertion pass — it would be testing the test.
//! Loading the recorded body and asserting the path EXISTS IN IT first is what makes the rest of
//! each test mean something: the capture is the evidence that this is the shape upstream emits, and
//! the reader assertion is the evidence that busbar reads it.
//!
//! WHY THE COUNTS ARE THEN VARIED. The recorded corpus is a *no-cache* corpus — every capture is a
//! turn where caching was inactive, so every tier count in it is `0` or absent. A zero cannot tell a
//! reader that reads the field from a reader that does not. So each test does two things in order:
//!
//! 1. asserts the tier member is present in the RECORDED body at the exact path the reader uses
//!    (and that busbar reads that recorded body without inventing a count); then
//! 2. re-reads the SAME recorded body with that one member set to the non-zero count the provider
//!    reports when caching IS active, and asserts the count lands in the right IR tier.
//!
//! The shape is never hand-made; only the magnitude is, and the magnitude is the one thing a
//! no-cache recording cannot supply.
//!
//! WHAT IS BEING PROVEN, PER PROVIDER:
//! * bedrock — `usage.cacheDetails[]`, the per-TTL (`5m`/`1h`) breakdown of `cacheWriteInputTokens`.
//!   The two TTLs price differently, so the total alone cannot be reconciled per line.
//! * cohere — `usage.cached_tokens`, a prompt-cache HIT, which must price at the cache-READ tier
//!   rather than the full input rate.
//! * openai_responses — `usage.input_tokens_details.cache_write_tokens`, which must price at the
//!   cache-WRITE tier. The Responses WRITER has always emitted this member; the reader never read it
//!   back, so the pair was asymmetric and the tokens silently fell to the plain input rate.
//! * openai_chat — `usage.prompt_tokens_details.cache_write_tokens`, same tier, same argument.
//! * cohere (truncated recovery) — the recovery path and the buffered path must bill the SAME
//!   bucket for the same completion.

use crate::bedrock::{BedrockReader, BedrockWriter};
use crate::cohere::CohereReader;
use crate::ir::{IrStreamEvent, StreamDecodeState};
use crate::openai_chat::OpenAiReader;
use crate::openai_responses::ResponsesReader;
use crate::proto_codec::{ProtocolReader, ProtocolWriter};
use serde_json::{json, Value};

/// Pull the usage off the one `MessageDelta` a terminal stream frame must emit.
///
/// Every dialect ends a stream with `MessageDelta{usage} → MessageStop`; this is where the streamed
/// answer to "what did this turn cost" lives, and asserting it beside the buffered answer is what
/// stops a tier from being reconcilable at `stream: false` and gone at `stream: true`.
fn terminal_usage(events: &[IrStreamEvent]) -> &crate::ir::IrUsage {
    events
        .iter()
        .find_map(|e| match e {
            IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .unwrap_or_else(|| panic!("the terminal frame must emit a MessageDelta carrying usage: {events:?}"))
}

// ── the capture loaders ─────────────────────────────────────────────────────────────────────────

/// The workspace root, derived from this crate's manifest dir (`crates/busbar-llm-codec`).
///
/// The recordings deliberately live OUTSIDE this crate: they are the property of the oracle and the
/// conformance rig, which record them against a real binary. Copying them in here would fork the
/// evidence, and a forked capture is a capture that can quietly stop matching what was recorded.
fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root is two levels above this crate")
}

/// Load the RESPONSE BODY busbar returned in a recorded shadow-oracle golden cell.
///
/// These cells are the signed-off 1.5.5 recording — the reference the money oracle itself diffs
/// against — so the `usage` object inside one is a real recorded provider usage object, not a
/// specimen someone typed. Panics loudly (naming the path) rather than skipping: a test that
/// silently no-ops when its evidence is missing is worse than no test.
fn oracle_cell_body(cell: &str) -> Value {
    let path = workspace_root()
        .join("testing/shadow-oracle/golden/1.5.5/cells")
        .join(format!("{cell}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("recorded oracle cell {} is missing ({e})", path.display()));
    let cell: Value = serde_json::from_str(&text).expect("a recorded cell is JSON");
    cell.pointer("/body/json")
        .unwrap_or_else(|| panic!("recorded cell has no /body/json: {cell}"))
        .clone()
}

/// Load a raw RECORDED UPSTREAM BODY from the llm-conformance fixtures — the bytes exactly as they
/// came off the wire, before any normalization. This is the strongest evidence in the tree: it is
/// the upstream's own response, not busbar's rendering of it.
fn conformance_raw_body(recording: &str, cell: &str) -> String {
    let path = workspace_root()
        .join("testing/llm-conformance/fixtures")
        .join(recording)
        .join("raw")
        .join(cell)
        .join("body");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("recorded raw body {} is missing ({e})", path.display()))
}

/// Set one nested member on a copy of a recorded body, returning the copy.
///
/// The ONLY mutation any test here performs: the recorded corpus is a no-cache corpus, so the tier
/// members it carries are `0`/absent and cannot discriminate a reader that reads them from one that
/// does not. The PATH is always one the recorded body already proved exists (each test asserts that
/// first); only the magnitude is supplied.
fn with_member(body: &Value, pointer: &str, value: Value) -> Value {
    let mut out = body.clone();
    // Walk/create the parents so a member the no-cache capture omits entirely can still be set.
    let parts: Vec<&str> = pointer.trim_start_matches('/').split('/').collect();
    let (last, parents) = parts.split_last().expect("a non-empty pointer");
    let mut cursor = &mut out;
    for p in parents {
        cursor = cursor
            .as_object_mut()
            .expect("a JSON object on the path")
            .entry((*p).to_string())
            .or_insert_with(|| json!({}));
    }
    cursor
        .as_object_mut()
        .expect("a JSON object at the leaf's parent")
        .insert((*last).to_string(), value);
    out
}

// ── bedrock: usage.cacheDetails[] is the per-TTL split of cacheWriteInputTokens ──────────────────

/// The recorded Bedrock Converse body is the shape the reader must handle, and busbar must not
/// invent a TTL split for a turn that reported none.
///
/// The `cacheDetails` member is documented as "Empty if no cache creation occurred", and this
/// recording is a no-cache turn — so `None` (NOT `Some(0)`) is the correct read, and asserting it
/// here is what stops a future "fix" from back-filling a fabricated zero tier onto every response.
#[test]
fn bedrock_recorded_no_cache_turn_invents_no_ttl_split() {
    let body = oracle_cell_body("llm__bedrock__bedrock__request__ok");
    assert!(
        body.pointer("/usage/inputTokens").is_some(),
        "the recorded bedrock cell must carry a Converse usage object: {body}"
    );
    assert!(
        body.pointer("/usage/cacheDetails").is_none(),
        "this recording is the NO-CACHE turn the tier test varies from; if it ever starts \
         carrying cacheDetails, use it directly instead of the varied copy: {body}"
    );

    let ir = BedrockReader.read_response(&body).expect("bedrock parses");
    assert_eq!(
        ir.usage.detail.cache_creation_5m_input_tokens, None,
        "a turn that reported no cache creation must report no 5m tier (None, never Some(0))"
    );
    assert_eq!(
        ir.usage.detail.cache_creation_1h_input_tokens, None,
        "a turn that reported no cache creation must report no 1h tier (None, never Some(0))"
    );
}

/// `usage.cacheDetails[]` → the IR's 5m/1h tiers, and back onto the Bedrock wire (1h before 5m).
///
/// The service model types `TokenUsage.cacheDetails` as "Detailed breakdown of cache writes by TTL
/// … Sorted by TTL duration (1h before 5m)", each entry a `{ttl, inputTokens}`. The two TTLs are
/// PRICED DIFFERENTLY, so reading only the `cacheWriteInputTokens` total leaves a bill that
/// reconciles in aggregate and cannot be reconciled per line — which is the failure this pins.
#[test]
fn bedrock_cache_details_ttl_split_reaches_the_ir_and_the_wire() {
    let recorded = oracle_cell_body("llm__bedrock__bedrock__request__ok");
    // The same recorded body, on a turn where caching WAS active. 20 + 10 == the write total, as a
    // real breakdown does.
    let body = with_member(
        &with_member(&recorded, "/usage/cacheWriteInputTokens", json!(30)),
        "/usage/cacheDetails",
        json!([
            {"ttl": "1h", "inputTokens": 20},
            {"ttl": "5m", "inputTokens": 10}
        ]),
    );

    let ir = BedrockReader.read_response(&body).expect("bedrock parses");
    assert_eq!(
        ir.usage.cache_creation_input_tokens,
        Some(30),
        "the write TOTAL still reads as it always did: {ir:?}"
    );
    assert_eq!(
        ir.usage.detail.cache_creation_1h_input_tokens,
        Some(20),
        "the 1h slice must land in cache_creation_1h_input_tokens: {ir:?}"
    );
    assert_eq!(
        ir.usage.detail.cache_creation_5m_input_tokens,
        Some(10),
        "the 5m slice must land in cache_creation_5m_input_tokens: {ir:?}"
    );

    let w = BedrockWriter;
    let out = w.write_response(&ir);
    assert_eq!(
        out.pointer("/usage/cacheDetails"),
        Some(&json!([
            {"ttl": "1h", "inputTokens": 20},
            {"ttl": "5m", "inputTokens": 10}
        ])),
        "the split must re-emit natively, 1h before 5m as the service model documents: {out}"
    );
}

/// The STREAM reports the same split the buffered response does.
///
/// A tier that is reconcilable at `stream: false` and gone at `stream: true` is the same bill
/// answering two ways depending on a transport flag, which is the recurring shape of every
/// attribution defect in this crate.
#[test]
fn bedrock_cache_details_ride_the_stream_metadata_frame() {
    let mut state = StreamDecodeState::default();
    let events = BedrockReader.read_response_events(
        "",
        &json!({
            "type": "metadata",
            "usage": {
                "inputTokens": 11, "outputTokens": 7,
                "cacheWriteInputTokens": 30,
                "cacheDetails": [{"ttl": "1h", "inputTokens": 20}, {"ttl": "5m", "inputTokens": 10}]
            }
        }),
        &mut state,
    );
    let usage = terminal_usage(&events);
    assert_eq!(
        usage.detail.cache_creation_1h_input_tokens,
        Some(20),
        "the streamed 1h slice must match the buffered one: {usage:?}"
    );
    assert_eq!(
        usage.detail.cache_creation_5m_input_tokens,
        Some(10),
        "the streamed 5m slice must match the buffered one: {usage:?}"
    );
}

// ── cohere: usage.cached_tokens prices at the cache-READ tier ────────────────────────────────────

/// The RAW RECORDED Cohere upstream body — the bytes off the wire — is the shape the reader handles,
/// and a turn with no cache hit must not acquire an invented cache-read count.
#[test]
fn cohere_recorded_raw_body_reads_without_inventing_a_cache_read() {
    let raw = conformance_raw_body("selftest-recording", "llm__cohere__cohere__request__ok");
    let body: Value = serde_json::from_str(&raw).expect("the recorded raw body is JSON");
    assert!(
        body.pointer("/usage/tokens/input_tokens").is_some(),
        "the recorded cohere body must carry the raw `tokens` bucket: {body}"
    );
    assert!(
        body.pointer("/usage/billed_units/input_tokens").is_some(),
        "the recorded cohere body must carry the separately-metered `billed_units` bucket: {body}"
    );

    let ir = CohereReader.read_response(&body).expect("cohere parses");
    assert_eq!(
        ir.usage.cache_read_input_tokens, None,
        "a turn that reported no cache hit must report no cache read (None, never Some(0))"
    );
}

/// `usage.cached_tokens` → `cache_read_input_tokens`, with `input_tokens` normalized to the UNCACHED
/// remainder.
///
/// Cohere reports prompt-cache hits on `ApiMeta` beside `tokens`/`billed_units`: prompt tokens
/// counted INSIDE `tokens.input_tokens` that the model did not have to process. Hardcoded `None`,
/// every one of them was billed at the full input rate. The IR keeps `input_tokens` uncached and the
/// cache fields ADDITIVE, so the pair reconstructs the reported total exactly — the TOTAL does not
/// move, only the tier the cached share prices at.
#[test]
fn cohere_cached_tokens_price_at_the_cache_read_tier() {
    let raw = conformance_raw_body("selftest-recording", "llm__cohere__cohere__request__ok");
    let recorded: Value = serde_json::from_str(&raw).expect("the recorded raw body is JSON");
    let reported_input = recorded
        .pointer("/usage/tokens/input_tokens")
        .and_then(Value::as_u64)
        .expect("the recording states an input total");
    // The same recorded turn, with a prompt-cache hit on it.
    let body = with_member(&recorded, "/usage/cached_tokens", json!(4));

    let ir = CohereReader.read_response(&body).expect("cohere parses");
    assert_eq!(
        ir.usage.cache_read_input_tokens,
        Some(4),
        "cached_tokens must read into cache_read_input_tokens: {ir:?}"
    );
    assert_eq!(
        ir.usage.input_tokens,
        reported_input - 4,
        "input_tokens must normalize to the UNCACHED remainder: {ir:?}"
    );
    assert_eq!(
        ir.usage.input_tokens + ir.usage.cache_read_input_tokens.unwrap_or(0),
        reported_input,
        "the two ADDITIVE fields must reconstruct the reported total exactly — only the tier moves"
    );
}

/// The STREAM terminal (`message-end.delta.usage`) prices the cache hit the same way the buffered
/// response does.
#[test]
fn cohere_cached_tokens_ride_the_stream_terminal() {
    let mut state = StreamDecodeState::default();
    let events = CohereReader.read_response_events(
        "",
        &json!({
            "type": "message-end",
            "delta": {
                "finish_reason": "COMPLETE",
                "usage": {
                    "tokens": {"input_tokens": 11, "output_tokens": 7},
                    "billed_units": {"input_tokens": 11, "output_tokens": 7},
                    "cached_tokens": 4
                }
            }
        }),
        &mut state,
    );
    let usage = terminal_usage(&events);
    assert_eq!(
        usage.cache_read_input_tokens,
        Some(4),
        "the streamed cache hit must price at the cache-read tier too: {usage:?}"
    );
    assert_eq!(
        usage.input_tokens, 7,
        "the streamed input total must normalize to the uncached remainder: {usage:?}"
    );
}

// ── cohere: the truncated-recovery path bills the same bucket as the buffered path ───────────────

/// ONE COMPLETION, ONE INVOICE — whichever path read it.
///
/// Cohere reports usage TWICE: a raw `tokens` bucket and a separately-metered `billed_units` bucket,
/// and `IrUsage::to_token_usage` lets the BILLED counts win for the reserved input/output tiers
/// because those are the counts an operator is actually invoiced on. The buffered and stream paths
/// both read `billed_units`; `recover_truncated_usage` read only `tokens`. So the same completion
/// billed two different figures, and which one you got was decided by nothing but whether the
/// response tail fit the reassembly cap.
///
/// The body is the RECORDED upstream body with the two buckets made to DISAGREE — in the recording
/// they are equal, which is exactly the case that cannot tell the two readings apart.
#[test]
fn cohere_truncated_recovery_bills_the_same_bucket_as_the_buffered_path() {
    let raw = conformance_raw_body("selftest-recording", "llm__cohere__cohere__request__ok");
    let recorded: Value = serde_json::from_str(&raw).expect("the recorded raw body is JSON");
    assert_eq!(
        recorded.pointer("/usage/billed_units/input_tokens"),
        recorded.pointer("/usage/tokens/input_tokens"),
        "the recording has the two buckets EQUAL, which is why this test must make them differ"
    );

    // The same body, on a turn where Cohere's billed attribution differs from the raw count — the
    // ordinary case for a short request (billed_units carries a minimum charge).
    let body = with_member(
        &with_member(&recorded, "/usage/billed_units/input_tokens", json!(25)),
        "/usage/billed_units/output_tokens",
        json!(13),
    );

    // The buffered path.
    let buffered = CohereReader
        .read_response(&body)
        .expect("cohere parses")
        .usage
        .to_token_usage();

    // The truncated-recovery path: the same bytes, arriving as a TAIL the reassembler could only
    // salvage the usage object from.
    let tail = serde_json::to_vec(&body).expect("serializes");
    let recovered = CohereReader
        .recover_truncated_usage(&tail)
        .expect("the usage object is recoverable from the tail");

    assert_eq!(
        recovered, buffered,
        "one completion must produce ONE invoice: the truncated-recovery path and the buffered \
         path must ledger identical counts.\n  recovered: {recovered:?}\n   buffered: {buffered:?}"
    );
    assert_eq!(
        buffered.input, 25,
        "and the bucket they agree on is the BILLED one (25), not the raw count: {buffered:?}"
    );
    assert_eq!(
        buffered.output, 13,
        "the billed output attribution must win over the raw count too: {buffered:?}"
    );
}

// ── openai_responses: input_tokens_details.cache_write_tokens prices at the cache-WRITE tier ─────

/// The recorded Responses body PROVES the member exists — and proves the reader/writer asymmetry.
///
/// `usage.input_tokens_details.cache_write_tokens` is in the recorded 1.5.5 golden because busbar's
/// own Responses WRITER has always emitted it (the pinned `ResponseUsage` schema requires the
/// member). The reader never read it back. That asymmetry is the defect: a Responses body stating a
/// cache write was re-emitted with its total intact and its write count zeroed, so the tokens
/// silently moved from the cache-write tier to the plain input rate.
#[test]
fn responses_recorded_body_carries_the_cache_write_member() {
    let body = oracle_cell_body("llm__responses__responses__request__ok");
    assert!(
        body.pointer("/usage/input_tokens_details/cache_write_tokens")
            .is_some(),
        "the recorded Responses cell must carry input_tokens_details.cache_write_tokens — it is \
         the member the writer emits and the reader must read back: {body}"
    );

    let ir = ResponsesReader.read_response(&body).expect("responses parses");
    assert_eq!(
        ir.usage.cache_creation_input_tokens,
        Some(0),
        "the recording REPORTS zero cache writes, so the IR must say `reported zero` (Some(0)), \
         not `not reported` (None): {ir:?}"
    );
}

/// `usage.input_tokens_details.cache_write_tokens` → the IR's ADDITIVE `cache_creation_input_tokens`,
/// with `input_tokens` normalized to the uncached remainder.
///
/// The Responses `input_tokens` is a TOTAL: uncached + cached + cache-write. Leaving the write slice
/// inside it charged the whole cache-writing turn at the plain input rate.
#[test]
fn responses_cache_write_tokens_price_at_the_cache_write_tier() {
    let recorded = oracle_cell_body("llm__responses__responses__request__ok");
    let reported_input = recorded
        .pointer("/usage/input_tokens")
        .and_then(Value::as_u64)
        .expect("the recording states an input total");
    // The same recorded turn, on a request that wrote to the cache and read from it.
    let body = with_member(
        &with_member(
            &recorded,
            "/usage/input_tokens_details/cache_write_tokens",
            json!(6),
        ),
        "/usage/input_tokens_details/cached_tokens",
        json!(2),
    );

    let ir = ResponsesReader.read_response(&body).expect("responses parses");
    assert_eq!(
        ir.usage.cache_creation_input_tokens,
        Some(6),
        "cache_write_tokens must land in the IR's cache-WRITE bucket: {ir:?}"
    );
    assert_eq!(
        ir.usage.cache_read_input_tokens,
        Some(2),
        "cached_tokens must stay in the cache-READ bucket: {ir:?}"
    );
    assert_eq!(
        ir.usage.input_tokens,
        reported_input - 6 - 2,
        "input_tokens must normalize to the UNCACHED remainder: {ir:?}"
    );
    assert_eq!(
        ir.usage.billable_tokens(),
        reported_input + ir.usage.output_tokens,
        "the three ADDITIVE input fields must still sum to the provider's stated total — the TOTAL \
         does not move, only which tier each share prices at"
    );
}

/// The STREAM terminal (`response.completed`) prices the cache write the same way.
#[test]
fn responses_cache_write_tokens_ride_the_stream_terminal() {
    let mut state = StreamDecodeState::default();
    let events = ResponsesReader.read_response_events(
        "response.completed",
        &json!({
            "type": "response.completed",
            "sequence_number": 1,
            "response": {
                "id": "resp_oracle", "object": "response", "status": "completed",
                "output": [],
                "usage": {
                    "input_tokens": 11, "output_tokens": 7, "total_tokens": 18,
                    "input_tokens_details": {"cached_tokens": 2, "cache_write_tokens": 6},
                    "output_tokens_details": {"reasoning_tokens": 0}
                }
            }
        }),
        &mut state,
    );
    let usage = terminal_usage(&events);
    assert_eq!(
        usage.cache_creation_input_tokens,
        Some(6),
        "the streamed cache write must price at the cache-write tier too: {usage:?}"
    );
    assert_eq!(
        usage.input_tokens, 3,
        "the streamed input total must normalize to the uncached remainder (11-2-6): {usage:?}"
    );
}

// ── openai_chat: prompt_tokens_details.cache_write_tokens prices at the cache-WRITE tier ─────────

/// The recorded Chat Completions body is the shape the reader handles, and a turn that reported no
/// cache detail at all must not acquire an invented one.
#[test]
fn openai_chat_recorded_body_invents_no_cache_write() {
    let body = oracle_cell_body("llm__openai__openai__request__ok");
    assert!(
        body.pointer("/usage/prompt_tokens").is_some(),
        "the recorded chat cell must carry a CompletionUsage object: {body}"
    );
    assert!(
        body.pointer("/usage/prompt_tokens_details").is_none(),
        "this recording reports NO prompt_tokens_details at all; if it ever starts to, use it \
         directly instead of the varied copy: {body}"
    );

    let ir = OpenAiReader.read_response(&body).expect("chat parses");
    assert_eq!(
        ir.usage.cache_creation_input_tokens, None,
        "a turn that reported no cache detail must report no cache write (None, never Some(0))"
    );
}

/// `usage.prompt_tokens_details.cache_write_tokens` → the IR's ADDITIVE `cache_creation_input_tokens`.
///
/// `CompletionUsage.prompt_tokens_details.cache_write_tokens` is "the number of prompt tokens written
/// to cache" — a SLICE of `prompt_tokens`, priced at its own tier, distinct from both the plain input
/// rate and the cache-READ rate. The reader hardcoded `None` with the comment "OpenAI doesn't provide
/// this split"; it does, and the whole write was billed as ordinary input.
#[test]
fn openai_chat_cache_write_tokens_price_at_the_cache_write_tier() {
    let recorded = oracle_cell_body("llm__openai__openai__request__ok");
    let reported_prompt = recorded
        .pointer("/usage/prompt_tokens")
        .and_then(Value::as_u64)
        .expect("the recording states a prompt total");
    // The same recorded turn, on a request that wrote to the cache and read from it.
    let body = with_member(
        &with_member(
            &recorded,
            "/usage/prompt_tokens_details/cache_write_tokens",
            json!(6),
        ),
        "/usage/prompt_tokens_details/cached_tokens",
        json!(2),
    );

    let ir = OpenAiReader.read_response(&body).expect("chat parses");
    assert_eq!(
        ir.usage.cache_creation_input_tokens,
        Some(6),
        "cache_write_tokens must land in the IR's cache-WRITE bucket: {ir:?}"
    );
    assert_eq!(
        ir.usage.cache_read_input_tokens,
        Some(2),
        "cached_tokens must stay in the cache-READ bucket: {ir:?}"
    );
    assert_eq!(
        ir.usage.input_tokens,
        reported_prompt - 6 - 2,
        "input_tokens must normalize to the UNCACHED remainder: {ir:?}"
    );
    assert_eq!(
        ir.usage.billable_tokens(),
        reported_prompt + ir.usage.output_tokens,
        "the three ADDITIVE input fields must still sum to the provider's stated total"
    );
}

/// The STREAM's `include_usage` chunk prices the cache write the same way.
#[test]
fn openai_chat_cache_write_tokens_ride_the_usage_chunk() {
    let mut state = StreamDecodeState::default();
    let events = OpenAiReader.read_response_events(
        "",
        &json!({
            "id": "chatcmpl-oracle", "object": "chat.completion.chunk", "created": 0,
            "model": "m", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18,
                "prompt_tokens_details": {"cached_tokens": 2, "cache_write_tokens": 6}
            }
        }),
        &mut state,
    );
    let usage = terminal_usage(&events);
    assert_eq!(
        usage.cache_creation_input_tokens,
        Some(6),
        "the streamed cache write must price at the cache-write tier too: {usage:?}"
    );
    assert_eq!(
        usage.input_tokens, 3,
        "the streamed input total must normalize to the uncached remainder (11-2-6): {usage:?}"
    );
}

// ── the money floor: the lanes never sum to more than the provider reported ──────────────────────

/// BUSBAR NEVER CHARGES MORE INPUT THAN THE PROVIDER STATED — including on the Cohere billed path.
///
/// Cohere is the one dialect where a bucket OTHER than `IrUsage::input_tokens` reaches the ledger:
/// `to_token_usage` lets `billed_units.input_tokens` win, because that is the count an operator is
/// invoiced on. That exception was written when Cohere reported no cache accounting at all, so the
/// billed count and a cache read could never both exist and the exception never had to state which
/// convention it followed.
///
/// Reading `usage.cached_tokens` makes them coexist, and the two lanes are summed by the meter. The
/// raw path subtracts the cached prefix out of `input_tokens`; if the billed path does not, a turn
/// Cohere states as 11 input tokens (4 cached) ledgers `input: 11` BESIDE `cache_read: 4` — 15
/// charged for 11 reported. An over-charge is the one error a customer cannot detect from the
/// invoice and busbar cannot undo, so this test pins the floor directly rather than pinning the
/// implementation: whatever the buckets, `input + cache_read` is what the provider said.
#[test]
fn cohere_billed_input_and_cache_read_never_exceed_the_reported_total() {
    let raw = conformance_raw_body("selftest-recording", "llm__cohere__cohere__request__ok");
    let recorded: Value = serde_json::from_str(&raw).expect("the recorded raw body is JSON");
    let reported_input = recorded
        .pointer("/usage/tokens/input_tokens")
        .and_then(Value::as_u64)
        .expect("the recording states an input total");
    // The recorded turn, with a prompt-cache hit on it. `billed_units` is present in the recording
    // already — it is the bucket that wins — so this is the exact coexistence the hazard needs.
    let body = with_member(&recorded, "/usage/cached_tokens", json!(4));

    let ir = CohereReader.read_response(&body).expect("cohere parses");
    assert!(
        ir.usage.detail.billed_input_tokens.is_some(),
        "the recording must carry billed_units for this test to exercise the billed-wins path: {ir:?}"
    );
    let ledgered = ir.usage.to_token_usage();
    assert_eq!(
        ledgered.input + ledgered.cache_read.unwrap_or(0),
        reported_input,
        "the ledgered input lanes must sum to the {reported_input} input tokens Cohere reported, \
         never more — got input={} + cache_read={:?}",
        ledgered.input,
        ledgered.cache_read
    );
    assert_eq!(
        ledgered.cache_read,
        Some(4),
        "and the cached share must still be attributed to the cache-READ tier: {ledgered:?}"
    );
}

/// The netting is SCOPED to the billed path — every other dialect projects exactly as before.
///
/// `billed_input_tokens` is populated by the Cohere reader alone, so a non-Cohere response must
/// take the untouched `unwrap_or(self.input_tokens)` arm. Pinned so a future edit to the projection
/// cannot quietly re-tier five providers while fixing one.
#[test]
fn the_billed_netting_does_not_touch_a_dialect_without_billed_units() {
    let recorded = oracle_cell_body("llm__responses__responses__request__ok");
    let body = with_member(
        &with_member(
            &recorded,
            "/usage/input_tokens_details/cache_write_tokens",
            json!(6),
        ),
        "/usage/input_tokens_details/cached_tokens",
        json!(2),
    );
    let ir = ResponsesReader.read_response(&body).expect("responses parses");
    assert_eq!(
        ir.usage.detail.billed_input_tokens, None,
        "no dialect but Cohere populates the billed bucket: {ir:?}"
    );
    let ledgered = ir.usage.to_token_usage();
    assert_eq!(
        ledgered.input, ir.usage.input_tokens,
        "with no billed bucket the projection is the plain normalized total: {ledgered:?}"
    );
    assert_eq!(
        ledgered.input
            + ledgered.cache_read.unwrap_or(0)
            + ledgered.cache_creation.unwrap_or(0),
        recorded
            .pointer("/usage/input_tokens")
            .and_then(Value::as_u64)
            .expect("stated input"),
        "and the three input-side lanes still reconstruct the provider's stated total: {ledgered:?}"
    );
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADVERSARIAL / HOSTILE-BODY suite for the LLM cross-protocol path (1.6.0).
//!
//! Where the dialect-local `input_hardening_tests.rs` files pin the REQUEST-path present-but-wrong-
//! typed rejects one dialect at a time, this shared file drives the SAME six readers (and the
//! `StreamTranslate` seam) through a HOSTILE-body matrix uniformly, via the neutral `protocol_for` /
//! `Protocol` / `StreamTranslate` surface (the exact production dispatch). Every case asserts the
//! CURRENT, post-hardening contract: a malformed / adversarial input is REFUSED cleanly (a typed
//! `ir_parse` 400) or DEGRADES cleanly (a bounded, uncorrupted IR) — never a panic, a hang, a silent
//! corruption, or an off-enum value leaked onto the wire. It runs single-compile (only ever inside
//! `busbar-core`'s test build), so it names dialects only through the neutral registry — no dialect
//! internals, no `crate::`-absolute cross-protocol reach.
//!
//! Matrix (rows) — each asserted below with the outcome named in the fn doc:
//!   1. non-object top-level body (request + response) ............. clean refusal (ir_parse 400)
//!   2. wrong-typed structural array (choices / output) ........... clean refusal (ir_parse 400)
//!   3. unknown enum value (finish_reason / stop_reason) .......... degrade to `Other`, never leak
//!   4. hostile stream events (u64::MAX index, wrong-typed
//!      delta/usage, empty-type frame, non-object) ............... clean degrade, no panic; index clamped
//!   5. over-deep nested body ..................................... MAX_JSON_DEPTH floor rejects pre-reader
//!   6. truncated SSE stream ..................................... `finish()` terminates; healthy frame kept
//!   7. garbage / non-JSON SSE frames ............................ skipped; healthy frame kept
//!   8. oversized-but-valid body ................................. reads Ok, payload intact
//!
//! Rows 4-8 each carry a POSITIVE outcome as well as the negative one. "Did not panic" / "did not
//! abort" alone is satisfied by a reader that drops every VALID input too, so each of those cases
//! also pins what must still come out: the decoded text delta, the surviving turn text, the exact
//! clamped index.

use super::*;

/// The six chat dialects reachable through the neutral registry.
const DIALECTS: [&str; 6] = [
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "responses",
    "cohere",
];

/// The bounded cap every reader clamps an attacker-controlled block index to
/// (`bedrock::MAX_CONTENT_BLOCK_INDEX`, restated here because it is private to its module; the
/// Anthropic and OpenAI readers clamp to the same 1023 — see `anthropic/mod.rs:544`).
const MAX_BLOCK_INDEX: usize = 1023;

/// A MINIMAL, genuinely-VALID request body in `dialect`'s native shape carrying `text` as the sole
/// user turn. Used by the two "must not panic" cases below, which previously discarded their result
/// (`let _ = …`): with a body that is valid for the dialect being read, the outcome is knowable, so
/// those cases now assert `Ok` and that the text SURVIVED, not merely the absence of a panic.
fn valid_request_body(dialect: &str, text: &str) -> serde_json::Value {
    use serde_json::json;
    match dialect {
        "anthropic" | "openai" | "cohere" => json!({
            "model": "m", "max_tokens": 16,
            "messages": [{"role": "user", "content": text}]
        }),
        "gemini" => json!({"contents": [{"role": "user", "parts": [{"text": text}]}]}),
        "bedrock" => json!({"messages": [{"role": "user", "content": [{"text": text}]}]}),
        "responses" => json!({"model": "m", "input": text}),
        other => panic!("unknown dialect {other}"),
    }
}

/// The concatenated text of the first user turn in `ir` — the payload a reader that silently
/// dropped, truncated or re-encoded the body would fail to reproduce.
fn first_user_text(ir: &crate::ir::IrRequest) -> String {
    ir.messages
        .iter()
        .find(|m| m.role == crate::ir::IrRole::User)
        .map(|m| {
            m.content
                .iter()
                .filter_map(|b| match b {
                    crate::ir::IrBlock::Text { text, .. } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<String>()
        })
        .unwrap_or_default()
}

/// Assert `res` is the canonical structural-parse rejection: `Err` with a client 400 carrying the
/// `ir_parse` signal — the shape busbar renders into the ingress dialect's native 400 envelope.
/// (Same predicate the dialect-local `input_hardening_tests` assert, restated here so this file is
/// self-contained; written without a `T: Debug` bound so it works over `IrRequest`/`IrResponse`.)
fn expect_ir_parse<T>(res: Result<T, IrError>, ctx: &str) {
    match res {
        Ok(_) => panic!("{ctx}: expected a clean ir_parse rejection, got Ok"),
        Err(err) => {
            assert_eq!(err.class, StatusClass::ClientError, "{ctx}: must be a 400");
            assert_eq!(
                err.provider_signal.as_deref(),
                Some(SIGNAL_IR_PARSE),
                "{ctx}: must carry the ir_parse signal"
            );
        }
    }
}

// ── 1. NON-OBJECT TOP-LEVEL BODY ─────────────────────────────────────────────
// Every reader dereferences the body as a JSON object up front. A non-object top-level value
// (string / number / bool / array / null) is structurally impossible for any dialect and MUST be
// refused as a typed 400 — never indexed into, never panicked on.

/// The five non-object JSON shapes an attacker can put at the top level.
fn non_object_bodies() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!("a bare string"),
        serde_json::json!(42),
        serde_json::json!(true),
        serde_json::json!([1, 2, 3]),
        serde_json::Value::Null,
    ]
}

#[test]
fn non_object_top_level_request_body_rejects_every_dialect() {
    for name in DIALECTS {
        let proto = protocol_for(name).expect("known dialect");
        for bad in non_object_bodies() {
            expect_ir_parse(
                proto.reader().read_request(&bad),
                &format!("{name}: non-object top-level request body ({bad})"),
            );
        }
    }
}

#[test]
fn non_object_top_level_response_body_rejects_every_dialect() {
    for name in DIALECTS {
        let proto = protocol_for(name).expect("known dialect");
        for bad in non_object_bodies() {
            expect_ir_parse(
                proto.reader().read_response(&bad),
                &format!("{name}: non-object top-level response body ({bad})"),
            );
        }
    }
}

// ── 2. WRONG-TYPED STRUCTURAL RESPONSE ARRAY ─────────────────────────────────

/// OpenAI Chat's `choices` is a REQUIRED array; a present-but-wrong-typed (or empty) `choices`
/// cannot yield a `choices[0]`, so the reader refuses with a typed 400 rather than index-panic or
/// invent a choice. (The exact class the old lenient tree would have `[0]`-indexed into.)
#[test]
fn openai_wrong_typed_or_empty_choices_response_rejects() {
    let proto = protocol_for("openai").expect("openai");
    for bad in [
        serde_json::json!({"id": "c", "object": "chat.completion", "choices": "nope"}),
        serde_json::json!({"id": "c", "object": "chat.completion", "choices": 7}),
        serde_json::json!({"id": "c", "object": "chat.completion", "choices": {"a": 1}}),
        serde_json::json!({"id": "c", "object": "chat.completion", "choices": []}),
        serde_json::json!({"id": "c", "object": "chat.completion"}), // absent
    ] {
        expect_ir_parse(
            proto.reader().read_response(&bad),
            &format!("openai: wrong-typed/empty/absent choices ({bad})"),
        );
    }
}

/// The Responses reader's terminal is `output`: a `status:"completed"` body whose `output` is
/// present-but-wrong-typed can produce no assistant content, so the reader REFUSES it with a typed
/// `ir_parse` 400 (the same clean-refusal class as OpenAI's `choices`) rather than emit a 200 with
/// silently-empty content that an SDK would read as `output[0]` and index-panic on.
#[test]
fn responses_wrong_typed_output_response_rejects() {
    let proto = protocol_for("responses").expect("responses");
    for bad in [
        serde_json::json!({"id": "r", "object": "response", "status": "completed", "output": "nope"}),
        serde_json::json!({"id": "r", "object": "response", "status": "completed", "output": 5}),
        serde_json::json!({"id": "r", "object": "response", "status": "completed", "output": {"a": 1}}),
    ] {
        expect_ir_parse(
            proto.reader().read_response(&bad),
            &format!("responses: wrong-typed output ({bad})"),
        );
    }
}

// ── 3. UNKNOWN ENUM VALUE (finish_reason / stop_reason) ──────────────────────
// Every dialect's stop-reason map has a `_ => Other` arm. An unknown/invalid terminal enum must
// DEGRADE to `Other` (or, for the Responses `status` vocabulary, to `None`) — never reject a
// valid 200, never carry the raw token forward, and (below) never leak it back onto a foreign wire.

/// Minimal valid assistant response body for `dialect` carrying `stop` as the terminal enum token.
fn native_response_with_stop(dialect: &str, stop: &str) -> serde_json::Value {
    use serde_json::json;
    match dialect {
        "anthropic" => json!({
            "id": "msg_1", "type": "message", "role": "assistant",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": stop, "model": "claude",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }),
        "openai" => json!({
            "id": "chatcmpl-1", "object": "chat.completion", "created": 1_700_000_000u64,
            "model": "gpt-4o",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": stop}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}
        }),
        "gemini" => json!({
            "candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": stop}],
            "modelVersion": "gemini-pro",
            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
        }),
        "bedrock" => json!({
            "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
            "stopReason": stop, "usage": {"inputTokens": 1, "outputTokens": 1}
        }),
        "cohere" => json!({
            "id": "co_1", "finish_reason": stop,
            "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
            "usage": {"tokens": {"input_tokens": 1, "output_tokens": 1}}
        }),
        other => panic!("unknown dialect {other}"),
    }
}

/// Unknown terminal enum on the five dialects whose terminal is a stop-reason token degrades to
/// `IrStopReason::Other` — a valid 200 body is preserved, the bogus token is normalized, nothing
/// panics.
#[test]
fn unknown_stop_reason_degrades_to_other_not_reject() {
    for dialect in ["anthropic", "openai", "gemini", "bedrock", "cohere"] {
        let proto = protocol_for(dialect).expect("dialect");
        let body = native_response_with_stop(dialect, "TOTALLY_MADE_UP_REASON_9000");
        let ir = proto.reader().read_response(&body).unwrap_or_else(|e| {
            panic!("{dialect}: unknown stop reason must degrade, not reject: {e:?}")
        });
        assert_eq!(
            ir.stop_reason,
            Some(crate::ir::IrStopReason::Other),
            "{dialect}: an unknown terminal enum must degrade to Other; got {:?}",
            ir.stop_reason
        );
    }
}

/// The Responses API's terminal vocabulary is `status`, not a stop-reason token. An unknown status
/// is not a completion signal, so it degrades to `stop_reason: None` (still a clean, valid IR — no
/// reject, no panic).
#[test]
fn responses_unknown_status_degrades_to_none() {
    let proto = protocol_for("responses").expect("responses");
    let body = serde_json::json!({
        "id": "r", "object": "response", "status": "made_up_status",
        "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "hi"}]}],
        "usage": {"input_tokens": 1, "output_tokens": 1}
    });
    let ir = proto
        .reader()
        .read_response(&body)
        .unwrap_or_else(|e| panic!("responses: unknown status must degrade, not reject: {e:?}"));
    assert_eq!(
        ir.stop_reason, None,
        "responses: unknown status carries no stop reason; got {:?}",
        ir.stop_reason
    );
}

/// NO-LEAK across the seam: an unknown upstream stop token, degraded to `Other`, must be written
/// back as a STRICT native enum value for the ingress dialect — never the raw off-enum token a
/// strict client SDK would reject. Drive the real cross-protocol path: anthropic response with a
/// bogus `stop_reason` → IR (`Other`) → OpenAI writer → `finish_reason` is the SDK-safe `stop`, and
/// the bogus token appears NOWHERE in the emitted body.
#[test]
fn unknown_stop_reason_does_not_leak_across_writer() {
    let anth = protocol_for("anthropic").expect("anthropic");
    let bogus = "attacker_controlled_reason";
    let body = native_response_with_stop("anthropic", bogus);
    let ir = anth
        .reader()
        .read_response(&body)
        .expect("degrades to Other");
    assert_eq!(ir.stop_reason, Some(crate::ir::IrStopReason::Other));
    let openai_out = protocol_for("openai")
        .expect("openai")
        .writer()
        .write_response(&ir);
    assert_eq!(
        openai_out["choices"][0]["finish_reason"], "stop",
        "the degraded `Other` must write as the SDK-safe `stop`, not the raw token; got {openai_out}"
    );
    assert!(
        !openai_out.to_string().contains(bogus),
        "the raw off-enum token must NEVER appear in the emitted native body; got {openai_out}"
    );
}

// ── 4. HOSTILE STREAM EVENTS ─────────────────────────────────────────────────
// `read_response_events` is the live translation seam. It must be TOTAL on adversarial frames:
// return a (possibly empty) Vec for any hostile (event_type, data) — never panic, never allocate
// against an attacker-controlled index.

/// The minimal VALID frame sequence that makes `dialect`'s reader emit one `TextDelta("ok")` —
/// the positive control for the hostile battery below. Without it, a reader rewritten as
/// `fn read_response_events(..) -> Vec::new()` (one that dropped every *valid* frame) passes the
/// hostile sweep on all six dialects, because the returned Vec is always empty and the inner match
/// never fires.
fn valid_text_delta_frames(dialect: &str) -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    match dialect {
        "anthropic" => vec![(
            "content_block_delta",
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "ok"}}),
        )],
        "openai" => vec![("", json!({"choices": [{"delta": {"content": "ok"}}]}))],
        "gemini" => vec![(
            "",
            json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "ok"}]}}]}),
        )],
        "bedrock" => vec![
            (
                "messageStart",
                json!({"type": "messageStart", "role": "assistant"}),
            ),
            (
                "contentBlockDelta",
                json!({"type": "contentBlockDelta", "contentBlockIndex": 0, "delta": {"text": "ok"}}),
            ),
        ],
        "responses" => vec![
            (
                "response.created",
                json!({"response": {"object": "response", "status": "in_progress"}}),
            ),
            (
                "response.output_text.delta",
                json!({"output_index": 0, "delta": "ok"}),
            ),
        ],
        "cohere" => vec![
            (
                "",
                json!({"type": "message-start", "delta": {"message": {"role": "assistant"}}}),
            ),
            (
                "",
                json!({"type": "content-start", "index": 0, "delta": {"message": {"content": {"type": "text", "text": ""}}}}),
            ),
            (
                "",
                json!({"type": "content-delta", "index": 0, "delta": {"message": {"content": "ok"}}}),
            ),
        ],
        other => panic!("unknown dialect {other}"),
    }
}

/// A battery of hostile de-framed stream events: non-object payloads, wrong-typed deltas/usage, an
/// empty-type frame, and a pathological `u64::MAX` block index. Each is fed through EVERY dialect's
/// `read_response_events` over a fresh decode state: the call must return (no panic), nothing may
/// degrade into a text delta at a pathological index, and — the positive control — the SAME reader
/// must still decode a healthy frame into its text delta, so "no events" can never stand in for
/// "no defect".
#[test]
fn hostile_stream_events_are_total_no_panic_no_bad_index() {
    let hostile: Vec<(&str, serde_json::Value)> = vec![
        // non-object payloads
        ("content_block_delta", serde_json::json!("a bare string")),
        ("message_delta", serde_json::json!(42)),
        ("", serde_json::Value::Null),
        // empty-type frame with an otherwise-plausible body
        ("", serde_json::json!({"delta": {"text": "x"}})),
        // wrong-typed delta
        (
            "content_block_delta",
            serde_json::json!({"type": "content_block_delta", "index": 0, "delta": 12345}),
        ),
        // wrong-typed usage
        (
            "message_delta",
            serde_json::json!({"type": "message_delta", "usage": "not-an-object", "delta": {"stop_reason": "end_turn"}}),
        ),
        // pathological u64::MAX index across the various shapes readers key on
        (
            "content_block_delta",
            serde_json::json!({"type": "content_block_delta", "index": u64::MAX, "delta": {"type": "text_delta", "text": "boom"}}),
        ),
        (
            "contentBlockDelta",
            serde_json::json!({"type": "contentBlockDelta", "contentBlockIndex": u64::MAX, "delta": {"text": "boom"}}),
        ),
        (
            "",
            serde_json::json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": u64::MAX, "id": "t", "function": {"name": "f", "arguments": "{}"}}]}}]}),
        ),
    ];

    for name in DIALECTS {
        let proto = protocol_for(name).expect("dialect");
        let mut state = crate::ir::StreamDecodeState::default();
        for (et, data) in &hostile {
            // Simulate the production event-stream decoder folding `:event-type` into `data["type"]`
            // for the eventstream (bedrock) transport, matching the sibling stream tests.
            let mut data = data.clone();
            if !et.is_empty() {
                if let Some(obj) = data.as_object_mut() {
                    obj.entry("type")
                        .or_insert_with(|| serde_json::Value::String((*et).to_string()));
                }
            }
            // The call itself is the assertion: a panic here fails the test.
            let events = proto.reader().read_response_events(et, &data, &mut state);
            // No hostile frame may surface a text delta at a pathological (unclamped) index.
            for ev in &events {
                if let crate::ir::IrStreamEvent::BlockDelta {
                    index,
                    delta: crate::ir::IrDelta::TextDelta(_),
                } = ev
                {
                    assert!(
                        *index <= MAX_BLOCK_INDEX,
                        "{name}: a hostile frame produced a text delta at index {index}, past the \
                         {MAX_BLOCK_INDEX} cap every reader clamps to"
                    );
                }
            }
        }

        // POSITIVE CONTROL, same reader, fresh state: a healthy frame sequence must still decode
        // into its text delta. Without this, an empty return for every input passes the sweep.
        let mut ok_state = crate::ir::StreamDecodeState::default();
        let mut healthy: Vec<crate::ir::IrStreamEvent> = Vec::new();
        for (et, data) in valid_text_delta_frames(name) {
            healthy.extend(
                proto
                    .reader()
                    .read_response_events(et, &data, &mut ok_state),
            );
        }
        let texts: Vec<&str> = healthy
            .iter()
            .filter_map(|e| match e {
                crate::ir::IrStreamEvent::BlockDelta {
                    delta: crate::ir::IrDelta::TextDelta(t),
                    ..
                } => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            texts,
            vec!["ok"],
            "{name}: the hostile battery proves nothing unless the same reader still decodes a \
             healthy frame into exactly one TextDelta(\"ok\"); got {healthy:?}"
        );
    }
}

/// Precise clamp proof for Bedrock: a `contentBlockStart` carrying `contentBlockIndex: u64::MAX`
/// (after a `messageStart`) must have its IR `BlockStart` index CLAMPED to the bounded cap
/// (`MAX_CONTENT_BLOCK_INDEX = 1023`), so a downstream per-index writer can never be driven to
/// allocate against `u64::MAX`.
#[test]
fn bedrock_huge_content_block_index_is_clamped() {
    let proto = protocol_for("bedrock").expect("bedrock");
    let mut state = crate::ir::StreamDecodeState::default();
    // Open the message first (BlockStart is guarded behind MessageStart).
    let start = serde_json::json!({"type": "messageStart", "role": "assistant"});
    let _ = proto
        .reader()
        .read_response_events("messageStart", &start, &mut state);
    let hostile = serde_json::json!({
        "type": "contentBlockStart",
        "contentBlockIndex": u64::MAX,
        "start": {"toolUse": {"toolUseId": "t1", "name": "f"}}
    });
    let events = proto
        .reader()
        .read_response_events("contentBlockStart", &hostile, &mut state);
    let block_start_idx = events.iter().find_map(|e| match e {
        crate::ir::IrStreamEvent::BlockStart { index, .. } => Some(*index),
        _ => None,
    });
    // Require the BlockStart to EXIST, and pin the clamped index EXACTLY. Guarded (`if let`), a
    // Bedrock reader that stopped emitting `BlockStart` for `contentBlockStart` — a silent
    // tool-use-stream regression — ran no assertion at all; and `<= 1023` was also satisfied by a
    // clamp changed to `.min(512)`, which would silently renumber every block past 512.
    let idx = block_start_idx
        .expect("bedrock must emit a BlockStart for a contentBlockStart carrying a toolUse");
    assert_eq!(
        idx, MAX_BLOCK_INDEX,
        "bedrock must clamp a u64::MAX contentBlockIndex to exactly the bounded cap; got {idx}"
    );
}

// ── 5. OVER-DEEP NESTED BODY ─────────────────────────────────────────────────

/// The MAX_JSON_DEPTH floor rejects a pathologically-nested body at the PARSE boundary
/// (`busbar_substrate_values::json::parse`) — the single seam every ingress body crosses before a
/// `serde_json::Value` (and therefore any reader recursion, re-serialize, or recursive drop) can be
/// built. A ~10k-deep body (well under the body cap) would otherwise overflow the worker stack and
/// abort the process; here it returns a clean parse `Err` and no `Value` is ever constructed, so no
/// reader is ever handed a deep tree. (Complements `json.rs`'s own guard tests from the reader's
/// vantage: the floor sits BEFORE the reader, not inside it.)
#[test]
fn overdeep_nested_body_rejected_at_parse_before_any_reader() {
    let depth = 10_000usize;
    let mut s = String::with_capacity(depth * 2 + 16);
    s.push_str(r#"{"messages":"#);
    for _ in 0..depth {
        s.push('[');
    }
    for _ in 0..depth {
        s.push(']');
    }
    s.push('}');
    let parsed = busbar_substrate_values::json::parse::<serde_json::Value>(s.as_bytes());
    assert!(
        parsed.is_err(),
        "a body nested past MAX_JSON_DEPTH must be rejected at the parse boundary, before any Value/reader"
    );
    // A realistically-shallow request body still parses AND reads on every dialect (the floor does
    // not over-reject normal traffic).
    let ok_body =
        br#"{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}"#;
    let value = busbar_substrate_values::json::parse::<serde_json::Value>(ok_body)
        .expect("shallow body parses");
    assert!(
        value.is_object(),
        "the shallow control body must parse into an object"
    );
    for name in DIALECTS {
        // Each dialect is handed a body in ITS OWN native shape, so the outcome is knowable: the
        // read must SUCCEED and the turn text must survive. Discarding the result (`let _ = …`)
        // meant an over-eager depth/size guard that started rejecting normal traffic — the exact
        // over-rejection this half exists to rule out — passed unnoticed.
        let body_bytes = serde_json::to_vec(&valid_request_body(name, "hi")).expect("serialize");
        let native = busbar_substrate_values::json::parse::<serde_json::Value>(&body_bytes)
            .unwrap_or_else(|e| panic!("{name}: a shallow native body must parse: {e:?}"));
        let ir = protocol_for(name)
            .expect("dialect")
            .reader()
            .read_request(&native)
            .unwrap_or_else(|e| {
                panic!("{name}: the depth floor must not reject a normal shallow body: {e:?}")
            });
        assert_eq!(
            first_user_text(&ir),
            "hi",
            "{name}: the user turn must survive the parse boundary intact"
        );
    }
}

// ── 6. TRUNCATED SSE STREAM ──────────────────────────────────────────────────

/// A truncated SSE egress stream (a `data:` frame that never receives its blank-line terminator)
/// must let `StreamTranslate::finish()` TERMINATE — it returns bytes and does not hang or loop.
/// The buffered partial is small (well under `MAX_BUF`), so the translator is not forced to abort;
/// the test COMPLETING is itself the no-hang proof.
#[test]
fn truncated_sse_stream_finish_terminates_no_hang() {
    // openai egress → anthropic ingress: an all-SSE cross-protocol pair that genuinely engages the
    // translate reassembly buffer.
    let mut st = StreamTranslate::new("anthropic", "openai").expect("translator");
    // A well-formed first frame, then a second frame that is cut off mid-JSON with no terminator.
    let mut out =
        st.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n");
    out.extend_from_slice(
        &st.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"never-term"),
    );
    // Must return (no hang) — the partial is small so the stream is not aborted for overflow.
    out.extend_from_slice(&st.finish());
    // The healthy FIRST frame must still reach the client. Discarding the output (`let _ = tail;`)
    // meant a translator that dropped the complete `"hi"` delta along with the truncated tail —
    // silent content loss on every truncated upstream — passed this case.
    let wire = String::from_utf8_lossy(&out);
    assert!(
        wire.contains(r#""text":"hi""#),
        "the complete frame preceding the truncation must still translate to an Anthropic \
         text_delta; got {wire}"
    );
    assert!(
        !wire.contains("never-term"),
        "the incomplete tail must never be spliced onto the client stream; got {wire}"
    );
    assert!(
        !st.aborted(),
        "a small truncated tail must not trip the MAX_BUF overflow-abort"
    );
}

// ── 7. GARBAGE / NON-JSON SSE FRAMES ─────────────────────────────────────────

/// Complete-but-garbage SSE frames (non-JSON `data:` payloads, comment/keepalive lines) must be
/// SKIPPED, not treated as a stream abort: a real upstream interleaves `: keep-alive` comments and
/// the occasional malformed chunk, and a false abort would corrupt an otherwise healthy stream.
/// Assert the translator does NOT abort and `finish()` still terminates cleanly.
#[test]
fn garbage_non_json_sse_frames_skipped_no_false_abort() {
    let mut st = StreamTranslate::new("anthropic", "openai").expect("translator");
    let mut out = st.feed(b": keep-alive comment\n\n");
    out.extend_from_slice(&st.feed(b"data: {this is not valid json\n\n"));
    out.extend_from_slice(&st.feed(b"data: not-json-at-all\n\n"));
    out.extend_from_slice(
        &st.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\n"),
    );
    out.extend_from_slice(&st.finish());
    // The healthy frame interleaved among the garbage must still reach the client. Discarding the
    // output (`let _ = out;`) meant a translator that dropped the `"ok"` delta together with the
    // garbage — precisely the "corrupt an otherwise healthy stream" outcome this case names —
    // passed on the strength of `!aborted()` alone.
    let wire = String::from_utf8_lossy(&out);
    assert!(
        wire.contains(r#""text":"ok""#),
        "the one healthy frame among the garbage must translate to an Anthropic text_delta; \
         got {wire}"
    );
    assert!(
        !wire.contains("not valid json") && !wire.contains("not-json-at-all"),
        "no garbage payload may be forwarded to the client; got {wire}"
    );
    assert!(
        !st.aborted(),
        "garbage/non-JSON SSE frames must be skipped, never mistaken for a stream abort"
    );
}

// ── 8. OVERSIZED-BUT-VALID BODY ──────────────────────────────────────────────

/// A large-but-well-formed request body (a multi-megabyte text content string, well under the
/// ingress byte cap) must read on every dialect without panic. Guards against an accidental
/// quadratic/recursive blow-up or an over-eager size assertion inside a reader — the reader is
/// linear in body size, so a big valid body is merely big, not hostile.
#[test]
fn oversized_but_valid_body_reads_without_panic() {
    let big = "x".repeat(5 * 1024 * 1024); // 5 MiB of text
    for name in DIALECTS {
        let body = valid_request_body(name, &big);
        // The body is valid FOR THIS DIALECT, so "Ok or a typed reject are both fine" was slack, not
        // tolerance: accepting a reject made this case pass under exactly the over-eager size guard
        // its doc says it guards against. The read must succeed and the 5 MiB must arrive whole.
        let ir = protocol_for(name)
            .expect("dialect")
            .reader()
            .read_request(&body)
            .unwrap_or_else(|e| {
                panic!("{name}: a large-but-well-formed body must READ, not be rejected: {e:?}")
            });
        let text = first_user_text(&ir);
        assert_eq!(
            text.len(),
            big.len(),
            "{name}: the 5 MiB user turn must arrive whole (no truncation); got {} bytes",
            text.len()
        );
        assert_eq!(text, big, "{name}: the large body must round-trip verbatim");
    }
}

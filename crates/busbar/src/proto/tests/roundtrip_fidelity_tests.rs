// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! READ → WRITE round-trip fidelity, per protocol, on a RICH body.
//!
//! # What this file is, and what it is not
//!
//! It is NOT `same_proto_fidelity_tests.rs`. That file tests the byte-verbatim SHORT-CIRCUIT
//! (`StreamTranslate::new_same_proto`, `proxy/wire.rs`'s `hop_bytes.clone()`), which by construction
//! cannot lose anything — it never calls a reader or a writer. This file drives the thing that CAN
//! lose: `read_request` → `write_request` and `read_response` → `write_response` through the neutral
//! IR, and diffs the result against the original body field by field.
//!
//! Until this existed there was NO property/round-trip test at all, only ~30 hand-written per-field
//! assertions scattered across six `tests/tests.rs` files. That absence is what let a whole class of
//! loss accumulate unnoticed: **a field that is never read and never emitted has nothing to check
//! it**, so the writers looked well covered while attachments, usage sub-buckets and citation
//! offsets were being dropped in silence. A field no test would miss is a field a future edit can
//! silently drop.
//!
//! # The contract: an EXACT allow-list, not a budget
//!
//! Each test declares the EXACT set of divergences it accepts, and asserts set EQUALITY. That fails
//! in BOTH directions on purpose:
//!
//! * a NEW divergence fails — the regression this file exists to catch;
//! * a divergence that DISAPPEARS also fails — so a fix must come here and delete its line, which
//!   makes the allow-list a live, reviewed inventory of what busbar does not carry rather than a
//!   stale comment. Every entry carries the reason it is acceptable.
//!
//! A same-protocol route never actually reaches these code paths in production (see the
//! short-circuit above), so nothing here is a live loss. It matters for two reasons: each entry is a
//! CROSS-protocol loss the moment that field's ingress differs from its egress, and this is the
//! regression surface if the pristine short-circuit is ever narrowed.

use serde_json::{json, Value};

/// One field-level divergence between an original body and its round-tripped form.
///
/// Rendered as a single stable string (`"LOST messages[1].content[2].input_audio.data"`) so the
/// allow-lists below read as prose and a failure diff is greppable. Values are NOT part of the key:
/// a test asserting on values would fail on cosmetic re-serialization (float formatting, key order)
/// rather than on loss, which is the thing being measured.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Divergence(String);

/// Recursively diff `got` against `want`, appending one [`Divergence`] per differing leaf.
///
/// Three classes, deliberately distinguished:
/// * `LOST`   — a leaf present in the original and absent after the round trip (the loss class);
/// * `ADDED`  — a leaf the writer synthesized that the original did not carry (a proxy tell, or a
///   default the target's SDK requires);
/// * `CHANGED`— a leaf whose value the round trip altered (the CORRUPTION class: a document
///   stringified into a JSON blob, an internal plan promoted to visible text).
fn diff(path: &str, want: &Value, got: &Value, out: &mut Vec<Divergence>) {
    match (want, got) {
        (Value::Object(w), Value::Object(g)) => {
            for (k, wv) in w {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                match g.get(k) {
                    Some(gv) => diff(&p, wv, gv, out),
                    None => out.push(Divergence(format!("LOST {p}"))),
                }
            }
            for k in g.keys() {
                if !w.contains_key(k) {
                    let p = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    out.push(Divergence(format!("ADDED {p}")));
                }
            }
        }
        (Value::Array(w), Value::Array(g)) => {
            for (i, wv) in w.iter().enumerate() {
                let p = format!("{path}[{i}]");
                match g.get(i) {
                    Some(gv) => diff(&p, wv, gv, out),
                    None => out.push(Divergence(format!("LOST {p}"))),
                }
            }
            for i in w.len()..g.len() {
                out.push(Divergence(format!("ADDED {path}[{i}]")));
            }
        }
        (w, g) if w == g => {}
        _ => out.push(Divergence(format!("CHANGED {path}"))),
    }
}

/// Run one protocol's request round trip and assert the divergence set EXACTLY equals `allowed`.
fn assert_request_roundtrip(proto: &str, body: Value, allowed: &[&str]) {
    let entry = crate::proto::protocol_for(proto).expect("protocol registered");
    let ir = entry
        .reader
        .read_request(&body)
        .unwrap_or_else(|e| panic!("{proto}: read_request failed: {e:?}"));
    let out = entry.writer.write_request(&ir);
    assert_divergences(proto, "REQ", &body, &out, allowed);
}

/// Run one protocol's response round trip and assert the divergence set EXACTLY equals `allowed`.
fn assert_response_roundtrip(proto: &str, body: Value, allowed: &[&str]) {
    let entry = crate::proto::protocol_for(proto).expect("protocol registered");
    let ir = entry
        .reader
        .read_response(&body)
        .unwrap_or_else(|e| panic!("{proto}: read_response failed: {e:?}"));
    let out = entry.writer.write_response(&ir);
    assert_divergences(proto, "RESP", &body, &out, allowed);
}

fn assert_divergences(proto: &str, dir: &str, want: &Value, got: &Value, allowed: &[&str]) {
    let mut found = Vec::new();
    diff("", want, got, &mut found);
    let mut found: Vec<String> = found.into_iter().map(|d| d.0).collect();
    found.sort();
    let mut allowed: Vec<String> = allowed.iter().map(|s| s.to_string()).collect();
    allowed.sort();

    let unexpected: Vec<&String> = found.iter().filter(|f| !allowed.contains(f)).collect();
    let fixed: Vec<&String> = allowed.iter().filter(|a| !found.contains(a)).collect();
    assert!(
        unexpected.is_empty(),
        "{proto} {dir}: NEW round-trip divergence(s) this protocol did not have before.\n  \
         {unexpected:#?}\nRound-tripped body:\n{}",
        crate::json::to_string(got).unwrap_or_default()
    );
    assert!(
        fixed.is_empty(),
        "{proto} {dir}: divergence(s) in the allow-list no longer occur — GOOD, a loss was fixed. \
         Delete these lines from the allow-list so it stays an accurate inventory:\n  {fixed:#?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ANTHROPIC
// ─────────────────────────────────────────────────────────────────────────────

fn anthropic_request() -> Value {
    json!({
        "model": "claude-sonnet-4",
        "max_tokens": 4096,
        "system": [{"type": "text", "text": "be brief"}],
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "read this"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAA"}},
                {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "JVBERi0="}, "title": "spec.pdf"}
            ]},
            {"role": "assistant", "content": [
                {"type": "text", "text": "ok"},
                {"type": "tool_use", "id": "toolu_1", "name": "search", "input": {"q": "x"}}
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "res"}]}
            ]}
        ],
        "temperature": 0.5,
        "top_p": 0.9,
        "stop_sequences": ["END"],
        "stream": false
    })
}

#[test]
fn roundtrip_anthropic_request() {
    assert_request_roundtrip(
        "anthropic",
        anthropic_request(),
        &[
            // `model` is set by the ENGINE, not by the reader/writer pair: `proxy/wire.rs` calls
            // `IrReq::set_model(lane.wire_model())` before the writer runs, because the caller's
            // model name is a ROUTING key that names a busbar lane, not necessarily a model the
            // backend knows. A harness that drives the reader/writer directly skips that step, so
            // the field is absent here and present on every real egress. Not a loss.
            "LOST model",
            // Anthropic omits `is_error` when false (the API default); the reader reads the default
            // and the writer omits it again — a correct default-omission, not a loss. It shows here
            // only because the fixture states the default explicitly.
        ],
    );
}

#[test]
fn roundtrip_anthropic_response() {
    assert_response_roundtrip(
        "anthropic",
        json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "cache_creation_input_tokens": 7,
                "cache_read_input_tokens": 3,
                "cache_creation": {
                    "ephemeral_5m_input_tokens": 4,
                    "ephemeral_1h_input_tokens": 3
                }
            }
        }),
        &[
            // `server_tool_use` (hosted web-search request counts) has no IR carrier: it counts
            // REQUESTS, not tokens, so no token field can hold it and the totals stay correct
            // without it. Deliberate; listed so its absence is a reviewed fact.
        ],
    );
}

/// The 5m/1h cache-creation TIER SPLIT survives a round trip.
///
/// This is a BILLING-ATTRIBUTION test, not a totals test: the two tiers have DIFFERENT PRICES, so
/// collapsing them into one `cache_creation_input_tokens` leaves a bill that reconciles in total and
/// cannot be reconciled per line. Before `IrUsageDetail` there was nowhere to put them.
#[test]
fn anthropic_cache_tier_split_survives_the_ir() {
    let entry = crate::proto::protocol_for("anthropic").expect("anthropic");
    let ir = entry
        .reader
        .read_response(&json!({
            "id": "msg_1", "role": "assistant", "model": "m",
            "content": [{"type": "text", "text": "hi"}],
            "usage": {
                "input_tokens": 10, "output_tokens": 5,
                "cache_creation_input_tokens": 7,
                "cache_creation": {"ephemeral_5m_input_tokens": 4, "ephemeral_1h_input_tokens": 3}
            }
        }))
        .expect("read");
    let u = &ir.usage;
    assert_eq!(u.detail.cache_creation_5m_input_tokens, Some(4));
    assert_eq!(u.detail.cache_creation_1h_input_tokens, Some(3));
    // The tiers are a SLICE of the total, never an addition to it — billing must not change.
    assert_eq!(u.cache_creation_input_tokens, Some(7));
    let out = entry.writer.write_response(&ir);
    assert_eq!(
        out["usage"]["cache_creation"]["ephemeral_5m_input_tokens"],
        4
    );
    assert_eq!(
        out["usage"]["cache_creation"]["ephemeral_1h_input_tokens"],
        3
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// OPENAI CHAT
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn roundtrip_openai_request() {
    assert_request_roundtrip(
        "openai",
        json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "be brief"},
                {"role": "user", "content": [
                    {"type": "text", "text": "transcribe this"},
                    {"type": "input_audio", "input_audio": {"data": "AAA", "format": "wav"}},
                    {"type": "file", "file": {"file_data": "data:application/pdf;base64,JVBERi0=", "filename": "spec.pdf"}}
                ]}
            ],
            "temperature": 0.5,
            "max_tokens": 100,
            "stream": false
        }),
        &[
            // `model` is set by the ENGINE, not by the reader/writer pair: `proxy/wire.rs` calls
            // `IrReq::set_model(lane.wire_model())` before the writer runs, because the caller's
            // model name is a ROUTING key that names a busbar lane, not necessarily a model the
            // backend knows. A harness that drives the reader/writer directly skips that step, so
            // the field is absent here and present on every real egress. Not a loss.
            "LOST model",
        ],
    );
}

/// An OpenAI `input_audio` / `file` attachment survives read → write instead of becoming
/// `{"type":"text","text":""}`.
///
/// The regression guard for the defect that most contradicted the losslessness claim: before
/// `IrBlock::Media`, BOTH of these parts degraded to an EMPTY TEXT BLOCK with no warn — the caller's
/// audio never reached the model and nothing in the logs said why.
#[test]
fn openai_attachments_survive_the_ir_rather_than_becoming_empty_text() {
    let entry = crate::proto::protocol_for("openai").expect("openai");
    let ir = entry
        .reader
        .read_request(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": [
                {"type": "input_audio", "input_audio": {"data": "AAA", "format": "wav"}},
                {"type": "file", "file": {"file_data": "data:application/pdf;base64,JVBERi0=", "filename": "spec.pdf"}},
                {"type": "file", "file": {"file_id": "file-1"}}
            ]}]
        }))
        .expect("read");
    let blocks = &ir.messages[0].content;
    assert!(
        matches!(
            &blocks[0],
            crate::ir::IrBlock::Media {
                kind: crate::ir::IrMediaKind::Audio,
                source: crate::ir::IrImageSource::Base64 { media_type, data },
                ..
            } if media_type == "audio/wav" && data == "AAA"
        ),
        "input_audio must reach the IR as an Audio media block, got {:?}",
        blocks[0]
    );
    assert!(
        matches!(
            &blocks[1],
            crate::ir::IrBlock::Media {
                kind: crate::ir::IrMediaKind::Document,
                name: Some(n),
                ..
            } if n == "spec.pdf"
        ),
        "an inline file must reach the IR as a Document media block, got {:?}",
        blocks[1]
    );
    assert!(
        matches!(
            &blocks[2],
            crate::ir::IrBlock::Media {
                source: crate::ir::IrImageSource::Vendor { value, .. },
                ..
            } if value["file_id"] == "file-1"
        ),
        "a file_id must ride the opaque vendor escape, got {:?}",
        blocks[2]
    );

    let out = entry.writer.write_request(&ir);
    let parts = out["messages"][0]["content"].as_array().expect("parts");
    assert_eq!(parts[0]["type"], "input_audio");
    assert_eq!(parts[0]["input_audio"]["data"], "AAA");
    assert_eq!(parts[0]["input_audio"]["format"], "wav");
    assert_eq!(parts[1]["type"], "file");
    assert_eq!(parts[1]["file"]["filename"], "spec.pdf");
    assert_eq!(parts[2]["file"]["file_id"], "file-1");
    // The failure mode being guarded: NOT one of these may be an empty text part.
    for p in parts {
        assert_ne!(
            p["type"], "text",
            "an attachment degraded to a text part again: {p}"
        );
    }
}

/// The OpenAI `reasoning_tokens` sub-bucket reaches the IR instead of being reported as a hard `0`.
#[test]
fn openai_reasoning_tokens_reach_the_ir() {
    let entry = crate::proto::protocol_for("openai").expect("openai");
    let ir = entry
        .reader
        .read_response(&json!({
            "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "o3",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30,
                "completion_tokens_details": {"reasoning_tokens": 12}
            }
        }))
        .expect("read");
    assert_eq!(
        ir.usage.detail.reasoning_tokens,
        Some(12),
        "reasoning_tokens must reach the IR: a customer reconciling a bill against it got a hard 0"
    );
    let out = entry.writer.write_response(&ir);
    assert_eq!(
        out["usage"]["completion_tokens_details"]["reasoning_tokens"],
        12
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// GEMINI
// ─────────────────────────────────────────────────────────────────────────────

/// A Gemini `inlineData` of a NON-image mime type must NOT become an `IrBlock::Image`.
///
/// The live-400 guard. `proto/gemini/reader.rs` used to map EVERY `inlineData` onto an Image
/// regardless of mime, and the Anthropic writer emitted `media_type` verbatim and unvalidated — so
/// `{"type":"image","source":{"type":"base64","media_type":"audio/mp3"}}` reached Anthropic, which
/// accepts only `image/{jpeg,png,gif,webp}` and rejects the request. That breaks the half of the
/// losslessness definition that says the backend never rejects the request.
#[test]
fn gemini_non_image_inline_data_is_not_an_image_block() {
    let entry = crate::proto::protocol_for("gemini").expect("gemini");
    let ir = entry
        .reader
        .read_request(&json!({
            "contents": [{"role": "user", "parts": [
                {"inlineData": {"mimeType": "audio/mp3", "data": "AAA"}},
                {"inlineData": {"mimeType": "application/pdf", "data": "BBB"}},
                {"inlineData": {"mimeType": "image/png", "data": "CCC"}}
            ]}]
        }))
        .expect("read");
    let blocks = &ir.messages[0].content;
    assert!(
        matches!(
            &blocks[0],
            crate::ir::IrBlock::Media {
                kind: crate::ir::IrMediaKind::Audio,
                ..
            }
        ),
        "audio/mp3 inlineData must be an Audio media block, got {:?}",
        blocks[0]
    );
    assert!(
        matches!(
            &blocks[1],
            crate::ir::IrBlock::Media {
                kind: crate::ir::IrMediaKind::Document,
                ..
            }
        ),
        "application/pdf inlineData must be a Document media block, got {:?}",
        blocks[1]
    );
    assert!(
        matches!(&blocks[2], crate::ir::IrBlock::Image { .. }),
        "image/png inlineData must still be an Image block, got {:?}",
        blocks[2]
    );

    // ...and the Anthropic egress must not put any of it on the wire as an `image`.
    let anthropic = crate::proto::protocol_for("anthropic").expect("anthropic");
    let out = anthropic.writer.write_request(&ir);
    let parts = out["messages"][0]["content"].as_array().expect("content");
    for p in parts {
        if p["type"] == "image" {
            let mt = p["source"]["media_type"].as_str().unwrap_or("");
            assert!(
                crate::ir::image_subtype_if_supported(mt).is_some(),
                "an image block reached the Anthropic wire with media_type {mt:?}, which Anthropic \
                 rejects with a 400"
            );
        }
    }
    // The PDF has an Anthropic home (`document`) and must have taken it.
    assert!(
        parts.iter().any(|p| p["type"] == "document"),
        "a PDF attachment must reach Anthropic as a native `document` block, got {out}"
    );
}

/// A non-image attachment reaches a Gemini backend as native `inlineData` rather than vanishing.
///
/// Gemini's attachment slots are mime-GENERIC, which is why the attachment gap was never an
/// untranslatable-concept problem: the target had a slot the whole time.
#[test]
fn attachments_reach_gemini_as_inline_data() {
    let openai = crate::proto::protocol_for("openai").expect("openai");
    let ir = openai
        .reader
        .read_request(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": [
                {"type": "input_audio", "input_audio": {"data": "AAA", "format": "wav"}}
            ]}]
        }))
        .expect("read");
    let gemini = crate::proto::protocol_for("gemini").expect("gemini");
    let out = gemini.writer.write_request(&ir);
    let parts = out["contents"][0]["parts"].as_array().expect("parts");
    assert_eq!(parts[0]["inlineData"]["mimeType"], "audio/wav");
    assert_eq!(parts[0]["inlineData"]["data"], "AAA");
}

// ─────────────────────────────────────────────────────────────────────────────
// BEDROCK
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn roundtrip_bedrock_request() {
    assert_request_roundtrip(
        "bedrock",
        json!({
            "messages": [
                {"role": "user", "content": [
                    {"text": "read this"},
                    {"image": {"format": "png", "source": {"bytes": "AAA"}}},
                    {"document": {"format": "pdf", "name": "spec", "source": {"bytes": "JVBERi0="}}},
                    {"video": {"format": "mp4", "source": {"bytes": "VVV"}}}
                ]}
            ],
            "system": [{"text": "be brief"}],
            "inferenceConfig": {"maxTokens": 100, "temperature": 0.5, "topP": 0.9}
        }),
        &[],
    );
}

/// A Bedrock `document` / `video` block reaches the IR (cross-protocol) AND is re-emitted verbatim
/// from the positional stash (same-protocol) — without being emitted twice.
///
/// The double-emit is the hazard the suppression in `bedrock/writer.rs` exists for: the reader now
/// both parks the raw block and models it, so a writer that honored both would send the attachment
/// upstream twice.
#[test]
fn bedrock_document_is_modelled_without_double_emitting() {
    let entry = crate::proto::protocol_for("bedrock").expect("bedrock");
    let body = json!({
        "messages": [{"role": "user", "content": [
            {"text": "hi"},
            {"document": {"format": "pdf", "name": "spec", "source": {"bytes": "JVBERi0="}}}
        ]}]
    });
    let ir = entry.reader.read_request(&body).expect("read");
    assert!(
        ir.messages[0].content.iter().any(|b| matches!(
            b,
            crate::ir::IrBlock::Media {
                kind: crate::ir::IrMediaKind::Document,
                ..
            }
        )),
        "a Converse document must be modelled so it survives a CROSS-protocol hop"
    );
    let out = entry.writer.write_request(&ir);
    let content = out["messages"][0]["content"].as_array().expect("content");
    assert_eq!(
        content.iter().filter(|b| b.get("document").is_some()).count(),
        1,
        "the document must be emitted exactly once (stash splice XOR modelled projection), got {out}"
    );
    assert_eq!(content[1]["document"]["name"], "spec");
}

// ─────────────────────────────────────────────────────────────────────────────
// COHERE
// ─────────────────────────────────────────────────────────────────────────────

/// Cohere's `message.tool_plan` must NOT be promoted into visible assistant text.
///
/// This is CONTENT INJECTION, not loss: `tool_plan` is the model's INTERNAL pre-tool-call plan, and
/// reading it into a leading `IrBlock::Text` made every cross-protocol client render it as the
/// answer's first paragraph — text the model never intended to show. It belongs in the IR's
/// reasoning carrier, which is also what lets the Cohere writer put it back in its native slot.
#[test]
fn cohere_tool_plan_is_reasoning_not_visible_text() {
    let entry = crate::proto::protocol_for("cohere").expect("cohere");
    let ir = entry
        .reader
        .read_response(&json!({
            "id": "c1",
            "message": {
                "role": "assistant",
                "tool_plan": "I will search for it",
                "content": [{"type": "text", "text": "hi"}]
            },
            "finish_reason": "COMPLETE"
        }))
        .expect("read");
    assert!(
        matches!(
            &ir.content[0],
            crate::ir::IrBlock::Thinking { text, .. } if text == "I will search for it"
        ),
        "tool_plan must land in the reasoning carrier, got {:?}",
        ir.content[0]
    );
    assert!(
        !ir.content.iter().any(|b| matches!(
            b, crate::ir::IrBlock::Text { text, .. } if text == "I will search for it"
        )),
        "tool_plan must NOT be a visible Text block: that shows the user text the model did not \
         intend to show"
    );

    // Same-protocol: it goes back into its native slot rather than into `content`.
    let out = entry.writer.write_response(&ir);
    assert_eq!(out["message"]["tool_plan"], "I will search for it");
    assert_eq!(out["message"]["content"][0]["text"], "hi");

    // Cross-protocol: an Anthropic client sees it as a `thinking` block, not as the answer.
    let anthropic = crate::proto::protocol_for("anthropic").expect("anthropic");
    let a = anthropic.writer.write_response(&ir);
    assert_eq!(a["content"][0]["type"], "thinking");
    assert_eq!(a["content"][1]["text"], "hi");
}

/// A Cohere tool-result `document` content part must keep its STRUCTURE instead of being stringified
/// into a literal JSON blob the model reads as escaped syntax.
#[test]
fn cohere_tool_result_document_is_not_stringified() {
    let entry = crate::proto::protocol_for("cohere").expect("cohere");
    let ir = entry
        .reader
        .read_request(&json!({
            "model": "command-r",
            "messages": [
                {"role": "user", "content": "q"},
                {"role": "assistant", "tool_calls": [
                    {"id": "t1", "type": "function", "function": {"name": "s", "arguments": "{}"}}
                ]},
                {"role": "tool", "tool_call_id": "t1", "content": [
                    {"type": "document", "document": {"id": "d1", "data": {"t": "x"}}}
                ]}
            ]
        }))
        .expect("read");
    let tool_msg = ir
        .messages
        .iter()
        .find(|m| m.role == crate::ir::IrRole::Tool)
        .expect("tool message");
    let crate::ir::IrBlock::ToolResult { content, .. } = &tool_msg.content[0] else {
        panic!("expected a ToolResult, got {:?}", tool_msg.content[0]);
    };
    assert!(
        content.iter().any(|b| matches!(
            b,
            crate::ir::IrBlock::Media {
                kind: crate::ir::IrMediaKind::Document,
                ..
            }
        )),
        "a tool-result document must reach the IR as a structured Media block, got {content:?}"
    );
    assert!(
        !content.iter().any(|b| matches!(
            b, crate::ir::IrBlock::Text { text, .. } if text.contains("\"type\":\"document\"")
        )),
        "the document must not be stringified into a JSON blob: the model then sees escaped JSON \
         syntax instead of the document"
    );
    let out = entry.writer.write_request(&ir);
    let tool_content = &out["messages"][2]["content"];
    assert_eq!(
        tool_content[0]["type"], "document",
        "the native document part must be re-emitted structurally, got {tool_content}"
    );
    assert_eq!(tool_content[0]["document"]["id"], "d1");
}

/// Cohere's `billed_units.search_units` is a SEPARATELY BILLED unit that no token field can carry —
/// its loss is invisible in a token total that reconciles perfectly.
#[test]
fn cohere_search_units_reach_the_ir() {
    let entry = crate::proto::protocol_for("cohere").expect("cohere");
    let ir = entry
        .reader
        .read_response(&json!({
            "id": "c1",
            "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
            "finish_reason": "COMPLETE",
            "usage": {
                "tokens": {"input_tokens": 10, "output_tokens": 5},
                "billed_units": {"input_tokens": 10, "output_tokens": 5, "search_units": 2}
            }
        }))
        .expect("read");
    assert_eq!(ir.usage.detail.search_units, Some(2));
    let out = entry.writer.write_response(&ir);
    assert_eq!(out["usage"]["billed_units"]["search_units"], 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// RESPONSES
// ─────────────────────────────────────────────────────────────────────────────

/// A Responses `input_file` survives read → write instead of becoming an empty `input_text` part.
#[test]
fn responses_input_file_survives_the_ir() {
    let entry = crate::proto::protocol_for("responses").expect("responses");
    let ir = entry
        .reader
        .read_request(&json!({
            "model": "gpt-4.1",
            "input": [{"role": "user", "content": [
                {"type": "input_text", "text": "read this"},
                {"type": "input_file", "file_data": "data:application/pdf;base64,JVBERi0=", "filename": "spec.pdf"}
            ]}]
        }))
        .expect("read");
    assert!(
        matches!(
            &ir.messages[0].content[1],
            crate::ir::IrBlock::Media {
                kind: crate::ir::IrMediaKind::Document,
                ..
            }
        ),
        "input_file must reach the IR as a Document media block, got {:?}",
        ir.messages[0].content[1]
    );
    let out = entry.writer.write_request(&ir);
    let parts = out["input"][0]["content"].as_array().expect("content");
    assert_eq!(parts[1]["type"], "input_file");
    assert_eq!(parts[1]["filename"], "spec.pdf");
    assert!(
        parts[1]["file_data"]
            .as_str()
            .unwrap_or_default()
            .starts_with("data:application/pdf;base64,"),
        "the file bytes must round-trip, got {}",
        parts[1]
    );
}

/// Responses `output_tokens_details.reasoning_tokens` no longer arrives as a hard `0`.
#[test]
fn responses_reasoning_tokens_are_not_zeroed() {
    let entry = crate::proto::protocol_for("responses").expect("responses");
    let ir = entry
        .reader
        .read_response(&json!({
            "id": "resp_1", "object": "response", "created_at": 1, "model": "o3",
            "status": "completed",
            "output": [{"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
                        "content": [{"type": "output_text", "text": "hi", "annotations": []}]}],
            "usage": {"input_tokens": 10, "output_tokens": 20, "total_tokens": 30,
                      "output_tokens_details": {"reasoning_tokens": 2}}
        }))
        .expect("read");
    assert_eq!(ir.usage.detail.reasoning_tokens, Some(2));
    let out = entry.writer.write_response(&ir);
    assert_eq!(out["usage"]["output_tokens_details"]["reasoning_tokens"], 2);
}

/// Gemini's `thoughtsTokenCount` is the reasoning sub-bucket, and recording it must not move any
/// total.
///
/// The two halves are separately load-bearing. The FOLD (thinking tokens counted inside
/// `output_tokens`) is what makes the bill right and predates this pass; the ATTRIBUTION is what
/// lets an OpenAI-dialect caller ask "how many of those were thinking?" instead of receiving a hard
/// `0`. Asserting them together is what stops a future edit from "fixing" the attribution by
/// double-counting.
#[test]
fn gemini_thoughts_token_count_is_the_reasoning_sub_bucket() {
    let entry = crate::proto::protocol_for("gemini").expect("gemini");
    let ir = entry
        .reader
        .read_response(&json!({
            "candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]},
                            "finishReason": "STOP"}],
            "usageMetadata": {
                "promptTokenCount": 10, "candidatesTokenCount": 5,
                "thoughtsTokenCount": 7, "totalTokenCount": 22
            }
        }))
        .expect("read");
    assert_eq!(ir.usage.detail.reasoning_tokens, Some(7));
    assert_eq!(
        ir.usage.output_tokens, 12,
        "thinking tokens stay FOLDED into output_tokens — the sub-bucket is attribution, never an \
         addition, or the bill inflates"
    );
    assert_eq!(ir.usage.billable_tokens(), 22);
}

/// A streamed citation reaches an OpenAI-ingress client instead of vanishing.
///
/// The asymmetry this closes is the worst shape of the loss: the SAME request against the SAME
/// backend returned sources at `stream:false` and no sources at `stream:true`, and nothing about
/// the request explained the difference.
#[test]
fn streamed_citations_reach_openai_and_cohere_clients() {
    let citation = crate::ir::IrCitation {
        kind: Some("web_search_result_location".to_string()),
        cited_text: Some("quoted".to_string()),
        title: Some("T".to_string()),
        url: Some("https://x".to_string()),
        document_index: None,
        start_index: Some(0),
        end_index: Some(6),
        encrypted_index: None,
        raw: None,
    };
    let ev = crate::ir::IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::CitationsDelta(vec![citation]),
    };

    let openai = crate::proto::protocol_for("openai").expect("openai");
    let (_, chunk) = openai
        .writer
        .write_response_event(&ev)
        .expect("a chat.completion.chunk carries delta.annotations");
    let ann = &chunk["choices"][0]["delta"]["annotations"][0];
    assert_eq!(ann["type"], "url_citation");
    assert_eq!(ann["url_citation"]["url"], "https://x");
    assert_eq!(ann["url_citation"]["start_index"], 0);

    let cohere = crate::proto::protocol_for("cohere").expect("cohere");
    let (_, frame) = cohere
        .writer
        .write_response_event(&ev)
        .expect("Cohere v2 has a native `citation-start` frame");
    assert_eq!(frame["type"], "citation-start");
    assert_eq!(frame["delta"]["message"]["citations"][0]["start"], 0);
    assert_eq!(
        frame["delta"]["message"]["citations"][0]["sources"][0]["document"]["url"],
        "https://x"
    );
}

/// A Cohere backend's grounding citations reach a foreign-dialect client.
///
/// The Cohere reader hardcoded `citations: Vec::new()` at every construction site while the Cohere
/// WRITER emitted citations — so a citation INTO Cohere worked and a citation OUT of Cohere
/// vanished. That asymmetry is the tell that it was a missing reader rather than a translation
/// limit: `IrCitation` already existed and both sides already spoke it. A customer running Cohere
/// RAG behind an Anthropic-dialect client got an ungrounded answer with the sources stripped, which
/// is a compliance problem, not a cosmetic one.
#[test]
fn cohere_response_citations_reach_a_foreign_client() {
    let cohere = crate::proto::protocol_for("cohere").expect("cohere");
    let ir = cohere
        .reader
        .read_response(&json!({
            "id": "c1",
            "finish_reason": "COMPLETE",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "Paris is the capital."}],
                "citations": [{
                    "start": 0, "end": 5, "text": "Paris",
                    "sources": [{"type": "document", "id": "d1",
                                 "document": {"title": "Atlas", "url": "https://atlas"}}]
                }]
            }
        }))
        .expect("read");
    let crate::ir::IrBlock::Text { citations, .. } = &ir.content[0] else {
        panic!("expected a Text block, got {:?}", ir.content[0]);
    };
    assert_eq!(citations.len(), 1, "the citation must reach the IR");
    assert_eq!(citations[0].start_index, Some(0));
    assert_eq!(citations[0].end_index, Some(5));
    assert_eq!(citations[0].url.as_deref(), Some("https://atlas"));

    // Cross-protocol: an Anthropic-dialect client sees the grounding rather than a bare assertion.
    let anthropic = crate::proto::protocol_for("anthropic").expect("anthropic");
    let out = anthropic.writer.write_response(&ir);
    assert!(
        out["content"][0]["citations"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "the citation must survive the hop to an Anthropic client: {out}"
    );

    // Same-protocol: the source object round-trips verbatim out of `raw`.
    let back = cohere.writer.write_response(&ir);
    assert_eq!(back["message"]["citations"][0]["text"], "Paris");
    assert_eq!(
        back["message"]["citations"][0]["sources"][0]["document"]["title"],
        "Atlas"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 1.6.0 GAP CLOSURES — see docs/protocols.md
//
// Every test below pins a construct that USED to be dropped on a cross-protocol hop. Each one
// asserts the value reaches THE OTHER SIDE (a foreign protocol's wire body or wire frame), not
// merely that the IR held it: "the IR carries it" is exactly the assertion that would have passed
// while the writers still threw it away.
// ─────────────────────────────────────────────────────────────────────────────

/// An Anthropic `search_result` block's retrieved passages reach a foreign client.
///
/// It used to fall into the reader's degrade-to-empty-Text arm, so a caller who paid to retrieve and
/// attach RAG passages got them replaced with `{"type":"text","text":""}` on every cross-protocol
/// egress and the model answered from its own memory instead. Unlike a `document`, the payload is
/// ENTIRELY TEXT by Anthropic's own schema, so there is nothing untranslatable about it — every
/// protocol in the matrix can carry text.
///
/// Both directions are asserted: the passages must cross, AND the same-protocol Anthropic re-emit
/// must still be byte-exact (the raw block is parked in the unmodeled sentinel, so modelling it here
/// must not have cost the verbatim round trip).
#[test]
fn anthropic_search_result_reaches_a_foreign_client() {
    let anthropic = crate::proto::protocol_for("anthropic").expect("anthropic");
    let body = json!({
        "model": "claude-x",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": [
            {
                "type": "search_result",
                "source": "https://kb/42",
                "title": "Refund policy",
                "content": [{"type": "text", "text": "Refunds are issued within 30 days."}],
                "citations": {"enabled": true}
            },
            {"type": "text", "text": "What is the refund window?"}
        ]}]
    });
    let ir = anthropic.reader.read_request(&body).expect("read");

    let crate::ir::IrBlock::Text {
        text, citations, ..
    } = &ir.messages[0].content[0]
    else {
        panic!(
            "expected the search_result to become a Text block, got {:?}",
            ir.messages[0].content[0]
        );
    };
    assert!(
        text.contains("Refunds are issued within 30 days."),
        "the retrieved passage must survive, not become an empty placeholder: {text:?}"
    );
    assert!(
        text.contains("Refund policy") && text.contains("https://kb/42"),
        "the source header must name the result so the model can attribute it: {text:?}"
    );
    assert_eq!(
        citations[0].url.as_deref(),
        Some("https://kb/42"),
        "the provenance must ride as a citation so a target that models citations shows it"
    );

    // CROSS-PROTOCOL, the direction that was broken: an OpenAI backend must receive the passage.
    let openai = crate::proto::protocol_for("openai").expect("openai");
    let out = openai.writer.write_request(&ir);
    let rendered = out["messages"][0]["content"].to_string();
    assert!(
        rendered.contains("Refunds are issued within 30 days."),
        "the passage must reach an OpenAI backend: {out}"
    );

    // ... and a Gemini backend, whose content shape is different again.
    let gemini = crate::proto::protocol_for("gemini").expect("gemini");
    let out = gemini.writer.write_request(&ir);
    assert!(
        out.to_string()
            .contains("Refunds are issued within 30 days."),
        "the passage must reach a Gemini backend: {out}"
    );

    // SAME-PROTOCOL: the original block re-emits verbatim out of the unmodeled sentinel, so nothing
    // about modelling it cross-protocol degraded the Anthropic→Anthropic path.
    let back = anthropic.writer.write_request(&ir);
    assert_eq!(
        back["messages"][0]["content"][0], body["messages"][0]["content"][0],
        "the Anthropic re-emit must be the ORIGINAL search_result block, byte-exact"
    );
}

/// A streamed citation reaches a BEDROCK-ingress client.
///
/// The third of the three writers that suppressed `CitationsDelta`. Bedrock ConverseStream's
/// `ContentBlockDelta` union DOES have a `citation` member, so the suppression was not a protocol
/// limit — it produced the same "sources at `stream:false`, none at `stream:true`" split the OpenAI
/// and Cohere writers had.
#[test]
fn streamed_citations_reach_a_bedrock_client() {
    let ev = crate::ir::IrStreamEvent::BlockDelta {
        index: 3,
        delta: crate::ir::IrDelta::CitationsDelta(vec![crate::ir::IrCitation {
            kind: Some("char_location".to_string()),
            cited_text: Some("Paris".to_string()),
            title: Some("Atlas".to_string()),
            url: None,
            document_index: Some(1),
            start_index: Some(0),
            end_index: Some(5),
            encrypted_index: None,
            raw: None,
        }]),
    };
    let bedrock = crate::proto::protocol_for("bedrock").expect("bedrock");
    let (et, frame) = bedrock
        .writer
        .write_response_event(&ev)
        .expect("Converse has a native `citation` ContentBlockDelta member");
    assert_eq!(et, "contentBlockDelta");
    assert_eq!(frame["contentBlockIndex"], 3);
    let c = &frame["delta"]["citation"];
    assert_eq!(c["title"], "Atlas");
    assert_eq!(c["sourceContent"][0]["text"], "Paris");
    assert_eq!(c["location"]["documentChar"]["documentIndex"], 1);
    assert_eq!(c["location"]["documentChar"]["start"], 0);
    assert_eq!(c["location"]["documentChar"]["end"], 5);
}

/// A page-located citation must not be mislabelled as a character offset on a Bedrock egress.
///
/// `IrCitation.start_index` is interpreted PER `kind`; for Anthropic's `page_location` it is a page
/// NUMBER. Writing `page 7` into `documentChar.start` would be a confident lie rather than a loss,
/// which is worse — so those citations cross with title and quoted text and no location.
#[test]
fn bedrock_citation_omits_a_location_it_cannot_honestly_fill() {
    let ev = crate::ir::IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::CitationsDelta(vec![crate::ir::IrCitation {
            kind: Some("page_location".to_string()),
            cited_text: Some("clause 4".to_string()),
            title: Some("Contract".to_string()),
            url: None,
            document_index: Some(0),
            start_index: Some(7),
            end_index: Some(8),
            encrypted_index: None,
            raw: None,
        }]),
    };
    let bedrock = crate::proto::protocol_for("bedrock").expect("bedrock");
    let (_, frame) = bedrock.writer.write_response_event(&ev).expect("frame");
    let c = &frame["delta"]["citation"];
    assert_eq!(c["title"], "Contract");
    assert_eq!(c["sourceContent"][0]["text"], "clause 4");
    assert!(
        c.get("location").is_none(),
        "a PAGE number must not be emitted as a CHARACTER offset: {c}"
    );
}

/// A Gemini Google-Search-grounded answer's SOURCES reach a foreign client.
///
/// `groundingMetadata` — not `citationMetadata` — is where a grounded Gemini answer puts its
/// provenance, and nothing read it. A customer could not tell a grounded reply from a hallucinated
/// one after a hop. This is not a vendor-specific concept: every protocol in the matrix models a
/// citation.
#[test]
fn gemini_grounding_metadata_reaches_a_foreign_client() {
    let gemini = crate::proto::protocol_for("gemini").expect("gemini");
    let ir = gemini
        .reader
        .read_response(&json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Paris is the capital."}]},
                "finishReason": "STOP",
                "groundingMetadata": {
                    "groundingChunks": [{"web": {"uri": "https://atlas", "title": "Atlas"}}],
                    "groundingSupports": [{
                        "segment": {"startIndex": 0, "endIndex": 5, "text": "Paris"},
                        "groundingChunkIndices": [0]
                    }]
                }
            }],
            "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 4, "totalTokenCount": 7}
        }))
        .expect("read");
    let crate::ir::IrBlock::Text { citations, .. } = &ir.content[0] else {
        panic!("expected a Text block, got {:?}", ir.content[0]);
    };
    assert_eq!(citations.len(), 1, "the grounding source must reach the IR");
    assert_eq!(citations[0].url.as_deref(), Some("https://atlas"));
    assert_eq!(citations[0].title.as_deref(), Some("Atlas"));

    // CROSS-PROTOCOL both ways out: an OpenAI client sees an annotation, an Anthropic client a
    // citation. Neither receives a bare unattributed paragraph.
    let openai = crate::proto::protocol_for("openai").expect("openai");
    let out = openai.writer.write_response(&ir);
    // NOTE the shape: the BUFFERED writer emits the flat `url_annotations` entry
    // (`{type,url,title,start_index,end_index}`) while the STREAMING arm emits the nested
    // `{type, url_citation:{…}}`. That divergence predates this change and is asserted as-is here
    // rather than quietly "corrected", which would move a wire byte no row of this work covers.
    assert_eq!(
        out["choices"][0]["message"]["annotations"][0]["url"], "https://atlas",
        "the grounding source must reach an OpenAI client: {out}"
    );
    let anthropic = crate::proto::protocol_for("anthropic").expect("anthropic");
    let out = anthropic.writer.write_response(&ir);
    assert!(
        out["content"][0]["citations"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "the grounding source must reach an Anthropic client: {out}"
    );
}

/// A grounded answer with sources but NO support spans still carries its sources.
///
/// Google omits `groundingSupports` on some grounded replies. Requiring them would have silently
/// re-created the exact gap this closes for that subset of responses.
#[test]
fn gemini_grounding_chunks_cross_without_support_spans() {
    let gemini = crate::proto::protocol_for("gemini").expect("gemini");
    let ir = gemini
        .reader
        .read_response(&json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "hi"}]},
                "finishReason": "STOP",
                "groundingMetadata": {
                    "groundingChunks": [{"web": {"uri": "https://a", "title": "A"}},
                                        {"web": {"uri": "https://b", "title": "B"}}]
                }
            }]
        }))
        .expect("read");
    let crate::ir::IrBlock::Text { citations, .. } = &ir.content[0] else {
        panic!("expected a Text block");
    };
    assert_eq!(citations.len(), 2, "both sources must cross: {citations:?}");
    assert_eq!(citations[1].url.as_deref(), Some("https://b"));
}

/// `tools[].strict` crosses the OpenAI Chat ↔ Responses pair, in both directions.
///
/// `strict: true` is a behavioural guarantee (the model's arguments WILL conform to the schema), so
/// dropping it silently turned validation off while the request still looked accepted. The two
/// dialects that model it must carry it between themselves.
#[test]
fn tool_strict_crosses_the_openai_responses_pair() {
    let openai = crate::proto::protocol_for("openai").expect("openai");
    let responses = crate::proto::protocol_for("responses").expect("responses");

    // Chat → Responses.
    let ir = openai
        .reader
        .read_request(&json!({
            "model": "gpt-x",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {
                "name": "f", "parameters": {"type": "object"}, "strict": true
            }}]
        }))
        .expect("read");
    assert_eq!(ir.tools[0].strict, Some(true));
    let out = responses.writer.write_request(&ir);
    assert_eq!(out["tools"][0]["strict"], true, "{out}");

    // Responses → Chat (the flat shape back into the nested one).
    let ir = responses
        .reader
        .read_request(&json!({
            "model": "gpt-x",
            "input": "hi",
            "tools": [{"type": "function", "name": "f", "parameters": {"type": "object"},
                       "strict": true}]
        }))
        .expect("read");
    assert_eq!(ir.tools[0].strict, Some(true));
    let out = openai.writer.write_request(&ir);
    assert_eq!(out["tools"][0]["function"]["strict"], true, "{out}");

    // A caller who said NOTHING must not acquire an invented `strict: false`.
    let ir = openai
        .reader
        .read_request(&json!({
            "model": "gpt-x",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {"name": "f", "parameters": {}}}]
        }))
        .expect("read");
    assert_eq!(ir.tools[0].strict, None);
    let out = openai.writer.write_request(&ir);
    assert!(
        out["tools"][0]["function"].get("strict").is_none(),
        "an absent flag must stay absent, not become an explicit opt-out: {out}"
    );
}

/// OpenAI `messages[].name` survives a same-protocol re-serialize, and never leaks its sentinel.
///
/// A pool-alias route rewrites the model and therefore re-serializes rather than forwarding the
/// caller's bytes — which stripped `name` from every message. No other protocol models a participant
/// name, so `extra` is the correct scope: it survives here and is NAMED (not silently cleared) at
/// the cross-protocol seam.
#[test]
fn openai_message_name_survives_a_same_protocol_reserialize() {
    let openai = crate::proto::protocol_for("openai").expect("openai");
    let ir = openai
        .reader
        .read_request(&json!({
            "model": "gpt-x",
            "messages": [
                {"role": "user", "name": "alice", "content": "hi"},
                {"role": "user", "content": "no name here"},
                {"role": "user", "name": "bob", "content": "hello"}
            ]
        }))
        .expect("read");
    let out = openai.writer.write_request(&ir);
    assert_eq!(out["messages"][0]["name"], "alice", "{out}");
    assert!(
        out["messages"][1].get("name").is_none(),
        "a message with no name must not acquire one: {out}"
    );
    assert_eq!(out["messages"][2]["name"], "bob", "{out}");
    assert!(
        out.get("__busbar_openai_message_names").is_none(),
        "the busbar-internal marker must never reach the wire: {out}"
    );
}

/// Usage sub-buckets survive on the STREAMING path, not only the buffered one.
///
/// The buffered path learned `IrUsageDetail` and the streaming readers/writers kept defaulting it
/// away, so the SAME request reported a reasoning-token count at `stream:false` and a hard `0` at
/// `stream:true` — the identical asymmetry that made the streamed-citation gap the worst-shaped one.
#[test]
fn streamed_usage_sub_buckets_are_not_zeroed() {
    let openai = crate::proto::protocol_for("openai").expect("openai");
    let mut state = crate::ir::StreamDecodeState::default();
    let events = openai.reader.read_response_events(
        "",
        &json!({
            "id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 1, "model": "o3",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30,
                      "completion_tokens_details": {"reasoning_tokens": 9}}
        }),
        &mut state,
    );
    let usage = events
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("a terminal MessageDelta");
    assert_eq!(
        usage.detail.reasoning_tokens,
        Some(9),
        "the streamed usage chunk carries the same sub-bucket the buffered response does"
    );

    // And it reaches the other side: an OpenAI-ingress client's terminal chunk carries it natively.
    let (_, chunk) = openai
        .writer
        .write_response_event(&crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 10,
                output_tokens: 20,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
                detail: crate::ir::IrUsageDetail {
                    reasoning_tokens: Some(9),
                    ..Default::default()
                },
            },
        })
        .expect("terminal chunk");
    assert_eq!(
        chunk["usage"]["completion_tokens_details"]["reasoning_tokens"], 9,
        "{chunk}"
    );
}

/// Anthropic's separately-priced 5m/1h cache tiers survive a STREAM.
#[test]
fn streamed_anthropic_cache_tiers_survive() {
    let anthropic = crate::proto::protocol_for("anthropic").expect("anthropic");
    let mut state = crate::ir::StreamDecodeState::default();
    let events = anthropic.reader.read_response_events(
        "message_start",
        &json!({
            "type": "message_start",
            "message": {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-x",
                        "content": [], "stop_reason": null,
                        "usage": {"input_tokens": 5, "output_tokens": 0,
                                  "cache_creation_input_tokens": 30,
                                  "cache_creation": {"ephemeral_5m_input_tokens": 10,
                                                     "ephemeral_1h_input_tokens": 20}}}
        }),
        &mut state,
    );
    let usage = events
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageStart { usage, .. } => usage.as_ref(),
            _ => None,
        })
        .expect("message_start usage");
    assert_eq!(usage.detail.cache_creation_5m_input_tokens, Some(10));
    assert_eq!(usage.detail.cache_creation_1h_input_tokens, Some(20));

    // The tier split reaches an Anthropic-ingress client's `message_delta`.
    let (_, frame) = anthropic
        .writer
        .write_response_event(&crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 5,
                output_tokens: 1,
                cache_creation_input_tokens: Some(30),
                cache_read_input_tokens: None,
                detail: crate::ir::IrUsageDetail {
                    cache_creation_5m_input_tokens: Some(10),
                    cache_creation_1h_input_tokens: Some(20),
                    ..Default::default()
                },
            },
        })
        .expect("message_delta");
    assert_eq!(
        frame["usage"]["cache_creation"]["ephemeral_5m_input_tokens"], 10,
        "{frame}"
    );
    assert_eq!(
        frame["usage"]["cache_creation"]["ephemeral_1h_input_tokens"], 20,
        "{frame}"
    );
}

/// Cohere's separately-billed `search_units` survive a STREAM.
///
/// `search_units` is not a token count at all, so its loss is invisible in a token total that
/// reconciles perfectly — which is exactly why it needs a test rather than a reviewer.
#[test]
fn streamed_cohere_search_units_survive() {
    let cohere = crate::proto::protocol_for("cohere").expect("cohere");
    let mut state = crate::ir::StreamDecodeState::default();
    let events = cohere.reader.read_response_events(
        "message-end",
        &json!({
            "type": "message-end",
            "delta": {"finish_reason": "COMPLETE",
                      "usage": {"tokens": {"input_tokens": 4, "output_tokens": 6},
                                "billed_units": {"search_units": 3}}}
        }),
        &mut state,
    );
    let usage = events
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("message-end usage");
    assert_eq!(usage.detail.search_units, Some(3));

    let (_, frame) = cohere
        .writer
        .write_response_event(&crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 4,
                output_tokens: 6,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
                detail: crate::ir::IrUsageDetail {
                    search_units: Some(3),
                    ..Default::default()
                },
            },
        })
        .expect("message-end");
    assert_eq!(
        frame["delta"]["usage"]["billed_units"]["search_units"], 3,
        "{frame}"
    );
}

/// A BUFFERED response's citations reach a Bedrock client too, not only a streamed one.
///
/// The buffered twin of `streamed_citations_reach_a_bedrock_client`. Closing only the streaming half
/// would have left the identical asymmetry the streaming gap was, merely inverted: sources when the
/// caller streams and none when it does not.
#[test]
fn buffered_citations_reach_a_bedrock_client() {
    let cohere = crate::proto::protocol_for("cohere").expect("cohere");
    let ir = cohere
        .reader
        .read_response(&json!({
            "id": "c1",
            "finish_reason": "COMPLETE",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "Paris is the capital."}],
                "citations": [{
                    "start": 0, "end": 5, "text": "Paris",
                    "sources": [{"type": "document", "id": "d1",
                                 "document": {"title": "Atlas", "url": "https://atlas"}}]
                }]
            }
        }))
        .expect("read");

    let bedrock = crate::proto::protocol_for("bedrock").expect("bedrock");
    let out = bedrock.writer.write_response(&ir);
    let block = &out["output"]["message"]["content"][0];
    assert_eq!(
        block["citationsContent"]["content"][0]["text"], "Paris is the capital.",
        "the answer text moves INSIDE the citations block, per the Converse union: {out}"
    );
    let c = &block["citationsContent"]["citations"][0];
    assert_eq!(c["title"], "Atlas", "{out}");
    assert_eq!(c["sourceContent"][0]["text"], "Paris", "{out}");
    assert_eq!(c["location"]["documentChar"]["start"], 0, "{out}");
}

/// A text block with NO citations keeps the plain `{"text": …}` shape.
///
/// `citationsContent` replaces the `text` member rather than sitting beside it, so emitting it
/// unconditionally would reshape every ordinary Bedrock response — a wire change for every consumer
/// in exchange for nothing.
#[test]
fn bedrock_uncited_text_keeps_the_plain_shape() {
    let bedrock = crate::proto::protocol_for("bedrock").expect("bedrock");
    let out = bedrock.writer.write_response(&crate::ir::IrResponse {
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "plain".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
            detail: crate::ir::IrUsageDetail::default(),
        },
        model: None,
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
        logprobs: Vec::new(),
    });
    assert_eq!(
        out["output"]["message"]["content"][0]["text"], "plain",
        "{out}"
    );
}

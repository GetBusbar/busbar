// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `v1.5.5` `crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs`, on the driver: what a
//! `prompt: ro` hook is shown of a request — the prompt view, the size signals, the end user, the
//! reasoning shapes and the opaque-content marker — as the llm plane's `project` writes it and the
//! driver hands it to the hook. Each test keeps its 1.5.5 name and the values 1.5.5 asserted.
//!
//! What a crossing does not carry is not asserted: whether a string was borrowed from the body
//! (every string crosses into the host's arena), and the system-only character count (the hook
//! wire never carried it; where a 1.5.5 test pinned it, the request carries no turn, so the total
//! it IS shown equals it).

use serde_json::{json, Value};

use crate::policies::{capturing, CapturedReq};
use crate::rig::{member, Hooks, Pool, Rig};

/// The fixed non-content marker shown in place of opaque provider-encrypted reasoning.
const MARKER: &str = "[busbar:redacted_reasoning]";

/// Where each dialect's request is posted, and what its body needs beside the content.
fn target(dialect: &str, mut v: Value) -> (&'static str, Value) {
    let obj = v.as_object_mut().expect("a JSON object body");
    match dialect {
        "anthropic" => {
            obj.entry("model").or_insert(json!("m0"));
            obj.entry("max_tokens").or_insert(json!(16));
            ("/v1/messages", v)
        }
        "openai" => {
            obj.entry("model").or_insert(json!("m0"));
            ("/v1/chat/completions", v)
        }
        "responses" => {
            obj.entry("model").or_insert(json!("m0"));
            ("/v1/responses", v)
        }
        "gemini" => ("/v1beta/models/m0:generateContent", v),
        "bedrock" => ("/model/m0/converse", v),
        "cohere" => {
            obj.entry("model").or_insert(json!("m0"));
            ("/v2/chat", v)
        }
        other => panic!("no target for {other}"),
    }
}

/// What a `prompt: ro` base policy is shown of `v` posted in `dialect`; `None` when the request
/// never reached the hooks.
async fn shown(dialect: &str, v: Value) -> Option<CapturedReq> {
    let (seen, policy) = capturing(true, true, None);
    let rig = Rig::new(
        Pool {
            name: "p",
            members: vec![member("m0", "m0")],
        },
        None,
        Hooks {
            policy: Some(policy),
            ..Hooks::default()
        },
    );
    let (path, body) = target(dialect, v);
    let answer = rig
        .fire_with(
            &crate::common::TestUnits::passing(),
            path,
            if dialect == "anthropic" {
                &[
                    ("content-type", "application/json"),
                    ("anthropic-version", "2023-06-01"),
                ]
            } else {
                &[("content-type", "application/json")]
            },
            &serde_json::to_vec(&body).expect("body serializes"),
        )
        .await;
    let captured = seen.lock().unwrap().clone();
    if captured.is_none() {
        eprintln!(
            "{dialect} {path}: {} {} {:?}",
            answer.status,
            answer.text(),
            answer.outcome
        );
    }
    captured
}

/// [`shown`], when the request must reach the hooks.
async fn seen(dialect: &str, v: Value) -> CapturedReq {
    shown(dialect, v)
        .await
        .unwrap_or_else(|| panic!("the hook was shown the {dialect} request"))
}

fn prompt(c: &CapturedReq) -> (Option<String>, Vec<(String, String)>) {
    c.prompt
        .clone()
        .expect("a prompt: ro hook is shown the prompt")
}

fn turns(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(r, t)| (r.to_string(), t.to_string()))
        .collect()
}

#[tokio::test]
async fn prompt_projection_flattens_string_and_block_content() {
    let c = seen(
        "anthropic",
        json!({
            "system": "be brief",
            "messages": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": [
                    {"type": "text", "text": "part one"},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}},
                    {"type": "text", "text": "part two"}
                ]}
            ]
        }),
    )
    .await;
    let (system, messages) = prompt(&c);
    assert_eq!(system.as_deref(), Some("be brief"));
    assert_eq!(
        messages,
        turns(&[("user", "hello"), ("assistant", "part one\npart two")])
    );
}

#[tokio::test]
async fn prompt_projection_system_blocks_and_absent() {
    let c = seen(
        "anthropic",
        json!({
            "system": [{"type": "text", "text": "sys a"}, {"type": "text", "text": "sys b"}],
            "messages": [{"role": "user", "content": "hi"}]
        }),
    )
    .await;
    assert_eq!(prompt(&c).0.as_deref(), Some("sys a\nsys b"));

    let c = seen(
        "anthropic",
        json!({"messages": [{"role": "user", "content": "hi"}]}),
    )
    .await;
    assert_eq!(prompt(&c).0, None);
}

#[tokio::test]
async fn prompt_projection_keeps_empty_entries_aligned() {
    let c = seen(
        "anthropic",
        json!({
            "messages": [
                {"role": "user", "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}
                ]},
                {"role": "assistant", "content": "second turn"}
            ]
        }),
    )
    .await;
    let (_, messages) = prompt(&c);
    assert_eq!(messages.len(), 2, "media-only entries must not vanish");
    assert_eq!(messages[0].0, "user");
    assert_eq!(messages[0].1, "", "media-only turn reads as empty text");
    assert_eq!(
        messages[1],
        ("assistant".to_string(), "second turn".to_string())
    );
    assert_eq!(c.message_count, 2);
}

#[tokio::test]
async fn system_text_chars_counts_block_arrays() {
    // No turn carries text, so the total a hook is shown is the system's own count.
    let c = seen(
        "anthropic",
        json!({
            "system": [{"type": "text", "text": "abcde"}, {"type": "text", "text": "fgh"}],
            "messages": [{"role": "user", "content": ""}]
        }),
    )
    .await;
    assert_eq!(c.total_chars, 8);
    assert_eq!(prompt(&c).0.as_deref(), Some("abcde\nfgh"));

    let c = seen(
        "anthropic",
        json!({"system": "plain", "messages": [{"role": "user", "content": ""}]}),
    )
    .await;
    assert_eq!(c.total_chars, 5);
}

#[tokio::test]
async fn prompt_projection_reads_gemini_contents() {
    let c = seen(
        "gemini",
        json!({
            "systemInstruction": {"parts": [{"text": "be brief"}]},
            "contents": [
                {"role": "user", "parts": [{"text": "hello"}]},
                {"role": "model", "parts": [
                    {"text": "part one"},
                    {"inlineData": {"mimeType": "image/png", "data": "AAAA"}},
                    {"text": "part two"}
                ]}
            ]
        }),
    )
    .await;
    let (system, messages) = prompt(&c);
    assert_eq!(system.as_deref(), Some("be brief"));
    assert_eq!(
        messages,
        turns(&[("user", "hello"), ("assistant", "part one\npart two")])
    );
    assert_eq!(c.message_count, 2);
    assert_eq!(c.total_chars, 8 + 5 + 16);
}

#[tokio::test]
async fn prompt_projection_reads_responses_input() {
    let c = seen(
        "responses",
        json!({
            "instructions": "be brief",
            "input": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": [{"type": "output_text", "text": "hi there"}]}
            ]
        }),
    )
    .await;
    let (system, messages) = prompt(&c);
    assert_eq!(system.as_deref(), Some("be brief"));
    assert_eq!(
        messages,
        turns(&[("user", "hello"), ("assistant", "hi there")])
    );
    assert_eq!(c.message_count, 2);

    // A bare-string `input` is ONE implicit user turn.
    let c = seen("responses", json!({"input": "just a question"})).await;
    assert_eq!(prompt(&c).1, turns(&[("user", "just a question")]));
    assert_eq!(c.message_count, 1);
    assert_eq!(c.total_chars, 15);

    // Top-level typed items carry text at the item root, roles inferred from `type`.
    let c = seen(
        "responses",
        json!({
            "input": [
                {"type": "input_text", "text": "hello"},
                {"type": "output_text", "text": "hi back"}
            ]
        }),
    )
    .await;
    assert_eq!(
        prompt(&c).1,
        turns(&[("user", "hello"), ("assistant", "hi back")]),
        "top-level input_text/output_text items must project with inferred roles, not blank"
    );
    assert_eq!(c.message_count, 2);
    assert_eq!(c.total_chars, 12);
}

#[tokio::test]
async fn max_tokens_signal_is_dialect_aware_for_responses() {
    // Responses ingress: only `max_output_tokens` is present.
    let c = seen(
        "responses",
        json!({"input": "hi", "max_output_tokens": 4096}),
    )
    .await;
    assert_eq!(c.max_tokens, Some(4096));
    // A stray `max_tokens` on a responses body is NOT the signal.
    let c = seen(
        "responses",
        json!({"input": "hi", "max_tokens": 999, "max_output_tokens": 4096}),
    )
    .await;
    assert_eq!(c.max_tokens, Some(4096));
    // Every other dialect reads `max_tokens`.
    let c = seen(
        "anthropic",
        json!({"messages": [{"role": "user", "content": "hi"}], "max_tokens": 512}),
    )
    .await;
    assert_eq!(c.max_tokens, Some(512));
    let c = seen(
        "gemini",
        json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}], "max_tokens": 512}),
    )
    .await;
    assert_eq!(c.max_tokens, Some(512));
    // An absurd cap saturates rather than wrapping.
    let c = seen(
        "openai",
        json!({"messages": [{"role": "user", "content": "hi"}], "max_tokens": u64::MAX}),
    )
    .await;
    assert_eq!(c.max_tokens, Some(u32::MAX));
}

#[tokio::test]
async fn prompt_projection_reads_bedrock_messages() {
    let c = seen(
        "bedrock",
        json!({
            "system": [{"text": "sys"}],
            "messages": [
                {"role": "user", "content": [{"text": "hello"}, {"text": "again"}]}
            ]
        }),
    )
    .await;
    let (system, messages) = prompt(&c);
    assert_eq!(system.as_deref(), Some("sys"));
    assert_eq!(messages[0].1, "hello\nagain");
    assert_eq!(c.message_count, 1);
    assert_eq!(c.total_chars, 3 + 10);
}

fn user_of(c: &CapturedReq) -> Option<String> {
    c.identity.clone().and_then(|(_, _, u)| u)
}

#[tokio::test]
async fn body_end_user_reads_both_dialects() {
    let hi = json!([{"role": "user", "content": "hi"}]);
    let c = seen("openai", json!({"user": "alice", "messages": hi})).await;
    assert_eq!(user_of(&c).as_deref(), Some("alice"));
    let c = seen(
        "anthropic",
        json!({"metadata": {"user_id": "bob"}, "messages": hi}),
    )
    .await;
    assert_eq!(user_of(&c).as_deref(), Some("bob"));
    let c = seen("anthropic", json!({"messages": hi})).await;
    assert_eq!(user_of(&c), None);
}

/// One assistant turn carrying `block`, in `dialect`'s own conversation shape.
fn assistant_turn(dialect: &str, block: Value) -> Value {
    match dialect {
        "responses" => json!({"input": [block]}),
        "gemini" => json!({"contents": [{"role": "model", "parts": [block]}]}),
        _ => json!({"messages": [{"role": "assistant", "content": [block]}]}),
    }
}

#[tokio::test]
async fn prompt_projection_sees_anthropic_thinking_text() {
    let c = seen(
        "anthropic",
        assistant_turn(
            "anthropic",
            json!({"type": "thinking", "thinking": "SMUGGLED", "signature": "sig"}),
        ),
    )
    .await;
    assert_eq!(prompt(&c).1, turns(&[("assistant", "SMUGGLED")]));
}

#[tokio::test]
async fn prompt_projection_sees_bedrock_reasoning_text() {
    let c = seen(
        "bedrock",
        assistant_turn(
            "bedrock",
            json!({"reasoningContent": {"reasoningText": {"text": "SMUGGLED", "signature": "sig-xyz"}}}),
        ),
    )
    .await;
    let (_, messages) = prompt(&c);
    assert_eq!(messages, turns(&[("assistant", "SMUGGLED")]));
    assert!(!messages[0].1.contains("sig-xyz"));
}

#[tokio::test]
async fn prompt_projection_sees_responses_reasoning_summary_only() {
    let c = seen(
        "responses",
        assistant_turn(
            "responses",
            json!({"type": "reasoning", "summary": [{"type": "summary_text", "text": "SMUGGLED"}]}),
        ),
    )
    .await;
    let (_, messages) = prompt(&c);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].1, "SMUGGLED");
}

#[tokio::test]
async fn prompt_projection_marks_anthropic_redacted_thinking() {
    let c = seen(
        "anthropic",
        assistant_turn(
            "anthropic",
            json!({"type": "redacted_thinking", "data": "OPAQUE_CIPHERTEXT_BYTES"}),
        ),
    )
    .await;
    let (_, messages) = prompt(&c);
    assert_eq!(messages, turns(&[("assistant", MARKER)]));
    assert!(!messages[0].1.contains("OPAQUE_CIPHERTEXT_BYTES"));
}

#[tokio::test]
async fn prompt_projection_marks_bedrock_redacted_content() {
    let c = seen(
        "bedrock",
        assistant_turn(
            "bedrock",
            json!({"reasoningContent": {"redactedContent": "OPAQUE_CIPHERTEXT_BYTES"}}),
        ),
    )
    .await;
    let (_, messages) = prompt(&c);
    assert_eq!(messages, turns(&[("assistant", MARKER)]));
    assert!(!messages[0].1.contains("OPAQUE_CIPHERTEXT_BYTES"));
}

#[tokio::test]
async fn prompt_projection_marks_responses_encrypted_content_only_reasoning() {
    let c = seen(
        "responses",
        assistant_turn(
            "responses",
            json!({"type": "reasoning", "encrypted_content": "OPAQUE_BLOB_XYZ"}),
        ),
    )
    .await;
    let (_, messages) = prompt(&c);
    assert_eq!(messages, turns(&[("assistant", MARKER)]));
    assert!(!messages[0].1.contains("OPAQUE_BLOB_XYZ"));
}

#[tokio::test]
async fn prompt_projection_and_total_chars_mark_responses_reasoning_with_empty_content_array() {
    let c = seen(
        "responses",
        assistant_turn(
            "responses",
            json!({"type": "reasoning", "content": [], "encrypted_content": "OPAQUE_BLOB_XYZ"}),
        ),
    )
    .await;
    let (_, messages) = prompt(&c);
    assert_eq!(messages, turns(&[("assistant", MARKER)]));
    assert!(!messages[0].1.contains("OPAQUE_BLOB_XYZ"));
    assert_eq!(
        c.total_chars,
        MARKER.chars().count(),
        "the size signal counts the marker's length, not silently 0"
    );
}

#[tokio::test]
async fn block_text_responses_reasoning_rejects_malformed_encrypted_content() {
    // A malformed blob is not a real opaque blob: an item carrying nothing else projects no
    // marker (the reader drops it, as it never ships it).
    for blob in [json!(""), json!(123)] {
        let c = seen(
            "responses",
            json!({"input": [
                {"type": "reasoning", "encrypted_content": blob},
                {"role": "user", "content": "q"}
            ]}),
        )
        .await;
        assert!(
            prompt(&c).1.iter().all(|(_, t)| !t.contains(MARKER)),
            "{blob}: a malformed encrypted_content must not read as opaque content"
        );
    }
}

#[tokio::test]
async fn prompt_projection_responses_reasoning_prefers_text_over_encrypted_content() {
    let c = seen(
        "responses",
        assistant_turn(
            "responses",
            json!({
                "type": "reasoning",
                "content": [{"type": "reasoning_text", "text": "VISIBLE"}],
                "encrypted_content": "ENC_BLOB_123"
            }),
        ),
    )
    .await;
    let (_, messages) = prompt(&c);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].1, "VISIBLE");
    assert!(!messages[0].1.contains(MARKER));
    assert!(!messages[0].1.contains("ENC_BLOB_123"));
}

#[tokio::test]
async fn responses_single_part_reasoning_text_borrows() {
    let c = seen(
        "responses",
        assistant_turn(
            "responses",
            json!({"type": "reasoning", "content": [{"type": "reasoning_text", "text": "one part"}]}),
        ),
    )
    .await;
    assert_eq!(prompt(&c).1[0].1, "one part");
    let c = seen(
        "responses",
        assistant_turn(
            "responses",
            json!({"type": "reasoning", "summary": [{"type": "summary_text", "text": "just a summary"}]}),
        ),
    )
    .await;
    assert_eq!(prompt(&c).1[0].1, "just a summary");
}

#[tokio::test]
async fn responses_multi_part_reasoning_text_concatenates() {
    let c = seen(
        "responses",
        assistant_turn(
            "responses",
            json!({
                "type": "reasoning",
                "content": [
                    {"type": "reasoning_text", "text": "first "},
                    {"type": "reasoning_text", "text": "second "}
                ],
                "summary": [{"type": "summary_text", "text": "third"}]
            }),
        ),
    )
    .await;
    assert_eq!(prompt(&c).1[0].1, "first second third");
}

#[tokio::test]
async fn prompt_projection_attributes_responses_reasoning_to_assistant() {
    let c = seen(
        "responses",
        assistant_turn(
            "responses",
            json!({"type": "reasoning", "content": [{"type": "reasoning_text", "text": "chain of thought"}]}),
        ),
    )
    .await;
    let (_, messages) = prompt(&c);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0, "assistant");
}

#[tokio::test]
async fn prompt_projection_mixed_text_and_thinking_turn_joins_both() {
    let c = seen(
        "anthropic",
        json!({
            "messages": [
                {"role": "assistant", "content": [
                    {"type": "text", "text": "visible answer"},
                    {"type": "thinking", "thinking": "SMUGGLED", "signature": "sig"}
                ]}
            ]
        }),
    )
    .await;
    assert_eq!(prompt(&c).1[0].1, "visible answer\nSMUGGLED");
}

#[tokio::test]
async fn prompt_projection_gemini_thought_part_still_projects() {
    let c = seen(
        "gemini",
        json!({
            "contents": [
                {"role": "model", "parts": [
                    {"text": "the answer", "thought": false},
                    {"text": "reasoning about it", "thought": true, "thoughtSignature": "sig"}
                ]}
            ]
        }),
    )
    .await;
    assert_eq!(prompt(&c).1[0].1, "the answer\nreasoning about it");
}

#[tokio::test]
async fn total_text_chars_counts_reasoning_text() {
    let c = seen(
        "anthropic",
        assistant_turn(
            "anthropic",
            json!({"type": "thinking", "thinking": "12345"}),
        ),
    )
    .await;
    assert_eq!(c.total_chars, 5);
    let c = seen(
        "bedrock",
        assistant_turn(
            "bedrock",
            json!({"reasoningContent": {"reasoningText": {"text": "1234567"}}}),
        ),
    )
    .await;
    assert_eq!(c.total_chars, 7);
    let c = seen(
        "responses",
        assistant_turn(
            "responses",
            json!({"type": "reasoning", "summary": [{"type": "summary_text", "text": "123"}]}),
        ),
    )
    .await;
    assert_eq!(c.total_chars, 3);
}

#[tokio::test]
async fn size_signal_and_projection_agree_on_reasoning() {
    let c = seen(
        "anthropic",
        json!({
            "messages": [
                {"role": "assistant", "content": [
                    {"type": "text", "text": "visible"},
                    {"type": "thinking", "thinking": "hidden reasoning"}
                ]},
                {"role": "assistant", "content": [
                    {"type": "redacted_thinking", "data": "opaque"}
                ]}
            ]
        }),
    )
    .await;
    let projected: usize = prompt(&c).1.iter().map(|(_, t)| t.chars().count()).sum();
    // One separator newline per block boundary within a turn; the size signal counts text only.
    assert_eq!(projected, c.total_chars + 1);
}

#[tokio::test]
async fn every_known_protocol_has_a_declared_reasoning_wire_shape() {
    // (dialect, a reasoning block in its own shape, the text it must show, or the marker).
    let rows: Vec<(&str, Option<Value>, Option<&str>)> = vec![
        (
            "anthropic",
            Some(json!({"type": "thinking", "thinking": "W"})),
            Some("W"),
        ),
        (
            "anthropic",
            Some(json!({"type": "redacted_thinking", "data": "b64"})),
            None,
        ),
        (
            "bedrock",
            Some(json!({"reasoningContent": {"reasoningText": {"text": "W"}}})),
            Some("W"),
        ),
        (
            "bedrock",
            Some(json!({"reasoningContent": {"redactedContent": "b64"}})),
            None,
        ),
        (
            "responses",
            Some(json!({"type": "reasoning", "summary": [{"type": "summary_text", "text": "W"}]})),
            Some("W"),
        ),
        (
            "responses",
            Some(json!({"type": "reasoning", "encrypted_content": "OPAQUE_BLOB"})),
            None,
        ),
        // No dialect-specific reasoning shape: the generic text probe covers it.
        ("gemini", None, None),
        ("openai", None, None),
        ("cohere", None, None),
    ];
    let dialects: Vec<&str> = crate::plane::dialect::DIALECTS
        .iter()
        .map(|d| d.name)
        .collect();
    for d in &dialects {
        assert!(
            rows.iter().any(|(p, _, _)| p == d),
            "dialect '{d}' has no row in this witness table — declare its reasoning wire shape"
        );
    }
    assert_eq!(
        rows.iter()
            .map(|(p, _, _)| *p)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        dialects.len(),
        "witness table covers a different dialect set than the plane's"
    );
    for (dialect, sample, text) in rows {
        let Some(sample) = sample else { continue };
        let c = seen(dialect, assistant_turn(dialect, sample)).await;
        let shown = prompt(&c).1;
        let turn = &shown.last().expect("the reasoning turn is shown").1;
        match text {
            Some(needle) => assert!(turn.contains(needle), "{dialect}: {turn:?}"),
            None => assert_eq!(turn, MARKER, "{dialect}"),
        }
    }
}

#[tokio::test]
async fn apply_rewrite_to_body_echoes_redacted_marker_as_visible_text() {
    let body = json!({
        "model": "m0",
        "max_tokens": 16,
        "messages": [
            {"role": "assistant", "content": [
                {"type": "redacted_thinking", "data": "OPAQUE_CIPHERTEXT_BYTES"}
            ]}
        ]
    });
    let c = seen("anthropic", body.clone()).await;
    assert_eq!(prompt(&c).1[0].1, MARKER);

    // A hook that echoes exactly what it was projected (the common "pass through" rewrite shape).
    let echo = std::sync::Arc::new(crate::policies::RewritingGate(vec![json!({
        "role": "assistant",
        "content": MARKER,
    })]));
    let rig = Rig::new(
        Pool {
            name: "p",
            members: vec![member("m0", "m0")],
        },
        None,
        Hooks {
            rewrites: vec![(std::time::Duration::from_millis(500), echo)],
            ..Hooks::default()
        },
    );
    let answer = rig.fire(&body).await;
    let sent: Value = serde_json::from_slice(
        &answer
            .sent
            .last()
            .expect("the rewritten request was dispatched")
            .body,
    )
    .expect("the far end's body is JSON");
    let msgs = sent["messages"].as_array().expect("messages array");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["content"].as_str(), Some(MARKER));
    assert!(!sent.to_string().contains("OPAQUE_CIPHERTEXT_BYTES"));
}

use super::*;

/// `build_prompt_projection` flattens both Anthropic content shapes: bare-string content and
/// `{type:"text"}` block arrays (text blocks joined by newline, non-text blocks skipped).
#[test]
fn prompt_projection_flattens_string_and_block_content() {
    let v: Value = serde_json::json!({
        "system": "be brief",
        "messages": [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "part one"},
                {"type": "image", "source": {"data": "AAAA"}},
                {"type": "text", "text": "part two"}
            ]}
        ]
    });
    let p = build_prompt_projection(&v, "anthropic");
    assert_eq!(p.system.as_deref(), Some("be brief"));
    assert_eq!(
        p.messages,
        vec![
            ("user".into(), "hello".into()),
            ("assistant".into(), "part one\npart two".into()),
        ] as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    // The bare-string message BORROWS from the body (the zero-copy path); the block-array
    // message is owned (flattening had to join).
    assert!(matches!(p.messages[0].1, std::borrow::Cow::Borrowed(_)));
    assert!(matches!(p.messages[1].1, std::borrow::Cow::Owned(_)));
}

/// A system prompt given as a BLOCK ARRAY (Anthropic allows both) flattens too; an absent /
/// empty system stays `None` so the wire omits the key.
#[test]
fn prompt_projection_system_blocks_and_absent() {
    let v: Value = serde_json::json!({
        "system": [{"type": "text", "text": "sys a"}, {"type": "text", "text": "sys b"}],
        "messages": []
    });
    let p = build_prompt_projection(&v, "anthropic");
    assert_eq!(p.system.as_deref(), Some("sys a\nsys b"));

    let v: Value = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});
    let p = build_prompt_projection(&v, "anthropic");
    assert_eq!(p.system, None);

    // A non-JSON / bodyless request (v == Null) projects empty, never panics.
    let p = build_prompt_projection(&Value::Null, "anthropic");
    assert_eq!(p.system, None);
    assert!(p.messages.is_empty());
}

/// PINS the message-entry contract: a media-only message (no text blocks) keeps its ENTRY with
/// empty text (index-aligned with the body and `message_count`, never silently dropped), and a
/// malformed message with no `role` key projects an empty role. The system field, by contrast,
/// coalesces empty to absent (there is no index to keep).
#[test]
fn prompt_projection_keeps_empty_entries_aligned() {
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "user", "content": [{"type": "image", "source": {"data": "AAAA"}}]},
            {"content": "no role on this one"}
        ]
    });
    let p = build_prompt_projection(&v, "anthropic");
    assert_eq!(p.messages.len(), 2, "media-only entries must not vanish");
    assert_eq!(p.messages[0].0, "user");
    assert_eq!(p.messages[0].1, "", "media-only turn reads as empty text");
    assert_eq!(p.messages[1].0, "", "missing role projects as empty role");
    assert_eq!(p.messages[1].1, "no role on this one");
}

/// The SIZE signal and the content projection agree on a BLOCK-ARRAY system prompt: Anthropic
/// allows `system` as text blocks, and `system_text_chars` must count what
/// `build_prompt_projection` flattens (they diverged once — this is the tripwire).
#[test]
fn system_text_chars_counts_block_arrays() {
    let v: Value = serde_json::json!({
        "system": [{"type": "text", "text": "abcde"}, {"type": "text", "text": "fgh"}],
        "messages": []
    });
    assert_eq!(system_text_chars(&v, "anthropic"), 8);
    let p = build_prompt_projection(&v, "anthropic");
    // The flattened projection joins with a newline; the SIZE signal counts text only.
    assert_eq!(p.system.as_deref(), Some("abcde\nfgh"));

    let v: Value = serde_json::json!({"system": "plain", "messages": []});
    assert_eq!(system_text_chars(&v, "anthropic"), 5);
    assert_eq!(system_text_chars(&Value::Null, "anthropic"), 0);
}

/// The projection read-path was blind to GEMINI ingress — it read
/// only `messages`/`system`, so a gemini body (`contents`/`systemInstruction`/`parts`)
/// projected EMPTY: a rewrite gate saw `message_count: 0` with no prompt and silently
/// no-oped. The read side must mirror the dialects `apply_rewrite_to_body` writes.
#[test]
fn prompt_projection_reads_gemini_contents() {
    let v: Value = serde_json::json!({
        "systemInstruction": {"parts": [{"text": "be brief"}]},
        "contents": [
            {"role": "user", "parts": [{"text": "hello"}]},
            {"role": "model", "parts": [
                {"text": "part one"},
                {"inlineData": {"mimeType": "image/png", "data": "AAAA"}},
                {"text": "part two"}
            ]}
        ]
    });
    let p = build_prompt_projection(&v, "gemini");
    assert_eq!(p.system.as_deref(), Some("be brief"));
    assert_eq!(
        p.messages,
        vec![
            ("user".into(), "hello".into()),
            // Gemini-native `model` is CANONICALIZED to `assistant` for the hook's IR view
            // (audit c1r14) — the hook sees the same vocabulary on every dialect.
            ("assistant".into(), "part one\npart two".into()),
        ] as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    // SIZE signals agree with the projection (minus join separators).
    assert_eq!(system_text_chars(&v, "gemini"), 8);
    assert_eq!(turn_count(&v, "gemini"), 2);
    assert_eq!(total_text_chars(&v, "gemini", 8), 8 + 5 + 16);
    // And the rewrite-request projection (the gate's view) is POPULATED, not blind.
    let req = build_rewrite_request(&v, "p", "gemini", false, true);
    assert_eq!(req.message_count, 2);
    assert!(req.total_chars > 0);
    assert_eq!(req.prompt.as_ref().unwrap().messages.len(), 2);
}

/// Responses-API half: `input` (list OR bare string) and
/// `instructions` must project — the old read-path saw neither.
#[test]
fn prompt_projection_reads_responses_input() {
    let v: Value = serde_json::json!({
        "instructions": "be brief",
        "input": [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": [{"type": "output_text", "text": "hi there"}]}
        ]
    });
    let p = build_prompt_projection(&v, "responses");
    assert_eq!(p.system.as_deref(), Some("be brief"));
    assert_eq!(
        p.messages,
        vec![
            ("user".into(), "hello".into()),
            ("assistant".into(), "hi there".into()),
        ] as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    assert_eq!(system_text_chars(&v, "responses"), 8);
    assert_eq!(turn_count(&v, "responses"), 2);

    // A bare-string `input` is ONE implicit user turn — in the projection AND the count.
    let v: Value = serde_json::json!({"input": "just a question"});
    let p = build_prompt_projection(&v, "responses");
    assert_eq!(
        p.messages,
        vec![("user".into(), "just a question".into())]
            as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    assert_eq!(turn_count(&v, "responses"), 1);
    assert_eq!(total_text_chars(&v, "responses", 0), 15);

    let req = build_rewrite_request(&v, "p", "responses", false, true);
    assert_eq!(req.message_count, 1);
    assert_eq!(req.total_chars, 15);

    // TOP-LEVEL typed items in `input[]` carry text at the item ROOT
    // (`{type:"input_text", text}`), not under `content`. They must project (not blank) and
    // count toward the SIZE signal, with role inferred from `type`.
    let v: Value = serde_json::json!({
        "input": [
            {"type": "input_text", "text": "hello"},
            {"type": "output_text", "text": "hi back"}
        ]
    });
    let p = build_prompt_projection(&v, "responses");
    assert_eq!(
        p.messages,
        vec![
            ("user".into(), "hello".into()),
            ("assistant".into(), "hi back".into()),
        ] as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>,
        "top-level input_text/output_text items must project with inferred roles, not blank"
    );
    assert_eq!(
        total_text_chars(&v, "responses", 0),
        5 + 7,
        "top-level item text must count toward the size signal, not read as 0"
    );
    let req = build_rewrite_request(&v, "p", "responses", false, true);
    assert_eq!(req.message_count, 2);
    assert_eq!(req.total_chars, 12);
}

/// The `max_tokens` routing SIZE signal must be dialect-aware. The
/// Responses API names it `max_output_tokens`, so reading `max_tokens` unconditionally projected
/// `None` for every responses-ingress request — silently blinding any routing policy/tap that
/// keys on the size signal. Non-responses dialects still read `max_tokens`.
#[test]
fn max_tokens_signal_is_dialect_aware_for_responses() {
    // Responses ingress: only `max_output_tokens` is present.
    let resp: Value = serde_json::json!({"input": "hi", "max_output_tokens": 4096});
    assert_eq!(max_tokens_for(&resp, "responses"), Some(4096));
    // A stray `max_tokens` on a responses body is NOT the signal — the dialect ignores it.
    let resp_stray: Value =
        serde_json::json!({"input": "hi", "max_tokens": 999, "max_output_tokens": 4096});
    assert_eq!(max_tokens_for(&resp_stray, "responses"), Some(4096));
    // The routing projection is now populated for a responses request.
    let req = build_rewrite_request(&resp, "p", "responses", false, true);
    assert_eq!(req.max_tokens, Some(4096));

    // Every other dialect keeps reading `max_tokens`.
    let anth: Value = serde_json::json!({"messages": [], "max_tokens": 512});
    assert_eq!(max_tokens_for(&anth, "anthropic"), Some(512));
    assert_eq!(max_tokens_for(&anth, "gemini"), Some(512));
    // Absurd cap saturates rather than wrapping.
    let huge: Value = serde_json::json!({"max_tokens": u64::MAX});
    assert_eq!(max_tokens_for(&huge, "anthropic"), Some(u32::MAX));
}

/// Bedrock ingress rides the `messages` default: its `content: [{text}]` blocks (no `type`
/// key) flatten via the same text-keyed match as Anthropic blocks.
#[test]
fn prompt_projection_reads_bedrock_messages() {
    let v: Value = serde_json::json!({
        "system": [{"text": "sys"}],
        "messages": [
            {"role": "user", "content": [{"text": "hello"}, {"text": "again"}]}
        ]
    });
    let p = build_prompt_projection(&v, "bedrock");
    assert_eq!(p.system.as_deref(), Some("sys"));
    assert_eq!(p.messages[0].1, "hello\nagain");
    assert_eq!(turn_count(&v, "bedrock"), 1);
    assert_eq!(total_text_chars(&v, "bedrock", 3), 3 + 10);
}

/// `body_end_user` is dialect-aware: OpenAI `user` first, Anthropic `metadata.user_id` second,
/// `None` when neither (or the field is not a string).
#[test]
fn body_end_user_reads_both_dialects() {
    let v: Value = serde_json::json!({"user": "alice"});
    assert_eq!(body_end_user(&v).as_deref(), Some("alice"));
    let v: Value = serde_json::json!({"metadata": {"user_id": "bob"}});
    assert_eq!(body_end_user(&v).as_deref(), Some("bob"));
    let v: Value = serde_json::json!({"user": "alice", "metadata": {"user_id": "bob"}});
    assert_eq!(body_end_user(&v).as_deref(), Some("alice"));
    let v: Value = serde_json::json!({"user": 42});
    assert_eq!(body_end_user(&v), None);
    assert_eq!(body_end_user(&Value::Null), None);
    // Empty means "not supplied" in EITHER position: an empty OpenAI `user` falls THROUGH to
    // a populated Anthropic `metadata.user_id` (never shadows it), and empty-everywhere is
    // `None` — so an empty string can never ride the wire as `"user": ""`.
    let v: Value = serde_json::json!({"user": "", "metadata": {"user_id": "bob"}});
    assert_eq!(body_end_user(&v).as_deref(), Some("bob"));
    let v: Value = serde_json::json!({"user": ""});
    assert_eq!(body_end_user(&v), None);
    let v: Value = serde_json::json!({"metadata": {"user_id": ""}});
    assert_eq!(body_end_user(&v), None);
}

// ---------------------------------------------------------------------------------------------
// Reasoning-block hook-visibility bypass (`block_text`). The old probes keyed on
// `b.get("text")`, which stands in for a typed dispatch over block/dialect kind — every reasoning
// wire shape that stores its text under a DIFFERENT key (`thinking`, `reasoningContent.
// reasoningText.text`, `summary[].text`) fell through silently, so a `prompt: ro` screening hook
// saw `{role, text: ""}` for a turn the provider received in full: an operator-owned PII/DLP/
// guardrail gate silently passing content it was deployed to inspect. Two of the three shapes
// (Bedrock `reasoningText`, Responses summary-only `reasoning`) require NO signature at all to
// reach the provider verbatim — equally clean, no-forgery bypasses, not one worse than the other.
// ---------------------------------------------------------------------------------------------

/// Bypass #1: Anthropic `thinking` plaintext lives under the key `thinking`, not `text`
/// (`proto/anthropic/mod.rs` reader). Before the fix the projection read `""`.
#[test]
fn prompt_projection_sees_anthropic_thinking_text() {
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "SMUGGLED", "signature": "sig"}
            ]}
        ]
    });
    let p = build_prompt_projection(&v, "anthropic");
    assert_eq!(
        p.messages,
        vec![("assistant".into(), "SMUGGLED".into())]
            as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
}

/// Bypass #2 — the highest-value case: Bedrock's writer re-emits `reasoningContent.reasoningText`
/// with NO unsigned-drop filter (unlike Anthropic's egress path), so a client-fabricated, entirely
/// unsigned block ships to the provider verbatim. Before the fix the projection read `""`.
#[test]
fn prompt_projection_sees_bedrock_reasoning_text() {
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "assistant", "content": [
                {"reasoningContent": {"reasoningText": {"text": "SMUGGLED", "signature": "sig-xyz"}}}
            ]}
        ]
    });
    let p = build_prompt_projection(&v, "bedrock");
    assert_eq!(
        p.messages,
        vec![("assistant".into(), "SMUGGLED".into())]
            as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    // The generic arms must not incidentally pick up the sibling `signature` field as if it were
    // content — opaque provider material is not screenable text either. The fixture above carries
    // a real `signature` (Bedrock's `reasoningText` shape is `{text, signature}`, see
    // `proto/bedrock/mod.rs`'s `read_bedrock_reasoning_block`), so this assertion is meaningful:
    // without it, a naive dispatch could accidentally string-search the whole `reasoningContent`
    // object rather than just `reasoningText.text`.
    assert!(!p.messages[0].1.contains("sig-xyz"));
}

/// Bypass #3: a Responses `reasoning` INPUT item with NO `content` key (summary-only — the second
/// no-signature bypass: `encrypted_content` is `Option`, the reader admits the item on
/// `!text.is_empty()` alone) carries its text under `summary[].text`, never at the item root.
/// Before the fix the projection took the item-root `text` probe and read `""`.
#[test]
fn prompt_projection_sees_responses_reasoning_summary_only() {
    let v: Value = serde_json::json!({
        "input": [
            {"type": "reasoning", "summary": [{"type": "summary_text", "text": "SMUGGLED"}]}
        ]
    });
    let p = build_prompt_projection(&v, "responses");
    assert_eq!(p.messages.len(), 1);
    assert_eq!(p.messages[0].1.as_ref(), "SMUGGLED");
}

/// Anthropic `redacted_thinking` carries only opaque encrypted bytes — IR never holds plaintext
/// for it. The projection must show the fixed marker (a screening hook's correct read is "there is
/// content here I cannot screen", not "this turn is empty") and must NEVER expose the ciphertext:
/// handing a hook a base64 blob has zero screening value and would be a new information
/// disclosure (the bytes would reach an operator-configured sidecar that never saw them before).
#[test]
fn prompt_projection_marks_anthropic_redacted_thinking() {
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "assistant", "content": [
                {"type": "redacted_thinking", "data": "OPAQUE_CIPHERTEXT_BYTES"}
            ]}
        ]
    });
    let p = build_prompt_projection(&v, "anthropic");
    assert_eq!(
        p.messages,
        vec![("assistant".into(), REDACTED_REASONING_MARKER.into())]
            as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    assert!(!p.messages[0].1.contains("OPAQUE_CIPHERTEXT_BYTES"));
}

/// Same guard as above, Bedrock's redacted shape (`reasoningContent.redactedContent`).
#[test]
fn prompt_projection_marks_bedrock_redacted_content() {
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "assistant", "content": [
                {"reasoningContent": {"redactedContent": "OPAQUE_CIPHERTEXT_BYTES"}}
            ]}
        ]
    });
    let p = build_prompt_projection(&v, "bedrock");
    assert_eq!(
        p.messages,
        vec![("assistant".into(), REDACTED_REASONING_MARKER.into())]
            as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    assert!(!p.messages[0].1.contains("OPAQUE_CIPHERTEXT_BYTES"));
}

/// Role-inference bug: a Responses `reasoning` item is assistant-authored (the reader already
/// maps it to a standalone assistant `IrMessage`, `responses/reader.rs`), but the old `_ => "user"`
/// fallback attributed it to the caller. Isolated from the summary-only test above by using a
/// `content[]`-bearing item, which already projected its text correctly today — so this fails
/// ONLY on role, not on text visibility.
#[test]
fn prompt_projection_attributes_responses_reasoning_to_assistant() {
    let v: Value = serde_json::json!({
        "input": [
            {"type": "reasoning", "content": [{"type": "reasoning_text", "text": "chain of thought"}]}
        ]
    });
    let p = build_prompt_projection(&v, "responses");
    assert_eq!(p.messages.len(), 1);
    assert_eq!(p.messages[0].0.as_ref(), "assistant");
}

/// A single turn carrying both a `text` block and a `thinking` block: both must be projected,
/// newline-joined, order preserved (mirrors the existing mixed-content test for text/image).
#[test]
fn prompt_projection_mixed_text_and_thinking_turn_joins_both() {
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "assistant", "content": [
                {"type": "text", "text": "visible answer"},
                {"type": "thinking", "thinking": "SMUGGLED", "signature": "sig"}
            ]}
        ]
    });
    let p = build_prompt_projection(&v, "anthropic");
    assert_eq!(p.messages[0].1.as_ref(), "visible answer\nSMUGGLED");
}

/// Regression guard, NOT a RED test (passes before and after this fix): Gemini's thought part
/// already carries a real `text` field (`{text, thought:true, thoughtSignature}`), so the
/// dialect-dispatch reordering in `block_text` must not break it.
#[test]
fn prompt_projection_gemini_thought_part_still_projects() {
    let v: Value = serde_json::json!({
        "contents": [
            {"role": "model", "parts": [
                {"text": "the answer", "thought": false},
                {"text": "reasoning about it", "thought": true, "thoughtSignature": "sig"}
            ]}
        ]
    });
    let p = build_prompt_projection(&v, "gemini");
    assert_eq!(p.messages[0].1.as_ref(), "the answer\nreasoning about it");
}

/// SIZE signal: `total_text_chars` must count reasoning text across all three bypass shapes —
/// before the fix each contributed 0, silently under-counting a request a size-keyed routing
/// policy or tap keys on.
#[test]
fn total_text_chars_counts_reasoning_text() {
    let anthropic: Value = serde_json::json!({
        "messages": [{"role": "assistant", "content": [{"type": "thinking", "thinking": "12345"}]}]
    });
    assert_eq!(total_text_chars(&anthropic, "anthropic", 0), 5);

    let bedrock: Value = serde_json::json!({
        "messages": [{"role": "assistant", "content": [
            {"reasoningContent": {"reasoningText": {"text": "1234567"}}}
        ]}]
    });
    assert_eq!(total_text_chars(&bedrock, "bedrock", 0), 7);

    let responses: Value = serde_json::json!({
        "input": [{"type": "reasoning", "summary": [{"type": "summary_text", "text": "123"}]}]
    });
    assert_eq!(total_text_chars(&responses, "responses", 0), 3);
}

/// The divergence tripwire (`system_text_chars_counts_block_arrays`'s sibling), extended to
/// reasoning: `total_text_chars` must agree with `build_prompt_projection`'s char count, modulo
/// the documented one-char-per-block-boundary newline allowance — this is what keeps the shared
/// `block_text` extractor from re-diverging into three probe sites that silently drift apart
/// again (that drift is the documented reason this test file already has a "they diverged once"
/// tripwire for the non-reasoning case).
#[test]
fn size_signal_and_projection_agree_on_reasoning() {
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "assistant", "content": [
                {"type": "text", "text": "visible"},
                {"type": "thinking", "thinking": "hidden reasoning"}
            ]},
            {"role": "assistant", "content": [
                {"type": "redacted_thinking", "data": "opaque"}
            ]}
        ]
    });
    let total = total_text_chars(&v, "anthropic", 0);
    let p = build_prompt_projection(&v, "anthropic");
    let projected_chars: usize = p.messages.iter().map(|(_, t)| t.chars().count()).sum();
    // One separator newline per block boundary within a turn (turn 1 has 2 blocks => 1 newline);
    // turn 2 has 1 block => 0 newlines. `total_text_chars` counts text only, no separators.
    assert_eq!(projected_chars, total + 1);
}

/// Exhaustiveness guard for `block_text`'s dispatch, modeled on `ProtocolRegistry::with_builtins`
/// (`proto/mod.rs`) rather than on an `IrBlock`-variant witness table (`all_block_metas()`,
/// `proto/tests/stream_translate_tests.rs`): unlike `IrBlock`, `ingress_protocol` is a `&str`, so
/// rustc cannot make an unmatched arm a hard compile error. This is deliberately keyed on the
/// PROTOCOL axis, not the IR-variant axis — all three bypasses above collapse onto the SAME
/// existing `IrBlock::Thinking` variant (the IR is already unified across dialects), so an
/// IR-variant witness table would add zero new rows for any of them and would not catch a future
/// protocol-specific reasoning wire shape either. `KNOWN_PROTOCOLS` is the single source of truth
/// (also used by `ProtocolRegistry::with_builtins` and the config validator); a 7th protocol added
/// there without a row below fails THIS test, which `cargo test --workspace` runs in CI.
#[test]
fn every_known_protocol_has_a_declared_reasoning_wire_shape() {
    struct Row {
        protocol: &'static str,
        // `None` = this dialect has no reasoning-specific wire shape; the generic `text` probe
        // covers it (declared explicitly, not by omission).
        sample: Option<serde_json::Value>,
        expect_text_contains: Option<&'static str>,
        expect_redacted: bool,
    }
    let rows = vec![
        Row {
            protocol: "anthropic",
            sample: Some(serde_json::json!({"type": "thinking", "thinking": "W"})),
            expect_text_contains: Some("W"),
            expect_redacted: false,
        },
        Row {
            protocol: "anthropic",
            sample: Some(serde_json::json!({"type": "redacted_thinking", "data": "b64"})),
            expect_text_contains: None,
            expect_redacted: true,
        },
        Row {
            protocol: "bedrock",
            sample: Some(serde_json::json!({"reasoningContent": {"reasoningText": {"text": "W"}}})),
            expect_text_contains: Some("W"),
            expect_redacted: false,
        },
        Row {
            protocol: "bedrock",
            sample: Some(serde_json::json!({"reasoningContent": {"redactedContent": "b64"}})),
            expect_text_contains: None,
            expect_redacted: true,
        },
        Row {
            protocol: "responses",
            sample: Some(serde_json::json!({
                "type": "reasoning",
                "summary": [{"type": "summary_text", "text": "W"}]
            })),
            expect_text_contains: Some("W"),
            expect_redacted: false,
        },
        // gemini/openai/cohere: no dialect-specific reasoning shape declared in `block_text` —
        // every block's text (if any) goes through the generic `text`-field probe.
        Row {
            protocol: "gemini",
            sample: None,
            expect_text_contains: None,
            expect_redacted: false,
        },
        Row {
            protocol: "openai",
            sample: None,
            expect_text_contains: None,
            expect_redacted: false,
        },
        Row {
            protocol: "cohere",
            sample: None,
            expect_text_contains: None,
            expect_redacted: false,
        },
    ];

    // Belt-and-suspenders, mirroring `ProtocolRegistry::with_builtins`'s
    // `debug_assert_eq!(map.len(), KNOWN_PROTOCOLS.len())`: every `KNOWN_PROTOCOLS` name must
    // appear here, or a newly registered protocol silently has no declared reasoning-shape row.
    for &proto in crate::proto::KNOWN_PROTOCOLS {
        assert!(
            rows.iter().any(|r| r.protocol == proto),
            "protocol '{proto}' was added to KNOWN_PROTOCOLS but has no row in this witness \
             table — declare its reasoning wire shape (or explicitly `None`) in `block_text`'s \
             protocol dispatch AND here"
        );
    }
    assert_eq!(
        rows.iter()
            .map(|r| r.protocol)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        crate::proto::KNOWN_PROTOCOLS.len(),
        "witness table covers a different protocol set than KNOWN_PROTOCOLS"
    );

    for row in &rows {
        let Some(sample) = &row.sample else { continue };
        match block_text(sample, row.protocol) {
            BlockText::Text(t) => assert!(
                row.expect_text_contains
                    .is_some_and(|needle| t.contains(needle)),
                "protocol {} sample unexpectedly produced Text({t:?})",
                row.protocol
            ),
            BlockText::Redacted => assert!(
                row.expect_redacted,
                "protocol {} sample unexpectedly produced Redacted",
                row.protocol
            ),
            BlockText::None => panic!(
                "protocol {} sample produced BlockText::None — its declared reasoning shape is \
                 not being dispatched",
                row.protocol
            ),
        }
    }
}

/// REQUIRED (not optional — the `prompt: rw` behavior change this fix carries needs a test, not
/// just a CHANGELOG line): `apply_rewrite_to_body` is NOT index-aligned, so a `prompt: rw` hook
/// that ECHOES the projection it received writes reasoning text — or, for a redacted turn, the
/// non-content marker — into a REAL, visible content block that ships upstream. This is a
/// pre-existing, out-of-scope-to-fix hazard (documented on `apply_rewrite_to_body` and on
/// `REDACTED_REASONING_MARKER`); this test pins the CURRENT behavior (marker echoes as literal
/// text, not as corrupted/garbage bytes, and not as if it were trusted ciphertext) so a future
/// change to the write-back path cannot silently regress the documented note into a stale claim.
#[test]
fn apply_rewrite_to_body_echoes_redacted_marker_as_visible_text() {
    let mut v: Value = serde_json::json!({
        "messages": [
            {"role": "assistant", "content": [
                {"type": "redacted_thinking", "data": "OPAQUE_CIPHERTEXT_BYTES"}
            ]}
        ]
    });
    let p = build_prompt_projection(&v, "anthropic");
    assert_eq!(p.messages[0].1.as_ref(), REDACTED_REASONING_MARKER);

    // A hook that echoes exactly what it was projected (the common "pass through" rewrite shape).
    let rewrite = crate::hooks::wire::RewriteReply {
        messages: vec![serde_json::json!({
            "role": "assistant",
            "content": REDACTED_REASONING_MARKER,
        })],
        tools: vec![],
    };
    let applied = apply_rewrite_to_body(&mut v, &rewrite, "anthropic");
    assert!(applied);

    // The marker is now the LITERAL, VISIBLE assistant content that ships upstream — inert text,
    // never the raw ciphertext (which never left this projection in the first place), but a real
    // content injection into the request the hook did not compose from scratch.
    let msgs = v
        .get("messages")
        .and_then(Value::as_array)
        .expect("messages array");
    assert_eq!(msgs.len(), 1);
    assert_eq!(
        msgs[0].get("content").and_then(Value::as_str),
        Some(REDACTED_REASONING_MARKER)
    );
    assert!(!v.to_string().contains("OPAQUE_CIPHERTEXT_BYTES"));
}

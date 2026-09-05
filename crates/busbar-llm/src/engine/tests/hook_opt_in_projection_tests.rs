//! The opt-in hook CONTENT projection, read from the IR.
//!
//! Every test below used to call a second implementation of "what is the text in this request" —
//! `build_prompt_projection` and its `block_text`/`flatten_content`/`total_text_chars` siblings,
//! which re-derived the answer from the raw ingress body with their own per-dialect dispatch. That
//! implementation is gone. The FIXTURES are the asset and are unchanged; the entry point is the
//! accident, and it now runs through the protocol's own reader into `ir::facts`.
//!
//! Where a fixture's EXPECTED VALUE changed, the change is a deliberate semantic one, it is named in
//! the CHANGELOG, and the test says so at its own site. Everywhere else the expectations are
//! byte-identical to what the deleted implementation produced — which is the point: the projection
//! moved, the contract did not.

use super::*;
use busbar_substrate::ir::facts::OPAQUE_CONTENT_MARKER;

/// Read the fixture body into the hook seam's facts, asserting the reader accepts it.
fn facts(v: &Value, proto: &str) -> HookFacts {
    // These fixtures are chat JSON bodies: the object arm reads through the CHAT operation handler,
    // byte-identically to the pre-change seam (the `body`/`content_type` args are unused for an
    // object body).
    match read_hook_facts(
        v,
        &[],
        APPLICATION_JSON,
        proto,
        Some(busbar_api::operation::Operation::CHAT),
    ) {
        Ok(f) => f,
        Err(HookIrRejected) => {
            panic!("the {proto} reader refused this fixture body; that is a finding, not a nit")
        }
    }
}

/// The projection flattens both Anthropic content shapes: bare-string content and `{type:"text"}`
/// block arrays (text blocks joined by newline, non-text blocks skipped).
#[test]
fn prompt_projection_flattens_string_and_block_content() {
    crate::testkit::install_test_seams();
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
    let f = facts(&v, "anthropic");
    let p = f.prompt();
    assert_eq!(p.system.as_deref(), Some("be brief"));
    assert_eq!(
        p.messages,
        vec![
            ("user".into(), "hello".into()),
            ("assistant".into(), "part one\npart two".into()),
        ] as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    // The single-block message BORROWS from the IR (the zero-copy path); the multi-block message is
    // owned (the join had to allocate).
    assert!(matches!(p.messages[0].1, std::borrow::Cow::Borrowed(_)));
    assert!(matches!(p.messages[1].1, std::borrow::Cow::Owned(_)));
}

/// A system prompt given as a BLOCK ARRAY (Anthropic allows both) flattens too; an absent /
/// empty system stays `None` so the wire omits the key.
#[test]
fn prompt_projection_system_blocks_and_absent() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "system": [{"type": "text", "text": "sys a"}, {"type": "text", "text": "sys b"}],
        "messages": []
    });
    let f = facts(&v, "anthropic");
    assert_eq!(f.prompt().system.as_deref(), Some("sys a\nsys b"));

    let v: Value = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});
    let f = facts(&v, "anthropic");
    assert_eq!(f.prompt().system, None);

    // A non-JSON / bodyless request (v == Null) projects empty, never panics AND never rejects: it
    // is a request whose payload this seam never claimed to understand, not a malformed one.
    let f = facts(&Value::Null, "anthropic");
    let p = f.prompt();
    assert_eq!(p.system, None);
    assert!(p.messages.is_empty());
}

/// THE ALIGNMENT CONTRACT, RESTATED — this test pinned the old one and now pins the new one.
///
/// The projection used to contract itself index-aligned with the WIRE `messages` array. The IR
/// cannot honour that and must not: every reader HOISTS system-role content into the system slot,
/// so an in-band system turn is a system prompt here and not a turn. What the old contract existed
/// to PROTECT survives exactly: a media-only turn keeps its entry with empty text, so a screening
/// hook never sees fewer turns than the provider does. Entries index against `IrRequest::messages`.
///
/// The second half of the old fixture — a message with NO `role` key — no longer projects an empty
/// role: five readers hard-reject a role they do not recognise, and the ruling is that a body busbar
/// cannot read is the REQUEST's failure rather than something to screen best-effort and forward
/// anyway. That is asserted here as the rejection it now is.
#[test]
fn prompt_projection_keeps_empty_entries_aligned() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "user", "content": [{"type": "image", "source": {"data": "AAAA"}}]},
            {"role": "assistant", "content": "second turn"}
        ]
    });
    let f = facts(&v, "anthropic");
    let p = f.prompt();
    assert_eq!(p.messages.len(), 2, "media-only entries must not vanish");
    assert_eq!(p.messages[0].0, "user");
    assert_eq!(p.messages[0].1, "", "media-only turn reads as empty text");
    assert_eq!(p.messages[1].0, "assistant");
    assert_eq!(p.messages[1].1, "second turn");

    // The in-band system turn: hoisted into the system slot for the prompt view, but the turn count
    // a hook sees stays the wire array's length, exactly as the previous release counted it (a hook
    // written against 1.5.5 must read the same message_count).
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "system", "content": "OPERATOR SYSTEM PROMPT"},
            {"role": "user", "content": "hi"}
        ]
    });
    let f = facts(&v, "openai");
    let p = f.prompt();
    assert_eq!(p.system.as_deref(), Some("OPERATOR SYSTEM PROMPT"));
    assert_eq!(
        p.messages.len(),
        1,
        "the system turn is not a turn any more"
    );
    assert_eq!(p.messages[0].0, "user");
    assert_eq!(
        f.shape().turn_count,
        2,
        "the folded system turn still counts on the wire"
    );

    // A role no reader recognises is a 400, not a `role: ""` a guardrail is asked to screen.
    let v: Value = serde_json::json!({"messages": [{"role": "wizard", "content": "hi"}]});
    assert!(read_hook_facts(
        &v,
        &[],
        APPLICATION_JSON,
        "openai",
        Some(busbar_api::operation::Operation::CHAT)
    )
    .is_err());
}

/// The SIZE signal and the content projection agree on a BLOCK-ARRAY system prompt: Anthropic
/// allows `system` as text blocks, and the system char count must count what the projection
/// flattens (they diverged once — this is the tripwire, and on the IR the two are now a single walk
/// so there is nothing left for them to disagree about).
#[test]
fn system_text_chars_counts_block_arrays() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "system": [{"type": "text", "text": "abcde"}, {"type": "text", "text": "fgh"}],
        "messages": []
    });
    assert_eq!(facts(&v, "anthropic").shape().system_chars, 8);
    let f = facts(&v, "anthropic");
    // The flattened projection joins with a newline; the SIZE signal counts text only.
    assert_eq!(f.prompt().system.as_deref(), Some("abcde\nfgh"));

    let v: Value = serde_json::json!({"system": "plain", "messages": []});
    assert_eq!(facts(&v, "anthropic").shape().system_chars, 5);
    assert_eq!(facts(&Value::Null, "anthropic").shape().system_chars, 0);
}

/// GEMINI ingress: the read path must see `contents`/`systemInstruction`/`parts`. On the IR it sees
/// them because the gemini READER does — there is no second read path left to be blind.
#[test]
fn prompt_projection_reads_gemini_contents() {
    crate::testkit::install_test_seams();
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
    let f = facts(&v, "gemini");
    let p = f.prompt();
    assert_eq!(p.system.as_deref(), Some("be brief"));
    assert_eq!(
        p.messages,
        vec![
            ("user".into(), "hello".into()),
            // Gemini-native `model` reaches the hook as canonical `assistant` — the IR's own role
            // vocabulary, so the hook sees the same words on every dialect.
            ("assistant".into(), "part one\npart two".into()),
        ] as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    // SIZE signals agree with the projection (minus join separators).
    let shape = f.shape();
    assert_eq!(shape.system_chars, 8);
    assert_eq!(shape.turn_count, 2);
    assert_eq!(shape.text_chars, 8 + 5 + 16);
    // And the rewrite-request projection (the gate's view) is POPULATED, not blind.
    let req = build_rewrite_request(&f, None, "p", "gemini", false, true, 1);
    assert_eq!(req.message_count, 2);
    assert!(req.total_chars > 0);
    assert_eq!(req.prompt.as_ref().unwrap().messages.len(), 2);
}

/// Responses-API half: `input` (list OR bare string) and `instructions` must project.
#[test]
fn prompt_projection_reads_responses_input() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "instructions": "be brief",
        "input": [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": [{"type": "output_text", "text": "hi there"}]}
        ]
    });
    let f = facts(&v, "responses");
    let p = f.prompt();
    assert_eq!(p.system.as_deref(), Some("be brief"));
    assert_eq!(
        p.messages,
        vec![
            ("user".into(), "hello".into()),
            ("assistant".into(), "hi there".into()),
        ] as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    let shape = f.shape();
    assert_eq!(shape.system_chars, 8);
    assert_eq!(shape.turn_count, 2);

    // A bare-string `input` is ONE implicit user turn — in the projection AND the count.
    let v: Value = serde_json::json!({"input": "just a question"});
    let f = facts(&v, "responses");
    let p = f.prompt();
    assert_eq!(
        p.messages,
        vec![("user".into(), "just a question".into())]
            as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    assert_eq!(f.shape().turn_count, 1);
    assert_eq!(f.shape().text_chars, 15);

    let req = build_rewrite_request(&f, None, "p", "responses", false, true, 1);
    assert_eq!(req.message_count, 1);
    assert_eq!(req.total_chars, 15);

    // TOP-LEVEL typed items in `input[]` carry text at the item ROOT (`{type:"input_text", text}`),
    // not under `content`. They must project (not blank) and count toward the SIZE signal, with the
    // role the reader assigns.
    let v: Value = serde_json::json!({
        "input": [
            {"type": "input_text", "text": "hello"},
            {"type": "output_text", "text": "hi back"}
        ]
    });
    let f = facts(&v, "responses");
    let p = f.prompt();
    assert_eq!(
        p.messages,
        vec![
            ("user".into(), "hello".into()),
            ("assistant".into(), "hi back".into()),
        ] as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>,
        "top-level input_text/output_text items must project with the reader's roles, not blank"
    );
    assert_eq!(
        f.shape().text_chars,
        5 + 7,
        "top-level item text must count toward the size signal, not read as 0"
    );
    let req = build_rewrite_request(&f, None, "p", "responses", false, true, 1);
    assert_eq!(req.message_count, 2);
    assert_eq!(req.total_chars, 12);
}

/// The `max_tokens` routing SIZE signal is DIALECT-NORMALIZED, and normalizing it is the READER's
/// job. The old projection was dialect-aware for exactly one dialect's spelling
/// (`max_output_tokens`) and read `max_tokens` everywhere else — so a dialect that spells the cap
/// inside a nested config object projected `None` and silently blinded any policy keyed on the
/// signal. On the IR every spelling lands in one field, which is a FIX and not merely a move.
#[test]
fn max_tokens_signal_is_dialect_aware_for_responses() {
    crate::testkit::install_test_seams();
    // Responses ingress: only `max_output_tokens` is present.
    let resp: Value = serde_json::json!({"input": "hi", "max_output_tokens": 4096});
    assert_eq!(facts(&resp, "responses").shape().max_tokens, Some(4096));
    // The routing projection is populated for a responses request.
    let f = facts(&resp, "responses");
    let req = build_rewrite_request(&f, None, "p", "responses", false, true, 1);
    assert_eq!(req.max_tokens, Some(4096));

    // Every other dialect keeps reading its own spelling.
    let anth: Value = serde_json::json!({"messages": [], "max_tokens": 512});
    assert_eq!(facts(&anth, "anthropic").shape().max_tokens, Some(512));

    // THE FIX: Bedrock Converse spells the cap `inferenceConfig.maxTokens`. The old projection read
    // `max_tokens`, found nothing, and reported `None` — a routing policy keyed on the size signal
    // was blind to a Bedrock caller's cap. The reader reads it, so the signal now carries it.
    let bedrock: Value = serde_json::json!({
        "inferenceConfig": {"maxTokens": 128},
        "messages": [{"role": "user", "content": [{"text": "hello"}]}]
    });
    assert_eq!(facts(&bedrock, "bedrock").shape().max_tokens, Some(128));
}

/// Bedrock ingress: its `content: [{text}]` blocks (no `type` key) read through the bedrock reader.
#[test]
fn prompt_projection_reads_bedrock_messages() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "system": [{"text": "sys"}],
        "messages": [
            {"role": "user", "content": [{"text": "hello"}, {"text": "again"}]}
        ]
    });
    let f = facts(&v, "bedrock");
    let p = f.prompt();
    assert_eq!(p.system.as_deref(), Some("sys"));
    assert_eq!(p.messages[0].1, "hello\nagain");
    assert_eq!(f.shape().turn_count, 1);
    assert_eq!(f.shape().text_chars, 3 + 10);
}

/// The end-user identifier is dialect-normalized BY THE READER: OpenAI spells it `user`, Anthropic
/// `metadata.user_id`, and the hook seam reads one field either way.
#[test]
fn body_end_user_reads_both_dialects() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({"messages": [], "user": "alice"});
    assert_eq!(facts(&v, "openai").end_user().as_deref(), Some("alice"));
    let v: Value = serde_json::json!({"messages": [], "metadata": {"user_id": "bob"}});
    assert_eq!(facts(&v, "anthropic").end_user().as_deref(), Some("bob"));
    let v: Value = serde_json::json!({"messages": []});
    assert_eq!(facts(&v, "openai").end_user(), None);
    assert_eq!(facts(&Value::Null, "openai").end_user(), None);
}

// ---------------------------------------------------------------------------------------------
// Reasoning-block hook-visibility. Every reasoning wire shape stores its text under a DIFFERENT key
// per dialect (`thinking`, `reasoningContent.reasoningText.text`, `summary[].text`); a projection
// that probed for a `text` field silently dropped every one of them, so a `prompt: ro` screening
// hook saw `{role, text: ""}` for a turn the provider received in full — an operator-owned PII/DLP
// gate silently passing content it was deployed to inspect. On the IR every one of them is an
// `IrBlock::Thinking` because the READER put it there, and the projection cannot miss it.
// ---------------------------------------------------------------------------------------------

/// Anthropic `thinking` plaintext lives under the key `thinking`, not `text`.
#[test]
fn prompt_projection_sees_anthropic_thinking_text() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "SMUGGLED", "signature": "sig"}
            ]}
        ]
    });
    let f = facts(&v, "anthropic");
    assert_eq!(
        f.prompt().messages,
        vec![("assistant".into(), "SMUGGLED".into())]
            as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
}

/// Bedrock's writer re-emits `reasoningContent.reasoningText` with NO unsigned-drop filter, so a
/// client-fabricated, entirely unsigned block ships to the provider verbatim. It must be screenable.
#[test]
fn prompt_projection_sees_bedrock_reasoning_text() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "assistant", "content": [
                {"reasoningContent": {"reasoningText": {"text": "SMUGGLED", "signature": "sig-xyz"}}}
            ]}
        ]
    });
    let f = facts(&v, "bedrock");
    let p = f.prompt();
    assert_eq!(
        p.messages,
        vec![("assistant".into(), "SMUGGLED".into())]
            as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    // The signature is opaque provider material, not screenable text, and must not ride along.
    assert!(!p.messages[0].1.contains("sig-xyz"));
}

/// A Responses `reasoning` INPUT item with NO `content` key (summary-only) carries its text under
/// `summary[].text`, never at the item root.
#[test]
fn prompt_projection_sees_responses_reasoning_summary_only() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "input": [
            {"type": "reasoning", "summary": [{"type": "summary_text", "text": "SMUGGLED"}]}
        ]
    });
    let f = facts(&v, "responses");
    let p = f.prompt();
    assert_eq!(p.messages.len(), 1);
    assert_eq!(p.messages[0].1.as_ref(), "SMUGGLED");
}

/// Anthropic `redacted_thinking` carries only opaque encrypted bytes. The projection must show the
/// fixed marker (a screening hook's correct read is "there is content here I cannot screen", not
/// "this turn is empty") and must NEVER expose the ciphertext: handing a hook a base64 blob has zero
/// screening value and would be a new information disclosure to an operator-configured sidecar.
///
/// On the IR the ciphertext IS `Thinking.text`, so this test is also the guard on the order of the
/// two checks: opacity is asked FIRST, `text` is read only after.
#[test]
fn prompt_projection_marks_anthropic_redacted_thinking() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "assistant", "content": [
                {"type": "redacted_thinking", "data": "OPAQUE_CIPHERTEXT_BYTES"}
            ]}
        ]
    });
    let f = facts(&v, "anthropic");
    let p = f.prompt();
    assert_eq!(
        p.messages,
        vec![("assistant".into(), OPAQUE_CONTENT_MARKER.into())]
            as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    assert!(!p.messages[0].1.contains("OPAQUE_CIPHERTEXT_BYTES"));
}

/// Same guard, Bedrock's redacted shape (`reasoningContent.redactedContent`).
#[test]
fn prompt_projection_marks_bedrock_redacted_content() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "assistant", "content": [
                {"reasoningContent": {"redactedContent": "OPAQUE_CIPHERTEXT_BYTES"}}
            ]}
        ]
    });
    let f = facts(&v, "bedrock");
    let p = f.prompt();
    assert_eq!(
        p.messages,
        vec![("assistant".into(), OPAQUE_CONTENT_MARKER.into())]
            as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    assert!(!p.messages[0].1.contains("OPAQUE_CIPHERTEXT_BYTES"));
}

/// A Responses `reasoning` item admitted by the reader on its opaque `encrypted_content` blob ALONE
/// must project the marker, not read as "nothing here". The blob rides `Thinking.signature` while
/// `Thinking.text` is EMPTY, so a projection that keyed on the text would show a hook an empty turn
/// for a request the provider receives in full — the original bypass, restored. The opacity
/// predicate is what stops that, and this is its witness.
#[test]
fn prompt_projection_marks_responses_encrypted_content_only_reasoning() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "input": [
            {"type": "reasoning", "encrypted_content": "OPAQUE_BLOB_XYZ"}
        ]
    });
    let f = facts(&v, "responses");
    let p = f.prompt();
    assert_eq!(
        p.messages,
        vec![("assistant".into(), OPAQUE_CONTENT_MARKER.into())]
            as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    assert!(!p.messages[0].1.contains("OPAQUE_BLOB_XYZ"));
}

/// The same item with `"content": []` explicitly PRESENT (an empty array, not absent) — a real,
/// client-triggerable shape the reader still admits on the blob alone. The SIZE signal must count
/// the marker, not silently contribute 0.
#[test]
fn prompt_projection_and_total_chars_mark_responses_reasoning_with_empty_content_array() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "input": [
            {"type": "reasoning", "content": [], "encrypted_content": "OPAQUE_BLOB_XYZ"}
        ]
    });
    let f = facts(&v, "responses");
    let p = f.prompt();
    assert_eq!(
        p.messages,
        vec![("assistant".into(), OPAQUE_CONTENT_MARKER.into())]
            as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    assert!(!p.messages[0].1.contains("OPAQUE_BLOB_XYZ"));
    assert_eq!(
        f.shape().text_chars,
        OPAQUE_CONTENT_MARKER.chars().count(),
        "the size signal must count the marker's length, not silently contribute 0"
    );
}

/// Malformed `encrypted_content` (empty string, non-string) must NOT be treated as a real opaque
/// blob. That filter is the READER's — `read_reasoning_encrypted_content` — and this test now points
/// at it directly, where it already lives, instead of at a second copy of its accept/skip rules.
#[test]
fn responses_reasoning_reader_rejects_malformed_encrypted_content() {
    crate::testkit::install_test_seams();
    // The reader's own accept/skip rules (`read_reasoning_encrypted_content` rejecting an empty
    // string / non-string blob) are asserted directly beside that codec now — RELOCATED to
    // `busbar-llm` (`src/tests/proto/phase1_5_relocated_tests.rs`).
    // What stays here is the END-TO-END projection assertion, which is core hook behavior.
    // An item carrying neither text nor a usable blob contributes no content at all.
    let v: Value = serde_json::json!({"input": [{"type": "reasoning", "encrypted_content": ""}]});
    let f = facts(&v, "responses");
    assert!(f.prompt().messages.iter().all(|(_, text)| text.is_empty()));
}

/// A realistic round-trip shape carrying BOTH real `content[reasoning_text]` text AND a non-empty
/// `encrypted_content` signature: the plaintext must win — project as real text, not the marker —
/// and neither the marker nor the blob's bytes leak into the wrong place.
#[test]
fn prompt_projection_responses_reasoning_prefers_text_over_encrypted_content() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "input": [
            {
                "type": "reasoning",
                "content": [{"type": "reasoning_text", "text": "VISIBLE"}],
                "encrypted_content": "ENC_BLOB_123"
            }
        ]
    });
    let f = facts(&v, "responses");
    let p = f.prompt();
    assert_eq!(p.messages.len(), 1);
    assert_eq!(p.messages[0].1.as_ref(), "VISIBLE");
    assert!(!p.messages[0].1.contains(OPAQUE_CONTENT_MARKER));
    assert!(!p.messages[0].1.contains("ENC_BLOB_123"));
}

// `responses_single_part_reasoning_text_borrows` and `responses_multi_part_reasoning_text_concatenates`
// RELOCATED to `busbar-llm` (`src/tests/proto/phase1_5_relocated_tests.rs`): they named the
// witnessed `openai_responses::read_reasoning_text` codec fn directly and
// exercised nothing else, so they now live beside that codec.

/// A Responses `reasoning` item is assistant-authored, and the READER already says so — it maps the
/// item to a standalone assistant `IrMessage`. Re-pointed here, the projection and the reader agree
/// by construction rather than by two functions happening to pick the same word.
#[test]
fn prompt_projection_attributes_responses_reasoning_to_assistant() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "input": [
            {"type": "reasoning", "content": [{"type": "reasoning_text", "text": "chain of thought"}]}
        ]
    });
    let f = facts(&v, "responses");
    let p = f.prompt();
    assert_eq!(p.messages.len(), 1);
    assert_eq!(p.messages[0].0.as_ref(), "assistant");
}

/// A single turn carrying both a `text` block and a `thinking` block: both must be projected,
/// newline-joined, in the order the reader produced them — which is the order the writer will send.
#[test]
fn prompt_projection_mixed_text_and_thinking_turn_joins_both() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "assistant", "content": [
                {"type": "text", "text": "visible answer"},
                {"type": "thinking", "thinking": "SMUGGLED", "signature": "sig"}
            ]}
        ]
    });
    let f = facts(&v, "anthropic");
    assert_eq!(
        f.prompt().messages[0].1.as_ref(),
        "visible answer\nSMUGGLED"
    );
}

/// Gemini's thought part (`{text, thought:true, thoughtSignature}`) is classified by the gemini
/// READER as reasoning rather than merged into ordinary text — a strictly better test after the
/// move, because it now asserts the classification instead of asserting that a generic `text` probe
/// happened to catch it.
#[test]
fn prompt_projection_gemini_thought_part_still_projects() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "contents": [
            {"role": "model", "parts": [
                {"text": "the answer", "thought": false},
                {"text": "reasoning about it", "thought": true, "thoughtSignature": "sig"}
            ]}
        ]
    });
    let f = facts(&v, "gemini");
    assert_eq!(
        f.prompt().messages[0].1.as_ref(),
        "the answer\nreasoning about it"
    );
}

/// SIZE signal: the char count must count reasoning text across all three wire shapes — each one
/// contributed 0 to the old count, silently under-counting a request a size-keyed policy keys on.
#[test]
fn total_text_chars_counts_reasoning_text() {
    crate::testkit::install_test_seams();
    let anthropic: Value = serde_json::json!({
        "messages": [{"role": "assistant", "content": [{"type": "thinking", "thinking": "12345"}]}]
    });
    assert_eq!(facts(&anthropic, "anthropic").shape().text_chars, 5);

    let bedrock: Value = serde_json::json!({
        "messages": [{"role": "assistant", "content": [
            {"reasoningContent": {"reasoningText": {"text": "1234567"}}}
        ]}]
    });
    assert_eq!(facts(&bedrock, "bedrock").shape().text_chars, 7);

    let responses: Value = serde_json::json!({
        "input": [{"type": "reasoning", "summary": [{"type": "summary_text", "text": "123"}]}]
    });
    assert_eq!(facts(&responses, "responses").shape().text_chars, 3);
}

/// The divergence tripwire, extended to reasoning: the SIZE signal must agree with the content
/// projection's char count, modulo the documented one-char-per-block-boundary newline allowance.
///
/// On the IR the two are a single walk over a single item stream, so the drift this tripwire was
/// written for is now structurally impossible rather than merely tested against. It stays because
/// "these two agree" is a claim worth continuing to check.
#[test]
fn size_signal_and_projection_agree_on_reasoning() {
    crate::testkit::install_test_seams();
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
    let f = facts(&v, "anthropic");
    let total = f.shape().text_chars;
    let p = f.prompt();
    let projected_chars: usize = p.messages.iter().map(|(_, t)| t.chars().count()).sum();
    // One separator newline per block boundary within a turn (turn 1 has 2 blocks => 1 newline);
    // turn 2 has 1 block => 0 newlines. The size signal counts text only, no separators.
    assert_eq!(projected_chars, total + 1);
}

/// The tripwire the other two do not reach: a TOOL-role message whose `content` is a bare string,
/// plus the assistant turn that CALLED the tool.
///
/// A tool result is the largest UNTRUSTED blob in a modern agent request — attacker-influenced
/// content (a web page, a file, a database row) that goes upstream verbatim. Both the size signal
/// and the content projection must carry it, or a PII redactor is a gate that passes what it never
/// saw.
///
/// WHAT CHANGED, deliberately: the tool CALL's arguments are now projected too. They are the most
/// attacker-influenceable field in an agent request, they went upstream verbatim, and the old
/// projection showed a gate nothing at all for the turn that carried them. That is a widening, it is
/// in the CHANGELOG, and it is bounded by `limits.hook_content_max_bytes`.
#[test]
fn size_signal_and_projection_agree_on_tool_role_content() {
    crate::testkit::install_test_seams();
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "user", "content": "run it"},
            {"role": "assistant", "content": null,
             "tool_calls": [{"id": "c1", "type": "function",
                             "function": {"name": "f", "arguments": "{\"q\":\"x\"}"}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "TOOL RESULT PAYLOAD"}
        ]
    });
    let f = facts(&v, "openai");
    let p = f.prompt();
    assert_eq!(p.messages.len(), 3, "no turn is dropped");
    assert_eq!(p.messages[2].0, "tool");
    assert_eq!(
        p.messages[2].1, "TOOL RESULT PAYLOAD",
        "a tool result is attacker-influenced content that goes upstream verbatim; a screening \
         hook that cannot see it is a gate that passes what it never saw"
    );
    assert!(
        p.messages[1].1.contains("\"q\""),
        "the tool call's ARGUMENTS are now projected: {:?}",
        p.messages[1].1
    );

    let total = f.shape().text_chars;
    let projected: usize = p.messages.iter().map(|(_, t)| t.chars().count()).sum();
    assert_eq!(
        projected, total,
        "SIZE signal and CONTENT projection must agree on a tool-role turn (no block-boundary \
         newlines here: every turn is a single item)"
    );

    // Block-array tool content agrees too, so the agreement is not an artifact of one wire shape.
    let arr: Value = serde_json::json!({
        "messages": [{"role": "tool", "tool_call_id": "c1",
                      "content": [{"type": "text", "text": "TOOL RESULT PAYLOAD"}]}]
    });
    let f = facts(&arr, "openai");
    assert_eq!(f.prompt().messages[0].1, "TOOL RESULT PAYLOAD");
    assert_eq!(f.shape().text_chars, 19);
}

// THE EXHAUSTIVENESS GUARD (every registered protocol has a reader that produces a readable IR, so
// a seventh protocol is covered by REGISTERING rather than by an arm added anywhere) —
// `every_known_protocol_has_a_declared_reasoning_wire_shape` RELOCATED to `busbar-llm`
// (`src/tests/proto/phase1_5_relocated_tests.rs`): it drove the
// witnessed codec (`protocol_for(...).reader()`) and named the concrete IR (`ir.shape()`,
// `ir::project`), so it now lives beside the codec/IR it exercises.

/// The write-back is NOT index-aligned, so a `prompt: rw` hook that ECHOES the projection it
/// received writes reasoning text — or, for an opaque turn, the non-content marker — into a REAL,
/// visible content block that ships upstream. This is a pre-existing hazard, documented on the
/// writer method that now owns the write-back framing; this test pins the CURRENT behaviour (the
/// marker echoes as literal text, not as corrupted bytes and not as if it were trusted ciphertext)
/// so a future change to the write-back path cannot silently regress the note into a stale claim.
#[test]
fn apply_rewrite_to_body_echoes_redacted_marker_as_visible_text() {
    crate::testkit::install_test_seams();
    let mut v: Value = serde_json::json!({
        "messages": [
            {"role": "assistant", "content": [
                {"type": "redacted_thinking", "data": "OPAQUE_CIPHERTEXT_BYTES"}
            ]}
        ]
    });
    {
        let f = facts(&v, "anthropic");
        assert_eq!(f.prompt().messages[0].1.as_ref(), OPAQUE_CONTENT_MARKER);
    }

    // A hook that echoes exactly what it was projected (the common "pass through" rewrite shape).
    let rewrite = busbar_api::RewriteReply {
        messages: vec![serde_json::json!({
            "role": "assistant",
            "content": OPAQUE_CONTENT_MARKER,
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
        Some(OPAQUE_CONTENT_MARKER)
    );
    assert!(!v.to_string().contains("OPAQUE_CIPHERTEXT_BYTES"));
}

/// The content ceiling (`limits.hook_content_max_bytes`), in two halves, run in ONE test because the
/// ceiling is a process-global atomic and mutating it from parallel tests would race.
///
/// 1. DEFAULT is UNLIMITED (`== 0`): the LLM prompt projection is sent UNCAPPED, byte-for-byte as
///    v1.5.4 did. This pins the fail-open-is-GONE contract — with the cap OFF (the default) a large
///    body is projected in FULL, so a `prompt: rw` redaction gate SEES the content it must redact
///    instead of being handed an empty projection while the ORIGINAL body sails upstream.
/// 2. The ceiling stays available as an OPT-IN: when an operator sets a non-zero ceiling, over-cap
///    content is OMITTED WHOLE — never truncated mid-value, because a guardrail that screens half a
///    payload and passes it is worse than one that refuses — and the grant is still honoured, so the
///    hook receives a PRESENT-but-EMPTY projection rather than the absence an ungranted hook sees.
///    The always-present size bucket still reports the real total, so the omission is visible.
#[test]
fn hook_content_uncapped_by_default_and_omits_whole_when_opted_in() {
    crate::testkit::install_test_seams();
    let big = "x".repeat(200_000);
    let v: Value = serde_json::json!({"messages": [{"role": "user", "content": big}]});
    let f = facts(&v, "openai");

    // 1. DEFAULT (unlimited): the over-64KiB body is projected in FULL — not blanked (v1.5.4 parity).
    crate::engine::set_hook_content_max_bytes(crate::engine::DEFAULT_HOOK_CONTENT_MAX_BYTES);
    assert_eq!(
        crate::engine::DEFAULT_HOOK_CONTENT_MAX_BYTES,
        0,
        "the LLM prompt projection default is UNLIMITED (0); anything else is fail-open regression"
    );
    let req = build_rewrite_request(&f, None, "p", "openai", false, true, 1);
    let prompt = req
        .prompt
        .as_ref()
        .expect("a rewrite gate always gets the prompt projection");
    assert_eq!(
        prompt.messages.len(),
        1,
        "with the cap OFF by default the body is projected in FULL — a redaction gate must SEE the \
         content it screens, never be fail-open no-op'd"
    );
    assert_eq!(prompt.messages[0].1.len(), 200_000, "content sent uncapped");

    // 2. OPT-IN ceiling: over-cap content is omitted WHOLE, grant stays visible (present-but-empty).
    crate::engine::set_hook_content_max_bytes(64 * 1024);
    let req = build_rewrite_request(&f, None, "p", "openai", false, true, 1);
    let prompt = req.prompt.as_ref().expect(
        "the grant is honoured: an over-cap projection is EMPTY, never absent — absence is what an \
         UNGRANTED hook sees, and the two must stay distinguishable",
    );
    assert!(prompt.messages.is_empty(), "content omitted whole");
    assert_eq!(prompt.system, None);
    assert_eq!(
        req.total_chars, 200_000,
        "the size bucket still reports the real total, so the omission is visible"
    );

    // Restore the unlimited default for other tests sharing the process-global ceiling.
    crate::engine::set_hook_content_max_bytes(crate::engine::DEFAULT_HOOK_CONTENT_MAX_BYTES);
}

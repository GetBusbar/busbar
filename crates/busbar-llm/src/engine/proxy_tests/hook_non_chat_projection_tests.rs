// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CLOSE NON-CHAT GATE-BLINDNESS — the seam-level proof.
//!
//! Before this change the hook/gate/tap seam (`read_hook_facts`) knew only the protocol and always
//! read through the CHAT reader, so a `prompt: ro` DLP/PII gate saw NOTHING on an embeddings / image
//! / audio / rerank / moderation / subscribe request while it forwarded upstream. Each test below
//! drives a real non-chat body through the seam with its resolved operation and asserts the gate now
//! sees the screenable content — and that binary inputs surface as the opaque marker, never silently
//! empty.

use super::*;
use busbar_core::operation::Operation;

/// The exact strings a `prompt: ro` gate is shown for this body, flattened across turns.
fn gate_view(facts: &HookFacts) -> String {
    let p = facts.prompt();
    let mut out: Vec<String> = p.system.map(|s| s.into_owned()).into_iter().collect();
    for (_role, text) in p.messages {
        out.push(text.into_owned());
    }
    out.join("\n")
}

/// Read a JSON-object body through the operation-general seam (the `body`/`content_type` args are
/// unused for an object body — the value reader is taken).
fn seam(v: &Value, proto: &str, op: Operation) -> HookFacts {
    read_hook_facts(v, &[], APPLICATION_JSON, proto, Some(op))
        .unwrap_or_else(|_| panic!("the {proto} {op:?} reader refused this body"))
}

#[test]
fn embeddings_body_is_no_longer_gate_blind() {
    let v = serde_json::json!({"model": "text-embedding-3-large", "input": "SCREEN-THIS-INPUT"});
    let f = seam(&v, "openai", Operation::EMBEDDINGS);
    assert!(
        f.shape().text_chars > 0,
        "embeddings request must not project empty"
    );
    assert!(gate_view(&f).contains("SCREEN-THIS-INPUT"));
}

#[test]
fn image_body_is_no_longer_gate_blind() {
    let v = serde_json::json!({"model": "gpt-image-1", "prompt": "SCREEN-THIS-PROMPT"});
    let f = seam(&v, "openai", Operation::IMAGE);
    assert!(gate_view(&f).contains("SCREEN-THIS-PROMPT"));
}

#[test]
fn speech_body_projects_input_and_instructions() {
    let v = serde_json::json!({
        "model": "gpt-4o-mini-tts",
        "input": "SPEAK-THIS",
        "voice": "alloy",
        "instructions": "STYLE-INSTRUCTIONS"
    });
    let f = seam(&v, "openai", Operation::SPEECH);
    let view = gate_view(&f);
    assert!(view.contains("SPEAK-THIS"));
    assert!(
        view.contains("STYLE-INSTRUCTIONS"),
        "FATAL-2: instructions must be screened"
    );
}

#[test]
fn moderation_body_projects_text_and_marks_image_url_opaque() {
    let v = serde_json::json!({
        "model": "omni-moderation-latest",
        "input": [
            {"type": "text", "text": "SCREEN-THIS-TEXT"},
            {"type": "image_url", "image_url": {"url": "https://x.test/y.png"}}
        ]
    });
    let f = seam(&v, "openai", Operation::MODERATION);
    let view = gate_view(&f);
    assert!(view.contains("SCREEN-THIS-TEXT"));
    // MAJOR-5: the ImageUrl is present-but-unscreenable, shown as the marker — not empty, not leaked.
    assert!(view.contains(busbar_substrate::ir::facts::OPAQUE_CONTENT_MARKER));
    assert!(!view.contains("x.test"));
}

#[test]
fn rerank_body_projects_query_and_documents() {
    let v = serde_json::json!({
        "model": "rerank-v3.5",
        "query": "THE-QUERY",
        "documents": ["DOC-ONE", "DOC-TWO"]
    });
    let f = seam(&v, "cohere", Operation::RERANK);
    let view = gate_view(&f);
    assert!(view.contains("THE-QUERY") && view.contains("DOC-ONE") && view.contains("DOC-TWO"));
}

#[test]
fn subscribe_body_projects_its_target() {
    let v = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "resources/subscribe",
        "params": {"uri": "mcp://resource/SECRET-TARGET"}
    });
    let f = seam(&v, "mcp", Operation::SUBSCRIBE);
    assert!(gate_view(&f).contains("SECRET-TARGET"));
}

/// FATAL-1: a multipart transcription body reaches the seam as a NON-object (its DOM is `Value::Null`
/// / absent), so the caller `prompt` is reachable ONLY through the byte reader. The seam must thread
/// the raw bytes + content-type and project the prompt — the `&Value` path physically cannot.
#[test]
fn transcription_prompt_is_seen_through_the_byte_seam() {
    let boundary = "----busbartestBOUNDARY";
    let body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n\
         --{b}\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nSCREEN-THIS-PROMPT\r\n\
         --{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.mp3\"\r\n\
         Content-Type: audio/mpeg\r\n\r\nRAWAUDIOBYTES\r\n\
         --{b}--\r\n",
        b = boundary
    );
    let ct = format!("multipart/form-data; boundary={boundary}");
    // The multipart body never parses as JSON, so the DOM is Null — exactly what the engine passes.
    let facts = read_hook_facts(
        &Value::Null,
        body.as_bytes(),
        &ct,
        "openai",
        Some(Operation::TRANSCRIPTION),
    )
    .expect("the transcription byte reader accepts this multipart body");
    assert!(
        gate_view(&facts).contains("SCREEN-THIS-PROMPT"),
        "the multipart transcription prompt must be screenable through the byte seam"
    );
}

/// The op-less / bodyless capture stays Absent, and a JSON body whose protocol serves no such
/// operation is Absent (no reader to ask) — never a spurious rejection.
#[test]
fn absent_semantics_hold_for_opless_and_bodyless() {
    // No operation (the pre-routing auth capture): Absent.
    assert!(matches!(
        read_hook_facts(&Value::Null, &[], "", "openai", None).unwrap(),
        HookFacts::Absent
    ));
    // A JSON object body but an unregistered protocol: no handler, so Absent (not a rejection).
    let v = serde_json::json!({"input": "x"});
    assert!(matches!(
        read_hook_facts(
            &v,
            &[],
            APPLICATION_JSON,
            "not-a-protocol",
            Some(Operation::EMBEDDINGS)
        )
        .unwrap(),
        HookFacts::Absent
    ));
}

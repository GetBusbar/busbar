// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ABSENT SEMANTICS for the hook projection, on the plane that projects it (ported from the
//! predev-only `busbar-llm` test `hook_non_chat_projection_tests::
//! absent_semantics_hold_for_opless_and_bodyless`, whose `read_hook_facts` is the plane's `project`
//! on the driver): an arrival the plane has no operation reader for, or one with no body, projects
//! the EMPTY view (no turn, no system text, no size signal) and is never refused as unreadable. So
//! does a multipart upload the operation's byte reader refuses: 1.5.5 showed a hook the null body
//! for every request body that was not JSON (`v1.5.5` `crates/busbar/src/proxy/engine/mod.rs:955-961`)
//! and served the request.

use busbar_plane_llm::exchange::arrive::Arrived;
use busbar_plane_llm::exchange::project::{project, HookView};

fn arrived(dialect: &'static str, body: &[u8], parsed: Option<serde_json::Value>) -> Arrived {
    Arrived {
        dialect,
        operation: busbar_contract::operation::OpVerb::EMBEDDINGS,
        model: "m0".to_string(),
        content_type: "application/json".to_string(),
        body: body.to_vec(),
        parsed,
        path: "/v1/embeddings".to_string(),
        query: None,
        path_model: None,
    }
}

#[test]
fn absent_semantics_hold_for_opless_and_bodyless() {
    // A JSON object body under a dialect with no operation reader: the empty view, not a refusal.
    let v = serde_json::json!({"input": "x"});
    let view = project(&arrived(
        "not-a-protocol",
        &serde_json::to_vec(&v).expect("serializes"),
        Some(v),
    ));
    assert_eq!(view, HookView::default());
    // No body at all: the empty view.
    let view = project(&arrived("openai", b"", None));
    assert_eq!(view.turns, Vec::<(String, String)>::new());
    assert_eq!(
        (view.system, view.text_chars, view.turn_count),
        (None, 0, 0)
    );
}

/// A transcription upload with no `file` part, which the byte reader refuses, projects the EMPTY
/// view (its `prompt` part unseen), never a refusal.
#[test]
fn a_multipart_body_the_byte_reader_refuses_projects_the_empty_view() {
    let boundary = "----busbarunreadable";
    let body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nm0\r\n\
         --{b}\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nNOT-PROJECTED\r\n\
         --{b}--\r\n",
        b = boundary
    );
    let content_type = format!("multipart/form-data; boundary={boundary}");
    let fields: &[(&[u8], &[u8])] = &[(b"content-type", content_type.as_bytes())];
    let arrived = busbar_plane_llm::exchange::arrive::arrive(
        "POST",
        "/v1/audio/transcriptions",
        fields,
        body.as_bytes(),
        &(),
    )
    .expect("the upload arrives");
    assert!(arrived.parsed.is_none(), "a multipart body is not JSON");
    let view = project(&arrived);
    assert_eq!(view.turns, Vec::<(String, String)>::new());
    assert_eq!(
        (view.system, view.text_chars, view.turn_count),
        (None, 0, 0)
    );
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ABSENT SEMANTICS for the hook projection, on the plane that projects it (ported from the
//! predev-only `busbar-llm` test `hook_non_chat_projection_tests::
//! absent_semantics_hold_for_opless_and_bodyless`, whose `read_hook_facts` is the plane's `project`
//! on the driver): an arrival the plane has no operation reader for, or one with no body, projects
//! the EMPTY view (no turn, no system text, no size signal) and is never refused as unreadable.

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
    ))
    .expect("an opless arrival is not unreadable");
    assert_eq!(view, HookView::default());
    // No body at all: the empty view.
    let view =
        project(&arrived("openai", b"", None)).expect("a bodyless arrival is not unreadable");
    assert_eq!(view.turns, Vec::<(String, String)>::new());
    assert_eq!(
        (view.system, view.text_chars, view.turn_count),
        (None, 0, 0)
    );
}

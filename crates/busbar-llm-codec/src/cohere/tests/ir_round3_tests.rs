// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR mapping: the Cohere request-side citation carrier (COH-17).
use crate::proto_codec::protocol_for;
use serde_json::json;

fn grounded_history_without_text() -> serde_json::Value {
    json!({
        "model": "command-a",
        "messages": [
            {"role": "user", "content": "q"},
            {"role": "assistant",
             "tool_calls": [{"id": "t1", "type": "function",
                             "function": {"name": "f", "arguments": "{}"}}],
             "citations": [{"start": 0, "end": 5, "text": "hello", "type": "TEXT_CONTENT",
                            "sources": [{"type": "document", "id": "d1",
                                         "document": {"title": "t"}}]}]},
            {"role": "tool", "tool_call_id": "t1", "content": "ok"}
        ]
    })
}

/// Item 13: a replayed grounded assistant turn with no text part keeps its citations in the IR
/// (an empty text carrier), and an Anthropic / Bedrock egress omits the carrier rather than send
/// the empty text block those APIs reject.
#[test]
fn item13_request_citations_without_text_are_carried_not_sent_as_empty_text() {
    let ir = protocol_for("cohere")
        .unwrap()
        .reader()
        .read_request(&grounded_history_without_text())
        .expect("read");
    let assistant = ir
        .messages
        .iter()
        .find(|m| m.role == crate::ir::IrRole::Assistant)
        .expect("assistant");
    assert!(
        assistant.content.iter().any(|b| b.is_citation_carrier()),
        "{assistant:?}"
    );
    for egress in ["anthropic", "bedrock", "gemini"] {
        let mut req = ir.clone();
        req.extra.clear();
        let out = protocol_for(egress).unwrap().writer().write_request(&req);
        let s = out.to_string();
        assert!(
            !s.contains(r#""text":"""#),
            "{egress}: an empty text block reached the wire: {out}"
        );
    }
}

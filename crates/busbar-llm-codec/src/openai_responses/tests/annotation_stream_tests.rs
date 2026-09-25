// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Item 305 — a STREAMED Responses upstream's `url_citation` annotations. A native stream carries
//! each annotation as a `response.output_text.annotation.added` frame; the reader must carry it as
//! an `IrDelta::CitationsDelta` on the text block, and the streamed citations must EQUAL what the
//! buffered `read_response` reads from the same answer's `annotations` array (stream ≡ non-stream).

use super::*;

const URL_A: &str = "https://example.com/sky";
const URL_B: &str = "https://example.org/rayleigh";

fn annotation(url: &str, title: &str, start: u64, end: u64) -> serde_json::Value {
    serde_json::json!({
        "type": "url_citation",
        "url": url,
        "title": title,
        "start_index": start,
        "end_index": end,
    })
}

fn annotations() -> Vec<serde_json::Value> {
    vec![
        annotation(URL_A, "Why the sky is blue", 0, 15),
        annotation(URL_B, "Rayleigh scattering", 16, 30),
    ]
}

const TEXT: &str = "The sky is blue. It scatters.";

/// The completed response body both paths describe.
fn completed_response() -> serde_json::Value {
    serde_json::json!({
        "id": "resp_ann",
        "object": "response",
        "created_at": 1_720_000_000_u64,
        "model": "gpt-4o",
        "status": "completed",
        "output": [{
            "type": "message",
            "id": "msg_1",
            "status": "completed",
            "role": "assistant",
            "content": [{
                "type": "output_text",
                "text": TEXT,
                "annotations": annotations(),
            }]
        }],
        "usage": {"input_tokens": 5, "output_tokens": 7, "total_tokens": 12}
    })
}

/// The native event sequence for `completed_response`, in wire order: the annotation frames arrive
/// after the text deltas and before `output_text.done`.
fn stream_events() -> Vec<crate::ir::IrStreamEvent> {
    let item =
        serde_json::json!({"type": "message", "id": "msg_1", "role": "assistant", "content": []});
    let mut frames: Vec<(&str, serde_json::Value)> = vec![
        (
            "response.created",
            serde_json::json!({"response": {"id": "resp_ann", "created_at": 1_720_000_000_u64, "model": "gpt-4o"}}),
        ),
        (
            "response.output_item.added",
            serde_json::json!({"output_index": 0, "item": item}),
        ),
        (
            "response.content_part.added",
            serde_json::json!({"output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}}),
        ),
        (
            "response.output_text.delta",
            serde_json::json!({"output_index": 0, "content_index": 0, "delta": "The sky is blue. "}),
        ),
        (
            "response.output_text.delta",
            serde_json::json!({"output_index": 0, "content_index": 0, "delta": "It scatters."}),
        ),
    ];
    for (i, a) in annotations().into_iter().enumerate() {
        frames.push((
            "response.output_text.annotation.added",
            serde_json::json!({
                "type": "response.output_text.annotation.added",
                "item_id": "msg_1",
                "output_index": 0,
                "content_index": 0,
                "annotation_index": i,
                "annotation": a,
            }),
        ));
    }
    frames.push((
        "response.output_text.done",
        serde_json::json!({"output_index": 0, "content_index": 0, "text": TEXT}),
    ));
    frames.push(("response.content_part.done", serde_json::json!({"output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": TEXT, "annotations": annotations()}})));
    frames.push((
        "response.output_item.done",
        serde_json::json!({"output_index": 0, "item": completed_response()["output"][0].clone()}),
    ));
    frames.push((
        "response.completed",
        serde_json::json!({"response": completed_response()}),
    ));

    let reader = ResponsesReader;
    let mut state = crate::ir::StreamDecodeState::default();
    frames
        .iter()
        .flat_map(|(t, d)| reader.read_response_events(t, d, &mut state))
        .collect()
}

#[test]
fn streamed_responses_annotations_equal_buffered_citations() {
    let buffered = ResponsesReader
        .read_response(&completed_response())
        .expect("buffered read");
    let buffered_citations: Vec<crate::ir::IrCitation> = buffered
        .content
        .iter()
        .filter_map(|b| match b {
            crate::ir::IrBlock::Text { citations, .. } => Some(citations.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(
        buffered_citations.len(),
        2,
        "positive control: the buffered path reads both"
    );

    let events = stream_events();
    let streamed_citations: Vec<crate::ir::IrCitation> = events
        .iter()
        .filter_map(|e| match e {
            crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::CitationsDelta(cs),
            } => Some(cs.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(
        streamed_citations, buffered_citations,
        "streamed annotations must equal the buffered ones: {events:?}"
    );

    // Every CitationsDelta lands inside the open text block: after its BlockStart, before its
    // BlockStop — never an orphan delta.
    let pos = |pred: &dyn Fn(&crate::ir::IrStreamEvent) -> bool| events.iter().position(pred);
    let start = pos(&|e| matches!(e, crate::ir::IrStreamEvent::BlockStart { index: 0, .. }))
        .expect("start");
    let stop =
        pos(&|e| matches!(e, crate::ir::IrStreamEvent::BlockStop { index: 0 })).expect("stop");
    for (i, e) in events.iter().enumerate() {
        if matches!(
            e,
            crate::ir::IrStreamEvent::BlockDelta {
                delta: crate::ir::IrDelta::CitationsDelta(_),
                ..
            }
        ) {
            assert!(
                start < i && i < stop,
                "citation delta outside its block: {events:?}"
            );
        }
    }
}

/// Cross-protocol: the streamed Responses citation reaches an Anthropic client as a native
/// `citations_delta`, carrying the url and title.
#[test]
fn streamed_responses_annotation_reaches_anthropic_egress() {
    let aw = super::super::anthropic::AnthropicWriter;
    let urls: Vec<String> = stream_events()
        .iter()
        .filter(|e| {
            matches!(
                e,
                crate::ir::IrStreamEvent::BlockDelta {
                    delta: crate::ir::IrDelta::CitationsDelta(_),
                    ..
                }
            )
        })
        .filter_map(|e| aw.write_response_event(e))
        .filter(|(_, body)| {
            body.pointer("/delta/type").and_then(|t| t.as_str()) == Some("citations_delta")
        })
        .filter_map(|(_, body)| {
            body.pointer("/delta/citation/url")
                .and_then(|u| u.as_str())
                .map(String::from)
        })
        .collect();
    assert_eq!(urls, vec![URL_A.to_string(), URL_B.to_string()]);
}

/// An annotation frame for an index with no open text block has nothing to attach to: no orphan
/// `CitationsDelta` is emitted.
#[test]
fn annotation_without_open_text_block_emits_nothing() {
    let reader = ResponsesReader;
    let mut state = crate::ir::StreamDecodeState::default();
    let out = reader.read_response_events(
        "response.output_text.annotation.added",
        &serde_json::json!({"output_index": 3, "content_index": 0, "annotation_index": 0, "annotation": annotation(URL_A, "t", 0, 1)}),
        &mut state,
    );
    assert!(out.is_empty(), "{out:?}");
}

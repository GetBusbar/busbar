// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CITATION CARRIAGE, STREAM ≡ NON-STREAM, END TO END (owner ruling Q57: upstream citations reach
//! clients; the IR maps a field wherever the target dialect can carry it). 1.5.5 dropped the
//! citations a STREAMED Cohere or Responses upstream sent; its buffered answers kept them. This is
//! the fixture the oracle corpus does not have (no cell carries a citation-bearing streamed
//! response): for each citing upstream × each client dialect that can carry a citation, the client
//! reading the STREAMED answer must receive the same citations as the client reading the BUFFERED
//! answer to the same upstream response.
//!
//! Streamed leg: the upstream's native SSE bytes → `StreamTranslate::new(client, upstream)` (the
//! production seam) → the client's wire bytes → the client dialect's own reader → every
//! `CitationsDelta` citation. A same-dialect hop is a verbatim passthrough, so the upstream bytes are
//! read by that dialect's reader directly. Buffered leg: the upstream's native body →
//! upstream reader → IR → client writer → client reader → the text blocks' citations.

use super::*;

/// The client dialects that can carry a citation on the wire, streamed and buffered.
const CITING_CLIENTS: [&str; 5] = ["anthropic", "bedrock", "gemini", "responses", "cohere"];

const TEXT: &str = "The sky is blue. It scatters.";
const URL_A: &str = "https://example.com/sky";
const URL_B: &str = "https://example.org/rayleigh";

fn sse(frames: &[(&str, serde_json::Value)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (et, data) in frames {
        write_sse_frame(&mut out, et, data);
    }
    out
}

// ── Responses upstream ─────────────────────────────────────────────────────────────────────────

fn responses_annotations() -> serde_json::Value {
    serde_json::json!([
        {"type": "url_citation", "url": URL_A, "title": "Why the sky is blue",
         "start_index": 0, "end_index": 15},
        {"type": "url_citation", "url": URL_B, "title": "Rayleigh scattering",
         "start_index": 17, "end_index": 29}
    ])
}

fn responses_buffered() -> serde_json::Value {
    serde_json::json!({
        "id": "resp_cit", "object": "response", "created_at": 1_720_000_000_u64,
        "model": "gpt-4o", "status": "completed",
        "output": [{
            "type": "message", "id": "msg_1", "status": "completed", "role": "assistant",
            "content": [{"type": "output_text", "text": TEXT, "annotations": responses_annotations()}]
        }],
        "usage": {"input_tokens": 5, "output_tokens": 7, "total_tokens": 12}
    })
}

fn responses_stream() -> Vec<u8> {
    let item =
        serde_json::json!({"type": "message", "id": "msg_1", "role": "assistant", "content": []});
    let mut frames: Vec<(&str, serde_json::Value)> = vec![
        (
            "response.created",
            serde_json::json!({"type": "response.created",
            "response": {"id": "resp_cit", "created_at": 1_720_000_000_u64, "model": "gpt-4o"}}),
        ),
        (
            "response.output_item.added",
            serde_json::json!({"type": "response.output_item.added",
            "output_index": 0, "item": item}),
        ),
        (
            "response.content_part.added",
            serde_json::json!({"type": "response.content_part.added",
            "output_index": 0, "content_index": 0,
            "part": {"type": "output_text", "text": "", "annotations": []}}),
        ),
        (
            "response.output_text.delta",
            serde_json::json!({"type": "response.output_text.delta",
            "output_index": 0, "content_index": 0, "delta": "The sky is blue. "}),
        ),
        (
            "response.output_text.delta",
            serde_json::json!({"type": "response.output_text.delta",
            "output_index": 0, "content_index": 0, "delta": "It scatters."}),
        ),
    ];
    for (i, a) in responses_annotations()
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        frames.push((
            "response.output_text.annotation.added",
            serde_json::json!({
            "type": "response.output_text.annotation.added", "item_id": "msg_1",
            "output_index": 0, "content_index": 0, "annotation_index": i, "annotation": a}),
        ));
    }
    frames.push((
        "response.output_text.done",
        serde_json::json!({"type": "response.output_text.done",
        "output_index": 0, "content_index": 0, "text": TEXT}),
    ));
    frames.push((
        "response.content_part.done",
        serde_json::json!({"type": "response.content_part.done",
        "output_index": 0, "content_index": 0,
        "part": {"type": "output_text", "text": TEXT, "annotations": responses_annotations()}}),
    ));
    frames.push((
        "response.output_item.done",
        serde_json::json!({"type": "response.output_item.done",
        "output_index": 0, "item": responses_buffered()["output"][0].clone()}),
    ));
    frames.push((
        "response.completed",
        serde_json::json!({"type": "response.completed",
        "response": responses_buffered()}),
    ));
    sse(&frames)
}

// ── Cohere upstream ────────────────────────────────────────────────────────────────────────────

fn cohere_citations() -> [serde_json::Value; 2] {
    [
        serde_json::json!({"start": 0, "end": 15, "text": "The sky is blue", "type": "TEXT_CONTENT",
            "sources": [{"type": "document", "id": "doc:0",
                         "document": {"title": "Why the sky is blue", "url": URL_A}}]}),
        serde_json::json!({"start": 17, "end": 29, "text": "It scatters", "type": "TEXT_CONTENT",
            "sources": [{"type": "document", "id": "doc:1",
                         "document": {"title": "Rayleigh scattering", "url": URL_B}}]}),
    ]
}

fn cohere_buffered() -> serde_json::Value {
    serde_json::json!({
        "id": "c1", "finish_reason": "COMPLETE",
        "message": {"role": "assistant", "content": [{"type": "text", "text": TEXT}],
                    "citations": cohere_citations()},
        "usage": {"tokens": {"input_tokens": 5, "output_tokens": 7}}
    })
}

fn cohere_stream() -> Vec<u8> {
    let [a, b] = cohere_citations();
    let frames = [
        serde_json::json!({"type": "message-start", "id": "c1",
                           "delta": {"message": {"role": "assistant"}}}),
        serde_json::json!({"type": "content-start", "index": 0,
                           "delta": {"message": {"content": {"type": "text", "text": ""}}}}),
        serde_json::json!({"type": "content-delta", "index": 0,
                           "delta": {"message": {"content": {"text": "The sky is blue. "}}}}),
        serde_json::json!({"type": "content-delta", "index": 0,
                           "delta": {"message": {"content": {"text": "It scatters."}}}}),
        serde_json::json!({"type": "citation-start", "index": 0,
                           "delta": {"message": {"citations": a}}}),
        serde_json::json!({"type": "citation-end", "index": 0}),
        serde_json::json!({"type": "citation-start", "index": 1,
                           "delta": {"message": {"citations": b}}}),
        serde_json::json!({"type": "citation-end", "index": 1}),
        serde_json::json!({"type": "content-end", "index": 0}),
        serde_json::json!({"type": "message-end",
                           "delta": {"finish_reason": "COMPLETE",
                                     "usage": {"tokens": {"input_tokens": 5, "output_tokens": 7}}}}),
    ];
    let named: Vec<(&str, serde_json::Value)> = frames
        .iter()
        .map(|f| (f["type"].as_str().unwrap(), f.clone()))
        .collect();
    sse(&named)
}

// ── the two legs ───────────────────────────────────────────────────────────────────────────────

/// Every citation-identifying string the upstream answer carries: both sources' URL and title.
const MARKS: [&str; 4] = [URL_A, "Why the sky is blue", URL_B, "Rayleigh scattering"];

/// Which of `MARKS` a client's wire bytes carry. Read off the WIRE, not re-read through busbar's own
/// reader, because the client is a native SDK: a Responses client finds the annotations on
/// `content_part.done`/`output_item.done`/`response.completed`, a Gemini client reads every
/// chunk's `citationMetadata`, a Bedrock client reads the event-stream payload JSON. A citation's
/// URL or title on the wire is the content a client can show; a dialect that has no member for one
/// of them (Anthropic's `char_location`, Bedrock's `documentChar` carry no URL) drops it on BOTH
/// legs, which this comparison allows — stream ≡ non-stream is the invariant pinned here.
fn carried(wire: &[u8]) -> Vec<&'static str> {
    let text = String::from_utf8_lossy(wire);
    MARKS.iter().copied().filter(|m| text.contains(m)).collect()
}

/// The client's streamed wire: the upstream's native stream through `StreamTranslate`, the
/// production seam; a same-dialect hop is a verbatim passthrough.
fn streamed_wire(upstream: &str, client: &str, upstream_bytes: &[u8]) -> Vec<u8> {
    match StreamTranslate::new(client, upstream) {
        Some(mut st) => {
            let mut out = st.feed(upstream_bytes);
            out.extend_from_slice(&st.finish());
            out
        }
        None => upstream_bytes.to_vec(),
    }
}

/// The client's buffered body: upstream reader → IR → client writer; a same-dialect hop is a
/// verbatim passthrough, exactly as on the stream.
fn buffered_wire(upstream: &str, client: &str, upstream_body: &serde_json::Value) -> Vec<u8> {
    if upstream == client {
        return upstream_body.to_string().into_bytes();
    }
    let ir = protocol_for(upstream)
        .expect("upstream dialect")
        .reader()
        .read_response(upstream_body)
        .unwrap_or_else(|e| panic!("{upstream}: buffered read: {e:?}"));
    protocol_for(client)
        .expect("client dialect")
        .writer()
        .write_response(&ir)
        .to_string()
        .into_bytes()
}

fn assert_carriage(upstream: &str, stream: &[u8], body: &serde_json::Value) {
    for client in CITING_CLIENTS {
        let buffered = carried(&buffered_wire(upstream, client, body));
        let streamed = carried(&streamed_wire(upstream, client, stream));
        assert!(
            !buffered.is_empty(),
            "{upstream} upstream → {client} client: the BUFFERED answer carries the citations"
        );
        assert_eq!(
            streamed, buffered,
            "{upstream} upstream → {client} client: the STREAMED answer carries what the BUFFERED \
             answer carries (1.5.5 dropped a streamed {upstream} upstream's citations)"
        );
    }
}

#[test]
fn responses_upstream_streamed_citations_reach_every_citing_client_as_buffered() {
    assert_carriage("responses", &responses_stream(), &responses_buffered());
}

#[test]
fn cohere_upstream_streamed_citations_reach_every_citing_client_as_buffered() {
    assert_carriage("cohere", &cohere_stream(), &cohere_buffered());
}

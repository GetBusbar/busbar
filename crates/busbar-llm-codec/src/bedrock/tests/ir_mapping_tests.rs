// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR MAPPING (owner directive Q57): a field the Bedrock Converse wire carries, that the neutral IR
//! and the other dialect can carry, must map. One test per defect id from the 1.6.0 IR-mapping audit
//! (`BED-xx`). Each drives the production seam — reader → `chat_prepare_for_egress` /
//! `chat_prepare_for_ingress` → writer, and `StreamTranslate` for streams — on a real body, so a
//! regression in the reader, the seam or the writer is caught.

use super::*;
use serde_json::{json, Value};

/// The production REQUEST translate steps (reader → egress seam → writer).
fn xreq(ingress: &'static str, egress: &str, body: &Value) -> Value {
    let ingress_p = crate::proto_codec::protocol_for(ingress).expect("ingress");
    let egress_p = crate::proto_codec::protocol_for(egress).expect("egress");
    let mut req = ingress_p.reader().read_request(body).expect("read_request");
    crate::chat_handle::chat_prepare_for_egress(
        &mut req,
        &busbar_substrate_values::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: ingress,
            egress_requires_max_tokens: egress_p.decl().is_some_and(|d| d.requires_max_tokens),
            lane_default_max_tokens: None,
            global_default_max_tokens: 4096,
            reasoning_allowed: true,
            reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
            prompt_caching_allowed: true,
            cache_control_cap: None,
        },
    );
    let mut out = egress_p.writer().write_request(&req);
    crate::wire_shim::strip_router_shim_keys(&mut out, egress);
    out
}

/// The production buffered RESPONSE translate steps (upstream reader → ingress seam → client writer).
fn xresp(upstream: &str, client: &'static str, body: &Value) -> Value {
    let up = crate::proto_codec::protocol_for(upstream).expect("upstream");
    let cl = crate::proto_codec::protocol_for(client).expect("client");
    let mut resp = up.reader().read_response(body).expect("read_response");
    crate::chat_handle::chat_prepare_for_ingress(&mut resp, client, 1_752_000_000);
    cl.writer().write_response(&resp)
}

/// A Bedrock ConverseStream upstream translated for `client` through the production stream seam.
fn xstream_from_bedrock(client: &str, frames: &[(&str, Value)]) -> String {
    let mut bytes = Vec::new();
    for (et, payload) in frames {
        bytes.extend(busbar_substrate_values::eventstream::encode_frame(
            et,
            payload.to_string().as_bytes(),
        ));
    }
    let mut st = crate::proto_stream::StreamTranslate::new(client, "bedrock").expect("translator");
    let mut out = st.feed(&bytes);
    out.extend(st.finish());
    String::from_utf8_lossy(&out).into_owned()
}

fn cited_response() -> Value {
    json!({
        "output": {"message": {"role": "assistant", "content": [
            {"citationsContent": {
                "content": [{"text": "hello"}],
                "citations": [{
                    "title": "doc",
                    "location": {"documentChar": {"documentIndex": 0, "start": 0, "end": 5}},
                    "sourceContent": [{"text": "hel"}]
                }]
            }},
            {"text": "world"}
        ]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15}
    })
}

/// BED-01 (buffered): the cited ANSWER TEXT lives inside `citationsContent`; with no reader arm it
/// was deleted on every foreign client, not only its sources.
#[test]
fn bed01_buffered_citations_content_text_and_citations_reach_foreign_clients() {
    for client in ["anthropic", "openai", "responses", "gemini", "cohere"] {
        let out = xresp("bedrock", client, &cited_response()).to_string();
        assert!(
            out.contains("hello"),
            "{client}: the cited answer text must survive; got {out}"
        );
    }
    let a = xresp("bedrock", "anthropic", &cited_response());
    let block = &a["content"][0];
    assert_eq!(block["text"], "hello", "{a}");
    let c = &block["citations"][0];
    assert_eq!(c["type"], "char_location", "{a}");
    assert_eq!(c["document_title"], "doc", "{a}");
    assert_eq!(c["cited_text"], "hel", "{a}");
    assert_eq!(c["start_char_index"], 0, "{a}");
    assert_eq!(c["end_char_index"], 5, "{a}");
}

/// BED-01 (request history): an assistant turn carried as `citationsContent` arrived as an EMPTY
/// turn (`content: []`, an Anthropic 400); its text must cross with its citations.
#[test]
fn bed01_request_history_citations_content_is_not_an_empty_turn() {
    let body = json!({
        "messages": [
            {"role": "user", "content": [{"text": "hi"}]},
            {"role": "assistant", "content": [{"citationsContent": {
                "content": [{"text": "cited answer"}],
                "citations": [{"title": "n",
                    "location": {"documentPage": {"documentIndex": 1, "start": 2, "end": 3}},
                    "sourceContent": [{"text": "plain"}]}]
            }}]},
            {"role": "user", "content": [{"text": "more"}]}
        ],
        "inferenceConfig": {"maxTokens": 100}
    });
    // The IR turn carries the text AND its citations (what each target writer does with history
    // citations is that writer's projection).
    let ir = BedrockReader.read_request(&body).expect("read");
    let crate::ir::IrBlock::Text {
        text, citations, ..
    } = &ir.messages[1].content[0]
    else {
        panic!("text block expected: {ir:?}");
    };
    assert_eq!(text, "cited answer");
    assert_eq!(citations[0].kind.as_deref(), Some("page_location"));
    assert_eq!(citations[0].document_index, Some(1));
    assert_eq!(citations[0].start_index, Some(2));
    assert_eq!(citations[0].cited_text.as_deref(), Some("plain"));
    let out = xreq("bedrock", "anthropic", &body);
    assert_eq!(
        out["messages"][1]["content"][0]["text"], "cited answer",
        "{out}"
    );
    let o = xreq("bedrock", "openai", &body);
    assert!(o["messages"][1].to_string().contains("cited answer"), "{o}");
}

/// BED-01 (stream): a ConverseStream `contentBlockDelta.delta.citation` was dropped; it must reach
/// a foreign streaming client as that client's citation event.
#[test]
fn bed01_stream_citation_delta_reaches_a_foreign_client() {
    let wire = xstream_from_bedrock(
        "anthropic",
        &[
            ("messageStart", json!({"role": "assistant"})),
            (
                "contentBlockDelta",
                json!({"contentBlockIndex": 0, "delta": {"text": "hello"}}),
            ),
            (
                "contentBlockDelta",
                json!({"contentBlockIndex": 0, "delta": {"citation": {
                    "title": "Atlas",
                    "sourceContent": [{"text": "hel"}],
                    "location": {"web": {"url": "https://atlas.example/a", "domain": "atlas.example"}}
                }}}),
            ),
            ("contentBlockStop", json!({"contentBlockIndex": 0})),
            ("messageStop", json!({"stopReason": "end_turn"})),
            (
                "metadata",
                json!({"usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}}),
            ),
        ],
    );
    assert!(wire.contains("citations_delta"), "{wire}");
    assert!(wire.contains("https://atlas.example/a"), "{wire}");
    assert!(wire.contains("Atlas"), "{wire}");
}

/// BED-02: `guardContent` text was kept only in a stash the seam clears, so the guarded prompt
/// text vanished cross-protocol. Same-protocol it still re-emits once, verbatim, at its position.
#[test]
fn bed02_guard_content_text_reaches_a_foreign_backend_and_round_trips_once() {
    let body = json!({
        "system": [{"text": "sys"}, {"guardContent": {"text": {"text": "guarded system text"}}}],
        "messages": [{"role": "user", "content": [
            {"text": "hi"},
            {"guardContent": {"text": {"text": "guarded user text", "qualifiers": ["query"]}}}
        ]}],
        "inferenceConfig": {"maxTokens": 100}
    });
    let a = xreq("bedrock", "anthropic", &body).to_string();
    assert!(a.contains("guarded system text"), "{a}");
    assert!(a.contains("guarded user text"), "{a}");

    let ir = BedrockReader.read_request(&body).expect("read");
    let back = writer().write_request(&ir);
    let wire = back.to_string();
    assert_eq!(
        wire.matches("guarded user text").count(),
        1,
        "same-protocol re-emits the guard span exactly once; got {back}"
    );
    assert_eq!(wire.matches("guarded system text").count(), 1, "{back}");
    assert_eq!(
        back["messages"][0]["content"][1]["guardContent"]["text"]["qualifiers"][0], "query",
        "{back}"
    );
    assert_eq!(
        back["system"][1]["guardContent"]["text"]["text"], "guarded system text",
        "{back}"
    );
}

/// BED-03: a TEXT document (`source.text` / chunked `source.content[]`) became a bedrock-only
/// Vendor reference every foreign writer dropped; it is a text/plain document.
#[test]
fn bed03_text_document_source_becomes_a_text_plain_document() {
    let body = json!({
        "messages": [{"role": "user", "content": [
            {"text": "hi"},
            {"document": {"format": "txt", "name": "n", "source": {"text": "plain text doc"}}},
            {"document": {"format": "md", "name": "m",
                "source": {"content": [{"text": "a"}, {"text": "b"}]}}}
        ]}]
    });
    let ir = BedrockReader.read_request(&body).expect("read");
    let media: Vec<_> = ir.messages[0]
        .content
        .iter()
        .filter_map(|b| match b {
            crate::ir::IrBlock::Media { source, .. } => Some(source.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        media,
        vec![
            crate::ir::IrImageSource::Base64 {
                media_type: "text/plain".into(),
                data: busbar_substrate_values::media::base64_encode(b"plain text doc"),
            },
            crate::ir::IrImageSource::Base64 {
                media_type: "text/markdown".into(),
                data: busbar_substrate_values::media::base64_encode(b"a\nb"),
            },
        ]
    );
    let g = xreq("bedrock", "gemini", &body).to_string();
    assert!(
        g.contains(&busbar_substrate_values::media::base64_encode(
            b"plain text doc"
        )),
        "{g}"
    );
}

/// BED-05: a `toolResult` `document` / `video` member was dropped (only nested text survived).
#[test]
fn bed05_tool_result_document_and_video_are_modelled() {
    let body = json!({
        "messages": [
            {"role": "user", "content": [{"text": "go"}]},
            {"role": "assistant", "content": [{"toolUse": {"toolUseId": "t1", "name": "f", "input": {}}}]},
            {"role": "user", "content": [{"toolResult": {"toolUseId": "t1", "content": [
                {"document": {"format": "pdf", "name": "r", "source": {"bytes": "JVBERi0="}}},
                {"video": {"format": "mp4", "source": {"bytes": "AAAA"}}}
            ]}}]}
        ]
    });
    let ir = BedrockReader.read_request(&body).expect("read");
    let crate::ir::IrBlock::ToolResult { content, .. } = &ir.messages[2].content[0] else {
        panic!("tool result expected: {ir:?}");
    };
    assert!(
        matches!(
            &content[0],
            crate::ir::IrBlock::Media { kind: crate::ir::IrMediaKind::Document, source: crate::ir::IrImageSource::Base64 { media_type, data }, name, .. }
                if media_type == "application/pdf" && data == "JVBERi0=" && name.as_deref() == Some("r")
        ),
        "{content:?}"
    );
    assert!(
        matches!(
            &content[1],
            crate::ir::IrBlock::Media {
                kind: crate::ir::IrMediaKind::Video,
                ..
            }
        ),
        "{content:?}"
    );
    let a = xreq("bedrock", "anthropic", &body).to_string();
    assert!(a.contains("JVBERi0="), "{a}");
}

/// BED-07: an Anthropic `cache_control` on an image / document / thinking block got no Bedrock
/// `cachePoint`; the breakpoint must follow the block it closes.
#[test]
fn bed07_cache_control_on_image_document_thinking_projects_a_cache_point() {
    let body = json!({
        "model": "claude", "max_tokens": 100,
        "messages": [
            {"role": "user", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBO"},
                 "cache_control": {"type": "ephemeral"}},
                {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "JVBERi0="},
                 "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": "q"}
            ]},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "hmm", "signature": "sig", "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": "a"}
            ]},
            {"role": "user", "content": [{"type": "text", "text": "q2"}]}
        ]
    });
    let out = xreq("anthropic", "bedrock", &body);
    let user = out["messages"][0]["content"].as_array().expect("content");
    assert!(user[0].get("image").is_some(), "{out}");
    assert!(user[1].get("cachePoint").is_some(), "{out}");
    assert!(user[2].get("document").is_some(), "{out}");
    assert!(user[3].get("cachePoint").is_some(), "{out}");
    let asst = out["messages"][1]["content"].as_array().expect("content");
    assert!(asst[0].get("reasoningContent").is_some(), "{out}");
    assert!(asst[1].get("cachePoint").is_some(), "{out}");

    // Reader half: a Bedrock cachePoint after an image lands on that image's cache_control.
    let b = json!({"messages": [{"role": "user", "content": [
        {"image": {"format": "png", "source": {"bytes": "iVBO"}}},
        {"cachePoint": {"type": "default"}},
        {"text": "q"}
    ]}]});
    let a = xreq("bedrock", "anthropic", &b);
    assert_eq!(
        a["messages"][0]["content"][0]["cache_control"]["type"], "ephemeral",
        "{a}"
    );
}

/// BED-09: a refusal wrote Converse `end_turn` — indistinguishable from a normal answer. It is a
/// content-policy stop: `content_filtered`.
#[test]
fn bed09_refusal_writes_content_filtered() {
    let resp = crate::ir::IrResponse {
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "I can't help".into(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::Refusal),
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
        request_echo: None,
    };
    let out = writer().write_response(&resp);
    assert_eq!(out["stopReason"], "content_filtered", "{out}");
    let es = bedrock_response_to_eventstream(&resp, Some(1));
    let wire = String::from_utf8_lossy(&es);
    assert!(wire.contains("content_filtered"), "{wire}");
}

/// BED-10: `model_context_window_exceeded` and `malformed_*` fell to `Other` (a foreign client saw
/// a natural stop). The first is a token-limit cut; the second an error termination.
#[test]
fn bed10_context_window_and_malformed_stop_reasons_map() {
    let mut body = cited_response();
    body["stopReason"] = json!("model_context_window_exceeded");
    let o = xresp("bedrock", "openai", &body);
    assert_eq!(o["choices"][0]["finish_reason"], "length", "{o}");
    let a = xresp("bedrock", "anthropic", &body);
    assert_eq!(a["stop_reason"], "max_tokens", "{a}");
    for token in ["malformed_model_output", "malformed_tool_use"] {
        body["stopReason"] = json!(token);
        let ir = BedrockReader.read_response(&body).expect("read");
        assert_eq!(
            ir.stop_reason,
            Some(crate::ir::IrStopReason::Error),
            "{token}"
        );
        let c = xresp("bedrock", "cohere", &body);
        assert_eq!(c["finish_reason"], "ERROR", "{token}: {c}");
    }
}

/// BED-11 (buffered half): Anthropic-on-Bedrock echoes the matched stop string under
/// `additionalModelResponseFields.stop_sequence`; the reader carries it into the IR slot.
#[test]
fn bed11_buffered_stop_sequence_is_read() {
    let mut body = cited_response();
    body["stopReason"] = json!("stop_sequence");
    body["additionalModelResponseFields"] = json!({"stop_sequence": "X"});
    let ir = BedrockReader.read_response(&body).expect("read");
    assert_eq!(ir.stop_sequence.as_deref(), Some("X"));
}

/// BED-12: a buffered answer synthesized as a ConverseStream (Bedrock client, buffered upstream)
/// dropped the citations the buffered body carries.
#[test]
fn bed12_synthesized_stream_carries_citations() {
    let ir = BedrockReader
        .read_response(&cited_response())
        .expect("read");
    let es = bedrock_response_to_eventstream(&ir, Some(1));
    let mut buf = es.clone();
    let frames = busbar_substrate_values::eventstream::drain_frames(&mut buf);
    let citation: Vec<Value> = frames
        .iter()
        .filter(|(et, _)| et == "contentBlockDelta")
        .filter_map(|(_, p)| serde_json::from_slice::<Value>(p).ok())
        .filter(|v| v.pointer("/delta/citation").is_some())
        .collect();
    assert_eq!(citation.len(), 1, "{frames:?}");
    assert_eq!(citation[0]["contentBlockIndex"], 0);
    assert_eq!(citation[0]["delta"]["citation"]["title"], "doc");
}

/// BED-13: text citations in assistant HISTORY were dropped on a Bedrock egress; Converse accepts
/// them as `citationsContent`.
#[test]
fn bed13_history_citations_write_citations_content() {
    let body = json!({
        "model": "claude", "max_tokens": 100,
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "q"}]},
            {"role": "assistant", "content": [{"type": "text", "text": "Paris is the capital.",
                "citations": [{"type": "char_location", "cited_text": "Paris", "document_index": 0,
                    "document_title": "Atlas", "start_char_index": 0, "end_char_index": 5}]}]},
            {"role": "user", "content": [{"type": "text", "text": "more"}]}
        ]
    });
    let out = xreq("anthropic", "bedrock", &body);
    let cc = &out["messages"][1]["content"][0]["citationsContent"];
    assert_eq!(cc["content"][0]["text"], "Paris is the capital.", "{out}");
    assert_eq!(cc["citations"][0]["title"], "Atlas", "{out}");
    assert_eq!(
        cc["citations"][0]["location"]["documentChar"]["end"], 5,
        "{out}"
    );
}

/// BED-14: a web citation's `url` was dropped (or folded into `title`); Converse's
/// `CitationLocation` has a `web` member carrying it.
#[test]
fn bed14_web_citation_url_rides_the_web_location() {
    let cit = crate::ir::IrCitation {
        kind: Some("web_search_result_location".into()),
        cited_text: None,
        title: Some("Why the sky is blue".into()),
        url: Some("https://example.com/sky".into()),
        document_index: None,
        start_index: None,
        end_index: None,
        encrypted_index: None,
        raw: None,
    };
    let c = write_bedrock_citation(&cit).expect("citation");
    assert_eq!(c["title"], "Why the sky is blue", "{c}");
    assert_eq!(
        c["location"]["web"]["url"], "https://example.com/sky",
        "{c}"
    );
    // And it reads back: Bedrock → IR keeps the url.
    let body = json!({
        "output": {"message": {"role": "assistant", "content": [
            {"citationsContent": {"content": [{"text": "blue"}], "citations": [c]}}
        ]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}
    });
    let ir = BedrockReader.read_response(&body).expect("read");
    let crate::ir::IrBlock::Text { citations, .. } = &ir.content[0] else {
        panic!("text expected: {ir:?}");
    };
    assert_eq!(citations[0].url.as_deref(), Some("https://example.com/sky"));
    assert_eq!(
        citations[0].kind.as_deref(),
        Some("web_search_result_location")
    );
}

/// A fresh writer per use (the const constructor carries per-stream state).
fn writer() -> BedrockWriter {
    BedrockWriter
}

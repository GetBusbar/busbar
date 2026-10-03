//! DF-MAP audit (ARCHITECT rulings 2026-10-02 items 1, 2, 5): the Responses answer slots.
use super::super::proto_codec::protocol_for;
use crate::codec::ir::{IrBlock, IrHostedToolKind, IrSearchResult};
use serde_json::json;

fn answer(output: serde_json::Value) -> serde_json::Value {
    json!({"id": "r1", "object": "response", "created_at": 1, "model": "m", "status": "completed",
           "output": output,
           "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}})
}

fn read(body: &serde_json::Value) -> crate::codec::ir::IrResponse {
    protocol_for("responses")
        .unwrap()
        .reader()
        .read_response(body)
        .expect("reads")
}

#[test]
fn a_web_search_call_reads_as_a_hosted_record_and_writes_back() {
    let resp = read(&answer(json!([
        {"type": "web_search_call", "id": "ws_1", "status": "completed",
         "action": {"type": "search", "query": "q",
                    "sources": [{"type": "url", "url": "https://a.example/x"}]}}])));
    let expected = IrBlock::HostedToolRecord {
        kind: IrHostedToolKind::WebSearch,
        call_id: Some("ws_1".to_string()),
        status: Some("completed".to_string()),
        results: vec![IrSearchResult {
            url: "https://a.example/x".to_string(),
            title: None,
            snippet: None,
        }],
    };
    assert_eq!(resp.content, vec![expected]);
    let out = protocol_for("responses")
        .unwrap()
        .writer()
        .write_response(&resp);
    assert_eq!(out["output"][0]["type"], "web_search_call");
    assert_eq!(out["output"][0]["id"], "ws_1");
    assert_eq!(
        out["output"][0]["action"]["sources"][0]["url"],
        "https://a.example/x"
    );
}

/// The cross-dialect GAIN: an Anthropic web search reaches a Responses client as its
/// `web_search_call` item (it was dropped before: neither side had an IR form).
#[test]
fn an_anthropic_web_search_reaches_a_responses_client() {
    let anthropic = json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
        "content": [{"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1",
                     "content": [{"type": "web_search_result", "url": "https://a.example/x",
                                  "title": "A", "encrypted_content": "e"}]},
                    {"type": "text", "text": "hi"}],
        "stop_reason": "end_turn", "stop_sequence": null,
        "usage": {"input_tokens": 1, "output_tokens": 1}});
    let resp = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_response(&anthropic)
        .expect("reads");
    let out = protocol_for("responses")
        .unwrap()
        .writer()
        .write_response(&resp);
    let item = &out["output"][0];
    assert_eq!(item["type"], "web_search_call", "{out}");
    assert_eq!(item["id"], "srvtoolu_1");
    assert_eq!(item["status"], "completed");
}

#[test]
fn file_citations_read_and_write() {
    let resp = read(&answer(json!([
        {"type": "message", "id": "m1", "status": "completed", "role": "assistant",
         "content": [{"type": "output_text", "text": "see file", "logprobs": [],
                      "annotations": [{"type": "file_citation", "file_id": "file_1",
                                       "filename": "a.pdf", "index": 4}]}]}])));
    let IrBlock::Text { citations, .. } = &resp.content[0] else {
        panic!("{:?}", resp.content);
    };
    let file = citations[0].file.clone().expect("file location");
    assert_eq!(
        (
            file.file_id.as_deref(),
            file.filename.as_deref(),
            file.index
        ),
        (Some("file_1"), Some("a.pdf"), Some(4))
    );
    let out = protocol_for("responses")
        .unwrap()
        .writer()
        .write_response(&resp);
    assert_eq!(
        out["output"][0]["content"][0]["annotations"][0]["file_id"], "file_1",
        "{out}"
    );
}

#[test]
fn moderation_reads_as_safety_verdicts() {
    let mut body = answer(json!([]));
    body["moderation"] = json!({"output": {"type": "moderation_result", "model": "omni",
        "flagged": true, "categories": {"self-harm": true, "violence": false},
        "category_scores": {"self-harm": 0.8}}});
    let resp = read(&body);
    assert_eq!(resp.safety.len(), 1);
    assert_eq!(resp.safety[0].category, "self-harm");
    assert!(resp.safety[0].flagged);
}

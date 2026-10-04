//! DF-MAP (ARCHITECT ruling 2026-10-02 item 2): an Anthropic `web_search_tool_result` is the IR's
//! hosted web-search record, in an answer and in replayed history. Before this, the reader degraded
//! it to an EMPTY text block.
use super::super::proto_codec::protocol_for;
use crate::codec::ir::{IrBlock, IrHostedToolKind, IrSearchResult};
use serde_json::json;

fn result_block() -> serde_json::Value {
    json!({"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1",
           "content": [{"type": "web_search_result", "url": "https://a.example/x",
                        "title": "A", "encrypted_content": "enc", "page_age": null}]})
}

fn expected() -> IrBlock {
    IrBlock::HostedToolRecord {
        kind: IrHostedToolKind::WebSearch,
        call_id: Some("srvtoolu_1".to_string()),
        status: None,
        results: vec![IrSearchResult {
            url: "https://a.example/x".to_string(),
            title: Some("A".to_string()),
            snippet: None,
        }],
    }
}

#[test]
fn an_answer_web_search_result_reads_as_a_hosted_record() {
    let body = json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
                      "content": [result_block(), {"type": "text", "text": "hi"}],
                      "stop_reason": "end_turn", "stop_sequence": null,
                      "usage": {"input_tokens": 1, "output_tokens": 1}});
    let resp = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_response(&body)
        .expect("reads");
    assert_eq!(
        resp.content.first(),
        Some(&expected()),
        "{:?}",
        resp.content
    );
}

#[test]
fn a_replayed_web_search_result_reads_as_a_hosted_record() {
    let body = json!({"model": "m", "max_tokens": 64, "messages": [
        {"role": "user", "content": "q"},
        {"role": "assistant", "content": [result_block()]}]});
    let req = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_request(&body)
        .expect("reads");
    assert_eq!(req.messages[1].content, vec![expected()]);
}

#[test]
fn a_web_search_error_reads_as_a_record_with_its_status() {
    let body = json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
                      "content": [{"type": "web_search_tool_result", "tool_use_id": "srvtoolu_2",
                                   "content": {"type": "web_search_tool_result_error",
                                               "error_code": "max_uses_exceeded"}}],
                      "stop_reason": "end_turn", "stop_sequence": null,
                      "usage": {"input_tokens": 1, "output_tokens": 1}});
    let resp = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_response(&body)
        .expect("reads");
    assert!(
        matches!(&resp.content[0], IrBlock::HostedToolRecord { status: Some(s), results, .. }
            if s == "max_uses_exceeded" && results.is_empty()),
        "{:?}",
        resp.content
    );
}

/// A record from another dialect cannot be written as Anthropic's block (it needs the
/// `encrypted_content` only Anthropic mints): it is dropped, never an empty text block.
#[test]
fn a_foreign_hosted_record_is_dropped_on_anthropic_egress() {
    let resp = crate::codec::ir::IrResponse {
        content: vec![
            expected(),
            IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
                refusal: false,
            },
        ],
        ..Default::default()
    };
    let out = protocol_for("anthropic")
        .unwrap()
        .writer()
        .write_response(&resp);
    let content = out["content"].as_array().expect("content");
    assert_eq!(content.len(), 1, "{out}");
    assert_eq!(content[0]["text"], "hi");
}

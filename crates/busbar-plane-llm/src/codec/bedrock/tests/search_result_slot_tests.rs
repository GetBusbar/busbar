// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEARCH-RESULT SLOT (ARCHITECT 2026-10-02, DF-MAP-2 gap (a)): a Converse `searchResult` block
//! (request content and `toolResult` content) is caller-supplied RAG content. The Bedrock reader
//! used to have no arm for it, so the block vanished on every translate. It now reads into the same
//! slot an Anthropic `search_result` reads into (`IrBlock::search_result`), so the passage, its
//! source and title and the `citations` switch translate both ways, and a Bedrock->Bedrock relay
//! re-emits the caller's original block.

use super::*;
use serde_json::{json, Value};

/// The production REQUEST translate steps (reader -> egress seam -> writer). The egress seam is the
/// CROSS-protocol one and runs only when the dialects differ, as in production: it clears `extra`,
/// where the reader parks a same-dialect hop's verbatim blocks.
fn xreq(ingress: &'static str, egress: &str, body: &Value) -> Value {
    let ingress_p = crate::codec::proto_codec::protocol_for(ingress).expect("ingress");
    let egress_p = crate::codec::proto_codec::protocol_for(egress).expect("egress");
    let mut req = ingress_p.reader().read_request(body).expect("read_request");
    if ingress != egress {
        prepare(
            &mut req,
            ingress,
            egress_p.decl().is_some_and(|d| d.requires_max_tokens),
        );
    }
    let mut out = egress_p.writer().write_request(&req);
    crate::codec::wire_shim::strip_router_shim_keys(&mut out, egress);
    out
}

fn prepare(req: &mut crate::codec::ir::IrRequest, ingress: &'static str, max_tokens: bool) {
    crate::codec::chat_handle::chat_prepare_for_egress(
        req,
        &busbar_contract::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: ingress,
            egress_requires_max_tokens: max_tokens,
            lane_default_max_tokens: None,
            global_default_max_tokens: 4096,
            reasoning_allowed: true,
            reasoning_budgets: crate::codec::ir::REASONING_BUDGET_DEFAULTS,
            prompt_caching_allowed: true,
            cache_control_cap: None,
            lane_caps: Default::default(),
        },
    );
}

fn converse_search_result(parts: &[&str], enabled: bool) -> Value {
    let content: Vec<Value> = parts.iter().map(|t| json!({ "text": t })).collect();
    json!({ "searchResult": {
        "source": "https://kb.example/doc-7",
        "title": "Refund policy",
        "content": content,
        "citations": { "enabled": enabled }
    }})
}

/// A Converse request carrying a `searchResult` in user content and one inside a `toolResult`.
fn bedrock_body() -> Value {
    json!({
        "messages": [
            {"role": "user", "content": [
                {"text": "what is the refund window?"},
                converse_search_result(&["Refunds within 30 days.", "Receipts required."], true)
            ]},
            {"role": "assistant", "content": [
                {"toolUse": {"toolUseId": "t1", "name": "kb", "input": {"q": "refund"}}}
            ]},
            {"role": "user", "content": [
                {"toolResult": {"toolUseId": "t1", "content": [
                    converse_search_result(&["Refunds within 30 days."], false)
                ], "status": "success"}}
            ]}
        ]
    })
}

fn anthropic_search_result(text: &str, enabled: bool) -> Value {
    json!({
        "type": "search_result",
        "source": "https://kb.example/doc-7",
        "title": "Refund policy",
        "content": [{ "type": "text", "text": text }],
        "citations": { "enabled": enabled }
    })
}

#[test]
fn a_bedrock_search_result_relays_bedrock_to_bedrock_byte_exact() {
    let body = bedrock_body();
    let out = xreq("bedrock", "bedrock", &body);
    assert_eq!(
        out["messages"].to_string(),
        body["messages"].to_string(),
        "the caller's searchResult blocks must come back byte-exact"
    );
}

#[test]
fn a_bedrock_search_result_reads_into_the_search_result_slot() {
    let ir = BedrockReader.read_request(&bedrock_body()).expect("read");
    let sr = ir.messages[0].content[1]
        .as_search_result()
        .expect("the searchResult block is the search-result slot, not dropped");
    assert_eq!(sr.source, "https://kb.example/doc-7");
    assert_eq!(sr.title, "Refund policy");
    assert_eq!(sr.body, "Refunds within 30 days.\nReceipts required.");
    assert_eq!(sr.citations_config, Some(&json!({ "enabled": true })));
    let crate::codec::ir::IrBlock::ToolResult { content, .. } = &ir.messages[2].content[0] else {
        panic!("tool result: {:?}", ir.messages[2].content);
    };
    let inner = content[0]
        .as_search_result()
        .expect("toolResult searchResult");
    assert_eq!(inner.body, "Refunds within 30 days.");
    assert_eq!(inner.citations_config, Some(&json!({ "enabled": false })));
}

#[test]
fn bedrock_to_anthropic_carries_source_title_content_and_the_citations_switch() {
    let out = xreq("bedrock", "anthropic", &bedrock_body());
    assert_eq!(
        out["messages"][0]["content"][1],
        anthropic_search_result("Refunds within 30 days.\nReceipts required.", true),
        "{out}"
    );
    assert_eq!(
        out["messages"][2]["content"][0]["content"][0],
        anthropic_search_result("Refunds within 30 days.", false),
        "{out}"
    );
}

#[test]
fn anthropic_to_bedrock_carries_source_title_content_and_the_citations_switch() {
    let body = json!({
        "model": "claude-x",
        "max_tokens": 64,
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "what is the refund window?"},
                anthropic_search_result("Refunds within 30 days.", true)
            ]},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "kb", "input": {"q": "refund"}}
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": [
                    anthropic_search_result("Receipts required.", false)
                ]}
            ]}
        ]
    });
    let out = xreq("anthropic", "bedrock", &body);
    assert_eq!(
        out["messages"][0]["content"][1],
        converse_search_result(&["Refunds within 30 days."], true),
        "{out}"
    );
    assert_eq!(
        out["messages"][2]["content"][0]["toolResult"]["content"][0],
        converse_search_result(&["Receipts required."], false),
        "{out}"
    );
}

#[test]
fn bedrock_to_anthropic_to_bedrock_round_trips_a_one_part_search_result() {
    let body = json!({
        "messages": [{"role": "user", "content": [
            {"text": "q"},
            converse_search_result(&["Refunds within 30 days."], true)
        ]}]
    });
    let anthropic = xreq("bedrock", "anthropic", &body);
    let back = xreq("anthropic", "bedrock", &anthropic);
    assert_eq!(back["messages"], body["messages"], "{anthropic}");
}

#[test]
fn a_dialect_without_the_block_still_reads_the_passage_and_its_source() {
    let out = xreq("bedrock", "openai_chat", &bedrock_body()).to_string();
    for needle in [
        "Refund policy",
        "https://kb.example/doc-7",
        "Receipts required.",
    ] {
        assert!(out.contains(needle), "{needle} missing: {out}");
    }
}

/// RED ARM: the provenance citation IS the slot. Strip it and the block no longer re-emits as a
/// search result on either side, so a reader that dropped the citation would fail the tests above.
#[test]
fn dropping_the_citation_loses_the_search_result_block() {
    let mut ir = BedrockReader.read_request(&bedrock_body()).expect("read");
    if let crate::codec::ir::IrBlock::Text { citations, .. } = &mut ir.messages[0].content[1] {
        citations.clear();
    }
    assert!(ir.messages[0].content[1].as_search_result().is_none());
    ir.extra.clear();
    let anthropic = crate::codec::proto_codec::protocol_for("anthropic")
        .expect("anthropic")
        .writer()
        .write_request(&ir);
    assert_eq!(
        anthropic["messages"][0]["content"][1]["type"], "text",
        "{anthropic}"
    );
    let bedrock = crate::codec::proto_codec::protocol_for("bedrock")
        .expect("bedrock")
        .writer()
        .write_request(&ir);
    assert!(
        bedrock["messages"][0]["content"][1]
            .get("searchResult")
            .is_none(),
        "{bedrock}"
    );
}

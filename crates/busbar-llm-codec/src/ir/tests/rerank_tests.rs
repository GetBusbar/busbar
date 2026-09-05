// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/ir/rerank.rs`.

use super::*;

#[test]
fn rerank_resp_billing_is_flat() {
    // Rerank has no token meter on either wire; until the 1.3 pricing engine prices search
    // units, the billing projection must be the flat marker.
    let resp = RerankResp::default();
    assert_eq!(resp.billing(), Some(Billing::Flat));
}

#[test]
fn rerank_resp_billing_flat_regardless_of_search_units() {
    // Even when Cohere reports billed search units, the projection stays Flat (search-unit
    // pricing is deferred; the count is echoed, not priced here).
    let resp = RerankResp {
        search_units: Some(3),
        ..Default::default()
    };
    assert_eq!(resp.billing(), Some(Billing::Flat));
}

// ── IrFacts projection (close-non-chat-gate-blindness) ───────────────────────────────────────────

use busbar_api::operation::Operation;
use busbar_substrate::ir::facts::{ContentItem, IrFacts};

#[test]
fn rerank_projects_query_and_every_document() {
    let req = RerankReq {
        model: "rerank-v3".into(),
        query: "the query".into(),
        documents: vec!["doc one".into(), "doc two".into()],
        ..Default::default()
    };
    assert_eq!(IrFacts::verb(&req), Operation::RERANK);
    assert!(!IrFacts::wants_stream(&req));
    let screened: Vec<String> = req
        .content()
        .iter()
        .map(|i| i.screenable_text().into_owned())
        .collect();
    assert_eq!(screened, vec!["the query", "doc one", "doc two"]);
    assert!(req
        .content()
        .iter()
        .all(|i| matches!(i, ContentItem::Text { .. })));
    assert_eq!(
        req.shape().text_chars,
        "the query".len() + "doc one".len() + "doc two".len()
    );
}

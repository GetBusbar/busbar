// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/ir/rerank.rs`.

use super::*;

#[test]
fn rerank_resp_billing_is_flat() {
    // Rerank has no token meter on either wire; a response reporting no search units is the flat
    // marker.
    let resp = RerankResp::default();
    assert_eq!(resp.billing(), Some(Billing::Flat));
}

/// ITEM 134: the search units Cohere billed REACH THE PRICE. `billing()` hardcoded `Flat` and
/// discarded the count it had correctly read, so a 5,000-document rerank billed like a 1-document
/// one. The count now leaves as the open class `search_units`, exactly as billed.
#[test]
fn rerank_resp_billing_counts_search_units_as_an_open_class() {
    let resp = RerankResp {
        search_units: Some(3),
        ..Default::default()
    };
    assert_eq!(
        resp.billing(),
        Some(Billing::Counted {
            class: "search_units".to_string(),
            count: 3
        })
    );
}

// ── IrFacts projection (close-non-chat-gate-blindness) ───────────────────────────────────────────

use busbar_api::operation::Operation;
use busbar_substrate_values::ir::facts::{ContentItem, IrFacts};

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

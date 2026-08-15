// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/ir/rerank.rs`.

use super::*;
use crate::ir::variant::IrResp;

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

#[test]
fn ir_resp_usage_rerank_arm_projects_flat() {
    // The IrResp::usage() symmetry gate must route the Rerank arm through RerankResp::billing().
    let ir = IrResp::Rerank(RerankResp::default());
    assert_eq!(ir.usage(), Some(Billing::Flat));
}

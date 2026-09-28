// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's ADMIT verdict: what a grant, a grantless admission and a refusal each answer.

use super::*;
use crate::plane_host::AdmitHandle;
use std::sync::Arc;

fn grant() -> AdmitHandle {
    AdmitHandle(Arc::new(()))
}

#[test]
fn an_admission_with_a_grant_charged_and_keeps_its_downgrade_pool() {
    let g = grant();
    let v = admit_verdict(Ok((Some(&g), Some("cheap".to_owned()))));
    assert_eq!(v.verdict, Ok(()));
    assert!(v.charged);
    assert_eq!(v.effective_pool.as_deref(), Some("cheap"));
}

#[test]
fn an_admission_without_a_grant_charged_nothing() {
    let v = admit_verdict(Ok((None, None)));
    assert_eq!(v.verdict, Ok(()));
    assert!(!v.charged, "a grantless admission must never be refunded");
    assert_eq!(v.effective_pool, None);
}

#[test]
fn a_refusal_is_over_budget_and_carries_the_rendered_retry_after() {
    let v = admit_verdict(Err(Some(30)));
    let refusal = v.verdict.expect_err("the door refused");
    assert_eq!(refusal.reason(), ReasonCode::OverBudget);
    assert_eq!(refusal.retry_after_secs(), Some(30));
    assert!(!v.charged);
    assert_eq!(v.effective_pool, None);
}

#[test]
fn a_refusal_without_a_retry_hint_carries_none() {
    let v = admit_verdict(Err(None));
    assert_eq!(v.verdict.expect_err("refused").retry_after_secs(), None);
}

fn usage(
    input: u64,
    output: u64,
    read: Option<u64>,
    write: Option<u64>,
) -> busbar_contract::billing::TokenUsage {
    busbar_contract::billing::TokenUsage {
        input,
        output,
        cache_read: read,
        cache_creation: write,
        ..Default::default()
    }
}

#[test]
fn the_fee_is_one_per_delivered_request_that_routed_upstream() {
    assert_eq!(fee_count(true, true), 1);
    assert_eq!(fee_count(true, false), 0);
    assert_eq!(fee_count(false, true), 0);
    assert_eq!(fee_count(false, false), 0);
}

#[test]
fn usage_lines_are_the_non_zero_tiers_in_canonical_order() {
    let u = usage(10, 5, Some(0), Some(3));
    let lines = usage_lines(Some(&u));
    let got: Vec<(&str, u64)> = lines
        .iter()
        .map(|l| (l.class.as_str(), l.quantity))
        .collect();
    assert_eq!(
        got,
        vec![
            (busbar_contract::records::UNIT_INPUT, 10),
            (busbar_contract::records::UNIT_OUTPUT, 5),
            (busbar_contract::records::UNIT_CACHE_WRITE, 3),
        ]
    );
    assert!(lines.iter().all(|l| !l.estimated));
}

#[test]
fn a_response_that_reported_nothing_reports_no_lines() {
    assert!(usage_lines(None).is_empty());
    assert!(usage_lines(Some(&usage(0, 0, None, None))).is_empty());
}

#[test]
fn the_metering_row_counts_its_request_and_carries_no_card_instant() {
    let u = usage(7, 2, Some(1), None);
    let row = metering_row("k1", "lane-a", "prov", Some(&u));
    assert_eq!(
        (
            row.key_id.as_str(),
            row.model.as_str(),
            row.provider.as_str()
        ),
        ("k1", "lane-a", "prov")
    );
    assert_eq!((row.tokens_input, row.tokens_output), (7, 2));
    assert_eq!((row.tokens_cache_read, row.tokens_cache_write), (1, 0));
    assert_eq!((row.requests, row.billable_requests), (1, 1));
    assert_eq!(row.priced_from_ms, 0);
    let empty = metering_row("k1", "lane-a", "prov", None);
    assert_eq!((empty.tokens_input, empty.requests), (0, 1));
}

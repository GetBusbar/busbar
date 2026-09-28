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

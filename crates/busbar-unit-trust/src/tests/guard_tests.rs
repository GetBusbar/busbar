// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The three guards: their answers, and above all their ORDER.

use super::Pools;
use crate::guard::{
    destination_guard, fallback_pools_authorized, pool_authorized, priced, RefusalKind,
};

const UNPRICED: &str = "no configured rate for model 'arbitrary'";

#[test]
fn a_key_restricted_to_another_pool_is_refused() {
    let pools = Pools::allowing(&["fast"]);
    let refusal = pool_authorized(&pools, "cold").expect("the key may not use this pool");
    assert_eq!(refusal.status, 403);
    assert_eq!(refusal.kind, RefusalKind::Permission);
    assert_eq!(
        refusal.message,
        "Your API key does not have permission to access this resource."
    );
    assert!(pool_authorized(&pools, "fast").is_none());
}

#[test]
fn the_refusal_body_names_no_key_and_no_pool() {
    let refusal = pool_authorized(&Pools::allowing(&["fast"]), "cold").expect("refused");
    for internal in ["cold", "fast", "pool", "key id", "governance", "vk_"] {
        assert!(
            !refusal.message.contains(internal),
            "the client-facing copy must not carry {internal:?}: {}",
            refusal.message
        );
    }
}

#[test]
fn an_omitted_restriction_admits_every_pool_and_an_empty_one_admits_none() {
    let unrestricted = Pools::default();
    assert!(pool_authorized(&unrestricted, "anything").is_none());
    let empty = Pools::allowing(&[]);
    assert!(
        pool_authorized(&empty, "anything").is_some(),
        "an explicit empty list is the empty set, not an absent restriction"
    );
}

#[test]
fn the_guards_are_inert_with_no_key() {
    let pools = Pools {
        has_key: false,
        ..Pools::allowing(&["fast"])
    };
    assert!(pool_authorized(&pools, "cold").is_none());
    assert!(fallback_pools_authorized(&pools, "cold").is_none());
}

#[test]
fn a_reachable_fallback_pool_the_key_may_not_use_is_refused() {
    // The key may use A, which falls over to B, which it may not.
    let pools = Pools {
        allowed: Some(vec!["a".to_string()]),
        ..Pools::default()
    }
    .falls_back("a", "b");
    assert!(
        pool_authorized(&pools, "a").is_none(),
        "the first pool itself is allowed"
    );
    let refusal = fallback_pools_authorized(&pools, "a").expect("the fallback is not");
    assert_eq!(
        refusal,
        pool_authorized(&Pools::allowing(&["a"]), "b").expect("the same refusal"),
        "a fallback denial is byte-for-byte the initial denial"
    );
}

#[test]
fn the_fallback_walk_is_multi_level() {
    // A to B to C: B is allowed, C is not.
    let pools = Pools {
        allowed: Some(vec!["a".to_string(), "b".to_string()]),
        ..Pools::default()
    }
    .falls_back("a", "b")
    .falls_back("b", "c");
    assert!(fallback_pools_authorized(&pools, "a").is_some());
}

#[test]
fn the_fallback_walk_terminates_on_a_cycle() {
    // A to B to A, both allowed: the visited set stops the walk rather than spinning.
    let pools = Pools {
        allowed: Some(vec!["a".to_string(), "b".to_string()]),
        ..Pools::default()
    }
    .falls_back("a", "b")
    .falls_back("b", "a");
    assert!(fallback_pools_authorized(&pools, "a").is_none());
}

#[test]
fn a_key_with_no_restriction_walks_no_fallback_chain() {
    let pools = Pools::default().falls_back("a", "b").falls_back("b", "a");
    assert!(fallback_pools_authorized(&pools, "a").is_none());
}

#[test]
fn an_unpriced_arbitrary_name_is_a_bad_request() {
    let pools = Pools::with_card_missing(&["arbitrary"]);
    let refusal = priced(&pools, "arbitrary", UNPRICED).expect("refused");
    assert_eq!(refusal.status, 400);
    assert_eq!(refusal.kind, RefusalKind::InvalidRequest);
    assert_eq!(refusal.message, UNPRICED);
}

#[test]
fn a_configured_name_is_priced_by_construction() {
    let pools = Pools::with_card_missing(&["fast"]).configuring("fast");
    assert!(
        priced(&pools, "fast", UNPRICED).is_none(),
        "a configured pool is never refused here; boot already proved the card covers it"
    );
}

#[test]
fn no_rate_card_means_no_unpriced_gate_at_all() {
    let mut pools = Pools::default();
    pools.unpriced.insert("arbitrary".to_string());
    assert!(priced(&pools, "arbitrary", UNPRICED).is_none());
}

#[test]
fn the_guards_run_in_order_pool_then_fallback_then_price() {
    // A request that would fail ALL THREE must report the FIRST one: the pool allow-list.
    let pools = Pools::with_card_missing(&["a"])
        .restricted_to(&[])
        .falls_back("a", "b");
    let refusal = destination_guard(&pools, "a", UNPRICED).expect_err("refused");
    assert_eq!(refusal.kind, RefusalKind::Permission);

    // With the first guard satisfied, the SECOND reports before the third.
    let pools = Pools::with_card_missing(&["a"])
        .restricted_to(&["a"])
        .falls_back("a", "b");
    let refusal = destination_guard(&pools, "a", UNPRICED).expect_err("refused");
    assert_eq!(refusal.kind, RefusalKind::Permission);
    assert_eq!(refusal.status, 403);

    // With both satisfied, the third reports.
    let pools = Pools::with_card_missing(&["a"]);
    let refusal = destination_guard(&pools, "a", UNPRICED).expect_err("refused");
    assert_eq!(refusal.kind, RefusalKind::InvalidRequest);
    assert_eq!(refusal.status, 400);
}

#[test]
fn a_clean_request_clears_every_guard() {
    assert!(destination_guard(&Pools::default(), "a", UNPRICED).is_ok());
}

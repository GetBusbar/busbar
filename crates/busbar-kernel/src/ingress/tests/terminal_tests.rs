// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE TERMINAL PER UNIT, counted on the metric the ingress terminal already emits.
//!
//! Every request this plane answers ends at `finish_inner` exactly once, through whichever door it
//! left by: the destination guard's refusal, the admission door's refusal, or the caller's
//! post-admission finish. A path that ended a unit twice would still return the right bytes, so the
//! bytes are not the proof; the count is. `busbar_requests_total` is that count: one increment per
//! terminal. The recorder is process-global, so each test speaks an `ingress_protocol` label nothing
//! else in this binary uses and asserts the exact delta on it. The pool label cannot carry that
//! isolation: a refusal labels its pool through `pool_label`, which bounds any pool the fallback
//! plane's view does not name to the shared `unresolved` label, and the neutral test plane has no
//! view.

use super::*;
use crate::test_support::{metric_sum, LaneSpec, TestApp};
use axum::response::IntoResponse;
use busbar_contract::records::{PlaneRequestCtx, ScopeRef, VirtualKey};

/// A deployment whose only pool is `pool`.
fn deployment(pool: &str) -> Arc<App> {
    crate::test_support::register_neutral_test_plane();
    crate::metrics::init();
    let proto = crate::proto::known_protocols()[0];
    TestApp::new()
        .lane(LaneSpec::new(pool, proto, "http://127.0.0.1:1"))
        .pool(pool, &[(0, 1)])
        .build()
}

/// A caller whose key grants exactly `pools`.
fn caller(pools: &[&str]) -> PlaneRequestCtx {
    PlaneRequestCtx {
        key: Some(Arc::new(VirtualKey {
            id: "ingress-terminal-key".to_string(),
            enabled: true,
            allowed_scopes: Some(pools.iter().map(|p| ScopeRef::pool(*p)).collect()),
            ..Default::default()
        })),
    }
}

/// How many terminals units spoken in `proto` have been through so far.
fn terminals(proto: &str) -> u64 {
    metric_sum(
        crate::metrics::REQUESTS_TOTAL,
        &[("ingress_protocol", proto)],
    )
    .round() as u64
}

/// The destination guard's refusal IS the unit's terminal: it ends the unit once, and the caller
/// that receives the refusal must not end it again.
#[test]
fn a_destination_refusal_ends_the_unit_exactly_once() {
    let pool = "ingress-terminal-acl-pool";
    let app = deployment(pool);
    let proto = "ingress-terminal-acl-proto";
    let before = terminals(proto);
    let refused = governance_guard(
        &app,
        &caller(&["some-other-pool"]),
        proto,
        pool,
        Instant::now(),
        0,
    )
    .err()
    .expect("a key without a grant on the pool is turned away");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        terminals(proto) - before,
        1,
        "one refused unit, one terminal: never none, never two"
    );
}

/// An admitted unit has NOT ended at the door: the guard posts nothing, and the caller's
/// post-admission finish is the one terminal.
#[test]
fn an_admitted_unit_ends_once_at_its_finish_and_never_at_the_door() {
    let pool = "ingress-terminal-admitted-pool";
    let app = deployment(pool);
    let proto = "ingress-terminal-admitted-proto";
    let gov = caller(&[pool]);
    let before = terminals(proto);
    let (grant, downgraded) = governance_guard(&app, &gov, proto, pool, Instant::now(), 0)
        .expect("the key holds a grant on the pool");
    assert_eq!(
        terminals(proto),
        before,
        "the door admitted the unit, so it must not have ended it"
    );
    let _ = finish_admitted(
        &app,
        &gov,
        proto,
        downgraded.as_deref().unwrap_or(pool),
        Instant::now(),
        0,
        StatusCode::BAD_GATEWAY.into_response(),
        grant.is_some(),
    );
    assert_eq!(
        terminals(proto) - before,
        1,
        "one admitted unit, one terminal"
    );
}

/// Each finish door is one terminal per call: a unit routed through either ends exactly once.
#[test]
fn each_finish_door_is_one_terminal() {
    let pool = "ingress-terminal-doors-pool";
    let app = deployment(pool);
    let proto = "ingress-terminal-doors-proto";
    let gov = caller(&[pool]);
    let before = terminals(proto);
    let _ = finish_rejected(
        &app,
        &gov,
        proto,
        pool,
        Instant::now(),
        0,
        StatusCode::BAD_REQUEST.into_response(),
    );
    assert_eq!(terminals(proto) - before, 1, "the not-charged door");
    let _ = finish_admitted(
        &app,
        &gov,
        proto,
        pool,
        Instant::now(),
        0,
        StatusCode::OK.into_response(),
        false,
    );
    assert_eq!(terminals(proto) - before, 2, "the charged door");
}

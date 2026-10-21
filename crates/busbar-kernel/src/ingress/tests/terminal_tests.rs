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

/// A deployment whose only pool is `pool`. The lane's protocol is a neutral name: the neutral test
/// plane builds no runtime from it, and no test here dispatches. (`known_protocols()` is empty when
/// these tests run alone, so it cannot supply one.)
fn deployment(pool: &str) -> Arc<App> {
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init();
    TestApp::new()
        .lane(LaneSpec::new(
            pool,
            "ingress-terminal-lane-proto",
            "http://127.0.0.1:1",
        ))
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
        crate::snapshot::REQUESTS_TOTAL,
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
    let Err(refused) = governance_guard(
        &app,
        &caller(&["some-other-pool"]),
        proto,
        pool,
        Instant::now(),
        0,
    ) else {
        panic!("a key without a grant on the pool is turned away");
    };
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
        grant.as_ref().map(crate::governance::AdmitGrant::charge),
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
        None,
    );
    assert_eq!(terminals(proto) - before, 2, "the charged door");
}

/// F25 row 702: rehomed from the retired engine crate's src/unit/tests/chain.rs::the_refused_terminal_labels_a_configured_pool_with_its_name.
/// Pins: the live pre-admission guard's refusal (403) against a CONFIGURED pool ends its unit on a
/// terminal labelled with that pool's own name, and a refusal against a name no deployment
/// configured is labelled with the reserved `unresolved` label — the bound is unchanged.
#[test]
fn the_refused_terminal_labels_a_configured_pool_with_its_name() {
    let pool = "ingress-terminal-label-pool";
    let app = deployment(pool);
    assert_eq!(
        pool_label(&app, pool),
        pool,
        "the fixture's pool is configured, so the live label is its name"
    );

    // LEG 1 — a configured pool the key may not reach: 403, one terminal, labelled by name.
    let proto = "ingress-terminal-label-proto";
    let labelled = |label: &str| {
        metric_sum(
            crate::snapshot::REQUESTS_TOTAL,
            &[("ingress_protocol", proto), ("pool", label)],
        )
        .round() as u64
    };
    let before = labelled(pool);
    let Err(refused) = destination_guard(
        &app,
        &caller(&["some-other-pool"]),
        proto,
        pool,
        Instant::now(),
        0,
    ) else {
        panic!("the key may not reach the pool it named");
    };
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        labelled(pool) - before,
        1,
        "the refusal's terminal is labelled with the configured pool's name"
    );

    // LEG 2 — a name nothing configured: the bound still reads it back as `unresolved`.
    let unknown = "ingress-terminal-no-such-pool";
    assert_eq!(
        pool_label(&app, unknown),
        crate::telemetry::POOL_LABEL_UNRESOLVED
    );
    let unresolved_proto = "ingress-terminal-label-unresolved-proto";
    let unresolved = || {
        metric_sum(
            crate::snapshot::REQUESTS_TOTAL,
            &[
                ("ingress_protocol", unresolved_proto),
                ("pool", crate::telemetry::POOL_LABEL_UNRESOLVED),
            ],
        )
        .round() as u64
    };
    let before = unresolved();
    let Err(refused) = destination_guard(
        &app,
        &caller(&["some-other-pool"]),
        unresolved_proto,
        unknown,
        Instant::now(),
        0,
    ) else {
        panic!("the key may not reach a name it holds no grant on");
    };
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        unresolved() - before,
        1,
        "an unconfigured name is never widened into a label of its own"
    );
}

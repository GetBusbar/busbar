// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::JsonValueTrait as _;
use busbar_contract::records::VirtualKey;

#[test]
fn an_explicit_empty_scope_list_sees_no_pool() {
    let mut key = VirtualKey {
        id: "vk_empty_scopes".to_string(),
        enabled: true,
        ..Default::default()
    };
    key.allowed_scopes = Some(Vec::new());
    assert!(
        !crate::governance::pool_allowed(&key, "any-pool"),
        "an explicit empty list is no scopes at all, never all pools"
    );
    key.allowed_scopes = None;
    assert!(
        crate::governance::pool_allowed(&key, "any-pool"),
        "only an omitted list is a wildcard"
    );
}

fn lane() -> busbar_kernel::store::LaneSnapshot {
    busbar_kernel::store::LaneSnapshot {
        member: "m".to_string(),
        route: "r".to_string(),
        max_concurrent: 7,
        inflight: 0,
        free_slots: 7,
        available: Some(7),
        at_capacity: false,
        availability: Ok(()),
        breaker_state: busbar_kernel::store::BreakerState::Closed,
        ok: 0,
        err: 0,
        client_fault: 0,
        usable: true,
        dead: false,
        dead_reason: String::new(),
        cooldown_remaining_s: 0,
        streak: 0,
        budget: -1,
        trips: 0,
        last_trip_at: 0,
    }
}

/// CLEAN-1.6: `/stats` reports a lane's concurrency cap as `max_concurrent` only; the 1.5.x
/// `limit` alias is gone (clients read `max_concurrent`).
#[test]
fn stats_lane_has_no_limit_alias() {
    let body = crate::endpoints::lane_body(lane(), 0);
    assert_eq!(body["max_concurrent"], 7, "the cap is max_concurrent");
    assert!(
        body.get("limit").is_none(),
        "the `limit` alias is removed in 1.6.0: {body}"
    );
}

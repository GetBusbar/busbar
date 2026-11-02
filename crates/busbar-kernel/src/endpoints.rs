// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::{json, Value};

use crate::governance::{pool_allowed, GovCtx};
use busbar_kernel::store::now;

use crate::state::App;

pub async fn stats(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Extension(gov): Extension<GovCtx>,
) -> Response {
    let t = now();

    let restricted = gov.key.as_ref().is_some_and(|k| k.allowed_scopes.is_some());

    let visible_pool = |name: &str| -> bool {
        match gov.key.as_ref() {
            Some(key) => pool_allowed(key, name),
            None => true,
        }
    };

    let view = app.engine_tables_view();
    let pools: std::collections::BTreeMap<&str, Vec<&str>> = view
        .pools()
        .into_iter()
        .filter(|(n, _)| visible_pool(n))
        .map(|(n, members)| {
            (
                n,
                members
                    .iter()
                    .map(|&idx| view.lane_view(idx).map(|l| l.model).unwrap_or(""))
                    .collect(),
            )
        })
        .collect();

    let lane_visible = |i: usize| -> bool {
        if !restricted {
            return true;
        }
        view.pools()
            .iter()
            .filter(|(n, _)| visible_pool(n))
            .any(|(_, members)| members.contains(&i))
    };

    let lanes: Vec<Value> = (0..view.lane_count())
        .filter(|&i| lane_visible(i))
        .map(|i| {
            let snap = app.store.snapshot(i, t);

            let (availability, recovery_hint_ms) = match snap.availability {
                Ok(()) => ("available", Value::Null),
                Err(reason) => (
                    reason.variant_name(),
                    match reason.recovery_hint_ms(t) {
                        Some(ms) => json!(ms),
                        None => Value::Null,
                    },
                ),
            };
            let breaker_state = match snap.breaker_state {
                busbar_kernel::store::BreakerState::Closed => "closed",
                busbar_kernel::store::BreakerState::Open { .. } => "open",
                busbar_kernel::store::BreakerState::HalfOpen => "half_open",
            };
            json!({
                "model": snap.member,
                "provider": snap.route,
                "max_concurrent": snap.max_concurrent,
                // Alias of `max_concurrent` under a shorter field name (the lane's concurrency
                // limit). Kept alongside `max_concurrent` for backward compatibility: an unbounded
                // lane reports the semaphore's max permit count, a bounded lane its configured cap.
                "limit": snap.max_concurrent,
                "inflight": snap.inflight,
                "free_slots": snap.free_slots,
                // Bug 1 capacity signal: a saturated lane is now externally distinguishable from an
                // idle or unbounded one. `available` is the free permit count for a bounded lane, or
                // the string "unbounded" when `max_concurrent` is omitted; `at_capacity` is true iff
                // a bounded lane is at its limit (available == 0) and is therefore shedding/spilling.
                "available": match snap.available {
                    Some(n) => json!(n),
                    None => json!("unbounded"),
                },
                "at_capacity": snap.at_capacity,
                // Unified availability signal + independent breaker axis.
                "availability": availability,
                "recovery_hint_ms": recovery_hint_ms,
                "breaker_state": breaker_state,
                "ok": snap.ok,
                "err": snap.err,
                "client_fault": snap.client_fault,
                "usable": snap.usable,
                "dead": snap.dead,
                "dead_reason": snap.dead_reason,
                "cooldown_remaining_s": snap.cooldown_remaining_s,
                "streak": snap.streak,
                "budget": snap.budget,
            })
        })
        .collect();

    Json(json!({ "pools": pools, "lanes": lanes })).into_response()
}

#[must_use]
pub fn catalog_names(app: &App, gov: &GovCtx) -> Vec<String> {
    let restricted = gov.key.as_ref().is_some_and(|k| k.allowed_scopes.is_some());

    let view = app.engine_tables_view();
    let pools = view.pools();

    let visible_pool = |name: &str| -> bool {
        match gov.key.as_ref() {
            Some(key) => pool_allowed(key, name),
            None => true,
        }
    };

    let mut names: Vec<&str> = pools
        .iter()
        .map(|(n, _)| *n)
        .filter(|n| visible_pool(n))
        .collect();
    names.sort_unstable();

    let mut models: Vec<&str> = view
        .model_indices()
        .into_iter()
        .filter_map(|(m, idx)| {
            if !restricted {
                return Some(m);
            }

            let routed = pools
                .iter()
                .filter(|(n, _)| visible_pool(n))
                .any(|(_, member_idxs)| member_idxs.contains(&idx));
            routed.then_some(m)
        })
        .collect();
    models.sort_unstable();
    names.extend(models);
    names.dedup();

    for name in crate::plane_driver::door::listed(&app.plane_slots, gov.key.as_deref()) {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names.into_iter().map(str::to_string).collect()
}

pub async fn healthz(crate::state::CurrentApp(app): crate::state::CurrentApp) -> Response {
    let latched = crate::preflight::root_rows()
        .dispatch_latched
        .is_some_and(|latched| latched());
    if let Some(halted) = plugin_dispatch_halted(latched) {
        return halted;
    }
    let t = now();

    let lanes = app.engine_tables_view().lane_count();
    let ready = if lanes == 0 {
        a_plane_opened(&app)
    } else {
        (0..lanes).any(|i| app.store.is_ready_any_cell(i, t))
    };
    if ready {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "no usable lanes").into_response()
    }
}

fn plugin_dispatch_halted(latched: bool) -> Option<Response> {
    latched.then(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "plugin dispatch halted; restart required",
        )
            .into_response()
    })
}

fn a_plane_opened(app: &crate::state::App) -> bool {
    crate::plane_driver::registry::plane_decls()
        .iter()
        .filter(|d| !d.fallback && app.plane_configured(d))
        .filter_map(|d| app.plane_slot(d.key))
        .any(|slot| crate::plane_driver::door::opened(slot.as_ref()))
}

#[cfg(test)]
#[path = "tests/endpoints_doc_tests.rs"]
mod endpoints_doc_tests;

#[cfg(test)]
#[path = "tests/plugin_dispatch_halted_tests.rs"]
mod plugin_dispatch_halted_tests;

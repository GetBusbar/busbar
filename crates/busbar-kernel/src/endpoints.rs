// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::{json, Value};

use crate::governance::{pool_allowed, GovCtx};
use busbar_kernel::store::now;

use crate::state::App;

/// `/stats` reports the pool/lane topology. It is governance-scoped: a virtual key minted with an
/// `allowed_scopes` list must NOT learn the full topology of pools and lanes it can never reach
/// (info disclosure — a restricted tenant could otherwise enumerate every model, provider, and pool
/// the gateway fronts). We FILTER the reported pools to those the caller may target, and the
/// reported lanes to the union of lanes reachable via those visible pools.
///
/// Only an OMITTED list is a wildcard, exactly as the frozen `VirtualKey::scope_allowed` reads it: a
/// key whose `allowed_scopes` is `None`, or no key at all (`key: None` — governance disabled, or the
/// operator/admin default `GovCtx`), sees the full topology. An explicit EMPTY list is no scopes at
/// all — never "all pools" — so such a key sees no pool and no lane.
pub async fn stats(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Extension(gov): Extension<GovCtx>,
) -> Response {
    let t = now();

    // Decide which pools are visible to this caller. No key => no restriction (the visible set is
    // every pool). A key whose `allowed_scopes` was omitted at mint (None) admits every pool via
    // `pool_allowed`, so an unrestricted key also sees everything; an explicit list (even empty)
    // restricts.
    let restricted = gov.key.as_ref().is_some_and(|k| k.allowed_scopes.is_some());

    let visible_pool = |name: &str| -> bool {
        match gov.key.as_ref() {
            Some(key) => pool_allowed(key, name),
            None => true,
        }
    };

    // BTreeMap (not HashMap) so the serialized `pools` object has a stable, sorted key order —
    // `app.pools` is a HashMap whose iteration order is randomized per process, which otherwise
    // makes `/stats` output non-reproducible across restarts. Lane order is already deterministic
    // (index order, and lane indices are now built sorted-by-model — see main.rs).
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

    // Lanes are filtered to those reachable via a visible pool ONLY when the caller is restricted.
    // An unrestricted caller (no key, or a key with no `allowed_scopes` list) sees every lane — any
    // lane not bound to a pool included. A restricted caller sees only the lanes its
    // visible pools route to; lanes outside those pools (and pool-less lanes) stay hidden, so the
    // lane list can't be used to enumerate the topology the pool filter just removed.
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
            // `availability` is rendered from the SHARED `Unavailable` taxonomy (the same
            // `classify` routing dispatches on), so /stats can't drift from behaviour. `Ok` → the
            // sentinel "available"; `Err` → the variant name + its `recovery_hint_ms` (null when the
            // reason has no self-recovery, e.g. dead/budget). `breaker_state` and `at_capacity` remain
            // SEPARATE, orthogonal axes: a saturated Open lane shows breaker_state="open" AND
            // at_capacity=true AND availability="breaker_open", so operators can see why its recovery
            // probe (which needs a dispatch it can't win) never fires — not collapsed into one string.
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
                "model": snap.model,
                "provider": snap.provider,
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

/// `GET /v1/models` and `GET /v1beta/models` — the list-models discovery surface. This is often the
/// first call an SDK (`client.models.list()`) or a self-hosted UI makes to populate a model picker,
/// so busbar answers it with every name a client can put in a request body: configured model
/// entries AND pool names (a pool is a routable model from the client's point of view), then each
/// plane generation's listed names.
///
/// Governance-scoped with the same rules as `/stats`: a virtual key with an `allowed_scopes` list
/// (even an empty one) sees only its visible pools and the models reachable through them — the
/// model list must not leak topology the pool ACL hides.
///
/// THE KERNEL COMPUTES THE NAMES; THE PLANE RENDERS THEM (ARCHITECT RULING D, 2026-10-07; spec Part
/// 2 #49, THE DESIGN §5 l.958-960). Several dialects put their list-models endpoint on this noun,
/// each with its own envelope, and which one a caller speaks is a dialect question the kernel does
/// not ask: the names go to the claimant of the plane line beneath the path
/// ([`crate::guest::ListenerLines::render_listing`], through its `serve`), which picks the dialect
/// by its own rule from the target and the caller's head and answers the whole reply. Not a unit:
/// nothing here is admitted, audited, metered or posted. With no plane line beneath the path (a
/// build with no plane claiming it), the answer is an empty JSON object, which names no dialect and
/// leaks no shape.
pub async fn list_models(
    axum::extract::State(handle): axum::extract::State<Arc<crate::state::AppHandle>>,
    Extension(gov): Extension<GovCtx>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
) -> Response {
    let app = handle.load();
    let lines = handle.listener_lines();
    let listed = lines.map(|l| l.listed()).unwrap_or_default();
    let names = visible_names(&app, &gov, &listed);
    let target = uri.path_and_query().map_or(uri.path(), |t| t.as_str());
    let rendered = match lines {
        Some(lines) => {
            lines
                .render_listing(target, listing_head(&headers), names)
                .await
        }
        None => None,
    };
    rendered
        .and_then(|r| rendered_response(&r))
        .unwrap_or_else(|| Json(json!({})).into_response())
}

/// THE NAMES `gov`'s caller may put in a request body, in the order the listing states them: the
/// visible pools (sorted), then the direct models (sorted; a restricted key sees one only when a
/// visible pool routes to its lane), adjacent repeats dropped; then each plane generation's
/// `listed` name its grant reaches and the list does not already hold, in the order stated.
#[must_use]
pub fn visible_names(app: &App, gov: &GovCtx, listed: &[crate::guest::Listed]) -> Vec<String> {
    let restricted = gov.key.as_ref().is_some_and(|k| k.allowed_scopes.is_some());
    // The routing tables through the NEUTRAL read seam (money-path Phase 3-4 B): discovery reads the
    // pool label space, the direct-model index, and pool membership as neutral projections, so
    // `/v1/models` names no `Lane`/`WeightedLane` and need not relocate with the tables. `pools()`
    // allocates its projection, so bind it once — the visible-name build reads membership repeatedly.
    let view = app.engine_tables_view();
    let pools = view.pools();

    let visible_pool = |name: &str| -> bool {
        match gov.key.as_ref() {
            Some(key) => pool_allowed(key, name),
            None => true,
        }
    };

    // Stable order: pools first, then direct models, each sorted — SDK consumers and UIs
    // render this list directly, and a deterministic order diffs cleanly in tests and docs.
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
            // A restricted key sees a direct model only if a visible pool routes to its lane
            // (mirrors the /stats lane rule; pool-less lanes stay hidden from restricted keys).
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

    let mut out: Vec<String> = names.into_iter().map(str::to_string).collect();
    // Each plane generation's listed names (spec l.410), behind the caller's grant: appended, so a
    // build whose planes list none answers the bytes it always did.
    for l in listed {
        let granted = gov
            .key
            .as_ref()
            .is_none_or(|k| k.scope_allowed(&l.scope.kind, &l.scope.value));
        if granted && !out.contains(&l.name) {
            out.push(l.name.clone());
        }
    }
    out
}

/// The caller's head as a listing render reads it: its fields in order, as every plane crossing
/// carries them ([`crate::plane_driver::caller_head`]), except that a field the contract never
/// keeps (a credential among them) crosses by NAME ALONE, its value empty. Which dialect a caller
/// speaks is told by which fields it sent (one dialect's SDK names its key in its own field), never
/// by a credential's value, and the value never leaves the kernel.
fn listing_head(headers: &axum::http::HeaderMap) -> Vec<(Vec<u8>, Vec<u8>)> {
    use busbar_contract::abi::host::conn::connector::NEVER_KEPT;
    let kept = crate::plane_driver::caller_head(headers);
    let mut out = Vec::with_capacity(headers.len());
    let mut kept = kept.into_iter().peekable();
    for (name, value) in headers {
        let name = name.as_str().as_bytes();
        if kept
            .peek()
            .is_some_and(|(n, v)| n.as_slice() == name && v.as_slice() == value.as_bytes())
        {
            out.extend(kept.next());
        } else if NEVER_KEPT
            .iter()
            .any(|n| n.as_bytes().eq_ignore_ascii_case(name))
        {
            out.push((name.to_vec(), Vec::new()));
        }
    }
    out
}

/// The claimant's rendered reply as the response; `None` when a status or field it wrote is not
/// one a reply can carry.
fn rendered_response(r: &crate::guest::Refused) -> Option<Response> {
    let status = StatusCode::from_u16(r.status).ok()?;
    let mut resp = Response::new(axum::body::Body::from(r.body.clone()));
    *resp.status_mut() = status;
    for (n, v) in &r.fields {
        let name = axum::http::HeaderName::from_bytes(n).ok()?;
        let value = axum::http::HeaderValue::from_bytes(v).ok()?;
        resp.headers_mut().append(name, value);
    }
    Some(resp)
}

pub async fn healthz(crate::state::CurrentApp(app): crate::state::CurrentApp) -> Response {
    let t = now();
    // Side-effect-FREE readiness check: `/healthz` is unauthenticated and high-frequency (k8s
    // liveness, load balancers), so it must NOT transition expired-Open lanes to HalfOpen or steal
    // the single-flight recovery probe from organic traffic — use the non-mutating `is_ready_any_cell`,
    // not the mutating `usable`. `is_ready_any_cell` (not the default-cell-only `is_ready`) checks the
    // default cell AND every per-pool cell: production routes through NAMED pools whose per-pool cells
    // trip independently, so reading only the default `""` cell would report 200 while every pool lane
    // is circuit-broken (the default cell never moves for pool-routed traffic).
    if (0..app.engine_tables_view().lane_count()).any(|i| app.store.is_ready_any_cell(i, t)) {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "no usable lanes").into_response()
    }
}

// `tests` (the `/stats`/`/v1/models` topology suite) MOVED to `tests/endpoints_cross_plane.rs` (the
// "fix the 38" pass after the A6/HostCtx dev-dependency-cycle cleanup): every test in it builds real
// lanes/pools, which only materialize through the REAL `busbar_llm` plane's `build_runtime`/`viewer`
// — an integration-test target, never this `#[cfg(test)]` unit module. See that file's header.

#[cfg(test)]
#[path = "tests/endpoints_doc_tests.rs"]
mod endpoints_doc_tests;

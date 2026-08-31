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
use crate::state::{now, App};

/// `/stats` reports the pool/lane topology. It is governance-scoped: a virtual key with a
/// non-empty `allowed_pools` must NOT learn the full topology of pools and lanes it can never
/// reach (info disclosure — a restricted tenant could otherwise enumerate every model, provider,
/// and pool the gateway fronts). We FILTER the reported pools to those the caller may target, and
/// the reported lanes to the union of lanes reachable via those visible pools.
///
/// An empty `allowed_pools` (or `key: None` — governance disabled, or the operator/admin default
/// `GovCtx`) means "all pools", so those callers see the full topology exactly as before: this
/// preserves today's operator/admin behavior.
pub(crate) async fn stats(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Extension(gov): Extension<GovCtx>,
) -> Response {
    let t = now();

    // Decide which pools are visible to this caller. No key => no restriction (the visible set is
    // every pool). A key whose `allowed_pools` was omitted at mint (None) admits every pool via
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
    let pools: std::collections::BTreeMap<&String, Vec<&str>> = app
        .pools
        .iter()
        .filter(|(n, _)| visible_pool(n))
        .map(|(n, weighted_lanes)| {
            (
                n,
                weighted_lanes
                    .iter()
                    .map(|wl| app.lanes[wl.idx].model.as_str())
                    .collect(),
            )
        })
        .collect();

    // Lanes are filtered to those reachable via a visible pool ONLY when the caller is restricted.
    // An unrestricted caller (no key, or empty `allowed_pools`) sees every lane — including any
    // lane not bound to a pool — exactly as before. A restricted caller sees only the lanes its
    // visible pools route to; lanes outside those pools (and pool-less lanes) stay hidden, so the
    // lane list can't be used to enumerate the topology the pool filter just removed.
    let lane_visible = |i: usize| -> bool {
        if !restricted {
            return true;
        }
        app.pools
            .iter()
            .filter(|(n, _)| visible_pool(n))
            .any(|(_, weighted_lanes)| weighted_lanes.iter().any(|wl| wl.idx == i))
    };

    let lanes: Vec<Value> = (0..app.lanes.len())
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
                crate::store::BreakerState::Closed => "closed",
                crate::store::BreakerState::Open { .. } => "open",
                crate::store::BreakerState::HalfOpen => "half_open",
            };
            json!({
                "model": snap.model,
                "provider": snap.provider,
                "max_concurrent": snap.max_concurrent,
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

/// `GET /v1/models` — the OpenAI list-models surface. This is the first call an OpenAI SDK
/// (`client.models.list()`) or a self-hosted UI (Open WebUI, LibreChat) makes to populate a
/// model picker, so busbar answers it with every name a client can put in a request body:
/// configured model entries AND pool names (a pool is a routable model from the client's
/// point of view).
///
/// Governance-scoped with the same rules as `/stats`: a virtual key with a non-empty
/// `allowed_pools` sees only its visible pools and the models reachable through them —
/// the model list must not leak topology the pool ACL hides.
pub(crate) async fn list_models(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Extension(gov): Extension<GovCtx>,
    headers: axum::http::HeaderMap,
) -> Response {
    list_models_dialect(app, gov, &headers, false)
}

/// `GET /v1beta/models` — the same list in Gemini's dialect (their SDK's discovery path).
pub(crate) async fn list_models_v1beta(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    Extension(gov): Extension<GovCtx>,
    headers: axum::http::HeaderMap,
) -> Response {
    list_models_dialect(app, gov, &headers, true)
}

/// Three protocols put their list-models endpoint on the same noun, each with its own
/// envelope: OpenAI and Anthropic share `GET /v1/models` outright, and Gemini lists at
/// `GET /v1(beta)/models`. Primary (POST) surfaces are disjoint by path, so this is the
/// one place busbar disambiguates callers by PROTOCOL FINGERPRINT instead:
///
/// - `anthropic-version` header — the Anthropic API requires it, so their SDK always
///   sends it -> Anthropic envelope
/// - `x-goog-api-key` header or the /v1beta path -> Gemini envelope
/// - otherwise -> OpenAI envelope (the compatible ecosystem's default; Cohere's SDK
///   carries no reliable fingerprint and receives this shape, documented)
///
/// The list itself is the same data in every dialect: the names a client may put in a
/// request body. No privileged protocol - the data is one, the rendering is the caller's.
fn list_models_dialect(
    app: Arc<App>,
    gov: GovCtx,
    headers: &axum::http::HeaderMap,
    gemini_path: bool,
) -> Response {
    let restricted = gov.key.as_ref().is_some_and(|k| k.allowed_scopes.is_some());

    let visible_pool = |name: &str| -> bool {
        match gov.key.as_ref() {
            Some(key) => pool_allowed(key, name),
            None => true,
        }
    };

    // Stable order: pools first, then direct models, each sorted — SDK consumers and UIs
    // render this list directly, and a deterministic order diffs cleanly in tests and docs.
    let mut names: Vec<&str> = app
        .pools
        .keys()
        .filter(|n| visible_pool(n))
        .map(String::as_str)
        .collect();
    names.sort_unstable();

    let mut models: Vec<&str> = app
        .by_model
        .keys()
        .filter(|m| {
            if !restricted {
                return true;
            }
            // A restricted key sees a direct model only if a visible pool routes to its lane
            // (mirrors the /stats lane rule; pool-less lanes stay hidden from restricted keys).
            let Some(&idx) = app.by_model.get(*m) else {
                return false;
            };
            app.pools
                .iter()
                .filter(|(n, _)| visible_pool(n))
                .any(|(_, wls)| wls.iter().any(|wl| wl.idx == idx))
        })
        .map(String::as_str)
        .collect();
    models.sort_unstable();
    names.extend(models);
    names.dedup();

    // Neutral dispatch: core resolves WHICH dialect answers from the request fingerprint, then hands
    // that dialect's declaration the visible name list and lets IT shape the envelope. The three
    // list-models envelope shapes (OpenAI's `{object:"list",data}`, Anthropic's paginated `{data,
    // has_more,…}`, Gemini's `{models}`) are LLM-specific and now live with the dialects in
    // `busbar-llm` behind `ProtocolDecl::models_list_envelope` — core names none of them here.
    // The dialect selection is the generic detection fold, restricted to the two fingerprints this
    // shared noun disambiguates on (the Anthropic version header, the Gemini key header / `/v1beta`
    // path) and defaulting to the registry's residual dialect — so core spells NO dialect name here.
    // Restricting the sniff to those two headers (rather than the full router headers) keeps this
    // byte-identical to the prior three-arm `if`: an incidental `x-api-key`/SigV4 on a models-list
    // GET must not steer the envelope, only the two fingerprints the SDKs actually send here do.
    let mut sniff = axum::http::HeaderMap::new();
    for &name in crate::proto::known_protocols() {
        let Some(decl) = crate::proto::decl_for(name) else {
            continue;
        };
        for &hn in decl.list_models_fingerprint_headers {
            if let Some(v) = headers.get(hn) {
                sniff.insert(hn, v.clone());
            }
        }
    }
    let sniff_path = if gemini_path {
        "/v1beta/models/"
    } else {
        "/v1/models"
    };
    let dialect = crate::proto::detect_protocol(sniff_path, &sniff)
        .or_else(crate::proto::residual_default_dialect);
    match dialect
        .and_then(crate::proto::decl_for)
        .and_then(|d| d.models_list_envelope)
    {
        Some(build) => Json(build(&names)).into_response(),
        // Unreachable while the LLM protocols are installed (they always declare this builder). If a
        // build ships without them, `/v1/models` still resolves but has no dialect to render for — an
        // empty JSON object names no protocol and leaks no shape.
        None => Json(json!({})).into_response(),
    }
}

pub(crate) async fn healthz(crate::state::CurrentApp(app): crate::state::CurrentApp) -> Response {
    let t = now();
    // Side-effect-FREE readiness check: `/healthz` is unauthenticated and high-frequency (k8s
    // liveness, load balancers), so it must NOT transition expired-Open lanes to HalfOpen or steal
    // the single-flight recovery probe from organic traffic — use the non-mutating `is_ready_any_cell`,
    // not the mutating `usable`. `is_ready_any_cell` (not the default-cell-only `is_ready`) checks the
    // default cell AND every per-pool cell: production routes through NAMED pools whose per-pool cells
    // trip independently, so reading only the default `""` cell would report 200 while every pool lane
    // is circuit-broken (the default cell never moves for pool-routed traffic).
    if (0..app.lanes.len()).any(|i| app.store.is_ready_any_cell(i, t)) {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "no usable lanes").into_response()
    }
}

#[cfg(test)]
#[path = "tests/endpoints_tests.rs"]
mod tests;

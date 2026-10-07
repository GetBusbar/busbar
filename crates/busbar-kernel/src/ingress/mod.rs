// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::OriginalUri,
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::state::App;

/// enforce a virtual key's allowed-pools list against the resolved target pool. No-op
/// when governance is off (`gov.key` is None) or the key allows all pools. Returns a 403 response
/// to short-circuit when the key may not use this pool.
pub fn pool_authorized(
    gov: &crate::governance::GovCtx,
    pool: &str,
    proto: &str,
) -> Option<Response> {
    if let Some(key) = &gov.key {
        if !crate::governance::pool_allowed(key, pool) {
            // The client-facing body carries only vendor-plausible copy — never the internal key id
            // or governance vocabulary (a native vendor 403 never names an operator key or a pool).
            // The key id + pool are recorded server-side via tracing for operator diagnosis.
            tracing::info!(key_id = %key.id, pool = %pool, "governance: key not authorized for pool");
            return Some(ingress_error(
                proto,
                StatusCode::FORBIDDEN,
                crate::proxy::KIND_PERMISSION,
                "Your API key does not have permission to access this resource.",
            ));
        }
    }
    None
}

/// Re-enforce the virtual key's `allowed_pools` ACL against EVERY fallback pool the request could
/// reach if the requested pool exhausts (`OnExhausted::FallbackPool`). The initial `pool_authorized`
/// check only gates the FIRST pool; without this, a key restricted to pool A could be served by a
/// fallback pool B (configured via A's `on_exhausted = fallback_pool:B`) it is not allowed to touch,
/// because the fallback dispatch in `proxy::handle_fallback_pool` never re-checks the key (the
/// `gov` context is not threaded that deep — the ACL is an INGRESS concern, enforced here).
///
/// The fallback chain is multi-level (A→B→C: B's own `on_exhausted` may name C) and may cycle
/// (A→B→A). We walk it with the SAME visited-pool termination guard `handle_fallback_pool` uses, so
/// the walk always terminates, and we reject (403) the moment any reachable fallback pool is one the
/// key may not use — mirroring the initial `pool_authorized` 403 exactly (same status/kind/body, so
/// the denial is vendor-indistinguishable whether it trips on the initial or a fallback pool).
///
/// No-op when governance is off (`gov.key` is None) or the key allows all pools.
pub fn fallback_pools_authorized(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    pool: &str,
    proto: &str,
) -> Option<Response> {
    let key = gov.key.as_ref()?;
    // A key with no restriction (`allowed_pools` omitted at mint = None) admits every pool,
    // nothing to walk. (An explicit empty list is the EMPTY set and walks like any list: every
    // pool denies.)
    key.allowed_scopes.as_ref()?;
    let view = app.engine_tables_view();
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut current = pool.to_string();
    loop {
        // Termination guard: a chain that cycles back to an already-walked pool (A→B→A) stops —
        // mirrors `handle_fallback_pool`'s `visited_pools` guard so the two cannot diverge.
        if !visited.insert(current.clone()) {
            return None;
        }
        // The FALLBACK-POOL target `current` fails over to, through the neutral read seam. `None` when
        // its `on_exhausted:` policy is `Status503`/`LeastBad`/`Queue` (all stay within `current` — no
        // new pool name) or the pool is unconfigured (defaults to 503) — the walk ends here.
        let next = view.on_exhausted_fallback(&current)?;
        // Re-run the identical ACL gate against the fallback pool name before it could ever be
        // dispatched to. A 403 here is byte-for-byte the initial-pool 403.
        if let Some(resp) = pool_authorized(gov, &next, proto) {
            return Some(resp);
        }
        current = next;
    }
}

/// Render the pool scope of a blocking limit for the client-facing rejection: a pool-qualified
/// limit caps only that pool's traffic, and saying so tells the caller the actionable part -
/// other pools may still serve them.
fn pool_scope_suffix(pool: &Option<String>) -> String {
    match pool {
        Some(p) => format!(", pool '{p}'"),
        None => String::new(),
    }
}

/// Run the atomic group-limit ADMISSION for a request that is about to be forwarded, through the
/// generic limit engine. `Ok(Some(grant))` = admitted AND charged (the flat per-request fee + one
/// request landed on every chain bucket; a non-2xx must refund, and the grant holds the
/// `concurrent` in-flight gauges until the response completes). `Ok(None)` = admitted WITHOUT a
/// charge (governance off / no key) - a non-2xx must NOT refund: there is no
/// [`FeeCharge`](crate::governance::FeeCharge) to return, and a refund without one would erode
/// ANOTHER request's spend/count in the same window (see `finish_rejected`). `Err(resp)` = rejected with the protocol-native error NAMING the exact
/// blocking bucket (group + metric + window).
///
/// The admission window is keyed off `charged_at` (the pinned header-arrival epoch), NOT a fresh
/// `store::now()`: the token fee (`UsageSink::charged_at` -> `record_usage`) bills into the SAME
/// window, so a request straddling a window boundary can never split its charges (#29).
pub fn admit_check(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &str,
    pool: &str,
    charged_at: u64,
) -> Result<(Option<crate::governance::AdmitGrant>, Option<String>), Box<Response>> {
    let (Some(g), Some(key)) = (&app.governance, &gov.key) else {
        // Governance off or no resolved key → no charge landed; nothing to refund on a non-2xx.
        return Ok((None, None));
    };
    // ONE indivisible check-and-charge over the whole chain: every group's every limit must admit
    // (AND / most-restrictive) and every bucket is charged in the same critical section - N
    // concurrent requests can never each read "under the cap" and all charge. Infallible
    // in-memory (write-behind store): admission never blocks on or fails from the durable store.
    // A budget block that downgrades re-admits on its `downgrade_to` pool ([`admit_downgrading`]).
    let view = app.engine_tables_view();
    let pools = view.pools();
    let walked = admit_downgrading(
        &key.id,
        pool,
        pools.len(),
        |to| pools.iter().any(|(n, _)| *n == to),
        |to| {
            pool_authorized(gov, to, proto).is_none()
                && fallback_pools_authorized(app, gov, to, proto).is_none()
        },
        |at| g.try_admit(&app.cost, key, at, charged_at),
    );
    let blocked = match walked {
        Ok((grant, effective)) => return Ok((Some(grant), effective)),
        Err(blocked) => blocked,
    };
    {
        // The rejection NAMES WHICH BUCKET blocked (group + metric + window). The key ID
        // itself is never echoed; a group name is an operator-chosen, caller-meaningful
        // bucket label, not an internal credential handle. Server-side tracing records the
        // full detail either way.
        tracing::info!(key_id = %key.id, blocked = ?blocked, "governance: limit bucket blocked admission");
        let (status, kind, message, retry_after) = limit_refusal(proto, &blocked);
        let mut resp = ingress_error(proto, status, kind, &message);
        // Standard `Retry-After` for a rolling window so a well-behaved SDK backs off the
        // right amount ('total' never rolls: no header).
        if let Some(retry) = retry_after {
            if let Ok(hv) = axum::http::HeaderValue::from_str(&retry.to_string()) {
                resp.headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, hv);
            }
        }
        Err(Box::new(resp))
    }
}

/// THE BUDGET DOWNGRADE WALK every door admits through: `admit` the request on `pool`; a budget
/// block whose limit declared `on_exhaust: downgrade` re-admits it on `downgrade_to` instead of
/// refusing - the caller's expensive traffic gets CHEAPER, not blocked. The chain may cascade (the
/// downgrade pool's own budget may downgrade further); each hop's target must be one of the
/// deployment's `pool_count` configured pools (a name `configured` holds) that the key may `reach`
/// (its pool grant, and the grant of every fallback pool beyond it: a downgrade must never route a
/// key into a pool it may not use). A visited set ends a cycle at the revisit, bounded by the pool
/// count besides. The charge lands on
/// the EFFECTIVE pool's buckets, and the caller dispatches there - accounting follows the traffic.
///
/// `Ok((grant, effective))`: admitted on `effective` (`None` = on `pool` itself).
///
/// # Errors
///
/// The block the walk ended on, which names its bucket.
pub fn admit_downgrading<G>(
    key_id: &str,
    pool: &str,
    pool_count: usize,
    configured: impl Fn(&str) -> bool,
    reach: impl Fn(&str) -> bool,
    mut admit: impl FnMut(&str) -> Result<G, crate::governance::LimitBlocked>,
) -> Result<(G, Option<String>), crate::governance::LimitBlocked> {
    let mut effective: Option<String> = None;
    let mut visited: Vec<String> = Vec::new();
    loop {
        let attempt_pool = effective.as_deref().unwrap_or(pool);
        match admit(attempt_pool) {
            Ok(grant) => return Ok((grant, effective)),
            Err(crate::governance::LimitBlocked::Limit {
                downgrade_to: Some(to),
                group,
                ..
            }) if !visited.iter().any(|v| v == &to)
                // Defense-in-depth, likely unreachable in practice: `visited` is a DUPLICATE-FREE
                // subset of the configured pools (the revisit guard above forbids re-pushing an
                // already seen pool; every push target is also checked by `configured` below
                // before being pushed). NOTE this does NOT mean the start pool can never appear in `visited` — a
                // downgrade target can legally cycle back to the start pool (e.g. a<->b: hop 1
                // pushes b, hop 2's target a passes both checks and gets pushed too), so `visited`
                // is not capped at `pool_count - 1`. The real bound is `visited.len() <=
                // pool_count` (it can never exceed the pool count, being duplicate-free): at
                // equality `visited` IS the full pool set, so either the earlier
                // `!visited.iter().any(...)` clause already rejected `to` (if `to` is a pool), or
                // the `configured` clause below rejects it (if it isn't) — making `<` vs `<=`
                // behaviorally indistinguishable right here (see
                // `test_downgrade_cycle_terminates_via_the_revisit_guard`'s doc comment for the
                // one guard clause that IS distinguishable). Kept as an explicit bound rather than
                // removed: it's the backstop if the duplicate-free invariant is ever loosened.
                && visited.len() < pool_count
                && configured(&to)
                && reach(&to) =>
            {
                tracing::info!(key_id, from = attempt_pool, to = %to, group = %group,
                    "governance: budget exhausted; downgrading pool (on_exhaust: downgrade)");
                visited.push(to.clone());
                effective = Some(to);
            }
            Err(blocked) => return Err(blocked),
        }
    }
}

/// THE LIMIT REFUSAL a blocked admission is answered with: its status in `proto`, its kind word,
/// its message (naming the group, metric and window, never the key), and its Retry-After seconds
/// (a rolling window's; `total` never rolls). One spelling, read by every door that admits.
#[must_use]
pub fn limit_refusal(
    proto: &str,
    blocked: &crate::governance::LimitBlocked,
) -> (StatusCode, &'static str, String, Option<u64>) {
    use crate::governance::LimitBlocked;
    match blocked {
        LimitBlocked::Limit {
            group,
            // The per-tier token caps (`tokens_input`/…) surface as a rate limit exactly like
            // the aggregate `tokens` metric — a 429 naming the tier — NOT as an over-quota
            // block. Without this arm they would fall to the budget/quota arm below and return
            // the vendor quota status (Bedrock 400), silently mislabelling the block.
            metric:
                metric @ ("requests" | "tokens" | "tokens_input" | "tokens_output" | "tokens_cache_read"
                | "tokens_cache_write"),
            window,
            pool: limit_pool,
            retry_after,
            ..
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            crate::proxy::KIND_RATE_LIMIT,
            format!(
                "Rate limit exceeded (group '{group}': {metric} per {}{}). Please retry \
                     after the indicated time.",
                window.unwrap_or("total"),
                pool_scope_suffix(limit_pool),
            ),
            *retry_after,
        ),
        LimitBlocked::Limit {
            group,
            metric: "concurrent",
            ..
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            crate::proxy::KIND_RATE_LIMIT,
            format!(
                "Too many concurrent requests (group '{group}' is at its in-flight \
                     limit). Please retry shortly."
            ),
            None,
        ),
        LimitBlocked::Limit {
            group,
            metric: "budget",
            window,
            pool: limit_pool,
            retry_after,
            ..
        } => (
            // Native quota status differs by vendor (Bedrock's
            // ServiceQuotaExceededException is 400; every other vendor surfaces
            // over-quota as 429). The writer owns that mapping.
            crate::proto::decl_for(proto)
                .map(|d| d.quota_exceeded_status)
                .unwrap_or(StatusCode::TOO_MANY_REQUESTS),
            crate::proxy::KIND_INSUFFICIENT_QUOTA,
            format!(
                "You have exceeded your current quota (group '{group}' budget per {}{} \
                     exhausted). Please check your plan and billing details.",
                window.unwrap_or("total"),
                pool_scope_suffix(limit_pool),
            ),
            *retry_after,
        ),
        // FAIL-SAFE catch-all for any FUTURE metric not yet given an explicit arm above. It
        // maps to a generic 429 rate limit — never the vendor quota status — so a new metric
        // can never silently inherit `budget`'s Bedrock-400 semantics. Every metric that exists
        // today (`requests`/`tokens`/the four `tokens_*` tiers/`concurrent`/`budget`) is matched
        // explicitly above; this arm only exists to keep the string match exhaustive.
        LimitBlocked::Limit {
            group,
            metric,
            window,
            pool: limit_pool,
            retry_after,
            ..
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            crate::proxy::KIND_RATE_LIMIT,
            format!(
                "Rate limit exceeded (group '{group}': {metric} per {}{}). Please retry \
                     after the indicated time.",
                window.unwrap_or("total"),
                pool_scope_suffix(limit_pool),
            ),
            *retry_after,
        ),
        // A FROZEN group (`enabled: false`) is an administrative freeze, not a quota: the
        // vendor-plausible shape is a permission denial.
        LimitBlocked::Disabled(group) => (
            StatusCode::FORBIDDEN,
            crate::proxy::KIND_PERMISSION,
            format!(
                "Your API key does not currently have access to this resource (group \
                     '{group}' is disabled)."
            ),
            None,
        ),
        // FAIL-CLOSED: a key bound to a group this node's config does not know is not
        // admitted; the message names the missing bucket so the operator can fix it.
        LimitBlocked::MissingGroup(group) => (
            crate::proto::decl_for(proto)
                .map(|d| d.quota_exceeded_status)
                .unwrap_or(StatusCode::TOO_MANY_REQUESTS),
            crate::proxy::KIND_INSUFFICIENT_QUOTA,
            format!(
                "Your quota configuration is incomplete (group '{group}' is not \
                     configured). Please contact your administrator."
            ),
            None,
        ),
    }
}

/// Run the governance guards (pool ACL / unpriced-model / the atomic group-limit admission) for a
/// request that is about to be forwarded. Returns the protocol-native rejection response already
/// passed through `finish_rejected`. The statuses are deliberately vendor-faithful and never 402:
/// pool-not-allowed and a frozen group map to 403, an exhausted budget maps to the vendor's quota
/// status (Bedrock's quota shape is a 400-class error, see `admit_check`), and requests / tokens /
/// concurrent limits map to 429 (+ `Retry-After` for rolling windows). busbar never emits 402 here
/// a blanket 402 was a vendor-agnostic tell, since no real provider returns 402 for these
/// conditions. Routing through `finish_rejected` means a governance-rejected request still emits
/// `REQUESTS_TOTAL`, the `REQUEST_DURATION_SECONDS` histogram, and the request-log webhook.
/// `Ok((Some(grant), effective_pool))` = admitted + charged (see `admit_check`); the caller
/// threads the grant into the request's `UsageSink` so the in-flight holds release at stream end,
/// and — when `effective_pool` is `Some` — DISPATCHES through that pool instead of the requested
/// one (a budget `on_exhaust: downgrade` fired; the charge already landed on the effective pool's
/// buckets, so routing must follow the accounting).
// `pub` (was module-private): a mounted plane's engine reaches the stage-2 (destination) + stage-4
// (budget door) pair through this wrapper — the allowed plane→core edge. Its `gov`/return name the
// still-crate-private `GovCtx`/`AdmitGrant` carriers, so the same narrow `private_interfaces` allow
// the other stay-stages carry keeps them `pub(crate)`.
#[allow(private_interfaces)]
pub fn governance_guard(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    pool: &str,
    started: Instant,
    charged_at: u64,
) -> Result<(Option<crate::governance::AdmitGrant>, Option<String>), Box<Response>> {
    // The gauntlet's stage-2 (destination) then stage-4 (budget door) run in this fixed order — the
    // pre-admission checks MUST all fire before the door charges (nothing may reject an
    // already-charged request). A plane's engine reaches the pair through this public wrapper,
    // driving the same two halves as the plane-hook + shared-budget-door split the other stay-stage
    // callers use, so every caller shares one implementation and cannot drift.
    destination_guard(app, gov, proto, pool, started, charged_at)?;
    admission_door(app, gov, proto, pool, started, charged_at)
}

/// STAGE 2 (a mounted plane's pre-forward destination check) — the PRE-ADMISSION destination
/// verification: the requested pool ACL (`pool_authorized`), every reachable fallback pool's ACL
/// (`fallback_pools_authorized`), and the fail-closed unpriced-model gate. Every check that can
/// reject fires here, BEFORE the budget door, so no rejection can ever land after a charge. `Ok(())`
/// clears the request to admission; `Err(resp)` is the protocol-native rejection already routed
/// through `finish_rejected` (so it still emits REQUESTS_TOTAL / the duration histogram / the
/// request-log webhook). The raw client-supplied `pool` is mapped to the bounded metric label BEFORE
/// it reaches `finish` — passing it raw was an unbounded-cardinality DoS vector.
// `pub` (was module-private): a mounted plane's engine calls DOWN into this neutral pre-admission
// gauntlet stage — the allowed plane→core edge. Its `gov: &crate::governance::GovCtx` names the
// still-crate-private carrier, so the same narrow `private_interfaces` allow `finish_admitted`
// carries keeps `GovCtx` `pub(crate)`.
#[allow(private_interfaces)]
pub fn destination_guard(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    pool: &str,
    started: Instant,
    charged_at: u64,
) -> Result<(), Box<Response>> {
    let label = pool_label(app, pool);
    if let Some(resp) = pool_authorized(gov, pool, proto) {
        return Err(Box::new(finish_rejected(
            app, gov, proto, label, started, charged_at, resp,
        )));
    }
    // The initial-pool ACL passed, but the requested pool may be configured to fail over to a
    // FALLBACK pool on exhaustion (`OnExhausted::FallbackPool`). Re-enforce the key's `allowed_pools`
    // against every fallback pool reachable from here, so a key restricted to pool A can never be
    // served by a fallback pool B it is not allowed to use (the fallback dispatch in
    // `proxy::handle_fallback_pool` does not — and cannot — re-check the key; the ACL is enforced
    // at this ingress boundary). A denial is the SAME protocol-native 403 the initial check emits.
    if let Some(resp) = fallback_pools_authorized(app, gov, pool, proto) {
        return Err(Box::new(finish_rejected(
            app, gov, proto, label, started, charged_at, resp,
        )));
    }
    // ALL-OR-NOTHING pricing, fail-closed arm: when a rate card is PRESENT, every governed request
    // must resolve to a priced model. A configured pool / by-model lane is priced by construction
    // (`--validate`/boot enforce rate-card completeness over config.models), so only an ARBITRARY
    // passthrough model string can be unpriced - reject it with a clear error rather than serve
    // tokens that cannot be billed. Zero-cost when no rate card is configured (one bool), and a
    // single borrowed map probe otherwise.
    if gov.key.is_some()
        && app.cost.pricing_enabled()
        && {
            // NEUTRAL read seam: the model names no configured pool AND no by-model lane.
            let v = app.engine_tables_view();
            !v.pools().iter().any(|(n, _)| *n == pool) && v.model_index(pool).is_none()
        }
        && app.cost.model_unpriced(pool)
    {
        tracing::info!(model = %pool, "governance: no configured rate for model; rejecting (rate_card is authoritative and complete)");
        let resp = ingress_error(
            proto,
            StatusCode::BAD_REQUEST,
            crate::proxy::KIND_INVALID_REQUEST,
            &crate::door::VerifyRefusal::NoRate { name: pool.into() }.message(),
        );
        return Err(Box::new(finish_rejected(
            app, gov, proto, label, started, charged_at, resp,
        )));
    }
    Ok(())
}

/// STAGE 4 — THE single budget-admission door, SHARED gauntlet core (never a plane
/// hook). The atomic group-limit ADMISSION runs here, after stage 2: it CHARGES every chain bucket
/// on admit, so nothing may reject an already-charged request after it. On rejection nothing was
/// charged → `finish_rejected` (no refund). On admission the returned grant reports whether the
/// charge LANDED (`Some` = refund on non-2xx) and holds the `concurrent` in-flight gauges;
/// `effective_pool` is `Some` when a budget `on_exhaust: downgrade` re-pooled the admission.
// `pub` (was module-private): a mounted plane's engine calls DOWN into this single budget-admission
// door — the allowed plane→core edge. Same `GovCtx` privacy allow as
// `finish_admitted`/`destination_guard`.
#[allow(private_interfaces)]
pub fn admission_door(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    pool: &str,
    started: Instant,
    charged_at: u64,
) -> Result<(Option<crate::governance::AdmitGrant>, Option<String>), Box<Response>> {
    let label = pool_label(app, pool);
    match admit_check(app, gov, proto, pool, charged_at) {
        Err(resp) => Err(Box::new(finish_rejected(
            app, gov, proto, label, started, charged_at, *resp,
        ))),
        Ok(admitted) => Ok(admitted),
    }
}

/// Map a client-supplied model/name string to a BOUNDED `pool` metric label (metrics.rs).
/// Returns the string verbatim ONLY when it names a configured pool (`app.pools`) or a configured
/// by-model lane (`app.by_model`) — i.e. a value drawn from the finite, operator-controlled label
/// space. For anything else (an unknown model, a governance-rejected request whose model was never
/// resolved, a provider-mismatched ad-hoc model) it returns the fixed sentinel `"unresolved"`.
///
/// Without this, every `finish`/webhook call on a 404 / governance-rejection path stamped the raw
/// attacker-controlled model as the `pool` label, letting a single valid credential mint an
/// unbounded number of Prometheus time series (one per distinct model string) — a low-effort
/// memory-exhaustion DoS that also bloats every `/metrics` scrape and leaks the attacker-chosen
/// string into the request-log webhook. The label space is now bounded BY CONSTRUCTION:
/// |configured pools| + |configured by-model lanes| + 1.
pub fn pool_label<'a>(app: &Arc<App>, model: &'a str) -> &'a str {
    let v = app.engine_tables_view();
    if v.pools().iter().any(|(n, _)| *n == model) || v.model_index(model).is_some() {
        model
    } else {
        crate::proxy::POOL_LABEL_UNRESOLVED
    }
}

/// The ingress boundary — emit per-request observability metrics (one client request =
/// one call here, unlike the re-entrant forward_with_pool) and, on a NON-2xx outcome, REFUND the
/// flat per-request fee charged at admission. `finish` does NOT charge: the flat fee is charged at
/// admission by `budget_check` → `try_charge_request_within_budget`. Outcome is derived from the
/// final status; duration is wall-clock.
/// Post-ADMISSION finish: the request passed `governance_guard`, so the flat per-request fee was
/// already charged ATOMICALLY at admission (in `budget_check`). This emits metrics + the
/// request-log webhook and, on a NON-2xx outcome (router 503, upstream 4xx/5xx, post-admit 404),
/// REFUNDS that flat fee — preserving the "bill 2xx only" flat-fee policy now that the hard-cap
/// charge bills every admitted request up front. Token fees are charged post-response only on success
/// (via `UsageSink`), so this keeps both fee policies "successful requests only".
///
/// Test-only now: every production admission threads its charge through [`finish_admitted`] (a
/// store-error fail-open admit must not refund); this always-refunding form survives only for the
/// tests that always charge, and refunds the `charge` they admitted with.
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::too_many_arguments)]
pub fn finish(
    app: &Arc<App>,
    _gov: &crate::governance::GovCtx,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    _charged_at: u64,
    resp: Response,
    charge: &crate::governance::FeeCharge,
) -> Response {
    finish_inner(app, ingress_protocol, pool, started, resp, Some(charge))
}

/// Post-admission finish whose non-2xx refund is CONDITIONAL on whether the flat fee actually landed
/// at admission (`charged`: the admission's own [`FeeCharge`](crate::governance::FeeCharge), from
/// its grant). Admitting a request WITHOUT charging (store-error fail-open, or governance off) and
/// then refunding on a non-2xx would decrement OTHER requests' spend/count in the same window — so
/// those requests finish with `charged = None`.
// `pub` (was module-private): the charged-admission finish/audit terminal a mounted plane's engine's
// native drive path ends on — surfaced through `crate::engine_facade` (Phase-0 visibility lift; pure
// visibility). Its `gov: &crate::governance::GovCtx` arg names a still-crate-private carrier, so a
// narrow `#[allow(private_interfaces)]` keeps `GovCtx` `pub(crate)` (reversible in Phase 6).
#[allow(private_interfaces)]
#[allow(clippy::too_many_arguments)]
pub fn finish_admitted(
    app: &Arc<App>,
    _gov: &crate::governance::GovCtx,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    _charged_at: u64,
    resp: Response,
    charged: Option<&crate::governance::FeeCharge>,
) -> Response {
    finish_inner(app, ingress_protocol, pool, started, resp, charged)
}

/// NOT-CHARGED finish: the request was turned away BEFORE the admission charge ever ran — either a
/// governance guard rejected it (pool / rate / over-budget / store-error-deny) OR it failed
/// pre-routing (malformed body, missing/unresolved model, unsupported path/action) before reaching
/// `governance_guard`. In every case the flat fee was NEVER charged, so this emits metrics + the
/// webhook with NO refund: a pre-charge path holds no admission charge, and a refund on it would
/// decrement the spend of OTHER, legitimately-charged requests in the same window, eroding the
/// budget cap. So every pre-charge exit MUST use this.
// `pub` (was module-private): the pre-charge turn-away finish terminal, surfaced through
// `crate::engine_facade` (Phase-0). Same `GovCtx` leak allow as `finish_admitted`.
#[allow(private_interfaces)]
pub fn finish_rejected(
    app: &Arc<App>,
    _gov: &crate::governance::GovCtx,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    _charged_at: u64,
    resp: Response,
) -> Response {
    finish_inner(app, ingress_protocol, pool, started, resp, None)
}

/// The one finish. It takes no key and no instant: a refund reads only the admission's own
/// [`FeeCharge`](crate::governance::FeeCharge), never a cell resolved again from the key and
/// `charged_at` (the three entries above still accept both for their callers).
fn finish_inner(
    app: &Arc<App>,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    resp: Response,
    refund_on_non_2xx: Option<&crate::governance::FeeCharge>,
) -> Response {
    // FINISH stage: metrics record + request-log gate + non-2xx refund check (zero cost unprofiled).
    let _fin = crate::profile::start(crate::profile::Stage::Finish);
    // Classified by the ONE function every plane's finish classifies with
    // (`telemetry::outcome_of`), so a 503 means the same thing on every `sum by (outcome)`.
    let outcome = crate::telemetry::outcome_of(resp.status().as_u16());
    // Per-request emits via the TELEMETRY BANK (telemetry.rs): a plain add into THIS thread's
    // pre-registered cells — no shared-atomic contention, no per-request `Label`/`Key` allocation,
    // no registry probe. The scrape-time aggregator folds the cells into the recorder, so the
    // rendered series/values are identical to the macro emission. Unregistered label values (e.g.
    // a bare test `App`) fall back to the cached-handle helpers in `metrics.rs` inside the helper.
    // This plane labels its own requests from in here rather than at the plane ingress
    // boundary (`plane::observe`), and that is a consequence of the spine's rule rather than a
    // carve-out: this plane speaks several dialects, so `ingress_protocol` is a fact only its reader
    // knows (`Plane::sole_wire_format` is `None` for it). This is the v1.5.4 request path: it emits
    // `busbar_requests_total` / `busbar_request_duration_seconds` with the exact 1.5.4 label set
    // `{ingress_protocol, pool, outcome}` and NO `plane` label, so a deployment with only this plane's
    // `/metrics` scrape is byte-identical to 1.5.4. Other mounted planes emit their own
    // `busbar_plane_*` families from `plane::observe` instead — same helper, same `outcome`
    // vocabulary, one family apart.
    let elapsed = started.elapsed();
    crate::telemetry::request_finished(
        app,
        crate::plane::fallback_key(),
        ingress_protocol,
        pool,
        outcome,
        elapsed.as_secs_f64(),
    );

    // Best-effort request log. THE COMPUTE GATE: the `logs` records are produced only if some
    // configured `export:` instance's projection subscribes to that stream — the union is resolved
    // once per config apply (`ExportCfg::projection_union`) and read here as a single mask test, the
    // same "the read runs ONLY when declared, never call-then-discard" discipline
    // `requested_signals` applies to hook signals. Nobody subscribed ⇒ nothing is generated. Each
    // sink then receives a payload built to ITS OWN projection (`crate::export::deliver_request_log`).
    if app
        .export_projections
        .wants_stream(busbar_contract::abi::export::ExportStream::Logs)
    {
        crate::export::deliver_request_log(&crate::export::RequestLogFacts {
            ts: busbar_kernel::store::now(),
            ingress_protocol,
            pool,
            outcome,
            latency_ms: elapsed.as_millis() as u64,
        });
    }

    let status = resp.status().as_u16();

    // The flat per-request fee was charged ATOMICALLY at admission. REFUND it for a request
    // that produced no usable upstream result (non-2xx: router 503 exhaustion, upstream 5xx, 4xx
    // upstream errors, post-admission 404) so a key is never billed the flat fee for a failure
    // outside its control — preserving the prior "bill 2xx only" policy. (Token fees are likewise
    // only charged on successful streams via UsageSink, so both fee policies stay consistent.) The
    // refund returns the fee from exactly the cells the admission's charge reached (its
    // `FeeCharge`), so a window-straddling request refunds where it charged (#29, M-1) and a charge
    // whose window has since rolled is taken back from that window, never the newer one.
    // `refund_on_non_2xx` is `None` for governance-rejection finishes (those were never charged —
    // nothing to refund).
    let is_success = matches!(status, 200..=299);
    if let (Some(charge), false) = (refund_on_non_2xx, is_success) {
        if let Some(g) = &app.governance {
            g.refund_charge(charge);
        }
    }
    resp
}

/// Render a router-side error as the ingress protocol's NATIVE error envelope (total
/// indistinguishability). A client on a vendor's official SDK gets the typed
/// exception it expects (JSON envelope) instead of a plain-text body it cannot decode. `proto`
/// names the ingress protocol of the route that failed; `status` is the HTTP status; `kind` is a
/// protocol-appropriate error category; `message` is the human-readable detail.
///
/// Thin delegation to the CANONICAL `crate::proxy::ingress_error` (the single
/// source of truth for native error shaping + per-protocol headers — Bedrock
/// `x-amzn-RequestId`/`x-amzn-errortype` via the `ProtocolWriter::attach_error_response_headers` vtable method (BedrockWriter delegates to its private helper), the generic
/// fallback envelope, etc.). Keeping ingress on this one function rather than a private copy means
/// route/forward error shaping cannot drift. The route call sites (and the in-module tests) keep
/// the short `proto`/`message` parameter names; the canonical fn names them `ingress`/`msg`.
pub fn ingress_error(proto: &str, status: StatusCode, kind: &str, message: &str) -> Response {
    crate::proxy::ingress_error(proto, status, kind, message)
}

// THE PLANE-NEUTRAL JSON-RPC ENVELOPE READER, shared by every JSON-RPC-fronted mounted plane. It
// lives under `ingress/` because that is the shared owner `structure-lint`'s plane ledger already
// names for the ingress concern: "one plane-neutral admission in ingress/, with the plane supplying
// its wire reader". This is the envelope half of that.
pub mod jsonrpc;

#[cfg(test)]
#[path = "tests/terminal_tests.rs"]
mod terminal_tests;

/// THE NEUTRAL INBOUND BYTE-DUPLEX TRANSPORT — the byte half of a single full-duplex channel.
/// Absorbed from busbar-substrate (W4.b P2).
pub mod byte_duplex;
/// THE NEUTRAL FULL-DUPLEX WS INGRESS ACCEPTOR, armed under `runtime`. Absorbed from busbar-substrate.
#[cfg(feature = "runtime")]
pub mod duplex_ws;

/// THE ONE JSON-RPC INGRESS SEQUENCE. Read its header: it carries the thirteen-step measurement
/// that says which four steps are a protocol's and which nine are core's.
pub mod protocol;

// The error-shaping boundary: the ONE place a resolved ingress becomes a native error envelope.
pub mod native;

/// The protocol catch-all.
pub mod dispatch;
// `protocol_dispatch` is the axum catch-all fallback the core router mounts and nothing outside core
// names, so it stays crate-private — keeping the confidential `CallerToken` it takes off the public
// seam. (The universal resolved-op ingress it used to hold — `operation_resolved`/`operation_ingress`
// — RELOCATED into the plane that owns it.)
pub(crate) use dispatch::protocol_dispatch;

/// Build the human-readable message for a model/pool-miss 404. `model_not_found_message` is a
/// dialect's PRE-SHAPED body in its own native vocabulary — built by the arrival that owns the request
/// (a path-model dialect whose real API uses a different not-found string than the canonical default
/// copy), and used VERBATIM when present. `None` for every caller that shares the canonical default
/// copy, so this fn names no dialect: core emits the neutral copy and a dialect that wants otherwise
/// supplies its own shaped body.
// `pub` (was module-private): a mounted plane's engine shapes its model-miss 404 body through this
// neutral helper — the allowed plane→core edge (names only `&str`).
// RELOCATED (1.6.0 KEYSTONE) to `busbar_kernel::ingress::not_found_message` — a pure `&str`→`String`
// shaper with no `App`/dialect — so the plane names it there; re-exported here byte-identically so
// every core `crate::ingress::not_found_message` call site resolves unchanged.
#[must_use]
pub fn not_found_message(model: &str, model_not_found_message: Option<&str>) -> String {
    match model_not_found_message {
        Some(shaped) => shaped.to_string(),
        None => format!("The model '{model}' does not exist or you do not have access to it."),
    }
}

/// Minimal percent-decoding for a single path segment (no external dependency). Decodes `%XX`
/// escapes as UTF-8; on any malformed escape it leaves the bytes as-is.
///
/// No longer on the request path: axum percent-decodes `Path` params before the handler runs, so
/// a path-model dialect's arrival handler uses the already-decoded segment directly (decoding twice
/// corrupts ids whose first decode yields a literal `%XX`). Retained as a `#[cfg(test)]` helper
/// documenting the decode semantics and guarding against accidental reintroduction of a
/// double-decode.
#[cfg(any(test, feature = "test-support"))]
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

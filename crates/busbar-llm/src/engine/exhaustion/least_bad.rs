// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LEAST-BAD mode: the ONE documented breaker bypass — route to the soonest-cooldown member even
//! though it is Open, as a last resort, owning no probe.

use super::{dispatch_degraded, handle_status_503};
use crate::engine::*;

/// LeastBad mode: actually route to the soonest-cooldown member even though it is Open
/// ("least-bad last resort"). Bypasses the breaker's usability check and acquires the
/// member's concurrency permit directly, then makes a single attempt (no failover from a
/// last-resort path). Logs loudly that this is a degraded route. Falls back to Status503 if
/// there is no candidate, the permit is unavailable, or the upstream is unreachable.
#[allow(clippy::too_many_arguments)] // plumbing: each arg is an independent request input
pub(crate) async fn handle_least_bad(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    cands: &[WeightedLane],
    now: u64,
    body: &Bytes,
    caller_token: Option<&str>,
    request_ctx: &RequestCtx,
    pool: &str,
    ingress_protocol: &str,
    op: busbar_substrate::handlers::Op,
    req_content_type: &str,
    mut usage_sink: Option<UsageSink>,
) -> Response {
    // Rank admissible members by soonest cooldown (the "least bad" order), then dispatch to the FIRST
    // that ALSO has a free concurrency permit. The soonest-cooldown member may itself
    // be AT-CAPACITY, and `least_bad` exists precisely to serve a degraded response when everything is
    // tripped — refusing with a hard 503 because the single best member is momentarily busy, while a
    // slightly-worse sibling has a free slot, defeats its purpose. The prior code did one `try_acquire`
    // on the single soonest member and 503'd on failure, so a saturated soonest member masked a serving
    // sibling. Admissibility (dead/budget) is filtered here too, so a dead lane's spurious cooldown-0
    // never sorts first. Sort is by the SAME `cooldown_remaining_in(pool, …)` the old single-pick used.
    //
    // Perf: this is an O(n log n) sort + per-candidate lock-guarded cooldown lookup, but least_bad is
    // an EXHAUSTION-PATH-ONLY degraded route (every member tripped/at-capacity) — not the steady-state
    // hot path — and a single-pass min would still need the same per-candidate cooldown lookups to
    // break ties, so the sort is left as-is for legibility on this cold path.
    let mut ranked: Vec<usize> = cands
        .iter()
        .map(|wl| wl.idx)
        .filter(|&idx| host.lane_store().lane_admissible(idx))
        .collect();
    ranked.sort_by_key(|&idx| host.lane_store().cooldown_remaining_in(pool, idx, now));

    // Bypass breaker usability for the last-resort path; grab the first free concurrency permit in
    // least-bad order. An at-capacity candidate (no permit) is SKIPPED to the next, not a 503.
    let mut dispatch = None;
    for idx in ranked {
        if let Some(permit) = host.lane_store().try_acquire(idx) {
            dispatch = Some((idx, permit));
            break;
        }
    }
    let Some((soonest_idx, permit)) = dispatch else {
        // No admissible candidate at all, or EVERY admissible candidate is at-capacity — no degraded
        // dispatch is possible, so shed with 503 (+ Retry-After).
        return handle_status_503(host, cands, now, pool, ingress_protocol);
    };

    // least-bad is a DESIGNED degraded mode, entered per-request whenever the pool is exhausted, so a
    // per-request `warn!` spams under sustained load for expected behavior. Log at `debug!`; the
    // exhaustion signal proper is the 503 shed path + breaker telemetry.
    tracing::debug!(
        pool = %pool,
        lane = %EngineTables::new(rt).lanes()[soonest_idx].model,
        cooldown_remaining_s = host.lane_store().cooldown_remaining_in(pool, soonest_idx, now),
        "least-bad mode: routing to a degraded member (pool exhausted)"
    );

    // The least-bad member was ranked via this pool's cell (`cooldown_remaining_in(pool, …)`), so
    // its breaker outcome is recorded against the POOL cell. least_bad BYPASSES the breaker: it
    // dispatches to an Open member via `try_acquire` and wins NO probe, so it OWNS NO PROBE to guard
    // — `None` makes the attempt build no guard at all, so a dropped least-bad future can NEVER
    // release/revert a probe. Passing the cell's CURRENT epoch instead would be UNSAFE: if the cell is
    // HalfOpen because a concurrent PEER legitimately won the probe, that epoch is the PEER's live
    // epoch, and an owner-checked release keyed on it would revert the peer's in-flight probe.
    match dispatch_degraded(
        host,
        rt,
        soonest_idx,
        permit,
        None,
        pool,
        cands,
        body,
        caller_token,
        request_ctx.remaining(now),
        ingress_protocol,
        op,
        req_content_type,
        &mut usage_sink,
        request_ctx.forwarded_client_headers.as_slice(),
    )
    .await
    {
        Ok(resp) => resp,
        Err(()) => handle_status_503(host, cands, now, pool, ingress_protocol),
    }
}

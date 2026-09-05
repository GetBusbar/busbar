// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! QUEUE mode: wait a BOUNDED time for a concurrency permit to free on an at-capacity member,
//! dispatch on the freed lane, else fall through to a 503 + Retry-After.

use super::{dispatch_degraded, handle_status_503};
use crate::engine::*;

/// Slack ε (milliseconds) for the `handle_queue` deadline-overrun `debug_assert`. Like
/// `select::BUDGET_ASSERT_EPSILON` this is a dev/CI regression tripwire, not a runtime bound: the
/// queue wait is a single `tokio::select!` against `sleep_until(deadline)`, so a healthy resume lands
/// within a few ms of the deadline, but scheduler jitter / a slow CI box can add a small overshoot. A
/// 250ms tolerance absorbs that without ever masking a real "blocked past the whole budget" regression
/// (which overshoots by seconds). Named + documented rather than an inline literal so a future tune for
/// CI-machine speed does not have to reverse-engineer where `250` came from.
const QUEUE_WAIT_ASSERT_EPSILON_MS: u64 = 250;

/// Queue mode: when a pool is exhausted with `on_exhausted: { queue: { max_ms } }`, wait a BOUNDED
/// time for a concurrency permit to free on an at-capacity member, dispatch on the freed lane, else
/// fall through to a 503 + Retry-After. Lives HERE in on_exhausted dispatch, never inside `pick_among`
/// — selection stays non-blocking, so the "no unbounded await in the pick path" rule holds
/// structurally.
///
/// Wait mechanism: the waiter acquires DIRECTLY on the candidate lanes' OWN FIFO semaphores (a
/// `select_all` over `sem.acquire_owned()`), RACED against `sleep_until(deadline)`. The semaphore
/// STORES a released permit (no lost wakeup — a permit freed in the small window between two polls is
/// not dropped) and hands one permit to one waiter (no thundering herd, FIFO fairness) — this is why
/// this replaced an earlier per-pool `Notify`.
///
/// Breaker composition: winning a permit proves capacity, NOT breaker admission. The won lane's
/// breaker is re-checked via `try_admit_breaker` (it may have TRIPPED Open while we were queued);
/// only on success do we dispatch. A lane whose breaker opened while queued can no longer be served by
/// waiting — it is dropped from the candidate set (same rationale as the entry pre-check) and we keep
/// waiting on the rest, never dispatching onto an Open lane and never blocking past the deadline.
#[allow(clippy::too_many_arguments)] // plumbing: each arg is an independent request input
pub(crate) async fn handle_queue(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    cands: &[WeightedLane],
    max_ms: u64,
    body: &Bytes,
    caller_token: Option<&str>,
    request_ctx: &RequestCtx,
    pool: &str,
    ingress_protocol: &str,
    op: busbar_substrate::handlers::Op,
    req_content_type: &str,
    mut usage_sink: Option<UsageSink>,
) -> Response {
    use busbar_substrate::store::Unavailable;

    // Pre-check: queue only helps if SOME excluded candidate is `AtCapacity` — a held permit can
    // drop. If every exclusion is Dead / BudgetExhausted / BreakerOpen / ProbeInFlight, nothing will
    // free a slot, so waiting is pointless (waiting 250ms for a pool that's DOWN, not busy). Skip the
    // wait and shed now. Dedup by lane (the sticky fast path may record a lane the main loop also did).
    let mut at_cap_lanes: Vec<usize> = Vec::new();
    for (lane, reason) in &request_ctx.excluded_reasons {
        if matches!(reason, Unavailable::AtCapacity { .. }) && !at_cap_lanes.contains(lane) {
            at_cap_lanes.push(*lane);
        }
    }
    if at_cap_lanes.is_empty() {
        return handle_status_503(host, cands, now(), pool, ingress_protocol);
    }

    // Ms-precision deadline: bound the wait by `min(max_ms, failover_budget_remaining)` in MS so a
    // sub-second `max_ms` is representable and a near-second-boundary budget does not collapse to 0.
    // Captured ONCE as an absolute instant so it survives the re-wait loop (a won-but-breaker-Open
    // permit re-enters the wait against the SAME deadline — it can never extend the budget).
    let wait_ms = max_ms.min(request_ctx.remaining_ms());
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(wait_ms);

    // `busbar_pool_queued` depth accounting — RAII, decremented on EVERY exit (dispatch, shed, or a
    // dropped future on client disconnect), so the gauge can never leak a phantom waiter.
    let _depth = EngineTables::new(rt).queued_depth().park(pool);

    loop {
        // Build one `acquire_owned()` future per still-viable AtCapacity candidate. An unbounded lane
        // has no semaphore (never AtCapacity), so `lane_semaphore` returns `None` and it is skipped —
        // it would never be in `at_cap_lanes` anyway.
        //
        // Perf: the full `sems` + `select_all` set is rebuilt on each loop re-entry rather than
        // incrementally patched. This is deliberate and cheaply bounded: re-entry happens ONLY when a
        // won permit's lane turned out to have tripped its breaker while queued (an off-common-path race
        // window, and the tripped lane is `retain`-dropped so `at_cap_lanes` STRICTLY shrinks — at most
        // `at_cap_lanes.len()` re-entries total for the whole wait). A freed permit that simply gets
        // re-acquired does not re-enter (it dispatches). Given the small, monotonically shrinking
        // candidate set, an incremental future-set patch would add complexity for no measurable win.
        let sems: Vec<(usize, std::sync::Arc<tokio::sync::Semaphore>)> = at_cap_lanes
            .iter()
            .filter_map(|&idx| host.lane_store().lane_semaphore(idx).map(|s| (idx, s)))
            .collect();
        if sems.is_empty() {
            return handle_status_503(host, cands, now(), pool, ingress_protocol);
        }
        let acquires = sems
            .into_iter()
            .map(|(idx, s)| Box::pin(async move { (idx, s.acquire_owned().await) }))
            .collect::<Vec<_>>();

        // Race the freed-permit acquisitions against the deadline. `biased` + deadline-first: if the
        // deadline has elapsed we shed even when a permit is simultaneously ready — NEVER block past
        // the budget.
        let won = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => None,
            (res, _idx, _rest) = futures::future::select_all(acquires) => Some(res),
        };

        let (lane, permit_res) = match won {
            Some(v) => v,
            // Deadline: shed with an honest Retry-After (`retry_after_secs` reads the same capacity /
            // cooldown axes `recovery_hint_ms` does). The ONE blocking await in the whole
            // dispatch path must never resume past its bounded `deadline` — assert it (dev/CI only).
            None => {
                debug_assert!(
                    tokio::time::Instant::now()
                        <= deadline
                            + std::time::Duration::from_millis(QUEUE_WAIT_ASSERT_EPSILON_MS),
                    "queue wait overran its bounded deadline — the on_exhausted queue blocked past \
                     min(max_ms, failover budget)"
                );
                return handle_status_503(host, cands, now(), pool, ingress_protocol);
            }
        };
        let owned = match permit_res {
            Ok(p) => p,
            // The semaphore was closed (shutdown) — no permit is coming; shed.
            Err(_) => return handle_status_503(host, cands, now(), pool, ingress_protocol),
        };
        let permit = busbar_substrate::store::Permit::Bounded(owned);

        // We hold capacity but have NOT passed the breaker. Run ONLY the breaker admission step on the
        // won lane — the dispatched request owns the probe it wins (the attempt releases it
        // owner-checked, exactly like the fallback dispatch path).
        match host.lane_store().try_admit_breaker(pool, lane, now()) {
            Ok(probe_epoch) => {
                // The queued waiter selected this member against THIS pool's cell (it was an
                // AtCapacity exclusion recorded by `pick_among` on the pool cell), so its breaker
                // outcome is recorded against the pool cell — mirrors the fallback/least_bad dispatch.
                // The probe `try_admit_breaker` won (or `None` for a Closed-ready no-op admit) is
                // released OWNER-CHECKED by the attempt's guard when `Some`; on `None` this dispatch
                // owns no probe and no guard is built.
                return match dispatch_degraded(
                    host,
                    rt,
                    lane,
                    permit,
                    probe_epoch,
                    pool,
                    cands,
                    body,
                    caller_token,
                    request_ctx.remaining(now()),
                    ingress_protocol,
                    op,
                    req_content_type,
                    &mut usage_sink,
                    request_ctx.forwarded_client_headers.as_slice(),
                )
                .await
                {
                    Ok(resp) => resp,
                    Err(()) => handle_status_503(host, cands, now(), pool, ingress_protocol),
                };
            }
            Err(reason) => {
                // The lane's breaker tripped Open (or it went dead / lost the probe race) while we were
                // queued. The disposition is correct (drop this lane, keep waiting or shed), but the
                // reason is a real diagnostic for an operator debugging a flapping queue-mode lane — log
                // it before dropping the lane rather than swallowing it.
                tracing::debug!(
                    pool = %pool,
                    lane = %EngineTables::new(rt).lanes()[lane].model,
                    reason = reason.variant_name(),
                    "on_exhausted queue: won a freed permit but the lane's breaker denied dispatch; \
                     dropping it from the wait set"
                );
                // RELEASE the permit (never hold a slot on a lane we won't dispatch to) and
                // drop this lane from the candidate set. Waiting cannot make an Open lane serveable
                // (same rationale as the entry pre-check); dropping it also prevents a tight
                // re-acquire spin on the permit we just released. Keep waiting on the remaining
                // candidates; if none remain, shed.
                drop(permit);
                at_cap_lanes.retain(|&l| l != lane);
                if at_cap_lanes.is_empty() {
                    return handle_status_503(host, cands, now(), pool, ingress_protocol);
                }
                continue;
            }
        }
    }
}

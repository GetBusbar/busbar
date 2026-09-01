//! ON_EXHAUSTED DISPOSITION — what the model plane does AFTER the one selection loop finds nowhere
//! to send a request. This file is NOT a selection loop and, since the one-loop unification (owner
//! ruling R-I), nothing here selects: `handle_fallback_pool` re-enters `pick_among` — which is the
//! model plane's [`busbar_core::failover::walk_with`] call site — for the spillover pool, `handle_queue`
//! waits for a permit and then re-asks the SAME `try_admit_breaker` every plane asks, and
//! `handle_least_bad` is the ONE documented breaker bypass in the tree (a last-resort degraded route
//! that owns no probe and says so). The candidate ordering, the pin check, the repeat-safety rule
//! and the admission all live in core, identically for llm, mcp and a2a.

use super::*;

use busbar_core::diagnostics::{
    diag_debug, ATTEMPT_TIMEOUT_DEGRADED, FALLBACK_RESTRICT_NO_ELIGIBLE_LANE,
};
// See `engine::mod`'s identical import for why this is a bare, unqualified import rather than a
// `busbar_core::observability::HOTPATH_LEVEL` path spelled out at the instrument site: `level = <path>`
// rejects a leading `crate` keyword segment.
use busbar_core::observability::HOTPATH_LEVEL;

/// Saturation Retry-After floor (whole seconds) for a 503 shed whose ONLY exhaustion cause is
/// at-capacity members (no genuine breaker cooldown). A busy concurrency slot typically frees on the
/// order of one in-flight request — there is no fixed breaker window to quote — but advertising the
/// bare 1s floor reads to a rate-aware client as "retry immediately", which just re-collides with the
/// saturation. A small non-trivial floor asks the client to back off briefly instead. An
/// at-capacity 503 is the COMMON shed shape, so this must not always be 1.
// DERIVED from the neutral store-side floor `store::AT_CAPACITY_RECOVERY_FLOOR_MS` (2000ms) so
// there is exactly one owner of the 2s value and the store never has to depend UP on `proxy`. This
// path floors the whole-second `Retry-After` at that same value rather than a separate — and
// regressing — literal.
pub(crate) const AT_CAPACITY_RETRY_AFTER_SECS: u64 =
    busbar_core::store::AT_CAPACITY_RECOVERY_FLOOR_MS / 1000;

/// Slack ε (milliseconds) for the `handle_queue` deadline-overrun `debug_assert`. Like
/// `select::BUDGET_ASSERT_EPSILON` this is a dev/CI regression tripwire, not a runtime bound: the
/// queue wait is a single `tokio::select!` against `sleep_until(deadline)`, so a healthy resume lands
/// within a few ms of the deadline, but scheduler jitter / a slow CI box can add a small overshoot. A
/// 250ms tolerance absorbs that without ever masking a real "blocked past the whole budget" regression
/// (which overshoots by seconds). Named + documented rather than an inline literal so a future tune for
/// CI-machine speed does not have to reverse-engineer where `250` came from.
const QUEUE_WAIT_ASSERT_EPSILON_MS: u64 = 250;

/// Compute the `Retry-After` (whole seconds) for a 503 shed, reflecting the ACTUAL backpressure axis.
///
/// Exhaustion has two distinct causes that want different backoff, and the pre-fix code conflated
/// them: it took the MINIMUM cooldown across admissible members, but an at-capacity-but-Closed member
/// reports cooldown 0 — so under saturation (now the common 503 shape) Retry-After always collapsed to
/// 1, badly under-serving backoff when siblings were in a long cooldown. Instead:
///   * If any admissible member has a GENUINE breaker cooldown (> 0), advertise the SOONEST such
///     cooldown — the client should retry when a benched lane is due to re-probe. An at-capacity
///     member's spurious 0 is ignored here, so a long-cooldown sibling is no longer masked by it.
///   * Else (no genuine cooldown) advertise the [`AT_CAPACITY_RETRY_AFTER_SECS`] floor. This covers
///     the SATURATION case (some candidate at-capacity, bounded lane, no free permit) AND, per the
///     next bullet, the empty/unknown-candidate case — both want the honest floor, never a bare 1.
///   * Else (no cooldown, nothing at-capacity — e.g. an EMPTY/unknown candidate set, reachable via a
///     fallback loop A→B→A or an unconfigured `fallback_pool` target, both of which call
///     `handle_status_503` with `&[]`) advertise the same [`AT_CAPACITY_RETRY_AFTER_SECS`] floor. An
///     empty/unknown candidate set is exactly where we know LEAST about when a slot frees, so it must
///     get the honest ≥2s floor — never the deceptive bare `1` (which reads as "retry immediately"),
///     the very signal the "never 1" rule was introduced to eliminate.
///
/// Always floored at 1 (a 0 Retry-After is meaningless).
fn retry_after_secs(app: &Arc<App>, cands: &[WeightedLane], now: u64, pool: &str) -> u64 {
    let soonest_genuine_cooldown = cands
        .iter()
        // Deadness lives outside the cell FSM (a dead/budget-exhausted lane reports cooldown 0), so
        // filter to admissible members exactly as the old `find_soonest_cooldown` did.
        .filter(|wl| app.store.lane_admissible(wl.idx))
        .map(|wl| app.store.cooldown_remaining_in(pool, wl.idx, now))
        .filter(|&r| r > 0)
        .min();
    match soonest_genuine_cooldown {
        Some(secs) => secs,
        // Both the at-capacity case AND the empty/unknown-candidate case get the ≥2s floor: never the
        // deceptive bare `1`. See the doc comment's third bullet.
        None => AT_CAPACITY_RETRY_AFTER_SECS,
    }
    .max(1)
}

/// Handle pool exhaustion based on configured mode for a specific pool.
#[allow(clippy::too_many_arguments)] // plumbing: each arg is an independent request input
pub(crate) async fn handle_exhaustion_for_pool(
    app: Arc<App>,
    cands: &[WeightedLane],
    now: u64,
    pool_name: &str,
    body: Bytes,
    caller_token: Option<&str>,
    request_ctx: &mut RequestCtx,
    ingress_protocol: &str,
    op: busbar_core::handlers::Op,
    req_content_type: &str,
    usage_sink: Option<UsageSink>,
) -> Response {
    // Cycle guard: mark the ORIGINATING pool visited here, BEFORE the mode lookup —
    // this is the single point every pool's exhaustion handling flows through. The loop guard in
    // `handle_fallback_pool` only checks/marks the FALLBACK pool name, so an A->B->A chain was not
    // caught on the second hop: when A exhausted it jumped straight to `handle_fallback_pool(B)`
    // (marking only B), and when B then fell back to A, the guard saw A as unvisited and recursed
    // into A's members again before terminating. Marking A here means a later hop back to A is
    // recognized as a cycle and terminates via the guard. Idempotent (set insert); harmless on the
    // non-cyclic single-hop case where A is never revisited.
    request_ctx.mark_pool_visited(pool_name);

    // Look up pool-specific on_exhausted config, default to Status503 for unknown pools.
    let mode = app
        .engine_tables()
        .on_exhausted_cfgs()
        .get(pool_name)
        .cloned()
        .unwrap_or(OnExhausted::Status503);

    let resp = match mode {
        OnExhausted::Status503 => handle_status_503(&app, cands, now, pool_name, ingress_protocol),
        OnExhausted::FallbackPool(ref fallback_pool) => {
            handle_fallback_pool(
                app.clone(),
                body,
                caller_token,
                fallback_pool,
                request_ctx,
                ingress_protocol,
                op,
                req_content_type,
                usage_sink,
            )
            .await
        }
        OnExhausted::LeastBad => {
            handle_least_bad(
                &app,
                cands,
                now,
                &body,
                caller_token,
                request_ctx,
                pool_name,
                ingress_protocol,
                op,
                req_content_type,
                usage_sink,
            )
            .await
        }
        OnExhausted::Queue { max_ms } => {
            handle_queue(
                &app,
                cands,
                max_ms,
                &body,
                caller_token,
                request_ctx,
                pool_name,
                ingress_protocol,
                op,
                req_content_type,
                usage_sink,
            )
            .await
        }
    };

    // Budget contract, asserted at the on_exhausted DISPOSITION (the one convergence point every
    // policy's shed/spill/queue outcome flows through). Under saturation every disposition here is
    // bounded — reject sheds now, queue waits ≤ max_ms, fallback spills — so the wall clock from
    // ingress must be within the failover budget + ε. A regression that blocks past the budget (a
    // park under saturation) trips this in dev/CI. No-op in release.
    request_ctx.debug_assert_within_budget(pool_name);
    resp
}

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
    app: &Arc<App>,
    cands: &[WeightedLane],
    max_ms: u64,
    body: &Bytes,
    caller_token: Option<&str>,
    request_ctx: &RequestCtx,
    pool: &str,
    ingress_protocol: &str,
    op: busbar_core::handlers::Op,
    req_content_type: &str,
    usage_sink: Option<UsageSink>,
) -> Response {
    use busbar_core::store::Unavailable;

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
        return handle_status_503(app, cands, now(), pool, ingress_protocol);
    }

    // Ms-precision deadline: bound the wait by `min(max_ms, failover_budget_remaining)` in MS so a
    // sub-second `max_ms` is representable and a near-second-boundary budget does not collapse to 0.
    // Captured ONCE as an absolute instant so it survives the re-wait loop (a won-but-breaker-Open
    // permit re-enters the wait against the SAME deadline — it can never extend the budget).
    let wait_ms = max_ms.min(request_ctx.remaining_ms());
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(wait_ms);

    // `busbar_pool_queued` depth accounting — RAII, decremented on EVERY exit (dispatch, shed, or a
    // dropped future on client disconnect), so the gauge can never leak a phantom waiter.
    let _depth = app.engine_tables().queued_depth().park(pool);

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
            .filter_map(|&idx| app.store.lane_semaphore(idx).map(|s| (idx, s)))
            .collect();
        if sems.is_empty() {
            return handle_status_503(app, cands, now(), pool, ingress_protocol);
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
                return handle_status_503(app, cands, now(), pool, ingress_protocol);
            }
        };
        let owned = match permit_res {
            Ok(p) => p,
            // The semaphore was closed (shutdown) — no permit is coming; shed.
            Err(_) => return handle_status_503(app, cands, now(), pool, ingress_protocol),
        };
        let permit = busbar_core::store::Permit::Bounded(owned);

        // We hold capacity but have NOT passed the breaker. Run ONLY the breaker admission step on the
        // won lane — the dispatched request owns the probe it wins (`forward_once` releases it
        // via `release_probe_in`, exactly like the fallback dispatch path).
        match app.store.try_admit_breaker(pool, lane, now()) {
            Ok(probe_epoch) => {
                let reasoning_override = cands
                    .iter()
                    .find(|w| w.idx == lane)
                    .and_then(|w| w.reasoning);
                return match forward_once(
                    app,
                    lane,
                    permit,
                    body,
                    caller_token,
                    request_ctx.remaining(now()),
                    ingress_protocol,
                    // The queued waiter selected this member against THIS pool's cell (it was an
                    // AtCapacity exclusion recorded by `pick_among` on the pool cell), so record its
                    // breaker outcome against the pool cell — mirrors the fallback/least_bad dispatch.
                    pool,
                    // The probe `try_admit_breaker` won (or `None` for a Closed-ready no-op admit),
                    // released OWNER-CHECKED by `forward_once`'s `ProbeGuard` when `Some` (consistent
                    // with the `Admit.probe_epoch` discipline everywhere else); on `None` this dispatch
                    // owns no probe and forward_once builds NO guard.
                    probe_epoch,
                    op,
                    req_content_type,
                    usage_sink,
                    reasoning_override,
                )
                .await
                {
                    Ok(resp) => resp,
                    Err(()) => handle_status_503(app, cands, now(), pool, ingress_protocol),
                };
            }
            Err(reason) => {
                // The lane's breaker tripped Open (or it went dead / lost the probe race) while we were
                // queued. The disposition is correct (drop this lane, keep waiting or shed), but the
                // reason is a real diagnostic for an operator debugging a flapping queue-mode lane — log
                // it before dropping the lane rather than swallowing it.
                tracing::debug!(
                    pool = %pool,
                    lane = %app.engine_tables().lanes()[lane].model,
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
                    return handle_status_503(app, cands, now(), pool, ingress_protocol);
                }
                continue;
            }
        }
    }
}

/// Status503 mode: return 503 with Retry-After header. The body is the ingress protocol's native
/// JSON error envelope (not `text/plain`) so an official SDK can decode it; the `Retry-After`
/// header is preserved so rate-aware clients still back off.
pub(crate) fn handle_status_503(
    app: &Arc<App>,
    cands: &[WeightedLane],
    now: u64,
    pool: &str,
    ingress_protocol: &str,
) -> Response {
    let retry_after = retry_after_secs(app, cands, now, pool);

    let mut resp = ingress_error(
        ingress_protocol,
        StatusCode::SERVICE_UNAVAILABLE,
        KIND_OVERLOADED,
        "The service is temporarily overloaded. Please retry shortly.",
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after.to_string()) {
        resp.headers_mut()
            .insert(axum::http::header::RETRY_AFTER, v);
    }
    resp
}

/// Forward one request to a specific lane and relay the response. Shared by the degraded
/// last-resort exhaustion paths (FallbackPool routing + LeastBad). Unlike the main forward
/// loop these paths do NOT apply breaker disposition/failover classification — they relay
/// whatever the upstream returns verbatim. On a pre-response transport error the lane's
/// transient counter is recorded and `Err(())` is returned so the caller can try another
/// candidate (or give up). The concurrency `permit` is held for the lifetime of a streamed
/// success body (invariant) and dropped on error.
///
/// Cross-protocol translation: this degraded path translates BOTH directions symmetrically with the
/// main `forward_with_pool` path — the request body is translated egress-side (via the superset IR)
/// and the 2xx response is translated back to the ingress protocol (buffered for non-stream, framed
/// via `StreamTranslate` for SSE). Non-2xx responses are reshaped to the ingress error envelope on a
/// crossed boundary. Same-protocol targets pass through verbatim.
#[allow(clippy::too_many_arguments)]
// plumbing: each arg is an independent request input
// `level = busbar_core::observability::HOTPATH_LEVEL` (the tracing seam): this span fires on EVERY
// degraded-path attempt (fallback-pool routing + least-bad), so it must be filtered off at the
// default `RUST_LOG=info` the same as the main `forward` span in `engine/mod.rs` — routed through
// the ONE named constant rather than a second hand-picked `"debug"` literal, so the hot-path level
// policy stays a one-spot change and `scripts/tracing-lint.sh` cannot see this as a rogue,
// level-less `#[instrument]`.
#[tracing::instrument(
    level = HOTPATH_LEVEL,
    name = "forward_once",
    skip_all,
    fields(lane = i)
)]
pub(crate) async fn forward_once(
    app: &Arc<App>,
    i: usize,
    permit: Permit,
    body: &Bytes,
    caller_token: Option<&str>,
    timeout_secs: u64,
    ingress_protocol: &str,
    // The routing POOL cell this degraded attempt was selected against (fallback-pool member or
    // least-bad member). ALL breaker recordings here (success/transient) must target THIS cell, not
    // the default `""` cell: the degraded callers select via the POOL cell and (for fallback) CAS-win
    // a single-flight HalfOpen probe on it, so recording on `""` left the pool cell wedged HalfOpen +
    // `probe_in_flight` forever. An empty `pool` means the lane-default cell (direct/ad-hoc routes).
    pool: &str,
    // Owner token for the single-flight recovery probe this dispatch owns on the `(pool, i)` cell.
    // `Some(epoch)` = this dispatch WON a probe (captured at the win: `Admit.probe_epoch` from
    // `pick_among`, or the epoch from `try_admit_breaker`); a RAII `ProbeGuard` is armed to release
    // that probe OWNER-CHECKED if this future is DROPPED mid-dispatch (client disconnect) — see the
    // guard construction. `None` = this dispatch OWNS NO PROBE (the least-bad path bypasses the breaker
    // and wins nothing), so NO guard is built and this call can never release/revert any probe — in
    // particular it can never revert a probe a concurrent PEER legitimately won on the same cell.
    probe_epoch: Option<u64>,
    op: busbar_core::handlers::Op,
    req_content_type: &str,
    usage_sink: Option<UsageSink>,
    // The selected pool member's `reasoning` override (`WeightedLane.reasoning`), resolved by the
    // caller from its candidate slice. `None` = no member override → fall back to the lane flag. The
    // degraded path has no `cands` in scope, so the caller passes the already-resolved override here
    // (mirrors the hot path's `effective_reasoning`).
    reasoning_override: Option<bool>,
) -> Result<Response, ()> {
    // RAII probe release covering the WHOLE dispatch window, built ONLY when
    // this dispatch actually won a probe (`probe_epoch == Some`). The caller won a single-flight
    // recovery probe on the `(pool, i)` cell before entering here; if THIS future is dropped mid-`.await`
    // (client disconnects while the upstream call is in flight) none of the explicit early-return paths
    // below run, so without a Drop guard the cell would stay HalfOpen + `probe_in_flight` forever and the
    // lane would be benched until the slow out-of-band prober reset it. `ProbeGuard::drop` releases it
    // OWNER-CHECKED (keyed on the captured `epoch`, so a stale drop never reverts a NEWER probe won by a
    // peer). It stays ARMED across every early-return error path (those paths record a transient first,
    // which already transitions the cell, making the guard's release a safe no-op) and is DISARMED
    // exactly once the request records a legitimate SUCCESS outcome (`record_success_in` below) — from
    // that point the dispatched request/stream owns the probe through its recorded outcome, so the guard
    // must not also release it. Idempotent, owner-checked: never a double-release. This supersedes the
    // previous scattered unowned `release_probe_in` calls.
    //
    // `probe_epoch == None` (the least-bad path, which bypasses the breaker and owns NO probe) builds NO
    // guard at all: there is nothing to release, so this dispatch can never revert a probe a concurrent
    // PEER legitimately won on the same cell. Representing "no probe" as `None` — rather than passing the
    // cell's CURRENT epoch to an armed guard — is what makes that safe: an epoch-equality release keyed
    // on a peer's live epoch would otherwise revert the peer's in-flight probe on a dropped future.
    let mut probe_guard = probe_epoch.map(|epoch| crate::engine::select::ProbeGuard {
        store: app.store.as_ref(),
        pool,
        lane: i,
        armed: true,
        probe_epoch: epoch,
    });
    // Re-parse body for per-lane model rewriting. An OPAQUE (non-JSON) body — multipart/binary
    // operations — parses to `None` and relays/translates at the byte level, exactly like the main
    // path; only a JSON-Content-Type body that FAILS to parse is the caller's 400.
    let v: Option<Value> = match busbar_core::json::parse(body) {
        Ok(v) => Some(v),
        Err(_) if !req_content_type.starts_with(APPLICATION_JSON) => None,
        Err(_) => {
            // See the main forward path: log a sanitized note for operators; never the parser's raw
            // error (with sonic-rs it embeds a fragment of the input body — secrets/PII) nor leak it
            // into the client 400 body.
            tracing::debug!(detail = %busbar_core::json::parse_err_log(body.len()), "request body JSON parse failed");
            // Pre-dispatch bail (no breaker outcome recorded): the armed `probe_guard` above releases
            // the POOL-cell single-flight probe on drop (owner-checked, idempotent, a no-op on the
            // default `""` / a non-HalfOpen cell), so the cell never wedges HalfOpen on this early exit.
            return Ok(ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                "We could not parse the JSON body of your request.",
            ));
        }
    };

    // stream intent for the stream-aware upstream path (Gemini).
    let wants_stream = v
        .as_ref()
        .and_then(|v| v.get("stream"))
        .and_then(|s| s.as_bool())
        .unwrap_or(false);
    // Gemini ingress streaming WITHOUT `?alt=sse` → JSON-array streamed body (see main path). GATED
    // on `uses_array_stream_shim()` (true only for GeminiWriter) so a body-model client cannot
    // smuggle the shim key to force JSON-array reframing of its SSE stream.
    let ingress_decl = busbar_core::proto::decl_for(ingress_protocol);
    let gemini_json_array = ingress_decl.is_some_and(|d| d.uses_array_stream_shim)
        && ingress_decl
            .and_then(|d| d.dialect())
            .map(|di| {
                v.as_ref()
                    .map(|v| di.wants_array_stream(v))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
    let egress_name = app.engine_tables().lanes()[i].protocol;

    // Breaker config for THIS degraded attempt's routing pool cell — resolved the same way the main
    // forward path resolves `breaker_cfg` (per-pool settings, ADR-0002 default fallback). All breaker
    // recordings below target the `pool` cell with this cfg so the degraded path trips/cools the pool
    // cell against its own thresholds, not a one-size default. Wrapped in an `Arc` so the streaming
    // `FirstByteBody` guard can record mid-stream failures with the SAME thresholds the synchronous
    // path used (mirrors `forward_with_pool`).
    let forward_once_cfg: std::sync::Arc<busbar_core::store::BreakerCfg> = resolve_breaker_cfg(app, pool);

    // Cross-protocol request shaping through the SINGLE shared seam (read→clear-extra→write, shim-key
    // strip, model rewrite, serialize) — the SAME function the hot `forward_with_pool` path uses, so
    // this degraded route cannot drift from it. Sharing the seam is what keeps them aligned (this path
    // previously lacked the `ir.extra.clear()` the hot path had, leaking source-only keys like OpenAI
    // `logprobs`/`top_logprobs`/`n` to a foreign backend): the clear now lives in the one shared fn,
    // so neither path can be missing it.
    let body_is_json = v.is_some();
    let payload = match translate_request_cross_protocol(
        app,
        i,
        ingress_protocol,
        op,
        v,
        req_content_type,
        // Honor the pool member's `reasoning` override (as the hot path does via
        // `effective_reasoning`), falling back to the lane-level flag.
        reasoning_override.unwrap_or(app.engine_tables().lanes()[i].reasoning),
        body,
        // This degraded/fallback path resolves no governance key (and `caller_token` is a raw bearer
        // secret, never a principal id), so the audit principal is `"anonymous"`.
        "anonymous",
    ) {
        Ok(p) => p,
        Err(resp) => {
            // Pre-dispatch bail on a translation failure (no breaker outcome recorded): the armed
            // `probe_guard` releases the POOL-cell single-flight probe on drop (owner-checked).
            return Ok(*resp);
        }
    };

    // Mode-aware key selection: passthrough uses caller token, others use lane's api_key.
    let key = match app.engine_tables().pool_upstream_creds(pool) {
        // Passthrough forwards the CALLER's credential upstream. When the caller presents NO
        // credential, fall back to an EMPTY credential — NOT the lane operator's `api_key`
        // (a SECURITY boundary): borrowing the operator key would let an unauthenticated caller
        // silently spend on the operator's upstream account. An empty credential makes the
        // provider return its own 401/403, attributed to the caller (a client-auth fault, no
        // lane penalty), matching the documented passthrough contract. No-op in canonical
        // keyless passthrough (lane.api_key already empty); only changes the misconfigured
        // passthrough+configured-key case.
        busbar_core::auth::UpstreamCreds::Passthrough => caller_token.unwrap_or(""),
        busbar_core::auth::UpstreamCreds::Own => app.engine_tables().lanes()[i].api_key.expose_secret(),
    };

    // per-request auth (SigV4 for Bedrock; static otherwise). The (operation × stream) egress
    // target — wire URL + SigV4 canonical URI — is the lane's boot-precomputed table (mirrors the
    // main forward path; see `egress::build_egress_targets` for the sign-what-you-send encoding
    // rule). A lookup miss is the old `upstream_path` `None` arm: unreachable for chat (the router
    // filters unsupported lanes before the degraded path is reached); bail safely — the armed
    // `probe_guard` releases any single-flight probe this lane won on drop (same probe contract as
    // forward_once's other pre-dispatch exits).
    let Some(target) = app.engine_tables().lanes()[i].egress_target(op.operation, wants_stream)
    else {
        return Ok(ingress_error(
            ingress_protocol,
            StatusCode::INTERNAL_SERVER_ERROR,
            KIND_API_ERROR,
            DETAIL_INTERNAL_ERROR,
        ));
    };
    let signing_ctx = busbar_core::proto::SigningContext {
        host: &app.engine_tables().lanes()[i].signing_host,
        canonical_uri: &target.canonical_uri,
        body: &payload,
        timestamp_epoch: now(),
        upstream_creds: app.upstream_creds(),
    };
    // Mirrors the main forward path: Own-mode on a lane-constant credential clones the
    // boot-prebuilt map; Passthrough / non-constant credentials build live.
    let egress_auth = match (
        &app.engine_tables().lanes()[i].prebuilt_auth,
        app.engine_tables().pool_upstream_creds(pool),
    ) {
        (Some(pre), busbar_core::auth::UpstreamCreds::Own) => pre.clone(),
        _ => convert_headers(lane_auth_headers(
            &app.engine_tables().lanes()[i],
            key,
            &signing_ctx,
        )),
    };

    // Egress Content-Type — mirror the main forward path exactly (it was hardcoded APPLICATION_JSON
    // here, which sent an opaque multipart transcription / binary body upstream as application/json,
    // a guaranteed 400). JSON body -> JSON; same-protocol opaque -> the caller's own CT (boundary
    // preserved); cross-protocol opaque -> the egress operation handler's declared wire CT.
    let egress_ct: &str = if body_is_json {
        APPLICATION_JSON
    } else if ingress_protocol == egress_name {
        req_content_type
    } else {
        busbar_core::handlers::request_handler(egress_name)
            .and_then(|rh| rh.operation_handler(op.operation))
            .map(|h| h.egress_request_content_type())
            .unwrap_or(APPLICATION_JSON)
    };
    // Egress header map (mirrors the main forward path): the auth map IS the base — prebuilt clone
    // or live-built above — then CT/UA/Accept in the same insertion order.
    let mut egress_headers = egress_auth;
    let ct_value = if body_is_json {
        // `from_static`: declaration constant — static bytes, no per-request alloc.
        axum::http::HeaderValue::from_static(APPLICATION_JSON)
    } else {
        // The caller's own CT (same-protocol opaque) / the egress handler's wire CT: runtime
        // strings, validated here exactly as the main path does — an unencodable CT is an
        // internal fault, never a panic on the request path.
        match axum::http::HeaderValue::from_str(egress_ct) {
            Ok(v) => v,
            Err(_) => {
                return Ok(ingress_error(
                    ingress_protocol,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    KIND_API_ERROR,
                    DETAIL_INTERNAL_ERROR,
                ));
            }
        }
    };
    egress_headers.insert(CONTENT_TYPE, ct_value);
    // Native-SDK User-Agent for the egress protocol (mirrors the main forward path).
    egress_headers.insert(
        USER_AGENT,
        axum::http::HeaderValue::from_static(crate::engine::egress_user_agent(egress_name)),
    );
    // Native-SDK Accept for the egress protocol — a declaration constant, chosen by the operation.
    egress_headers.insert(
        ACCEPT,
        axum::http::HeaderValue::from_static(op.egress_accept(egress_name, wants_stream)),
    );
    // The precomputed egress `http::Uri` (mirrors the main forward path): hand-assembled request,
    // no builder machinery, no per-request compose + WHATWG parse.
    let hreq = crate::engine::egress_request(target.uri.clone(), egress_headers, payload);
    // TIMEOUT RE-PROVISION (mirrors the main forward path EXACTLY — the re-audit caught this
    // path keeping the pre-fix shape, the F1 hole's second home): ONE deadline per attempt.
    // Non-stream: the failover deadline. Stream: the client-level ceiling — bounding a stream
    // with the (short) failover wall-clock would truncate healthy generations, but bounding it
    // with NOTHING let a black-holed upstream hang the degraded send forever — and the degraded
    // walk fires precisely when lanes are unhealthy, exactly where black-holing upstreams live.
    let send_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(if wants_stream {
            app.client_settings.upstream_request_timeout_secs.max(1)
        } else {
            timeout_secs.max(1)
        });
    // Wall-clock start of the upstream call, for the `metrics.latencyMs` a native bedrock
    // ConverseStream `metadata` frame carries on the buffered-synthesis path below.
    let upstream_started = std::time::Instant::now();
    // Per-attempt time-to-headers cap on the DEGRADED path too (lane-level only: this path selects
    // by pool cell, not a member row, so the member override does not apply here). Expiry = the same
    // transport-timeout handling as the transport error below. The non-stream budget deadline wraps
    // BOTH send arms (the attempt cap, when smaller, still fires first inside).
    let send_fut = async {
        let send = app.engine_tables().client().get().request(hreq);
        match app.engine_tables().lanes()[i].attempt_timeout_ms {
            Some(ms) => {
                let cap = attempt_cap(ms, timeout_secs);
                match tokio::time::timeout(cap, send).await {
                    Ok(r) => SendOutcome::Sent(r),
                    Err(_elapsed) => SendOutcome::AttemptTimeout(ms),
                }
            }
            None => SendOutcome::Sent(send.await),
        }
    };
    let outcome = match tokio::time::timeout_at(send_deadline, send_fut).await {
        Ok(o) => o,
        Err(_elapsed) => SendOutcome::BudgetTimeout,
    };
    let res = match outcome {
        SendOutcome::Sent(r) => r.map_err(EgressSendError::Client),
        SendOutcome::BudgetTimeout => Err(EgressSendError::Timeout),
        SendOutcome::AttemptTimeout(ms) => {
            record_upstream_rtt(upstream_started.elapsed());
            diag_debug!(
                ATTEMPT_TIMEOUT_DEGRADED,
                pool = %pool,
                lane = %app.engine_tables().lanes()[i].model,
                attempt_timeout_ms = ms,
                "no response headers within the attempt cap (degraded path)"
            );
            // Mirror the transport-error handling: record transient on the POOL cell and
            // signal the caller to try the next degraded candidate.
            let tripped = app.store.record_transient_in(
                pool,
                i,
                ERR_NET_TIMEOUT,
                forward_once_cfg.as_ref(),
                None,
            );
            if tripped {
                emit_breaker_trip(app, pool, i);
            }
            // `record_transient_in` above already transitioned the cell; the armed `probe_guard`
            // releases the probe on drop (owner-checked no-op after the transient). Record
            // BEFORE release preserved (the guard drops at return, after this recording).
            busbar_core::telemetry::upstream_failure(app, pool, i, DISPOSITION_ATTEMPT_TIMEOUT);
            // Parity with the organic path: a degraded-path attempt-timeout is a failover
            // (the caller tries the next candidate), so count it under FAILOVERS_TOTAL too.
            busbar_core::telemetry::failover(app, pool, DISPOSITION_ATTEMPT_TIMEOUT);
            return Err(());
        }
    };
    record_upstream_rtt(upstream_started.elapsed());
    // Every buffered read of this response rides the SAME deadline as the send (mirrors the
    // main forward path): one instant, one envelope.
    let read_deadline = send_deadline;

    match res {
        Ok(r) => {
            let status = r.status();
            let ct = r.headers().get(CONTENT_TYPE).cloned();
            // Capture the upstream relayed request-id-class headers before `r` is consumed, keyed off
            // the ingress writer's `ingress_relayed_response_header_names` so this names no protocol
            // module. For a bedrock ingress this captures `x-amzn-requestid` (the PRIMARY id —
            // forwarded verbatim on a same-protocol passthrough, or replaced by a synthesized id
            // cross-protocol below) followed by `x-amzn-errortype` (a native ConverseStream/Converse
            // error always carries it; AWS SDKs dispatch the typed exception from this header FIRST,
            // before the body `__type`; its absence is a detectable proxy tell). For an anthropic
            // ingress it captures `request-id` (the primary id). Empty for non-relaying ingress.
            let bedrock_relay_headers: Vec<(&'static str, String)> =
                ingress_relayed_response_header_names(ingress_protocol)
                    .iter()
                    .filter_map(|name| {
                        let v = r.headers().get(*name)?.to_str().ok()?.to_string();
                        Some((*name, v))
                    })
                    .collect();
            // The PRIMARY relayed id is the FIRST relayed header (x-amzn-requestid for bedrock,
            // request-id for anthropic); the writer vtable picks the correct response header to attach
            // it under on the 2xx success path. The bedrock-only second header (`x-amzn-errortype`) is
            // forwarded verbatim alongside it from `bedrock_relay_headers` on the error relay below.
            let upstream_relay_id = bedrock_relay_headers.first().map(|(_, v)| v.clone());
            let cross_protocol = ingress_protocol != egress_name;

            if !status.is_success() {
                let bytes = read_capped_body(r, read_deadline).await;
                // PX1 (availability): classify the upstream disposition BEFORE penalizing the
                // breaker. Both degraded relay branches below previously recorded a transient
                // failure (`record_transient_in`) on ANY non-2xx — counting deterministic
                // client-error 4xx (400/401/403/404/422) and deliberate 429 rate-limits as
                // transient upstream FAULTS, tripping the breaker against a HEALTHY upstream (a
                // self-inflicted outage). Reuse the SAME two-stage classifier the main
                // `forward_with_pool` path uses (op cell `extract_error` → `normalize_raw_error`
                // over the lane's `error_map` → `breaker::classify`), so ONLY a genuine upstream
                // fault (5xx / overload / timeout / network → `TransientUpstream`) feeds the
                // breaker. Every other disposition — client fault (4xx), auth/billing HardDown,
                // ContextLength — relays verbatim with NO transient penalty; the still-armed
                // `probe_guard` releases any won HalfOpen probe on drop (mirrors the main path's
                // ClientFault/ContextLength arms). Body-only classification here (no headers);
                // `retry_after` only floors the cooldown, not the disposition, so it is omitted.
                let penalize_breaker = {
                    let raw = busbar_core::handlers::op_for(
                        egress_name,
                        op.operation,
                        busbar_core::transport::Transport::Http,
                    )
                    .map(|cell| cell.extract_error(status.as_u16(), &bytes))
                    .unwrap_or_else(|| {
                        busbar_core::breaker::RawUpstreamError::from_status(status.as_u16())
                    });
                    let sig = busbar_core::breaker::normalize_raw_error(
                        &raw,
                        &app.engine_tables().lanes()[i].error_map,
                    );
                    matches!(
                        busbar_core::breaker::classify(&sig),
                        busbar_core::breaker::Disposition::TransientUpstream
                    )
                };
                // Cross-protocol: relaying the EGRESS provider's native error body+Content-Type to a
                // different-protocol client is a foreign-format leak. Reshape to the ingress
                // protocol's native error envelope, lifting the upstream's human message where
                // present. Same-protocol passthrough relays verbatim (already the client's shape).
                if cross_protocol {
                    // Shared finalizer: the kind→native-envelope mapping (401→authentication_error,
                    // 403→permission_error, 429→rate_limit_error, 5xx→api_error, else
                    // invalid_request_error) is now IDENTICAL to the main `forward_with_pool` path, so
                    // this degraded route can no longer drift (the bug it fixes: a 401/403 on the
                    // degraded path was labeled `invalid_request_error`, the wrong typed-exception
                    // discriminant for an Anthropic SDK and a proxy tell).
                    // Probe-leak guard: a non-fault non-2xx (client 4xx / auth / context-length)
                    // records no breaker outcome on this degraded relay path (it relays verbatim),
                    // so the single-flight HalfOpen probe this fallback attempt CAS-won on the POOL
                    // cell is still in flight. Release it before returning or the cell stays HalfOpen
                    // + `probe_in_flight` forever. Idempotent; no-op off a HalfOpen / default cell.
                    //
                    // Cooldown-backoff fix: on a genuine upstream FAULT (`penalize_breaker`, see the
                    // PX1 classification above), record a transient failure BEFORE releasing the
                    // probe, so a non-2xx on a HalfOpen probe bumps the cooldown (exponential
                    // backoff) exactly like the MAIN forward path's non-2xx branch. Releasing alone
                    // left the cooldown at its original expiry, so the lane re-probed at the base
                    // interval with no backoff. A threshold re-trip here is a breaker trip too (#29).
                    // On a NON-fault (client 4xx, auth/billing, context-length) `penalize_breaker`
                    // is false: the `&&` short-circuits so `record_transient_in` is NEVER called, and
                    // the still-armed `probe_guard` releases the probe on drop — no breaker penalty.
                    let tripped = penalize_breaker
                        && app.store.record_transient_in(
                            pool,
                            i,
                            ERR_DEGRADED_NON2XX,
                            forward_once_cfg.as_ref(),
                            None,
                        );
                    if tripped {
                        emit_breaker_trip(app, pool, i);
                    }
                    // On a fault, `record_transient_in` above transitioned the cell (cooldown-backoff
                    // preserved); the armed `probe_guard` releases the probe on drop (owner-checked
                    // no-op after). On a non-fault, the guard is the SOLE releaser.
                    return Ok(shape_cross_protocol_error(ingress_protocol, status, &bytes));
                }
                // Same-protocol degraded path: relay the upstream error verbatim (no classification).
                let mut rb = Response::builder().status(status);
                if let Some(ct) = ct {
                    rb = rb.header(CONTENT_TYPE, ct);
                }
                if ingress_relays_amzn_headers(ingress_protocol) {
                    // Bedrock-ingress same-protocol error relay: forward BOTH `x-amzn-requestid` and
                    // `x-amzn-errortype` VERBATIM (no synth), mirroring the main `forward_with_pool`
                    // path. Without them a native AWS SDK's `request_id()` returns None and the
                    // typed-exception dispatch falls back from header-first to body `__type` — both
                    // detectable tells. (This degraded route previously captured the id but never
                    // attached it, and dropped the errortype.) The header NAMES + VALUES come from the
                    // vtable-keyed `bedrock_relay_headers` capture, so this names no protocol module.
                    for (name, value) in &bedrock_relay_headers {
                        rb = rb.header(*name, value);
                    }
                } else {
                    // Anthropic-ingress same-protocol error relay: forward the upstream `request-id`
                    // (a native Anthropic error always carries it; the SDK reads it into
                    // `APIError.request_id`), synthesizing one if the upstream omitted it. The writer
                    // vtable selects the `request-id` header name and the upstream-or-synth value.
                    rb = maybe_attach_response_request_id(
                        rb,
                        ingress_protocol,
                        upstream_relay_id.as_deref(),
                    );
                }
                // Probe-leak guard: same as the cross-protocol non-2xx branch above —
                // a non-fault verbatim same-protocol error relay records no breaker outcome, so
                // release the POOL-cell single-flight probe this fallback attempt CAS-won before
                // returning, or the cell stays HalfOpen + `probe_in_flight` forever. Idempotent;
                // no-op off a HalfOpen / default cell.
                //
                // Cooldown-backoff fix: on a genuine upstream FAULT (`penalize_breaker`, see the PX1
                // classification above), record a transient failure BEFORE releasing the probe, so a
                // non-2xx on a HalfOpen probe bumps the cooldown (exponential backoff) like the MAIN
                // forward path's non-2xx branch. Without it the cooldown stayed at its original expiry
                // and the lane re-probed at the base interval with no backoff. A threshold re-trip
                // here is a breaker trip too (#29). On a NON-fault (client 4xx, auth/billing,
                // context-length) `penalize_breaker` is false: the `&&` short-circuits so
                // `record_transient_in` is NEVER called and the armed `probe_guard` alone releases the
                // probe — a healthy upstream's deterministic 4xx no longer trips the breaker.
                let tripped = penalize_breaker
                    && app.store.record_transient_in(
                        pool,
                        i,
                        ERR_DEGRADED_NON2XX,
                        forward_once_cfg.as_ref(),
                        None,
                    );
                if tripped {
                    emit_breaker_trip(app, pool, i);
                }
                // On a fault, `record_transient_in` above transitioned the cell (cooldown-backoff
                // preserved); the armed `probe_guard` releases the probe on drop (owner-checked no-op
                // after). On a non-fault, the guard is the SOLE releaser.
                return Ok(rb
                    .body(Body::from(bytes))
                    .unwrap_or_else(|_| status.into_response()));
            }

            // SUCCESS: the degraded path served a 2xx. Mirror the main forward loop
            // (forward_with_pool) — record the lane success against the ROUTING POOL cell (feeds the
            // breaker success window so a HalfOpen lane served via fallback/least-bad recovers the
            // POOL cell to Closed and clears its single-flight probe) and consume one unit of its
            // lifetime request budget. The degraded callers select via the pool cell, so recording on
            // the default `""` cell left the pool cell wedged HalfOpen + probe_in_flight forever.
            app.store.record_success_in(pool, i);
            // DISARM the probe guard: `record_success_in` recorded this dispatch's legitimate outcome
            // (HalfOpen→Closed, probe cleared), so the request now owns the probe through to that
            // outcome. From here the streamed/buffered success body (or its own mid-stream failure
            // recording) is responsible for the cell, and the guard must NOT also release on drop. No-op
            // when no guard was built (least-bad path, `probe_epoch == None`).
            if let Some(g) = probe_guard.as_mut() {
                g.armed = false;
            }
            // Mirror the main path: fold time-to-headers into the lane's latency EWMA (routing
            // `fastest` signal). Lane-global; off the selection path.
            app.store
                .record_latency_in(pool, i, upstream_started.elapsed().as_secs_f64() * 1000.0);
            // BIND the spend result (#21): a paired post-headers body TransportError below refunds the
            // budget, but `refund_budget` UNCONDITIONALLY fetch_adds — so refunding a spend that was a
            // no-op (budget already 0) would raise the budget ABOVE its cap. Only refund if this spend
            // actually decremented. `budget_spent` is `true` for an unlimited lane (spend is a no-op
            // success there), so an unlimited lane never refunds (refund_budget is also a no-op there).
            let budget_spent = app.store.spend_budget(i);
            // Guards the buffered path's spend→`read_capped(...).await` window (#21): armed now,
            // disarmed at every exit below that must KEEP the charge. Disarmed (without refunding)
            // just before the streaming builder, which hands `budget_spent` to `FirstByteBody` for
            // its own cancellation-safe refund. See `engine::mod::BudgetSpendGuard`.
            let mut budget_guard = super::BudgetSpendGuard {
                store: app.store.as_ref(),
                lane: i,
                armed: budget_spent,
            };

            // SUCCESS: stream the response body incrementally (permit held for stream life).
            let is_sse = ct
                .as_ref()
                .map(|h| is_streaming_content_type(h.to_str().unwrap_or("")))
                .unwrap_or(false);

            // Non-streaming cross-protocol response: buffer + translate egress→IR→ingress, mirroring
            // the main forward_with_pool path so this degraded route does not leak the egress wire
            // format to a different-protocol client.
            if cross_protocol && !is_sse {
                return Ok(super::translate_response_cross_protocol(
                    app,
                    i,
                    ingress_protocol,
                    op,
                    pool,
                    forward_once_cfg.as_ref(),
                    r,
                    read_deadline,
                    permit,
                    &mut budget_guard,
                    usage_sink,
                    status,
                    wants_stream,
                    gemini_json_array,
                    upstream_started,
                    // The degraded (FallbackPool/LeastBad) path has no `chosen_policy_name` in scope —
                    // there is no routing-policy decision on this hop — and `maybe_attach_route_policy`
                    // is already a no-op on `None`, so this reproduces the prior behavior (no
                    // `x-busbar-route-*` headers on this path) exactly.
                    None,
                    true, // degraded path: selects the "degraded"-labeled warn strings
                )
                .await);
            }

            // Streaming (or same-protocol non-stream): stream with first-byte boundary tracking. On a
            // cross-protocol SSE response, translate egress frames → ingress frames, matching the main
            // path. Mid-stream breaker failures must record against the ROUTING POOL cell with this
            // pool's resolved breaker cfg (mirrors `forward_with_pool`) — NOT the default `""` cell —
            // so a fallback/least-bad stream that fails mid-flight reopens the pool cell it was
            // selected against, never the unrelated default cell.
            // ONE registry-resolved factory, IDENTICAL to the hot `forward_with_pool` path (extracted
            // so the two cannot drift): cross-protocol SSE builds the reframing translator,
            // same-protocol SSE the verbatim same-proto translator (byte-exact re-emit + IR usage
            // A-tap), `!is_sse`/unknown-protocol yields `None` → legacy passthrough.
            let translate =
                busbar_core::proto::new_stream_translator(ingress_protocol, egress_name, is_sse);
            let json_array = (gemini_json_array && is_sse)
                .then(|| {
                    busbar_core::proto::decl_for(ingress_protocol)
                        .and_then(|d| d.dialect())
                        .and_then(|dc| dc.make_array_stream_framer())
                })
                .flatten();
            // Handing the budget-refund decision to `FirstByteBody` (via `budget_spent` below) —
            // disarm the local guard so it does not ALSO refund when this frame unwinds.
            budget_guard.disarm();
            let upstream_stream = {
                use http_body_util::BodyExt;
                r.into_body().into_data_stream()
            };
            let guarded_body = FirstByteBody::new(
                upstream_stream,
                is_sse,
                ingress_protocol,
                op,
                permit,
                read_deadline,
                app.clone(),
                i,
                forward_once_cfg.clone(),
                pool, // degraded path: the routing pool's breaker cell
                translate,
                json_array,
                usage_sink,
                budget_spent,
            );
            let mut rb = Response::builder().status(status);
            // Cross-protocol streaming: the body is reframed to the client's format, so the CT must
            // describe the ingress client's wire, not the upstream's. Same-protocol keeps the upstream
            // CT verbatim.
            if gemini_json_array && is_sse {
                rb = rb.header(CONTENT_TYPE, APPLICATION_JSON);
            } else {
                match (cross_protocol && is_sse)
                    .then(|| ingress_stream_content_type(ingress_protocol))
                    .flatten()
                {
                    Some(client_ct) => {
                        rb = rb.header(CONTENT_TYPE, client_ct);
                    }
                    None => {
                        if let Some(ct) = ct {
                            rb = rb.header(CONTENT_TYPE, ct);
                        }
                    }
                }
            }
            // Bedrock-ingress 2xx carries `x-amzn-RequestId`; anthropic-ingress 2xx carries
            // `request-id`: forward the captured upstream id verbatim on a same-protocol passthrough,
            // else synthesize. The writer vtable selects the correct header name + upstream-or-synth
            // value per protocol; non-relaying ingress: omit.
            rb = maybe_attach_response_request_id(
                rb,
                ingress_protocol,
                upstream_relay_id.as_deref(),
            );
            Ok(rb
                .body(guarded_body.into_body())
                .unwrap_or_else(|_| status.into_response()))
        }
        Err(e) => {
            // Pre-response transport error: record transient against the ROUTING POOL cell, drop the
            // permit, signal "try next". The degraded callers selected via the pool cell (fallback CAS
            // -wins a HalfOpen probe on it), so this transport failure must reopen the POOL cell — not
            // the default `""` cell, which would leave the pool cell wedged HalfOpen forever.
            // BREAKER_TRIPS_TOTAL is emitted here too, gated on the trip bool, mirroring the sibling
            // degraded arms (the two non-2xx relays and the post-headers transport arm) so a logical
            // Closed→Open trip is counted exactly once regardless of which degraded failure shape hit
            // it. (`tripped` is false for a HalfOpen reopen / already-Open no-op, so it is not
            // inflated.) Keeps the cross-arm counters symmetric.
            let err_type = if e.is_timeout() {
                ERR_NET_TIMEOUT
            } else {
                ERR_NET_CONNECT
            };
            let tripped =
                app.store
                    .record_transient_in(pool, i, err_type, forward_once_cfg.as_ref(), None);
            if tripped {
                emit_breaker_trip(app, pool, i);
            }
            drop(permit);
            Err(())
        }
    }
}

/// FallbackPool mode: actually route the request to a configured fallback pool's healthy
/// member. Supports multi-level chains (A→B→C): when the fallback pool is itself exhausted
/// it consults THAT pool's own `on_exhausted` config and re-enters. The `visited_pools` set
/// in `RequestCtx` is the loop guard — a chain that cycles back to an already-visited pool
/// (A→B→A) terminates with 503 instead of recursing forever.
#[allow(clippy::too_many_arguments)] // plumbing: each arg is an independent request input
pub(crate) async fn handle_fallback_pool(
    app: Arc<App>,
    body: Bytes,
    caller_token: Option<&str>,
    pool_name: &str,
    request_ctx: &mut RequestCtx,
    ingress_protocol: &str,
    op: busbar_core::handlers::Op,
    req_content_type: &str,
    usage_sink: Option<UsageSink>,
) -> Response {
    // Deadline propagated across hops.
    if request_ctx.expired(now()) {
        return ingress_error(
            ingress_protocol,
            StatusCode::SERVICE_UNAVAILABLE,
            KIND_OVERLOADED,
            DETAIL_REQUEST_TIMEOUT,
        );
    }

    // Loop guard: if this request already routed through this pool, stop (A→B→A).
    if request_ctx.is_pool_visited(pool_name) {
        return handle_status_503(&app, &[], now(), pool_name, ingress_protocol);
    }

    let Some(fallback_cands) = app.engine_tables().fallback_pools().get(pool_name).cloned() else {
        // Fallback pool not configured — cascade to Status503.
        return handle_status_503(&app, &[], now(), pool_name, ingress_protocol);
    };

    // Re-apply any compliance restrict from the primary pool against THIS fallback pool's own member
    // tags — the fallback pool is an independent membership, so without this the "restrictions hold
    // across failover" guarantee would break at the pool boundary. Fail closed (503) if a required
    // restrict leaves no eligible fallback lane.
    let fallback_cands = match request_ctx.enforce_restricts(&app, pool_name, fallback_cands) {
        Ok(c) => c,
        Err(name) => {
            diag_debug!(
                FALLBACK_RESTRICT_NO_ELIGIBLE_LANE,
                policy = name,
                pool = pool_name,
                "compliance restrict left no eligible lane in the fallback pool; fail closed \
                 rather than spill to an ineligible upstream"
            );
            return gate_rejected(ingress_error(
                ingress_protocol,
                StatusCode::SERVICE_UNAVAILABLE,
                KIND_OVERLOADED,
                "No upstream satisfies a required gate's restriction. Please retry shortly.",
            ));
        }
    };

    // Apply the FALLBACK pool's OWN `failover.exclusions`. Exclusions are a per-pool member
    // blocklist, and the fallback pool is an independent membership — the primary pool's blocklist
    // says nothing about it, and its own was never consulted, so a member the operator blocklisted
    // here could still be reached by spilling into this pool.
    let fallback_cands = match app
        .engine_tables()
        .pool_runtime()
        .get(pool_name)
        .and_then(|r| r.failover.as_ref())
        .or(app.engine_tables().failover_cfg().as_ref())
        .and_then(|f| f.exclusions.as_ref())
    {
        Some(excl) => fallback_cands
            .into_iter()
            .filter(|wl| {
                !excl
                    .iter()
                    .any(|m| m == &app.engine_tables().lanes()[wl.idx].model)
            })
            .collect(),
        None => fallback_cands,
    };

    // Mark before re-entering so a cycle back to this pool is detected.
    request_ctx.mark_pool_visited(pool_name);

    // Try the fallback pool's members (concurrency-aware, accumulating exclusions across hops).
    loop {
        if request_ctx.expired(now()) {
            return ingress_error(
                ingress_protocol,
                StatusCode::SERVICE_UNAVAILABLE,
                KIND_OVERLOADED,
                DETAIL_REQUEST_TIMEOUT,
            );
        }

        let Some((i, permit, probe_epoch)) =
            // Fallback-pool selection uses plain SWRR by design: routing POLICY applies to the PRIMARY
            // pool (where it shapes the normal-path lane choice); the fallback pool is the
            // already-degraded overflow path, so it deliberately selects with the unchanged inline SWRR
            // (`policy_order == None`) rather than re-running a policy over the spillover candidates.
            // The probe epoch is threaded into `forward_once` so its `ProbeGuard` releases the
            // single-flight probe OWNER-CHECKED (a dropped dispatch future no longer wedges the cell
            // HalfOpen), consistent with the `Admit.probe_epoch` discipline everywhere else.
            pick_among(&app, &fallback_cands, request_ctx, None, pool_name, None).await
        else {
            // Fallback pool itself exhausted — consult ITS on_exhausted config (multi-level
            // chains). The visited-set guarantees this recursion terminates.
            return Box::pin(handle_exhaustion_for_pool(
                app.clone(),
                &fallback_cands,
                now(),
                pool_name,
                body,
                caller_token,
                request_ctx,
                ingress_protocol,
                op,
                req_content_type,
                usage_sink,
            ))
            .await;
        };

        request_ctx.exclude(i);

        match forward_once(
            &app,
            i,
            permit,
            &body,
            caller_token,
            request_ctx.remaining(now()),
            ingress_protocol,
            // The fallback pool's cell is the one `pick_among` selected this member against (and
            // CAS-won the single-flight HalfOpen probe on) — record this attempt's breaker outcome
            // against THAT cell, not the default `""` cell.
            pool_name,
            // `pick_among`'s probe token: `Some(epoch)` when this dispatch WON a single-flight probe
            // (guard IS built), `None` for a Closed-ready no-op admit (no guard).
            probe_epoch,
            op,
            req_content_type,
            // Clone per attempt: a transient transport failure retries the next member, so the sink
            // must survive into the next loop iteration; only a successful stream consumes it.
            usage_sink.clone(),
            // The selected member's `reasoning` override from this fallback pool's candidate slice.
            fallback_cands
                .iter()
                .find(|w| w.idx == i)
                .and_then(|w| w.reasoning),
        )
        .await
        {
            Ok(resp) => return resp,
            Err(()) => continue, // transient transport error → try next member
        }
    }
}

/// LeastBad mode: actually route to the soonest-cooldown member even though it is Open
/// ("least-bad last resort"). Bypasses the breaker's usability check and acquires the
/// member's concurrency permit directly, then makes a single attempt (no failover from a
/// last-resort path). Logs loudly that this is a degraded route. Falls back to Status503 if
/// there is no candidate, the permit is unavailable, or the upstream is unreachable.
#[allow(clippy::too_many_arguments)] // plumbing: each arg is an independent request input
pub(crate) async fn handle_least_bad(
    app: &Arc<App>,
    cands: &[WeightedLane],
    now: u64,
    body: &Bytes,
    caller_token: Option<&str>,
    request_ctx: &RequestCtx,
    pool: &str,
    ingress_protocol: &str,
    op: busbar_core::handlers::Op,
    req_content_type: &str,
    usage_sink: Option<UsageSink>,
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
        .filter(|&idx| app.store.lane_admissible(idx))
        .collect();
    ranked.sort_by_key(|&idx| app.store.cooldown_remaining_in(pool, idx, now));

    // Bypass breaker usability for the last-resort path; grab the first free concurrency permit in
    // least-bad order. An at-capacity candidate (no permit) is SKIPPED to the next, not a 503.
    let mut dispatch = None;
    for idx in ranked {
        if let Some(permit) = app.store.try_acquire(idx) {
            dispatch = Some((idx, permit));
            break;
        }
    }
    let Some((soonest_idx, permit)) = dispatch else {
        // No admissible candidate at all, or EVERY admissible candidate is at-capacity — no degraded
        // dispatch is possible, so shed with 503 (+ Retry-After).
        return handle_status_503(app, cands, now, pool, ingress_protocol);
    };

    // least-bad is a DESIGNED degraded mode, entered per-request whenever the pool is exhausted, so a
    // per-request `warn!` spams under sustained load for expected behavior. Log at `debug!`; the
    // exhaustion signal proper is the 503 shed path + breaker telemetry.
    tracing::debug!(
        pool = %pool,
        lane = %app.engine_tables().lanes()[soonest_idx].model,
        cooldown_remaining_s = app.store.cooldown_remaining_in(pool, soonest_idx, now),
        "least-bad mode: routing to a degraded member (pool exhausted)"
    );

    match forward_once(
        app,
        soonest_idx,
        permit,
        body,
        caller_token,
        request_ctx.remaining(now),
        ingress_protocol,
        // The least-bad member was ranked via this pool's cell (`cooldown_remaining_in(pool, …)`), so
        // record its breaker outcome against the POOL cell.
        pool,
        // least_bad BYPASSES the breaker: it dispatches to an Open member via `try_acquire` and wins NO
        // probe, so it OWNS NO PROBE to guard — pass `None`. `forward_once` then builds NO `ProbeGuard`
        // at all, so a dropped least-bad future can NEVER release/revert a probe. Passing the cell's
        // CURRENT epoch here instead (as an armed guard) would be UNSAFE: if the cell is HalfOpen because
        // a concurrent PEER legitimately won the probe, that current epoch is the PEER's live epoch, and
        // an owner-checked release keyed on it would match and revert the peer's in-flight probe on drop
        // — breaking single-flight. `None` is the type-enforced statement of "owns no probe".
        None,
        op,
        req_content_type,
        usage_sink,
        // The least-bad member's `reasoning` override from this pool's candidate slice.
        cands
            .iter()
            .find(|w| w.idx == soonest_idx)
            .and_then(|w| w.reasoning),
    )
    .await
    {
        Ok(resp) => resp,
        Err(()) => handle_status_503(app, cands, now, pool, ingress_protocol),
    }
}

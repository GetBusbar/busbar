// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ON_EXHAUSTED DISPOSITION — what the model plane does AFTER the one selection loop finds nowhere
//! to send a request. Nothing here is a selection loop and nothing here sends: [`fallback`]
//! re-enters `pick_among` — the model plane's [`busbar_substrate::failover::walk_with`] call site —
//! for the spillover pool, [`queue`] waits for a permit and then re-asks the SAME
//! `try_admit_breaker` every plane asks, [`least_bad`] is the ONE documented breaker bypass in the
//! tree (a last-resort degraded route that owns no probe and says so), and every one of them
//! dispatches through [`crate::engine::attempt::attempt`] — the same attempt the hot loop runs —
//! via [`dispatch_degraded`], which maps the outcome the degraded way: an upstream error is relayed
//! to the client as-is; only an attempt that produced no response at all (transport error, attempt
//! cap) moves on to the next member.

use super::*;

pub(crate) mod fallback;
pub(crate) mod least_bad;
pub(crate) mod queue;

pub(crate) use fallback::handle_fallback_pool;
pub(crate) use least_bad::handle_least_bad;
pub(crate) use queue::handle_queue;

use crate::engine::attempt::{attempt, AttemptInput, AttemptOutcome, Hop};

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
    busbar_substrate::store::AT_CAPACITY_RECOVERY_FLOOR_MS / 1000;

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
fn retry_after_secs(
    host: &Arc<dyn EngineHost>,
    cands: &[WeightedLane],
    now: u64,
    pool: &str,
) -> u64 {
    let soonest_genuine_cooldown = cands
        .iter()
        // Deadness lives outside the cell FSM (a dead/budget-exhausted lane reports cooldown 0), so
        // filter to admissible members exactly as the old `find_soonest_cooldown` did.
        .filter(|wl| host.lane_store().lane_admissible(wl.idx))
        .map(|wl| host.lane_store().cooldown_remaining_in(pool, wl.idx, now))
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
    host: Arc<dyn EngineHost>,
    rt: Arc<NativeRuntime>,
    cands: &[WeightedLane],
    now: u64,
    pool_name: &str,
    body: Bytes,
    caller_token: Option<&str>,
    request_ctx: &mut RequestCtx,
    ingress_protocol: &str,
    op: busbar_substrate::handlers::Op,
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
    let mode = EngineTables::new(&rt)
        .on_exhausted_cfgs()
        .get(pool_name)
        .cloned()
        .unwrap_or(OnExhausted::Status503);

    let resp = match mode {
        OnExhausted::Status503 => handle_status_503(&host, cands, now, pool_name, ingress_protocol),
        OnExhausted::FallbackPool(ref fallback_pool) => {
            handle_fallback_pool(
                host.clone(),
                rt.clone(),
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
                &host,
                &rt,
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
                &host,
                &rt,
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

/// Status503 mode: return 503 with Retry-After header. The body is the ingress protocol's native
/// JSON error envelope (not `text/plain`) so an official SDK can decode it; the `Retry-After`
/// header is preserved so rate-aware clients still back off.
pub(crate) fn handle_status_503(
    host: &Arc<dyn EngineHost>,
    cands: &[WeightedLane],
    now: u64,
    pool: &str,
    ingress_protocol: &str,
) -> Response {
    let retry_after = retry_after_secs(host, cands, now, pool);

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

/// One degraded dispatch: the same [`attempt`] the hot loop runs, in the degraded posture, with the
/// degraded outcome map. `Ok(resp)` is a response for the client — a delivered body, a relayed
/// upstream error, or a pre-dispatch bail; `Err(())` means the upstream produced no response at
/// all (transport error, attempt cap) and the caller may try another member.
///
/// The body is re-parsed here for the per-lane rewrite/translate: an OPAQUE (non-JSON) body —
/// multipart/binary operations — parses to `None` and relays at the byte level; only a
/// JSON-Content-Type body that FAILS to parse is the caller's 400. The stream intent and the
/// streaming-usage flags are read exactly as the hot loop reads them, so a fallback or least-bad
/// stream to an OpenAI Chat lane is billed the same way a primary one is.
#[allow(clippy::too_many_arguments)] // plumbing: each arg is an independent request input
pub(crate) async fn dispatch_degraded(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    i: usize,
    permit: Permit,
    probe_epoch: Option<u64>,
    pool: &str,
    cands: &[WeightedLane],
    body: &Bytes,
    caller_token: Option<&str>,
    remaining_secs: u64,
    ingress_protocol: &str,
    op: busbar_substrate::handlers::Op,
    req_content_type: &str,
    usage_sink: &mut Option<UsageSink>,
    client_fwd: &[(axum::http::HeaderName, axum::http::HeaderValue)],
) -> Result<Response, ()> {
    let hop_v: Option<Value> = match busbar_substrate::json::parse(body) {
        Ok(v) => Some(v),
        Err(_) if !req_content_type.starts_with(APPLICATION_JSON) => None,
        Err(_) => {
            // Log a sanitized note for operators; never the parser's raw error (it embeds a fragment
            // of the input body) nor leak it into the client 400 body. Nothing was dispatched, so a
            // probe this dispatch won is released owner-checked here rather than by the attempt.
            tracing::debug!(detail = %busbar_substrate::json::parse_err_log(body.len()), "request body JSON parse failed");
            if let Some(epoch) = probe_epoch {
                host.lane_store().release_probe_owned_in(pool, i, epoch);
            }
            drop(permit);
            return Ok(ingress_error(
                ingress_protocol,
                StatusCode::BAD_REQUEST,
                KIND_INVALID_REQUEST,
                "We could not parse the JSON body of your request.",
            ));
        }
    };
    let body_is_json = hop_v.is_some();
    let wants_stream = hop_v.as_ref().map(|v| op.wants_stream(v)).unwrap_or(false);
    let client_include_usage = wants_stream
        && hop_v
            .as_ref()
            .and_then(|v| v.pointer("/stream_options/include_usage"))
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
    let client_has_stream_options = wants_stream
        && hop_v
            .as_ref()
            .map(|v| v.get("stream_options").is_some())
            .unwrap_or(false);
    // Gemini ingress streaming WITHOUT `?alt=sse` wants a JSON-array streamed body. Gated on the
    // ingress declaring the array shim (only a genuine Gemini client can ask) and on the operation
    // streaming at all, exactly as the hot loop gates it.
    let ingress_decl = busbar_substrate::proto::decl_for(ingress_protocol);
    let gemini_json_array = op.streaming()
        && ingress_decl.is_some_and(|d| d.uses_array_stream_shim)
        && ingress_decl
            .and_then(|d| d.dialect())
            .map(|di| {
                hop_v
                    .as_ref()
                    .map(|v| di.wants_array_stream(v))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
    // The breaker config for the routing pool cell this attempt records against (per-pool
    // settings, default fallback), shared with the streaming body for its mid-stream recording.
    let breaker_cfg = resolve_breaker_cfg(rt, pool);
    let outcome = attempt(AttemptInput {
        hop: Hop {
            host,
            rt,
            lane: i,
            pool_cell: pool,
            cands,
            body,
            pristine: false,
            body_is_json,
            req_content_type,
            ingress_protocol,
            egress_name: EngineTables::new(rt).lanes()[i].protocol,
            op,
            wants_stream,
            client_include_usage,
            client_has_stream_options,
            gemini_json_array,
            caller_token,
            upstream_creds: EngineTables::new(rt).pool_upstream_creds(pool),
            // The degraded path resolves no governance key (the caller token is a raw bearer
            // secret, never a principal id), so the audit principal is "anonymous".
            resolved_gov_key: None,
            remaining_secs,
            breaker_cfg: &breaker_cfg,
            client_fwd,
            // No routing-policy decision on a degraded hop: no transparency header. Telemetry is
            // labelled by the raw pool cell this attempt was selected against.
            chosen_policy_name: None,
            metric_pool: pool,
            degraded: true,
        },
        permit,
        probe_epoch,
        hop_v,
        usage_sink,
    })
    .await;
    match outcome {
        AttemptOutcome::Response(resp) | AttemptOutcome::Bail(resp) => Ok(resp),
        // The upstream answered and the breaker was told: relay that answer as-is.
        AttemptOutcome::Failed {
            relay: Some(resp), ..
        } => Ok(resp),
        // Nothing came back (transport error, attempt cap): the caller tries the next member, so
        // this counts as a failover.
        AttemptOutcome::Failed {
            relay: None,
            err_type,
            ..
        } => {
            host.telemetry_failover(pool, err_type);
            Err(())
        }
    }
}

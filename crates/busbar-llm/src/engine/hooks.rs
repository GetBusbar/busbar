use super::*;

// THE RUNNER MOVED. The projection / rewrite / decision-mapping half of this seam — 751 lines that
// named the hook contract and the neutral substrate and nothing of this crate — now lives in
// `busbar_core_policy::runner`, by identity: same items, same bodies, same behaviour, the
// `busbar_api::` spellings re-pointed to the `busbar_contract::` definitions they were already
// re-exports of. It is re-exported here at its historical short paths so every call site in this
// engine (`crate::engine::{read_hook_facts, apply_global_rewrites, capture_stage_shape, …}`) keeps
// resolving unchanged.
//
// WHAT STAYED: `decide_policy_order` below, and only it. It names this crate's own `NativeRuntime`,
// `WeightedLane`, `RequestCtx` and `EngineTables` — the routing engine's tables — so it rides the
// engine's own move rather than this one. When the engine moves, this file goes with it and the
// re-export above is the whole remainder.
use busbar_substrate::diagnostics::{
    ROUTING_POLICY_DEADLINE_EXCEEDED, ROUTING_POLICY_FAILED_ON_ERROR_FALLBACK,
};
use busbar_substrate::{diag_debug, diag_warn};

// Named at their historical short paths. Some are reached only from this crate's test build (the
// hook-seam batteries), which is what the attribute is for — the same idiom `engine/mod.rs` uses
// for every other re-export whose only shipped reader is a sibling module.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use busbar_core_policy::runner::{
    apply_global_rewrites, apply_rewrite_to_body, build_rewrite_request, capture_stage_shape,
    enforce_content_cap, fire_stage_taps, gate_rejected, map_decision, policy_fault_clear,
    policy_fault_enter, read_hook_facts, reject_kind_for_status, run_on_error_chain,
    spawn_bounded_tap, unreadable_body_message, GateRejected, HookFacts, HookIrRejected,
    PolicyOutcome,
};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn decide_policy_order(
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    resolved: &busbar_substrate::hooks::ResolvedPolicy,
    cands: &[WeightedLane],
    request_ctx: &RequestCtx,
    v: &Value,
    body: &[u8],
    content_type: &str,
    pool_name: &str,
    ingress_protocol: &str,
    operation: busbar_api::operation::Operation,
    wants_stream: bool,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&std::sync::Arc<busbar_api::VirtualKey>>,
) -> PolicyOutcome {
    // The hook CONTRACT projection types are api-owned; the resolved-policy carrier is neutral
    // substrate. Named at their canonical homes (the reverse-edge rule) rather than through the
    // core `hooks` re-export.
    use busbar_api::{Candidate, RoutingContext, RoutingDecision, RoutingRequest};
    use busbar_substrate::hooks::ResolvedPolicy;

    // A weighted/default pool resolves to `None` at config load (no policy object is constructed), so
    // the only `ResolvedPolicy` that can reach this seam is a constructed `Policy`.
    let (policy, on_error, on_error_chain, timeout, send_prompt, send_user, on_empty) =
        match resolved {
            ResolvedPolicy::Policy {
                policy,
                on_error,
                on_error_chain,
                timeout,
                send_prompt,
                send_user,
                on_empty,
            } => (
                policy,
                on_error,
                on_error_chain,
                *timeout,
                *send_prompt,
                *send_user,
                on_empty,
            ),
        };

    // The candidate set the policy ranks over = this pool's members MINUS the already-excluded ones
    // (configured exclusions). `idx` is the stable lane handle the ordered walk speaks.
    let mut live_buf: Vec<&WeightedLane> = Vec::with_capacity(cands.len());
    request_ctx.fill_candidates(cands, &mut live_buf);
    let live = &live_buf;
    if live.is_empty() {
        // Nothing to rank — let the loop's exhaustion handling take over (SWRR will also find none).
        return PolicyOutcome::Weighted;
    }

    // ONE governance key serves both consumers: the per-key rate headroom (always, same value
    // across candidates today — rate limits are per-key; see `Candidate.rate_headroom`) and, behind
    // `policy.send_user`, the caller identity projection. Prefer `resolved_gov_key` — the SAME key
    // `auth::mod`'s middleware already resolved and installed as `GovCtx.key` — over re-deriving it
    // here. Auth's resolution is authoritative: it consults the revocation denylist internally
    // (`verify_token`) and otherwise falls through to a SYNTHESIZED principal key for a GROUP/SSO
    // caller. The fallback below is reached only by the `#[cfg(test)]` bytes-only
    // `forward_with_pool` helper: every production ingress route installs a `GovCtx` via
    // `forward_with_pool_keyed` (`engine/mod.rs`), so `resolved_gov_key` is always `Some` whenever
    // `app.governance` is `Some` and this closure never runs there. Cfg-gated rather than deleted
    // per the house rule against dead code — the branch is provably unreachable outside tests (many
    // tests DO exercise the raw token-resolution path without building a full `GovCtx`), so it is
    // compiled out of the production binary entirely instead of shipping unreachable logic behind a
    // live-looking arm.
    // App-retype WEDGE 3: the governance/cost reaches now cross the host seam. `gov_handle`/`cost_handle`
    // are the opaque handles the host mints over the SAME `GovState`/`CostModel` the pre-flip
    // `app.governance`/`app.cost` named; `rate_headroom`/`budget_state` downcast them host-side and drive
    // the identical pure observation.
    let gov_handle = host.governance();
    let cost_handle = host.cost();
    let gov_key = resolved_gov_key.cloned().or_else(|| {
        #[cfg(test)]
        {
            // Test-only raw-token resolution rides the DATA-PLANE boundary (no audience), through the
            // test-support host seam (the neutral form of `App::governance.verify_token(...)`).
            caller_token.and_then(|tok| host.verify_token_test(tok))
        }
        #[cfg(not(test))]
        {
            let _ = caller_token;
            None
        }
    });
    let rate_headroom: Option<f64> = match (gov_handle.as_ref(), gov_key.as_ref()) {
        (Some(g), Some(key)) => host.rate_headroom(g, &cost_handle, key, Some(pool_name), now()),
        _ => None,
    };

    // THE ONE READ. Everything this seam projects — counts, sizes, the caller's cap, the end-user
    // id, and the content itself — comes from the IR the ingress protocol's own reader produced. A
    // body that reader REFUSES is the request's failure, surfaced as the gate's own first-class
    // rejection rather than screened as best-effort and forwarded upstream anyway.
    let facts = match read_hook_facts(v, body, content_type, ingress_protocol, Some(operation)) {
        Ok(f) => f,
        Err(HookIrRejected) => {
            return PolicyOutcome::RejectRequest {
                status: 400,
                message: unreadable_body_message().to_string(),
                name: policy.name(),
            }
        }
    };
    let shape = facts.shape();

    // `policy.send_user` opt-in (default off): project the caller identity — the virtual key's
    // id/name (from the resolved record, NEVER the token) plus the request's end-user field,
    // normalized by the reader from whichever field its dialect spells it in.
    let identity = if send_user {
        Some(busbar_api::CallerIdentity {
            key_id: gov_key.as_ref().map(|k| k.id.clone()),
            key_name: gov_key.as_ref().map(|k| k.name.clone()),
            user: facts.end_user(),
        })
    } else {
        None
    };

    // `policy.send_prompt` opt-in (default off): project the prompt content for the hook. The
    // allocation cost lives entirely behind the flag — a shape-only pool never runs this.
    let prompt = enforce_content_cap(send_prompt.then(|| facts.prompt()));

    let member_meta = EngineTables::new(rt)
        .pool_runtime()
        .get(pool_name)
        .map(|r| &r.members);

    let req = RoutingRequest {
        request_id: request_ctx.request_id,
        pool: pool_name,
        ingress_protocol,
        // The one scalar still read off the pristine body: the requested model is a ROUTING noun
        // rather than a conversation fact, and the chat IR does not model it (a path-model dialect
        // never carries it in the body at all, and reads `None` here exactly as it did before).
        requested_model: v.get("model").and_then(|m| m.as_str()),
        message_count: shape.turn_count,
        tool_count: shape.tool_count,
        has_tools: shape.has_tools,
        total_chars: shape.text_chars,
        system_chars: shape.system_chars,
        // Normalized by the reader from whichever field its dialect spells the cap in — including
        // the nested config object one dialect uses, which the raw-body projection could not see.
        // A SIZE signal, not a limit.
        max_tokens: shape.max_tokens,
        stream: wants_stream,
        prompt,
        identity,
        // Request-phase catalog signals: none wired to the decide path in this pass (the existing
        // core fields above already cover every request-shape signal a route policy reads today).
        signals: Default::default(),
    };

    // "Decision observability": the config generation's declared-signal
    // bitmask, resolved ONCE at config apply (`hooks::requested_signals`) and read here with a
    // single `u64` comparison — never recomputed per request. `is_empty()` short-circuits the
    // WHOLE candidate-signal loop below on the zero-cost default (no hook anywhere declared a
    // catalog signal): no `SignalBag` is ever written to, so none ever allocates.
    let requested = host.requested_signals();
    let now_ts = now();

    let candidates: Vec<Candidate> = live
        .iter()
        .map(|wl| {
            let lane = &EngineTables::new(rt).lanes()[wl.idx];
            let meta = member_meta.and_then(|m| m.get(&wl.idx));
            let mut signals = busbar_api::SignalBag::new();
            if !requested.is_empty() {
                // Both are PURE projections of state the breaker FSM already maintains on every
                // request/outcome regardless of declaration (see `LaneRuntime::
                // breaker_state_snapshot_in`/`error_rate_in`'s doc comments) — the gate below is
                // the compute-the-sliver check: the read runs ONLY when
                // declared, never call-then-discard.
                if requested.wants(busbar_api::Signal::CandidateBreakerState) {
                    let label = match host
                        .lane_store()
                        .breaker_state_snapshot_in(pool_name, wl.idx)
                    {
                        busbar_substrate::store::BreakerState::Closed => "closed",
                        busbar_substrate::store::BreakerState::Open { .. } => "open",
                        busbar_substrate::store::BreakerState::HalfOpen => "half_open",
                    };
                    signals.upsert(
                        busbar_api::Signal::CandidateBreakerState,
                        busbar_api::SignalValue::Str(std::borrow::Cow::Borrowed(label)),
                    );
                }
                if requested.wants(busbar_api::Signal::CandidateErrorRate) {
                    if let Some(rate) = host.lane_store().error_rate_in(pool_name, wl.idx, now_ts) {
                        signals.upsert(
                            busbar_api::Signal::CandidateErrorRate,
                            busbar_api::SignalValue::F64(rate),
                        );
                    }
                }
            }
            Candidate {
                idx: wl.idx,
                model: &lane.model,
                provider: &lane.provider,
                weight: wl.weight,
                context_max: lane.context_max,
                tier: meta.and_then(|m| m.tier.as_deref()),
                cost_per_mtok: meta.and_then(|m| m.cost_per_mtok),
                tags: meta.map(|m| m.tags.as_slice()).unwrap_or(&[]),
                latency_ms: host.lane_store().lane_latency_ms(wl.idx),
                available_concurrency: host.lane_store().available_permits(wl.idx),
                budget_remaining: host.lane_store().lane_budget_remaining(wl.idx),
                rate_headroom,
                signals,
            }
        })
        .collect();

    // The HOOK SEAM's budget projection: for the caller key and each ancestor
    // budget group, {bucket_id, spend_micros_at_current_rate, remaining_micros, window} - derived
    // fresh from the token ledger x the CURRENT rate card at this moment. Built ONLY here (a
    // routing-policy pool; the zero-cost default path never runs this fn), so its allocation stays
    // off the default hot path. Busbar exposes the READ surface only; downshifting to a cheaper
    // model on it is the hook's policy, never core's.
    let budget_chain: Vec<busbar_api::BudgetBucketState> =
        match (gov_handle.as_ref(), gov_key.as_ref()) {
            (Some(g), Some(key)) => host.budget_state(g, &cost_handle, key, now()),
            _ => Vec::new(),
        };
    let ctx = RoutingContext {
        pool: pool_name,
        // Lane-health-shaped budget signal (legacy v1 field): still not fed - the per-request
        // budget signal now rides the structured `budget` chain below.
        budget_remaining: None,
        budget: &budget_chain,
    };

    // Run the decision under a HARD wall-clock timeout (the policy is also asked to respect `budget`).
    // A timeout or an `Err` is coerced to `on_error`; an impl that simply has no opinion returns
    // `Ok(Abstain)`. The decision NEVER blocks past `timeout` and NEVER propagates an error to the
    // client.
    let decision: RoutingDecision = match tokio::time::timeout(
        timeout,
        policy.decide(&req, &candidates, &ctx, timeout),
    )
    .await
    {
        Ok(Ok(d)) => {
            // Success clears the fault window so a future fault re-warns on its first occurrence.
            policy_fault_clear(&format!("{}@{}", policy.name(), pool_name));
            d
        }
        // Policy errored: apply on_error — but LOG the error first. A hook binary that is down,
        // deadline-exceeded, or replying garbage would otherwise fail silently on every request
        // (the pool degrades to on_error with no operator-visible signal that the hook is broken).
        // Warn ONCE per fault window (reset on the next success); continued failures log `debug!` —
        // the bounded ROUTE_POLICY counters carry the per-request volume.
        Ok(Err(e)) => {
            let key = format!("{}@{}", policy.name(), pool_name);
            if policy_fault_enter(&key) {
                diag_warn!(
                    ROUTING_POLICY_FAILED_ON_ERROR_FALLBACK,
                    policy = policy.name(),
                    pool = pool_name,
                    error = %e,
                    "routing policy failed; applying on_error fallback"
                );
            } else {
                diag_debug!(
                    ROUTING_POLICY_FAILED_ON_ERROR_FALLBACK,
                    policy = policy.name(),
                    pool = pool_name,
                    error = %e,
                    "routing policy still failing; applying on_error fallback"
                );
            }
            return run_on_error_chain(
                on_error_chain,
                on_error,
                &req,
                &candidates,
                &ctx,
                policy.name(),
                pool_name,
            )
            .await;
        }
        // Timed out at the seam's own hard deadline: same fallback, same visibility. The policy/
        // transport stays cancel-safe — a dropped future on timeout is fine.
        Err(_) => {
            let key = format!("{}@{}", policy.name(), pool_name);
            if policy_fault_enter(&key) {
                diag_warn!(
                    ROUTING_POLICY_DEADLINE_EXCEEDED,
                    policy = policy.name(),
                    pool = pool_name,
                    timeout_ms = timeout.as_millis() as u64,
                    "routing policy deadline exceeded; applying on_error fallback"
                );
            } else {
                diag_debug!(
                    ROUTING_POLICY_DEADLINE_EXCEEDED,
                    policy = policy.name(),
                    pool = pool_name,
                    timeout_ms = timeout.as_millis() as u64,
                    "routing policy deadline still exceeded; applying on_error fallback"
                );
            }
            return run_on_error_chain(
                on_error_chain,
                on_error,
                &req,
                &candidates,
                &ctx,
                policy.name(),
                pool_name,
            )
            .await;
        }
    };

    map_decision(decision, policy.name(), &candidates, on_empty)
}

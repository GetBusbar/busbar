// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FALLBACK-POOL mode: route the request to a configured fallback pool's healthy member, with
//! multi-level chains (A→B→C) and the visited-pool loop guard.

use super::{dispatch_degraded, handle_exhaustion_for_pool, handle_status_503};
use crate::engine::*;

use busbar_substrate::diag_debug;
use busbar_substrate::diagnostics::FALLBACK_RESTRICT_NO_ELIGIBLE_LANE;

/// FallbackPool mode: actually route the request to a configured fallback pool's healthy
/// member. Supports multi-level chains (A→B→C): when the fallback pool is itself exhausted
/// it consults THAT pool's own `on_exhausted` config and re-enters. The `visited_pools` set
/// in `RequestCtx` is the loop guard — a chain that cycles back to an already-visited pool
/// (A→B→A) terminates with 503 instead of recursing forever.
#[allow(clippy::too_many_arguments)] // plumbing: each arg is an independent request input
pub(crate) async fn handle_fallback_pool(
    host: Arc<dyn EngineHost>,
    rt: Arc<NativeRuntime>,
    body: Bytes,
    caller_token: Option<&str>,
    pool_name: &str,
    request_ctx: &mut RequestCtx,
    ingress_protocol: &str,
    op: busbar_substrate::handlers::Op,
    req_content_type: &str,
    mut usage_sink: Option<UsageSink>,
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
        return handle_status_503(&host, &[], now(), pool_name, ingress_protocol);
    }

    let Some(fallback_cands) = EngineTables::new(&rt)
        .fallback_pools()
        .get(pool_name)
        .cloned()
    else {
        // Fallback pool not configured — cascade to Status503.
        return handle_status_503(&host, &[], now(), pool_name, ingress_protocol);
    };

    // Re-apply any compliance restrict from the primary pool against THIS fallback pool's own member
    // tags — the fallback pool is an independent membership, so without this the "restrictions hold
    // across failover" guarantee would break at the pool boundary. Fail closed (503) if a required
    // restrict leaves no eligible fallback lane.
    let fallback_cands = match request_ctx.enforce_restricts(&rt, pool_name, fallback_cands) {
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
    let fallback_cands = match EngineTables::new(&rt)
        .pool_runtime()
        .get(pool_name)
        .and_then(|r| r.failover.as_ref())
        .or(EngineTables::new(&rt).failover_cfg().as_ref())
        .and_then(|f| f.exclusions.as_ref())
    {
        Some(excl) => fallback_cands
            .into_iter()
            .filter(|wl| {
                !excl
                    .iter()
                    .any(|m| m == &EngineTables::new(&rt).lanes()[wl.idx].model)
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
            // The probe epoch is threaded into the attempt so its guard releases the single-flight
            // probe OWNER-CHECKED (a dropped dispatch future no longer wedges the cell HalfOpen).
            pick_among(&host, &rt, &fallback_cands, request_ctx, None, pool_name, None).await
        else {
            // Fallback pool itself exhausted — consult ITS on_exhausted config (multi-level
            // chains). The visited-set guarantees this recursion terminates.
            return Box::pin(handle_exhaustion_for_pool(
                host.clone(),
                rt.clone(),
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

        // The fallback pool's cell is the one `pick_among` selected this member against (and
        // CAS-won the single-flight HalfOpen probe on) — this attempt's breaker outcome is recorded
        // against THAT cell, not the default `""` cell. The usage sink is borrowed: a transient
        // transport failure retries the next member, so the sink must survive into the next loop
        // iteration; only a delivered response consumes it.
        match dispatch_degraded(
            &host,
            &rt,
            i,
            permit,
            probe_epoch,
            pool_name,
            &fallback_cands,
            &body,
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
            Ok(resp) => return resp,
            Err(()) => continue, // no upstream response at all → try next member
        }
    }
}

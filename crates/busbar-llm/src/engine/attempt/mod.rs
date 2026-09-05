// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE ATTEMPT — the single place in the workspace that sends an assembled request to an
//! upstream lane and turns what comes back into a breaker outcome and a client-facing result.
//!
//! Both the pooled hot path (`pipeline::forward_with_pool_parsed_inner`'s failover loop) and every
//! degraded exhaustion path (`exhaustion::{queue, fallback, least_bad}`) call [`attempt`] with an
//! [`AttemptInput`] describing the posture of this one hop, and map the [`AttemptOutcome`] with
//! their own policy: the hot loop fails over on a `Failed` outcome, the degraded callers relay the
//! upstream error when one is attached and try the next member only when nothing came back at all.
//! Everything that must happen exactly once per attempt — probe ownership, request assembly, the
//! send with its two deadlines, breaker recording, the trip emit, success bookkeeping, the budget
//! spend and its refund guard, the response build — lives under this module and nowhere else.
//!
//! The pieces, in call order: [`assemble`] (translate + credentials + auth + headers + streaming
//! usage injection), [`send`] (the attempt cap and the budget/ceiling deadline), [`classify`] (the
//! non-2xx and transport dispositions), [`respond`] (the delivered 2xx: bookkeeping and the body
//! wrapper), [`buffered`] (the buffered cross-protocol translate).

use super::*;

pub(crate) mod assemble;
pub(crate) mod buffered;
pub(crate) mod classify;
pub(crate) mod respond;
pub(crate) mod send;

#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use assemble::{
    inject_openai_stream_include_usage, inject_openai_stream_include_usage_pristine,
};
pub(crate) use buffered::{translate_response_cross_protocol, BudgetSpendGuard};
pub(crate) use send::{EgressSendError, SendOutcome};

/// Everything one attempt needs: the borrowed view of the hop plus the four owned parts. Kept as a
/// small struct on purpose — an `async fn` stores its argument twice (once as a capture, once as the
/// re-bound local), so [`attempt`] takes this apart in a plain prologue and captures only the
/// pieces in the future it returns.
pub(crate) struct AttemptInput<'a> {
    pub(crate) hop: Hop<'a>,
    /// The concurrency permit the caller acquired for the lane; held for the life of a streamed
    /// success body, dropped on every failure.
    pub(crate) permit: Permit,
    /// `Some(epoch)` when the caller's selection WON a single-flight recovery probe on the
    /// `(pool_cell, lane)` cell — this attempt then owns its release. `None` = no probe owned, no
    /// guard built (a Closed-cell dispatch, or the least-bad path that bypasses the breaker).
    pub(crate) probe_epoch: Option<u64>,
    /// This hop's parsed request DOM; `None` for an opaque (non-JSON) body or a pristine hop.
    pub(crate) hop_v: Option<Value>,
    /// Where a delivered response bills its tokens. Borrowed so only the attempt that actually
    /// delivers a body consumes it; a failed attempt leaves it for the next hop.
    pub(crate) usage_sink: &'a mut Option<UsageSink>,
}

/// What one attempt produced.
pub(crate) enum AttemptOutcome {
    /// A response for the client: a delivered 2xx body, a relayed client-fault or passthrough 40x,
    /// or the normalized auth-failure envelope for a hard-down lane credential.
    Response(Response),
    /// The upstream did not serve this request and the lane's breaker has been told why. The caller
    /// decides between failing over and relaying: `relay` carries the shaped upstream error when the
    /// caller asked for it (`degraded`) and there was a response to relay (never for a transport
    /// error or an attempt timeout).
    Failed {
        disposition: Disposition,
        err_type: &'static str,
        relay: Option<Response>,
    },
    /// The attempt could not be assembled (internal error before any send); nothing was recorded
    /// against the breaker. The caller returns this response.
    Bail(Response),
}

/// The borrowed, `Copy` view of one hop that every attempt stage shares. The fields that differ
/// between the hot loop and the degraded callers are plain inputs here, so the two postures are
/// data, not code: `pristine` carries the hot loop's head short-circuit decision, `cands` supplies
/// the pool-member overrides (attempt timeout, reasoning), `metric_pool` and `chosen_policy_name`
/// carry the telemetry label and the routing-policy transparency header the hot loop resolved, and
/// `degraded` selects the degraded-path diagnostics and asks for the relay response a degraded
/// caller returns instead of failing over.
#[derive(Clone, Copy)]
pub(crate) struct Hop<'a> {
    pub(crate) host: &'a Arc<dyn EngineHost>,
    pub(crate) rt: &'a Arc<NativeRuntime>,
    pub(crate) lane: usize,
    pub(crate) pool_cell: &'a str,
    pub(crate) cands: &'a [WeightedLane],
    pub(crate) body: &'a Bytes,
    pub(crate) pristine: bool,
    pub(crate) body_is_json: bool,
    pub(crate) req_content_type: &'a str,
    pub(crate) ingress_protocol: &'a str,
    /// The lane's egress protocol name, read once.
    pub(crate) egress_name: &'a str,
    pub(crate) op: busbar_substrate::handlers::Op,
    pub(crate) wants_stream: bool,
    pub(crate) client_include_usage: bool,
    pub(crate) client_has_stream_options: bool,
    pub(crate) gemini_json_array: bool,
    pub(crate) caller_token: Option<&'a str>,
    pub(crate) upstream_creds: busbar_api::UpstreamCreds,
    pub(crate) resolved_gov_key: Option<&'a Arc<busbar_api::VirtualKey>>,
    pub(crate) remaining_secs: u64,
    pub(crate) breaker_cfg: &'a Arc<busbar_substrate::store::BreakerCfg>,
    pub(crate) client_fwd: &'a [(axum::http::HeaderName, axum::http::HeaderValue)],
    pub(crate) chosen_policy_name: Option<&'static str>,
    pub(crate) metric_pool: &'a str,
    pub(crate) degraded: bool,
}

impl<'a> Hop<'a> {
    pub(crate) fn lane_row(&self) -> &'a Lane {
        &EngineTables::new(self.rt).lanes()[self.lane]
    }
}

/// The one attempt. See the module doc for what lives here and why. A plain fn returning an
/// `async move` block (not an `async fn`) so the input is taken apart once, in the prologue, and the
/// future captures only the pieces — the argument is not stored a second time as a re-bound local.
pub(crate) fn attempt<'a>(
    a: AttemptInput<'a>,
) -> impl std::future::Future<Output = AttemptOutcome> + 'a {
    let AttemptInput {
        hop,
        permit,
        probe_epoch,
        hop_v,
        usage_sink,
    } = a;
    async move {
        let (host, rt, lane, pool_cell, cands, remaining_secs) = (
            hop.host,
            hop.rt,
            hop.lane,
            hop.pool_cell,
            hop.cands,
            hop.remaining_secs,
        );
        // Probe ownership for the whole attempt window, armed only when this dispatch won a probe. If
        // this future is dropped mid-await (client disconnect) the guard releases the probe owner-checked,
        // so the cell never wedges HalfOpen; it stays armed across every failure exit (each records an
        // outcome first, making the release a safe no-op) and is disarmed once a success is recorded.
        let mut probe_guard = probe_epoch.map(|epoch| crate::engine::select::ProbeGuard {
            store: host.lane_store(),
            pool: pool_cell,
            lane,
            armed: true,
            probe_epoch: epoch,
        });

        // Assemble: translate, inject streaming usage, credentials, auth, headers, the egress request.
        // A failure here is an internal error before any send: nothing is recorded against the breaker
        // and the armed probe guard releases the probe on return.
        let hreq = match assemble::build(&hop, hop_v).await {
            Ok(hreq) => hreq,
            Err(resp) => {
                drop(permit);
                return AttemptOutcome::Bail(resp);
            }
        };

        // Send, under the per-attempt hang cap and the budget (non-stream) / client-ceiling (stream)
        // deadline. The send verb below is the only upstream send in the workspace.
        let send_deadline = send::deadline(&hop);
        let attempt_ms =
            effective_attempt_timeout_ms(cands, lane, hop.lane_row().attempt_timeout_ms);
        let upstream_started = std::time::Instant::now();
        // The attempt cap races the send inline (no helper): the client's request future is large
        // and an `async fn` wrapper would hold a second copy of it.
        let send_fut = async {
            let send = EngineTables::new(rt).client().get().request(hreq);
            match attempt_ms {
                Some(ms) => {
                    let cap = attempt_cap(ms, remaining_secs);
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
                drop(permit);
                return classify::attempt_timeout(&hop, ms);
            }
        };
        record_upstream_rtt(upstream_started.elapsed());
        // Every buffered read of this response rides the same deadline as the send: one instant, one
        // envelope.
        let read_deadline = send_deadline;

        let r = match res {
            Err(e) => {
                drop(permit);
                return classify::transport_error(&hop, &e);
            }
            Ok(r) => r,
        };
        let status = r.status();
        if !status.is_success() {
            return classify::non_2xx(&hop, r, status, read_deadline, permit).await;
        }
        AttemptOutcome::Response(
            respond::deliver(
                &hop,
                r,
                status,
                read_deadline,
                permit,
                &mut probe_guard,
                usage_sink,
                upstream_started,
            )
            .await,
        )
    }
}

/// The identity harness for this seam: `attempt()` against the legacy degraded-path twin, over the
/// scripted upstreams and every ingress dialect. Registered here (not from `engine/mod.rs`'s test
/// list) so the seam's own module owns its proof.
#[cfg(test)]
#[path = "../tests/attempt_identity_tests.rs"]
mod attempt_identity_tests;

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RESPOND — the delivered 2xx. Records the lane success against the routing pool cell (which
//! closes a HalfOpen cell and clears its probe), hands probe ownership to the response, folds the
//! time-to-headers into the latency signal, spends one unit of the lane's request budget under a
//! refund guard, then either buffers and translates a non-stream cross-protocol body or wraps the
//! upstream body in the first-byte-tracking stream wrapper that owns the permit, the mid-stream
//! breaker recording, the usage tap and the budget refund from here on.

use super::Hop;
use crate::engine::*;

/// Deliver a 2xx upstream response to the client. A plain fn returning an `async move` block so
/// the response is captured once, not re-bound as a local; the synchronous bookkeeping (success,
/// probe hand-off, latency, budget spend) runs in the prologue, before the first await.
#[allow(clippy::too_many_arguments)]
pub(super) fn deliver<'a>(
    hop: &'a Hop<'a>,
    r: http::Response<hyper::body::Incoming>,
    status: StatusCode,
    read_deadline: tokio::time::Instant,
    permit: Permit,
    probe_guard: &mut Option<crate::engine::select::ProbeGuard<'_>>,
    usage_sink: &'a mut Option<UsageSink>,
    upstream_started: std::time::Instant,
) -> impl std::future::Future<Output = Response> + 'a {
    let (host, rt, i, pool) = (hop.host, hop.rt, hop.lane, hop.pool_cell);
    let _rec = busbar_substrate::profile::start(busbar_substrate::profile::Stage::RecordSuccess);
    // The success feeds the per-lane `ok` counter and the breaker's success window on the ROUTING
    // POOL cell (a HalfOpen lane served here recovers that cell to Closed and clears its probe).
    host.lane_store().record_success_in(pool, i);
    // The request now owns the probe through its recorded outcome; from here the body (or its own
    // mid-stream failure recording) is responsible for the cell, so the guard must not also release.
    if let Some(g) = probe_guard.as_mut() {
        g.armed = false;
    }
    // Time-to-headers into the lane's latency signal (the `fastest` routing input). Measured to
    // response headers — a bounded proxy that never waits out a streaming body.
    host.lane_store()
        .record_latency_in(pool, i, upstream_started.elapsed().as_secs_f64() * 1000.0);
    // Cost accounting, not admission: consume one unit of the lane's lifetime request budget. The
    // result is BOUND to the refund decision — `refund_budget` unconditionally adds, so refunding a
    // no-op spend would push the budget above its cap. `true` for an unlimited lane (a no-op spend
    // and a no-op refund, so it neither over- nor under-counts).
    let budget_spent = host.lane_store().spend_budget(i);
    // Refund guard for the buffered path's spend → read window: armed now, disarmed at every exit
    // that must KEEP the charge, and handed off (disarmed without refunding) to the stream wrapper,
    // which owns the cancellation-safe refund for a streamed body.
    let mut budget_guard = BudgetSpendGuard {
        store: host.lane_store(),
        lane: i,
        armed: budget_spent,
    };
    drop(_rec);
    async move {
        let _resp = busbar_substrate::profile::start(busbar_substrate::profile::Stage::RespBuild);
        let _rb_pre = busbar_substrate::profile::start(busbar_substrate::profile::Stage::RbPre);

        let ct = r.headers().get(CONTENT_TYPE).cloned();
        // The upstream's primary relayed id (bedrock `x-amzn-RequestId`, anthropic `request-id`),
        // captured before the body is consumed: forwarded verbatim on a same-protocol passthrough,
        // synthesized on a cross-protocol stream, so the header is always there where a real endpoint
        // would carry it.
        let upstream_relay_id = ingress_relayed_response_header_names(hop.ingress_protocol)
            .first()
            .and_then(|name| r.headers().get(*name))
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        let is_sse = ct
            .as_ref()
            .map(|h| is_streaming_content_type(h.to_str().unwrap_or("")))
            .unwrap_or(false);
        let cross_protocol = hop.ingress_protocol != hop.egress_name;

        // A non-stream cross-protocol response is buffered whole and translated egress → IR → ingress.
        // A same-protocol buffered response also takes this path when the client asked to stream:
        // the client's dialect stream (SSE framing, metering-at-end) must be served even though the
        // upstream itself ignored `stream` and answered one JSON body — the raw same-protocol relay
        // below only fits a client that did not ask for a stream. Boxed: this arm is cold and its
        // future is large relative to the pinned hot path.
        if !is_sse && (cross_protocol || hop.wants_stream) {
            return Box::pin(translate_response_cross_protocol(
                host,
                rt,
                i,
                hop.ingress_protocol,
                hop.op,
                pool,
                hop.breaker_cfg,
                r,
                read_deadline,
                permit,
                &mut budget_guard,
                usage_sink.take(),
                status,
                hop.wants_stream,
                hop.gemini_json_array,
                upstream_started,
                hop.chosen_policy_name,
                hop.degraded,
            ))
            .await;
        }

        // Streaming (or same-protocol non-stream): the first-byte-tracking wrapper. ONE
        // registry-resolved translator factory: same-protocol SSE builds the verbatim re-emit with the
        // usage tap, cross-protocol SSE the reframing translator, anything else `None` (raw passthrough).
        // Named directly from this crate rather than through the installable pointer: an uninstalled
        // pointer would silently drop both the reframing and the stream-end metering.
        let translate = crate::proto_stream::new_stream_translator(
            hop.ingress_protocol,
            hop.egress_name,
            is_sse,
        );
        // The upstream stream always carries a trailing usage chunk (busbar injected the opt-in); the
        // framing surfaces it to the client ONLY when the client itself opted in.
        let translate = translate.map(|mut t| {
            t.set_client_include_usage(hop.client_include_usage);
            t
        });
        let json_array = (hop.gemini_json_array && is_sse)
            .then(|| {
                busbar_substrate::proto::decl_for(hop.ingress_protocol)
                    .and_then(|d| d.dialect())
                    .and_then(|dc| dc.make_array_stream_framer())
            })
            .flatten();
        // The stream wrapper owns the refund decision from here (via `budget_spent`).
        budget_guard.disarm();
        drop(_rb_pre);
        let _rb_body = busbar_substrate::profile::start(busbar_substrate::profile::Stage::RbBody);
        let _rb_new = busbar_substrate::profile::start(busbar_substrate::profile::Stage::RbNew);
        let upstream_stream = {
            use http_body_util::BodyExt;
            r.into_body().into_data_stream()
        };
        let guarded_body = FirstByteBody::new(
            upstream_stream,
            is_sse,
            hop.ingress_protocol,
            hop.op,
            permit,
            read_deadline,
            host.clone(),
            rt.clone(),
            i,
            hop.breaker_cfg.clone(),
            pool,
            translate,
            json_array,
            usage_sink.take(),
            budget_spent,
        );
        let axum_body = guarded_body.into_body();
        drop(_rb_new);
        let _rb_finish =
            busbar_substrate::profile::start(busbar_substrate::profile::Stage::RbFinish);
        let _rbf_build =
            busbar_substrate::profile::start(busbar_substrate::profile::Stage::RbfBuild);
        let mut rb = Response::builder().status(status);
        // Cross-protocol streaming reframes the body to the client's format, so the CT must be the
        // ingress client's; same-protocol keeps the upstream CT verbatim.
        if hop.gemini_json_array && is_sse {
            rb = rb.header(CONTENT_TYPE, APPLICATION_JSON);
        } else {
            match (cross_protocol && is_sse)
                .then(|| ingress_stream_content_type(hop.ingress_protocol))
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
        drop(_rbf_build);
        let _rbf_attach =
            busbar_substrate::profile::start(busbar_substrate::profile::Stage::RbfAttach);
        rb = maybe_attach_response_request_id(
            rb,
            hop.ingress_protocol,
            upstream_relay_id.as_deref(),
        );
        // Which routing policy chose this target (a no-op on the default path / when none did).
        rb = maybe_attach_route_policy(rb, hop.chosen_policy_name, &hop.lane_row().model);
        drop(_rbf_attach);
        let _rbf_body = busbar_substrate::profile::start(busbar_substrate::profile::Stage::RbfBody);
        rb.body(axum_body)
            .unwrap_or_else(|_| status.into_response())
    }
}

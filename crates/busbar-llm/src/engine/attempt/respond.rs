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
    let _rec = busbar_kernel::profile::start(busbar_kernel::profile::Stage::RecordSuccess);
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
    let latency_ms = upstream_started.elapsed().as_secs_f64() * 1000.0;
    host.lane_store().record_latency_in(pool, i, latency_ms);
    // The same sample into the lane's p95 reservoir, collected ONLY while the config generation
    // declares `CandidateLatencyP95Ms` — an undeclared deployment never allocates or writes it.
    if host
        .requested_signals()
        .wants(busbar_contract::signal::Signal::CandidateLatencyP95Ms)
    {
        hop.lane_row().record_latency_sample(latency_ms);
    }
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
        let _resp = busbar_kernel::profile::start(busbar_kernel::profile::Stage::RespBuild);
        // THE REPORT-BACK CELL for this delivery. Handed to whichever tap ends this response — the
        // buffered translate below, or the streaming body wrapper further down — and RIDDEN BACK on
        // the response itself, so the steps that ran before the tap existed can read what it saw
        // without the plane growing a second carry between them.
        let tap = TapCell::new();
        let _rb_pre = busbar_kernel::profile::start(busbar_kernel::profile::Stage::RbPre);

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
            .map(|h| is_stream_content_type(h.to_str().unwrap_or("")))
            .unwrap_or(false);

        // The ORIGINAL ingress request body, parsed once (when it was JSON), so a cross-protocol
        // response can be threaded a request-echo context: a dialect whose response spec requires
        // certain members to MIRROR the request (OpenAI Responses: `temperature`, `top_p`,
        // `instructions`, `metadata`, `tool_choice`, `parallel_tool_calls`, `tools`) answers with the
        // client's actual values instead of the spec's bare defaults. `None` for a non-JSON ingress
        // body (the opaque/audio bridge) or a body that fails to parse.
        let ingress_request_body: Option<Value> = hop
            .body_is_json
            .then(|| busbar_plane_llm::codec::json::parse::<Value>(hop.body).ok())
            .flatten();

        // A non-stream cross-protocol response is buffered whole and translated egress → IR → ingress.
        // A same-protocol buffered response also takes this path when the client asked to stream:
        // the client's dialect stream (SSE framing, metering-at-end) must be served even though the
        // upstream itself ignored `stream` and answered one JSON body — the raw same-protocol relay
        // below only fits a client that did not ask for a stream. Boxed: this arm is cold and its
        // future is large relative to the pinned hot path.
        if crate::engine::xchg::reply::relay::takes_whole(
            hop.ingress_protocol,
            hop.egress_name,
            is_sse,
            hop.wants_stream,
        ) {
            return deliver_buffered(
                hop,
                host,
                rt,
                i,
                pool,
                r,
                status,
                read_deadline,
                permit,
                &mut budget_guard,
                usage_sink,
                upstream_started,
                ingress_request_body,
                tap,
            )
            .await;
        }

        deliver_stream(
            hop,
            host,
            rt,
            i,
            pool,
            r,
            status,
            read_deadline,
            permit,
            budget_guard,
            budget_spent,
            usage_sink,
            ingress_request_body,
            ct,
            is_sse,
            upstream_relay_id,
            tap,
            _rb_pre,
        )
        .await
    }
}

/// The `!is_sse && (cross_protocol || wants_stream)` delivery: buffer the whole upstream body and
/// translate egress → IR → ingress, then ride the finished tap back on the response. Pure extraction
/// of the buffered branch of [`deliver`]; the caller's `budget_guard` is borrowed so the arm that
/// keeps/refunds the charge is the same guard the streaming sibling would have used.
#[allow(clippy::too_many_arguments)]
async fn deliver_buffered(
    hop: &Hop<'_>,
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    i: usize,
    pool: &str,
    r: http::Response<hyper::body::Incoming>,
    status: StatusCode,
    read_deadline: tokio::time::Instant,
    permit: Permit,
    budget_guard: &mut BudgetSpendGuard<'_>,
    usage_sink: &mut Option<UsageSink>,
    upstream_started: std::time::Instant,
    ingress_request_body: Option<Value>,
    tap: TapCell,
) -> Response {
    let mut resp = Box::pin(translate_response_cross_protocol(
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
        budget_guard,
        usage_sink.take(),
        status,
        hop.wants_stream,
        hop.gemini_json_array,
        upstream_started,
        hop.chosen_policy_name,
        hop.degraded,
        // MOVED, not cloned: this arm returns below, so nothing downstream can read the
        // parsed body again — and a clone here is a second full per-node materialization of
        // a value the CLIENT chose the size of, on every buffered delivery. The live-stream
        // twin further down is on the other side of that return and still borrows it.
        ingress_request_body,
        &tap,
    ))
    .await;
    // The buffered tap has already finished by the time this returns — a non-stream body is
    // read whole before it is translated — so the cell it rides back on is FILLED, and the
    // Route step reads the serving lane, the usage and the finish class off it without
    // waiting for anything.
    resp.extensions_mut().insert(tap);
    resp
}

/// The streaming (or same-protocol non-stream) delivery: the first-byte-tracking wrapper that owns
/// the permit, the mid-stream breaker recording, the usage tap and the budget refund from here on.
/// Pure extraction of the streaming branch of [`deliver`]; `budget_guard` is MOVED in (disarmed
/// here, handed off to the wrapper via `budget_spent`) and `rb_pre` is threaded so the RbPre span
/// still closes at the exact point the inline code dropped it.
#[allow(clippy::too_many_arguments)]
async fn deliver_stream(
    hop: &Hop<'_>,
    host: &Arc<dyn EngineHost>,
    rt: &Arc<NativeRuntime>,
    i: usize,
    pool: &str,
    r: http::Response<hyper::body::Incoming>,
    status: StatusCode,
    read_deadline: tokio::time::Instant,
    permit: Permit,
    mut budget_guard: BudgetSpendGuard<'_>,
    budget_spent: bool,
    usage_sink: &mut Option<UsageSink>,
    ingress_request_body: Option<Value>,
    ct: Option<axum::http::HeaderValue>,
    is_sse: bool,
    upstream_relay_id: Option<String>,
    tap: TapCell,
    rb_pre: Option<busbar_kernel::profile::Timer>,
) -> Response {
    // Streaming (or same-protocol non-stream): the first-byte-tracking wrapper over the plane's
    // relay parts — the translator the dialect pair names (reframing across dialects, a verbatim
    // re-emit with the usage tap within one, `None` for a raw passthrough), told the client's usage
    // opt-in and request echo, and the JSON-array framer for a client that asked for an array.
    let (translate, json_array) =
        crate::engine::xchg::reply::relay::parts(&crate::engine::xchg::reply::relay::RelayCtx {
            ingress: hop.ingress_protocol,
            egress: hop.egress_name,
            far_is_stream: is_sse,
            json_array: hop.gemini_json_array,
            client_include_usage: hop.client_include_usage,
            request: ingress_request_body.as_ref(),
            handler: hop.op.op_handler,
            meter: usage_sink.is_some(),
        });
    // The stream wrapper owns the refund decision from here (via `budget_spent`).
    budget_guard.disarm();
    drop(rb_pre);
    let _rb_body = busbar_kernel::profile::start(busbar_kernel::profile::Stage::RbBody);
    let _rb_new = busbar_kernel::profile::start(busbar_kernel::profile::Stage::RbNew);
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
        tap.clone(),
    );
    let axum_body = guarded_body.into_body();
    drop(_rb_new);
    let _rb_finish = busbar_kernel::profile::start(busbar_kernel::profile::Stage::RbFinish);
    let _rbf_build = busbar_kernel::profile::start(busbar_kernel::profile::Stage::RbfBuild);
    let mut rb = Response::builder().status(status);
    // The content type is the plane's: a JSON array, the client's own streamed content type across
    // dialects, else the upstream's verbatim.
    match crate::engine::xchg::reply::relay::content_type(
        hop.ingress_protocol,
        hop.egress_name,
        is_sse,
        hop.gemini_json_array,
    ) {
        crate::engine::xchg::reply::relay::ContentType::Json => {
            rb = rb.header(CONTENT_TYPE, APPLICATION_JSON);
        }
        crate::engine::xchg::reply::relay::ContentType::Ingress(client_ct) => {
            rb = rb.header(CONTENT_TYPE, client_ct);
        }
        crate::engine::xchg::reply::relay::ContentType::Far => {
            if let Some(ct) = ct {
                rb = rb.header(CONTENT_TYPE, ct);
            }
        }
    }
    drop(_rbf_build);
    let _rbf_attach = busbar_kernel::profile::start(busbar_kernel::profile::Stage::RbfAttach);
    rb = maybe_attach_response_request_id(rb, hop.ingress_protocol, upstream_relay_id.as_deref());
    // Which routing policy chose this target (a no-op on the default path / when none did).
    rb = maybe_attach_route_policy(rb, hop.chosen_policy_name, &hop.lane_row().model);
    drop(_rbf_attach);
    let _rbf_body = busbar_kernel::profile::start(busbar_kernel::profile::Stage::RbfBody);
    let mut resp = rb
        .body(axum_body)
        .unwrap_or_else(|_| status.into_response());
    // The cell rides out EMPTY here and stays empty until the body ends: a stream is served on
    // its headers and its figures do not exist yet. That is the point — the Route step returns
    // while this is still in flight, and the cell is what lets the tap answer it afterwards.
    resp.extensions_mut().insert(tap);
    resp
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CLASSIFY — what a failed attempt means for the lane's breaker and for the client. One copy of
//! the disposition rules for every path: a transport error or an attempt-cap expiry records a
//! transient failure; a non-2xx runs the two-stage classifier (the egress cell's `extract_error`
//! → `normalize_raw_error` over the lane's `error_map` → `breaker::classify`) and records per
//! disposition. A client fault (the caller's own bad input, or a passthrough caller's own key
//! failing) never penalizes the lane; a hard-down (auth/billing) trips it in every cell; a
//! transient trips it in the routing pool's cell with the upstream's `Retry-After` as the floor.

use super::{AttemptOutcome, Hop};
use crate::engine::*;

use busbar_substrate::diagnostics::{
    ATTEMPT_TIMEOUT_DEGRADED, ATTEMPT_TIMEOUT_FAILOVER, LANE_HARD_DOWN,
};
use busbar_substrate::{diag_debug, diag_warn};

/// The attempt cap fired before response headers arrived: a transient failure on the pool cell,
/// counted as its own `attempt_timeout` series so operators can see hang-hops separately.
pub(super) fn attempt_timeout(hop: &Hop<'_>, ms: u64) -> AttemptOutcome {
    let (host, rt, i, pool) = (hop.host, hop.rt, hop.lane, hop.pool_cell);
    let tripped =
        host.lane_store()
            .record_transient_in(pool, i, ERR_NET_TIMEOUT, hop.breaker_cfg, None);
    if tripped {
        emit_breaker_trip(host, rt, pool, i);
    }
    host.telemetry_upstream_failure(hop.metric_pool, i, DISPOSITION_ATTEMPT_TIMEOUT);
    if hop.degraded {
        diag_debug!(
            ATTEMPT_TIMEOUT_DEGRADED,
            pool = %pool,
            lane = %hop.lane_row().model,
            attempt_timeout_ms = ms,
            "no response headers within the attempt cap (degraded path)"
        );
    } else {
        diag_debug!(
            ATTEMPT_TIMEOUT_FAILOVER,
            pool = %pool,
            lane = %hop.lane_row().model,
            attempt_timeout_ms = ms,
            "no response headers within the attempt cap; failing over"
        );
    }
    AttemptOutcome::Failed {
        disposition: Disposition::TransientUpstream,
        err_type: DISPOSITION_ATTEMPT_TIMEOUT,
        relay: None,
    }
}

/// A pre-response transport error (refused, reset, TLS failure, budget/connect timeout): a
/// transient failure on the pool cell, split timeout-vs-connect exactly as the old client did.
pub(super) fn transport_error(hop: &Hop<'_>, e: &EgressSendError) -> AttemptOutcome {
    let (host, rt, i, pool) = (hop.host, hop.rt, hop.lane, hop.pool_cell);
    let err_type = if e.is_timeout() {
        ERR_NET_TIMEOUT
    } else {
        ERR_NET_CONNECT
    };
    let tripped = host
        .lane_store()
        .record_transient_in(pool, i, err_type, hop.breaker_cfg, None);
    // A threshold-based Closed→Open trip is counted once; `record_transient_in` returns `true` only
    // on a logical trip (not a HalfOpen reopen or an already-Open no-op).
    if tripped {
        emit_breaker_trip(host, rt, pool, i);
    }
    host.telemetry_upstream_failure(hop.metric_pool, i, DISPOSITION_TRANSIENT);
    AttemptOutcome::Failed {
        disposition: Disposition::TransientUpstream,
        err_type,
        relay: None,
    }
}

/// The captured upstream error response, read and ready to classify or relay.
struct UpstreamError {
    status: StatusCode,
    ct: Option<axum::http::HeaderValue>,
    retry_after_secs: Option<u64>,
    /// The upstream's relayed request-id-class headers, for a same-protocol relay on an ingress
    /// that forwards them verbatim (bedrock: `x-amzn-requestid` + `x-amzn-errortype`).
    amzn_headers: Vec<(axum::http::HeaderName, axum::http::HeaderValue)>,
    /// The upstream's PRIMARY relayed id (anthropic `request-id`), forwarded or synthesized.
    relay_id: Option<String>,
    bytes: Bytes,
}

impl UpstreamError {
    /// Everything the relay and the classifier need from the response HEADERS, captured before the
    /// body is consumed. The body is read by the caller (one `.await`, no nested future holding a
    /// second copy of the response).
    fn from_headers(
        hop: &Hop<'_>,
        r: &http::Response<hyper::body::Incoming>,
        status: StatusCode,
    ) -> Self {
        let ct = r.headers().get(CONTENT_TYPE).cloned();
        // The upstream `Retry-After` header (whole seconds) is captured here: the per-protocol
        // `extract_error` only sees the body, so the cooldown floor would otherwise be dropped.
        let retry_after_secs = busbar_substrate::breaker::parse_retry_after(r.headers());
        let amzn_headers = if ingress_relays_amzn_headers(hop.ingress_protocol) {
            ingress_relayed_response_header_names(hop.ingress_protocol)
                .iter()
                .filter_map(|name| {
                    let v = r.headers().get(*name)?.clone();
                    Some((axum::http::HeaderName::from_static(name), v))
                })
                .collect()
        } else {
            Vec::new()
        };
        let relay_id = ingress_relayed_response_header_names(hop.ingress_protocol)
            .first()
            .and_then(|name| r.headers().get(*name))
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        Self {
            status,
            ct,
            retry_after_secs,
            amzn_headers,
            relay_id,
            bytes: Bytes::new(),
        }
    }

    /// The client-facing relay of this error. Cross-protocol: reshaped into the ingress protocol's
    /// native envelope (relaying the egress provider's native error body to a different-protocol
    /// SDK is a foreign-format leak). Same-protocol: the upstream body + Content-Type verbatim,
    /// with the native request-id header(s) a real endpoint carries.
    fn relay(&self, hop: &Hop<'_>) -> Response {
        if hop.ingress_protocol != hop.egress_name {
            return shape_cross_protocol_error(hop.ingress_protocol, self.status, &self.bytes);
        }
        self.relay_verbatim(hop)
    }

    fn relay_verbatim(&self, hop: &Hop<'_>) -> Response {
        let mut rb = Response::builder().status(self.status);
        if let Some(ct) = &self.ct {
            rb = rb.header(CONTENT_TYPE, ct);
        }
        if ingress_relays_amzn_headers(hop.ingress_protocol) {
            for (name, value) in &self.amzn_headers {
                rb = rb.header(name, value);
            }
        } else {
            rb = maybe_attach_response_request_id(
                rb,
                hop.ingress_protocol,
                self.relay_id.as_deref(),
            );
        }
        rb.body(Body::from(self.bytes.clone()))
            .unwrap_or_else(|_| self.status.into_response())
    }
}

/// A non-2xx upstream response: classify, record, and decide what the client sees. A plain fn
/// returning an `async move` block so the response is captured once, not re-bound as a local.
pub(super) fn non_2xx<'a>(
    hop: &'a Hop<'a>,
    r: http::Response<hyper::body::Incoming>,
    status: StatusCode,
    read_deadline: tokio::time::Instant,
    permit: Permit,
) -> impl std::future::Future<Output = AttemptOutcome> + 'a {
    let mut err = UpstreamError::from_headers(hop, &r, status);
    async move {
        // Size-capped read: a hostile upstream must not force an unbounded allocation for a non-2xx
        // body before the breaker classification runs.
        err.bytes = read_capped_body(r, read_deadline).await;
        classify_error(hop, err, status, permit)
    }
}

/// The disposition of a captured non-2xx: record against the breaker and shape the outcome.
fn classify_error(
    hop: &Hop<'_>,
    err: UpstreamError,
    status: StatusCode,
    permit: Permit,
) -> AttemptOutcome {
    let (host, rt, i, pool) = (hop.host, hop.rt, hop.lane, hop.pool_cell);
    // A passthrough 401/403 is the CALLER's key failing, not busbar's: no breaker penalty, relay.
    let is_passthrough_40x = hop.upstream_creds == busbar_api::UpstreamCreds::Passthrough
        && (status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN);
    if is_passthrough_40x {
        // Nothing records an outcome here, so the still-armed probe guard releases any won
        // recovery probe on return (owner-checked); the lane never wedges HalfOpen.
        return AttemptOutcome::Response(err.relay(hop));
    }

    // Two-stage pipeline: the cell that spoke to this upstream extracts the raw error, the lane's
    // error map normalizes it, the breaker classifies it.
    let mut raw = busbar_substrate::handlers::op_for(
        hop.egress_name,
        hop.op.operation,
        busbar_substrate::transport::Transport::Http,
    )
    .map(|cell| cell.extract_error(status.as_u16(), &err.bytes))
    .unwrap_or_else(|| busbar_substrate::breaker::RawUpstreamError::from_status(status.as_u16()));
    raw.retry_after_secs = err.retry_after_secs;
    let sig = normalize_raw_error(&raw, &hop.lane_row().error_map);
    let disposition = classify_disposition(&sig);

    // Exhaustive over the dispositions: a new one breaks the build rather than falling through.
    match disposition {
        Disposition::ClientFault => {
            // The caller's bad input: no breaker penalty, a separate observability counter only.
            // Nothing clears `probe_in_flight`, so the armed probe guard releases any won probe on
            // return. Cross-protocol reshapes into the ingress envelope with the kind derived from
            // the classified status class; same-protocol relays verbatim.
            host.lane_store().record_client_fault(i);
            if hop.ingress_protocol != hop.egress_name {
                let kind = client_fault_kind(sig.class);
                let msg = extract_error_message(&err.bytes)
                    .unwrap_or_else(|| GENERIC_REJECTED_DETAIL.to_string());
                return AttemptOutcome::Response(ingress_error(
                    hop.ingress_protocol,
                    status,
                    kind,
                    &msg,
                ));
            }
            AttemptOutcome::Response(err.relay_verbatim(hop))
        }
        Disposition::TransientUpstream => {
            // Record by class: a rate limit carries its own cooldown rule and the upstream's
            // `Retry-After` floor; everything else is a transient with a class label.
            let tripped = if matches!(sig.class, StatusClass::RateLimit) {
                host.lane_store().record_rate_limit_in(
                    pool,
                    i,
                    now(),
                    hop.breaker_cfg,
                    sig.retry_after,
                )
            } else {
                let what = match sig.class {
                    StatusClass::ServerError => "5xx",
                    StatusClass::Timeout => ERR_NET_TIMEOUT,
                    StatusClass::Network => "network",
                    StatusClass::Overloaded => KIND_OVERLOADED,
                    StatusClass::RateLimit => "rate_limit",
                    // Not mapped to this disposition today; a generic label rather than a panic on
                    // the request path if the classifier ever changes.
                    StatusClass::Auth
                    | StatusClass::Billing
                    | StatusClass::ClientError
                    | StatusClass::ContextLength => "transient",
                };
                host.lane_store().record_transient_in(
                    pool,
                    i,
                    what,
                    hop.breaker_cfg,
                    sig.retry_after,
                )
            };
            if tripped {
                emit_breaker_trip(host, rt, pool, i);
            }
            host.telemetry_upstream_failure(hop.metric_pool, i, DISPOSITION_TRANSIENT);
            drop(permit);
            AttemptOutcome::Failed {
                disposition,
                err_type: DISPOSITION_TRANSIENT,
                relay: hop.degraded.then(|| err.relay(hop)),
            }
        }
        Disposition::HardDown => hard_down(hop, &err, &sig, status, permit),
        Disposition::ContextLength => {
            // The request is too large for THIS model's window: a client-fault variant with no
            // breaker penalty. The caller excludes the smaller-window siblings and fails over.
            host.telemetry_upstream_failure(hop.metric_pool, i, DISPOSITION_CONTEXT_LENGTH);
            drop(permit);
            AttemptOutcome::Failed {
                disposition,
                err_type: DISPOSITION_CONTEXT_LENGTH,
                relay: hop.degraded.then(|| err.relay(hop)),
            }
        }
    }
}

/// An auth rejection or billing exhaustion is a property of the SHARED upstream, not of one routing
/// pool: trip the lane in EVERY cell. An auth failure of busbar's OWN lane credential returns the
/// ingress protocol's native auth-failure envelope (never the upstream's body, which is
/// busbar-internal context); a billing hard-down fails over.
fn hard_down(
    hop: &Hop<'_>,
    err: &UpstreamError,
    sig: &busbar_substrate::breaker::CanonicalSignal,
    status: StatusCode,
    permit: Permit,
) -> AttemptOutcome {
    let (host, i) = (hop.host, hop.lane);
    let reason = match sig.class {
        StatusClass::Billing => "billing / insufficient balance".to_string(),
        StatusClass::Auth => format!("auth rejected (HTTP {})", status.as_u16()),
        // Only Auth/Billing reach this arm today; a generic reason rather than a panic otherwise.
        StatusClass::RateLimit
        | StatusClass::Overloaded
        | StatusClass::ServerError
        | StatusClass::Timeout
        | StatusClass::Network
        | StatusClass::ClientError
        | StatusClass::ContextLength => format!("request rejected (HTTP {})", status.as_u16()),
    };
    let newly_tripped = host.lane_store().record_hard_down_all_cells(i, &reason);
    // Count and warn only on the LOGICAL Closed→Open trip: a persistently-dead lane re-enters this
    // arm on every recovery-probe cycle.
    if newly_tripped {
        host.telemetry_breaker_trip(hop.metric_pool, i);
        diag_warn!(LANE_HARD_DOWN, pool = %hop.pool_cell, lane = %hop.lane_row().model, reason = %reason, "lane hard-down (breaker trip)");
    } else {
        diag_debug!(LANE_HARD_DOWN, pool = %hop.pool_cell, lane = %hop.lane_row().model, reason = %reason, "lane still hard-down (recovery probe re-tripped)");
    }
    host.telemetry_upstream_failure(hop.metric_pool, i, DISPOSITION_HARD_DOWN);
    drop(permit);
    if matches!(sig.class, StatusClass::Auth) {
        // The ingress-protocol-native auth-failure status and kind (a real Bedrock auth failure is
        // a 403 AccessDeniedException, a real Gemini bad key a 400 INVALID_ARGUMENT), with the
        // vendor-plausible message — never the egress backend's raw status or body.
        let (auth_status, auth_kind) =
            busbar_substrate::proxy::auth_failure_status_and_kind(hop.ingress_protocol);
        return AttemptOutcome::Response(ingress_error(
            hop.ingress_protocol,
            auth_status,
            auth_kind,
            busbar_substrate::proto::vendor_auth_failure_message(hop.ingress_protocol),
        ));
    }
    AttemptOutcome::Failed {
        disposition: Disposition::HardDown,
        err_type: DISPOSITION_HARD_DOWN,
        relay: hop.degraded.then(|| err.relay(hop)),
    }
}

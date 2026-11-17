// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Instant;

use axum::{extract::OriginalUri, http::StatusCode, response::Response};

use crate::state::App;

pub fn pool_authorized(
    gov: &crate::governance::GovCtx,
    pool: &str,
    proto: &str,
) -> Option<Response> {
    if let Some(key) = &gov.key {
        if !crate::governance::pool_allowed(key, pool) {
            tracing::info!(key_id = %key.id, pool = %pool, "governance: key not authorized for pool");
            return Some(ingress_error(
                proto,
                StatusCode::FORBIDDEN,
                busbar_contract::protocol::KIND_PERMISSION,
                "Your API key does not have permission to access this resource.",
            ));
        }
    }
    None
}

pub fn fallback_pools_authorized(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    pool: &str,
    proto: &str,
) -> Option<Response> {
    let key = gov.key.as_ref()?;

    key.allowed_scopes.as_ref()?;
    let view = app.engine_tables_view();
    // Walk the fallback chain until it ends, a pool is refused, or it loops. Brent's cycle check
    // holds one earlier chain member (moved in, never copied) instead of a set of visited names.
    let mut anchor: std::borrow::Cow<'_, str> = std::borrow::Cow::Borrowed(pool);
    let mut next = view.on_exhausted_fallback(pool)?;
    let (mut power, mut steps) = (1_usize, 0_usize);
    loop {
        if let Some(resp) = pool_authorized(gov, &next, proto) {
            return Some(resp);
        }
        if *anchor == *next {
            return None;
        }
        steps += 1;
        if steps == power {
            anchor = std::borrow::Cow::Owned(next);
            (power, steps) = (power * 2, 0);
            next = view.on_exhausted_fallback(&anchor)?;
        } else {
            next = view.on_exhausted_fallback(&next)?;
        }
    }
}

/// `, pool '<p>'` when a limit is pool-scoped, nothing otherwise.
struct PoolScope<'a>(&'a Option<String>);

impl std::fmt::Display for PoolScope<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(p) => write!(f, ", pool '{p}'"),
            None => Ok(()),
        }
    }
}

/// The client-facing text of a limit refusal, written straight into its destination.
struct RefusalText<'a>(&'a crate::governance::LimitBlocked);

impl std::fmt::Display for RefusalText<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::governance::LimitBlocked;
        match self.0 {
            LimitBlocked::Limit {
                group,
                metric: "concurrent",
                ..
            } => write!(
                f,
                "Too many concurrent requests (group '{group}' is at its in-flight \
                     limit). Please retry shortly."
            ),
            LimitBlocked::Limit {
                group,
                metric: "budget",
                window,
                pool: limit_pool,
                ..
            } => write!(
                f,
                "You have exceeded your current quota (group '{group}' budget per {}{} \
                     exhausted). Please check your plan and billing details.",
                window.unwrap_or("total"),
                PoolScope(limit_pool),
            ),
            LimitBlocked::Limit {
                group,
                metric,
                window,
                pool: limit_pool,
                ..
            } => write!(
                f,
                "Rate limit exceeded (group '{group}': {metric} per {}{}). Please retry \
                     after the indicated time.",
                window.unwrap_or("total"),
                PoolScope(limit_pool),
            ),
            LimitBlocked::Disabled(group) => write!(
                f,
                "Your API key does not currently have access to this resource (group \
                     '{group}' is disabled)."
            ),
            LimitBlocked::MissingGroup(group) => write!(
                f,
                "Your quota configuration is incomplete (group '{group}' is not \
                     configured). Please contact your administrator."
            ),
            LimitBlocked::Draining => {
                f.write_str("gateway is shutting down; retry on another instance")
            }
            LimitBlocked::CustodyFull { backlog, cap } => write!(
                f,
                "usage custody is at capacity ({backlog} of {cap} finished requests await \
                     settlement in the store); retry shortly"
            ),
        }
    }
}

#[must_use]
pub fn limit_refusal(
    proto: &str,
    blocked: &crate::governance::LimitBlocked,
) -> (StatusCode, &'static str, String, Option<u64>) {
    use crate::governance::LimitBlocked;
    let quota_status = || {
        StatusCode::from_u16(protocols::quota_exceeded_status(proto))
            .ok()
            .unwrap_or(StatusCode::TOO_MANY_REQUESTS)
    };
    let (status, kind, retry_after) = match blocked {
        LimitBlocked::Limit {
            metric: "concurrent",
            ..
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            busbar_contract::protocol::KIND_RATE_LIMIT,
            None,
        ),
        LimitBlocked::Limit {
            metric: "budget",
            retry_after,
            ..
        } => (
            quota_status(),
            busbar_contract::protocol::KIND_INSUFFICIENT_QUOTA,
            *retry_after,
        ),
        LimitBlocked::Limit { retry_after, .. } => (
            StatusCode::TOO_MANY_REQUESTS,
            busbar_contract::protocol::KIND_RATE_LIMIT,
            *retry_after,
        ),
        LimitBlocked::Disabled(_) => (
            StatusCode::FORBIDDEN,
            busbar_contract::protocol::KIND_PERMISSION,
            None,
        ),
        LimitBlocked::MissingGroup(_) => (
            quota_status(),
            busbar_contract::protocol::KIND_INSUFFICIENT_QUOTA,
            None,
        ),
        LimitBlocked::Draining => (
            StatusCode::SERVICE_UNAVAILABLE,
            busbar_contract::protocol::KIND_OVERLOADED,
            None,
        ),
        LimitBlocked::CustodyFull { .. } => (
            StatusCode::SERVICE_UNAVAILABLE,
            busbar_contract::protocol::KIND_OVERLOADED,
            Some(1),
        ),
    };
    let message = crate::cold::host::ingress_refusal_text(&RefusalText(blocked));
    (status, kind, message, retry_after)
}

pub fn destination_guard(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    pool: &str,
    started: Instant,
    charged_at: u64,
) -> Result<(), Box<Response>> {
    let label = pool_label(app, pool);
    if let Some(resp) = pool_authorized(gov, pool, proto) {
        return Err(Box::new(finish_rejected(
            app, gov, proto, label, started, charged_at, resp,
        )));
    }

    if let Some(resp) = fallback_pools_authorized(app, gov, pool, proto) {
        return Err(Box::new(finish_rejected(
            app, gov, proto, label, started, charged_at, resp,
        )));
    }

    if gov.key.is_some()
        && app.cost.pricing_enabled()
        && {
            let v = app.engine_tables_view();
            !v.pools().iter().any(|(n, _)| *n == pool) && v.model_index(pool).is_none()
        }
        && app.cost.model_unpriced(pool)
    {
        tracing::info!(model = %pool, "governance: no configured rate for model; rejecting (rate_card is authoritative and complete)");
        let resp = ingress_error(
            proto,
            StatusCode::BAD_REQUEST,
            busbar_contract::protocol::KIND_INVALID_REQUEST,
            &crate::door::VerifyRefusal::NoRate { name: pool.into() }.message(),
        );
        return Err(Box::new(finish_rejected(
            app, gov, proto, label, started, charged_at, resp,
        )));
    }
    Ok(())
}

pub fn pool_label<'a>(app: &Arc<App>, model: &'a str) -> &'a str {
    let v = app.engine_tables_view();
    if v.pools().iter().any(|(n, _)| *n == model) || v.model_index(model).is_some() {
        model
    } else {
        crate::telemetry::POOL_LABEL_UNRESOLVED
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn finish(
    app: &Arc<App>,
    _gov: &crate::governance::GovCtx,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    _charged_at: u64,
    resp: Response,
    charge: &crate::governance::FeeCharge,
) -> Response {
    finish_inner(app, ingress_protocol, pool, started, resp, Some(charge))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the ingress terminal's public signature carries the whole admission context"
)]
pub fn finish_admitted(
    app: &Arc<App>,
    _gov: &crate::governance::GovCtx,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    _charged_at: u64,
    resp: Response,
    charged: Option<&crate::governance::FeeCharge>,
) -> Response {
    finish_inner(app, ingress_protocol, pool, started, resp, charged)
}

pub fn finish_rejected(
    app: &Arc<App>,
    _gov: &crate::governance::GovCtx,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    _charged_at: u64,
    resp: Response,
) -> Response {
    finish_inner(app, ingress_protocol, pool, started, resp, None)
}

fn finish_inner(
    app: &Arc<App>,
    ingress_protocol: &str,
    pool: &str,
    started: Instant,
    resp: Response,
    refund_on_non_2xx: Option<&crate::governance::FeeCharge>,
) -> Response {
    let outcome = crate::telemetry::outcome_of(resp.status().as_u16());

    let elapsed = crate::store::elapsed(started);
    crate::telemetry::request_finished(
        app,
        crate::plane_driver::dispatch::fallback_key(),
        ingress_protocol,
        pool,
        outcome,
        elapsed.as_secs_f64(),
    );

    if app
        .export_projections
        .wants_stream(busbar_contract::export_stream::ExportStream::Logs)
    {
        export_request_log(
            &app.exports,
            ingress_protocol,
            pool,
            outcome,
            elapsed.as_millis() as u64,
        );
    }

    let status = resp.status().as_u16();

    let is_success = matches!(status, 200..=299);
    if let (Some(charge), false) = (refund_on_non_2xx, is_success) {
        if let Some(g) = &app.governance {
            g.refund_charge(charge);
        }
    }
    resp
}

/// The request-log export record, dated by the wall clock when a sink wants it.
fn export_request_log(
    exports: &crate::export::plugin::Exports,
    ingress_protocol: &str,
    pool: &str,
    outcome: &str,
    latency_ms: u64,
) {
    crate::export::deliver_request_log(
        exports,
        &crate::export::RequestLogFacts {
            correlation_id: None,
            ts: busbar_kernel::store::now(),
            ingress_protocol,
            pool,
            outcome,
            latency_ms,
        },
    );
}

pub fn ingress_error(proto: &str, status: StatusCode, kind: &str, message: &str) -> Response {
    use axum::response::IntoResponse;
    let (envelope, fields) = protocols::error_parts(proto, status.as_u16(), kind, message);
    let body = crate::json::to_vec(&envelope).unwrap_or_default();
    let mut resp = Response::builder()
        .status(status)
        .header(
            axum::http::header::CONTENT_TYPE,
            busbar_contract::protocol::APPLICATION_JSON,
        )
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| status.into_response());
    for (name, value) in fields {
        if let (Ok(n), Ok(v)) = (
            axum::http::HeaderName::from_bytes(name.as_bytes()),
            axum::http::HeaderValue::from_bytes(&value),
        ) {
            resp.headers_mut().insert(n, v);
        }
    }
    resp
}

pub mod jsonrpc;
pub mod protocols;
pub mod replay;
pub mod signed_ingress;

#[cfg(test)]
#[path = "tests/terminal_tests.rs"]
mod terminal_tests;

pub mod arrival;

pub mod byte_duplex;

pub mod session;

pub mod protocol;

pub mod native;

pub mod dispatch;

pub mod observe;

pub(crate) use dispatch::protocol_dispatch;

#[cfg(test)]
pub fn percent_decode(s: &str) -> String {
    String::from_utf8_lossy(&busbar_contract::net::percent_decoded_bytes(s)).into_owned()
}

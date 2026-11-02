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
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut current = pool.to_string();
    loop {
        if !visited.insert(current.clone()) {
            return None;
        }

        let next = view.on_exhausted_fallback(&current)?;

        if let Some(resp) = pool_authorized(gov, &next, proto) {
            return Some(resp);
        }
        current = next;
    }
}

fn pool_scope_suffix(pool: &Option<String>) -> String {
    match pool {
        Some(p) => format!(", pool '{p}'"),
        None => String::new(),
    }
}

pub fn admit_check(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &str,
    pool: &str,
    charged_at: u64,
) -> Result<(Option<crate::governance::AdmitGrant>, Option<String>), Box<Response>> {
    let (Some(g), Some(key)) = (&app.governance, &gov.key) else {
        return Ok((None, None));
    };

    let mut effective: Option<String> = None;
    let mut visited: Vec<String> = Vec::new();
    let blocked = loop {
        let attempt_pool = effective.as_deref().unwrap_or(pool);
        match g.try_admit(&app.cost, key, attempt_pool, charged_at) {
            Ok(grant) => return Ok((Some(grant), effective)),
            Err(crate::governance::LimitBlocked::Limit {
                downgrade_to: Some(to),
                group,
                ..
            }) if !visited.iter().any(|v| v == &to)
                && visited.len() < app.engine_tables_view().pools().len()
                && app
                    .engine_tables_view()
                    .pools()
                    .iter()
                    .any(|(n, _)| *n == to.as_str())
                && pool_authorized(gov, &to, proto).is_none()
                && fallback_pools_authorized(app, gov, &to, proto).is_none() =>
            {
                tracing::info!(key_id = %key.id, from = attempt_pool, to = %to, group = %group,
                    "governance: budget exhausted; downgrading pool (on_exhaust: downgrade)");
                visited.push(to.clone());
                effective = Some(to);
            }
            Err(blocked) => break blocked,
        }
    };
    {
        tracing::info!(key_id = %key.id, blocked = ?blocked, "governance: limit bucket blocked admission");
        let (status, kind, message, retry_after) = limit_refusal(proto, &blocked);
        let mut resp = ingress_error(proto, status, kind, &message);

        if let Some(retry) = retry_after {
            if let Ok(hv) = axum::http::HeaderValue::from_str(&retry.to_string()) {
                resp.headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, hv);
            }
        }
        Err(Box::new(resp))
    }
}

#[must_use]
pub fn limit_refusal(
    proto: &str,
    blocked: &crate::governance::LimitBlocked,
) -> (StatusCode, &'static str, String, Option<u64>) {
    use crate::governance::LimitBlocked;
    match blocked {
        LimitBlocked::Limit {
            group,
            metric: "concurrent",
            ..
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            busbar_contract::protocol::KIND_RATE_LIMIT,
            format!(
                "Too many concurrent requests (group '{group}' is at its in-flight \
                     limit). Please retry shortly."
            ),
            None,
        ),
        LimitBlocked::Limit {
            group,
            metric: "budget",
            window,
            pool: limit_pool,
            retry_after,
            ..
        } => (
            StatusCode::from_u16(protocols::quota_exceeded_status(proto))
                .ok()
                .unwrap_or(StatusCode::TOO_MANY_REQUESTS),
            busbar_contract::protocol::KIND_INSUFFICIENT_QUOTA,
            format!(
                "You have exceeded your current quota (group '{group}' budget per {}{} \
                     exhausted). Please check your plan and billing details.",
                window.unwrap_or("total"),
                pool_scope_suffix(limit_pool),
            ),
            *retry_after,
        ),

        LimitBlocked::Limit {
            group,
            metric,
            window,
            pool: limit_pool,
            retry_after,
            ..
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            busbar_contract::protocol::KIND_RATE_LIMIT,
            format!(
                "Rate limit exceeded (group '{group}': {metric} per {}{}). Please retry \
                     after the indicated time.",
                window.unwrap_or("total"),
                pool_scope_suffix(limit_pool),
            ),
            *retry_after,
        ),

        LimitBlocked::Disabled(group) => (
            StatusCode::FORBIDDEN,
            busbar_contract::protocol::KIND_PERMISSION,
            format!(
                "Your API key does not currently have access to this resource (group \
                     '{group}' is disabled)."
            ),
            None,
        ),

        LimitBlocked::MissingGroup(group) => (
            StatusCode::from_u16(protocols::quota_exceeded_status(proto))
                .ok()
                .unwrap_or(StatusCode::TOO_MANY_REQUESTS),
            busbar_contract::protocol::KIND_INSUFFICIENT_QUOTA,
            format!(
                "Your quota configuration is incomplete (group '{group}' is not \
                     configured). Please contact your administrator."
            ),
            None,
        ),
    }
}

#[allow(private_interfaces)]
pub fn governance_guard(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    pool: &str,
    started: Instant,
    charged_at: u64,
) -> Result<(Option<crate::governance::AdmitGrant>, Option<String>), Box<Response>> {
    destination_guard(app, gov, proto, pool, started, charged_at)?;
    admission_door(app, gov, proto, pool, started, charged_at)
}

#[allow(private_interfaces)]
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

#[allow(private_interfaces)]
pub fn admission_door(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    proto: &'static str,
    pool: &str,
    started: Instant,
    charged_at: u64,
) -> Result<(Option<crate::governance::AdmitGrant>, Option<String>), Box<Response>> {
    let label = pool_label(app, pool);
    match admit_check(app, gov, proto, pool, charged_at) {
        Err(resp) => Err(Box::new(finish_rejected(
            app, gov, proto, label, started, charged_at, *resp,
        ))),
        Ok(admitted) => Ok(admitted),
    }
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

#[allow(private_interfaces)]
#[allow(clippy::too_many_arguments)]
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

#[allow(private_interfaces)]
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
    let _fin = crate::profile::start(crate::profile::Stage::Finish);

    let outcome = crate::telemetry::outcome_of(resp.status().as_u16());

    let elapsed = started.elapsed();
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
        .wants_stream(busbar_contract::abi::export::ExportStream::Logs)
    {
        crate::export::deliver_request_log(&crate::export::RequestLogFacts {
            ts: busbar_kernel::store::now(),
            ingress_protocol,
            pool,
            outcome,
            latency_ms: elapsed.as_millis() as u64,
        });
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

pub fn ingress_error(proto: &str, status: StatusCode, kind: &str, message: &str) -> Response {
    use axum::response::IntoResponse;
    let (envelope, fields) = protocols::error_parts(proto, status.as_u16(), kind, message);
    let body = crate::json::to_string(&envelope)
        .unwrap_or_else(|_| agnostic_error_envelope(kind, message).to_string());
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

fn agnostic_error_envelope(kind: &str, msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "message": msg, "type": kind } })
}

pub mod jsonrpc;
pub mod protocols;

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

#[must_use]
pub fn not_found_message(model: &str, model_not_found_message: Option<&str>) -> String {
    match model_not_found_message {
        Some(shaped) => shaped.to_string(),
        None => format!("The model '{model}' does not exist or you do not have access to it."),
    }
}

#[cfg(test)]
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::AdminError;

pub fn ok_json<T: Serialize>(status: StatusCode, view: &T) -> Response {
    match serde_json::to_string(view) {
        Ok(body) => (
            status,
            [(CONTENT_TYPE, busbar_contract::protocol::APPLICATION_JSON)],
            body,
        )
            .into_response(),
        Err(_) => busbar_kernel::admin::gate::admin_error_envelope(
            StatusCode::INTERNAL_SERVER_ERROR.into(),
            "internal",
            "response serialization failed",
        ),
    }
}

pub fn err_json(e: &AdminError) -> Response {
    err_json_tagged(e, None)
}

pub fn err_json_cond(e: &AdminError, cond: Cond) -> Response {
    err_json_tagged(e, Some(cond))
}

/// A plugin's own words, bounded and stripped of control characters, for `details.text`.
fn scrubbed(text: &str) -> String {
    const MAX_CHARS: usize = 512;
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_CHARS)
        .collect()
}

/// The typed `details` of one error (section 1.2): the scope a refusal needed, or a plugin's text
/// (`PluginTextDetails`, section 1.3), else the empty object.
fn details_of(e: &AdminError, reason: Option<&str>) -> busbar_contract::json::Value {
    match e {
        AdminError::Forbidden { needed } => {
            busbar_kernel::admin::gate::scope_details(needed.as_str())
        }
        AdminError::PluginText {
            cond,
            text,
            plugin_diag,
            condition,
        } => {
            let mut details = busbar_contract::json::json!({
                "text": text.as_deref().map(scrubbed),
                "plugin_diag": plugin_diag.as_deref().map(scrubbed),
            });
            if *cond == Cond::PluginRejected {
                details["condition"] = busbar_contract::json::json!(condition);
            }
            details
        }
        _ if matches!(reason, Some("hook_no_ack" | "plugin_rejected")) => {
            busbar_contract::json::json!({ "text": null, "plugin_diag": null })
        }
        _ => busbar_contract::json::json!({}),
    }
}

fn err_json_tagged(e: &AdminError, cond: Option<Cond>) -> Response {
    let cond = match e {
        AdminError::PluginText { cond, .. } => Some(*cond),
        _ => cond,
    };
    let reason = cond.map(Cond::reason);
    let details = details_of(e, reason);
    let mut resp = busbar_kernel::admin::gate::admin_error_envelope_with(
        e.http_status(),
        e.code(),
        reason,
        &e.message(),
        &details,
    );
    if let AdminError::RetryLater { retry_after_s, .. } = e {
        resp.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from(*retry_after_s),
        );
    }
    tagged(resp, e, cond)
}

/// Test builds tag the envelope with the declared kind and condition the contract tests read back.
#[cfg(test)]
fn tagged(mut resp: Response, e: &AdminError, cond: Option<Cond>) -> Response {
    if let Some(kind) = crate::v1::contract::taxonomy::err_kind_of(e) {
        resp.extensions_mut()
            .insert(crate::v1::contract::taxonomy::observed::Tag { kind, cond });
    }
    resp
}

/// Production envelopes carry no test tag.
#[cfg(not(test))]
fn tagged(resp: Response, _: &AdminError, _: Option<Cond>) -> Response {
    resp
}

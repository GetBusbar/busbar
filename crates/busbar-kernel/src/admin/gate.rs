// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};

pub const API_ROOT: &str = "/api";

pub use crate::api::ADMIN_PREFIX;

pub const PATH_ADMIN_AUTH: &str = "/admin-auth";

pub const PATH_CONFIG_VALIDATE: &str = "/config/validate";

pub const PATH_PLUGINS_INSPECT: &str = "/plugins/inspect";

pub fn required_scope(method: &axum::http::Method, path: &str) -> busbar_contract::authz::Scope {
    super::scope::admin_required_scope(method.as_str(), path)
}

/// THE ANSWERS THE KERNEL GIVES ON THE NATIVE-API ROOT ITSELF, in the frozen v1 error envelope.
/// Each variant's `code`, status and message are the frozen ones of the `AdminError` variant of the
/// same name (core-admin's taxonomy reads them from here, so the two cannot drift).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// No such resource on the native-API root (the router fallback). `code = not_found`.
    NotFound,
    /// No/invalid admin credential (the admin gate). `code = unauthorized`.
    Unauthorized,
    /// The path exists on the surface but not with this HTTP method. `code = method_not_allowed`.
    MethodNotAllowed,
    /// The principal exhausted its per-minute mutation budget. `code = rate_limited`.
    RateLimited,
    /// An internal failure (the request-panic boundary). `code = internal`.
    Internal,
    /// The admin chain could not be judged within its bound. `code = unavailable`; the message is
    /// caller-safe and specific.
    Unavailable(String),
}

impl ApiError {
    pub fn code(&self) -> &'static str {
        match self {
            ApiError::NotFound => "not_found",
            ApiError::Unauthorized => "unauthorized",
            ApiError::MethodNotAllowed => "method_not_allowed",
            ApiError::RateLimited => "rate_limited",
            ApiError::Internal => "internal",
            ApiError::Unavailable(_) => "unavailable",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            ApiError::NotFound => 404,
            ApiError::Unauthorized => 401,
            ApiError::MethodNotAllowed => 405,
            ApiError::RateLimited => 429,
            ApiError::Internal => 500,
            ApiError::Unavailable(_) => 503,
        }
    }

    pub fn message(&self) -> String {
        match self {
            ApiError::NotFound => format!("{} not found", Self::NOT_FOUND_SUBJECT),
            ApiError::Unauthorized => {
                "missing or invalid admin credential (Bearer or x-admin-token)".to_string()
            }
            ApiError::MethodNotAllowed => "method not allowed for this resource".to_string(),
            ApiError::RateLimited => {
                "admin mutation rate limit exceeded; retry next minute".to_string()
            }
            ApiError::Internal => "internal error".to_string(),
            ApiError::Unavailable(msg) => msg.clone(),
        }
    }

    pub(crate) const NOT_FOUND_SUBJECT: &'static str = "resource";
}

pub fn error_envelope(status: u16, code: &str, message: &str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        [(CONTENT_TYPE, busbar_contract::protocol::APPLICATION_JSON)],
        serde_json::json!({"error": {"code": code, "message": message}}).to_string(),
    )
        .into_response()
}

pub fn err_json(e: &ApiError) -> Response {
    admin_error_envelope(e.http_status(), e.code(), &e.message())
}

/// THE ADMIN ERROR'S CATALOG CODE (owner decision 2026-11-12): the admin envelope's `error.code`
/// is a closed reason vocabulary; each reason reports one `BUSBAR-81xx` catalog code, carried in a
/// top-level `code` field beside `error` (the envelope's own rule: additive changes go outside
/// `error`, which stays exactly `code` + `message`). Error paths only.
#[must_use]
fn admin_diag(code: &str) -> &'static busbar_contract::diagnostic::Diagnostic {
    use crate::diagnostics as d;
    match code {
        "not_found" => &d::ADMIN_NOT_FOUND,
        "unauthorized" | "invalid_api_key" => &d::ADMIN_UNAUTHORIZED,
        "method_not_allowed" => &d::ADMIN_METHOD_NOT_ALLOWED,
        "forbidden" => &d::ADMIN_FORBIDDEN,
        "invalid_request" => &d::ADMIN_INVALID_REQUEST,
        "version_conflict" => &d::ADMIN_VERSION_CONFLICT,
        "conflict" => &d::ADMIN_CONFLICT,
        "rate_limited" => &d::ADMIN_RATE_LIMITED,
        "internal" => &d::ADMIN_INTERNAL,
        "unavailable" => &d::ADMIN_UNAVAILABLE,
        "unpriced_class" => &d::ADMIN_UNPRICED_CLASS,
        busbar_contract::protocol::ERR_TYPE_REQUEST_TOO_LARGE => &d::ADMIN_REQUEST_TOO_LARGE,
        _ => &d::ADMIN_REQUEST_REFUSED,
    }
}

/// The admin error envelope body: 1.5.5's `{"error":{"code","message"}}`, unchanged, plus the
/// catalog code as a top-level `code` (`{"code":"BUSBAR-8101","error":{...}}`).
#[must_use]
pub fn admin_envelope_body(code: &str, message: &str) -> String {
    serde_json::json!({
        "code": admin_diag(code).banner().to_string(),
        "error": { "code": code, "message": message },
    })
    .to_string()
}

/// [`error_envelope`] for the ADMIN surface: the same envelope plus the top-level `code`. The plain
/// [`error_envelope`] stays as it is for the data-plane fallback, whose bodies are client-facing.
pub fn admin_error_envelope(status: u16, code: &str, message: &str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        [(CONTENT_TYPE, busbar_contract::protocol::APPLICATION_JSON)],
        admin_envelope_body(code, message),
    )
        .into_response()
}

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

    pub const NOT_FOUND_SUBJECT: &'static str = "resource";
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
    error_envelope(e.http_status(), e.code(), &e.message())
}

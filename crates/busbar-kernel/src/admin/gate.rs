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

    /// The closed reason (`admin::reasons`) this error carries; `internal` carries none.
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            ApiError::NotFound => Some("unknown_resource"),
            ApiError::Unauthorized => Some("credential_invalid"),
            ApiError::MethodNotAllowed => Some("method_not_allowed"),
            ApiError::RateLimited => Some("mutation_budget"),
            ApiError::Internal => None,
            ApiError::Unavailable(_) => Some("service_unavailable"),
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

pub fn err_json(e: &ApiError) -> Response {
    admin_error_envelope_with(
        e.http_status(),
        e.code(),
        e.reason(),
        &e.message(),
        &serde_json::json!({}),
    )
}

/// THE ADMIN ERROR'S CATALOG CODE (owner decision 2026-11-12): the admin envelope's `error.code`
/// is a closed reason vocabulary; each reason reports one `BUSBAR-81xx` catalog code, carried in a
/// top-level `code` field beside `error` (the envelope's `error` object carries
/// `code`, `reason`, `message`, `request_id`, `retryable` and `details`, section 1.2). Error paths only.
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

tokio::task_local! {
    /// The id of the admin request in flight, set at the admin boundary (`router`): the one
    /// `request_id` every envelope of that request carries and its `X-Request-Id` header repeats.
    static REQUEST_ID: String;
}

/// The header that carries the request id on every admin response.
pub const HEADER_REQUEST_ID: &str = "x-request-id";

/// Run `future` as the admin request `id`.
pub async fn with_request_id<F: std::future::Future>(id: String, future: F) -> F::Output {
    REQUEST_ID.scope(id, future).await
}

/// Run `f` as the admin request `id` (for envelopes built after the request's future returned).
pub fn in_request_scope<T>(id: &str, f: impl FnOnce() -> T) -> T {
    REQUEST_ID.sync_scope(id.to_string(), f)
}

/// The id of the admin request in flight. Outside a request (a unit test calling a handler
/// directly) a process-local id is minted, so an envelope always has one.
#[must_use]
pub fn current_request_id() -> String {
    static UNSCOPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    REQUEST_ID.try_with(Clone::clone).unwrap_or_else(|_| {
        format!(
            "r_{:016x}",
            UNSCOPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    })
}

/// The id of the admin request in flight, or `None` outside one (an audit row written by no
/// request carries no `request_id`).
#[must_use]
pub fn request_id_in_scope() -> Option<String> {
    REQUEST_ID.try_with(Clone::clone).ok()
}

/// `r_` and the sixteen hex digits of a request counter value.
#[must_use]
pub fn request_id_of(counter: u64) -> String {
    format!("r_{counter:016x}")
}

/// The `error` object of the admin envelope (ADMIN-API-1.6 section 1.2): `code`, `reason`
/// (`null` only for `internal`), `message`, `request_id`, `retryable` and `details`. A `reason` the
/// raiser did not name is the default of `code`.
#[must_use]
pub fn error_object(
    code: &str,
    reason: Option<&str>,
    message: &str,
    details: &serde_json::Value,
    request_id: &str,
) -> serde_json::Value {
    let reason = if code == "internal" {
        None
    } else {
        reason.or_else(|| super::reasons::default_reason(code))
    };
    serde_json::json!({
        "code": code,
        "reason": reason,
        "message": message,
        "request_id": request_id,
        "retryable": super::reasons::retryable(code, reason),
        "details": details,
    })
}

fn envelope_text(
    code: &str,
    reason: Option<&str>,
    message: &str,
    details: &serde_json::Value,
    request_id: &str,
) -> String {
    serde_json::json!({
        "code": admin_diag(code).banner().to_string(),
        "error": error_object(code, reason, message, details, request_id),
    })
    .to_string()
}

/// The admin error envelope body: `{"code":"BUSBAR-8101","error":{code, reason, message,
/// request_id, retryable, details}}`, with the reason that `code` defaults to.
#[must_use]
pub fn admin_envelope_body(code: &str, message: &str) -> String {
    envelope_text(
        code,
        None,
        message,
        &serde_json::json!({}),
        &current_request_id(),
    )
}

/// [`admin_envelope_body`] with the raiser's `reason` and at most one text member of `details`,
/// for an answer a handler returns as bytes (`/records`' `cursor_mismatch`, `cursor_expired`).
#[must_use]
pub fn admin_envelope_body_with(
    code: &str,
    reason: Option<&str>,
    message: &str,
    detail: Option<(&str, &str)>,
) -> String {
    let mut details = serde_json::Map::new();
    if let Some((name, value)) = detail {
        details.insert(name.to_owned(), serde_json::Value::from(value));
    }
    envelope_text(
        code,
        reason,
        message,
        &serde_json::Value::Object(details),
        &current_request_id(),
    )
}

/// The admin error envelope response, with the reason `code` defaults to and empty `details`.
pub fn admin_error_envelope(status: u16, code: &str, message: &str) -> Response {
    admin_error_envelope_with(status, code, None, message, &serde_json::json!({}))
}

/// [`admin_error_envelope`] with the raiser's reason and typed details. The response carries
/// `X-Request-Id`, equal to the body's `request_id`.
pub fn admin_error_envelope_with(
    status: u16,
    code: &str,
    reason: Option<&str>,
    message: &str,
    details: &serde_json::Value,
) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let request_id = current_request_id();
    let mut response = (
        status,
        [(CONTENT_TYPE, busbar_contract::protocol::APPLICATION_JSON)],
        envelope_text(code, reason, message, details, &request_id),
    )
        .into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(HEADER_REQUEST_ID, value);
    }
    response
}

/// The one path `GET /whoami` answers on; the gate takes the caller's identity for it.
pub const WHOAMI_PATH: &str = "/api/v1/admin/whoami";

/// `POST /keys`: the one mutation that takes the caller's identity, to refuse an `admin` grant to a
/// caller that is not a full operator.
pub const KEYS_PATH: &str = "/api/v1/admin/keys";

/// The typed `details` of reason `scope_insufficient` (section 1.3): the scope the refused call
/// needed, and the verb (`null` until per-verb authorization, MR2).
#[must_use]
pub fn scope_details(needed_scope: &str) -> serde_json::Value {
    scope_details_for(needed_scope, None)
}

/// [`scope_details`] naming the verb the refused call needed (per-verb authorization, MR2).
#[must_use]
pub fn scope_details_for(needed_scope: &str, needed_verb: Option<&str>) -> serde_json::Value {
    serde_json::json!({ "needed_scope": needed_scope, "needed_verb": needed_verb })
}

/// The admin 403 for a credential whose scope is below `needed_scope`: code `forbidden`, reason
/// `scope_insufficient`, with [`scope_details`].
pub fn scope_insufficient(needed_scope: &str) -> Response {
    scope_insufficient_for(needed_scope, None)
}

/// The admin 401 for a presented admin credential refused for the closed `reason`
/// (`credential_expired`, `credential_revoked` or `credential_invalid`).
pub fn unauthorized_for(reason: &str) -> Response {
    admin_error_envelope_with(
        401,
        "unauthorized",
        Some(reason),
        "missing or invalid admin credential (Bearer or x-admin-token)",
        &serde_json::json!({}),
    )
}

/// [`scope_insufficient`] naming the verb the refused call needed.
pub fn scope_insufficient_for(needed_scope: &str, needed_verb: Option<&str>) -> Response {
    admin_error_envelope_with(
        403,
        "forbidden",
        Some("scope_insufficient"),
        &format!("this endpoint requires the `{needed_scope}` admin scope"),
        &scope_details_for(needed_scope, needed_verb),
    )
}

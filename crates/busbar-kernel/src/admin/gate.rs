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
            ApiError::Unauthorized => "missing or invalid admin credential (Bearer)".to_string(),
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

/// The header a client's own request id comes in on: the same `X-Request-Id` the engine answers
/// with its own id (ADMIN-API-1.6-ONE-MODEL section 7).
pub const HEADER_CLIENT_REQUEST_ID: &str = "x-client-request-id";

/// The W3C trace context header, in and out.
pub const HEADER_TRACEPARENT: &str = "traceparent";

/// The longest client request id the engine keeps.
pub const CLIENT_REQUEST_ID_MAX: usize = 128;

/// A client `X-Request-Id` the engine keeps: 1 to 128 of `[A-Za-z0-9._:-]`.
#[must_use]
pub fn valid_client_request_id(value: &[u8]) -> bool {
    (1..=CLIENT_REQUEST_ID_MAX).contains(&value.len())
        && value
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn lower_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The W3C trace an admin request arrived in (`traceparent`, W3C Trace Context level 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceParent {
    /// 32 lowercase hex digits, never all zero.
    pub trace_id: String,
    /// The caller's span: 16 lowercase hex digits, never all zero.
    pub parent_id: String,
    /// The trace flags: 2 lowercase hex digits.
    pub flags: String,
}

impl TraceParent {
    /// Read a `traceparent` value. Version `00` is exactly `00-<trace>-<parent>-<flags>`; a later
    /// version (never `ff`) is read by its first four fields, as the specification asks. Anything
    /// else is no trace: the request is not refused for it.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let head = value.get(..55)?;
        let rest = &value[55..];
        let mut fields = head.split('-');
        let (version, trace_id, parent_id, flags) = (
            fields.next()?,
            fields.next()?,
            fields.next()?,
            fields.next()?,
        );
        let well_formed = lower_hex(version, 2)
            && version != "ff"
            && lower_hex(trace_id, 32)
            && trace_id.bytes().any(|b| b != b'0')
            && lower_hex(parent_id, 16)
            && parent_id.bytes().any(|b| b != b'0')
            && lower_hex(flags, 2)
            && if version == "00" {
                rest.is_empty()
            } else {
                rest.is_empty() || rest.starts_with('-')
            };
        well_formed.then(|| Self {
            trace_id: trace_id.to_owned(),
            parent_id: parent_id.to_owned(),
            flags: flags.to_owned(),
        })
    }

    /// The `traceparent` the engine answers with: the caller's trace and flags, and the admin
    /// span's own id.
    #[must_use]
    pub fn child(&self, span_id: &[u8; 8]) -> String {
        format!(
            "00-{}-{}-{}",
            self.trace_id,
            hex::encode(span_id),
            self.flags
        )
    }
}

/// What a caller sent to correlate its admin request with its own records
/// (ADMIN-API-1.6-ONE-MODEL section 7): its own request id, when valid, and the trace it arrived in.
/// Neither is ever the request's `request_id`, which the engine always mints.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Correlation {
    pub client_request_id: Option<String>,
    pub trace: Option<TraceParent>,
}

impl Correlation {
    /// Read the correlation from a request's headers. A header sent more than once, or a value
    /// that is not valid, is dropped without comment: a proxy may have set it.
    #[must_use]
    pub fn of(headers: &axum::http::HeaderMap) -> Self {
        let single = |name: &str| {
            let mut values = headers.get_all(name).iter();
            match (values.next(), values.next()) {
                (Some(value), None) => Some(value),
                _ => None,
            }
        };
        Self {
            client_request_id: single(HEADER_REQUEST_ID)
                .filter(|value| valid_client_request_id(value.as_bytes()))
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            trace: single(HEADER_TRACEPARENT)
                .and_then(|value| value.to_str().ok())
                .and_then(TraceParent::parse),
        }
    }

    /// Answer the caller's correlation on `headers`: `X-Client-Request-Id` when it sent a valid
    /// id, and `traceparent` on its trace, naming the admin span `span_id`, when it sent one.
    pub fn answer(&self, span_id: Option<&[u8; 8]>, headers: &mut axum::http::HeaderMap) {
        if let Some(value) = self
            .client_request_id
            .as_deref()
            .and_then(|id| axum::http::HeaderValue::from_str(id).ok())
        {
            headers.insert(HEADER_CLIENT_REQUEST_ID, value);
        }
        if let Some(value) =
            self.trace.as_ref().zip(span_id).and_then(|(trace, span)| {
                axum::http::HeaderValue::from_str(&trace.child(span)).ok()
            })
        {
            headers.insert(HEADER_TRACEPARENT, value);
        }
    }
}

tokio::task_local! {
    /// The correlation of the admin request in flight, set at the admin boundary beside its id.
    static CORRELATION: Correlation;
}

/// Run `future` with the admin request's correlation in scope.
pub async fn with_correlation<F: std::future::Future>(
    correlation: Correlation,
    future: F,
) -> F::Output {
    CORRELATION.scope(correlation, future).await
}

/// The correlation of the admin request in flight, or `None` outside one.
#[must_use]
pub fn correlation_in_scope() -> Option<Correlation> {
    CORRELATION.try_with(Clone::clone).ok()
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

/// [`admin_envelope_body`] with the raiser's `reason` and typed `details`, built through the JSON
/// facade end to end (TRUST-ADMIN-PRODUCER-DESIGN r3 §4.5): for answers whose `details` the raiser
/// assembles as facade values, so no `serde_json` value is passed in.
#[must_use]
pub fn admin_envelope_body_details(
    code: &str,
    reason: Option<&str>,
    message: &str,
    details: &busbar_contract::json::Value,
) -> String {
    let reason = if code == "internal" {
        None
    } else {
        reason.or_else(|| super::reasons::default_reason(code))
    };
    let body = busbar_contract::json::json!({
        "code": admin_diag(code).banner().to_string(),
        "error": {
            "code": code,
            "reason": reason,
            "message": message,
            "request_id": current_request_id(),
            "retryable": super::reasons::retryable(code, reason),
            "details": details,
        },
    });
    busbar_contract::json::to_string(&body)
        .expect("the admin envelope holds only strings, booleans and facade values")
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

/// [`admin_error_envelope_with`] whose `details` are a JSON facade value
/// ([`admin_envelope_body_details`]). The response carries `X-Request-Id`, equal to the body's
/// `request_id`.
pub fn admin_error_envelope_details(
    status: u16,
    code: &str,
    reason: Option<&str>,
    message: &str,
    details: &busbar_contract::json::Value,
) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let request_id = current_request_id();
    let mut response = (
        status,
        [(CONTENT_TYPE, busbar_contract::protocol::APPLICATION_JSON)],
        admin_envelope_body_details(code, reason, message, details),
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
pub(crate) fn scope_details_for(
    needed_scope: &str,
    needed_verb: Option<&str>,
) -> serde_json::Value {
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
        "missing or invalid admin credential (Bearer)",
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

#[cfg(test)]
#[path = "tests/correlation_tests.rs"]
mod correlation_tests;

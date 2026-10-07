// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN GATE'S KERNEL HALF (P2 D4, ARCHITECT Q-D4-ADMIN (b) 2026-10-04): what the kernel itself
//! answers on the native-API root, and nothing more. The admin contract — the views, the full
//! `AdminError` taxonomy, the JSON envelope helpers, the plane-verb envelope — is
//! `busbar-core-admin`'s (`busbar_core_admin::v1::contract`); core-admin depends on the kernel one
//! way, so what the kernel answers BEFORE any admin handler runs stays here:
//!
//! - the gate's scope matrix ([`required_scope`]) and the paths it and the mutation-rate classifier
//!   (`crate::ratelimit`) key off — core owns the auth verify on the request path;
//! - ONE small neutral `/api` error envelope ([`ApiError`], [`err_json`]) for exactly the answers the
//!   kernel gives itself: the admin gate's 401/429/503, the router fallback's 404/405/500 and the
//!   plane-driver serve's 405. Each is byte-identical to the `AdminError` variant core-admin answers
//!   with the same code: core-admin's taxonomy reads these variants' words from here.

use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};

/// The root every busbar-NATIVE API surface mounts under (`/api/<version>/<area>/…`). A plane's own
/// mimicked wire surface is deliberately OUTSIDE this root — its paths are dictated by whatever
/// external protocol it mimics, not by busbar.
pub const API_ROOT: &str = "/api";

/// The frozen Admin API v1 path prefix (`busbar_contract::surface`), re-exported for the gate.
pub use crate::api::ADMIN_PREFIX;

/// Relative (post-`ADMIN_PREFIX`) path segments matched in more than one place — the scope matrix
/// ([`required_scope`]), the mutation-rate classifier (`crate::ratelimit`), and core-admin's
/// router/OpenAPI builder — single-sourced here so the surfaces cannot drift.
pub const PATH_ADMIN_AUTH: &str = "/admin-auth";
/// `POST /config/validate` — a stateless, `read-only`-scope dry run.
pub const PATH_CONFIG_VALIDATE: &str = "/config/validate";
/// `POST /plugins/inspect` — a stateless, `read-only`-scope preview of a candidate plugin
/// tarball. Single-sourced here for the same reason as `PATH_CONFIG_VALIDATE`: the scope matrix, the
/// mutation-rate classifier, and the router all key off this exact string.
pub const PATH_PLUGINS_INSPECT: &str = "/plugins/inspect";

/// The AUTHORIZATION MATRIX: the scope an admin endpoint requires, derived from METHOD + PATH —
/// never from the body (a crafted request cannot escalate). A strict two-rung split (1.5.2 scope
/// collapse): every read (`GET`/`HEAD`) plus the two stateless dry-run POSTs (`config/validate`,
/// `plugins/inspect`) is `read-only`; every mutation — config apply/rollback, auth chains, keys,
/// hooks, group_map, cache — needs `full`. Unknown methods fail closed to `full`. Body-derived
/// refinements (a non-`full` caller must not register a hook wired into a security-critical path)
/// remain at the service layer as defense-in-depth.
// `pub`: the extracted plane crates' admin-verb conformance tests assert their declared route scope
// equals the bar this one function ENFORCES (`busbar_kernel::admin_verbs` documents the invariant),
// so they name it across the honest crate boundary. A pure `(method, path) → Scope` function with no
// state to leak.
pub fn required_scope(method: &axum::http::Method, path: &str) -> busbar_contract::authz::Scope {
    use axum::http::Method;
    use busbar_contract::authz::Scope;
    if method == Method::GET || method == Method::HEAD {
        return Scope::ReadOnly;
    }
    // Match RELATIVE to the one true prefix so the matrix can never drift from the mount grammar.
    // A path outside the prefix (impossible for a mounted admin route) fails closed to `full`.
    let rel = path.strip_prefix(ADMIN_PREFIX).unwrap_or(path);
    // `POST /config/validate` (and `POST /plugins/inspect`) are STATELESS DRY-RUNS — reads in POST
    // clothing (the body is the config to lint / tarball to preview, far past URL length limits). A
    // read-only CI token must be able to lint configs.
    if rel == PATH_CONFIG_VALIDATE || rel == PATH_PLUGINS_INSPECT {
        return Scope::ReadOnly;
    }
    // Every other mutation (and any non-read extension method) is full-only.
    Scope::Full
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
    /// The FROZEN stable code.
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

    /// The HTTP status.
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

    /// The human-facing message. Caller-safe only.
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

    /// What the router fallback's not-found names: no resource in particular.
    pub const NOT_FOUND_SUBJECT: &'static str = "resource";
}

/// The ONE construction of the v1 error envelope `{"error":{"code":<stable>,"message":<human>}}`
/// with `status` — the kernel's own answers ([`err_json`]) and core-admin's (`AdminError`) are both
/// framed by it, so the bytes cannot differ.
pub fn error_envelope(status: u16, code: &str, message: &str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        [(CONTENT_TYPE, crate::proxy::APPLICATION_JSON)],
        serde_json::json!({"error": {"code": code, "message": message}}).to_string(),
    )
        .into_response()
}

/// Project a kernel answer onto the frozen v1 error envelope with its HTTP status.
pub fn err_json(e: &ApiError) -> Response {
    error_envelope(e.http_status(), e.code(), &e.message())
}

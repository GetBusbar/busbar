// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S OWN ANSWERS ON THE OPERATOR SURFACE, protocol-free.
//!
//! The kernel's gate judges every `/api` request before the admin crate's handlers run: who the
//! caller is, whether the operation's scope admits them, whether their mutation budget is spent. It
//! also answers the paths no route matched. Those answers are verdicts — a stable `code`, a status
//! number and a caller-safe message — and this module is where each one is decided, once. The
//! framing (how a verdict becomes bytes on a wire) belongs to whoever writes the response, and the
//! admin crate's frozen error taxonomy reads its matching variants from here rather than restating
//! them.
//!
//! The other half of the gate's decision is [`required_scope`]: the scope an operation needs, from
//! its method and path as plain strings.

use busbar_contract::authz::Scope;

/// One answer the kernel gives on the operator surface without an admin handler running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The named thing does not exist. The message is `"<what> not found"`.
    NotFound {
        /// What was missing (`"resource"` for an unmatched path).
        what: String,
    },
    /// No credential, or one the operator chain did not accept.
    Unauthorized,
    /// The path exists on the surface but not with this method.
    MethodNotAllowed,
    /// The principal's mutation budget for this window is spent.
    RateLimited,
    /// An internal failure. The message is generic; details stay in the process.
    Internal,
}

impl Refusal {
    /// The frozen machine-stable code tooling branches on.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::NotFound { .. } => "not_found",
            Refusal::Unauthorized => "unauthorized",
            Refusal::MethodNotAllowed => "method_not_allowed",
            Refusal::RateLimited => "rate_limited",
            Refusal::Internal => "internal",
        }
    }

    /// The status number a framed response carries.
    pub fn status(&self) -> u16 {
        match self {
            Refusal::NotFound { .. } => 404,
            Refusal::Unauthorized => 401,
            Refusal::MethodNotAllowed => 405,
            Refusal::RateLimited => 429,
            Refusal::Internal => 500,
        }
    }

    /// The caller-safe human message.
    pub fn message(&self) -> String {
        match self {
            Refusal::NotFound { what } => format!("{what} not found"),
            Refusal::Unauthorized => {
                "missing or invalid admin credential (Bearer or x-admin-token)".to_string()
            }
            Refusal::MethodNotAllowed => "method not allowed for this resource".to_string(),
            Refusal::RateLimited => {
                "admin mutation rate limit exceeded; retry next minute".to_string()
            }
            Refusal::Internal => "internal error".to_string(),
        }
    }
}

/// The frozen error body every operator-surface refusal carries:
/// `{"error":{"code":<stable>,"message":<human>}}`. The one construction of those bytes; a framer
/// adds the status and content type.
pub fn envelope(code: &str, message: &str) -> String {
    serde_json::json!({"error": {"code": code, "message": message}}).to_string()
}

/// THE AUTHORIZATION MATRIX: the scope an operator-surface operation requires, derived from its
/// METHOD and PATH — never from the body, so a crafted request cannot escalate. Every read (`GET`,
/// `HEAD`) plus the two stateless dry-runs (`config/validate`, `plugins/inspect`, reads in POST
/// clothing whose body is the config to lint or the archive to preview) is `read-only`; every other
/// method needs `full`, and an unknown method fails closed to `full`. The method is compared
/// exactly: a lowercase `get` is an extension method, not a read.
pub fn required_scope(method: &str, path: &str) -> Scope {
    if method == "GET" || method == "HEAD" {
        return Scope::ReadOnly;
    }
    // Matched RELATIVE to the one prefix so the matrix cannot drift from the mount grammar. A path
    // outside the prefix (impossible for a mounted admin route) fails closed to `full`.
    let rel = path.strip_prefix(crate::api::ADMIN_PREFIX).unwrap_or(path);
    if rel == PATH_CONFIG_VALIDATE || rel == PATH_PLUGINS_INSPECT {
        return Scope::ReadOnly;
    }
    Scope::Full
}

/// `POST /config/validate` — the stateless config lint, read-only although it is a POST.
pub const PATH_CONFIG_VALIDATE: &str = "/config/validate";
/// `POST /plugins/inspect` — the stateless archive preview, read-only although it is a POST.
pub const PATH_PLUGINS_INSPECT: &str = "/plugins/inspect";

#[cfg(test)]
#[path = "tests/refusal_tests.rs"]
mod tests;

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The frozen 1.5.5 administrative error taxonomy: ten variants, ten `code` strings, ten statuses.
//!
//! ## Why the taxonomy lives beside the envelope
//!
//! [`refusal::envelope_of`](crate::refusal::envelope_of) already owned the wire SHAPE — the two keys,
//! their order, the quoting — and says so in its own doc comment: the shape lives there and nowhere
//! else, because a second `format!` of it somewhere else is a second chance for a surface a client
//! pinned to move in one place and not the other. What it did not own was the pair of strings it is
//! handed. Those came from an enum in the retiring surface's own crate, and every one of the
//! operations went through that enum to produce them.
//!
//! Shape in one crate and content in another is the same split with an extra seam: the `code` a
//! condition renders under and the status that accompanies it are as much the frozen contract as the
//! brace placement is, and neither half means anything without the other. So the taxonomy sits next
//! to the envelope it feeds, in the crate whose whole job is what this surface's bytes look like.
//!
//! ## What this is NOT
//!
//! It is not a decision about WHEN an operation is refused. Nothing here inspects a request, holds a
//! grant, or compares one against the other — [`AdminError`] is what a refusal that has already
//! happened is rendered as. The deciding is the units' (`busbar-unit-scope` compares a held grant
//! against a requirement; `busbar-unit-verbs` executes), exactly as this crate's own scope boundary
//! says.
//!
//! That boundary is also why [`AdminError::Forbidden`] carries a `&'static str` rather than a scope
//! value. The message needs the scope's WIRE TOKEN and has never needed anything else about it; a
//! plane naming the scope unit to obtain a token it immediately turns back into a string would be
//! the coupling the plugin contract exists to prevent, bought for nothing.
//!
//! ## Additive-only
//!
//! Fields may be added to a view and variants may be added here; an error `code` string is never
//! removed or repurposed once shipped. Some variants are exercised only by parts of the surface that
//! landed later than the taxonomy — it was defined whole so the frozen contract and its test lock
//! existed from the start.

/// The stable v1 error taxonomy. Each variant maps to a fixed `code` (the machine-stable branch key
/// tooling switches on — NEVER `message`) and an HTTP status the JSON-REST adapter uses. A non-HTTP
/// transport reads `code` and ignores the status. Adding a variant is additive; an existing `code`
/// string is frozen.
#[derive(Debug, Clone)]
pub enum AdminError {
    /// The named resource does not exist. `code = not_found`. `what` NAMES the missing thing (the
    /// message is `"<what> not found"`), and the optional `note` appends a parenthetical reason for
    /// the cases where "missing" has a cause worth stating — e.g. a single-key read on a server with
    /// governance disabled, where no key CAN exist. Build one with [`AdminError::not_found`] /
    /// [`AdminError::not_found_because`] rather than the variant, so the phrasing stays in one place.
    NotFound {
        /// The missing thing, named as the message will name it.
        what: String,
        /// A parenthetical cause, for an absence that is a property of the server rather than of
        /// the request.
        note: Option<&'static str>,
    },
    /// No/invalid admin credential (the auth middleware could not authenticate the caller).
    /// `code = unauthorized`. Distinct from `forbidden` (authenticated but under-scoped).
    Unauthorized,
    /// The path exists on the surface but not with this HTTP method. `code = method_not_allowed`.
    MethodNotAllowed,
    /// The principal's scope is insufficient for the endpoint. `code = forbidden`. Carries the WIRE
    /// TOKEN of the scope that would have sufficed, for a precise client message (never leaks other
    /// principals' data). A token rather than a scope value because the message has never needed
    /// anything else about it — see this module's doc comment.
    Forbidden {
        /// The wire token of the scope that would have sufficed (`read-only`, `full`).
        needed: &'static str,
    },
    /// The request is structurally invalid (bad field, unknown enum, failed validation).
    /// `code = invalid_request`.
    Validation(String),
    /// Optimistic-concurrency mismatch: the caller's `If-Match` is STALE — re-read the resource and
    /// retry. `code = version_conflict`. Split from `conflict`: a client must distinguish RETRYABLE
    /// (this) from TERMINAL state conflicts without string-matching the human message.
    VersionConflict(String),
    /// A TERMINAL state conflict: the request contradicts server state in a way a retry cannot fix
    /// (governance disabled, base-defined hook, immutable grant change, in-flight idempotency
    /// reservation). `code = conflict`.
    Conflict(String),
    /// The principal exhausted its per-minute mutation allowance. `code = rate_limited`.
    RateLimited,
    /// An internal failure (store/plugin). `code = internal`. The human `message` is generic; details
    /// are logged server-side, never returned.
    Internal,
    /// An operation that is normally fast could not complete (or even START) within its bound and was
    /// abandoned rather than left to hang the request indefinitely. `code = unavailable`. Unlike
    /// [`AdminError::Internal`] the message is specific and caller-safe (e.g. "the plugin catalog
    /// scan is taking too long") — this is a timeout/backpressure signal the caller can retry, not an
    /// internal defect.
    Unavailable(String),
}

impl AdminError {
    /// The plain "no such thing" — message `"<what> not found"`.
    #[must_use]
    pub fn not_found(what: impl Into<String>) -> Self {
        AdminError::NotFound {
            what: what.into(),
            note: None,
        }
    }

    /// A not-found WITH a reason — message `"<what> not found (<why>)"`. For the cases where the
    /// absence is a property of the server's configuration rather than of the request.
    #[must_use]
    pub fn not_found_because(what: impl Into<String>, why: &'static str) -> Self {
        AdminError::NotFound {
            what: what.into(),
            note: Some(why),
        }
    }

    /// The FROZEN stable code. Tooling branches on this string; it never changes for a shipped
    /// variant.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AdminError::NotFound { .. } => "not_found",
            AdminError::Unauthorized => "unauthorized",
            AdminError::MethodNotAllowed => "method_not_allowed",
            AdminError::Forbidden { .. } => "forbidden",
            AdminError::Validation(_) => "invalid_request",
            AdminError::VersionConflict(_) => "version_conflict",
            AdminError::Conflict(_) => "conflict",
            AdminError::RateLimited => "rate_limited",
            AdminError::Internal => "internal",
            AdminError::Unavailable(_) => "unavailable",
        }
    }

    /// The HTTP status the JSON-REST adapter returns for this error. A non-HTTP transport ignores it.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            AdminError::NotFound { .. } => 404,
            AdminError::Unauthorized => 401,
            AdminError::MethodNotAllowed => 405,
            AdminError::Forbidden { .. } => 403,
            AdminError::Validation(_) => 400,
            AdminError::VersionConflict(_) => 409,
            AdminError::Conflict(_) => 409,
            AdminError::RateLimited => 429,
            AdminError::Internal => 500,
            AdminError::Unavailable(_) => 503,
        }
    }

    /// The human-facing message. Caller-safe only — internal store/plugin detail never lands here.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            AdminError::NotFound {
                what,
                note: Some(why),
            } => format!("{what} not found ({why})"),
            AdminError::NotFound { what, note: None } => format!("{what} not found"),
            AdminError::Unauthorized => {
                "missing or invalid admin credential (Bearer or x-admin-token)".to_string()
            }
            AdminError::MethodNotAllowed => "method not allowed for this resource".to_string(),
            AdminError::Forbidden { needed } => {
                format!("insufficient scope: this endpoint requires `{needed}`")
            }
            AdminError::Validation(msg) => msg.clone(),
            AdminError::VersionConflict(msg) => msg.clone(),
            AdminError::Conflict(msg) => msg.clone(),
            AdminError::RateLimited => {
                "admin mutation rate limit exceeded; retry next minute".to_string()
            }
            AdminError::Internal => "internal error".to_string(),
            AdminError::Unavailable(msg) => msg.clone(),
        }
    }

    /// This error's whole body: the frozen envelope around this error's own code and message.
    ///
    /// The one place the taxonomy and the shape meet, so that no caller has to remember to bring
    /// them together in the right order. A transport adapter takes these bytes and adds the status
    /// [`AdminError::http_status`] gives it and the content type its wire format declares; nothing
    /// else about the body is any adapter's to decide.
    #[must_use]
    pub fn envelope(&self) -> String {
        crate::refusal::envelope_of(self.code(), &self.message())
    }
}

#[cfg(test)]
#[path = "tests/envelope.rs"]
mod tests;

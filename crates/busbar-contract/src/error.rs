// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE STRUCTURED ERROR A FACE CARRIES WHEN IT REFUSES A CALLER, and the frozen envelope it
//! renders into.
//!
//! ## Why this is contract and not any one kind's
//!
//! The v1 error taxonomy is the pair of strings every refusal of the node's management surface
//! reaches a client as: a machine-stable `code` tooling branches on and a caller-safe `message` a
//! human reads, wrapped in a two-key document a client pinned. It was split across two crates — the
//! SHAPE rendered in one, the CONTENT in another, and each rendering the other's half a second time
//! — and a split like that is a surface that can move in one place and not the other.
//!
//! Putting the two halves together is right. Putting them together inside ONE KIND's crate is not:
//! the retiring engine would then have to name that kind's crate in order to refuse a caller, which
//! is exactly the coupling this release exists to remove, and the purity rule refuses it by name. So
//! the pair lives HERE, in the face every kind is written against, and is reached the same way by
//! every crate that renders a refusal — the composition root, the management surface, and the engine
//! still being drained — none of which reaches either of the others.
//!
//! ## Kind-neutral names, frozen strings
//!
//! Nothing here is named for a kind. [`ErrorClass`] is the closed set of conditions a face may
//! refuse under; [`PluginError`] is one refusal, its class plus the caller-safe detail that class
//! carries. What IS frozen — because a client pinned it — is the ten `code` strings, the ten
//! statuses, the message phrasing and the envelope's two keys and their order. A variant may be
//! added; a shipped `code` is never removed or repurposed.
//!
//! ## What this is NOT
//!
//! It is not a decision about WHEN a caller is refused. Nothing here inspects a request, holds a
//! grant or reads a policy. It is the vocabulary a refusal is SAID IN, and the ten variants were
//! defined whole so that the frozen contract and its test lock existed from the start — some are
//! exercised only by parts of the surface that landed later than the taxonomy.

/// The closed set of conditions a face refuses a caller under.
///
/// CLOSED, like every other grammar in this crate: a new class is a contract change and is meant to
/// look like one. The `code` is the machine-stable branch key — tooling switches on it and NEVER on
/// the message — and the numeric status is what an adapter whose wire format carries one answers
/// with. A dialect that has none reads the code and ignores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum ErrorClass {
    /// The named thing does not exist.
    NotFound,
    /// No credential, or one that did not authenticate. Distinct from [`ErrorClass::Forbidden`],
    /// which is an authenticated caller that is under-scoped.
    Unauthorized,
    /// The path exists on the surface but not with this method.
    MethodNotAllowed,
    /// The caller authenticated and lacks the scope this operation requires.
    Forbidden,
    /// The request is structurally invalid — a bad field, an unknown enum, a failed validation.
    Validation,
    /// Optimistic-concurrency mismatch: the caller's precondition is STALE. Re-read and retry.
    /// Split from [`ErrorClass::Conflict`] so a client can tell RETRYABLE from TERMINAL without
    /// string-matching a human message.
    VersionConflict,
    /// A TERMINAL state conflict: the request contradicts server state in a way a retry cannot fix.
    Conflict,
    /// The caller exhausted a per-window allowance.
    RateLimited,
    /// An internal failure. The message is generic; detail is logged and never returned.
    Internal,
    /// Something normally fast could not complete — or even start — within its bound and was
    /// abandoned rather than left to hang the request. Unlike [`ErrorClass::Internal`] the message
    /// is specific and caller-safe: this is backpressure a caller can retry, not a defect.
    Unavailable,
}

impl ErrorClass {
    /// The FROZEN stable code. Tooling branches on this string; it never changes for a shipped
    /// class.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            ErrorClass::NotFound => "not_found",
            ErrorClass::Unauthorized => "unauthorized",
            ErrorClass::MethodNotAllowed => "method_not_allowed",
            ErrorClass::Forbidden => "forbidden",
            ErrorClass::Validation => "invalid_request",
            ErrorClass::VersionConflict => "version_conflict",
            ErrorClass::Conflict => "conflict",
            ErrorClass::RateLimited => "rate_limited",
            ErrorClass::Internal => "internal",
            ErrorClass::Unavailable => "unavailable",
        }
    }

    /// The numeric status an adapter whose wire format carries one answers this class with.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            ErrorClass::NotFound => 404,
            ErrorClass::Unauthorized => 401,
            ErrorClass::MethodNotAllowed => 405,
            ErrorClass::Forbidden => 403,
            ErrorClass::Validation => 400,
            ErrorClass::VersionConflict | ErrorClass::Conflict => 409,
            ErrorClass::RateLimited => 429,
            ErrorClass::Internal => 500,
            ErrorClass::Unavailable => 503,
        }
    }
}

/// ONE refusal: its [`ErrorClass`] and the caller-safe detail that class carries.
///
/// The detail is part of the variant rather than a free-form string beside the class, because the
/// classes do not all carry the same thing and a type that pretends they do is a type that lets a
/// caller put a store's error text in an `Internal`. What a variant carries is exactly what its
/// message renders.
#[derive(Debug, Clone)]
pub enum PluginError {
    /// The named thing does not exist. `what` NAMES the missing thing — the message is
    /// `"<what> not found"` — and `note` appends a parenthetical cause for the cases where the
    /// absence is a property of the server rather than of the request (a single-key read on a node
    /// whose key store is switched off, where no key CAN exist). Build one with
    /// [`PluginError::not_found`]
    /// or [`PluginError::not_found_because`] rather than the variant, so the phrasing stays in one
    /// place.
    NotFound {
        /// The missing thing, named as the message will name it.
        what: String,
        /// A parenthetical cause, for an absence that is the server's property and not the
        /// request's.
        note: Option<&'static str>,
    },
    /// No credential, or one that did not authenticate.
    Unauthorized,
    /// The path exists on the surface but not with this method.
    MethodNotAllowed,
    /// The caller is under-scoped, carrying the WIRE TOKEN of the scope that would have sufficed.
    ///
    /// A token rather than a scope value, deliberately: the message has never needed anything else
    /// about the scope, and this crate may not name the crate that decides one. Obtaining a value
    /// only to turn it straight back into a string would buy that coupling for nothing.
    Forbidden {
        /// The wire token of the scope that would have sufficed.
        needed: &'static str,
    },
    /// The request is structurally invalid; the string is the caller-safe complaint.
    Validation(String),
    /// The caller's precondition is stale; the string says which.
    VersionConflict(String),
    /// A terminal state conflict; the string says which.
    Conflict(String),
    /// The caller exhausted a per-window allowance.
    RateLimited,
    /// An internal failure. Carries nothing: detail is logged server-side and never returned.
    Internal,
    /// Backpressure or a bound reached; the string is the caller-safe reason.
    Unavailable(String),
}

impl PluginError {
    /// The plain "no such thing" — message `"<what> not found"`.
    #[must_use]
    pub fn not_found(what: impl Into<String>) -> Self {
        PluginError::NotFound {
            what: what.into(),
            note: None,
        }
    }

    /// A not-found WITH a reason — message `"<what> not found (<why>)"`.
    #[must_use]
    pub fn not_found_because(what: impl Into<String>, why: &'static str) -> Self {
        PluginError::NotFound {
            what: what.into(),
            note: Some(why),
        }
    }

    /// Which of the ten this is.
    #[must_use]
    pub const fn class(&self) -> ErrorClass {
        match self {
            PluginError::NotFound { .. } => ErrorClass::NotFound,
            PluginError::Unauthorized => ErrorClass::Unauthorized,
            PluginError::MethodNotAllowed => ErrorClass::MethodNotAllowed,
            PluginError::Forbidden { .. } => ErrorClass::Forbidden,
            PluginError::Validation(_) => ErrorClass::Validation,
            PluginError::VersionConflict(_) => ErrorClass::VersionConflict,
            PluginError::Conflict(_) => ErrorClass::Conflict,
            PluginError::RateLimited => ErrorClass::RateLimited,
            PluginError::Internal => ErrorClass::Internal,
            PluginError::Unavailable(_) => ErrorClass::Unavailable,
        }
    }

    /// The FROZEN stable code — this refusal's class's code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.class().code()
    }

    /// The numeric status an adapter whose wire format carries one answers this refusal with.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.class().status()
    }

    /// The human-facing message. Caller-safe only — internal store or plugin detail never lands
    /// here, which is why [`PluginError::Internal`] carries nothing to render.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            PluginError::NotFound {
                what,
                note: Some(why),
            } => format!("{what} not found ({why})"),
            PluginError::NotFound { what, note: None } => format!("{what} not found"),
            PluginError::Unauthorized => {
                "missing or invalid admin credential (Bearer or x-admin-token)".to_string()
            }
            PluginError::MethodNotAllowed => "method not allowed for this resource".to_string(),
            PluginError::Forbidden { needed } => {
                format!("insufficient scope: this endpoint requires `{needed}`")
            }
            PluginError::Validation(msg)
            | PluginError::VersionConflict(msg)
            | PluginError::Conflict(msg)
            | PluginError::Unavailable(msg) => msg.clone(),
            PluginError::RateLimited => {
                "admin mutation rate limit exceeded; retry next minute".to_string()
            }
            PluginError::Internal => "internal error".to_string(),
        }
    }

    /// This refusal's whole body: the frozen envelope around its own code and message.
    ///
    /// The one place the taxonomy and the shape meet, so no caller has to remember to bring them
    /// together in the right order. An adapter takes these bytes and adds the status
    /// [`PluginError::status`] gives it and the content type its wire format declares; nothing else
    /// about the body is any adapter's to decide.
    #[must_use]
    pub fn envelope(&self) -> String {
        envelope_of(self.code(), &self.message())
    }
}

/// The frozen v1 envelope around one code and one message.
///
/// THE SHAPE LIVES HERE AND NOWHERE ELSE. Which code a condition renders under is a different
/// question for the side of the tree that maps a refusal reason than for the composition root
/// (which maps a kernel reason code and pairs it with a status), and those two tables legitimately
/// differ because they answer different questions — but the two keys, their order, the quoting and the absence of a
/// trailing byte are ONE frozen wire shape, and a second `format!` of it somewhere else is a second
/// chance for the surface a client pinned to change in one place and not the other. So the callers
/// bring the code and the message, and this brings the envelope.
///
/// SERIALIZED, not hand-formatted. The two are the same bytes for a caller that brings closed,
/// quote-free prose, and they stop being the same bytes the moment a message carries text a CALLER
/// wrote — a resource name in a not-found, the human half of a validation complaint — because a `"`
/// in one of those closes the string early and hands the reader a different document, with a `code`
/// its parser never reaches. The escape set is JSON's, not this crate's, so the honest way to apply
/// it is to ask the serializer.
///
/// The key order is `code` then `message` whichever way the map is built — the serializer orders a
/// map's keys and `code` sorts before `message` — so the frozen shape does not depend on the order
/// this function happens to insert them in.
#[must_use]
pub fn envelope_of(code: &str, message: &str) -> String {
    serde_json::json!({ "error": { "code": code, "message": message } }).to_string()
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The client-facing answers this unit can produce, and the literal words in them.

/// The kind a shed carries when the pool had nowhere to send the request.
pub const KIND_OVERLOADED: &str = "overloaded";

/// The words a shed says when the pool is exhausted.
pub const DETAIL_OVERLOADED: &str = "The service is temporarily overloaded. Please retry shortly.";

/// The kind an internal failure before any send carries.
pub const KIND_API_ERROR: &str = "api_error";

/// The words a shed says when the walk deadline passed before an attempt could start.
pub const DETAIL_REQUEST_TIMEOUT: &str = "The request timed out. Please retry shortly.";

/// The words an internal failure before any send says.
pub const DETAIL_INTERNAL_ERROR: &str =
    "We received an unexpected internal error. Please try again.";

/// The words a spill says when a gate's restriction left no eligible member in the pool it spilled
pub const DETAIL_RESTRICT_NO_LANE: &str =
    "No upstream satisfies a required gate's restriction. Please retry shortly.";

/// The status every shed above carries.
pub const STATUS_SERVICE_UNAVAILABLE: u16 = 503;

/// The status an internal failure before any send carries.
pub const STATUS_INTERNAL_ERROR: u16 = 500;

/// A refusal this unit produced, in the words the previous release used.
///
/// The `retry_after_secs` field is what the exhaustion terminal computed from the pool's own
/// members; it is present only where the previous release sent the header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shed {
    /// The status the client sees.
    pub status: u16,
    /// The dialect-agnostic kind the plane maps into its own envelope.
    pub kind: &'static str,
    /// The words.
    pub detail: &'static str,
    /// How long the client should wait, where the terminal computed one.
    pub retry_after_secs: Option<u64>,
    /// Whether a gate's restriction, rather than capacity, produced this refusal. The previous
    /// release marked these separately so a compliance shed is distinguishable from an overload
    /// shed in the metrics.
    pub gate_rejected: bool,
}

impl Shed {
    /// A shed with no advertised wait: the one literal every constructor below reads from.
    const fn of(
        status: u16,
        kind: &'static str,
        detail: &'static str,
        gate_rejected: bool,
    ) -> Self {
        Self {
            status,
            kind,
            detail,
            retry_after_secs: None,
            gate_rejected,
        }
    }

    /// The pool is exhausted: the overload shed with the terminal's computed wait.
    #[must_use]
    pub fn overloaded(retry_after_secs: u64) -> Self {
        Self {
            retry_after_secs: Some(retry_after_secs),
            ..Self::empty_pool()
        }
    }

    /// The walk deadline passed. No wait is advertised: the previous release sent this one with no
    #[must_use]
    pub fn request_timeout() -> Self {
        Self::of(
            STATUS_SERVICE_UNAVAILABLE,
            KIND_OVERLOADED,
            DETAIL_REQUEST_TIMEOUT,
            false,
        )
    }

    /// The pool has no members at all. Same words as an exhausted pool and, like the previous
    #[must_use]
    pub fn empty_pool() -> Self {
        Self::of(
            STATUS_SERVICE_UNAVAILABLE,
            KIND_OVERLOADED,
            DETAIL_OVERLOADED,
            false,
        )
    }

    /// A gate's restriction left no eligible member in the pool a spill landed in.
    #[must_use]
    pub fn restrict_no_lane() -> Self {
        Self::of(
            STATUS_SERVICE_UNAVAILABLE,
            KIND_OVERLOADED,
            DETAIL_RESTRICT_NO_LANE,
            true,
        )
    }

    /// Nothing could be sent and nothing was recorded against the member: the dispatch could not
    #[must_use]
    pub fn internal() -> Self {
        Self::of(
            STATUS_INTERNAL_ERROR,
            KIND_API_ERROR,
            DETAIL_INTERNAL_ERROR,
            false,
        )
    }
}

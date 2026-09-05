// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The client-facing answers this unit can produce, and the literal words in them.
//!
//! Every string in this module is the one the previous release put on the wire. They are gathered
//! here, once, so a terminal cannot quietly reword itself: the walk and the four exhaustion
//! terminals all build their answer from these constants, and the tests assert the constants
//! rather than a paraphrase.
//!
//! What this unit produces is a DESCRIPTION of the answer — a status, a kind, a detail and a
//! retry hint — not the bytes. The bytes are the plane's: the kernel hands this description to the
//! plane's refusal encoder, so the same shed renders in each dialect's own envelope, exactly as
//! the previous release rendered its 503 through the ingress protocol's native error writer.

/// The kind a shed carries when the pool had nowhere to send the request.
pub const KIND_OVERLOADED: &str = "overloaded";

/// The kind a body that could not be read carries.
pub const KIND_INVALID_REQUEST: &str = "invalid_request_error";

/// The kind an internal failure before any send carries.
pub const KIND_API_ERROR: &str = "api_error";

/// The words a shed says when the pool is exhausted.
pub const DETAIL_OVERLOADED: &str = "The service is temporarily overloaded. Please retry shortly.";

/// The words a shed says when the walk deadline passed before an attempt could start.
pub const DETAIL_REQUEST_TIMEOUT: &str = "The request timed out. Please retry shortly.";

/// The words an internal failure before any send says.
pub const DETAIL_INTERNAL_ERROR: &str =
    "We received an unexpected internal error. Please try again.";

/// The words an unreadable body says.
pub const DETAIL_INVALID_JSON: &str = "We could not parse the JSON body of your request.";

/// The words a spill says when a gate's restriction left no eligible member in the pool it spilled
/// into. Failing closed here is the point: spilling into a member the restriction excludes would
/// break the promise that a restriction holds across a failover.
pub const DETAIL_RESTRICT_NO_LANE: &str =
    "No upstream satisfies a required gate's restriction. Please retry shortly.";

/// The status every shed above carries.
pub const STATUS_SERVICE_UNAVAILABLE: u16 = 503;

/// The status a body that could not be read carries.
pub const STATUS_BAD_REQUEST: u16 = 400;

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
    /// The pool is exhausted: the overload shed with the terminal's computed wait.
    #[must_use]
    pub fn overloaded(retry_after_secs: u64) -> Self {
        Self {
            status: STATUS_SERVICE_UNAVAILABLE,
            kind: KIND_OVERLOADED,
            detail: DETAIL_OVERLOADED,
            retry_after_secs: Some(retry_after_secs),
            gate_rejected: false,
        }
    }

    /// The walk deadline passed. No wait is advertised: the previous release sent this one with no
    /// `Retry-After` at all, and a client that has already waited out the whole budget is not told
    /// to wait again.
    #[must_use]
    pub fn request_timeout() -> Self {
        Self {
            status: STATUS_SERVICE_UNAVAILABLE,
            kind: KIND_OVERLOADED,
            detail: DETAIL_REQUEST_TIMEOUT,
            retry_after_secs: None,
            gate_rejected: false,
        }
    }

    /// The pool has no members at all. Same words as an exhausted pool and, like the previous
    /// release's own arm, no wait: there is nothing to wait for.
    #[must_use]
    pub fn empty_pool() -> Self {
        Self {
            status: STATUS_SERVICE_UNAVAILABLE,
            kind: KIND_OVERLOADED,
            detail: DETAIL_OVERLOADED,
            retry_after_secs: None,
            gate_rejected: false,
        }
    }

    /// A gate's restriction left no eligible member in the pool a spill landed in.
    #[must_use]
    pub fn restrict_no_lane() -> Self {
        Self {
            status: STATUS_SERVICE_UNAVAILABLE,
            kind: KIND_OVERLOADED,
            detail: DETAIL_RESTRICT_NO_LANE,
            retry_after_secs: None,
            gate_rejected: true,
        }
    }

    /// The request body was not the shape its content type claimed.
    #[must_use]
    pub fn invalid_body() -> Self {
        Self {
            status: STATUS_BAD_REQUEST,
            kind: KIND_INVALID_REQUEST,
            detail: DETAIL_INVALID_JSON,
            retry_after_secs: None,
            gate_rejected: false,
        }
    }

    /// The attempt could not be assembled. Nothing was sent and nothing was recorded.
    #[must_use]
    pub fn internal() -> Self {
        Self {
            status: STATUS_INTERNAL_ERROR,
            kind: KIND_API_ERROR,
            detail: DETAIL_INTERNAL_ERROR,
            retry_after_secs: None,
            gate_rejected: false,
        }
    }
}

/// What one leg of a route came back with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteOutcome {
    /// An upstream answered and its frames were relayed under the hold.
    Delivered(Delivered),
    /// Nothing was delivered; this is the refusal the client sees.
    Refused(Shed),
}

impl RouteOutcome {
    /// The refusal, where the leg produced one.
    #[must_use]
    pub fn shed(&self) -> Option<&Shed> {
        match self {
            Self::Refused(s) => Some(s),
            Self::Delivered(_) => None,
        }
    }

    /// Whether an upstream answered.
    #[must_use]
    pub fn is_delivered(&self) -> bool {
        matches!(self, Self::Delivered(_))
    }
}

/// A delivered answer: which member served it, what the transport made of it, and how many frames
/// were relayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    /// Which member of the verified set served the request.
    pub destination: crate::ports::DestinationId,
    /// Which pool cell the attempt was recorded against.
    pub pool: String,
    /// The transport's own reading of the first relayed frame, where it carries one.
    pub status: Option<busbar_contract::StatusClass>,
    /// How many response frames were relayed to the client.
    pub frames: usize,
    /// The plane's reading of how the answer ended.
    pub finish: Option<busbar_contract::FinishClass>,
    /// Whether the answer came off a degraded path (a spill, a queued permit, or the one
    /// documented breaker bypass) rather than the ordered walk.
    pub degraded: bool,
    /// The upstream's own refusal, relayed as-is. Only a degraded caller asks for this; the walk
    /// fails over instead.
    pub relayed_error: Option<u16>,
}

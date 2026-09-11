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

use busbar_caps::{BodyLease, Completion};

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

/// WHAT ONE LEG OF A ROUTE ANSWERED, AND THE RELAY IT LEFT BEHIND IT.
///
/// The walk answers with this rather than with the outcome alone, and the reason is the whole of
/// the body pump: the outcome is known at the FIRST frame and the body is still arriving. A walk
/// that returned only the outcome had to drain the answer before it could answer at all, which
/// made the kernel's hold over the routed body a hold over a body that was already drained.
///
/// The pump is `None` for every leg that delivered nothing, and for the one-frame refusal a
/// degraded caller relays as-is — an answer that was over before it got here has no stream left.
pub struct Routed<'a> {
    /// What came back.
    pub outcome: RouteOutcome,
    /// The relay, unrun. The ROOT drives it, on the runtime the frames are arriving on.
    pub pump: Option<crate::attempt::BodyPump<'a>>,
}

impl Routed<'_> {
    /// A leg that delivered nothing: the refusal, and no body to relay.
    #[must_use]
    pub fn refused(shed: Shed) -> Self {
        Routed {
            outcome: RouteOutcome::Refused(shed),
            pump: None,
        }
    }

    /// The refusal, where the leg produced one.
    #[must_use]
    pub fn shed(&self) -> Option<&Shed> {
        self.outcome.shed()
    }

    /// Whether an upstream answered.
    #[must_use]
    pub fn is_delivered(&self) -> bool {
        self.outcome.is_delivered()
    }
}

impl std::fmt::Debug for Routed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Routed")
            .field("outcome", &self.outcome)
            .field("pump", &self.pump.is_some())
            .finish()
    }
}

/// WHAT THE RELAY MADE OF THE ANSWER'S BODY, once the body finished.
///
/// Three readings of one stream, produced together by the one pass that made them, and kept
/// together because they are one instant: how many frames went past, what the PLANE made of the
/// ending, and what the answer carried per dimension the plane declared.
///
/// It is a value of its own and not three fields on the delivered answer, because it does not exist
/// at the same time the delivered answer does. The answer's head is known when the first frame
/// comes back; what the body carried is known when the last one does, and between those two
/// instants the walk has returned and the unit is not blocked on anything. A type that carried both
/// would be a type with three fields that are hollow for the length of an upstream call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Relayed {
    /// How many response frames were relayed to the client.
    pub frames: usize,
    /// The PLANE's reading of how the answer ended — its own decode of the frames, and never the
    /// transport's status re-derived. This is the second of the fee decision's two sources, and
    /// the reason it is independent is that it is read from a different thing.
    pub finish: Option<busbar_contract::FinishClass>,
    /// WHAT THE STREAM CARRIED, as the relay counted it while it ran.
    ///
    /// Quantities against declared keys and never an amount: what a quantity is worth is the cost
    /// unit's answer, and a plane that could name an amount could name an invoice. The frames and
    /// the bytes are this unit's own count of what it relayed; the per-class dimensions are the
    /// PLANE's declared locators evaluated over the plane's own decoded response, which is a
    /// reading this unit does not make — it holds a value the plane produced and asks the plane
    /// what is in it.
    ///
    /// It travels rather than being recomputed at the meter because there is no second reading of
    /// the body to recompute it from: the bytes were the transport's and by the time the meter runs
    /// they are gone. One reading, carried forward, is what makes the money side's figure and the
    /// relay's figure incapable of disagreeing.
    pub carried: Completion,
}

/// A delivered answer's HEAD: which member served it and what the transport made of it.
///
/// Everything here is known at the FIRST frame. What the body carried is [`Relayed`], and it
/// arrives when the pump the walk handed back has finished.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    /// Which member of the verified set served the request.
    pub destination: crate::ports::DestinationId,
    /// Which pool cell the attempt was recorded against.
    pub pool: String,
    /// The transport's own reading of the first relayed frame, where it carries one. This is the
    /// first of the fee decision's two sources.
    pub status: Option<busbar_contract_transport::wire::StatusClass>,
    /// Whether the answer came off a degraded path (a spill, a queued permit, or the one
    /// documented breaker bypass) rather than the ordered walk.
    pub degraded: bool,
    /// The upstream's own refusal, relayed as-is — the number AND the numbering that spelled it,
    /// because a relayed `14` that does not say it is gRPC's is a number a reader can only guess
    /// at. Only a degraded caller asks for this; the walk fails over instead.
    pub relayed_error: Option<busbar_contract_transport::wire::WireStatus>,
    /// THE ANSWER'S BODY, NAMED AND NEVER CARRIED: the lease the stream it came back on is held
    /// under.
    ///
    /// A handle, so this unit does not buffer. Taking the bytes here would mean draining the body
    /// here, and on a billing plane the instant a body finishes draining is the instant the money
    /// is read — a seam that buffered would be deciding when a stream ended, which is a decision
    /// that moves money and is not this unit's to make. So the outcome names the stream, the
    /// KERNEL holds it under the unit's hold across this call's return, and the Meter step reads
    /// what it carried. Nothing in this crate ever reads a body, and this field is what keeps that
    /// true while still giving the meter something to read.
    pub body: BodyLease,
    /// WHAT THE RELAY MADE OF THE BODY, where the whole answer left this unit in one piece.
    ///
    /// `None` is the ordinary case and it means the body has NOT been relayed yet: the walk has
    /// answered with the head and handed back a pump, and the reading arrives when the root has
    /// driven it. `Some` is the one-frame answer a degraded caller relays as-is, which was over
    /// before it got here and has no stream left to pump.
    ///
    /// It is an option and not a hollow value for a reason that is about readers: a caller that
    /// reads a frame count of zero off an answer that has not been relayed yet has read a lie, and
    /// there is no spelling of zero that says "not yet".
    pub relayed: Option<Relayed>,
}

impl Delivered {
    /// THE ANSWER'S HEAD, as the fee decision reads it — from TWO sources, one each.
    ///
    /// The transport's status class is this value's; the plane's finish is the relay's, read off
    /// the plane's own decode of the frames that followed. That is what makes them independent and
    /// it is the whole of why the kernel's dispute arm is reachable at all: a leg that derived the
    /// finish from the status had two sources that were one source, and a mid-stream cut after a
    /// good head billed the same fee a clean answer did and flagged nothing.
    ///
    /// `at` is the transport's own declaration of WHICH frame carries its status, and it is an
    /// argument rather than a reading because this unit is handed a transport behind a port and the
    /// composition root is the one place entitled to know which transport is under which plane.
    #[must_use]
    pub fn head(
        &self,
        at: Option<busbar_contract::StatusAt>,
        relayed: &Relayed,
    ) -> busbar_contract::StatusLeg {
        busbar_contract::StatusLeg {
            at,
            status: self.status,
            finish: relayed.finish,
            // A frame reached the client. A status frame with an empty body counts, which is why
            // this reads the relay's count and not the body's byte total.
            delivered: relayed.frames > 0,
            degraded: self.degraded,
            relayed_error: self.relayed_error,
        }
    }
}

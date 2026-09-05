// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The seams this unit is bound to, and nothing behind them.
//!
//! The egress unit owns the pool, the walk and the attempt. It does NOT own the breaker's state
//! machine, the credential that decorates an outbound request, the durable record that has to land
//! before a dial, or the concurrency permits the pool hands out. Each of those is another unit's,
//! and each enters here as one small trait.
//!
//! Every trait in this module is marked `// contract:` at its definition. That marker means the
//! same thing everywhere it appears in this crate: the shape is settled and the walk is written
//! against it, but the implementation belongs to another crate and the integrator binds it. A
//! marker is not a placeholder for a decision that has not been made — it is the record of a
//! decision made in a different unit.

use std::future::Future;
use std::pin::Pin;

use busbar_caps::{Route, UnitToken};

/// Which member of the verified set a call is about.
///
/// This is a position in the pool's member list, which is what the previous release's selection,
/// exclusion and breaker calls all keyed on. Keeping the same key is what makes the pick order
/// comparable hop for hop against the release that shipped.
///
/// The contract crate defines it, and the breaker unit names the same one, so the two units that
/// key on a pool member key on the same object at the same width. There is nothing left to narrow.
pub use busbar_contract::DestinationId;

/// The one boxed future this crate's ports return.
///
/// Same reasoning as the transport axis in the contract crate: an asynchronous trait method has to
/// box its future, and one box per port call is the price of the seam being a trait at all.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ── the breaker seam ────────────────────────────────────────────────────────────────────────────

/// Why a member cannot take a request right now.
///
/// This is the taxonomy every consumer in this crate speaks: selection excludes on it, the
/// least-bad terminal ranks on it, the wait terminal decides whether waiting could ever help from
/// it, and the shed's retry hint is computed from it. One list, so those five can never disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// Administratively down. Does not recover without a configuration change.
    Dead,
    /// The destination's lifetime request budget is spent. Does not recover.
    BudgetExhausted,
    /// The breaker is open, or a closed cell is still inside a pending cooldown. `until` is exact.
    BreakerOpen {
        /// When the cooldown ends, in whole seconds since the epoch.
        until: u64,
    },
    /// A peer holds the single-flight recovery probe. Resolves within one request.
    ProbeInFlight,
    /// Every concurrency permit is held. This is the only reason that waiting can cure, which is
    /// why the wait terminal tests for it by name.
    AtCapacity {
        /// An estimate of when a permit frees, where there is a basis for one.
        drain_hint_ms: Option<u64>,
    },
}

impl Unavailable {
    /// The stable name of this reason, for a diagnostic an operator reads.
    #[must_use]
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::Dead => "dead",
            Self::BudgetExhausted => "budget_exhausted",
            Self::BreakerOpen { .. } => "breaker_open",
            Self::ProbeInFlight => "probe_in_flight",
            Self::AtCapacity { .. } => "at_capacity",
        }
    }
}

/// What a successful admission hands over.
///
/// The probe epoch is an owner token, not a flag. A dispatch that abandons after an await could
/// otherwise release a probe a different request has since won, so every release is checked
/// against the epoch that was captured at the moment of the win.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admit {
    /// Set only when this admission actually won a half-open recovery probe. A plain ready-cell
    /// admission wins nothing and owns nothing to release.
    pub probe_epoch: Option<u64>,
}

/// What one attempt meant to the destination's breaker.
///
/// The 31-row table that turns an upstream status into one of these is the breaker unit's data,
/// not this unit's code. This unit hands over the classified answer and the upstream's own retry
/// request; what that does to a cooldown is decided on the other side of this trait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The upstream served the request.
    Success,
    /// A transient failure. Cooldown and error counter, with the upstream's own wait as a floor.
    Transient {
        /// The wait the upstream asked for, in seconds, where it asked for one.
        retry_after: Option<u64>,
    },
    /// A definitive signal about the shared destination — a rejected key, an exhausted account.
    /// It trips every pool's cell for that destination, not only the one this attempt ran through.
    HardDown,
    /// The caller's own fault, or a request too large for this destination's window. The
    /// destination is healthy either way and nothing is recorded.
    RecordNothing,
}

/// What the upstream said, as the classifier reads it.
///
/// The unit reads no body: the transport's own status reading and the plane's finish class are the
/// two legs, and the wait the upstream asked for is the third input. Everything else about what a
/// given code means to a given destination is configuration, and it lives on the other side of the
/// classify call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UpstreamStatus {
    /// The transport's own reading of the frame, where it carries one.
    pub class: Option<busbar_contract_transport::wire::StatusClass>,
    /// The upstream's numeric status, where the transport reports one.
    pub code: Option<u16>,
    /// The wait the upstream asked for, in seconds.
    pub retry_after: Option<u64>,
}

/// Where a classified failure sends the request next.
///
/// This is the walk's own vocabulary, and it is exhaustive on purpose: a new disposition breaks
/// the build here rather than falling through some default arm on the request path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// The caller's own bad input. The destination is not penalised and the answer is relayed.
    ClientFault,
    /// A transient upstream failure. The walk fails over.
    TransientUpstream,
    /// A definitive signal about the shared destination.
    HardDown,
    /// The request is too large for this destination's window. The destination is healthy; the
    /// walk excludes every member that shares or undercuts the limit and fails over.
    ContextLength,
}

/// What the classifier made of one upstream answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Classified {
    /// Where the walk sends the request next.
    pub disposition: Disposition,
    /// What the destination's breaker should be told.
    pub outcome: Outcome,
    /// The metric label for this failure.
    pub label: &'static str,
}

/// `// contract:` the breaker unit, as this unit needs it.
///
/// Bound by the integrator to `busbar-unit-breaker`. Six of the eight methods below map one to one
/// onto that crate's own surface; `ready` and `admissible` are the side-effect-free peeks the
/// order needs, which the breaker unit answers from `state`.
///
/// The division of labour is the design's: this unit decides WHO is asked first, the breaker
/// decides WHO IS ALLOWED. Nothing in the order may mutate a cell — that is what keeps the order
/// from being a second selection loop — so `ready` and `admissible` must not transition anything.
pub trait Breaker: Send + Sync {
    /// Mutating admission: win or lose the single-flight probe on this cell. This is the ONE call
    /// in the walk that can change a cell's state before the request is sent.
    ///
    /// # Errors
    /// Returns why the member cannot take the request, for the exclusion record the exhaustion
    /// terminal reads.
    fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, Unavailable>;

    /// Side-effect-free: could this cell take a request right now? The order's own filter, and the
    /// same predicate the weighted walk applies before its credit walk.
    fn ready(&self, pool: &str, destination: DestinationId, now: u64) -> bool;

    /// Side-effect-free: is this destination usable at all — not administratively down, and with
    /// lifetime budget left? This is a property of the destination, not of one pool's cell, which
    /// is why it takes no pool.
    fn admissible(&self, destination: DestinationId) -> bool;

    /// Side-effect-free: how many whole seconds of genuine cooldown this cell has left, or zero.
    fn cooldown_remaining(&self, pool: &str, destination: DestinationId, now: u64) -> u64;

    /// Turn one upstream answer into a disposition and a breaker outcome.
    ///
    /// The table behind this — which code from which destination means transient, which means the
    /// key is bad, which means the request was simply too big — is the breaker unit's own data,
    /// including the operator's per-destination overrides. This unit passes the answer through and
    /// acts on what comes back; it holds no copy of the table and no literal from it.
    fn classify(&self, destination: DestinationId, status: UpstreamStatus) -> Classified;

    /// Record what one attempt meant. Returns true only on a fresh logical trip — the one signal a
    /// trip counter should increment on, never a re-trip of an already-open cell.
    ///
    /// `token` is the capability token that proves the loop is at the route step for this unit
    /// right now (per `busbar-caps`'s `&UnitToken<Route>`, mirroring the breaker unit's own sealed
    /// `Breaker::observe`, CG-29) — this unit's `route` entry point already receives one; every
    /// call down through the walk to this port threads the same borrow.
    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        now: u64,
        token: &UnitToken<Route>,
    ) -> bool;

    /// Release a probe that was won but never dispatched. Owner-checked against the epoch that was
    /// captured at the win, so a late release cannot revert a newer probe.
    fn release_probe(&self, pool: &str, destination: DestinationId, epoch: u64, now: u64);

    /// Spend one unit of the destination's lifetime request budget. True when the spend happened
    /// or the destination is unbounded; false when it was already spent out.
    ///
    /// The design pins the moment: one unit is spent AFTER the upstream's success is read, never
    /// at selection, and it is reversed only on the endings the previous release reversed it on.
    fn spend_budget(&self, destination: DestinationId) -> bool;

    /// Give back one unit spent by a delivery that then failed to complete. The refund is
    /// unconditional on this side, so a caller must only call it for a spend that happened.
    fn refund_budget(&self, destination: DestinationId);
}

// ── the pool's own concurrency ──────────────────────────────────────────────────────────────────

/// A held concurrency slot on one member.
///
/// Dropping it frees the slot. It is held for the whole life of a streamed answer and dropped on
/// every failure, which is why it is passed by value into the attempt and never borrowed.
#[derive(Debug)]
#[must_use = "a permit that is dropped immediately frees the slot the attempt was about to use"]
pub struct Permit(Box<dyn PermitHandle>);

impl Permit {
    /// Wrap a store's own permit.
    pub fn new(handle: Box<dyn PermitHandle>) -> Self {
        Self(handle)
    }

    /// Which member the slot is on.
    #[must_use]
    pub fn destination(&self) -> DestinationId {
        self.0.destination()
    }
}

/// `// contract:` what a permit store puts behind a [`Permit`]. Dropping the handle must free the
/// slot; nothing in this crate calls a release verb.
pub trait PermitHandle: std::fmt::Debug + Send + Sync {
    /// Which member the slot is on.
    fn destination(&self) -> DestinationId;
}

/// `// contract:` the pool's permit store, bound by the integrator.
///
/// The design gives the pool to this unit, but the permits themselves are node-local runtime state
/// that outlives any one request, so they live behind this seam rather than inside the walk.
pub trait Capacity: Send + Sync {
    /// Take a slot on this member if one is free. Never blocks: the pick path holds no unbounded
    /// await, which is what keeps the wait terminal the only place this unit ever parks.
    fn try_acquire(&self, destination: DestinationId) -> Option<Permit>;

    /// Wait for a slot to free on any of these members, in arrival order, resolving to `None` only
    /// when every one of their queues is closed.
    ///
    /// This is the ONE blocking await in the unit and it is used from exactly one place, the wait
    /// terminal, which races it against a bounded deadline. The store hands one freed slot to one
    /// waiter — no lost wakeup, no thundering herd — which is why the terminal can re-check the
    /// breaker on the winner instead of re-entering selection.
    fn acquire_any<'a>(
        &'a self,
        destinations: &'a [DestinationId],
    ) -> BoxFut<'a, Option<(DestinationId, Permit)>>;
}

// ── the egress-auth seam ────────────────────────────────────────────────────────────────────────

/// `// contract:` the egress-auth unit, as the attempt needs it.
///
/// The plane names the scheme and never holds the credential; this unit hands the encoded request
/// to the scheme's own unit, which decorates it and substitutes every secret slot itself. The
/// decoration comes back as fields to set and, where the scheme signs one, a body signature — the
/// caller then re-runs the lane cross-check on the decorated result, which is the whole reason the
/// decoration is a separate step and not something the plane did on the way out.
pub trait EgressAuth: Send + Sync {
    /// Decorate one outbound request for one verified destination.
    ///
    /// # Errors
    /// Returns the scheme's own refusal when the request cannot be decorated — an unresolvable
    /// secret, an unknown scheme. The attempt treats that as a failure to assemble: nothing was
    /// sent and nothing is recorded against the destination.
    fn decorate(&self, request: &mut OutboundRequest<'_>) -> Result<(), DecorationRefused>;
}

/// The outbound request as the decoration sees it: the envelope the plane built, the body it
/// encoded, and the scheme it named.
#[derive(Debug)]
pub struct OutboundRequest<'u> {
    /// The transport-level envelope, as fields the decoration may add to.
    pub fields: Vec<(String, Vec<u8>)>,
    /// The body bytes the plane encoded.
    pub body: &'u [u8],
    /// Which scheme decorates it.
    pub scheme: busbar_contract::SchemeKey,
    /// The signature the scheme wrote over the body, where it signs one.
    pub body_signature: Option<Vec<u8>>,
}

/// The egress-auth unit declined to decorate the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecorationRefused;

impl std::fmt::Display for DecorationRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the outbound request could not be decorated")
    }
}

impl std::error::Error for DecorationRefused {}

// ── the journal seam ────────────────────────────────────────────────────────────────────────────

/// One dispatch, as the journal records it before the dial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dispatched {
    /// Which leg of the route plan this is.
    pub leg: u8,
    /// Which attempt of the walk this is, counted from one.
    pub attempt: u32,
    /// Which pool cell the attempt is recorded against.
    pub pool: String,
    /// Which member of the verified set is being dialled.
    pub destination: DestinationId,
    /// The lane the destination was sealed on.
    pub lane: Option<busbar_contract::LaneId>,
}

/// `// contract:` the write-ahead journal, as the attempt needs it.
///
/// The design is explicit about the ordering: the delta record is durable BEFORE the dial. That is
/// the whole reason this is a seam and not a fire-and-forget — a dispatch this unit cannot prove
/// it recorded is a dispatch that must not happen, so the write is fallible and its failure ends
/// the attempt before any byte leaves.
pub trait Journal: Send + Sync {
    /// Record that a dispatch is about to happen, and do not return until it is durable.
    ///
    /// # Errors
    /// Returns the durability marker when the record cannot be made durable. The attempt then
    /// sends nothing.
    fn dispatched(&self, record: &Dispatched) -> Result<(), DurabilityUnavailable>;

    /// Record that a dispatch which was journaled never produced an answer. The design requires an
    /// abandoned attempt to be explicit rather than inferred from a missing settle.
    fn abandoned(&self, record: &Dispatched);
}

/// The journal could not make the record durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurabilityUnavailable;

impl std::fmt::Display for DurabilityUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the dispatch record could not be made durable")
    }
}

impl std::error::Error for DurabilityUnavailable {}

// ── the clock ───────────────────────────────────────────────────────────────────────────────────

/// `// contract:` the node's clock and its only sleep.
///
/// Time is an input, not an ambient fact. Every deadline in this unit is computed from `now_secs`
/// or `now_millis` and every wait is this `sleep`, so a test drives the whole walk — including the
/// bounded wait terminal — on one thread with no timer wheel, and the determinism of the pick
/// order does not depend on how fast the machine is.
pub trait Clock: Send + Sync {
    /// Whole seconds since the epoch. Every deadline in the walk is second-granular, exactly as
    /// the previous release's was.
    fn now_secs(&self) -> u64;

    /// Milliseconds since an arbitrary fixed point, for the one wait that needs sub-second
    /// precision: a wait bounded by a few hundred milliseconds is unrepresentable in whole
    /// seconds, and a budget close to a second boundary would collapse to zero.
    fn now_millis(&self) -> u128;

    /// A future that completes no earlier than `ms` milliseconds from now.
    fn sleep(&self, ms: u64) -> BoxFut<'_, ()>;
}

// ── telemetry ───────────────────────────────────────────────────────────────────────────────────

/// `// contract:` the counters the walk moves. Every method is an observation and none may fail,
/// block, or change what the walk does next.
pub trait Telemetry: Send + Sync {
    /// One upstream attempt was started against this member.
    fn upstream_attempt(&self, pool: &str, destination: DestinationId);

    /// One attempt failed, with the disposition label the previous release used.
    fn upstream_failure(&self, pool: &str, destination: DestinationId, disposition: &'static str);

    /// One attempt failed over to the next candidate, with the reason label.
    fn failover(&self, pool: &str, reason: &'static str);

    /// A cell tripped, freshly.
    fn breaker_trip(&self, pool: &str, destination: DestinationId);

    /// A request parked in the wait terminal, or left it. The gauge is a depth, so the two calls
    /// must be balanced on every exit including a dropped future.
    fn queued(&self, pool: &str, delta: i64);
}

/// The disposition labels, verbatim.
///
/// These are metric label values, so they are part of the observable surface and reworded only
/// with the dashboards that read them.
pub mod disposition {
    /// A transient upstream failure.
    pub const TRANSIENT: &str = "transient_upstream";
    /// The per-attempt cap fired before response headers arrived.
    pub const ATTEMPT_TIMEOUT: &str = "attempt_timeout";
    /// A definitive signal about the shared destination.
    pub const HARD_DOWN: &str = "hard_down";
    /// The request was too large for this destination's window.
    pub const CONTEXT_LENGTH: &str = "context_length";
}

/// The network failure labels the breaker records against, verbatim.
pub mod net {
    /// A connection that could not be made.
    pub const CONNECT: &str = "connect";
    /// A deadline that expired.
    pub const TIMEOUT: &str = "timeout";
}

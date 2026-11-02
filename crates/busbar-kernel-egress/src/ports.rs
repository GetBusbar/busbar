// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The seams this unit is bound to, and nothing behind them.

use std::future::Future;
use std::pin::Pin;

use busbar_contract::caps::{Pass, Route};

/// Which member of the verified set a call is about.
pub use busbar_contract::DestinationId;

/// The one boxed future this crate's ports return.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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

/// What a successful admission hands over, what one attempt meant to the destination's breaker,
pub use busbar_kernel_breaker::port::Classified;
pub use busbar_kernel_breaker::{Admit, Outcome};

/// What the upstream said, as the classifier reads it.
///
/// The transport's own class of the frame (the fee leg, which also tells a success from a failure),
/// its fault reading of the answer for the breaker, the upstream's numbered status in the numbering
/// that spelled it, and the wait the upstream asked for. THE BREAKER CLASSIFIES FROM THE FAULT
/// READING ALONE and never reads `code` (the kernel names no protocol); what a given code means to
/// the breaker is the transport's own declared table, read on the transport's side of the frame.
/// `code` crosses for the composition root's model egress, which runs the previous release's 429
/// rate-limit ladder and 4xx client-fault count on the number (the transport ABI carries the number
/// beside the class, `FrameMeta`'s `status_code`, BUSBAR-1.6.0.md l.4036-4053).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UpstreamStatus {
    /// The transport's own class of the frame, where it carries one.
    pub class: Option<busbar_contract::transport::wire::WireStatusClass>,
    /// The transport's fault reading of the answer, where it states one (`None` is read as the
    /// caller's). With no class and no reading at all, no answer came.
    pub fault: Option<busbar_contract::transport::wire::WireFault>,
    /// The upstream's numeric status AND the numbering that spelled it, where the transport
    /// reports one, carried across from the frame exactly as the transport named it. Never read by
    /// the breaker.
    pub code: Option<busbar_contract::transport::wire::WireStatus>,
    /// The wait the upstream asked for, in seconds.
    pub retry_after: Option<u64>,
}

/// Where a classified failure sends the request next: the contract's disposition, which the
pub use busbar_contract::upstream::Disposition;

/// `// contract:` the breaker unit, as this unit needs it.
pub trait Breaker: Send + Sync {
    /// Mutating admission: win or lose the single-flight probe on this cell. This is the ONE call
    fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, Unavailable>;

    /// Side-effect-free reason this member cannot admit now, or `None` if it is ready.
    fn unavailable(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> Option<Unavailable>;

    /// Side-effect-free: could this cell take a request right now? The order's own filter, and the
    fn ready(&self, pool: &str, destination: DestinationId, now: u64, token: &Pass<Route>) -> bool;

    /// Side-effect-free: is this destination usable at all — not administratively down, and with
    fn admissible(&self, destination: DestinationId) -> bool;

    /// Side-effect-free: how many whole seconds of genuine cooldown this cell has left, or zero.
    fn cooldown_remaining(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> u64;

    /// Turn one upstream answer into a disposition and a breaker outcome.
    fn classify(&self, destination: DestinationId, status: UpstreamStatus) -> Classified;

    /// Record what one attempt meant. Returns true only on a fresh logical trip — the one signal a
    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        now: u64,
        token: &Pass<Route>,
    ) -> bool;

    /// [`Self::observe`] of an outcome the PLANE read, with the reason its reading states: the
    fn observe_stated(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        reason: Option<&str>,
        now: u64,
        token: &Pass<Route>,
    ) -> bool {
        let _ = reason;
        self.observe(pool, destination, outcome, now, token)
    }

    /// A non-success answer judged and recorded: [`Self::classify`], then [`Self::observe`] of the
    fn judge(
        &self,
        pool: &str,
        destination: DestinationId,
        status: UpstreamStatus,
        now: u64,
        token: &Pass<Route>,
    ) -> (Classified, bool) {
        let classified = self.classify(destination, status);
        let tripped = self.observe(pool, destination, classified.outcome, now, token);
        (classified, tripped)
    }

    /// Side-effect-free: whether the breaker suppresses `destination` in ANY cell — the health
    fn suppressing(&self, destination: DestinationId, now: u64) -> bool;

    /// A health probe's answer, already classified, recorded on EVERY cell of `destination`: a
    fn probed(&self, destination: DestinationId, outcome: Outcome, now: u64, token: &Pass<Route>);

    /// Release a probe that was won but never dispatched. Owner-checked against the epoch that was
    fn release_probe(&self, pool: &str, destination: DestinationId, epoch: u64, now: u64);

    /// Spend one unit of the destination's lifetime request budget. True when the spend happened
    fn spend_budget(&self, destination: DestinationId) -> bool;

    /// Give back one unit spent by a delivery that then failed to complete. The refund is
    fn refund_budget(&self, destination: DestinationId);
}

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
pub trait PermitHandle: std::fmt::Debug + Send + Sync {
    /// Which member the slot is on.
    fn destination(&self) -> DestinationId;
}

/// `// contract:` the pool's permit store, bound by the integrator.
pub trait Capacity: Send + Sync {
    /// Take a slot on this member if one is free. Never blocks: the pick path holds no unbounded
    fn try_acquire(&self, destination: DestinationId) -> Option<Permit>;

    /// Wait for a slot to free on any of these members, in arrival order, resolving to `None` only
    fn acquire_any<'a>(
        &'a self,
        destinations: &'a [DestinationId],
    ) -> BoxFut<'a, Option<(DestinationId, Permit)>>;
}

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
    /// The unit the walk serves: the record is written under that unit's facts.
    pub unit: busbar_contract::UnitKey,
}

/// `// contract:` the write-ahead journal, as the attempt needs it.
pub trait Journal: Send + Sync {
    /// Record that a dispatch is about to happen, and do not return until it is durable.
    fn dispatched(&self, record: &Dispatched) -> Result<(), DurabilityUnavailable>;

    /// Record that a dispatch which was journaled never produced an answer. The design requires an
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

/// `// contract:` the node's clock and its only sleep.
pub trait Clock: Send + Sync {
    /// Whole seconds since the epoch. Every deadline in the walk is second-granular, exactly as
    fn now_secs(&self) -> u64;

    /// Milliseconds since an arbitrary fixed point, for the one wait that needs sub-second
    fn now_millis(&self) -> u128;

    /// Microseconds since the same fixed point, for a latency sample: 1.5.5 measured an
    fn now_micros(&self) -> u128 {
        self.now_millis().saturating_mul(1000)
    }

    /// A future that completes no earlier than `ms` milliseconds from now.
    fn sleep(&self, ms: u64) -> BoxFut<'_, ()>;
}

/// THE LABELS A PLANE STATED for one attempt's counters (`OnPieceOut::metric_pool` /
/// `metric_lane`): each `None` where it stated none. Words, never trusted: the counters take a
/// stated word only from the bound their implementation holds, and keep their own otherwise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatedLabels {
    /// The `pool` label the plane stated.
    pub pool: Option<String>,
    /// The `lane` label the plane stated.
    pub lane: Option<String>,
}

/// `// contract:` the counters the walk moves. Every method is an observation and none may fail,
pub trait Telemetry: Send + Sync {
    /// One upstream attempt was started against this member.
    fn upstream_attempt(&self, pool: &str, destination: DestinationId);

    /// A served attempt's time to the upstream's response head, in milliseconds (the destination's
    fn upstream_latency(&self, _destination: DestinationId, _ms: f64) {}

    /// One attempt failed, with the disposition label the previous release used.
    fn upstream_failure(&self, pool: &str, destination: DestinationId, disposition: &'static str);

    /// [`Telemetry::upstream_attempt`] for an attempt whose plane stated its counter labels
    fn upstream_attempt_stated(
        &self,
        pool: &str,
        destination: DestinationId,
        stated: Option<&StatedLabels>,
    ) {
        let _ = stated;
        self.upstream_attempt(pool, destination);
    }

    /// [`Telemetry::upstream_failure`] for an attempt whose plane stated its counter labels, as
    fn upstream_failure_stated(
        &self,
        pool: &str,
        destination: DestinationId,
        disposition: &'static str,
        stated: Option<&StatedLabels>,
    ) {
        let _ = stated;
        self.upstream_failure(pool, destination, disposition);
    }

    /// One attempt failed over to the next candidate, with the reason label.
    fn failover(&self, pool: &str, reason: &'static str);

    /// A cell tripped, freshly.
    fn breaker_trip(&self, pool: &str, destination: DestinationId);

    /// A request parked in the wait terminal, or left it. The gauge is a depth, so the two calls
    fn queued(&self, pool: &str, delta: i64);
}

/// The disposition labels, verbatim.
pub mod disposition {
    use busbar_contract::upstream::Disposition;
    /// A transient upstream failure.
    pub const TRANSIENT: &str = Disposition::TransientUpstream.label();
    /// The per-attempt cap fired before response headers arrived.
    pub const ATTEMPT_TIMEOUT: &str = "attempt_timeout";
    /// A definitive signal about the shared destination.
    pub const HARD_DOWN: &str = Disposition::HardDown.label();
    /// The request was too large for this destination's window.
    pub const CONTEXT_LENGTH: &str = Disposition::ContextLength.label();
}

/// The network failure labels the breaker records against, verbatim.
pub mod net {
    /// A connection that could not be made.
    pub const CONNECT: &str = "connect";
    /// A deadline that expired.
    pub const TIMEOUT: &str = "timeout";
}

//! The unit as a plugin sees it: the steps, the ends, the refusal codes and the context.
//!
//! A unit is one governed transaction — one authorization and one settlement, whatever the frame
//! count. The plane delimits units from frames; the kernel constructs them and is the sole writer
//! of their identity. Everything below is read-only from a plugin's side.

use crate::bounded::{ArenaBytes, BoundedVec, Facts, Ir, Labels, MAX_USAGE_LINES};
use crate::grammar::Location;
use crate::ids::{
    CorrelationRef, LaneId, MeterClassId, OpClassId, PrincipalId, SessionId, StreamId, UnitKey,
};
use crate::plugin::KernelSeal;
use crate::wire::Direction;
use core::fmt;

/// The closed list of steps every unit runs, in order.
///
/// The arrival, decode and encode steps are the kernel's own and carry kernel-held tokens; the
/// seven between them are the teller's. No plugin adds a step and no plane skips one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum Step {
    /// The kernel gate: size, rate, source, cursor and spill budgets.
    Arrival,
    /// The plane says what the bytes mean.
    Decode,
    /// Who is this.
    Authenticate,
    /// Where may they send it.
    Verify,
    /// Are they allowed to ask for it.
    Approve,
    /// Can they afford it.
    Admit,
    /// Send it.
    Route,
    /// What did it cost.
    Meter,
    /// Seal what happened.
    Audit,
    /// The kernel writes the answer back.
    Encode,
}

impl Step {
    /// Every step, in loop order.
    pub const ALL: &'static [Step] = &[
        Step::Arrival,
        Step::Decode,
        Step::Authenticate,
        Step::Verify,
        Step::Approve,
        Step::Admit,
        Step::Route,
        Step::Meter,
        Step::Audit,
        Step::Encode,
    ];
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Why a unit exists.
///
/// Origin decides which destination kinds a unit may reach at all, so it is closed and it is the
/// kernel's to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Origin {
    /// A client asked for it.
    Client,
    /// An upstream pushed it.
    Provider,
    /// The node's own clock raised it.
    Tick,
    /// Bytes arrived and were refused before a plane was known.
    Arrival,
    /// A challenge-response exchange.
    Handshake,
    /// The first boot of a deployment.
    Bootstrap,
    /// One plane called another.
    Nested {
        /// The unit that called.
        parent: u64,
    },
    /// One recipient of a fan-out.
    Delivery {
        /// The unit that scattered.
        parent: u64,
    },
}

/// The closed reason codes a refusal may carry.
///
/// These are opaque to a client: the wire rendering is the dialect's, and the code is what the
/// journal and the exceptions report read. Adding one is a kernel change, because every code has
/// to have a settlement row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum RefusalReason {
    /// The in-flight table is full.
    InFlightCap,
    /// The per-connection read cursor ceiling was reached.
    CursorBudget,
    /// The per-connection credential slab was too small for the located span.
    CredentialBudget,
    /// The node-global session budget was reached.
    SessionBudget,
    /// The request body was larger than configuration allows.
    BodyTooLarge,
    /// A second open unit was offered on a direction that already has one.
    OpenSlotBusy,
    /// The plane narrowed to a scheme its claim does not declare.
    SchemeNotDeclared,
    /// The credential did not verify.
    CredentialRejected,
    /// The session is not bound, so a session-carried credential cannot be used.
    SessionUnbound,
    /// The principal's authority was withdrawn.
    Revoked,
    /// The principal lacks the scope this operation requires.
    ScopeMissing,
    /// A gate hook vetoed the unit.
    Vetoed,
    /// The verified set is empty.
    NoDestination,
    /// The principal is over a money cap.
    OverBudget,
    /// The principal's group is frozen.
    GroupFrozen,
    /// A meter class this unit would consume has no price and none is allowed.
    Unpriced,
    /// The overdraft ceiling was reached.
    OverdraftCeiling,
    /// The node's slice of a bucket window is out of date.
    StaleSlice,
    /// The journal cannot be written, so nothing may be admitted.
    DurabilityUnavailable,
    /// The chain's buckets disagree on the tier multiplier.
    TierMismatch,
}

/// The closed reason codes a failure may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum FailureReason {
    /// A plugin call did not return within its deadline.
    PluginTimeout,
    /// A plane call panicked.
    PlanePanic,
    /// The per-unit arena was exhausted.
    ArenaBudget,
    /// The session fact map is at its key ceiling.
    SessionFactsExhausted,
    /// A minted secret's placeholder did not appear exactly once.
    SecretPlaceholder,
    /// The unit's task disappeared without an end.
    TaskLost,
    /// The transport failed.
    Transport,
    /// The plane could not read the bytes.
    Decode,
    /// The plane could not write the bytes.
    Encode,
    /// Every destination's lifetime request budget is spent.
    DestinationBudgetExhausted,
}

/// Who ended a unit early.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum AbortBy {
    /// The client went away.
    Client,
    /// The kernel ended it.
    Kernel {
        /// Why.
        reason: RefusalReason,
    },
}

/// A refusal, as the plane is asked to render it.
///
/// The reason is a closed code and the client sees the dialect's own rendering of it, never the
/// code itself. The refusal names the fact — which step, which stream, which correlation — so the
/// journal row and the wire bytes are derived from one value rather than written twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Refusal {
    /// The step that refused.
    pub step: Step,
    /// Why.
    pub reason: RefusalReason,
    /// How long the client should wait, where the reason implies a wait.
    pub retry_after_secs: Option<u32>,
    /// Which stream the refusal belongs to.
    pub stream: Option<StreamId>,
    /// Which request the refusal answers.
    pub correlates: Option<CorrelationRef>,
}

/// How a unit ended, as a plugin sees it.
///
/// The capability crate carries what a settlement *is*; this is the shape a plane is handed so it
/// can render an ending. A plane cannot construct one, because a plane does not decide endings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum UnitEnd {
    /// The unit ran the whole loop.
    Completed,
    /// A step refused it.
    Refused(Refusal),
    /// A step failed.
    Failed {
        /// Which step.
        step: Step,
        /// Why.
        reason: FailureReason,
    },
    /// It was ended early.
    Aborted(AbortBy),
    /// It stopped advancing and the sweep took it.
    Stalled,
}

/// How a plane says a response ended.
///
/// This is the second source for the fee decision. Where it and the transport's status class
/// disagree, the ledger posts the lower evidence and flags the dispute; it never silently prefers
/// the house's reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum FinishClass {
    /// The whole answer arrived.
    Complete,
    /// One turn of a duplex exchange ended; the session continues.
    TurnComplete,
    /// The answer was cut short.
    Partial,
    /// The upstream reported an error.
    Error,
}

/// Where a plane found the values the metering step folds.
///
/// A plane returns locators, never amounts: the type carries a class, where the value was found,
/// and the value itself when the plane read it out of a response it already parsed. The kernel's
/// own accrual is the floor these are checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct UsageLocator {
    /// Which class the value is for.
    pub class: MeterClassId,
    /// Where in the response the value was found.
    pub location: Option<Location>,
    /// The value, in the class's own quantity.
    pub quantity: Option<u64>,
    /// The lane the response itself named, where the dialect names one.
    pub lane: Option<LaneId>,
}

/// Every locator one unit's metering step folds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsageLocators {
    /// The lines, one per class the plane read.
    pub lines: BoundedVec<UsageLocator, MAX_USAGE_LINES>,
}

/// What the audit step seals about a unit.
///
/// The operation class here is checked against the one the draft declared, because the draft's is
/// the one that priced the unit; a difference is a dispute, not a re-price.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct AuditFacts {
    /// The operation class the plane says this unit was.
    pub op_class: OpClassId,
    /// How the plane says it ended.
    pub finish: FinishClass,
}

/// One resource a principal must hold scope over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ResourceLocator {
    /// The kind of resource, in the plane's own vocabulary.
    pub kind: &'static str,
    /// Which one.
    pub name: &'static str,
}

/// What a plane offers the approve step: resource locators, and nothing else.
///
/// Not a decision, not a scope, not an amount. The scope unit reads the required scope out of
/// policy and compares it against the principal; the plane only says what is being asked for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeFacts {
    /// The resources this unit touches.
    pub resources: BoundedVec<ResourceLocator, MAX_USAGE_LINES>,
}

/// What a plane offers the admission step.
///
/// Three pointers and nothing more: where the lane name is in the request, where the client's
/// response ceiling is, and which span of the body counts as input. The kernel resolves all three
/// itself, so a plane that lies about them is caught by the lane cross-check rather than believed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct AdmitFacts {
    /// Where the lane name is in the request.
    pub lane_locator: Option<Location>,
    /// Where the client's own response ceiling is, clamped to the lane's declared maximum.
    pub max_response_ptr: Option<Location>,
    /// Which span of the body is the priced input.
    pub input_span: Option<crate::bounded::Span>,
}

/// The node's read-only clock.
///
/// A plane is pure over its inputs, and time is an input, so it comes from here rather than from
/// the system. The determinism meta-test depends on that being the only source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct Clock {
    /// Wall-clock seconds since the epoch, as the node reads them.
    pub unix_secs: u64,
    /// A monotonic reading in nanoseconds, for elapsed measurements.
    pub monotonic_nanos: u128,
}

/// The configuration a plugin declared a schema for, as a read-only view.
///
/// A plugin reads its own block and nothing else. There is no way from here to another plugin's
/// configuration, to policy, or to a secret.
pub trait ConfigView: Send + Sync {
    /// A string value from this plugin's own configuration block.
    fn get_str(&self, key: &str) -> Option<&str>;

    /// A whole-number value from this plugin's own configuration block.
    fn get_int(&self, key: &str) -> Option<i64>;

    /// A flag from this plugin's own configuration block.
    fn get_bool(&self, key: &str) -> Option<bool>;
}

/// The session's kernel-owned fact maps, as a read-only view.
///
/// Both maps are pre-allocated at session open from the declared key sets, and both are
/// last-write-wins. A plane writes session facts through its own answers; a transport writes
/// transport facts at accept, dial, upgrade and handoff. Neither can write the other's.
pub trait SessionView: Send + Sync {
    /// Which session this is.
    fn id(&self) -> SessionId;

    /// Whether the session's principal is cached, or every unit re-authenticates.
    fn is_bound(&self) -> bool;

    /// A session fact, by declared key.
    fn session_fact(&self, key: &str) -> Option<&str>;

    /// A transport fact, by declared key.
    fn transport_fact(&self, key: &str) -> Option<&str>;

    /// How many upstreams this session has paired with itself.
    fn upstream_count(&self) -> usize;
}

/// The transport stack under this unit, as a read-only view.
pub trait TransportView: Send + Sync {
    /// The top transport's key.
    fn key(&self) -> &'static str;

    /// The composed stack, bottom layer first.
    fn chain(&self) -> &[&'static str];

    /// A transport fact, by declared key.
    fn fact(&self, key: &str) -> Option<&str>;
}

/// Everything a plugin call is given besides its own arguments.
///
/// The context carries exactly one resource — the arena — and the rest are borrowed views. There
/// is no handle here that reaches the kernel, no way to mount a route, and no way to open a
/// connection.
pub struct Ctx<'u> {
    clock: Clock,
    config: &'u dyn ConfigView,
    session: Option<&'u dyn SessionView>,
    transport: &'u dyn TransportView,
    labels: &'u Labels<'u>,
    arena: &'u dyn crate::bounded::Arena,
}

impl<'u> Ctx<'u> {
    /// Assemble a context. The kernel builds every one of these.
    #[must_use]
    pub fn new(
        clock: Clock,
        config: &'u dyn ConfigView,
        session: Option<&'u dyn SessionView>,
        transport: &'u dyn TransportView,
        labels: &'u Labels<'u>,
        arena: &'u dyn crate::bounded::Arena,
    ) -> Self {
        Self {
            clock,
            config,
            session,
            transport,
            labels,
            arena,
        }
    }

    /// The node's clock reading for this call.
    #[must_use]
    pub fn clock(&self) -> Clock {
        self.clock
    }

    /// This plugin's own configuration.
    #[must_use]
    pub fn config(&self) -> &'u dyn ConfigView {
        self.config
    }

    /// The session, on a session transport. A one-shot transport has none.
    #[must_use]
    pub fn session(&self) -> Option<&'u dyn SessionView> {
        self.session
    }

    /// The transport stack under this unit.
    #[must_use]
    pub fn transport(&self) -> &'u dyn TransportView {
        self.transport
    }

    /// The metric labels for this unit.
    #[must_use]
    pub fn labels(&self) -> &'u Labels<'u> {
        self.labels
    }

    /// The per-unit arena — the one resource handle.
    #[must_use]
    pub fn arena(&self) -> &'u dyn crate::bounded::Arena {
        self.arena
    }
}

impl fmt::Debug for Ctx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ctx")
            .field("clock", &self.clock)
            .field("transport", &self.transport.key())
            .field("session", &self.session.map(SessionView::id))
            .finish()
    }
}

/// What one leg of a route came back with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegResult<'u> {
    /// Which leg, by position in the route plan.
    pub leg: u8,
    /// The reply's body, where the leg produced one.
    pub body: Option<ArenaBytes<'u>>,
    /// The facts the plane read off the reply.
    pub facts: Facts<'u>,
}

/// The unit, as a plugin reads it.
///
/// The kernel is the sole writer of the identity fields — key, origin, session, reply-to — and it
/// builds every one of these. The constructor takes a kernel seal for that reason: a plane holding
/// a unit it wrote itself would be a plane writing its own evidence.
#[derive(Debug)]
pub struct Unit<'u> {
    key: UnitKey,
    origin: Origin,
    session: Option<SessionId>,
    stream: Option<StreamId>,
    direction: Direction,
    principal: Option<PrincipalId>,
    op: OpClassId,
    body: Ir<'u>,
    correlates: Option<CorrelationRef>,
    byte_counts: (u64, u64),
    frame_counts: (u32, u32),
    leg_results: BoundedVec<LegResult<'u>, { crate::bounded::MAX_LEG_REPLIES }>,
}

impl<'u> Unit<'u> {
    /// Build a unit. Kernel-only; the seal is what says so.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        _seal: &dyn KernelSeal,
        key: UnitKey,
        origin: Origin,
        session: Option<SessionId>,
        stream: Option<StreamId>,
        direction: Direction,
        principal: Option<PrincipalId>,
        op: OpClassId,
        body: Ir<'u>,
        correlates: Option<CorrelationRef>,
    ) -> Self {
        Self {
            key,
            origin,
            session,
            stream,
            direction,
            principal,
            op,
            body,
            correlates,
            byte_counts: (0, 0),
            frame_counts: (0, 0),
            leg_results: BoundedVec::new(),
        }
    }

    /// The unit's node-local identity.
    #[must_use]
    pub fn key(&self) -> UnitKey {
        self.key
    }

    /// Why the unit exists.
    #[must_use]
    pub fn origin(&self) -> Origin {
        self.origin
    }

    /// Which session it belongs to, on a session transport.
    #[must_use]
    pub fn session(&self) -> Option<SessionId> {
        self.session
    }

    /// Which stream it belongs to.
    #[must_use]
    pub fn stream(&self) -> Option<StreamId> {
        self.stream
    }

    /// Which way it is flowing.
    #[must_use]
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Who it is for, once the authenticate step has answered.
    #[must_use]
    pub fn principal(&self) -> Option<&PrincipalId> {
        self.principal.as_ref()
    }

    /// The operation class the draft declared. This is the one that priced the unit.
    #[must_use]
    pub fn op(&self) -> OpClassId {
        self.op
    }

    /// The decoded body and its resolved pointer spans.
    #[must_use]
    pub fn body(&self) -> Ir<'u> {
        self.body
    }

    /// Which request this unit answers, where it answers one.
    #[must_use]
    pub fn correlates(&self) -> Option<CorrelationRef> {
        self.correlates
    }

    /// Bytes in, bytes out, as the kernel counted them.
    #[must_use]
    pub fn byte_counts(&self) -> (u64, u64) {
        self.byte_counts
    }

    /// Frames in, frames out, as the kernel counted them.
    #[must_use]
    pub fn frame_counts(&self) -> (u32, u32) {
        self.frame_counts
    }

    /// What the unit's legs came back with.
    #[must_use]
    pub fn leg_results(&self) -> &[LegResult<'u>] {
        self.leg_results.as_slice()
    }

    /// Record the kernel's byte and frame counts. Kernel-only.
    pub fn set_counts(
        &mut self,
        _seal: &dyn KernelSeal,
        byte_counts: (u64, u64),
        frame_counts: (u32, u32),
    ) {
        self.byte_counts = byte_counts;
        self.frame_counts = frame_counts;
    }

    /// Record a leg's reply. Kernel-only.
    ///
    /// # Errors
    /// Returns the reply back, boxed, when the unit already holds its bounded number of leg
    /// replies. Boxed because a reply carries a fact map pre-sized to its key ceiling.
    pub fn push_leg_result(
        &mut self,
        _seal: &dyn KernelSeal,
        result: LegResult<'u>,
    ) -> Result<(), Box<LegResult<'u>>> {
        self.leg_results.push(result).map_err(|o| Box::new(o.item))
    }
}

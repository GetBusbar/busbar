// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The voice plane, driven through the kernel.
//!
//! This is the switch-over for one plane: the file where a live voice session stops being a thing
//! the plane crate does to itself behind its own mount and becomes a sequence of ordinary units, run
//! by the kernel's loop, over the same fourteen units every other plane is judged by. Nothing here
//! is voice-specific machinery. What is voice-specific is only *which* facts each step is handed.
//!
//! ## The session-bound path, station by station
//!
//! A duplex voice session is one long conversation and a great many governed transactions. The
//! kernel's shape for that is: a session is a pairing of one client connection with zero or more
//! upstream connections, and every frame that crosses it belongs to some unit. There are three
//! shapes of unit in a session's life and they are told apart here, once, by [`UnitShape`].
//!
//! **Unit 0 — the handshake.** The connection arrives on the WebSocket transport, which is only
//! serviceable composed over HTTP: the client speaks HTTP, the 101 is answered by the WS layer, and
//! the arrival chain records both. Unit 0 is the unit that answers that arrival. It is a handshake
//! unit: it runs every step, reaches a destination, is scoped, admitted and audited — and no money
//! moves in it. Its admission is the zero-priced one, drawing no request slot and taking no
//! concurrency lease, which is what lets a node hand shake before it has authenticated anybody. Its
//! route leg is the provider dial; its egress body is the first upstream frame. When it completes,
//! the session exists and its principal is cached on it.
//!
//! **The arrival hold comes from the door, not from the table.** Before Unit 0 reaches any step it
//! is inserted into the in-flight table, and the table asks the admission unit for the hold it
//! carries. The hold reserves nothing — a unit refused at the gate has spent nothing — and its whole
//! point is that even a refusal is an event with a cell of its own to settle. The root binds that
//! door to the admission unit and to nothing else; the table never mints.
//!
//! **Per-frame units through the pump.** Every later frame is handed to the kernel's pump, which
//! reads what the plane made of it and decides what happens to the unit table: open a turn, relay
//! onto the open one, supersede it on a barge-in, close it, or drop it. One open unit per direction
//! of a stream, because two units relaying one direction would be two holds over one conversation.
//! A provider tool call takes no slot at all — it runs under the small fixed one-shot concurrency,
//! so a burst of them cannot starve the conversation.
//!
//! **A tool call waits, and the wait has a table.** A provider-pushed tool call's leg is a client
//! await-reply: the unit is not finished when the call is delivered, it is finished when the answer
//! carrying that call's identifier comes back. Two of them open at once is the ordinary shape of a
//! turn that asks for two tools, so which answer finishes which unit is a decision, and
//! [`OpenToolCalls`] is where it is made. Three moments, and each of them is a real call site:
//!
//! - **Planned.** The wait is entered at [`Units::verify`], because that is the frame that plans the
//!   leg and the last frame in which the identifier the plane's draft minted is readable at all.
//! - **Answered.** A client's reply names the call it answers — the voice plane decodes it as a
//!   frame of that call rather than of the turn it rode in on — and the pump hands the correlation
//!   to [`OpenToolCalls::replied`], which either names the unit it wakes or refuses. There is no
//!   third answer: a reply matched against "the only call open" is one collision away from paying a
//!   call's hold out against another call's answer.
//! - **Unanswered.** [`OpenToolCalls::expired`] is the node tick's sweep. It leaves an ending behind,
//!   the unit's own [`Units::route`] reads it, and the call ends under the deadline its leg declared
//!   rather than settling as though the answer had arrived.
//!
//! **The metering lease is the hold.** A live session cannot be metered after the fact: audio
//! already streamed cannot be refunded, so a budget that is only checked afterwards is not a budget.
//! The primitive that can enforce one is reserve-then-settle, and in this architecture that
//! primitive is the hold. Unit 0's admission reserves the session's coarse opening estimate; each
//! turn settles its own exact figure against what the upstream reported; exhaustion is a refusal at
//! the door of the next unit, which hard-closes the session. There is no second ledger and no
//! parallel lease object — [`SessionLease`] below is the seam the I/O half drives that hold through,
//! and the accounting is the usage and cost units' as it is for every other plane.
//!
//! **Audit, and the exit.** A session opening is not an audit event kind of its own: the record's
//! shape is fixed for every plane and a plane contributes exactly two ids to it, an operation class
//! and a finish class. So Unit 0 seals under the operation class the voice plane declares for it,
//! and the sealing is the audit unit's — the only thing that can put a record on the chain. Every
//! unit then leaves through the one exit path, which takes the hold from its cell by
//! compare-and-set. Exactly once: the cell is a two-state slot and taking it is what the second
//! taker loses.
//!
//! ## What binds to what
//!
//! | station | unit(s) | what this file supplies |
//! |---|---|---|
//! | arrival | *none* — the kernel's gate | the connection's own arrival record |
//! | decode | the voice plane | the shape the pump already read off the frame |
//! | authenticate | `busbar-unit-auth` | the claim's declared alternatives, the plane's narrowing, whether the credential rides the session |
//! | verify | `busbar-unit-trust` | the plane's proposed destinations, the pool view, the network guard over the dial target, and a tool call's reply leg entered as a wait |
//! | approve | `busbar-unit-scope` | the policy view, where silence is a refusal |
//! | admit | `busbar-unit-admission`, priced by `busbar-unit-cost` | the estimate, the bucket chain, the pinned arrival epoch |
//! | route | the provider dial, over `busbar-unit-egress` | the dial target and the guard posture, and what became of a tool call's wait |
//! | meter | `busbar-unit-usage` | the turn's reported classes and the configured policy |
//! | audit | `busbar-unit-audit` | the operation class and the finish class |
//! | exit | `busbar-unit-ledger` under `busbar-unit-wal` | nothing: the loop settles |
//!
//! ## The seams to the I/O half, and why they are seams
//!
//! `busbar-voice` is the half of the plane that owns sockets: the telephony carrier, the WebSocket
//! accept, the provider dial, the session pump and the lease that drives them. All of it is
//! asynchronous, and all of it is behind that crate's own runtime feature. A composition root that
//! named those types directly would pull an async runtime, a WebSocket client and a substrate host
//! into the one file whose whole job is to be a table of bindings. So the binding is by seam: the
//! traits below are what the root needs said about the I/O half, the I/O half is what says it, and
//! the root holds implementors behind `dyn`. Four seams, each with the item on the other side named:
//!
//! 1. [`ProviderDial`] — `busbar_voice::topology::dial_provider`, which selects the WebSocket
//!    transport, lets the substrate resolve-pin-guard the target, folds the outcome into the breaker
//!    cell, and hands back the message stream/sink pair the pump consumes.
//! 2. [`SessionPump`] — `busbar_voice::runtime::{SessionCore, VoiceSession, UplinkForwarder,
//!    Outbound}`, the per-frame loop over a byte duplex.
//! 3. [`SessionLease`] — `busbar_voice::runtime::{MeteringPort, MeteringLease, LeaseState,
//!    LeaseCloseGuard}`, the reserve-then-settle object the hold is driven through.
//! 4. [`Carrier`] — `busbar_voice::topology::telephony` and `busbar_voice::runtime::carrier`, the
//!    inbound telephony leg.
//!
//! Every one is a trait declared here and implemented there. The default implementor, [`Detached`],
//! refuses each of the four honestly rather than pretending: a node whose I/O half was never
//! installed cannot dial, cannot pump and cannot lease, and saying so at the seam is better than
//! discovering it as a socket that never opened.
//!
//! ## What is deliberately not here
//!
//! No wire shape, no dialect, no audio. The word for a frame's contents appears in this file exactly
//! as often as it appears in the kernel: never. What arrives is a shape and a set of facts, and the
//! plane is what turned bytes into either.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use busbar_caps::{
    Admission, Admit, AdmitToken, Approve, Arrival, ArrivalRecord, Audit, AuditFacts, Authenticate,
    Decision, Decode, Encode, Meter, MeterClassId, OpClassId, Outcome, PrincipalId, QuantitySource,
    ReasonCode, Refusal, Route, RoutePlan, ScopeFacts, TrustToken, UnitKey, UnitToken, Usage,
    UsageLine, UsageToken, VerifiedDestination, Verify,
};
use busbar_contract::dest::ClientMode;
use busbar_contract::ids::{CorrelationRef, CorrelationValue, LaneId};
use busbar_contract::ClaimKey;
use busbar_kernel::reply::{AwaitingReplies, NotWaiting};
use busbar_kernel::slice::{DoorGrant, GroupLeaseSlip};
use busbar_kernel::teller::{AccrualMeter, Evidence, FeeEvidence, UnitCtx, Units};
use busbar_kernel::Millis;
use busbar_plane_voice::claims::Dialect;
use busbar_plane_voice::{meta, Upstream, VoicePlane};
use busbar_unit_admission::{Admission as _, Door, Estimate, InMemoryCells, Pricer};
use busbar_unit_auth::{Auth, AuthRequest};
use busbar_unit_scope::{Grants, Scope, TRANSPORT_HANDSHAKE};
use busbar_unit_trust::net::GuardPolicy;

/// Every meter class this plane declares fits in one usage report, with room to spare.
///
/// The report is a bounded collection and the metering step's only failure arm is overrunning it.
/// Asserting the fit here is what makes that arm unreachable from the declarations rather than
/// unreachable by inspection, so a plane that grows a class has to come past this line.
const _: () = assert!(
    <VoicePlane as busbar_contract::plane::PlaneMeta>::METER_CLASSES.len()
        <= busbar_caps::MAX_USAGE_LINES
);

/// Nano-units in a cent, for the one place this file turns the rate card's flat fee into the unit a
/// reservation is taken in. Spelled here rather than reached for so the root's arithmetic is the
/// root's; the plane never sees a fee at all.
const NANOS_PER_CENT: u64 = 10_000_000;

/// The operation class a turn is audited and priced under.
const OP_DUPLEX_TURN: &str = "duplex_turn";
/// The operation class a provider-pushed tool call is audited and priced under.
const OP_TOOL_CALL: &str = "tool_call";

/// The credential scheme every one of this plane's claims authenticates under, and the two
/// alternatives its session dialects narrow within.
///
/// Named here rather than reached for through the plane because the authenticate step is handed the
/// *claim's* declared alternatives, and the claim is what the boot seal matched — the root is the
/// only thing holding both the claim and the unit it is about to run.
const SESSION_SCHEME_ALTERNATIVES: &[&str] = &["bearer", "api-key"];

// ---------------------------------------------------------------------------------------------
// The two composed provider endpoints
// ---------------------------------------------------------------------------------------------

/// The two upstreams this plane can dial, as the registry holds them.
///
/// Both are duplex JSON dialects and both are reached on the WebSocket transport; what differs is
/// the wire grammar, which is the plane's business and not this file's. They are `&'static` because
/// a plane's upstream list outlives every unit that reads it: the root interned each host through the
/// vocabulary once, at registration, and a per-dial leak would be a defect rather than a variant of
/// the leak-once rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderEndpoints {
    /// The realtime endpoint, in its dialect.
    pub realtime: Upstream,
    /// The live endpoint, in its dialect.
    pub live: Upstream,
}

impl ProviderEndpoints {
    /// Compose the two endpoints from names configuration decided.
    ///
    /// Every argument is already `&'static`: the interning happened at registration, and taking
    /// borrowed names here is what makes it impossible to intern one at dial time by accident.
    #[must_use]
    pub const fn new(
        realtime_host: &'static str,
        realtime_lane: LaneId,
        live_host: &'static str,
        live_lane: LaneId,
    ) -> Self {
        ProviderEndpoints {
            realtime: Upstream {
                lane: realtime_lane,
                host: realtime_host,
                dialect: Dialect::OpenaiRealtime,
            },
            live: Upstream {
                lane: live_lane,
                host: live_host,
                dialect: Dialect::GeminiLive,
            },
        }
    }

    /// The pair as the plane reads it, in declaration order.
    #[must_use]
    pub fn as_slice(&self) -> [Upstream; 2] {
        [self.realtime, self.live]
    }
}

// ---------------------------------------------------------------------------------------------
// The seams to the I/O half
// ---------------------------------------------------------------------------------------------

/// Where a dial is going and how far the guard will let it.
#[derive(Debug, Clone)]
pub struct DialTarget {
    /// The endpoint's own name, as the breaker cell keys it and a refusal names it.
    pub pool: String,
    /// Which member of that cell. Zero for a degenerate one.
    pub lane: usize,
    /// The absolute target.
    pub url: String,
    /// The outbound trust posture. A public provider endpoint takes the fail-closed default, and the
    /// guard never opens a socket to a target it did not pin.
    pub policy: GuardPolicy,
}

/// Why a governed dial did not open a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialRefusal {
    /// The endpoint's breaker cell was open. Fast-fail, in microseconds, rather than waiting out a
    /// dial timeout against a target already known to be down.
    BreakerOpen,
    /// The network guard refused the target — an internal address, a cloud metadata host, a scheme
    /// the posture forbids, or a name that resolved to one of those.
    GuardRefused,
    /// The socket did not open: connect, TLS or handshake.
    Unreachable,
    /// Nothing on this node can dial, because no I/O half was installed.
    Detached,
}

impl DialRefusal {
    /// The reason a refused unit ends under.
    #[must_use]
    pub fn reason(self) -> ReasonCode {
        match self {
            // The node declining to try, which is its own reason and not a network failure: a cell
            // that fast-failed in microseconds and a socket that timed out are different evidence.
            DialRefusal::BreakerOpen => ReasonCode::BreakerOpen,
            // A guard refusal is about WHERE the request wanted to go. Nothing survived the walk to
            // a target the guard would open, which is exactly the no-destination answer -- and not a
            // scope denial, because the principal's scope was never the question.
            DialRefusal::GuardRefused => ReasonCode::NoDestination,
            DialRefusal::Unreachable | DialRefusal::Detached => ReasonCode::DestinationUnreachable,
        }
    }
}

/// **Seam 1 — the provider dial.** The egress leg of a session: one outbound duplex socket, opened
/// through the network guard, with the breaker beneath it.
///
/// Satisfied by `busbar_voice::topology::dial_provider`. That function selects the WebSocket
/// transport, resolves the axis to the neutral duplex wire, lets the substrate resolve-then-pin-then
/// -guard the target, probes the breaker cell before any socket and folds the outcome back into it.
/// None of that belongs in a composition root, and none of it is re-stated here: the root says what
/// it wants dialed and reads whether it opened.
pub trait ProviderDial: Send + Sync {
    /// Open the leg, or say why not.
    ///
    /// # Errors
    ///
    /// The breaker cell was open, the guard refused the target, the socket did not open, or no I/O
    /// half is installed.
    fn dial(&self, target: &DialTarget) -> Result<(), DialRefusal>;
}

/// **Seam 2 — the session pump.** The per-frame loop over a byte duplex, once both legs are open.
///
/// Satisfied by `busbar_voice::runtime::{SessionCore, VoiceSession, UplinkForwarder, Outbound}`. The
/// root's interest in it is one bit wide: whether the session is still pumping. What a frame *is* is
/// the plane's answer and what happens to the unit table because of it is the kernel pump's; this
/// seam is only how the root asks the I/O half to keep the two connected.
///
/// It is also what drives [`OpenToolCalls`]: a frame that carries a tool reply is handed to
/// [`OpenToolCalls::replied`], and the tick that runs beside the pump is what calls
/// [`OpenToolCalls::expired`]. Neither is a method here, because neither is a question about the
/// pump — they are the node's own table, and a seam that owned them would be the I/O half deciding
/// which unit an answer belongs to.
///
/// What the pump reaches them through is [`NodeCalls`], the one port whose direction is inverted:
/// `busbar_voice::runtime::GovernedCalls` is declared over there and implemented here, the way that
/// crate's tool executor already is. Two facts cross it — a reply arrived, sweep the deadlines — and
/// the runtime learns nothing else about a call.
pub trait SessionPump: Send + Sync {
    /// Whether the pump is running for this session.
    fn is_pumping(&self, session: u64) -> bool;
}

/// **Seam 3 — the metering lease.** Reserve at open, settle per turn, close once.
///
/// Satisfied by `busbar_voice::runtime::{MeteringPort, MeteringLease, LeaseState, LeaseCloseGuard}`.
/// This is not a second ledger: the reservation it drives IS the unit's hold, the settlements it
/// takes are what the usage and cost units folded, and the close is the exit path. The seam exists
/// because the object that has to be told those three things lives on the far side of the async
/// boundary.
pub trait SessionLease: Send + Sync {
    /// Reserve the session's coarse opening estimate, in nano-units.
    ///
    /// # Errors
    ///
    /// The principal's chain cannot cover it, which is the exhaustion answer.
    fn reserve(&self, session: u64, nanos: u64) -> Result<(), ReasonCode>;

    /// Settle one turn's exact figure against the reservation, and say whether anything is left.
    ///
    /// `false` means the budget is dry, which the caller turns into a hard close: a session that
    /// cannot pay for the next frame must stop receiving them, and that is the one thing metering
    /// after the fact cannot do.
    fn settle(&self, session: u64, nanos: u64) -> bool;

    /// Close the lease. Called once, on the exit path, whatever the end.
    fn close(&self, session: u64);
}

/// **Seam 4 — the telephony carrier.** The inbound leg that is not a WebSocket the client opened.
///
/// Satisfied by `busbar_voice::topology::telephony` and `busbar_voice::runtime::carrier`. The claim
/// that would route bytes to it is not declared today — the transport it named has no crate — so
/// this seam is declared and its default implementor refuses. It is here rather than deferred
/// because the seam is what the transport will be plugged into when it lands, and a seam invented
/// at that point would be a seam nobody had reviewed.
pub trait Carrier: Send + Sync {
    /// Whether a carrier leg is available at all.
    fn available(&self) -> bool;
}

/// The four seams, unimplemented, refusing honestly.
///
/// A node built with no I/O half is a real configuration — it is what every test in this file runs
/// against, and what a `--validate` run is — and the difference between "detached" and "broken" is
/// worth being able to say. Each answer below is the safe end of a choice that had an unsafe end.
#[derive(Debug, Default, Clone, Copy)]
pub struct Detached;

impl ProviderDial for Detached {
    fn dial(&self, _target: &DialTarget) -> Result<(), DialRefusal> {
        Err(DialRefusal::Detached)
    }
}

impl SessionPump for Detached {
    fn is_pumping(&self, _session: u64) -> bool {
        false
    }
}

impl SessionLease for Detached {
    fn reserve(&self, _session: u64, _nanos: u64) -> Result<(), ReasonCode> {
        // Not `Ok(())`. A lease that cannot be taken must not read as one that was: the whole point
        // of reserve-then-settle is that the reservation is what a later frame is allowed against.
        //
        // The reason is the durability one rather than a budget one, and the distinction is the
        // point: nothing is wrong with the principal's chain. What is missing is anywhere to record
        // the reservation, which is the same shape as a journal that cannot be written.
        Err(ReasonCode::DurabilityUnavailable)
    }

    fn settle(&self, _session: u64, _nanos: u64) -> bool {
        false
    }

    fn close(&self, _session: u64) {}
}

impl Carrier for Detached {
    fn available(&self) -> bool {
        false
    }
}

/// The I/O half, as the root holds it.
pub struct VoiceIo {
    /// The egress leg.
    pub dial: Box<dyn ProviderDial>,
    /// The per-frame loop.
    pub pump: Box<dyn SessionPump>,
    /// The reserve-then-settle object the hold is driven through.
    pub lease: Box<dyn SessionLease>,
    /// The inbound telephony leg.
    pub carrier: Box<dyn Carrier>,
}

impl Default for VoiceIo {
    fn default() -> Self {
        VoiceIo {
            dial: Box::new(Detached),
            pump: Box::new(Detached),
            lease: Box::new(Detached),
            carrier: Box::new(Detached),
        }
    }
}

impl std::fmt::Debug for VoiceIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoiceIo").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------------------------
// The tool calls a session has open
// ---------------------------------------------------------------------------------------------

/// The leg a provider-pushed tool call plans: deliver it to the client, and wait for the answer.
///
/// The key and the deadline are the plane's own declarations, read from it rather than restated. A
/// second spelling of either here would be a wait entered under one key and answered under another,
/// with both files looking correct on their own.
const TOOL_REPLY_LEG: ClientMode = ClientMode::AwaitReply {
    correlation_key: busbar_plane_voice::plane::FACT_TOOL_CORRELATION,
    deadline_secs: busbar_plane_voice::plane::TOOL_REPLY_DEADLINE_SECS,
};

/// Why a client's tool reply woke nothing.
///
/// Refused rather than dropped, and that is the whole of this type. A reply nobody is waiting for is
/// either a client answering a call it was never asked to make or a call this node has already
/// ended, and both are worth being able to say — a dropped frame is indistinguishable from a frame
/// that was never sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyRefused {
    /// This node holds no tool calls on that session.
    NoSuchSession,
    /// The session is here, but nothing open on it is waiting on the identifier the reply carried.
    UnknownCall,
}

/// What became of one tool call, once it stopped waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEnd {
    /// The client answered it, carrying the identifier the call was entered under.
    Answered,
    /// Nobody answered before the deadline the leg declared.
    Unanswered,
}

/// One call the sweep found unanswered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnansweredCall {
    /// Which session it was open on.
    pub session: u64,
    /// Which unit was waiting.
    pub unit: UnitKey,
}

/// One session's open calls, and the endings its units have not read yet.
#[derive(Debug, Default)]
struct SessionCalls {
    /// The kernel's own table: which reply wakes which unit.
    awaiting: AwaitingReplies,
    /// How a call ended, held until the unit's exit path reads it.
    ended: HashMap<UnitKey, CallEnd>,
}

/// Every tool call this node has open, session by session.
///
/// The kernel's [`AwaitingReplies`] answers "which unit does this reply wake" and is deliberately
/// keyed by unit alone; it is one session's table, and this is what holds one per session. The
/// division matters: two sessions may legitimately have calls open under identical identifiers —
/// providers mint them per conversation — and a single node-wide table would have to decide which
/// of them a reply belonged to before it had the session to decide it with.
///
/// The endings sit beside the waits rather than inside them because they outlive the wait by exactly
/// one frame: the pump wakes or sweeps, and the unit's own exit path is what reads what happened to
/// it. A call's ending is final — re-planning a leg for a unit that already ended does not reopen
/// it, which is what keeps a resumed unit from waiting a second time on an answer that is not coming.
#[derive(Debug, Default)]
pub struct OpenToolCalls {
    sessions: Mutex<BTreeMap<u64, SessionCalls>>,
}

impl OpenToolCalls {
    /// A node holding no calls.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enter a tool call's reply leg as waiting, in the frame that planned it.
    ///
    /// `correlation_out` is the unit's own draft field, borrowed for the length of this call: the
    /// kernel's table copies the identifier into its own memory here, which is the one moment it is
    /// guaranteed readable.
    ///
    /// # Errors
    /// Returns why the leg is not a wait: it delivers, the unit minted no identifier for an answer
    /// to carry, or the draft's key is not the one the leg named.
    pub fn planned(
        &self,
        session: u64,
        unit: UnitKey,
        mode: ClientMode,
        correlation_out: Option<CorrelationRef<'_>>,
        now: Millis,
    ) -> Result<(), NotWaiting> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let calls = sessions.entry(session).or_default();
        if calls.ended.contains_key(&unit) {
            // The call is over and its unit has not read the ending yet. Entering it again would be
            // a second wait on an answer that has already come or already timed out.
            return Ok(());
        }
        calls.awaiting.enter(unit, mode, correlation_out, now)
    }

    /// The unit a client's reply answers, taken out of the table.
    ///
    /// # Errors
    /// The session holds no calls, or nothing open on it carries that identifier under that key.
    pub fn replied(
        &self,
        session: u64,
        correlates: CorrelationRef<'_>,
    ) -> Result<UnitKey, ReplyRefused> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let calls = sessions
            .get_mut(&session)
            .ok_or(ReplyRefused::NoSuchSession)?;
        let unit = calls.awaiting.wake(correlates).ok_or(
            // Not "the only call open", and not silence either. A reply that matches nothing is
            // refused as what it is, because paying it out against whichever call happens to be
            // standing is the exact failure the whole correlation exists to prevent.
            ReplyRefused::UnknownCall,
        )?;
        calls.ended.insert(unit, CallEnd::Answered);
        Ok(unit)
    }

    /// **The sweep.** Every call whose declared deadline has passed, named so its unit can be ended.
    ///
    /// A wait that is never woken is a hold that is never settled, so this runs on the node's tick
    /// rather than being something a caller is trusted to remember. What it leaves behind is the
    /// ending the unit's exit path reads.
    pub fn expired(&self, now: Millis) -> Vec<UnansweredCall> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let mut swept = Vec::new();
        for (session, calls) in sessions.iter_mut() {
            for unit in calls.awaiting.expired(now) {
                calls.ended.insert(unit, CallEnd::Unanswered);
                swept.push(UnansweredCall {
                    session: *session,
                    unit,
                });
            }
        }
        swept
    }

    /// How one call ended, taken out of the table.
    ///
    /// Read once, by the unit's own exit path. Taking it rather than copying it is what keeps the
    /// table the size of the calls that are actually open: an ending nobody is going to read is a
    /// row that never comes back out.
    pub fn ending(&self, session: u64, unit: UnitKey) -> Option<CallEnd> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let calls = sessions.get_mut(&session)?;
        calls.ended.remove(&unit)
    }

    /// Whether one unit is still waiting on its answer.
    #[must_use]
    pub fn waiting(&self, session: u64, unit: UnitKey) -> bool {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions
            .get(&session)
            .is_some_and(|calls| calls.awaiting.waiting(unit).is_some())
    }

    /// How many calls are open across every session.
    #[must_use]
    pub fn open(&self) -> usize {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.values().map(|calls| calls.awaiting.len()).sum()
    }

    /// Forget a session's calls, when the session itself ends.
    ///
    /// A conversation that is over cannot answer anything, so its waits end with it rather than
    /// waiting out deadlines nobody is left to satisfy.
    pub fn closed(&self, session: u64) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.remove(&session);
    }
}

// ---------------------------------------------------------------------------------------------
// What the I/O half is allowed to see of that table
// ---------------------------------------------------------------------------------------------

/// The node's open-call table, as the session runtime reaches it.
///
/// The two moments [`OpenToolCalls`] does not own a call site for are the ones that happen on a
/// socket: a client's reply arriving, and the tick beside the pump. Both live in `busbar-voice`, and
/// neither can be a method on one of the four seams above — a seam that answered "which unit does
/// this reply wake" would be the I/O half deciding it.
///
/// So the direction inverts here, exactly once, and it inverts the way the plane's tool executor
/// already does: `busbar-voice` declares the port, the root implements it, and what crosses is two
/// facts and no more. The runtime never learns which unit a call belongs to, how long its deadline
/// is, or what a refusal costs.
///
/// A node's own calls, held by `Arc` because a session outlives the frame that opened it and the
/// pump holds this for as long as it is pumping.
#[cfg(feature = "plane-voice")]
#[derive(Clone)]
pub struct NodeCalls {
    node: std::sync::Arc<VoiceNode>,
}

#[cfg(feature = "plane-voice")]
impl std::fmt::Debug for NodeCalls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCalls")
            .field("open", &self.node.tool_calls.open())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "plane-voice")]
impl NodeCalls {
    /// Bind the port to one node's table.
    #[must_use]
    pub fn new(node: std::sync::Arc<VoiceNode>) -> Self {
        NodeCalls { node }
    }
}

#[cfg(feature = "plane-voice")]
impl busbar_voice::runtime::GovernedCalls for NodeCalls {
    fn replied(
        &self,
        session: u64,
        call_id: &str,
    ) -> Result<(), busbar_voice::runtime::ReplyRefusal> {
        // The identifier as itself, under the key the leg named — the same pair the plane's draft
        // minted the wait under. Spelling either differently here would be a wait entered under one
        // key and answered under another, with both sides looking correct on their own.
        let correlates = CorrelationRef {
            fact_key: busbar_plane_voice::plane::FACT_TOOL_CORRELATION,
            value: CorrelationValue::Str(call_id),
        };
        match self.node.tool_calls.replied(session, correlates) {
            // The unit is named, and naming it is all the runtime needs: what happens to it is the
            // kernel loop's, read off the ending on its own exit path.
            Ok(_unit) => Ok(()),
            Err(ReplyRefused::NoSuchSession) => {
                Err(busbar_voice::runtime::ReplyRefusal::NoSuchSession)
            }
            Err(ReplyRefused::UnknownCall) => Err(busbar_voice::runtime::ReplyRefusal::UnknownCall),
        }
    }

    fn expired(&self, now_ms: u64) -> usize {
        // The sweep leaves the ending behind; the unit's own `route` reads it and ends the call under
        // the deadline its leg declared. Counting is all that comes back, because a count is all the
        // pump can honestly do anything with.
        self.node.tool_calls.expired(now_ms).len()
    }
}

// ---------------------------------------------------------------------------------------------
// The node's long-lived half
// ---------------------------------------------------------------------------------------------

/// Everything a voice unit reads that outlives it.
///
/// One per node, built at boot. The units with state across requests are fields; the rest are
/// facades reached as free functions with the facts the step was handed, and holding an empty value
/// for each of those would be furniture rather than structure.
pub struct VoiceNode {
    /// The plane, with its configured upstream list.
    pub plane: VoicePlane,
    /// The admission unit's long-lived door. Its ledger cells are hydrated once, at boot, and are
    /// never re-read on the request path.
    pub door: Mutex<Door<InMemoryCells>>,
    /// The configured limit tree, resolved once at boot into the shape the door walks.
    ///
    /// One table for the node, because the parent indices a chain chases are positions in it: two
    /// tables would be two readings of what a group's cap is.
    pub groups: busbar_unit_admission::GroupTable,
    /// What the door prices an estimate against.
    pub pricer: Pricer,
    /// The authentication chain, resolved from configuration at boot.
    pub auth: Auth,
    /// The credential cache, the signed-key verifier and the revocation view the chain is handed
    /// beside the request. Built once for the node, so a session's credential is one row and an
    /// operator's flush reaches every plane at once.
    pub auth_bindings: crate::root::kernel::auth_bindings::AuthBindings,
    /// What the scope unit reads at approve. Silence is a refusal.
    pub scope: crate::root::policy::ScopePolicy,
    /// What the usage unit meters against, built from the configured rate cards.
    pub meter_policy: crate::root::policy::MeterPolicyHandle,
    /// The record chain, the ledger and the journal beneath both.
    pub durability: Mutex<crate::root::durability::Durability>,
    /// The I/O half, behind its four seams.
    pub io: VoiceIo,
    /// The tool calls this node's sessions have open, waiting on a client's reply.
    ///
    /// Node-held rather than passed in, because nothing configuration decides is in it: it is empty
    /// at boot and its whole contents are what the sessions running on this node have opened since.
    pub tool_calls: OpenToolCalls,
    /// The origin every unit of this plane carries into its audit record, minted once at boot.
    ///
    /// A sealed origin cannot be constructed outside the kernel, and the audit step is lent its own
    /// token and nothing else — so a unit cannot mint one where it is used. Minting it here, from
    /// the kernel the root already holds, is the composition that makes the record's "where it came
    /// from" field a fact rather than a value the root chose per record.
    pub origin: busbar_caps::Origin,
    /// The node's monotonic sequence for the audit record's second clock, so a wall clock that
    /// jumped cannot reorder one unit's own events.
    mono: AtomicU64,
    /// The sessions whose metering lease has said there is nothing left.
    ///
    /// It lives on the node rather than on a unit because a unit is one frame and the answer has to
    /// outlive it: the frame that emptied the lease is delivered and paid for, and what the
    /// exhaustion decides is every frame after it. Audio already streamed cannot be refunded, so
    /// the next door is the only enforcement point there is.
    exhausted: Mutex<std::collections::BTreeSet<u64>>,
}

impl std::fmt::Debug for VoiceNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoiceNode")
            .field("upstreams", &self.plane.upstreams().len())
            .field("scope_entries", &self.scope.len())
            .finish_non_exhaustive()
    }
}

/// Everything the node is assembled from, named rather than ordered.
///
/// Eight values, all of them things configuration decided, and every one of them a type that would
/// silently swap with at least one other in a positional call. Naming them is what makes it
/// impossible to hand the auth chain where the scope policy goes; it is also the shape that makes a
/// deployment which never read its rate cards fail to compile rather than fall back to a default.
pub struct VoiceNodeParts {
    /// The plane, with its configured upstream list.
    pub plane: VoicePlane,
    /// The configured limit tree, resolved at boot into the shape the door walks.
    pub groups: busbar_unit_admission::GroupTable,
    /// What the door prices an estimate against.
    pub pricer: Pricer,
    /// The authentication chain, resolved at boot.
    pub auth: Auth,
    /// The three seams the chain is handed beside the request.
    pub auth_bindings: crate::root::kernel::auth_bindings::AuthBindings,
    /// What the scope unit reads at approve.
    pub scope: crate::root::policy::ScopePolicy,
    /// What the usage unit meters against.
    pub meter_policy: crate::root::policy::MeterPolicyHandle,
    /// The journal, the ledger and the two chains.
    pub durability: crate::root::durability::Durability,
    /// The I/O half, behind its four seams.
    pub io: VoiceIo,
    /// The sealed origin every unit of this plane carries into its record.
    pub origin: busbar_caps::Origin,
}

impl VoiceNode {
    /// Assemble the node's half over what the root already built.
    #[must_use]
    pub fn new(parts: VoiceNodeParts) -> Self {
        VoiceNode {
            plane: parts.plane,
            door: Mutex::new(Door::new(InMemoryCells::new())),
            groups: parts.groups,
            pricer: parts.pricer,
            auth: parts.auth,
            auth_bindings: parts.auth_bindings,
            scope: parts.scope,
            meter_policy: parts.meter_policy,
            durability: Mutex::new(parts.durability),
            io: parts.io,
            tool_calls: OpenToolCalls::new(),
            origin: parts.origin,
            mono: AtomicU64::new(0),
            exhausted: Mutex::new(std::collections::BTreeSet::new()),
        }
    }

    /// Resolve one caller's chain against the configured tree — once, at the session's open.
    ///
    /// The one place on this plane a chain is built. The session keeps what comes back and lends it
    /// to every turn, so the walk of the group tree and the bucket ids it owns are paid for once per
    /// conversation rather than once per frame.
    ///
    /// `None` is the caller bound to a group this node's configuration does not have: fail-closed,
    /// and the unit lent no chain refuses. A caller bound to no group at all is `Some` — a chain of
    /// one uncapped attribution bucket, which is what a deployment with no `groups:` section has.
    #[must_use]
    pub fn chain_for(
        &self,
        principal: &PrincipalId,
        group: Option<&str>,
    ) -> Option<busbar_unit_admission::BucketChain> {
        self.groups.chain_for(principal.as_str(), group).ok()
    }

    /// The next reading of the node's monotonic clock.
    fn tick(&self) -> u64 {
        self.mono.fetch_add(1, Ordering::AcqRel)
    }

    /// Record that a session's lease has nothing left.
    fn exhaust(&self, session: u64) {
        self.exhausted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session);
    }

    /// Forget whatever a previous session on this identifier ended as.
    fn reopened(&self, session: u64) {
        self.exhausted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session);
    }

    /// Whether a session's lease has already said it is dry.
    fn is_exhausted(&self, session: u64) -> bool {
        self.exhausted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&session)
    }
}

// ---------------------------------------------------------------------------------------------
// One unit
// ---------------------------------------------------------------------------------------------

/// Which of a session's three unit shapes this one is.
///
/// The pump already decided this from what the plane made of the frame; it is carried rather than
/// re-derived, because re-deriving it would mean reading the frame a second time, and the codec's
/// reader is stateful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitShape {
    /// The unit that opens the session. Runs every step; no money moves in it.
    SessionOpen,
    /// A turn: the governed transaction a conversation is made of.
    Turn,
    /// A provider-pushed tool call. Takes no open slot.
    ToolCall,
}

impl UnitShape {
    /// The operation class this shape is audited and priced under.
    #[must_use]
    pub fn op_class(self) -> OpClassId {
        match self {
            UnitShape::SessionOpen => meta::OP_SESSION_OPEN,
            UnitShape::Turn => OpClassId::new(OP_DUPLEX_TURN),
            UnitShape::ToolCall => OpClassId::new(OP_TOOL_CALL),
        }
    }

    /// Whether this shape is the zero-priced handshake.
    #[must_use]
    pub fn is_handshake(self) -> bool {
        matches!(self, UnitShape::SessionOpen)
    }
}

/// What one turn reported, as the classes the plane declares.
///
/// The plane derives these off the upstream's own usage report and its own frame bookkeeping; this
/// struct is how they reach the metering step. Text is a pair because the two halves price under
/// different classes at different rates, which is a money question and not a spelling one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TurnUsage {
    /// Audio tokens the turn consumed.
    pub audio_tokens_in: u64,
    /// Audio tokens the model emitted.
    pub audio_tokens_out: u64,
    /// Text tokens the turn consumed.
    pub text_tokens_in: u64,
    /// Text tokens the model emitted.
    pub text_tokens_out: u64,
    /// Tokens served from the upstream's cache.
    pub cached_tokens: u64,
    /// Milliseconds of uplink audio the turn admitted. Derived by the plane from the frame byte
    /// counts under the declared format assumption, not reported by the upstream.
    pub audio_ms_in: u64,
    /// Tool calls the upstream opened during the turn.
    pub tool_calls: u64,
}

/// The declared class this key names, as the PLANE spells it, or `None` if the plane no longer
/// declares one under that name.
///
/// Every class id this file puts on a line, on an estimate or on the exit evidence comes back
/// through here, so the spelling that reaches the rate card is the declaration's own and never a
/// second copy of it kept in the root. That is the whole point: a rate card selects a unit price by
/// class label, so a class the plane renamed and the root did not would be priced at nothing, in
/// silence, on every turn.
///
/// The lookup is by key rather than by position because a declaration is a set and not an order: a
/// class inserted in the middle of the list must not shift what the one after it is priced as. A key
/// the plane stopped declaring resolves to `None` here, which is what makes the rename show up as an
/// absent line and a red assertion in `every_declared_class_carries_a_figure` rather than as a
/// mispriced turn.
fn declared_class(key: &str) -> Option<MeterClassId> {
    <VoicePlane as busbar_contract::plane::PlaneMeta>::METER_CLASSES
        .iter()
        .find(|decl| decl.key.as_str() == key)
        .map(|decl| decl.key)
}

impl TurnUsage {
    /// The figure this report carries for one class the plane declared, with the evidence it is.
    ///
    /// Written as a function OVER THE DECLARATION rather than as a list of names this file keeps:
    /// the caller walks the plane's own class list and asks this what each entry is worth, so a
    /// class the plane declares and this file does not recognise produces no line and is caught by
    /// the assertion below, and a class this file recognises is emitted under the declaration's key.
    fn figure(
        &self,
        decl: &busbar_contract::ids::MeterClassDecl,
    ) -> Option<(u64, QuantitySource, bool)> {
        // The four token figures and the cache figure are the upstream's own: reported, not derived,
        // so nothing here is marked as an estimate.
        let reported = |quantity| Some((quantity, QuantitySource::Count, false));
        match decl.key.as_str() {
            "audio_tokens_in" => reported(self.audio_tokens_in),
            "audio_tokens_out" => reported(self.audio_tokens_out),
            "text_tokens_in" => reported(self.text_tokens_in),
            "text_tokens_out" => reported(self.text_tokens_out),
            "cached_tokens" => reported(self.cached_tokens),
            // The duration this plane counted itself rather than read off the upstream, in SECONDS,
            // through the plane's own boundary. The counter is milliseconds; the class the plane
            // declares is denominated in seconds, and a figure that settled in the counter's unit
            // would settle a turn of audio at a thousand times its duration. Marked an estimate
            // because that is what it is — a duration derived from a byte count under an assumed
            // format — and a billing dispute turns on the difference between that and a figure the
            // destination confirmed.
            "audio_seconds_in" => Some((
                meta::audio_seconds_in(self.audio_ms_in),
                QuantitySource::Count,
                true,
            )),
            // A cardinality the plane surfaced as a declared content fact, named as the fact it was
            // read from rather than as a bare count: the variance rule needs to know which
            // declaration a figure came from to find its kernel-derived companion.
            "tool_calls" => Some((
                self.tool_calls,
                QuantitySource::PlaneCount {
                    content_fact_key: meta::FACT_TOOL_CALLS.to_string(),
                },
                false,
            )),
            _ => None,
        }
    }

    /// The report as usage lines, one per class the plane declares that carried a figure.
    ///
    /// A class with nothing to report produces no line rather than a zero: a line that says zero and
    /// a line that is absent settle the same, but only one of them claims the upstream said so.
    fn lines(&self) -> Vec<UsageLine> {
        <VoicePlane as busbar_contract::plane::PlaneMeta>::METER_CLASSES
            .iter()
            .filter_map(|decl| {
                let (quantity, source, estimated) = self.figure(decl)?;
                (quantity > 0).then_some(UsageLine {
                    class: decl.key,
                    quantity,
                    source,
                    estimated,
                })
            })
            .collect()
    }

    /// Everything this turn metered, over every class the plane declares.
    ///
    /// One figure, read by the metering step to settle the session's lease and by the exit evidence
    /// as what the turn located. They are the same number BECAUSE they are one reading: a lease
    /// drawn down at the whole report and a posting settled at one class of it would charge the
    /// session for audio and bill the caller for none of the text that went with it.
    fn total(&self) -> u64 {
        self.lines()
            .iter()
            .fold(0u64, |sum, line| sum.saturating_add(line.quantity))
    }
}

/// The coarse opening magnitude of one turn, in tokens of the dearest class it may charge under.
///
/// Deliberately generous, and the asymmetry is the reason: an under-sized reservation has to be
/// topped up mid-turn out of the principal's slice, and a slice that has run dry turns the rest of
/// the turn into an overdraft the deployment carries. An over-sized one costs nothing at all — the
/// residual is released at settlement, in the same act that posts the figure. So this is sized to be
/// wrong in the cheap direction.
const TURN_OPENING_TOKENS: u64 = 4_096;

/// How many turns of that magnitude the session's own opening reservation covers.
///
/// A live session cannot be metered after the fact, so unit zero reserves for the conversation and
/// each turn settles against it. This is what "the metering lease is the hold" is sized by.
const SESSION_OPENING_TURNS: u64 = 8;

/// One voice unit, as the loop reaches it.
///
/// Constructed per unit, cheap, and holding only what this unit is about: the node's half is
/// borrowed. Every field is a fact some earlier stage already determined — the pump read the shape,
/// the transport recorded the arrival, the plane named the dialect — so no step here re-derives what
/// another already knew.
pub struct VoiceUnit<'n> {
    /// The node's long-lived half.
    pub node: &'n VoiceNode,
    /// Which shape this unit is.
    pub shape: UnitShape,
    /// The session this unit belongs to.
    pub session: u64,
    /// What the transport recorded about the connection.
    pub arrival: ArrivalRecord,
    /// The credential the carriers presented, where one was.
    pub credential: Option<String>,
    /// What the caller's credential is entitled to, as the auth chain resolved it.
    ///
    /// Held on the unit rather than looked up at the step that checks it, for the reason every other
    /// plane holds it the same way: the grants are the CALLER's and are decided once, and a step that
    /// went looking for them a second time would be a second place for a principal's entitlement to
    /// be decided.
    pub grants: Grants,
    /// Whether the credential rides the session rather than being presented per unit.
    pub from_session: bool,
    /// The dialect the decode step named.
    pub dialect: Dialect,
    /// The buckets this session's caller is judged and charged against: its own attribution bucket,
    /// then the group its key is bound to, then that group's parent, to the root.
    ///
    /// BORROWED, and a session-long fact rather than a per-turn one. The key is presented once, at
    /// the open, so the chain it resolves to is settled before the first turn and cannot change
    /// under the session; resolving it per turn would put a fresh vector of owned bucket ids on the
    /// door's path for every frame of a live conversation, which is the one place on this plane
    /// where per-unit work is per-frame work.
    ///
    /// `None` is the fail-closed arm and NOT the uncapped one: it is a caller bound to a group this
    /// node's configuration does not have, whose caps therefore could not be read. A caller bound
    /// to no group at all has a perfectly good chain of one uncapped attribution bucket, and gets
    /// it.
    pub chain: Option<&'n busbar_unit_admission::BucketChain>,
    /// What the turn reported, once the upstream reported it.
    pub usage: TurnUsage,
    /// The identifier a tool call's answer must carry, as the plane's draft minted it.
    ///
    /// The unit's own copy, and it is here rather than reached for because the frame that plans the
    /// leg is the frame that has to enter the wait: by the time anything else could ask, the arena
    /// the plane decoded the identifier into is gone.
    pub call_id: Option<String>,
    /// The node's monotonic reading when this unit's frame arrived, in milliseconds.
    ///
    /// A deadline is a difference between two of these, never a wall-clock reading: [`epoch`] is
    /// pinned at arrival so the unit is judged and charged in one window, which is a different
    /// question from how long a client has to answer a tool call.
    ///
    /// [`epoch`]: VoiceUnit::epoch
    pub now_ms: Millis,
    /// The wall clock this unit is judged against, pinned at arrival. Never a fresh read: a
    /// straddling unit judged against one clock and charged against another is a unit whose charge
    /// landed in a window it was not checked in.
    pub epoch: u64,
    /// What the route step spent, read back by the settlement table.
    accrued: AtomicU64,
    /// Whether the dial opened.
    dialed: Mutex<Option<Result<(), DialRefusal>>>,
    /// How the audit step classified this unit's ending, once it sealed one.
    ///
    /// The record is sealed before the exit path settles, and the ending it sealed is one of the
    /// facts the fee is decided from. Carrying it here is what lets the settlement read the plane's
    /// verdict rather than a second guess at it: a record that says the turn errored and a posting
    /// that charged for it would be two answers to one question.
    sealed_finish: Mutex<Option<busbar_contract::FinishClass>>,
    /// WHO THIS UNIT IS FOR, as the auth chain resolved it.
    ///
    /// The chain's answer is the chain's: a decision has no reader on it by design, and the only
    /// thing that opens one is the loop. So the principal is recorded at the first step the loop
    /// hands it to — verify — and the record reads it back from here. The audit record names a
    /// subject, and a paid unit whose subject is "an arrival" names nobody at all: a bill nobody
    /// can be shown, and a revocation nobody can be traced through.
    principal: Mutex<Option<PrincipalId>>,
}

impl std::fmt::Debug for VoiceUnit<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoiceUnit")
            .field("shape", &self.shape)
            .field("session", &self.session)
            .field("dialect", &self.dialect.name())
            .finish_non_exhaustive()
    }
}

impl<'n> VoiceUnit<'n> {
    /// A unit of one shape, on one session.
    #[must_use]
    pub fn new(node: &'n VoiceNode, shape: UnitShape, session: u64, epoch: u64) -> Self {
        VoiceUnit {
            node,
            shape,
            session,
            arrival: ArrivalRecord {
                source: String::new(),
                port: 0,
                alpn: None,
                sni: None,
                peer_cert: None,
                // Composed, not layered by accident: the WebSocket transport is only serviceable
                // built over HTTP, so the chain a voice session arrives on names both. A chain of
                // one would be the under-reported shape composition exists to fix.
                transport_chain: vec!["http", "ws"],
            },
            credential: None,
            // The full grant until a caller says otherwise through `holding`. This is the seam's
            // default and not a policy: no transport composes a voice unit yet, so there is no
            // credential for a narrower value to have come from, and a default that refused would
            // refuse a caller nobody has authenticated rather than one who was found wanting.
            grants: Grants::of(Scope::Full),
            from_session: shape != UnitShape::SessionOpen,
            dialect: Dialect::OpenaiRealtime,
            chain: None,
            usage: TurnUsage::default(),
            call_id: None,
            now_ms: 0,
            epoch,
            accrued: AtomicU64::new(0),
            dialed: Mutex::new(None),
            sealed_finish: Mutex::new(None),
            principal: Mutex::new(None),
        }
    }

    /// The credential this unit presents.
    #[must_use]
    pub fn with_credential(mut self, credential: impl Into<String>) -> Self {
        self.credential = Some(credential.into());
        self
    }

    /// What this unit's caller is entitled to.
    #[must_use]
    pub fn holding(mut self, grants: Grants) -> Self {
        self.grants = grants;
        self
    }

    /// The dialect the decode step named.
    #[must_use]
    pub fn on_dialect(mut self, dialect: Dialect) -> Self {
        self.dialect = dialect;
        self
    }

    /// The chain this unit's caller charges through, as the session resolved it at the open.
    ///
    /// Carried in rather than resolved here, for the reason every other fact on this struct is:
    /// which buckets a key charges is settled before the first step runs, and a step that resolved
    /// it would be a step deciding its own input — once per frame, for an answer that is the same
    /// every time.
    #[must_use]
    pub fn charging_through(mut self, chain: &'n busbar_unit_admission::BucketChain) -> Self {
        self.chain = Some(chain);
        self
    }

    /// What the turn reported.
    #[must_use]
    pub fn reporting(mut self, usage: TurnUsage) -> Self {
        self.usage = usage;
        self
    }

    /// Whether anything the upstream produced reached the caller.
    ///
    /// On a duplex plane there is no headers frame to count: the first thing a caller sees of an
    /// answer is the first token of it, so what the upstream reported having emitted is the record
    /// of a frame having been relayed. Input the turn consumed is not an answer — a turn that was
    /// heard and never replied to relayed nothing.
    #[must_use]
    fn answered(&self) -> bool {
        self.usage.audio_tokens_out > 0 || self.usage.text_tokens_out > 0
    }

    /// The call this tool-call unit is, named by the identifier its answer must carry.
    #[must_use]
    pub fn calling(mut self, call_id: impl Into<String>) -> Self {
        self.call_id = Some(call_id.into());
        self
    }

    /// The node's monotonic reading this unit's frame arrived at.
    #[must_use]
    pub fn at_ms(mut self, now_ms: Millis) -> Self {
        self.now_ms = now_ms;
        self
    }

    /// The correlation an answer to this unit must carry, borrowed from the unit's own copy.
    ///
    /// Borrowed rather than owned, and borrowed for no longer than the call that enters it: the
    /// waiting table copies the identifier into the kernel's own memory and keeps no borrow, which
    /// is what lets a wait outlive the frame that planned it.
    fn correlation_out(&self) -> Option<CorrelationRef<'_>> {
        self.call_id.as_deref().map(|id| CorrelationRef {
            fact_key: busbar_plane_voice::plane::FACT_TOOL_CORRELATION,
            value: CorrelationValue::Str(id),
        })
    }

    /// Whether the dial was attempted and what it answered.
    #[must_use]
    pub fn dial_outcome(&self) -> Option<Result<(), DialRefusal>> {
        *self.dialed.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The upstream this unit's session dials, given the dialect it arrived on.
    fn upstream(&self) -> Option<&'static Upstream> {
        if self.dialect.is_duplex_upstream() {
            if let Some(found) = self.node.plane.upstream_for_dialect(self.dialect) {
                return Some(found);
            }
        }
        self.node.plane.upstreams().first()
    }

    /// The dial target for this unit's upstream.
    fn target(&self) -> Option<DialTarget> {
        let upstream = self.upstream()?;
        Some(DialTarget {
            pool: upstream.lane.as_str().to_string(),
            lane: 0,
            url: format!("wss://{}", upstream.host),
            // The fail-closed posture, unconditionally. A public provider endpoint is exactly the
            // shape the default exists for, and a root that widened it per dial would be a root
            // deciding a security question the trust unit owns.
            policy: GuardPolicy::default(),
        })
    }

    /// What the door is asked to reserve.
    ///
    /// A handshake unit reserves nothing at all AT THE DOOR — its whole admission is the zero-priced
    /// one, drawing no request slot and taking no concurrency lease, which is what lets a node hand
    /// shake before it has authenticated anybody. The session's opening figure, and the one flat fee
    /// with it, are taken on the SESSION's lease instead (`session_opening_nanos`); the two are
    /// different reservations for different things and the distinction is the design.
    ///
    /// A turn reserves the coarse opening magnitude the session's own budget names, over-estimated on
    /// purpose. An under-sized hold tops up; an over-sized one costs nothing but headroom the unit
    /// gives straight back at settlement, and the asymmetry is why the estimate is deliberately
    /// generous rather than tight.
    fn estimate(&self) -> Estimate {
        if self.shape.is_handshake() {
            return Estimate::zero();
        }
        // The highest price any class this turn may charge under carries the whole estimate. Pricing
        // the opening magnitude at the cheapest class and then charging at the dearest is how a
        // reservation is under-sized on every single turn; taking the maximum costs nothing but
        // headroom the settlement gives straight back.
        let rate = self
            .node
            .pricer
            .rate_for(self.dialect.name())
            .unwrap_or_default();
        let dearest = rate
            .input
            .max(rate.output)
            .max(rate.cache_read)
            .max(rate.cache_write);
        Estimate {
            per_class: vec![busbar_unit_admission::ClassEstimate {
                class: meta::CLASS_AUDIO_TOKENS_OUT.as_str().to_string(),
                quantity: TURN_OPENING_TOKENS,
                max_unit_price_nanos: dearest,
            }],
            // A turn is a frame of a conversation the session already paid to open, not a request of
            // its own, so it carries no flat fee. Unit zero drew the slot — and now the settlement
            // agrees: the fee this line declines to reserve is the fee `fee_evidence` declines to
            // post, one decision read in two places instead of two decisions disagreeing.
            fee_nanos: 0,
        }
    }

    /// The flat fee ONE VOICE SESSION pays, in nano-units.
    ///
    /// **Once per session, at the open.** A voice session is one billable arrival that then runs for
    /// minutes: the caller connects once, the node dials one upstream leg once, and everything after
    /// that is frames of the conversation that leg carries. That is the rule the previous release
    /// shipped and metered — its lease reserved `estimate + fee` at the open and its settle path was
    /// explicit that the fee is not re-debited per turn — and it is the rule the rate card's own
    /// per-request fee means, because a session is the request.
    ///
    /// The root reads the figure; the plane never sees it. What the plane says is what it consumed.
    fn session_fee_nanos(&self) -> u64 {
        u64::try_from(self.node.pricer.price_per_request_cents().max(0))
            .unwrap_or(0)
            .saturating_mul(NANOS_PER_CENT)
    }

    /// How far this unit's reservation may still be grown, in nano-units.
    ///
    /// The door's own read of what the principal's slice has left in the window. It is not a
    /// decision and cannot become one: zero means the reservation does not grow and the rest of the
    /// turn is carried as an overdraft, which is a turn that still runs.
    ///
    /// Read off the session's own chain — the same value the door was judged against, not a second
    /// copy of it — so a turn grows into the window its group actually has left rather than into an
    /// unbounded one. A caller whose caps could not be read is zero, the same fail-closed direction
    /// the door takes.
    fn headroom_nanos(&self) -> u64 {
        let Some(chain) = self.chain else {
            return 0;
        };
        let door = self.node.door.lock().unwrap_or_else(|e| e.into_inner());
        busbar_unit_admission::AdmissionUnit::new(
            &door,
            &self.node.pricer,
            self.dialect.name(),
            self.epoch,
        )
        .headroom_nanos(chain)
    }

    /// The session's coarse opening reservation, in nano-units: what unit zero takes the lease for
    /// and every later frame is allowed against.
    ///
    /// **The coarse estimate PLUS the session's one flat fee**, which is where the fee is reserved
    /// and the only place it is. Unit zero's own admission is still the zero-priced one — it draws
    /// no request slot and takes no concurrency lease, which is what lets a node hand shake before it
    /// has authenticated anybody — so the fee cannot ride the door's hold; it rides the session's,
    /// taken here, once, exactly as the previous release's lease took it. A fee that settled and was
    /// never reserved is a session billed past a budget that was never asked about it.
    fn session_opening_nanos(&self) -> u64 {
        let rate = self
            .node
            .pricer
            .rate_for(self.dialect.name())
            .unwrap_or_default();
        let dearest = rate
            .input
            .max(rate.output)
            .max(rate.cache_read)
            .max(rate.cache_write);
        TURN_OPENING_TOKENS
            .saturating_mul(SESSION_OPENING_TURNS)
            .saturating_mul(dearest)
            .saturating_add(self.session_fee_nanos())
    }

    /// The two facts about this unit's upstream leg the flat fee is decided from.
    ///
    /// Whether a leg was SELECTED, and whether it ANSWERED. On this plane both are unit zero's: the
    /// session's one dial is what selects the leg and what opens it, and every later frame relays
    /// onto a leg that already exists. So a turn's answer to the second question is what the turn
    /// itself emitted, and its answer to the first is that the session's leg is there.
    fn upstream_leg(&self) -> (bool, bool) {
        if self.shape.is_handshake() {
            (
                self.target().is_some(),
                matches!(self.dial_outcome(), Some(Ok(()))),
            )
        } else {
            (true, self.answered())
        }
    }

    /// Everything the flat fee is decided from, for this unit.
    fn fee(&self, ctx: &UnitCtx, finish: Option<busbar_contract::FinishClass>) -> FeeEvidence {
        let (selected_upstream, relayed) = self.upstream_leg();
        fee_evidence(self.shape, ctx.origin, selected_upstream, relayed, finish)
    }
}

// ---------------------------------------------------------------------------------------------
// The twelve methods
// ---------------------------------------------------------------------------------------------

impl Units for VoiceUnit<'_> {
    fn arrival(&self, token: &UnitToken<Arrival>, _ctx: &UnitCtx) -> Decision<Arrival> {
        // The kernel's own gate, over the configured budgets. There is no unit behind this step and
        // there was never meant to be: what it answers is the connection's own arrival record, which
        // the transport built and this file carries.
        Decision::proceed(token, self.arrival.clone())
    }

    fn decode(&self, token: &UnitToken<Decode>, _ctx: &UnitCtx) -> Decision<Decode> {
        // The plane already read the frame; the pump already turned what it read into a shape. What
        // reaches the loop here is the operation class that shape is, and re-reading the frame to
        // re-derive it would advance the codec's per-session sequence a second time.
        Decision::proceed(token, self.shape.op_class())
    }

    fn authenticate(
        &self,
        token: &UnitToken<Authenticate>,
        _ctx: &UnitCtx,
    ) -> Decision<Authenticate> {
        let request = AuthRequest {
            candidate: self.credential.as_deref(),
            // The plane narrows within the claim's alternatives and never outside them; the unit is
            // handed both so the auth unit can check the narrowing before it looks at a credential.
            scheme: None,
            declared_schemes: SESSION_SCHEME_ALTERNATIVES,
            // The audience a signed token must carry to be accepted on this plane's ingress. The
            // plane's own name, so a token minted for another plane's audience is refused here and
            // not at the destination it was going to reach.
            expected_aud: Some(<VoicePlane as busbar_contract::plane::PlaneMeta>::KEY),
            in_handshake: self.shape.is_handshake(),
            now: self.epoch,
            // Revocation gates NEW units only. Unit 0 is new; a later frame of a session already
            // open is not, and re-checking it would end a paying conversation mid-sentence for a
            // revocation that arrived after it started.
            new_unit: self.shape.is_handshake(),
        };
        // The three seams the chain cannot own: the credential cache, so a session's credential
        // consults its module once per lifetime rather than once per frame; the signed-key
        // verifier, which is what makes the audience above something that can be checked rather
        // than something that is merely declared; and the revocation view, which the request above
        // has already said applies to the opening unit and to no later one.
        let bindings = &self.node.auth_bindings;
        self.node.auth.resolve(
            &request,
            bindings.cache(),
            bindings.keys(),
            bindings.revocations(),
            None,
            token,
        )
    }

    fn verify(
        &self,
        token: &UnitToken<Verify>,
        trust: &TrustToken,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> Decision<Verify> {
        // THE FIRST STEP THAT IS HANDED THE PRINCIPAL IS THE FIRST THAT CAN RECORD IT, and the
        // record is the only reader that needs one. The authenticate step's answer belongs to the
        // chain and nothing may open it there; here the loop has already opened it and hands over
        // who it named. Recorded once, on the unit, for the same reason the grants are.
        *self.principal.lock().unwrap_or_else(|e| e.into_inner()) = Some(principal.clone());
        // **The one frame a wait can be entered in.** A tool call's leg is a client await-reply, and
        // the value it waits on is the identifier this unit's own draft minted, which lives no
        // longer than the frame that decoded it. So the wait is entered HERE, where the leg is
        // planned and the identifier is still readable, and not on some later step that would have
        // to have kept a borrow it cannot keep.
        if matches!(self.shape, UnitShape::ToolCall)
            && self
                .node
                .tool_calls
                .planned(
                    self.session,
                    ctx.key,
                    TOOL_REPLY_LEG,
                    self.correlation_out(),
                    self.now_ms,
                )
                .is_err()
        {
            // A call nothing can answer. The leg names a key and the draft minted nothing under it,
            // or minted under another — either way there is no client this reply could come back
            // from, which is the no-destination answer and not a wait with a wildcard in it.
            return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
        }
        // The trust unit's answer is a set of SEALED destinations, and sealing takes the trust token
        // the loop lends this step beside its own — the same shape admit and meter are lent. So the
        // destination this session's dialect resolves to is sealed HERE, once, and the route step
        // dials what this says rather than re-resolving the upstream on its own.
        //
        // The empty set is still the honest answer when configuration named no upstream at all: a
        // unit with nowhere to go proceeds, the door draws and retains its slot, and the unit ends
        // at the plane's no-destination terminal. What is no longer true is that a CONFIGURED
        // upstream is answered the same way as an absent one.
        let destinations: Vec<VerifiedDestination> = self
            .upstream()
            .map(|upstream| vec![VerifiedDestination::seal(trust, upstream.lane)])
            .unwrap_or_default();
        Decision::proceed(token, destinations)
    }

    fn approve(
        &self,
        token: &UnitToken<Approve>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> Decision<Approve> {
        // A handshake unit's scope is kernel-granted, for every principal including the anonymous
        // one. That is what lets a node hand shake before it has authenticated anybody, and it is
        // never a policy key — a deployment cannot revoke it by leaving it out of a table.
        if self.shape.is_handshake() {
            return Decision::proceed(token, ScopeFacts::default());
        }
        // Everything else asks the policy, and silence is a refusal. The scope unit answers `None`
        // for a pair it was told nothing about, and reading `None` as a pass would be authorization
        // by omission — every operation class a deployment forgot to name would be open.
        let claim = ClaimKey::new(<VoicePlane as busbar_contract::plane::PlaneMeta>::KEY);
        let Some(needed) =
            busbar_unit_scope::required_scope(claim, self.shape.op_class(), &self.node.scope)
        else {
            return Decision::refuse(token, Refusal::new(ReasonCode::ScopeDenied));
        };
        // And having found what the operation requires, the caller's grant is compared against it —
        // which is the half that was missing. Finding the requirement and not checking it is a
        // lookup, not an authorization: it refuses a class the deployment forgot to name and admits
        // every principal for every class it did, including the read-only one opening a session.
        match busbar_unit_scope::approve(self.grants, needed) {
            Ok(()) => Decision::proceed(token, ScopeFacts::default()),
            Err(_) => Decision::refuse(token, Refusal::new(ReasonCode::ScopeDenied)),
        }
    }

    fn admit(
        &self,
        token: &UnitToken<Admit>,
        admit: &AdmitToken<Admit>,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
        leases: &GroupLeaseSlip,
    ) -> Decision<Admit> {
        // A SESSION WHOSE LEASE RAN DRY GETS NO FURTHER FRAME. The turn that emptied it was
        // delivered and settled — this is the one after it — and the refusal is raised at the door
        // under the door's own money reason, which is what the kernel reads when it decides a
        // refusal closes the session rather than merely ending the unit.
        if !self.shape.is_handshake() && self.node.is_exhausted(self.session) {
            return Decision::refuse(token, Refusal::new(ReasonCode::OverBudget));
        }

        // The handshake's admission: a hold that reserves nothing, drawing no request slot and
        // taking no concurrency lease. It is still an admission and it still ends at the exit path
        // with a settlement of zero — the point of the zero-priced hold is that the unit is
        // accounted for, not that it is exempt from accounting.
        if self.shape.is_handshake() {
            // Unit zero is a NEW session, whatever ran on this identifier before it. The mark is
            // the previous session's and is dropped here rather than left to refuse a conversation
            // that has its own reservation to take — which is also what keeps the marks from
            // outliving the sessions they were made for.
            self.node.reopened(self.session);
            // The session's opening reservation is taken here, once, and it is the reservation every
            // later frame of the session is allowed against. A lease that cannot be opened is an
            // exhaustion answer at the door rather than a session that opens and then cannot pay.
            if let Err(reason) = self
                .node
                .io
                .lease
                .reserve(self.session, self.session_opening_nanos())
            {
                // A detached I/O half is not an over-budget principal, and the two must not be
                // reported as the same thing. The reservation failing for want of a lease is the
                // node's own unavailability.
                return Decision::refuse(token, Refusal::new(reason));
            }
            return Decision::proceed(token, Admission::ZeroHold);
        }

        // The door opens the hold, not this arm. That is the ordering the whole accounting rests on:
        // a reservation exists because a decision said yes, and it is sized by the estimate that
        // decision was handed. Opening one here — beside the door rather than out of it — would be a
        // reservation with no admission behind it, and a unit whose hold and whose answer could
        // disagree about whether it was let in.
        let estimate = self.estimate();
        // The chain the deployment configured, not an empty one. An empty chain is a yes from every
        // cap at once: no gauge is raised, no window bucket is read and no freeze flag is
        // consulted, so a group's `concurrent: 1` would admit every turn that ever arrives. Read
        // from the session rather than resolved here, so this step allocates nothing to be judged.
        let Some(chain) = self.chain else {
            // Fail-closed, rendered the way the door renders the same cause: a principal whose caps
            // cannot be read is over quota, not merely rate-limited.
            return Decision::refuse(token, Refusal::new(ReasonCode::OverBudget));
        };
        let door = self.node.door.lock().unwrap_or_else(|e| e.into_inner());
        // The pinned arrival epoch, never a fresh clock read: the door's own contract.
        let mut unit = busbar_unit_admission::AdmissionUnit::new(
            &door,
            &self.node.pricer,
            self.dialect.name(),
            self.epoch,
        );
        let decision = unit.admit(&estimate, principal, chain, admit, token);
        // What the door counted, said out loud, so the loop can record one lease per capped group on
        // this unit's slot. The names are the root's interned ones; a refusal names nothing.
        for group in unit.group_leases() {
            leases.counted(group);
        }
        // AND THE COUNT ITSELF. The names above are what the node reads; this is the door's own
        // gauge, and the gauge is the cap. It is raised by the yes and lowered when the grant dies,
        // so a grant that does not outlive this call caps nothing at all. On the slot it lives as
        // long as the unit does, and the unit's end — or the sweep, if the task is lost — is what
        // gives the group its room back.
        if let Some(grant) = unit.take_grant() {
            leases.holding(DoorGrant::new(grant));
        }
        decision
    }

    fn route(
        &self,
        token: &UnitToken<Route>,
        ctx: &UnitCtx,
        meter: &AccrualMeter,
    ) -> Decision<Route> {
        // **The exit for a call nobody answered.** The sweep took the wait out of the table and left
        // the ending behind; this is where the unit reads it. A call that ran out its declared
        // deadline ends under that deadline rather than settling as though the answer arrived, which
        // is the difference between a hold that closes and a hold that is held open by a client that
        // simply never replied.
        if matches!(self.shape, UnitShape::ToolCall)
            && self.node.tool_calls.ending(self.session, ctx.key) == Some(CallEnd::Unanswered)
        {
            return Decision::refuse(token, Refusal::new(ReasonCode::DeadlineExceeded));
        }

        // A turn does not dial: it relays onto the upstream the session already opened. Only unit
        // zero opens the leg, which is why the dial is here and under this shape's arm alone — a
        // second dial per turn would be a second socket per sentence.
        if !self.shape.is_handshake() {
            let spent = self.usage.audio_ms_in;
            self.accrued.fetch_add(spent, Ordering::AcqRel);
            meter.accrue(spent);
            // How far this turn's reservation may still grow, read off the same chain the door was
            // judged against. Offered here rather than at the door because it is a reading of the
            // window as it is NOW, and the exit is where it is spent.
            meter.offer_headroom(self.headroom_nanos());
            return Decision::proceed(token, RoutePlan::default());
        }

        let Some(target) = self.target() else {
            // No upstream configured. The plane says so honestly rather than fabricating a host,
            // and the answer here is the same: nowhere to go.
            return Decision::refuse(token, Refusal::new(ReasonCode::NoDestination));
        };
        let outcome = self.node.io.dial.dial(&target);
        *self.dialed.lock().unwrap_or_else(|e| e.into_inner()) = Some(outcome);
        match outcome {
            Ok(()) => Decision::proceed(token, RoutePlan::default()),
            Err(refusal) => Decision::refuse(token, Refusal::new(refusal.reason())),
        }
    }

    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage: &UsageToken,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
    ) -> Decision<Meter> {
        let lines = self.usage.lines();
        // The turn's exact figure settles against the session's reservation. An exhausted lease is
        // reported and acted on — the session hard-closes — rather than swallowed: audio already
        // streamed cannot be refunded, so the only enforcement point is the next frame.
        let total = self.usage.total();
        if !self.shape.is_handshake() && !self.node.io.lease.settle(self.session, total) {
            // Not a refusal of this unit. This unit's value was delivered and is metered; what the
            // exhausted lease decides is whether there is a next one — and it decides no. The
            // session is marked here and refused at the door below, which is the answer the seam's
            // own contract asks for: a session that cannot pay for the next frame must stop
            // receiving them, and that is the one thing metering after the fact cannot do.
            self.node.exhaust(self.session);
        }
        match Usage::report(usage, lines) {
            Ok(report) => Decision::proceed(token, report),
            // More lines than the report's own bound allows. The assertion beside this module's
            // class list makes the arm unreachable from the declarations — which is exactly why it
            // is an honest refusal rather than an unwrap: the day a class is added is the day the
            // assertion, not this arm, is what says so.
            Err(_) => Decision::refuse(token, Refusal::new(ReasonCode::ArenaBudget)),
        }
    }

    fn audit(&self, token: &UnitToken<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> Decision<Audit> {
        self.seal(token, ctx, *outcome, outcome_finish(outcome))
    }

    fn audit_refused(
        &self,
        token: &UnitToken<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> Decision<Audit> {
        // The second door: a unit that never passed the door and was charged nothing. It still gets
        // a record, because a refusal is an event — and the record says which step said no and why,
        // because a refusal nobody can name is an event with no information in it.
        let outcome = Outcome::Refused(
            refusal.step().unwrap_or(busbar_caps::StepName::Admit),
            refusal.reason(),
        );
        self.seal(token, ctx, outcome, busbar_contract::FinishClass::Error)
    }

    fn encode(
        &self,
        token: &UnitToken<Encode>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> Decision<Encode> {
        // The plane renders the bytes; what the loop needs here is the frame they travel in. A voice
        // unit's ending is carried by the turn's own terminal frame, so the envelope is empty rather
        // than carrying a trailer this dialect does not write.
        Decision::proceed(
            token,
            busbar_caps::Frame {
                direction: busbar_contract::Direction::Outbound,
                stream: busbar_contract::StreamId(0),
                bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(&b""[..])),
                meta: busbar_contract::FrameMeta::default(),
            },
        )
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        // The ending the audit step already sealed, read once for the two answers below that turn
        // on it. Deciding it a second time here is how a record that says a turn errored ends up
        // beside a posting that charged for it.
        let finish = *self.sealed_finish.lock().unwrap_or_else(|e| e.into_inner());
        Evidence {
            // WHAT THE TURN METERED, over every class the plane declares — the same figure the
            // metering step settles the session's lease at, read from the same place. One class of
            // it is not the turn: a turn that answered in text emitted no audio, and locating only
            // the emitted audio posted nothing for a completed turn whose lease had already been
            // drawn down by the whole report. Nothing located is `None` and not a zero, because the
            // two are different rows of the settlement table.
            located: Some(self.usage.total()).filter(|total| *total > 0),
            // What the kernel counted while the unit ran, IN THE UNIT OF THE CLASS IT IS COUNTED
            // UNDER. The counter is milliseconds of uplink audio; the class the plane declares for
            // the audio a turn takes in is denominated in seconds, and the label is what says which
            // rate a figure is read at. Reported verbatim, the one row of the settlement table that
            // reads the floor settled a turn of audio at a thousand times its duration — the same
            // mismatch the metered lines already meet at the plane's own boundary, met here too so
            // the two readings of one quantity are in one unit.
            //
            // The floor is evidence, never a charge.
            accrued_floor: meta::audio_seconds_in(self.accrued.load(Ordering::Acquire)),
            locator_required: false,
            // DERIVED FROM THE ENDING THE PLANE SEALED, as it is on every other plane, rather than
            // written here as a constant no. This is the row that decides whether a stream that
            // stopped on an error still bills for what it had located: it must not, and hardcoding
            // "no error" billed every one of them in full.
            terminal_error: matches!(finish, Some(busbar_contract::FinishClass::Error)),
            recovered: false,
            dispatched: matches!(self.dial_outcome(), Some(Ok(()))),
            checkpointed: 0,
            variance: None,
            lane_mismatch: None,
            settle_record_lost: false,
            // THE CLASS THE FLOOR ABOVE IS COUNTED UNDER — the plane's one inbound-duration class,
            // read back off the declaration by the same selector `TurnUsage::figure` uses, so a
            // rename in the plane leaves this `None` rather than labelling the figure with a class
            // nobody declares. It used to name the EMITTED-AUDIO class, which was wrong twice over:
            // wrong direction, because what the kernel counts here is the audio that came IN, and
            // wrong unit, because that class is tokens and this figure is a duration.
            //
            // The located figure beside it spans every class the plane declares, and the exit path
            // posts it as the settled amount rather than pricing it through this label; what the
            // label is for is saying what the kernel's own counting was OF.
            class: declared_class("audio_seconds_in"),
            // A handshake reaches no upstream candidate, which is what makes it draw no request
            // slot. Every other shape of unit on this plane does.
            upstream_candidate: !self.shape.is_handshake(),
            fee: self.fee(ctx, finish),
        }
    }
}

impl VoiceUnit<'_> {
    /// The balance one unit of this plane settles into: the caller's own attribution bucket, in
    /// nano-units, across every pool.
    ///
    /// The plane names the balance because the plane is what knows which pot its traffic belongs
    /// in; the ledger keeps it. An uncapped attribution bucket is still a balance, which is the
    /// point — a deployment that configured no group still has one figure per principal.
    #[must_use]
    pub fn balance(principal: &PrincipalId) -> busbar_unit_ledger::totals::TotalsKey {
        busbar_unit_ledger::totals::TotalsKey::new(
            busbar_unit_ledger::totals::BucketId::new(principal.as_str()),
            busbar_unit_ledger::totals::CapDimension::NanoUnits,
            busbar_unit_ledger::totals::BucketScope::All,
        )
    }

    /// **The exit arm.** Move the books for what this unit posted, and put the posting on the
    /// journal.
    ///
    /// The loop's exit path takes the hold out of its cell, applies what the unit spent and settles
    /// it — that is where the hold stops existing. What comes back is the POSTING, and until it
    /// reaches here it has moved no balance and left no record. So this is the far end of the hold's
    /// life: opened at the door, accrued while the unit ran, and closed here, with the residual
    /// released and any overdraft carried out as a record of its own.
    ///
    /// The window is the unit's pinned arrival epoch's day, never a fresh clock read, so a session
    /// that straddles a boundary posts in the window it was admitted in.
    ///
    /// # Errors
    ///
    /// The journal could not make the record durable. The books have already moved: value was
    /// delivered, and a settlement is not rolled back because a write failed.
    pub fn settle(
        &self,
        principal: &PrincipalId,
        posted: busbar_caps::Posted,
        token: &busbar_caps::DurabilityToken,
    ) -> Result<crate::root::durability::Settled, busbar_caps::DurabilityLost> {
        let key = Self::balance(principal);
        let at = crate::root::durability::Settling {
            key: &key,
            window: busbar_unit_admission::budget_window(
                busbar_unit_admission::window::WINDOW_DAY,
                self.epoch,
            ),
            durability: token,
            // The loop has no exit step of its own; the figure this posting is OF is the metering
            // step's, and that is the step a durability loss here is attributed to.
            step: busbar_caps::StepName::Meter,
            stamp: crate::root::durability::PostingStamp {
                rate_card_version: 0,
                wall: self.epoch,
                mono: self.node.tick(),
            },
        };
        let mut durability = self
            .node
            .durability
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        durability.settle_posted(&at, posted)
    }

    /// Seal one record onto the record chain.
    ///
    /// The chain is the audit unit's and nothing else can put a record on it: a plane can say what it
    /// saw and a hook can say what it did, but turning either into a record takes the audit step's
    /// own token, which the loop lends for the length of this call.
    fn seal(
        &self,
        token: &UnitToken<Audit>,
        ctx: &UnitCtx,
        outcome: Outcome,
        finish: busbar_contract::FinishClass,
    ) -> Decision<Audit> {
        let facts = AuditFacts {
            op_class: self.shape.op_class(),
            finish,
        };
        // Written before the record is, so the settlement that follows reads the ending this record
        // carries rather than deciding the same question a second time.
        *self.sealed_finish.lock().unwrap_or_else(|e| e.into_inner()) = Some(finish);
        let inputs = self.audit_inputs(ctx, outcome, finish);
        let mut durability = self
            .node
            .durability
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _record = busbar_unit_audit::record::Audit::seal(&mut durability.record, inputs, token);
        Decision::proceed(token, facts)
    }

    /// What one record says, before the chain is touched.
    ///
    /// Separated from the sealing so the ending a record carries is a value this file computes and
    /// can be read back, rather than a literal buried under a lock.
    fn audit_inputs(
        &self,
        ctx: &UnitCtx,
        outcome: Outcome,
        finish: busbar_contract::FinishClass,
    ) -> busbar_unit_audit::record::AuditInputs {
        // The record does not decide the fee a second time: it reads the same evidence the exit
        // path settles from, through the same function.
        let (fee_count, _) = busbar_kernel::teller::fee_count(&self.fee(ctx, Some(finish)));
        busbar_unit_audit::record::AuditInputs {
            // WHO THE RECORD IS ABOUT. The principal the auth chain named, where the unit got as far
            // as being handed one. `Arrival` is the honest answer for a unit that was refused before
            // any principal existed — a connection that never got past decode is nobody's — and it
            // was the answer for every unit on this plane, including the paid ones: a settled turn
            // whose row named no principal cannot be shown to the account it charged.
            subject: match self
                .principal
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
            {
                Some(principal) => {
                    busbar_unit_audit::record::Subject::PrincipalId(principal.as_str().to_string())
                }
                None => busbar_unit_audit::record::Subject::Arrival,
            },
            what: busbar_unit_audit::record::What {
                unit_key: ctx.key,
                op_class: busbar_unit_audit::record::OpClassId::new(self.shape.op_class().as_str()),
                destination: None,
                parent: None,
                pre_hook_head: None,
                post_hook_head: None,
            },
            wall: self.epoch,
            mono: self.node.tick(),
            origin: self.node.origin,
            outcome: busbar_unit_audit::record::OutcomeFacts {
                // How the LOOP ended this unit, and the step it ended at. Both are carried in
                // rather than written here: a record that says every unit completed is a record
                // that cannot tell a turn from the refusal that replaced it.
                unit_end: outcome,
                step: outcome.step(),
                finish: audit_finish(finish),
                hook_failed: false,
                emission_delta: 0,
                stale_policy: false,
            },
            amount: busbar_unit_audit::record::Amount {
                lines: self.usage.lines(),
                pre_tier: 0,
                priced: 0,
                tier_bp: busbar_unit_admission::STANDARD_TIER_BP,
                fee_count,
                currency: String::new(),
                rate_card_version: 0,
                bucket_chain_ref: String::new(),
            },
            controls: busbar_unit_audit::record::Controls::default(),
            // The label itself never reaches the chain — only its digest does — so what travels here
            // is what the chain hashes, and nothing a reader could resolve back to a conversation.
            correlation_label: None,
        }
    }
}

/// The facts this plane's flat per-request fee is decided from.
///
/// One function, read by the record and by the settlement, because they are two readers of ONE
/// decision — a row that says a fee was charged over a posting that charged none is a discrepancy
/// nothing downstream can settle.
///
/// **ONE FLAT FEE PER SESSION, AND THE SESSION'S OPENING UNIT IS WHAT PAYS IT.** A voice session is
/// one billable arrival that then runs for minutes: the caller connects once, the node dials one
/// upstream leg once, and every frame after that is the conversation that leg carries. Charging the
/// fee per turn billed a ten-minute call ten, twenty, a hundred times over for one connection — and
/// it disagreed with the hold, which reserved no fee on a turn at all on the stated grounds that
/// unit zero had drawn the slot. Both halves now say the same thing, and the previous release's own
/// metering is what they say: its lease reserved `estimate + fee` at the open and never re-debited
/// the fee on a settle.
///
/// A tool call is the provider pushing through the session's own upstream, which is not a caller's
/// request and pays nothing; a turn is a frame of a conversation already paid for.
///
/// The leg is the session's upstream: unit zero's dial is what SELECTS it and what OPENS it, so for
/// the unit that pays, those two questions are that dial's two answers. This dialect writes no
/// status frame of its own — the answer's first token is the first thing the caller sees — so the
/// plane's sealed ending is the single source, and an ending it called an error posts nothing.
fn fee_evidence(
    shape: UnitShape,
    origin: busbar_caps::OriginKind,
    selected_upstream: bool,
    relayed_first_response_frame: bool,
    finish: Option<busbar_contract::FinishClass>,
) -> FeeEvidence {
    FeeEvidence {
        client_open_or_one_shot: origin == busbar_caps::OriginKind::Client && shape.is_handshake(),
        selected_upstream,
        relayed_first_response_frame,
        status_at: None,
        status: None,
        finish,
    }
}

/// How the plane classifies an ending, from how the loop ended it.
fn outcome_finish(outcome: &Outcome) -> busbar_contract::FinishClass {
    if outcome.is_completed() {
        // A turn completing is not the conversation completing. Every other plane's completion is
        // the end of the thing; here it is the end of one turn of a thing that continues.
        busbar_contract::FinishClass::TurnComplete
    } else {
        busbar_contract::FinishClass::Error
    }
}

/// The audit crate's own spelling of a finish class.
fn audit_finish(finish: busbar_contract::FinishClass) -> busbar_unit_audit::record::FinishClass {
    match finish {
        busbar_contract::FinishClass::Complete => busbar_unit_audit::record::FinishClass::Complete,
        busbar_contract::FinishClass::TurnComplete => {
            busbar_unit_audit::record::FinishClass::TurnComplete
        }
        busbar_contract::FinishClass::Partial => busbar_unit_audit::record::FinishClass::Partial,
        busbar_contract::FinishClass::Error => busbar_unit_audit::record::FinishClass::Error,
    }
}

/// A scope policy that declares what this plane's operation classes require.
///
/// Built here rather than left to a deployment's own table because the five classes are the plane's
/// own declaration and a deployment that had to restate them could restate one of them wrong. What a
/// deployment decides is which principals hold which scope; what the classes need is structure.
#[must_use]
pub fn scope_policy() -> crate::root::policy::ScopePolicy {
    let claim = ClaimKey::new(<VoicePlane as busbar_contract::plane::PlaneMeta>::KEY);
    crate::root::policy::ScopePolicy::new()
        // The handshake's own class is declared for completeness, but the approve step answers it
        // before the policy is asked: a kernel-granted operation needs no policy entry at all.
        .declaring(claim, meta::OP_SESSION_OPEN, Scope::Full)
        .declaring(claim, OpClassId::new(OP_DUPLEX_TURN), Scope::Full)
        .declaring(claim, OpClassId::new(OP_TOOL_CALL), Scope::Full)
        .declaring(claim, OpClassId::new("transcribe"), Scope::Full)
        .declaring(claim, OpClassId::new("tts"), Scope::Full)
}

/// The kernel-granted scope a handshake unit runs under, named so the approve arm above can be read
/// against the thing it is implementing.
#[must_use]
pub const fn handshake_scope() -> &'static str {
    TRANSPORT_HANDSHAKE
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_caps::Canary;
    use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
    use busbar_kernel::teller::{run_unit, Ended, Kernel, Run};
    use busbar_unit_auth::AuthChain;

    const REALTIME: LaneId = LaneId::new("voice-realtime");
    const LIVE: LaneId = LaneId::new("voice-live");

    /// The two composed provider endpoints, as a node's registry would hold them.
    static UPSTREAMS: &[Upstream] = &[
        Upstream {
            lane: REALTIME,
            host: "api.openai.com",
            dialect: Dialect::OpenaiRealtime,
        },
        Upstream {
            lane: LIVE,
            host: "generativelanguage.googleapis.com",
            dialect: Dialect::GeminiLive,
        },
    ];

    /// THE CLASS THE ROOT NAMES IS THE CLASS THE PLANE DECLARES, at every site that names it.
    ///
    /// The label selects the unit price, so a turn admitted against one spelling and settled under
    /// another is money on a rate card where the two rates differ — and a wire string re-spelled in
    /// the root is a rename in the plane that leaves the root pricing under a class nobody declares.
    /// The plane's declaration is the one source, and every reading below comes from it.
    #[test]
    fn the_emitted_audio_class_is_the_one_the_plane_declares() {
        let declared = <VoicePlane as busbar_contract::plane::PlaneMeta>::METER_CLASSES
            .iter()
            .any(|class| class.key == meta::CLASS_AUDIO_TOKENS_OUT);
        assert!(
            declared,
            "the plane declares the class the root prices under"
        );

        let usage = TurnUsage {
            audio_tokens_out: 3,
            ..TurnUsage::default()
        };
        let line = usage
            .lines()
            .into_iter()
            .find(|line| line.quantity == 3)
            .expect("the emitted audio is reported");
        assert_eq!(line.class, meta::CLASS_AUDIO_TOKENS_OUT);
        // And the one spelling is still the released one: a shared constant makes a rename cheap,
        // which is exactly why the wire string it carries is pinned here.
        assert_eq!(line.class.as_str(), "audio_tokens_out");
    }

    /// EVERY class the plane declares is a class the root knows what to put in, and the root emits
    /// none the plane does not declare.
    ///
    /// This is the assertion that turns a rename from a silent mispricing into a red build. The root
    /// no longer keeps its own list of class names — it walks the plane's declaration and asks what
    /// each entry is worth — so a class the plane renames stops being recognised, produces no line,
    /// and is caught here. Without this, that class would simply stop being reported, and a class
    /// that is not reported settles at nothing on every turn of every session.
    #[test]
    fn every_declared_class_carries_a_figure() {
        // A turn that carried something under all seven, so the only reason a class can be missing
        // from the report below is that the root did not recognise it.
        let usage = TurnUsage {
            audio_tokens_in: 11,
            audio_tokens_out: 12,
            text_tokens_in: 13,
            text_tokens_out: 14,
            cached_tokens: 15,
            audio_ms_in: 16_000,
            tool_calls: 17,
        };
        let lines = usage.lines();
        let declared = <VoicePlane as busbar_contract::plane::PlaneMeta>::METER_CLASSES;
        assert_eq!(
            lines.len(),
            declared.len(),
            "one line per declared class, and no line the plane did not declare"
        );
        for decl in declared {
            assert!(
                lines.iter().any(|line| line.class == decl.key),
                "the root has a figure for every class the plane declares"
            );
        }
        // And the sum the lease and the exit evidence both read is the sum of exactly those lines.
        assert_eq!(
            usage.total(),
            lines.iter().map(|line| line.quantity).sum::<u64>()
        );
    }

    /// A dial that opens, so a cell can reach the stations past route without an I/O half.
    struct OpenDial;
    impl ProviderDial for OpenDial {
        fn dial(&self, _target: &DialTarget) -> Result<(), DialRefusal> {
            Ok(())
        }
    }

    /// A lease that can be taken and never runs dry.
    struct OpenLease;
    impl SessionLease for OpenLease {
        fn reserve(&self, _session: u64, _nanos: u64) -> Result<(), ReasonCode> {
            Ok(())
        }
        fn settle(&self, _session: u64, _nanos: u64) -> bool {
            true
        }
        fn close(&self, _session: u64) {}
    }

    fn node(io: VoiceIo) -> VoiceNode {
        // A deployment that configured no group: every caller is attributed and none is capped.
        node_governed_by(io, busbar_unit_admission::GroupTable::default())
    }

    fn node_governed_by(io: VoiceIo, groups: busbar_unit_admission::GroupTable) -> VoiceNode {
        node_behind(
            io,
            groups,
            // The chain these tests run is the empty one — the open front door — so the seams have
            // nothing to answer and the unbound posture is the honest fixture for them.
            Auth::new(AuthChain::new(Vec::new(), false)),
            crate::root::kernel::auth_bindings::AuthBindings::without_directory(),
        )
    }

    /// The same node behind a door a deployment actually shut.
    ///
    /// Split out of `node` rather than duplicated because the only thing an authenticate cell may
    /// vary is the door: a fixture that also swapped the pricer, the scope table or the journal
    /// would be asserting about a different node than every other cell in this file.
    fn node_behind(
        io: VoiceIo,
        groups: busbar_unit_admission::GroupTable,
        auth: Auth,
        auth_bindings: crate::root::kernel::auth_bindings::AuthBindings,
    ) -> VoiceNode {
        let durability = crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_unit_wal::NullShipper::new()),
            Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open");
        VoiceNode::new(VoiceNodeParts {
            plane: VoicePlane::new(UPSTREAMS),
            groups,
            pricer: Pricer::flat(0),
            auth,
            auth_bindings,
            scope: scope_policy(),
            meter_policy: crate::root::policy::build(
                &crate::root::policy::MeterPolicyConfig::default(),
            ),
            durability,
            io,
            origin: Kernel::new().origin(busbar_caps::OriginKind::Client),
        })
    }

    fn serviceable() -> VoiceIo {
        VoiceIo {
            dial: Box::new(OpenDial),
            lease: Box::new(OpenLease),
            ..VoiceIo::default()
        }
    }

    /// The chain a deployment with no `groups:` section resolves for every caller: one uncapped
    /// attribution bucket, charged on every admission and blocking nothing.
    ///
    /// One value for the whole test module, because it is one value for the whole node — which is
    /// the property the unit's borrow exists to make visible.
    fn ungoverned() -> &'static busbar_unit_admission::BucketChain {
        static CHAIN: std::sync::OnceLock<busbar_unit_admission::BucketChain> =
            std::sync::OnceLock::new();
        CHAIN.get_or_init(|| {
            busbar_unit_admission::GroupTable::default()
                .chain_for("acct:voice", None)
                .expect("a caller bound to no group always resolves")
        })
    }

    fn ctx(key: u64) -> UnitCtx {
        UnitCtx {
            key: busbar_caps::UnitKey::new(key),
            origin: busbar_caps::OriginKind::Client,
            session: Some(Kernel::new().session_id(7)),
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        }
    }

    fn run(kernel: &Kernel, unit: &VoiceUnit<'_>) -> Ended {
        let cell = busbar_caps::HoldCell::new(busbar_caps::Hold::open(
            &kernel.admit_token(),
            PrincipalId::new("acct:voice"),
            0,
        ));
        let gauge = ConcurrencyGauge::new();
        let canary = Canary::new();
        let leases = LeaseCell::new();
        let meter = AccrualMeter::new();
        run_unit(
            kernel,
            unit,
            &ctx(1),
            Run {
                cell: &cell,
                parent: None,
                leases: &leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
            },
        )
    }

    /// The whole session-bound path, as one unit: the connection arrives over a composed transport,
    /// the handshake runs every station, the lease is taken at the door, the provider leg opens, and
    /// the unit settles once. That last word is the assertion — `Settled` is the exit path having
    /// taken the hold, and there is no second taker in this run.
    #[test]
    fn unit_zero_runs_every_station_and_settles_exactly_once() {
        let kernel = Kernel::new();
        let node = node(serviceable());
        let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
        let ended = run(&kernel, &unit);
        assert!(matches!(ended, Ended::Settled { .. }));
        assert_eq!(unit.dial_outcome(), Some(Ok(())));
    }

    /// A CREDENTIAL THE NODE'S OWN DOOR DOES NOT ACCEPT ENDS THE SESSION AT THE AUTHENTICATE STEP,
    /// and the audience is the thing that decides it.
    ///
    /// Authenticate is a gating step, and until this cell existed nothing drove one over the loop on
    /// this plane: the conformance rig's credential leg proves the credential the node dials OUT
    /// under, which is the other direction entirely. A plane that ships through the composition root
    /// with its inbound credential check driven by nobody is a door whose lock has never been turned.
    ///
    /// The audience is where the turn happens. Every one of this plane's credentialed claims carries
    /// one, so a token minted for a SIBLING plane's audience is a well-formed, unexpired, correctly
    /// signed token — and must still be refused here, at the plane boundary, rather than at whatever
    /// it was going to reach. That is the shape a wrong-audience token has to be refused in for the
    /// audience to be a boundary rather than a decoration.
    ///
    /// The accepted control runs beside it, because a door that refuses everything is not a door: the
    /// same directory, the same chain, the plane's own audience, and the unit runs to its end.
    #[test]
    fn a_credential_the_door_does_not_accept_ends_the_session_at_authenticate() {
        use crate::root::kernel::auth_bindings::{AuthBindings, KeyFacts, VirtualKeyDirectory};

        /// One issued key, accepted only under the audience this plane declares — and a record of
        /// the audience it was asked under, so the boundary is measured and not merely stated.
        #[derive(Default)]
        struct OneKey {
            asked_under: Mutex<Vec<Option<String>>>,
        }

        impl VirtualKeyDirectory for OneKey {
            fn verify(
                &self,
                credential: &str,
                _now: u64,
                expected_aud: Option<&str>,
            ) -> Option<KeyFacts> {
                self.asked_under
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(expected_aud.map(str::to_string));
                (credential == "tok"
                    && expected_aud == Some(<VoicePlane as busbar_contract::plane::PlaneMeta>::KEY))
                .then(|| KeyFacts {
                    id: "key-voice-1".to_string(),
                    name: "an approved key".to_string(),
                })
            }

            fn revoked(&self, _credential: &str) -> bool {
                false
            }
        }

        // A chain naming the signed-key arm and no boxed module: the front door is SHUT, and the arm
        // is the one thing that can open it — which is what makes this cell about the arm.
        let shut = || Auth::new(AuthChain::new(Vec::new(), true));
        assert!(!shut().chain().is_open());

        // ONE directory across all three runs, so what it was asked can be read at the end.
        let directory = std::sync::Arc::new(OneKey::default());
        let kernel = Kernel::new();
        let door = |credential: Option<&str>| -> Outcome {
            let node = node_behind(
                serviceable(),
                busbar_unit_admission::GroupTable::default(),
                shut(),
                AuthBindings::new(std::sync::Arc::clone(&directory) as _),
            );
            let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
            let unit = match credential {
                Some(c) => unit.with_credential(c),
                None => unit,
            };
            let Ended::Settled { end, .. } = run(&kernel, &unit) else {
                panic!("a refused unit settles through the same exit");
            };
            let outcome = end.outcome();
            if matches!(outcome, Outcome::Refused(_, _)) {
                // Read while the node is still alive: a unit refused at the door must not have
                // dialed, and the dial is the first thing a half-opened session would show.
                assert_eq!(
                    unit.dial_outcome(),
                    None,
                    "a session refused at authenticate never reaches the provider"
                );
            }
            outcome
        };

        // A token this node's directory never issued, and no token at all — the two shapes an
        // unauthenticated open arrives in.
        for presented in [Some("nope"), None] {
            let outcome = door(presented);
            assert!(
                matches!(
                    outcome,
                    Outcome::Refused(
                        busbar_caps::StepName::Authenticate,
                        ReasonCode::Unauthenticated
                    )
                ),
                "presented {presented:?}, got {outcome:?}"
            );
        }

        // THE CONTROL: the key the directory did issue. A door that refuses everything is not a
        // door, and a refusal cell without one proves only that nothing gets in.
        let outcome = door(Some("tok"));
        assert!(
            matches!(outcome, Outcome::Completed),
            "the accepted credential runs the session to its end, got {outcome:?}"
        );

        // AND THE AUDIENCE IS THE PLANE'S OWN, every time it was asked. The expected audience is
        // what makes a sibling plane's well-formed token refusable HERE rather than at whatever it
        // was going to reach — a root that passed `None` would verify signatures and check no
        // boundary, and every assertion above would still read the same.
        let asked = directory
            .asked_under
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert!(!asked.is_empty(), "the arm was reached at all");
        for aud in asked.iter() {
            assert_eq!(
                aud.as_deref(),
                Some(<VoicePlane as busbar_contract::plane::PlaneMeta>::KEY)
            );
        }
    }

    /// The alternatives the authenticate step offers the auth unit are the ones the claim declared.
    ///
    /// The unit refuses a narrowing OUTSIDE the declared set before it looks at a credential, so a
    /// root that offered a smaller set than the claims declare would refuse a caller the deployment
    /// meant to admit, and one that offered a larger set would let the plane pick a scheme no claim
    /// ever made.
    #[test]
    fn the_declared_alternatives_are_the_claims_own() {
        assert_eq!(SESSION_SCHEME_ALTERNATIVES, &["bearer", "api-key"]);
    }

    /// The grant a caller holds is compared against what the class requires, and a caller who holds
    /// less is refused.
    ///
    /// The step used to stop one line short: it found the required scope and then proceeded on
    /// having FOUND it, which authorizes every principal for every class a deployment did name and
    /// refuses only the classes it forgot. On this plane every governed class requires the full
    /// grant, so a read-only credential reached a turn — the priced operation — on the strength of a
    /// lookup that never compared anything.
    ///
    /// The handshake arm is asserted beside it because it is the one thing that must NOT change: a
    /// kernel-granted operation is answered before the policy is asked, which is what lets a node
    /// hand shake before it has authenticated anybody.
    #[test]
    fn a_caller_who_holds_less_than_the_class_requires_is_refused() {
        let seal = busbar_caps::KernelSeal::acquire_for_kernel();
        let node = node(serviceable());

        let decide = |shape: UnitShape, held: Grants| -> bool {
            let unit = VoiceUnit::new(&node, shape, 7, 1_700_000_000).holding(held);
            let token: UnitToken<busbar_caps::step::Approve> = UnitToken::mint(&seal);
            unit.approve(&token, &ctx(1), &PrincipalId::new("acct:voice"), &[])
                .into_result(&seal)
                .is_ok()
        };

        assert!(
            !decide(UnitShape::Turn, Grants::of(Scope::ReadOnly)),
            "a read-only credential reached a turn, which the plane declares as full"
        );
        assert!(
            !decide(UnitShape::ToolCall, Grants::of(Scope::ReadOnly)),
            "a read-only credential reached a tool call"
        );
        assert!(
            decide(UnitShape::Turn, Grants::of(Scope::Full)),
            "a full credential was refused the operation it holds the grant for"
        );
        assert!(
            decide(UnitShape::SessionOpen, Grants::of(Scope::ReadOnly)),
            "the handshake stopped being kernel-granted"
        );
    }

    /// A handshake POSTS nothing and draws no request slot — which is what lets a node hand shake
    /// before it has authenticated anybody without the shaking taking a caller's concurrency. No
    /// class of usage passes through unit zero, so the amount it settles is zero.
    ///
    /// What it DOES draw is the session's one flat fee, which is a count and not a posting: opening
    /// the session is the billable arrival, and every frame after it is the conversation that
    /// arrival paid for.
    #[test]
    fn the_handshake_draws_no_request_slot_and_posts_nothing() {
        let kernel = Kernel::new();
        let node = node(serviceable());
        let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
        let Ended::Settled { requests, fee, end } = run(&kernel, &unit) else {
            panic!("the exit path settles a handshake like anything else");
        };
        assert_eq!(requests, 0, "a handshake reaches no upstream candidate");
        assert_eq!(fee, 1, "the session's one flat fee is drawn where it opens");
        assert!(matches!(end.outcome(), Outcome::Completed));
        assert_eq!(
            end.into_posted().expect("the report fits").settled(),
            0,
            "and it meters nothing: no class of usage passes through unit zero"
        );
    }

    /// A node with no I/O half cannot open a session, and says so at the door rather than opening one
    /// that cannot pay. The reservation IS the budget: a lease that could not be taken must not read
    /// as one that was.
    #[test]
    fn a_detached_node_refuses_the_session_at_the_door() {
        let kernel = Kernel::new();
        let node = node(VoiceIo::default());
        let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
        let Ended::Settled { end, .. } = run(&kernel, &unit) else {
            panic!("a refused unit settles through the same exit");
        };
        assert!(
            matches!(end.outcome(), Outcome::Refused(_, _)),
            "got {:?}",
            end.outcome()
        );
        assert_eq!(
            unit.dial_outcome(),
            None,
            "a unit refused at the door never reaches the dial"
        );
    }

    /// A guard-refused or breaker-open dial ends the opening unit rather than half-opening a session.
    /// The dial is the handshake's route leg, so its refusal is the unit's ending, and the session
    /// the unit would have created does not exist.
    #[test]
    fn a_refused_dial_ends_the_opening_unit() {
        struct Guarded;
        impl ProviderDial for Guarded {
            fn dial(&self, _target: &DialTarget) -> Result<(), DialRefusal> {
                Err(DialRefusal::GuardRefused)
            }
        }
        let kernel = Kernel::new();
        let node = node(VoiceIo {
            dial: Box::new(Guarded),
            lease: Box::new(OpenLease),
            ..VoiceIo::default()
        });
        let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
        let Ended::Settled { end, .. } = run(&kernel, &unit) else {
            panic!("the exit settles it");
        };
        // **Past the door it is a failure, not a refusal, and the difference is the money.** A unit
        // stopped before admission was never charged and ends `Refused`; this one was admitted, so
        // whatever it spent is real and the ending has to say the unit ran and did not get there.
        // The loop draws that line itself — the step's decision was a refusal either way — which is
        // why this cell asserts the loop's answer rather than the step's.
        assert!(
            matches!(
                end.outcome(),
                Outcome::Failed(busbar_caps::StepName::Route, ReasonCode::NoDestination)
            ),
            "got {:?}",
            end.outcome()
        );
        assert_eq!(unit.dial_outcome(), Some(Err(DialRefusal::GuardRefused)));
    }

    /// A turn is the governed transaction, and what it reports is what it settles against. The two
    /// text halves land on their own classes: summed into one, the emitted half would price at the
    /// input rate, which is a money question and not a spelling one.
    #[test]
    fn a_turn_meters_the_classes_the_plane_declares_with_text_split_by_direction() {
        let kernel = Kernel::new();
        let node = node(serviceable());
        let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
            .charging_through(ungoverned())
            .on_dialect(Dialect::OpenaiRealtime)
            .reporting(TurnUsage {
                audio_tokens_in: 10,
                audio_tokens_out: 20,
                text_tokens_in: 3,
                text_tokens_out: 4,
                cached_tokens: 1,
                audio_ms_in: 640,
                tool_calls: 2,
            });
        let lines = unit.usage.lines();
        let quantity = |class: &str| {
            lines
                .iter()
                .find(|l| l.class.as_str() == class)
                .map(|l| l.quantity)
        };
        assert_eq!(quantity("text_tokens_in"), Some(3));
        assert_eq!(quantity("text_tokens_out"), Some(4));
        // 640 ms of admitted audio is one second on a seconds-denominated class, not 640 of them.
        assert_eq!(quantity("audio_seconds_in"), Some(1));
        assert_eq!(quantity("tool_calls"), Some(2));

        let ended = run(&kernel, &unit);
        assert!(matches!(ended, Ended::Settled { .. }));
    }

    /// The two quantities this plane derives itself are marked as what they are. A figure the
    /// destination confirmed and one the node counted are not the same evidence, and the whole point
    /// of carrying the source with the quantity is that a dispute turns on exactly that difference.
    #[test]
    fn the_derived_quantities_are_marked_estimated_and_the_reported_ones_are_not() {
        let usage = TurnUsage {
            audio_tokens_in: 10,
            audio_ms_in: 640,
            ..TurnUsage::default()
        };
        let lines = usage.lines();
        let estimated = |class: &str| {
            lines
                .iter()
                .find(|l| l.class.as_str() == class)
                .map(|l| l.estimated)
        };
        assert_eq!(estimated("audio_tokens_in"), Some(false));
        assert_eq!(estimated("audio_seconds_in"), Some(true));
    }

    /// A class with nothing to report produces no line. A zero line and an absent line settle the
    /// same, but only one of them claims the upstream said so.
    #[test]
    fn a_class_with_nothing_to_report_produces_no_line() {
        assert!(TurnUsage::default().lines().is_empty());
    }

    /// The policy is asked about every class the plane declares, and it is asked rather than assumed:
    /// a pair the policy says nothing about answers `None`, and `None` is a refusal.
    #[test]
    fn silence_in_the_scope_policy_is_a_refusal() {
        use busbar_unit_scope::PolicyView;
        let claim = ClaimKey::new(<VoicePlane as busbar_contract::plane::PlaneMeta>::KEY);
        let policy = scope_policy();
        assert!(policy
            .required_scope(claim, OpClassId::new(OP_DUPLEX_TURN))
            .is_some());
        assert!(
            policy
                .required_scope(claim, OpClassId::new("a-class-nobody-declared"))
                .is_none(),
            "a class the policy was never told about must not answer"
        );
    }

    /// A turn on an undeclared operation class is refused at approve, not admitted and charged. This
    /// is the same finding as the one above, driven through the loop rather than asserted at the
    /// table: authorization by omission is what the empty answer exists to prevent.
    #[test]
    fn an_undeclared_operation_class_is_refused_before_the_door() {
        let kernel = Kernel::new();
        let mut node = node(serviceable());
        node.scope = crate::root::policy::ScopePolicy::new();
        let unit =
            VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
        let Ended::Settled { end, requests, .. } = run(&kernel, &unit) else {
            panic!("the exit settles it");
        };
        assert!(matches!(end.outcome(), Outcome::Refused(_, _)));
        assert_eq!(requests, 0, "a unit refused before the door draws nothing");
    }

    /// The composed transport, recorded as composed. A voice session arrives on WebSocket, which is
    /// only serviceable built over HTTP, and the chain names both — the under-reported chain of one
    /// is the shape composition exists to fix.
    #[test]
    fn the_arrival_chain_records_both_composed_layers() {
        let node = node(serviceable());
        let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
        assert_eq!(unit.arrival.transport_chain, vec!["http", "ws"]);
    }

    /// Both composed provider endpoints are reachable by their own dialect, and neither is reachable
    /// by the other's. A session that arrived speaking one wire dialing the other's endpoint would be
    /// a session speaking to a server that cannot parse it.
    #[test]
    fn each_dialect_dials_its_own_composed_endpoint() {
        let node = node(serviceable());
        let realtime = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 0);
        assert_eq!(
            realtime.target().map(|t| t.url),
            Some("wss://api.openai.com".to_string())
        );
        let live =
            VoiceUnit::new(&node, UnitShape::SessionOpen, 8, 0).on_dialect(Dialect::GeminiLive);
        assert_eq!(
            live.target().map(|t| t.url),
            Some("wss://generativelanguage.googleapis.com".to_string())
        );
    }

    /// The dial posture is the fail-closed one, and it is not a per-dial choice. A root that widened
    /// it for one endpoint would be a root deciding a question the trust unit owns.
    #[test]
    fn every_dial_takes_the_fail_closed_guard_posture() {
        let node = node(serviceable());
        let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 0);
        let target = unit.target().expect("an endpoint is configured");
        assert_eq!(target.policy, GuardPolicy::default());
        assert!(
            !target.policy.plaintext_admissible(),
            "the default posture does not admit plaintext"
        );
    }

    /// The endpoints compose from names, and the names are borrowed for the life of the program. A
    /// per-dial allocation of an endpoint name would be a leak the fixed-memory term cannot account
    /// for, which is why the constructor cannot take an owned string.
    #[test]
    fn the_two_endpoints_compose_from_borrowed_names() {
        let endpoints = ProviderEndpoints::new(
            "api.openai.com",
            REALTIME,
            "generativelanguage.googleapis.com",
            LIVE,
        );
        let pair = endpoints.as_slice();
        assert_eq!(pair[0].dialect, Dialect::OpenaiRealtime);
        assert_eq!(pair[1].dialect, Dialect::GeminiLive);
        assert!(pair.iter().all(|u| u.dialect.is_duplex_upstream()));
    }

    /// Every unit of a session leaves a record, including the one that opened it, and the operation
    /// class it leaves under is the one the plane declared. "A session opened" is not an event kind
    /// of its own: the record's shape is fixed for every plane and a plane contributes two ids.
    #[test]
    fn the_opening_unit_seals_under_the_declared_operation_class() {
        let kernel = Kernel::new();
        let node = node(serviceable());
        let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
        let before = node
            .durability
            .lock()
            .expect("record chain")
            .record
            .sealed();
        let _ = run(&kernel, &unit);
        let after = node
            .durability
            .lock()
            .expect("record chain")
            .record
            .sealed();
        assert_eq!(after, before + 1, "exactly one record for one unit");
        assert_eq!(UnitShape::SessionOpen.op_class(), meta::OP_SESSION_OPEN);
    }

    /// A lease that answers "nothing left" closes the session it answered for.
    ///
    /// The turn that emptied it is served and settled in full — audio that has already streamed
    /// cannot be refunded, so refusing it would be a refusal of value the caller already received.
    /// The frame AFTER it is the enforcement point, and it is refused at the door under the money
    /// reason, which is the same one the kernel reads to close a session rather than merely to end
    /// a unit. A session that never ran dry is untouched by any of this.
    #[test]
    fn a_session_whose_lease_runs_dry_is_closed_and_its_next_frame_refused() {
        struct DryLease;
        impl SessionLease for DryLease {
            fn reserve(&self, _session: u64, _nanos: u64) -> Result<(), ReasonCode> {
                Ok(())
            }
            fn settle(&self, _session: u64, _nanos: u64) -> bool {
                false
            }
            fn close(&self, _session: u64) {}
        }
        let node = priced_node(VoiceIo {
            dial: Box::new(OpenDial),
            lease: Box::new(DryLease),
            ..VoiceIo::default()
        });
        let kernel = Kernel::new();

        // The turn that empties the lease runs to the end and settles.
        let turn = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
            .charging_through(ungoverned())
            .reporting(TurnUsage {
                audio_tokens_out: 120,
                audio_ms_in: 900,
                ..TurnUsage::default()
            });
        let Ended::Settled { end, .. } = run(&kernel, &turn) else {
            panic!("the exit path settles it");
        };
        assert_eq!(end.outcome(), Outcome::Completed);
        assert_eq!(
            end.into_posted().expect("the report fits").settled(),
            121,
            "the frame that emptied the lease is charged exactly what it delivered: the 120 emitted \
             audio tokens plus the one second of audio it took in"
        );

        // And the next frame on that session does not get in.
        let next =
            VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
        let Ended::Settled { end, .. } = run(&kernel, &next) else {
            panic!("the exit path settles it");
        };
        assert_eq!(
            end.outcome(),
            Outcome::Refused(busbar_caps::StepName::Admit, ReasonCode::OverBudget),
            "the door refuses a session that cannot pay for another frame"
        );
        assert_eq!(
            busbar_kernel::inflight::hard_closes(
                busbar_caps::OriginKind::Provider,
                busbar_caps::StepName::Admit,
                ReasonCode::OverBudget,
                busbar_contract::Framing::Stream,
                busbar_kernel::inflight::Binding::Bound,
            ),
            Some(busbar_kernel::inflight::HardClose::ProviderRefusedForMoney),
            "and that refusal is the one that closes the session"
        );

        // A session that never ran dry is not caught by the mark.
        let other =
            VoiceUnit::new(&node, UnitShape::Turn, 8, 1_700_000_000).charging_through(ungoverned());
        let Ended::Settled { end, .. } = run(&kernel, &other) else {
            panic!("the exit path settles it");
        };
        assert_eq!(end.outcome(), Outcome::Completed);

        // And a NEW session on the same identifier is a new session: it takes its own reservation
        // and is not refused for what the last one spent.
        let reopened = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
        let Ended::Settled { end, .. } = run(&kernel, &reopened) else {
            panic!("the exit path settles it");
        };
        assert_eq!(end.outcome(), Outcome::Completed);
        let turn =
            VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
        let Ended::Settled { end, .. } = run(&kernel, &turn) else {
            panic!("the exit path settles it");
        };
        assert_eq!(end.outcome(), Outcome::Completed);
    }

    /// A refused unit's record says it was refused, and names the step that refused it.
    ///
    /// The record is the only place a refusal survives the connection it happened on, so a chain
    /// that spells every ending "completed" is a chain an operator cannot ask why anything stopped.
    #[test]
    fn a_refused_units_record_carries_the_refusal_and_its_step() {
        let node = node(serviceable());
        let unit =
            VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
        let refused = Outcome::Refused(busbar_caps::StepName::Approve, ReasonCode::ScopeDenied);
        let inputs = unit.audit_inputs(&ctx(1), refused, busbar_contract::FinishClass::Error);
        assert_eq!(inputs.outcome.unit_end, refused);
        assert_eq!(inputs.outcome.step, Some(busbar_caps::StepName::Approve));

        // And a turn that ran is still recorded as one: threading the ending through did not turn
        // every record into a refusal.
        let done = unit.audit_inputs(
            &ctx(1),
            Outcome::Completed,
            busbar_contract::FinishClass::TurnComplete,
        );
        assert_eq!(done.outcome.unit_end, Outcome::Completed);
        assert_eq!(done.outcome.step, None);
    }

    /// The four seams refuse rather than pretend. A node whose I/O half was never installed cannot
    /// dial, cannot pump, cannot lease and has no carrier; saying so at the seam is what keeps
    /// "detached" from being reported as "broken", and keeps neither from being reported as "fine".
    #[test]
    fn the_detached_seams_refuse_honestly() {
        let io = VoiceIo::default();
        assert_eq!(
            io.dial.dial(&DialTarget {
                pool: "voice".into(),
                lane: 0,
                url: "wss://example.invalid".into(),
                policy: GuardPolicy::default(),
            }),
            Err(DialRefusal::Detached)
        );
        assert!(!io.pump.is_pumping(7));
        assert!(io.lease.reserve(7, 1).is_err());
        assert!(!io.lease.settle(7, 1));
        assert!(!io.carrier.available());
    }

    /// The kernel-granted scope a handshake runs under is the transport's, never a policy key. A
    /// deployment cannot revoke it by leaving it out of a table, which is what makes shaking hands
    /// possible before anybody is authenticated.
    #[test]
    fn the_handshake_scope_is_the_kernel_granted_one() {
        assert_eq!(handshake_scope(), "transport:handshake");
    }

    // -----------------------------------------------------------------------------------------
    // The tool calls a session waits on
    // -----------------------------------------------------------------------------------------

    /// The correlation a client's reply carries, as the plane reads it off the bytes.
    fn reply(call_id: &str) -> CorrelationRef<'_> {
        CorrelationRef {
            fact_key: busbar_plane_voice::plane::FACT_TOOL_CORRELATION,
            value: CorrelationValue::Str(call_id),
        }
    }

    /// Run one tool-call unit far enough to plan its leg, which is where the wait is entered.
    fn plan(kernel: &Kernel, node: &VoiceNode, key: u64, call_id: &str, now_ms: Millis) -> Ended {
        plan_on(kernel, node, 7, key, call_id, now_ms)
    }

    /// [`plan`], on a named session — the shape a cell needs when the session identifier is not this
    /// module's to choose because the served door minted it.
    fn plan_on(
        kernel: &Kernel,
        node: &VoiceNode,
        session: u64,
        key: u64,
        call_id: &str,
        now_ms: Millis,
    ) -> Ended {
        let unit = VoiceUnit::new(node, UnitShape::ToolCall, session, 1_700_000_000)
            .charging_through(ungoverned())
            .calling(call_id)
            .at_ms(now_ms);
        let cell = busbar_caps::HoldCell::new(busbar_caps::Hold::open(
            &kernel.admit_token(),
            PrincipalId::new("acct:voice"),
            0,
        ));
        let gauge = ConcurrencyGauge::new();
        let canary = Canary::new();
        let leases = busbar_kernel::slice::LeaseCell::new();
        let meter = AccrualMeter::new();
        run_unit(
            kernel,
            &unit,
            &ctx(key),
            Run {
                cell: &cell,
                parent: None,
                leases: &leases,
                gauge: &gauge,
                canary: &canary,
                meter: &meter,
            },
        )
    }

    /// **Two calls open at once, and each reply wakes only its own.**
    ///
    /// A turn that asks for two tools opens two units. They are identical apart from the identifier
    /// each minted — same key, same selector, same deadline — which is exactly the pair that a wait
    /// on a constant, or on a fold of an identifier, is free to confuse. The replies come back in
    /// the opposite order to the calls, so "whichever is waiting" cannot pass either.
    #[test]
    fn two_tool_calls_on_one_session_each_wake_only_the_call_they_answer() {
        let kernel = Kernel::new();
        let node = node(serviceable());
        let (weather, tide) = (11, 22);
        let _ = plan(&kernel, &node, weather, "call_aaa", 0);
        let _ = plan(&kernel, &node, tide, "call_bbb", 0);
        assert_eq!(node.tool_calls.open(), 2, "two calls are open, not one");

        // The SECOND call answers first.
        assert_eq!(
            node.tool_calls.replied(7, reply("call_bbb")),
            Ok(UnitKey::new(tide)),
            "the reply wakes the call whose identifier it carries"
        );
        assert!(
            node.tool_calls.waiting(7, UnitKey::new(weather)),
            "and leaves the other call waiting on its own identifier, untouched"
        );
        assert_eq!(
            node.tool_calls.replied(7, reply("call_aaa")),
            Ok(UnitKey::new(weather)),
            "which is still there for its own answer"
        );
        assert_eq!(node.tool_calls.open(), 0, "and both calls are settled");
        assert_eq!(
            node.tool_calls.ending(7, UnitKey::new(weather)),
            Some(CallEnd::Answered),
            "each unit reads its own ending, once"
        );
    }

    /// A reply nobody is waiting for is refused, not dropped.
    ///
    /// The temptation the refusal exists to remove is "there is one call open, so this must be for
    /// it". Paying a hold out against an answer that named something else is the failure a
    /// correlation exists to prevent, and it costs a real principal real money.
    #[test]
    fn a_reply_for_a_call_nobody_opened_is_refused_rather_than_dropped() {
        let kernel = Kernel::new();
        let node = node(serviceable());
        let _ = plan(&kernel, &node, 11, "call_aaa", 0);

        assert_eq!(
            node.tool_calls.replied(7, reply("call_zzz")),
            Err(ReplyRefused::UnknownCall),
            "an unmatched reply is not paid out against the only call standing"
        );
        assert_eq!(
            node.tool_calls.replied(9, reply("call_aaa")),
            Err(ReplyRefused::NoSuchSession),
            "and the same identifier on another session is another conversation's business"
        );
        assert!(
            node.tool_calls.waiting(7, UnitKey::new(11)),
            "the open call is untouched by either"
        );
        assert_eq!(
            node.tool_calls.replied(7, reply("call_aaa")),
            Ok(UnitKey::new(11)),
            "and still answers to its own identifier"
        );
    }

    /// **An unanswered call ends at the deadline it declared.**
    ///
    /// The wait is entered with the plane's own thirty seconds; the sweep at thirty-one names it,
    /// and the unit's exit path ends it under the deadline rather than settling as though the answer
    /// had arrived. Before this was wired the wait was entered nowhere at all, so an unanswered call
    /// was a hold nothing ever closed.
    #[test]
    fn an_unanswered_tool_call_ends_at_the_deadline_its_leg_declared() {
        let kernel = Kernel::new();
        let node = node(serviceable());
        let _ = plan(&kernel, &node, 11, "call_aaa", 0);
        let _ = plan(&kernel, &node, 22, "call_bbb", 20_000);

        let deadline = u64::from(busbar_plane_voice::plane::TOOL_REPLY_DEADLINE_SECS) * 1_000;
        assert!(
            node.tool_calls.expired(deadline - 1).is_empty(),
            "a call is not swept one millisecond before its own deadline"
        );
        assert_eq!(
            node.tool_calls.expired(deadline + 1),
            vec![UnansweredCall {
                session: 7,
                unit: UnitKey::new(11)
            }],
            "the first call's deadline is up; the one opened twenty seconds later is not"
        );
        assert_eq!(
            node.tool_calls.open(),
            1,
            "the second call is still waiting"
        );

        // The exit: the unit is resumed and reads what became of its wait.
        let Ended::Settled { end, .. } = plan(&kernel, &node, 11, "call_aaa", deadline + 1) else {
            panic!("the exit path settles an unanswered call like anything else");
        };
        assert!(
            matches!(
                end.outcome(),
                Outcome::Failed(busbar_caps::StepName::Route, ReasonCode::DeadlineExceeded)
            ),
            "got {:?}",
            end.outcome()
        );
    }

    /// A call that minted no identifier is not entered as a wildcard.
    ///
    /// A wait with no identity matches the first reply that arrives, whoever it was for. Refusing
    /// the unit says so where it happens rather than at the first reply that goes to the wrong call.
    #[test]
    fn a_tool_call_that_minted_no_identifier_is_refused_rather_than_entered() {
        let kernel = Kernel::new();
        let node = node(serviceable());
        let unit = VoiceUnit::new(&node, UnitShape::ToolCall, 7, 1_700_000_000)
            .charging_through(ungoverned());
        let Ended::Settled { end, .. } = run(&kernel, &unit) else {
            panic!("the exit settles it");
        };
        assert!(
            matches!(
                end.outcome(),
                Outcome::Refused(_, ReasonCode::NoDestination)
            ),
            "got {:?}",
            end.outcome()
        );
        assert_eq!(node.tool_calls.open(), 0, "and nothing is waiting");
    }

    /// **The port the served path reaches the table through.**
    ///
    /// Every assertion above drives [`OpenToolCalls`] directly, which is the right way to judge the
    /// table but says nothing about whether anything on a socket can get to it. This judges the seam
    /// the session runtime holds: the same three answers — woken, refused, swept — asked in the
    /// spelling `busbar-voice` asks them in. Before this port existed the runtime had no way to ask.
    #[cfg(feature = "plane-voice")]
    #[test]
    fn the_runtimes_port_reaches_the_nodes_own_table() {
        use busbar_voice::runtime::{GovernedCalls, ReplyRefusal};

        let kernel = Kernel::new();
        let node = std::sync::Arc::new(node(serviceable()));
        let _ = plan(&kernel, &node, 11, "call_aaa", 0);
        let _ = plan(&kernel, &node, 22, "call_bbb", 0);
        let port = NodeCalls::new(std::sync::Arc::clone(&node));

        assert_eq!(
            port.replied(9, "call_aaa"),
            Err(ReplyRefusal::NoSuchSession),
            "a reply on a session this node holds nothing for wakes nothing"
        );
        assert_eq!(
            port.replied(7, "call_zzz"),
            Err(ReplyRefusal::UnknownCall),
            "and one naming a call nobody is waiting on is refused, not matched to whichever is open"
        );
        assert_eq!(
            port.replied(7, "call_bbb"),
            Ok(()),
            "the answer wakes its own"
        );
        assert!(
            !node.tool_calls.waiting(7, UnitKey::new(22)),
            "which is the wait leaving the table"
        );
        assert!(
            node.tool_calls.waiting(7, UnitKey::new(11)),
            "and the call it did not answer is still waiting"
        );

        // The tick's sweep, through the same port, at the deadline the plane's own leg declared.
        let deadline = u64::from(busbar_plane_voice::plane::TOOL_REPLY_DEADLINE_SECS) * 1_000;
        assert_eq!(port.expired(deadline - 1), 0, "not one millisecond early");
        assert_eq!(
            port.expired(deadline + 1),
            1,
            "the unanswered call is swept"
        );

        // And what the sweep left behind is what ends the unit — under its own deadline, not as a
        // settlement that pretends the answer arrived.
        let Ended::Settled { end, .. } = plan(&kernel, &node, 11, "call_aaa", deadline + 1) else {
            panic!("the exit path settles an unanswered call like anything else");
        };
        assert!(
            matches!(
                end.outcome(),
                Outcome::Failed(busbar_caps::StepName::Route, ReasonCode::DeadlineExceeded)
            ),
            "got {:?}",
            end.outcome()
        );
    }

    /// **THE ROOT IDENTITY: on the served composition there is no ungoverned session left to reach.**
    ///
    /// Two things are judged here and they are the two halves of one claim.
    ///
    /// The first is that the root composes at all. `mount_root_voice` seals the registry and then
    /// writes this node's open-call table onto the served door; after it has run, the door's own
    /// per-session binding answers with a table rather than with nothing, and it answers with a
    /// fresh identifier each time — which is what a session is told apart by on a node where two
    /// conversations may carry identical call identifiers. Before this the port and its implementor
    /// both existed and no served session had ever been handed one.
    ///
    /// The second is what that binding is worth: a call nobody answers, ended THROUGH the served
    /// path. The tick is the session pump's own `sweep_expired`, the table is this node's, and the
    /// wall is the plane's declared `TOOL_REPLY_DEADLINE_SECS` read rather than restated — not one
    /// millisecond early, and the unit that was waiting exits `Failed(Route, DeadlineExceeded)`
    /// rather than settling as though the answer had arrived.
    #[cfg(all(feature = "root-voice", feature = "plane-voice"))]
    #[test]
    fn the_served_composition_has_no_ungoverned_session_left_in_it() {
        use busbar_voice::runtime::{Carrier, MeteringPort, SessionCore};

        // (1) THE ROOT'S OWN COMPOSITION. First writer wins on the plane's side, so this cell is the
        // one place in the crate that writes it, and it writes it the way `main()` does.
        crate::compose_voice_governed_calls();
        let bound = busbar_voice::mount::served_governed_session()
            .expect("after the root has mounted, every session the door opens is bound to a table");
        let next = busbar_voice::mount::served_governed_session()
            .expect("and so is the next one, on its own identifier");
        assert_ne!(
            bound.session, next.session,
            "two conversations are told apart before either has a call open"
        );
        assert_eq!(
            bound.calls.replied(bound.session, "call_aaa"),
            Err(busbar_voice::runtime::ReplyRefusal::NoSuchSession),
            "the table the door was handed is a real one, holding nothing at boot"
        );

        // (2) WHAT THE BINDING IS WORTH, through a real session pump. The node here is the cell's
        // own, reached through the same port the door was handed, because the node `main()` composed
        // is not a handle this cell holds.
        let kernel = Kernel::new();
        let node = std::sync::Arc::new(node(serviceable()));
        let session = 4_242;
        let _ = plan_on(&kernel, &node, session, 11, "call_aaa", 0);
        assert!(
            node.tool_calls.waiting(session, UnitKey::new(11)),
            "the leg was planned, so the wait is entered"
        );

        let lease = busbar_voice::runtime::LocalMeteringPort
            .reserve(1_000, 0, None)
            .expect("an uncapped lease always opens");
        let core = SessionCore::new(
            busbar_voice::ir::codec::OpenAiRealtimeCodec,
            lease,
            None,
            std::sync::Arc::new(busbar_voice::runtime::EchoToolExecutor),
            Carrier::sideband(),
            None,
        )
        .with_governed(busbar_voice::runtime::GovernedSession {
            session,
            calls: std::sync::Arc::new(NodeCalls::new(std::sync::Arc::clone(&node))),
        });
        assert_eq!(
            core.governed_session(),
            Some(session),
            "the pump knows itself by the identifier the door minted"
        );

        let deadline = u64::from(busbar_plane_voice::plane::TOOL_REPLY_DEADLINE_SECS) * 1_000;
        assert_eq!(
            core.sweep_expired(deadline - 1),
            0,
            "the session's own tick ends nothing one millisecond before the declared deadline"
        );
        assert_eq!(
            core.sweep_expired(deadline),
            1,
            "and ends the unanswered call at it"
        );

        let Ended::Settled { end, .. } = plan_on(
            &kernel,
            &node,
            session,
            11,
            "call_aaa",
            Millis::from(deadline as u32),
        ) else {
            panic!("the exit path settles an unanswered call like anything else");
        };
        assert!(
            matches!(
                end.outcome(),
                Outcome::Failed(busbar_caps::StepName::Route, ReasonCode::DeadlineExceeded)
            ),
            "got {:?}",
            end.outcome()
        );
    }

    /// A conversation that is over cannot answer anything.
    #[test]
    fn a_closed_session_stops_waiting_on_the_calls_it_had_open() {
        let kernel = Kernel::new();
        let node = node(serviceable());
        let _ = plan(&kernel, &node, 11, "call_aaa", 0);
        node.tool_calls.closed(7);
        assert_eq!(node.tool_calls.open(), 0);
        assert_eq!(
            node.tool_calls.replied(7, reply("call_aaa")),
            Err(ReplyRefused::NoSuchSession)
        );
    }

    // -----------------------------------------------------------------------------------------
    // The hold's five acts, on this plane
    // -----------------------------------------------------------------------------------------

    /// A node whose card prices the dialect, so a turn's estimate is a figure rather than a zero.
    fn priced_node(io: VoiceIo) -> VoiceNode {
        let mut node = node(io);
        let mut rates = std::collections::BTreeMap::new();
        rates.insert(
            Dialect::OpenaiRealtime.name().to_string(),
            busbar_unit_admission::RateNanos::from_micros_per_token(2.0, 5.0, 0.0, 0.0),
        );
        node.pricer = Pricer::with_card(0, rates);
        node
    }

    /// A handshake reserves nothing of its own, and takes the SESSION's opening reservation on the
    /// lease. The two are different things and the distinction is the whole design: no money moves
    /// in unit zero, but the conversation it opens is allowed against a figure taken here, because a
    /// live session cannot be metered after the fact.
    #[test]
    fn unit_zero_reserves_nothing_itself_and_takes_the_sessions_opening_reservation() {
        /// A lease that records what it was reserved for.
        struct Recording(std::sync::Mutex<Vec<u64>>);
        impl SessionLease for Recording {
            fn reserve(&self, _session: u64, nanos: u64) -> Result<(), ReasonCode> {
                self.0.lock().expect("lock").push(nanos);
                Ok(())
            }
            fn settle(&self, _session: u64, _nanos: u64) -> bool {
                true
            }
            fn close(&self, _session: u64) {}
        }
        let seen = std::sync::Arc::new(Recording(std::sync::Mutex::new(Vec::new())));
        struct Shared(std::sync::Arc<Recording>);
        impl SessionLease for Shared {
            fn reserve(&self, session: u64, nanos: u64) -> Result<(), ReasonCode> {
                self.0.reserve(session, nanos)
            }
            fn settle(&self, session: u64, nanos: u64) -> bool {
                self.0.settle(session, nanos)
            }
            fn close(&self, session: u64) {
                self.0.close(session);
            }
        }
        let node = priced_node(VoiceIo {
            dial: Box::new(OpenDial),
            lease: Box::new(Shared(std::sync::Arc::clone(&seen))),
            ..VoiceIo::default()
        });
        let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
        assert_eq!(
            unit.estimate(),
            Estimate::zero(),
            "no money moves in unit 0"
        );
        let opening = unit.session_opening_nanos();
        assert!(opening > 0, "a priced dialect names a session budget");

        let _ = run(&Kernel::new(), &unit);
        assert_eq!(
            *seen.0.lock().expect("lock"),
            vec![opening],
            "the lease was taken for the session's opening reservation, once"
        );
    }

    /// The flat fee is the SESSION's, drawn on the unit that opens it, and it is drawn once.
    ///
    /// A turn is a frame of a conversation already paid for, the provider's tool call is not a
    /// caller's request, a session whose leg never opened relayed nothing, and an ending the plane
    /// called an error pays nothing.
    #[test]
    fn the_flat_fee_is_the_session_open_and_nothing_else() {
        use busbar_caps::OriginKind;
        use busbar_contract::FinishClass;
        use busbar_kernel::teller::fee_count;

        let open = |finish| {
            fee_evidence(
                UnitShape::SessionOpen,
                OriginKind::Client,
                true,
                true,
                Some(finish),
            )
        };
        assert_eq!(fee_count(&open(FinishClass::Complete)).0, 1);
        assert_eq!(fee_count(&open(FinishClass::Error)).0, 0);
        // A session that named no upstream, and one whose dial never opened: neither reached a leg,
        // and a fee is for a connection that was actually made.
        assert_eq!(
            fee_count(&fee_evidence(
                UnitShape::SessionOpen,
                OriginKind::Client,
                false,
                true,
                Some(FinishClass::Complete),
            ))
            .0,
            0
        );
        assert_eq!(
            fee_count(&fee_evidence(
                UnitShape::SessionOpen,
                OriginKind::Client,
                true,
                false,
                Some(FinishClass::Complete),
            ))
            .0,
            0
        );
        // A turn of a conversation the session already paid to open pays nothing, however it ended.
        for finish in [FinishClass::TurnComplete, FinishClass::Error] {
            assert_eq!(
                fee_count(&fee_evidence(
                    UnitShape::Turn,
                    OriginKind::Client,
                    true,
                    true,
                    Some(finish),
                ))
                .0,
                0
            );
        }
        // The provider's own push through the session's leg is not a caller's request.
        assert_eq!(
            fee_count(&fee_evidence(
                UnitShape::ToolCall,
                OriginKind::Provider,
                true,
                true,
                Some(FinishClass::TurnComplete),
            ))
            .0,
            0
        );
    }

    /// **THREE TURNS ON ONE SESSION PAY ONE FLAT FEE.**
    ///
    /// The rule the whole finding turns on, measured over the loop rather than over the evidence
    /// function: a conversation is billed one flat fee for the connection that carried it, no matter
    /// how many times the caller speaks. Charged per turn, this session paid three — and a real call
    /// is not three turns, it is hundreds. The hold agrees: the fee is reserved once, on the
    /// session's opening reservation, and no turn's estimate reserves one.
    #[test]
    fn a_three_turn_session_pays_one_flat_fee() {
        let kernel = Kernel::new();
        let node = priced_node(VoiceIo {
            dial: Box::new(OpenDial),
            lease: Box::new(OpenLease),
            ..VoiceIo::default()
        });

        let opening = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
        let Ended::Settled {
            fee: opening_fee, ..
        } = run(&kernel, &opening)
        else {
            panic!("the exit path settles the open");
        };
        assert_eq!(opening_fee, 1, "the session's one flat fee, at the open");

        let mut turn_fees = 0;
        for _ in 0..3 {
            let turn = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
                .charging_through(ungoverned())
                .reporting(TurnUsage {
                    audio_tokens_out: 30,
                    audio_ms_in: 400,
                    ..TurnUsage::default()
                });
            let Ended::Settled { fee, end, .. } = run(&kernel, &turn) else {
                panic!("the exit path settles a turn");
            };
            assert_eq!(end.outcome(), Outcome::Completed, "the turn was served");
            turn_fees += fee;
        }
        assert_eq!(
            opening_fee + turn_fees,
            1,
            "one session, one flat fee, however many turns rode it"
        );

        // And the reservation side says the same. The turn's estimate reserves no fee; the session's
        // opening figure carries the one there is.
        let turn = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000);
        assert_eq!(turn.estimate().fee_nanos, 0, "no turn reserves a fee");
        let mut fee_bearing = priced_node(serviceable());
        fee_bearing.pricer = Pricer::flat(25);
        let open = VoiceUnit::new(&fee_bearing, UnitShape::SessionOpen, 7, 1_700_000_000);
        assert_eq!(
            open.session_fee_nanos(),
            25 * NANOS_PER_CENT,
            "the card's per-request fee, in nano-units"
        );
        assert!(
            open.session_opening_nanos() >= open.session_fee_nanos(),
            "and the session's opening reservation is what carries it"
        );
    }

    /// A TURN THAT SPOKE ONLY IN TEXT BILLS ITS TEXT.
    ///
    /// The exit's located figure is the whole report and not one class of it. A turn that emitted no
    /// audio at all is an ordinary shape of turn on this plane — a transcript-only exchange, a
    /// tool-driven turn, a dialect answering in text — and reading only the emitted-audio class made
    /// every one of them settle a completed turn at nothing while the session's lease had already
    /// been drawn down by the same report in full. The lease and the posting read ONE number here.
    #[test]
    fn a_text_only_turn_settles_the_text_it_metered() {
        use busbar_kernel::teller::settle_amount;

        let node = priced_node(serviceable());
        let usage = TurnUsage {
            text_tokens_in: 40,
            text_tokens_out: 60,
            ..TurnUsage::default()
        };
        let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
            .charging_through(ungoverned())
            .reporting(usage);
        let evidence = unit.evidence(&ctx(1));
        assert_eq!(
            evidence.located,
            Some(100),
            "the located figure is every class the turn metered"
        );
        assert_eq!(
            settle_amount(&Outcome::Completed, &evidence).0,
            usage.total(),
            "a completed turn posts what it metered, not what it drew the lease at"
        );
    }

    /// A PAID TURN'S RECORD NAMES THE PRINCIPAL IT CHARGED, and a refusal before anyone was named
    /// still names an arrival.
    ///
    /// The subject is what makes a row belong to an account. Written as `Arrival` on every unit, the
    /// chain carried a full set of settled turns that no account could be shown, no revocation could
    /// be traced through and no dispute could be answered from. The principal is the auth chain's,
    /// recorded at the first step the loop hands it over on, and read back here.
    #[test]
    fn a_paid_turns_record_names_its_principal() {
        use busbar_unit_audit::record::Subject;

        let node = priced_node(serviceable());
        let kernel = Kernel::new();
        let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
            .charging_through(ungoverned())
            .reporting(TurnUsage {
                audio_tokens_out: 12,
                ..TurnUsage::default()
            });
        let _ = run(&kernel, &unit);
        let inputs = unit.audit_inputs(
            &ctx(1),
            Outcome::Completed,
            busbar_contract::FinishClass::TurnComplete,
        );
        assert!(
            matches!(inputs.subject, Subject::PrincipalId(ref who) if !who.is_empty()),
            "a turn that was authenticated names who it was for"
        );

        // And the unit that never reached verify — a refusal before any principal existed — is an
        // arrival, which is the one thing `Arrival` is the honest answer to.
        let unseen = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000);
        let refused = unseen.audit_inputs(
            &ctx(1),
            Outcome::Refused(busbar_caps::StepName::Decode, ReasonCode::DecodeFailed),
            busbar_contract::FinishClass::Error,
        );
        assert!(matches!(refused.subject, Subject::Arrival));
    }

    /// THE KERNEL'S OWN FLOOR IS THE AUDIO THAT CAME IN, IN THE UNIT ITS CLASS IS DENOMINATED IN.
    ///
    /// The floor is what the one settlement row that reads it posts, so its unit and its label are
    /// money. It counts uplink milliseconds and the class the plane declares for uplink audio is in
    /// seconds: reported verbatim it is a thousand times the duration, and reported under the
    /// emitted-audio token class it is a duration priced at a token rate, in the wrong direction.
    #[test]
    fn the_floor_is_inbound_audio_in_the_declared_classs_own_unit() {
        use busbar_kernel::teller::settle_amount;

        let node = priced_node(serviceable());
        let kernel = Kernel::new();
        // Two and a half seconds of uplink audio, and no report from the upstream at all: the shape
        // that reaches the floor row.
        let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
            .charging_through(ungoverned())
            .reporting(TurnUsage {
                audio_ms_in: 2_500,
                ..TurnUsage::default()
            });
        let _ = run(&kernel, &unit);
        let evidence = unit.evidence(&ctx(1));
        assert_eq!(
            evidence.accrued_floor, 3,
            "2_500 ms is three seconds of billable audio, not 2_500 of anything"
        );
        let class = evidence.class.expect("the plane still declares the class");
        assert_ne!(
            class,
            meta::CLASS_AUDIO_TOKENS_OUT,
            "what the kernel counted is not the audio the turn emitted"
        );
        assert!(
            <VoicePlane as busbar_contract::plane::PlaneMeta>::METER_CLASSES
                .iter()
                .any(|decl| decl.key == class
                    && decl.direction == busbar_contract::ids::ClassDirection::Input),
            "and the class it is counted under is one the plane declares, on the inbound side"
        );
        // The floor row: a live end that is not a completion with nothing located posts the floor.
        let end = Outcome::Refused(busbar_caps::StepName::Route, ReasonCode::DeadlineExceeded);
        let floor_only = Evidence {
            located: None,
            ..evidence
        };
        assert_eq!(settle_amount(&end, &floor_only).0, 3);
    }

    /// A STREAM THAT ENDED ON AN ERROR BILLS NOTHING, even with a figure located.
    ///
    /// The settlement table has a row for exactly this — a live end that is not a completion, with
    /// something located, whose stream carried an error signal — and it posts zero. Reaching that
    /// row takes the plane saying the stream errored, and this file used to say the opposite
    /// unconditionally: every dropped session, every upstream failure, every refused frame settled
    /// in full for audio the caller never got the end of. The ending is the one the audit step
    /// already sealed, so the record and the posting cannot tell two stories about one turn.
    #[test]
    fn an_errored_turn_bills_nothing_though_it_located_a_figure() {
        use busbar_kernel::teller::settle_amount;

        let node = priced_node(serviceable());
        let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
            .charging_through(ungoverned())
            .reporting(TurnUsage {
                audio_tokens_out: 120,
                ..TurnUsage::default()
            });
        let seal = busbar_caps::KernelSeal::acquire_for_kernel();
        let token: UnitToken<Audit> = UnitToken::mint(&seal);
        let refusal = Refusal::new(ReasonCode::DeadlineExceeded);
        let _ = unit.audit_refused(&token, &ctx(1), &refusal);

        let evidence = unit.evidence(&ctx(1));
        assert!(
            evidence.terminal_error,
            "the plane sealed an error ending and the evidence says so"
        );
        assert_eq!(evidence.located, Some(120), "the figure is still located");
        let end = Outcome::Refused(busbar_caps::StepName::Route, ReasonCode::DeadlineExceeded);
        assert_eq!(
            settle_amount(&end, &evidence).0,
            0,
            "and an errored stream posts nothing against it"
        );

        // And the completing turn beside it is untouched: the derivation only ever reads what the
        // plane sealed, so a turn that finished cleanly still settles what it metered.
        let clean = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
            .charging_through(ungoverned())
            .reporting(TurnUsage {
                audio_tokens_out: 120,
                ..TurnUsage::default()
            });
        let _ = clean.audit(&token, &ctx(1), &Outcome::Completed);
        assert!(!clean.evidence(&ctx(1)).terminal_error);
    }

    /// A turn that reported no output relayed no answer; one that emitted tokens did.
    #[test]
    fn an_answered_turn_is_one_that_emitted_something() {
        let node = priced_node(serviceable());
        let silent = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
            .charging_through(ungoverned())
            .reporting(TurnUsage {
                audio_tokens_in: 90,
                ..TurnUsage::default()
            });
        assert!(!silent.answered());
        let spoken = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
            .charging_through(ungoverned())
            .reporting(TurnUsage {
                audio_tokens_out: 3,
                ..TurnUsage::default()
            });
        assert!(spoken.answered());
    }

    /// A turn's reservation is the coarse opening magnitude at the dearest price the dialect's
    /// classes charge, and the door is what opens it. Over-sized on purpose: the residual comes
    /// straight back at settlement.
    #[test]
    fn a_turn_opens_a_reservation_the_door_sized_off_the_estimate() {
        let node = priced_node(serviceable());
        let unit =
            VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
        // 5 micro-units per output token is 5_000 nano-units, and it is the dearest of the four.
        let estimate = unit.estimate();
        assert_eq!(estimate.per_class.len(), 1);
        assert_eq!(estimate.per_class[0].max_unit_price_nanos, 5_000);
        assert_eq!(
            estimate.hold_nanos(busbar_unit_admission::STANDARD_TIER_BP),
            TURN_OPENING_TOKENS * 5_000
        );

        let seal = busbar_caps::KernelSeal::acquire_for_kernel();
        let admit = busbar_caps::AdmitToken::<Admit>::mint(&seal);
        let token: UnitToken<Admit> = UnitToken::mint(&seal);
        let admission = unit
            .admit(
                &token,
                &admit,
                &ctx(1),
                &PrincipalId::new("acct:voice"),
                &[],
                &GroupLeaseSlip::new(),
            )
            .into_result(&seal)
            .expect("the empty chain admits");
        match admission {
            busbar_caps::Admission::Own(hold) => {
                assert_eq!(hold.reserved(), TURN_OPENING_TOKENS * 5_000);
                assert_eq!(hold.accrued(), 0, "a reservation is not a spend");
                let _ = busbar_caps::Posted::settle(
                    hold,
                    0,
                    &busbar_caps::Usage::report(&busbar_caps::UsageToken::mint(&seal), Vec::new())
                        .expect("empty"),
                    &busbar_caps::LedgerToken::mint(&seal),
                );
            }
            other => panic!("a priced turn opens a hold of its own, got {other:?}"),
        }
    }

    /// THE DOOR'S COUNT LEAVES THE DOOR'S STEP, or this plane's `concurrent` caps are decoration.
    ///
    /// A yes raises a gauge per capped group in the chain and the value it hands back is what holds
    /// them up. Dropped where the decision was taken, the gauges are back to where they started
    /// before the admitted unit has run a single step, and the next arrival is judged against a
    /// count of nothing however many units are in flight. So the step has to hand the count over,
    /// and the slip is where. The kernel does the rest: it belongs to the unit's slot from here,
    /// and it goes back at whichever of the unit's two ends arrives first.
    ///
    /// The chain this deployment hands the door declares no capped group, so the count here is of
    /// none — which is exactly why the assertion is about the HANDOVER and not about a number. A
    /// step that keeps the grant caps nothing on any chain; a step that hands it over caps every
    /// group the chain names.
    #[test]
    fn the_door_step_hands_its_count_to_the_slot_rather_than_dropping_it() {
        let node = priced_node(serviceable());
        let unit =
            VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
        let seal = busbar_caps::KernelSeal::acquire_for_kernel();
        let admit = busbar_caps::AdmitToken::<Admit>::mint(&seal);
        let token: UnitToken<Admit> = UnitToken::mint(&seal);
        let leases = GroupLeaseSlip::new();

        let admission = unit
            .admit(
                &token,
                &admit,
                &ctx(1),
                &PrincipalId::new("acct:voice"),
                &[],
                &leases,
            )
            .into_result(&seal)
            .expect("the chain admits");
        assert!(
            leases.grant_taken().is_some(),
            "the door's own count came out of the step, where the loop can put it on the slot"
        );
        if let busbar_caps::Admission::Own(hold) = admission {
            let _ = busbar_caps::Posted::settle(
                hold,
                0,
                &busbar_caps::Usage::report(&busbar_caps::UsageToken::mint(&seal), Vec::new())
                    .expect("empty"),
                &busbar_caps::LedgerToken::mint(&seal),
            );
        }
    }

    /// A refusal hands over nothing, because a refusal counted nothing.
    ///
    /// The other half of the rule, and the one that keeps the handover from becoming a leak: the
    /// grant only exists on a yes, so a slip that carried one out of a refusal would be a count on
    /// a group for a unit that never ran. The handshake is this plane's admission that never
    /// reaches the chain at all.
    #[test]
    fn an_admission_that_never_reaches_the_chain_hands_over_no_count() {
        let node = priced_node(serviceable());
        let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
        let seal = busbar_caps::KernelSeal::acquire_for_kernel();
        let admit = busbar_caps::AdmitToken::<Admit>::mint(&seal);
        let token: UnitToken<Admit> = UnitToken::mint(&seal);
        let leases = GroupLeaseSlip::new();

        let _ = unit
            .admit(
                &token,
                &admit,
                &ctx(1),
                &PrincipalId::new("acct:voice"),
                &[],
                &leases,
            )
            .into_result(&seal)
            .expect("a handshake is admitted holding nothing");
        assert!(
            leases.grant_taken().is_none(),
            "the handshake never asked the door, so there is no count to hold"
        );
    }

    /// **The lifecycle, end to end.** The door opens the reservation, the meter accrues against it,
    /// the exit path settles it, and the posting moves this plane's balance and lands on the
    /// journal. Before the exit arm was bound, the last two of those four happened nowhere.
    #[test]
    fn a_turn_opens_accrues_settles_and_lands_on_the_journal() {
        let node = priced_node(serviceable());
        let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
            .charging_through(ungoverned())
            .reporting(TurnUsage {
                audio_tokens_out: 120,
                audio_ms_in: 900,
                ..TurnUsage::default()
            });
        let seal = busbar_caps::KernelSeal::acquire_for_kernel();
        let kernel = Kernel::new();
        let Ended::Settled { end, .. } = run(&kernel, &unit) else {
            panic!("the exit path settles it");
        };
        let posted = end.into_posted().expect("the usage report fits the record");
        assert_eq!(
            posted.reserved(),
            TURN_OPENING_TOKENS * 5_000,
            "what the door reserved"
        );
        // What the settlement table posts is the WHOLE report — every class the turn metered, which
        // here is 120 emitted audio tokens and the one second of audio the turn took in — not what
        // the kernel's meter counted; the accrual is the floor beside it, and the hold carries both.
        assert_eq!(posted.settled(), 121, "what the turn metered");
        assert_eq!(posted.overdraft(), 0, "well inside the reservation");
        assert_eq!(
            posted.released(),
            TURN_OPENING_TOKENS * 5_000 - 121,
            "and the residual the settlement hands back"
        );

        let who = PrincipalId::new("acct:voice");
        let settled = unit
            .settle(&who, posted, &busbar_caps::DurabilityToken::mint(&seal))
            .expect("the memory-buffered journal takes it");
        assert_eq!(
            settled.settlement.released,
            i128::from(TURN_OPENING_TOKENS * 5_000 - 121)
        );
        assert!(settled.overdraft.is_none());

        let durability = node.durability.lock().expect("lock");
        let key = VoiceUnit::balance(&who);
        let window = busbar_unit_admission::budget_window(
            busbar_unit_admission::window::WINDOW_DAY,
            1_700_000_000,
        );
        assert_eq!(durability.ledger.book().get(&key, window).settled, 121);
        let replayed = durability
            .journal
            .replay()
            .expect("reads back")
            .expect("verifies");
        assert_eq!(
            replayed.len(),
            1,
            "one posting, one record — and no overdraft record beside it"
        );
    }

    /// A turn that outruns the coarse estimate tops the reservation up out of the headroom its own
    /// leg offered while it ran, rather than carrying the excess. The overdraft is the last resort,
    /// not the ordinary answer to a guess that was low.
    #[test]
    fn a_turn_past_its_estimate_grows_the_reservation_out_of_the_offered_headroom() {
        let node = priced_node(serviceable());
        let reserved = TURN_OPENING_TOKENS * 5_000;
        let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
            .charging_through(ungoverned())
            .reporting(TurnUsage {
                audio_tokens_out: 3,
                // Far past what the door sized for, and the chain this node runs caps nothing.
                audio_ms_in: reserved + 12_345,
                ..TurnUsage::default()
            });
        assert_eq!(
            unit.headroom_nanos(),
            u64::MAX,
            "an unconfigured chain caps no spend, so there is no ceiling to grow into"
        );
        let Ended::Settled { end, .. } = run(&Kernel::new(), &unit) else {
            panic!("the exit path settles it");
        };
        let posted = end.into_posted().expect("the report fits the record");
        assert_eq!(
            posted.reserved(),
            reserved + 12_345,
            "the reservation grew to cover the spend"
        );
        assert_eq!(posted.overdraft(), 0, "so nothing had to be carried");
        assert!(!posted
            .flags()
            .contains(busbar_caps::PostingFlags::OVERDRAFT));
    }

    /// The other end of the same lifecycle: a turn that ran far past what the door sized for it.
    /// It is not refused, it is not trimmed, and what nothing backed becomes a record of its own.
    #[test]
    fn a_turn_that_outruns_its_reservation_posts_in_full_and_carries_the_rest() {
        let node = priced_node(serviceable());
        let who = PrincipalId::new("acct:voice");
        let seal = busbar_caps::KernelSeal::acquire_for_kernel();

        // The hold the door would have opened, and a spend far past it with an empty slice behind.
        let reserved = TURN_OPENING_TOKENS * 5_000;
        let mut hold = busbar_caps::Hold::open(
            &busbar_caps::AdmitToken::<Admit>::mint(&seal),
            who.clone(),
            reserved,
        );
        let spend = hold.spend(reserved + 7_000, 0);
        assert_eq!(
            spend.accrued,
            reserved + 7_000,
            "the spend is never trimmed"
        );
        assert_eq!(spend.overdraft, 7_000);

        let usage = busbar_caps::Usage::report(
            &busbar_caps::UsageToken::mint(&seal),
            vec![UsageLine {
                class: MeterClassId::new("audio_tokens_out"),
                quantity: reserved + 7_000,
                source: QuantitySource::Count,
                estimated: false,
            }],
        )
        .expect("one line");
        let posted = busbar_caps::Posted::settle(
            hold,
            u128::from(reserved + 7_000),
            &usage,
            &busbar_caps::LedgerToken::mint(&seal),
        );
        assert!(posted
            .flags()
            .contains(busbar_caps::PostingFlags::OVERDRAFT));

        let unit =
            VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
        let settled = unit
            .settle(&who, posted, &busbar_caps::DurabilityToken::mint(&seal))
            .expect("the journal takes both records");
        let note = settled
            .settlement
            .overdraft
            .as_ref()
            .expect("the ledger noted the carry");
        assert_eq!(note.principal, "acct:voice");
        assert_eq!(note.amount, 7_000);

        let durability = node.durability.lock().expect("lock");
        let window = busbar_unit_admission::budget_window(
            busbar_unit_admission::window::WINDOW_DAY,
            1_700_000_000,
        );
        let figures = durability
            .ledger
            .book()
            .get(&VoiceUnit::balance(&who), window);
        assert_eq!(figures.settled, i128::from(reserved + 7_000));
        assert_eq!(figures.overdraft_carried_out, 7_000);
        let replayed = durability
            .journal
            .replay()
            .expect("reads back")
            .expect("verifies");
        assert_eq!(replayed.len(), 2, "the posting, then the carry");
    }

    // ── the decode step's own scaffolding ──────────────────────────────────────────────────────
    //
    // The production half of this file names no wire shape and no dialect, and it stays that way.
    // But the decode step's whole content is the plane's reading of a frame, so a cell that drove
    // it from a shape this module chose would be asserting its own answer. These build the four
    // borrowed views and the one resource a plugin call is given, so the plane's own decoder can be
    // handed a real frame.

    /// A leaking arena. Test-only, run a bounded number of times per process: the trait's
    /// allocators hand back borrowed slices, so an honest double either leaks or is unsafe.
    struct CellArena;

    impl busbar_contract::bounded::Arena for CellArena {
        fn alloc_bytes<'a>(
            &'a self,
            src: &[u8],
        ) -> Result<busbar_contract::bounded::ArenaBytes<'a>, busbar_contract::bounded::ArenaBudget>
        {
            let leaked: &'static [u8] = Box::leak(src.to_vec().into_boxed_slice());
            Ok(busbar_contract::bounded::ArenaBytes::new(leaked))
        }

        fn alloc_str<'a>(
            &'a self,
            src: &str,
        ) -> Result<&'a str, busbar_contract::bounded::ArenaBudget> {
            Ok(Box::leak(src.to_string().into_boxed_str()))
        }

        fn alloc_spans<'a>(
            &'a self,
            src: &[(&'a str, busbar_contract::bounded::Span)],
        ) -> Result<
            &'a [(&'a str, busbar_contract::bounded::Span)],
            busbar_contract::bounded::ArenaBudget,
        > {
            Ok(Box::leak(src.to_vec().into_boxed_slice()))
        }

        fn remaining(&self) -> usize {
            usize::MAX
        }
    }

    struct CellConfig;

    impl busbar_contract::unit::ConfigView for CellConfig {
        fn get_str(&self, _key: &str) -> Option<&str> {
            None
        }
        fn get_int(&self, _key: &str) -> Option<i64> {
            None
        }
        fn get_bool(&self, _key: &str) -> Option<bool> {
            None
        }
    }

    /// The socket surface, composed the way a voice session arrives on it.
    struct CellTransport;

    impl busbar_contract::unit::TransportView for CellTransport {
        fn key(&self) -> &'static str {
            "ws"
        }
        fn chain(&self) -> &[&'static str] {
            &["tcp", "tls", "http", "ws"]
        }
        fn fact(&self, _key: &str) -> Option<&str> {
            None
        }
    }

    /// One inbound frame carrying `body`.
    fn one_frame(body: &str) -> Vec<busbar_contract::wire::Frame> {
        vec![busbar_contract::wire::Frame {
            direction: busbar_contract::wire::Direction::Inbound,
            stream: busbar_contract::ids::StreamId(0),
            bytes: busbar_contract::bounded::SlabBytes::new(std::sync::Arc::from(body.as_bytes())),
            meta: busbar_contract::wire::FrameMeta::default(),
        }]
    }

    /// A client event on an open session resolves to a turn or to a frame of the turn already open,
    /// and a carrier frame this session's dialect cannot read resolves to neither.
    ///
    /// The decode step of this plane carries a shape the pump already read, so the question the step
    /// answers is not "what are these bytes" — it is whether the class the loop goes on to price and
    /// audit under is the class the plane's own reader produced. Three answers are driven.
    ///
    /// A first client event OPENS a turn: any client event does, not audio specifically, because a
    /// session's first frame is routinely `session.update` and there is no reason to hold a session
    /// without a unit to carry its facts and size its hold. A second event on the same session does
    /// NOT open a second one — it relays onto the turn's own correlation, which is what "one open
    /// unit per direction" means, and a tool result is exactly that kind of frame. And a frame the
    /// session's dialect cannot read is refused at the step that read it, rather than opening a unit
    /// under a class nobody decoded.
    #[test]
    fn a_client_event_opens_a_turn_and_a_later_one_relays_onto_it() {
        use busbar_caps::KernelSeal;
        use busbar_contract::bounded::Labels;
        use busbar_contract::plane::{Ingress, Plane, PlaneSessionState};
        use busbar_contract::unit::{Clock, Ctx};
        use busbar_contract::wire::FrameCursor;
        use busbar_plane_voice::session::VoiceSessionState;

        let seal = KernelSeal::acquire_for_kernel();
        let arena = CellArena;
        let config = CellConfig;
        let transport = CellTransport;
        let labels = Labels::new();
        let clock = Clock {
            unix_secs: 1_700_000_000,
            monotonic_nanos: 0,
        };
        let plane = VoicePlane::new(UPSTREAMS);
        let mut state =
            PlaneSessionState::new(VoiceSessionState::for_dialect(Dialect::OpenaiRealtime));

        // The first client event of the session. `session.update` is what a real client sends
        // first, and it opens the turn.
        let frames = one_frame(r#"{"type":"session.update","session":{}}"#);
        let mut cursor = FrameCursor::new(&frames);
        let pctx = Ctx::new(clock, &config, None, &transport, &labels, &arena);
        let ingress = plane
            .decode_ingress(&mut cursor, Some(&mut state), &pctx)
            .expect("a client event this dialect names is readable");
        let Ingress::Open(draft) = ingress else {
            panic!("the first client event opens a turn, got {ingress:?}");
        };
        let opened = draft.op;
        let correlation = draft
            .correlation_out
            .expect("an opened turn mints the correlation its frames relay under");

        // The class the plane produced is the class the step carries. Not "a" turn class — THE one,
        // read off the plane's answer rather than restated, so a shape that drifted from the plane's
        // own vocabulary goes red here instead of pricing under a name nothing declares.
        let node = node(serviceable());
        let unit =
            VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
        assert_eq!(
            unit.decode(&UnitToken::mint(&seal), &ctx(1))
                .into_result(&seal)
                .expect("a turn proceeds"),
            opened
        );
        // And it is a class this plane DECLARES. A step carrying a class outside the declared set
        // would be a unit the audit record and the rate card have no row for.
        for shape in [UnitShape::SessionOpen, UnitShape::Turn, UnitShape::ToolCall] {
            assert!(
                <VoicePlane as busbar_contract::plane::PlaneMeta>::OP_CLASSES
                    .contains(&shape.op_class()),
                "{shape:?} carries a class this plane never declared"
            );
        }

        // A tool result on the same session. It is a client event that relays rather than opening
        // a second unit, and it names the CALL it answers, not the turn it rode in on: two calls
        // open on one session at one moment are told apart by that identifier alone.
        let frames = one_frame(
            r#"{"type":"conversation.item.create","item":{"type":"function_call_output","call_id":"c-1","output":"42"}}"#,
        );
        let mut cursor = FrameCursor::new(&frames);
        let pctx = Ctx::new(clock, &config, None, &transport, &labels, &arena);
        let ingress = plane
            .decode_ingress(&mut cursor, Some(&mut state), &pctx)
            .expect("a tool result is a client event this dialect names");
        let Ingress::Frame { for_, .. } = ingress else {
            panic!("a later client event relays, got {ingress:?}");
        };
        assert_eq!(
            for_,
            Some(CorrelationRef {
                fact_key: busbar_plane_voice::plane::FACT_TOOL_CORRELATION,
                value: CorrelationValue::Str("c-1"),
            })
        );
        let _ = correlation;

        // A session bound to the telephony carrier, handed bytes that are not that carrier's shape.
        // The refusal is raised at the step that read them, and no unit exists to have been given a
        // class.
        let mut telephony =
            PlaneSessionState::new(VoiceSessionState::for_dialect(Dialect::TwilioMediaStreams));
        let frames = one_frame("not a carrier frame at all");
        let mut cursor = FrameCursor::new(&frames);
        let pctx = Ctx::new(clock, &config, None, &transport, &labels, &arena);
        assert_eq!(
            plane.decode_ingress(&mut cursor, Some(&mut telephony), &pctx),
            Err(busbar_contract::wire::Decode::Malformed)
        );
    }
    /// A credential is resolved through the node's own signed-key seam, and the audience is this
    /// plane's own name.
    ///
    /// Three answers on one session, because the third is the one an open front door hides. A good
    /// credential resolves to the key's identity. A credential the directory does not hold resolves
    /// to nothing and the unit is refused before it can reach a destination. And a credential that
    /// IS valid — genuinely minted, genuinely unexpired — but was minted for another plane's
    /// audience is refused HERE, at this plane's ingress, rather than at the upstream it was going
    /// to reach: an audience that is declared and never checked is not an audience.
    #[test]
    fn a_credential_is_resolved_against_this_planes_own_audience() {
        use crate::root::kernel::auth_bindings::{AuthBindings, KeyFacts, VirtualKeyDirectory};
        use busbar_caps::{Authenticated, KernelSeal};

        /// One key, minted for one audience.
        struct Directory;

        impl VirtualKeyDirectory for Directory {
            fn verify(
                &self,
                credential: &str,
                _now: u64,
                expected_aud: Option<&str>,
            ) -> Option<KeyFacts> {
                // The audience is the plane boundary and the verifier is where it is enforced. Both
                // credentials below are real keys; only one of them was minted for this plane.
                let minted_for = match credential {
                    "voice-tok" => "voice",
                    "mcp-tok" => "mcp",
                    _ => return None,
                };
                (expected_aud == Some(minted_for)).then(|| KeyFacts {
                    id: "key-voice-1".to_string(),
                    name: "an approved key".to_string(),
                })
            }

            fn revoked(&self, _credential: &str) -> bool {
                false
            }
        }

        // A closed chain naming the signed-key arm and no boxed module, so the arm is the only
        // thing that can open the door and this cell is about that arm.
        let durability = crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_unit_wal::NullShipper::new()),
            Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open");
        let node = VoiceNode::new(VoiceNodeParts {
            plane: VoicePlane::new(UPSTREAMS),
            groups: crate::root::policy::group_table(
                &std::collections::BTreeMap::new(),
                &std::collections::BTreeMap::new(),
            ),
            pricer: Pricer::flat(0),
            auth: Auth::new(AuthChain::new(Vec::new(), true)),
            auth_bindings: AuthBindings::new(std::sync::Arc::new(Directory)),
            scope: scope_policy(),
            meter_policy: crate::root::policy::build(
                &crate::root::policy::MeterPolicyConfig::default(),
            ),
            durability,
            io: serviceable(),
            origin: Kernel::new().origin(busbar_caps::OriginKind::Client),
        });

        let seal = KernelSeal::acquire_for_kernel();
        let answer = |credential: Option<&str>| {
            let mut unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
            if let Some(credential) = credential {
                unit = unit.with_credential(credential);
            }
            unit.authenticate(&UnitToken::mint(&seal), &ctx(1))
                .into_result(&seal)
        };

        // Minted for this plane: admitted, carrying the key's own id, which is what the audit row
        // and the settlement are attributed to.
        match answer(Some("voice-tok")) {
            Ok(Authenticated::Principal(who)) => assert_eq!(who.as_str(), "key-voice-1"),
            other => panic!("a key minted for this plane opens the session: {other:?}"),
        }

        // A credential the directory does not hold, and no credential at all. The chain is closed,
        // so neither is the anonymous principal — both are refusals, and both are raised before the
        // unit reaches a destination.
        for absent in [Some("forged"), None] {
            let refusal = answer(absent)
                .err()
                .unwrap_or_else(|| panic!("{absent:?} must not open a session"));
            assert_eq!(refusal.reason(), ReasonCode::Unauthenticated);
            assert_eq!(refusal.step(), Some(busbar_caps::StepName::Authenticate));
        }

        // The one that matters: a real key, for the wrong plane. Refused here rather than carried
        // to an upstream that would have honoured it.
        let refusal =
            answer(Some("mcp-tok")).expect_err("another plane's audience does not open this one");
        assert_eq!(refusal.reason(), ReasonCode::Unauthenticated);
    }

    // ─────────────────────────────────────────────────────────────────────
    // The configured group reaches the door
    // ─────────────────────────────────────────────────────────────────────

    /// One group, one turn at a time — the smallest cap an operator can write.
    fn one_turn_at_a_time(group: &str) -> busbar_unit_admission::GroupTable {
        let groups = std::collections::BTreeMap::from([(
            group.to_string(),
            busbar_substrate::config::groups::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![busbar_substrate::config::groups::LimitCfg {
                    metric: busbar_substrate::config::groups::LimitMetric::Concurrent,
                    amount: 1,
                    per: None,
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                }],
                child_default: None,
            },
        )]);
        // Through the interner the root uses at boot, so the name the slot records is the same
        // static the vocabulary holds rather than one this fixture invented.
        let mut vocabulary = crate::root::vocabulary::Vocabulary::new();
        let ids = vocabulary.group_ids(&crate::root::vocabulary::ConfigKeys {
            groups: vec![group.to_string()],
            ..crate::root::vocabulary::ConfigKeys::default()
        });
        crate::root::policy::group_table(&groups, &ids)
    }

    /// Ask the door for one turn, keeping what its yes counted.
    fn ask_the_door(
        kernel: &Kernel,
        unit: &VoiceUnit<'_>,
        who: &PrincipalId,
    ) -> (Result<Admission, busbar_caps::Refusal>, GroupLeaseSlip) {
        let slip = GroupLeaseSlip::new();
        let decision = Units::admit(
            unit,
            &busbar_caps::UnitToken::mint(&busbar_caps::KernelSeal::acquire_for_kernel()),
            &kernel.admit_token(),
            &ctx(1),
            who,
            &[],
            &slip,
        );
        (
            decision.into_result(&busbar_caps::KernelSeal::acquire_for_kernel()),
            slip,
        )
    }

    /// **The cap is a cap.** A deployment that wrote `concurrent: 1` against a voice group gets one
    /// turn in the air at a time: the second is refused while the first is still running, and it is
    /// admitted once the first has ended.
    ///
    /// This is the whole point of the chain being the configured one. With an empty chain the door
    /// walks no group, raises no gauge and says yes to both — which is what a node whose operator
    /// wrote this cap down did, silently, with nothing on any surface to say the limit was inert.
    #[test]
    fn a_voice_group_capped_at_one_turn_refuses_the_second_and_admits_it_after_the_first_ends() {
        const GROUP: &str = "voice-team";
        let node = node_governed_by(serviceable(), one_turn_at_a_time(GROUP));
        let kernel = Kernel::new();
        let who = PrincipalId::new("acct:voice");
        // Resolved once, at the open. Every turn below is lent this one value.
        let chain = node.chain_for(&who, Some(GROUP)).expect("configured");
        let turn =
            || VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(&chain);

        let first = turn();
        let (admitted, held) = ask_the_door(&kernel, &first, &who);
        assert!(admitted.is_ok(), "the first turn of a group capped at one");
        assert_eq!(
            held.taken().len(),
            1,
            "and the yes names the one capped group it counted"
        );
        // The count itself, taken onto the slot as the loop takes it. Held for as long as the unit
        // it admitted is running, which is what makes the next line a refusal rather than a second
        // yes.
        let running = held.grant_taken().expect("the yes is holding a count");

        let second = turn();
        let (refused, _) = ask_the_door(&kernel, &second, &who);
        let refusal = refused.expect_err("the group is full");
        assert_eq!(
            refusal.reason(),
            ReasonCode::RateLimited,
            "an in-flight gauge is a count cap, not a spend cap"
        );

        // The unit ends: the slot gives back what it held, and the group has room again.
        drop(running);
        let third = turn();
        let (after, _) = ask_the_door(&kernel, &third, &who);
        assert!(
            after.is_ok(),
            "the cap is instantaneous — it gates what is running, never what has run"
        );
    }

    /// A caller bound to a group this node's configuration does not have is refused, not admitted
    /// under caps that could not be read. Fail-closed, and rendered as over-quota, which is what the
    /// door itself answers for the same cause.
    #[test]
    fn a_voice_caller_bound_to_an_unconfigured_group_is_refused() {
        let node = node_governed_by(serviceable(), one_turn_at_a_time("voice-team"));
        let kernel = Kernel::new();
        let who = PrincipalId::new("acct:voice");
        assert!(
            node.chain_for(&who, Some("a-group-this-node-never-had"))
                .is_none(),
            "the group is not in the table, so the session has no chain to lend"
        );
        // And a turn lent none refuses, rather than running under caps nothing could read.
        let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000);
        let (decision, _) = ask_the_door(&kernel, &unit, &who);
        assert_eq!(
            decision
                .expect_err("nothing is admitted under caps that cannot be read")
                .reason(),
            ReasonCode::OverBudget
        );
    }

    /// The handshake stays exempt. A group capped out still opens its sessions, because unit zero
    /// takes no lease of either kind — the posture that keeps an operator's own surface answering
    /// while everything else is at its cap.
    #[test]
    fn a_capped_group_still_opens_a_session() {
        const GROUP: &str = "voice-team";
        let node = node_governed_by(serviceable(), one_turn_at_a_time(GROUP));
        let kernel = Kernel::new();
        let who = PrincipalId::new("acct:voice");
        let chain = node.chain_for(&who, Some(GROUP)).expect("configured");
        let turn =
            VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(&chain);
        let (_, held) = ask_the_door(&kernel, &turn, &who);
        let _running = held.grant_taken().expect("the turn is counted");

        let open = VoiceUnit::new(&node, UnitShape::SessionOpen, 8, 1_700_000_000)
            .charging_through(&chain);
        let (decision, _) = ask_the_door(&kernel, &open, &who);
        assert!(
            decision.is_ok(),
            "unit zero's admission is the zero-priced one and draws no lease"
        );
    }

    /// **The chain is lent, never rebuilt.** A live session's turns are frames of a conversation and
    /// the door is on every one of them; a chain is a vector of owned bucket ids, so resolving one
    /// per turn would put that vector on the admitting path per frame for an answer settled at the
    /// open and unable to change under the session.
    ///
    /// So the unit holds a BORROW of what the session resolved. Two turns are handed the same
    /// address — the property a per-turn `chain_for` cannot have however cheap it looks. The pin is
    /// on the reference rather than on an allocation count because this crate has no library target
    /// for a counting-allocator test binary to reach.
    #[test]
    fn two_turns_of_one_session_are_handed_the_same_chain() {
        const GROUP: &str = "voice-team";
        let node = node_governed_by(serviceable(), one_turn_at_a_time(GROUP));
        let who = PrincipalId::new("acct:voice");
        let chain = node.chain_for(&who, Some(GROUP)).expect("configured");

        let first =
            VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(&chain);
        let second =
            VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(&chain);
        let (Some(one), Some(two)) = (first.chain, second.chain) else {
            panic!("both turns were lent the session's chain");
        };
        assert!(
            std::ptr::eq(one, two),
            "one resolved chain, lent twice — not two copies of one answer"
        );
        assert!(
            std::ptr::eq(one, &chain),
            "and it is the session's own value"
        );
    }
}

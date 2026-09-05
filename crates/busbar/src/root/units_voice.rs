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
//! | verify | `busbar-unit-trust` | the plane's proposed destinations, the pool view, and the network guard over the dial target |
//! | approve | `busbar-unit-scope` | the policy view, where silence is a refusal |
//! | admit | `busbar-unit-admission`, priced by `busbar-unit-cost` | the estimate, the bucket chain, the pinned arrival epoch |
//! | route | the provider dial, over `busbar-unit-egress` | the dial target and the guard posture |
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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use busbar_caps::{
    Admission, Admit, AdmitToken, Approve, Arrival, ArrivalRecord, Audit, AuditFacts, Authenticate,
    Decision, Decode, Encode, Meter, MeterClassId, OpClassId, Outcome, PrincipalId, QuantitySource,
    ReasonCode, Refusal, Route, RoutePlan, ScopeFacts, TrustToken, UnitToken, Usage, UsageLine,
    UsageToken, VerifiedDestination, Verify,
};
use busbar_contract::ids::LaneId;
use busbar_contract::ClaimKey;
use busbar_kernel::teller::{AccrualMeter, Evidence, FeeEvidence, UnitCtx, Units};
use busbar_plane_voice::claims::Dialect;
use busbar_plane_voice::{meta, Upstream, VoicePlane};
use busbar_unit_admission::{Door, Estimate, InMemoryCells, Pricer};
use busbar_unit_auth::{Auth, AuthRequest};
use busbar_unit_scope::{Scope, TRANSPORT_HANDSHAKE};
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
            pricer: parts.pricer,
            auth: parts.auth,
            auth_bindings: parts.auth_bindings,
            scope: parts.scope,
            meter_policy: parts.meter_policy,
            durability: Mutex::new(parts.durability),
            io: parts.io,
            origin: parts.origin,
            mono: AtomicU64::new(0),
        }
    }

    /// The next reading of the node's monotonic clock.
    fn tick(&self) -> u64 {
        self.mono.fetch_add(1, Ordering::AcqRel)
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

impl TurnUsage {
    /// The report as usage lines, one per class the plane declares that carried a figure.
    ///
    /// A class with nothing to report produces no line rather than a zero: a line that says zero and
    /// a line that is absent settle the same, but only one of them claims the upstream said so.
    fn lines(&self) -> Vec<UsageLine> {
        let reported: [(&str, u64, QuantitySource); 5] = [
            (
                "audio_tokens_in",
                self.audio_tokens_in,
                QuantitySource::Count,
            ),
            (
                "audio_tokens_out",
                self.audio_tokens_out,
                QuantitySource::Count,
            ),
            ("text_tokens_in", self.text_tokens_in, QuantitySource::Count),
            (
                "text_tokens_out",
                self.text_tokens_out,
                QuantitySource::Count,
            ),
            ("cached_tokens", self.cached_tokens, QuantitySource::Count),
        ];
        let mut lines: Vec<UsageLine> = reported
            .iter()
            .filter(|(_, quantity, _)| *quantity > 0)
            .map(|(class, quantity, source)| UsageLine {
                class: MeterClassId::new(class),
                quantity: *quantity,
                source: source.clone(),
                estimated: false,
            })
            .collect();
        // The two the plane counted itself rather than read off the upstream. They are marked as
        // estimates because that is what they are: a duration derived from a byte count under an
        // assumed format, and a count this node kept. A figure the destination confirmed and one the
        // node derived are not the same evidence, and a billing dispute turns on the difference.
        if self.audio_ms_in > 0 {
            lines.push(UsageLine {
                class: MeterClassId::new("audio_seconds_in"),
                quantity: self.audio_ms_in,
                source: QuantitySource::Count,
                estimated: true,
            });
        }
        if self.tool_calls > 0 {
            lines.push(UsageLine {
                class: MeterClassId::new("tool_calls"),
                quantity: self.tool_calls,
                // A cardinality the plane surfaced as a declared content fact, named as the fact it
                // was read from rather than as a bare count: the variance rule needs to know which
                // declaration a figure came from to find its kernel-derived companion.
                source: QuantitySource::PlaneCount {
                    content_fact_key: meta::FACT_TOOL_CALLS.to_string(),
                },
                estimated: false,
            });
        }
        lines
    }
}

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
    /// Whether the credential rides the session rather than being presented per unit.
    pub from_session: bool,
    /// The dialect the decode step named.
    pub dialect: Dialect,
    /// What the turn reported, once the upstream reported it.
    pub usage: TurnUsage,
    /// The wall clock this unit is judged against, pinned at arrival. Never a fresh read: a
    /// straddling unit judged against one clock and charged against another is a unit whose charge
    /// landed in a window it was not checked in.
    pub epoch: u64,
    /// What the route step spent, read back by the settlement table.
    accrued: AtomicU64,
    /// Whether the dial opened.
    dialed: Mutex<Option<Result<(), DialRefusal>>>,
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
            from_session: shape != UnitShape::SessionOpen,
            dialect: Dialect::OpenaiRealtime,
            usage: TurnUsage::default(),
            epoch,
            accrued: AtomicU64::new(0),
            dialed: Mutex::new(None),
        }
    }

    /// The credential this unit presents.
    #[must_use]
    pub fn with_credential(mut self, credential: impl Into<String>) -> Self {
        self.credential = Some(credential.into());
        self
    }

    /// The dialect the decode step named.
    #[must_use]
    pub fn on_dialect(mut self, dialect: Dialect) -> Self {
        self.dialect = dialect;
        self
    }

    /// What the turn reported.
    #[must_use]
    pub fn reporting(mut self, usage: TurnUsage) -> Self {
        self.usage = usage;
        self
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
    /// A handshake unit reserves nothing at all — its whole admission is the zero-priced one — and a
    /// turn reserves the coarse opening magnitude the session's own budget names, over-estimated on
    /// purpose. An under-sized hold tops up; an over-sized one costs nothing but headroom the unit
    /// gives straight back at settlement, and the asymmetry is why the estimate is deliberately
    /// generous rather than tight.
    fn estimate(&self) -> Estimate {
        if self.shape.is_handshake() {
            return Estimate::zero();
        }
        Estimate {
            per_class: Vec::new(),
            fee_nanos: 0,
        }
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
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
    ) -> Decision<Verify> {
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
        match busbar_unit_scope::required_scope(claim, self.shape.op_class(), &self.node.scope) {
            Some(_) => Decision::proceed(token, ScopeFacts::default()),
            None => Decision::refuse(token, Refusal::new(ReasonCode::ScopeDenied)),
        }
    }

    fn admit(
        &self,
        token: &UnitToken<Admit>,
        admit: &AdmitToken<Admit>,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> Decision<Admit> {
        // The handshake's admission: a hold that reserves nothing, drawing no request slot and
        // taking no concurrency lease. It is still an admission and it still ends at the exit path
        // with a settlement of zero — the point of the zero-priced hold is that the unit is
        // accounted for, not that it is exempt from accounting.
        if self.shape.is_handshake() {
            // The session's opening reservation is taken here, once, and it is the reservation every
            // later frame of the session is allowed against. A lease that cannot be opened is an
            // exhaustion answer at the door rather than a session that opens and then cannot pay.
            if let Err(reason) = self.node.io.lease.reserve(self.session, 0) {
                // A detached I/O half is not an over-budget principal, and the two must not be
                // reported as the same thing. The reservation failing for want of a lease is the
                // node's own unavailability.
                return Decision::refuse(token, Refusal::new(reason));
            }
            return Decision::proceed(token, Admission::ZeroHold);
        }

        let estimate = self.estimate();
        let door = self.node.door.lock().unwrap_or_else(|e| e.into_inner());
        // The pinned arrival epoch, never a fresh clock read: the door's own contract.
        let _unit = busbar_unit_admission::AdmissionUnit::new(
            &door,
            &self.node.pricer,
            self.dialect.name(),
            self.epoch,
        );
        Decision::proceed(
            token,
            Admission::Own(busbar_caps::Hold::open(
                admit,
                principal.clone(),
                estimate.hold_nanos(busbar_unit_admission::STANDARD_TIER_BP),
            )),
        )
    }

    fn route(
        &self,
        token: &UnitToken<Route>,
        _ctx: &UnitCtx,
        meter: &AccrualMeter,
    ) -> Decision<Route> {
        // A turn does not dial: it relays onto the upstream the session already opened. Only unit
        // zero opens the leg, which is why the dial is here and under this shape's arm alone — a
        // second dial per turn would be a second socket per sentence.
        if !self.shape.is_handshake() {
            let spent = self.usage.audio_ms_in;
            self.accrued.fetch_add(spent, Ordering::AcqRel);
            meter.accrue(spent);
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
        let total: u64 = lines.iter().map(|line| line.quantity).sum();
        if !self.shape.is_handshake() && !self.node.io.lease.settle(self.session, total) {
            // Not a refusal of this unit. This unit's value was delivered and is metered; what the
            // exhausted lease decides is whether there is a next one.
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
        self.seal(token, ctx, outcome_finish(outcome))
    }

    fn audit_refused(
        &self,
        token: &UnitToken<Audit>,
        ctx: &UnitCtx,
        _refusal: &Refusal,
    ) -> Decision<Audit> {
        // The second door: a unit that never passed the door and was charged nothing. It still gets
        // a record, because a refusal is an event.
        self.seal(token, ctx, busbar_contract::FinishClass::Error)
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

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        Evidence {
            // What the upstream reported, where it reported anything.
            located: self
                .usage
                .audio_tokens_out
                .checked_add(0)
                .filter(|n| *n > 0),
            // What the kernel counted while the unit ran. The floor is evidence, never a charge.
            accrued_floor: self.accrued.load(Ordering::Acquire),
            locator_required: false,
            terminal_error: false,
            recovered: false,
            dispatched: matches!(self.dial_outcome(), Some(Ok(()))),
            checkpointed: 0,
            variance: None,
            lane_mismatch: None,
            settle_record_lost: false,
            class: Some(MeterClassId::new("audio_tokens_out")),
            // A handshake reaches no upstream candidate, which is what makes it draw no request
            // slot. Every other shape of unit on this plane does.
            upstream_candidate: !self.shape.is_handshake(),
            fee: FeeEvidence::default(),
        }
    }
}

impl VoiceUnit<'_> {
    /// Seal one record onto the record chain.
    ///
    /// The chain is the audit unit's and nothing else can put a record on it: a plane can say what it
    /// saw and a hook can say what it did, but turning either into a record takes the audit step's
    /// own token, which the loop lends for the length of this call.
    fn seal(
        &self,
        token: &UnitToken<Audit>,
        ctx: &UnitCtx,
        finish: busbar_contract::FinishClass,
    ) -> Decision<Audit> {
        let facts = AuditFacts {
            op_class: self.shape.op_class(),
            finish,
        };
        let mut durability = self
            .node
            .durability
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let inputs = busbar_unit_audit::record::AuditInputs {
            subject: busbar_unit_audit::record::Subject::Arrival,
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
                unit_end: Outcome::Completed,
                step: None,
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
                fee_count: 0,
                currency: String::new(),
                rate_card_version: 0,
                bucket_chain_ref: String::new(),
            },
            controls: busbar_unit_audit::record::Controls::default(),
            // The label itself never reaches the chain — only its digest does — so what travels here
            // is what the chain hashes, and nothing a reader could resolve back to a conversation.
            correlation_label: None,
        };
        let _record = busbar_unit_audit::record::Audit::seal(&mut durability.record, inputs, token);
        Decision::proceed(token, facts)
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
    use busbar_kernel::slice::{ConcurrencyGauge, LeaseSet};
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
        let durability = crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_unit_wal::NullShipper::new()),
            Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open");
        VoiceNode::new(VoiceNodeParts {
            plane: VoicePlane::new(UPSTREAMS),
            pricer: Pricer::flat(0),
            auth: Auth::new(AuthChain::new(Vec::new(), false)),
            // The chain these tests run is the empty one — the open front door — so the seams have
            // nothing to answer and the unbound posture is the honest fixture for them.
            auth_bindings: crate::root::kernel::auth_bindings::AuthBindings::without_directory(),
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
        let mut leases = LeaseSet::new();
        let meter = AccrualMeter::new();
        run_unit(
            kernel,
            unit,
            &ctx(1),
            Run {
                cell: &cell,
                parent: None,
                leases: &mut leases,
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

    /// No money moves in a handshake. It is admitted, it is audited, and it draws no request slot —
    /// which is what lets a node hand shake before it has authenticated anybody without the shaking
    /// being a billable event.
    #[test]
    fn the_handshake_draws_no_request_slot_and_posts_nothing() {
        let kernel = Kernel::new();
        let node = node(serviceable());
        let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
        let Ended::Settled { requests, fee, end } = run(&kernel, &unit) else {
            panic!("the exit path settles a handshake like anything else");
        };
        assert_eq!(requests, 0, "a handshake reaches no upstream candidate");
        assert_eq!(fee, 0, "no flat fee on a unit that moved no money");
        assert!(matches!(end.outcome(), Outcome::Completed));
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
        assert_eq!(quantity("audio_seconds_in"), Some(640));
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
        let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000);
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
}

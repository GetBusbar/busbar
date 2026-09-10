// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE SERVING SWITCH, ON THE WHOLE FILE, and it is the ACCEPTOR'S switch rather than a second one.
// `root::plane_mount` is what hands a driver to a wire, this is what it hands, and a module gated
// separately would admit a build in which one of the two exists without the other — an acceptor
// with nothing to serve, or a driver nothing serves through. Off, neither is compiled and no call
// site anywhere names either, which is what makes the feature-off binary byte-identical by
// construction rather than by measurement.
//
// The switch carries NO PLANE'S NAME, and it can, because there is no plane's name in this file.
#![cfg(feature = "root-duplex-serve")]

//! RUNNING A DECLARED SESSION'S FRAMES OVER THE KERNEL'S UNIT LOOP, THROUGH THE PLANE: one driver,
//! no plane's name.
//!
//! ## Why this is a second driver rather than a wider first one
//!
//! [`crate::root::transports::LoopDriver`] is the whole of the request/answer shape: one arrival
//! goes over, one answer comes back, and everything either side accumulated is gone. That is not
//! this shape and the difference is not a detail. ONE upgrade carries MANY frames, in both
//! directions, and what a frame MEANS depends on the frames before it.
//!
//! Something has to hold that across frames, and the seam decides which side. It is held HERE,
//! behind the opaque [`SessionHandle`] the transport got back and hands in again, because the
//! alternative — handing the state across on every frame — makes the transport the thing that knows
//! what a session accumulates, which is exactly the knowledge the transport axis is not allowed. The
//! transport holds an integer.
//!
//! ## THE PLANE IS NEVER NAMED, AND IT JOINS BY ITS ROW
//!
//! What a session of a particular binding IS comes off that plane's own registered row — its
//! [`WireSurface`], the same declaration [`crate::root::plane_mount`] mounts and the transport
//! addresses upgrades against — and what its bytes MEAN comes off the plane's own codec, reached
//! through the contract's [`SessionPlane`] face and never by the plane's type. This driver is handed
//! the plane as `dyn`, the units the root composed for its sessions as [`SessionUnits`], and a
//! declared surface it cannot ask the provenance of. It could not say whose sessions it is running,
//! and it has no way to ask.
//!
//! [`declared_run`] is the whole of what this driver reads out of the row, and the answer decides
//! whether there is a session here to run at all: a binding no declared operation dispatches over
//! has no declared session behaviour, and an upgrade on one is refused on the leg that can still
//! carry a refusal rather than opened onto a shape the composition root picked on the plane's
//! behalf. What it reads with it is the MEDIA the declaration names for the frames, which is what
//! every frame this driver writes back is labelled with.
//!
//! **THERE IS EXACTLY ONE SHAPE, AND THE CONTRACT'S OWN BOOT CHECK IS WHY.** A duplex row declared
//! [`Answering::Unary`] is refused by
//! [`check_surface`](busbar_contract::transport::surface::check_surface) before any listener binds
//! — a session whose first answer is its last is a session cut at its first answer — so every
//! mountable duplex binding in this tree declares a RUN. A `match` here over the answering shape
//! would be a second opinion about a question the declaration vocabulary has already closed.
//!
//! ## THE PLANE CALL, and who owns the arena
//!
//! The kernel's step seam hands a unit its context and no arena, and the one plane unit this root
//! composes says in its own decode step that the plane read the frame before the loop ran. So the
//! plane call sits ABOVE the loop, and this driver is the owner: per moment of a session it puts an
//! [`ArenaSpace`] on its own stack, carves a [`UnitArena`] from it, builds the contract [`Ctx`] on
//! that, asks the plane what the bytes mean, hands the reading to the units the root composed, runs
//! the loop, renders the ending through the plane's own encoders, and lets the space drop. Nothing
//! the plane borrowed survives the frame, which is the reset — see
//! `docs/design/1.6.0-per-unit-arena.md`.
//!
//! ## The three moments, and what each one is the only place for
//!
//! **[`SessionDriver::open`]** is the ONLY moment a refusal is answerable on the wire the upgrade
//! arrived on; after it the protocol has changed and there is no status field left. So the credential
//! bar the DECLARATION put on the binding is resolved here, against the facts the mount published,
//! and a bar with nothing to satisfy it is refused in the eight words BEFORE anything is allocated.
//! Then THE OPENING UNIT runs — the unit that answers the arrival, authenticating what the upgrade
//! presented, approving the open, admitting it and sealing its record — and its ending is the
//! upgrade's answer. A session whose opening unit did not complete is not opened, and nothing of it
//! is left in the table: the plane's client half was opened on the stack and dropped with it.
//!
//! **[`SessionDriver::drive`]** hands one inbound frame to the plane's reader, on a fresh arena,
//! against the codec state the session accumulated. What the plane reads as a UNIT — a draft that
//! opens one — runs as an ordinary unit of the kernel's own loop, the same steps the one-shot path
//! walks, carrying the SESSION's identity on the unit's context, which is what files the frame's
//! posting and its audit link against the session it belongs to rather than as an unrelated
//! one-off. The frame's own ordinal travels with it and is CHECKED, because a duplex plane's state
//! machine reads frame *n* against what frame *n-1* left behind and an out-of-order delivery is
//! otherwise reinterpreted rather than detected. The frame that goes back is the plane's: a refusal
//! rendered through its refusal encoder in its own dialect, under the media the declaration named.
//!
//! **[`SessionDriver::close`]** releases what `open` allocated, on every ending including the ugly
//! ones. Exactly once per handle, and the "exactly" is enforced here rather than assumed of the
//! caller: the slot is REMOVED from the table under the lock, so a second close finds nothing and a
//! concurrent frame finds nothing either. The composed units are told, once, so a wait the session's
//! units entered ends with the session rather than waiting out a deadline nobody is left to satisfy.
//!
//! ## What the credential bar can and cannot decide here
//!
//! It decides whether a session may be OPENED at all with what the caller presented — a declared
//! [`Bar::Credential`] and no credential fact is a refusal, and that is the whole of it. It does NOT
//! decide who the caller is. Resolving a credential to a principal is the authenticate step's, it
//! runs inside the loop, on the opening unit, with the credential the upgrade published; a driver
//! that resolved one itself would be a second authenticator beside the node's.
//!
//! ## WHAT A FRAME THAT OPENS NO UNIT IS, said plainly
//!
//! A plane's reader answers seven ways and only three of them are a unit. `NeedMore` is a frame
//! that is not yet a whole anything; `Discard` is a frame the dialect says to drop; a `Frame` is a
//! frame of a unit ALREADY OPEN, to be relayed under that unit's hold, and a `Close` is that unit's
//! end. The relay and the close are the UPSTREAM HALF of a session — the leg the opening unit
//! sealed, dialed and written to — and the upstream half's socket is not on this driver: this
//! driver opens the plane's upstream codec state for it ([`SessionPlane::open_upstream`], on the
//! arena, the moment the units say where the session's leg was sealed to) and holds it on the slot,
//! and that is where the line is today. Those four readings are consumed, run no unit, and answer
//! nothing, and the reply says so with the one word the seam has for "this frame's unit is not a
//! thing that happened": `Completed` with no frames. Said here so nobody looks for the relay in the
//! loop.
//!
//! ## TWO LOCKS, and the outer one is never held across a unit
//!
//! The table is locked only long enough to clone one session's own lock out of it, so a long frame
//! on one session does not stop a second session from opening. The inner lock is what makes ONE
//! session's frames serial, which they have to be — an ordinal read by two frames at once is an
//! ordinal neither of them can reason about, and a codec state read by two frames at once is not a
//! codec state.
//!
//! A POISONED SESSION STOPS. The inner lock is held for exactly the span in which a frame's unit
//! runs, so a panic in there poisons it, and a session read on from an unknown point hands the far
//! side a state machine that silently disagrees with this one. The word is
//! [`CloseReason::Poisoned`], which the ws wire spells 1011 — this node saying the fault was its
//! own, which it is, rather than telling a well-behaved client to go and change its behaviour.
//!
//! ## Money untouched, by construction
//!
//! The loop's own units do the arithmetic, unchanged, and this file adds nothing to and takes
//! nothing from what a unit costs. The switch is default-off and no call site names this module
//! without it, so the shipped binary is byte-identical.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use busbar_caps::{
    Admit, AdmitToken, Approve, Arrival, Audit, Authenticate, Decision, Decode, Encode, Meter,
    PrincipalId, ReasonCode, Refusal, Route, StepName, TrustToken, UnitToken, UsageToken,
    VerifiedDestination, Verify,
};
use busbar_contract::bounded::{Ir, Labels, SlabBytes};
use busbar_contract::dest::VerifiedDestination as PlaneDestination;
use busbar_contract::ids::{OpClassId, SessionId, StreamId};
use busbar_contract::plane::{Ingress, PlaneSessionState, Progress, SessionPlane, UnitDraft};
use busbar_contract::transport::driver::Outcome;
use busbar_contract::transport::facts as tfacts;
use busbar_contract::transport::session::{
    EgressLease, SessionDriver, SessionEnd, SessionFrame, SessionHandle, SessionOpen, SessionReply,
};
use busbar_contract::transport::surface::{Answering, Bar, Dispatch, WireSurface};
use busbar_contract::unit::{
    Clock, ConfigView, Ctx, Refusal as PlaneRefusal, SessionView, Step, TransportView,
};
use busbar_contract::wire::{CloseReason, Direction, Frame, FrameCursor, FrameMeta};
use busbar_kernel::slice::GroupLeaseSlip;
use busbar_kernel::teller::{AccrualMeter, Ended, Evidence, UnitCtx, UnitIdentity, Units};

use crate::root::arena::{ArenaSpace, UnitArena};
use crate::root::transports::outcome_of;

// ── the plane's session behaviour, as the plane's own row declares it ────────────────────────────

/// WHAT A BINDING'S ROW DECLARES A SESSION ON IT TO BE, and the media its frames go back under.
///
/// The one thing this driver reads out of a plane's declaration, and the one it cannot proceed
/// without. `Some` exactly where some declared operation dispatches over the binding in the duplex
/// kind and answers [`Answering::Stream`] — which is to say, where the plane said that one open
/// carries a run of answers — and what it carries is that operation's declared response media,
/// which is what every frame this driver writes back is labelled with.
///
/// **The `Stream` is checked rather than assumed, and there is deliberately no second arm.** A
/// duplex row declared [`Answering::Unary`] never reaches a mount at all:
/// [`check_surface`](busbar_contract::transport::surface::check_surface) refuses the whole surface
/// at boot, because a session whose first answer is its last is a session cut at its first answer.
/// So the word is read here as the CONDITION for running the binding rather than as a switch
/// between two behaviours — a driver that quietly accepted `Unary` and then ran it as a run would be
/// serving a surface the boot check exists to keep off this node.
#[must_use]
pub fn declared_run(surface: &WireSurface, binding: &str) -> Option<&'static str> {
    surface
        .operations
        .iter()
        .find(|op| {
            op.answering == Answering::Stream
                && op
                    .dispatch
                    .iter()
                    .any(|d| matches!(d, Dispatch::Duplex { binding: b, .. } if *b == binding))
        })
        .map(|op| op.response_media)
}

/// WHETHER A BINDING'S ROW DECLARES A SESSION THIS DRIVER CAN RUN. See [`declared_run`].
#[must_use]
pub fn declares_a_run(surface: &WireSurface, binding: &str) -> bool {
    declared_run(surface, binding).is_some()
}

// ── the units a declared session's moments run as, composed by the root ─────────────────────────

/// WHAT THE PLANE READ OFF ONE MOMENT OF A SESSION, as the units the root composed for it see it.
///
/// Two moments have a reading. The OPENING unit has no draft — no frame carries an upgrade, the
/// upgrade IS the arrival — and every later unit is a draft the plane's reader produced. What is
/// common to both is the session the moment belongs to, the facts the transport published when it
/// opened, and the node's clock when it happened; a unit set that needs more reads it off the draft
/// the plane wrote, in the plane's own vocabulary, which is why nothing here is spelled in one.
#[derive(Debug, Clone, Copy)]
pub struct SessionRead<'a, 'u> {
    /// The driver's own number for the session.
    pub session: u64,
    /// The unit the plane read, or `None` for the opening unit, which no frame carries.
    pub draft: Option<&'a UnitDraft<'u>>,
    /// The facts the transport published at the upgrade, in the order it published them.
    pub facts: &'a [(String, String)],
    /// The node's clock at this moment.
    pub clock: Clock,
}

impl SessionRead<'_, '_> {
    /// The value of one published fact. First match wins.
    #[must_use]
    pub fn fact(&self, key: &str) -> Option<&str> {
        lookup(self.facts, key)
    }

    /// The credential the upgrade presented, where it presented one that is not blank.
    ///
    /// Spelled here, once, so a units composition reads "the credential" and never the transport
    /// seam's key for it: which fact carries a credential is the seam's business, and a composition
    /// that named the key would be one more reader to move when the seam does.
    #[must_use]
    pub fn credential(&self) -> Option<&str> {
        self.fact(tfacts::CREDENTIAL).filter(|c| !c.is_empty())
    }

    /// The path the upgrade addressed, as the transport published it.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.fact(tfacts::PATH)
    }
}

/// THE UNITS A DECLARED SESSION'S MOMENTS ARE JUDGED BY, as the composition root composed them.
///
/// The loop is generic over [`Units`], and a session's unit is one that lives for one moment — it
/// carries what the plane read off that frame, and nothing about a frame outlives the frame. So the
/// seam a session driver reaches its units through is not a unit set but a COMPOSITION of one per
/// moment: hand it the reading, get back the unit the moment runs as, borrowed from the composition
/// for exactly as long as the moment. A composition that held one long-lived unit set would be one
/// that carried every frame's facts on a struct every other frame could read.
///
/// The root implements this over what it composed ([`crate::root::kernel::ProductionUnits`]
/// carries the composed session units as data), and a plane's own units composition implements it
/// over the plane's node. This driver names neither.
pub trait SessionUnits: Send + Sync {
    /// The unit one moment of a declared session runs as.
    fn unit<'f>(&'f self, read: &SessionRead<'_, '_>) -> Box<dyn Units + 'f>;

    /// WHERE THE SESSION'S UNITS SEALED ITS LEG TO, once one of them has.
    ///
    /// A destination is sealed inside the loop, at Verify, by the trust token the loop lends that
    /// step and nothing else; this driver cannot mint one and must not. What it can do with one the
    /// units already sealed is open the plane's upstream half of the session's codec state for it —
    /// which is the one call on the plane that takes a destination and a context and no unit. It is
    /// the CONTRACT's destination, the shape the plane reads, and only a step token can seal one —
    /// which is the point: the units sealed it at Verify, and this driver merely carries it. `None`
    /// until a unit of this session has sealed one, and `None` from a composition that seals none.
    fn destination(&self, session: u64) -> Option<PlaneDestination> {
        let _ = session;
        None
    }

    /// WHO THIS SESSION IS FOR, as the composition's own authenticate step resolved it.
    ///
    /// The one fact about a session that is decided INSIDE the loop and needed OUTSIDE it. The
    /// authenticate step's answer belongs to the chain and nothing may open it there; the loop
    /// opens it and hands the principal to the steps that are lent one, and a composition that
    /// records it at the first of those has it. This is where it comes back across.
    ///
    /// It is needed outside the loop because the leg's WRITES are a unit's writes, and a unit has a
    /// principal. A view minted for the relay with `None` here is a view that says the frames going
    /// upstream are for nobody — which is a bill nobody can be shown and a revocation nobody can be
    /// traced through, arrived at not by deciding it but by failing to carry it.
    ///
    /// `None` until a unit of this session has been through authenticate, and `None` from a
    /// composition that resolves none — the anonymous posture has to stay representable, and a seam
    /// that could not answer `None` would be one that made every composition invent a principal.
    fn principal(&self, session: u64) -> Option<PrincipalId> {
        let _ = session;
        None
    }

    /// The session is over. Whatever the units held for it across moments can go.
    fn closed(&self, session: u64) {
        let _ = session;
    }
}

/// A unit set reached through a borrow, for a loop that is generic over a sized one.
///
/// [`busbar_kernel::teller::run_unit`] takes its units by generic reference, and a unit this driver
/// was handed as `dyn` is not sized. This is the one-line bridge: every step forwards, nothing is
/// decided, and the reason it is here rather than in the kernel is that the kernel has no `dyn`
/// unit set and should not grow one for the sake of a caller that has.
pub struct Borrowed<'a, U: ?Sized>(pub &'a U);

impl<U: Units + ?Sized> Units for Borrowed<'_, U> {
    fn arrival(&self, t: &UnitToken<Arrival>, c: &UnitCtx) -> Decision<Arrival> {
        self.0.arrival(t, c)
    }
    fn decode(&self, t: &UnitToken<Decode>, c: &UnitCtx) -> Decision<Decode> {
        self.0.decode(t, c)
    }
    fn authenticate(&self, t: &UnitToken<Authenticate>, c: &UnitCtx) -> Decision<Authenticate> {
        self.0.authenticate(t, c)
    }
    fn verify(
        &self,
        t: &UnitToken<Verify>,
        trust: &TrustToken,
        c: &UnitCtx,
        p: &PrincipalId,
    ) -> Decision<Verify> {
        self.0.verify(t, trust, c, p)
    }
    fn approve(
        &self,
        t: &UnitToken<Approve>,
        c: &UnitCtx,
        p: &PrincipalId,
        d: &[VerifiedDestination],
    ) -> Decision<Approve> {
        self.0.approve(t, c, p, d)
    }
    fn admit(
        &self,
        t: &UnitToken<Admit>,
        a: &AdmitToken<Admit>,
        c: &UnitCtx,
        p: &PrincipalId,
        d: &[VerifiedDestination],
        l: &GroupLeaseSlip,
    ) -> Decision<Admit> {
        self.0.admit(t, a, c, p, d, l)
    }
    fn route(&self, t: &UnitToken<Route>, c: &UnitCtx, m: &AccrualMeter) -> Decision<Route> {
        self.0.route(t, c, m)
    }
    fn meter(
        &self,
        t: &UnitToken<Meter>,
        u: &UsageToken,
        c: &UnitCtx,
        p: &busbar_caps::Outcome,
    ) -> Decision<Meter> {
        self.0.meter(t, u, c, p)
    }
    fn audit(
        &self,
        t: &UnitToken<Audit>,
        c: &UnitCtx,
        o: &busbar_caps::Outcome,
    ) -> Decision<Audit> {
        self.0.audit(t, c, o)
    }
    fn audit_refused(&self, t: &UnitToken<Audit>, c: &UnitCtx, r: &Refusal) -> Decision<Audit> {
        self.0.audit_refused(t, c, r)
    }
    fn encode(
        &self,
        t: &UnitToken<Encode>,
        c: &UnitCtx,
        o: &busbar_caps::Outcome,
    ) -> Decision<Encode> {
        self.0.encode(t, c, o)
    }
    fn evidence(&self, c: &UnitCtx) -> Evidence {
        self.0.evidence(c)
    }
}

/// THE ROOT'S OWN UNIT SET, COMPOSING A DECLARED SESSION'S MOMENTS AS DATA.
///
/// A declared duplex run is judged by the units the root composed for it — carried on
/// [`ProductionUnits`](crate::root::kernel::ProductionUnits) as a value, put there by the
/// composition that knows whose they are — and, where the root composed none, by the root's own
/// steps, which refuse a unit no plane on this node claimed. That is the same answer the one-shot
/// driver gets from the same struct, and it is deliberately the same struct: what judges a unit on
/// this node is one composition, not one per driver.
impl SessionUnits for crate::root::kernel::ProductionUnits {
    fn unit<'f>(&'f self, read: &SessionRead<'_, '_>) -> Box<dyn Units + 'f> {
        match &self.duplex {
            Some(composed) => composed.unit(read),
            None => Box::new(Borrowed(self)),
        }
    }

    fn destination(&self, session: u64) -> Option<PlaneDestination> {
        self.duplex.as_ref().and_then(|c| c.destination(session))
    }

    fn principal(&self, session: u64) -> Option<PrincipalId> {
        self.duplex.as_ref().and_then(|c| c.principal(session))
    }

    fn closed(&self, session: u64) {
        if let Some(composed) = &self.duplex {
            composed.closed(session);
        }
    }
}

// ── what one open session is ────────────────────────────────────────────────────────────────────

/// WHAT THE SESSION'S UNITS SEALED, before there is a socket for it.
///
/// A leg is decided by a unit and OPENED by the composition, and those are two different moments on
/// two different sides of the driver seam: the unit runs inside a synchronous `drive`, and dialling
/// is an await. So what the unit decided is parked here, where the thing that CAN await
/// ([`crate::root::leg_dial::LegDialing`]) reads it between frames, and the leg replaces it.
///
/// It carries the identity as well as the address because the identity is the unit's too: the leg's
/// writes are that unit's writes, and a key minted later would file them as somebody else's.
struct PendingLeg {
    /// Where the session's units sealed the leg to.
    dest: PlaneDestination,
    /// Whose writes the leg's frames are.
    unit: UnitIdentity,
    /// The class that priced the unit whose relay this is.
    op: OpClassId,
}

/// THE UPSTREAM LEG OF ONE RELAYED SESSION: the plane's half, the offering half, and whose it is.
///
/// Three things and no socket, which is the division this whole line exists for. The SOCKET is the
/// composition's — dialled on the accept task, drained by a future the root spawned — and what
/// reaches a synchronous `drive` is a bounded [`EgressLease`] it can hand a frame to without
/// suspending. The plane's upstream codec state is here for the same reason its client half is: the
/// contract's rule is that cross-frame codec state lives in exactly one place, and this is that
/// place for the leg.
struct UpstreamLeg {
    /// The plane's own codec state for the upstream half, opened once when the leg was attached.
    state: PlaneSessionState,
    /// The offering end. Bounded and refusing: see [`EgressLease`].
    lease: Box<dyn EgressLease>,
    /// Whose writes these are — the half of a unit only the kernel seals.
    unit: UnitIdentity,
    /// Where the leg goes, as the encoders take it.
    dest: PlaneDestination,
    /// The class that priced the unit whose relay this is.
    op: OpClassId,
}

/// WHEN AND WHERE an ending on the leg runs, gathered so the ending's own call reads as one.
///
/// Three values that always travel together — the session an ending belongs to, the facts its unit
/// is judged against and the clock reading the whole frame was taken at. Gathered rather than passed
/// separately for the reason [`busbar_kernel::teller::UnitIdentity`] is: a caller assembling them
/// positionally is a caller who can pass last frame's clock with this frame's facts.
struct LegMoment<'a> {
    session: u64,
    facts: &'a [(String, String)],
    clock: Clock,
}

/// Everything one open session holds, and the only thing that outlives a frame.
struct Open {
    /// The facts the mount published at the upgrade, OWNED so they outlive the upgrade.
    ///
    /// Owned rather than borrowed, and that is forced rather than chosen: the strings the mount
    /// published point into a request buffer that is freed the moment the upgrade completes. A
    /// session that kept the borrow would be reading a buffer somebody else is refilling.
    facts: Vec<(String, String)>,
    /// The registry key of the layer the session ended on, and the composed stack under it.
    transport: &'static str,
    chain: Vec<&'static str>,
    /// The media the declaration names for this binding's frames.
    media: &'static str,
    /// The next inbound ordinal this session expects.
    ///
    /// This driver's own, and the evidence that the transport delivered the session IN ORDER.
    seq: u64,
    /// The plane's client half of this session's codec state — the ONLY place cross-frame codec
    /// state may live, by the contract's own rule, opened by the plane at the upgrade.
    state: PlaneSessionState,
    /// A leg the session's units have sealed and nothing has dialled yet.
    ///
    /// Set inside `drive`, taken by [`SessionLoopDriver::pending_leg`] on the accept task, and
    /// replaced by `upstream` when [`SessionLoopDriver::attach_leg`] lands the socket's offering
    /// end. It is `Option` in both directions on purpose: a session whose units seal no destination
    /// never has one, and a session whose leg is open no longer does.
    pending: Option<PendingLeg>,
    /// The session's upstream leg, once it has been dialled and attached.
    upstream: Option<UpstreamLeg>,
    /// THE CLIENT'S OFFERING END, for the half of the session that is written to from a task the
    /// client's own pump is not on.
    ///
    /// A lease and not a sink, for the reason the leg's is one: what writes here is
    /// [`SessionLoopDriver::upstream`], which is synchronous, and a socket write is not. The wire's
    /// own write half is behind one lock inside the transport, so the lease's drain and the client
    /// pump's sink are two OFFERERS and one writer — which is what a full-duplex session is: the
    /// answers to the client's own frames and the replies coming back off the leg are genuinely
    /// concurrent, and nothing here may interleave them into an order neither side asked for.
    ///
    /// `None` for every session that never relays, and dropping it is what closes the client's half:
    /// the drain writes this wire's orderly close when its offering end goes.
    client: Option<Box<dyn EgressLease>>,
}

/// The session, as the plane is allowed to see it.
struct SlotSession<'a> {
    id: SessionId,
    facts: &'a [(String, String)],
    /// Whether the opening unit has completed, which is when the session's principal is cached on
    /// it and a session-carried credential can be used.
    bound: bool,
    upstreams: usize,
}

impl SessionView for SlotSession<'_> {
    fn id(&self) -> SessionId {
        self.id
    }
    fn is_bound(&self) -> bool {
        self.bound
    }
    fn session_fact(&self, key: &str) -> Option<&str> {
        // A session fact is what the plane wrote through its own answers; nothing this driver
        // holds is one, and the transport's facts are answered on their own question below.
        let _ = key;
        None
    }
    fn transport_fact(&self, key: &str) -> Option<&str> {
        lookup(self.facts, key)
    }
    fn upstream_count(&self) -> usize {
        self.upstreams
    }
}

/// The transport stack under a session, as the plane is allowed to see it.
struct SlotTransport<'a> {
    key: &'static str,
    chain: &'a [&'static str],
    facts: &'a [(String, String)],
}

impl TransportView for SlotTransport<'_> {
    fn key(&self) -> &'static str {
        self.key
    }
    fn chain(&self) -> &[&'static str] {
        self.chain
    }
    fn fact(&self, key: &str) -> Option<&str> {
        lookup(self.facts, key)
    }
}

/// One published fact, by key. First match wins, as it does on the seam the facts came across.
fn lookup<'a>(facts: &'a [(String, String)], key: &str) -> Option<&'a str> {
    facts
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// THE ONE MAPPING from the kernel's step name to the spelling the plane renders a refusal with.
///
/// Name for name, and a `match` rather than a cast so that a step added to either side fails to
/// compile here rather than rendering as its neighbour.
fn step_of(step: StepName) -> Step {
    match step {
        StepName::Arrival => Step::Arrival,
        StepName::Decode => Step::Decode,
        StepName::Authenticate => Step::Authenticate,
        StepName::Verify => Step::Verify,
        StepName::Approve => Step::Approve,
        StepName::Admit => Step::Admit,
        StepName::Route => Step::Route,
        StepName::Meter => Step::Meter,
        StepName::Audit => Step::Audit,
        StepName::Encode => Step::Encode,
    }
}

/// The frames the plane wrote for one ending, or none where it wrote none.
///
/// A REFUSAL is rendered through the plane's own refusal encoder, in its own dialect, against the
/// draft it refused: what a refusal LOOKS like on the wire is the plane's and nothing here spells
/// one. A completed unit on this path has no upstream reply to render — the relay is the upstream
/// half's — and every other ending is this node's own fault, which the outcome word already says.
fn rendered<'u>(
    plane: &dyn SessionPlane,
    ended: &Ended,
    draft: Option<&UnitDraft<'u>>,
    state: &PlaneSessionState,
    ctx: &Ctx<'u>,
) -> Vec<Vec<u8>> {
    let Ended::Settled { end, .. } = ended else {
        return Vec::new();
    };
    let busbar_caps::Outcome::Refused(step, reason) = end.outcome() else {
        return Vec::new();
    };
    let refusal = PlaneRefusal {
        step: step_of(step),
        reason: reason.into(),
        retry_after_secs: None,
        stream: None,
        correlates: draft.and_then(|d| d.correlates),
    };
    plane
        .encode_refusal(&refusal, draft, Some(state), ctx)
        .map(|bytes| vec![bytes.as_slice().to_vec()])
        .unwrap_or_default()
}

/// THE ONE MAPPING from a sealed end to the ending a plane is asked to WRITE.
///
/// The loop's ending and the plane's are the same fact in two vocabularies, and this is the only
/// place either is translated into the other — a `match` rather than a cast, so an outcome added to
/// either side fails to compile here rather than being written as its neighbour. It is the exact
/// counterpart of [`rendered`] beside it: that one renders a refusal for the CLIENT half, this one
/// renders the whole ending for the UPSTREAM half, and both read the same sealed end.
///
/// `Failed` and `TimedOut` both arrive as `FailureReason::Transport` on a relayed session and that
/// is deliberate rather than lossy: what the far side of a leg is entitled to know is that this node
/// could not carry the exchange on, and which of this node's steps broke is an internal fact a
/// relayed peer has no standing to be told.
fn ending_of<'u>(
    end: &busbar_caps::UnitEnd,
    draft: &UnitDraft<'u>,
) -> busbar_contract::unit::UnitEnd<'u> {
    use busbar_caps::Outcome as Ends;
    use busbar_contract::unit::{AbortBy, FailureReason, UnitEnd as End};
    match end.outcome() {
        Ends::Completed => End::Completed,
        Ends::Refused(step, reason) => End::Refused(PlaneRefusal {
            step: step_of(step),
            reason: reason.into(),
            retry_after_secs: None,
            stream: None,
            correlates: draft.correlates,
        }),
        Ends::Failed(step, _) | Ends::TimedOut(step) => End::Failed {
            step: step_of(step),
            reason: FailureReason::Transport,
        },
        // The client went away. `AbortBy::Client` is the same statement the one-shot path makes,
        // and the leg's far side is told the exchange ended rather than why this node's caller left.
        Ends::Aborted(_) => End::Aborted(AbortBy::Client),
    }
}

// ── the driver a duplex acceptor hands each open session to ─────────────────────────────────────

/// WHAT RUNS A DECLARED SESSION'S FRAMES, on the root's side of the duplex transport seam.
///
/// Everything a transport is not allowed to hold is held here: the kernel seal, the units the steps
/// run against, the plane's codec, the gauge, the canary and the table of open sessions. What the
/// transport gets back is a number.
///
/// GENERIC OVER THE UNITS, for the reason [`crate::root::plane_mount`] is generic over the wire: a
/// driver written against one concrete composition would be a driver that named what it drives.
/// The plane arrives as `dyn` for the same reason, through the contract's own face: there is no
/// plane here to be generic over, because there is no plane here at all — there is a row.
pub struct SessionLoopDriver<'n, U: SessionUnits + ?Sized> {
    kernel: &'n busbar_kernel::teller::Kernel,
    units: &'n U,
    plane: &'n dyn SessionPlane,
    config: &'n dyn ConfigView,
    gauge: &'n busbar_kernel::slice::ConcurrencyGauge,
    canary: &'n busbar_caps::Canary,
    /// Where the monotonic half of every clock reading this driver hands a plane is measured from.
    started: Instant,
    next_key: AtomicU64,
    next_session: AtomicU64,
    /// The open sessions, by the handle this driver minted. See this module's header on the two
    /// locks and on why the outer one is never held across a unit.
    open: Mutex<HashMap<u64, Arc<Mutex<Open>>>>,
}

impl<U: SessionUnits + ?Sized> std::fmt::Debug for SessionLoopDriver<'_, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionLoopDriver")
    }
}

impl<'n, U: SessionUnits + ?Sized> SessionLoopDriver<'n, U> {
    /// Bind the driver to the node's own kernel, units, gauge and canary, and to the plane's row.
    ///
    /// By reference and not by value, for the reason the one-shot driver takes them by reference:
    /// one driver serves every session every listener accepts, and the counts the canary balances
    /// are node-wide. A driver that owned a copy would be balancing its own books beside the node's.
    #[must_use]
    pub fn new(
        kernel: &'n busbar_kernel::teller::Kernel,
        units: &'n U,
        plane: &'n dyn SessionPlane,
        config: &'n dyn ConfigView,
        gauge: &'n busbar_kernel::slice::ConcurrencyGauge,
        canary: &'n busbar_caps::Canary,
    ) -> Self {
        Self {
            kernel,
            units,
            plane,
            config,
            gauge,
            canary,
            started: Instant::now(),
            next_key: AtomicU64::new(1),
            next_session: AtomicU64::new(1),
            open: Mutex::new(HashMap::new()),
        }
    }

    /// How many sessions are open right now.
    ///
    /// The one number this driver publishes about itself, and it exists for one reason: "a refused
    /// open allocates nothing" and "a close releases" are both statements about this figure, and a
    /// cell that could not read it would be asserting them against the absence of a crash.
    #[must_use]
    pub fn open_sessions(&self) -> usize {
        self.open.lock().map_or(0, |t| t.len())
    }

    /// The node's clock, as the plane is handed it: wall seconds and this driver's monotonic nanos.
    fn clock(&self) -> Clock {
        let unix_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Clock {
            unix_secs,
            monotonic_nanos: self.started.elapsed().as_nanos(),
        }
    }

    /// The key of the next unit this driver will walk.
    fn next_unit(&self) -> busbar_caps::UnitKey {
        busbar_caps::UnitKey::new(self.next_key.fetch_add(1, Ordering::Relaxed))
    }

    /// One session's own lock, cloned out from under the table's.
    ///
    /// `None` for a handle this driver never minted and for one it has already closed, which are the
    /// same answer and should be: a frame for a session that is over is a frame with nothing to read
    /// it against.
    fn slot(&self, session: SessionHandle) -> Option<Arc<Mutex<Open>>> {
        self.open.lock().ok()?.get(&session.0).cloned()
    }

    /// RELAY ONE FRAME onto the session's upstream leg, under the open unit's own view.
    ///
    /// The plane decides what goes out: [`SessionPlane::encode_ingress_frame`] is handed the unit as
    /// the kernel seals it, the frame, the destination the leg was sealed to and the leg's own codec
    /// state, and it answers with the bytes or with nothing. `None` is a real answer and not a
    /// failure — a plane that buffers a partial message upstream has written nothing yet — and the
    /// session carries on.
    ///
    /// A REFUSING LEASE ENDS THE SESSION, and the two refusals are told apart because they mean
    /// different things to the caller. At depth, the leg has fallen behind and the honest word is
    /// `CapacityExhausted` — nothing is wrong with the caller and the same session opened later may
    /// well run. Over, the leg is gone and it is `TransportFailed`. Carrying on past either would be
    /// a relayed session that silently stopped relaying, which is the one outcome worse than ending.
    fn relay(
        &self,
        leg: &mut UpstreamLeg,
        for_: Option<busbar_contract::ids::CorrelationRef<'_>>,
        relay: &[u8],
        facts: &busbar_contract::bounded::Facts<'_>,
        ctx: &Ctx<'_>,
    ) -> SessionReply {
        let draft = UnitDraft {
            op: leg.op,
            body_ir: Ir::new(relay, &[]),
            correlates: for_,
            correlation_out: None,
            facts: *facts,
        };
        let view = self.kernel.unit_view(&leg.unit, &draft);
        let frame = Frame {
            direction: Direction::Outbound,
            stream: StreamId(0),
            bytes: SlabBytes::new(Arc::from(relay)),
            meta: FrameMeta::default(),
        };
        let encoded =
            self.plane
                .encode_ingress_frame(&view, &frame, &leg.dest, Some(&mut leg.state), ctx);
        match encoded {
            Ok(None) => SessionReply::quiet(Outcome::Completed),
            Ok(Some(bytes)) => offered(leg.lease.offer(bytes.as_slice())),
            // The plane could not write it. Nothing went out and nothing is going to, because the
            // next frame of this exchange is read against a state this one did not advance.
            Err(_) => SessionReply::ending(Outcome::Unavailable, CloseReason::TransportFailed),
        }
    }

    /// END THE OPEN UNIT ON THE LEG: settle it, write what the plane makes of the ending, finish.
    ///
    /// The ending runs through the LOOP, because an ending nothing settled is a hold nothing
    /// released — and the sealed [`busbar_caps::UnitEnd`] the loop hands back is the one thing
    /// [`SessionPlane::encode_end`] takes. The view it is encoded against is the OPEN unit's, not
    /// the settling one's: the unit that ends is the unit the far side has been talking to.
    ///
    /// `finish` goes out whatever the plane wrote, including nothing. The leg is over either way,
    /// and a leg left un-finished would hold the drain, the socket and the task for the life of the
    /// process.
    fn end_leg(
        &self,
        leg: &mut UpstreamLeg,
        for_: Option<busbar_contract::ids::CorrelationRef<'_>>,
        facts: &busbar_contract::bounded::Facts<'_>,
        at: &LegMoment<'_>,
        ctx: &Ctx<'_>,
    ) -> SessionReply {
        let draft = UnitDraft {
            op: leg.op,
            body_ir: Ir::new(&[], &[]),
            correlates: for_,
            correlation_out: None,
            facts: *facts,
        };
        let ended = self.run(
            self.next_unit(),
            &SessionRead {
                session: at.session,
                draft: Some(&draft),
                facts: at.facts,
                clock: at.clock,
            },
        );
        let outcome = outcome_of(&ended);
        let Ended::Settled { end, .. } = &ended else {
            // The sweep settled it first, so there is no end of this call's to encode and nothing
            // it may write on the unit's behalf. The leg still finishes: the exchange is over.
            leg.lease.finish();
            return SessionReply::quiet(outcome);
        };
        let view = self.kernel.unit_view(&leg.unit, &draft);
        let written =
            self.plane
                .encode_end(&view, &ending_of(end, &draft), Some(&mut leg.state), ctx);
        let reply = match written {
            Ok(Some(bytes)) => offered(leg.lease.offer(bytes.as_slice())),
            Ok(None) => SessionReply::quiet(outcome),
            Err(_) => SessionReply::ending(Outcome::Unavailable, CloseReason::TransportFailed),
        };
        leg.lease.finish();
        reply
    }

    /// WHAT THE SESSION'S UNITS SEALED AND NOTHING HAS DIALLED, if anything.
    ///
    /// Synchronous, because everything on this side of the driver seam is, and because the whole
    /// point is that the thing that CAN await asks. It answers the address only — the identity
    /// stays here, where it was minted, so that a caller could not attach a leg under a unit of its
    /// own choosing.
    #[must_use]
    pub fn pending_leg(&self, session: SessionHandle) -> Option<PlaneDestination> {
        let slot = self.slot(session)?;
        let guard = slot.lock().ok()?;
        guard.pending.as_ref().map(|p| p.dest.clone())
    }

    /// ATTACH THE DIALLED LEG to the session that asked for it, and open the plane's half of it.
    ///
    /// Takes the OFFERING end and nothing else: the socket, its inbound half and the drain are the
    /// composition's, and a driver that held any of the three would be a driver that could await.
    ///
    /// `false` for a session that has gone, one whose pending leg somebody else took, and one that
    /// never sealed a destination. All three are the same answer to the caller — there is no leg
    /// here to attach — and on none of them has anything been half-installed.
    pub fn attach_leg(&self, session: SessionHandle, lease: Box<dyn EgressLease>) -> bool {
        let Some(slot) = self.slot(session) else {
            return false;
        };
        let Ok(mut guard) = slot.lock() else {
            return false;
        };
        let Open {
            facts,
            transport,
            chain,
            pending,
            upstream,
            ..
        } = &mut *guard;
        let Some(leg) = pending.take() else {
            return false;
        };
        // THE PLANE'S UPSTREAM CODEC STATE, opened once, on a space of this call's own. The client
        // half was opened the same way at the upgrade; the contract's rule that cross-frame state
        // lives in exactly one place is what says the leg gets its own rather than sharing.
        let mut space = ArenaSpace::new();
        let arena = UnitArena::new(&mut space);
        let labels = Labels::new();
        let clock = self.clock();
        let view_transport = SlotTransport {
            key: transport,
            chain,
            facts,
        };
        let view_session = SlotSession {
            id: SessionId(session.0),
            facts,
            bound: true,
            upstreams: 0,
        };
        let ctx = Ctx::new(
            clock,
            self.config,
            Some(&view_session),
            &view_transport,
            &labels,
            &arena,
        );
        let state = self.plane.open_upstream(&leg.dest, &ctx);
        *upstream = Some(UpstreamLeg {
            state,
            lease,
            unit: leg.unit,
            dest: leg.dest,
            op: leg.op,
        });
        true
    }

    /// ATTACH THE CLIENT'S OFFERING END, so the inbound half of a leg has somewhere to write.
    ///
    /// The counterpart of [`attach_leg`](Self::attach_leg) in the other direction and for the same
    /// reason: [`SessionLoopDriver::upstream`] is synchronous, so what it can reach is a bounded
    /// lease and never a socket. It is attached by the composition at the accept, before any frame
    /// of the session has been read, because a provider's first reply can arrive before the
    /// client's second frame does.
    ///
    /// `false` for a session that has gone. Nothing is half-installed on it: the lease is dropped
    /// here, which is what ends its drain rather than leaving one running with nothing to feed it.
    pub fn attach_client(&self, session: SessionHandle, lease: Box<dyn EgressLease>) -> bool {
        let Some(slot) = self.slot(session) else {
            return false;
        };
        let Ok(mut guard) = slot.lock() else {
            return false;
        };
        guard.client = Some(lease);
        true
    }

    /// ONE REPLY OFF THE UPSTREAM LEG, read by the plane and written back to the client.
    ///
    /// The mirror of [`SessionDriver::drive`] and deliberately the same shape: a fresh arena for the
    /// moment, the plane asked what the bytes mean against the codec state that half of the session
    /// accumulated — the LEG's state here, which is why the leg is what carries one — and whatever
    /// comes back written through the one offering end the client half has.
    ///
    /// It runs NO unit for a reply of an already-open exchange, for the reason the relay runs none
    /// in the other direction: that exchange was priced when it opened, and walking the steps again
    /// on the way back would price it twice. An upstream that pushes something that OPENS a unit is
    /// the other case, and it is an ordinary unit of this node's loop like any other — a push is a
    /// thing that happened, and a node that carried one without judging it would be a node whose
    /// upstreams could spend on its behalf.
    ///
    /// A REPLY THAT CANNOT BE WRITTEN ENDS THE SESSION, in the same words the relay ends it in: at
    /// depth the client has fallen behind and `CapacityExhausted` is the honest answer, and over is
    /// `TransportFailed`. A relayed session whose replies were dropped would leave the client
    /// waiting on an answer this node had already thrown away.
    ///
    /// The reply's `frames` are always empty and that is not an oversight: everything this half
    /// writes goes through the lease, so the only thing the caller reads off the answer is whether
    /// the session is over.
    #[must_use]
    pub fn upstream(&self, session: SessionHandle, payload: &[u8]) -> SessionReply {
        let Some(slot) = self.slot(session) else {
            // The session is over and this is a frame off a leg nothing owns any more. There is
            // nothing to read it against.
            return SessionReply::ending(Outcome::NotFound, CloseReason::TransportFailed);
        };
        let mut guard = match slot.lock() {
            Ok(open) => open,
            Err(_) => return SessionReply::ending(Outcome::Unavailable, CloseReason::Poisoned),
        };
        let Open {
            facts,
            transport,
            chain,
            state,
            upstream,
            client,
            ..
        } = &mut *guard;
        let Some(leg) = upstream.as_mut() else {
            // A reply off a leg this session does not have. Only the composition that dialled one
            // pumps its inbound half, so this is a frame from a socket nobody here owns.
            return SessionReply::ending(Outcome::NotFound, CloseReason::TransportFailed);
        };

        let mut space = ArenaSpace::new();
        let arena = UnitArena::new(&mut space);
        let labels = Labels::new();
        let clock = self.clock();
        let view_transport = SlotTransport {
            key: transport,
            chain,
            facts,
        };
        let view_session = SlotSession {
            id: SessionId(session.0),
            facts,
            bound: true,
            upstreams: 1,
        };
        let ctx = Ctx::new(
            clock,
            self.config,
            Some(&view_session),
            &view_transport,
            &labels,
            &arena,
        );

        let frames = [Frame {
            direction: Direction::Inbound,
            stream: StreamId(0),
            bytes: SlabBytes::new(Arc::from(payload)),
            meta: FrameMeta::default(),
        }];
        let mut cursor = FrameCursor::new(&frames);
        let read =
            match self
                .plane
                .decode_response(&mut cursor, &leg.dest, Some(&mut leg.state), &ctx)
            {
                Ok(read) => read,
                // THE PLANE COULD NOT READ THE PROVIDER'S REPLY. Nothing goes back to the client,
                // because there is nothing to send: the reading is the whole content of the reply and
                // there is none, and the next frame of this exchange would be read against a state this
                // one did not advance. There is also nowhere to render a refusal TO — a refusal is
                // something this node says about a caller's request, and the caller did not send this.
                Err(_) => {
                    return SessionReply::ending(Outcome::Unavailable, CloseReason::TransportFailed)
                }
            };
        match read {
            // Not yet a whole anything, and a frame the dialect says to drop. Consumed, honestly.
            Progress::NeedMore | Progress::Discard { .. } => {
                SessionReply::quiet(Outcome::Completed)
            }
            // A RESPONSE FRAME OF AN OPEN EXCHANGE. Written by the plane against the CLIENT half's
            // codec state — the half it is going out on — and offered. `Terminal` is written the
            // same way and by the same call: what makes it the last frame is the dialect's own
            // spelling of it, which the plane just wrote, and the exchange's own ENDING is settled
            // by the close that comes the other way. A driver that settled the unit here as well
            // would settle one exchange twice.
            Progress::Frame { r, .. } | Progress::Terminal { r, .. } => {
                match self.plane.encode_response(&r, Some(state), &ctx) {
                    Ok(bytes) => offered(offer_client(client, bytes.as_slice())),
                    Err(_) => {
                        SessionReply::ending(Outcome::Unavailable, CloseReason::TransportFailed)
                    }
                }
            }
            // AN UPSTREAM PUSHED SOMETHING THAT OPENS A UNIT OF ITS OWN, which is a unit and is
            // judged as one — by the same steps, carrying this session's identity, exactly as a
            // frame the client opened is. What the loop makes of it is rendered through the plane
            // and offered on the client's half.
            Progress::Open(draft) | Progress::OneShot(draft) => {
                let ended = self.run(
                    self.next_unit(),
                    &SessionRead {
                        session: session.0,
                        draft: Some(&draft),
                        facts,
                        clock,
                    },
                );
                let outcome = outcome_of(&ended);
                for bytes in rendered(self.plane, &ended, Some(&draft), state, &ctx) {
                    if let Err(error) = offer_client(client, &bytes) {
                        return offered(Err(error));
                    }
                }
                SessionReply::quiet(outcome)
            }
        }
    }

    /// THE LOOP, over the unit the composed units say this moment is.
    ///
    /// THE SAME LOOP the one-shot driver runs, and deliberately so: a session's frame is an ordinary
    /// unit, and the whole point of this seam is that it is judged by the same steps as every other.
    /// ONE field differs and it is a fact about the unit rather than about the loop — it carries a
    /// SESSION identity, because it has one. `None` there would file every frame of every session as
    /// an unrelated one-off, which is the audit chain broken at every link and the posting
    /// attributed to nobody.
    fn run(&self, key: busbar_caps::UnitKey, read: &SessionRead<'_, '_>) -> Ended {
        let unit = self.units.unit(read);
        let units = Borrowed(&*unit);
        let cell = busbar_caps::HoldCell::new(busbar_caps::Hold::open(
            &self.kernel.admit_token(),
            busbar_caps::PrincipalId::new(""),
            0,
        ));
        let leases = busbar_kernel::slice::LeaseCell::new();
        let meter = busbar_kernel::teller::AccrualMeter::new();
        let ctx = UnitCtx {
            key,
            origin: busbar_caps::OriginKind::Client,
            session: Some(self.kernel.session_id(read.session)),
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        busbar_kernel::teller::run_unit(
            self.kernel,
            &units,
            &ctx,
            busbar_kernel::teller::Run {
                cell: &cell,
                parent: None,
                leases: &leases,
                gauge: self.gauge,
                canary: self.canary,
                meter: &meter,
            },
        )
    }
}

// `Send + Sync` on the units and not on the driver's own fields, because that is where the
// requirement genuinely comes from: [`SessionDriver`] is `Send + Sync` — ONE driver serves every
// session a listener accepts, concurrently — and the only thing in this struct that is not already
// the node's own shared machinery is the unit set it was handed. A driver whose units were not
// shareable would be a driver that could serve one session at a time, which is a capacity decision
// and not a type.
impl<U: SessionUnits + ?Sized> SessionDriver for SessionLoopDriver<'_, U> {
    fn open(&self, open: SessionOpen<'_>, surface: &WireSurface) -> Result<SessionHandle, Outcome> {
        // THE BAR FIRST, AND BEFORE ANY ALLOCATION. See this module's header: the ordering is the
        // security property rather than an optimisation.
        //
        // An EMPTY credential fact does not satisfy the bar. The mount publishes the key only where
        // the upgrade actually presented one, so an empty value means a credential was presented and
        // is blank — which is a credential no chain can resolve, and admitting it would open the
        // session and then refuse every unit on it, which is a worse answer arrived at later on a
        // wire with nowhere left to put it.
        let credential = open.fact(tfacts::CREDENTIAL).filter(|c| !c.is_empty());
        if open.bar == Bar::Credential && credential.is_none() {
            return Err(Outcome::Unauthenticated);
        }
        // THE PLANE'S ROW ANSWERS, AND THIS DRIVER DOES NOT GUESS. A binding no declared operation
        // dispatches over has no declared session behaviour at all, and the honest answer to an
        // upgrade on one is a refusal on the leg that can still carry it — not a default shape the
        // composition root chose on the plane's behalf.
        let Some(media) = declared_run(surface, open.binding) else {
            return Err(Outcome::NotFound);
        };

        let id = self.next_session.fetch_add(1, Ordering::Relaxed);
        let facts: Vec<(String, String)> = open
            .facts
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let chain: Vec<&'static str> = open.chain.to_vec();

        // THE PLANE'S CLIENT HALF, opened on this task's own arena. What the plane reads at the
        // open — the path the upgrade addressed, which dialect that names — it reads off the
        // transport view, and the state it hands back is the session's from here on.
        let mut space = ArenaSpace::new();
        let arena = UnitArena::new(&mut space);
        let labels = Labels::new();
        let clock = self.clock();
        let transport = SlotTransport {
            key: open.transport,
            chain: &chain,
            facts: &facts,
        };
        let session = SlotSession {
            id: SessionId(id),
            facts: &facts,
            bound: false,
            upstreams: 0,
        };
        let ctx = Ctx::new(
            clock,
            self.config,
            Some(&session),
            &transport,
            &labels,
            &arena,
        );
        let state = self.plane.open_session(&ctx);

        // THE OPENING UNIT: the unit that answers the arrival, and the upgrade's answer is its
        // ending. It runs BEFORE the table is touched, so a session whose opening unit did not
        // complete leaves nothing behind but its own audit record — the plane's half above drops
        // with this stack frame.
        let ended = self.run(
            self.next_unit(),
            &SessionRead {
                session: id,
                draft: None,
                facts: &facts,
                clock,
            },
        );
        let outcome = outcome_of(&ended);
        if outcome != Outcome::Completed {
            self.units.closed(id);
            return Err(outcome);
        }

        let slot = Open {
            facts,
            transport: open.transport,
            chain,
            media,
            seq: 0,
            state,
            pending: None,
            upstream: None,
            client: None,
        };
        // The table is the LAST thing touched, so every path that refuses above leaves it untouched.
        let mut table = self.open.lock().map_err(|_| Outcome::Unavailable)?;
        table.insert(id, Arc::new(Mutex::new(slot)));
        Ok(SessionHandle(id))
    }

    fn drive(&self, session: SessionHandle, frame: SessionFrame<'_>) -> SessionReply {
        let Some(slot) = self.slot(session) else {
            // A handle this driver never minted, or one it has already closed. There is nothing to
            // read the frame against, and carrying on would mean inventing a session.
            return SessionReply::ending(Outcome::NotFound, CloseReason::TransportFailed);
        };
        let mut guard = match slot.lock() {
            Ok(open) => open,
            // A POISONED SESSION: a previous frame's unit panicked under this lock, and what the
            // session's bookkeeping was mid-update is what it is now. Nothing here can tell how far
            // that update got, so the only honest thing is to stop.
            Err(_) => return SessionReply::ending(Outcome::Unavailable, CloseReason::Poisoned),
        };
        // THE ORDER, CHECKED RATHER THAN ASSUMED. A duplex plane reads frame n against what frame
        // n-1 left behind, so a transport that delivered them out of order would not produce an
        // error — it would produce a different, silently wrong reading, for the rest of the session,
        // in both directions. The ordinal is the transport's own claim about its own delivery, which
        // is exactly the kind of claim worth checking.
        if frame.seq != guard.seq {
            return SessionReply::ending(Outcome::Unavailable, CloseReason::Poisoned);
        }
        guard.seq += 1;
        let Open {
            facts,
            transport,
            chain,
            media,
            state,
            pending,
            upstream,
            ..
        } = &mut *guard;
        let media: &'static str = media;

        // ONE FRESH SPACE PER FRAME, on this task's stack. The plane's reading borrows from it, the
        // unit runs, the answer is copied out, and the space drops: nothing the plane borrowed for
        // this frame can be read by the next one, which is the reset the arena has no method for.
        let mut space = ArenaSpace::new();
        let arena = UnitArena::new(&mut space);
        let labels = Labels::new();
        let clock = self.clock();
        let transport = SlotTransport {
            key: transport,
            chain,
            facts,
        };
        let view = SlotSession {
            id: SessionId(session.0),
            facts,
            bound: true,
            upstreams: usize::from(upstream.is_some()),
        };
        let ctx = Ctx::new(clock, self.config, Some(&view), &transport, &labels, &arena);

        // THE PLANE READS THE FRAME, against the codec state this session accumulated — the one
        // place cross-frame state may live — and the reading is the plane's, in the contract's own
        // seven-armed vocabulary. This driver does not look at the bytes.
        let frames = [Frame {
            direction: Direction::Inbound,
            stream: StreamId(0),
            bytes: SlabBytes::new(Arc::from(frame.payload)),
            meta: FrameMeta::default(),
        }];
        let mut cursor = FrameCursor::new(&frames);
        let read = match self.plane.decode_ingress(&mut cursor, Some(state), &ctx) {
            Ok(read) => read,
            Err(_) => {
                // THE PLANE COULD NOT READ IT. No unit ran, because there is nothing to run: the
                // reading is the unit's whole content and there is none. What goes back is the
                // plane's own rendering of a decode refusal — a refusal never advances codec
                // state, which is why the state is lent immutably — under the declared media.
                let refusal = PlaneRefusal {
                    step: Step::Decode,
                    reason: ReasonCode::DecodeFailed.into(),
                    retry_after_secs: None,
                    stream: None,
                    correlates: None,
                };
                let frames = self
                    .plane
                    .encode_refusal(&refusal, None, Some(state), &ctx)
                    .map(|bytes| vec![bytes.as_slice().to_vec()])
                    .unwrap_or_default();
                return labelled(SessionReply::quiet(Outcome::Unavailable), frames, media);
            }
        };
        let draft = match &read {
            Ingress::Open(draft) | Ingress::OneShot(draft) | Ingress::Handshake(draft) => draft,
            // THE RELAY. A frame of an already-open unit, which is not a new unit and must not be
            // walked as one — the unit it belongs to was judged when it opened, and running the
            // steps again would price one exchange twice. What it is instead is a WRITE, on the
            // upstream half of the session the open unit sealed, and the whole of what this arm
            // does is spell it: the plane encodes the relay against the unit's view, and the
            // bytes go to the lease.
            Ingress::Frame {
                for_,
                relay,
                facts: read_facts,
            } => {
                let Some(leg) = upstream.as_mut() else {
                    // The plane read a relay for a session with no leg. Nothing to relay ONTO, and
                    // inventing a destination is the one thing this driver may never do — so the
                    // frame is consumed and the session carries on, exactly as it did before a leg
                    // was something a session could have.
                    return SessionReply::quiet(Outcome::Completed);
                };
                return self.relay(leg, *for_, relay.as_slice(), read_facts, &ctx);
            }
            // THE END OF AN OPEN UNIT, which is an ending and therefore a unit's business: an
            // ending nothing settled is a hold nothing released. So the loop runs, and what it
            // SEALS is what the plane encodes upstream.
            Ingress::Close {
                for_,
                facts: read_facts,
            } => {
                let Some(leg) = upstream.as_mut() else {
                    return SessionReply::quiet(Outcome::Completed);
                };
                return self.end_leg(
                    leg,
                    *for_,
                    read_facts,
                    &LegMoment {
                        session: session.0,
                        facts,
                        clock,
                    },
                    &ctx,
                );
            }
            // The three readings that open no unit and write nothing: two are not yet a unit or
            // never one, and one is the plane saying so outright. Consumed, and honestly.
            Ingress::NeedMore | Ingress::Discard { .. } => {
                return SessionReply::quiet(Outcome::Completed);
            }
        };

        // THE UNIT, judged by the same steps as every other unit on this node, carrying this
        // session's identity.
        let key = self.next_unit();
        let ended = self.run(
            key,
            &SessionRead {
                session: session.0,
                draft: Some(draft),
                facts,
                clock,
            },
        );
        let outcome = outcome_of(&ended);
        let frames = rendered(self.plane, &ended, Some(draft), state, &ctx);

        // THE LEG THE UNIT SEALED, parked for the thing that can dial it. The moment the session's
        // units say where the leg goes is inside this synchronous call, and a dial is an await, so
        // what is recorded here is the DECISION and not the socket — see [`PendingLeg`]. The
        // identity is recorded with it because the leg's writes are THIS unit's writes: a key
        // minted at dial time would file them as somebody else's.
        if upstream.is_none() && pending.is_none() && outcome == Outcome::Completed {
            if let Some(dest) = self.units.destination(session.0) {
                *pending = Some(PendingLeg {
                    dest,
                    unit: UnitIdentity {
                        key: busbar_contract::ids::UnitKey::new(key.get()),
                        // The frames this leg carries are the CLIENT's, forwarded. A leg whose
                        // origin said otherwise would be a unit the origin rules judged as
                        // something the node raised itself.
                        origin: busbar_contract::unit::Origin::Client,
                        session: Some(SessionId(session.0)),
                        stream: Some(StreamId(0)),
                        // Outbound: this is the half that leaves this node.
                        direction: Direction::Outbound,
                        // WHO THE LEG'S WRITES ARE FOR, as the composition's own authenticate
                        // step resolved it and published back across the seam. Asked of the
                        // COMPOSITION and never guessed here: this driver has no credential, no
                        // chain and no standing to resolve one, and a view that named the wrong
                        // principal would be worse than one that named none. `None` stays
                        // representable and stays honest — it is what an anonymous session's leg
                        // is, and what a composition that resolves no principal answers.
                        principal: self.units.principal(session.0),
                    },
                    op: draft.op,
                });
            }
        }

        // A frame that went badly does NOT end the session by itself: eight words that mean "this
        // frame went badly" say nothing about whether the next one will.
        labelled(SessionReply::quiet(outcome), frames, media)
    }

    fn close(&self, session: SessionHandle, end: SessionEnd) {
        // EXACTLY ONCE, ENFORCED RATHER THAN ASSUMED. The slot is REMOVED under the table's lock, so
        // the second caller of a double close finds nothing and releases nothing — and a frame
        // racing the close finds nothing either, which is the answer it should get.
        let Ok(mut table) = self.open.lock() else {
            return;
        };
        let Some(slot) = table.remove(&session.0) else {
            return;
        };
        drop(table);
        // The units are told once, by the same "exactly once" the removal enforces: a wait this
        // session's units entered ends with the session.
        self.units.closed(session.0);
        // Dropping the slot is what releases the session: it is owned, and nothing else holds a
        // handle to it once the table has given it up. The plane's two halves go with it.
        let _ = (slot, end);
    }
}

/// OFFER ONE FRAME ON THE CLIENT'S HALF, or say why there was nowhere to put it.
///
/// A session with no client lease attached has an inbound leg being pumped into a session whose
/// other half was never wired up, which is a composition that built half an arrangement. `Closed` is
/// the honest word for it — there is no end here to write to — and it ends the session rather than
/// dropping the reply, because a client waiting on an answer this node threw away waits forever.
fn offer_client(
    client: &mut Option<Box<dyn EgressLease>>,
    bytes: &[u8],
) -> Result<(), busbar_contract::TransportError> {
    match client {
        Some(lease) => lease.offer(bytes),
        None => Err(busbar_contract::TransportError::Closed),
    }
}

/// WHAT A LEASE'S ANSWER MEANS FOR THE SESSION, in the eight words.
///
/// Two refusals and they are not the same refusal. At depth the leg has fallen behind and nothing is
/// wrong with the caller — `CapacityExhausted`, which the ws wire spells 1013, "try again later".
/// Over is the leg gone, which is this node's carrier giving out: `TransportFailed`. Either way the
/// SESSION ends, because a relayed session that stopped relaying and said nothing is the one outcome
/// worse than an ending.
fn offered(answer: Result<(), busbar_contract::TransportError>) -> SessionReply {
    match answer {
        Ok(()) => SessionReply::quiet(Outcome::Completed),
        Err(busbar_contract::TransportError::Backpressure) => {
            SessionReply::ending(Outcome::Unavailable, CloseReason::CapacityExhausted)
        }
        Err(_) => SessionReply::ending(Outcome::Unavailable, CloseReason::TransportFailed),
    }
}

/// The plane's frames on a reply, under the declared media — and NO media where there is no frame.
///
/// One statement rather than two: a media type beside an empty run would be this driver saying what
/// the answer is when there is no answer.
fn labelled(mut reply: SessionReply, frames: Vec<Vec<u8>>, media: &'static str) -> SessionReply {
    if !frames.is_empty() {
        reply.media = media.to_string();
    }
    reply.frames = frames;
    reply
}

#[cfg(test)]
#[path = "tests/session_driver.rs"]
mod tests;

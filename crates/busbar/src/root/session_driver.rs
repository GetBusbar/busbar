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

//! RUNNING A DECLARED SESSION'S FRAMES OVER THE KERNEL'S UNIT LOOP: one driver, no plane's name.
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
//! ## THE PLANE IS NEVER NAMED, AND ITS BEHAVIOUR IS NOT SPELLED HERE EITHER
//!
//! What a session of a particular binding IS comes off that plane's own registered row — its
//! [`WireSurface`], the same declaration [`crate::root::plane_mount`] mounts and the transport
//! addresses upgrades against. [`declares_a_run`] is the whole of what this driver reads out of it,
//! and the answer decides whether there is a session here to run at all: a binding no declared
//! operation dispatches over has no declared session behaviour, and an upgrade on one is refused on
//! the leg that can still carry a refusal rather than opened onto a shape the composition root
//! picked on the plane's behalf.
//!
//! **THERE IS EXACTLY ONE SHAPE, AND THE CONTRACT'S OWN BOOT CHECK IS WHY.** A duplex row declared
//! [`Answering::Unary`] is refused by
//! [`check_surface`](busbar_contract::transport::surface::check_surface) before any listener binds
//! — a session whose first answer is its last is a session cut at its first answer — so every
//! mountable duplex binding in this tree declares a RUN, and one inbound frame is one unit of the
//! loop. A `match` here over the answering shape would be a second opinion about a question the
//! declaration vocabulary has already closed, and the arm that disagreed would be the arm no
//! surface could ever reach.
//!
//! There is no plane name, no dialect, no protocol and no wire in this file, and no `match` on any
//! of them. A second duplex plane lands without a line here changing.
//!
//! ## The three moments, and what each one is the only place for
//!
//! **[`SessionDriver::open`]** is the ONLY moment a refusal is answerable on the wire the upgrade
//! arrived on; after it the protocol has changed and there is no status field left. So the credential
//! bar the DECLARATION put on the binding is resolved here, against the facts the mount published,
//! and a bar with nothing to satisfy it is refused in the eight words BEFORE anything is allocated.
//! A refused open that had already carved out a session's state would be a stranger choosing how
//! much of this node's memory an unauthenticated upgrade occupies.
//!
//! **[`SessionDriver::drive`]** runs one inbound frame as an ordinary unit of the kernel's own loop
//! — the same steps the one-shot path walks — carrying the SESSION's identity on the unit's context,
//! which is what files the frame's posting and its audit link against the session it belongs to
//! rather than as an unrelated one-off. The frame's own ordinal travels with it and is CHECKED,
//! because a duplex plane's state machine reads frame *n* against what frame *n-1* left behind and
//! an out-of-order delivery is otherwise reinterpreted rather than detected.
//!
//! **[`SessionDriver::close`]** releases what `open` allocated, on every ending including the ugly
//! ones. Exactly once per handle, and the "exactly" is enforced here rather than assumed of the
//! caller: the slot is REMOVED from the table under the lock, so a second close finds nothing and a
//! concurrent frame finds nothing either.
//!
//! ## What the credential bar can and cannot decide here
//!
//! It decides whether a session may be OPENED at all with what the caller presented — a declared
//! [`Bar::Credential`] and no credential fact is a refusal, and that is the whole of it. It does NOT
//! decide who the caller is. Resolving a credential to a principal is the authenticate step's, it
//! runs inside the loop, on every unit, with the credential this session carries; a driver that
//! resolved one itself would be a second authenticator beside the node's, answering the one question
//! the unit chain exists to answer.
//!
//! ## TWO LOCKS, and the outer one is never held across a unit
//!
//! The table is locked only long enough to clone one session's own lock out of it, so a long frame
//! on one session does not stop a second session from opening. The inner lock is what makes ONE
//! session's frames serial, which they have to be — an ordinal read by two frames at once is an
//! ordinal neither of them can reason about.
//!
//! A POISONED SESSION STOPS. The inner lock is held for exactly the span in which a frame's unit
//! runs, so a panic in there poisons it, and a session read on from an unknown point hands the far
//! side a state machine that silently disagrees with this one. The word is
//! [`CloseReason::Poisoned`], which the ws wire spells 1011 — this node saying the fault was its
//! own, which it is, rather than telling a well-behaved client to go and change its behaviour.
//!
//! ## WHAT THIS DRIVER DOES NOT DO YET, said plainly
//!
//! It runs the loop, carries the session identity, and maps the ending. It does NOT call the plane,
//! so the frames it answers with are EMPTY — for the same two reasons
//! [`crate::root::transports::LoopDriver`] states, and neither of them is this file's to fix: there
//! is no per-unit arena that ships, so there is nothing to build a plane `Ctx` around, and
//! `ProductionUnits` answers every non-admin step with a refusal. Wiring it half-built and calling
//! it served would be the failure this whole seam exists to prevent, so it answers honestly instead:
//! the loop really runs, the ending really is the loop's, the session identity really is on the
//! unit, and there is no frame back because no plane was asked. The declared media type is read at
//! the same moment the frames are — which is to say, not yet, and by the same commit.
//!
//! ## Money untouched, by construction
//!
//! The loop's own units do the arithmetic, unchanged, and this file adds nothing to and takes
//! nothing from what a unit costs. The switch is default-off and no call site names this module
//! without it, so the shipped binary is byte-identical.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::transport::driver::Outcome;
use busbar_contract::transport::facts as tfacts;
use busbar_contract::transport::session::{
    SessionDriver, SessionEnd, SessionFrame, SessionHandle, SessionOpen, SessionReply,
};
use busbar_contract::transport::surface::{Answering, Bar, Dispatch, WireSurface};
use busbar_contract::wire::CloseReason;
use busbar_kernel::teller::Units;

use crate::root::transports::outcome_of;

// ── the plane's session behaviour, as the plane's own row declares it ────────────────────────────

/// WHETHER A BINDING'S ROW DECLARES A SESSION THIS DRIVER CAN RUN.
///
/// The one thing this driver reads out of a plane's declaration, and the one it cannot proceed
/// without. True exactly where some declared operation dispatches over the binding in the duplex
/// kind and answers [`Answering::Stream`] — which is to say, where the plane said that one open
/// carries a run of answers.
///
/// **The `Stream` is checked rather than assumed, and there is deliberately no second arm.** A
/// duplex row declared [`Answering::Unary`] never reaches a mount at all:
/// [`check_surface`](busbar_contract::transport::surface::check_surface) refuses the whole surface
/// at boot, because a session whose first answer is its last is a session cut at its first answer.
/// So the word is read here as the CONDITION for running the binding rather than as a switch
/// between two behaviours — a driver that quietly accepted `Unary` and then ran it as a run would be
/// serving a surface the boot check exists to keep off this node.
#[must_use]
pub fn declares_a_run(surface: &WireSurface, binding: &str) -> bool {
    surface.operations.iter().any(|op| {
        op.answering == Answering::Stream
            && op
                .dispatch
                .iter()
                .any(|d| matches!(d, Dispatch::Duplex { binding: b, .. } if *b == binding))
    })
}

// ── what one open session is ────────────────────────────────────────────────────────────────────

/// Everything one open session holds, and the only thing that outlives a frame.
struct Open {
    /// The facts the mount published at the upgrade, OWNED so they outlive the upgrade.
    ///
    /// Owned rather than borrowed, and that is forced rather than chosen: the strings the mount
    /// published point into a request buffer that is freed the moment the upgrade completes. A
    /// session that kept the borrow would be reading a buffer somebody else is refilling.
    facts: Vec<(String, String)>,
    /// The next inbound ordinal this session expects.
    ///
    /// This driver's own, and the evidence that the transport delivered the session IN ORDER.
    seq: u64,
}

// ── the driver a duplex acceptor hands each open session to ─────────────────────────────────────

/// WHAT RUNS A DECLARED SESSION'S FRAMES, on the root's side of the duplex transport seam.
///
/// Everything a transport is not allowed to hold is held here: the kernel seal, the units the steps
/// run against, the gauge, the canary and the table of open sessions. What the transport gets back
/// is a number.
///
/// GENERIC OVER THE UNITS, for the reason [`crate::root::plane_mount`] is generic over the wire: a
/// driver written against one concrete unit set would be a driver that named what it drives, and the
/// kernel's own loop is already generic over exactly this. There is no plane here to be generic
/// over, because there is no plane here at all.
pub struct SessionLoopDriver<'n, U: Units> {
    kernel: &'n busbar_kernel::teller::Kernel,
    units: &'n U,
    gauge: &'n busbar_kernel::slice::ConcurrencyGauge,
    canary: &'n busbar_caps::Canary,
    next_key: AtomicU64,
    next_session: AtomicU64,
    /// The open sessions, by the handle this driver minted. See this module's header on the two
    /// locks and on why the outer one is never held across a unit.
    open: Mutex<HashMap<u64, Arc<Mutex<Open>>>>,
}

impl<U: Units> std::fmt::Debug for SessionLoopDriver<'_, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionLoopDriver")
    }
}

impl<'n, U: Units> SessionLoopDriver<'n, U> {
    /// Bind the driver to the node's own kernel, units, gauge and canary.
    ///
    /// By reference and not by value, for the reason the one-shot driver takes them by reference:
    /// one driver serves every session every listener accepts, and the counts the canary balances
    /// are node-wide. A driver that owned a copy would be balancing its own books beside the node's.
    #[must_use]
    pub fn new(
        kernel: &'n busbar_kernel::teller::Kernel,
        units: &'n U,
        gauge: &'n busbar_kernel::slice::ConcurrencyGauge,
        canary: &'n busbar_caps::Canary,
    ) -> Self {
        Self {
            kernel,
            units,
            gauge,
            canary,
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

    /// THE LOOP, against whatever units this driver was composed with.
    ///
    /// THE SAME LOOP the one-shot driver runs, and deliberately so: a session's frame is an ordinary
    /// unit, and the whole point of this seam is that it is judged by the same steps as every other.
    /// ONE field differs and it is a fact about the unit rather than about the loop — it carries a
    /// SESSION identity, because it has one. `None` there would file every frame of every session as
    /// an unrelated one-off, which is the audit chain broken at every link and the posting
    /// attributed to nobody.
    fn run(&self, session: u64) -> busbar_kernel::teller::Ended {
        let key = self.next_unit();
        let cell = busbar_caps::HoldCell::new(busbar_caps::Hold::open(
            &self.kernel.admit_token(),
            busbar_caps::PrincipalId::new(""),
            0,
        ));
        let leases = busbar_kernel::slice::LeaseCell::new();
        let meter = busbar_kernel::teller::AccrualMeter::new();
        let ctx = busbar_kernel::teller::UnitCtx {
            key,
            origin: busbar_caps::OriginKind::Client,
            session: Some(self.kernel.session_id(session)),
            generation: busbar_kernel::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        busbar_kernel::teller::run_unit(
            self.kernel,
            self.units,
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
impl<U: Units + Send + Sync> SessionDriver for SessionLoopDriver<'_, U> {
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
        if !declares_a_run(surface, open.binding) {
            return Err(Outcome::NotFound);
        }

        let id = self.next_session.fetch_add(1, Ordering::Relaxed);
        let slot = Open {
            facts: open
                .facts
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            seq: 0,
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
        let mut open = match slot.lock() {
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
        if frame.seq != open.seq {
            return SessionReply::ending(Outcome::Unavailable, CloseReason::Poisoned);
        }
        open.seq += 1;
        // The payload is the PLANE's to read and no plane is asked yet, so it is not read here — see
        // this module's header. It is named rather than ignored because the frame's bytes are what
        // the next commit hands the plane, and a parameter silently dropped is the one a reader
        // assumes was used.
        let _ = frame.payload;

        let ended = self.run(session.0);
        SessionReply {
            // NO FRAME, and honestly. The loop really ran and the ending really is the loop's; what
            // goes back out is the plane's, and no plane was asked.
            frames: Vec::new(),
            // Empty for the same reason, and the two are one statement rather than two: a media type
            // beside an empty run would be this driver saying what the answer is when there is no
            // answer. What the declaration names for this binding's frames is read by the commit
            // that has a frame to put it on.
            media: String::new(),
            outcome: outcome_of(&ended),
            // A frame that went badly does NOT end the session by itself: eight words that mean
            // "this frame went badly" say nothing about whether the next one will.
            close: None,
        }
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
        // Dropping the slot is what releases the session: it is owned, and nothing else holds a
        // handle to it once the table has given it up.
        let _ = (slot, end);
    }
}

#[cfg(test)]
#[path = "tests/session_driver.rs"]
mod tests;

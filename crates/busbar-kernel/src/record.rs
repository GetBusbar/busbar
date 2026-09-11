// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-UNIT RECORD: what one unit IS, for the length of one unit.
//!
//! The loop used to hand every step the same six scalars and nothing else. A step that needed
//! anything the kernel had already established — the arena, the views a plugin call is given, the
//! destinations Verify sealed, the key handle the unit dials under — had no way to reach it, so it
//! either re-derived the fact or did without. Re-deriving a verified set is the one that moves
//! money: `walk()` indexes the set by destination id, so a second derivation is a different index
//! space and a hop charged against a lane it was not sealed for.
//!
//! The record is the answer, and it is one value with one lifetime. It is built ONCE, at the
//! loop's entry, over memory the loop's own frame owns for the whole unit, and every step is lent
//! it. Nothing in it is a plane's: the views are traits the contract declares and the root fills,
//! and this file names no plane and no dialect.
//!
//! ## Why the memory is a separate value
//!
//! [`UnitMemory`] owns the 4 KiB and the span table; the record owns the [`Ctx`] built over ONE
//! lease of them. They cannot be one value, and the reason is the borrow the arena is: `lease`
//! takes `&mut self` and hands back a view that borrows what it leased, so a value holding both
//! the buffer and a context over that buffer would be a value borrowing from itself. Two values,
//! one owning and one borrowing, is the shape that compiles without `unsafe` — and it is also the
//! honest one, because the loop's frame is exactly what owns a unit's memory for a unit's life.
//!
//! ## The two facts Verify seals, and why they are sealed rather than passed
//!
//! **The verified set** is what Verify established: a `TrustToken` was lent for the length of that
//! one call, the step answered with sealed destinations, and every later step reads THAT set.
//! Sealing it here rather than threading it through three signatures is what makes "no step
//! re-derives it" a property of the type instead of a rule reviewers enforce.
//!
//! **The key handle** is a handle and never bytes — a slot number and a fingerprint. It is pinned
//! at Verify, from the generation the unit started on, so a unit finishes against the material it
//! started with while a reload installs a replacement. It is not snapshotted at compose time and
//! it is not re-read at Route: Route reads the pin.
//!
//! Both are write-once. A second write is refused by the cell rather than by a rule, so there is no
//! path on which a later step replaces what Verify established.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use busbar_caps::{
    BodyLease, Completion, ExitToken, OriginKind, Route, SessionId, TransportKeyHandle, TrustToken,
    UnitKey, UnitToken, VerifiedDestination,
};
use busbar_contract::bounded::{Arena, Labels, Span, MAX_KEYS};
use busbar_contract::unit::{Clock, ConfigView, Ctx, SessionView, StatusLeg, TransportView};

use crate::arena::{span_slab, ArenaBuf, UnitArena};
use crate::registry::Generation;
use crate::teller::UnitCtx;

/// The memory one unit owns: the 4 KiB and the span table, before either is lent.
///
/// One allocation per unit, made where the unit is set up. [`lease`](UnitMemory::lease) hands both
/// to one [`UnitArena`] and takes `&mut self` to do it, which is what makes the lease's end
/// provable rather than promised.
#[derive(Debug)]
pub struct UnitMemory<'u> {
    buf: ArenaBuf,
    spans: [(&'u str, Span); MAX_KEYS],
}

impl Default for UnitMemory<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'u> UnitMemory<'u> {
    /// A unit's memory: one 4 KiB buffer and one span table of the width a fact map is bounded to.
    #[must_use]
    pub fn new() -> Self {
        UnitMemory {
            buf: ArenaBuf::new(),
            spans: span_slab(),
        }
    }

    /// Lend the whole of it to one arena, for the unit's life.
    ///
    /// `&'u mut self` and not `&mut self`: the lease lives as long as the memory's own parameter,
    /// which is what says there is exactly one of them per unit. A relay path that resets per
    /// frame leases the [`ArenaBuf`] directly, where the reset is what re-leasing means.
    pub fn lease(&'u mut self) -> UnitArena<'u> {
        self.buf.lease(&mut self.spans)
    }

    /// Lend the SAME 4 KiB again, for one frame of a relayed unit.
    ///
    /// The second constructor, and it exists because the first one cannot be it.
    /// [`lease`](UnitMemory::lease) takes `&'u mut self` — the memory's own parameter — which is
    /// exactly what makes it once per unit: the lease and the memory end together. A relay path
    /// resets per frame, so it needs a lease whose life is the FRAME's, and the span table is why
    /// that cannot be the same call. A slot in the table is typed at the lease's lifetime, and
    /// `&'f mut [(&'u str, Span)]` cannot be shortened to `&'f mut [(&'f str, Span)]` — a mutable
    /// borrow is invariant in what it points at — so a second lease over the unit's own table
    /// would have to be a lease at the unit's lifetime again, which is the first one.
    ///
    /// So the FRAME owns the frame's table and the unit owns the bytes, and this hands both to one
    /// arena. That is the whole of the re-lease: the cursor goes back to zero over the same
    /// allocation, the reset is counted, and a session that relays for an hour is still holding the
    /// 4 KiB it was given at its first frame — which is what this module claims and what
    /// `busbar-kernel/tests/arena_reuse.rs` measures.
    pub fn relay<'f>(&'f mut self, spans: &'f mut [(&'f str, Span); MAX_KEYS]) -> UnitArena<'f> {
        self.buf.lease(spans)
    }

    /// How many times this unit's 4 KiB has been given back to itself. One per frame on a relay.
    #[must_use]
    pub fn resets(&self) -> u64 {
        self.buf.resets()
    }

    /// The most bytes any ONE lease of this unit's memory ever held at once.
    ///
    /// Across every lease and never cleared, so a relay whose high-water stops moving after the
    /// first frame is a relay that is reusing the buffer and one that climbs is one that is not.
    #[must_use]
    pub fn high_water(&self) -> usize {
        self.buf.high_water()
    }
}

/// The borrowed views a plugin call is given, as the ROOT fills them.
///
/// Kind-neutral by construction: four traits the contract declares plus the clock and the key
/// handle. The kernel never builds one — it is data that arrives on [`Run`](crate::teller::Run),
/// because what a plane's configuration block says, which transport stack is under this unit and
/// which session it belongs to are all the composition root's to know and none of them are the
/// loop's.
pub struct UnitViews<'v> {
    /// The node's read-only clock, as this unit reads it.
    pub clock: Clock,
    /// This plugin's own configuration block, and nothing else's.
    pub config: &'v dyn ConfigView,
    /// The session, on a session transport. A one-shot transport has none.
    pub session: Option<&'v dyn SessionView>,
    /// The transport stack under this unit.
    pub transport: &'v dyn TransportView,
    /// The metric labels for this unit.
    pub labels: &'v Labels<'v>,
    /// The generation's key handle, where the unit's stack was provisioned with one.
    ///
    /// A handle: a slot number and a fingerprint, never material. It is offered here and PINNED at
    /// Verify; nothing downstream of the pin reads this field.
    pub key_handle: Option<&'v TransportKeyHandle>,
}

impl std::fmt::Debug for UnitViews<'_> {
    /// Says what the views are over, never what is in them. A configuration block and a session's
    /// fact maps are the two things a log line must not print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnitViews")
            .field("clock", &self.clock)
            .field("transport", &self.transport.key())
            .field("session", &self.session.map(SessionView::id))
            .field("key_handle", &self.key_handle)
            .finish()
    }
}

/// EVERYTHING THE LOOP KNOWS ABOUT ONE UNIT, as every step is lent it.
///
/// Built once, at the loop's entry, and lent to all twelve steps. What it carries is the unit's
/// identity, the context a plugin call is given, and the two facts Verify seals.
#[derive(Debug)]
pub struct UnitRecord<'u> {
    unit: UnitCtx,
    ctx: Ctx<'u>,
    offered_key: Option<&'u TransportKeyHandle>,
    verified: OnceLock<Vec<VerifiedDestination>>,
    pinned_key: OnceLock<TransportKeyHandle>,
    body: OnceLock<BodyLease>,
    carried: OnceLock<Completion>,
    head: OnceLock<StatusLeg>,
    body_released: AtomicBool,
}

impl<'u> UnitRecord<'u> {
    /// Open a record: the unit's identity, the root's views, and one lease of the unit's memory.
    ///
    /// The one place a production [`Ctx`] is built. Every other `Ctx::new` in this tree is a test
    /// fixture, and the reason there was no production one until now is that there was no
    /// production arena for it to be built around.
    #[must_use]
    pub fn open(unit: &UnitCtx, views: &UnitViews<'u>, arena: &'u dyn Arena) -> Self {
        UnitRecord {
            unit: unit.clone(),
            ctx: Ctx::new(
                views.clock,
                views.config,
                views.session,
                views.transport,
                views.labels,
                arena,
            ),
            offered_key: views.key_handle,
            verified: OnceLock::new(),
            pinned_key: OnceLock::new(),
            body: OnceLock::new(),
            carried: OnceLock::new(),
            head: OnceLock::new(),
            body_released: AtomicBool::new(false),
        }
    }

    /// The context a plugin call is given.
    #[must_use]
    pub fn ctx(&self) -> &Ctx<'u> {
        &self.ctx
    }

    /// The unit's key.
    #[must_use]
    pub fn key(&self) -> UnitKey {
        self.unit.key
    }

    /// Where it came from.
    #[must_use]
    pub fn origin(&self) -> OriginKind {
        self.unit.origin
    }

    /// Its session, if it has one.
    #[must_use]
    pub fn session(&self) -> Option<SessionId> {
        self.unit.session
    }

    /// The registry generation it pinned when it started.
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.unit.generation
    }

    /// The unit's identity as the root filled it, for the two flags that are read by name.
    ///
    /// Named through the value rather than restated as accessors: both of the remaining flags
    /// spell a word that belongs to another kind's vocabulary, and a second spelling of either is
    /// a second place that coupling is counted from.
    #[must_use]
    pub fn unit(&self) -> &UnitCtx {
        &self.unit
    }

    /// SEAL WHAT VERIFY ESTABLISHED onto the unit, once.
    ///
    /// The trust token is what says the caller is the Verify step: sealing a destination takes it,
    /// so a set recorded here came from the one call that was lent it. The key handle the unit's
    /// generation offered is pinned in the same breath and for the same reason — the step that
    /// decided where the unit may go is the step the material it goes under is fixed at.
    ///
    /// A second call writes nothing. The set the first one sealed is what every later step reads.
    pub fn seal_verified(&self, _trust: &TrustToken, destinations: Vec<VerifiedDestination>) {
        let _ = self.verified.set(destinations);
        if let Some(handle) = self.offered_key {
            let _ = self.pinned_key.set(handle.clone());
        }
    }

    /// WHAT VERIFY ESTABLISHED, as Approve, Admit, Route and Meter read it.
    ///
    /// The empty set before Verify has answered and after a Verify that sealed nothing — which is a
    /// legitimate answer for a pool with every lane excluded, and the only one a step that runs
    /// before Verify can be given.
    #[must_use]
    pub fn verified(&self) -> &[VerifiedDestination] {
        self.verified.get().map_or(&[], Vec::as_slice)
    }

    /// THE KEY HANDLE THE UNIT DIALS UNDER, as Route and Meter read it.
    ///
    /// `None` until Verify pins it, and `None` for a unit whose stack was provisioned without one.
    /// Never bytes: the handle names a slot and carries a fingerprint, and the three units the
    /// design lets expose a secret are not reached from here.
    #[must_use]
    pub fn key_handle(&self) -> Option<&TransportKeyHandle> {
        self.pinned_key.get()
    }

    /// TAKE THE ROUTED BODY UNDER THE UNIT'S HOLD, once.
    ///
    /// What is taken is a HANDLE — a lease number naming the stream the transport is holding — and
    /// never the bytes. Taking the bytes here would mean draining the body here, and on a billing
    /// plane the instant a body finishes draining is the instant the money is read, so a record
    /// that owned the body would be deciding when a stream ended. This one names it.
    ///
    /// The Route token is what says the caller is the step that dialled: nothing before Route has
    /// one, and nothing after Route is lent one either. A second call writes nothing.
    ///
    /// The hold is NOT given back when Route returns. It is given back by
    /// [`release_body`](UnitRecord::release_body), which only the exit path can call, so the Meter
    /// step in between reads a body that is still the unit's.
    pub fn hold_body(&self, _token: &UnitToken<Route>, lease: BodyLease) -> bool {
        self.body.set(lease).is_ok()
    }

    /// Which stream the unit is holding, where it routed to one.
    #[must_use]
    pub fn body(&self) -> Option<BodyLease> {
        self.body.get().copied()
    }

    /// THE STREAM FINISHED; this is what it carried. Route step only, and once.
    ///
    /// Recorded by the relay that counted it, while it ran. Answers whether this call is the one
    /// that recorded it, so a second relay writing a second figure is visible to its caller rather
    /// than quietly ignored.
    pub fn body_finished(&self, _token: &UnitToken<Route>, carried: Completion) -> bool {
        self.carried.set(carried).is_ok()
    }

    /// WHAT THE ROUTED BODY CARRIED, as the Meter step reads it.
    ///
    /// The figure the relay counted while it ran, against the dimensions the plane declared —
    /// quantities and never an amount. No step re-derives it, because there is no second reading
    /// of the body to derive it from: the bytes were the transport's and they are gone.
    ///
    /// `None` for a unit that routed nowhere, for a body still running, and for a body whose hold
    /// the exit has already released — the last two are the same answer for the same reason,
    /// because neither is a completed body the meter may report.
    #[must_use]
    pub fn completion(&self) -> Option<&Completion> {
        if self.body_is_released() {
            return None;
        }
        self.carried.get()
    }

    /// THE ANSWER'S HEAD, FROM THE ONE STEP THAT SAW IT. Once per unit.
    ///
    /// The fee is decided at the unit's exit and the head is seen long before it, so until there
    /// was a cell for it every leg wrote "this transport reports no status" as a literal and the
    /// kernel's dispute arm was unreachable on every plane at once. This is that cell.
    ///
    /// Which step records it is the step that SAW it, and that is not the same step on every
    /// plane: a routed answer's head comes off the wire at Route, a locally served plane's comes
    /// off its own response encoder, and a plane whose answer document IS the response knows its
    /// finish at the step that read the document. So the token this takes is any step's — what
    /// makes the head trustworthy is not which step wrote it but that exactly ONE did.
    ///
    /// Write-once, and it answers whether this call is the one that wrote. A second reading of one
    /// answer is how a unit ends up with two heads and the fee decision reads whichever ran last,
    /// so the second writer is told rather than quietly ignored.
    pub fn record_head<S: busbar_caps::Step>(
        &self,
        _token: &UnitToken<S>,
        head: StatusLeg,
    ) -> bool {
        self.head.set(head).is_ok()
    }

    /// THE ANSWER'S HEAD, as the Meter step and the settlement table read it.
    ///
    /// `None` for a unit that never got an answer — refused at the door, or a leg that dialled and
    /// heard nothing. The fee decision reads that as "nothing was relayed", which is the same
    /// answer it gave before this face existed.
    #[must_use]
    pub fn head(&self) -> Option<&StatusLeg> {
        self.head.get()
    }

    /// GIVE THE BODY BACK. The exit path, and nothing before it.
    ///
    /// One of the unit's two ends has arrived, so the stream the hold was over is over too. After
    /// this the completion reads as absent, which is what makes "the meter ran before the exit" a
    /// fact this type carries rather than an ordering a reader is asked to check.
    pub fn release_body(&self, _exit: &ExitToken) {
        self.body_released.store(true, Ordering::Release);
    }

    /// Whether the exit has given it back.
    #[must_use]
    pub fn body_is_released(&self) -> bool {
        self.body_released.load(Ordering::Acquire)
    }
}

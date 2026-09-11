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

use std::sync::OnceLock;

use busbar_caps::{
    OriginKind, SessionId, TransportKeyHandle, TrustToken, UnitKey, VerifiedDestination,
};
use busbar_contract::bounded::{Arena, Labels, Span, MAX_KEYS};
use busbar_contract::unit::{Clock, ConfigView, Ctx, SessionView, TransportView};

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
}

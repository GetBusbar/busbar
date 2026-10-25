// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hold, the cell it lives in, the accrual that borrows a parent's, and the posting that
//! closes it. These are COUNT-ONLY unit facts: a hold names whose admission a unit runs under, and
//! a posting names how many units it reported. No money figure lives here — money is the ledger's
//! counts priced by the rate card, in core, at read time (MONEY-DESIGN §3). A hold has no `Drop` of
//! its own on purpose: a hold that goes away without a posting is a bug the canary must see, not a
//! thing a destructor should paper over. See `docs/design/BUSBAR-1.6.0.md` #38.
//!
//! # What the rest of the system cannot do
//!
//! It cannot open a hold, because opening one needs the admission unit's own token:
//!
//! ```compile_fail,E0061
//! use busbar_contract::caps::{Hold, PrincipalId};
//! let hold = Hold::open(PrincipalId::new("acct-1"));
//! ```
//!
//! With the token, the same call is ordinary — which is the point, and what keeps the fixture above
//! honest about WHY it fails:
//!
#![cfg_attr(feature = "test-seal", doc = "```")]
#![cfg_attr(not(feature = "test-seal"), doc = "```ignore")]
//! use busbar_contract::caps::{Admit, Admittance, Consumption, Grant, Hold, KernelSeal, Posted, PrincipalId, Usage, WriteMoney};
//! let seal = KernelSeal::acquire_for_kernel();          // the kernel, and only the kernel
//! let admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
//! let hold = Hold::open(&admit, PrincipalId::new("acct-1"));
//! assert_eq!(hold.principal().as_str(), "acct-1");
//! let usage = Usage::report(&Grant::<Consumption>::mint(&seal), Vec::new()).unwrap();
//! let posted = Posted::settle(hold, 0, &usage, &Grant::<WriteMoney>::mint(&seal));
//! assert_eq!(posted.quantity(), 0);
//! ```
//!
//! It cannot carry a hold into a `catch_unwind` closure. A hold is deliberately not unwind-safe, so
//! the compiler refuses the shape where a panic would swallow one:
//!
//! ```compile_fail,E0277
//! use busbar_contract::caps::Hold;
//! fn smuggle(hold: Hold) {
//!     let _ = std::panic::catch_unwind(move || {
//!         let _h = hold;
//!     });
//! }
//! ```
//!
//! It cannot let one fall out of scope where dropping it is denied — the accidental loss:
//!
//! ```compile_fail
//! #![deny(unused_must_use)]
//! use busbar_contract::caps::Hold;
//! fn lose_it(hold: Hold) {
//!     hold;   // never posted, never taken from a cell: the lint stops this here
//! }
//! ```
//!
//! It cannot take one out of its cell, because there are exactly three take sites, all in the
//! kernel and all holding an exit grant — the exit path and a child unit's end
//! (`busbar-kernel/src/teller.rs`), and the node's sweep (`busbar-kernel/src/tick.rs`):
//!
//! ```compile_fail,E0061
//! use busbar_contract::caps::HoldCell;
//! fn steal(cell: &HoldCell) {
//!     let _ = cell.take();
//! }
//! ```
//!
//! And it cannot duplicate one, because a hold is neither `Clone` nor `Copy`:
//!
//! ```compile_fail
//! use busbar_contract::caps::Hold;
//! fn twice(h: Hold) -> (Hold, Hold) {
//!     (h.clone(), h)
//! }
//! ```
//!
//! # What the compiler cannot refuse, stated plainly
//!
//! `drop(hold)`, `std::mem::forget(hold)`, `ManuallyDrop::new(hold)` and `Box::leak` all compile,
//! and no amount of type design changes that: Rust has no linear types, so "this value must be
//! consumed by exactly this function" is not expressible. Four partial mechanisms cover it instead,
//! and it is worth being exact about which does what. `#[must_use]` catches the accident above. The
//! cell catches the double take. The canary catches the omission, after the fact, in arithmetic.
//! The deliberate escape is caught by a source scan — the construction gate's `hold-escapes` rule
//! — and the symbols it looks for are written down in the crate's `fixtures/lint_rules.txt` rather
//! than left to a reviewer to remember; a test in this crate holds the two tables to each other.

use crate::caps::capability::{Admittance, DurableWrite, Exit, WriteMoney};
use crate::caps::step::PrincipalId;
use crate::caps::token::{CallId, Grant};
use crate::caps::usage::Usage;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// What the door produced.
///
/// Most units get a hold of their own. A child unit that runs under its parent's admission gets
/// an accrual instead. A zero-priced unit — the heartbeat sweep — gets neither, which is why it can
/// always run even when the table is full.
#[derive(Debug)]
#[must_use = "the door's answer decides whether the unit is admitted; dropping it loses the hold"]
pub enum Admission {
    /// The unit's own hold.
    Own(Hold),
    /// A child's accrual against a parent unit's still-open hold.
    Accrual(HoldAccrual),
    /// Nothing is held: the unit is priced at zero.
    ZeroHold,
}

/// The unit's admission, as a fact: whose it is and which call opened it. It carries no figure.
///
/// `#[must_use]`, no `Clone`, no `Copy`, no `Drop`, and not unwind-safe. One unit has at most one.
#[must_use = "a hold must reach the exit path; dropping it here loses the unit's admission"]
pub struct Hold {
    principal: PrincipalId,
    /// The call whose admittance grant opened it (#74): the grant that later admits it into a cell
    /// must be that call's.
    call: CallId,
    /// Makes a hold not unwind-safe, so the compiler refuses to let one be captured by a
    /// `catch_unwind` closure. (A caller that wraps the closure in `AssertUnwindSafe` defeats this;
    /// that is precisely the shape the source scan bans.)
    _not_unwind_safe: PhantomData<&'static mut ()>,
}

impl Hold {
    /// Open the unit's hold at the door.
    pub fn open(token: &Grant<Admittance>, principal: PrincipalId) -> Self {
        Hold {
            principal,
            call: token.call(),
            _not_unwind_safe: PhantomData,
        }
    }

    /// Whose admission this is.
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// The call whose admittance grant opened it (#74).
    pub fn call(&self) -> CallId {
        self.call
    }
}

impl std::fmt::Debug for Hold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hold")
            .field("principal", &self.principal.as_str())
            .finish()
    }
}

/// A child unit's run under a parent unit's still-open hold.
///
/// Sealed at runtime rather than by type: the parent's cell must still be admitted and the two
/// principals must be the same. A child that asks after its parent has exited is refused and posts
/// on its own, late.
#[must_use = "an accrual must reach the parent's posting or be posted late on its own"]
#[derive(Debug)]
pub struct HoldAccrual {
    principal: PrincipalId,
    /// The child's call, from the admittance grant it accrued with (#74): the grant that converts it
    /// at the parent's exit must be that call's.
    call: CallId,
}

impl HoldAccrual {
    /// Whose admission the child runs under.
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Convert an outstanding accrual into a child-owned hold, at the parent's exit, so the child
    /// ends on a hold of its own.
    ///
    /// # Errors
    ///
    /// The accrual itself, untouched, when `token` was minted for another call than the one that
    /// accrued it (#74): a grant of call A never converts call B's accrual.
    pub fn convert_at_parent_exit(self, token: &Grant<Admittance>) -> Result<Hold, HoldAccrual> {
        if token.call() != self.call {
            return Err(self);
        }
        Ok(Hold::open(token, self.principal))
    }
}

/// Why an accrual into a parent's hold was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccrualRefused {
    /// The parent has not passed the door yet.
    ParentNotAdmitted,
    /// The parent has already exited; the child must post late, on its own.
    ParentExited,
    /// The child belongs to a different principal than the parent.
    PrincipalMismatch,
}

impl std::fmt::Display for AccrualRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AccrualRefused::ParentNotAdmitted => "parent not admitted",
            AccrualRefused::ParentExited => "parent already exited",
            AccrualRefused::PrincipalMismatch => "principal mismatch",
        })
    }
}

impl std::error::Error for AccrualRefused {}

/// Which of the cell's three states it is in, as a value that carries no hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldCellState {
    /// The arrival hold is in the slot; the unit has not reached the door.
    Arrival,
    /// The door passed and the admitted hold replaced the arrival one.
    Admitted,
    /// The hold has been taken. Nothing can put one back.
    Taken,
}

/// Why a transition on the cell was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellError {
    /// A second hold was offered to a cell that is already admitted.
    AlreadyAdmitted,
    /// A hold was offered to a cell whose hold has already been taken.
    AlreadyTaken,
    /// The admittance grant offered with a hold was minted for another call than the hold (#74).
    CallMismatch,
}

impl std::fmt::Display for CellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CellError::AlreadyAdmitted => "cell already admitted",
            CellError::AlreadyTaken => "cell already taken",
            CellError::CallMismatch => "admittance grant of another call",
        })
    }
}

impl std::error::Error for CellError {}

/// A hold that the cell would not accept, handed straight back rather than dropped.
///
/// The error path must not be the place a hold quietly disappears, so the rejected hold comes back
/// with the reason attached and the caller has to decide what to do with it.
#[derive(Debug)]
#[must_use = "the rejected hold is still a hold; it has to be settled or explicitly voided"]
pub struct AdmitRejected {
    /// The hold the cell refused.
    pub hold: Hold,
    /// Why it refused.
    pub error: CellError,
}

/// The in-flight table's slot for one unit's hold.
///
/// Two states and one transition: an arrival hold goes in when the unit enters the table, the door
/// swaps it for the admitted hold, and either state is takeable exactly once. The swap and the take
/// are compare-and-set: two racing callers cannot both win, and the loser is told so rather than
/// silently overwriting.
#[derive(Debug)]
pub struct HoldCell {
    slot: Mutex<Slot>,
    accruals: AtomicU64,
}

#[derive(Debug)]
enum Slot {
    Arrival(Hold),
    Admitted(Hold),
    Taken,
}

impl HoldCell {
    /// Put the unit's arrival hold into a fresh cell.
    pub fn new(arrival: Hold) -> Self {
        HoldCell {
            slot: Mutex::new(Slot::Arrival(arrival)),
            accruals: AtomicU64::new(0),
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Slot> {
        // A poisoned cell still owns a hold, and losing it would lose the unit's end. Recovering the
        // guard is the only correct answer here; the panic that poisoned it is already on its way to
        // an end.
        self.slot.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Which state the cell is in.
    pub fn state(&self) -> HoldCellState {
        match *self.slot() {
            Slot::Arrival(_) => HoldCellState::Arrival,
            Slot::Admitted(_) => HoldCellState::Admitted,
            Slot::Taken => HoldCellState::Taken,
        }
    }

    /// The one transition: swap the arrival hold for the admitted one, and hand the arrival hold
    /// back so the admission unit can fold it into the record.
    ///
    /// A second attempt is refused, and the hold that lost comes back untouched.
    pub fn admit(&self, admitted: Hold, token: &Grant<Admittance>) -> Result<Hold, AdmitRejected> {
        // THE PER-CALL BINDING (#74): the grant that admits a hold is the grant of the call that
        // opened it. A grant from another call is refused and the hold comes back untouched.
        if token.call() != admitted.call {
            return Err(AdmitRejected {
                hold: admitted,
                error: CellError::CallMismatch,
            });
        }
        let mut slot = self.slot();
        match std::mem::replace(&mut *slot, Slot::Taken) {
            Slot::Arrival(arrival) => {
                *slot = Slot::Admitted(admitted);
                Ok(arrival)
            }
            Slot::Admitted(existing) => {
                *slot = Slot::Admitted(existing);
                Err(AdmitRejected {
                    hold: admitted,
                    error: CellError::AlreadyAdmitted,
                })
            }
            Slot::Taken => {
                *slot = Slot::Taken;
                Err(AdmitRejected {
                    hold: admitted,
                    error: CellError::AlreadyTaken,
                })
            }
        }
    }

    /// Take the hold, whichever state it is in. Exactly three take sites hold an exit grant, all in
    /// the kernel — the exit path and a child unit's end (`busbar-kernel/src/teller.rs`), and the
    /// node's sweep (`busbar-kernel/src/tick.rs`) — and whichever reaches a cell second gets `None`.
    pub fn take(&self, _token: &Grant<Exit>) -> Option<Hold> {
        let mut slot = self.slot();
        match std::mem::replace(&mut *slot, Slot::Taken) {
            Slot::Arrival(h) | Slot::Admitted(h) => Some(h),
            Slot::Taken => None,
        }
    }

    /// Let a child unit run under this cell's admission.
    ///
    /// Refused unless the cell is admitted and the principals match — the runtime seal that stands
    /// in for a type-level one, because a parent's hold is a value the child never sees.
    pub fn accrue_child(
        &self,
        principal: &PrincipalId,
        token: &Grant<Admittance>,
    ) -> Result<HoldAccrual, AccrualRefused> {
        let slot = self.slot();
        match &*slot {
            Slot::Admitted(parent) => {
                if parent.principal() != principal {
                    return Err(AccrualRefused::PrincipalMismatch);
                }
                self.accruals.fetch_add(1, Ordering::Relaxed);
                Ok(HoldAccrual {
                    principal: principal.clone(),
                    call: token.call(),
                })
            }
            Slot::Arrival(_) => Err(AccrualRefused::ParentNotAdmitted),
            Slot::Taken => Err(AccrualRefused::ParentExited),
        }
    }

    /// Write a child's posting into this cell's admission, under one guard.
    ///
    /// The state that decides the answer and the answer itself come out of the same critical
    /// section, so a clean in-parent posting is never written against a slot that had already been
    /// emptied by the parent's exit or the node's sweep.
    ///
    /// The refusal hands the accrual back rather than consuming it, because a child that missed
    /// its parent still has to post; it posts late, on its own.
    pub fn post_child(
        &self,
        accrual: HoldAccrual,
        _token: &Grant<WriteMoney>,
    ) -> Result<Posted, HoldAccrual> {
        let slot = self.slot();
        match &*slot {
            Slot::Admitted(_) => Ok(Posted {
                principal: accrual.principal,
                quantity: 0,
                flags: PostingFlags::NONE,
            }),
            Slot::Arrival(_) | Slot::Taken => Err(accrual),
        }
    }

    /// How many accruals this cell has taken — one of the numbers the canary balances.
    pub fn accruals(&self) -> u64 {
        self.accruals.load(Ordering::Relaxed)
    }
}

/// The flags a posting can carry: how far its count is believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PostingFlags(u16);

impl PostingFlags {
    /// No flags: the count is what the destination reported and nothing disagreed.
    pub const NONE: PostingFlags = PostingFlags(0);
    /// The count is the kernel's own floor, not a figure the destination reported.
    pub const ESTIMATED: PostingFlags = PostingFlags(1 << 0);
    /// Two sources for the same figure disagreed; the lower one was posted.
    pub const METER_DISPUTED: PostingFlags = PostingFlags(1 << 1);
    /// A child's run that ended after its parent had already exited.
    pub const LATE_ACCRUAL: PostingFlags = PostingFlags(1 << 3);
    /// The unit was served from a bucket it was downgraded into.
    pub const DOWNGRADED: PostingFlags = PostingFlags(1 << 7);
    /// The unit reported a class no plane declared: its money is refused, never priced.
    pub const UNDECLARED: PostingFlags = PostingFlags(1 << 8);

    /// Whether every flag in `other` is set here.
    pub fn contains(self, other: PostingFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// This set with `other` added.
    pub fn with(self, other: PostingFlags) -> PostingFlags {
        PostingFlags(self.0 | other.0)
    }

    /// This set with `other` removed.
    pub fn without(self, other: PostingFlags) -> PostingFlags {
        PostingFlags(self.0 & !other.0)
    }

    /// Whether no flag is set.
    pub fn is_clean(self) -> bool {
        self.0 == 0
    }
}

/// The proof that a unit ended: its hold and its usage report became one posting, and there is
/// exactly one per hold because posting consumes the hold by value. It carries the COUNT the unit
/// reported, never money: money is the ledger's counts priced by the rate card, in core.
#[derive(Debug)]
pub struct Posted {
    principal: PrincipalId,
    quantity: u64,
    flags: PostingFlags,
}

impl Posted {
    /// Close a hold at the count its unit reported. Takes the hold by value: a hold that has been
    /// posted no longer exists, so a second posting of the same hold cannot be written.
    ///
    /// The report is taken for its evidence: whether the destination confirmed the count or the
    /// node floored it travels from here onto the posting's flags.
    pub fn settle(hold: Hold, quantity: u64, usage: &Usage, _token: &Grant<WriteMoney>) -> Self {
        let flags = if usage.is_estimated() {
            PostingFlags::ESTIMATED
        } else {
            PostingFlags::NONE
        };
        Posted {
            principal: hold.principal,
            quantity,
            flags,
        }
    }

    /// Post a child's run that ended inside its parent's admission. The caller-facing spelling of
    /// the cell's own [`HoldCell::post_child`], because the state and the posting come out of one
    /// guard. A parent that exited between the door and here hands the accrual back.
    pub fn into_parent(
        accrual: HoldAccrual,
        parent: &HoldCell,
        token: &Grant<WriteMoney>,
    ) -> Result<Self, HoldAccrual> {
        parent.post_child(accrual, token)
    }

    /// Post a child's run that missed its parent: always posted, flagged late.
    pub fn settle_late(accrual: HoldAccrual, _token: &Grant<WriteMoney>) -> Self {
        Posted {
            principal: accrual.principal,
            quantity: 0,
            flags: PostingFlags::LATE_ACCRUAL,
        }
    }

    /// Add a flag decided outside the hold: a dispute, a downgrade.
    pub fn flagged(mut self, flag: PostingFlags) -> Self {
        self.flags = self.flags.with(flag);
        self
    }

    /// Whose posting this is.
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// The count the unit reported.
    pub fn quantity(&self) -> u64 {
        self.quantity
    }

    /// How far the posting is believed.
    pub fn flags(&self) -> PostingFlags {
        self.flags
    }
}

/// The write-ahead log observed a durable write fail. A unit that reaches the exit with one of
/// these delivered value it cannot prove it recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurabilityLost {
    at: crate::caps::step::StepName,
}

impl DurabilityLost {
    /// Record the loss. Only the write-ahead-log unit can, and only on an observed failure.
    pub fn observed(
        _token: &crate::caps::token::Grant<DurableWrite>,
        at: crate::caps::step::StepName,
    ) -> Self {
        DurabilityLost { at }
    }

    /// The step the durable write was attempted at.
    pub fn step(&self) -> crate::caps::step::StepName {
        self.at
    }
}

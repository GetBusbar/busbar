// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hold, the cell it lives in, the accrual that borrows a parent's, and the posting that closes
//! it.
//!
//! A hold is the accounting side of admission: the door decides, and the hold is the reservation
//! that decision sized. It comes into being at the door and it is taken out of its cell exactly
//! once, on the one exit path. It has no `Drop` of its own on purpose — there is no such thing as
//! "the hold cleaned itself up"; a hold that goes away without a posting is a bug the canary must
//! see, not a thing a destructor should paper over.
//!
//! # What the rest of the system cannot do
//!
//! It cannot open a hold, because opening one needs the admission unit's own token:
//!
//! ```compile_fail,E0061
//! use busbar_caps::{Hold, Principal};
//! let hold = Hold::open(Principal::new("acct-1"), 1_000);
//! ```
//!
//! With the token, the same call is ordinary — which is the point, and what keeps the fixture above
//! honest about WHY it fails:
//!
//! ```
//! use busbar_caps::{Admit, AdmitToken, Hold, KernelSeal, LedgerToken, Posted, Principal, Usage, UsageToken};
//! let seal = KernelSeal::acquire_for_kernel();          // the kernel, and only the kernel
//! let admit: AdmitToken<Admit> = AdmitToken::mint(&seal);
//! let hold = Hold::open(&admit, Principal::new("acct-1"), 1_000);
//! assert_eq!(hold.remaining(), 1_000);
//! let usage = Usage::report(&UsageToken::mint(&seal), Vec::new()).unwrap();
//! let posted = Posted::settle(hold, &usage, &LedgerToken::mint(&seal));
//! assert_eq!(posted.settled(), 0);
//! ```
//!
//! It cannot carry a hold into a `catch_unwind` closure. A hold is deliberately not unwind-safe, so
//! the compiler refuses the shape where a panic would swallow one:
//!
//! ```compile_fail,E0277
//! use busbar_caps::Hold;
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
//! use busbar_caps::Hold;
//! fn lose_it(hold: Hold) {
//!     hold;   // never posted, never taken from a cell: the lint stops this here
//! }
//! ```
//!
//! It cannot take one out of its cell, because there are exactly two callers who can — the exit
//! path and the node's sweep — and both are holding an exit token:
//!
//! ```compile_fail,E0061
//! use busbar_caps::HoldCell;
//! fn steal(cell: &HoldCell) {
//!     let _ = cell.take();
//! }
//! ```
//!
//! And it cannot duplicate one, because a hold is neither `Clone` nor `Copy`:
//!
//! ```compile_fail
//! use busbar_caps::Hold;
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
//! The deliberate escape is caught by a source scan, and the symbols it looks for are written down
//! in [`crate::lint::HOLD_ESCAPES`] rather than left to a reviewer to remember.

use crate::step::{Principal, Step};
use crate::token::{AdmitToken, ExitToken, LedgerToken, RecoveryToken};
use crate::usage::Usage;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// What the door produced.
///
/// Most units get a hold of their own. A child unit that spends against its parent's admission gets
/// an accrual instead. A zero-priced unit — the heartbeat sweep — gets neither, which is why it can
/// always run even when the table is full.
#[derive(Debug)]
#[must_use = "the door's answer decides whether the unit is admitted; dropping it loses the hold"]
pub enum Admission {
    /// The unit's own hold.
    Own(Hold),
    /// A spend against a parent unit's still-open hold.
    Accrual(HoldAccrual),
    /// Nothing is held: the unit is priced at zero.
    ZeroHold,
}

/// The unit's reservation: what the door sized, what the unit has spent against it so far, and
/// whether it ran past the end.
///
/// `#[must_use]`, no `Clone`, no `Copy`, no `Drop`, and not unwind-safe. One unit has at most one.
#[must_use = "a hold must reach the exit path; dropping it here loses the unit's admission"]
pub struct Hold {
    principal: Principal,
    reserved: u64,
    accrued: u64,
    topped_up: u64,
    overdraft: u64,
    recovered: bool,
    /// Makes a hold not unwind-safe, so the compiler refuses to let one be captured by a
    /// `catch_unwind` closure. (A caller that wraps the closure in `AssertUnwindSafe` defeats this;
    /// that is precisely the shape the source scan bans.)
    _not_unwind_safe: PhantomData<&'static mut ()>,
}

/// What a spend against a hold did to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accrual {
    /// The spend fitted inside what was reserved; this much of the reservation is left.
    Within {
        /// Nano-units still available before the reservation is used up.
        remaining: u64,
    },
    /// The reservation is used up. The caller draws a top-up from its slice; if the slice is empty
    /// it reserves once more; if THAT is refused the unit still runs to its end and posts the full
    /// amount as an overdraft, because value has already been delivered.
    Exhausted {
        /// How much of the spend went past the reservation.
        shortfall: u64,
    },
}

impl Hold {
    /// Open the unit's hold at the door, sized at `reserved` nano-units.
    pub fn open<S: Step>(_token: &AdmitToken<S>, principal: Principal, reserved: u64) -> Self {
        Hold::raw(principal, reserved, 0, false)
    }

    /// Bring a hold back from its journal record after a crash, with whatever accrual was last
    /// checkpointed. The one way a hold exists without passing the door, and the reason the
    /// recovery token is confined to one module.
    pub fn materialize(
        _token: &RecoveryToken,
        principal: Principal,
        reserved: u64,
        checkpointed: u64,
    ) -> Self {
        Hold::raw(principal, reserved, checkpointed, true)
    }

    fn raw(principal: Principal, reserved: u64, accrued: u64, recovered: bool) -> Self {
        Hold {
            principal,
            reserved,
            accrued,
            topped_up: 0,
            overdraft: 0,
            recovered,
            _not_unwind_safe: PhantomData,
        }
    }

    /// Whose admission this is.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// What the door reserved, plus every top-up since.
    pub fn reserved(&self) -> u64 {
        self.reserved.saturating_add(self.topped_up)
    }

    /// What has been spent against it so far.
    pub fn accrued(&self) -> u64 {
        self.accrued
    }

    /// What is left of the reservation.
    pub fn remaining(&self) -> u64 {
        self.reserved().saturating_sub(self.accrued)
    }

    /// Whether this hold came back from a journal record rather than through the door.
    pub fn is_recovered(&self) -> bool {
        self.recovered
    }

    /// Spend `amount` against the reservation. Accounting only: this records the spend and says
    /// whether it fitted. Drawing the top-up from the node's slice of the bucket window is the
    /// admission unit's job, and it calls [`Hold::top_up`] with what it got.
    pub fn accrue(&mut self, amount: u64) -> Accrual {
        self.accrued = self.accrued.saturating_add(amount);
        if self.accrued <= self.reserved() {
            Accrual::Within {
                remaining: self.remaining(),
            }
        } else {
            Accrual::Exhausted {
                shortfall: self.accrued.saturating_sub(self.reserved()),
            }
        }
    }

    /// Add a slice draw to the reservation. Returns what is now left.
    pub fn top_up(&mut self, amount: u64) -> u64 {
        self.topped_up = self.topped_up.saturating_add(amount);
        self.remaining()
    }

    /// Record that the unit ran past everything it could reserve. The unit still finishes and still
    /// posts; the excess is carried into the next window's admissible budget.
    pub fn record_overdraft(&mut self, amount: u64) {
        self.overdraft = self.overdraft.saturating_add(amount);
    }

    /// How much of the spend was never backed by a reservation.
    pub fn overdraft(&self) -> u64 {
        self.overdraft
    }
}

impl std::fmt::Debug for Hold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hold")
            .field("principal", &self.principal.id())
            .field("reserved", &self.reserved())
            .field("accrued", &self.accrued)
            .field("overdraft", &self.overdraft)
            .field("recovered", &self.recovered)
            .finish()
    }
}

/// A child unit's spend against a parent unit's still-open hold.
///
/// Sealed at runtime rather than by type: the parent's cell must still be admitted and the two
/// principals must be the same. A child that asks after its parent has exited is refused and posts
/// on its own, late, against a synchronous slice draw.
#[must_use = "an accrual must reach the parent's posting or be posted late on its own"]
#[derive(Debug)]
pub struct HoldAccrual {
    principal: Principal,
    amount: u64,
}

impl HoldAccrual {
    /// Whose admission is being spent.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// How much.
    pub fn amount(&self) -> u64 {
        self.amount
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
}

impl std::fmt::Display for CellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CellError::AlreadyAdmitted => "cell already admitted",
            CellError::AlreadyTaken => "cell already taken",
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
        // A poisoned cell still owns a hold, and losing it would lose money. Recovering the guard is
        // the only correct answer here; the panic that poisoned it is already on its way to an end.
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
    pub fn admit(
        &self,
        admitted: Hold,
        _token: &AdmitToken<crate::step::Admit>,
    ) -> Result<Hold, AdmitRejected> {
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

    /// Take the hold, whichever state it is in. Exactly two callers hold an exit token — the exit
    /// path and the node's sweep — and the second one to arrive gets `None`.
    pub fn take(&self, _token: &ExitToken) -> Option<Hold> {
        let mut slot = self.slot();
        match std::mem::replace(&mut *slot, Slot::Taken) {
            Slot::Arrival(h) | Slot::Admitted(h) => Some(h),
            Slot::Taken => None,
        }
    }

    /// Let a child unit spend against this cell's admission.
    ///
    /// Refused unless the cell is admitted and the principals match — the runtime seal that stands
    /// in for a type-level one, because a parent's hold is a value the child never sees.
    pub fn accrue_child(
        &self,
        principal: &Principal,
        amount: u64,
        _token: &AdmitToken<crate::step::Admit>,
    ) -> Result<HoldAccrual, AccrualRefused> {
        let mut slot = self.slot();
        match &mut *slot {
            Slot::Admitted(parent) => {
                if parent.principal() != principal {
                    return Err(AccrualRefused::PrincipalMismatch);
                }
                parent.accrue(amount);
                self.accruals.fetch_add(1, Ordering::Relaxed);
                Ok(HoldAccrual {
                    principal: principal.clone(),
                    amount,
                })
            }
            Slot::Arrival(_) => Err(AccrualRefused::ParentNotAdmitted),
            Slot::Taken => Err(AccrualRefused::ParentExited),
        }
    }

    /// How many accruals this cell has taken — one of the numbers the canary balances.
    pub fn accruals(&self) -> u64 {
        self.accruals.load(Ordering::Relaxed)
    }
}

/// The flags a posting can carry. A posting is never just an amount: it says how much the amount is
/// believed, and every flag here puts the posting on a report someone reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PostingFlags(u16);

impl PostingFlags {
    /// No flags: the amount is what the destination reported and nothing disagreed.
    pub const NONE: PostingFlags = PostingFlags(0);
    /// The amount is the kernel's own floor, not a figure the destination reported.
    pub const ESTIMATED: PostingFlags = PostingFlags(1 << 0);
    /// Two sources for the same figure disagreed; the lower one was posted.
    pub const METER_DISPUTED: PostingFlags = PostingFlags(1 << 1);
    /// The unit spent more than it could reserve.
    pub const OVERDRAFT: PostingFlags = PostingFlags(1 << 2);
    /// A child's spend that arrived after its parent had already exited.
    pub const LATE_ACCRUAL: PostingFlags = PostingFlags(1 << 3);
    /// The hold was materialised from a journal record after a crash.
    pub const RECOVERED: PostingFlags = PostingFlags(1 << 4);
    /// Nothing was dispatched, so nothing is owed.
    pub const VOIDED: PostingFlags = PostingFlags(1 << 5);
    /// Value was delivered but the settle record was lost; it is retained and re-appended.
    pub const UNPOSTED: PostingFlags = PostingFlags(1 << 6);
    /// The unit was served from a pool it was downgraded into.
    pub const DOWNGRADED: PostingFlags = PostingFlags(1 << 7);

    /// Whether every flag in `other` is set here.
    pub fn contains(self, other: PostingFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// This set with `other` added.
    pub fn with(self, other: PostingFlags) -> PostingFlags {
        PostingFlags(self.0 | other.0)
    }

    /// Whether no flag is set.
    pub fn is_clean(self) -> bool {
        self.0 == 0
    }
}

/// The proof that a unit was settled: the ledger unit turned a hold and a usage report into one
/// posting, and there is exactly one per hold because settling consumes the hold by value.
#[derive(Debug)]
pub struct Posted {
    principal: Principal,
    reserved: u64,
    settled: u64,
    overdraft: u64,
    flags: PostingFlags,
}

impl Posted {
    /// Settle a hold against what the unit actually used. Takes the hold by value: a hold that has
    /// been settled no longer exists, so a second settlement of the same hold cannot be written.
    pub fn settle(hold: Hold, usage: &Usage, _token: &LedgerToken) -> Self {
        let mut flags = PostingFlags::NONE;
        if hold.overdraft() > 0 {
            flags = flags.with(PostingFlags::OVERDRAFT);
        }
        if hold.is_recovered() {
            flags = flags.with(PostingFlags::RECOVERED);
        }
        if usage.is_estimated() {
            flags = flags.with(PostingFlags::ESTIMATED);
        }
        Posted {
            principal: hold.principal.clone(),
            reserved: hold.reserved(),
            settled: usage.total(),
            overdraft: hold.overdraft(),
            flags,
        }
    }

    /// Post a child's spend that missed its parent — always posted, backed by a synchronous slice
    /// draw, flagged late.
    pub fn settle_late(accrual: HoldAccrual, _token: &LedgerToken) -> Self {
        Posted {
            principal: accrual.principal,
            reserved: 0,
            settled: accrual.amount,
            overdraft: accrual.amount,
            flags: PostingFlags::LATE_ACCRUAL.with(PostingFlags::OVERDRAFT),
        }
    }

    /// Add a flag the ledger decided on rather than the hold: a dispute, a downgrade, a void.
    pub fn flagged(mut self, flag: PostingFlags) -> Self {
        self.flags = self.flags.with(flag);
        self
    }

    /// Whose posting this is.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// What was reserved for the unit.
    pub fn reserved(&self) -> u64 {
        self.reserved
    }

    /// What was actually posted.
    pub fn settled(&self) -> u64 {
        self.settled
    }

    /// How much of what was posted had no reservation behind it.
    pub fn overdraft(&self) -> u64 {
        self.overdraft
    }

    /// How far the posting is believed.
    pub fn flags(&self) -> PostingFlags {
        self.flags
    }
}

/// The write-ahead log observed a durable write fail. A unit that reaches the exit with one of
/// these delivered value it cannot prove it recorded; the posting is retained and re-appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurabilityLost {
    at: crate::step::StepName,
}

impl DurabilityLost {
    /// Record the loss. Only the write-ahead-log unit can, and only on an observed failure.
    pub fn observed(_token: &crate::token::DurabilityToken, at: crate::step::StepName) -> Self {
        DurabilityLost { at }
    }

    /// The step the durable write was attempted at.
    pub fn step(&self) -> crate::step::StepName {
        self.at
    }
}

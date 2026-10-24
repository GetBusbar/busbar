// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money-book seam: the descriptor an exit arm settles with, what one settlement left on the
//! book and the chain, the [`MoneyBook`] trait and its one pass-through impl onto the shared
//! [`Durability`].
//!
//! Split out of `durability/mod.rs` (structure-lint) — a private child module reached only through
//! the parent, which re-exports every item here so no caller's path changes.

use super::*;

/// The facts a posting record needs that neither the books nor the hold hold.
///
/// A stamp rather than three arguments, so a caller cannot get the clock and the card version in the
/// wrong order without the compiler noticing, and so adding a fourth is one change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PostingStamp {
    /// Which card version priced the unit.
    pub rate_card_version: u64,
    /// The wall clock, in whole seconds. The unit's pinned arrival epoch, never a fresh read.
    pub wall: u64,
    /// The node's monotonic clock.
    pub mono: u64,
}

/// Where a settlement lands: which balance, which window, on whose authority, and stamped how.
///
/// One borrowed value rather than six arguments, and it is not only tidiness. The window and the
/// stamp's wall clock are the same pinned arrival epoch read two ways; passing them separately is
/// how a straddling unit ends up booked in one window and recorded in another.
#[derive(Debug, Clone, Copy)]
pub struct Settling<'a> {
    /// Which balance moves.
    pub key: &'a TotalsKey,
    /// Which window it moves in.
    pub window: WindowStart,
    /// The token the journal append is made under.
    pub durability: &'a Grant<DurableWrite>,
    /// Which step the append is attributed to.
    pub step: StepName,
    /// What the record carries beyond the figures.
    pub stamp: PostingStamp,
}

/// What one settlement moved and what it left on the chain.
#[derive(Debug)]
pub struct Settled {
    /// What the ledger did: the posting, the residual released, the overdraft noted.
    pub settlement: Settlement,
    /// The settlement's own journal record.
    pub posting: Posting,
    /// The overdraft's journal record, where the unit ran past everything reservable.
    pub overdraft: Option<Posting>,
}

/// THE MONEY-BOOK SETTLING SEAM (DECISIONS #25 / #26 S2).
///
/// The single interface an exit arm calls to settle its cost onto the durability book. Its DTO is
/// the neutral [`Settling`] descriptor already in this module: it carries the balance the hold
/// reserved against (`key` + `window`), the authority the append is made under (`durability`), and
/// the [`PostingStamp`] the record is dated and ordered by — the reserve/settle/stamp the exit arm
/// performs, expressed with no plane in the name. What settles through it is "an exit arm"; what it
/// settles onto is "the book".
///
/// The seam is `&self`, not `&mut`: the lock over the one book is taken and released BEHIND the
/// seam, per settlement. So any number of exit arms hold the same seam and settle through it
/// concurrently — the seam is the whole of their contention, not a single book each arm has to
/// reach past the others to lock. That is what dissolves the "one-book serialization point": exit
/// arms compose behind the seam rather than sharing one `&mut Durability`.
///
/// Today the only impl is [`SharedBook`], a verbatim pass-through onto the one shared [`Durability`]
/// — byte-for-byte the settlement every exit arm makes now. The consolidated one-book is a later
/// impl swapped in behind this same trait by a one-line composition flip; nothing above the seam
/// changes when it is.
pub trait MoneyBook: Send + Sync {
    /// Settle a posting the exit path already built, and journal it.
    ///
    /// The exit path owns the hold and consumes it there, so what reaches the seam is a
    /// [`busbar_contract::caps::Posted`] and never a hold. This is the settlement act every plane's exit arm
    /// makes; see [`Durability::settle_posted`] for the book side of it.
    ///
    /// # Errors
    ///
    /// The journal could not make the record durable. The books have already moved — value was
    /// delivered and the settlement is the truth about it — so this is a durability loss to be
    /// retained and re-appended, never a settlement that is rolled back.
    fn settle_posted(
        &self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
    ) -> Result<Settled, DurabilityLost>;

    /// [`MoneyBook::settle_posted`] with the unit's raw counts on the record (#71). See
    /// [`Durability::settle_counted`].
    ///
    /// # Errors
    ///
    /// As [`MoneyBook::settle_posted`].
    fn settle_counted(
        &self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
        counts: &UnitCounts,
        arrived_ms: u64,
    ) -> Result<Settled, DurabilityLost>;

    /// [`MoneyBook::settle_counted`] carrying the card's pricing refusal, if any. See
    /// [`Durability::settle_counted_refusing`].
    ///
    /// # Errors
    ///
    /// As [`MoneyBook::settle_posted`].
    fn settle_counted_refusing(
        &self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
        counts: &UnitCounts,
        arrived_ms: u64,
        refusal: Option<String>,
    ) -> Result<Settled, DurabilityLost>;

    /// Close the exit's hold with a COUNTS ROW: the unit's counts priced to nothing (billing off,
    /// or a card that prices them at zero). See [`Durability::close_counted`].
    ///
    /// # Errors
    ///
    /// As [`MoneyBook::settle_posted`].
    fn close_counted(
        &self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
        counts: &UnitCounts,
        arrived_ms: u64,
    ) -> Result<Settled, DurabilityLost>;

    /// The unit's raw counts with no figure behind them — priced to nothing, or REFUSED (#42/#43).
    /// See [`Durability::post_counts`].
    ///
    /// # Errors
    ///
    /// As [`MoneyBook::settle_posted`].
    fn post_counts(
        &self,
        at: &Settling<'_>,
        principal: &busbar_contract::caps::PrincipalId,
        counts: &UnitCounts,
        arrived_ms: u64,
        refusal: Option<String>,
    ) -> Result<Posting, DurabilityLost>;
}

/// The byte-identical pass-through: settle onto the ONE shared durability book (DECISION #25).
///
/// Holds a handle on the same `Arc<Mutex<Durability>>` every view reads and every arm settles onto,
/// takes that lock exactly the way every other holder takes it, and delegates verbatim to
/// [`Durability::settle_posted`]. It adds nothing and changes nothing: the `Settling` it is handed
/// and the `Posted` it settles reach the ledger's one book-moving function unaltered, so the postings
/// on the chain are the same bytes in the same order they are today. It exists so exit arms name a
/// seam instead of a book, not so the book behaves differently.
///
/// What it does keep is WHERE the settlement landed ([`SharedBook::landed`]): the seq of the record
/// the last settlement through it put on the chain, read under the same lock the settlement took,
/// so the unit's audit record can name the settlement that closed its hold (THE DESIGN §1: the
/// record's controls carry the hold and settle seqs).
pub struct SharedBook {
    pub(super) durability: std::sync::Arc<std::sync::Mutex<Durability>>,
    landed: std::sync::Mutex<Option<u64>>,
}

impl SharedBook {
    /// A pass-through over a book the caller already opened and shares.
    #[must_use]
    pub fn over(durability: std::sync::Arc<std::sync::Mutex<Durability>>) -> Self {
        SharedBook {
            durability,
            landed: std::sync::Mutex::new(None),
        }
    }

    /// The seq of the settlement record the last settlement through this seam put on the chain.
    ///
    /// `None` when nothing settled through it, when the journal did not take the record (the log
    /// retains and re-offers it, and a seq the chain never confirmed is not one to cite), and for a
    /// counts row ([`MoneyBook::post_counts`]), which closes no hold.
    #[must_use]
    pub fn landed(&self) -> Option<u64> {
        *self
            .landed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// One settlement, under the book's one lock, noting where its record landed.
    ///
    /// A settlement's records are the first the append seals, in order from the journal's next
    /// seq; the one record that can precede them is the `ChainBreak` an append at the bound seals
    /// first, and that break names its own seq. So the settlement sits at the seq offered, or one
    /// past it when the break took that seq.
    fn settling(
        &self,
        line: impl FnOnce(&mut Durability) -> Result<Settled, DurabilityLost>,
    ) -> Result<Settled, DurabilityLost> {
        // The same lock, taken the way every other holder of it takes it — read through a poisoning
        // an unrelated unit caused rather than refusing to settle a delivered unit. Held for exactly
        // the settlement and released, which is what lets a second arm settle behind this one.
        let mut durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
        let offered_at = durability.journal.next_seq();
        let settled = line(&mut durability);
        let landed = settled.is_ok().then(|| {
            let broke = durability
                .journal
                .overflows()
                .iter()
                .any(|overflow| overflow.chain_break_seq == offered_at);
            offered_at.saturating_add(u64::from(broke))
        });
        *self
            .landed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = landed;
        settled
    }
}

impl std::fmt::Debug for SharedBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedBook").finish_non_exhaustive()
    }
}

impl MoneyBook for SharedBook {
    fn settle_posted(
        &self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
    ) -> Result<Settled, DurabilityLost> {
        self.settling(|durability| durability.settle_posted(at, posted))
    }

    fn settle_counted(
        &self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
        counts: &UnitCounts,
        arrived_ms: u64,
    ) -> Result<Settled, DurabilityLost> {
        self.settling(|durability| durability.settle_counted(at, posted, counts, arrived_ms))
    }

    fn settle_counted_refusing(
        &self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
        counts: &UnitCounts,
        arrived_ms: u64,
        refusal: Option<String>,
    ) -> Result<Settled, DurabilityLost> {
        self.settling(|durability| {
            durability.settle_counted_refusing(at, posted, counts, arrived_ms, refusal)
        })
    }

    fn close_counted(
        &self,
        at: &Settling<'_>,
        posted: busbar_contract::caps::Posted,
        counts: &UnitCounts,
        arrived_ms: u64,
    ) -> Result<Settled, DurabilityLost> {
        self.settling(|durability| durability.close_counted(at, posted, counts, arrived_ms))
    }

    fn post_counts(
        &self,
        at: &Settling<'_>,
        principal: &busbar_contract::caps::PrincipalId,
        counts: &UnitCounts,
        arrived_ms: u64,
        refusal: Option<String>,
    ) -> Result<Posting, DurabilityLost> {
        let mut durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
        durability.post_counts(at, principal, counts, arrived_ms, refusal)
    }
}

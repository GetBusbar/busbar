// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money-book seam: the descriptor an exit arm settles with, what one settlement left on the
//! book and the chain, and the [`SharedBook`] seam onto the shared [`Durability`].
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

/// THE MONEY-BOOK SETTLING SEAM (DECISIONS #25 / #26 S2): settle onto the ONE shared durability
/// book.
///
/// Holds a handle on the same `Arc<Mutex<Durability>>` every view reads and every arm settles onto,
/// takes that lock exactly the way every other holder takes it, and hands the book's own settling
/// function ([`Durability::settle_posted`] and its counted forms) the `Settling` and the `Posted`
/// unaltered, so the postings on the chain are the same bytes in the same order. The lock is taken
/// and released BEHIND the seam, once per step ([`SharedBook::settling_then`]): any number of exit
/// arms hold the same seam and settle through it concurrently.
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
    /// counts row ([`Self::posting_then`]), which closes no hold.
    #[must_use]
    pub fn landed(&self) -> Option<u64> {
        *self
            .landed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// ONE STEP, ONE ACQUISITION: one settlement, noting where its record landed, and the append
    /// that follows it in the same step (the unit's audit record), under one hold of the book's lock.
    ///
    /// A settlement's records are the first the append seals, in order from the journal's next
    /// seq; the one record that can precede them is the `ChainBreak` an append at the bound seals
    /// first, and that break names its own seq. So the settlement sits at the seq offered, or one
    /// past it when the break took that seq.
    ///
    /// `then` is handed the same book and the seq the settlement landed at ([`Self::landed`]), and
    /// makes its own append. The records, their
    /// order and each append's own durability point are the two acquisitions' exactly; what goes is
    /// the second acquisition, and the window in which another unit's append could land between a
    /// unit's settlement and its record. Nothing in `then` awaits or crosses a plugin.
    pub fn settling_then(
        &self,
        line: impl FnOnce(&mut Durability) -> Result<Settled, DurabilityLost>,
        then: impl FnOnce(&mut Durability, Option<u64>),
    ) -> Result<Settled, DurabilityLost> {
        // The same lock, taken the way every other holder of it takes it — read through a poisoning
        // an unrelated unit caused rather than refusing to settle a delivered unit. Held for exactly
        // the step's appends and released, which is what lets a second arm settle behind this one.
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
        then(&mut durability, landed);
        settled
    }

    /// [`Self::settling_then`] for a counts row ([`Durability::post_counts`]): the row and the
    /// append that follows it under one hold of the lock. A counts row closes no hold, so `then` is
    /// handed where the last settlement through this seam landed, as [`Self::landed`] reads it.
    pub fn posting_then(
        &self,
        line: impl FnOnce(&mut Durability) -> Result<Posting, DurabilityLost>,
        then: impl FnOnce(&mut Durability, Option<u64>),
    ) -> Result<Posting, DurabilityLost> {
        let mut durability = self.durability.lock().unwrap_or_else(|p| p.into_inner());
        let posted = line(&mut durability);
        then(&mut durability, self.landed());
        posted
    }
}

impl std::fmt::Debug for SharedBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedBook").finish_non_exhaustive()
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE METERING LEASE.** Reserve a coarse over-estimate, settle the exact charge as it becomes
//! known, answer "is the caller's budget dry?" mid-stream, and reconcile the refund at the end.
//!
//! A high-rate carrier — a live streaming session nobody can price after the fact — cannot
//! wait for a final invoice to find out it has overspent. It opens a LEASE at admit against a hard
//! money ceiling, settles exact already-priced increments against it as it consumes, and reads back
//! exhaustion so it can hard-close the carrier the instant the budget is dry. That arithmetic is
//! money arithmetic and it lives here, with the card and the posting, for the reason this crate
//! exists: a reserve that refunds the wrong amount, or an exhaustion that fires late, is a changed
//! invoice, and it must be re-derivable by hand from integers with no runtime in the way.
//!
//! # This module holds no state of its own
//!
//! [`LeaseBook`] is a VALUE — a book of open leases and the next id to mint. It carries no lock, no
//! clock and no global: whoever needs the book to be reachable from more than one place wraps this
//! in whatever the composition it lives in already uses, and the book stays a thing that can be
//! constructed in a test and read line by line. That is what keeps the crate's own promise (no
//! clock, no store) true with a lease in it.
//!
//! # Who prices (this book prices nothing)
//!
//! Every amount here is ALREADY money — [`CostAmount`], u128 nanodollars. Turning a work magnitude
//! (elapsed seconds, tokens, …) into nanodollars is PRICING and it happens at the card
//! ([`crate::price`], [`crate::rate`]), never here. A lease never sees a unit count; it is
//! money-denominated end to end.

use std::collections::BTreeMap;

/// Exact money in **nanodollars** (1e-9 USD), the same integer unit the per-token pricing already
/// settles in (the card, read through [`crate::CostModel`]). Integer so accounting is lossless — a
/// caller's `0.0078345` USD is exactly `7_834_500` nanodollars, with no float drift on the way to
/// the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct CostAmount(pub u128);

impl CostAmount {
    /// The zero amount.
    pub const ZERO: CostAmount = CostAmount(0);

    /// Nanodollars as a raw integer.
    #[inline]
    #[must_use]
    pub fn nanodollars(self) -> u128 {
        self.0
    }
}

impl std::ops::Add for CostAmount {
    type Output = CostAmount;
    #[inline]
    fn add(self, rhs: CostAmount) -> CostAmount {
        // Saturating, matching the fail-closed money-path discipline (`finalize` uses
        // saturating_sub, `derive_spend_cents` saturating_add). A hostile/buggy plugin
        // breakdown or a long run of partial settles must NOT wrap the accumulator to ~0
        // (silent under-settlement in release, debug panic) — it caps at the ceiling instead.
        CostAmount(self.0.saturating_add(rhs.0))
    }
}

impl std::iter::Sum for CostAmount {
    fn sum<I: Iterator<Item = CostAmount>>(iter: I) -> CostAmount {
        // Saturating fold — see the `Add` impl above; a summed sequence cannot wrap to under-charge.
        iter.fold(CostAmount(0), |acc, c| acc + c)
    }
}

/// The outcome of finalizing a [`CostHold`]: the exact amount to ledger, and the refund owed back to
/// the budget cell the reserve was taken from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settlement {
    /// The true charge — the sum of the exact settlements. This is what the ledger records; it is
    /// NEVER an estimate.
    pub ledgered_total: CostAmount,
    /// `reserved − settled`, saturating at zero: the unspent reserve to return to the budget cell. Zero
    /// when the exact charge met or exceeded the (coarse) reserve.
    pub refund: CostAmount,
}

/// A cost reserve held across a request or a live streaming session: reserve a coarse over-estimate
/// at admit for a hard budget-cell debit, settle the EXACT charge as it becomes known, answer "is the
/// caller's budget dry?" mid-stream so a live session can HARD-STOP, and reconcile the refund at the
/// end.
///
/// # Exhaustion (the mid-stream hard-stop)
///
/// A live session must be able to HARD-STOP the instant the caller's budget is dry — not wait for
/// [`Self::finalize`]. The hard ceiling is the caller's money `cap` (third argument to
/// [`Self::reserve`]), held SEPARATELY from the coarse admission `reserved`: [`Self::is_exhausted`]
/// fires exactly at `settled ≥ cap`, so a coarse *over-estimated* `reserved` does NOT push the stop
/// late. The dry signal is therefore NOT `settled ≥ reserved`. An UNCAPPED lease (`cap == None`) is
/// never exhausted; a zero cap (`Some(CostAmount::ZERO)`, refuse-all) is exhausted from the outset and
/// is representable DISTINCTLY from "no cap".
///
/// # Ledger boundary
///
/// This type owns the correctness of the *amounts* — the reserve total, the exact settled sum, the
/// once-only flat fee, the cap headroom, and the refund — but NOT the ledger: the caller applies
/// `reserved` to its budget cell at [`CostHold::reserve`] and the [`Settlement`] at
/// [`CostHold::finalize`]. Pinning the hold to a `(bucket, window)` so the refund lands where it was
/// reserved is the caller's key choice; this value carries no clock and no cell.
///
/// **Accuracy invariant:** the ledgered charge is the sum of the exact `settle_partial`s, never the
/// coarse reserve. **No double-count:** the flat per-request fee is folded into `reserved` once and
/// never re-added on settle. **Exhaustion invariant:** the dry signal is `settled ≥ cap`, measured
/// against the true budget ceiling, independent of the coarse `reserved`.
#[derive(Debug)]
pub struct CostHold {
    reserved: CostAmount,
    settled: CostAmount,
    cap: Option<CostAmount>,
}

impl CostHold {
    /// Open a hold reserving a coarse `estimate` plus the once-only flat per-request `fee` (the caller
    /// debits `reserved()` from the budget cell now; the unspent part comes back at [`Self::finalize`]),
    /// with a hard money `cap` the exact `settled` charge may not exceed before the session is dry.
    ///
    /// `cap` is the caller's TRUE budget ceiling in nanodollars, NOT the coarse `estimate`: `None`
    /// leaves the lease uncapped (never exhausts); `Some(CostAmount::ZERO)` is a refuse-all cap,
    /// distinct from `None`. All three amounts are money — the caller priced them (see the type doc).
    #[must_use]
    pub fn reserve(estimate: CostAmount, fee: CostAmount, cap: Option<CostAmount>) -> CostHold {
        CostHold {
            reserved: estimate + fee,
            settled: CostAmount::ZERO,
            cap,
        }
    }

    /// The amount debited from the budget cell at admit (coarse estimate + flat fee).
    #[must_use]
    pub fn reserved(&self) -> CostAmount {
        self.reserved
    }

    /// The exact charge settled so far — the running sum of the [`Self::settle_partial`] totals, which
    /// is what will be ledgered (never the coarse reserve).
    #[must_use]
    pub fn settled(&self) -> CostAmount {
        self.settled
    }

    /// The remaining budget headroom before exhaustion: `cap − settled`, saturating at zero. `None`
    /// for an uncapped lease (no finite ceiling); `Some(CostAmount::ZERO)` exactly when exhausted.
    #[must_use]
    pub fn remaining(&self) -> Option<CostAmount> {
        self.cap
            .map(|c| CostAmount(c.0.saturating_sub(self.settled.0)))
    }

    /// Whether the caller's budget is dry: the exact `settled` charge has met or passed the money
    /// `cap`. A live session reads this after each [`Self::settle_partial`] to hard-stop mid-stream.
    /// Always `false` for an uncapped lease; `true` from the outset for a `Some(CostAmount::ZERO)` cap.
    ///
    /// Answered against the TRUE ceiling (`cap`), NOT against the coarse `reserved` — so an
    /// over-estimated reserve cannot make the stop fire late.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        matches!(self.cap, Some(cap) if self.settled >= cap)
    }

    /// Record an EXACT increment the caller computed and PRICED — a streamed turn's cost as a money
    /// `exact_total` scalar. Repeatable; the running sum is the true charge. Nothing here derives it
    /// and nothing here parses an itemization on this hot path: the itemized breakdown is audit-only
    /// and travels a SEPARATE tap, so the per-frame settle a high-rate carrier drives accrues in O(1)
    /// from the scalar total.
    pub fn settle_partial(&mut self, exact_total: CostAmount) {
        self.settled = self.settled + exact_total;
    }

    /// Reconcile: the exact total to ledger, and the refund (`reserved − settled`, saturating). An
    /// over-settle (exact charge above the coarse reserve — the estimate was low) ledgers the true
    /// amount and refunds zero, never a negative.
    #[must_use]
    pub fn finalize(self) -> Settlement {
        let refund = CostAmount(self.reserved.0.saturating_sub(self.settled.0));
        Settlement {
            ledgered_total: self.settled,
            refund,
        }
    }
}

/// **THE BOOK OF OPEN LEASES**, keyed by the opaque id it minted. One book is one ledger: a lease
/// opened through any caller of this book accrues against the same cap as any other, which is what
/// makes exhaustion reflect the real grant ceiling the reserve was opened with rather than a
/// caller-private counter.
///
/// Ids are minted monotonically from `1`, so a minted id is NEVER `0` — callers whose seam reserves
/// zero as a "no lease" sentinel can rely on that without restating it.
#[derive(Debug, Default)]
pub struct LeaseBook {
    /// Ordered rather than hashed: an ordered map needs no random state, so an empty book is a
    /// CONSTANT and a caller can declare one without a lazy initializer standing between the book
    /// and its first reader. Nothing here looks a lease up by anything but its exact minted id, so
    /// the ordering costs the hot settle nothing a hash would have saved.
    open: BTreeMap<u64, CostHold>,
    next_id: u64,
}

impl LeaseBook {
    /// An empty book. `const`, so a composition can declare the one book it shares as a constant
    /// rather than build it behind a lazy initializer.
    #[must_use]
    pub const fn new() -> LeaseBook {
        LeaseBook {
            open: BTreeMap::new(),
            next_id: 0,
        }
    }

    /// OPEN a reserve-then-settle lease over already-priced amounts and return its id, or `None` on a
    /// REFUSE-ALL cap (present, zero) — a lease that can never settle a nonzero increment is denied at
    /// the door rather than opened and immediately exhausted.
    pub fn open(
        &mut self,
        estimate: CostAmount,
        fee: CostAmount,
        cap: Option<CostAmount>,
    ) -> Option<u64> {
        if matches!(cap, Some(CostAmount::ZERO)) {
            return None;
        }
        self.next_id = self.next_id.saturating_add(1);
        let id = self.next_id;
        self.open.insert(id, CostHold::reserve(estimate, fee, cap));
        Some(id)
    }

    /// ACCRUE one exact increment against the open lease `id` and report exhaustion (`settled ≥ cap`),
    /// or `None` when `id` names no open lease (unknown / already closed).
    ///
    /// The lease STAYS OPEN after a settle: a live carrier keeps settling increments until it closes.
    pub fn settle(&mut self, id: u64, exact: CostAmount) -> Option<bool> {
        let hold = self.open.get_mut(&id)?;
        hold.settle_partial(exact);
        Some(hold.is_exhausted())
    }

    /// The exact amount SETTLED so far against `id` (the audit tap), or `None` for an unknown lease.
    #[must_use]
    pub fn settled_of(&self, id: u64) -> Option<CostAmount> {
        Some(self.open.get(&id)?.settled())
    }

    /// CLOSE and forget the lease `id`, returning its finalized [`Settlement`], or `None` for an
    /// unknown / already-closed lease.
    ///
    /// Idempotent BY CONSTRUCTION, and that is the DOUBLE-REFUND guard: the entry is REMOVED before it
    /// is finalized, so a second close — a lingering caller-side handle, or a by-value close guard
    /// racing that handle — finds no entry and returns `None`. A refund is therefore applied at most
    /// once, and a finished carrier's lease does not leak the book.
    pub fn close(&mut self, id: u64) -> Option<Settlement> {
        Some(self.open.remove(&id)?.finalize())
    }

    /// How many leases are open. A reader for the "a finished carrier does not leak the book" claim.
    #[must_use]
    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Whether no lease is open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }
}

#[cfg(test)]
#[path = "tests/lease_tests.rs"]
mod lease_tests;

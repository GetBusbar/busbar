// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **Boot: the ledger reads its own spend back off the durable record.**
//!
//! ## Why this is the ledger's job and not the door's
//!
//! The previous release hydrated at the DOOR: `GovState::hydrate_budgets` re-read the per-bucket
//! token ledgers out of the store and stamped them into the admission cells, and the money the
//! budget cap compared was re-derived from those tokens at whatever rate card happened to be
//! configured at the moment of the read. That is two facts held in one place — what was counted and
//! what it cost — and it is the reason a rate correction silently repriced a window that had already
//! been billed.
//!
//! The ledger already holds the other half: a settled posting is money that was delivered, at the
//! card that was in force when it was delivered, and it is on the journal. So the restoration
//! belongs here. The ledger replays what it settled, folds it back into the book it settles into,
//! and hands the door ONE figure per balance — what that balance already carried before this
//! process existed. The door adds its own post-boot accrual to it and compares; it does not reprice
//! anything, and nothing it does can move a figure that was settled under an older card.
//!
//! ## What is restored, and what deliberately is not
//!
//! Restored: `settled`, the carried overdraft, and the `drawn` those two imply. Those are the
//! figures the durable record actually carries — a posting record names what was reserved, what was
//! settled and what nothing backed — and they are the figures a spend cap reads.
//!
//! NOT restored: open holds and open slice remainders. A process that has just started has nothing
//! in flight, so every hold that was open when it stopped is closed by the restart, and restoring
//! one would reserve budget against a request that will never arrive. A draw that was taken and
//! never spent is the same case. This is stated rather than left implicit because the identity is
//! checked over the hydrated book: `drawn` is set to `settled` less the carried overdraft — the
//! overdraft being precisely the part that was never drawn — so a book restored from an empty set
//! of holds balances at zero rather than reporting every replayed posting as an imbalance.
//!
//! ## The seam, and why it takes decoded postings
//!
//! The journal's record bodies are the composition root's encoding: the log unit frames bytes and
//! deliberately cannot parse them, and the ledger unit knows nothing about a chain. So the seam is
//! stated in the ledger's OWN vocabulary — a balance, a window, and the three figures — and whoever
//! owns the encoding decodes it. That keeps this crate free of a second opinion about what a journal
//! record looks like, which is the same rule the dual write already follows.

use std::collections::BTreeMap;

use crate::settle::Ledger;
use crate::totals::{TotalsKey, WindowStart};

/// One settled posting, as the durable record carries it.
///
/// The ledger's own vocabulary and nothing else: which balance, which window, and the three figures
/// a posting moved. A record that could not be read at all is not one of these — it is a
/// [`HydrationError::Unreadable`], because a posting silently dropped is spend that comes back as
/// admissible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydratedPosting {
    /// Which balance moved.
    pub key: TotalsKey,
    /// Which window it moved in.
    pub window: WindowStart,
    /// What was settled.
    pub settled: i128,
    /// What was spent with nothing reserved behind it.
    pub overdraft: i128,
}

/// Why the ledger could not restore its spend.
///
/// An error and never an empty answer. The distinction is the whole point: a deployment whose
/// durable record could not be read has an UNKNOWN spend, and answering "nothing spent" to that is
/// how a maxed-out key spends its whole cap again after a restart. The previous release's own
/// hydrate says so at length and propagates; this keeps that posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydrationError {
    /// The durable record could not be read.
    RecordUnavailable(String),
    /// A record was read but could not be understood as a posting.
    Unreadable {
        /// Which node wrote it.
        node: u64,
        /// That node's sequence number for it.
        node_seq: u64,
    },
}

impl std::fmt::Display for HydrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HydrationError::RecordUnavailable(why) => {
                write!(f, "the durable record could not be read: {why}")
            }
            HydrationError::Unreadable { node, node_seq } => write!(
                f,
                "node {node}'s record {node_seq} could not be read as a posting"
            ),
        }
    }
}

impl std::error::Error for HydrationError {}

/// Where the ledger reads its settled postings back from at boot.
///
/// One method, called once, off every hot path. The implementer owns the encoding and the chain;
/// what it hands back is postings in the order they were settled.
pub trait SpendSource {
    /// Every settled posting the durable record holds, oldest first.
    ///
    /// # Errors
    ///
    /// The record could not be read, or a record in it could not be understood.
    fn postings(&self) -> Result<Vec<HydratedPosting>, HydrationError>;
}

/// **What each balance already carried when this process started.**
///
/// A VALUE taken once at boot, and deliberately not a live view of the book. The door adds this to
/// its own post-boot accrual, so a figure that moved as settlements landed would be counted twice —
/// once in the carried figure and once in the cells that recorded the same request. Frozen at
/// hydration, the sum is each balance's spend exactly once.
///
/// Empty is the honest answer for a node whose durable record holds no postings, and it makes the
/// door's comparison bit-for-bit the one it made before this existed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Carried {
    rows: BTreeMap<(TotalsKey, WindowStart), i128>,
}

impl Carried {
    /// Nothing carried: every balance starts this process at zero.
    #[must_use]
    pub fn nothing() -> Self {
        Carried::default()
    }

    /// What one balance carried, in nano-units.
    #[must_use]
    pub fn nanos(&self, key: &TotalsKey, window: WindowStart) -> i128 {
        self.rows.get(&(key.clone(), window)).copied().unwrap_or(0)
    }

    /// What one balance carried, in whole cents.
    ///
    /// The projection is the cost unit's, once, for the reason that crate gives at length: the
    /// divisor, the truncation direction and the saturation posture are the pricing law's and a
    /// second copy of them here would be a second answer to what a nano-unit is worth.
    #[must_use]
    pub fn cents(&self, key: &TotalsKey, window: WindowStart) -> i64 {
        let nanos = self.nanos(key, window);
        busbar_unit_cost::cents_of(u128::try_from(nanos).unwrap_or(0))
    }

    /// **What one BUCKET carried, in whole cents — every dimension and scope on it, and either one
    /// window or all of them.**
    ///
    /// The door names a bucket and a window; the book names a balance, which is a bucket in one
    /// dimension at one scope. So the two vocabularies meet here, once, rather than at whichever
    /// composition root happens to need the figure: a bucket's spend is what every balance on it
    /// settled, and a caller that picked one dimension would silently drop the rest.
    ///
    /// `window` of `None` is every window, which is the answer for the all-time bucket — the one
    /// that never rolls, and the one the door reads under [`WindowStart`] zero while the settlements
    /// against it land in whichever dated window they happened in.
    ///
    /// The sum is over nano-units and the divide happens once at the end, for the reason the cost
    /// unit gives about per-line floors: two balances each carrying half a cent carry a whole cent
    /// between them, and flooring each first would drop both.
    #[must_use]
    pub fn bucket_cents(&self, bucket: &str, window: Option<WindowStart>) -> i64 {
        let nanos = self
            .rows
            .iter()
            .filter(|((key, at), _)| {
                key.bucket.as_str() == bucket && window.is_none_or(|w| *at == w)
            })
            .fold(0i128, |sum, (_, nanos)| sum.saturating_add(*nanos));
        busbar_unit_cost::cents_of(u128::try_from(nanos).unwrap_or(0))
    }

    /// How many balances carried anything.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether nothing was carried.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Every balance and its carried figure, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&(TotalsKey, WindowStart), &i128)> {
        self.rows.iter()
    }
}

/// What one hydration restored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hydration {
    /// How many postings were replayed.
    pub postings: u64,
    /// How many balances they moved.
    pub balances: usize,
    /// What each balance carries into this process.
    pub carried: Carried,
}

impl Ledger {
    /// **Restore this ledger's settled spend from the durable record.**
    ///
    /// Boot only, once per process, off every hot path — the same posture the previous release's
    /// hydrate had and for the same reason: the figures it restores are the ones a spend cap is
    /// compared against, and a re-read on the request path would be a rate the request was judged at
    /// changing under it.
    ///
    /// Idempotent it is NOT, and it is not meant to be: calling it twice folds every posting in
    /// twice. It is called from the composition root at boot, before anything listens, which is the
    /// only moment at which "the book is empty and the record is the truth" is a fact rather than a
    /// hope.
    ///
    /// # Errors
    ///
    /// The source could not be read. Nothing has been folded in when this happens: the postings are
    /// collected before the book is touched, so a boot that fails here fails with an EMPTY book
    /// rather than a partly restored one, and the caller's only correct response is to refuse to
    /// start.
    pub fn hydrate(&mut self, source: &dyn SpendSource) -> Result<Hydration, HydrationError> {
        let postings = source.postings()?;
        let mut carried: BTreeMap<(TotalsKey, WindowStart), i128> = BTreeMap::new();
        for posting in &postings {
            let figures = self.book_mut().entry(posting.key.clone(), posting.window);
            figures.settled += posting.settled;
            figures.overdraft_carried_out += posting.overdraft;
            // The overdraft is the one part of a posting that nothing drew — that is exactly why
            // the identity subtracts it — so what the store gave up is the settlement less the
            // carry. Restoring `drawn` as anything else would report every replayed posting as an
            // imbalance the moment the books were checked.
            figures.drawn += posting.settled - posting.overdraft;
            *carried
                .entry((posting.key.clone(), posting.window))
                .or_insert(0) += posting.settled;
        }
        // A balance whose postings cancelled to nothing carries nothing, and listing it would put a
        // zero row in front of every reader of the carried figures.
        carried.retain(|_, nanos| *nanos != 0);
        Ok(Hydration {
            postings: postings.len() as u64,
            balances: carried.len(),
            carried: Carried { rows: carried },
        })
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a checkpoint seals: the running figures for one bucket, in one dimension, at one scope.
//!
//! ## Why the key is three things and not one
//!
//! A bucket is a pot of budget. A dimension is what is being counted out of it — money, requests,
//! concurrency, or any declared meter class. A scope narrows a bucket to a pool. The same bucket in
//! two dimensions has two independent balances, and folding them into one figure would mean a token
//! cap and a spend cap could pay each other's overdrafts. So the key carries all three, and every
//! figure below is per key.
//!
//! ## Why every figure is a signed 128-bit integer
//!
//! Amounts are nano-units, so a modest deployment's yearly turnover already needs more than 64 bits
//! of headroom once adjustments and reversals are in the same column as settlements. Signed, because
//! an adjustment is a reversal and a reversal is negative; storing it as an unsigned figure with a
//! separate direction flag is how a sign error becomes invisible. Nothing here is floating point,
//! for the reason nothing in a ledger ever is.

use std::collections::BTreeMap;

use busbar_caps::MeterClassId;

/// Which pot of budget.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BucketId(String);

impl BucketId {
    /// Name a bucket.
    pub fn new(id: impl Into<String>) -> Self {
        BucketId(id.into())
    }

    /// Its name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BucketId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What is being counted out of a bucket.
///
/// A closed shape over an open key: the four forms are fixed, but any declared meter class can be
/// the subject of the fourth, so a deployment with no rate card still has volume control.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapDimension {
    /// Money, in nano-units.
    NanoUnits,
    /// A count of units admitted.
    Requests,
    /// How many units may be in flight at once.
    Concurrent,
    /// Any declared meter class, by name.
    ///
    /// The class is held as its NAME rather than as the capability crate's identifier, and the
    /// reason is mechanical rather than aesthetic: a checkpoint's figures are digested in key order
    /// and signed, so the key has to have a total order. The identifier does not have one, and it
    /// is not this crate's to give it one. [`CapDimension::class`] does the conversion in one place
    /// so no call site has to think about it.
    Class(String),
}

impl CapDimension {
    /// The dimension for a declared meter class.
    pub fn class(id: &MeterClassId) -> Self {
        CapDimension::Class(id.as_str().to_string())
    }
}

impl std::fmt::Display for CapDimension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapDimension::NanoUnits => f.write_str("nano-units"),
            CapDimension::Requests => f.write_str("requests"),
            CapDimension::Concurrent => f.write_str("concurrent"),
            CapDimension::Class(c) => write!(f, "class {c}"),
        }
    }
}

/// How wide a bucket's reach is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BucketScope {
    /// Everything the bucket covers.
    All,
    /// One named pool inside it.
    Pool(String),
}

impl std::fmt::Display for BucketScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BucketScope::All => f.write_str("all"),
            BucketScope::Pool(name) => write!(f, "pool:{name}"),
        }
    }
}

/// The three things that make one balance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TotalsKey {
    /// Which pot.
    pub bucket: BucketId,
    /// Counting what.
    pub dimension: CapDimension,
    /// How wide.
    pub scope: BucketScope,
}

impl TotalsKey {
    /// Build a key.
    pub fn new(bucket: BucketId, dimension: CapDimension, scope: BucketScope) -> Self {
        TotalsKey {
            bucket,
            dimension,
            scope,
        }
    }
}

impl std::fmt::Display for TotalsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.bucket, self.dimension, self.scope)
    }
}

/// A window's opening instant, in whole seconds. Windows do not overlap, so this identifies one.
pub type WindowStart = u64;

/// One balance's running figures, as a checkpoint seals them.
///
/// Every field is a running total for one key, not a delta. The identity is stated over the
/// DIFFERENCE between two of these, which is why nothing here has to be reset at a window boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    /// What the window was allowed to spend.
    pub budget: i128,
    /// How much has been taken out of the store for this key.
    pub drawn: i128,
    /// How much of what was drawn has been given back.
    pub released: i128,
    /// How much has actually been posted.
    pub settled: i128,
    /// How much is reserved against holds that have not closed.
    pub open_holds: i128,
    /// How much sits in slices that have been drawn but not yet spent or released.
    pub open_slice_remainders: i128,
    /// How much has been moved by a correction, positive or negative.
    pub adjustments: i128,
    /// How much has been posted that the recompute has not yet agreed with.
    pub unreconciled: i128,
    /// Overdraft carried into this window from the last one.
    pub overdraft_carried_in: i128,
    /// Overdraft this window is carrying out to the next.
    pub overdraft_carried_out: i128,
    /// Value that has crossed this window's boundary: what went OUT, less what came IN.
    ///
    /// The sign takes a moment and is worth stating plainly. The identity asks "everything drawn
    /// into this window — where is it now?", and value that was transferred out is still accounted
    /// for, just somewhere else. So a transfer OUT is positive here (it stands in for the value that
    /// left the other columns) and a transfer IN is negative (the value arrived in another column
    /// without this window having drawn it). Both sides of one transfer are recorded together, so
    /// neither window can be left holding half of it.
    pub cross_window_transfers: i128,
    /// How much is under dispute.
    pub disputed: i128,
    /// The age of the oldest hold still open, in seconds.
    pub oldest_open_hold_age_secs: u64,
    /// How many disputes are open.
    pub open_dispute_count: u64,
    /// The age of the oldest open dispute, in seconds.
    pub oldest_dispute_age_secs: u64,
}

impl Totals {
    /// Nothing yet.
    pub fn zero() -> Self {
        Totals::default()
    }

    /// The single overdraft figure the identity uses: what is being carried OUT, less what was
    /// carried IN.
    ///
    /// Stated as one derived figure rather than left as two fields, because the identity subtracts
    /// "overdraft carried" once and a reader should not have to guess which of the two it meant.
    /// The two fields survive separately because a checkpoint seals both, and an operator asking
    /// "what did the last window hand us" is asking for the one the identity has already folded in.
    pub fn overdraft_carried(&self) -> i128 {
        self.overdraft_carried_out - self.overdraft_carried_in
    }

    /// What is left of the budget once everything posted, held, and carried is accounted for.
    pub fn headroom(&self) -> i128 {
        self.budget - self.settled - self.open_holds - self.overdraft_carried_in
    }
}

/// Every balance the node is keeping, keyed by bucket, dimension, scope and window.
///
/// A `BTreeMap` rather than a hash map on purpose: a checkpoint's body is hashed and signed, and a
/// signature over a map with a non-deterministic iteration order would verify on the node that made
/// it and nowhere else.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Book {
    totals: BTreeMap<(TotalsKey, WindowStart), Totals>,
}

impl Book {
    /// An empty book.
    pub fn new() -> Self {
        Book::default()
    }

    /// The totals for one key in one window, zeros if the key has not been touched.
    pub fn get(&self, key: &TotalsKey, window: WindowStart) -> Totals {
        self.totals
            .get(&(key.clone(), window))
            .copied()
            .unwrap_or_default()
    }

    /// Change the totals for one key in one window.
    pub fn entry(&mut self, key: TotalsKey, window: WindowStart) -> &mut Totals {
        self.totals.entry((key, window)).or_default()
    }

    /// Every key and window in the book, in a fixed order.
    pub fn iter(&self) -> impl Iterator<Item = (&(TotalsKey, WindowStart), &Totals)> {
        self.totals.iter()
    }

    /// How many balances the book holds.
    pub fn len(&self) -> usize {
        self.totals.len()
    }

    /// Whether the book holds nothing.
    pub fn is_empty(&self) -> bool {
        self.totals.is_empty()
    }

    /// The book as a plain map, for a checkpoint to seal.
    pub fn snapshot(&self) -> BTreeMap<(TotalsKey, WindowStart), Totals> {
        self.totals.clone()
    }
}

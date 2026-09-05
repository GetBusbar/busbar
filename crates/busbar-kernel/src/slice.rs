// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The node's share of a window, the fence that keeps two nodes from spending it twice, and the
//! leases that count what is happening right now.
//!
//! A cap is a number in a window that belongs to the whole fleet. A node does not ask the store on
//! every unit — that would put a network round trip in the middle of every request — it draws a
//! SLICE of the window and spends against it locally. Three things make that safe:
//!
//! - **The slice is fenced by an epoch.** A slice drawn under an old epoch is stale, and a stale
//!   slice cannot be spent. That is what makes a partition recoverable: the other side's draws are
//!   accounted, and this side's stop.
//! - **The draw across a chain is all or nothing.** A principal's buckets are a chain, and either
//!   every dimension of every bucket in it draws, or none does and the ones that did are released.
//!   A half-drawn chain is money that exists in one place and not another.
//! - **Running out is not a refusal mid-unit.** Value has already been delivered, so the unit runs
//!   to its end, posts the full amount, and the overdraft reduces the next window. Refusing here
//!   would lose the ledger's identity for the sake of a number that is already spent.
//!
//! Leases are the other half: a concurrency cap is not a window, it is a gauge, so it is one lease
//! per capped group per unit, taken at the door and released on the exit path for EVERY end.
//!
//! The store itself is a trait. The kernel says what it needs — reserve, release, the epoch — and
//! the integrator's store plugin answers.

use std::collections::HashMap;

use busbar_caps::{MeterClassId, OriginKind, ReasonCode};

use crate::Millis;

/// A capped axis: an amount of money, a count of requests, a live gauge, or any declared meter
/// class by key.
///
/// The SHAPE is closed and the key is open: a plane that declares a class gets volume control over
/// it for free, and the kernel never learns what the class means.
// contract: CapDimension
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CapDimension {
    /// Money, in nano-units.
    NanoUnits,
    /// A count of admitted units.
    Requests,
    /// A gauge of how many are in flight at once.
    Concurrent,
    /// Any declared meter class, by its key.
    Class(MeterClassId),
}

impl CapDimension {
    /// Whether this dimension accrues DURING a unit, and can therefore overdraw.
    ///
    /// Requests and concurrency are known at the door; money and class quantities are not, which is
    /// why only they can end a unit owing something.
    pub fn accrues_mid_unit(&self) -> bool {
        matches!(self, CapDimension::NanoUnits | CapDimension::Class(_))
    }
}

/// Whether a bucket applies everywhere, or only to one pool.
// contract: BucketScope
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BucketScope {
    /// Every unit of the principal.
    All,
    /// Only units routed through this pool.
    Pool(String),
}

/// One bucket of one principal's chain.
// contract: the bucket id
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BucketId {
    /// The bucket's configured name.
    pub name: String,
    /// What it applies to.
    pub scope: BucketScope,
}

impl BucketId {
    /// A bucket that applies to everything.
    pub fn all(name: impl Into<String>) -> Self {
        BucketId {
            name: name.into(),
            scope: BucketScope::All,
        }
    }

    /// A bucket scoped to one pool.
    pub fn pool(name: impl Into<String>, pool: impl Into<String>) -> Self {
        BucketId {
            name: name.into(),
            scope: BucketScope::Pool(pool.into()),
        }
    }

    /// Whether this bucket draws for a unit that routed through `pool`.
    ///
    /// A scoped bucket draws when its scope EQUALS the effective pool: a hop into a fallback pool
    /// draws nothing from the pool it fell back from.
    pub fn draws_for(&self, pool: Option<&str>) -> bool {
        match (&self.scope, pool) {
            (BucketScope::All, _) => true,
            (BucketScope::Pool(mine), Some(theirs)) => mine == theirs,
            (BucketScope::Pool(_), None) => false,
        }
    }
}

/// Which generation of the fleet's leases a slice belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(pub u64);

/// A slice, as the store hands it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceId(pub u64);

/// What the node is asking the store for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceRequest {
    /// Which bucket.
    pub bucket: BucketId,
    /// Which axis of it.
    pub dimension: CapDimension,
    /// How much it wants.
    pub wanted: u64,
    /// The epoch it believes it is in.
    pub epoch: Epoch,
}

/// What the store gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceGrant {
    /// The store's handle for it.
    pub id: SliceId,
    /// How much was granted, which may be less than was wanted.
    pub granted: u64,
    /// When the node must stop drawing new slices against it.
    pub valid_until: Millis,
    /// The epoch it was granted under.
    pub epoch: Epoch,
}

/// Why a slice could not be had.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceError {
    /// The window has no headroom left.
    Exhausted,
    /// The node is behind the fleet's current epoch.
    StaleEpoch,
    /// The store could not be reached.
    Unavailable,
}

impl SliceError {
    /// The reason a refusal carries for this failure.
    pub fn reason(self) -> ReasonCode {
        match self {
            SliceError::Exhausted => ReasonCode::OverBudget,
            SliceError::StaleEpoch => ReasonCode::StaleSlice,
            SliceError::Unavailable => ReasonCode::DurabilityUnavailable,
        }
    }
}

/// What the kernel needs from a store to run slices. The integrator implements it.
pub trait SliceStore: Send + Sync {
    /// Draw a slice of a window.
    fn reserve(&self, request: &SliceRequest) -> Result<SliceGrant, SliceError>;

    /// Give back what was not spent.
    fn release(&self, id: SliceId, unspent: u64) -> Result<(), SliceError>;

    /// The fleet's current epoch, as this node last observed it.
    fn epoch(&self) -> Epoch;
}

/// One held slice and what has been spent against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slice {
    /// The grant it came from.
    pub grant: SliceGrant,
    /// How much of it is spent.
    pub spent: u64,
}

impl Slice {
    /// How much is left.
    pub fn remaining(self) -> u64 {
        self.grant.granted.saturating_sub(self.spent)
    }
}

/// Whether the node is serving normally or through an outage of the store.
///
/// The distinction matters for exactly one rule: during an outage a slice already drawn stays
/// spendable past the moment it would normally expire, because the store still accounts it as
/// drawn and no other node can have it. What is NOT allowed in either branch is a NEW draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// The store is reachable.
    Normal,
    /// The store is not, and the node is serving on what it already holds.
    Outage,
}

/// What a local draw did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Draw {
    /// It fitted in the slice the node holds.
    Granted,
    /// The slice is short by this much; the caller reserves once more.
    NeedReserve {
        /// How much more is needed.
        shortfall: u64,
    },
    /// The node's slice is behind the fleet's epoch, so it cannot be spent.
    Stale,
}

/// The slices this node is holding, by bucket and dimension.
#[derive(Debug, Default)]
pub struct SliceBook {
    held: HashMap<(BucketId, CapDimension), Slice>,
}

impl SliceBook {
    /// An empty book.
    pub fn new() -> Self {
        SliceBook::default()
    }

    /// Put a grant in the book.
    pub fn install(&mut self, bucket: BucketId, dimension: CapDimension, grant: SliceGrant) {
        self.held
            .entry((bucket, dimension))
            .and_modify(|slice| {
                slice.grant.granted = slice.grant.granted.saturating_add(grant.granted);
                slice.grant.valid_until = grant.valid_until;
                slice.grant.epoch = grant.epoch;
            })
            .or_insert(Slice { grant, spent: 0 });
    }

    /// What the node holds for a bucket and dimension.
    pub fn get(&self, bucket: &BucketId, dimension: &CapDimension) -> Option<Slice> {
        self.held.get(&(bucket.clone(), dimension.clone())).copied()
    }

    /// Spend against a held slice.
    ///
    /// A slice whose epoch is behind the fleet's is stale and refuses. A slice that has passed its
    /// validity refuses too — EXCEPT during a store outage, where an already-drawn slice stays
    /// spendable, because the alternative is refusing units the fleet has already accounted for.
    pub fn draw(
        &mut self,
        bucket: &BucketId,
        dimension: &CapDimension,
        amount: u64,
        now: Millis,
        epoch: Epoch,
        posture: Posture,
    ) -> Draw {
        let key = (bucket.clone(), dimension.clone());
        match self.held.get_mut(&key) {
            None => Draw::NeedReserve { shortfall: amount },
            Some(slice) => {
                if slice.grant.epoch < epoch {
                    return Draw::Stale;
                }
                if now > slice.grant.valid_until && posture == Posture::Normal {
                    return Draw::Stale;
                }
                if slice.remaining() >= amount {
                    slice.spent = slice.spent.saturating_add(amount);
                    Draw::Granted
                } else {
                    Draw::NeedReserve {
                        shortfall: amount - slice.remaining(),
                    }
                }
            }
        }
    }

    /// Give a draw back — the release at route of every dimension drawn on a scope the unit did
    /// not route through.
    pub fn give_back(&mut self, bucket: &BucketId, dimension: &CapDimension, amount: u64) {
        if let Some(slice) = self.held.get_mut(&(bucket.clone(), dimension.clone())) {
            slice.spent = slice.spent.saturating_sub(amount);
        }
    }

    /// One line of a chain draw.
    pub fn draw_chain(
        &mut self,
        lines: &[(BucketId, CapDimension, u64)],
        now: Millis,
        epoch: Epoch,
        posture: Posture,
    ) -> Result<(), ChainRefused> {
        let mut done: Vec<(BucketId, CapDimension, u64)> = Vec::new();
        for (index, (bucket, dimension, amount)) in lines.iter().enumerate() {
            match self.draw(bucket, dimension, *amount, now, epoch, posture) {
                Draw::Granted => done.push((bucket.clone(), dimension.clone(), *amount)),
                other => {
                    // All or nothing: every line that drew gives it straight back, so a refusal at
                    // the parent bucket releases the child's slice.
                    for (bucket, dimension, amount) in &done {
                        self.give_back(bucket, dimension, *amount);
                    }
                    return Err(ChainRefused {
                        at: index,
                        bucket: bucket.clone(),
                        dimension: dimension.clone(),
                        draw: other,
                    });
                }
            }
        }
        Ok(())
    }
}

/// A chain draw that could not be completed. Everything it had already drawn is released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRefused {
    /// Which line of the chain refused.
    pub at: usize,
    /// The bucket that refused.
    pub bucket: BucketId,
    /// The dimension of it.
    pub dimension: CapDimension,
    /// What the draw said.
    pub draw: Draw,
}

/// Does a unit of this origin take a concurrency lease?
///
/// Handshake units and tick units move no money and take none, so a node at a saturated
/// concurrency cap still finishes its handshakes and still runs its ticks. Kernel-verb units take
/// none either, which is what makes the administrative surface answer while everything else is
/// capped out — the one moment an operator most needs it to.
pub fn takes_lease(origin: OriginKind, kernel_verb_only: bool) -> bool {
    if kernel_verb_only {
        return false;
    }
    !matches!(origin, OriginKind::Handshake | OriginKind::Tick)
}

/// The concurrency leases one unit holds.
///
/// Released on the exit path, for every end. Not on the success path, not in a drop guard: on the
/// one path every unit leaves through, whatever it was that ended it.
#[derive(Debug, Default)]
#[must_use = "leases have to be released on the exit path, whatever the end"]
pub struct LeaseSet {
    held: Vec<BucketId>,
}

impl LeaseSet {
    /// A unit holding no leases.
    pub fn new() -> Self {
        LeaseSet::default()
    }

    /// How many it holds.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Record a lease taken at the door.
    pub fn take(&mut self, bucket: BucketId) {
        self.held.push(bucket);
    }

    /// Give every lease back, and say how many were given.
    pub fn release_all(&mut self, gauge: &ConcurrencyGauge) -> usize {
        let count = self.held.len();
        for bucket in self.held.drain(..) {
            gauge.release(&bucket);
        }
        count
    }
}

/// The live count per capped group.
///
/// One lease per capped group, not per dimension: a group with a concurrency cap and two windows
/// takes ONE lease, because the gauge counts units, not axes.
#[derive(Debug, Default)]
pub struct ConcurrencyGauge {
    counts: std::sync::Mutex<HashMap<BucketId, usize>>,
}

impl ConcurrencyGauge {
    /// A gauge reading zero everywhere.
    pub fn new() -> Self {
        ConcurrencyGauge::default()
    }

    /// The live count for a group.
    pub fn count(&self, bucket: &BucketId) -> usize {
        self.counts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(bucket)
            .copied()
            .unwrap_or(0)
    }

    /// Take a lease, if the group has room.
    pub fn acquire(&self, bucket: &BucketId, cap: usize) -> Result<(), ReasonCode> {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let entry = counts.entry(bucket.clone()).or_insert(0);
        if *entry >= cap {
            return Err(ReasonCode::OverBudget);
        }
        *entry += 1;
        Ok(())
    }

    /// Give a lease back.
    pub fn release(&self, bucket: &BucketId) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = counts.get_mut(bucket) {
            *entry = entry.saturating_sub(1);
        }
    }
}

/// What the overdraft rule says about a unit that has run past everything it can reserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overdraft {
    /// Keep going and post the full amount. Value was delivered; the excess is carried into the
    /// next window, which is what makes it impossible to escape a cap by overrunning it.
    ContinueAndCarry,
    /// The bucket's window never rolls, so there is no next window to carry into: the unit posts
    /// what it used with nothing carried out, and the identity still balances.
    ContinueNoCarry,
    /// The ceiling on this bucket is reached: new units are refused, and a unit already in flight
    /// on a session plane is cut at its next accrual.
    Ceiling,
}

/// Decide the overdraft answer for a bucket.
///
/// `total_window` is a window that never rolls; `at_ceiling` is the hard bound the operator set,
/// which is released only under dual control.
pub fn overdraft(total_window: bool, at_ceiling: bool) -> Overdraft {
    match (at_ceiling, total_window) {
        (true, _) => Overdraft::Ceiling,
        (false, true) => Overdraft::ContinueNoCarry,
        (false, false) => Overdraft::ContinueAndCarry,
    }
}

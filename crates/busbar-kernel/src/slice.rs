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

use busbar_caps::{OriginKind, ReasonCode};

use crate::Millis;

/// A capped axis: an amount of money, a count of requests, a live gauge, or any declared meter
/// class by key.
///
/// The SHAPE is closed and the key is open: a plane that declares a class gets volume control over
/// it for free, and the kernel never learns what the class means.
///
/// The dimension, the scope and the bucket itself are the contract's own, because a plane declares
/// the class a cap is taken on and a refusal names the bucket back to the caller. What stays here
/// is the kernel's reading OF a bucket — how to build one, and whether it draws for a given pool —
/// which is loop policy rather than part of what a bucket is.
pub use busbar_contract::{BucketRef as BucketId, BucketScope, CapDimension};

/// Whether a dimension accrues DURING a unit, and can therefore overdraw.
///
/// Requests and concurrency are known at the door; money and class quantities are not, which is
/// why only they can end a unit owing something.
pub fn accrues_mid_unit(dimension: &CapDimension) -> bool {
    matches!(dimension, CapDimension::NanoUnits | CapDimension::Class(_))
}

/// A bucket that applies to everything.
#[must_use]
pub const fn bucket_all(id: &'static str) -> BucketId {
    BucketId {
        id,
        scope: BucketScope::All,
        capped: true,
    }
}

/// A bucket scoped to one pool.
#[must_use]
pub const fn bucket_pool(id: &'static str, pool: &'static str) -> BucketId {
    BucketId {
        id,
        scope: BucketScope::Pool(pool),
        capped: true,
    }
}

/// Whether a bucket draws for a unit that routed through `pool`.
///
/// A scoped bucket draws when its scope EQUALS the effective pool: a hop into a fallback pool
/// draws nothing from the pool it fell back from.
#[must_use]
pub fn draws_for(bucket: &BucketId, pool: Option<&str>) -> bool {
    match (&bucket.scope, pool) {
        (BucketScope::All, _) => true,
        (BucketScope::Pool(mine), Some(theirs)) => *mine == theirs,
        (BucketScope::Pool(_), None) => false,
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
    /// Every grant that went into the held slice, in the order the store gave them.
    ///
    /// The held slice is the MERGED view a draw spends against; this is what the store is owed
    /// back. They are not the same thing the moment a bucket is topped up: a top-up adds headroom
    /// to something the node is already spending, and the second grant has an id of its own that
    /// only ever gets spoken again if somebody kept it.
    drawn: HashMap<(BucketId, CapDimension), Vec<SliceGrant>>,
}

impl SliceBook {
    /// An empty book.
    pub fn new() -> Self {
        SliceBook::default()
    }

    /// Put a grant in the book.
    ///
    /// A top-up MERGES: the headroom adds up, and the validity and epoch are the newer grant's,
    /// because that is the window the node is now spending in. What does not merge is the grant
    /// itself — the store handed out two slices and is owed two back, so both are kept.
    pub fn install(&mut self, bucket: BucketId, dimension: CapDimension, grant: SliceGrant) {
        self.held
            .entry((bucket, dimension))
            .and_modify(|slice| {
                slice.grant.granted = slice.grant.granted.saturating_add(grant.granted);
                slice.grant.valid_until = grant.valid_until;
                slice.grant.epoch = grant.epoch;
            })
            .or_insert(Slice { grant, spent: 0 });
        self.drawn
            .entry((bucket, dimension))
            .or_default()
            .push(grant);
    }

    /// Give a bucket's dimension back to the store: every grant that went into it, with what is
    /// left unspent of that grant.
    ///
    /// Spend is attributed in the order the grants arrived — the node spent the headroom it had
    /// before it spent the headroom it topped up with — so the unspent remainders add up to the
    /// slice's own remainder and no grant is returned twice over.
    pub fn release(&mut self, bucket: &BucketId, dimension: &CapDimension) -> Vec<(SliceId, u64)> {
        let key = (*bucket, *dimension);
        let mut spent = self.held.remove(&key).map(|slice| slice.spent).unwrap_or(0);
        self.drawn
            .remove(&key)
            .unwrap_or_default()
            .into_iter()
            .map(|grant| {
                let consumed = spent.min(grant.granted);
                spent -= consumed;
                (grant.id, grant.granted - consumed)
            })
            .collect()
    }

    /// What the node holds for a bucket and dimension.
    pub fn get(&self, bucket: &BucketId, dimension: &CapDimension) -> Option<Slice> {
        self.held.get(&(*bucket, *dimension)).copied()
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
        let key = (*bucket, *dimension);
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
        if let Some(slice) = self.held.get_mut(&(*bucket, *dimension)) {
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
                Draw::Granted => done.push((*bucket, *dimension, *amount)),
                other => {
                    // All or nothing: every line that drew gives it straight back, so a refusal at
                    // the parent bucket releases the child's slice.
                    for (bucket, dimension, amount) in &done {
                        self.give_back(bucket, dimension, *amount);
                    }
                    return Err(ChainRefused {
                        at: index,
                        bucket: *bucket,
                        dimension: *dimension,
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

/// The bucket a unit's in-flight slot is counted on.
///
/// One bucket, node-wide, because that is what the node's own concurrency limit is: the count of
/// units this node is running right now. The per-group gauges a chain declares are a second axis
/// the door already enforces, on its own counters, at its own statuses; this is the kernel's
/// reading of the slot the door's yes occupied, and it is the reading the sweep gives back.
pub const IN_FLIGHT: BucketId = bucket_all("kernel:in_flight");

/// The bucket one capped-`concurrent` GROUP's leases are counted on.
///
/// Node-wide, like [`IN_FLIGHT`] and for the same reason: a group's concurrency limit counts the
/// units of that group this node is running, and there is nothing else it could count. The id is
/// the group's own name as the composition root interned it, so the two never collide unless an
/// operator names a group `kernel:in_flight` — at which point the two readings are of the same set
/// anyway.
pub const fn group_lease(group: &'static str) -> BucketId {
    bucket_all(group)
}

/// THE DOOR'S OWN COUNT OF THIS UNIT, held for as long as the unit is running.
///
/// The door's `concurrent` cap is enforced on the door's own counters, and the thing that keeps one
/// of them raised is the value its yes handed back. Held for the length of the decision, the cap is
/// a comparison against a number that has already been given away: every unit is admitted, however
/// many are in flight. Held for the length of the UNIT, it is a cap.
///
/// Opaque because the kernel has no business knowing what a door counts on. What it knows is the
/// one rule that makes the count right — a count taken at the yes goes back at the unit's end,
/// whatever the end was — and that rule is expressed here as ownership: the grant lives on the
/// unit's slot beside its leases, and giving it back is dropping it. The kernel never reads it,
/// never copies it and never hands it to anything but the slot.
///
/// `Send + Sync` because the slot outlives the task and the sweep is on another one; `'static`
/// because a slot's lifetime is not the frame that admitted it.
pub struct DoorGrant(Box<dyn std::any::Any + Send + Sync>);

impl DoorGrant {
    /// Carry a door's grant, whatever it is.
    pub fn new<G: std::any::Any + Send + Sync>(grant: G) -> Self {
        DoorGrant(Box::new(grant))
    }
}

impl std::fmt::Debug for DoorGrant {
    /// The type it carries, and nothing of what is inside it. A grant is a door's own counter and
    /// the kernel neither knows nor prints what a door counts; what an operator reading a slot
    /// needs is which door is holding it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DoorGrant")
            .field(&std::any::Any::type_id(&*self.0))
            .finish()
    }
}

/// Where the door names the capped groups its yes counted, for the slot to record.
///
/// The door decides and the kernel counts, and this is the whole of the seam between the two. It is
/// created on the loop's own frame, lent to the door's step for the length of that one call, and
/// read once immediately after — so a name written here belongs to this unit and to no other, with
/// no allocation and nothing to clean up.
///
/// Interior mutability because the step is lent everything by shared reference; a slip is not a
/// capability and carries no token. Writing to it cannot admit, refuse, charge or release anything:
/// the worst a wrong name can do is make the node's own reading of what it is running wrong, which
/// is why it is a reading and not a gate.
#[derive(Debug, Default)]
pub struct GroupLeaseSlip {
    named: std::sync::Mutex<Vec<BucketId>>,
    grant: std::sync::Mutex<Option<DoorGrant>>,
}

impl GroupLeaseSlip {
    /// An empty slip.
    pub fn new() -> Self {
        GroupLeaseSlip::default()
    }

    /// Name a group the door counted this unit against.
    pub fn counted(&self, group: &'static str) {
        self.named
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(group_lease(group));
    }

    /// Take what the door named, emptying the slip. Called once, by the draw.
    pub fn taken(&self) -> Vec<BucketId> {
        std::mem::take(&mut *self.named.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Hand over the count the door's yes is holding, for the slot to keep.
    ///
    /// Written on the same line as the names and for the same reason: the door is the only thing
    /// that has it, and the loop is the only thing that can put it somewhere both of the unit's
    /// ends can reach. A slip that is dropped without ever being read gives the count straight
    /// back, which is what a refused or exempt unit needs and is exactly what happened before
    /// anything held it at all.
    pub fn holding(&self, grant: DoorGrant) {
        *self.grant.lock().unwrap_or_else(|e| e.into_inner()) = Some(grant);
    }

    /// Take what the door is holding, emptying the slip. Called once, by the draw.
    pub fn grant_taken(&self) -> Option<DoorGrant> {
        self.grant.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
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
    grant: Option<DoorGrant>,
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

    /// Keep the door's own count of this unit alongside the kernel's.
    ///
    /// One per unit: the door answers once, so a second grant here would be a second yes, and the
    /// first is given back rather than kept beside it.
    pub fn hold_grant(&mut self, grant: DoorGrant) {
        self.grant = Some(grant);
    }

    /// Whether the door's count is still being held here.
    pub fn holds_grant(&self) -> bool {
        self.grant.is_some()
    }

    /// Give every lease back, and say how many were given.
    ///
    /// The door's count goes back in the same breath, and by the same rule: this runs on the one
    /// path every unit leaves through, so the count the door took at the yes is released at the
    /// unit's end whatever the end was — a completion, a refusal after the door, a caller who went
    /// away, or the sweep on a task that is not there any more.
    pub fn release_all(&mut self, gauge: &ConcurrencyGauge) -> usize {
        let count = self.held.len();
        for bucket in self.held.drain(..) {
            gauge.release(&bucket);
        }
        self.grant = None;
        count
    }
}

/// The one owner of a unit's concurrency leases: the unit's slot in the in-flight table.
///
/// A unit has TWO ends — its own exit path and the node's sweep — and the rule is that leases go
/// back on every end. So they have to live where both ends can reach them, which is the slot and
/// not the running task's frame: a task that disappeared took its frame, and its `LeaseSet` with
/// it, leaving the gauge counting a unit that no longer exists. A cap that only ever goes up is a
/// node that stops admitting anything, and nothing about it is visible until it does.
///
/// Whichever end arrives first takes the set out of the cell; the second finds an unowned slot and
/// does nothing. That is the same shape as the hold cell beside it, for the same reason: one lease,
/// given back exactly once.
#[derive(Debug)]
pub struct LeaseCell {
    held: std::sync::Mutex<Option<LeaseSet>>,
}

impl LeaseCell {
    /// A cell owned by its unit, holding no leases yet.
    pub fn new() -> Self {
        LeaseCell {
            held: std::sync::Mutex::new(Some(LeaseSet::new())),
        }
    }

    /// Record a lease taken at the door.
    ///
    /// False once the leases have gone back, which is a lease taken against a unit that has already
    /// ended — the caller is holding a gauge count nothing will ever release, and it is told so
    /// here rather than finding out from a cap that never recovers.
    pub fn take(&self, bucket: BucketId) -> bool {
        match self.held.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            Some(set) => {
                set.take(bucket);
                true
            }
            None => false,
        }
    }

    /// Keep the door's own count of this unit here, for the life of the unit.
    ///
    /// True when the slot took it. False is a cell whose leases have already gone back — a unit
    /// whose other end ran while the door was still answering — and the count is released here
    /// instead of being parked on a slot nothing will ever empty. Either way the door's counter
    /// comes back down exactly once, which is the only property the cap depends on.
    pub fn hold_grant(&self, grant: DoorGrant) -> bool {
        match self.held.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            Some(set) => {
                set.hold_grant(grant);
                true
            }
            None => false,
        }
    }

    /// Whether the door's count of this unit is still held here.
    pub fn holds_grant(&self) -> bool {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(LeaseSet::holds_grant)
    }

    /// How many leases the unit is holding.
    pub fn held(&self) -> usize {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map_or(0, LeaseSet::len)
    }

    /// Whether the leases are still the unit's own. An unowned cell is a slot one of the two ends
    /// has already reclaimed, and the sweep reclaims nothing else of it.
    pub fn is_owned(&self) -> bool {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Give every lease back, and say how many. `None` when the other end got there first.
    pub fn release_all(&self, gauge: &ConcurrencyGauge) -> Option<usize> {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .map(|mut set| set.release_all(gauge))
    }
}

impl Default for LeaseCell {
    fn default() -> Self {
        LeaseCell::new()
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
        let entry = counts.entry(*bucket).or_insert(0);
        if *entry >= cap {
            return Err(ReasonCode::OverBudget);
        }
        *entry += 1;
        Ok(())
    }

    /// Count a lease a door has already granted.
    ///
    /// [`ConcurrencyGauge::acquire`] is a gate: it reads a cap and can refuse. This is not one, and
    /// deliberately cannot be. The decision about whether a unit may run was taken at the door, on
    /// the door's own counters, at the status and in the order the caller already sees; a second
    /// gate here would be a second place a unit can be turned away, and a refusal nobody asked for
    /// is the one change a lease that is only ever COUNTED cannot make.
    pub fn record(&self, bucket: &BucketId) {
        *self
            .counts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(*bucket)
            .or_insert(0) += 1;
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

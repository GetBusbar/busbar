// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The leases that count what a node is running right now, and the epoch a node's leases belong

use std::collections::HashMap;

use busbar_contract::caps::{OriginKind, ReasonCode};

/// A capped axis: an amount of money, a count of requests, a live gauge, or any declared meter
pub use busbar_contract::{BucketRef as BucketId, BucketScope, CapDimension};

/// A bucket that applies to everything.
#[must_use]
pub const fn bucket_all(id: &'static str) -> BucketId {
    BucketId {
        id,
        scope: BucketScope::All,
        capped: true,
    }
}

/// Which generation of the fleet's leases a slice belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(pub u64);

/// The bucket a unit's in-flight slot is counted on.
pub const IN_FLIGHT: BucketId = bucket_all("kernel:in_flight");

/// The bucket one capped-`concurrent` GROUP's leases are counted on.
pub const fn group_lease(group: &'static str) -> BucketId {
    bucket_all(group)
}

/// THE DOOR'S OWN COUNT OF THIS UNIT, held for as long as the unit is running.
pub struct DoorGrant(Box<dyn std::any::Any + Send + Sync>);

impl DoorGrant {
    /// Carry a door's grant, whatever it is.
    pub fn new<G: std::any::Any + Send + Sync>(grant: G) -> Self {
        DoorGrant(Box::new(grant))
    }
}

impl std::fmt::Debug for DoorGrant {
    /// The type it carries, and nothing of what is inside it. A grant is a door's own counter and
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
    pub fn holding(&self, grant: DoorGrant) {
        *self.grant.lock().unwrap_or_else(|e| e.into_inner()) = Some(grant);
    }

    /// Take what the door is holding, emptying the slip. Called once, by the draw.
    pub fn grant_taken(&self) -> Option<DoorGrant> {
        self.grant.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

/// Does a unit of this origin take a concurrency lease?
pub fn takes_lease(origin: OriginKind, kernel_verb_only: bool) -> bool {
    if kernel_verb_only {
        return false;
    }
    !matches!(origin, OriginKind::Handshake | OriginKind::Tick)
}

/// The concurrency leases one unit holds.
///
/// Released at the unit's END, for every end — never on the success path alone, never in a drop
/// guard. A unit has two ends and so this has two releasers, both reaching it through the unit's
/// [`LeaseCell`]: its own exit (the teller's exit path, and the settle arm that ends a child against
/// its parent) and the node's sweep (`tick::sweep_settle`) for a unit whose task disappeared.
/// Whichever arrives first gives the leases back; the second finds them gone.
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
    pub fn hold_grant(&mut self, grant: DoorGrant) {
        self.grant = Some(grant);
    }

    /// Whether the door's count is still being held here.
    pub fn holds_grant(&self) -> bool {
        self.grant.is_some()
    }

    /// Give every lease back, and say how many were given.
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

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Original native fee debt receipt (FEE-DEBT r1, d0c0f410). The existing budget flusher is the
//! only executor; this module holds its private capture evidence and the nonparticipating
//! observer a native ordinary admission funds before its first charge.
//!
//! Applied proves inclusion of an original mutation in the original aggregate flush lineage; it
//! never asserts a separate ledger row per request. CancelledBeforeSend is only the no-write
//! result of an immutable capture whose exact plain and dated debt was neutral. Neither is ever
//! inferred from a current cell read, a finished flag, or an equal bucket/window elsewhere.

use std::alloc::Layout;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use busbar_contract::storage::{StorageCredit, StorageSource};

/// The adopted bound on candidate entries one association slice examines.
pub const ASSOCIATION_CANDIDATES: usize = 64;

/// The bounded number of distinct captures one target can wait on at once. A target that would
/// need more reports Unresolved; no dependency is ever erased to fit.
const CAPTURES_PER_TARGET: usize = 4;

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Per-GovState producer identity. Cell incarnations are minted here, never accepted from callers.
#[derive(Default)]
pub(crate) struct FeeDebtProducer {
    identity: Arc<()>,
    incarnations: AtomicU64,
    association: OnceLock<Weak<dyn FeeDebtAssociate>>,
}

impl FeeDebtProducer {
    /// A distinct nonzero incarnation for one installed cell; exhaustion refuses.
    pub(crate) fn next_incarnation(&self) -> Option<u64> {
        self.incarnations
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .ok()?
            .checked_add(1)
    }

    pub(crate) fn identity(&self) -> &Arc<()> {
        &self.identity
    }

    /// Bind the trusted observer owner once. It is held weakly: no strong Node reference.
    pub(crate) fn bind(&self, owner: Weak<dyn FeeDebtAssociate>) -> Result<(), &'static str> {
        self.association
            .set(owner)
            .map_err(|_| "fee debt association already bound")
    }

    fn owner(&self) -> Option<Arc<dyn FeeDebtAssociate>> {
        self.association.get()?.upgrade()
    }

    /// Offer one capture to every retained observer, slice by slice. Called by the flusher after
    /// releasing all budget, money and checkpoint locks. The flight retains the capture and its
    /// cursor, so an interrupted association resumes rather than restarting or losing evidence.
    /// Without a bound owner (or after it is destroyed) no live observer can exist.
    pub(crate) fn associate(&self, capture: &Arc<FeeCapture>) {
        let Some(owner) = self.owner() else {
            locked(&capture.association).complete = true;
            return;
        };
        loop {
            let cursor = {
                let association = locked(&capture.association);
                if association.complete {
                    return;
                }
                association.cursor
            };
            let next = owner.associate(capture, cursor);
            let mut association = locked(&capture.association);
            match next {
                FeeAssociation::Complete => {
                    association.complete = true;
                    return;
                }
                FeeAssociation::Pending(cursor) => {
                    let valid = cursor.upper == association.cursor.upper.or(cursor.upper)
                        && cursor.last > association.cursor.last;
                    if !valid {
                        // A non-progressing or horizon-changing owner cannot be trusted to
                        // finish; the capture stays unassociated and its targets unresolved.
                        return;
                    }
                    association.cursor = cursor;
                }
            }
        }
    }
}

/// The finite horizon cursor of one capture's association, retained by its flight.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeeCursor {
    pub last: Option<u64>,
    pub upper: Option<u64>,
}

pub enum FeeAssociation {
    Pending(FeeCursor),
    Complete,
}

/// The trusted original observer owner (the Node terminal book), bound once at assembly. One
/// call examines at most [`ASSOCIATION_CANDIDATES`] entries, never performs Store I/O, and is
/// never entered while a budget, money or checkpoint lock is held.
pub trait FeeDebtAssociate: Send + Sync {
    fn associate(&self, capture: &Arc<FeeCapture>, cursor: FeeCursor) -> FeeAssociation;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaptureOutcome {
    Pending,
    Applied,
    CancelledBeforeSend,
    /// The flight moved part of this debt back to the original cell: a later capture of the
    /// same original target must consume this witness once.
    Deferred,
    Unresolved,
}

#[derive(Default)]
struct Association {
    cursor: FeeCursor,
    complete: bool,
}

/// Immutable original capture evidence frozen under the source cell lock and retained by the
/// existing flight until it is associated and resolved.
pub struct FeeCapture {
    identity: Arc<()>,
    bucket: String,
    incarnation: u64,
    window: u64,
    cut: u64,
    no_write: bool,
    outcome: Mutex<CaptureOutcome>,
    association: Mutex<Association>,
}

impl FeeCapture {
    pub(crate) fn frozen(
        producer: &FeeDebtProducer,
        bucket: &str,
        incarnation: u64,
        window: u64,
        cut: u64,
        no_write: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            identity: producer.identity.clone(),
            bucket: bucket.to_owned(),
            incarnation,
            window,
            cut,
            no_write,
            outcome: Mutex::new(CaptureOutcome::Pending),
            association: Mutex::new(Association::default()),
        })
    }

    pub(crate) fn associated(&self) -> bool {
        locked(&self.association).complete
    }

    /// The existing flusher's terminal result for this capture. Only called once the original
    /// flight has finished its own custody; an unassociated capture can never publish.
    pub(crate) fn finish(&self, applied: bool, deferred: bool) {
        let mut outcome = locked(&self.outcome);
        if *outcome != CaptureOutcome::Pending {
            return;
        }
        *outcome = if !self.associated() || !applied {
            CaptureOutcome::Unresolved
        } else if self.no_write {
            CaptureOutcome::CancelledBeforeSend
        } else if deferred {
            CaptureOutcome::Deferred
        } else {
            CaptureOutcome::Applied
        };
    }

    fn outcome(&self) -> CaptureOutcome {
        *locked(&self.outcome)
    }
}

/// One original bucket leg actually charged by the observed admission.
struct Target {
    bucket: Box<str>,
    incarnation: u64,
    window: Option<u64>,
    last: u64,
    covered: u64,
    captures: [Option<Arc<FeeCapture>>; CAPTURES_PER_TARGET],
    unresolved: bool,
}

impl Target {
    fn matches(&self, identity: &Arc<()>, capture: &FeeCapture) -> bool {
        Arc::ptr_eq(identity, &capture.identity)
            && self.incarnation != 0
            && self.incarnation == capture.incarnation
            && self.window == Some(capture.window)
            && *self.bucket == *capture.bucket
    }

    fn offer(&mut self, capture: &Arc<FeeCapture>) {
        if self
            .captures
            .iter()
            .flatten()
            .any(|held| Arc::ptr_eq(held, capture))
        {
            return;
        }
        // A deferred witness is consumed once by the next original capture of this target.
        if let Some(slot) = self.captures.iter_mut().find(|slot| {
            slot.as_ref().is_some_and(|held| {
                held.outcome() == CaptureOutcome::Deferred && held.cut < capture.cut
            })
        }) {
            *slot = Some(capture.clone());
            self.covered = self.covered.max(capture.cut.min(self.last));
            return;
        }
        // Membership: an uncovered original marker existed in the source before this cut.
        if self.last <= self.covered || self.covered >= capture.cut {
            return;
        }
        match self.captures.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(capture.clone());
                self.covered = capture.cut.min(self.last);
            }
            None => self.unresolved = true,
        }
    }

    fn status(&self) -> TargetStatus {
        if self.unresolved {
            return TargetStatus::Unresolved;
        }
        if self.incarnation == 0 || self.last == 0 || self.last > self.covered {
            return TargetStatus::Pending;
        }
        let mut applied = false;
        for capture in self.captures.iter().flatten() {
            match capture.outcome() {
                CaptureOutcome::Applied => applied = true,
                CaptureOutcome::CancelledBeforeSend => {}
                CaptureOutcome::Pending | CaptureOutcome::Deferred => return TargetStatus::Pending,
                CaptureOutcome::Unresolved => return TargetStatus::Unresolved,
            }
        }
        if applied {
            TargetStatus::Applied
        } else {
            TargetStatus::CancelledBeforeSend
        }
    }
}

enum TargetStatus {
    Pending,
    Applied,
    CancelledBeforeSend,
    Unresolved,
}

/// The whole original target set's typed receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeDebtReceipt {
    pub applied: u16,
    pub cancelled_before_send: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeDebtStatus {
    Pending,
    Complete(FeeDebtReceipt),
    /// Original custody remains; this observer can never publish a receipt.
    Unresolved,
}

/// Why an observed admission refused before any effect.
#[derive(Debug)]
pub enum FeeDebtRefusal {
    Capacity,
    Identity,
}

struct ObserverState {
    prepared: bool,
    targets: Vec<Target>,
    unresolved: bool,
    // Charged target backing; dropped after the targets themselves.
    credit: Option<StorageCredit>,
}

/// Private nonparticipating observer funded before the original native money admission. It
/// holds no FeeParticipation child, grant, or strong Node/GovState reference.
pub struct FeeDebtObserver {
    identity: Arc<()>,
    gov: Weak<super::GovState>,
    source: StorageSource,
    state: Mutex<ObserverState>,
    _credit: StorageCredit,
}

impl FeeDebtObserver {
    /// Fund the observer payload from the original request source before admission.
    pub(crate) fn reserve(
        gov: &Arc<super::GovState>,
        source: &StorageSource,
    ) -> Result<Arc<Self>, FeeDebtRefusal> {
        let credit = source
            .try_reserve(Layout::new::<Self>().size())
            .map_err(|_| FeeDebtRefusal::Capacity)?;
        Ok(Arc::new(Self {
            identity: gov.fee_debt.identity.clone(),
            gov: Arc::downgrade(gov),
            source: source.clone(),
            state: Mutex::new(ObserverState {
                prepared: false,
                targets: Vec::new(),
                unresolved: false,
                credit: None,
            }),
            _credit: credit,
        }))
    }

    /// Reserve one fixed target slot per original bucket leg, plus its identifier bytes, before
    /// the first mutation. Refusal leaves the admission gate closed.
    pub(crate) fn prepare<'a>(
        &self,
        gov: &super::GovState,
        buckets: impl Iterator<Item = &'a str> + Clone,
    ) -> Result<(), FeeDebtRefusal> {
        if !Arc::ptr_eq(&self.identity, &gov.fee_debt.identity) {
            return Err(FeeDebtRefusal::Identity);
        }
        let mut state = locked(&self.state);
        if state.prepared {
            return Err(FeeDebtRefusal::Identity);
        }
        let count = buckets.clone().count();
        let names = buckets
            .clone()
            .try_fold(0usize, |sum, bucket| sum.checked_add(bucket.len()))
            .ok_or(FeeDebtRefusal::Capacity)?;
        let bytes = Layout::array::<Target>(count)
            .map_err(|_| FeeDebtRefusal::Capacity)?
            .size()
            .checked_add(names)
            .ok_or(FeeDebtRefusal::Capacity)?;
        let credit = self
            .source
            .try_reserve(bytes)
            .map_err(|_| FeeDebtRefusal::Capacity)?;
        let mut targets = Vec::new();
        if targets.try_reserve_exact(count).is_err() {
            return Err(FeeDebtRefusal::Capacity);
        }
        for bucket in buckets {
            targets.push(Target {
                bucket: bucket.into(),
                incarnation: 0,
                window: None,
                last: 0,
                covered: 0,
                captures: Default::default(),
                unresolved: false,
            });
        }
        state.targets = targets;
        state.credit = Some(credit);
        state.prepared = true;
        Ok(())
    }

    /// Publish one original mutation marker. Called under the SAME budget shard lock as the
    /// mutation it records; performs only local field updates and allocates nothing.
    pub(crate) fn mark(&self, leg: usize, bucket: &str, incarnation: u64, window: u64, seq: u64) {
        let mut state = locked(&self.state);
        let Some(target) = state.targets.get_mut(leg) else {
            state.unresolved = true;
            return;
        };
        if *target.bucket != *bucket
            || (target.incarnation != 0 && target.incarnation != incarnation)
            || target.window.is_some_and(|held| held != window)
            || seq <= target.last
        {
            target.unresolved = true;
            return;
        }
        target.incarnation = incarnation;
        target.window = Some(window);
        target.last = seq;
    }

    /// A refund hook found no original cell or a different target than the one charged.
    pub(crate) fn unresolved(&self) {
        locked(&self.state).unresolved = true;
    }

    /// The leg index of an original (bucket, window) target, for refund markers.
    pub(crate) fn leg(&self, bucket: &str, window: u64) -> Option<usize> {
        locked(&self.state)
            .targets
            .iter()
            .position(|target| *target.bucket == *bucket && target.window == Some(window))
    }

    /// Associate one original capture with every matching target of this observer.
    pub fn offer(&self, capture: &Arc<FeeCapture>) {
        let mut state = locked(&self.state);
        for target in &mut state.targets {
            if target.matches(&self.identity, capture) {
                target.offer(capture);
            }
        }
    }

    /// The whole original target set: Complete only when every target is Applied or honestly
    /// CancelledBeforeSend.
    pub fn status(&self) -> FeeDebtStatus {
        let state = locked(&self.state);
        if state.unresolved {
            return FeeDebtStatus::Unresolved;
        }
        if !state.prepared {
            return FeeDebtStatus::Pending;
        }
        let mut receipt = FeeDebtReceipt {
            applied: 0,
            cancelled_before_send: 0,
        };
        for target in &state.targets {
            match target.status() {
                TargetStatus::Pending => return FeeDebtStatus::Pending,
                TargetStatus::Unresolved => return FeeDebtStatus::Unresolved,
                TargetStatus::Applied => receipt.applied = receipt.applied.saturating_add(1),
                TargetStatus::CancelledBeforeSend => {
                    receipt.cancelled_before_send = receipt.cancelled_before_send.saturating_add(1);
                }
            }
        }
        FeeDebtStatus::Complete(receipt)
    }
}

impl Drop for FeeDebtObserver {
    /// Release this observer's eviction obligations on the exact original cells.
    fn drop(&mut self) {
        let Some(gov) = self.gov.upgrade() else {
            return;
        };
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for target in &state.targets {
            if target.incarnation != 0 {
                gov.release_fee_obligation(&target.bucket, target.incarnation);
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/fee_debt_tests.rs"]
mod tests;

/// Why an observed native admission refused before effects.
#[derive(Debug)]
pub enum ObservedAdmission {
    Blocked(super::LimitBlocked),
    Observer(FeeDebtRefusal),
}

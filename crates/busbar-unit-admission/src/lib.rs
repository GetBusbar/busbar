// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-unit-admission — the door
//!
//! Step 4. The one place a request is told yes or no for a reason that costs money.
//!
//! ## The one rule this crate exists to keep
//!
//! **The decision is 1.5.5's.** Not "equivalent to", not "faithful to the spirit of" — the same
//! function, moved. Every comparison, every truncation, every ordering is the one at the tag. A
//! request that 1.5.5 admitted is admitted here; a request that 1.5.5 refused is refused here, at
//! the same bucket, on the same metric, with the same retry hint. The only things that changed are
//! the ones that could not carry: the ledger cells arrive through a trait instead of a field, and
//! the answer is wrapped in a capability type instead of returned bare. Neither touches an
//! arithmetic operator.
//!
//! That constraint is the whole design. It is why there is no config parser here, no store, no
//! HTTP, no async runtime, and exactly one workspace dependency. Nothing in this crate can quietly
//! change who gets served.
//!
//! ## The shape
//!
//! - [`Door`] holds the decision: check-then-charge over a bucket chain, under one set of locks.
//! - [`AdmissionUnit`] wraps it in the sealed step-4 trait shape, turning the answer into a
//!   [`Decision<Admit>`] carrying a hold.
//! - [`BucketChain`] is what the door walks: the principal's attribution bucket, then each
//!   ancestor group's per-window buckets.
//! - [`Pricer`] derives spend from tokens, because no spend figure is ever stored.
//! - [`CellStore`] is the seam to the ledger cells — the only I/O in the crate, and it is
//!   somebody else's.
//!
//! ## The hold is accounting, not a second door
//!
//! The door's answer carries a hold, and the hold is sized from the estimate. It does not decide
//! anything. It reserves; if the reservation turns out too small the unit tops it up, and if there
//! is nothing left to draw the unit still runs to its end and posts the excess. A hold can never
//! refuse a request the decision admitted. This matters more than it sounds: it is the reason a
//! conservative estimate is invisible to a caller, and the reason the door needs no exception in
//! the parity corpus.
//!
//! ## What is deliberately node-local
//!
//! The cells are hydrated once at boot and never re-read on the request path. Two nodes sharing a
//! durable store therefore each admit up to the full cap until one restarts. That is the behaviour
//! at the tag, reproduced on purpose, not a gap waiting to be closed here.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod cells;
pub mod chain;
pub mod decide;
pub mod estimate;
pub mod price;
pub mod window;

pub use cells::{CellStore, Cells, InMemoryCells, InMemoryLocked, LedgerCell};
pub use chain::{
    BucketChain, ChainBucket, ChainError, ChainGroup, GroupBucket, GroupRuntime, GroupTable,
    MissingGroup, STANDARD_TIER_BP,
};
pub use decide::{AdmitGrant, Blocked, Door, Gauges, Metric};
pub use estimate::{ClassEstimate, Estimate};
pub use price::{Pricer, RateNanos};
pub use window::{budget_window, window_end};

use busbar_caps::{
    step::Admit, AdmitToken, Decision, Hold, HoldCell, PostingFlags, PrincipalId, ReasonCode,
    Refusal, UnitToken,
};

/// The sealed step-4 shape: the door, asked.
///
/// The signature is the one the architecture pins, with one addition it cannot avoid: building a
/// [`Decision`] takes the step's own unit token, and opening a [`Hold`] takes the admit token, so
/// the call is lent both. Neither is stored; both are gone when the call returns.
pub trait Admission {
    /// Judge one unit. The answer either carries the unit's admission — its own hold, a spend
    /// against a parent's, or nothing at all for a unit priced at zero — or a refusal naming why.
    fn admit(
        &mut self,
        estimate: &Estimate,
        principal: &PrincipalId,
        chain: &BucketChain,
        admit_token: &AdmitToken<Admit>,
        unit_token: &UnitToken<Admit>,
    ) -> Decision<Admit>;
}

/// Open a unit's arrival hold.
///
/// The hold a unit carries into the in-flight table before it has reached the door. It reserves
/// nothing — a unit refused at the gate has spent nothing — and its whole point is that even a
/// refusal is an event with a cell of its own to settle.
///
/// It lives here, in the door, rather than in the table that carries it, because the design's claim
/// is that a hold cannot exist without this unit's own token. The kernel lends the token for the
/// length of this call, exactly as the loop does at step 4; the constructor is called here.
pub fn arrival_hold(principal: PrincipalId, admit_token: &AdmitToken<Admit>) -> Hold {
    Hold::open(admit_token, principal, 0)
}

/// The door, bound to one request.
///
/// The decision needs three things the trait shape has nowhere to put: which pool the request is
/// dispatched through, which rate table it is judged against, and the pinned arrival epoch every
/// charge lands in. They are bound here, once, at the top of the request, so a straddling request
/// can never be judged against one clock and charged against another.
///
/// After the call the caller reads back what the decision produced: the in-flight grant to hold
/// for the life of the request, or the blocking bucket to render. The refusal's reason code is a
/// closed vocabulary and cannot carry a bucket name, so the byte-exact refusal is rendered from
/// [`AdmissionUnit::blocked`], not from the decision.
pub struct AdmissionUnit<'r, S: CellStore> {
    door: &'r Door<S>,
    pricer: &'r Pricer,
    pool: &'r str,
    now: u64,
    parent: Option<&'r HoldCell>,
    grant: Option<AdmitGrant>,
    blocked: Option<Blocked>,
    downgraded_from: Option<&'r str>,
}

impl<'r, S: CellStore> AdmissionUnit<'r, S> {
    /// Bind the door to one request: its pool, its rate table, its pinned arrival epoch.
    pub fn new(door: &'r Door<S>, pricer: &'r Pricer, pool: &'r str, now: u64) -> Self {
        AdmissionUnit {
            door,
            pricer,
            pool,
            now,
            parent: None,
            grant: None,
            blocked: None,
            downgraded_from: None,
        }
    }

    /// Mark this unit as a child spending against a parent's still-open hold. The parent's cell is
    /// the runtime seal: a child whose parent has already exited is refused there and posts late
    /// on its own, which is the ledger's problem, not the door's.
    pub fn with_parent(mut self, parent: &'r HoldCell) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Mark this admission as the far end of a downgrade: the pool named here blocked on a budget
    /// limit that declared a downgrade, and this unit is the re-admission through the pool it
    /// pointed at.
    ///
    /// The caller drives the cascade, because only the caller knows which pools it walked. What it
    /// hands back here is the one thing the ledger cannot re-derive later: by the time a posting is
    /// written, a downgraded unit looks like any other unit on this pool, and the fact that it is
    /// here only because a narrower pool ran out of budget is gone unless the door says so.
    #[must_use]
    pub fn after_downgrade(mut self, from: &'r str) -> Self {
        self.downgraded_from = Some(from);
        self
    }

    /// The pool this unit was downgraded from, where it was.
    #[must_use]
    pub fn downgraded_from(&self) -> Option<&str> {
        self.downgraded_from
    }

    /// The flags the door decided this unit's posting carries.
    ///
    /// The cascade is the only one of them: everything else about a posting is decided by the hold,
    /// the usage report or the ledger. A unit served through a pool it was downgraded into is
    /// journaled as downgraded, which is what the design's own cell for the exhaustion behaviour
    /// asserts.
    #[must_use]
    pub fn posting_flags(&self) -> PostingFlags {
        if self.downgraded_from.is_some() {
            PostingFlags::DOWNGRADED
        } else {
            PostingFlags::NONE
        }
    }

    /// The in-flight grant the admission took, once it has been taken. Holding it is what keeps a
    /// concurrent-capped group's gauge raised; dropping it releases every lease at once.
    pub fn take_grant(&mut self) -> Option<AdmitGrant> {
        self.grant.take()
    }

    /// The blocking bucket, when the door refused. Carries the group, the metric, the window and
    /// the pool scope, which is everything the refusal has to print and more than the closed
    /// reason code can hold.
    pub fn blocked(&self) -> Option<&Blocked> {
        self.blocked.as_ref()
    }

    /// How far this unit's reservation may still be grown, in nano-units.
    ///
    /// The other half of "the hold is accounting". The door sized the reservation off an estimate;
    /// when the unit's accrual passes it, the reservation is topped up out of what the principal's
    /// slice still holds, and THIS is that figure. A chain that declares no spend cap has no ceiling
    /// to grow into, so the answer is unbounded; a window already at its cap answers zero, and zero
    /// is a top-up that does not happen — never a unit that does not run. Nothing here charges,
    /// blocks or refuses.
    #[must_use]
    pub fn headroom_nanos(&self, chain: &BucketChain) -> u64 {
        match self
            .door
            .budget_headroom_cents(self.pricer, chain, self.pool, self.now)
        {
            None => u64::MAX,
            Some(cents) => {
                let cents = u128::try_from(cents.max(0)).unwrap_or(0);
                u64::try_from(cents.saturating_mul(price::NANOS_PER_CENT)).unwrap_or(u64::MAX)
            }
        }
    }

    /// Spend against the unit's hold, growing the reservation out of the slice where the slice has
    /// anything left and carrying the remainder as an overdraft where it has not.
    ///
    /// One call so that the two halves cannot drift: whatever the headroom says, the spend lands.
    pub fn spend(
        &self,
        hold: &mut busbar_caps::Hold,
        chain: &BucketChain,
        amount: u64,
    ) -> busbar_caps::Spend {
        hold.spend(amount, self.headroom_nanos(chain))
    }

    /// Refund the fee for a request that produced no usable result. The request slot stays
    /// consumed; see [`Door::refund_request`] for why that is the whole point.
    pub fn refund(&self, chain: &BucketChain) {
        self.door.refund_request(chain, self.pool, self.now);
    }
}

impl<S: CellStore> Admission for AdmissionUnit<'_, S> {
    fn admit(
        &mut self,
        estimate: &Estimate,
        principal: &PrincipalId,
        chain: &BucketChain,
        admit_token: &AdmitToken<Admit>,
        unit_token: &UnitToken<Admit>,
    ) -> Decision<Admit> {
        match self.door.try_admit(self.pricer, chain, self.pool, self.now) {
            Ok(grant) => {
                self.grant = Some(grant);
                self.blocked = None;
                let nanos = estimate.hold_nanos(chain.tier_bp());
                // A child spends against its parent's reservation rather than opening one of its
                // own. If the parent has already gone, the child is still ADMITTED — the door said
                // yes and the counters are charged — and the ledger posts it late against a
                // synchronous draw. Refusing here would refuse a unit the decision admitted.
                if let Some(cell) = self.parent {
                    if let Ok(accrual) = cell.accrue_child(principal, nanos, admit_token) {
                        return Decision::proceed(
                            unit_token,
                            busbar_caps::Admission::Accrual(accrual),
                        );
                    }
                }
                if nanos == 0 {
                    return Decision::proceed(unit_token, busbar_caps::Admission::ZeroHold);
                }
                Decision::proceed(
                    unit_token,
                    busbar_caps::Admission::Own(Hold::open(admit_token, principal.clone(), nanos)),
                )
            }
            Err(blocked) => {
                let refusal = refusal_for(&blocked);
                self.blocked = Some(blocked);
                self.grant = None;
                Decision::refuse(unit_token, refusal)
            }
        }
    }
}

/// Turn a blocking bucket into the closed refusal the journal records.
///
/// The split is the one the wire already made at the tag and must keep: a spend cap, and a
/// principal bound to a group this node does not have, are over-quota; every count cap — requests,
/// tokens of any tier, and the in-flight gauge — is a rate limit. One dialect answers those two
/// with different statuses, so collapsing them would silently relabel a block.
fn refusal_for(blocked: &Blocked) -> Refusal {
    match blocked {
        Blocked::Disabled(_) => Refusal::new(ReasonCode::GroupFrozen),
        // Fail-closed: the caps cannot be read, so nothing is admitted under them. It renders as
        // over-quota, the same as a spend cap.
        Blocked::MissingGroup(_) => Refusal::new(ReasonCode::OverBudget),
        Blocked::Limit {
            metric,
            retry_after,
            ..
        } => {
            let reason = if metric.is_quota() {
                ReasonCode::OverBudget
            } else {
                ReasonCode::RateLimited
            };
            let refusal = Refusal::new(reason);
            match retry_after {
                Some(secs) => refusal.retry_after(u32::try_from(*secs).unwrap_or(u32::MAX)),
                None => refusal,
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

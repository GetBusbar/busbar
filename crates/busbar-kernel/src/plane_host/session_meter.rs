// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL-OWNED SESSION METER — the pricing half of a live carrier, on the kernel's side of the
//! seam (BUSBAR-1.6.0 #43: a plane is PRICING-BLIND and emits usage facts; the rate card and fees are
//! core-owned and never cross the ABI; #71: the ledger event is raw counts per class).
//!
//! A live voice carrier cannot be priced after the fact: the plane must be able to HARD-CLOSE it the
//! moment the caller's budget is dry. Until this module the plane did that arithmetic itself — it
//! priced each turn (`price_usage`), settled the nanodollar increment against a lease (`cost_settle`)
//! and read the cap back. Now the plane holds a [`SessionMeter`] and speaks COUNTS only:
//!
//! * [`SessionMeter::open`] — at session start, over a [`SessionBudget`] the KERNEL derived
//!   ([`SessionBudget::for_principal`]); `None` is a refuse-all budget and the session never opens;
//! * [`SessionMeter::report_turn`] — one turn's raw counts per class; the answer is
//!   [`TurnVerdict::Live`] or [`TurnVerdict::MustClose`], never a figure;
//! * [`SessionMeter::close`] — at teardown, idempotent.
//!
//! THE ARITHMETIC IS THE LEASE'S, MOVED, NOT CHANGED. [`HostMeteringPort`] runs exactly what the
//! plane's host lease ran: price through the host's rate card (`MeteringHost::price_usage`), clamp the
//! `u128` into `u64` saturating HIGH, settle it (`MeteringHost::cost_settle`), and close on an unpriced
//! model, an unknown lease or `settled ≥ cap`. [`LocalMeteringPort`] is the pre-host stand-in with
//! pricing off: a refuse-all cap is denied at the door and every turn is live, exactly as the
//! in-process lease priced at zero behaved. So the stored figure, the cap comparison and the hard-close
//! turn are byte-identical to the lease the plane used to drive.

use super::{CostLeaseId, EngineHost, MeteringHost, SettleOutcome};
use crate::billing::Usage;
use busbar_api::{BudgetBucketState, VirtualKey};

/// A SESSION'S MONEY TERMS, all nanodollars and all kernel-derived: the coarse `estimate_nanos`
/// debited at open, the once-per-session `fee_nanos` (`0` = none), and the TRUE ceiling `cap_nanos`
/// exhaustion is judged against (`None` = uncapped, `Some(0)` = refuse-all). A plane passes it through
/// to [`SessionMeter::open`] and reads none of it. The default is uncapped with no estimate — the
/// budget a meter that prices nothing (or decides from counts alone) is opened under.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SessionBudget {
    pub estimate_nanos: u64,
    pub fee_nanos: u64,
    pub cap_nanos: Option<u64>,
}

impl SessionBudget {
    /// The budget a presenting key opens a session under: the coarse estimate, no flat fee, and the
    /// tightest remaining bucket of the key's budget chain as the cap. Uncapped when there is no key,
    /// governance is off, or nothing in the chain is capped.
    pub fn for_principal(host: &dyn EngineHost, key: Option<&VirtualKey>, now: u64) -> Self {
        SessionBudget {
            // The coarse over-estimate debited at open — an audit tap, not a ceiling.
            estimate_nanos: 1_000,
            fee_nanos: 0,
            cap_nanos: key.zip(host.governance()).and_then(|(key, gov)| {
                cap_nanos_from_buckets(&host.budget_state(&gov, &host.cost(), key, now))
            }),
        }
    }
}

/// THE SESSION CAP A BUDGET CHAIN IMPOSES — the tightest remaining amount across the chain, widened
/// to nanodollars. `None` when no bucket is capped; `Some(0)` (refuse-all) when the tightest is already
/// spent. Saturating, so an implausibly large budget clamps instead of wrapping into a tiny one.
pub fn cap_nanos_from_buckets(buckets: &[BudgetBucketState]) -> Option<u64> {
    let tightest = buckets.iter().filter_map(|b| b.remaining_micros).min()?;
    // An already-spent (or overspent) chain is a refuse-all `Some(0)`; otherwise widen micro-units
    // (1e-6) to the lease's nanodollars (1e-9).
    Some((tightest.max(0) as u64).saturating_mul(1_000))
}

/// One open metered session, as the meter that opened it knows it. Opaque to the plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeterId(pub u64);

/// What a reported turn means for the carrier. The plane never learns why a session must close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnVerdict {
    Live,
    MustClose,
}

/// THE COUNT-ONLY SESSION METER a plane holds. See the module doc.
pub trait SessionMeter: Send + Sync {
    /// Open a metered session; `None` is a refused budget and the session must not open.
    fn open(&self, budget: &SessionBudget) -> Option<MeterId>;
    /// Report ONE turn's raw counts per class for `model`.
    fn report_turn(&self, id: MeterId, model: &str, counts: &Usage) -> TurnVerdict;
    /// What the session has settled so far — the audit tap; `0` for an unknown or closed session,
    /// and for a meter that settles nothing.
    fn settled(&self, _id: MeterId) -> u64 {
        0
    }
    /// Close the session. Idempotent; a meter with nothing host-side to close does nothing.
    fn close(&self, _id: MeterId) {}
}

/// THE PRODUCTION METER — the host's reserve-then-settle lease, priced through the host's rate card.
pub struct HostMeteringPort(std::sync::Arc<dyn MeteringHost>);

impl HostMeteringPort {
    /// Bind the meter over a host's lease slice.
    pub fn new(host: std::sync::Arc<dyn MeteringHost>) -> Self {
        HostMeteringPort(host)
    }
}

impl SessionMeter for HostMeteringPort {
    fn open(&self, budget: &SessionBudget) -> Option<MeterId> {
        let (estimate, fee) = (budget.estimate_nanos.into(), budget.fee_nanos.into());
        let cap = budget.cap_nanos.map(u128::from);
        let lease = self.0.cost_reserve(estimate, fee, cap)?;
        Some(MeterId(lease.0))
    }

    fn report_turn(&self, id: MeterId, model: &str, counts: &Usage) -> TurnVerdict {
        // An unpriced model on a present rate card fails CLOSED: it must not meter as free.
        let Some(priced) = self.0.price_usage(model, counts) else {
            return TurnVerdict::MustClose;
        };
        // The increment clamps into u64 saturating HIGH, exactly as the plane's lease did.
        let clamped = priced.min(u128::from(u64::MAX));
        match self.0.cost_settle(CostLeaseId(id.0), clamped) {
            Some(SettleOutcome { exhausted: false }) => TurnVerdict::Live,
            _ => TurnVerdict::MustClose,
        }
    }

    fn settled(&self, id: MeterId) -> u64 {
        self.0
            .cost_settled(CostLeaseId(id.0))
            .map_or(0, |n| u64::try_from(n).unwrap_or(u64::MAX))
    }

    fn close(&self, id: MeterId) {
        let _ = self.0.cost_close(CostLeaseId(id.0));
    }
}

/// THE PRE-HOST METER — pricing off, in process: a refuse-all cap is denied at the door, every turn
/// prices at zero and so never dries the cap, and nothing host-side needs closing.
pub struct LocalMeteringPort;

impl SessionMeter for LocalMeteringPort {
    fn open(&self, budget: &SessionBudget) -> Option<MeterId> {
        (budget.cap_nanos != Some(0)).then_some(MeterId(0))
    }

    fn report_turn(&self, _id: MeterId, _model: &str, _counts: &Usage) -> TurnVerdict {
        TurnVerdict::Live
    }
}

#[cfg(test)]
#[path = "tests/session_meter_tests.rs"]
mod session_meter_tests;

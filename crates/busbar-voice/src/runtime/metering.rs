// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONTINUOUS-METERING LEASE — the marquee guarantee (design `plane4-duplex-session.md` §2.5, §4 "the D2 lease").
//!
//! A live voice carrier cannot be priced after the fact the way a one-shot request is: the session is
//! open-ended and the plane must be able to HARD-CLOSE it mid-stream the instant the budget is dry.
//!
//! THE PLANE IS PRICING-BLIND (BUSBAR-1.6.0 #43, #71). It used to price each turn itself — the host's
//! rate card through `price_usage`, then a nanodollar settle against its lease — and read exhaustion
//! back. That arithmetic now lives on the kernel's side of the seam, in
//! `busbar_kernel::plane_host::session_meter`: the plane holds a [`SessionMeter`], opens a
//! [`SessionLease`] over a kernel-derived [`SessionBudget`] it never reads, reports each turn's RAW
//! COUNTS, and is told only [`TurnVerdict::Live`] or [`TurnVerdict::MustClose`]. The production meter
//! is the kernel's [`HostMeteringPort`] over the live host's lease slice; the pre-host stand-in is the
//! kernel's [`LocalMeteringPort`] (pricing off). The figures are the lease's, byte for byte — the
//! kernel runs the arithmetic the plane used to.

pub use busbar_kernel::plane_host::session_meter::{
    HostMeteringPort, LocalMeteringPort, MeterId, SessionBudget, SessionMeter, TurnVerdict,
};
use busbar_kernel::plane_host::EngineHost;
use std::sync::Arc;

/// THE PRESENTING-KEY ATTRIBUTION a live session lands each turn's usage on — through the CORE METER
/// SEAM (`host.meter_ledger` + `host.meter_series`), exactly as the LLM plane's `ledger_and_meter`.
/// Voice has NO meter and NO budget of its own (the vetted doctrine: "no separate meter, no separate
/// budget"); this routes each turn's token usage onto the ONE ledger, attributed to the presenting
/// virtual key, so a voice session's spend shows up on `usage_for(key)` / the admin usage series just
/// like a model call or a tool call. Built at the governed session-open (where the resolved key + the
/// live host are both in hand) and `None` on an ungoverned deployment (no key ⇒ nothing to attribute).
pub struct TurnMeter {
    /// The live engine host — the one seam every plane meters through.
    host: Arc<dyn EngineHost>,
    /// The presenting virtual key the turn's spend is attributed to (owned; cloned at open).
    key: busbar_api::VirtualKey,
    /// The pool label for the metering series (the voice front-door pool).
    pool: &'static str,
    /// The provider label for the per-(key, model, provider) metering series.
    provider: &'static str,
}

impl TurnMeter {
    /// Bind the attribution over a live host + resolved key.
    #[must_use]
    pub(crate) fn new(
        host: Arc<dyn EngineHost>,
        key: busbar_api::VirtualKey,
        pool: &'static str,
        provider: &'static str,
    ) -> Self {
        TurnMeter {
            host,
            key,
            pool,
            provider,
        }
    }

    /// Land ONE turn's usage on the principal's ledger + metering series through the core seam — the
    /// voice twin of the LLM plane's `ledger_and_meter`. The budget-chain accrual (`meter_ledger`)
    /// is the money signal `usage_for(key)` derives spend from; the raw series (`meter_series`) feeds
    /// the admin usage report. No-ops when governance is off (the host mints no meter pin).
    pub(crate) fn record_turn(&self, model: &str, usage: &busbar_substrate_values::billing::Usage) {
        if let Some(pin) = self.host.meter_pin() {
            let now = self.host.clock_now_secs();
            self.host
                .meter_ledger(&pin, &self.key, self.pool, model, usage, now);
            self.host
                .meter_series(pin.gov(), &self.key.id, model, self.provider, None, now);
        }
    }
}

/// ONE OPEN METERED SESSION, plane-side: the kernel [`SessionMeter`] that opened it and the id it
/// knows the session by. The plane reports each turn's RAW COUNTS and reads back only whether the
/// carrier may stay open — it names no price, rate card, cost or nanodollar figure (#43, #71). The
/// session is closed when this handle drops, and — through a [`LeaseCloseGuard`] the topology frame
/// owns — on every exit of the session loop.
pub struct SessionLease {
    meter: Arc<dyn SessionMeter>,
    id: MeterId,
}

impl SessionLease {
    /// Open a metered session on `meter` over the kernel-derived `budget`. `None` is a refused budget:
    /// the plane fails closed and the session never opens.
    #[must_use]
    pub fn open(meter: &Arc<dyn SessionMeter>, budget: &SessionBudget) -> Option<Self> {
        let id = meter.open(budget)?;
        Some(SessionLease {
            meter: Arc::clone(meter),
            id,
        })
    }

    /// Report ONE turn's raw counts for `model`; the kernel answers whether the carrier stays open.
    #[must_use]
    pub fn report_turn(
        &self,
        model: &str,
        counts: &busbar_substrate_values::billing::Usage,
    ) -> TurnVerdict {
        self.meter.report_turn(self.id, model, counts)
    }

    /// What the kernel has settled on this session so far — the audit tap, read only by tests.
    #[cfg(test)]
    pub(crate) fn settled(&self) -> u64 {
        self.meter.settled(self.id)
    }

    /// Mint a BY-VALUE [`LeaseCloseGuard`] a topology's `run()` frame OWNS, so the session is closed
    /// deterministically on EVERY exit of the session loop — EOF, the hard-close `select!` race, or a
    /// panic unwinding through it — independent of a detached `Arc<SessionCore>` a parked-at-await
    /// frame handler may pin (which would otherwise refcount-gate this handle's own `Drop` close).
    #[must_use]
    pub fn close_guard(&self) -> LeaseCloseGuard {
        LeaseCloseGuard {
            meter: Some(Arc::clone(&self.meter)),
            id: self.id,
        }
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        // Idempotent: a close the topology's guard already made is a harmless no-op.
        self.meter.close(self.id);
    }
}

/// A BY-VALUE close guard for a metered session. The topology `run()` frame holds it by value so the
/// session closes on ANY return path (including a panic unwinding through `run()`), decoupled from the
/// refcount of a core a parked per-frame handler may pin. The kernel's close is idempotent, so a later
/// close from the dropped [`SessionLease`] is harmless.
pub struct LeaseCloseGuard {
    /// `None` for the no-op guard.
    meter: Option<Arc<dyn SessionMeter>>,
    id: MeterId,
}

impl LeaseCloseGuard {
    /// A guard that closes nothing.
    #[must_use]
    pub fn none() -> Self {
        LeaseCloseGuard {
            meter: None,
            id: MeterId(0),
        }
    }
}

impl Drop for LeaseCloseGuard {
    fn drop(&mut self) {
        if let Some(meter) = &self.meter {
            meter.close(self.id);
        }
    }
}

#[cfg(test)]
pub(crate) use mock::MockMeteringHost;

/// The in-test host double (test scope only).
#[cfg(test)]
mod mock {
    use busbar_kernel::plane_host::{CostLeaseId, MeteringHost, SettleOutcome};

    /// A FAITHFUL in-test mock of the host's [`MeteringHost`] seam — a `CostHold`-shaped registry keyed by
    /// lease id PLUS the real-rate `price_usage` pricing leg — shared by the runtime and topology tests so
    /// both exercise the PRODUCTION shape (host lease + host pricing) rather than the pre-host
    /// `LocalMeteringPort` (which prices at 0). Reserve = estimate+fee (audit tap), exact increments accrue toward the TRUE cap,
    /// exhausted = `settled ≥ cap`, refuse-all denies; `price_usage` prices every reserved key at 1 nano/unit
    /// (so a turn's usage_units sum IS its nanodollar cost) unless the model is the sentinel `UNPRICED_MODEL`,
    /// which returns `None` to drive the fail-closed path. `cost_close` records each closed id ONCE, so a test
    /// can prove a by-value guard closed the lease exactly once even under a parked-task refcount pin.
    #[derive(Default)]
    pub(crate) struct MockMeteringHost {
        inner: std::sync::Mutex<MockInner>,
    }

    #[derive(Default)]
    pub(crate) struct MockInner {
        next: u64,
        leases: std::collections::HashMap<u64, MockLease>,
        /// Every id closed host-side (each recorded ONCE — a second close is a harmless `None`), so a test
        /// proves a dropped/guarded lease closed exactly once.
        pub(crate) closed: Vec<u64>,
    }

    pub(crate) struct MockLease {
        pub(crate) reserved: u128,
        settled: u128,
        cap: Option<u128>,
    }

    impl MockMeteringHost {
        /// The sentinel model whose `price_usage` returns `None` — drives the caller's fail-closed path.
        pub(crate) const UNPRICED_MODEL: &'static str = "__unpriced__";

        /// A snapshot of the ids closed host-side so far (for the lease-leak witness).
        pub(crate) fn closed_ids(&self) -> Vec<u64> {
            self.inner.lock().unwrap().closed.clone()
        }

        /// The number of leases ever MINTED (reserved) — `0` proves a refused session never charged.
        pub(crate) fn minted_count(&self) -> u64 {
            self.inner.lock().unwrap().next
        }

        /// The reserved (estimate+fee) recorded for lease `id`, if still open (for reserve-audit asserts).
        pub(crate) fn reserved_of(&self, id: u64) -> Option<u128> {
            self.inner
                .lock()
                .unwrap()
                .leases
                .get(&id)
                .map(|l| l.reserved)
        }

        /// Forget every open lease host-side — simulate the host dropping a lease out from under a handle.
        pub(crate) fn clear_leases(&self) {
            self.inner.lock().unwrap().leases.clear();
        }
    }

    impl MeteringHost for MockMeteringHost {
        fn cost_reserve(
            &self,
            estimate_nanos: u128,
            fee_nanos: u128,
            cap_nanos: Option<u128>,
        ) -> Option<CostLeaseId> {
            if matches!(cap_nanos, Some(0)) {
                return None; // refuse-all denies at the door.
            }
            let mut g = self.inner.lock().unwrap();
            g.next += 1;
            let id = g.next;
            g.leases.insert(
                id,
                MockLease {
                    reserved: estimate_nanos + fee_nanos,
                    settled: 0,
                    cap: cap_nanos,
                },
            );
            Some(CostLeaseId(id))
        }

        fn cost_settle(&self, lease: CostLeaseId, exact_nanos: u128) -> Option<SettleOutcome> {
            let mut g = self.inner.lock().unwrap();
            let l = g.leases.get_mut(&lease.0)?;
            l.settled += exact_nanos;
            let exhausted = matches!(l.cap, Some(c) if l.settled >= c);
            Some(SettleOutcome { exhausted })
        }

        fn cost_settled(&self, lease: CostLeaseId) -> Option<u128> {
            Some(self.inner.lock().unwrap().leases.get(&lease.0)?.settled)
        }

        fn cost_close(&self, lease: CostLeaseId) -> Option<u128> {
            let mut g = self.inner.lock().unwrap();
            let l = g.leases.remove(&lease.0)?;
            g.closed.push(lease.0);
            Some(l.settled)
        }

        fn price_usage(
            &self,
            model: &str,
            usage: &busbar_substrate_values::billing::Usage,
        ) -> Option<u128> {
            if model == Self::UNPRICED_MODEL {
                return None; // rate card present, model unpriced → the caller fails closed.
            }
            // 1 nano per reserved unit: a turn's usage_units sum IS its nanodollar cost (legible asserts).
            Some(usage.usage_units.values().copied().map(u128::from).sum())
        }
    }
}

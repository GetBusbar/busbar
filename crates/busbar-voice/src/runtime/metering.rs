// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONTINUOUS-METERING LEASE — the marquee guarantee (design `plane4-duplex-session.md` §2.5, §4 "the D2 lease").
//!
//! A live voice carrier cannot be priced after the fact the way a one-shot request is: the session is
//! open-ended and the plane must be able to HARD-CLOSE it mid-stream the instant the budget is dry.
//! That is what the frozen D2 `cost_reserve`/`cost_settle` ABI exists for — open a reserve-then-settle
//! lease over ALREADY-PRICED nanodollars at session start, settle EXACT increments per turn, and read
//! back exhaustion so the carrier is closed the moment `settled ≥ cap`.
//!
//! THE NEUTRAL-SEAM GAP IS NOW CLOSED (minor-19). The neutral seam a statically-linked plane is handed
//! at request time — `busbar_substrate::plane_host::EngineHost` — now carries a real reserve-then-settle
//! cost lease through its [`MeteringHost`](busbar_substrate::plane_host::MeteringHost) supertrait
//! (`cost_reserve`/`cost_settle`/`cost_settled`/`cost_close`), backed host-side by the SAME `CostHold`
//! registry the frozen hot-ABI cost slots fill. So the D2 money hop is REAL: [`HostMeteringPort`] opens a
//! host-owned lease against the caller's live grant ceiling, [`HostLease`] settles EXACT increments
//! against it and reads exhaustion off the real cap — no plane-private counter. The composition root
//! (`build_runtime`) binds [`HostMeteringPort`] as the PRODUCTION path.
//!
//! [`LocalLease`] / [`LocalMeteringPort`] stay the TEST default: the runtime tests, the topology tests
//! and the in-flight conformance governance leg all drive the faithful in-process lease whose
//! reserve/settle/exhaustion contract is byte-for-byte the host D2 lease's (reserve = estimate+fee,
//! settle accrues exact increments, exhausted = `settled ≥ cap`, refuse-all cap denies at the door). The
//! port abstraction ([`MeteringLease`] / [`MeteringPort`]) is the seam both share.

use busbar_substrate::plane_host::{CostLeaseId, EngineHost, MeteringHost, SettleOutcome};
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// the admin usage report. No-ops when governance is off (the host mints no `GovHandle`).
    pub(crate) fn record_turn(&self, model: &str, usage: &busbar_substrate::billing::Usage) {
        if let Some(gov) = self.host.governance() {
            let cost = self.host.cost();
            let now = self.host.clock_now_secs();
            self.host
                .meter_ledger(&gov, &cost, &self.key, self.pool, model, usage, now);
            self.host
                .meter_series(&gov, &self.key.id, model, self.provider, None, now);
        }
    }
}

/// Micro-units per nanodollar. The budget projection accounts in MICRO-units (1e-6 USD) while the
/// metering lease is denominated in NANO-dollars (1e-9 USD), so a remaining budget widens by this
/// factor on the way into a session's ceiling.
const NANOS_PER_MICRO: u64 = 1_000;

/// THE SESSION CEILING A PRINCIPAL'S REAL BUDGET IMPOSES — the tightest remaining amount across the
/// key's whole budget chain (its own bucket plus every ancestor group bucket), widened to nanodollars.
///
/// `None` means "no bucket in the chain is capped", which is genuinely uncapped: an unbudgeted key has
/// no ceiling to hard-close a session against, exactly as an unbudgeted model call has none. A chain
/// whose tightest bucket is already spent yields `Some(0)` — a refuse-all ceiling the lease denies at
/// the door, so such a caller never opens a session at all rather than opening one that can spend.
///
/// Kept as a free function over the neutral projection so it is testable on its own: the arithmetic
/// that decides whether a session may open is the part worth pinning, and it needs no host to run.
#[must_use]
pub fn cap_nanos_from_buckets(buckets: &[busbar_api::BudgetBucketState]) -> Option<u64> {
    let tightest = buckets.iter().filter_map(|b| b.remaining_micros).min()?;
    if tightest <= 0 {
        // Already spent (or overspent): a refuse-all ceiling, denied at reserve.
        return Some(0);
    }
    // Widen micro-units to nanodollars. Saturating rather than wrapping: an implausibly large budget
    // clamps to the u64 ceiling instead of rolling over into a tiny one.
    Some((tightest as u64).saturating_mul(NANOS_PER_MICRO))
}

/// The live-host form of [`cap_nanos_from_buckets`]: read the presenting key's budget chain off the
/// host and derive this session's ceiling from it. `None` (uncapped) when there is no presenting key,
/// when governance is off (there is no grant to read), or when nothing in the chain is capped.
#[must_use]
pub fn principal_cap_nanos(
    host: &Arc<dyn EngineHost>,
    key: Option<&busbar_api::VirtualKey>,
    now: u64,
) -> Option<u64> {
    let key = key?;
    let gov = host.governance()?;
    let cost = host.cost();
    cap_nanos_from_buckets(&host.budget_state(&gov, &cost, key, now))
}

/// THE POST-SETTLE STATE the plane reads back to decide whether to hard-close — the mirror of the D2
/// `CostSettleOut.exhausted` flag plus the `StatusClass::Refused`/`Fault` fail-closed cases folded in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// Budget remains — keep the carrier open.
    Live,
    /// The lease's budget is now DRY (`settled ≥ cap`) — the plane MUST hard-close the carrier. The one
    /// thing post-hoc metering structurally cannot do.
    Exhausted,
    /// The settle was REFUSED (unknown / already-closed lease) or FAULTED — the plane fails CLOSED and
    /// hard-closes the carrier just as an exhaustion would.
    Refused,
}

impl LeaseState {
    /// Whether this state demands a carrier hard-close (everything but [`LeaseState::Live`]).
    #[must_use]
    pub fn must_close(self) -> bool {
        !matches!(self, LeaseState::Live)
    }
}

/// ONE OPEN METERING LEASE — the plane-side port over the D2 `cost_settle` leg. `Send + Sync` so the
/// per-frame session handlers (which run concurrently under `Arc<Self>`) can settle against it.
pub trait MeteringLease: Send + Sync {
    /// PRICE one turn's neutral usage_units for `model` into an already-priced nanodollar increment via
    /// the deployment rate card — the plane's `price_usage`-before-`settle` step. The HOST prices (core's
    /// `CostModel`, the SAME arithmetic the LLM path uses), so the plane stays neutral and never names a
    /// pricer. `None` when the rate card is present but names no rate for `model` (the caller FAILS CLOSED
    /// and hard-closes the carrier, exactly as on exhaustion); `Some(0)` when pricing is off (no rate
    /// card) or the turn is empty. The host u128 nanodollars clamp saturating into u64 (a per-turn
    /// increment fits u64 far below the ~$18.4B ceiling), fail-closed HIGH.
    fn price_usage(&self, model: &str, usage: &busbar_substrate::billing::Usage) -> Option<u64>;

    /// Settle ONE exact already-priced increment (nanodollars) against this lease and read back the
    /// post-settle state — the `cost_settle` leg. Idempotent after exhaustion: once dry it stays dry.
    fn settle(&self, nanos: u64) -> LeaseState;

    /// The total nanodollars settled so far — the audit tap the caller journals (and the tests assert).
    fn settled_nanos(&self) -> u64;

    /// Mint a BY-VALUE [`LeaseCloseGuard`] a topology's `run()` frame OWNS, so the host lease is closed
    /// deterministically on EVERY exit of the session loop — EOF, the hard-close `select!` race, or a
    /// panic unwinding through it — independent of a detached `Arc<SessionCore>` a parked-at-await frame
    /// handler may pin (which would otherwise refcount-gate this lease's own `Drop` close and leak the
    /// reserve). Empty for the in-process [`LocalLease`] (it owns its budget cell directly; nothing
    /// host-side to close).
    fn close_guard(&self) -> LeaseCloseGuard;
}

/// A BY-VALUE close guard for the D2 lease. The topology `run()` frame holds it by value so
/// [`MeteringHost::cost_close`] fires on ANY return path (including a panic unwinding through `run()`),
/// closing the hard-close-race hole the session-drop audit found: a per-frame handler PARKED at an
/// `.await` keeps an `Arc<SessionCore>` alive, so the settle handle's own `Drop` close is refcount-gated
/// and never runs while parked. The guard is decoupled from that refcount, so the reserve is released the
/// instant `run()` returns. `cost_close` is idempotent (the registry entry is removed on first close), so
/// a redundant close from a later-dropped settle handle is a harmless `None` — no double refund.
pub struct LeaseCloseGuard {
    /// The host to close against — `None` for a lease with no host-side registry entry (the dev
    /// [`LocalLease`], which owns its budget cell in-process and leaks nothing).
    host: Option<Arc<dyn MeteringHost>>,
    /// The lease id to close; [`CostLeaseId::NONE`] for the no-op guard.
    lease: CostLeaseId,
}

impl LeaseCloseGuard {
    /// A guard over a live host lease — closes `lease` against `host` on drop.
    #[must_use]
    fn hosted(host: Arc<dyn MeteringHost>, lease: CostLeaseId) -> Self {
        LeaseCloseGuard {
            host: Some(host),
            lease,
        }
    }

    /// A NO-OP guard — the in-process lease has no host-side registry entry to close.
    #[must_use]
    fn none() -> Self {
        LeaseCloseGuard {
            host: None,
            lease: CostLeaseId::NONE,
        }
    }
}

impl Drop for LeaseCloseGuard {
    fn drop(&mut self) {
        // Deterministic host-side close on run() exit; idempotent, so harmless if the lease already
        // closed (a lingering settle handle, or a previous guard drop).
        if let Some(host) = &self.host {
            let _ = host.cost_close(self.lease);
        }
    }
}

/// OPENS a metering lease at session start — the plane-side port over the D2 `cost_reserve` leg. The
/// plane hands ALREADY-PRICED nanodollars: `estimate` (the coarse over-estimate debited up front),
/// `fee` (the once-per-session flat fee, `0` = none), and `cap` (the TRUE budget ceiling exhaustion is
/// judged against — `None` = uncapped, `Some(0)` = refuse-all).
pub trait MeteringPort: Send + Sync {
    /// Open a reserve-then-settle lease. `None` mirrors a `cost_reserve` `StatusClass::Refused` (a
    /// refuse-all cap): the plane reads it as "no lease" and fails closed — the session never opens.
    fn reserve(
        &self,
        estimate_nanos: u64,
        fee_nanos: u64,
        cap_nanos: Option<u64>,
    ) -> Option<Box<dyn MeteringLease>>;
}

/// THE FAITHFUL, FULLY-WIRED LEASE the runtime drives today — the plane-side twin of the host's
/// `CostHold` (busbar-core `plane/cost.rs`): `reserved = estimate + fee` debited up front, `settled`
/// accrues exact increments, and exhaustion is `matches!(cap, Some(c) if settled ≥ c)`. It holds the
/// budget cell in-process rather than in the host's global registry (the reported neutral-seam gap),
/// but the reserve/settle/exhaustion CONTRACT — and therefore the hard-close behaviour the marquee
/// guarantee rests on — is byte-for-byte the D2 lease's.
#[derive(Debug)]
pub struct LocalLease {
    /// The coarse over-estimate + flat fee debited at reserve (audit tap; not itself a ceiling).
    reserved_nanos: u64,
    /// Exact nanodollars settled so far — the value compared to the cap.
    settled_nanos: AtomicU64,
    /// The TRUE budget ceiling; `None` = uncapped (never exhausts).
    cap_nanos: Option<u64>,
}

impl LocalLease {
    /// The reserved (estimate + fee) nanodollars this lease debited up front.
    #[must_use]
    pub fn reserved_nanos(&self) -> u64 {
        self.reserved_nanos
    }
}

impl MeteringLease for LocalLease {
    fn price_usage(&self, _model: &str, _usage: &busbar_substrate::billing::Usage) -> Option<u64> {
        // The in-process TEST/DEV lease carries NO rate card (the money hop's rates live host-side): a
        // dev build with no configured rate card prices at 0, exactly as core's `CostModel` does when
        // `rate_card` is absent. This is NOT a plane-private price book — it holds no rates, labels or
        // units; it is the honest "pricing off" for the dev stand-in. The REAL rate-card pricing rides
        // the host lease ([`HostLease::price_usage`] → [`MeteringHost::price_usage`]); the runtime tests
        // drive that faithful path over a mock host with real rates.
        Some(0)
    }

    fn settle(&self, nanos: u64) -> LeaseState {
        // Saturating accrual: the budget arithmetic can never wrap below the cap.
        let prior = self.settled_nanos.fetch_add(nanos, Ordering::SeqCst);
        let total = prior.saturating_add(nanos);
        // Re-store the saturated total so a near-u64::MAX run cannot silently roll the counter.
        self.settled_nanos.store(total, Ordering::SeqCst);
        match self.cap_nanos {
            Some(cap) if total >= cap => LeaseState::Exhausted,
            _ => LeaseState::Live,
        }
    }

    fn settled_nanos(&self) -> u64 {
        self.settled_nanos.load(Ordering::SeqCst)
    }

    fn close_guard(&self) -> LeaseCloseGuard {
        // No host-side registry entry: the in-process budget cell drops with this lease. No-op guard.
        LeaseCloseGuard::none()
    }
}

/// THE DEFAULT [`MeteringPort`] — mints [`LocalLease`]s. Binds the real host lease's REFUSE-ALL rule at
/// the door: a `Some(0)` cap denies the reserve (`None`), so the session never opens on a zero budget.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalMeteringPort;

impl MeteringPort for LocalMeteringPort {
    fn reserve(
        &self,
        estimate_nanos: u64,
        fee_nanos: u64,
        cap_nanos: Option<u64>,
    ) -> Option<Box<dyn MeteringLease>> {
        // A refuse-all cap (`Some(0)`) denies at the door, exactly like the host `cost_reserve`.
        if matches!(cap_nanos, Some(0)) {
            return None;
        }
        Some(Box::new(LocalLease {
            reserved_nanos: estimate_nanos.saturating_add(fee_nanos),
            settled_nanos: AtomicU64::new(0),
            cap_nanos,
        }))
    }
}

/// THE PRODUCTION [`MeteringPort`] — the REAL D2 money hop. Backed by the host's reserve-then-settle
/// cost lease over the neutral [`MeteringHost`] seam (core's `EngineHostImpl`), so a live voice carrier
/// meters CONTINUOUSLY against the caller's real grant/budget rather than a plane-local counter. Holds an
/// `Arc<dyn MeteringHost>` — the narrow lease slice of `EngineHost` — so a full-`EngineHost` production
/// host binds here and a test's tiny mock `MeteringHost` binds identically.
pub struct HostMeteringPort {
    host: Arc<dyn MeteringHost>,
}

impl HostMeteringPort {
    /// Bind the port over a host's metering seam (an `Arc<dyn MeteringHost>` — an `Arc<dyn EngineHost>`
    /// upcasts into it, or a plane hands the narrow slice directly).
    #[must_use]
    pub fn new(host: Arc<dyn MeteringHost>) -> Self {
        HostMeteringPort { host }
    }
}

impl MeteringPort for HostMeteringPort {
    fn reserve(
        &self,
        estimate_nanos: u64,
        fee_nanos: u64,
        cap_nanos: Option<u64>,
    ) -> Option<Box<dyn MeteringLease>> {
        // Widen the plane's already-priced `u64` nanodollars to the host seam's `u128`; a refuse-all cap
        // is denied host-side (returns `None`) so the session fails closed and never opens.
        let lease = self.host.cost_reserve(
            u128::from(estimate_nanos),
            u128::from(fee_nanos),
            cap_nanos.map(u128::from),
        )?;
        Some(Box::new(HostLease {
            host: Arc::clone(&self.host),
            lease,
        }))
    }
}

/// ONE open host-backed metering lease — the production twin of [`LocalLease`]. Every settle and the
/// settled-total read cross the neutral [`MeteringHost`] seam into the host-owned `CostHold`, so the
/// budget/cap state lives HOST-side (the closed neutral-seam gap), not in this handle.
pub struct HostLease {
    host: Arc<dyn MeteringHost>,
    lease: CostLeaseId,
}

impl MeteringLease for HostLease {
    fn price_usage(&self, model: &str, usage: &busbar_substrate::billing::Usage) -> Option<u64> {
        // The REAL money hop's pricing leg: the host prices the turn's usage_units against the deployment
        // rate card (the SAME `CostModel` arithmetic the LLM path uses), so the plane never names a pricer.
        // A per-turn increment fits u64 far below the ~$18.4B ceiling; saturate defensively (fail-closed
        // HIGH) rather than wrap. `None` (rate card present, model unpriced) surfaces so the caller fails
        // closed and hard-closes — an unpriced passthrough model must not meter as free.
        self.host
            .price_usage(model, usage)
            .map(|n| u64::try_from(n).unwrap_or(u64::MAX))
    }

    fn settle(&self, nanos: u64) -> LeaseState {
        // The `cost_settle` leg: accrue the exact increment host-side and map the outcome. An unknown /
        // already-closed lease (`None`) fails CLOSED — the plane hard-closes just as on exhaustion.
        match self.host.cost_settle(self.lease, u128::from(nanos)) {
            Some(SettleOutcome { exhausted: false }) => LeaseState::Live,
            Some(SettleOutcome { exhausted: true }) => LeaseState::Exhausted,
            None => LeaseState::Refused,
        }
    }

    fn settled_nanos(&self) -> u64 {
        // The host accounts in u128; a per-lease settled total fits u64 (a ~$18.4B ceiling far above any
        // one session). Saturate defensively rather than wrap, and read `0` for an unknown/closed lease.
        self.host
            .cost_settled(self.lease)
            .map(|n| u64::try_from(n).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    fn close_guard(&self) -> LeaseCloseGuard {
        // A live host lease: hand the topology a by-value guard that closes it deterministically on
        // run() exit, decoupled from this settle handle's refcount-gated `Drop`.
        LeaseCloseGuard::hosted(Arc::clone(&self.host), self.lease)
    }
}

impl Drop for HostLease {
    fn drop(&mut self) {
        // Close the lease host-side when the carrier finishes so its `CostHold` does not leak the host
        // registry. Idempotent and fire-and-forget: a second close (or an already-forgotten lease) is a
        // harmless `None`.
        let _ = self.host.cost_close(self.lease);
    }
}

/// A FAITHFUL in-test mock of the host's [`MeteringHost`] seam — a `CostHold`-shaped registry keyed by
/// lease id PLUS the real-rate `price_usage` pricing leg — shared by the runtime and topology tests so
/// both exercise the PRODUCTION shape (host lease + host pricing) rather than the dev [`LocalLease`]
/// (which prices at 0). Reserve = estimate+fee (audit tap), exact increments accrue toward the TRUE cap,
/// exhausted = `settled ≥ cap`, refuse-all denies; `price_usage` prices every reserved key at 1 nano/unit
/// (so a turn's usage_units sum IS its nanodollar cost) unless the model is the sentinel `UNPRICED_MODEL`,
/// which returns `None` to drive the fail-closed path. `cost_close` records each closed id ONCE, so a test
/// can prove a by-value guard closed the lease exactly once even under a parked-task refcount pin.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MockMeteringHost {
    inner: std::sync::Mutex<MockInner>,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct MockInner {
    next: u64,
    leases: std::collections::HashMap<u64, MockLease>,
    /// Every id closed host-side (each recorded ONCE — a second close is a harmless `None`), so a test
    /// proves a dropped/guarded lease closed exactly once.
    pub(crate) closed: Vec<u64>,
}

#[cfg(test)]
pub(crate) struct MockLease {
    pub(crate) reserved: u128,
    settled: u128,
    cap: Option<u128>,
}

#[cfg(test)]
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

#[cfg(test)]
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

    fn price_usage(&self, model: &str, usage: &busbar_substrate::billing::Usage) -> Option<u128> {
        if model == Self::UNPRICED_MODEL {
            return None; // rate card present, model unpriced → the caller fails closed.
        }
        // 1 nano per reserved unit: a turn's usage_units sum IS its nanodollar cost (legible asserts).
        Some(usage.usage_units.values().copied().map(u128::from).sum())
    }
}

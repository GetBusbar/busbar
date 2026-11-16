// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
// busbar:request-path
#![cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]
#![deny(missing_docs)]

//! # The breaker unit

pub mod budget;
pub mod cell;
pub mod cfg;
pub mod classify;
pub mod port;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use budget::LifetimeBudget;
use busbar_contract::caps::{Pass, Route};
use cell::{
    BreakerCell, BreakerState as CellState, BreakerVerdict, CellSnapshot, DeniedBy, ProbeAdmit,
};
use cfg::BreakerCfg;

/// The pool-member locator, as the contract crate defines it. The egress unit names the same one,
pub use busbar_contract::DestinationId;

/// The default sticky cooldown applied by a hard-down trip (1.5.5's `DEFAULT_HARD_DOWN_COOLDOWN_SECS`).
pub const DEFAULT_HARD_DOWN_COOLDOWN_SECS: u64 = 1800;

/// The default absolute ceiling on an honored upstream requested wait (1.5.5's
pub const DEFAULT_MAX_HONORED_RETRY_AFTER_SECS: u64 = 86_400;

/// Why a `(pool, destination)` cannot admit right now, from the BREAKER's own point of view —
/// deliberately narrower than the egress unit's lane-availability taxonomy (`Unavailable` in
/// 1.5.5's substrate), which also carries `AtCapacity`/`Shedding`/`Dead`: those are concurrency and
/// operator-declaration facts the egress/admission units own, not this one.
///
/// A member in any non-`Ready` state is EXCLUDED from the walk, never "ordered last and
/// attempted" — the egress unit's selection filter is expected to drop anything this reports as
/// not `Ready` before ranking, exactly as 1.5.5's `try_admit`/`lane_admissible` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneState {
    /// Would admit a request right now.
    Ready,
    /// Breaker-suppressed (Open, or Closed inside a pending soft cooldown) until the deadline.
    Suppressed {
        /// The cooldown deadline, in Unix seconds.
        until: u64,
    },
    /// A peer holds the single-flight recovery probe.
    ProbeInFlight,
    /// The destination's lifetime request budget is spent. Does not self-recover.
    BudgetExhausted,
}

fn lane_state_from_verdict(v: BreakerVerdict) -> LaneState {
    match v {
        BreakerVerdict::Ready | BreakerVerdict::ProbeWinnable => LaneState::Ready,
        BreakerVerdict::Open { until } => LaneState::Suppressed { until },
        BreakerVerdict::HalfOpen => LaneState::ProbeInFlight,
    }
}

/// The held resource a successful [`BreakerUnit::try_admit`] transfers to the caller: the
/// single-flight probe owner token, if this admission actually won a half-open recovery probe.
/// `None` means a plain Closed-and-ready admission, which owns nothing to release.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admit {
    /// `Some(epoch)` iff this admission won the half-open recovery probe.
    pub probe_epoch: Option<u64>,
}

/// The classified outcome of one attempt against a destination, as the breaker cares about it. A
/// disposition (see [`classify::Disposition`]) collapses to one of these four; `ClientFault`/
/// `ContextLength` both mean "record nothing" and are folded into their own variants so a caller
/// cannot accidentally attach a `retry_after` that would be ignored anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The attempt succeeded.
    Success,
    /// A transient upstream failure — cooldown + error counter. `retry_after` is the wait the
    /// answer's frame stated, in whole seconds, if any.
    Transient {
        /// The upstream's requested wait, in seconds, if any.
        retry_after: Option<u64>,
    },
    /// A throttled request: transient health with a distinct retry ladder.
    RateLimit {
        /// The upstream's requested wait, in seconds.
        retry_after: Option<u64>,
    },
    /// A definitive signal (bad key, billing exhausted): trips every pool cell for this
    /// destination, not just the one this attempt ran through — see [`BreakerUnit::hard_down_all`].
    HardDown,
    /// The request was too big for this destination, or the caller's own fault: record nothing,
    /// the destination is healthy either way.
    RecordNothing,
}

mod sealed {
    pub trait Sealed {}
}

/// The breaker unit's sealed trait shape (`docs/design/BUSBAR-1.6.0.md` THE DESIGN, §9: `Breaker::observe/
pub trait Breaker: sealed::Sealed {
    /// Record one classified [`Outcome`] against `(pool, destination)`, applying the state
    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        cfg: &BreakerCfg,
        now: u64,
        token: &Pass<Route>,
    ) -> bool;

    /// This `(pool, destination)` cell's current [`LaneState`], folding in the destination's
    fn state(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> LaneState;
}

/// One destination's breaker state: its lifetime budget, where one is declared, and its cells —
/// the default cell (direct/ad-hoc routes, pool `""`), exactly as 1.5.5's `LaneState`-embedded
/// default cell did, and one per named pool that has touched it, keyed by the pool name.
///
/// A lookup is one `foldhash` of the borrowed pool name (none for the default cell), never a scan,
/// and nothing on the hot path owns a copy of the name: only creating a cell spells it into a
/// `Box<str>`. Every cell lives here, so a cell is reachable exactly when it is registered for the
/// destination's hard-down fan-out ([`BreakerUnit::hard_down_all`]).
#[derive(Default)]
struct Destination {
    budget: Option<Arc<LifetimeBudget>>,
    default: Option<Arc<BreakerCell>>,
    pools: foldhash::HashMap<Box<str>, Arc<BreakerCell>>,
}

impl Destination {
    fn cell(&self, pool: &str) -> Option<&Arc<BreakerCell>> {
        if pool.is_empty() {
            self.default.as_ref()
        } else {
            self.pools.get(pool)
        }
    }
}

/// The destination map: a destination is a small integer, so `foldhash` spreads it over the table
/// with one folded multiply where the default SipHash would spend a keyed hash per admission.
type Destinations = foldhash::HashMap<DestinationId, Destination>;

/// The breaker unit: every `(pool, destination)` breaker cell plus every destination's lifetime
pub struct BreakerUnit {
    destinations: RwLock<Destinations>,
    /// Atomics, not plain fields: a unit that outlives one configuration generation (the plane
    hard_down_cooldown_secs: AtomicU64,
    max_honored_retry_after_secs: AtomicU64,
}

impl Default for BreakerUnit {
    fn default() -> Self {
        Self::new()
    }
}

impl BreakerUnit {
    /// A breaker unit with the ADR-0002 defaults.
    pub fn new() -> Self {
        Self {
            destinations: RwLock::new(Destinations::default()),
            hard_down_cooldown_secs: AtomicU64::new(DEFAULT_HARD_DOWN_COOLDOWN_SECS),
            max_honored_retry_after_secs: AtomicU64::new(DEFAULT_MAX_HONORED_RETRY_AFTER_SECS),
        }
    }

    /// Override the hard-down sticky cooldown and the absolute requested-wait honoring ceiling
    pub fn with_limits(
        self,
        hard_down_cooldown_secs: u64,
        max_honored_retry_after_secs: u64,
    ) -> Self {
        self.set_limits(hard_down_cooldown_secs, max_honored_retry_after_secs);
        self
    }

    /// [`Self::with_limits`] on a unit already in service: the next hard-down arms the new sticky
    pub(crate) fn set_limits(
        &self,
        hard_down_cooldown_secs: u64,
        max_honored_retry_after_secs: u64,
    ) {
        self.hard_down_cooldown_secs
            .store(hard_down_cooldown_secs, Ordering::Relaxed);
        self.max_honored_retry_after_secs
            .store(max_honored_retry_after_secs, Ordering::Relaxed);
    }

    /// The destination map, read. A poisoned lock is recovered: every write under it leaves the map
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Destinations> {
        self.destinations.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Declare a destination's lifetime request budget. `max_requests < 0` means unlimited
    pub fn set_budget(&self, destination: DestinationId, max_requests: i64) {
        let budget = LifetimeBudget::limited(max_requests);
        self.destinations
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .entry(destination)
            .or_default()
            .budget = Some(Arc::new(budget));
    }

    /// The destination's declared budget itself, shared rather than copied: a caller that
    pub fn budget(&self, destination: DestinationId) -> Option<Arc<LifetimeBudget>> {
        self.read().get(&destination)?.budget.clone()
    }

    /// The sticky cooldown a hard-down trip arms (see [`Self::with_limits`]).
    pub fn hard_down_cooldown_secs(&self) -> u64 {
        self.hard_down_cooldown_secs.load(Ordering::Relaxed)
    }

    /// The absolute ceiling on an honored upstream requested wait (see [`Self::with_limits`]).
    pub fn max_honored_retry_after_secs(&self) -> u64 {
        self.max_honored_retry_after_secs.load(Ordering::Relaxed)
    }

    /// Remaining lifetime budget for a destination, or `None` if unlimited or never declared
    pub fn budget_remaining(&self, destination: DestinationId) -> Option<i64> {
        self.read().get(&destination)?.budget.as_ref()?.remaining()
    }

    /// Whether the destination has nothing left to spend: the same test [`LifetimeBudget::spend`]
    fn budget_exhausted(&self, destination: DestinationId) -> bool {
        matches!(self.budget_remaining(destination), Some(remaining) if remaining <= 0)
    }

    /// Spend one unit of `destination`'s lifetime budget. `true` if spent (or the destination is
    #[must_use]
    pub fn spend_budget(&self, destination: DestinationId) -> bool {
        match self
            .read()
            .get(&destination)
            .and_then(|d| d.budget.as_ref())
        {
            Some(b) => b.spend(),
            None => true,
        }
    }

    /// Compensating refund of one unit previously spent (see [`budget::LifetimeBudget::refund`]).
    pub fn refund_budget(&self, destination: DestinationId) {
        if let Some(b) = self
            .read()
            .get(&destination)
            .and_then(|d| d.budget.as_ref())
        {
            b.refund();
        }
    }

    /// The `(pool, destination)` cell, registered for the destination's hard-down fan-out
    pub fn cell(&self, pool: &str, destination: DestinationId) -> Arc<BreakerCell> {
        self.cell_with(pool, destination, |fresh, default| {
            if let Some(default) = default {
                fresh.restore(inherited(default));
            }
        })
    }

    /// [`Self::cell`], with `seed` run on the cell exactly when THIS call creates it, before any
    pub fn cell_seeded(
        &self,
        pool: &str,
        destination: DestinationId,
        seed: impl FnOnce(&BreakerCell),
    ) -> Arc<BreakerCell> {
        self.cell_with(pool, destination, |fresh, _| seed(fresh))
    }

    /// The `(pool, destination)` cell if it exists, creating nothing.
    fn existing(&self, pool: &str, destination: DestinationId) -> Option<Arc<BreakerCell>> {
        self.read().get(&destination)?.cell(pool).cloned()
    }

    /// Run `f` on the `(pool, destination)` cell under the map's read lock, with no copy of the
    fn on_cell<R>(
        &self,
        pool: &str,
        destination: DestinationId,
        f: impl Fn(&BreakerCell) -> R,
    ) -> R {
        if let Some(cell) = self.read().get(&destination).and_then(|d| d.cell(pool)) {
            return f(cell);
        }
        f(&self.cell(pool, destination))
    }

    /// The one creation path. `seed` runs on the cell exactly when THIS call creates it, under the
    fn cell_with(
        &self,
        pool: &str,
        destination: DestinationId,
        seed: impl FnOnce(&BreakerCell, Option<&BreakerCell>),
    ) -> Arc<BreakerCell> {
        if let Some(c) = self.existing(pool, destination) {
            return c;
        }
        let mut destinations = self.destinations.write().unwrap_or_else(|e| e.into_inner());
        let dest = destinations.entry(destination).or_default();
        if let Some(c) = dest.cell(pool) {
            return Arc::clone(c);
        }
        let cell = BreakerCell::new();
        seed(
            &cell,
            (!pool.is_empty())
                .then(|| dest.cell(""))
                .flatten()
                .map(|c| &**c),
        );
        let cell = Arc::new(cell);
        if pool.is_empty() {
            dest.default = Some(Arc::clone(&cell));
        } else {
            let key = Box::from(pool);
            dest.pools.insert(key, Arc::clone(&cell));
        }
        cell
    }

    /// Whether a cell for this pool and destination already exists, without creating one.
    #[cfg(test)]
    pub(crate) fn has_cell(&self, pool: &str, destination: DestinationId) -> bool {
        self.existing(pool, destination).is_some()
    }

    /// Trip EVERY existing pool cell for `destination` hard-down at once (the default `""`
    pub fn hard_down_all(&self, destination: DestinationId, now: u64) -> bool {
        let cooldown = self.hard_down_cooldown_secs();
        self.fan_out(destination, |_, cell| cell.hard_down(now, cooldown))
    }

    /// Run `f` on `destination`'s default cell (created as [`Self::cell`] creates it), then on every
    /// named pool's cell with its pool, in place under the map's read lock: no copy of the cell list
    /// or of a pool name. `f` touches only the cell it is given (and, for a probe, the caller's
    /// policy lookup), never this unit, so it runs under the read lock without re-entering it.
    /// Returns `f`'s answer for the default cell.
    fn fan_out<R>(&self, destination: DestinationId, f: impl Fn(&str, &BreakerCell) -> R) -> R {
        let default = f("", &self.cell("", destination));
        if let Some(d) = self.read().get(&destination) {
            for (pool, cell) in &d.pools {
                let _ = f(pool, cell);
            }
        }
        default
    }

    /// THE HEALTH PROBER'S TRIGGER (1.5.5 `lane_needs_probe`): whether the breaker suppresses
    pub fn suppressing(&self, destination: DestinationId, now: u64) -> bool {
        self.read().get(&destination).is_some_and(|d| {
            d.default
                .iter()
                .chain(d.pools.values())
                .any(|cell| suppressed(cell, now).is_some())
        })
    }

    /// ONE HEALTH PROBE'S ANSWER, folded into EVERY cell of `destination` — the default cell and
    pub fn probed(
        &self,
        destination: DestinationId,
        outcome: Outcome,
        cfg_of: &dyn Fn(&str) -> Option<BreakerCfg>,
        now: u64,
        _token: &Pass<Route>,
    ) {
        match outcome {
            Outcome::RecordNothing => {}
            Outcome::HardDown => {
                let _ = self.hard_down_all(destination, now);
            }
            Outcome::Success => self.fan_out(destination, |_, cell| {
                if let Some(observed) = suppressed(cell, now) {
                    let _ = cell.close_if_recoverable(now, observed);
                }
                let _ = cell.record_success(now);
            }),
            Outcome::Transient { retry_after } | Outcome::RateLimit { retry_after } => {
                let max_honored = self.max_honored_retry_after_secs();
                self.fan_out(destination, |pool, cell| {
                    if let Some(cfg) = cfg_of(pool) {
                        let _ = cell.record_failure(now, &cfg, retry_after, max_honored);
                    }
                });
            }
        }
    }

    /// Mutating admission attempt: wins-or-loses the single-flight probe, checking the destination's
    pub fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, LaneState> {
        if self.budget_exhausted(destination) {
            return Err(LaneState::BudgetExhausted);
        }
        self.on_cell(pool, destination, |cell| match cell.acquire(now) {
            ProbeAdmit::Denied(DeniedBy::Cooling { until }) => Err(LaneState::Suppressed { until }),
            ProbeAdmit::Denied(DeniedBy::ProbeInFlight) => Err(LaneState::ProbeInFlight),
            ProbeAdmit::ReadyNoProbe => Ok(Admit { probe_epoch: None }),
            ProbeAdmit::ProbeWon(epoch) => Ok(Admit {
                probe_epoch: Some(epoch),
            }),
        })
    }

    /// Release a probe won by [`Self::try_admit`] but never dispatched (owner-checked: a stale,
    pub fn release_probe(&self, pool: &str, destination: DestinationId, owned_epoch: u64) {
        self.on_cell(pool, destination, |cell| {
            cell.release_probe_owned(owned_epoch)
        });
    }
}

/// What a named pool's cell is created carrying from the destination's default cell: its state,
fn inherited(default: &BreakerCell) -> CellSnapshot {
    CellSnapshot {
        err: 0,
        ..default.snapshot()
    }
}

/// Whether `cell` is suppressed at `now` (not Closed, or Closed inside a pending soft cooldown),
fn suppressed(cell: &BreakerCell, now: u64) -> Option<u64> {
    let cooldown = cell.cooldown_until();
    (!matches!(cell.state(), CellState::Closed) || cooldown > now).then_some(cooldown)
}

impl sealed::Sealed for BreakerUnit {}

impl Breaker for BreakerUnit {
    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        cfg: &BreakerCfg,
        now: u64,
        _token: &Pass<Route>,
    ) -> bool {
        match outcome {
            Outcome::RecordNothing => false,
            Outcome::HardDown => self.hard_down_all(destination, now),
            Outcome::Success => {
                let _ = self.on_cell(pool, destination, |cell| cell.record_success(now));
                false
            }

            Outcome::Transient { retry_after } | Outcome::RateLimit { retry_after } => {
                let max_honored = self.max_honored_retry_after_secs();
                self.on_cell(pool, destination, |cell| {
                    cell.record_failure(now, cfg, retry_after, max_honored)
                        .tripped()
                })
            }
        }
    }

    fn state(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        _token: &Pass<Route>,
    ) -> LaneState {
        if self.budget_exhausted(destination) {
            return LaneState::BudgetExhausted;
        }
        if let Some(cell) = self.existing(pool, destination) {
            return lane_state_from_verdict(cell.verdict(now));
        }

        let unborn = match (pool.is_empty(), self.existing("", destination)) {
            (false, Some(default)) => inherited(&default),
            _ => CellSnapshot::default(),
        };
        lane_state_from_verdict(unborn.verdict(now))
    }
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! # busbar-unit-breaker — the breaker unit
//!
//! The design (`docs/design/ARCHITECTURE.md` §3.1, §3.4) splits egress into two units: the EGRESS
//! unit owns the pool per `(transport, destination)` — selection, weighting, concurrency; the
//! BREAKER unit (this crate) owns trip / cooldown / fast-fail per `(pool, destination)`, plus the
//! per-destination lifetime request budget. A `BreakerCell` is per pool MEMBER, independent per
//! pool — the same destination can be Open in one pool and Closed in another. Only the lifetime
//! request budget and a hard-down trip are lane-global (they trip every pool's cell at once).
//!
//! This is a MOVE, not a rewrite: the state machine in [`cell`] (trip condition, escalating
//! cooldown with jitter, the Retry-After floor, half-open recovery) and the classifier in
//! [`classify`] are byte-identical to 1.5.5's `busbar-core::store::in_memory::breaker` and
//! `busbar-substrate::breaker`. See each module's doc comment for the handful of call-site
//! adaptations required by depending on nothing but `busbar-caps` (no `axum`, no `tracing`, no
//! SWRR/pool-selection state, which belongs to the egress unit).
//!
//! ## What's new here, not ported
//!
//! - [`journal`]: a `JournalSink` trait for probe lifecycle events. 1.5.5 had no probe journal;
//!   the architecture's ledger (§4.1) requires one, so this crate defines the seam without owning
//!   the actual journal writer.
//! - The sealed [`Breaker`] trait itself (`observe`/`state`, per §3.1's unit-trait shape). 1.5.5
//!   exposed the FSM through a much larger `LaneRuntime` trait (concurrency, SWRR, `/stats`, health
//!   snapshots — all egress/observability concerns); this crate exposes only the breaker's own two
//!   verbs, sealed so no plugin can implement it.
//! - [`DestinationId`] is the contract crate's pool-member locator, named here and by the egress
//!   unit, so the two units that key on a member key on one object.

pub mod budget;
pub mod cell;
pub mod cfg;
pub mod classify;
pub mod clock;
pub mod journal;
pub mod port;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use budget::LifetimeBudget;
use busbar_caps::{Route, UnitToken};
use cell::{BreakerCell, BreakerState as CellState, BreakerVerdict, ProbeAdmit};
use cfg::BreakerCfg;
use classify::Diagnostics;
use journal::{JournalSink, NoopJournal, ProbeEvent};

/// The pool-member locator, as the contract crate defines it. The egress unit names the same one,
/// which is what makes `(transport, destination)` and `(pool, destination)` the same key.
pub use busbar_contract::DestinationId;

/// The at-capacity Retry-After floor in whole seconds — the answer when no admissible pool member
/// reports a genuine cooldown to wait out. Pinned to the 1.5.5 constant
/// (`AT_CAPACITY_RETRY_AFTER_SECS = AT_CAPACITY_RECOVERY_FLOOR_MS / 1000 = 2`).
///
/// The egress unit mirrors this value in its own crate rather than importing it, because unit
/// crates do not depend on one another — the breaker reaches that unit through its `ports::Breaker`
/// seam alone, and the composition root binds the two. The mirror is deliberate, not an oversight;
/// what keeps the two honest is an assertion in the egress unit's own tests, where the breaker is a
/// dev-dependency, that the two constants are still the same number.
pub const AT_CAPACITY_RETRY_AFTER_SECS: u64 = 2;

/// The default sticky cooldown applied by a hard-down trip (1.5.5's `DEFAULT_HARD_DOWN_COOLDOWN_SECS`).
pub const DEFAULT_HARD_DOWN_COOLDOWN_SECS: u64 = 1800;

/// The default absolute ceiling on an honored upstream Retry-After (1.5.5's
/// `DEFAULT_MAX_HONORED_RETRY_AFTER_SECS`).
pub const DEFAULT_MAX_HONORED_RETRY_AFTER_SECS: u64 = 86_400;

/// Why a `(pool, destination)` cannot admit right now, from the BREAKER's own point of view —
/// deliberately narrower than the egress unit's lane-availability taxonomy (`Unavailable` in
/// 1.5.5's substrate), which also carries `AtCapacity`/`Shedding`/`Dead`: those are concurrency and
/// operator-declaration facts the egress/admission units own, not this one.
///
/// Per PB-3, a member in any non-`Ready` state is EXCLUDED from the walk, never "ordered last and
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
    /// A transient upstream failure — cooldown + error counter. `retry_after` is the parsed
    /// `Retry-After` header, if any (see [`classify::parse_retry_after`]).
    Transient {
        /// The upstream's requested Retry-After, in seconds, if any.
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

/// The breaker unit's sealed trait shape (`docs/design/ARCHITECTURE.md` §3.1: `Breaker::observe/
/// state`). Sealed on a private supertrait so no plugin crate can implement it — only
/// [`BreakerUnit`] does. Per CG-29 and the design's other seven token-taking unit traits, every call also
/// takes a `&UnitToken<Route>` (`busbar-caps`'s capability token): the proof that the loop is at
/// the route step for this unit right now. The token is minted fresh per step call and taken by
/// reference, never stored, so this trait cannot be driven outside the step it was lent for.
pub trait Breaker: sealed::Sealed {
    /// Record one classified [`Outcome`] against `(pool, destination)`, applying the state
    /// machine's trip/cooldown/recovery rules and (for a probe outcome) journaling it. Returns
    /// `true` IFF this observation drove a fresh, logical Closed→Open trip (a success, a
    /// `HardDown` fan-out counts only the DEFAULT cell's freshness, and a sub-threshold or
    /// already-Open failure all return `false`) — the one signal a trip-count metric should
    /// increment on.
    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        cfg: &BreakerCfg,
        now: u64,
        token: &UnitToken<Route>,
    ) -> bool;

    /// Side-effect-free: this `(pool, destination)` cell's current [`LaneState`], folding in the
    /// destination's lifetime budget (`BudgetExhausted` takes precedence — an exhausted destination
    /// is excluded regardless of what its breaker cell reads).
    fn state(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &UnitToken<Route>,
    ) -> LaneState;
}

/// One `(pool, destination)` cell key. The default cell (direct/ad-hoc routes) uses pool `""`,
/// exactly as 1.5.5's `LaneState`-embedded default cell did.
type CellKey = (String, DestinationId);

/// The breaker unit: every `(pool, destination)` breaker cell plus every destination's lifetime
/// budget, behind one lock each. Cells are created lazily on first touch (a cell not yet created
/// inherits Closed-and-unspent, matching 1.5.5's lazy per-pool cell creation).
///
/// Generic over its [`JournalSink`] (`J`) and its `error_map` [`Diagnostics`] sink (`D`, CG-43):
/// both default to a noop so `BreakerUnit::new()` keeps 1.5.5's silent behavior, and a caller wires
/// a real sink through [`Self::with_journal_and_diagnostics`] (or the single-axis
/// [`Self::with_journal`] / [`Self::with_diagnostics`] shortcuts) without this unit taking a
/// logging dependency of its own.
pub struct BreakerUnit<J: JournalSink = NoopJournal, D: Diagnostics = classify::NoopDiagnostics> {
    cells: RwLock<HashMap<CellKey, Arc<BreakerCell>>>,
    /// Which pools exist for a given destination, so a hard-down fan-out can reach every one of
    /// them without scanning the whole cell map. Populated the first time a pool cell for that
    /// destination is touched.
    pools_by_destination: RwLock<HashMap<DestinationId, Vec<String>>>,
    budgets: RwLock<HashMap<DestinationId, Arc<LifetimeBudget>>>,
    /// Each destination's declared operator `error_map` override (see [`Self::set_error_map`]).
    /// Undeclared is an EMPTY map — HTTP-status classification alone still applies, matching
    /// 1.5.5's "empty error_map is valid".
    error_maps: RwLock<HashMap<DestinationId, HashMap<String, String>>>,
    hard_down_cooldown_secs: u64,
    max_honored_retry_after_secs: u64,
    journal: J,
    /// The sink an unrecognized `error_map` value (CG-43) is reported to. `classify::classify`
    /// itself never sees this — it is [`Self::classify`]'s own read of the declared `error_map`
    /// that can produce the diagnostic, via [`port::classify_upstream`].
    diagnostics: D,
}

impl BreakerUnit<NoopJournal, classify::NoopDiagnostics> {
    /// A breaker unit with the ADR-0002 defaults, no journal and no diagnostics sink (both
    /// discarded).
    pub fn new() -> Self {
        Self::with_journal_and_diagnostics(NoopJournal, classify::NoopDiagnostics)
    }
}

impl Default for BreakerUnit<NoopJournal, classify::NoopDiagnostics> {
    fn default() -> Self {
        Self::new()
    }
}

impl<J: JournalSink> BreakerUnit<J, classify::NoopDiagnostics> {
    /// A breaker unit with the ADR-0002 defaults, journaling probe lifecycle events to `journal`
    /// and discarding the `error_map` diagnostic.
    pub fn with_journal(journal: J) -> Self {
        Self::with_journal_and_diagnostics(journal, classify::NoopDiagnostics)
    }
}

impl<D: Diagnostics> BreakerUnit<NoopJournal, D> {
    /// A breaker unit with the ADR-0002 defaults, no journal, reporting an unrecognized
    /// `error_map` value (CG-43) to `diagnostics`.
    pub fn with_diagnostics(diagnostics: D) -> Self {
        Self::with_journal_and_diagnostics(NoopJournal, diagnostics)
    }
}

impl<J: JournalSink, D: Diagnostics> BreakerUnit<J, D> {
    /// A breaker unit with the ADR-0002 defaults, journaling probe lifecycle events to `journal`
    /// and reporting an unrecognized `error_map` value (CG-43) to `diagnostics`.
    pub fn with_journal_and_diagnostics(journal: J, diagnostics: D) -> Self {
        Self {
            cells: RwLock::new(HashMap::new()),
            pools_by_destination: RwLock::new(HashMap::new()),
            budgets: RwLock::new(HashMap::new()),
            error_maps: RwLock::new(HashMap::new()),
            hard_down_cooldown_secs: DEFAULT_HARD_DOWN_COOLDOWN_SECS,
            max_honored_retry_after_secs: DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
            journal,
            diagnostics,
        }
    }

    /// Override the hard-down sticky cooldown and the absolute Retry-After honoring ceiling
    /// (1.5.5's `limits.hard_down_cooldown_secs` / `limits.max_honored_retry_after_secs`).
    pub fn with_limits(
        mut self,
        hard_down_cooldown_secs: u64,
        max_honored_retry_after_secs: u64,
    ) -> Self {
        self.hard_down_cooldown_secs = hard_down_cooldown_secs;
        self.max_honored_retry_after_secs = max_honored_retry_after_secs;
        self
    }

    /// Declare a destination's lifetime request budget. `max_requests < 0` means unlimited
    /// (1.5.5's default). Calling this again for the same destination replaces its budget counter
    /// (a config-apply rebuild, not a per-request operation).
    pub fn set_budget(&self, destination: DestinationId, max_requests: i64) {
        let budget = if max_requests < 0 {
            LifetimeBudget::unlimited()
        } else {
            LifetimeBudget::limited(max_requests)
        };
        self.budgets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(destination, Arc::new(budget));
    }

    /// Remaining lifetime budget for a destination, or `None` if unlimited or never declared
    /// (an undeclared destination is treated as unlimited, matching 1.5.5's default).
    pub fn budget_remaining(&self, destination: DestinationId) -> Option<i64> {
        self.budgets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&destination)
            .and_then(|b| b.remaining())
    }

    fn budget_exhausted(&self, destination: DestinationId) -> bool {
        matches!(self.budget_remaining(destination), Some(0))
    }

    /// Spend one unit of `destination`'s lifetime budget. `true` if spent (or the destination is
    /// unlimited/undeclared); `false` if it was already exhausted.
    #[must_use]
    pub fn spend_budget(&self, destination: DestinationId) -> bool {
        match self
            .budgets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&destination)
        {
            Some(b) => b.spend(),
            None => true,
        }
    }

    /// Compensating refund of one unit previously spent (see [`budget::LifetimeBudget::refund`]).
    pub fn refund_budget(&self, destination: DestinationId) {
        if let Some(b) = self
            .budgets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&destination)
        {
            b.refund();
        }
    }

    /// Declare (or replace) `destination`'s operator `error_map` override: the same
    /// provider-code/structured-type → status-class table 1.5.5 read from `ModelCfg::error_map`.
    /// Calling this again for the same destination replaces its map wholesale (a config-apply
    /// rebuild, not a per-request merge), matching [`Self::set_budget`]'s own replace semantics.
    pub fn set_error_map(&self, destination: DestinationId, error_map: HashMap<String, String>) {
        self.error_maps
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(destination, error_map);
    }

    /// Turn one upstream answer into a [`port::Classified`] disposition/outcome/label, reading
    /// `destination`'s declared `error_map` (empty when none was ever declared). The stateful
    /// method [`port::classify_upstream`] is implemented over — this is the one the egress unit's
    /// `Breaker::classify` port is bound to. An `error_map` value that does not name a recognized
    /// [`classify::StatusClass`] is reported to this unit's own [`Diagnostics`] sink (CG-43),
    /// wired in at construction (see [`Self::with_diagnostics`]).
    #[must_use]
    pub fn classify(
        &self,
        destination: DestinationId,
        status: port::UpstreamStatus,
    ) -> port::Classified {
        let error_map = self
            .error_maps
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&destination)
            .cloned()
            .unwrap_or_default();
        port::classify_upstream(&error_map, status, &self.diagnostics)
    }

    fn cell(&self, pool: &str, destination: DestinationId) -> Arc<BreakerCell> {
        let key = (pool.to_string(), destination);
        if let Some(c) = self
            .cells
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            return c.clone();
        }
        let mut cells = self.cells.write().unwrap_or_else(|e| e.into_inner());
        let cell = cells
            .entry(key)
            .or_insert_with(|| Arc::new(BreakerCell::new()));
        let cell = cell.clone();
        drop(cells);
        let mut pools = self
            .pools_by_destination
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let list = pools.entry(destination).or_default();
        if !list.iter().any(|p| p == pool) {
            list.push(pool.to_string());
        }
        cell
    }

    /// Trip EVERY existing pool cell for `destination` hard-down at once (PB-83: the default `""`
    /// cell and every named pool's cell), each with the SAME sticky cooldown — a hard-down fault
    /// (bad key, billing exhausted) is a property of the shared destination, not of the one pool
    /// the failing attempt happened to run through. Returns `true` IFF the default cell's trip was
    /// fresh (it was Closed beforehand), for a trip-count metric.
    pub fn hard_down_all(&self, destination: DestinationId, now: u64) -> bool {
        let default_cell = self.cell("", destination);
        let default_was_fresh = default_cell.hard_down(now, self.hard_down_cooldown_secs);

        let pools: Vec<String> = self
            .pools_by_destination
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&destination)
            .cloned()
            .unwrap_or_default();
        for pool in pools {
            if pool.is_empty() {
                continue; // already tripped above
            }
            let cell = self.cell(&pool, destination);
            let _ = cell.hard_down(now, self.hard_down_cooldown_secs);
        }
        default_was_fresh
    }

    /// Mutating admission attempt: wins-or-loses the single-flight probe, checking the destination's
    /// lifetime budget first (an exhausted destination is excluded before the breaker is even
    /// consulted, matching 1.5.5's `classify` reading `dead`/budget separately from the breaker).
    /// On success, journals a won probe.
    pub fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, LaneState> {
        if self.budget_exhausted(destination) {
            return Err(LaneState::BudgetExhausted);
        }
        let cell = self.cell(pool, destination);
        match cell.acquire(now) {
            ProbeAdmit::Denied => Err(lane_state_from_verdict(cell.verdict(now))),
            ProbeAdmit::ReadyNoProbe => Ok(Admit { probe_epoch: None }),
            ProbeAdmit::ProbeWon(epoch) => {
                self.journal.record(ProbeEvent::Won {
                    pool: pool.to_string(),
                    destination,
                    epoch,
                    now,
                });
                Ok(Admit {
                    probe_epoch: Some(epoch),
                })
            }
        }
    }

    /// Release a probe won by [`Self::try_admit`] but never dispatched (owner-checked: a stale,
    /// late release cannot revert a newer probe a different caller has since won). Journals the
    /// release.
    pub fn release_probe(
        &self,
        pool: &str,
        destination: DestinationId,
        owned_epoch: u64,
        now: u64,
    ) {
        let cell = self.cell(pool, destination);
        cell.release_probe_owned(owned_epoch);
        self.journal.record(ProbeEvent::Released {
            pool: pool.to_string(),
            destination,
            epoch: owned_epoch,
            now,
        });
    }

    /// The at-capacity terminal's `Retry-After`, per PB-4: the SOONEST genuine (`> 0`) cooldown
    /// among the given members' states, else [`AT_CAPACITY_RETRY_AFTER_SECS`], always floored at 1.
    /// A member reporting `Suppressed { until }` with `until <= now` (an expired cooldown — the
    /// member is actually probe-winnable) contributes no genuine cooldown, matching 1.5.5's
    /// exclusion of an at-capacity-but-Closed member from this same computation.
    pub fn on_exhausted_retry_after(states: impl IntoIterator<Item = LaneState>, now: u64) -> u64 {
        let soonest = states
            .into_iter()
            .filter_map(|s| match s {
                LaneState::Suppressed { until } => {
                    let remaining = until.saturating_sub(now);
                    (remaining > 0).then_some(remaining)
                }
                _ => None,
            })
            .min();
        soonest.unwrap_or(AT_CAPACITY_RETRY_AFTER_SECS).max(1)
    }
}

impl<J: JournalSink, D: Diagnostics> sealed::Sealed for BreakerUnit<J, D> {}

impl<J: JournalSink, D: Diagnostics> Breaker for BreakerUnit<J, D> {
    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        cfg: &BreakerCfg,
        now: u64,
        _token: &UnitToken<Route>,
    ) -> bool {
        match outcome {
            Outcome::RecordNothing => false,
            Outcome::HardDown => self.hard_down_all(destination, now),
            Outcome::Success => {
                let cell = self.cell(pool, destination);
                let was_probe = matches!(cell.state(), CellState::HalfOpen);
                let closed = cell.record_success(now);
                if was_probe && closed {
                    self.journal.record(ProbeEvent::Succeeded {
                        pool: pool.to_string(),
                        destination,
                        now,
                    });
                }
                false
            }
            Outcome::Transient { retry_after } => {
                let cell = self.cell(pool, destination);
                // Gated on what the call REPORTS, not on a state read before it — the same way the
                // Success arm gates on record_success's own answer. A state read here can be stale
                // by the time record_failure takes the transition lock, and the journal would then
                // name a probe failure for a fresh trip, or miss one for a reopen.
                let effect =
                    cell.record_failure(now, cfg, retry_after, self.max_honored_retry_after_secs);
                if effect.reopened() {
                    let cooldown_until = match cell.state() {
                        CellState::Open { until } => until,
                        _ => now,
                    };
                    self.journal.record(ProbeEvent::Failed {
                        pool: pool.to_string(),
                        destination,
                        cooldown_until,
                        now,
                    });
                }
                effect.tripped()
            }
        }
    }

    fn state(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        _token: &UnitToken<Route>,
    ) -> LaneState {
        if self.budget_exhausted(destination) {
            return LaneState::BudgetExhausted;
        }
        lane_state_from_verdict(self.cell(pool, destination).verdict(now))
    }
}

#[cfg(test)]
mod tests;

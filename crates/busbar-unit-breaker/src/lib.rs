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
//!   the architecture's ledger requires one, so this crate defines the seam without owning
//!   the actual journal writer.
//! - The sealed [`Breaker`] trait itself (`observe`/`state`, in the unit-trait shape). 1.5.5
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
pub mod probe;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use budget::LifetimeBudget;
use busbar_caps::{Route, UnitToken};
use cell::{BreakerCell, BreakerState as CellState, BreakerVerdict, DeniedBy, ProbeAdmit};
use cfg::BreakerCfg;
use classify::Diagnostics;
use journal::{JournalSink, NoopJournal, ProbeEvent};
use probe::{DueProbe, ProbePolicy, Scheduled};

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

/// The recovery hint for a lost single-flight probe race: the peer's probe resolves the cell within
/// one request, so the wait is "next tick" (1.5.5's `PROBE_RETRY_FLOOR_MS`).
const PROBE_RETRY_FLOOR_MS: u64 = 250;

/// The honest floor under an at-capacity wait when there is no drain estimate to give — capacity has
/// no scheduled recovery the way a breaker does (1.5.5's `AT_CAPACITY_RECOVERY_FLOOR_MS`).
pub const AT_CAPACITY_RECOVERY_FLOOR_MS: u64 = 2_000;

/// The floor under a shed request's wait (1.5.5's `SHED_RETRY_FLOOR_MS`).
pub const SHED_RETRY_FLOOR_MS: u64 = 1_000;

/// Why a `(pool, destination)` cannot admit right now — THE one taxonomy every consumer speaks:
/// selection (exclude), least-bad (rank), `Retry-After` (hint), `/stats` and `/metrics` (render),
/// the queue (budget). Moved from 1.5.5's `Unavailable` (`busbar-substrate/src/store.rs:47-88`)
/// whole, because a narrower one is those five consumers quietly disagreeing: a reason a caller
/// cannot name is a reason it cannot rank, budget or render, and it renders SOMETHING regardless.
///
/// A member in any non-`Ready` state is EXCLUDED from the walk, never "ordered last and
/// attempted" — the egress unit's selection filter is expected to drop anything this reports as
/// not `Ready` before ranking, exactly as 1.5.5's `try_admit`/`lane_admissible` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneState {
    /// Would admit a request right now.
    Ready,
    /// Administratively down (see [`BreakerUnit::set_dead`]). Does not self-recover: the operator's
    /// declaration is what put it here and only a config apply takes it back out.
    Dead,
    /// Breaker-suppressed (Open, or Closed inside a pending soft cooldown) until the deadline.
    Suppressed {
        /// The cooldown deadline, in Unix seconds.
        until: u64,
    },
    /// A peer holds the single-flight recovery probe.
    ProbeInFlight,
    /// The destination's lifetime request budget is spent. Does not self-recover.
    BudgetExhausted,
    /// Every concurrency permit is held.
    AtCapacity {
        /// How long until a slot plausibly frees, in ms. An ESTIMATE, never exact — capacity has no
        /// scheduled recovery the way a breaker does. `None` when there is no basis to estimate, in
        /// which case the hint falls back to [`AT_CAPACITY_RECOVERY_FLOOR_MS`].
        drain_hint_ms: Option<u64>,
    },
    /// Inbound backpressure shed this request before selection ever ran.
    Shedding,
}

impl LaneState {
    /// THE single definition of "when could this plausibly serve again", in ms from `now` —
    /// 1.5.5's `Unavailable::recovery_hint_ms` (`busbar-substrate/src/store.rs:74-88`). `None` means
    /// no self-recovery: nothing this unit will do brings it back.
    ///
    /// One function, because `Retry-After`, least-bad ranking, queue budgeting and the `/stats`
    /// gauge ALL consume it, and four consumers deriving it separately is four answers.
    #[must_use]
    pub fn recovery_hint_ms(&self, now: u64) -> Option<u64> {
        match self {
            // Nothing to wait for: one is admitting already, the other two do not self-recover.
            LaneState::Ready | LaneState::Dead | LaneState::BudgetExhausted => None,
            LaneState::Suppressed { until } => Some(until.saturating_sub(now).saturating_mul(1000)),
            LaneState::ProbeInFlight => Some(PROBE_RETRY_FLOOR_MS), // ~one request
            LaneState::AtCapacity { drain_hint_ms } => {
                Some(drain_hint_ms.unwrap_or(AT_CAPACITY_RECOVERY_FLOOR_MS))
            }
            LaneState::Shedding => Some(SHED_RETRY_FLOOR_MS),
        }
    }

    /// The stable, snake_case name of this state — the SINGLE rendering `/stats` and any
    /// operator-facing surface read, derived from the same taxonomy routing dispatches on.
    #[must_use]
    pub fn variant_name(&self) -> &'static str {
        match self {
            LaneState::Ready => "available",
            LaneState::Dead => "dead",
            LaneState::Suppressed { .. } => "breaker_open",
            LaneState::ProbeInFlight => "probe_in_flight",
            LaneState::BudgetExhausted => "budget_exhausted",
            LaneState::AtCapacity { .. } => "at_capacity",
            LaneState::Shedding => "shedding",
        }
    }
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
/// [`BreakerUnit`] does. Like the design's other seven token-taking unit traits, every call also
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
    ///
    /// `now_nanos` is the SAME instant as `now`, read in nanoseconds: the cooldown jitter seed
    /// 1.5.5 read from `SystemTime::now().as_nanos()` inside the cell. It is a parameter for the
    /// same reason `now` is — a unit crate reads no clock, so the root reads this once and hands it
    /// down (`crate::clock::unix_time_nanos`).
    // One over the default threshold, and the one over is the clock: `now` and `now_nanos` are two
    // resolutions of ONE reading, and a struct to carry the pair would be a type the rest of this
    // trait does not take (`state`/`try_admit` are answered from whole seconds alone). Widening the
    // seam's vocabulary to quiet a count is the more expensive trade.
    #[allow(clippy::too_many_arguments)]
    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        cfg: &BreakerCfg,
        now: u64,
        now_nanos: u128,
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

/// The destination-GLOBAL counters, as `/stats` renders them — 1.5.5's
/// `LaneState.{ok, err, client_fault, trips, last_trip_at}`.
///
/// Destination-global and not per cell: they are what an operator reads about an UPSTREAM, and a
/// destination fronted by three pools is still one upstream. The per-cell error count stays where
/// it is (`BreakerCell::err_count`), a per-pool diagnostic and a different question.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DestinationCounters {
    /// Successes recorded against this destination.
    pub ok: u64,
    /// Upstream failures recorded against this destination.
    pub err: u64,
    /// The CALLER's own faults — counted apart, because they say nothing about the upstream.
    pub client_fault: u64,
    /// Monotonic count of genuine Closed→Open trips.
    pub trips: u64,
    /// When the most recent trip happened, in Unix seconds. `0` means never.
    pub last_trip_at: u64,
}

#[derive(Default)]
struct CounterCell {
    ok: AtomicU64,
    err: AtomicU64,
    client_fault: AtomicU64,
    trips: AtomicU64,
    last_trip_at: AtomicU64,
}

impl CounterCell {
    fn snapshot(&self) -> DestinationCounters {
        DestinationCounters {
            ok: self.ok.load(Ordering::Relaxed),
            err: self.err.load(Ordering::Relaxed),
            client_fault: self.client_fault.load(Ordering::Relaxed),
            trips: self.trips.load(Ordering::Relaxed),
            last_trip_at: self.last_trip_at.load(Ordering::Relaxed),
        }
    }

    fn trip(&self, now: u64) {
        self.trips.fetch_add(1, Ordering::Relaxed);
        self.last_trip_at.store(now, Ordering::Relaxed);
    }
}

/// Every `(pool, destination)` cell, nested pool-first. The default cell (direct/ad-hoc routes)
/// lives under pool `""`, exactly as 1.5.5's `LaneState`-embedded default cell did.
///
/// Nested rather than keyed on a `(String, DestinationId)` tuple because a tuple key can only be
/// looked up by a whole tuple, which means minting an owned `String` from the caller's `&str` on
/// EVERY lookup — an allocation per admission and per observation, on the hot path, thrown away
/// again immediately. Nested, both halves are borrowed: the pool as `&str`, the destination as the
/// small `Copy` locator it is. Only creating a cell spells the pool name into a `String`.
type CellMap = HashMap<String, HashMap<DestinationId, Arc<BreakerCell>>>;

/// The breaker unit: every `(pool, destination)` breaker cell plus every destination's lifetime
/// budget, behind one lock each. Cells are created lazily on first touch (a cell not yet created
/// inherits Closed-and-unspent, matching 1.5.5's lazy per-pool cell creation).
///
/// Generic over its [`JournalSink`] (`J`) and its `error_map` [`Diagnostics`] sink (`D`):
/// both default to a noop so `BreakerUnit::new()` keeps 1.5.5's silent behavior, and a caller wires
/// a real sink through [`Self::with_journal_and_diagnostics`] (or the single-axis
/// [`Self::with_journal`] / [`Self::with_diagnostics`] shortcuts) without this unit taking a
/// logging dependency of its own.
pub struct BreakerUnit<J: JournalSink = NoopJournal, D: Diagnostics = classify::NoopDiagnostics> {
    cells: RwLock<CellMap>,
    /// Which pools exist for a given destination, so a hard-down fan-out can reach every one of
    /// them without scanning the whole cell map. Populated the first time a pool cell for that
    /// destination is touched.
    pools_by_destination: RwLock<HashMap<DestinationId, Vec<String>>>,
    budgets: RwLock<HashMap<DestinationId, Arc<LifetimeBudget>>>,
    /// Which destinations an operator has declared administratively down (see [`Self::set_dead`]).
    /// Absent is alive, which is 1.5.5's default for a lane nobody said anything about.
    dead: RwLock<HashMap<DestinationId, bool>>,
    /// Each destination's own counters (see [`DestinationCounters`]).
    counters: RwLock<HashMap<DestinationId, Arc<CounterCell>>>,
    /// What an upstream last said when it was hard-downed (see [`Self::hard_down_all_with_reason`]).
    hard_down_reasons: RwLock<HashMap<DestinationId, String>>,
    /// Each destination's declared operator `error_map` override (see [`Self::set_error_map`]).
    /// Undeclared is an EMPTY map — HTTP-status classification alone still applies, matching
    /// 1.5.5's "empty error_map is valid".
    ///
    /// Behind an `Arc` so a classification takes a REFERENCE-COUNT bump out from under the lock
    /// rather than a deep copy of every entry: the map is written once per config apply and read
    /// once per upstream answer, and copying its keys and values on each of those reads meant an
    /// allocation per entry on the response path. The `Arc` also keeps the lock held only for the
    /// lookup, so a classifier's own diagnostics sink cannot run while this unit's `error_maps`
    /// lock is held.
    error_maps: RwLock<HashMap<DestinationId, Arc<HashMap<String, String>>>>,
    /// Each destination's declared active-probe policy and the moment it is next due
    /// (see [`probe`]). Undeclared is ABSENT rather than a `None`-mode entry, so a destination the
    /// operator never asked to probe costs nothing to hold and nothing to walk.
    ///
    /// One lock, not the per-lane atomic slots 1.5.5 needed: those existed because several
    /// generations of prober tasks raced over one deadline table, and the whole point of putting
    /// the schedule here is that the racers are gone. The map is written once per config apply and
    /// walked once per Tick, both of them at a seconds cadence, so a lock is the right primitive
    /// and a compare-exchange would be machinery for a race that no longer exists.
    probes: RwLock<HashMap<DestinationId, Scheduled>>,
    hard_down_cooldown_secs: u64,
    max_honored_retry_after_secs: u64,
    journal: J,
    /// The sink an unrecognized `error_map` value is reported to. `classify::classify`
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
    /// `error_map` value to `diagnostics`.
    pub fn with_diagnostics(diagnostics: D) -> Self {
        Self::with_journal_and_diagnostics(NoopJournal, diagnostics)
    }
}

impl<J: JournalSink, D: Diagnostics> BreakerUnit<J, D> {
    /// A breaker unit with the ADR-0002 defaults, journaling probe lifecycle events to `journal`
    /// and reporting an unrecognized `error_map` value to `diagnostics`.
    pub fn with_journal_and_diagnostics(journal: J, diagnostics: D) -> Self {
        Self {
            cells: RwLock::new(HashMap::new()),
            pools_by_destination: RwLock::new(HashMap::new()),
            budgets: RwLock::new(HashMap::new()),
            dead: RwLock::new(HashMap::new()),
            counters: RwLock::new(HashMap::new()),
            hard_down_reasons: RwLock::new(HashMap::new()),
            error_maps: RwLock::new(HashMap::new()),
            probes: RwLock::new(HashMap::new()),
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

    /// Declare a destination's active-probe policy, as of `now`.
    ///
    /// The same shape as [`Self::set_budget`] and `set_error_map`, and called from the same place
    /// for the same reason: the composition root reads the operator's per-destination `health:`
    /// block, narrows it to a [`DestinationId`], and declares it. Nothing plane-shaped crosses —
    /// this unit never learns which dialect, which model or which host is behind the destination,
    /// and could not send the probe if it did.
    ///
    /// RE-DECLARING IS THE NORMAL CASE, not the exception: every config apply re-declares every
    /// destination it still carries. A destination that keeps its policy keeps its deadline (see
    /// [`Scheduled::declare`] for why that must be monotone-earliest), so probing does not go dark
    /// under a burst of applies. A `none` mode is stored rather than dropped, because storing it is
    /// what makes it survive as an ANSWER — a destination the operator explicitly turned probing
    /// off for reads back as declared-and-silent, not as never-mentioned.
    pub fn set_probe_policy(&self, destination: DestinationId, policy: ProbePolicy, now: u64) {
        let mut probes = self.probes.write().unwrap_or_else(|e| e.into_inner());
        let previous = probes.get(&destination).copied();
        probes.insert(destination, Scheduled::declare(previous, policy, now));
    }

    /// Withdraw a destination's probe policy — the config no longer carries it.
    ///
    /// A destination dropped from the config must lose its slot, or its deadline outlives the
    /// declaration that made it and the schedule keeps naming something nothing else in the node
    /// knows about.
    pub fn forget_probe_policy(&self, destination: DestinationId) {
        self.probes
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&destination);
    }

    /// Which destinations are due to be probed at `now`, and how long each probe may take.
    ///
    /// THIS IS THE TICK'S QUESTION, and it is the whole of what the node's clock asks this unit.
    /// The answer is a decision over the values handed in — the declared policies, the deadlines,
    /// and each destination's own current state — so replaying the same inputs replays the same
    /// answer. What happens next is not this unit's: the plane writes the request
    /// (`Plane::probe_request`), the egress-auth unit decorates it, the egress unit sends it, and
    /// the outcome comes back through [`Breaker::observe`] like any other.
    ///
    /// TAKING A TURN AND ANSWERING ARE THE SAME CALL, deliberately. A destination whose deadline
    /// passed has its next one set here whether or not this Tick ends up asking it, so a `dead`
    /// destination that is healthy — the common case, and the one that answers nothing — does not
    /// accumulate an elapsed deadline that fires the instant it finally trips.
    ///
    /// `Dead` mode's filter reads every pool cell this destination already HAS: suppressed in any
    /// one of them means unusable there, and recovering it early is the entire job of the mode.
    /// That is 1.5.5's `lane_needs_probe`, expressed in the vocabulary this crate already had.
    pub fn probes_due(&self, now: u64) -> Vec<DueProbe> {
        let due: Vec<(DestinationId, Scheduled)> = {
            let mut probes = self.probes.write().unwrap_or_else(|e| e.into_inner());
            let taken: Vec<(DestinationId, Scheduled)> = probes
                .iter()
                .filter(|(_, s)| s.due(now))
                .map(|(d, s)| (*d, *s))
                .collect();
            for (destination, scheduled) in &taken {
                probes.insert(*destination, scheduled.taken(now));
            }
            taken
        };
        due.into_iter()
            .filter(|(destination, scheduled)| match scheduled.policy.mode {
                probe::ProbeMode::Active => true,
                probe::ProbeMode::Dead => self.suppressed_anywhere(*destination, now),
                probe::ProbeMode::None => false,
            })
            .map(|(destination, scheduled)| DueProbe {
                destination,
                timeout_secs: scheduled.policy.timeout_secs.max(1),
            })
            .collect()
    }

    /// Whether the breaker is suppressing this destination in any cell it is registered in — the
    /// default `""` cell included, because a destination reached without a pool routes through it.
    ///
    /// A destination whose lifetime budget is spent is NOT suppressed in the sense this asks about:
    /// it does not self-recover, so probing it can only produce failures against an upstream that
    /// was never the problem.
    /// A Tick MUST NOT MATERIALIZE A CELL. Cells are created on first touch by the traffic that
    /// routes through them, and that is what makes the map a record of what this node has actually
    /// reached; a sweep that created one per declared destination per Tick would fill it with cells
    /// nothing ever used and make "which pools is this destination in" answer a config question
    /// instead of a traffic one. So this reads the existing cells only — and a destination with no
    /// cell yet is Closed-and-unspent by this crate's own lazy rule, which is not suppressed.
    fn suppressed_anywhere(&self, destination: DestinationId, now: u64) -> bool {
        if self.budget_exhausted(destination) {
            return false;
        }
        self.cells
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter_map(|by_destination| by_destination.get(&destination))
            .any(|cell| matches!(cell.verdict(now), BreakerVerdict::Open { .. }))
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
            .insert(destination, Arc::new(error_map));
    }

    /// Turn one upstream answer into a [`port::Classified`] disposition/outcome/label, reading
    /// `destination`'s declared `error_map` (empty when none was ever declared). The stateful
    /// method [`port::classify_upstream`] is implemented over — this is the one the egress unit's
    /// `Breaker::classify` port is bound to. An `error_map` value that does not name a recognized
    /// [`classify::StatusClass`] is reported to this unit's own [`Diagnostics`] sink,
    /// wired in at construction (see [`Self::with_diagnostics`]).
    #[must_use]
    pub fn classify(
        &self,
        destination: DestinationId,
        status: port::UpstreamStatus<'_>,
    ) -> port::Classified {
        // The shared map comes out from under the lock as a reference count, never a copy, and the
        // lock is released before the pure classification runs. A destination that declared no
        // map classifies against a borrowed empty one, which allocates nothing at all.
        let error_map = self
            .error_maps
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&destination)
            .map(Arc::clone);
        match error_map {
            Some(map) => port::classify_upstream(&map, status, &self.diagnostics),
            None => port::classify_upstream(&HashMap::new(), status, &self.diagnostics),
        }
    }

    fn cell(&self, pool: &str, destination: DestinationId) -> Arc<BreakerCell> {
        // The hit path — every admission and every observation of an already-touched member —
        // borrows the whole key from the caller's own arguments and allocates nothing.
        if let Some(c) = self
            .cells
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(pool)
            .and_then(|by_destination| by_destination.get(&destination))
        {
            return c.clone();
        }
        let mut cells = self.cells.write().unwrap_or_else(|e| e.into_inner());
        // The pool name is registered against the destination BEFORE the cell is published, and
        // both happen under the cell map's write lock. Publishing first left a window in which the
        // cell was fully reachable — admissions ran through it — while `hard_down_all`, which walks
        // the destination's registered names, could not see it: a bad key would suppress every
        // other pool for that destination and leave this one serving. Reachable now implies
        // registered. The lock order matches `hard_down_all`'s own, cells before pools.
        {
            let mut pools = self
                .pools_by_destination
                .write()
                .unwrap_or_else(|e| e.into_inner());
            let list = pools.entry(destination).or_default();
            if !list.iter().any(|p| p == pool) {
                list.push(pool.to_string());
            }
        }
        cells
            .entry(pool.to_string())
            .or_default()
            .entry(destination)
            .or_insert_with(|| Arc::new(BreakerCell::new()))
            .clone()
    }

    /// Whether a cell for this pool and destination already exists, without creating one.
    ///
    /// Reachability made observable, so a test can wait for the exact moment a cell becomes usable
    /// and ask what else can see it then.
    #[cfg(test)]
    pub(crate) fn has_cell(&self, pool: &str, destination: DestinationId) -> bool {
        self.cells
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(pool)
            .is_some_and(|by_destination| by_destination.contains_key(&destination))
    }

    /// Trip EVERY existing pool cell for `destination` hard-down at once (the default `""`
    /// cell and every named pool's cell), each with the SAME sticky cooldown — a hard-down fault
    /// (bad key, billing exhausted) is a property of the shared destination, not of the one pool
    /// the failing attempt happened to run through. Returns `true` IFF the default cell's trip was
    /// fresh (it was Closed beforehand), for a trip-count metric.
    pub fn hard_down_all(&self, destination: DestinationId, now: u64) -> bool {
        let mut cells = self.cells_for(destination).into_iter();
        // The default cell is always the first of the fan-out, and its freshness is the answer.
        let (_, default_cell) = cells
            .next()
            .expect("the fan-out always yields the default cell");
        let default_was_fresh = default_cell.hard_down(now, self.hard_down_cooldown_secs);
        for (_, cell) in cells {
            let _ = cell.hard_down(now, self.hard_down_cooldown_secs);
        }
        // The same seam a transient trip counts at: one LOGICAL trip, counted once, so a
        // persistently dead destination does not re-count on every recovery-probe cycle.
        if default_was_fresh {
            self.counters(destination).trip(now);
        }
        default_was_fresh
    }

    /// [`Self::hard_down_all`], recording WHY — 1.5.5's `record_hard_down_all_cells(lane, reason)`
    /// (`busbar-core/src/store/in_memory/availability.rs:535-593`), which records the reason
    /// lane-wide and emits an operator diagnostic before it trips anything.
    ///
    /// The reason is the whole value of the event to whoever has to explain it. "This destination
    /// went dark" is a fact an operator can already see; "and here is what it said when it went" is
    /// the part that exists only at this instant, and discarding it at the call site — as this unit
    /// did — leaves the one question the page will ask with no answer anywhere.
    ///
    /// [`Self::hard_down_all`] leaves any recorded reason alone rather than blanking it, because
    /// the classifier holds the reason and `Outcome::HardDown` does not carry one across yet; that
    /// widening belongs to the landing that serves the route step, not to this one.
    pub fn hard_down_all_with_reason(
        &self,
        destination: DestinationId,
        reason: &str,
        now: u64,
    ) -> bool {
        self.hard_down_reasons
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(destination, reason.to_string());
        self.diagnostics.destination_hard_down(reason);
        self.hard_down_all(destination, now)
    }

    /// What the upstream said the last time this destination was hard-downed, if anything did.
    #[must_use]
    pub fn hard_down_reason(&self, destination: DestinationId) -> Option<String> {
        self.hard_down_reasons
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&destination)
            .cloned()
    }

    fn counters(&self, destination: DestinationId) -> Arc<CounterCell> {
        if let Some(c) = self
            .counters
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&destination)
        {
            return c.clone();
        }
        self.counters
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .entry(destination)
            .or_default()
            .clone()
    }

    /// This destination's counters (see [`DestinationCounters`]).
    #[must_use]
    pub fn destination_counters(&self, destination: DestinationId) -> DestinationCounters {
        self.counters(destination).snapshot()
    }

    /// Record one CLIENT fault against this destination — 1.5.5's `record_client_fault`
    /// (`availability.rs:479`). It touches no breaker state and never the error counter: the
    /// caller's own bad input says nothing about the upstream's health, and folding it into `err`
    /// would trip destinations on the strength of requests they answered correctly.
    pub fn record_client_fault(&self, destination: DestinationId) {
        self.counters(destination)
            .client_fault
            .fetch_add(1, Ordering::Relaxed);
    }

    /// The destination-GLOBAL availability: the BEST verdict across the cells traffic is actually
    /// routed through, folded into one — 1.5.5's `lane_breaker_verdict` (`availability.rs:14-43`)
    /// under `classify_lane`, which is what `/stats` renders from.
    ///
    /// Best wins, so the aggregate matches "would this destination serve at all": `Ready` beats
    /// `ProbeWinnable` beats `HalfOpen` beats `Open`, and among Open cells the SOONEST deadline is
    /// kept, because that is when the destination could next serve. The cell set is 1.5.5's own: the
    /// per-pool cells where there are any, else the default cell, which IS the routed cell for a
    /// destination reached only directly. Read-only — no probe CAS, no Open→HalfOpen transition.
    ///
    /// Capacity is not folded in, exactly as it is not folded into [`Breaker::state`]: this unit
    /// holds no permits, and the caller that peeks them for [`Self::try_admit_gated`] is the one
    /// that can answer that axis. Breaker-first either way, as 1.5.5 is.
    #[must_use]
    pub fn lane_state(&self, destination: DestinationId, now: u64) -> LaneState {
        if self.is_dead(destination) {
            return LaneState::Dead;
        }
        if self.budget_exhausted(destination) {
            return LaneState::BudgetExhausted;
        }
        // Rank two verdicts, keeping the more available and — among Opens — the sooner.
        fn better(a: BreakerVerdict, b: BreakerVerdict) -> BreakerVerdict {
            fn rank(v: BreakerVerdict) -> u8 {
                match v {
                    BreakerVerdict::Ready => 3,
                    BreakerVerdict::ProbeWinnable => 2,
                    BreakerVerdict::HalfOpen => 1,
                    BreakerVerdict::Open { .. } => 0,
                }
            }
            match (a, b) {
                (BreakerVerdict::Open { until: ua }, BreakerVerdict::Open { until: ub }) => {
                    BreakerVerdict::Open { until: ua.min(ub) }
                }
                _ if rank(a) >= rank(b) => a,
                _ => b,
            }
        }
        let cells = self.cells_for(destination);
        let folded = cells
            .iter()
            .filter(|(pool, _)| !pool.is_empty())
            .map(|(_, cell)| cell.verdict(now))
            .reduce(better)
            // A destination with no named pool: the default cell IS the routed cell.
            .unwrap_or_else(|| self.cell("", destination).verdict(now));
        lane_state_from_verdict(folded)
    }

    /// EVERY existing cell naming this destination — the default `""` cell first, then each named
    /// pool's — which is the reach every destination-wide verb on this unit has.
    ///
    /// A destination is a shared upstream. A hard-down is a fact about it (a bad key is bad in
    /// every pool), and so is a health probe's answer: 1.5.5's `record_hard_down_all_cells`,
    /// `recover_lane`, `record_probe_success_all_cells` and `record_probe_failure_all_cells` all
    /// walk exactly this set, and they walk it because a fact recorded in one pool's cell alone
    /// leaves the other pools' traffic routing against an upstream that has already answered.
    ///
    /// Existing cells only, as 1.5.5 iterated: a cell not yet created inherits health lazily on
    /// first access. The default cell is created if it is missing, because in 1.5.5 it IS the lane
    /// and therefore always exists.
    fn cells_for(&self, destination: DestinationId) -> Vec<(String, Arc<BreakerCell>)> {
        let pools: Vec<String> = self
            .pools_by_destination
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&destination)
            .cloned()
            .unwrap_or_default();
        let mut out = vec![(String::new(), self.cell("", destination))];
        for pool in pools {
            if pool.is_empty() {
                continue; // the default cell, already first
            }
            let cell = self.cell(&pool, destination);
            out.push((pool, cell));
        }
        out
    }

    /// Is this destination due for an out-of-band health probe? True when ANY cell naming it is
    /// suppressed — 1.5.5's `lane_needs_probe`
    /// (`busbar-core/src/store/in_memory/availability.rs:684-691`).
    ///
    /// This is the filter `ProbeMode::Dead` reads, and the one PROBE-1's `probes_due(now)`
    /// composes on: the schedule says WHEN, this says WHETHER.
    #[must_use]
    pub fn needs_probe(&self, destination: DestinationId, now: u64) -> bool {
        self.cells_for(destination)
            .iter()
            .any(|(_, cell)| cell.suppressed(now))
    }

    /// A SUCCESSFUL out-of-band health probe: the shared upstream is demonstrably alive, so every
    /// cell naming it recovers — 1.5.5's `recover_lane` followed by
    /// `record_probe_success_all_cells` (`availability.rs:595` and `:434`), which is the pair
    /// `engine/health.rs:398,:407` calls on a 2xx.
    ///
    /// Recovering only the cell the probe happened to run through is the difference that made this
    /// verb necessary: a lane recovered today across N pools would, without the fan-out, recover in
    /// zero of them, and organic traffic would stay benched against an upstream that had just
    /// answered. The recovery close comes first and the success outcome second, in that order,
    /// exactly as the prober calls them — the close clears the window the outcome then seeds.
    pub fn record_probe_success_all(&self, destination: DestinationId, now: u64) {
        let mut recovered = false;
        for (_, cell) in self.cells_for(destination) {
            recovered |= cell.recover(now);
            // Pushes the success outcome and runs the HalfOpen->Closed CAS, so a peer that won the
            // probe between the close above and this push still gets its terminal record.
            recovered |= cell.record_success(now);
        }
        // EXACTLY ONCE per probe, not once per cell: a destination in N pools would otherwise count
        // one probe as N successes and dilute its own error rate by its pool count.
        self.counters(destination)
            .ok
            .fetch_add(1, Ordering::Relaxed);
        if recovered {
            self.journal.record(ProbeEvent::Succeeded {
                pool: String::new(),
                destination,
                now,
            });
        }
    }

    /// A FAILED out-of-band health probe: record a transient against every cell naming the
    /// destination, each evaluated against ITS OWN pool's resolved configuration — 1.5.5's
    /// `record_probe_failure_all_cells` with its per-pool `resolve_cfg` callback
    /// (`availability.rs:641-682`).
    ///
    /// The callback is the load-bearing part and not a convenience: organic traffic is selected
    /// against the per-pool cells, and a probe failure evaluated against one default ladder would
    /// trip a pool whose operator declared a laxer threshold and spare one who declared a stricter.
    /// It is called with `""` for the default cell and with each pool's own name.
    ///
    /// The trip bool every cell returns is deliberately discarded: the out-of-band prober does not
    /// emit the trip counter, which is reserved for the organic request path.
    pub fn record_probe_failure_all(
        &self,
        destination: DestinationId,
        now: u64,
        now_nanos: u128,
        resolve_cfg: &dyn Fn(&str) -> BreakerCfg,
        retry_after: Option<u64>,
    ) {
        // The mirror of the success fan-out: one destination-global failure per PROBE.
        self.counters(destination)
            .err
            .fetch_add(1, Ordering::Relaxed);
        for (pool, cell) in self.cells_for(destination) {
            let cfg = resolve_cfg(&pool);
            let _ = cell.record_failure(
                now,
                now_nanos,
                &cfg,
                retry_after,
                self.max_honored_retry_after_secs,
            );
        }
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
        self.try_admit_gated(pool, destination, now, || Some(()))
            .map(|(admit, ())| admit)
    }

    /// [`Self::try_admit`] with the caller's CONCURRENCY PERMIT taken before the probe CAS.
    ///
    /// `acquire` is the caller's own permit source — this unit owns no semaphore and takes no
    /// runtime dependency to hold one — and the permit it yields is handed straight back, so the
    /// caller holds the slot for exactly as long as it holds the admission. `None` means the
    /// destination is saturated.
    ///
    /// The ORDER is the whole point, and it is 1.5.5's
    /// (`busbar-core/src/store/in_memory/availability.rs:277-287`, whose comment names the
    /// regression it fixed). A cell whose Open cooldown has expired is probe-winnable; if it is also
    /// at capacity, taking the probe first wins the single-flight recovery and then immediately
    /// reverts it when no permit can be had — every attempt, forever — so a tripped-and-saturated
    /// destination never observes a real dispatch outcome and never recovers. Peeking capacity FIRST
    /// returns `AtCapacity` without ever touching the probe, so the probe is preserved for the
    /// moment a permit is actually available. On a Closed-ready cell the CAS is a pure no-op, so the
    /// earlier acquisition is byte-for-byte identical to the breaker-first order; and a permit taken
    /// for an admission the CAS then refuses is dropped rather than held, because a slot nothing
    /// will dispatch to is a slot taken from a caller who would have.
    pub fn try_admit_gated<P>(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        acquire: impl FnOnce() -> Option<P>,
    ) -> Result<(Admit, P), LaneState> {
        // The destination-global gates, read SEPARATELY, exactly as 1.5.5 reads them: an
        // administratively-dead destination is not a budget fact and neither is a breaker fact.
        if self.is_dead(destination) {
            return Err(LaneState::Dead);
        }
        if self.budget_exhausted(destination) {
            return Err(LaneState::BudgetExhausted);
        }
        let cell = self.cell(pool, destination);
        // The SINGLE verdict decoder, consumed BEFORE the mutating CAS below, so the failure
        // taxonomy is decided without re-deriving "is the breaker open".
        match cell.verdict(now) {
            BreakerVerdict::Open { until } => return Err(LaneState::Suppressed { until }),
            BreakerVerdict::HalfOpen => return Err(LaneState::ProbeInFlight),
            BreakerVerdict::Ready | BreakerVerdict::ProbeWinnable => {}
        }
        let Some(permit) = acquire() else {
            return Err(LaneState::AtCapacity {
                drain_hint_ms: None,
            });
        };
        match cell.acquire(now) {
            // The refusal's own reason, not a second look at a cell a peer may have moved: a
            // caller is entitled to read a refusal as "this would not have admitted".
            ProbeAdmit::Denied(DeniedBy::Cooling { until }) => {
                drop(permit);
                Err(LaneState::Suppressed { until })
            }
            ProbeAdmit::Denied(DeniedBy::ProbeInFlight) => {
                drop(permit);
                Err(LaneState::ProbeInFlight)
            }
            ProbeAdmit::ReadyNoProbe => Ok((Admit { probe_epoch: None }, permit)),
            ProbeAdmit::ProbeWon(epoch) => {
                self.journal.record(ProbeEvent::Won {
                    pool: pool.to_string(),
                    destination,
                    epoch,
                    now,
                });
                Ok((
                    Admit {
                        probe_epoch: Some(epoch),
                    },
                    permit,
                ))
            }
        }
    }

    /// The QUEUE path's admission: re-check the breaker and win the single-flight probe, but take
    /// NO permit — a caller parked on the destination's own semaphore already holds one. 1.5.5's
    /// `try_admit_breaker` (`availability.rs:324-359`).
    ///
    /// The re-check is load-bearing and is the reason this verb exists at all: the breaker may have
    /// tripped, or a peer may have taken the probe, while the caller was queued, and this is what
    /// stops the queue ever dispatching onto a now-Open destination. `Some(epoch)` transfers probe
    /// ownership to the caller under the same owner-checked release discipline
    /// [`Self::try_admit`] uses; `None` is a plain Closed-ready admit that owns nothing.
    pub fn try_admit_breaker(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Option<u64>, LaneState> {
        self.try_admit(pool, destination, now)
            .map(|admit| admit.probe_epoch)
    }

    /// Park ONE `(pool, destination)` cell Open until `cooldown_until` — 1.5.5's `force_open_in`
    /// (`busbar-substrate/src/store.rs:620`), the admin/deadline verb that benches a member without
    /// walking the state machine to the bench.
    ///
    /// Per cell, and deliberately not the destination-wide fan-out: `force_open_in` is an operator
    /// or deadline benching ONE route, where a hard-down is a fact about the shared upstream. The
    /// two reach different sets and the difference is the point — a per-cell trip that fanned out
    /// would bench routes nobody asked to bench.
    pub fn force_open(&self, pool: &str, destination: DestinationId, cooldown_until: u64) {
        let _ = self.cell(pool, destination).open_until(cooldown_until);
    }

    /// Declare a destination administratively DOWN, or bring it back. An operator's declaration,
    /// replaced wholesale on a config apply exactly as [`Self::set_budget`] and
    /// [`Self::set_error_map`] are — never a thing the state machine decides for itself, which is
    /// why a hard-down is a sticky cooldown and NOT this (1.5.5:
    /// "hard-down is RECOVERABLE ... do NOT set `dead` (that would block recovery)").
    pub fn set_dead(&self, destination: DestinationId, dead: bool) {
        self.dead
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(destination, dead);
    }

    fn is_dead(&self, destination: DestinationId) -> bool {
        self.dead
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&destination)
            .copied()
            .unwrap_or(false)
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

    /// The at-capacity terminal's `Retry-After`: the SOONEST genuine (`> 0`) cooldown
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
    #[allow(clippy::too_many_arguments)]
    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        cfg: &BreakerCfg,
        now: u64,
        now_nanos: u128,
        _token: &UnitToken<Route>,
    ) -> bool {
        match outcome {
            // Deliberately touches no counter: a client fault is counted through
            // `record_client_fault`, which the caller reaches directly because only the caller can
            // tell a client fault from a context-length answer, and 1.5.5 counts the one not the
            // other.
            Outcome::RecordNothing => false,
            Outcome::HardDown => self.hard_down_all(destination, now),
            Outcome::Success => {
                let cell = self.cell(pool, destination);
                // Gated on what the call REPORTS, exactly as the Transient arm below is. The
                // recovery CAS can only succeed from HalfOpen, so `closed` IS the proof that this
                // call closed a probing cell. Reading the state beforehand instead lost the other
                // direction of the same race: a peer winning the probe between the read and the
                // CAS left this call closing a HalfOpen cell while believing it had been Closed,
                // and the won probe got no terminal record at all.
                let closed = cell.record_success(now);
                self.counters(destination)
                    .ok
                    .fetch_add(1, Ordering::Relaxed);
                if closed {
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
                let effect = cell.record_failure(
                    now,
                    now_nanos,
                    cfg,
                    retry_after,
                    self.max_honored_retry_after_secs,
                );
                // ONE bump per recorded failure, whichever cell it landed in. 1.5.5 reaches the
                // same count by two routes — the default cell IS the lane, so its own `err` is the
                // lane's, and a named pool's cell has its own — and the guard at
                // `store/in_memory/mod.rs:797` exists so the default path is not counted twice.
                let counters = self.counters(destination);
                counters.err.fetch_add(1, Ordering::Relaxed);
                if effect.tripped() {
                    counters.trip(now);
                }
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
        // The destination-global gates, read SEPARATELY and in 1.5.5's own order.
        if self.is_dead(destination) {
            return LaneState::Dead;
        }
        if self.budget_exhausted(destination) {
            return LaneState::BudgetExhausted;
        }
        lane_state_from_verdict(self.cell(pool, destination).verdict(now))
    }
}

#[cfg(test)]
mod tests;

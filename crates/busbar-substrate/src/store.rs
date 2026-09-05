// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral LANE-AVAILABILITY taxonomy. `Unavailable` is the ONE vocabulary every consumer speaks
//! — selection (exclude), least_bad (rank), `Retry-After` (hint), `/stats` + `/metrics` (render),
//! failover (`Refusal::NoneAdmissible`). Relocated here in Phase-B B1 with `failover::walk_with`, the
//! neutral walk that carries it; the rest of `store` (the breaker cells, `LaneRuntime`) stays in
//! core, which re-exports this taxonomy so `crate::store::Unavailable` resolves unchanged.
//!
//! The two consumer-facing recovery FLOORS (`SHED_RETRY_FLOOR_MS`, `AT_CAPACITY_RECOVERY_FLOOR_MS`)
//! are `pub` because a core consumer derives its whole-second `Retry-After` from each; the probe
//! floor moved with its only reader (`recovery_hint_ms`) and stays private.

// ── Lane availability taxonomy ──────────────────────────────────────────────────────────────────
//
// The advisory recovery FLOORS below are consumed ONLY by `Unavailable::recovery_hint_ms`, the single
// definition of "when could this lane plausibly be usable again". They are floors — honest lower
// bounds — not fabricated exact times.

/// Advisory recovery floor for a lost single-flight probe race: the peer's probe resolves the cell
/// within roughly one request, so "come back very shortly". Advisory only (not yet wired to the
/// production `Retry-After`, which is repointed at `recovery_hint_ms` in a later phase).
const PROBE_RETRY_FLOOR_MS: u64 = 250;

/// Advisory recovery floor for an inbound-shed request (`limits.max_inbound_concurrent`). Advisory
/// only until the observability phase renders it.
///
/// `pub(crate)` so the inbound-admission `Retry-After` DERIVES its whole-second value from this one
/// source rather than hardcoding a bare `"1"` beside it — the same coupling
/// [`AT_CAPACITY_RECOVERY_FLOOR_MS`] gives the proxy's at-capacity `Retry-After`. The store must not
/// depend on `limits`, so the derivation lives at the consumer (`limits::admission`), reading this
/// const, never the reverse.
pub const SHED_RETRY_FLOOR_MS: u64 = 1000;

/// At-capacity recovery FLOOR in milliseconds. A busy concurrency slot has no scheduled recovery
/// the way a breaker `until` does, so absent a per-lane drain estimate this floor is the honest "back
/// off ~2s" answer (never the deceptive `1`). This is the NEUTRAL store-side source of truth for the
/// 2s floor: the store must not depend on `proxy`, so the proxy `Retry-After` path
/// (`proxy::…::AT_CAPACITY_RETRY_AFTER_SECS`) DERIVES its whole-second floor from THIS const rather
/// than the reverse.
pub const AT_CAPACITY_RECOVERY_FLOOR_MS: u64 = 2_000;

/// Why a lane cannot accept a request right now — the ONE taxonomy every consumer speaks: selection
/// (exclude), least_bad (rank), `Retry-After` (hint), `/stats` + `/metrics` (render), queue (wait).
/// Add a future reason (e.g. `RateLimited { until }`) in ONE place and every consumer inherits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// Administratively down. Does not self-recover (until config change).
    Dead,
    /// Lifetime request budget (`max_requests`) spent. Does not self-recover.
    BudgetExhausted,
    /// Circuit breaker Open (or a Closed cell still inside a pending soft cooldown). `until` is EXACT
    /// (epoch secs) — recovery time is known, not estimated.
    BreakerOpen { until: u64 },
    /// Lost the HalfOpen single-flight probe race to a peer. Transient; the peer's probe resolves the
    /// cell within one request. Recovery is "next tick", carried as [`PROBE_RETRY_FLOOR_MS`].
    ProbeInFlight,
    /// All concurrency permits held. `drain_hint_ms` is an ESTIMATE, NOT exact —
    /// capacity has no scheduled recovery the way a breaker does. `None` when there is no basis to
    /// estimate, in which case `recovery_hint_ms` falls back to [`AT_CAPACITY_RECOVERY_FLOOR_MS`].
    AtCapacity { drain_hint_ms: Option<u64> },
    /// Inbound backpressure shed this request before lane selection (`limits.max_inbound_concurrent`).
    //
    // Constructed only by the observability/shed wiring landed in a later phase; the variant is part
    // of the taxonomy vocabulary now (and exercised by the unit tests). `#[cfg(test)]`-scoped
    // construction means the release build has no constructor yet, so silence the lint there only.
    #[cfg_attr(not(test), allow(dead_code))]
    Shedding,
}

impl Unavailable {
    /// Single definition of "when could this lane plausibly be usable again", in ms from `now`. This
    /// is what `Retry-After`, least_bad ranking, and queue budgeting ALL consume — one function, so
    /// those consumers can never disagree about recovery timing. It is ALSO the source of the
    /// `/stats` `recovery_hint_ms` field and the `busbar_lane_recovery_hint_ms` gauge.
    pub fn recovery_hint_ms(&self, now: u64) -> Option<u64> {
        match self {
            Unavailable::Dead | Unavailable::BudgetExhausted => None, // no self-recovery
            Unavailable::BreakerOpen { until } => {
                Some(until.saturating_sub(now).saturating_mul(1000))
            }
            Unavailable::ProbeInFlight => Some(PROBE_RETRY_FLOOR_MS), // ~one request
            // Honest floor when there is no drain estimate — never regress this below 2s.
            Unavailable::AtCapacity { drain_hint_ms } => {
                Some(drain_hint_ms.unwrap_or(AT_CAPACITY_RECOVERY_FLOOR_MS))
            }
            Unavailable::Shedding => Some(SHED_RETRY_FLOOR_MS),
        }
    }

    /// The stable, snake_case name of this variant — the SINGLE rendering used by both `/stats`
    /// (`availability` field) and any operator-facing surface, so the string an operator reads is
    /// derived from the same taxonomy routing dispatches on. The `Ok` side of a
    /// classification renders as the sentinel `"available"`, owned by the caller.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Unavailable::Dead => "dead",
            Unavailable::BudgetExhausted => "budget_exhausted",
            Unavailable::BreakerOpen { .. } => "breaker_open",
            Unavailable::ProbeInFlight => "probe_in_flight",
            Unavailable::AtCapacity { .. } => "at_capacity",
            Unavailable::Shedding => "shedding",
        }
    }
}

/// Breaker state for a lane per ADR-0002.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open { until: u64 },
    HalfOpen,
}

/// The MCP plane's breaker-cell key for one registered tool server: the `tool:` prefix is the
/// plane-qualified keyspace rule (LLM pools keep bare names, so a `tool_pools:` can never collide
/// with an LLM pool, and `tool:`/`agent:` cannot collide with each other), the id is the operator's
/// registration id which is what every refusal names. Lives here (not only on core's `PlaneBreakers`)
/// so the MCP plane builds the key without reaching into `busbar-core`; core's `PlaneBreakers::tool_key`
/// delegates to it so the ONE spelling of the prefix stays single-sourced.
#[cfg_attr(not(feature = "dispatch"), allow(dead_code))]
pub fn tool_key(server: &str) -> String {
    format!("tool:{server}")
}

/// The A2A plane's breaker-cell key for one registered agent: the `agent:` prefix is the
/// plane-qualified keyspace rule (LLM pools keep bare names, so an `agent_pools:` can never collide
/// with an LLM pool, and `tool:`/`agent:` cannot collide with each other), the id is the operator's
/// registration id which is what every refusal names. Lives here (not only on core's `PlaneBreakers`)
/// so the A2A plane builds the key without reaching into `busbar-core`; core's `PlaneBreakers::agent_key`
/// delegates to it so the ONE spelling of the prefix stays single-sourced.
#[cfg_attr(not(feature = "relay"), allow(dead_code))]
pub fn agent_key(agent: &str) -> String {
    format!("agent:{agent}")
}

/// THE WALL CLOCK, re-exported at its historical path. THE CUT: the rest of this module names
/// `tokio::sync` — the lane-availability taxonomy's semaphore-permit arm and the `lane_semaphore`
/// accessor — while `now`/`now_ms` are a pure `SystemTime` read that a dialect writer calls on the
/// response path (an omitted `created` timestamp). So the clock crossed into the values crate and
/// the semaphore-shaped remainder stayed here; `busbar_substrate::store::now` resolves unchanged.
pub use busbar_substrate_values::store::{now, now_ms};

// ── The FNV-1a 64-bit string hash, relocated DOWN from `busbar-core`'s `store` so a plane crate
//    (SWRR shard selection, session affinity) hashes without reaching into `busbar-core`; core's
//    `store` re-exports the fn AND the two constants (its breaker seed-mixer names them directly).
/// FNV-1a offset basis (64-bit). Algorithm-fixed constant.
pub const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a prime (64-bit). Algorithm-fixed constant.
pub const FNV1A_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Deterministic FNV-1a 64-bit hash of a string's bytes. Stable across processes/restarts (unlike
/// the std `DefaultHasher`, whose seed is randomized), so callers that need a process-independent
/// hash (SWRR shard selection, session affinity) get identical results everywhere. Distribution,
/// not cryptographic strength, is all that matters.
pub fn fnv1a_u64(s: &str) -> u64 {
    let mut hash = FNV1A_OFFSET_BASIS;
    for &byte in s.as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV1A_PRIME);
    }
    hash
}

/// RAII concurrency permit, held for the request's lifetime and released on drop.
///
/// A lane with `max_concurrent` SET holds a real slot on its semaphore (`Bounded`) — the cap is
/// enforced exactly, at any configured value. A lane with `max_concurrent` OMITTED is unbounded:
/// there is nothing to enforce, so nothing is counted — `Unbounded` touches no shared state at all.
///
/// Neutral (pure `tokio::sync` + no config/serde coupling), so it lives HERE in the substrate: the
/// LLM plane's `walk` mints `Permit::Bounded(owned)` and core's `LaneRuntime::try_admit` returns it,
/// both naming the ONE type without the plane reaching into `busbar-core`. Core's `store` re-exports
/// it at its historical `crate::store::Permit` path.
#[must_use]
pub enum Permit {
    // The permit is never READ — it exists to be HELD (its Drop returns the slot).
    Bounded(#[allow(dead_code)] tokio::sync::OwnedSemaphorePermit),
    Unbounded,
}

// ── The RESOLVED runtime breaker configuration the FSM evaluates. Neutral DATA (no serde, no config
//    grammar attached — the serialized `config::BreakerCfg` grammar and the config->runtime lowering
//    stay in core). Relocated DOWN here so the LLM plane names the breaker cfg in its money-path
//    signatures and reconstructs it via `from_llm` without reaching into `busbar-core`; core's `store`
//    re-exports `BreakerCfg`/`TripConfig`/`TripMode` at their historical `crate::store::*` paths (the
//    breaker FSM, `appbuild`, and the store tests are untouched), and core owns the
//    `config::BreakerCfg -> BreakerCfg` lowering as an inherent `to_runtime` method.

/// Trip configuration mode.
#[derive(Debug, Clone)]
pub enum TripMode {
    ErrorRate,
    Consecutive,
}

/// Trip configuration parameters (ADR-0002 defaults).
#[derive(Debug, Clone)]
pub struct TripConfig {
    pub mode: TripMode,
    pub window_s: u64,
    pub threshold: f64,
    pub min_requests: usize,
    pub consecutive_n: u32, // For consecutive mode
}

impl Default for TripConfig {
    fn default() -> Self {
        Self {
            mode: TripMode::ErrorRate,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 3, // 3 consecutive errors
        }
    }
}

/// Breaker configuration per pool.
#[derive(Debug, Clone)]
pub struct BreakerCfg {
    pub base_cooldown_secs: u64,
    pub max_cooldown_secs: u64,
    pub honor_retry_after: bool,
    pub trip: TripConfig,
    /// Whether a transient failure that did NOT breach the trip threshold still benches the cell
    /// for a cooldown. See ADR-0002 / `docs/circuit-breaker.md`: `true` on a walked (LLM) pool with
    /// siblings, `false` on a degenerate single-member cell (MCP client leg / A2A relay) that would
    /// otherwise refuse every caller after one blip.
    pub bench_below_trip_threshold: bool,
}

impl Default for BreakerCfg {
    fn default() -> Self {
        Self {
            base_cooldown_secs: 15,
            max_cooldown_secs: 120,
            honor_retry_after: true, // default to honoring Retry-After header
            trip: TripConfig::default(),
            // The LLM plane's pools, which is what every `Default` here builds, DO fail over.
            bench_below_trip_threshold: true,
        }
    }
}

impl BreakerCfg {
    /// Flatten this RESOLVED runtime breaker cfg into the neutral carrier the LLM plane's
    /// `build_runtime` reconstructs from (money-path Phase 3-4 C). Lossless over every field the FSM
    /// reads. `honor_retry_after`/`bench_below_trip_threshold` are always `true` on the LLM path,
    /// carried anyway so a future divergence cannot silently drop.
    pub fn to_llm(&self) -> crate::plane_host::BreakerInput {
        crate::plane_host::BreakerInput {
            base_cooldown_secs: self.base_cooldown_secs,
            max_cooldown_secs: self.max_cooldown_secs,
            honor_retry_after: self.honor_retry_after,
            bench_below_trip_threshold: self.bench_below_trip_threshold,
            trip: crate::plane_host::TripInput {
                mode: match self.trip.mode {
                    TripMode::ErrorRate => crate::plane_host::TripModeInput::ErrorRate,
                    TripMode::Consecutive => crate::plane_host::TripModeInput::Consecutive,
                },
                window_s: self.trip.window_s,
                threshold: self.trip.threshold,
                min_requests: self.trip.min_requests,
                consecutive_n: self.trip.consecutive_n,
            },
        }
    }

    /// Reconstruct the runtime breaker cfg from the neutral carrier — the inverse of [`to_llm`],
    /// called IN-PLANE by the LLM plane's `build_runtime` (the allowed plane->core edge; the plane
    /// names only this pub constructor and the neutral input type).
    ///
    /// [`to_llm`]: Self::to_llm
    pub fn from_llm(i: &crate::plane_host::BreakerInput) -> Self {
        Self {
            base_cooldown_secs: i.base_cooldown_secs,
            max_cooldown_secs: i.max_cooldown_secs,
            honor_retry_after: i.honor_retry_after,
            bench_below_trip_threshold: i.bench_below_trip_threshold,
            trip: TripConfig {
                mode: match i.trip.mode {
                    crate::plane_host::TripModeInput::ErrorRate => TripMode::ErrorRate,
                    crate::plane_host::TripModeInput::Consecutive => TripMode::Consecutive,
                },
                window_s: i.trip.window_s,
                threshold: i.trip.threshold,
                min_requests: i.trip.min_requests,
                consecutive_n: i.trip.consecutive_n,
            },
        }
    }
}

// ── App-retype WEDGE 1 (1.6.0): the `LaneRuntime` type family relocated DOWN from `busbar-core`'s
//    `store` so the LLM plane names the lane-runtime seam via the ABI instead of reaching back into
//    `busbar_core::store::LaneRuntime`. `Admit`/`LaneSnapshot`/`LaneHealthSnapshot`(+its per-pool
//    `PoolCellHealthSnapshot`) travel with the trait because its method signatures name them; every
//    other type they name (`Permit`/`BreakerState`/`Unavailable`/`BreakerCfg`) already lives here.
//    Core re-exports each at its historical `crate::store::…` path so the in-memory breaker engine's
//    `impl LaneRuntime for HealthState`, `/stats`, the `/metrics` scrape, and the export/restore path
//    are all UNCHANGED. By-identity relocation only — no behavior, serde, or representation change:
//    the two snapshots keep their derives + `#[serde(default)]` attrs VERBATIM so the persisted form
//    is byte-identical. The snapshot fields were `pub(crate)` in core (read/constructed only by the
//    core in-memory store's `export_health`/`restore_health_impl`); they become `pub` here — a plain
//    serde DTO carries no internal invariant to protect, matching `LaneSnapshot`'s already-`pub`
//    fields — so core's struct-literal construction and field reads keep working across the crate line.

/// The held resources a successful [`LaneRuntime::try_admit`] transfers to the caller: the concurrency
/// permit (held for the request's lifetime) and the single-flight probe owner token (`probe_epoch`),
/// which the dispatched request later releases via `release_probe_owned_in` once it records an
/// outcome. Ownership of the probe transfers OUT of `try_admit` on success; on failure `try_admit`
/// releases it internally (exactly, owner-checked), so no `Admit` ever leaks a probe.
///
/// `probe_epoch` is `Some(epoch)` ONLY when this admission actually WON a single-flight recovery
/// probe (an expired-Open cell driven Open→HalfOpen). A Closed-and-ready admission wins no probe and
/// carries `None`: the dispatch path then builds NO `ProbeGuard`, so it can never revert a probe a
/// peer legitimately won on the same cell (see `ProbeAdmit`).
pub struct Admit {
    pub permit: Permit,
    pub probe_epoch: Option<u64>,
}

/// Snapshot of lane stats for /stats endpoint.
#[derive(Debug, Clone)]
pub struct LaneSnapshot {
    pub model: String,
    pub provider: String,
    pub max_concurrent: usize,
    pub inflight: i64,
    pub free_slots: usize,
    /// Available concurrency permits for a BOUNDED lane (`Some(n)`); `None` for an unbounded lane
    /// (`max_concurrent` omitted — nothing is counted). Distinct from `free_slots` only in that it
    /// makes "unbounded" explicit rather than reporting an effectively-infinite number: a saturated
    /// lane must be externally distinguishable — `Some(0)` — from an idle or unbounded one.
    pub available: Option<usize>,
    /// True iff this lane is BOUNDED and has zero available permits — i.e. at its `max_concurrent`
    /// limit. Post the at-capacity-exhaustion fix, such a lane sheds/spills rather than queueing, so
    /// this flag is the external signal that a pool is oversubscribed (not merely slow). This is the
    /// CAPACITY axis, deliberately kept INDEPENDENT of `availability`/`breaker_state`: a lane can
    /// be both breaker-Open AND at-capacity, and an operator must see both facts to understand why an
    /// Open lane's breaker never recovers (its recovery probe needs a dispatch it can never win).
    pub at_capacity: bool,
    /// Lane-GLOBAL availability over the shared [`Unavailable`] taxonomy: the SAME
    /// classification `classify`/routing speaks, aggregated across the cells production routes through.
    /// `Ok(())` = the lane would admit; `Err(_)` carries the reason (and its `recovery_hint_ms`). This
    /// is the ONE source `/stats` and (per-pool) `/metrics` render from, so observability cannot drift
    /// from behaviour. Breaker-first: an Open-and-at-capacity lane classifies `BreakerOpen`, while the
    /// orthogonal `at_capacity`/`breaker_state` fields still expose each axis independently.
    pub availability: Result<(), Unavailable>,
    /// Lane-GLOBAL aggregate breaker FSM state (best-case across the routed cells, matching `usable`),
    /// surfaced as its own field so the BREAKER axis is legible independently of `availability` and
    /// `at_capacity`. An expired-Open cell still reports `Open` here even though it would win a
    /// recovery probe (so `availability` may read `at_capacity` while this reads `open`) — that pairing
    /// is exactly the Open+AtCapacity operators need to see.
    pub breaker_state: BreakerState,
    pub ok: u64,
    pub err: u64,
    pub client_fault: u64,
    pub usable: bool,
    pub dead: bool,
    pub dead_reason: String,
    pub cooldown_remaining_s: u64,
    pub streak: u32,
    pub budget: i64,
    /// Monotonic Closed→Open trip count + the most recent trip's epoch (0 = never) — the
    /// poll-safe "did a trip happen since I last looked" signal.
    pub trips: u64,
    pub last_trip_at: u64,
}

/// One lane's PORTABLE health state, keyed by its STABLE IDENTITY (model + provider) instead of
/// its array position. This is the carrier that lets learned reliability state survive the
/// two events that invalidate positional indexing: a config APPLY that changes the lane set (the
/// new store is built with the surviving lanes' snapshots restored), and — via serde, for the
/// persistence follow-up — a RESTART. Ephemeral state is deliberately NOT carried: semaphores /
/// in-flight counts (empty by definition in a fresh store), the single-flight probe flag (reset —
/// an in-flight probe records into the OLD store snapshot it was dispatched under), SWRR fairness
/// counters (positional by nature; reset is harmless), and the rolling outcome windows (strictly
/// time-windowed — they refill within seconds and carrying them would import stale samples).
// Bin-target consumer is the config-apply core (next slice); tests exercise it now.
#[allow(dead_code)]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LaneHealthSnapshot {
    pub model: String,
    pub provider: String,
    /// Remaining lifetime request budget (`-1` = unlimited).
    pub budget: i64,
    /// Default-cell breaker: FSM state, cooldown deadline (unix secs), consecutive-error streak.
    pub breaker_state: u64,
    pub cooldown_until: u64,
    pub streak: u32,
    /// Lane-global hard-down latch + reason.
    pub dead: bool,
    pub dead_reason: String,
    /// Lifetime counters (feed /stats continuity).
    pub ok: u64,
    pub err: u64,
    pub client_fault: u64,
    /// Latency EWMA (raw f64 bits; 0 = no sample).
    pub latency_ewma_bits: u64,
    /// Monotonic Closed→Open trip count + last-trip epoch (0 = never) — learned reliability, so it
    /// carries across apply/restart like ok/err. `serde(default)` reads pre-1.3 persisted snapshots.
    #[serde(default)]
    pub trips: u64,
    #[serde(default)]
    pub last_trip_at: u64,
    /// Per-(pool) breaker cells for this lane.
    pub cells: Vec<PoolCellHealthSnapshot>,
}

/// One per-pool breaker cell's portable state (the FSM triple; windows/probe/SWRR stay ephemeral).
#[allow(dead_code)]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PoolCellHealthSnapshot {
    pub pool: String,
    pub breaker_state: u64,
    pub cooldown_until: u64,
    pub streak: u32,
    pub err: u64,
}

/// LaneRuntime trait - the seam for lane state access.
/// Operations, NOT field access. `lane: usize` identifies a member.
///
/// The in-memory breaker engine (`busbar_core::store::HealthState`) is the sole implementer; the
/// LLM plane's money path names `&dyn LaneRuntime` here so it drives lane admission/health without
/// reaching into `busbar-core`. Its method signatures name only substrate types
/// (`Permit`/`BreakerCfg`/`Admit`/`LaneSnapshot`/`LaneHealthSnapshot`/`BreakerState`/`Unavailable`),
/// so nothing here is a private interface.
pub trait LaneRuntime: Send + Sync + 'static {
    // ── Health queries ─────────────────────────────────────────────────────────────────────────
    // The bare `lane` methods operate on the lane-default cell (direct/ad-hoc routes, `/stats`);
    // the `_in(pool, …)` variants operate on the per-(pool, lane) breaker cell so a lane shared
    // across pools carries independent Open/Closed status per pool. Lane-global checks (dead /
    // budget) are identical across both — only the breaker FSM is isolated.
    // `usable` (mutating, lane-default cell) is exercised by the unit tests; in release, dispatch
    // goes through `usable_in`/`acquire_for_dispatch_in` and non-dispatching observers use the
    // side-effect-free all-cells `is_ready_any_cell` (so /healthz and /stats can't steal a recovery
    // probe), leaving the bare form test-only — so it is `#[cfg(test)]`-gated out of the release
    // binary entirely rather than merely silenced.
    #[cfg(any(test, feature = "test-support"))]
    fn usable(&self, lane: usize, now: u64) -> bool;
    // As of the lane-availability refactor, `pick_among`'s sticky fast path uses `try_admit` instead
    // of `usable_in`, so this has no non-test caller left; retained as a tested primitive.
    #[cfg_attr(not(test), allow(dead_code))]
    fn usable_in(&self, pool: &str, lane: usize, now: u64) -> bool;
    /// Side-effect-FREE readiness check: would this lane admit a request right now, WITHOUT
    /// transitioning an expired-Open lane to HalfOpen or CAS-acquiring its single-flight probe. The
    /// bare-lane (pool `""`) form covers ONLY the default cell — `/healthz` now uses the all-cells
    /// `is_ready_any_cell` instead (production routes through NAMED pools whose cells trip
    /// independently), leaving this default-cell-only form exercised by the unit tests, so it is
    /// `#[cfg(test)]`-gated out of the release binary entirely.
    #[cfg(any(test, feature = "test-support"))]
    fn is_ready(&self, lane: usize, now: u64) -> bool;
    /// Side-effect-FREE readiness across ANY cell: true iff the lane is admissible (not dead / in
    /// budget) AND the default cell OR ANY per-pool cell would admit a request right now. `/healthz`
    /// must use this, not the default-cell-only `is_ready`: production traffic routes through NAMED
    /// pools whose cells trip independently, so a lane whose every per-pool cell is Open is NOT
    /// serviceable even though its default `""` cell (which pool-routed traffic never touches) reads
    /// ready — and `/healthz` would otherwise return 200 while every pool lane is circuit-broken.
    fn is_ready_any_cell(&self, lane: usize, now: u64) -> bool;
    /// Side-effect-FREE, POOL-AWARE readiness: would this lane admit a request right now in THIS
    /// pool's breaker cell, WITHOUT the Open→HalfOpen transition or single-flight probe CAS that
    /// `usable_in` performs. This is the EXACT predicate `select_weighted_in` uses to filter its
    /// healthy candidate set (lane-admissible + `cell_ready_breaker`), exposed for the routing-policy
    /// ordered walk so it filters the policy's ranked order by health identically to SWRR — the walk
    /// only ORDERS; the unchanged `acquire_for_dispatch_in` (called once on the chosen lane) still
    /// owns the HalfOpen probe race. Using `usable_in` here instead would steal recovery probes for
    /// every ranked lane the walk merely peeks at.
    // ROUTING-POLICY SIGNAL ACCESSORS: read per-request by `proxy::decide_policy_order` (and
    // `pick_among` for `ready_in`) to build the `Candidate` projection the resolved policy ranks on.
    fn ready_in(&self, pool: &str, lane: usize, now: u64) -> bool;
    /// PRODUCTION-SAFE, side-effect-free breaker FSM state for a (pool, lane), for the
    /// `Signal::CandidateBreakerState` catalog entry. Unlike `breaker_state`/
    /// `breaker_state_in` above (both `#[cfg(test)]`-gated OUT of the release binary — see their
    /// doc comment), this is a PURE projection of the already-maintained atomic breaker state,
    /// released for real traffic: it performs no Open→HalfOpen transition and steals no recovery
    /// probe (mirrors `is_ready_any_cell`/`cell_ready_breaker`'s non-mutating read discipline).
    /// Zero new tracking — the breaker FSM already maintains this state on every request
    /// regardless of whether any consumer declares the signal; only the READ is gated by
    /// `RequestedSignals::wants(Signal::CandidateBreakerState)` at the call site.
    fn breaker_state_snapshot_in(&self, pool: &str, lane: usize) -> BreakerState;
    /// PRODUCTION-SAFE recent error rate (errors / total outcomes) for a (pool, lane) over the
    /// breaker's existing sliding outcome window — for the `Signal::CandidateErrorRate`
    /// catalog entry. `None` when the lane has served no outcomes in the window yet
    /// (never a fabricated `0.0`, which would misread as "definitely healthy"). PURE PROJECTION:
    /// the outcome window is the SAME state the breaker's error-rate trip mode already maintains
    /// on every outcome regardless of whether any consumer declares this signal (see
    /// `store::in_memory::breaker::OutcomeWindow`) — no new collection, only the read is gated.
    fn error_rate_in(&self, pool: &str, lane: usize, now: u64) -> Option<f64>;
    /// Available (free) concurrency permits on a lane's semaphore right now — a routing-policy signal
    /// (`least_busy`). Read-only snapshot; racy by nature (permits change between read and dispatch),
    /// which is fine for a ranking hint.
    fn available_permits(&self, lane: usize) -> usize;
    /// Per-lane lifetime request budget remaining (`None` = unlimited / unmetered). A routing-policy
    /// signal (`usage`) read cheaply from the store. Read-only.
    fn lane_budget_remaining(&self, lane: usize) -> Option<i64>;
    /// Lane-global admissibility IGNORING the breaker: false when the lane is marked dead or has
    /// exhausted its `max_requests` budget. Separated from `ready_in` because the `least_bad`
    /// exhaustion mode deliberately overrides an Open breaker — an inference busbar made — but must
    /// never override these two, which are operator declarations. Read-only.
    fn lane_admissible(&self, lane: usize) -> bool;
    /// Rolling EWMA of observed end-to-end latency for this lane, in milliseconds — a routing-policy
    /// signal (`fastest`). `None` until the lane has served at least one request. Read-only, lock-free.
    fn lane_latency_ms(&self, lane: usize) -> Option<f64>;
    /// Fold one observed end-to-end latency SAMPLE (milliseconds) into this lane's rolling EWMA. Called
    /// after a request completes (off the selection hot path). Lock-free, bounded, allocation-free; a
    /// non-finite or non-positive sample is ignored so a bad measurement can never poison the signal.
    /// `pool` is accepted for symmetry with the other `_in` recorders, but latency is lane-global, so
    /// the EWMA is shared across every pool fronting the lane.
    fn record_latency_in(&self, pool: &str, lane: usize, latency_ms: f64);
    /// Mutating admission for a lane selection is about to DISPATCH to: performs the Open→HalfOpen
    /// transition + single-flight probe CAS exactly once. Returns false if the probe was already
    /// taken (lost the race) so the caller can pick another lane.
    ///
    /// `pick_among` now admits via `try_admit`, so `acquire_for_dispatch_in` has no non-test
    /// caller left — but it is deliberately RETAINED (not deleted) as the tested breaker-acquisition
    /// primitive the ~15 probe-race/epoch regression tests drive directly. `try_admit` performs the
    /// equivalent breaker CAS via `cell_acquire_breaker` internally.
    #[cfg_attr(not(test), allow(dead_code))]
    fn acquire_for_dispatch_in(&self, pool: &str, lane: usize, now: u64) -> bool;

    /// READ-ONLY availability classification over the shared [`Unavailable`] taxonomy. Side-effect
    /// free: peeks the breaker (no probe CAS via the single `breaker_verdict` decoder), peeks permits,
    /// and reads `dead`/`budget` SEPARATELY (NOT the bool-collapsing `lane_admissible`) so it can
    /// distinguish `Dead` from `BudgetExhausted`. Returns `Ok(())` if the lane WOULD admit right now
    /// (best-effort; racy by nature — advisory). For observability, least_bad reads, and the queue
    /// pre-check. The `/metrics` scrape renders the per-(pool, lane) availability gauges directly
    /// from this (production-live); least_bad/queue consumers land later.
    fn classify(&self, pool: &str, lane: usize, now: u64) -> Result<(), Unavailable>;

    /// MUTATING admission attempt — a thin COMPOSITION over the SAME `breaker_verdict` decoder
    /// `classify` uses, the existing `acquire_for_dispatch_in`/breaker CAS, and `try_acquire`.
    /// Wins-or-loses the single-flight probe and grabs-or-fails the permit, returning the held
    /// resources ([`Admit`]) on success or the SAME [`Unavailable`] taxonomy on failure. On the
    /// at-capacity path it releases the won-but-undispatched probe EXACTLY (owner-checked) so it never
    /// leaks the single-flight probe and never double-releases. The sole non-test callers are
    /// `pick_among`'s main selection loop and its sticky-affinity fast path.
    fn try_admit(&self, pool: &str, lane: usize, now: u64) -> Result<Admit, Unavailable>;

    /// The concurrency semaphore of a BOUNDED lane, for the `on_exhausted: queue` wait to acquire a
    /// freed permit DIRECTLY on the lane's OWN FIFO semaphore. This is the wait primitive: the
    /// semaphore STORES released permits (no lost wakeup — a permit freed in the window between a
    /// waiter's re-poll and its next await is not dropped) and hands one permit to one waiter (no
    /// thundering herd, FIFO fairness). `None` for an UNBOUNDED lane (`max_concurrent` omitted —
    /// nothing is counted, so it is never `AtCapacity` and never a queue candidate).
    fn lane_semaphore(&self, lane: usize) -> Option<std::sync::Arc<tokio::sync::Semaphore>>;

    /// Run ONLY the breaker admission step of [`try_admit`] (the shared `breaker_verdict` decoder +
    /// the single-flight probe CAS) WITHOUT acquiring a concurrency permit — for the `on_exhausted:
    /// queue` dispatch path, which has ALREADY won a permit directly on the lane's semaphore (via
    /// [`lane_semaphore`](Self::lane_semaphore)) and must still pass the breaker before dispatch.
    /// `Ok(Some(epoch))` = the caller may dispatch AND it won a single-flight probe: it owns that
    /// probe, released OWNER-CHECKED via `release_probe_owned_in(pool, lane, epoch)` after the
    /// dispatched request records its outcome — the SAME `Admit.probe_epoch` discipline `try_admit`
    /// uses, so the queue path no longer relies on the weaker unowned `release_probe_in` (a stale
    /// unowned release could revert a NEWER probe won by a peer). `Ok(None)` = the caller may dispatch
    /// but it won NO probe (a Closed-and-ready no-op admit), so it must build no release guard.
    /// `Err(_)` = the lane went Dead / BudgetExhausted / BreakerOpen / lost the probe WHILE the caller
    /// was queued; the caller must release its held permit and never dispatch onto it. No permit is
    /// touched here, so a probe won on the `Ok(Some)` path is the caller's to release; otherwise
    /// nothing is left armed.
    fn try_admit_breaker(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
    ) -> Result<Option<u64>, Unavailable>;
    /// Release a single-flight recovery probe WON by `acquire_for_dispatch_in` but then NOT dispatched
    /// (the chosen lane couldn't get a concurrency slot before the request deadline, the semaphore
    /// closed on shutdown, etc.). The probe winner left the cell in HalfOpen with `probe_in_flight ==
    /// true`; if it returns without ever recording success/failure, neither `cell_closed` nor
    /// `cell_open` runs, so the flag stays `true` and the cell stays HalfOpen — `usable_for` then
    /// refuses every subsequent request and the lane is benched until the out-of-band prober catches
    /// it (a self-inflicted availability regression on the recovery path). This reverts the cell to
    /// Open WITHOUT escalating the cooldown (treating an undispatched probe winner as a no-op rather
    /// than a consumed probe): it clears `probe_in_flight` and only stores Open when the cell is still
    /// HalfOpen, leaving the existing (already-expired) cooldown intact so the very next request can
    /// re-win the probe. No-op when the cell is no longer HalfOpen (a concurrent success/failure
    /// already transitioned it) or when the probe flag was already clear.
    //
    // No PRODUCTION caller remains: every dispatch path now covers the won probe with a `ProbeGuard`
    // whose drop uses the OWNER-CHECKED `release_probe_owned_in` (the unowned variant here could revert
    // a peer's live probe). Retained for the store regression tests that pin the unowned-release
    // mechanism directly.
    #[cfg_attr(not(test), allow(dead_code))]
    fn release_probe_in(&self, pool: &str, lane: usize);
    /// Read a (pool, lane) cell's current single-flight probe epoch (owner token). A probe winner
    /// captures this immediately after `acquire_for_dispatch_in` succeeds and later passes it to
    /// `release_probe_owned_in` so a STALLED, late release cannot revert a newer probe.
    //
    // `try_admit`/`Admit` now surface the epoch to `pick_among` directly, so the standalone accessor
    // has no non-test caller left; retained for the probe-epoch regression tests.
    #[cfg_attr(not(test), allow(dead_code))]
    fn probe_epoch_in(&self, pool: &str, lane: usize) -> u64;
    /// OWNER-CHECKED variant of `release_probe_in`: reverts the undispatched probe ONLY when the cell's
    /// probe epoch still equals `owned_epoch`. Used by the `ProbeGuard` drop path (the one release site
    /// that can outlive its acquisition across an await, so the one that can be stale). A strict no-op
    /// when the epoch has moved on - the probe we won was already consumed or superseded.
    fn release_probe_owned_in(&self, pool: &str, lane: usize, owned_epoch: u64);
    // The bare lane-default breaker mutators below are exercised by the unit tests; in release,
    // ALL dispatch (including the degraded `forward_once` fallback/least-bad path) now routes through
    // the `_in(pool, …)` variants against the ROUTING POOL cell — recording on the default `""` cell
    // left the pool cell wedged HalfOpen forever — so the bare forms are release-dead. NOTE:
    // `is_ready`, `breaker_state`, `usable`, `record_success`, `record_rate_limit`, `record_hard_down`
    // are all `#[cfg(test)]`-gated out of the release binary entirely rather than merely silenced with
    // a dead-code allow.
    #[cfg(any(test, feature = "test-support"))]
    fn breaker_state(&self, lane: usize) -> BreakerState;
    /// Per-(pool, lane) breaker FSM state — test-only, so regressions can assert the POOL cell (not
    /// just the default `""` cell) transitions correctly on the degraded forward path.
    #[cfg(any(test, feature = "test-support"))]
    fn breaker_state_in(&self, pool: &str, lane: usize) -> BreakerState;
    /// Force a (pool, lane) breaker cell into Open with the given `cooldown_until` — test-only. Set
    /// `cooldown_until` in the PAST for an expired-Open cell, which `acquire_for_dispatch_in`
    /// transitions to HalfOpen (the single-flight recovery probe) on the next dispatch — the exact
    /// state the degraded-forward regression requires on the ROUTING POOL cell.
    #[cfg(any(test, feature = "test-support"))]
    fn force_open_in(&self, pool: &str, lane: usize, cooldown_until: u64);
    // `snapshot()` now reports the lane-GLOBAL (worst-across-all-pool-cells) cooldown via
    // `lane_max_cooldown_remaining`, not the default-cell-only `cooldown_remaining` (which stayed 0
    // for pool-routed traffic), so this bare-lane form is release-dead and exercised only by tests.
    #[cfg(any(test, feature = "test-support"))]
    fn cooldown_remaining(&self, lane: usize, now: u64) -> u64;
    fn cooldown_remaining_in(&self, pool: &str, lane: usize, now: u64) -> u64;
    /// True if the breaker is suppressing this lane in ANY cell (default or any pool) — either a
    /// non-Closed (Open/HalfOpen) state OR a Closed lane with a pending soft cooldown
    /// (`cooldown_until > now`). Gates the health prober: both states make the lane unusable, and a
    /// probe tests the shared upstream, so either should be recovered early.
    fn lane_needs_probe(&self, lane: usize, now: u64) -> bool;

    // ── Outcome recording (the breaker's write path) ─────────────────────────────────────────────
    // `record_success` is now release-dead: the degraded `forward_once` path records against the
    // ROUTING POOL cell via `record_success_in`, so this bare default-cell form is test-only and
    // `#[cfg(test)]`-gated out of the release binary.
    #[cfg(any(test, feature = "test-support"))]
    fn record_success(&self, lane: usize);
    fn record_success_in(&self, pool: &str, lane: usize);
    /// A SUCCESSFUL (2xx) out-of-band health probe: push a success outcome into the sliding
    /// error-rate window of EVERY cell for the lane (the default/direct-route cell AND every existing
    /// per-pool cell), mirroring the all-cells iteration of `record_probe_failure_all_cells`. The
    /// failed-probe path feeds a failure into each cell's window, so without a matching success record
    /// a lane whose probes sometimes fail and sometimes succeed would present a window of ONLY
    /// failures and the error-rate breaker would read 100% error and trip a mostly-healthy lane (the
    /// success half of symmetric probe accounting).
    ///
    /// Crucially the lane-global `LaneState.ok` stat is bumped EXACTLY ONCE per probe — once per
    /// SUCCESSFUL PROBE, not once per cell. Recording per cell via `record_success_in` instead bumped
    /// `LaneState.ok` (N+1) times for a lane in N pools (the default cell plus one per pool), inflating
    /// the public `/stats` `ok` metric. This is the exact mirror of how `record_probe_failure_all_cells`
    /// bumps `LaneState.err` exactly once (only the default cell's `cell_record_failure` touches
    /// `LaneState.err`; the per-pool cells bump their own separate `BreakerCell.err`). Here the
    /// per-cell `cell_record_success` touches no `ok`/`err` counter at all, so the single lane-global
    /// `ok` bump is applied explicitly, once.
    ///
    /// If a per-cell success push wins a HalfOpen→Closed CAS (possible when this push races a peer that
    /// re-armed the cell after the caller's `recover_lane`), the implementation MUST reset that cell's
    /// SWRR accumulator — the matching `reset_swrr_for` bumps the cell's stripe generation so every
    /// worker's stripe rejoins from 0, holding the per-stripe `Σ == 0` invariant. Gating the reset
    /// on the recovered-bool mirrors `record_success_for`/`recover_lane`.
    fn record_probe_success_all_cells(&self, lane: usize);
    fn record_client_fault(&self, lane: usize);
    /// Record a transient upstream failure. `cfg` is the routing pool's resolved breaker config,
    /// which drives the trip decision (error-rate vs consecutive thresholds) and cooldown backoff.
    /// Returns `true` iff this failure drove a Closed→Open trip on the (pool, lane) cell, so the
    /// caller emits `BREAKER_TRIPS_TOTAL` once per logical trip.
    #[cfg(any(test, feature = "test-support"))]
    fn record_transient(
        &self,
        lane: usize,
        what: &str,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool;
    fn record_transient_in(
        &self,
        pool: &str,
        lane: usize,
        what: &str,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool;
    #[cfg(any(test, feature = "test-support"))]
    fn record_rate_limit(
        &self,
        lane: usize,
        now: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool;
    fn record_rate_limit_in(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool;
    // `record_hard_down` is the bare-lane (default-cell) hard-down primitive. The release hard-down
    // paths (the organic forward `HardDown` arm and the health prober's `HardDown` arm) both now go
    // through the all-cells `record_hard_down_all_cells` primitive (which inlines the per-cell trip to
    // avoid re-locking `pool_cells`), so this bare form is exercised only by the unit tests in release
    // — hence the not(test) dead-code allow, matching the other release-dead bare mutators above.
    #[cfg(any(test, feature = "test-support"))]
    fn record_hard_down(&self, lane: usize, reason: &str);
    /// Hard-down the lane in EVERY cell (the default/direct-route cell AND every existing per-pool
    /// cell), mirroring the all-cells reach of `recover_lane` / `record_probe_failure_all_cells`. A
    /// hard-down (auth rejection / billing exhaustion) is a property of the SHARED upstream, not of
    /// one routing pool: a credential billing-suspended for a pool-routed request is equally dead for
    /// the default-cell `named`/`adhoc` routes and every other pool fronting the lane. Tripping only
    /// the routing pool's cell (the old organic-forward behavior) left the same upstream Closed in the
    /// other cells, so legacy/cross-protocol routes kept hammering a known-dead lane until the
    /// out-of-band prober caught it. This is the lane-global sibling of the per-cell
    /// `record_hard_down`/`record_hard_down_in` primitives, used on the organic forward path so any
    /// route through `forward_with_pool` trips the lane in every namespace at once.
    /// Trips every cell for `lane` hard-down. Returns `true` iff this was a genuine fresh trip of the
    /// default cell (it was `ST_CLOSED` before) — so callers can gate `BREAKER_TRIPS_TOTAL` on a
    /// LOGICAL Closed→Open trip and not re-count a persistently-dead lane on every recovery-probe.
    fn record_hard_down_all_cells(&self, lane: usize, reason: &str) -> bool;
    /// A successful out-of-band health probe: recover the lane to Closed in EVERY cell (default and
    /// all pools), since the probe tests the shared upstream. No-op on cells already Closed.
    fn recover_lane(&self, lane: usize);
    /// A FAILED out-of-band health probe: record a transient failure against EVERY cell for the
    /// lane (the default cell AND every existing per-pool cell), mirroring `recover_lane`'s
    /// all-cells iteration. The probe tests the shared upstream, and organic traffic routes against
    /// per-pool cells, so a probe failure that only hit the default cell could never trip the
    /// per-pool breakers real traffic is selected against.
    ///
    /// `resolve_cfg` resolves the breaker config to apply to a given cell BY POOL NAME: it is called
    /// with `""` for the default cell and with each per-pool cell's pool name, so a probe failure
    /// trips/cools each cell against THAT pool's own configured thresholds and backoff —
    /// not a one-size `BreakerCfg::default()` that ignored per-pool trip thresholds and cooldowns.
    /// The resolver falls back to the ADR-0002 default for any pool without its own config.
    /// `retry_after` (server-requested cooldown floor, e.g. a 429 `Retry-After`) is honored when the
    /// resolved cfg's `honor_retry_after` is set, exactly as on the organic failure path.
    fn record_probe_failure_all_cells(
        &self,
        lane: usize,
        what: &str,
        resolve_cfg: &dyn Fn(&str) -> BreakerCfg,
        retry_after: Option<u64>,
    );

    // concurrency + budget — lane-global (shared across every pool fronting the lane).
    fn try_acquire(&self, lane: usize) -> Option<Permit>;
    /// Atomically consume one unit of the lane's lifetime request budget. Returns `false` when the
    /// budget was already exhausted (the spend was a no-op — the budget is never driven negative).
    /// `#[must_use]`: the bool is the over-spend signal; a silent discard hid the prior concurrent
    /// over-spend bug, so call sites that intentionally ignore it must say so with `let _ =`.
    #[must_use]
    fn spend_budget(&self, lane: usize) -> bool; // false => exhausted

    /// Return one previously-spent unit to the lane's lifetime request budget. Used to COMPENSATE a
    /// `spend_budget` that was charged optimistically on the 2xx response HEADERS when the response
    /// body then failed to transfer intact — no usable response was delivered, so the spend must be
    /// reversed or every post-headers transport failure permanently drains the lane's `max_requests`
    /// budget and stealthily removes capacity. A no-op for an unlimited lane. Never raises the budget
    /// above the configured `max_requests` ceiling (a refund is only ever the inverse of a spend).
    fn refund_budget(&self, lane: usize);

    // weighted member selection (SWRR algorithm)
    /// Select a candidate from the given list using smooth weighted round-robin over healthy members.
    /// `candidates` are indices into the store's lane array.
    /// `weights` is the per-member weight for each candidate (must match candidates length).
    /// Returns None if no healthy members or all candidates are unusable.
    #[cfg(any(test, feature = "test-support"))]
    fn select_weighted(&self, candidates: &[usize], weights: &[u32], now: u64) -> Option<usize>;
    fn select_weighted_in(
        &self,
        pool: &str,
        candidates: &[usize],
        weights: &[u32],
        now: u64,
    ) -> Option<usize>;

    // stats snapshot for /stats
    fn snapshot(&self, lane: usize, now: u64) -> LaneSnapshot;

    /// Export every lane's PORTABLE health state, keyed by stable identity — the input to a
    /// state-carrying store rebuild on config apply (RAM→RAM, by identity; `new_with_limits_restored`
    /// consumes it via `restore_health_impl`). Reliability state is NEVER persisted to disk (store-or-
    /// RAM rule): a process restart re-learns it from live traffic, so there is no boot-restore path.
    fn export_health(&self) -> Vec<LaneHealthSnapshot>;
}

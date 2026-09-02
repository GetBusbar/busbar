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

/// Get current time in seconds since epoch. The shared wall clock both core and the plane crates
/// read (the plane via the `clock_now` host seam long-term; this is the single implementation).
pub fn now() -> u64 {
    let _t = busbar_timing::timeit!("store_now");
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The same wall clock in MILLISECONDS — for the two sub-second callers (an operator TTL and the
/// A2A task poll). `u64`, matching [`now`]: a duration since the epoch, never negative.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

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
    pub fn to_llm(&self) -> crate::plane_host::LlmBreakerInput {
        crate::plane_host::LlmBreakerInput {
            base_cooldown_secs: self.base_cooldown_secs,
            max_cooldown_secs: self.max_cooldown_secs,
            honor_retry_after: self.honor_retry_after,
            bench_below_trip_threshold: self.bench_below_trip_threshold,
            trip: crate::plane_host::LlmTripInput {
                mode: match self.trip.mode {
                    TripMode::ErrorRate => crate::plane_host::LlmTripMode::ErrorRate,
                    TripMode::Consecutive => crate::plane_host::LlmTripMode::Consecutive,
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
    pub fn from_llm(i: &crate::plane_host::LlmBreakerInput) -> Self {
        Self {
            base_cooldown_secs: i.base_cooldown_secs,
            max_cooldown_secs: i.max_cooldown_secs,
            honor_retry_after: i.honor_retry_after,
            bench_below_trip_threshold: i.bench_below_trip_threshold,
            trip: TripConfig {
                mode: match i.trip.mode {
                    crate::plane_host::LlmTripMode::ErrorRate => TripMode::ErrorRate,
                    crate::plane_host::LlmTripMode::Consecutive => TripMode::Consecutive,
                },
                window_s: i.trip.window_s,
                threshold: i.trip.threshold,
                min_requests: i.trip.min_requests,
                consecutive_n: i.trip.consecutive_n,
            },
        }
    }
}

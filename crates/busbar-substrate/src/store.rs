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
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
pub fn tool_key(server: &str) -> String {
    format!("tool:{server}")
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
#[cfg_attr(
    not(any(feature = "plane-mcp", feature = "plane-a2a")),
    allow(dead_code)
)]
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

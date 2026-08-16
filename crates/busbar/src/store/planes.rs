// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NON-LLM PLANES' HANDLE ON THE ONE BREAKER — the degenerate single-member cell of
//! the breaker-all-planes audit's closing design, and nothing more.
//!
//! ## What this is and, as loudly, what it is not
//!
//! The MCP client leg and the A2A relay get TRIP + FAST-FAIL against the same breaker FSM the model
//! plane has always used: [`LaneRuntime::try_admit_breaker`] over a [`HealthState`] cell, closed →
//! open on the core thresholds, recovered by the same single-flight half-open probe. There is NO
//! second state machine here — every method below is a thin resolution of a plane-qualified key
//! onto the one cell store, and the FSM transitions all run in `store::in_memory`.
//!
//! This is deliberately NOT failover and NOT pools. `failover::walk`, `tool_pools:` and
//! `agent_pools:` stay exactly where the audit left them: the unification unit mounts the walk;
//! this module is only "the audit's degenerate fast-fail cell", the half the owner called core
//! functionality and the goal's D6 allows on the way ("transitional wiring only where the audit's
//! degenerate fast-fail cell is genuinely cheap"). Accordingly nothing here selects among
//! candidates, and a tripped target is REFUSED, never rerouted.
//!
//! ## The key, per the audit
//!
//! Cells are `(pool, lane)`-keyed strings-plus-index. The pool string is PLANE-QUALIFIED at this
//! boundary — `"tool:<server-id>"` / `"agent:<agent-id>"` — which is the audit's own rule for the
//! keyspace: LLM pools keep bare names, so a `tool_pools: search` can never collide with an LLM
//! `pools: search`, and the two prefixes cannot collide with each other. The lane is ALWAYS 0: a
//! degenerate pool has one member, and its index in the (one-element) member list is 0, exactly the
//! allocation rule the audit fixes for the real pools later ("lane index = the member's position in
//! the pool's ordered `members:` list").
//!
//! ## Why a private single-lane [`HealthState`] rather than the LLM plane's store
//!
//! The cell FSM is `(pool, lane)`-scoped, but the store's LANE-GLOBAL gates (dead, budget,
//! permits) and its all-cells writes (`record_hard_down_all_cells`, `recover_lane`) index
//! `lanes[lane]` — the MODEL lanes. Recording a tool server's 401 into the LLM store at lane 0
//! would trip whatever model happens to occupy index 0, and a deployment with no models at all
//! would panic on the index. So the plane cells live in their own one-lane `HealthState`: same
//! type, same FSM code, same thresholds, zero copies of any transition — and the LLM store is
//! byte-untouched, which is the audit's "existing breaker suite passes unedited" guard. The
//! `HardDown` write goes through the per-cell [`HealthState::record_hard_down_for`], never the
//! all-cells primitive, because on a shared lane index "all cells" would be every OTHER tool server
//! and agent too.

use super::in_memory::{BreakerCfg, HealthState, LaneData};
use super::{LaneRuntime, Unavailable};
use std::sync::Arc;

/// One process-lifetime handle: every registered MCP server's and A2A agent's availability cell.
///
/// Held on [`crate::state::App`] and carried across a config apply the way the LLM store is —
/// learned reliability must survive a snapshot swap, or every apply un-trips every dead upstream.
pub(crate) struct PlaneBreakers {
    /// ONE lane, index 0, never dead, never budgeted, permits never consulted
    /// (`try_admit_breaker` is the queue-shaped admission: breaker only, no permit acquisition).
    /// All per-target state lives in the per-pool cells keyed by the plane-qualified strings.
    health: HealthState,
    /// The core defaults (ADR-0002): error-rate trip over a 30s window, 15s→120s cooldown backoff.
    /// Deliberately NOT operator-tunable per `tools:`/`agents:` — that absence stays until someone
    /// asks, as `docs/circuit-breaker.md` already discloses.
    cfg: BreakerCfg,
}

impl PlaneBreakers {
    pub(crate) fn new() -> Self {
        Self {
            health: HealthState::new(vec![LaneData {
                model: "plane-target".to_string(),
                provider: "plane".to_string(),
                max: 1,
                sem: Arc::new(tokio::sync::Semaphore::new(1)),
                limited: false,
                budget: -1,
                cooldown_until: 0,
                streak: 0,
                dead: false,
                dead_reason: String::new(),
                ok: 0,
                err: 0,
                client_fault: 0,
                upstream_model: None,
                attempt_timeout_ms: None,
                reasoning: false,
                prompt_caching: false,
            }]),
            cfg: BreakerCfg::default(),
        }
    }

    /// The MCP plane's key for one registered tool server. The `tool:` prefix is the audit's
    /// keyspace rule; the id is the operator's registration id, which is what every refusal names.
    pub(crate) fn tool_key(server: &str) -> String {
        format!("tool:{server}")
    }

    /// The A2A plane's key for one registered agent.
    pub(crate) fn agent_key(agent: &str) -> String {
        format!("agent:{agent}")
    }

    /// ADMIT ONE DISPATCH against the target's cell — [`LaneRuntime::try_admit_breaker`], the same
    /// admission the model plane's queue dispatch makes. `Ok` carries the single-flight probe owner
    /// token; the dispatch MUST end in exactly one of `record_success` / `record_signal` /
    /// [`Self::release`] or a won recovery probe is leaked and the cell wedges HalfOpen. Production
    /// call sites use [`Self::admit`], whose RAII token cannot be leaked by a dropped future.
    pub(crate) fn try_admit(&self, key: &str) -> Result<u64, Unavailable> {
        self.health
            .try_admit_breaker(key, 0, HealthState::now_secs())
    }

    /// [`Self::try_admit`] as an RAII token. The owner-checked release runs on DROP, which is the
    /// only shape that survives every way a dispatch can end without recording — a refusal between
    /// admission and the wire, a caller that disconnected (axum drops the handler future), a task
    /// runner aborted by `tasks/cancel`. An explicit release call misses the dropped-future cases,
    /// and a missed release wedges the cell HalfOpen forever.
    pub(crate) fn admit(self: &Arc<Self>, key: &str) -> Result<Admission, Unavailable> {
        let epoch = self.try_admit(key)?;
        Ok(Admission {
            breakers: Arc::clone(self),
            key: key.to_string(),
            epoch,
        })
    }

    /// OWNER-CHECKED release of the probe token [`Self::try_admit`] returned, for a dispatch that
    /// settles. Safe to call unconditionally after the outcome: a recorded success/failure has
    /// already consumed the HalfOpen state, so this is a no-op there and only reverts a probe the
    /// dispatch genuinely abandoned (refused before any leg went out).
    pub(crate) fn release(&self, key: &str, probe_epoch: u64) {
        self.health.release_probe_owned_in(key, 0, probe_epoch);
    }

    /// The wire answered and busbar could serve it. Closes a half-open probe, dilutes the
    /// error-rate window — the success half of the one disposition pipeline.
    pub(crate) fn record_success(&self, key: &str) {
        self.health.record_success_in(key, 0);
    }

    /// RECORD ONE NORMALIZED FAILURE through the ONE classifier ([`crate::breaker::classify`],
    /// Stage 2) onto the target's cell. The plane's own Stage-1 normalizer produced `sig`; this is
    /// the same disposition split `failover::record_outcome` makes, minus the all-cells hard-down
    /// (see the module header: on a shared degenerate lane, "all cells" would be every other
    /// target). Returns the disposition so a caller can log it without re-deciding.
    pub(crate) fn record_signal(
        &self,
        key: &str,
        sig: &crate::breaker::CanonicalSignal,
    ) -> crate::breaker::Disposition {
        let disposition = crate::breaker::classify(sig);
        match disposition {
            crate::breaker::Disposition::ClientFault => self.health.record_client_fault(0),
            crate::breaker::Disposition::TransientUpstream => {
                let tripped = if sig.class == crate::breaker::StatusClass::RateLimit {
                    self.health.record_rate_limit_in(
                        key,
                        0,
                        HealthState::now_secs(),
                        &self.cfg,
                        sig.retry_after,
                    )
                } else {
                    self.health.record_transient_in(
                        key,
                        0,
                        sig.provider_signal.as_deref().unwrap_or("upstream"),
                        &self.cfg,
                        sig.retry_after,
                    )
                };
                // THE OPERATOR'S TRIP SIGNAL, naming the TARGET. The store's own warn names the
                // lane, and every plane target shares the one degenerate lane — so without this
                // line a trip says "plane-target" and the operator learns which server is down
                // from a user. Emitted once per logical Closed→Open trip, never per failure.
                if tripped {
                    tracing::warn!(
                        target_key = key,
                        "plane breaker tripped: the upstream target is failing and further \
                         dispatches will fast-fail until the half-open probe recovers it"
                    );
                }
            }
            crate::breaker::Disposition::HardDown => {
                self.health.record_hard_down_for(
                    key,
                    0,
                    sig.provider_signal.as_deref().unwrap_or("hard_down"),
                );
                tracing::warn!(
                    target_key = key,
                    "plane breaker tripped hard-down: the upstream target answered a definitive \
                     failure (auth/billing); dispatches fast-fail for the sticky cooldown"
                );
            }
            // The target is healthy and the request was wrong for it — record nothing, exactly as
            // the model plane's walk records nothing.
            crate::breaker::Disposition::ContextLength => {}
        }
        disposition
    }

    /// The EXACT remaining cooldown for a tripped target, floored at 1 — the `Retry-After` value,
    /// populated from the cell's own `until` rather than guessed (the shape budget already uses
    /// with `429` + `Retry-After`). The floor covers `ProbeInFlight`, whose honest answer is "next
    /// tick" and whose remaining cooldown reads 0.
    pub(crate) fn retry_after_secs(&self, key: &str) -> u64 {
        self.health
            .cooldown_remaining_in(key, 0, HealthState::now_secs())
            .max(1)
    }

    /// The raw FSM state of one target's cell, for tests and operator surfaces. Pure projection —
    /// no probe CAS.
    #[cfg(test)]
    pub(crate) fn state(&self, key: &str) -> super::BreakerState {
        self.health.breaker_state_snapshot_in(key, 0)
    }

    /// FORCE one target's cell back to Closed with no pending cooldown — a TEST-ONLY bypass of the
    /// outer breaker, for batteries whose subject is an INNER arm this cell would otherwise shadow
    /// (the stdio supervisor's backoff/quarantine, reachable through dispatch only while the core
    /// cell admits). Production has no caller and must never grow one: an operator un-trip is a
    /// remedy decision that belongs to its own surface.
    #[cfg(test)]
    pub(crate) fn reset(&self, key: &str) {
        use std::sync::atomic::Ordering;
        let cell = self.health.cell(key, 0);
        let _tx = crate::store::lock_recover(cell.transition_lock());
        cell.cooldown_until().store(0, Ordering::Release);
        cell.breaker_state()
            .store(crate::store::ST_CLOSED, Ordering::Release);
        cell.probe_in_flight().store(false, Ordering::Release);
        cell.streak().store(0, Ordering::Release);
    }
}

/// One admitted dispatch's hold on the single-flight recovery probe. See [`PlaneBreakers::admit`]:
/// the release is on `Drop` because that is the only release a dropped future still performs.
/// Releasing after a recorded outcome is a no-op (the record already consumed the HalfOpen state),
/// so holders simply let it fall out of scope when the dispatch settles.
pub(crate) struct Admission {
    breakers: Arc<PlaneBreakers>,
    key: String,
    epoch: u64,
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.breakers.release(&self.key, self.epoch);
    }
}

#[cfg(test)]
#[path = "tests/planes_tests.rs"]
mod planes_tests;

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
//! This is deliberately NOT failover and NOT pools: nothing here SELECTS among candidates. The
//! selection loop is [`crate::failover::walk`], which the reroute-parity unit mounts on both
//! planes' dispatch paths; it reaches these same cells through [`PlaneBreakers::runtime`] and this
//! module stays what it was — the plane's handle on the one cell store, plus the recording half of
//! the disposition pipeline.
//!
//! ## The key, per the audit
//!
//! Cells are `(pool, lane)`-keyed strings-plus-index. The pool string is PLANE-QUALIFIED at this
//! boundary — `"tool:<name>"` / `"agent:<name>"` — which is the audit's own rule for the keyspace:
//! LLM pools keep bare names, so a `tool_pools: search` can never collide with an LLM
//! `pools: search`, and the two prefixes cannot collide with each other. The NAME is a registered
//! server/agent id for the degenerate single-member cell, or a `tool_pools:`/`agent_pools:` pool
//! name for a pooled one — and config validation refuses a pool whose name collides with a
//! registration id on its own plane, so the two spellings cannot alias one cell. The LANE is the
//! member's position in the pool's ordered `members:` list (the audit's allocation rule); a
//! degenerate cell's one member is position 0.
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

// This is the non-LLM planes' handle on the breaker: every item exists for the MCP client leg and
// the A2A relay. With BOTH planes compiled out nothing holds it, so its items read dead — scoped to
// exactly that config. The two per-plane key helpers below carry their own attrs because each is
// used by only ONE plane and so reads dead in the other's single-plane build too.
#![cfg_attr(
    not(any(feature = "plane-mcp", feature = "plane-a2a")),
    allow(dead_code)
)]

use super::in_memory::{BreakerCfg, HealthState, LaneData};
use super::{LaneRuntime, Unavailable};
use crate::diagnostics::{diag_warn, PLANE_BREAKER_HARD_DOWN, PLANE_BREAKER_TRIPPED};
use std::sync::Arc;

/// One process-lifetime handle: every registered MCP server's and A2A agent's availability cell.
///
/// Held on [`crate::state::App`] and carried across a config apply the way the LLM store is —
/// learned reliability must survive a snapshot swap, or every apply un-trips every dead upstream.
pub(crate) struct PlaneBreakers {
    /// [`MAX_POOL_MEMBERS`] identical lanes — one per possible member position — never dead, never
    /// budgeted, permits never consulted (`try_admit_breaker` is the queue-shaped admission:
    /// breaker only, no permit acquisition). All per-target state lives in the per-pool cells keyed
    /// by the plane-qualified strings; the lane table exists only because the cell store's
    /// lane-global gates index it, and every entry is the same inert placeholder.
    health: HealthState,
    /// The core defaults (ADR-0002): error-rate trip over a 30s window, 15s→120s cooldown backoff.
    /// Deliberately NOT operator-tunable per `tools:`/`agents:` — that absence stays until someone
    /// asks, as `docs/circuit-breaker.md` already discloses.
    cfg: BreakerCfg,
}

/// The CEILING on a `tool_pools:`/`agent_pools:` member list, enforced at config validation
/// (`config::check_failover_pool`) so an admission can never index past the plane store's fixed
/// lane table. A constant rather than a config-derived size because [`PlaneBreakers`] is
/// PROCESS-LIFETIME (learned reliability survives every apply) while pool sizes are per-generation
/// config — a table sized to one generation's pools would need rebuilding, and rebuilding is
/// exactly the state loss the process-lifetime rule exists to prevent. Eight is generous for the
/// canonical case (one deployment, registered a handful of times); raising it is a one-line change
/// plus the validation message.
pub(crate) const MAX_POOL_MEMBERS: usize = 8;

impl PlaneBreakers {
    pub(crate) fn new() -> Self {
        Self {
            health: HealthState::new(
                (0..MAX_POOL_MEMBERS)
                    .map(|_| LaneData {
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
                    })
                    .collect(),
            ),
            cfg: BreakerCfg {
                // THE ONE FIELD THIS PLANE DOES NOT TAKE FROM THE LLM DEFAULTS, and the reason
                // survives the arrival of reroute: a plane target is DEGENERATE unless an operator
                // put it in a `tool_pools:`/`agent_pools:` set, and the unpooled single
                // registration is the canonical case. ADR-0002's sub-threshold cooldown is the
                // "prefer a sibling" half of a rule whose other half is "fail over to the next
                // candidate"; with no sibling declared there is nothing to prefer, and benching
                // the only member is not a preference, it is a 15-120s outage for every caller of
                // that server, minted by ONE transient blip and rendered as `-32030
                // upstream_unavailable` ... "open after repeated failures".
                //
                // This is a per-BREAKER setting, not a per-cell one, so it is set for the
                // conservative case and a pooled cell inherits it: a pooled member is deprioritised
                // by a TRIP, which `failover::walk` already routes around, rather than by a
                // sub-threshold bench. So these cells refuse on a TRIP and nothing less:
                // error-rate >= 0.5 over >= 5 outcomes in 30s, exactly the contract ADR-0002 and
                // `docs/circuit-breaker.md` publish for this plane. An upstream's own `Retry-After`
                // is still honoured.
                bench_below_trip_threshold: false,
                ..BreakerCfg::default()
            },
        }
    }

    /// The cell store as the [`LaneRuntime`] the failover seam's `walk` consults — the SAME object
    /// every method below writes, so a selection admitted by `failover::walk` and an outcome
    /// recorded by [`Self::record_signal`] meet on one cell. Exposed as the trait rather than the
    /// concrete type so the walk cannot grow a plane-store-specific dependency.
    pub(crate) fn runtime(&self) -> &dyn super::LaneRuntime {
        &self.health
    }

    /// The MCP plane's key for one registered tool server. The `tool:` prefix is the audit's
    /// keyspace rule; the id is the operator's registration id, which is what every refusal names.
    // MCP-only: keyed by the MCP plane alone, so with `plane-mcp` off (and A2A on) it has no caller.
    #[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
    pub(crate) fn tool_key(server: &str) -> String {
        format!("tool:{server}")
    }

    /// The A2A plane's key for one registered agent.
    // A2A-only: keyed by the A2A plane alone, so with `plane-a2a` off (and MCP on) it has no caller.
    #[cfg_attr(not(feature = "plane-a2a"), allow(dead_code))]
    pub(crate) fn agent_key(agent: &str) -> String {
        format!("agent:{agent}")
    }

    /// ADMIT ONE DISPATCH against the target's cell — [`LaneRuntime::try_admit_breaker`], the same
    /// admission the model plane's queue dispatch makes. `lane` is the member's position in its
    /// pool (0 for a degenerate cell). `Ok` carries the single-flight probe owner token; the
    /// dispatch MUST end in exactly one of `record_success` / `record_signal` / [`Self::release`]
    /// or a won recovery probe is leaked and the cell wedges HalfOpen. Production call sites use
    /// [`Self::admit`], whose RAII token cannot be leaked by a dropped future.
    // A2A-only direct admission: the A2A relay admits through this RAII pair, while the MCP leg
    // reaches the same cell via `failover::walk` + [`Self::adopt`]. So with `plane-a2a` off (and MCP
    // on) neither this nor [`Self::admit`] has a caller.
    #[cfg_attr(not(feature = "plane-a2a"), allow(dead_code))]
    pub(crate) fn try_admit(&self, key: &str, lane: usize) -> Result<u64, Unavailable> {
        self.health
            .try_admit_breaker(key, lane, HealthState::now_secs())
    }

    /// [`Self::try_admit`] as an RAII token. The owner-checked release runs on DROP, which is the
    /// only shape that survives every way a dispatch can end without recording — a refusal between
    /// admission and the wire, a caller that disconnected (axum drops the handler future), a task
    /// runner aborted by `tasks/cancel`. An explicit release call misses the dropped-future cases,
    /// and a missed release wedges the cell HalfOpen forever.
    #[cfg_attr(not(feature = "plane-a2a"), allow(dead_code))]
    pub(crate) fn admit(
        self: &Arc<Self>,
        key: &str,
        lane: usize,
    ) -> Result<Admission, Unavailable> {
        let epoch = self.try_admit(key, lane)?;
        Ok(Admission {
            breakers: Arc::clone(self),
            key: key.to_string(),
            lane,
            epoch,
        })
    }

    /// A probe token won OUTSIDE this module — by `failover::walk`, whose admission is the same
    /// [`LaneRuntime::try_admit_breaker`] against the same cell — wrapped into the RAII
    /// [`Admission`] so a walked selection inherits the identical cannot-be-leaked discipline the
    /// degenerate path has.
    pub(crate) fn adopt(self: &Arc<Self>, key: &str, lane: usize, epoch: u64) -> Admission {
        Admission {
            breakers: Arc::clone(self),
            key: key.to_string(),
            lane,
            epoch,
        }
    }

    /// OWNER-CHECKED release of the probe token [`Self::try_admit`] returned, for a dispatch that
    /// settles. Safe to call unconditionally after the outcome: a recorded success/failure has
    /// already consumed the HalfOpen state, so this is a no-op there and only reverts a probe the
    /// dispatch genuinely abandoned (refused before any leg went out).
    pub(crate) fn release(&self, key: &str, lane: usize, probe_epoch: u64) {
        self.health.release_probe_owned_in(key, lane, probe_epoch);
    }

    /// The wire answered and busbar could serve it. Closes a half-open probe, dilutes the
    /// error-rate window — the success half of the one disposition pipeline.
    pub(crate) fn record_success(&self, key: &str, lane: usize) {
        self.health.record_success_in(key, lane);
    }

    /// RECORD ONE NORMALIZED FAILURE through the ONE classifier ([`crate::breaker::classify`],
    /// Stage 2) onto the target's cell. The plane's own Stage-1 normalizer produced `sig`; this is
    /// the same disposition split `failover::record_outcome` makes, minus the all-cells hard-down
    /// (see the module header: on a shared degenerate lane, "all cells" would be every other
    /// target). Returns the disposition so a caller can log it without re-deciding.
    pub(crate) fn record_signal(
        &self,
        key: &str,
        lane: usize,
        sig: &crate::breaker::CanonicalSignal,
    ) -> crate::breaker::Disposition {
        let disposition = crate::breaker::classify(sig);
        match disposition {
            crate::breaker::Disposition::ClientFault => self.health.record_client_fault(lane),
            crate::breaker::Disposition::TransientUpstream => {
                let tripped = if sig.class == crate::breaker::StatusClass::RateLimit {
                    self.health.record_rate_limit_in(
                        key,
                        lane,
                        HealthState::now_secs(),
                        &self.cfg,
                        sig.retry_after,
                    )
                } else {
                    self.health.record_transient_in(
                        key,
                        lane,
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
                    diag_warn!(
                        PLANE_BREAKER_TRIPPED,
                        target_key = key,
                        "plane breaker tripped: the upstream target is failing and further \
                         dispatches will fast-fail until the half-open probe recovers it"
                    );
                }
            }
            crate::breaker::Disposition::HardDown => {
                self.health.record_hard_down_for(
                    key,
                    lane,
                    sig.provider_signal.as_deref().unwrap_or("hard_down"),
                );
                diag_warn!(
                    PLANE_BREAKER_HARD_DOWN,
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
    pub(crate) fn retry_after_secs(&self, key: &str, lane: usize) -> u64 {
        self.health
            .cooldown_remaining_in(key, lane, HealthState::now_secs())
            .max(1)
    }

    /// The raw FSM state of one target's cell, for tests and operator surfaces. Pure projection —
    /// no probe CAS.
    #[cfg(test)]
    pub(crate) fn state(&self, key: &str) -> super::BreakerState {
        self.state_at(key, 0)
    }

    /// [`Self::state`] for a pooled member's cell.
    #[cfg(test)]
    pub(crate) fn state_at(&self, key: &str, lane: usize) -> super::BreakerState {
        self.health.breaker_state_snapshot_in(key, lane)
    }

    /// FORCE one target's cell back to Closed with no pending cooldown — a TEST-ONLY bypass of the
    /// outer breaker, for batteries whose subject is an INNER arm this cell would otherwise shadow
    /// (the stdio supervisor's backoff/quarantine, reachable through dispatch only while the core
    /// cell admits). Production has no caller and must never grow one: an operator un-trip is a
    /// remedy decision that belongs to its own surface.
    ///
    /// `unix` in the gate, not just `test`: its one caller is `mcp/tests/stdio_dispatch_tests.rs`,
    /// which is `#![cfg(unix)]` (the fixture spawns a real child process to crash-loop), so on a
    /// Windows test build this method has no caller at all and `-D warnings` makes that dead code.
    #[cfg(all(test, unix))]
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

    /// FORCE one target's cell Open until `until` — the test-only inverse of [`Self::reset`], for
    /// batteries whose subject is what a dispatch does when a member is ALREADY tripped (the pinned
    /// A2A task refusal) without having to burn real failures to get there.
    #[cfg(test)]
    pub(crate) fn force_open(&self, key: &str, lane: usize, until: u64) {
        use std::sync::atomic::Ordering;
        let cell = self.health.cell(key, lane);
        let _tx = crate::store::lock_recover(cell.transition_lock());
        cell.cooldown_until().store(until, Ordering::Release);
        cell.breaker_state()
            .store(crate::store::ST_OPEN, Ordering::Release);
        cell.probe_in_flight().store(false, Ordering::Release);
    }
}

/// One admitted dispatch's hold on the single-flight recovery probe. See [`PlaneBreakers::admit`]:
/// the release is on `Drop` because that is the only release a dropped future still performs.
/// Releasing after a recorded outcome is a no-op (the record already consumed the HalfOpen state),
/// so holders simply let it fall out of scope when the dispatch settles.
pub(crate) struct Admission {
    breakers: Arc<PlaneBreakers>,
    key: String,
    lane: usize,
    epoch: u64,
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.breakers.release(&self.key, self.lane, self.epoch);
    }
}

#[cfg(test)]
#[path = "tests/planes_tests.rs"]
mod planes_tests;

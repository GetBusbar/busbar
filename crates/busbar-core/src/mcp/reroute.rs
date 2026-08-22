// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FAILOVER SEAM, MOUNTED ON THIS PLANE — `tool_pools:` becomes a candidate set, the set goes
//! through the ONE selection loop ([`crate::failover::walk`]), and the admitted member is
//! dispatched by the same `upstream::call` every un-pooled server has always been.
//!
//! ## What this module owns and what it inherits
//!
//! Owned here: the [`crate::failover::Candidate`] impl for a tool-pool member (name, lane, pin),
//! the route construction (which members exist, which are authorised for THIS caller, which cell
//! each records into), and the reroute loop's bookkeeping. Inherited, deliberately and completely:
//! the selection ORDER, the pin check, the retry-safety rule and the breaker admission are all
//! [`crate::failover::walk`]'s — this file contains no `if` about any of them.
//!
//! ## The three movements, and which calls make them
//!
//! 1. **Admission** ([`PoolRoute::admit`]) — before any socket, the walk selects the first member
//!    whose cell admits. A pool whose every interchangeable member is tripped refuses HERE, in
//!    milliseconds, exactly like the degenerate cell (it IS the degenerate cell when no pool is
//!    configured: one member, lane 0, same walk).
//! 2. **Reroute** (inside [`PoolRoute::dispatch`]) — a leg that fails with
//!    [`crate::failover::Stage::BeforeFirstByte`] (the wire says nothing was transmitted) records
//!    against the failed member's cell and RE-ENTERS the walk with that member in `tried`. The
//!    caller gets the twin's answer and never learns. A leg that fails AFTER dispatch re-enters
//!    the walk too — and the walk's own safety rule refuses the hop unless the operator listed the
//!    operation in `repeatable:`. No new config, no local override.
//! 3. **Pinning** — the first round that produces an outcome the loop will not reroute (success,
//!    or a kept failure) pins the route to that member: the MRTR input-required continuation is a
//!    conversation with ONE server, and moving it would hand a later round's `requestState` to a peer
//!    that never issued it.

use super::upstream::{Authorised, BreakerCell, LegFailure};
use crate::failover::{walk, Attempt, Candidate, Refusal, Repeatable, Stage};
use crate::store::{PlaneAdmission, PlaneBreakers};
use std::sync::{Arc, Mutex};

/// One pool member as the walk sees it. `auth` is `None` when THIS CALLER cannot dispatch to the
/// member (no grant, pending approval, unresolvable credential): the member is pre-`tried` so the
/// walk never selects it, and nothing is recorded against it — an authorisation refusal is a fact
/// about the caller, never a penalty on the upstream.
pub(crate) struct RouteMember {
    name: String,
    lane: usize,
    /// The approved schema digest of THIS tool on THIS member — the pin the seam checks. `None`
    /// (nothing approved) never matches, so a pending registration cannot be failed over to or
    /// from; that is the seam's rule, inherited rather than re-decided.
    pin: Option<String>,
    auth: Option<Authorised>,
}

impl Candidate for RouteMember {
    fn name(&self) -> &str {
        &self.name
    }
    fn lane(&self) -> usize {
        self.lane
    }
    fn interchange_key(&self) -> Option<&str> {
        self.pin.as_deref()
    }
}

/// What the route is doing right now. Behind ONE mutex so the reroute decision — mark tried, drop
/// the admission, re-walk, adopt the new probe — is a single transition no concurrent reader can
/// observe half-made. The lock is never held across an await.
struct RouteState {
    /// The member currently selected and admitted. `None` between a pre-first-byte failure and the
    /// re-walk that replaces it.
    active: Option<usize>,
    /// Set the moment a round produces an outcome the loop keeps (success or a kept failure).
    /// A pinned route never selects again: later input-required rounds are a continuation with
    /// exactly this member.
    pinned: bool,
    /// Positions already dispatched to (or unauthorised for this caller). Handed to the walk,
    /// which never selects them again for this request.
    tried: Vec<usize>,
    /// The RAII probe hold for `active`. Dropping it releases owner-checked; a recorded outcome
    /// has already consumed the probe and makes that a no-op.
    admission: Option<PlaneAdmission>,
}

/// A dispatchable route: the candidate set, the cell key they share, and the walk's live state.
pub(crate) struct PoolRoute {
    /// The plane-qualified breaker pool key: `"tool:<pool>"`, or `"tool:<server>"` degenerate.
    pool_key: String,
    /// What refusals name: the pool name, or the server id when no pool is configured.
    display: String,
    /// Whether this route is a real `tool_pools:` pool (false = the degenerate single-member set).
    pooled: bool,
    members: Vec<RouteMember>,
    repeatable: Repeatable,
    /// The bare tool name, for the walk's refusal wording.
    operation: String,
    state: Mutex<RouteState>,
}

/// Why the route refused to admit anything — the walk's own refusal plus the `Retry-After` the
/// rendering owes the caller (the soonest any member's cooldown expires, floored at 1).
pub(crate) struct RouteRefused {
    pub(crate) refusal: Refusal,
    pub(crate) retry_after_secs: u64,
}

impl PoolRoute {
    /// Build the candidate set for one admitted `tools/call`.
    ///
    /// `selected`/`selected_auth` are the caller-named tool and its already-authorised leg — the
    /// gate for the named server ran in `method.rs` and its refusals render there, so this function
    /// never re-judges it. Twins are resolved and authorised HERE, under the same live snapshot,
    /// and a twin that refuses is skipped (pre-`tried`), never rendered: the caller asked for a
    /// tool, not for a twin inventory.
    pub(crate) fn build(
        app: &crate::state::App,
        principal: Option<&busbar_api::VirtualKey>,
        selected: &super::catalogue::ToolEntry,
        selected_auth: Authorised,
        arguments: &serde_json::Value,
    ) -> PoolRoute {
        let pool = app
            .tool_pools
            .iter()
            .find(|(_, cfg)| cfg.members.iter().any(|m| m == &selected.server));
        let Some((pool_name, cfg)) = pool else {
            // THE DEGENERATE SINGLE-MEMBER SET — the breaker unit's cell, unchanged: same key,
            // lane 0, fast-fail and no reroute, exactly what an un-pooled registration had.
            return PoolRoute {
                pool_key: BreakerCell::degenerate(&selected.server).key,
                display: selected.server.clone(),
                pooled: false,
                members: vec![RouteMember {
                    name: selected.server.clone(),
                    lane: 0,
                    pin: selected.schema_hash.clone(),
                    auth: Some(selected_auth),
                }],
                repeatable: Repeatable::No,
                operation: selected.tool.clone(),
                state: Mutex::new(RouteState {
                    active: None,
                    pinned: false,
                    tried: Vec::new(),
                    admission: None,
                }),
            };
        };

        let sightings = super::runtime(app).sightings.load();
        let live = super::client::catalogue::LiveSightings::of(&sightings);
        let generation = crate::trust::validate::Generations::at_admission(
            super::runtime(app).catalogue.generation(),
        );
        let now = crate::store::now();
        let mut selected_auth = Some(selected_auth);
        let mut tried = Vec::new();
        let members: Vec<RouteMember> =
            cfg.members
                .iter()
                .enumerate()
                .map(|(lane, member)| {
                    if member == &selected.server {
                        return RouteMember {
                            name: member.clone(),
                            lane,
                            pin: selected.schema_hash.clone(),
                            auth: selected_auth.take(),
                        };
                    }
                    // THE TWIN'S OWN ADMISSION, in full: the caller's grant on the twin's published
                    // name, the twin's live trust state, the twin's credential plan and the argument
                    // guard against the twin's approved schema. A twin this caller may not reach is
                    // skipped — busbar never widens a grant because an operator declared a pool.
                    let entry = super::runtime(app)
                        .catalogue
                        .tool_on(member, &selected.tool)
                        .and_then(|e| {
                            super::runtime(app)
                                .catalogue
                                .resolve(principal, live, &e.namespaced, generation, now)
                                .ok()
                        });
                    let pin = entry.and_then(|e| e.schema_hash.clone());
                    let auth = entry.and_then(|e| {
                        super::runtime(app).catalogue.server(member).and_then(|s| {
                            super::upstream::authorise(s, e, arguments, principal).ok()
                        })
                    });
                    if auth.is_none() {
                        tried.push(lane);
                    }
                    RouteMember {
                        name: member.clone(),
                        lane,
                        pin,
                        auth,
                    }
                })
                .collect();

        PoolRoute {
            pool_key: PlaneBreakers::tool_key(pool_name),
            display: pool_name.clone(),
            pooled: true,
            members,
            repeatable: cfg.repeatability(&selected.tool),
            operation: selected.tool.clone(),
            state: Mutex::new(RouteState {
                active: None,
                pinned: false,
                tried,
                admission: None,
            }),
        }
    }

    /// What refusals and audit rows name.
    pub(crate) fn display(&self) -> &str {
        &self.display
    }

    /// Whether the route is a configured pool (drives which refusal wording the caller sees).
    pub(crate) fn pooled(&self) -> bool {
        self.pooled
    }

    /// The member the route is currently dispatching to (or last dispatched to) — what the ask
    /// loop's per-round grant and roots lookups must read, because a rerouted conversation is the
    /// TWIN's, judged under the twin's own operator declarations.
    pub(crate) fn active_member(&self) -> String {
        let s = lock(&self.state);
        let idx = s.active.or_else(|| s.tried.last().copied()).unwrap_or(0);
        self.members[idx].name.clone()
    }

    /// ADMIT: run the walk and hold the admitted member's probe. The pre-socket gate — a refusal
    /// here cost no token exchange and no socket, and the rendering is the caller's 503.
    pub(crate) fn admit(&self, breakers: &Arc<PlaneBreakers>) -> Result<(), Box<RouteRefused>> {
        let mut s = lock(&self.state);
        self.select_locked(&mut s, Stage::BeforeFirstByte, breakers)
            .map_err(|refusal| {
                Box::new(RouteRefused {
                    refusal,
                    retry_after_secs: self.soonest_retry(breakers),
                })
            })
    }

    /// The walk, under the lock: selects into `state.active` and adopts the probe.
    fn select_locked(
        &self,
        s: &mut RouteState,
        stage: Stage,
        breakers: &Arc<PlaneBreakers>,
    ) -> Result<(), Refusal> {
        let attempt = Attempt {
            tried: &s.tried,
            stage,
            repeatable: self.repeatable,
            operation: &self.operation,
        };
        let admitted = walk(
            breakers.runtime(),
            &self.pool_key,
            &self.members,
            &attempt,
            crate::store::now(),
        )?;
        s.active = Some(admitted.position());
        s.admission = Some(breakers.adopt(
            &self.pool_key,
            admitted.candidate().lane(),
            admitted.probe_epoch(),
        ));
        Ok(())
    }

    /// The soonest any member's cooldown expires — the honest `Retry-After` for a pool where the
    /// members trip independently.
    fn soonest_retry(&self, breakers: &PlaneBreakers) -> u64 {
        self.members
            .iter()
            .map(|m| breakers.retry_after_secs(&self.pool_key, m.lane))
            .min()
            .unwrap_or(1)
    }

    /// ONE ROUND of the routed dispatch: send to the admitted member; on a failure the seam's
    /// rules allow moving, record (already done inside `call`), mark tried, re-walk, and try the
    /// next member. The caller sees exactly one answer, and an exhausted pool answers with the
    /// LAST member's failure — the same rendering an un-pooled server's failure has always had.
    pub(crate) async fn dispatch(
        &self,
        pool: &super::client::pool::McpConnectionPool,
        breakers: &Arc<PlaneBreakers>,
        arguments: &serde_json::Value,
        request_id: u64,
        satisfaction: Option<serde_json::Value>,
    ) -> Result<super::inputreq::Round, String> {
        loop {
            let (idx, cell) = {
                let s = lock(&self.state);
                let idx = s
                    .active
                    .expect("a routed dispatch runs only after `admit` selected a member");
                (
                    idx,
                    BreakerCell {
                        key: self.pool_key.clone(),
                        lane: self.members[idx].lane,
                    },
                )
            };
            let auth = self.members[idx]
                .auth
                .as_ref()
                .expect("the walk only selects authorised members (unauthorised are pre-tried)");
            let outcome = super::upstream::call(
                pool,
                breakers,
                &cell,
                auth,
                arguments,
                request_id,
                satisfaction.clone(),
            )
            .await;
            let failure: LegFailure = match outcome {
                Ok(round) => {
                    lock(&self.state).pinned = true;
                    return Ok(round);
                }
                Err(f) => f,
            };
            {
                let mut s = lock(&self.state);
                if s.pinned {
                    // A continuation round failed. The conversation is this member's; there is
                    // nothing to reroute without inventing a second conversation.
                    return Err(failure.message);
                }
                // The failed member is spent for this request, whatever happens next. Its outcome
                // was recorded inside `call`, against its own cell; the admission drop below
                // releases an unconsumed probe owner-checked.
                s.tried.push(idx);
                s.active = None;
                s.admission = None;
                // RE-ENTER THE ONE WALK. Its safety rule — not this file — decides whether the
                // failure's stage and the operator's `repeatable:` allow another member; a refusal
                // keeps the failure the caller was already owed.
                if self.select_locked(&mut s, failure.stage, breakers).is_err() {
                    s.pinned = true;
                    return Err(failure.message);
                }
                tracing::info!(
                    pool = %self.display,
                    failed_member = %self.members[idx].name,
                    "mcp reroute: the member failed before the seam's rules forbade moving; \
                     re-dispatching to the next interchangeable member"
                );
            }
        }
    }

    /// Hand the admitted member to the TASK path: its authorised leg, its cell, the probe hold as a
    /// DURABLE-SCOPED handle, and its server id (for per-server grants/roots lookups inside the
    /// runner). Consumes the route — a task dispatches exactly one member and never reroutes mid-task.
    ///
    /// THE PROBE HOLD LEAVES THE REQUEST'S SCOPE (§4 durable handoff). The breaker `PlaneAdmission`
    /// this route won moves out of the per-request dispatch arena into a [`DurableScope`] the RUNNER
    /// owns, so its owner-checked release reclaims at TASK end (the runner's normal end OR a
    /// `tasks/cancel` abort) — never at request-future drop, which would release the probe mid-task
    /// and wedge the cell. Yielding the durable-scoped handle here is what re-homes that lifetime.
    pub(crate) fn into_task_dispatch(
        self,
        breakers: &Arc<PlaneBreakers>,
    ) -> Option<(
        Authorised,
        BreakerCell,
        crate::plane_host::DurableScope,
        busbar_plugin::hot::AdmissionId,
        String,
    )> {
        let mut s = lock(&self.state);
        let idx = s.active?;
        let admission = s.admission.take()?;
        drop(s);
        let lane = self.members[idx].lane;
        let pool_key = self.pool_key.clone();
        let cell = BreakerCell {
            key: pool_key.clone(),
            lane,
        };
        let member = self.members.into_iter().nth(idx)?;
        // The probe hold rides into the durable scope as a SETTLE-CAPABLE admission: the detached
        // runner can record its observed outcome against the same `(key, lane)` cell through the host
        // seam, and only an UNSETTLED probe releases when the durable scope drops at task end. This is
        // the §4 handoff — the probe's lifetime re-homes from the request future to the task's.
        let settling =
            crate::plane_host::breaker::settling_admission(Arc::clone(breakers), pool_key, lane, admission);
        let (durable, admission_id) =
            crate::plane_host::DurableScope::with_settling_handoff(settling);
        Some((member.auth?, cell, durable, admission_id, member.name))
    }
}

/// Poisoning: a panicked holder leaves consistent-enough state (every transition is applied before
/// any await); recover rather than propagate, matching the store's own `lock_recover` posture.
fn lock<'a>(m: &'a Mutex<RouteState>) -> std::sync::MutexGuard<'a, RouteState> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

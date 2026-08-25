// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FAILOVER SEAM, MOUNTED ON THIS PLANE — `tool_pools:` becomes a candidate set, the set goes
//! through the ONE selection loop ([`busbar_substrate::failover::walk`]), and the admitted member is
//! dispatched by the same `upstream::call` every un-pooled server has always been.
//!
//! ## What this module owns and what it inherits
//!
//! Owned here: the [`busbar_substrate::failover::Candidate`] impl for a tool-pool member (name, lane, pin),
//! the route construction (which members exist, which are authorised for THIS caller, which cell
//! each records into), and the reroute loop's bookkeeping. Inherited, deliberately and completely:
//! the selection ORDER, the pin check, the retry-safety rule and the breaker admission are all
//! [`busbar_substrate::failover::walk`]'s — this file contains no `if` about any of them.
//!
//! ## The three movements, and which calls make them
//!
//! 1. **Admission** ([`PoolRoute::admit`]) — before any socket, the walk selects the first member
//!    whose cell admits. A pool whose every interchangeable member is tripped refuses HERE, in
//!    milliseconds, exactly like the degenerate cell (it IS the degenerate cell when no pool is
//!    configured: one member, lane 0, same walk).
//! 2. **Reroute** (inside [`PoolRoute::dispatch`]) — a leg that fails with
//!    [`busbar_substrate::failover::Stage::BeforeFirstByte`] (the wire says nothing was transmitted) records
//!    against the failed member's cell and RE-ENTERS the walk with that member in `tried`. The
//!    caller gets the twin's answer and never learns. A leg that fails AFTER dispatch re-enters
//!    the walk too — and the walk's own safety rule refuses the hop unless the operator listed the
//!    operation in `repeatable:`. No new config, no local override.
//! 3. **Pinning** — the first round that produces an outcome the loop will not reroute (success,
//!    or a kept failure) pins the route to that member: the MRTR input-required continuation is a
//!    conversation with ONE server, and moving it would hand a later round's `requestState` to a peer
//!    that never issued it.

use super::upstream::{Authorised, BreakerCell, LegFailure, LegOutcome};
use busbar_core::plane_host::DispatchScope;
use busbar_core::store::PlaneBreakers;
use busbar_plugin::hot::AdmissionId;
use busbar_substrate::failover::{Attempt, Candidate, Refusal, Repeatable, Stage};
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

/// What the route is doing right now. Behind ONE mutex so the reroute decision — mark tried, clear
/// the admission id, re-walk and win the next probe through the host seam — is a single transition no
/// concurrent reader can observe half-made. The lock is never held across an await.
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
    /// The host [`AdmissionId`] for `active`: the id the shared [`DispatchScope`] (the sync request
    /// arena OR the runner's durable arena on the task path) minted when the walk won the probe
    /// through the host `breaker_admit` seam, and the id the leg's settle folds its outcome through.
    /// The plane NEVER holds a bare `PlaneAdmission` — the arena owns the real probe. [`AdmissionId::NONE`]
    /// between a pre-first-byte failure and the re-walk that replaces it.
    admission_id: AdmissionId,
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
        app: &busbar_core::state::App,
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
                    admission_id: AdmissionId::NONE,
                }),
            };
        };

        let sightings = super::runtime(app).sightings.load();
        let live = super::client::catalogue::LiveSightings::of(&sightings);
        let generation = busbar_substrate::trust::validate::Generations::at_admission(
            super::runtime(app).catalogue.generation(),
        );
        let now = busbar_core::plane_host::clock_now_secs_over(app);
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
                admission_id: AdmissionId::NONE,
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

    /// ADMIT: run the walk and win the admitted member's probe. The pre-socket gate — a refusal
    /// here cost no token exchange and no socket, and the rendering is the caller's 503.
    ///
    /// `scope` is the shared [`DispatchScope`] the won probe is REGISTERED in as a settle-capable
    /// admission — the sync request arena on the synchronous path, or the runner's durable arena
    /// (via [`DurableScope::arena`](busbar_core::plane_host::DurableScope::arena)) on the task path, so the
    /// task's probe is BORN in the durable scope. The plane holds only the POD [`AdmissionId`]; the
    /// arena owns the real probe and its outcome is later folded through the scope.
    pub(crate) fn admit(
        &self,
        app: &busbar_core::state::App,
        breakers: &Arc<PlaneBreakers>,
        scope: &DispatchScope,
    ) -> Result<(), Box<RouteRefused>> {
        let mut s = lock(&self.state);
        self.select_locked(app, &mut s, Stage::BeforeFirstByte, scope)
            .map_err(|refusal| {
                Box::new(RouteRefused {
                    refusal,
                    retry_after_secs: self.soonest_retry(breakers),
                })
            })
    }

    /// The walk, under the lock: selects into `state.active` and wins the probe through the shared
    /// `scope`, keeping only its host id in `state.admission_id`.
    ///
    /// The WIN rides the host `breaker_admit` seam PER CANDIDATE. The walk's own pin/repeatability/order
    /// still select (probe-win-last preserved: `walk_with` runs the pin check BEFORE the admit closure),
    /// and the host wins+registers+mints ATOMICALLY, so the plane holds only the POD `AdmissionId` and
    /// never a `PlaneAdmission`. A reroute re-walks and re-admits through the same seam, minting a fresh
    /// id per leg.
    fn select_locked(
        &self,
        app: &busbar_core::state::App,
        s: &mut RouteState,
        stage: Stage,
        scope: &DispatchScope,
    ) -> Result<(), Refusal> {
        let attempt = Attempt {
            tried: &s.tried,
            stage,
            repeatable: self.repeatable,
            operation: &self.operation,
        };
        let mut order = busbar_substrate::failover::InOrder::new(&s.tried, self.members.len());
        let mut passed_over = Vec::new();
        let admitted = busbar_substrate::failover::walk_with(
            &self.pool_key,
            &self.members,
            &attempt,
            &mut order,
            &mut passed_over,
            &mut |_position, member: &RouteMember| {
                busbar_core::plane_host::breaker::breaker_admit_over(
                    app,
                    scope,
                    self.pool_key.as_bytes(),
                    member.lane() as u32,
                )
            },
        )?;
        s.active = Some(admitted.position());
        s.admission_id = admitted.into_token();
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

    /// ONE ROUND of the routed dispatch: send to the admitted member; `call` classifies the leg's
    /// breaker outcome, this SETTLES it (CLUSTER-1 — through the shared `scope` when one owns the
    /// probe, else in place), and on a failure the seam's rules allow moving it marks tried, re-walks,
    /// and tries the next member. The caller sees exactly one answer, and an exhausted pool answers
    /// with the LAST member's failure — the same rendering an un-pooled server's failure always had.
    #[allow(clippy::too_many_arguments)] // the routed dispatch's own facts, gathered where made.
    pub(crate) async fn dispatch(
        &self,
        app: &busbar_core::state::App,
        pool: &super::client::pool::McpConnectionPool,
        breakers: &Arc<PlaneBreakers>,
        scope: &DispatchScope,
        arguments: &serde_json::Value,
        request_id: u64,
        satisfaction: Option<serde_json::Value>,
    ) -> Result<super::inputreq::Round, String> {
        loop {
            let (idx, cell, admission_id) = {
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
                    s.admission_id,
                )
            };
            let auth = self.members[idx]
                .auth
                .as_ref()
                .expect("the walk only selects authorised members (unauthorised are pre-tried)");
            let mut leg_outcome = LegOutcome::Nothing;
            let outcome = super::upstream::call(
                pool,
                auth,
                arguments,
                request_id,
                satisfaction.clone(),
                &mut leg_outcome,
            )
            .await;
            // SETTLE this leg's classified outcome where the probe lives (CLUSTER-1): through the
            // shared scope over this leg's id, or — with no scope, or a multi-round leg whose probe
            // was already settled on an earlier round — in place against the member's own cell.
            settle_leg(
                app,
                breakers,
                &cell,
                Some(scope),
                admission_id,
                &leg_outcome,
            );
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
                // The failed member is spent for this request, whatever happens next. Its outcome was
                // just settled above (consuming/releasing the scope's admission, or recorded in
                // place); clearing the id abandons any still-live admission the re-walk replaces.
                s.tried.push(idx);
                s.active = None;
                s.admission_id = AdmissionId::NONE;
                // RE-ENTER THE ONE WALK. Its safety rule — not this file — decides whether the
                // failure's stage and the operator's `repeatable:` allow another member; a refusal
                // keeps the failure the caller was already owed.
                if self
                    .select_locked(app, &mut s, failure.stage, scope)
                    .is_err()
                {
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

    /// Hand the admitted member to the TASK path: its authorised leg, its cell, the durable
    /// [`AdmissionId`] the probe was minted under, and its server id (for per-server grants/roots
    /// lookups inside the runner). Consumes the route — a task dispatches exactly one member and never
    /// reroutes mid-task.
    ///
    /// NO RE-HOME: the probe is already BORN in the runner's [`DurableScope`], because
    /// [`admit`](Self::admit) ran the task's walk through the host `breaker_admit` seam over the durable
    /// arena. Its owner-checked release therefore already reclaims at TASK end (the runner's normal end
    /// OR a `tasks/cancel` abort) — never at request-future drop. This yields the POD id the detached
    /// runner settles by; the durable scope itself is owned by `create_task` and moved into the runner.
    pub(crate) fn into_task_dispatch(
        self,
    ) -> Option<(
        Authorised,
        BreakerCell,
        busbar_plugin::hot::AdmissionId,
        String,
    )> {
        let (idx, admission_id) = {
            let s = lock(&self.state);
            (s.active?, s.admission_id)
        };
        let lane = self.members[idx].lane;
        let cell = BreakerCell {
            key: self.pool_key.clone(),
            lane,
        };
        let member = self.members.into_iter().nth(idx)?;
        Some((member.auth?, cell, admission_id, member.name))
    }
}

/// SETTLE ONE dispatched leg's classified breaker outcome (CLUSTER-1). With a shared `scope` that
/// owns this leg's probe (`admission_id` live), fold the outcome through it — the same
/// `record_signal`/`record_success` disposition the plane's own recorder runs, byte-identically.
/// Otherwise (no scope, or a multi-round leg whose one probe was already settled on an earlier round)
/// record in place against the member's own cell — leaving a `Nothing` unrecorded exactly as dropping
/// the raw probe did.
fn settle_leg(
    app: &busbar_core::state::App,
    breakers: &Arc<PlaneBreakers>,
    cell: &BreakerCell,
    scope: Option<&DispatchScope>,
    admission_id: AdmissionId,
    outcome: &LegOutcome,
) {
    if let Some(scope) = scope {
        if !admission_id.is_none() {
            let sig = match outcome {
                LegOutcome::Success => busbar_core::plane_host::breaker::success_signal(),
                LegOutcome::Failure(cs) => busbar_core::plane_host::breaker::failure_signal(cs),
                // A settled `Refused` records nothing and RELEASES the probe — the raw-drop behaviour.
                LegOutcome::Nothing => busbar_core::plane_host::breaker::refused_signal(),
            };
            // Fold the outcome through the host `breaker_settle` seam over this leg's id. `Ok` means the
            // live admission was found and settled; `Gone` means the probe was already settled (a later
            // multi-round leg) → fall through to the in-place record, exactly as before.
            let settled = busbar_core::plane_host::with_borrowed_host(app, scope, |host, vt| {
                (vt.breaker_settle.expect("breaker_settle is a wired slot"))(
                    host,
                    admission_id,
                    &sig as *const busbar_plugin::hot::Signal,
                )
            });
            if settled == busbar_plugin::hot::StatusClass::Ok {
                return;
            }
        }
    }
    match outcome {
        LegOutcome::Success => {
            breakers.record_success(&cell.key, cell.lane);
        }
        LegOutcome::Failure(cs) => {
            breakers.record_signal(&cell.key, cell.lane, cs);
        }
        // Not an upstream health signal: record nothing (a raw probe, if any, releases on drop).
        LegOutcome::Nothing => {}
    }
}

/// Poisoning: a panicked holder leaves consistent-enough state (every transition is applied before
/// any await); recover rather than propagate, matching the store's own `lock_recover` posture.
fn lock<'a>(m: &'a Mutex<RouteState>) -> std::sync::MutexGuard<'a, RouteState> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

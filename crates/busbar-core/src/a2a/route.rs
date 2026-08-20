// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MEMBER SELECTION for one admitted A2A call — the failover seam mounted at ADMISSION TIME,
//! factored out of `receive` whole: which `agent_pools:` member (if any) a hop targets, which
//! breaker cell it admits against, and what the ingress renders when the walk refuses.
//!
//! The rules, stated once here and inherited by `receive`:
//!
//! - A FRESH submission to a pooled agent goes through the ONE candidate loop
//!   ([`crate::failover::walk`] over the pool's members, pin-checked against the approved card
//!   fingerprints, admitted through the one breaker), so a tripped primary reroutes to its
//!   verified twin BEFORE anything reaches a socket and the caller never learns.
//! - An ADDRESSED or RESUMED task is PINNED to the member that accepted it — the task id names
//!   state that exists at exactly one backend, so failover on this plane is an admission-time
//!   choice, NEVER a migration: a pinned member that is tripped refuses THE VERB (503 +
//!   `Retry-After`, task state stays readable from busbar's own store) rather than dispatching to
//!   a twin.
//! - An un-pooled agent keeps its degenerate single-member cell, byte-for-byte the breaker unit's
//!   behaviour.

use super::relay::RelayBreaker;
use crate::diagnostics::{
    diag_debug, diag_error, diag_warn, A2A_EXTENDED_CARD_BUILD_FAILED, A2A_PIN_REFUSAL_UNRECORDED,
    A2A_POOL_NOT_INTERCHANGEABLE,
};
use crate::state::App;
use axum::response::{IntoResponse as _, Response};
use std::sync::Arc;

/// One `agent_pools:` member as the walk sees it — this plane's whole cost of inheriting the
/// seam, exactly as the seam's module header promised ("a third plane costs a candidate type").
struct AgentCandidate {
    name: String,
    lane: usize,
    /// The approved canonical card fingerprint, or `None` when nothing is approved (which never
    /// matches — a pending registration cannot be failed over to or from).
    pin: Option<String>,
    /// Whether THIS caller may reach the member at all (inbound authorization + egress grant).
    /// Ineligible members are pre-`tried` and never selected or penalised.
    eligible: bool,
}

impl crate::failover::Candidate for AgentCandidate {
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

/// The pool the caller-named agent belongs to, if any — resolved ONCE per call and read by the
/// resume lookup, the walk and the pinning.
pub(super) fn pool_of<'a>(
    app: &'a App,
    agent_id: &str,
) -> Option<(&'a String, &'a crate::failover::CandidatePoolCfg)> {
    app.agent_pools
        .iter()
        .find(|(_, cfg)| cfg.members.iter().any(|m| m == agent_id))
}

/// What [`select_member`] decided for this call.
pub(super) struct SelectedMember {
    /// The member the hop targets — the walked twin on a rerouted fresh submission, the pinned
    /// member on a task-scoped verb, the caller-named agent otherwise.
    pub(super) agent_id: String,
    /// The breaker cell the hop admits against and records into.
    pub(super) breaker: RelayBreaker,
    /// The probe hold a walked selection already won (RAII; held by the caller across the hop —
    /// the recorded outcome consumes it and the drop is then a no-op).
    pub(super) admission: Option<crate::store::PlaneAdmission>,
    /// Set when the walk found nothing admissible: the ingress renders it AFTER the task row
    /// exists, through the degenerate breaker refusal's own rendering.
    pub(super) walk_refusal: Option<super::relay::RelayRefusal>,
    /// Set when the walk refused on the pin check — the operator's same-deployment claim failed.
    pub(super) pin_mismatch: Option<String>,
}

/// Decide the target member for one admitted call. See the module header for the three rules.
#[allow(clippy::too_many_arguments)] // the admission's own facts, gathered where they were made.
pub(super) fn select_member(
    app: &App,
    plane: &super::plane::A2aPlane,
    key: &busbar_api::VirtualKey,
    kind: &'static str,
    admitted_agent: &str,
    generation: u64,
    pinned_member: Option<&str>,
    method: &str,
    now: u64,
) -> SelectedMember {
    let breakers = Arc::clone(&app.plane_breakers);
    let pool = pool_of(app, admitted_agent);
    let mut selected = SelectedMember {
        agent_id: admitted_agent.to_string(),
        breaker: RelayBreaker::degenerate(admitted_agent, Arc::clone(&breakers)),
        admission: None,
        walk_refusal: None,
        pin_mismatch: None,
    };
    match (pool, pinned_member) {
        // Un-pooled: the degenerate single-member cell, byte-for-byte the breaker unit's
        // behaviour. (A pinned task on a single registration is trivially pinned to it.)
        (None, _) => {}
        // Task-scoped verbs and resumes: PINNED. The member's own pool cell; `prepare` admits it
        // (not pre-admitted), so a tripped member refuses the verb without ending the task.
        (Some((pool_name, cfg)), Some(pinned)) => {
            selected.agent_id = pinned.to_string();
            selected.breaker = match cfg.members.iter().position(|m| m == pinned) {
                Some(lane) => RelayBreaker {
                    breakers: Arc::clone(&breakers),
                    key: crate::store::PlaneBreakers::agent_key(pool_name),
                    lane,
                    pre_admitted: false,
                },
                // Dispatched before the pool existed, or a member since removed from it: the
                // task stays pinned and the cell is the member's own degenerate one.
                None => RelayBreaker::degenerate(pinned, Arc::clone(&breakers)),
            };
        }
        // Fresh submission to a pooled agent: THE WALK.
        (Some((pool_name, cfg)), None) => {
            let candidates: Vec<AgentCandidate> = plane.with_registrations(|regs| {
                cfg.members
                    .iter()
                    .enumerate()
                    .map(|(lane, member)| {
                        // THE PIN is the approved canonical card fingerprint — the value busbar
                        // already computed and locked; `None` (nothing approved) never matches, so
                        // a pending registration cannot be failed over to or from.
                        let pin = regs
                            .iter()
                            .find(|r| &r.agent_id == member)
                            .and_then(|r| r.approval.pin())
                            .and_then(|p| p.card_fingerprint())
                            .map(str::to_string);
                        // ELIGIBILITY is this caller's, judged per member with the same two gates
                        // the named agent passed — inbound authorization and the egress grant. A
                        // member this caller may not reach is pre-`tried`, never selected, and
                        // never penalised: an authorization refusal is a fact about the caller.
                        let eligible =
                            super::inbound::authorize(key, kind, member, regs, generation, now)
                                .is_ok()
                                && super::creds::authorise_egress(key, member, now).is_ok();
                        AgentCandidate {
                            name: member.clone(),
                            lane,
                            pin,
                            eligible,
                        }
                    })
                    .collect()
            });
            let pool_key = crate::store::PlaneBreakers::agent_key(pool_name);
            let tried: Vec<usize> = candidates
                .iter()
                .filter(|c| !c.eligible)
                .map(|c| c.lane)
                .collect();
            let attempt = crate::failover::Attempt {
                tried: &tried,
                stage: crate::failover::Stage::BeforeFirstByte,
                repeatable: crate::failover::Repeatable::No,
                operation: method,
            };
            match crate::failover::walk(breakers.runtime(), &pool_key, &candidates, &attempt, now) {
                Ok(adm) => {
                    let lane = adm.candidate().lane;
                    let chosen = adm.candidate().name.clone();
                    // The probe hold, adopted RAII and held across the hop; the recorded outcome
                    // consumes it and the drop after the hop is then a no-op.
                    selected.admission = Some(breakers.adopt(&pool_key, lane, adm.probe_epoch()));
                    if lane != 0 {
                        tracing::info!(
                            pool = %pool_name,
                            member = %chosen,
                            "a2a reroute: the pool's primary is not admissible; this fresh \
                             submission dispatches to the verified twin"
                        );
                    }
                    selected.agent_id = chosen;
                    selected.breaker = RelayBreaker {
                        breakers: Arc::clone(&breakers),
                        key: pool_key,
                        lane,
                        pre_admitted: true,
                    };
                }
                Err(refusal) => {
                    // Nothing admissible (or the operator's same-deployment claim failed the pin
                    // check). The task row is still opened by the ingress so the caller keeps an
                    // id to poll; the refusal fires after the row exists, through the same
                    // rendering the degenerate breaker refusal uses.
                    match &refusal {
                        crate::failover::Refusal::NotInterchangeable { .. } => {
                            selected.pin_mismatch = Some(refusal.to_string());
                        }
                        _ => {
                            let retry_after_secs = candidates
                                .iter()
                                .map(|c| breakers.retry_after_secs(&pool_key, c.lane))
                                .min()
                                .unwrap_or(1);
                            selected.walk_refusal = Some(super::relay::RelayRefusal::BreakerOpen {
                                agent_id: pool_name.clone(),
                                retry_after_secs,
                            });
                        }
                    }
                }
            }
        }
    }
    selected
}

/// The target member's own registration facts — its backend URL and its credential HANDLE (never
/// a secret) — for a hop re-targeted away from the caller-named agent. `None` when the pinned
/// member's registration is gone.
fn member_facts(
    plane: &super::plane::A2aPlane,
    target: &str,
) -> Option<(String, Option<super::creds::OutboundCredential>)> {
    plane.with_registrations(|regs| {
        regs.iter()
            .find(|r| r.agent_id == target)
            .map(|r| (r.backend_url.clone(), r.outbound_cred.clone()))
    })
}

/// THE HOP'S OWN FACTS for the selected member. For the caller-named agent these are exactly the
/// values admission resolved; a rerouted or pinned-elsewhere member re-reads its registration —
/// its own backend URL and its own credential handle — and RE-DERIVES the egress grant FOR THAT
/// MEMBER, so busbar's credential is never leased for a backend the caller's grant does not
/// cover. (The walk already checked this for a rerouted member; the pinned path re-asks live.)
///
/// `Err(None)` = the pinned member's registration is gone (the ingress fails the hop, task state
/// stays readable); `Err(Some(resp))` = the egress gate refused the re-targeted member, already
/// audited `rejected` here so a second caller cannot forget to.
#[allow(clippy::too_many_arguments)] // the hop's own facts, no more.
pub(super) fn hop_facts<'a>(
    plane: &super::plane::A2aPlane,
    key: &busbar_api::VirtualKey,
    admitted: &'a super::receive::Admitted,
    target: &'a str,
    grant: super::creds::EgressGrant<'a>,
    rpc_id: &serde_json::Value,
    resource: &str,
    actor: &str,
    now: u64,
) -> Result<
    (
        String,
        Option<super::creds::OutboundCredential>,
        super::creds::EgressGrant<'a>,
    ),
    Option<Box<Response>>,
> {
    if target == admitted.dispatch.agent_id {
        return Ok((
            admitted.dispatch.backend_url.clone(),
            admitted.outbound_cred.clone(),
            grant,
        ));
    }
    let Some((url, cred)) = member_facts(plane, target) else {
        return Err(None);
    };
    match super::creds::authorise_egress(key, target, now) {
        Ok(g) => Ok((url, cred, g)),
        Err(e) => {
            crate::admin::audit::AUDIT.record_by(
                super::receive::AUDIT_ACTION,
                resource,
                crate::admin::audit::OUTCOME_REJECTED,
                actor,
            );
            Err(Some(Box::new(
                (
                    axum::http::StatusCode::FORBIDDEN,
                    axum::Json(super::rpcerror::body(
                        rpc_id,
                        super::rpcerror::A2aError::UnsupportedOperation,
                        e.to_string(),
                    )),
                )
                    .into_response(),
            )))
        }
    }
}

/// Render the walk's PIN-MISMATCH refusal: not an availability fact — the operator's
/// same-deployment claim failed busbar's check — so it carries the walk's own wording and no
/// `Retry-After`, but the task is equally NOT ACCEPTED and the id still resolves.
#[allow(clippy::too_many_arguments)] // the refusal's own facts, no more.
pub(super) fn render_pin_mismatch(
    seam: &Arc<dyn super::relay::RelaySeam>,
    rpc_id: &serde_json::Value,
    task_id: &str,
    request_id: &str,
    addressed: bool,
    now: u64,
    reason: String,
) -> Response {
    diag_debug!(
        A2A_POOL_NOT_INTERCHANGEABLE,
        task = %task_id,
        %reason,
        "a2a: the pool's members are not interchangeable; the submission is not accepted"
    );
    if !addressed {
        match crate::plane::taskstore::TASKS.transition(
            task_id,
            super::task::TaskState::Rejected,
            now,
            request_id,
        ) {
            Ok(task) => super::receive::notify_push(seam, task),
            Err(e) => {
                // Error-once latch: a store that refuses the `rejected` transition is a STABLE
                // condition (a store outage persists across every refused submission), and this
                // path runs per request. Error on the TRANSITION into the failing state; hold
                // subsequent failures at debug so a store outage cannot spam the log.
                static PIN_REFUSAL_UNRECORDED_WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !PIN_REFUSAL_UNRECORDED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    diag_error!(A2A_PIN_REFUSAL_UNRECORDED, task = %task_id, error = %e, "a2a: a pin-refused task could not be recorded as rejected");
                } else {
                    diag_debug!(A2A_PIN_REFUSAL_UNRECORDED, task = %task_id, error = %e, "a2a: a pin-refused task could not be recorded as rejected");
                }
            }
        }
    }
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(super::rpcerror::about_task(
            rpc_id,
            super::rpcerror::A2aError::UnsupportedOperation,
            reason,
            task_id,
        )),
    )
        .into_response()
}

/// `GetExtendedAgentCard` / `agent/getAuthenticatedExtendedCard` — BUSBAR'S OWN CARD, for a caller
/// that has authenticated.
///
/// [`super::serve::extended_card`] carries the argument for what this publishes and why it is the
/// caller's catalogue rather than a merge across upstreams. What is decided HERE is the one thing
/// that needs the request: WHICH agents are this caller's, and it is answered by
/// [`super::registry::inbound_catalogue`] — the same judgement that decides dispatch, so the card
/// cannot name an agent a submission would refuse.
///
/// THE EMPTY TASK SHAPE, deliberately. The catalogue's structural filter narrows a set to the
/// agents that can accept a PARTICULAR task, and this request is not a task: it asks what this
/// caller may reach at all. Passing a shape here would silently drop every agent that cannot serve
/// whatever shape was invented.
pub(super) fn extended_agent_card(
    app: &App,
    key: &busbar_api::VirtualKey,
    rpc_id: &serde_json::Value,
) -> Response {
    let Some(plane) = app.a2a.as_ref() else {
        return super::words::plane_absent();
    };
    let Some(public_url) = plane.public_url() else {
        return super::receive::no_receiving_side();
    };
    let signer = app.governance.as_ref().and_then(|g| g.a2a_card_signer());

    // NOTHING FRONTED AT ALL is the one shape A2A has a specific error for: the card declares the
    // capability (it is a property of the binary, and busbar always has this verb) and the
    // deployment has no extended content for anybody. SPEC 3.1.11 binds that to
    // `ExtendedAgentCardNotConfiguredError`, so it is answered rather than dressed up as an empty
    // card — an empty card would say "you may reach nothing", which is a statement about the CALLER
    // and is a different and misleading answer.
    //
    // A caller entitled to none of several configured agents DOES get the empty card, and the
    // distinction is deliberate: that is a statement about that caller's grants, which is exactly
    // what the caller is entitled to be told.
    let caller = crate::catalogue::Caller {
        key: Some(key),
        now: crate::store::now(),
        generation: crate::trust::validate::Generations::at_admission(plane.generation()),
    };
    let anything = super::registry::Wanted::default();
    let card = plane.with_registrations(|regs| {
        if regs.is_empty() {
            return None;
        }
        // THE EMPTY TASK SHAPE, deliberately. The structural filter narrows a set to the agents
        // that can accept a PARTICULAR task, and this request is not a task: it asks what this
        // caller may reach at all. Passing a shape here would silently drop every agent that cannot
        // serve whatever shape was invented.
        let entitled: Vec<super::serve::EntitledAgent<'_>> =
            super::registry::entitled_agents(&caller, regs, &anything);
        Some(super::serve::extended_card(
            public_url,
            &entitled,
            signer.as_ref(),
        ))
    });

    match card {
        None => super::rpcerror::respond(
            rpc_id,
            super::rpcerror::A2aError::ExtendedAgentCardNotConfigured,
            "this deployment fronts no agents, so there is no extended agent card to serve",
        ),
        Some(Ok(doc)) => {
            use axum::response::IntoResponse as _;
            (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": doc,
                })),
            )
                .into_response()
        }
        // A card busbar cannot build is a refusal, not a hollow document. The failures that reach
        // here are a `public_url` that will not parse and a signing key that will not sign, and
        // both would otherwise publish a card asserting something busbar cannot stand behind.
        Some(Err(e)) => {
            diag_warn!(A2A_EXTENDED_CARD_BUILD_FAILED, error = %e, "a2a: could not build the extended agent card");
            super::rpcerror::respond(
                rpc_id,
                super::rpcerror::A2aError::Internal,
                "the extended agent card could not be built",
            )
        }
    }
}

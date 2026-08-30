// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR AS A CLIENT ON A VERB IT ALSO ANSWERS ITSELF.
//!
//! `super::local` answers six verbs without a hop, and every argument it gives for doing so still
//! stands: the ANSWER is a fact about busbar. What follows is the OTHER half of two of those
//! arguments, which was missing and whose absence was a functional hole rather than a caution.
//!
//! * A push-notification config is busbar's to hold — and a backend that was never told anything
//!   never reported anything, so a task interrupted and finished OUT OF BAND delivered nothing at
//!   all to a caller that had registered a callback precisely so it would not have to poll. So
//!   busbar SUBSTITUTES: it registers its OWN callback with the backend and holds the caller's. See
//!   `super::pushback`.
//! * `ListTasks` is answered from busbar's own store — and that store holds THE LAST STATE THE
//!   BACKEND REPORTED, which `super::local` says out loud is not a live poll. So busbar asks the
//!   backend what it now holds and refreshes the rows it can match, and the sentence stops being a
//!   limitation the caller has to know about.
//!
//! Neither is a second path to a backend. Both compose a document and hand it to the ONE relay,
//! through the ONE egress gate, over the binding the registration's own verified card declares.

use std::collections::HashMap;
use std::sync::Arc;

use super::receive::{notify_push, Admitted};
use busbar_substrate::diag_warn;
use busbar_substrate::diagnostics::{A2A_OUTBOUND_CRED_UNLEASED, A2A_PUSH_REARM_FAILED};

/// EVERYTHING ONE BUSBAR-ORIGINATED HOP NEEDS that is neither the document nor the verb.
///
/// The twin of `super::receive`'s `HopContext`, and deliberately smaller: a hop busbar originates has no caller
/// waiting on it, no task identity to substitute into the answer and no stream to re-frame. What it
/// does have is every gate a relayed hop has, because they are the same gates.
struct Originated {
    seam: Arc<dyn super::relay::RelaySeam>,
    gate: Arc<dyn super::relay::DelegationGate>,
    /// BUSBAR'S OWN credential for this backend, minted from the egress grant. The grant is the only
    /// way to construct one, so a call site that skipped the gate does not compile.
    lease: Option<super::creds::Lease>,
    framing: &'static dyn super::relay::OutboundFraming,
    policy: super::fetch::FetchPolicy,
    agent_id: String,
    backend_url: String,
    admitted_generation: u64,
    a2a_version: &'static str,
    now_ms: u64,
}

/// ASK THE ONE EGRESS GATE, MINT THE LEASE, AND RESOLVE THE BINDING — or `None`, having said in the
/// log why busbar will not originate this hop.
///
/// `None` on every refusal rather than an error type, because there is exactly one thing every
/// caller does with a refusal here: nothing. These hops are busbar's own housekeeping and the
/// CALLER's answer is already decided and already correct; a backend busbar may not reach leaves the
/// customer exactly where they were before this existed, never with a failed request.
fn originate(
    engine_host: &dyn busbar_substrate::plane_host::EngineHost,
    plane: &Arc<super::plane::A2aPlane>,
    admitted: &Admitted,
    key: &busbar_api::VirtualKey,
    a2a_version: &'static str,
    now: u64,
) -> Option<Originated> {
    // ── THE ONE EGRESS GATE, ASKED FOR THIS HOP. The local verb was answered before it because a
    //    locally-answered verb spends no credential of busbar's. This one does, so the question is
    //    asked here rather than assumed from the fact that the call was admitted.
    let grant = match super::creds::authorise_egress(key, &admitted.dispatch.agent_id, now) {
        Ok(g) => g,
        Err(e) => {
            tracing::info!(
                agent = %admitted.dispatch.agent_id, error = %e,
                "a2a: busbar did not make its own hop to this agent"
            );
            return None;
        }
    };
    let now_ms = now.saturating_mul(1_000);
    let resolver = engine_host.a2a_secret_resolver();
    let lease = match admitted.outbound_cred.as_ref() {
        Some(cred) => match super::creds::mint_from(&grant, cred, resolver.as_ref(), now_ms) {
            Ok(lease) => Some(lease),
            Err(e) => {
                diag_warn!(A2A_OUTBOUND_CRED_UNLEASED, agent = %admitted.dispatch.agent_id, error = %e, "a2a: the outbound credential could not be leased");
                return None;
            }
        },
        None => None,
    };
    // WHICH BINDING, off the registration's own verified card — the same lookup the relayed hop
    // makes, never a branch and never a default. A card declaring a binding this build cannot speak
    // means busbar does not originate here either.
    let binding = super::relay::binding_of(
        plane
            .with_registrations(|regs| {
                regs.iter()
                    .find(|r| r.agent_id == admitted.dispatch.agent_id)
                    .and_then(|r| r.cached_card.clone())
            })
            .as_ref(),
    );
    let Some(framing) = super::relay::framing_for(&binding) else {
        tracing::info!(
            agent = %admitted.dispatch.agent_id, binding = %binding,
            "a2a: busbar cannot originate a hop over a binding it does not speak"
        );
        return None;
    };
    Some(Originated {
        seam: plane.relay_seam(),
        gate: Arc::new(super::plane::LiveGate(Arc::clone(plane))),
        lease,
        framing,
        policy: plane.fetch_policy_for(&admitted.dispatch.agent_id),
        agent_id: admitted.dispatch.agent_id.clone(),
        backend_url: admitted.dispatch.backend_url.clone(),
        admitted_generation: admitted.generation,
        a2a_version,
        now_ms,
    })
}

/// ONE OPERATION BUSBAR ORIGINATES, on whichever of A2A's three bindings this backend speaks.
///
/// Synchronous and blocking, like [`super::relay::relay`] itself, and called from inside a
/// `spawn_blocking` for the reason `unary_hop` states: the seam is the card fetch's transport and it
/// blocks a thread per hop.
///
/// EVERY GATE IS THE SAME GATE — see [`Originated`], which is the only way to obtain the arguments.
/// Nothing here is a second path; it is the one path, carrying a document busbar composed rather
/// than a document a caller sent.
fn issue_originated(
    method: &'static str,
    params: serde_json::Value,
    at: &Originated,
) -> Result<super::relay::RelayReply, super::relay::RelayRefusal> {
    // THE ID OF A REQUEST NOBODY ELSE IS WAITING ON. busbar originated this hop, so there is no
    // caller id to echo; it is a fixed string that says so, for the same reason
    // `super::rest::REST_RPC_ID` is one — the shared response reader requires a string or a number,
    // and a generated value would suggest a multiplexing this hop does not have.
    let rpc_id = serde_json::Value::String(ORIGINATED_RPC_ID.to_string());
    let envelope = serde_json::json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": method,
        "params": params,
    });
    let body = serde_json::to_vec(&envelope).unwrap_or_default();
    super::relay::relay(
        &super::relay::RelayCall {
            agent_id: &at.agent_id,
            backend_url: &at.backend_url,
            lease: at.lease.as_ref(),
            gate: at.gate.as_ref(),
            admitted_generation: at.admitted_generation,
            body: &body,
            rpc_id: &rpc_id,
            policy: &at.policy,
            a2a_version: at.a2a_version,
            framing: at.framing,
            // The originate direction is scoped OUT of the breaker unit (the audit's own table row);
            // `None` admits everything and records nothing (the breaker seam is never reached).
            breakers: None,
            // No breaker cell here, so no admit to re-home and no host seam to thread.
            host: None,
            host_scope: None,
            admission: busbar_plugin::hot::AdmissionId::NONE,
        },
        at.seam.as_ref(),
        at.now_ms,
    )
}

/// The `id` every busbar-originated hop carries. See [`issue_originated`].
const ORIGINATED_RPC_ID: &str = "busbar-originated";

/// MIRROR THE CALLER'S PUSH-CONFIG VERB ONTO BUSBAR'S OWN REGISTRATION AT THE BACKEND.
///
/// One rule, four verbs: whatever the caller did to the config busbar holds for it, busbar does to
/// the config BUSBAR holds at the backend. A create arms the backend, a delete disarms it, and a
/// read reconciles — because busbar's answer to a `get` asserts that this callback will fire, and
/// that assertion is only true while busbar's own registration is still live at the backend. A read
/// that finds it gone RE-ARMS, which is the only reason issuing the read is worth anything.
///
/// BEST EFFORT, ALWAYS LOGGED, NEVER FATAL. The caller's answer is already decided and is about
/// busbar's own record, which is correct whatever the backend says.
#[allow(clippy::too_many_arguments)] // plumbing: each arg is an independent request input
pub(super) async fn mirror_push_config(
    engine_host: &Arc<dyn busbar_substrate::plane_host::EngineHost>,
    admitted: &Admitted,
    key: &busbar_api::VirtualKey,
    method: &'static str,
    task: &super::task::Task,
    a2a_version: &'static str,
    now: u64,
) {
    let Some(plane) = crate::a2a::runtime_arc_of(engine_host) else {
        return;
    };
    // THE ADDRESS BUSBAR OFFERS, or nothing at all. `callback_url` refuses a deployment with no
    // receiving side and refuses a PLAINTEXT one — see its own note for why there is no knob.
    let Some(our_url) = plane.public_url().and_then(super::pushback::callback_url) else {
        tracing::debug!(
            task = %task.task_id,
            "a2a: no https public url, so busbar registered no callback of its own with the agent"
        );
        return;
    };
    // THE BACKEND'S OWN NAME FOR THIS TASK. busbar's id names a row the backend has never heard of,
    // so a registration addressed with it would be refused — or, worse, accepted against nothing.
    // No mapping means busbar has not yet learnt the backend's id for this work, and there is
    // nothing to address until it has.
    // THE TASK'S OWN PRINCIPAL. Not a bypass of the scoped lookup — the owner is admitted by it by
    // definition — and passing it rather than reaching for an unscoped variant is what keeps there
    // being only one lookup for a future caller to find.
    let Some(backend_task) = super::idmap::backend_id_for(&task.principal, &task.task_id) else {
        tracing::debug!(
            task = %task.task_id,
            "a2a: the backend has not yet named this task, so there is no registration to mirror"
        );
        return;
    };
    // A TASK BUSBAR ALREADY HOLDS AS TERMINAL IS NOT ARMED: that would be registering a webhook for
    // an event that cannot happen, and handing a backend a live capability for finished work.
    if !super::pushback::worth_registering(task.state) {
        return;
    }
    let Some(token) = super::pushback::mint(&task.task_id) else {
        return;
    };
    let Some(at) = originate(
        engine_host.as_ref(),
        &plane,
        admitted,
        key,
        a2a_version,
        now,
    ) else {
        return;
    };
    let busbar_task = task.task_id.clone();

    let _ = tokio::task::spawn_blocking(move || {
        let create = super::pushback::create_params(&backend_task, &our_url, &token);
        // ONE PARAMS SHAPE PER REQUEST SHAPE. See `pushback::list_params`: a `list` names the task
        // and no config, and a spare member on a `GET` is a refusal on the HTTP+JSON leg.
        let params = match method {
            m if m == super::rest::method::CREATE_PUSH_CONFIG => create.clone(),
            m if m == super::rest::method::LIST_PUSH_CONFIGS => {
                super::pushback::list_params(&backend_task)
            }
            _ => super::pushback::config_params(&backend_task),
        };
        let outcome = issue_originated(method, params, &at);
        // ── THE RECONCILIATION. A read that does not find busbar's own registration — because the
        //    backend refused it, dropped it, or was restarted without it — is a read that has just
        //    discovered the caller's callback armed at busbar and dead at the agent. Re-arming is
        //    what makes issuing the read worth the hop.
        let is_read = method == super::rest::method::GET_PUSH_CONFIG
            || method == super::rest::method::LIST_PUSH_CONFIGS;
        let drifted = match &outcome {
            Ok(reply) => {
                is_read
                    && !reply
                        .result
                        .to_string()
                        .contains(&super::pushback::config_id(&backend_task))
            }
            Err(e) => {
                tracing::info!(
                    agent = %at.agent_id, task = %busbar_task, method, error = %e,
                    "a2a: busbar's own push registration at the agent did not answer"
                );
                is_read
            }
        };
        if drifted {
            // ISSUE FIRST, then report what actually happened: the first cut logged "was re-made"
            // BEFORE issuing and discarded the result, so a re-arm the agent refused read in the
            // log as a success — the exact armed-at-busbar-dead-at-the-agent state the
            // reconciliation exists to close, reported as closed.
            match issue_originated(super::rest::method::CREATE_PUSH_CONFIG, create, &at) {
                Ok(_) => tracing::info!(
                    agent = %at.agent_id, task = %busbar_task,
                    "a2a: busbar's own push registration was gone at the agent, and was re-made"
                ),
                Err(e) => diag_warn!(
                    A2A_PUSH_REARM_FAILED,
                    agent = %at.agent_id, task = %busbar_task, error = %e,
                    "a2a: busbar's own push registration was gone at the agent, and the re-arm \
                     FAILED — the caller's callback stays dead at the agent until a later \
                     reconciliation succeeds"
                ),
            }
        }
    })
    .await;
}

/// REFRESH WHAT BUSBAR LAST SAW, FROM THE AGENT THAT IS DOING THE WORK — busbar's `ListTasks` as a
/// CLIENT.
///
/// `super::local` is unchanged and is still the answer: busbar issues its own task ids, the
/// backend's names for the same work are never client-visible, and busbar's own rows are the only
/// set that answers the question the caller asked. What it also said, out loud, was that those rows
/// carry THE LAST STATE THE BACKEND REPORTED and are not a live poll. This is the poll — so the
/// caller's list is refreshed from the agent immediately before it is rendered, and a task the
/// backend moved on out of band stops being invisible until somebody happens to read it.
///
/// **NOTHING FROM THE ANSWER IS RENDERED TO THE CALLER, AND THAT IS THE SCOPING RULE.** The only
/// thing taken from the backend's list is a STATE, and only for a row busbar already holds, that
/// this principal already owns, on this agent, whose backend id busbar itself recorded. A task the
/// backend names that busbar cannot match is IGNORED — so a backend enumerating every task busbar
/// ever opened on it, across every tenant, moves nothing and shows nobody anything. `list_tasks`
/// then renders busbar's own scoped rows exactly as it always did.
pub(super) async fn refresh_listed_tasks(
    engine_host: &Arc<dyn busbar_substrate::plane_host::EngineHost>,
    admitted: &Admitted,
    key: &busbar_api::VirtualKey,
    principal: &str,
    a2a_version: &'static str,
    now: u64,
) {
    let Some(plane) = crate::a2a::runtime_arc_of(engine_host) else {
        return;
    };
    // THE ROWS THIS CALLER OWNS ON THIS AGENT, and the backend's name for each. Built BEFORE the
    // hop, because it is also the whitelist: an id that is not in here is an id the answer cannot
    // move.
    let ours: HashMap<String, String> = busbar_substrate::plane_host::task_reader()
        .map(|reader| reader.list_scoped(principal))
        .unwrap_or_default()
        .iter()
        // The engine is `TaskRow`-neutral; convert back to the canonical `Task` at this A2A boundary
        // so the `is_terminal` / field reads below stay codec-side. Working-set rows are always
        // readable.
        .filter_map(|r| super::task::Task::from_row(r).ok())
        .filter(|t| t.agent_id == admitted.dispatch.agent_id && !t.state.is_terminal())
        .filter_map(|t| {
            let backend = super::idmap::backend_id_for(&t.principal, &t.task_id)?;
            Some((backend, t.task_id))
        })
        .collect();
    if ours.is_empty() {
        // Nothing this hop could teach busbar. Not making it is not a shortcut: it is refusing to
        // ask a backend to enumerate its work for a caller with nothing outstanding on it.
        return;
    }
    let Some(at) = originate(
        engine_host.as_ref(),
        &plane,
        admitted,
        key,
        a2a_version,
        now,
    ) else {
        return;
    };

    // A SECOND HANDLE ON THE SEAM, taken before the hop moves the rest: a state this refresh
    // records is a transition like any other, and a transition on a task with a callback is a
    // delivery owed. A refresh that recorded the move and did not deliver it would be the same
    // silence this whole area exists to remove, one function further along.
    let seam = Arc::clone(&at.seam);
    let reply = tokio::task::spawn_blocking(move || {
        // NO PAGING MEMBERS. busbar is not paging the backend's list on the caller's behalf — the
        // caller's own page is cut from busbar's rows by `local::list_tasks` — so this asks for the
        // backend's default page and takes what it can match from it.
        issue_originated(super::rest::method::LIST_TASKS, serde_json::json!({}), &at)
    })
    .await;
    let Ok(Ok(reply)) = reply else {
        tracing::debug!(
            agent = %admitted.dispatch.agent_id,
            "a2a: the agent did not answer a task list, so busbar's own rows stand unrefreshed"
        );
        return;
    };

    // BOTH SHAPES. A2A v1.0 wraps the list under `tasks`; the v0.3 spelling answers a bare array.
    let listed = reply
        .result
        .get("tasks")
        .and_then(serde_json::Value::as_array)
        .or_else(|| reply.result.as_array())
        .cloned()
        .unwrap_or_default();
    // Each matched observation is a transition through the durable `task_event` seam, driven over the
    // admitted `EngineHost` — its `task_journal_write` mints the transient host per call.
    for entry in listed {
        let Some(backend_id) = entry.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(busbar_id) = ours.get(backend_id) else {
            // NOT THIS CALLER'S, or not this agent's, or not a task busbar opened. Ignored in
            // silence: this is the ordinary case for a shared backend and it is exactly what stops
            // one tenant's list from moving another tenant's row.
            continue;
        };
        // STRICT. An entry whose state busbar cannot read taught it nothing, and `reported_task_state`
        // would have answered `Working` for it — moving a submitted task on the strength of a token
        // nobody understood.
        let Some(state) = super::relay::read_task_state(&entry) else {
            continue;
        };
        // THROUGH THE SAME TRANSITION TABLE AND THE SAME PER-TASK CHAIN as every other observation.
        // A refusal is the table doing its job — a backend re-reporting a state busbar already
        // holds, or one the table forbids — and is not an error to raise at a caller who asked for
        // a list.
        match engine_host
            .task_journal_write(
                busbar_id,
                busbar_substrate::plane_host::TaskWrite::Transition {
                    to_state: state.as_str(),
                },
                now,
                busbar_id,
            )
            .and_then(|row| super::task::Task::from_row(&row).map_err(|e| e.to_string()))
        {
            Ok(task) => notify_push(Arc::clone(engine_host), &seam, task),
            Err(e) => {
                tracing::trace!(task = %busbar_id, error = %e, "a2a: a listed state was not recordable")
            }
        }
    }
}

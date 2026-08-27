// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RECEIVING: the inbound credential kind, the authorization decision, and the dispatch
//! target.
//!
//! ## The three layers, in this order, and the order is the decision
//!
//! 1. AUTHENTICATE — the caller presents a busbar credential of kind `a2a_inbound`.
//! 2. AUTHORIZE — `scope_allowed("agent", agent_id)`: may this key invoke THIS fronted agent?
//! 3. DISPATCH — only now is a backend named.
//!
//! Authorization happens BEFORE the backend agent runs, which is the whole posture: a 403 that
//! arrives after the work is done is a 403 that has already cost the operator the work, and on this
//! plane the "work" may be a long-running task that reached down into L2 tools. [`authorize`]
//! therefore returns the dispatch target and nothing else returns one, so there is no path to a
//! backend that skipped the check.
//!
//! ## `a2a_inbound` is a new `kind` VALUE, not a new code path
//!
//! `CredentialMeta.kind` is an open string and `VirtualKey::scope_allowed` takes an open-string
//! kind whose cross-kind semantics are fail-closed and frozen. So a key that lists only `pool`
//! scopes acquires access to NO agents on upgrade — it acquires access to none of them, and an
//! operator must add entries to grant any. That is verified here by test rather than assumed, on
//! the way past.
//!
//! ## Enumeration is not a lesser question than invocation
//!
//! The catalogue and the invocation check ask the SAME question of the same key. A caller that can
//! list an agent it cannot invoke has learned that the agent exists, which is the first half of
//! every targeted attack on it, and the two answers coming from one function is what stops them
//! drifting apart.
//!
//! ## AND THE ORDER IS NOT THIS FILE'S ANY MORE
//!
//! Layer 2 above is one step of a four-step sequence — identity, grant, artifact, generation — that
//! every request on every plane passes through, and that sequence is
//! [`busbar_substrate::trust::validate::validate_request`]. This file used to write three of those steps out by
//! hand, as did the catalogue and the pre-socket relay gate, and nothing owned the order between
//! them; a fourth path that forgot one would have been a silent hole with no failing test, because
//! there was no site whose job the sequence was.
//!
//! What stays here is the AUTHENTICATION layer, the registration lookup, and the RENDERING — the
//! statuses and the words this plane answers with. The decision is core's.

use busbar_api::VirtualKey;

use busbar_substrate::trust::TrustState;

use super::registry::AgentRegistration;

/// The `CredentialMeta.kind` an inbound A2A caller's credential carries.
///
/// A new VALUE on the existing generalized credential type, which is the mechanism the inbound
/// A2A credential was always specified as. Not a new type, not a new table, not a new trait method — the repeatable-accretion
/// pattern that generalization exists to close off.
pub(crate) const CREDENTIAL_KIND_A2A_INBOUND: &str = "a2a_inbound";

/// The `ScopeRef` kind an agent grant is written under, inbound and outbound alike.
///
/// ONE kind for both directions, deliberately: "may this key invoke fronted agent X" and "may
/// fronted agent Y delegate to registered agent X" are both statements about an agent's name, and a
/// second kind would mean an operator granting one and being surprised by the other.
pub(crate) const SCOPE_KIND_AGENT: &str = "agent";

/// Why an inbound task was refused, and with what status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InboundRefusal {
    /// The presented credential is not of kind `a2a_inbound`. 401.
    WrongCredentialKind { presented: String },
    /// The key is disabled, tombstoned, or expired. 401.
    KeyNotLive { key_id: String },
    /// No such fronted agent. 404 — and it is a 404 for a key that could not have invoked it
    /// anyway, see [`InboundRefusal::status`].
    NoSuchAgent { agent_id: String },
    /// The key may not invoke this agent. 403, BEFORE the backend runs.
    NotInScope { key_id: String, agent_id: String },
    /// The agent exists and is not currently serving: suspended, quarantined, pending or in error.
    /// 503, because it is a statement about the agent rather than about the caller.
    NotServing {
        agent_id: String,
        state: TrustState,
        reason: Option<String>,
    },
}

impl InboundRefusal {
    /// The HTTP status this refusal presents as.
    ///
    /// `NoSuchAgent` is a 404 and `NotInScope` is a 403, which does leak existence to a caller who
    /// probes. That is deliberate and bounded: the catalogue already tells an authorized caller
    /// exactly which agents exist, the id is operator-chosen rather than secret, and returning 404
    /// for an unauthorized-but-real agent would mean an operator debugging a scope grant is shown
    /// "no such agent" for one they are looking at. The confusable case is the one that matters and
    /// it is not confusable: an agent that exists and is out of scope says so.
    pub(crate) fn status(&self) -> u16 {
        match self {
            InboundRefusal::WrongCredentialKind { .. } | InboundRefusal::KeyNotLive { .. } => 401,
            InboundRefusal::NoSuchAgent { .. } => 404,
            InboundRefusal::NotInScope { .. } => 403,
            InboundRefusal::NotServing { .. } => 503,
        }
    }
}

impl std::fmt::Display for InboundRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InboundRefusal::WrongCredentialKind { presented } => write!(
                f,
                "this endpoint accepts a busbar credential of kind `{CREDENTIAL_KIND_A2A_INBOUND}`; \
                 the presented credential is of kind `{presented}`"
            ),
            InboundRefusal::KeyNotLive { key_id } => {
                write!(f, "key `{key_id}` is not live")
            }
            InboundRefusal::NoSuchAgent { agent_id } => {
                write!(f, "no fronted agent `{agent_id}`")
            }
            InboundRefusal::NotInScope { key_id, agent_id } => write!(
                f,
                "key `{key_id}` is not granted `{SCOPE_KIND_AGENT}:{agent_id}`"
            ),
            InboundRefusal::NotServing {
                agent_id,
                state,
                reason,
            } => match reason {
                Some(r) => write!(f, "fronted agent `{agent_id}` is not serving ({state:?}): {r}"),
                None => write!(f, "fronted agent `{agent_id}` is not serving ({state:?})"),
            },
        }
    }
}

/// AN AUTHORIZED INBOUND TASK: who is paying, and where it goes.
///
/// The only way to obtain one is [`authorize`], and it is the only thing that names a backend. A
/// dispatch that skipped the check is therefore not a state this type can be in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Dispatch {
    /// The fronted agent the task is for.
    pub(crate) agent_id: String,
    /// The LOCAL backend endpoint. Never returned to the caller.
    pub(crate) backend_url: String,
    /// The key whose budget this task, and its downstream L2 MCP spend, bills.
    pub(crate) billed_key_id: String,
}

/// AUTHENTICATE, AUTHORIZE, THEN NAME A BACKEND.
///
/// `credential_kind` is what the verify path resolved the presented credential as. It is an
/// argument rather than something re-derived here, because the one place that knows how a caller
/// authenticated is the place that authenticated them.
pub(crate) fn authorize(
    key: &VirtualKey,
    credential_kind: &str,
    agent_id: &str,
    registrations: &[AgentRegistration],
    generation: u64,
    now: u64,
) -> Result<Dispatch, InboundRefusal> {
    if credential_kind != CREDENTIAL_KIND_A2A_INBOUND {
        return Err(InboundRefusal::WrongCredentialKind {
            presented: credential_kind.to_string(),
        });
    }

    let found = registrations.iter().find(|r| r.agent_id == agent_id);
    // THE FAIL-CLOSED FLOOR stands in for a registration this deployment does not front, so the
    // ordered gate below is reached on EVERY path rather than short-circuited on one of them. It is
    // `Pending` and serves nothing, which is what the validator's artifact step then says — and this
    // function turns that into the 404 an unknown id has always answered.
    let floor = busbar_substrate::trust::Approval::registered();
    let never = busbar_substrate::trust::Sighting::Never;

    // AN UNKNOWN ID HAS NO SCOPE TO BE GRANTED ON, so the grant list for one is empty. That is not a
    // skipped step: the step runs and finds nothing to check, and the artifact step below refuses
    // the request a moment later. Keeping it empty is what preserves the 404-before-403 ordering
    // `InboundRefusal::status` reasons about — an operator debugging a scope grant must not be shown
    // "not in scope" for an agent that does not exist.
    let agent_scope = [busbar_substrate::trust::validate::Grant::Scope {
        kind: SCOPE_KIND_AGENT,
        name: agent_id,
    }];
    let grants: &[busbar_substrate::trust::validate::Grant] =
        if found.is_some() { &agent_scope } else { &[] };

    // THE ONE ORDERED GATE. Identity, then grant, then the agent's own state — including the
    // suspension, because the breaker trips on how the agent BEHAVES and an agent behaving badly
    // behaves badly for whoever reached it.
    if let Err(refusal) = busbar_substrate::trust::validate::validate_request(
        &busbar_substrate::trust::validate::Ask {
            principal: Some(key),
            now,
            grants,
            approval: found.map_or(&floor, |r| &r.approval),
            sighting: found.map_or(&never, |r| &r.sighting),
            // The wire names no skill at this layer; the catalogue is what matches a task shape against
            // one. An ask addressed to the registration itself has no capability to fingerprint.
            capability: None,
            // ADMISSION. There is no earlier snapshot for this request to have outlived, because this is
            // the one it is arriving on. The value is recorded and re-compared at the relay gate.
            generation: busbar_substrate::trust::validate::Generations::at_admission(generation),
        },
    ) {
        return Err(as_inbound_refusal(refusal, key, agent_id, found));
    }

    let reg = found.expect("the floor registration refuses at the artifact step");
    Ok(Dispatch {
        agent_id: reg.agent_id.clone(),
        backend_url: reg.backend_url.clone(),
        billed_key_id: key.id.clone(),
    })
}

/// RENDER the core refusal as this plane's own wire refusal. and in its status codes.
///
/// The DECISION is core's; only the wording and the status are this plane's. That split is why the
/// arms below map rather than re-derive: a second derivation here could disagree with the gate at
/// exactly the moment a request races a suspension.
fn as_inbound_refusal(
    refusal: busbar_substrate::trust::validate::Refusal,
    key: &VirtualKey,
    agent_id: &str,
    found: Option<&AgentRegistration>,
) -> InboundRefusal {
    use busbar_substrate::trust::validate::Refusal;
    match refusal {
        Refusal::IdentityNotLive { .. } => InboundRefusal::KeyNotLive {
            key_id: key.id.clone(),
        },
        Refusal::NotGranted { .. } | Refusal::EgressDenied { .. } => InboundRefusal::NotInScope {
            key_id: key.id.clone(),
            agent_id: agent_id.to_string(),
        },
        // The floor registration is the "no such agent" case, and it is the ONLY way to reach this
        // arm with nothing found.
        Refusal::NotServing { state, reason } => match found {
            None => InboundRefusal::NoSuchAgent {
                agent_id: agent_id.to_string(),
            },
            Some(_) => InboundRefusal::NotServing {
                agent_id: agent_id.to_string(),
                state,
                reason,
            },
        },
        // Unreachable at admission — the capability is `None` and the generation is compared against
        // itself — and answered rather than unwrapped, because "unreachable" is a claim about
        // today's arguments and this is a request path.
        Refusal::ArtifactDrifted { .. }
        | Refusal::Unobservable { .. }
        | Refusal::GenerationMoved { .. } => InboundRefusal::NotServing {
            agent_id: agent_id.to_string(),
            state: found.map_or(TrustState::Pending, AgentRegistration::trust_state),
            reason: Some(refusal.to_string()),
        },
    }
}

#[cfg(test)]
#[path = "tests/inbound_tests.rs"]
mod inbound_tests;

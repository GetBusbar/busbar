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

use busbar_api::VirtualKey;

use crate::trust::TrustState;

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
    now: u64,
) -> Result<Dispatch, InboundRefusal> {
    if credential_kind != CREDENTIAL_KIND_A2A_INBOUND {
        return Err(InboundRefusal::WrongCredentialKind {
            presented: credential_kind.to_string(),
        });
    }
    // A tombstoned key's row survives forever so billing and audit keep resolving it, which means
    // `is_live` is the check and a row's existence is not.
    if !key.is_live() || !key.enabled || key.expires_at.is_some_and(|exp| now >= exp) {
        return Err(InboundRefusal::KeyNotLive {
            key_id: key.id.clone(),
        });
    }

    let Some(reg) = registrations.iter().find(|r| r.agent_id == agent_id) else {
        return Err(InboundRefusal::NoSuchAgent {
            agent_id: agent_id.to_string(),
        });
    };

    // AUTHORIZATION, BEFORE THE BACKEND. The same call the catalogue makes.
    if !key.scope_allowed(SCOPE_KIND_AGENT, agent_id) {
        return Err(InboundRefusal::NotInScope {
            key_id: key.id.clone(),
            agent_id: agent_id.to_string(),
        });
    }

    // AND THE AGENT'S OWN STATE. A suspended fronted agent is refused inbound as well as outbound:
    // the breaker trips on how the agent BEHAVES, and an agent behaving badly behaves badly for
    // whoever reached it.
    if !reg.is_delegable() {
        return Err(InboundRefusal::NotServing {
            agent_id: agent_id.to_string(),
            state: reg.trust_state(),
            reason: reg.suspension_reason().map(str::to_string),
        });
    }

    Ok(Dispatch {
        agent_id: reg.agent_id.clone(),
        backend_url: reg.backend_url.clone(),
        billed_key_id: key.id.clone(),
    })
}

#[cfg(test)]
#[path = "tests/inbound_tests.rs"]
mod inbound_tests;

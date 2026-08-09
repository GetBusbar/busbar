// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CATALOGUE: which agents a given caller may even SEE.
//!
//! Not "discovery". The vocabulary is CATALOGUE and DISPATCH, and the split is load-bearing:
//! catalogue is AUTHORIZATION plus STRUCTURAL FITNESS and is owned by core; dispatch ordering is
//! ordinary pool machinery. Nothing here is a hook, nothing here is a score, and nothing here reads
//! task content.
//!
//! ## Four conjunctive filters, and they are conjunctive
//!
//! 1. **Trusted.** Only an `Approved` registration is ever a candidate. `Pending`, `Quarantined`,
//!    `Suspended` and `Error` are not, and that is [`super::registry::AgentRegistration::is_delegable`],
//!    which derives from the lifecycle rather than reading a stored flag.
//! 2. **Scope-granted.** `scope_allowed("agent", agent_id)`. No hook on this path, no filter verb,
//!    no auto-tagging, no tag conventions. TAGS GROUP, IDENTITY IDENTIFIES.
//! 3. **Capability-matched.** A2A agents are NOT FUNGIBLE: an arbitrary agent cannot serve an
//!    arbitrary task, so an unfiltered candidate set is unsafe in a way an LLM lane set is not.
//!    This is STRUCTURAL matching — an agent either can accept this shape of task or it cannot —
//!    and never a score.
//! 4. **Not suspended.** Folded into (1) rather than checked twice: `Suspended` outranks every
//!    other state in the lifecycle, so a suspended registration is not `Approved` and is already
//!    out. Two checks would be two things to keep in agreement.
//!
//! ## Structural matching reads TYPES, never prose
//!
//! [`TaskShape`] carries a skill id, requested capabilities and input/output MIME modes. There is
//! deliberately no field on it for text: the dispatch decision is content-blind, and the way that
//! is enforced is that the decision function is not given any content to read.
//!
//! Content-blindness defeats the PROSE attack, not the TYPED-FIELD attack: `skills[]` and
//! `capabilities` are upstream-authored, and what bounds them is that only an operator-approved
//! `Approved` registration is ever a candidate. Operator approval is a capability VOUCH as well as
//! an authenticity check, and the anomaly breaker is what catches an agent that betrays the vouch.

// PARTLY UNMOUNTED. `inbound_catalogue` and `explain` are on the receiving hot path and driven by
// `ingress::admit`; `delegation_catalogue` is the DELEGATING direction's half and has no caller
// because nothing yet delegates outward. The two differ only by the egress-grant filter, which is
// exactly why they live together — and why the unused one is not deleted.
#![cfg_attr(not(test), allow(dead_code))]

use busbar_api::VirtualKey;

use super::card::{AgentCard, CardError};
use super::inbound::SCOPE_KIND_AGENT;
use super::registry::AgentRegistration;

/// THE SHAPE OF A TASK, as the catalogue is allowed to see it.
///
/// Typed metadata only. There is no `text` member and there is not going to be one: a field for
/// prose is a field somebody eventually matches on, and the moment selection reads prose the
/// upstream's free text is deciding where tasks go.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TaskShape {
    /// The skill being asked for, by `id`. `None` means "any skill this agent declares".
    pub(crate) skill: Option<String>,
    /// Protocol features the task REQUIRES (`streaming`, `pushNotifications`, …). An agent that
    /// does not declare a required feature cannot accept this shape of task.
    pub(crate) requires_streaming: bool,
    pub(crate) requires_push_notifications: bool,
    /// MIME modes the caller will SEND and the modes it can ACCEPT back.
    pub(crate) input_modes: Vec<String>,
    pub(crate) output_modes: Vec<String>,
}

/// Why a registration is not in a caller's catalogue. Returned rather than merely filtered, because
/// "why can this key not see the planner" is the question an operator actually asks, and a filter
/// that only ever returns survivors cannot answer it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Excluded {
    /// Not `Approved`: pending, quarantined, suspended or in error.
    NotTrusted(crate::trust::TrustState),
    /// The caller's key does not grant `agent:<id>`.
    NotInScope,
    /// The FRONTED agent asking is not on this registration's `egress_scopes`. Delegation only.
    NoEgressGrant,
    /// The card declares no skill with the requested id.
    SkillNotDeclared(String),
    /// The card does not declare a capability the task requires.
    CapabilityNotDeclared(&'static str),
    /// The card accepts none of the modes the caller will send, or produces none it can accept.
    ModesIncompatible,
    /// There is no cached card, so there is nothing to match against. An agent whose card has never
    /// been captured is not a candidate, whatever its approval says.
    NoCachedCard,
    /// The cached card cannot be read.
    Unreadable(CardError),
}

/// One catalogue row: the registration, and the skill it matched.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Candidate<'a> {
    pub(crate) registration: &'a AgentRegistration,
    /// The skill id the task shape matched. `None` when the task named no skill.
    pub(crate) matched_skill: Option<String>,
}

/// JUDGE ONE REGISTRATION for one caller and one task shape. The single place the four filters are
/// applied, so the inbound catalogue, the delegation catalogue and the invocation check cannot
/// drift apart.
fn judge<'a>(
    registration: &'a AgentRegistration,
    key: &VirtualKey,
    shape: &TaskShape,
    delegating_from: Option<&str>,
) -> Result<Candidate<'a>, Excluded> {
    // (1) and (4): trust, which already subsumes suspension.
    if !registration.is_delegable() {
        return Err(Excluded::NotTrusted(registration.trust_state()));
    }
    // (2) scope.
    if !key.scope_allowed(SCOPE_KIND_AGENT, &registration.agent_id) {
        return Err(Excluded::NotInScope);
    }
    // (2b) EGRESS, on the delegation side only: which fronted agents may delegate HERE. Empty is
    // NONE, never everyone.
    if let Some(from) = delegating_from {
        if !registration.egress_scopes.iter().any(|s| s == from) {
            return Err(Excluded::NoEgressGrant);
        }
    }
    // (3) structural fitness against the CACHED card.
    let document = registration
        .cached_card
        .as_ref()
        .ok_or(Excluded::NoCachedCard)?;
    let card = super::card::parse(document).map_err(Excluded::Unreadable)?;
    let matched_skill = match_shape(&card, shape)?;

    Ok(Candidate {
        registration,
        matched_skill,
    })
}

/// STRUCTURAL MATCHING. An agent either can accept this shape of task or it cannot.
fn match_shape(card: &AgentCard, shape: &TaskShape) -> Result<Option<String>, Excluded> {
    if shape.requires_streaming && !card.capabilities.streaming {
        return Err(Excluded::CapabilityNotDeclared("streaming"));
    }
    if shape.requires_push_notifications && !card.capabilities.push_notifications {
        return Err(Excluded::CapabilityNotDeclared("pushNotifications"));
    }

    let matched = match &shape.skill {
        None => None,
        Some(wanted) => {
            let skill = card
                .skills
                .iter()
                .find(|s| &s.id == wanted)
                .ok_or_else(|| Excluded::SkillNotDeclared(wanted.clone()))?;
            // A skill's own modes OVERRIDE the card defaults where it declares them, and fall back
            // to the defaults where it does not. Reading the skill's empty list as "accepts
            // nothing" would exclude every agent that sensibly declares its modes once.
            let inputs = pick(&skill.input_modes, &card.default_input_modes);
            let outputs = pick(&skill.output_modes, &card.default_output_modes);
            check_modes(shape, inputs, outputs)?;
            return Ok(Some(skill.id.clone()));
        }
    };

    check_modes(shape, &card.default_input_modes, &card.default_output_modes)?;
    Ok(matched)
}

fn pick<'a>(specific: &'a [String], fallback: &'a [String]) -> &'a [String] {
    if specific.is_empty() {
        fallback
    } else {
        specific
    }
}

/// The caller must be able to SEND something the agent accepts, and RECEIVE something the agent
/// produces. Both directions, because an agent that accepts the request and answers in a format the
/// caller cannot read has not served the task.
///
/// A caller that names no modes is not constraining the match: it has said nothing, and treating
/// silence as "accepts nothing" would empty every catalogue by default.
fn check_modes(
    shape: &TaskShape,
    agent_inputs: &[String],
    agent_outputs: &[String],
) -> Result<(), Excluded> {
    let compatible = |wanted: &[String], declared: &[String]| -> bool {
        wanted.is_empty() || declared.is_empty() || wanted.iter().any(|w| declared.contains(w))
    };
    if !compatible(&shape.input_modes, agent_inputs)
        || !compatible(&shape.output_modes, agent_outputs)
    {
        return Err(Excluded::ModesIncompatible);
    }
    Ok(())
}

/// RECEIVING: which LOCAL fronted agents this caller may see and invoke.
///
/// Order follows the registry's own, which is insertion-ordered from config, so an operator-facing
/// listing is deterministic rather than hash-ordered.
pub(crate) fn inbound_catalogue<'a>(
    key: &VirtualKey,
    registrations: &'a [AgentRegistration],
    shape: &TaskShape,
) -> Vec<Candidate<'a>> {
    registrations
        .iter()
        .filter_map(|r| judge(r, key, shape, None).ok())
        .collect()
}

/// DELEGATING: which registered agents THIS FRONTED AGENT may see as delegation
/// targets.
///
/// The extra filter over the inbound catalogue is the egress grant, which is the only structural
/// difference between the two directions on this path — receiving is a strict subset of delegating
/// minus the trust root, and this is where the subset relation is visible in code.
pub(crate) fn delegation_catalogue<'a>(
    from_agent: &str,
    key: &VirtualKey,
    registrations: &'a [AgentRegistration],
    shape: &TaskShape,
) -> Vec<Candidate<'a>> {
    registrations
        .iter()
        .filter_map(|r| judge(r, key, shape, Some(from_agent)).ok())
        .collect()
}

/// WHY a named registration is not in a caller's catalogue. The same judgement, with the reason
/// kept — for the admin surface and for the operator asking "why can this key not see the planner".
pub(crate) fn explain(
    registration: &AgentRegistration,
    key: &VirtualKey,
    shape: &TaskShape,
    delegating_from: Option<&str>,
) -> Result<(), Excluded> {
    judge(registration, key, shape, delegating_from).map(|_| ())
}

#[cfg(test)]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `AgentRegistration` ROW: one registered external agent, as the control plane holds it.
//!
//! ## This is a RECORD, not a second state machine
//!
//! The trust state, the changes queue and the dispatch gate are [`crate::trust`], reached through
//! the [`busbar_substrate::trust::Approval`] this record CARRIES. Nothing here re-derives any of them.
//! `tests/reuse_tests.rs::the_a2a_plane_declares_no_trust_state_of_its_own` reads this file, among
//! the plane's others, and fails on a re-declaration — so the discipline is machine-checked rather
//! than remembered.
//!
//! ## The overlay/store split is a property of the FIELDS, and it is spelled out per field
//!
//! Config is operator INTENT; the store is WHAT ACCUMULATES. That ruling is easy to agree with and
//! easy to violate one field at a time, so every field below is labelled with which side it is on.
//! The test `intent_and_accumulation_are_separable` takes the record apart along that line and
//! fails if a field cannot be assigned to one — which is what stops an approval quietly migrating
//! into the store where an admin write could rewrite history through it.
//!
//! ## Why `backend_url` is never client-visible
//!
//! A caller reaching a fronted agent talks to busbar. The real endpoint is the one thing busbar
//! must not publish, because publishing it is publishing the way around busbar. [`super::serve`]
//! rewrites it out of every served card; this record is where the value that gets rewritten lives.

// PARTLY UNMOUNTED. `trust_state`/`is_delegable` are consulted on every inbound request and by the
// sweep. `may_dispatch` takes a capability digest, which only a caller that has resolved a skill
// against a served card can supply — the relay leg, not mounted here.
#![cfg_attr(not(test), allow(dead_code))]

use serde_json::Value;

use busbar_substrate::catalogue::{Caller, CatalogueItem};
use busbar_substrate::trust::validate::Grant;
use busbar_substrate::trust::{Approval, Sighting, TrustState};

use super::anomaly;
use super::card::{AgentCard, CardError};
use super::inbound::SCOPE_KIND_AGENT;
use super::pin::CardPin;
use super::reverify;

/// The wire format a registration speaks. `JSONRPC` today; `GRPC` is out of scope until it exists,
/// and it is deliberately an enum arm rather than a free string so adding it is a decision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ProtocolBinding {
    #[default]
    JsonRpc,
    Grpc,
}

impl ProtocolBinding {
    pub(crate) fn label(self) -> &'static str {
        match self {
            ProtocolBinding::JsonRpc => "JSONRPC",
            ProtocolBinding::Grpc => "GRPC",
        }
    }
}

/// The release's default A2A protocol version, used by a registration that pins none.
pub(crate) const DEFAULT_PROTOCOL_VERSION: &str = "0.3.0";

/// ONE REGISTERED AGENT, as the control plane holds it: the operator's intent, the observations
/// that have accumulated against it, and nothing derived.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AgentRegistration {
    // ── INTENT (config overlay) ──────────────────────────────────────────────────────────────────
    /// busbar-local stable id. The value `scope_allowed("agent", …)` is asked about, so it is the
    /// operator's word and never anything the upstream supplied.
    pub(crate) agent_id: String,
    /// The REAL remote A2A endpoint. Never client-visible; see the module note.
    pub(crate) backend_url: String,
    /// PINNED per registration, because the well-known card path moved between revisions and a
    /// registration that follows whatever the upstream now claims has no pin at all.
    pub(crate) protocol_version: String,
    pub(crate) protocol_binding: ProtocolBinding,
    /// The operator's standing decision: the locked pin, the approved per-skill digests, the
    /// suspension. THE MACHINE'S TYPE, held, not copied.
    pub(crate) approval: Approval<CardPin>,
    /// The cadence, lowered from config by [`super::config::policy_for`].
    pub(crate) reverify: reverify::Policy,
    /// The breaker's trip points.
    pub(crate) thresholds: anomaly::Thresholds,
    /// WHICH FRONTED AGENTS MAY DELEGATE HERE. Egress policy, checked with the same `ScopeRef`
    /// mechanism as inbound authZ. Empty means no fronted agent may: the fail-closed floor, because
    /// the alternative reading of an empty list is "everyone", and that is a registration granting
    /// egress nobody wrote down.
    pub(crate) egress_scopes: Vec<String>,
    /// The outbound credential HANDLE and its lease. Never the secret; see [`super::creds`].
    pub(crate) outbound_cred: Option<super::creds::OutboundCredential>,
    /// `agents.<name>.allow_private:` — may this registration's endpoint be a private or loopback
    /// one, reached over plaintext. INTENT, carried on the record so the guard that acts on it and
    /// the operator's line of YAML are provably the same value; see
    /// [`super::fetch::FetchPolicy::allow_private`] for what it does and does not permit.
    pub(crate) allow_private: bool,

    // ── ACCUMULATION (store) ─────────────────────────────────────────────────────────────────────
    /// The last contact: what the endpoint presented and offered, or why contact failed.
    pub(crate) sighting: Sighting<CardPin>,
    /// The card AS RECEIVED at the last successful contact. Kept verbatim: the fingerprint an
    /// operator approved is over the received document, so a re-serialization is a different
    /// document.
    pub(crate) cached_card: Option<Value>,
    /// The re-verification ledger: when we last looked, when drift was last seen, how often.
    pub(crate) ledger: reverify::Ledger,
    /// The breaker's observation window.
    pub(crate) window: anomaly::Window,
}

impl AgentRegistration {
    /// A FRESHLY REGISTERED agent: nothing pinned, nothing approved, nothing observed, nothing
    /// served. The fail-closed floor, and the only constructor, so a registration cannot come into
    /// existence already trusted.
    pub(crate) fn registered(agent_id: impl Into<String>, backend_url: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            backend_url: backend_url.into(),
            protocol_version: DEFAULT_PROTOCOL_VERSION.to_string(),
            protocol_binding: ProtocolBinding::JsonRpc,
            approval: Approval::registered(),
            reverify: reverify::Policy {
                ttl_ms: 6 * 60 * 60 * 1_000,
                recovery_backoff_ms: super::config::DEFAULT_RECOVERY_BACKOFF_MS,
            },
            thresholds: anomaly::Thresholds::default(),
            egress_scopes: Vec::new(),
            outbound_cred: None,
            allow_private: false,
            sighting: Sighting::Never,
            cached_card: None,
            ledger: reverify::Ledger::default(),
            window: anomaly::Window::default(),
        }
    }

    /// THE DERIVED TRUST STATE. Delegated, never computed here: a second opinion is a second
    /// opinion that can disagree with the one the operator is reading.
    pub(crate) fn trust_state(&self) -> TrustState {
        self.approval.state(&self.sighting)
    }

    /// The changes queue for the last sighting.
    pub(crate) fn changes(&self) -> busbar_substrate::trust::Drift {
        self.approval.drift(&self.sighting)
    }

    /// May this registration be DISPATCHED TO for one skill at one digest?
    ///
    /// A CONJUNCTION of the machine's own gate and the derived state, and the second half is not
    /// redundant. `Approval::serves` answers "is this skill approved AT this digest", which is the
    /// right question when the digest handed to it is the one the endpoint is CURRENTLY offering.
    /// Hand it a stale digest — the one that was approved before a drift — and it answers `true`
    /// for a registration an operator is looking at as `Quarantined`, because the comparison it
    /// makes is against the approval and not against the last sighting.
    ///
    /// That is not a fault in the machine: it is a caller obligation the machine's own doc states.
    /// It IS a fault waiting to happen at a call site, so the obligation is discharged here, once,
    /// rather than at every dispatch. This can only ever be MORE closed than the machine, never
    /// differently closed, so it is not a second opinion that could disagree.
    pub(crate) fn may_dispatch(&self, skill: &str, digest: &str) -> bool {
        self.is_delegable() && self.approval.serves(skill, digest)
    }

    /// The operator-visible suspension reason, if suspended.
    pub(crate) fn suspension_reason(&self) -> Option<&str> {
        self.approval.suspension()
    }

    /// EVALUATE THE ANOMALY BREAKER AND ACT ON IT.
    ///
    /// This is the only place the breaker's verdict becomes a suspension, and it is deliberately
    /// one function rather than "evaluate here, suspend there": a trip that is computed and not
    /// applied is a security control that reports rather than protects. Returns the trip that was
    /// applied, so the caller can audit it without recomputing it.
    ///
    /// It does NOT lift an existing suspension. A breaker whose window recovers must not
    /// un-suspend an agent an operator suspended by hand, and it must not un-suspend itself either
    /// — resuming is an operator act, because the breaker cannot know whether the upstream got
    /// better or merely got quiet.
    pub(crate) fn apply_anomaly_breaker(&mut self) -> Option<anomaly::Trip> {
        if self.approval.suspension().is_some() {
            return None;
        }
        let trip = anomaly::evaluate(&self.window, &self.thresholds)?;
        self.approval.suspend(&trip.reason());
        Some(trip)
    }

    /// Whether this registration is a candidate for the DELEGATION CATALOGUE at all: approved, and
    /// therefore neither pending, quarantined, suspended nor in error.
    ///
    /// Scope is the ordered gate's ([`busbar_substrate::trust::validate`]) and capability matching is
    /// [`judge`]'s; this is only the trust half, and it is the same derivation the gate makes.
    pub(crate) fn is_delegable(&self) -> bool {
        self.trust_state() == TrustState::Approved
    }
}

// ══ THE CATALOGUE: WHICH AGENTS A GIVEN CALLER MAY EVEN SEE ══════════════════════════════════════
//
// Not "discovery". The vocabulary is CATALOGUE and DISPATCH, and the split is load-bearing:
// catalogue is AUTHORIZATION plus STRUCTURAL FITNESS; dispatch ordering is ordinary pool machinery.
// Nothing here is a hook, nothing here is a score, and nothing here reads task content.
//
// ## THE WALK IS CORE'S AND THE GATE IS CORE'S. THIS PLANE SUPPLIES AN ITEM TYPE.
//
// [`crate::catalogue`] owns the mechanism — walk the inventory, collect what each item requires,
// hand it to the ordered gate, keep the entitled subset, render it — and [`busbar_substrate::trust::validate`]
// owns the entitlement decision. This file supplies the four things a plane owes them: the item
// (`AgentRegistration`, the record this module already was), the grants it requires, its structural
// fitness and refusal words, and its wire form. The catalogue module this plane kept of its own is
// gone: two implementations of "who may see what" agree right up until they do not, and the
// divergence fails OPEN.
//
// ## Four conjunctive filters, and only one of them is this file's
//
// 1. **Trusted.** Only an `Approved` registration is ever a candidate. `Pending`, `Quarantined`,
//    `Suspended` and `Error` are not.
// 2. **Scope-granted.** `scope_allowed("agent", agent_id)`. No hook on this path, no filter verb, no
//    auto-tagging, no tag conventions. TAGS GROUP, IDENTITY IDENTIFIES.
// 3. **Capability-matched.** A2A agents are NOT FUNGIBLE: an arbitrary agent cannot serve an
//    arbitrary task, so an unfiltered candidate set is unsafe in a way an LLM lane set is not. This
//    is STRUCTURAL matching — an agent either can accept this shape of task or it cannot — and never
//    a score.
// 4. **Not suspended.** Folded into (1) rather than checked twice: `Suspended` outranks every other
//    state in the lifecycle, so a suspended registration is not `Approved` and is already out.
//
// FILTERS 1, 2 AND 4 ARE ONE CALL to [`busbar_substrate::trust::validate::validate_request`], made from
// [`CatalogueItem::admit`] below. Only filter 3 is this file's, because only filter 3 is about this
// wire format's document. THIS PLANE ASKS THE FULL ORDERED GATE — identity, grant, artifact,
// generation — because on A2A a listing IS an admission: an agent that is not `Approved` is not a
// candidate for anything. MCP's catalogue asks only identity and grant, because it deliberately
// LISTS what it will not dispatch so an operator can see the approval queue. That difference is a
// fact about the two protocols, stated at two `admit` call sites, and never a step a shared function
// decided to skip.
//
// ## Structural matching reads TYPES, never prose
//
// [`TaskShape`] carries a skill id, requested capabilities and input/output MIME modes. There is
// deliberately no field on it for text: the dispatch decision is content-blind, and the way that is
// enforced is that the decision function is not given any content to read.
//
// Content-blindness defeats the PROSE attack, not the TYPED-FIELD attack: `skills[]` and
// `capabilities` are upstream-authored, and what bounds them is that only an operator-approved
// `Approved` registration is ever a candidate. Operator approval is a capability VOUCH as well as an
// authenticity check, and the anomaly breaker is what catches an agent that betrays the vouch.

/// THE SHAPE OF A TASK, as the catalogue is allowed to see it.
///
/// Typed metadata only. There is no `text` member and there is not going to be one: a field for
/// prose is a field somebody eventually matches on, and the moment selection reads prose the
/// upstream's free text is deciding where tasks go.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TaskShape {
    /// The skill being asked for, by `id`. `None` means "any skill this agent declares".
    pub(crate) skill: Option<String>,
    /// Protocol features the task REQUIRES (`streaming`, `pushNotifications`, …). An agent that does
    /// not declare a required feature cannot accept this shape of task.
    pub(crate) requires_streaming: bool,
    pub(crate) requires_push_notifications: bool,
    /// MIME modes the caller will SEND and the modes it can ACCEPT back.
    pub(crate) input_modes: Vec<String>,
    pub(crate) output_modes: Vec<String>,
}

/// WHAT THE CALLER WANTS — everything the grant list and the fitness test need beyond the
/// registration itself, and this plane's [`CatalogueItem::Query`].
///
/// It carries no caller-authored content and cannot: [`TaskShape`] has no channel for prose, and
/// `delegating_from` is a busbar-local agent id the operator wrote, never anything an upstream
/// supplied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Wanted {
    pub(crate) shape: TaskShape,
    /// The FRONTED agent doing the delegating, on the delegation side only. `None` is the receiving
    /// direction, where the egress grant does not apply.
    pub(crate) delegating_from: Option<String>,
}

/// Why a registration is not in a caller's catalogue. Returned rather than merely filtered, because
/// "why can this key not see the planner" is the question an operator actually asks, and a filter
/// that only ever returns survivors cannot answer it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Excluded {
    /// Not `Approved`: pending, quarantined, suspended or in error.
    NotTrusted(TrustState),
    /// The caller's key does not grant `agent:<id>`.
    NotInScope,
    /// The caller's key is no longer live: deleted, disabled or expired. Its own arm rather than
    /// folded into `NotInScope`, because "grant this key a scope" and "this key is gone" are two
    /// different things for an operator to do.
    CallerNotLive,
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

/// One catalogue row: the registration, and the skill it matched. Core's type, aliased rather than
/// redeclared — a plane that keeps its own row type is a plane that can quietly add a field the
/// mechanism does not know it is carrying.
pub(crate) type Candidate<'a> = busbar_substrate::catalogue::Entitled<'a, AgentRegistration>;

impl CatalogueItem for AgentRegistration {
    type Excluded = Excluded;
    type Query = Wanted;
    /// The skill id the task shape matched. `None` when the task named no skill.
    type Fit = Option<String>;
    type Wire<'a> = super::serve::EntitledAgent<'a>;

    /// ONE GRANT on the receiving side, TWO on the delegating side.
    ///
    /// The scope grant names the OPERATOR's id for the agent, never anything the upstream supplied.
    /// The egress grant is the only structural difference between the two directions on this path —
    /// receiving is a strict subset of delegating minus the trust root — and it is the target's
    /// standing list rather than the caller's, which is why the ordered gate has two grant arms and
    /// not one.
    fn required_grants<'g>(&'g self, wanted: &'g Wanted, out: &mut Vec<Grant<'g>>) {
        out.push(Grant::Scope {
            kind: SCOPE_KIND_AGENT,
            name: &self.agent_id,
        });
        if let Some(from) = wanted.delegating_from.as_deref() {
            // Empty is NOBODY, never everybody — the ordered gate's rule, not a second one here.
            out.push(Grant::Egress {
                from,
                allowed: &self.egress_scopes,
            });
        }
    }

    /// THE FULL ORDERED GATE. Identity, grant, artifact and generation, in one call, and it is the
    /// same call the invocation check and the pre-socket relay gate make.
    fn admit(&self, caller: &Caller<'_>, grants: &[Grant<'_>]) -> Result<(), Excluded> {
        busbar_substrate::trust::validate::validate_request(
            &busbar_substrate::trust::validate::Ask {
                principal: caller.key,
                now: caller.now,
                grants,
                approval: &self.approval,
                sighting: &self.sighting,
                // The card's SKILL is matched structurally in `fit`, against a declaration rather than
                // against an approved digest: this plane approves a card, and the skill list is part of
                // the document the fingerprint already covers.
                capability: None,
                generation: caller.generation,
            },
        )
        .map_err(|refusal| match refusal {
            busbar_substrate::trust::validate::Refusal::NotGranted { .. } => Excluded::NotInScope,
            busbar_substrate::trust::validate::Refusal::EgressDenied { .. } => {
                Excluded::NoEgressGrant
            }
            busbar_substrate::trust::validate::Refusal::IdentityNotLive { .. } => {
                Excluded::CallerNotLive
            }
            busbar_substrate::trust::validate::Refusal::NotServing { state, .. } => {
                Excluded::NotTrusted(state)
            }
            // The catalogue asks at admission with no capability, where neither can fire; answered
            // rather than unwrapped because this is a request path.
            _ => Excluded::NotTrusted(self.approval.state(&self.sighting)),
        })
    }

    /// STRUCTURAL FITNESS against the CACHED card — filter (3), and the only one this file owns.
    fn fit(&self, wanted: &Wanted) -> Result<Option<String>, Excluded> {
        let document = self.cached_card.as_ref().ok_or(Excluded::NoCachedCard)?;
        let card = super::card::parse(document).map_err(Excluded::Unreadable)?;
        judge(&card, &wanted.shape)
    }

    /// A registration reaches this only if it named no grant at all, which it cannot: the scope
    /// grant above is unconditional. It exists because core will not enumerate an item that declares
    /// none, and a plane that could answer that case with `Ok` would be a plane with a way past the
    /// floor.
    fn ungranted(&self) -> Excluded {
        Excluded::NotInScope
    }

    /// ONE ENTITLED AGENT, as the extended card carries it. Rendered only after core has decided the
    /// caller may see it — which is the whole defence against the naive extended card that unions
    /// every fronted agent's skills and hands the estate to anybody who authenticates.
    fn render(&self) -> super::serve::EntitledAgent<'_> {
        super::serve::EntitledAgent {
            agent_id: &self.agent_id,
            backend_url: &self.backend_url,
            card: self.cached_card.as_ref(),
        }
    }
}

/// JUDGE WHETHER AN AGENT CARD MATCHES A TASK SHAPE. Structural, never a score: an agent either can
/// accept this shape of task or it cannot.
///
/// Unrelated to `mcp/client/argguard.rs`'s `judge`, which asks whether an ARGUMENT is a URL-ish SSRF
/// hazard. Same verb, unrelated subjects; `scripts/structure-lint.sh` carries that as a signed
/// DISTINCT row rather than leaving it as duplication nobody noticed.
fn judge(card: &AgentCard, shape: &TaskShape) -> Result<Option<String>, Excluded> {
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
            // to the defaults where it does not. Reading the skill's empty list as "accepts nothing"
            // would exclude every agent that sensibly declares its modes once.
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
/// listing is deterministic rather than hash-ordered. Core preserves it and does not re-sort.
pub(crate) fn inbound_catalogue<'a>(
    caller: &Caller<'_>,
    registrations: &'a [AgentRegistration],
    wanted: &Wanted,
) -> Vec<Candidate<'a>> {
    busbar_substrate::catalogue::entitled(registrations, caller, wanted)
}

/// DELEGATING: which registered agents THIS FRONTED AGENT may see as delegation targets.
///
/// It is the same walk with one more grant in the list, which is what makes the subset relation a
/// property of the data rather than of two functions that must be kept in agreement.
pub(crate) fn delegation_catalogue<'a>(
    caller: &Caller<'_>,
    registrations: &'a [AgentRegistration],
    wanted: &Wanted,
) -> Vec<Candidate<'a>> {
    busbar_substrate::catalogue::entitled(registrations, caller, wanted)
}

/// THE ENTITLED AGENTS, AS THE EXTENDED CARD CARRIES THEM — the same walk as [`inbound_catalogue`],
/// rendered by core rather than projected at the call site.
///
/// This is the data-exposure surface the extended card is: the naive implementation unions every
/// fronted agent's `skills[]` and hands every authenticated caller the whole inventory. Rendering
/// through [`busbar_substrate::catalogue::rendered`] makes that shape unreachable — an item is rendered only
/// after core has decided the caller may see it, and there is no path here that renders first.
pub(crate) fn entitled_agents<'a>(
    caller: &Caller<'_>,
    registrations: &'a [AgentRegistration],
    wanted: &Wanted,
) -> Vec<super::serve::EntitledAgent<'a>> {
    busbar_substrate::catalogue::rendered(registrations, caller, wanted)
}

/// WHY a named registration is not in a caller's catalogue. The same judgement, with the reason kept
/// — for the admin surface and for the operator asking "why can this key not see the planner".
pub(crate) fn explain(
    registration: &AgentRegistration,
    caller: &Caller<'_>,
    wanted: &Wanted,
) -> Result<(), Excluded> {
    busbar_substrate::catalogue::judge(registration, caller, wanted).map(|_| ())
}

#[cfg(test)]
#[path = "tests/registry_tests.rs"]
mod registry_tests;

#[cfg(test)]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;

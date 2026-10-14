// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS GATE: may busbar spend its own outbound credential on a subject, on behalf of the
//! inbound caller? A virtual-key grant check, so it is authorization and lives with the APPROVE
//! step (BUSBAR-1.6.0.md Part 2 #36: `busbar-kernel-scope` is authZ). Moved verbatim from
//! `busbar-kernel/src/egress_auth/gate.rs` (D1, ARCHITECT ruling 2026-10-02). Each plane supplies
//! its grant kind ([`EgressSubject`]) and words the refusal; the gate, the refusal and the
//! witness are written once, here.

use busbar_contract::records::VirtualKey;

/// ONE GRANT THAT MUST PASS: which check this is, the scope KIND it is asked under, and the VALUE
/// looked up in the caller's grant list.
///
/// `grant` is the consumer's own marker for the check, so a consumer's `From` conversion can give
/// each check its own sentence without matching on a string. `scope_kind` is `&'static str` because
/// a scope kind is a vocabulary constant fixed by the consumer's own grant taxonomy, never a runtime
/// value — a computed kind would be a caller choosing which grant list it is checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement<G> {
    /// The consumer's own marker for this check.
    pub grant: G,
    /// The scope kind the grant is asked under (a vocabulary constant of the consumer).
    pub scope_kind: &'static str,
    /// The value looked up in the caller's grant list.
    pub value: String,
}

/// WHAT A CONSUMER SUPPLIES: the grants an egress on this subject requires. Everything else —
/// including the caller key's liveness, which every plane gets alike — is [`authorise`]'s business.
pub trait EgressSubject {
    /// The consumer's own enumeration of the checks — ONE variant per requirement. An enum rather
    /// than a string so the consumer's refusal conversion is exhaustive over its own checks: a
    /// consumer that grows a third requirement gets a compile error at its wording, not a nearby arm
    /// silently reused.
    type Grant: Copy + std::fmt::Debug;

    /// EVERY grant that must pass, IN THE ORDER THEY ARE CHECKED. All of them must pass; the first
    /// that fails is the refusal reported, so the order is the operator-facing diagnosis order and
    /// is part of the contract rather than an implementation detail.
    fn grants_required(&self) -> Vec<Requirement<Self::Grant>>;
}

/// WHY NO OUTBOUND CREDENTIAL MAY BE SELECTED FOR THIS CALLER.
///
/// Core's refusal, which every plane converts into its own wording with a TOTAL `From`. Totality is
/// deliberate: a refusal this enum grows must be given a sentence on every plane rather than
/// being folded silently into a nearby arm, and an exhaustive match is what forces that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressRefusal<G> {
    /// The key is disabled, tombstoned or expired. A key that may not authenticate may certainly not
    /// cause a credential to be minted, and a credential outliving the key that occasioned it is a
    /// hop nobody's grant covers.
    KeyNotLive {
        /// The refused key's id.
        caller: String,
    },
    /// The inbound principal holds no grant covering this requirement. FAIL CLOSED: busbar does not
    /// spend its own credential on behalf of a caller that is not itself authorised for the
    /// destination.
    NoGrant {
        /// The refused key's id.
        caller: String,
        /// The consumer's marker for the missing grant.
        grant: G,
        /// The scope kind the missing grant is asked under.
        scope_kind: &'static str,
        /// The value the caller holds no grant for.
        value: String,
    },
}

impl<G> std::fmt::Display for EgressRefusal<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EgressRefusal::KeyNotLive { caller } => write!(
                f,
                "key `{caller}` is not live, so no outbound credential is leased for it"
            ),
            EgressRefusal::NoGrant {
                caller,
                scope_kind,
                value,
                ..
            } => write!(
                f,
                "key `{caller}` holds no `{scope_kind}:{value}` grant, so no outbound credential is \
                 selected for it: busbar does not spend its own credentials on behalf of a caller \
                 that is not itself authorised for the destination"
            ),
        }
    }
}

/// PROOF THAT THE INBOUND PRINCIPAL IS ITSELF AUTHORISED FOR THIS DESTINATION.
///
/// The whole value of this type is that it cannot be built anywhere but [`authorise`]: the field is
/// private to this module, so no other module in the crate can construct one. It carries the SUBJECT
/// the check was made against, so a mint reads the destination OFF the witness instead of taking it
/// as a second parameter — a signature that took both would admit the one combination that defeats
/// the whole gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressGrant<S> {
    subject: S,
}

impl<S> EgressGrant<S> {
    /// The subject this grant was taken against.
    pub fn subject(&self) -> &S {
        &self.subject
    }
}

/// THE GATE: may busbar spend ITS OWN credential on this subject, ON BEHALF OF THIS CALLER?
///
/// Two checks and an order:
///
/// 1. LIVENESS, FIRST, for every plane alike (THE DESIGN §1: every plane gets every capability) —
///    a key that is tombstoned, disabled or past its own `expires_at` at `now` may not cause a
///    credential to be minted, and is refused as itself rather than as a missing grant, because
///    those are different operator actions. `now` is the caller's clock in the key's unit (unix
///    seconds); a consumer passing a clock it does not have would be switching this check off.
/// 2. EVERY requirement, in the plane's declared order. ALL must pass. Requiring all of them is what
///    keeps a coarse grant from silently becoming a fine one.
///
/// `VirtualKey::scope_allowed` is reused verbatim rather than reimplemented: its cross-kind
/// fail-closed semantics are frozen at 1.5.3 (an OMITTED scope list is a wildcard, an EMPTY one is
/// the empty set) and a second implementation of a frozen rule is a second chance to get it wrong.
pub fn authorise<S: EgressSubject>(
    caller: &VirtualKey,
    subject: S,
    now: u64,
) -> Result<EgressGrant<S>, EgressRefusal<S::Grant>> {
    if !caller.is_live() || !caller.enabled || caller.expires_at.is_some_and(|exp| now >= exp) {
        return Err(EgressRefusal::KeyNotLive {
            caller: caller.id.clone(),
        });
    }
    for req in subject.grants_required() {
        if !caller.scope_allowed(req.scope_kind, &req.value) {
            return Err(EgressRefusal::NoGrant {
                caller: caller.id.clone(),
                grant: req.grant,
                scope_kind: req.scope_kind,
                value: req.value,
            });
        }
    }
    Ok(EgressGrant { subject })
}

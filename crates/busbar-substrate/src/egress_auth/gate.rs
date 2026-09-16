// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS GATE — one gate, shared by every consumer that spends this substrate's own
//! credential on an inbound caller's behalf.
//!
//! ## Why this lives once, here, rather than once per consumer
//!
//! The check below used to be written independently at each consumer's own credential-selection
//! site, and the copies had already diverged: one checked that the caller's key was still LIVE and
//! the other did not, and nobody decided that. Two implementations of one authorisation control is
//! the shape this tree's `structure-lint` gate ledger calls DEBT, because the copy that is hardened
//! and the copy that is not are indistinguishable from the outside.
//!
//! **What this module owns:** the liveness judgement, the grant walk, the ORDER of the checks, the
//! fail-closed default, the refusal it produces and the witness it hands back. **What a consumer
//! owns:** its GRANT KIND ([`EgressSubject`]) and its refusal WORDING (a total
//! `From<EgressRefusal<_>>`). A consumer keeps its own vocabulary for the reason a caller was
//! refused — two different missing-grant kinds should read as two different sentences to an
//! operator reading a denial — but it does not keep its own decision about whether to refuse.
//!
//! [`crate::trust`] is the precedent this copies rather than a new idea, and [`crate::audit`] is the
//! nearer one: this module owns the lifecycle, the consumer supplies the artifact.
//!
//! ## THE CONFUSED DEPUTY, which is the only reason this gate exists
//!
//! An egress-capable substrate is BOTH directions at once. An authenticated inbound call can cause
//! it to spend its OWN standing outbound credential on a destination the caller was never entitled
//! to reach — every byte of that hop is the substrate's own, so "the caller's key never leaves" is
//! satisfied while the caller has just gained reach it does not hold. A client-only gateway cannot
//! have this bug, because it has no inbound principal to be confused about. The gate binds the
//! OUTBOUND credential to the INBOUND principal's grant, and it is the same rule for every consumer
//! because the deputy is a property of the bundle rather than of a protocol.
//!
//! ## THE WITNESS IS A TYPE, so forgetting the gate is a COMPILE error
//!
//! [`authorise`] is the only way to obtain an [`EgressGrant`]: its field is private to this module,
//! so nothing else in the crate can build one, and a consumer's mint takes one by reference. A
//! future delegating call site that skipped the check does not compile — which matters because the
//! caller that will forget is the one that does not exist yet. The subject the check was made
//! AGAINST is carried ON the witness rather than passed beside it, so "authorise against `planner`,
//! mint against `payments`" is unexpressible rather than merely discouraged.
//!
//! ## ADDING A NEW CONSUMER COSTS A GRANT KIND AND NOTHING ELSE
//!
//! That is the acceptance test for this seam, and `tests/gate_tests.rs` writes a throwaway grant
//! kind for a consumer this crate does not otherwise know about and shows it is gated, refused and
//! audited with NO gate, NO refusal enum and NO error type written for it.

// Shared infrastructure: with every consumer feature compiled out the whole gate is vestigial, so
// its items read dead — scoped to exactly that config so a real single-consumer build still lints
// every item its own consumer leaves unused (those carry their own per-consumer attrs below).
#![cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]

use busbar_api::VirtualKey;

/// ONE GRANT THAT MUST PASS: which check this is, the scope KIND it is asked under, and the VALUE
/// looked up in the caller's grant list.
///
/// `grant` is the consumer's own marker for the check, so a consumer's `From` conversion can give
/// each check its own sentence without matching on a string. `scope_kind` is `&'static str` because
/// a scope kind is a vocabulary constant fixed by the consumer's own grant taxonomy, never a runtime
/// value — a computed kind would be a caller choosing which grant list it is checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement<G> {
    pub grant: G,
    pub scope_kind: &'static str,
    pub value: String,
}

/// WHAT A CONSUMER SUPPLIES: the grants an egress on this subject requires, and whether the
/// consumer's key-liveness rule applies. Everything else is [`authorise`]'s business.
pub trait EgressSubject {
    /// The consumer's own enumeration of the checks — ONE variant per requirement. An enum rather
    /// than a string so the consumer's refusal conversion is exhaustive over its own checks: a
    /// consumer that grows a third requirement gets a compile error at its wording, not a nearby arm
    /// silently reused.
    type Grant: Copy + std::fmt::Debug;

    /// Whether the caller's KEY must still be live (not tombstoned, enabled, not expired) for this
    /// consumer's egress.
    ///
    /// A CONST rather than a runtime flag, because it is a property of the consumer and not of the
    /// request. Different consumers can legitimately disagree on this, and this const is where that
    /// divergence is stated rather than being an accident of which file a reader opens. Unifying the
    /// gate does not force either answer: a gate that quietly started refusing more for one
    /// consumer, or less, would be a behaviour change wearing a refactor's clothes.
    const REQUIRE_LIVE_KEY: bool;

    /// EVERY grant that must pass, IN THE ORDER THEY ARE CHECKED. All of them must pass; the first
    /// that fails is the refusal reported, so the order is the operator-facing diagnosis order and
    /// is part of the contract rather than an implementation detail.
    fn grants_required(&self) -> Vec<Requirement<Self::Grant>>;
}

/// WHY NO OUTBOUND CREDENTIAL MAY BE SELECTED FOR THIS CALLER.
///
/// Core's refusal, which every plane converts into its own wording with a TOTAL `From`. Totality is
/// deliberate: a refusal this enum grows later must be given a sentence on every plane rather than
/// being folded silently into a nearby arm, and an exhaustive match is what forces that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressRefusal<G> {
    /// The key is disabled, tombstoned or expired. A key that may not authenticate may certainly not
    /// cause a credential to be minted, and a credential outliving the key that occasioned it is a
    /// hop nobody's grant covers.
    KeyNotLive { caller: String },
    /// The inbound principal holds no grant covering this requirement. FAIL CLOSED: busbar does not
    /// spend its own credential on behalf of a caller that is not itself authorised for the
    /// destination.
    NoGrant {
        caller: String,
        grant: G,
        scope_kind: &'static str,
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

// NOT MOUNTED YET, deliberately named rather than omitted. Existing consumers each audit their own
// egress refusal at their ingress with their own resource spelling; those call sites are what these
// methods exist to replace, and the replacement is a separate change because it edits an ingress
// module. Present now because the audit VOCABULARY is the part that needs to be shared, and a
// consumer that arrives later must find it here rather than invent a third spelling. Exercised by
// `tests/gate_tests.rs`.
#[cfg_attr(not(test), allow(dead_code))]
impl<G> EgressRefusal<G> {
    /// The refused destination in the vocabulary the AUDIT ring speaks: `<scope kind>:<value>`, or
    /// the key itself when the refusal is about the key rather than the destination.
    ///
    /// Here rather than on each consumer because an audit row that is spelled one way per consumer
    /// is an audit an auditor cannot read across — a single shared spelling keeps the audit trail
    /// legible no matter which consumer produced the refusal.
    pub fn audit_resource(&self) -> String {
        match self {
            EgressRefusal::KeyNotLive { caller } => format!("key:{caller}"),
            EgressRefusal::NoGrant {
                scope_kind, value, ..
            } => format!("{scope_kind}:{value}"),
        }
    }

    /// WHO was refused. Every refusal names the caller, because an unattributable denial is a denial
    /// nobody can act on.
    pub fn caller(&self) -> &str {
        match self {
            EgressRefusal::KeyNotLive { caller } | EgressRefusal::NoGrant { caller, .. } => caller,
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
    // Used only by consumers built under the `relay` feature: they read the subject back off the
    // witness at mint time, while other consumers do not — so with `relay` off this accessor has no
    // caller.
    #[cfg_attr(not(feature = "relay"), allow(dead_code))]
    pub fn subject(&self) -> &S {
        &self.subject
    }
}

/// THE GATE: may busbar spend ITS OWN credential on this subject, ON BEHALF OF THIS CALLER?
///
/// Two checks and an order:
///
/// 1. LIVENESS, when the plane requires it, FIRST — a key that may not authenticate at all is
///    refused as itself rather than as a missing grant, because those are different operator
///    actions.
/// 2. EVERY requirement, in the plane's declared order. ALL must pass. Requiring all of them is what
///    keeps a coarse grant (`mcp_server`) from silently becoming a fine one (`mcp_tool`).
///
/// `VirtualKey::scope_allowed` is reused verbatim rather than reimplemented: its cross-kind
/// fail-closed semantics are frozen at 1.5.3 (an OMITTED scope list is a wildcard, an EMPTY one is
/// the empty set) and a second implementation of a frozen rule is a second chance to get it wrong.
pub fn authorise<S: EgressSubject>(
    caller: &VirtualKey,
    subject: S,
    now: u64,
) -> Result<EgressGrant<S>, EgressRefusal<S::Grant>> {
    if S::REQUIRE_LIVE_KEY
        && (!caller.is_live() || !caller.enabled || caller.expires_at.is_some_and(|exp| now >= exp))
    {
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

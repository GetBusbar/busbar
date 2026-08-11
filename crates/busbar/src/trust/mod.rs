// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRUSTED-UPSTREAM TRUST LIFECYCLE, written plane-neutral with the pinned artifact as a type
//! parameter.
//!
//! An MCP server and an A2A agent pose the same problem: take an untrusted external upstream, let an
//! operator inspect and approve it, PIN its identity, hash-pin its capability set, and demote it on
//! drift pending re-approval. The 1.5.3 named-definition chassis already gives both of them CRUD
//! generically. What it does not model is the LIFECYCLE, and the lifecycle is this module.
//!
//! ## Why generic on the FIRST build rather than extracted on the second
//!
//! The house preference is to extract an abstraction on its second use. That preference assumes a
//! first use exists to extract FROM. Here it does not: nothing in the tree implements any of this,
//! so a second plane would be extracting from a codebase that never had the abstraction, and would
//! in practice write a parallel copy. So the parameter goes in from the first line, and
//! `tests/genericity_tests.rs` runs ONE transition table over two deliberately different artifact
//! shapes to keep the claim honest.
//!
//! ## What is parameterised, and what is deliberately not
//!
//! The PINNED ARTIFACT is a type parameter ([`PinnedArtifact`]), because the two planes do not agree
//! on its arity: an MCP server offers one opaque transport-layer value (a certificate SPKI), while a
//! signed A2A card offers an issuer key AND a card fingerprint, and drift in either half is drift.
//! A single string would have quietly encoded the MCP arity as the universal one.
//!
//! A CAPABILITY is deliberately NOT parameterised: both planes need exactly a name and a comparable
//! digest, and a type parameter that every instantiation would fill with the same shape is noise
//! that has to be threaded through every signature. Tools and skills are two vocabularies for one
//! structure, so the structure is concrete and the vocabulary stays at the edges.
//!
//! ## The state is DERIVED, never stored
//!
//! This is the load-bearing design decision and it falls straight out of the config ruling that the
//! overlay is operator INTENT while the store is what ACCUMULATES.
//!
//! [`Approval`] is intent: the locked pin, the approved per-capability digests, the suspension. It
//! belongs in the config overlay, and it is written per FIELD (see [`crate::config::patch`]), so
//! recording an approval never rewrites the endpoint the operator wrote beside it.
//!
//! [`Sighting`] is accumulation: what the upstream was last observed to offer, or why the last
//! contact failed. It belongs in the store.
//!
//! [`TrustState`] is then a pure FUNCTION of the two. Quarantine is not a flag somebody remembers to
//! set; it is what you get when the observation disagrees with the approval. Nothing can leave a
//! stale `approved` behind after a drift, because there is no stored `approved` to leave behind, and
//! the dispatch-time gate ([`Approval::serves`]) is the same comparison rather than a second one
//! that could disagree with it.

// NO PRODUCTION CALLER YET, and landed ahead of one deliberately. The lifecycle is the part with a
// dependant waiting on it (the sibling plane parameterises this rather than writing a second copy),
// and the transitions are the part worth settling and pinning before any wire, store table or admin
// verb is built on top of them. Its callers are the registry's config section, its store-side
// sighting table, and the admin verbs, each of which is a later increment. Same posture as the
// audience-bound mint and the entry merge patch on this branch.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::BTreeMap;

/// The IDENTITY a registration is pinned to: the thing an operator supplies out of band and the
/// upstream must keep presenting. The trust root, not a convenience.
///
/// Implementors are compared by `PartialEq`, so the plane decides what identity equality MEANS: a
/// single-value transport pin compares one value, a signed-card pin compares issuer key and card
/// fingerprint together. The machine never takes that decision apart.
pub(crate) trait PinnedArtifact: Clone + PartialEq + std::fmt::Debug {
    /// The operator-facing name of the pinning MECHANISM (`cert_spki`, `jws_issuer`, `mtls`, …).
    /// Read by operator-facing views and audit records; never interpreted by the machine, which is
    /// why the machine cannot acquire a per-mechanism special case by accident.
    fn mechanism(&self) -> &'static str;

    /// A short, stable rendering for audit rows and drift reports. NOT the equality test: comparison
    /// goes through `PartialEq` so a plane whose artifact has several parts cannot have them
    /// flattened into one string behind its back.
    fn digest(&self) -> String;
}

/// The operator's standing decision about one capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CapabilityApproval {
    /// Approved AT this digest. Serving requires the observed digest to still match it.
    At(String),
    /// Refused. Never served, and never drift again: the operator has already ruled, so a rejected
    /// capability must not keep re-raising an alarm every refresh.
    Rejected,
}

/// What an upstream was observed to OFFER at one moment: its presented identity and its capability
/// set as `name -> digest`. Accumulated data, so it belongs in the store.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Observation<A: PinnedArtifact> {
    /// The identity the endpoint presented, if it presented one at all.
    pub(crate) pin: Option<A>,
    /// The capability set, `name -> digest`.
    pub(crate) capabilities: BTreeMap<String, String>,
}

/// The last contact attempt. `Never` is not a failure: a record approved from a declarative config
/// pin has legitimately never been reached.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Sighting<A: PinnedArtifact> {
    /// Never contacted.
    Never,
    /// Contact failed, with the operator-visible reason (connect, handshake, signature).
    Failed(String),
    /// Contacted, and this is what it offered.
    Seen(Observation<A>),
}

impl<A: PinnedArtifact> Sighting<A> {
    /// The observation, if the last contact succeeded.
    fn observation(&self) -> Option<&Observation<A>> {
        match self {
            Sighting::Seen(o) => Some(o),
            _ => None,
        }
    }
}

/// The operator-facing trust state. Derived from an [`Approval`] and a [`Sighting`]; never stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrustState {
    /// No locked pin, so nothing is approved and nothing is served. Covers both of the design's
    /// pending sub-states: whether a candidate has been captured is a question about the SIGHTING,
    /// which is why it is not a second state here.
    Pending,
    /// Locked pin, no drift against the last sighting. Serves, subject to scope.
    Approved,
    /// Locked pin, but the last sighting disagrees with what was approved. Dispatch is refused until
    /// the operator works the drift.
    Quarantined,
    /// Suspended by an operator or by an anomaly control, with a reason. Outranks every other state:
    /// it is a security control, not a ranking, so it has no soft form.
    Suspended,
    /// The last contact failed. Never serves, and never silently becomes `Approved`.
    Error,
}

/// What the last sighting changed relative to what was approved: the changes queue, derived.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Drift {
    /// The presented identity is not the locked one. Its OWN axis, deliberately: adopting a new
    /// identity is a different act from adopting new content, and the two must never be settled by
    /// one bulk approval.
    pub(crate) pin_changed: bool,
    /// Offered now, never ruled on by the operator.
    pub(crate) added: Vec<String>,
    /// Approved, but offered at a different digest.
    pub(crate) changed: Vec<String>,
    /// Approved, and no longer offered.
    pub(crate) removed: Vec<String>,
}

impl Drift {
    /// Nothing to work: the sighting agrees with the approval on every axis.
    pub(crate) fn is_empty(&self) -> bool {
        !self.pin_changed
            && self.added.is_empty()
            && self.changed.is_empty()
            && self.removed.is_empty()
    }
}

/// Why a transition was refused. Every arm is a case where the alternative would be inventing trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TrustError {
    /// Approve was asked to lock a pin when neither the operator nor the endpoint supplied one.
    NoPinToLock,
    /// A capability was named that the endpoint is not currently offering, so there is no digest to
    /// adopt.
    CapabilityNotObserved(String),
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustError::NoPinToLock => write!(
                f,
                "cannot approve: no identity pin was supplied and none was observed"
            ),
            TrustError::CapabilityNotObserved(name) => write!(
                f,
                "cannot approve `{name}`: it is not in the last observed capability set"
            ),
        }
    }
}

/// The operator's INTENT about one upstream: what they approved, pinned to what identity. Config
/// overlay state, written per field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Approval<A: PinnedArtifact> {
    pin: Option<A>,
    capabilities: BTreeMap<String, CapabilityApproval>,
    suspension: Option<String>,
}

impl<A: PinnedArtifact> Approval<A> {
    /// A freshly REGISTERED upstream: nothing pinned, nothing approved, nothing served. The
    /// fail-closed floor.
    pub(crate) fn registered() -> Self {
        Self {
            pin: None,
            capabilities: BTreeMap::new(),
            suspension: None,
        }
    }

    /// THE DECLARATIVE APPROVAL: the intent an operator wrote down in config rather than worked
    /// through the changes queue against a live sighting. Same intent, different route in.
    ///
    /// The pin is taken BY VALUE, not as an `Option`, and that is the whole reason this exists as a
    /// constructor instead of a caller assembling the fields. An upstream with no authenticity root
    /// has no artifact to pass, so it cannot build one of these AT ALL: "unpinned can never be
    /// approved" becomes a fact about what is constructible rather than a runtime check somebody
    /// could later relax. [`Approval::registered`] is the only thing an unrooted registration can
    /// be, and it serves nothing.
    ///
    /// `capabilities` is `name -> approved digest`. A capability the operator allowed but approved
    /// no digest for is simply ABSENT, which is `pending`: [`Approval::serves`] finds no entry and
    /// refuses whatever digest it is handed, so "allowed" never quietly becomes "approved".
    pub(crate) fn declared(pin: A, capabilities: BTreeMap<String, String>) -> Self {
        Self {
            pin: Some(pin),
            capabilities: capabilities
                .into_iter()
                .map(|(name, digest)| (name, CapabilityApproval::At(digest)))
                .collect(),
            suspension: None,
        }
    }

    /// The locked identity pin, or `None` while unapproved.
    pub(crate) fn pin(&self) -> Option<&A> {
        self.pin.as_ref()
    }

    /// EVERY STANDING PER-CAPABILITY DECISION, in name order.
    ///
    /// A READ, not a transition — which is the point. A trust view has to render three distinct
    /// answers per capability (approved at a digest, rejected, or absent-and-therefore-pending) and
    /// with no accessor the only way to distinguish the first two from outside is to re-derive them
    /// from a sighting, which answers a different question and gets `Rejected` wrong. Nothing here
    /// can change a decision; the transitions above remain the only way in.
    pub(crate) fn capabilities(&self) -> impl Iterator<Item = (&str, &CapabilityApproval)> {
        self.capabilities.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// The operator-visible suspension reason, if suspended.
    pub(crate) fn suspension(&self) -> Option<&str> {
        self.suspension.as_deref()
    }

    /// THE DERIVED STATE. Order is precedence, and each step is a rule rather than a convenience:
    /// a suspension is a security control so it outranks everything; a failed contact is never
    /// reported as trust; an unpinned record is pending whatever else is true of it; and quarantine
    /// is simply the presence of drift.
    pub(crate) fn state(&self, sighting: &Sighting<A>) -> TrustState {
        if self.suspension.is_some() {
            return TrustState::Suspended;
        }
        if matches!(sighting, Sighting::Failed(_)) {
            return TrustState::Error;
        }
        if self.pin.is_none() {
            return TrustState::Pending;
        }
        match sighting.observation() {
            // Approved and not re-observed since (the declarative-pin path, and every moment
            // between refreshes). There is nothing to disagree with.
            None => TrustState::Approved,
            Some(obs) if self.drift_against(obs).is_empty() => TrustState::Approved,
            Some(_) => TrustState::Quarantined,
        }
    }

    /// The changes queue for the last sighting. Empty when there was no successful sighting to
    /// compare against.
    pub(crate) fn drift(&self, sighting: &Sighting<A>) -> Drift {
        sighting
            .observation()
            .map(|o| self.drift_against(o))
            .unwrap_or_default()
    }

    fn drift_against(&self, obs: &Observation<A>) -> Drift {
        let mut d = Drift {
            pin_changed: self.pin.is_some() && self.pin.as_ref() != obs.pin.as_ref(),
            ..Drift::default()
        };
        for (name, digest) in &obs.capabilities {
            match self.capabilities.get(name) {
                // Settled by the operator: refused capabilities are not drift, whatever their
                // digest does afterwards.
                Some(CapabilityApproval::Rejected) => {}
                Some(CapabilityApproval::At(approved)) if approved == digest => {}
                Some(CapabilityApproval::At(_)) => d.changed.push(name.clone()),
                None => d.added.push(name.clone()),
            }
        }
        for (name, approval) in &self.capabilities {
            if matches!(approval, CapabilityApproval::At(_)) && !obs.capabilities.contains_key(name)
            {
                d.removed.push(name.clone());
            }
        }
        d
    }

    /// THE DISPATCH GATE. `true` only when this upstream is pinned, not suspended, and the named
    /// capability is approved AT the digest being dispatched against.
    ///
    /// It is the same comparison [`Approval::drift`] makes, deliberately: a separate dispatch check
    /// is a second opinion that can disagree with the one the operator is looking at, and an
    /// in-flight call that raced a quarantine is exactly the moment that disagreement would matter.
    pub(crate) fn serves(&self, capability: &str, observed_digest: &str) -> bool {
        if self.suspension.is_some() || self.pin.is_none() {
            return false;
        }
        matches!(
            self.capabilities.get(capability),
            Some(CapabilityApproval::At(approved)) if approved == observed_digest
        )
    }

    /// APPROVE: lock the identity and adopt the currently offered digests.
    ///
    /// `pin_override` is the operator's out-of-band value and WINS over the observed candidate,
    /// which is what keeps this a real authenticity root rather than trust-on-first-use with a human
    /// in it. A capability the operator has REJECTED stays rejected: a bulk approval must not
    /// quietly reinstate a standing refusal.
    pub(crate) fn approve(
        &mut self,
        sighting: &Sighting<A>,
        pin_override: Option<A>,
    ) -> Result<(), TrustError> {
        let pin = pin_override
            .or_else(|| sighting.observation().and_then(|o| o.pin.clone()))
            .ok_or(TrustError::NoPinToLock)?;
        self.pin = Some(pin);
        if let Some(obs) = sighting.observation() {
            for (name, digest) in &obs.capabilities {
                if matches!(
                    self.capabilities.get(name),
                    Some(CapabilityApproval::Rejected)
                ) {
                    continue;
                }
                self.capabilities
                    .insert(name.clone(), CapabilityApproval::At(digest.clone()));
            }
        }
        Ok(())
    }

    /// APPROVE-PIN: adopt the presented identity as the new locked pin, and touch nothing else. A
    /// separate act from approving content, so that accepting a rotated certificate can never smuggle
    /// a changed tool through with it.
    pub(crate) fn approve_pin(&mut self, sighting: &Sighting<A>) -> Result<(), TrustError> {
        let pin = sighting
            .observation()
            .and_then(|o| o.pin.clone())
            .ok_or(TrustError::NoPinToLock)?;
        self.pin = Some(pin);
        Ok(())
    }

    /// Adopt the currently offered digest for ONE capability: the changes queue worked a row at a
    /// time, so every acceptance is its own auditable act.
    pub(crate) fn approve_capability(
        &mut self,
        capability: &str,
        sighting: &Sighting<A>,
    ) -> Result<(), TrustError> {
        let digest = sighting
            .observation()
            .and_then(|o| o.capabilities.get(capability))
            .ok_or_else(|| TrustError::CapabilityNotObserved(capability.to_string()))?;
        self.capabilities.insert(
            capability.to_string(),
            CapabilityApproval::At(digest.clone()),
        );
        Ok(())
    }

    /// Refuse a capability permanently. It leaves the served set and stops being drift.
    pub(crate) fn reject_capability(&mut self, capability: &str) {
        self.capabilities
            .insert(capability.to_string(), CapabilityApproval::Rejected);
    }

    /// SUSPEND with an operator-visible reason. Outranks every other state and serves nothing.
    pub(crate) fn suspend(&mut self, reason: &str) {
        self.suspension = Some(reason.to_string());
    }

    /// Lift a suspension. The record returns to whatever its approval and last sighting actually
    /// say, which may well be `Quarantined`: resuming is not a re-approval.
    pub(crate) fn resume(&mut self) {
        self.suspension = None;
    }

    /// UNPIN: the endpoint or the pin changed, so force re-approval. The locked pin and every
    /// capability APPROVAL are discarded, because they were assertions about a different upstream and
    /// an identity change must never ride the old approval.
    ///
    /// REJECTIONS survive. "Never serve this capability" is a standing instruction about a name, not
    /// a fact about the endpoint's current identity, and discarding it here is how a rejected
    /// capability comes back at the next bulk approval.
    pub(crate) fn unpin(&mut self) {
        self.pin = None;
        self.capabilities
            .retain(|_, v| matches!(v, CapabilityApproval::Rejected));
    }
}

/// THE RE-VERIFICATION CADENCE — when to look again at a pinned upstream, and what to believe when
/// the answer keeps changing. Promoted here from `crate::a2a` on its SECOND consumer, which is the
/// move that module's own header specified: "it stays where its one caller is, and moves when a
/// second plane wants it". The MCP refresh timer is that second plane.
pub(crate) mod reverify;

#[cfg(test)]
#[path = "tests/lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "tests/genericity_tests.rs"]
mod genericity_tests;

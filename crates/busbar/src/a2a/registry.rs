// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `AgentRegistration` ROW: one registered external agent, as the control plane holds it.
//!
//! ## This is a RECORD, not a second state machine
//!
//! The trust state, the changes queue and the dispatch gate are [`crate::trust`], reached through
//! the [`crate::trust::Approval`] this record CARRIES. Nothing here re-derives any of them.
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

use crate::trust::{Approval, Sighting, TrustState};

use super::anomaly;
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
    pub(crate) fn changes(&self) -> crate::trust::Drift {
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
    /// Scope and capability matching are [`super::catalogue`]'s; this is only the trust half.
    pub(crate) fn is_delegable(&self) -> bool {
        self.trust_state() == TrustState::Approved
    }
}

#[cfg(test)]
#[path = "tests/registry_tests.rs"]
mod registry_tests;

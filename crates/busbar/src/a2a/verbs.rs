// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE THREE NON-CRUD ADMIN VERBS: `connect`, `sync`, `suspend`.
//!
//! The generic registry chassis models list, get, put, patch-settings and delete. None of those is
//! any of these. `connect` is a PREVIEW that must never grant anything, `sync` is an operator
//! forcing a re-verification the timer has not asked for, and `suspend` is a human pulling an agent
//! out of service on evidence the machine does not have. This module is the verb layer: it decides
//! what each verb DOES to the trust lifecycle, and it is written over the plane-neutral machine in
//! [`crate::trust`] so none of these adds a state or a transition to it.
//!
//! ## `connect` PREVIEWS. It never grants.
//!
//! The single most important property here. An operator registering an agent wants to see the card
//! before approving it, and the naive implementation — fetch, verify, mark trusted — is how an
//! ecosystem gets an "approve" button nobody reads. So `connect` fetches, verifies, and reports, and
//! the ONLY state it can produce is one that cannot serve. Approval is a separate, explicit act by a
//! human against a fingerprint they have seen. That is enforced here by construction: this module
//! never calls `approve`.
//!
//! ## `sync` OUTRANKS THE TIMER, but changes nothing else
//!
//! `sync` is exactly [`super::reverify::due`] with `operator_sync` set. It re-fetches, re-verifies
//! and folds the observation through the SAME [`super::reverify::settle`] the background job uses,
//! so an operator-driven check and a timer-driven check cannot reach different conclusions from the
//! same answer. The asymmetry that matters is preserved because it lives in `settle`: detection is
//! never rate-limited, and the direction held back is recovery, never demotion.
//!
//! ## `suspend` IS INDEPENDENT OF THE TRUST STATE, and that is the point
//!
//! An operator with out-of-band intelligence — a vendor breach notice, a report from a peer — must
//! be able to stop an agent that has a perfectly valid, perfectly pinned, byte-identical card. So
//! suspension is its own field with its own reason string, checked independently of the pin, and a
//! suspended agent is out of the catalogue and refused at dispatch regardless of how trusted it is.
//! A reason is REQUIRED, not optional: a suspension nobody can explain is one whose thresholds get
//! raised into uselessness.
//!
//! ## The fetch is a SEAM, and it is a seam on purpose
//!
//! Nothing here performs I/O. The card fetch (its SSRF guard, its two well-known paths, its
//! redirect policy) is the delegating side's, and this module takes it as a [`CardSource`]. That
//! keeps every verb's DECISION unit-testable against a source that returns exactly the answer a test
//! wants — including the answers a real network makes hard to produce on demand, like "the same host
//! served a different card the second time".

use super::pin::CardPin;
use super::reverify::{self, Due, Ledger, Policy};
use crate::trust::{Approval, Drift, Observation, Sighting, TrustState};

/// WHERE A CARD COMES FROM. Implemented by the delegating side's fetcher; implemented by a stub in
/// tests. The verbs never learn whether the answer came from a socket or a fixture.
///
/// `agent_id` rather than a URL: the backend URL is server-side only and is never client-visible,
/// and a verb layer that took a URL would be one an admin request could aim.
pub(crate) trait CardSource {
    /// Fetch the agent's card and hand back the document AS RECEIVED. `Err` is a CONTACT failure
    /// (DNS, TLS, HTTP, malformed document) — anything where busbar did not obtain a card it could
    /// read.
    ///
    /// THE RAW DOCUMENT, NOT [`super::card::AgentCard`], and that is a correctness requirement rather
    /// than a convenience. Both hashes on this plane — the pinned fingerprint and the per-skill digests —
    /// are taken over the received bytes, precisely so that a member busbar does not model cannot
    /// change without registering as drift. That type is busbar's PROJECTION: parsing to it
    /// discards every unmodelled member, so a fingerprint computed downstream of one would be blind
    /// to exactly the silent rug-pull the pin exists to catch. This seam originally carried
    /// the projection; the type is what makes the mistake impossible rather than remembered.
    fn fetch_card(&self, agent_id: &str) -> Result<serde_json::Value, String>;
}

/// HOW A CARD BECOMES AN OBSERVATION: the JWS verification against the operator-pinned issuer key,
/// the canonical fingerprint, and the per-skill digests that make up the capability set.
///
/// A SECOND seam rather than a method on [`CardSource`], because the two are genuinely separate
/// concerns and are owned by different halves of this plane: obtaining bytes over a hostile network,
/// and deciding what those bytes prove. Keeping them apart is also what lets a test exercise "the
/// fetch succeeded and the signature did not", which is the case that matters most and the hardest
/// one to stage against a real endpoint.
pub(crate) trait CardObserver {
    /// `Err` is a VERIFICATION failure (unpinned card, wrong issuer key, bad signature). It is
    /// deliberately the same arm a contact failure lands in downstream — both derive `Error`, and
    /// neither may ever silently read as "unchanged".
    ///
    /// Takes the document AS RECEIVED for the reason [`CardSource::fetch_card`] returns one: the
    /// signature covers the canonical received bytes with `signatures` removed, and the fingerprint
    /// covers the canonical received bytes entire. Neither is computable from busbar's projection.
    fn observe(&self, card: &serde_json::Value) -> Result<Observation<CardPin>, String>;
}

/// THE TWO SEAMS, TRAVELLING TOGETHER. Fetch and verify are separate concerns but they are never
/// used apart — a fetch nobody verifies produces a document with no standing, and a verification
/// with nothing to verify is not a thing. Bundling them keeps each verb's signature about the
/// DECISION it makes rather than about how a card is obtained.
pub(crate) struct CardProbe<'a> {
    pub(crate) source: &'a dyn CardSource,
    pub(crate) observer: &'a dyn CardObserver,
}

impl CardProbe<'_> {
    /// Fetch, verify, and reduce both failures to the SAME arm.
    ///
    /// A contact failure and a verification failure are different events with an identical
    /// consequence: neither may ever read as "unchanged". Collapsing them here, once, is what stops
    /// a future call site from handling one and forgetting the other.
    fn look(&self, agent_id: &str) -> Sighting<CardPin> {
        match self.source.fetch_card(agent_id) {
            Err(e) => Sighting::Failed(e),
            Ok(card) => match self.observer.observe(&card) {
                Err(e) => Sighting::Failed(e),
                Ok(observation) => Sighting::Seen(observation),
            },
        }
    }
}

/// What `connect` found. A REPORT, not a grant.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ConnectPreview {
    /// The agent this preview is about.
    pub(crate) agent_id: String,
    /// The sighting that would be RECORDED if the operator approves. Carries the observed pin.
    pub(crate) sighting: Sighting<CardPin>,
    /// The trust state the registration is in AFTER the preview. Always a state that cannot serve —
    /// see [`ConnectPreview::grants_nothing`].
    pub(crate) state: TrustState,
    /// What differs from what is already approved. Empty on a first connect (nothing is approved
    /// yet, so nothing can differ); populated when an operator re-connects an existing registration
    /// and the card has moved.
    pub(crate) drift: Drift,
    /// The canonical card fingerprint an operator is being asked to approve, when one exists. This
    /// is the string that goes in front of the human, so it is surfaced explicitly rather than left
    /// for a caller to dig out of the sighting.
    pub(crate) fingerprint: Option<String>,
}

impl ConnectPreview {
    /// The invariant this whole verb exists to hold: a preview can never leave a registration in a
    /// state that serves traffic. Asserted by the verb's own tests over every branch.
    pub(crate) fn grants_nothing(&self) -> bool {
        !matches!(self.state, TrustState::Approved)
    }
}

/// `POST /agents/{id}/connect` — FETCH, VERIFY, REPORT. Grants nothing, ever.
///
/// The approval decision is deliberately NOT taken here even when everything checks out, because
/// "everything checked out" is a statement about a signature and a fingerprint, and the operator is
/// being asked a different question: is this the agent I meant, run by the party I think runs it.
/// Only a human holds that.
pub(crate) fn connect(
    agent_id: &str,
    approval: &Approval<CardPin>,
    probe: &CardProbe<'_>,
) -> ConnectPreview {
    // A CONTACT FAILURE IS A SIGHTING, not an absence. Recording it derives `Error`, which never
    // serves; treating it as "nothing observed" would leave a previously-trusted registration
    // looking fine because the check could not be performed, which is the cheapest possible way for
    // an upstream to avoid being checked.
    let sighting = probe.look(agent_id);
    let state = approval.state(&sighting);
    let drift = approval.drift(&sighting);
    let fingerprint = match &sighting {
        Sighting::Seen(o) => o
            .pin
            .as_ref()
            .and_then(|p| p.card_fingerprint())
            .map(str::to_string),
        _ => None,
    };
    ConnectPreview {
        agent_id: agent_id.to_string(),
        sighting,
        // A PREVIEW NEVER REPORTS `Approved`. `Approval::state` can legitimately derive `Approved`
        // when the observed card matches an ALREADY-locked pin, and that is an honest answer to a
        // different question — but returning it FROM `connect` invites a caller to treat the preview
        // as the grant, which is the exact confusion this verb exists to prevent. The preview reports
        // `Pending`; the registration itself is what a caller reads for the live state. Nothing here
        // writes, so the live state is untouched either way.
        state: if matches!(state, TrustState::Approved) {
            TrustState::Pending
        } else {
            state
        },
        drift,
        fingerprint,
    }
}

/// What `sync` did. Every field is something an operator asked a question that this answers.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SyncOutcome {
    pub(crate) agent_id: String,
    /// Why the check ran. Always [`Due::OperatorSync`] for this verb — carried so the audit row and
    /// the background job's row have the same shape and can be read together.
    pub(crate) due: Due,
    /// The sighting now RECORDED, after the recovery-backoff fold.
    pub(crate) recorded: Sighting<CardPin>,
    /// The trust state that sighting derives.
    pub(crate) state: TrustState,
    /// Drift was OBSERVED on this pass, whether or not it was acted on.
    pub(crate) drift_observed: bool,
    /// A clean answer was DISBELIEVED because the backoff since the last drift has not elapsed.
    pub(crate) recovery_held: bool,
}

/// `POST /agents/{id}/sync` — force the re-fetch and re-verify NOW.
///
/// Everything it does, the background job also does; the only difference is that the timer is not
/// consulted. That is deliberate and is the anti-drift property of this verb: two code paths that
/// could reach different conclusions from the same card is a bug waiting for the day they disagree.
pub(crate) fn sync(
    agent_id: &str,
    approval: &Approval<CardPin>,
    recorded: &Sighting<CardPin>,
    ledger: &mut Ledger,
    policy: &Policy,
    now_ms: u64,
    probe: &CardProbe<'_>,
) -> SyncOutcome {
    let due = reverify::due(ledger, policy, now_ms, true);
    debug_assert!(due.should_check(), "an operator sync is always due");
    let observed = probe.look(agent_id);
    let settled = reverify::settle(approval, recorded, observed, ledger, policy, now_ms);
    let state = approval.state(&settled.sighting);
    SyncOutcome {
        agent_id: agent_id.to_string(),
        due,
        recorded: settled.sighting,
        state,
        drift_observed: settled.drift_observed,
        recovery_held: settled.recovery_held,
    }
}

/// Why a `suspend` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SuspendError {
    /// No reason, or a reason that names nothing. REQUIRED, and this is not bureaucracy: the reason
    /// is what lets the next operator tell a real degradation from a false positive in seconds, and
    /// a breaker whose trips are unexplainable gets its thresholds raised until it never trips.
    ReasonMissing,
}

impl std::fmt::Display for SuspendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SuspendError::ReasonMissing => write!(
                f,
                "a suspension must carry an operator-visible reason naming why the agent was pulled \
                 out of service"
            ),
        }
    }
}

/// The shortest reason that says anything. A token like `x` or `bad` names nothing and is refused
/// for the same reason an empty string is.
const MIN_REASON_LEN: usize = 8;

/// `POST /agents/{id}/suspend` — the human override.
///
/// Applies to the registration REGARDLESS of trust state, and that independence is the whole point:
/// the failure this defends against is a legitimately-approved agent with a byte-identical card that
/// simply starts behaving badly, which triggers nothing in the card-identity machinery by
/// construction.
pub(crate) fn operator_suspend(
    approval: &mut Approval<CardPin>,
    reason: &str,
    operator: &str,
) -> Result<String, SuspendError> {
    let reason = reason.trim();
    if reason.len() < MIN_REASON_LEN {
        return Err(SuspendError::ReasonMissing);
    }
    // The operator's id is folded into the stored reason rather than kept beside it, because the two
    // are only useful together: "suspended: vendor breach notice" without a name is an assertion
    // nobody can follow up on.
    let stamped = format!("{reason} (suspended by {operator})");
    approval.suspend(&stamped);
    Ok(stamped)
}

/// `POST /agents/{id}/resume` — the inverse, and deliberately NOT symmetric in what it requires.
///
/// Suspension demands a reason because it takes an agent out of service on a human's judgement.
/// Resumption does not, because the evidence that matters for a resume is the trust state the
/// machine still holds: a resumed agent is only usable if its pin still verifies, and this cannot
/// make an unverified agent serve. Requiring ceremony here would buy nothing and would slow the
/// recovery from a false positive, which is the failure mode that trains operators to stop
/// suspending at all.
pub(crate) fn operator_resume(approval: &mut Approval<CardPin>) {
    approval.resume();
}

#[cfg(test)]
#[path = "tests/verbs_tests.rs"]
mod verbs_tests;

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NON-CRUD ADMIN VERBS: `connect`, `approve`, `sync`, `suspend`.
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

// `connect` IS MOUNTED, and the mount is not here. `POST /api/v1/admin/agents/{name}/connect` is
// [`crate::admin::planeverbs::connect`], written once and parameterised by plane; what this plane
// supplies is [`A2aAgents`] at the foot of this file — where a registration is resolved from, and
// what looking at one means. The approval half, `POST .../approve`, IS here, because echoing a
// fingerprint back is a verb only this plane has. Until both landed, this file was tested and
// unreachable, and a busbar booted from YAML could not serve a fronted agent by any sequence of
// operator actions.
//
// STILL UNMOUNTED, and named rather than left to be discovered: `sync`, `operator_suspend` and
// `operator_resume`. The re-verification the first forces happens on the timer, and the other two
// are the out-of-band-intelligence override; each needs its own admin verb and its own audit row,
// and adding them alongside `connect` would have been three unreviewed surfaces instead of one.
#![cfg_attr(not(test), allow(dead_code))]

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;

use super::config::AgentPinCfg;
use super::pin::CardPin;
use super::plane::A2aPlane;
use super::registry::AgentRegistration;
use super::reverify::{self, Due, Ledger, Policy};
use crate::admin::planeverbs::{self, PlaneTrust};
use crate::admin::v1::contract::taxonomy::Cond;
use crate::admin::v1::contract::AdminError;
use crate::diagnostics::{diag_error, A2A_CARD_FETCH_PANICKED};
use crate::plane::Plane;
use crate::state::AppHandle;
use crate::trust::{Approval, Drift, Observation, Sighting, TrustState};

/// A CARD, PLUS WHAT THE CONNECTION IT ARRIVED ON PROVED.
///
/// Two facts rather than one, because an A2A card's signature is OPTIONAL and an unsigned card's
/// only authenticity root is the transport it came over. A seam that carried the document alone
/// would make `cert_spki` unobservable through the verb layer while the re-verification sweep could
/// see it — one plane with two answers about the same registration, decided by which code path
/// asked.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SightedCard {
    /// The document AS RECEIVED. Never a re-serialization; see [`CardSource::fetch_card`].
    pub(crate) document: serde_json::Value,
    /// The `sha256/…` SPKI pin of the certificate the SERVING hop presented, where the hop ran over
    /// TLS. `None` on plaintext, and `None` is a refusal for a transport-pinned registration rather
    /// than a pass.
    pub(crate) peer_spki: Option<String>,
    /// THE OTHER END OF THE SAME HANDSHAKE: whether the hop that served this card carried busbar's
    /// client certificate for the registration it was fetched for. Carried for the same reason the
    /// peer's pin is — an `mtls` registration's mutual half is a fact about the connection, so a
    /// seam that dropped it would make the verb layer answer "not presented" about a card the sweep
    /// verified, which is one plane with two answers decided by which path asked.
    pub(crate) client_identity_offered: bool,
}

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
    fn fetch_card(&self, agent_id: &str) -> Result<SightedCard, String>;
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
    fn observe(&self, card: &SightedCard) -> Result<Observation<CardPin>, String>;
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
        self.look_documented(agent_id).0
    }

    /// As [`Self::look`], but also returns the card document AS RECEIVED on a verified sighting.
    ///
    /// The document is the exact bytes an operator is being asked to approve, and `approve` caches
    /// them so the agent it just adopted is immediately servable rather than waiting for a
    /// delegation to warm the catalogue: under verify-on-call there is no background sweep to fetch
    /// the first card, so an approved-but-never-delegated agent would otherwise stay excluded from
    /// every caller's catalogue (`Excluded::NoCachedCard`) and answer `503` on `/a2a/agents/{id}`.
    /// `None` on any failure arm, exactly as the sighting is `Failed` there.
    fn look_documented(&self, agent_id: &str) -> (Sighting<CardPin>, Option<serde_json::Value>) {
        match self.source.fetch_card(agent_id) {
            Err(e) => (Sighting::Failed(e), None),
            Ok(card) => match self.observer.observe(&card) {
                Err(e) => (Sighting::Failed(e), None),
                Ok(observation) => (Sighting::Seen(observation), Some(card.document)),
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
    /// The card document AS RECEIVED on a verified sighting — the exact bytes behind `fingerprint`.
    /// `None` on a failed sighting. Carried so `approve` can cache the document it just verified
    /// (`AgentRegistration::cached_card`), which is what makes an approved agent servable at all
    /// under verify-on-call: there is no sweep to fetch the first card, so without this the
    /// catalogue would exclude the agent for `NoCachedCard` no matter how the trust axis reads.
    pub(crate) observed_document: Option<serde_json::Value>,
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
    let (sighting, observed_document) = probe.look_documented(agent_id);
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
        observed_document,
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
    // The operator `sync` verb ALWAYS re-checks: `reverify::due(.., operator_sync = true)` is
    // unconditionally `Due::OperatorSync`. Route it through the same host seam the background job uses
    // (`plane_host::trust::verify_decide_due`, `operator_sync = true`) rather than reaching
    // `crate::trust::reverify::due` directly, so the a2a plane no longer touches the reverify primitive.
    let due = crate::plane_host::trust::verify_decide_due(ledger.last_checked_ms, policy.ttl_ms, now_ms, true);
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

// ══ THE ADMIN MOUNT: this plane's half of the ONE surface in `crate::admin::planeverbs` ══════════
//
// The sequence a trust verb follows — resolve the registration or refuse with a `404`, go and look,
// audit whatever was found — is not this plane's. It is `admin::planeverbs`, once, because it was
// written down twice and a shape written twice is a shape whose two copies get fixed once each.
//
// What is genuinely this plane's is below: where a registration is resolved from, what looking at
// one means, and `approve` — the verb that has no sibling, because echoing a fingerprint back is a
// trust root only a plane with a signed document to fingerprint can have.
//
// THE CARD FETCH IS BLOCKING, which is why the look hops threads. `super::fetch` resolves, pins and
// connects synchronously behind its SSRF guard, and running that on a reactor thread would stall
// every request sharing it for as long as an upstream chose to take. The registration and its pin
// are CLONED out from under the registry lock before the hop, so no lock is held across it.

/// THE TRUST VIEW of one registered agent — what both verbs answer with.
///
/// The sibling of [`crate::mcp::admin_view::McpTrustView`] and shaped like it on purpose: an
/// operator console rendering both planes should be rendering one component. It is NOT the same
/// type, because the two planes' capability vocabularies differ (a `tools:` entry has an approved
/// digest per tool; an `agents:` entry has a skill set on a card) and merging them would mean one
/// of the planes filling in fields that mean nothing to it.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct A2aTrustView {
    pub(crate) name: String,
    /// `pending`, `approved`, `quarantined`, `suspended` or `error`. DERIVED on every read from the
    /// standing approval and the sighting, so there is no stored state to go stale.
    pub(crate) state: &'static str,
    /// The operator's word for the authenticity root, as the OBSERVED pin names it. Never
    /// interpreted by the machine.
    pub(crate) pin_mechanism: &'static str,
    /// THE CANONICAL CARD FINGERPRINT AN OPERATOR IS BEING ASKED TO APPROVE. Surfaced explicitly
    /// rather than left for a caller to dig out, because this is the one string that goes in front
    /// of the human and `approve` refuses anything else.
    pub(crate) fingerprint: Option<String>,
    /// The presented identity is not the locked one. Its own axis: adopting a new identity is a
    /// different act from adopting new content.
    pub(crate) pin_changed: bool,
    /// Offered now, never ruled on.
    pub(crate) added: Vec<String>,
    /// Approved, but offered at a DIFFERENT digest. THIS IS THE RUG-PULL ROW.
    pub(crate) changed: Vec<String>,
    /// Approved, and no longer offered.
    pub(crate) removed: Vec<String>,
    /// How many skills the observation carried.
    pub(crate) observed_skills: usize,
    /// Why the contact failed, when it did.
    pub(crate) failure: Option<String>,
}

/// The `approve` request body. ONE required field, and it is required because it is the operator's
/// evidence that they looked.
#[derive(Debug, Clone, serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(crate) struct ApproveReq {
    /// The canonical card fingerprint EXACTLY as `connect` reported it.
    pub(crate) fingerprint: String,
}

/// Everything the A2A look needs, cloned out of the live snapshot.
///
/// Both the REGISTRATION (which carries the standing approval and the accumulated sighting) and the
/// operator's PIN (which is re-read from config on every apply, and is what a card is verified
/// against) are required. A registration present without a pin is not a state a config generation
/// can produce — [`A2aPlane::from_config`] inserts both in one pass — so a missing either way is the
/// same not-found rather than two answers a caller could tell apart.
pub(crate) struct A2aSubject {
    plane: Arc<A2aPlane>,
    registration: AgentRegistration,
    pin_cfg: AgentPinCfg,
}

/// THE A2A PLANE'S TRUST SURFACE. Three items, and the shared surface owns everything else.
pub(crate) struct A2aAgents;

impl PlaneTrust for A2aAgents {
    const PLANE: Plane = Plane::A2a;
    type Subject = A2aSubject;
    type View = A2aTrustView;

    fn resolve(app: &Arc<crate::state::App>, name: &str) -> Result<A2aSubject, AdminError> {
        planeverbs::registered(Plane::A2a, name, || {
            let plane = app.a2a.clone()?;
            let registration = plane
                .with_registrations(|regs| regs.iter().find(|r| r.agent_id == name).cloned())?;
            let pin_cfg = plane.pin_for(name).cloned()?;
            Some(A2aSubject {
                plane,
                registration,
                pin_cfg,
            })
        })
    }

    async fn look(subject: A2aSubject, name: String) -> Result<A2aTrustView, AdminError> {
        let preview = look(&subject).await?;
        debug_assert!(
            preview.grants_nothing(),
            "a preview may never report a state that serves"
        );
        Ok(preview_view(&name, &preview))
    }
}

/// THE LOOK: fetch, verify, and report, off the reactor.
///
/// One function for both verbs so an `approve` cannot be judging a different observation from the
/// one an operator previewed. Returns this layer's own preview type — it decides nothing about
/// trust, it only carries the answer.
async fn look(subject: &A2aSubject) -> Result<ConnectPreview, AdminError> {
    let policy = subject
        .plane
        .fetch_policy_for(&subject.registration.agent_id);
    let registration = subject.registration.clone();
    let pin_cfg = subject.pin_cfg.clone();
    tokio::task::spawn_blocking(move || {
        let live = super::transport::LiveCardFetch::new(policy);
        let probe = live.probe(&registration, &pin_cfg);
        let seams = CardProbe {
            source: &probe,
            observer: &probe,
        };
        connect(&registration.agent_id, &registration.approval, &seams)
    })
    .await
    .map_err(|e| {
        // A PANIC IN THE FETCH IS NOT A TRUST ANSWER. Reported as an internal failure rather than
        // folded into the preview, because a preview that reads `error` is a statement about the
        // upstream and this is a statement about busbar.
        diag_error!(A2A_CARD_FETCH_PANICKED, error = %e, "a2a: the card fetch panicked during an operator-driven verb");
        AdminError::Internal
    })
}

/// `POST /api/v1/admin/agents/{name}/approve` — lock the identity the operator has SEEN.
///
/// The body carries the fingerprint `connect` reported. The card is re-fetched and re-verified here
/// rather than taken from anything `connect` left behind, and the two must agree: an `approve` that
/// adopted whatever the endpoint happened to be serving at the moment the button was pressed would
/// be trust-on-first-use with a human in the loop for decoration.
///
/// It is NOT on the shared surface, and that is the honest boundary rather than an omission. The
/// shared `connect` is "resolve, look, audit"; this is "resolve, look, COMPARE AGAINST WHAT THE
/// HUMAN SAW, then write under the registry lock". The comparison and the write are the verb, and
/// the plane that has no signed document to fingerprint has no counterpart to share them with.
///
/// What it does NOT do: lift an `unpinned` registration. That cap is
/// [`super::pin::approve_registration`]'s and is not re-decided here — a second opinion about what
/// may be approved is a second opinion that can disagree.
pub(crate) async fn approve(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
    body: Result<axum::Json<ApproveReq>, axum::extract::rejection::JsonRejection>,
) -> Response {
    const VERB: &str = "approve";
    let app = handle.load();
    // THE 404 BEFORE THE BODY. An unknown agent must answer the same way whether or not the caller
    // sent something parseable, or the shape of the error becomes an existence oracle.
    let subject = match A2aAgents::resolve(&app, &name) {
        Ok(v) => v,
        Err(e) => return crate::admin::v1::json::err_json(&e),
    };
    let req = match body {
        Ok(axum::Json(req)) => req,
        Err(e) => {
            // TAGGED with its condition. This operation declares two `Validation` conditions, and
            // an untagged emission proves only that one of them is reachable — see the over-claim
            // half of `declared_error_set_is_exactly_what_the_handlers_emit`.
            return crate::admin::v1::json::err_json_cond(
                &AdminError::Validation(format!(
                    "the approve body must be `{{\"fingerprint\": \"…\"}}` naming the \
                     fingerprint `connect` reported: {e}"
                )),
                Cond::MalformedBody,
            );
        }
    };

    let preview = match look(&subject).await {
        Ok(p) => p,
        Err(e) => return crate::admin::v1::json::err_json(&e),
    };
    if let Err(refusal) = agrees(&preview, req.fingerprint.trim()) {
        planeverbs::audit(
            Plane::A2a,
            VERB,
            &name,
            crate::admin::audit::OUTCOME_REJECTED,
            &principal,
        );
        return crate::admin::v1::json::err_json_cond(
            &AdminError::Validation(refusal),
            Cond::InvalidConfig,
        );
    }

    // ── THE WRITE, under the registry's own lock, against the sighting just observed. ────────────
    let applied = subject.plane.with_registrations_mut(|regs| {
        // RE-FOUND under the lock rather than mutating the clone: a config apply may have removed
        // the registration while the card was being fetched, and writing an approval back into a
        // registry that no longer has the row would be approving something nobody registered.
        let Some(reg) = regs.iter_mut().find(|r| r.agent_id == name) else {
            return Err(AdminError::not_found(format!(
                "{} `{name}`",
                Plane::A2a.subject_noun()
            )));
        };
        super::pin::approve_registration(&mut reg.approval, &preview.sighting, None)
            .map_err(|e| AdminError::Validation(e.to_string()))?;
        // RECORD WHAT WAS SEEN. The approval just adopted this exact observation, so it derives no
        // drift and the state is `Approved` either way — but leaving `Never` behind would report a
        // registration that has demonstrably been contacted as one that never has.
        reg.sighting = preview.sighting.clone();
        // WARM THE SERVED CARD from the exact document this approval just verified. Under
        // verify-on-call there is no background sweep, so the first card has to be cached by the
        // operator act that adopted it — otherwise the registration is `Approved` (delegable on the
        // trust axis) yet absent from every caller's catalogue for `NoCachedCard`, `/a2a/agents/{id}`
        // answers `503`, and every delegation is refused before it can warm anything. These are the
        // bytes behind the fingerprint the operator echoed (`agrees` above), so caching them cannot
        // adopt a card the human did not see; verify-on-call re-checks them on the delegation path
        // within `verify_ttl` thereafter. Present on every `Seen` sighting, which an agreeing
        // fingerprint is.
        if let Some(document) = preview.observed_document.clone() {
            reg.cached_card = Some(document);
        }
        Ok(reg.clone())
    });
    let reg = match applied {
        Ok(r) => r,
        Err(e) => {
            planeverbs::audit(
                Plane::A2a,
                VERB,
                &name,
                crate::admin::audit::OUTCOME_REJECTED,
                &principal,
            );
            return crate::admin::v1::json::err_json(&e);
        }
    };
    planeverbs::audit(
        Plane::A2a,
        VERB,
        &name,
        crate::admin::audit::OUTCOME_APPLIED,
        &principal,
    );
    crate::admin::v1::json::ok_json(StatusCode::OK, &registration_view(&name, &reg))
}

/// Does what the endpoint is serving RIGHT NOW agree with what the operator says they approved?
///
/// Split out so the three refusals are one readable table rather than three arms threaded through
/// the handler. Every arm is a refusal: there is no path here that approves something the operator
/// did not name.
fn agrees(preview: &ConnectPreview, claimed: &str) -> Result<(), String> {
    if claimed.is_empty() {
        return Err(
            "`fingerprint` must name the canonical card fingerprint `connect` reported. An \
             approval with nothing to compare is trust-on-first-use with a button on it."
                .to_string(),
        );
    }
    if let Sighting::Failed(reason) = &preview.sighting {
        return Err(format!(
            "the agent's card could not be authenticated, so there is nothing to approve: {reason}"
        ));
    }
    match preview.fingerprint.as_deref() {
        // An observation with no fingerprint is an `unpinned` registration. It is refused HERE with
        // the reason an operator can act on, and it would be refused again by
        // `pin::approve_registration`; this arm exists so the message names the registration's
        // posture rather than the machine's internal "no pin to lock".
        None => Err(
            "this registration has no authenticity root (`pin.mechanism: unpinned`), so the card \
             it serves has no fingerprint to approve. Supply an issuer key or a certificate SPKI \
             out of band and name it in `pin:`."
                .to_string(),
        ),
        Some(observed) if observed == claimed => Ok(()),
        Some(observed) => Err(format!(
            "the endpoint is serving fingerprint `{observed}` and the approval names `{claimed}`. \
             The card moved between the preview and the approval, or the approval is for a \
             different agent; re-run `connect` and read the new fingerprint before approving."
        )),
    }
}

/// Project a preview onto the trust view.
fn preview_view(name: &str, preview: &ConnectPreview) -> A2aTrustView {
    A2aTrustView {
        name: name.to_string(),
        state: preview.state.word(),
        pin_mechanism: mechanism_of(&preview.sighting),
        fingerprint: preview.fingerprint.clone(),
        pin_changed: preview.drift.pin_changed,
        added: preview.drift.added.clone(),
        changed: preview.drift.changed.clone(),
        removed: preview.drift.removed.clone(),
        observed_skills: observed_skills(&preview.sighting),
        failure: match &preview.sighting {
            Sighting::Failed(reason) => Some(reason.clone()),
            _ => None,
        },
    }
}

/// Project a LIVE registration onto the same view — what `approve` answers with, so the operator
/// reads the state the registry now holds rather than the preview that preceded it.
fn registration_view(name: &str, reg: &AgentRegistration) -> A2aTrustView {
    let drift = reg.changes();
    A2aTrustView {
        name: name.to_string(),
        state: reg.trust_state().word(),
        pin_mechanism: mechanism_of(&reg.sighting),
        fingerprint: reg
            .approval
            .pin()
            .and_then(CardPin::card_fingerprint)
            .map(str::to_string),
        pin_changed: drift.pin_changed,
        added: drift.added,
        changed: drift.changed,
        removed: drift.removed,
        observed_skills: observed_skills(&reg.sighting),
        failure: match &reg.sighting {
            Sighting::Failed(reason) => Some(reason.clone()),
            _ => None,
        },
    }
}

/// The mechanism the OBSERVED pin names, or `unpinned` where nothing was observed.
///
/// Read off the sighting rather than off the config, deliberately: the question an operator is
/// asking on this surface is what the endpoint proved, and echoing back the mechanism they
/// configured would answer it with their own input.
fn mechanism_of(sighting: &Sighting<CardPin>) -> &'static str {
    use crate::trust::PinnedArtifact as _;
    sighting
        .observation()
        .and_then(|o| o.pin.as_ref())
        .map_or("unpinned", |p| p.mechanism())
}

/// How many skills the observation carried. Zero for a failed or absent contact, which is honest:
/// nothing was observed.
fn observed_skills(sighting: &Sighting<CardPin>) -> usize {
    sighting.observation().map_or(0, |o| o.capabilities.len())
}

#[cfg(test)]
#[path = "tests/verbs_tests.rs"]
mod verbs_tests;

// Driven over the REAL router, because "mounted and reachable at the right scope" is the claim — and
// on this plane it is the WHOLE claim, since the verb underneath was already tested and already
// unreachable.
//
// GATED ON `auth-admin-tokens` for the reason the MCP plane's sibling gives: every test in there
// authenticates with `x-admin-token`, and under `--no-default-features` there is no admin auth
// module, so the chain fails closed and every request is a 401 before it reaches a verb.
#[cfg(all(test, feature = "auth-admin-tokens"))]
#[path = "tests/adminverbs_tests.rs"]
pub(crate) mod adminverbs_tests;

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A TRUST VERBS on the admin API — `connect` and `approve`.
//!
//! ## Why this file exists, stated plainly
//!
//! Every `agents:` registration is born `Pending` ([`super::registry::AgentRegistration::registered`]
//! is the only constructor and it is the fail-closed floor), and
//! [`super::plane::A2aPlane::from_config`] correctly declines to lift a declared pin into an
//! approval — an approval is a statement about a document that was actually SEEN. All of that is
//! right and stays. What was missing was the other half: [`super::verbs::connect`] existed, was
//! unit-tested, and **had no mounted route**, while the sibling plane's
//! [`crate::mcp::adminverbs::connect`] had one. So a busbar booted from YAML could not serve a
//! fronted agent by any sequence of operator actions — the receiving plane was unreachable in
//! production, and every A2A unit test passed while it was.
//!
//! The defect was never that `Pending` exists. It is that nothing could leave it.
//!
//! ## It is the SAME SHAPE as the MCP plane's, deliberately
//!
//! `registered()` lookup and its single 404, an `AUDIT_ACTION` named once, `POST` because the verb
//! reaches the network, the frozen `{"error":{"code","message"}}` envelope through
//! `admin::v1::json::{ok_json, err_json}`, audited whatever it found. Three of this release's
//! security defects came from plane-local drift, so the second implementation of a shape is written
//! as a copy of the first or not at all — and where the two genuinely shared a value, the value
//! moved into the shared machine instead ([`crate::trust::TrustState::word`], which
//! `mcp::connect::ConnectReport::state_word` now calls).
//!
//! ## `connect` PREVIEWS and WRITES NOTHING; `approve` is the separate human act
//!
//! [`super::verbs::connect`]'s whole property is that it never grants and never writes, and this
//! layer does not reach around it: `connect` fetches, verifies and reports, and the registry is
//! untouched by it. The fingerprint the preview surfaces is what a human reads.
//!
//! `approve` then requires that human to ECHO that fingerprint back. That echo is the trust root,
//! and it is why the two verbs do not share state: an `approve` that adopted whatever the endpoint
//! happened to be serving at the moment the button was pressed would be trust-on-first-use with a
//! human in the loop for decoration. The fingerprint is re-observed on the approve call itself and
//! compared, so a card that changed between the preview and the click is a refusal rather than an
//! approval of something nobody looked at.
//!
//! ## The card fetch is BLOCKING, and that is why the handlers hop threads
//!
//! [`super::fetch`] resolves, pins and connects synchronously behind its SSRF guard. Running that on
//! a reactor thread would stall every request sharing it for as long as an upstream chose to take,
//! which is the same reason [`super::scheduler::spawn_reverifier`] uses `spawn_blocking`. The
//! registration and its pin are CLONED out from under the registry lock before the hop, so no lock
//! is held across it.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::admin::v1::contract::taxonomy::Cond;
use crate::admin::v1::contract::AdminError;
use crate::state::AppHandle;
use crate::trust::Sighting;

use super::config::AgentPinCfg;
use super::pin::CardPin;
use super::plane::A2aPlane;
use super::registry::AgentRegistration;

/// The audit action words, named once each so a new verb cannot invent a spelling.
const AUDIT_CONNECT: &str = "a2a_agent.connect";
const AUDIT_APPROVE: &str = "a2a_agent.approve";

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

/// The `approve` request body. ONE required field, and it is required for the reason the module note
/// gives: it is the operator's evidence that they looked.
#[derive(Debug, Clone, serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub(crate) struct ApproveReq {
    /// The canonical card fingerprint EXACTLY as `connect` reported it.
    pub(crate) fingerprint: String,
}

/// Look one registered agent up on the live plane, or produce the 404.
///
/// Both the REGISTRATION (which carries the standing approval and the accumulated sighting) and the
/// operator's PIN (which is re-read from config on every apply, and is what a card is verified
/// against) are needed. A registration present without a pin is not a state a config generation can
/// produce — [`A2aPlane::from_config`] inserts both in one pass — so a missing either way is the
/// same `not_found` rather than two answers a caller would have to distinguish.
fn registered(
    app: &Arc<crate::state::App>,
    name: &str,
) -> Result<(Arc<A2aPlane>, AgentRegistration, AgentPinCfg), AdminError> {
    let plane = app
        .a2a
        .clone()
        .ok_or_else(|| AdminError::not_found(format!("fronted agent `{name}`")))?;
    let registration =
        plane.with_registrations(|regs| regs.iter().find(|r| r.agent_id == name).cloned());
    match (registration, plane.pin_for(name).cloned()) {
        (Some(reg), Some(pin)) => Ok((plane, reg, pin)),
        _ => Err(AdminError::not_found(format!("fronted agent `{name}`"))),
    }
}

/// THE LOOK: fetch, verify, and report, off the reactor.
///
/// One function for both verbs so an `approve` cannot be judging a different observation from the
/// one an operator previewed. Returns the verb layer's own preview type — this layer decides nothing
/// about trust, it only carries the answer.
async fn look(
    plane: &Arc<A2aPlane>,
    registration: &AgentRegistration,
    pin_cfg: &AgentPinCfg,
) -> Result<super::verbs::ConnectPreview, AdminError> {
    let policy = plane.fetch_policy_for(&registration.agent_id);
    let registration = registration.clone();
    let pin_cfg = pin_cfg.clone();
    tokio::task::spawn_blocking(move || {
        let live = super::transport::LiveCardFetch::new(policy);
        let probe = live.probe(&registration, &pin_cfg);
        let seams = super::verbs::CardProbe {
            source: &probe,
            observer: &probe,
        };
        super::verbs::connect(&registration.agent_id, &registration.approval, &seams)
    })
    .await
    .map_err(|e| {
        // A PANIC IN THE FETCH IS NOT A TRUST ANSWER. Reported as an internal failure rather than
        // folded into the preview, because a preview that reads `error` is a statement about the
        // upstream and this is a statement about busbar.
        tracing::error!(error = %e, "a2a: the card fetch panicked during an operator-driven verb");
        AdminError::Internal
    })
}

/// `POST /api/v1/admin/agents/{name}/connect` — fetch the card, verify it, and report. GRANTS
/// NOTHING, and writes nothing.
///
/// A CONTACT OR VERIFICATION FAILURE IS A `200`, with the reason in `failure` and `state: error`.
/// The request succeeded — it found something, and what it found is that the endpoint cannot
/// currently be authenticated. The sibling plane answers the same way for the same reason: a 5xx
/// here would say busbar failed, and busbar did not.
pub(crate) async fn connect(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
) -> Response {
    let app = handle.load();
    let (plane, registration, pin_cfg) = match registered(&app, &name) {
        Ok(v) => v,
        Err(e) => return crate::admin::v1::json::err_json(&e),
    };
    let preview = match look(&plane, &registration, &pin_cfg).await {
        Ok(p) => p,
        Err(e) => return crate::admin::v1::json::err_json(&e),
    };
    // AUDITED WHATEVER IT FOUND. A preview that could not authenticate the endpoint is the single
    // most operator-relevant thing this surface reports, and recording only the clean ones would
    // make the trail silent at exactly the moment it matters.
    crate::admin::audit::AUDIT.record_by(
        AUDIT_CONNECT,
        &format!("a2a_agent:{name}"),
        crate::admin::audit::OUTCOME_APPLIED,
        principal.actor_id(),
    );
    debug_assert!(
        preview.grants_nothing(),
        "a preview may never report a state that serves"
    );
    crate::admin::v1::json::ok_json(StatusCode::OK, &preview_view(&name, &preview))
}

/// `POST /api/v1/admin/agents/{name}/approve` — lock the identity the operator has SEEN.
///
/// The body carries the fingerprint `connect` reported. The card is re-fetched and re-verified here
/// rather than taken from anything `connect` left behind, and the two must agree; see the module
/// note for why the echo is the trust root rather than ceremony.
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
    let app = handle.load();
    // THE 404 BEFORE THE BODY. An unknown agent must answer the same way whether or not the caller
    // sent something parseable, or the shape of the error becomes an existence oracle.
    let (plane, registration, pin_cfg) = match registered(&app, &name) {
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

    let preview = match look(&plane, &registration, &pin_cfg).await {
        Ok(p) => p,
        Err(e) => return crate::admin::v1::json::err_json(&e),
    };
    if let Err(refusal) = agrees(&preview, req.fingerprint.trim()) {
        crate::admin::audit::AUDIT.record_by(
            AUDIT_APPROVE,
            &format!("a2a_agent:{name}"),
            crate::admin::audit::OUTCOME_REJECTED,
            principal.actor_id(),
        );
        return crate::admin::v1::json::err_json_cond(
            &AdminError::Validation(refusal),
            Cond::InvalidConfig,
        );
    }

    // ── THE WRITE, under the registry's own lock, against the sighting just observed. ────────────
    let applied = plane.with_registrations_mut(|regs| {
        // RE-FOUND under the lock rather than mutating the clone: a config apply may have removed
        // the registration while the card was being fetched, and writing an approval back into a
        // registry that no longer has the row would be approving something nobody registered.
        let Some(reg) = regs.iter_mut().find(|r| r.agent_id == name) else {
            return Err(AdminError::not_found(format!("fronted agent `{name}`")));
        };
        super::pin::approve_registration(&mut reg.approval, &preview.sighting, None)
            .map_err(|e| AdminError::Validation(e.to_string()))?;
        // RECORD WHAT WAS SEEN. The approval just adopted this exact observation, so it derives no
        // drift and the state is `Approved` either way — but leaving `Never` behind would report a
        // registration that has demonstrably been contacted as one that never has.
        reg.sighting = preview.sighting.clone();
        Ok(reg.clone())
    });
    let reg = match applied {
        Ok(r) => r,
        Err(e) => {
            crate::admin::audit::AUDIT.record_by(
                AUDIT_APPROVE,
                &format!("a2a_agent:{name}"),
                crate::admin::audit::OUTCOME_REJECTED,
                principal.actor_id(),
            );
            return crate::admin::v1::json::err_json(&e);
        }
    };
    crate::admin::audit::AUDIT.record_by(
        AUDIT_APPROVE,
        &format!("a2a_agent:{name}"),
        crate::admin::audit::OUTCOME_APPLIED,
        principal.actor_id(),
    );
    crate::admin::v1::json::ok_json(StatusCode::OK, &registration_view(&name, &reg))
}

/// Does what the endpoint is serving RIGHT NOW agree with what the operator says they approved?
///
/// Split out so the three refusals are one readable table rather than three arms threaded through
/// the handler. Every arm is a refusal: there is no path here that approves something the operator
/// did not name.
fn agrees(preview: &super::verbs::ConnectPreview, claimed: &str) -> Result<(), String> {
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
fn preview_view(name: &str, preview: &super::verbs::ConnectPreview) -> A2aTrustView {
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

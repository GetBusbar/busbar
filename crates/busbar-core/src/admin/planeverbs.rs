// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE TRUST VERB SURFACE on the admin API, written ONCE and parameterised by plane.
//!
//! Every plane that fronts a registered upstream owes an operator the same three things, in the same
//! order: resolve the registration or refuse with a `404`, GO AND LOOK at the upstream, and record
//! what was found in the audit trail whatever it turned out to be. That sequence is this module.
//!
//! ## Why it is here and not once per plane
//!
//! It was twice. Both copies opened with a `registered()` that returned the same `404` for a
//! registration missing from either of two places, both named their audit action word in a private
//! constant, both were `POST` because the verb reaches the network, both answered through the frozen
//! `{"error":{"code","message"}}` envelope, and both audited whatever they found. That is one shape
//! written down twice, and a shape written twice is a shape whose two copies get fixed once each.
//!
//! ## What the plane supplies, and what it may not
//!
//! [`PlaneTrust`] is three items: which plane this is, how to resolve one registration, and how to
//! look at it. Everything else — the refusal wording, the audit resource, the ordering of the audit
//! record against the answer, the envelope — belongs to this file and a plane cannot restate it.
//!
//! The plane's IDENTITY STRINGS are not restated either: the `404` noun and the audit resource kind
//! come from the plane decl's `subject_noun` and `audit_kind`, beside the config section and the
//! scope kinds that already live on the spine. There is no `match` on the plane in this file, and
//! adding one would mean the parameterisation had failed.
//!
//! ## THE 404 IS ONE RULE because the alternative is an existence oracle
//!
//! A registration that is present in the catalogue and absent from config — or the reverse — is not
//! a state a config generation can produce. Both planes therefore answer a missing EITHER half with
//! the same not-found rather than two answers a caller could tell apart, and [`registered`] is where
//! that is decided once. Two hand-written copies of the rule are two chances for one of them to
//! start distinguishing the halves, and a refusal that distinguishes them tells an unauthorised
//! caller which names exist.
//!
//! ## `connect` REACHES THE NETWORK, which is why it is a POST and why it is audited
//!
//! It takes no body and returns a projection, which makes it look like a read. It is not: it makes
//! busbar open a connection to an operator-named endpoint, and on at least one plane it replaces the
//! recorded observation, which can move a registration from approved to quarantined. Both are
//! effects, so it takes the mutation scope every non-GET admin route takes.
//!
//! What it does NOT do, on any plane, is approve anything. Adopting what was seen is a separate,
//! explicit operator act, precisely so that a poisoned capability list cannot be adopted by the same
//! call that fetched it.

use std::future::Future;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::admin::v1::contract::AdminError;
use crate::state::AppHandle;

/// ONE PLANE'S REGISTERED-UPSTREAM SURFACE: which plane, how to find one registration, and how to
/// look at it.
///
/// A marker type per plane rather than a value, because there is nothing to carry: everything the
/// verbs need is on the live [`crate::state::App`] snapshot the handler already loads. That also
/// makes the plane a TYPE parameter at the mount, so the router names which plane it is wiring and
/// the handler cannot be mounted without one.
pub trait PlaneTrust: Send + Sync + 'static {
    /// Which plane this surface belongs to, by registry key. Supplies the `404` noun and the audit
    /// resource kind.
    const PLANE: &'static str;

    /// Everything the look needs, cloned out of the live snapshot. Cloned rather than borrowed
    /// because the look may hop threads and must not hold a lock or a snapshot borrow across it.
    type Subject: Send + 'static;

    /// What this plane answers with. The two planes' capability vocabularies genuinely differ — a
    /// `tools:` entry has an approved digest per tool, an `agents:` entry has a skill set on a card
    /// — so merging the views would mean one plane filling in fields that mean nothing to it.
    type View: serde::Serialize;

    /// Resolve one registration on the live snapshot, or refuse. Implementations state only WHERE
    /// to look; the refusal itself is [`registered`]'s, so it reads identically on every plane.
    fn resolve(app: &Arc<crate::state::App>, name: &str) -> Result<Self::Subject, AdminError>;

    /// GO AND LOOK: contact the upstream, verify what came back, and project it onto the view.
    ///
    /// A CONTACT OR VERIFICATION FAILURE IS NOT AN `Err` — it is a view whose state says the
    /// endpoint could not be authenticated. The request succeeded; what it found is that the
    /// upstream cannot currently be trusted, and a 5xx would say busbar failed when busbar did not.
    /// `Err` is reserved for what is genuinely busbar's own: an operator configuration that makes
    /// the look impossible, and an internal failure.
    fn look(
        subject: Self::Subject,
        name: String,
    ) -> impl Future<Output = Result<Self::View, AdminError>> + Send;
}

/// THE ONE NOT-FOUND for a registration on any plane.
///
/// `lookup` returns `Some` only when EVERY half a plane needs is present. See the module note: the
/// halves are never distinguished in the answer, because a refusal that distinguishes them is an
/// existence oracle.
pub fn registered<T>(
    plane: &'static str,
    name: &str,
    lookup: impl FnOnce() -> Option<T>,
) -> Result<T, AdminError> {
    lookup().ok_or_else(|| {
        AdminError::not_found(format!(
            "{} `{name}`",
            crate::plane::builtin_decl(plane).subject_noun
        ))
    })
}

/// RECORD ONE PLANE TRUST VERB in the audit trail.
///
/// The action word and the resource are DERIVED from the plane and the verb rather than spelled out
/// per plane, so a new verb cannot invent a spelling and a new plane cannot invent a naming scheme.
/// The shape is the established one: `<kind>.<verb>` acting on `<kind>:<name>`.
pub(crate) fn audit(
    plane: &'static str,
    verb: &str,
    name: &str,
    outcome: &'static str,
    principal: &crate::auth::AuthPrincipal,
) {
    let audit_kind = crate::plane::builtin_decl(plane).audit_kind;
    crate::admin::audit::AUDIT.record_by(
        &format!("{audit_kind}.{verb}"),
        &format!("{audit_kind}:{name}"),
        outcome,
        principal.actor_id(),
    );
}

/// The verb word `connect` records. Named once so the audit action and any future caller cannot
/// drift apart by a letter.
const VERB_CONNECT: &str = "connect";

/// `POST /api/v1/admin/{section}/{name}/connect` — fetch the upstream's live capability set, verify
/// it, and answer with the derived trust state. GRANTS NOTHING.
///
/// THIS is the verb that gives the dispatch gate a right-hand side to compare against; without it
/// the gate compares the operator's configured hash with itself and a rug-pull is undetectable by
/// construction.
///
/// AUDITED WHATEVER IT FOUND. A look that landed a quarantine, or that could not authenticate the
/// endpoint at all, is the single most operator-relevant thing this surface does, and recording only
/// the clean ones would make the trail silent at exactly the moment it matters.
pub async fn connect<P: PlaneTrust>(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
) -> Response {
    let app = handle.load();
    // THE 404 BEFORE ANYTHING ELSE. An unknown registration must answer the same way whatever else
    // is wrong with the request, or the shape of the error becomes an existence oracle.
    let subject = match P::resolve(&app, &name) {
        Ok(v) => v,
        Err(e) => return crate::admin::v1::json::err_json(&e),
    };
    match P::look(subject, name.clone()).await {
        Ok(view) => {
            audit(
                P::PLANE,
                VERB_CONNECT,
                &name,
                crate::admin::audit::OUTCOME_APPLIED,
                &principal,
            );
            crate::admin::v1::json::ok_json(StatusCode::OK, &view)
        }
        Err(e) => {
            audit(
                P::PLANE,
                VERB_CONNECT,
                &name,
                crate::admin::audit::OUTCOME_REJECTED,
                &principal,
            );
            crate::admin::v1::json::err_json(&e)
        }
    }
}

#[cfg(test)]
#[path = "tests/planeverbs_tests.rs"]
mod planeverbs_tests;

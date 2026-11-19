// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::Bytes;
use busbar_contract::route::RouteMethod;

use crate::plane_driver::EngineHost;

/// THE NEUTRAL PLANE-VERB ERROR — the typed shapes a plane's `resolve`/`look` ever
/// produce (a validation refusal with or without its named condition). A plane never produces a
/// `Forbidden`/`Scope` answer: authorization is enforced by the admin auth middleware BEFORE the
/// handler runs, so a verb only ever refuses with a missing registration, an operator-configuration
/// problem, temporary unavailability, or an internal failure. Core maps each variant back onto its
/// frozen `AdminError` at the
/// boundary (`NotFound` → `not_found`, `Validation` and `ValidationOf` → `Validation`, `Internal` →
/// `Internal`, `Unavailable` → `Unavailable`), so no plane names `AdminError` and `Scope` stays wholly core.
#[derive(Debug, Clone)]
pub enum PlaneVerbError {
    /// The registration is missing (either half a plane needs is absent). Carries no message: the core
    /// boundary reconstructs the frozen `"<subject_noun> `<name>`"` phrasing from the plane decl and
    /// the request name, so the not-found wording stays in one place and cannot drift per plane.
    NotFound,
    /// The request is structurally invalid or the operator configuration makes the look impossible —
    /// core's `invalid_request` (400). The string is the human message, carried verbatim.
    Validation(String),
    /// A [`PlaneVerbError::Validation`] whose condition the plane named, so core frames it
    /// condition-tagged (an operation declaring two validation conditions is witnessed only by an
    /// emission that says which one it is).
    ValidationOf(String, PlaneAdminCond),
    /// An internal failure — core's `internal` (500). The string is diagnostic only; the wire message
    /// is core's generic one (details never leave the process).
    Internal(String),
    /// A temporarily unavailable plane dependency (503). No backend detail crosses the boundary.
    Unavailable,
}

pub trait PlaneTrust: Send + Sync + 'static {
    const PLANE: &'static str;

    type Subject: Send + 'static;

    type View: serde::Serialize;

    fn resolve(host: &Arc<dyn EngineHost>, name: &str) -> Result<Self::Subject, PlaneVerbError>;

    fn look(
        subject: Self::Subject,
        host: Arc<dyn EngineHost>,
        name: String,
    ) -> impl Future<Output = Result<Self::View, PlaneVerbError>> + Send;
}

pub fn registered<T>(lookup: impl FnOnce() -> Option<T>) -> Result<T, PlaneVerbError> {
    lookup().ok_or(PlaneVerbError::NotFound)
}

/// The NEUTRAL two-rung admin scope a route DECLARES, mirroring what core's `required_scope(method,
/// path)` derives for it. NOT the core authorization `Scope` (which carries the whole authz matrix and
/// stays wholly core, untouched): this is a route-declaration marker the core adapter asserts against
/// the enforced `required_scope`, so a spec that drifts from the enforced bar is caught at boot/test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminScope {
    /// Every read (`GET`/`HEAD`): `read-only`.
    ReadOnly,
    /// Every mutation (`connect`/`approve`, and any non-read method): `full`.
    Full,
}

pub struct AdminReqCtx {
    pub host: Arc<dyn EngineHost>,

    pub name: String,

    pub body: Bytes,

    pub headers: crate::inbound::http_projection::AdminHeaders,

    pub principal: Option<busbar_contract::auth::AuthPrincipal>,

    pub consumed: Option<crate::auth::ConsumedCredentials>,

    pub query: Option<String>,

    /// The trust decision authority the admin gate built from its admission verdict and the caller's
    /// verb grant; `None` = the plane may not decide trust (TRUST-ADMIN-PRODUCER-DESIGN r3 §4.2a).
    pub trust_authority: Option<crate::host_services::TrustDecisionAuthority>,
}

pub enum AdminReply {
    Refused(PlaneVerbError),

    Applied(String),

    Rejected(PlaneVerbError),
}

pub async fn connect_reply<P: PlaneTrust>(ctx: AdminReqCtx) -> AdminReply {
    let subject = match P::resolve(&ctx.host, &ctx.name) {
        Ok(v) => v,

        Err(e) => return AdminReply::Refused(e),
    };
    match P::look(subject, ctx.host, ctx.name).await {
        Ok(view) => match busbar_contract::json::to_string(&view) {
            Ok(body) => AdminReply::Applied(body),
            Err(e) => AdminReply::Rejected(PlaneVerbError::Internal(format!(
                "the {} view did not serialize: {e}",
                P::PLANE
            ))),
        },

        Err(e) => AdminReply::Rejected(e),
    }
}

/// THE CONDITION TAGS a plane attaches to a validation refusal ([`PlaneVerbError::ValidationOf`]) —
/// the neutral subset the planes actually emit. Core maps each onto its frozen `taxonomy::Cond` so the
/// class-level drift test witnesses the declaration at CONDITION granularity.
#[derive(Debug, Clone, Copy)]
pub enum PlaneAdminCond {
    /// The request body did not parse as the verb's expected shape → core's `Cond::MalformedBody`.
    MalformedBody,
    /// The request contradicts the operator's configured state → core's `Cond::InvalidConfig`.
    InvalidConfig,
}

#[cfg(test)]
#[path = "tests/admin_verbs.rs"]
mod tests;

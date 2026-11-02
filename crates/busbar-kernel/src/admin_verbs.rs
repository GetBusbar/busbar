// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::Bytes;
use axum::http::HeaderMap;
use busbar_contract::abi::mechanism::route::RouteMethod;

use crate::plane_driver::EngineHost;

/// THE NEUTRAL PLANE-VERB ERROR — the three, and only three, shapes a plane's `resolve`/`look` ever
/// produce (a validation refusal with or without its named condition). A plane never produces a
/// `Forbidden`/`Scope` answer: authorization is enforced by the admin auth middleware BEFORE the
/// handler runs, so a verb only ever refuses with a missing registration, an operator-configuration
/// problem, or an internal failure. Core maps each variant back onto its frozen `AdminError` at the
/// boundary (`NotFound` → `not_found`, `Validation` and `ValidationOf` → `Validation`, `Internal` →
/// `Internal`), so no plane names `AdminError` and `Scope` stays wholly core.
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

/// WHAT THE CORE SHIM DOES AROUND A VERB. `Read` is a `GET` that audits nothing; `Audited` is a
/// mutation whose applied/rejected outcome the core adapter records in the audit trail, deriving the
/// audit resource kind from the plane decl. The `verb` is the audit action word (`connect`), named once
/// so the audit action and the route cannot drift apart.
#[derive(Debug, Clone, Copy)]
pub enum AdminVerbKind {
    /// A derived read — no audit.
    Read,
    /// A mutation the core adapter audits (applied on success, rejected on refusal).
    Audited {
        /// The audit action word (`connect`). The resource kind is derived core-side from the plane
        /// decl, so a plane cannot invent a naming scheme.
        verb: &'static str,
    },
}

pub struct AdminReqCtx {
    pub host: Arc<dyn EngineHost>,

    pub name: String,

    pub body: Bytes,

    pub headers: HeaderMap,

    pub principal: Option<busbar_contract::auth::AuthPrincipal>,

    pub consumed: Option<crate::auth::ConsumedCredentials>,

    pub query: Option<String>,

    pub serve: crate::plane_driver::serve::ServeTables,
}

pub enum AdminReply {
    Refused(PlaneVerbError),

    Applied(String),

    Rejected(PlaneVerbError),
}

pub type AdminReplyFuture = Pin<Box<dyn Future<Output = AdminReply> + Send>>;

pub type AdminHandler = Arc<dyn Fn(AdminReqCtx) -> AdminReplyFuture + Send + Sync>;

pub async fn connect_reply<P: PlaneTrust>(ctx: AdminReqCtx) -> AdminReply {
    let subject = match P::resolve(&ctx.host, &ctx.name) {
        Ok(v) => v,

        Err(e) => return AdminReply::Refused(e),
    };
    match P::look(subject, ctx.host, ctx.name).await {
        Ok(view) => match serde_json::to_string(&view) {
            Ok(body) => AdminReply::Applied(body),
            Err(e) => AdminReply::Rejected(PlaneVerbError::Internal(format!(
                "the {} view did not serialize: {e}",
                P::PLANE
            ))),
        },

        Err(e) => AdminReply::Rejected(e),
    }
}

pub struct AdminRouteSpec {
    pub method: RouteMethod,

    pub path: String,

    pub scope: AdminScope,

    pub kind: AdminVerbKind,

    pub handler: AdminHandler,
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

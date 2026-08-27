// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL PLANE TRUST-VERB SEAM — the vocabulary a plane uses to DECLARE its admin trust verbs
//! (`connect`/`changes`/`health`/`approve`) and to resolve/look at one registration WITHOUT naming a
//! core admin type (`AdminError`, `Scope`), the core router state (`Arc<AppHandle>`), or the core JSON
//! envelope helpers (`ok_json`/`err_json`).
//!
//! ## Two halves, one seam
//!
//! - [`PlaneTrust`] + [`PlaneVerbError`] + [`registered`] are the RESOLVE/LOOK half (ADMIN-2): a plane
//!   states only WHERE a registration is resolved from and what LOOKING at one means; the neutral host
//!   ([`crate::plane_host::EngineHost`]) is the one snapshot handle both steps read through. A plane's
//!   resolve/look never produce a `Forbidden`/`Scope` answer — authorization is enforced by the admin
//!   auth middleware BEFORE the handler runs — so the three shapes here (`NotFound`, `Validation`,
//!   `Internal`) are the whole of what a verb can refuse with. Core maps them back onto its own frozen
//!   `AdminError` at the boundary.
//!
//! - [`AdminRouteSpec`] + [`AdminReqCtx`] + [`AdminReply`] are the ROUTE-MOUNT half (ADMIN-3), mirroring
//!   the data plane's [`crate::plane_routes`]: a plane returns a flat list of `(method, path, scope,
//!   kind, handler)` specs; the CORE-side adapter (`busbar_core::admin::v1::json`) is the single place
//!   that still names `Arc<AppHandle>` / `ok_json` / `err_json` / the audit chain. It loads the handle,
//!   mints the host, builds an [`AdminReqCtx`], awaits the neutral handler, and — for an
//!   [`AdminVerbKind::Audited`] verb — records the audit row from the [`AdminReply`] the handler
//!   returned. Registering each spec at its VERBATIM `(method, path)` keeps the auth middleware's
//!   `required_scope(method, path)` byte-identical, which is the security invariant this seam preserves.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::Bytes;
use axum::http::HeaderMap;
use busbar_plugin::cold::http_endpoint::RouteMethod;

use crate::plane_host::EngineHost;

/// THE NEUTRAL PLANE-VERB ERROR — the three, and only three, shapes a plane's `resolve`/`look` ever
/// produce. A plane never produces a `Forbidden`/`Scope` answer: authorization is enforced by the
/// admin auth middleware BEFORE the handler runs, so a verb only ever refuses with a missing
/// registration, an operator-configuration problem, or an internal failure. Core maps each variant
/// back onto its frozen `AdminError` at the boundary (`NotFound` → `not_found`, `Validation` →
/// `Validation`, `Internal` → `Internal`), so no plane names `AdminError` and `Scope` stays wholly
/// core.
#[derive(Debug, Clone)]
pub enum PlaneVerbError {
    /// The registration is missing (either half a plane needs is absent). Carries no message: the core
    /// boundary reconstructs the frozen `"<subject_noun> `<name>`"` phrasing from the plane decl and
    /// the request name, so the not-found wording stays in one place and cannot drift per plane.
    NotFound,
    /// The request is structurally invalid or the operator configuration makes the look impossible —
    /// core's `invalid_request` (400). The string is the human message, carried verbatim.
    Validation(String),
    /// An internal failure — core's `internal` (500). The string is diagnostic only; the wire message
    /// is core's generic one (details never leave the process).
    Internal(String),
}

/// ONE PLANE'S REGISTERED-UPSTREAM SURFACE: which plane, how to find one registration, and how to look
/// at it. Relocated here (ADMIN-2) now that both `resolve` and `look` name only neutral types — the
/// host seam and [`PlaneVerbError`]. Core re-exports this as `busbar_core::admin::planeverbs::PlaneTrust`
/// for `connect`'s bound; a plane's `impl PlaneTrust` names this crate, not core.
pub trait PlaneTrust: Send + Sync + 'static {
    /// Which plane this surface belongs to, by registry key. Supplies the `404` noun and the audit
    /// resource kind — both derived core-side from the plane decl, never restated by the plane.
    const PLANE: &'static str;

    /// Everything the look needs, cloned out of the snapshot the host was minted on. Cloned rather than
    /// borrowed because the look may hop threads and must not hold a lock or a snapshot borrow across it.
    type Subject: Send + 'static;

    /// What this plane answers with — a plane-specific serde view.
    type View: serde::Serialize;

    /// Resolve one registration off the neutral host seam minted over the admitted snapshot, or refuse
    /// with [`PlaneVerbError::NotFound`]. Implementations state only WHERE to look; the refusal wording
    /// is reconstructed core-side, so it reads identically on every plane.
    fn resolve(host: &Arc<dyn EngineHost>, name: &str) -> Result<Self::Subject, PlaneVerbError>;

    /// GO AND LOOK: contact the upstream, verify what came back, and project it onto the view. A CONTACT
    /// OR VERIFICATION FAILURE IS NOT AN `Err` — it is a view whose state says the endpoint could not be
    /// authenticated. `Err` is reserved for what is genuinely busbar's own: an operator configuration
    /// that makes the look impossible ([`PlaneVerbError::Validation`]) and an internal failure
    /// ([`PlaneVerbError::Internal`]).
    fn look(
        subject: Self::Subject,
        host: Arc<dyn EngineHost>,
        name: String,
    ) -> impl Future<Output = Result<Self::View, PlaneVerbError>> + Send;
}

/// THE ONE NOT-FOUND for a registration on any plane. `lookup` returns `Some` only when EVERY half a
/// plane needs is present — the halves are never distinguished in the answer, because a refusal that
/// distinguishes them is an existence oracle. The `NotFound` carries no wording: core reconstructs the
/// frozen phrasing at the boundary from the plane decl's `subject_noun`.
pub fn registered<T>(lookup: impl FnOnce() -> Option<T>) -> Result<T, PlaneVerbError> {
    lookup().ok_or(PlaneVerbError::NotFound)
}

// ── The route-mount half (ADMIN-3) ───────────────────────────────────────────────────────────────

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
    /// A mutation the core adapter audits (applied on success, rejected on refusal) UNLESS the handler
    /// returned a [`AdminReply::Prebuilt`] response (a plane that did its own audit + envelope, e.g.
    /// A2A `approve`).
    Audited {
        /// The audit action word (`connect`). The resource kind is derived core-side from the plane
        /// decl, so a plane cannot invent a naming scheme.
        verb: &'static str,
    },
}

/// The per-request context the core adapter builds and hands an admin verb handler — everything the
/// handler needs, sourced from the SAME extractors the old typed handlers used but assembled by core so
/// the plane names no `axum` extractor and no `Arc<AppHandle>` router state.
pub struct AdminReqCtx {
    /// The neutral host seam minted core-side from `handle.load()` — the plane reads its runtime object
    /// and reaches host capabilities through typed methods on this.
    pub host: Arc<dyn EngineHost>,
    /// The `{name}` path capture.
    pub name: String,
    /// The buffered request body bytes (empty on a `GET`). A write verb (A2A `approve`) parses this
    /// with `axum::Json::from_bytes`, byte-identically to the old `Json<..>` extractor.
    pub body: Bytes,
    /// The request headers — a write verb reads them to reproduce the old extractor's content-type
    /// guard exactly.
    pub headers: HeaderMap,
    /// The middleware-resolved auth principal (always present on an admin route; `None` only on the
    /// impossible open path). A self-auditing verb (`approve`) records with it; the `Audited` shim
    /// audits with it.
    pub principal: Option<busbar_api::AuthPrincipal>,
}

/// WHAT A VERB HANDLER ANSWERS WITH, and how the core shim frames it. The variants encode both the wire
/// answer AND the audit decision, so the shim reproduces the pre-seam behaviour byte-for-byte — in
/// particular that a resolve-time `404` is NOT audited while a look-time refusal IS.
pub enum AdminReply {
    /// A resolve/preamble refusal (the `404`, or a write verb's pre-look rejection): the core shim maps
    /// it to `err_json` and audits NOTHING, exactly as the old `connect`/`approve` returned before their
    /// audit point.
    Refused(PlaneVerbError),
    /// The verb ran and SUCCEEDED. Carries the ALREADY-SERIALIZED success body (`serde_json::to_string`
    /// of the view, so the JSON key order is the struct's declaration order — a `serde_json::Value`
    /// round-trip would re-sort keys and change the bytes). The shim emits it as a `200` and, for an
    /// `Audited` verb, records `applied`.
    Applied(String),
    /// The verb ran and was REJECTED after its look/decision: the shim maps it to `err_json` and, for an
    /// `Audited` verb, records `rejected`.
    Rejected(PlaneVerbError),
    /// The handler built the ENTIRE response itself and performed its OWN audit (a plane whose verb
    /// carries condition-tagged errors and a bespoke success view, e.g. A2A `approve`). The shim returns
    /// it verbatim and audits nothing.
    Prebuilt(axum::response::Response),
}

/// The boxed, `Send` future an admin verb handler returns.
pub type AdminReplyFuture = Pin<Box<dyn Future<Output = AdminReply> + Send>>;

/// ONE ADMIN VERB HANDLER: a neutral async fn over an [`AdminReqCtx`]. `Arc<dyn Fn…>` because a plane
/// returns many in one `Vec` and the core adapter clones each into the per-request `axum` closure.
pub type AdminHandler = Arc<dyn Fn(AdminReqCtx) -> AdminReplyFuture + Send + Sync>;

/// THE SHARED `connect` SEQUENCE, written ONCE for every plane: resolve the registration or refuse
/// with the `404`, GO AND LOOK at the upstream, and hand the answer back for the core adapter to audit
/// (`applied` on a view, `rejected` on a refusal). A resolve-time refusal is [`AdminReply::Refused`],
/// which the adapter does NOT audit — byte-identical to the pre-seam `connect` returning the `404`
/// before its audit point. The success body is serialized HERE (`serde_json::to_string`, declaration
/// order) so the adapter emits it without a key-resorting `serde_json::Value` round-trip.
pub async fn connect_reply<P: PlaneTrust>(ctx: AdminReqCtx) -> AdminReply {
    let subject = match P::resolve(&ctx.host, &ctx.name) {
        Ok(v) => v,
        // THE 404 BEFORE ANYTHING ELSE, and NOT audited — an unknown registration must answer the same
        // way whatever else is wrong, or the shape of the error becomes an existence oracle.
        Err(e) => return AdminReply::Refused(e),
    };
    match P::look(subject, ctx.host, ctx.name).await {
        Ok(view) => {
            AdminReply::Applied(serde_json::to_string(&view).unwrap_or_else(|_| "{}".to_string()))
        }
        // A look that landed a quarantine, or could not authenticate the endpoint, is the single most
        // operator-relevant thing this surface does — recorded whatever it found (the adapter audits
        // `rejected`).
        Err(e) => AdminReply::Rejected(e),
    }
}

/// One admin verb a plane DECLARES: the exact method and path (handed VERBATIM to the core router, so
/// the auth middleware's `required_scope(method, path)` is byte-identical), the declared scope (asserted
/// against the enforced `required_scope`), the shim behaviour, and the neutral handler.
pub struct AdminRouteSpec {
    /// The declared HTTP method — VERBATIM, so the scope matrix reads it unchanged.
    pub method: RouteMethod,
    /// The RELATIVE (post-`ADMIN_PREFIX`) path pattern — VERBATIM (`/tools/{name}/connect`).
    pub path: String,
    /// The scope this route DECLARES it requires. Asserted equal to core's enforced
    /// `required_scope(method, ADMIN_PREFIX + path)` by the route-table guard, so a mutation cannot
    /// silently declare `ReadOnly`.
    pub scope: AdminScope,
    /// What the core shim does around the handler (audit or not).
    pub kind: AdminVerbKind,
    /// The neutral handler the core adapter awaits, having built an [`AdminReqCtx`].
    pub handler: AdminHandler,
}

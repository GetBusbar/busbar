// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The provisioning mount and its admin (IF §12.29, W2-K8P).
//!
//! - **The mount (CA-2).** For each auth instance whose image declared FB_PROVISION and whose config carries a
//!   `provisioning:` block, core claims `/provision/<instance>/{*rest}` on the data listener (all methods). Per
//!   request, before any plugin call: the body is capped by the instance's `limits` (413); the request head goes to
//!   **this instance's own** verify exactly as an inbound request (no credential 401 with `WWW-Authenticate:
//!   Bearer`, REFUSED 401, FAILED the §12.15 mapping); the verified principal must equal an entry of
//!   `provisioning.clients` (else 403); `Authorization`, `Cookie` and the instance's D_CRED_HEADER headers are
//!   stripped; `serve` is called with Q_CLIENT = the matched entry. Each refusal is audited
//!   `provision_refused{instance, status}` with no credential text.
//! - **The guard's admin.** `GET /admin/provisioning/{instance}/guard` and `POST
//!   /admin/provisioning/{instance}/guard/release` (`{"for_s": n}`, default 900, 60..=86,400), behind admin authz
//!   as every admin write; the release is audited `directory_guard_released` with the admin principal.

use std::collections::BTreeMap;
use std::future::Future;

use axum::body::{Body, Bytes};
use axum::http::header::{AUTHORIZATION, COOKIE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};

use busbar_kernel::config::min3::{ProvisioningCfg, ProvisioningGuard};
use busbar_kernel::directory::MAX_ATTEMPTS;
use busbar_kernel::holds::guard::{self, GuardCell, ReleaseRefused};

/// The mount prefix; the claimed pattern is `/provision/<instance>/{*rest}`.
pub const MOUNT_PREFIX: &str = "/provision/";

/// The claimed path pattern for provisioning instance `instance`.
pub fn mount_path(instance: &str) -> String {
    format!("{MOUNT_PREFIX}{instance}/{{*rest}}")
}

/// The instances that get a mount: a `provisioning:` block **and** an image that declared FB_PROVISION. An
/// FB_PROVISION image without the block loads and mounts nothing (its DIRECTORY Needs are DENIED by the
/// directory); the block without FB_PROVISION is refused at config load (W1-K6P), so it never reaches here.
pub fn mounted<'a, F>(provisioning: &'a BTreeMap<Box<str>, ProvisioningCfg>, declares_provision: F) -> Vec<&'a str>
where
    F: Fn(&str) -> bool,
{
    provisioning
        .keys()
        .map(|k| &**k)
        .filter(|name| declares_provision(name))
        .collect()
}

/// What this instance's own verify said about the request head (through the verdict cache, §12.28).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verified {
    /// The request carried no credential at all.
    NoCredential,
    /// REFUSED.
    Refused,
    /// FAILED: the §12.15 refusal mapping's status (502 or 503).
    Failed(StatusCode),
    /// Identified this principal.
    Principal(Box<str>),
}

/// One mounted provisioning instance, as the mount sees it. The kernel's auth port (the instance's verify and
/// `serve`, L5) implements it; tests use a fake.
pub trait ProvisionInstance: Send + Sync {
    /// The configured instance name.
    fn name(&self) -> &str;
    /// The instance's `limits` body cap, bytes.
    fn body_cap(&self) -> usize;
    /// The instance's D_CRED_HEADER headers (stripped with `Authorization` and `Cookie`).
    fn cred_headers(&self) -> &[HeaderName];
    /// This instance's own verify over the request head, exactly as an inbound request.
    fn verify(&self, head: &HeaderMap, path: &str) -> impl Future<Output = Verified> + Send;
    /// `serve` with Q_CLIENT = `client` (an entry of `provisioning.clients`), the stripped head and the body.
    fn serve(
        &self,
        client: &str,
        req: Request<Bytes>,
    ) -> impl Future<Output = Response> + Send;
    /// A refusal of the mount, audited `provision_refused{instance, status}` (no credential text).
    fn refused(&self, status: StatusCode) {
        busbar_kernel::audit::auditlog::emit_admin_hostless_now(
            "provision_refused",
            &format!("provisioning:{}#{}", self.name(), status.as_u16()),
            busbar_contract::vocab::OUTCOME_REFUSED,
            busbar_kernel::audit::auditlog::PLUGIN_REFUSAL_PRINCIPAL,
        );
    }
}

/// The `provisioning.clients` entry equal to `principal` (exact bytes), if any.
pub fn client_entry<'a>(clients: &'a [Box<str>], principal: &str) -> Option<&'a str> {
    clients.iter().map(|c| &**c).find(|c| *c == principal)
}

/// Strips `Authorization`, `Cookie` and every one of `extra` from `headers`.
pub fn strip_credentials(headers: &mut HeaderMap, extra: &[HeaderName]) {
    headers.remove(AUTHORIZATION);
    headers.remove(COOKIE);
    for name in extra {
        headers.remove(name);
    }
}

fn refuse<I: ProvisionInstance>(inst: &I, status: StatusCode) -> Response {
    inst.refused(status);
    let mut resp = status.into_response();
    if status == StatusCode::UNAUTHORIZED {
        resp.headers_mut()
            .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    resp
}

/// One request on `/provision/<instance>/*`: the CA-2 client check, then `serve`. No plugin is called before the
/// check passes.
pub async fn mount<I: ProvisionInstance>(inst: &I, clients: &[Box<str>], req: Request<Body>) -> Response {
    let (mut head, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, inst.body_cap()).await {
        Ok(b) => b,
        Err(_) => return refuse(inst, StatusCode::PAYLOAD_TOO_LARGE),
    };
    let client = match inst.verify(&head.headers, head.uri.path()).await {
        Verified::NoCredential | Verified::Refused => {
            return refuse(inst, StatusCode::UNAUTHORIZED)
        }
        Verified::Failed(status) => return refuse(inst, status),
        Verified::Principal(p) => match client_entry(clients, &p) {
            Some(c) => c,
            None => return refuse(inst, StatusCode::FORBIDDEN),
        },
    };
    strip_credentials(&mut head.headers, inst.cred_headers());
    inst.serve(client, Request::from_parts(head, body)).await
}

/// The store did not answer (or answered a fault).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreFault;

/// The guard cell's store access for one provisioning instance (its `dir_ns` `W` key), implemented by the kernel
/// directory (W1-K6P) over the core store.
pub trait GuardStore: Send + Sync {
    /// The raw `W` bytes; None = absent.
    fn read_w(&self, instance: &str) -> impl Future<Output = Result<Option<Vec<u8>>, StoreFault>> + Send;
    /// One slotted commit putting `new`, predicated `Exact(expected)` or `Absent` (None). Ok(false) = the
    /// predicate lost (another writer moved `W`).
    fn commit_w(
        &self,
        instance: &str,
        expected: Option<&[u8]>,
        new: [u8; guard::W_LEN],
    ) -> impl Future<Output = Result<bool, StoreFault>> + Send;
}

/// `GET /admin/provisioning/{instance}/guard`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct GuardView {
    pub max: u32,
    pub window_s: u64,
    pub window_start_s: u64,
    pub moved: u32,
    pub released_until_s: u64,
}

impl GuardView {
    fn of(g: ProvisioningGuard, c: GuardCell) -> Self {
        Self {
            max: g.max,
            window_s: g.window_s,
            window_start_s: c.window_start_s,
            moved: c.moved,
            released_until_s: c.released_until_s,
        }
    }
}

/// `POST .../guard/release` body.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBody {
    pub for_s: Option<u64>,
}

/// An admin refusal on the guard routes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardAdminError {
    /// No such provisioning instance (404).
    UnknownInstance,
    /// The body is invalid (400, the text names the field).
    Invalid(String),
    /// The store did not answer, the cell does not decode, or the commit lost MAX_ATTEMPTS times (503).
    Unavailable,
}

impl GuardAdminError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::UnknownInstance => StatusCode::NOT_FOUND,
            Self::Invalid(_) => StatusCode::BAD_REQUEST,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl IntoResponse for GuardAdminError {
    fn into_response(self) -> Response {
        let message = match &self {
            Self::UnknownInstance => "no provisioning instance by that name".to_string(),
            Self::Invalid(text) => text.clone(),
            Self::Unavailable => "the provisioning store did not answer; retry".to_string(),
        };
        (
            self.status(),
            axum::Json(serde_json::json!({ "error": { "message": message } })),
        )
            .into_response()
    }
}

fn guard_of<'a>(
    provisioning: &'a BTreeMap<Box<str>, ProvisioningCfg>,
    instance: &str,
) -> Result<&'a ProvisioningCfg, GuardAdminError> {
    provisioning
        .get(instance)
        .ok_or(GuardAdminError::UnknownInstance)
}

fn decode(raw: Option<&[u8]>) -> Result<Option<GuardCell>, GuardAdminError> {
    match raw {
        None => Ok(None),
        Some(b) => GuardCell::decode(b)
            .map(Some)
            .ok_or(GuardAdminError::Unavailable),
    }
}

/// `GET /admin/provisioning/{instance}/guard` as of `now_s` (a window that ran out reads as restarted).
pub async fn guard_view<S: GuardStore>(
    store: &S,
    provisioning: &BTreeMap<Box<str>, ProvisioningCfg>,
    instance: &str,
    now_s: u64,
) -> Result<GuardView, GuardAdminError> {
    let cfg = guard_of(provisioning, instance)?;
    let raw = store
        .read_w(instance)
        .await
        .map_err(|StoreFault| GuardAdminError::Unavailable)?;
    let cell = GuardCell::current(decode(raw.as_deref())?, now_s, cfg.guard.window_s);
    Ok(GuardView::of(cfg.guard, cell))
}

/// `POST /admin/provisioning/{instance}/guard/release` by admin principal `admin` (already through admin authz):
/// commits `W` with `moved` 0 and `released_until_s = now_s + for_s`, under `Exact(read)` / `Absent`, at most
/// MAX_ATTEMPTS times; audited `directory_guard_released` with the admin principal.
pub async fn release_guard<S: GuardStore>(
    store: &S,
    provisioning: &BTreeMap<Box<str>, ProvisioningCfg>,
    instance: &str,
    body: ReleaseBody,
    admin: &str,
    now_s: u64,
) -> Result<GuardView, GuardAdminError> {
    let cfg = guard_of(provisioning, instance)?;
    for _ in 0..MAX_ATTEMPTS {
        let raw = store
            .read_w(instance)
            .await
            .map_err(|StoreFault| GuardAdminError::Unavailable)?;
        let cell = decode(raw.as_deref())?;
        let next = guard::release(cell, now_s, body.for_s, cfg.guard.window_s)
            .map_err(|e: ReleaseRefused| GuardAdminError::Invalid(e.to_string()))?;
        let won = store
            .commit_w(instance, raw.as_deref(), next.encode())
            .await
            .map_err(|StoreFault| GuardAdminError::Unavailable)?;
        if won {
            busbar_kernel::audit::auditlog::emit_admin_hostless_now(
                "directory_guard_released",
                &format!("provisioning:{instance}#until={}", next.released_until_s),
                busbar_contract::vocab::OUTCOME_APPLIED,
                admin,
            );
            return Ok(GuardView::of(cfg.guard, next));
        }
    }
    Err(GuardAdminError::Unavailable)
}

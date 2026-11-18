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

use busbar_kernel::config::min3::ProvisioningCfg;
use busbar_kernel::directory::{GuardView, KernelDirectory};
use busbar_plugin_abi::host_side::needs::NeedErr;

/// The mount prefix; the claimed pattern is `/provision/<instance>/{*rest}`.
pub const MOUNT_PREFIX: &str = "/provision/";

/// The claimed path pattern for provisioning instance `instance`.
pub fn mount_path(instance: &str) -> String {
    format!("{MOUNT_PREFIX}{instance}/{{*rest}}")
}

/// The instances that get a mount: a `provisioning:` block **and** an image that declared FB_PROVISION. An
/// FB_PROVISION image without the block loads and mounts nothing (its DIRECTORY Needs are DENIED by the
/// directory); the block without FB_PROVISION is refused at config load (W1-K6P), so it never reaches here.
pub fn mounted<F>(
    provisioning: &BTreeMap<Box<str>, ProvisioningCfg>,
    declares_provision: F,
) -> Vec<&str>
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
    fn verify(&self, request: &Request<Bytes>) -> impl Future<Output = Verified> + Send;
    /// `serve` with Q_CLIENT = `client` (an entry of `provisioning.clients`), the stripped head and the body.
    fn serve(&self, client: &str, req: Request<Bytes>) -> impl Future<Output = Response> + Send;
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
pub async fn mount<I: ProvisionInstance>(
    inst: &I,
    clients: &[Box<str>],
    req: Request<Body>,
) -> Response {
    let (head, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, inst.body_cap()).await {
        Ok(b) => b,
        Err(_) => return refuse(inst, StatusCode::PAYLOAD_TOO_LARGE),
    };
    let mut request = Request::from_parts(head, body);
    let client = match inst.verify(&request).await {
        Verified::NoCredential | Verified::Refused => {
            return refuse(inst, StatusCode::UNAUTHORIZED)
        }
        Verified::Failed(status) => return refuse(inst, status),
        Verified::Principal(p) => match client_entry(clients, &p) {
            Some(c) => c,
            None => return refuse(inst, StatusCode::FORBIDDEN),
        },
    };
    strip_credentials(request.headers_mut(), inst.cred_headers());
    inst.serve(client, request).await
}

/// `GET /admin/provisioning/{instance}/guard`, the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct GuardBody {
    pub max: u32,
    pub window_s: u64,
    pub window_start_s: u64,
    pub moved: u32,
    pub released_until_s: u64,
}

impl From<GuardView> for GuardBody {
    fn from(v: GuardView) -> Self {
        Self {
            max: v.max,
            window_s: v.window_s,
            window_start_s: v.window_start_s,
            moved: v.moved,
            released_until_s: v.released_until_s,
        }
    }
}

/// `POST .../guard/release` body. `for_s` defaults to 900; the directory checks 60..=86,400.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBody {
    pub for_s: Option<u64>,
}

/// `for_s` of a release without a body.
const RELEASE_DEFAULT_S: u64 = 900;

/// An admin refusal on the guard routes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardAdminError {
    /// No such provisioning instance (404).
    UnknownInstance,
    /// `for_s` is outside 60..=86,400 (400, the text names the field).
    Invalid,
    /// The store did not answer, or the commit lost MAX_ATTEMPTS times (503).
    Unavailable,
}

impl GuardAdminError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::UnknownInstance => StatusCode::NOT_FOUND,
            Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn of(e: NeedErr) -> Self {
        match e {
            NeedErr::Denied => Self::UnknownInstance,
            NeedErr::Invalid => Self::Invalid,
            _ => Self::Unavailable,
        }
    }
}

impl IntoResponse for GuardAdminError {
    fn into_response(self) -> Response {
        let message = match &self {
            Self::UnknownInstance => "no provisioning instance by that name",
            Self::Invalid => "for_s must be between 60 and 86400 seconds",
            Self::Unavailable => "the provisioning store did not answer; retry",
        };
        let code = match &self {
            Self::UnknownInstance => "not_found",
            Self::Invalid => "invalid_request",
            Self::Unavailable => "unavailable",
        };
        busbar_kernel::admin::gate::admin_error_envelope(self.status().as_u16(), code, message)
    }
}

/// `GET /admin/provisioning/{instance}/guard`.
pub async fn guard_view(
    dir: &KernelDirectory,
    instance: &str,
) -> Result<GuardBody, GuardAdminError> {
    dir.guard(instance)
        .await
        .map(Into::into)
        .map_err(GuardAdminError::of)
}

/// `POST /admin/provisioning/{instance}/guard/release` by admin principal `admin` (already through admin authz).
/// The directory commits `moved` 0 and `released_until_s = now + for_s` and audits `directory_guard_released` with
/// the admin principal.
pub async fn release_guard(
    dir: &KernelDirectory,
    instance: &str,
    body: ReleaseBody,
    admin: &str,
) -> Result<GuardBody, GuardAdminError> {
    dir.release_guard(instance, body.for_s.unwrap_or(RELEASE_DEFAULT_S), admin)
        .await
        .map(Into::into)
        .map_err(GuardAdminError::of)
}

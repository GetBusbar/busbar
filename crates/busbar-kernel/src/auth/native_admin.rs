// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native verification is preparation. Only final admin completion obtains execution custody.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_ports::auth::Identity;
use busbar_ports::{CallCx, PortError};

use crate::inbound::request_snapshot::ChargedRequestSnapshot;
use crate::state::{AdmissionLease, App, AppHandle, InvocationId};

pub trait NativeAdmin: Send + Sync {
    fn prepare<'a>(
        &'a self,
        name: &'a str,
        cx: CallCx,
        request: Arc<ChargedRequestSnapshot>,
    ) -> BoxFut<'a, Result<PreparedAnswer, PortError>>;
}

pub enum PreparedAnswer {
    Identity(Arc<dyn PreparedIdentity>),
    NotMine,
    Rejected,
    Held,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionRefused;

/// Host-only immutable verification state. Neither identity projection nor STRIP certifies that
/// every declared credential field was verified; field provenance needs its own attestation.
pub trait PreparedIdentity: Send + Sync {
    fn provider(&self) -> &str;
    fn credential_headers(&self) -> &[Box<str>];
    fn identity(&self) -> &Identity;
    fn request(&self) -> &Arc<ChargedRequestSnapshot>;
    fn authorize(&self, now_s: u64) -> Result<(), u32>;
    fn claim(&self) -> BoxFut<'_, bool>;
}

impl std::fmt::Debug for dyn PreparedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedIdentity").finish_non_exhaustive()
    }
}

/// Actual selected generation and host invocation, supplied at the request entry point. It is
/// never captured by the App-installed callback, which would create a generation ownership cycle.
#[derive(Clone)]
pub struct Invocation {
    pub handle: Arc<AppHandle>,
    pub selected: Arc<App>,
    pub id: InvocationId,
    pub cx: CallCx,
    pub request: Arc<ChargedRequestSnapshot>,
}

pub(super) struct Pending {
    invocation: Invocation,
    prepared: Arc<dyn PreparedIdentity>,
    spent: AtomicBool,
}

impl Pending {
    pub(super) fn new(invocation: Invocation, prepared: Arc<dyn PreparedIdentity>) -> Self {
        Self {
            invocation,
            prepared,
            spent: AtomicBool::new(false),
        }
    }

    pub(super) async fn complete(&self) -> Result<ExecutionAdmission, AdmissionRefused> {
        // Consume before the first await. A cancelled or failed store call cannot retry this right.
        if self.spent.swap(true, Ordering::AcqRel)
            || !Arc::ptr_eq(&self.invocation.request, self.prepared.request())
            || self.invocation.cx.request_id != self.invocation.id.request_id().get()
            || std::time::Instant::now() >= self.invocation.cx.deadline
        {
            return Err(AdmissionRefused);
        }
        let lease = self
            .invocation
            .handle
            .admit_current(&self.invocation.selected, self.invocation.id, |_| {
                self.prepared.authorize(crate::store::now())
            })
            .map_err(|_| AdmissionRefused)?;
        if !self.prepared.claim().await {
            return Err(AdmissionRefused);
        }
        // Publication after the lease is not cancellation of this already-admitted operation.
        Ok(ExecutionAdmission {
            native: Some((lease, Arc::clone(&self.prepared))),
            origin: Some(self.invocation.clone()),
        })
    }
}

/// Retained by the actual execution owner through terminal effects. There is no public constructor
/// or conversion back to pending, and cloning an Arc to this value does not mint execution rights.
pub struct ExecutionAdmission {
    native: Option<(AdmissionLease, Arc<dyn PreparedIdentity>)>,
    origin: Option<Invocation>,
}

impl ExecutionAdmission {
    pub(super) fn legacy() -> Self {
        Self {
            native: None,
            origin: None,
        }
    }
    pub fn native(&self) -> Option<(&AdmissionLease, &dyn PreparedIdentity)> {
        self.native
            .as_ref()
            .map(|(lease, prepared)| (lease, prepared.as_ref()))
    }

    /// Lend the actual origin for the physical request's final join. Equal generation pointers
    /// cannot substitute for the originating publication owner, request id or call deadline.
    pub fn native_origin(&self) -> Option<(&Arc<AppHandle>, CallCx)> {
        self.origin
            .as_ref()
            .map(|origin| (&origin.handle, origin.cx))
    }

    pub(super) fn door_for(&self, app: &App) -> Option<super::AdminDoor> {
        let (_, prepared) = self.native()?;
        let identity = prepared.identity();
        Some(super::admin_door_of(
            app,
            super::ChainVerdict::Identified {
                module: prepared.provider().to_owned(),
                principal: super::Principal {
                    id: identity.subject().to_owned(),
                    name: None,
                    roles: identity.groups().map(str::to_owned).collect(),
                    ttl_secs: identity.cache_s().map(u64::from),
                },
                resolved: None,
            },
            super::module_admin_scope_cap(app, prepared.provider()),
        ))
    }

    pub(super) fn who(&self) -> Option<super::AdminWho> {
        let (lease, prepared) = self.native()?;
        let identity = prepared.identity();
        super::admin_who_of(
            lease.generation(),
            super::ChainVerdict::Identified {
                module: prepared.provider().to_owned(),
                principal: super::Principal {
                    id: identity.subject().to_owned(),
                    name: None,
                    roles: identity.groups().map(str::to_owned).collect(),
                    ttl_secs: identity.cache_s().map(u64::from),
                },
                resolved: None,
            },
            super::module_admin_scope_cap(lease.generation(), prepared.provider()),
            identity.expires_at_s(),
        )
    }

    pub(super) fn matches_http(
        &self,
        method: &str,
        target: &str,
        headers: &axum::http::HeaderMap,
        body: &[u8],
    ) -> bool {
        let Some((_, prepared)) = self.native() else {
            return false;
        };
        snapshot_matches_http(prepared.request(), method, target, headers, body)
    }
}

/// Validate an HTTP projection without allocating an ABI Pair view or losing empty-query presence.
/// This compares content only; execution additionally requires the exact snapshot Arc identity.
pub fn snapshot_matches_http(
    original: &ChargedRequestSnapshot,
    method: &str,
    target: &str,
    headers: &axum::http::HeaderMap,
    body: &[u8],
) -> bool {
    original.method() == method
        && original.target() == target
        && original.body() == body
        && original.headers().len() == headers.len()
        && original.headers().all(|(name, _)| {
            original
                .headers()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value)
                .eq(headers
                    .get_all(name)
                    .iter()
                    .map(axum::http::HeaderValue::as_bytes))
        })
}

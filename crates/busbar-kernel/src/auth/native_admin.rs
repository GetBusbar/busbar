// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native verification is preparation. Only final admin completion obtains execution custody.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_ports::auth::Identity;
use busbar_ports::{CallCx, PortError};

use super::chain_run::Request;
use crate::state::{AdmissionLease, App, AppHandle, InvocationId};

/// Snapshot the actual HTTP carrier. Transport adapters with peer/certificate custody extend the
/// view before snapshotting; an unavailable transport property is represented as absent.
pub fn http_request(
    method: &str,
    target: &str,
    headers: &axum::http::HeaderMap,
    body: &[u8],
    now_s: u64,
) -> Request {
    use busbar_plugin_abi::types::{Bytes, Pair, Str};
    let fields: Vec<_> = headers
        .iter()
        .map(|(name, value)| Pair {
            name: Str::new(name.as_str()),
            value: Bytes::new(value.as_bytes()),
        })
        .collect();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Request::new(&busbar_ports::auth::AuthIn {
        method,
        path,
        query,
        authority: headers
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        headers: &fields,
        peer: "",
        tls_peer_cert: &[],
        body,
        now_s,
    })
}

pub trait NativeAdmin: Send + Sync {
    fn prepare<'a>(
        &'a self,
        name: &'a str,
        cx: CallCx,
        request: Request,
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
    fn request(&self) -> &Request;
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
    pub request: Arc<Request>,
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
        })
    }
}

/// Retained by the actual execution owner through terminal effects. There is no public constructor
/// or conversion back to pending, and cloning an Arc to this value does not mint execution rights.
pub struct ExecutionAdmission {
    native: Option<(AdmissionLease, Arc<dyn PreparedIdentity>)>,
}

impl ExecutionAdmission {
    pub(super) fn legacy() -> Self {
        Self { native: None }
    }
    pub fn native(&self) -> Option<(&AdmissionLease, &dyn PreparedIdentity)> {
        self.native
            .as_ref()
            .map(|(lease, prepared)| (lease, prepared.as_ref()))
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
}

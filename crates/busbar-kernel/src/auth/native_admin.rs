// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native verification is preparation. Only final admin completion obtains execution custody.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_ports::{CallCx, PortError};

use super::native_chain::NativeChain;
use crate::inbound::request_snapshot::ChargedRequestSnapshot;
use crate::state::{AdmissionLease, App, AppHandle, InvocationId};

/// The configured native admin positions: one verification chain per name, and the names left unset.
pub struct NativeAdmin {
    chains: BTreeMap<String, Arc<NativeChain>>,
    unset: BTreeSet<String>,
}

impl NativeAdmin {
    pub fn new(chains: BTreeMap<String, Arc<NativeChain>>, unset: BTreeSet<String>) -> Self {
        Self { chains, unset }
    }

    pub fn prepare<'a>(
        &'a self,
        name: &'a str,
        cx: CallCx,
        request: Arc<ChargedRequestSnapshot>,
    ) -> BoxFut<'a, Result<PreparedAnswer, PortError>> {
        Box::pin(async move {
            if self.unset.contains(name) {
                return Ok(PreparedAnswer::NotMine);
            }
            let chain = self.chains.get(name).ok_or(PortError::Call(
                busbar_plugin_abi::fail::CallError::NotDeclared,
            ))?;
            chain.prepare(cx, request).await
        })
    }
}

pub enum PreparedAnswer {
    Identity(Arc<PreparedIdentity>),
    NotMine,
    Rejected,
    Held,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionRefused;

/// The actual single replay call result; only Duplicate is a confirmed rejection.
pub enum NativeReplayClaim {
    Claimed,
    Duplicate,
    Unknown(crate::plugin_records::RecordsDenied),
    Inconsistent,
}

pub struct AdminReplayDenial {
    _lease: AdmissionLease,
    invocation: Invocation,
    _prepared: Arc<PreparedIdentity>,
}

impl AdminReplayDenial {
    pub fn matches(&self, binding: &crate::inbound::native::RequestBinding) -> bool {
        Arc::ptr_eq(binding.handle(), &self.invocation.handle)
            && Arc::ptr_eq(binding.app(), &self.invocation.selected)
            && binding.invocation() == self.invocation.id
            && binding
                .snapshot()
                .is_ok_and(|snapshot| Arc::ptr_eq(&snapshot, &self.invocation.request))
    }
}

/// Retains original preparation/operation custody without manufacturing a duplicate refusal.
pub struct AdminReplayUnknown {
    _lease: AdmissionLease,
    _invocation: Invocation,
    _prepared: Arc<PreparedIdentity>,
    _error: crate::plugin_records::RecordsDenied,
}

pub enum AdminCompletionRefused {
    Unavailable,
    ReplayDenied(Box<AdminReplayDenial>),
    ReplayUnknown(Box<AdminReplayUnknown>),
}

impl std::fmt::Debug for AdminCompletionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "AdminCompletionRefused::Unavailable",
            Self::ReplayDenied(_) => "AdminCompletionRefused::ReplayDenied",
            Self::ReplayUnknown(_) => "AdminCompletionRefused::ReplayUnknown",
        })
    }
}

/// Host-only immutable verification state: the one prepared native identity (arch lints section 3.1).
/// Neither identity projection nor STRIP certifies that every declared credential field was verified;
/// field provenance needs its own attestation.
pub use super::native_chain::PreparedNativeIdentity as PreparedIdentity;

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
    prepared: Arc<PreparedIdentity>,
    spent: AtomicBool,
}

impl Pending {
    pub(super) fn new(invocation: Invocation, prepared: Arc<PreparedIdentity>) -> Self {
        Self {
            invocation,
            prepared,
            spent: AtomicBool::new(false),
        }
    }

    pub(super) async fn complete(&self) -> Result<ExecutionAdmission, AdmissionRefused> {
        self.complete_classified()
            .await
            .map_err(|_| AdmissionRefused)
    }

    pub(super) async fn complete_classified(
        &self,
    ) -> Result<ExecutionAdmission, AdminCompletionRefused> {
        // Consume before the first await. A cancelled or failed store call cannot retry this right.
        if self.spent.swap(true, Ordering::AcqRel)
            || !Arc::ptr_eq(&self.invocation.request, self.prepared.request())
            || self.invocation.cx.request_id != self.invocation.id.request_id().get()
            || std::time::Instant::now() >= self.invocation.cx.deadline
        {
            return Err(AdminCompletionRefused::Unavailable);
        }
        let lease = self
            .invocation
            .handle
            .admit_current(&self.invocation.selected, self.invocation.id, |_| {
                self.prepared.authorize(crate::store::now())
            })
            .map_err(|_| AdminCompletionRefused::Unavailable)?;
        match self.prepared.claim_classified().await {
            NativeReplayClaim::Claimed => {}
            NativeReplayClaim::Duplicate => {
                return Err(AdminCompletionRefused::ReplayDenied(Box::new(
                    AdminReplayDenial {
                        _lease: lease,
                        invocation: self.invocation.clone(),
                        _prepared: Arc::clone(&self.prepared),
                    },
                )))
            }
            NativeReplayClaim::Unknown(error) => {
                return Err(AdminCompletionRefused::ReplayUnknown(Box::new(
                    AdminReplayUnknown {
                        _lease: lease,
                        _invocation: self.invocation.clone(),
                        _prepared: Arc::clone(&self.prepared),
                        _error: error,
                    },
                )))
            }
            NativeReplayClaim::Inconsistent => return Err(AdminCompletionRefused::Unavailable),
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
    native: Option<(AdmissionLease, Arc<PreparedIdentity>)>,
    origin: Option<Invocation>,
}

impl ExecutionAdmission {
    pub(super) fn legacy() -> Self {
        Self {
            native: None,
            origin: None,
        }
    }
    pub fn native(&self) -> Option<(&AdmissionLease, &PreparedIdentity)> {
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
                module: prepared.provider_text(),
                principal: super::Principal {
                    id: identity.subject().to_owned(),
                    name: None,
                    roles: identity.groups().map(str::to_owned).collect(),
                    ttl_secs: identity.cache_s().map(u64::from),
                },
                resolved: None,
                signed_authority: None,
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
                module: prepared.provider_text(),
                principal: super::Principal {
                    id: identity.subject().to_owned(),
                    name: None,
                    roles: identity.groups().map(str::to_owned).collect(),
                    ttl_secs: identity.cache_s().map(u64::from),
                },
                resolved: None,
                signed_authority: None,
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

/// Keep the exact physical owner both in the transport handoff and in the body lifetime.
/// The native bridge moves the extension into delivery custody alongside its StreamOwner.
pub fn retain_physical_response(
    mut response: axum::response::Response,
    physical: Arc<crate::inbound::native::PhysicalAdminExecution>,
) -> axum::response::Response {
    use http_body_util::BodyExt;
    response.extensions_mut().insert(physical.clone());
    let body = std::mem::replace(response.body_mut(), axum::body::Body::empty());
    *response.body_mut() = axum::body::Body::new(body.map_frame(move |frame| {
        let _retain_until_body_drop = &physical;
        frame
    }));
    response
}

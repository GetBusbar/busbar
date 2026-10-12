// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S `records.secret`, COMPOSED AT THE ROOT (AUTH-DOOR Q2a; ARCHITECT 2026-10-01, option
//! (ii): the root composes, the rule stays in the kernel's credential lookup): the kernel's host
//! services serve every other service, and [`CredentialServices`] adds the credential read over
//! them, from [`AppCredentials`]: the CURRENT App snapshot's governance, read through the App's own
//! swap handle on every call, so a reload takes effect at once. The rule (a dummy secret, not live,
//! for an unknown id, at equal cost) is the kernel's `GovState::credential_secret`; this file only
//! delegates and converts.

use std::sync::{Arc, OnceLock};

use busbar_contract::abi::host::service::{ItemSpan, SECRET_LIVE, SECRET_NOT_LIVE};
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
use busbar_contract::redacted::Redacted;
use busbar_contract::services::{
    Caller, CredentialRead, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, Reading,
    RecordsList, Stored,
};

/// The App's swap handle, once it exists.
type Slot = Arc<OnceLock<Arc<busbar_kernel::state::AppHandle>>>;

/// The credential source over the App's swap handle: every read is the current snapshot's. The
/// handle may be set after the services are installed ([`AppCredentials::late`]): the serve path
/// composes the host services before the App is built (a plugin opened while the App builds may
/// judge a destination), and the App's swap handle exists only once it is.
pub struct AppCredentials(Slot);

impl AppCredentials {
    /// The reads over `handle`, the App's own swap handle.
    #[must_use]
    pub fn new(handle: Arc<busbar_kernel::state::AppHandle>) -> Self {
        let slot = OnceLock::new();
        let _ = slot.set(handle);
        Self(Arc::new(slot))
    }

    /// The reads over a swap handle set later, through the returned [`LateHandle`]: until it is,
    /// `records.secret` answers REFUSED.
    #[must_use]
    pub fn late() -> (Self, LateHandle) {
        let slot: Slot = Arc::default();
        (Self(slot.clone()), LateHandle(slot))
    }
}

/// Where the App's swap handle is set, once, after the App is built.
pub struct LateHandle(Slot);

impl LateHandle {
    /// Set the swap handle the reads go through (the first set stands).
    pub fn set(&self, handle: Arc<busbar_kernel::state::AppHandle>) {
        let _ = self.0.set(handle);
    }

    /// Whether it is set.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.0.get().is_some()
    }
}

/// The reason `records.secret` answers before a late source's handle is set.
pub const NOT_READABLE: &str = "the credential read is not installed yet";

/// A credential source the root serves `records.secret` over, and whether it can be read yet.
pub trait RootCredentials: CredentialRead {
    /// Whether a read can be answered (a late source cannot, until its handle is set).
    fn installed(&self) -> bool {
        true
    }
}

impl RootCredentials for AppCredentials {
    fn installed(&self) -> bool {
        self.0.get().is_some()
    }
}

impl CredentialRead for AppCredentials {
    fn read(&self, kind: &str, id: &str) -> (Redacted<String>, bool) {
        let Some(handle) = self.0.get() else {
            return (
                Redacted::new(busbar_kernel::auth::DUMMY_SECRET.to_string()),
                false,
            );
        };
        let app = handle.snapshot();
        let now = busbar_kernel::store::now();
        match app.governance.as_ref() {
            Some(gov) => gov.credential_secret(kind, id, now),
            // A node without governance holds no credential.
            None => (
                Redacted::new(busbar_kernel::auth::DUMMY_SECRET.to_string()),
                false,
            ),
        }
    }
}

/// The host services with `records.secret`: every other service is `inner`'s answer, and the
/// credential read is `credentials`', answered at once (span `0` the secret, the value its
/// liveness).
pub struct CredentialServices {
    inner: Arc<dyn HostServices>,
    credentials: Arc<dyn RootCredentials>,
}

impl CredentialServices {
    /// `inner` (the kernel's services) with the credential read over `credentials`.
    #[must_use]
    pub fn new(inner: Arc<dyn HostServices>, credentials: Arc<dyn RootCredentials>) -> Self {
        Self { inner, credentials }
    }
}

impl HostServices for CredentialServices {
    fn now(&self) -> Reading {
        self.inner.now()
    }

    fn dest_judge(&self, dest: &str, class: u32, flags: u32, later: Option<Later>) -> Ran {
        self.inner.dest_judge(dest, class, flags, later)
    }

    fn records_get(&self, caller: &Caller, kind: &str, key: &[u8], later: Later) -> Ran {
        self.inner.records_get(caller, kind, key, later)
    }

    fn records_list(&self, caller: &Caller, list: RecordsList, later: Later) -> Ran {
        self.inner.records_list(caller, list, later)
    }

    fn records_claim(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        ttl_ms: u64,
        later: Later,
    ) -> Ran {
        self.inner.records_claim(caller, kind, key, ttl_ms, later)
    }

    fn sign(&self, caller: &Caller, data: &[u8]) -> Stored {
        self.inner.sign(caller, data)
    }

    fn trust_sight(&self, caller: &Caller, counterparty: &str, hash: &str, later: Later) -> Ran {
        self.inner.trust_sight(caller, counterparty, hash, later)
    }

    fn trust_due(&self, caller: &Caller) -> Stored {
        self.inner.trust_due(caller)
    }

    fn trust_unreached(&self, caller: &Caller, counterparty: &str) -> Stored {
        self.inner.trust_unreached(caller, counterparty)
    }

    fn trust_decide(
        &self,
        caller: &Caller,
        key: busbar_contract::services::TrustKeyRef<'_>,
        expected: Option<&str>,
        approve: bool,
    ) -> Stored {
        self.inner.trust_decide(caller, key, expected, approve)
    }

    fn trust_state(&self, caller: &Caller, counterparty: &str) -> Stored {
        self.inner.trust_state(caller, counterparty)
    }

    fn trust_sight_item(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: &str,
        digest: &str,
    ) -> Stored {
        self.inner
            .trust_sight_item(caller, counterparty, item, digest)
    }

    fn trust_serves(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: Option<&str>,
        digest: Option<&str>,
    ) -> Stored {
        self.inner.trust_serves(caller, counterparty, item, digest)
    }

    fn trust_verify(
        &self,
        caller: &Caller,
        counterparty: &str,
        payload: &[u8],
        signatures: &[u8],
    ) -> Stored {
        self.inner
            .trust_verify(caller, counterparty, payload, signatures)
    }

    fn entitlement_check(&self, caller: &Caller, unit: Option<u64>, target: &str) -> Stored {
        self.inner.entitlement_check(caller, unit, target)
    }

    fn random_fill(&self, len: u64) -> Stored {
        self.inner.random_fill(len)
    }

    fn session_emit(&self, caller: &Caller, session: u64, bytes: &[u8]) -> Stored {
        self.inner.session_emit(caller, session, bytes)
    }

    fn records_secret(&self, kind: &str, id: &str, _later: Later) -> Ran {
        if !self.credentials.installed() {
            return Ran::Now(Stored::refused(NOT_READABLE));
        }
        let (secret, live) = self.credentials.read(kind, id);
        let bytes = secret.expose_secret().as_bytes().to_vec();
        let span = ItemSpan {
            key: Span {
                offset: SPAN_ABSENT,
                len: 0,
            },
            value: Span {
                offset: 0,
                len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            },
        };
        Ran::Now(Stored {
            bytes,
            spans: vec![span],
            ..Stored::ready(if live { SECRET_LIVE } else { SECRET_NOT_LIVE })
        })
    }

    fn unit_nest(&self, caller: &Caller, unit: Option<u64>, ask: NestAsk, later: Later) -> Ran {
        self.inner.unit_nest(caller, unit, ask, later)
    }

    fn work_open(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        kind: &str,
        record: &[u8],
        later: Later,
    ) -> Ran {
        self.inner.work_open(caller, unit, kind, record, later)
    }

    fn work_find(&self, caller: &Caller, unit: Option<u64>, reference: &[u8], later: Later) -> Ran {
        self.inner.work_find(caller, unit, reference, later)
    }

    fn work_settle(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        handle: u64,
        record: &[u8],
        later: Later,
    ) -> Ran {
        self.inner.work_settle(caller, unit, handle, record, later)
    }

    fn work_resume(&self, caller: &Caller, unit: Option<u64>, handle: u64, later: Later) -> Ran {
        self.inner.work_resume(caller, unit, handle, later)
    }

    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran {
        self.inner.disk_append(dest, bytes, later)
    }

    fn verify_lookup(&self, caller: &Caller, key: &[u8], later: Later) -> Ran {
        self.inner.verify_lookup(caller, key, later)
    }

    fn verify_store(&self, caller: &Caller, key: &[u8], entry: &[u8], ttl_ms: u64) -> Stored {
        self.inner.verify_store(caller, key, entry, ttl_ms)
    }

    fn content_scan(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        content: &[u8],
        later: Later,
    ) -> Ran {
        self.inner.content_scan(caller, unit, content, later)
    }

    fn hook_call(&self, caller: &Caller, unit: Option<u64>, ask: HookAsk, later: Later) -> Ran {
        self.inner.hook_call(caller, unit, ask, later)
    }

    fn snapshot_read(&self, caller: &Caller, scope: u32) -> busbar_contract::services::Snapshot {
        self.inner.snapshot_read(caller, scope)
    }
}

#[cfg(test)]
#[path = "tests/credentials.rs"]
mod tests;

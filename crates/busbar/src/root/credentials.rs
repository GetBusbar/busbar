// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S `records.secret`, COMPOSED AT THE ROOT (AUTH-DOOR Q2a; ARCHITECT 2026-10-01, option
//! (ii): the root composes, the rule stays in the kernel's credential lookup): the kernel's host
//! services serve every other service, and [`CredentialServices`] adds the credential read over
//! them, from [`AppCredentials`]: the CURRENT App snapshot's governance, read through the App's own
//! swap handle on every call, so a reload takes effect at once. The rule (a dummy secret, not live,
//! for an unknown id, at equal cost) is the kernel's `GovState::credential_secret`; this file only
//! delegates and converts.

use std::sync::Arc;

use busbar_contract::abi::host::service::{ItemSpan, SECRET_LIVE, SECRET_NOT_LIVE};
use busbar_contract::abi::mechanism::call::Span;
use busbar_contract::abi::mechanism::check::SPAN_ABSENT;
use busbar_contract::redacted::Redacted;
use busbar_contract::services::{
    Caller, CredentialRead, HostServices, Later, Ran, Reading, RecordsList, Stored,
};

/// The credential source over the App's swap handle: every read is the current snapshot's.
pub struct AppCredentials(Arc<busbar_kernel::state::AppHandle>);

impl AppCredentials {
    /// The reads over `handle`, the App's own swap handle.
    #[must_use]
    pub fn new(handle: Arc<busbar_kernel::state::AppHandle>) -> Self {
        Self(handle)
    }
}

impl CredentialRead for AppCredentials {
    fn read(&self, kind: &str, id: &str) -> (Redacted<String>, bool) {
        let app = self.0.snapshot();
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
    credentials: Arc<dyn CredentialRead>,
}

impl CredentialServices {
    /// `inner` (the kernel's services) with the credential read over `credentials`.
    #[must_use]
    pub fn new(inner: Arc<dyn HostServices>, credentials: Arc<dyn CredentialRead>) -> Self {
        Self { inner, credentials }
    }
}

impl HostServices for CredentialServices {
    fn now(&self) -> Reading {
        self.inner.now()
    }

    fn dest_judge(&self, dest: &str, class: u32, resolve: bool, later: Option<Later>) -> Ran {
        self.inner.dest_judge(dest, class, resolve, later)
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

    fn records_secret(&self, kind: &str, id: &str, _later: Later) -> Ran {
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
}

#[cfg(test)]
#[path = "tests/credentials.rs"]
mod tests;

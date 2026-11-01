// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S CREDENTIAL SOURCE (AUTH-DOOR Q2a): [`AppCredentials`] reads the CURRENT App
//! snapshot's governance, through the App's own swap handle on every call, so a reload takes effect
//! at once. The kernel's host services serve `records.secret` over it
//! (`KernelServices::with_credentials`). The rule (a dummy secret, not live, for an unknown id, at
//! equal cost) is the kernel's `GovState::credential_secret`; this file only delegates.

use std::sync::{Arc, OnceLock};

use busbar_contract::redacted::Secret;
use busbar_contract::services::CredentialRead;

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

impl CredentialRead for AppCredentials {
    fn installed(&self) -> bool {
        self.0.get().is_some()
    }

    fn read(&self, kind: &str, id: &str) -> (Secret<String>, bool) {
        let Some(handle) = self.0.get() else {
            return (Secret::new(String::new()), false);
        };
        let app = handle.snapshot();
        let now = busbar_kernel::store::now();
        match app.governance.as_ref() {
            Some(gov) => gov.credential_secret(kind, id, now),
            // A node without governance holds no credential.
            None => (Secret::new(String::new()), false),
        }
    }
}

#[cfg(test)]
#[path = "tests/credentials.rs"]
mod tests;

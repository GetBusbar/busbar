// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, OnceLock};

use busbar_contract::redacted::Secret;
use busbar_contract::services::CredentialRead;

type Slot = Arc<OnceLock<std::sync::Weak<busbar_kernel::state::AppHandle>>>;

pub struct AppCredentials(Slot);

impl AppCredentials {
    #[must_use]
    pub fn new(handle: Arc<busbar_kernel::state::AppHandle>) -> Self {
        let slot = OnceLock::new();
        let _ = slot.set(Arc::downgrade(&handle));
        Self(Arc::new(slot))
    }

    #[must_use]
    pub fn late() -> (Self, LateHandle) {
        let slot: Slot = Arc::default();
        (Self(slot.clone()), LateHandle(slot))
    }
}

pub struct LateHandle(Slot);

impl LateHandle {
    pub fn set(&self, handle: Arc<busbar_kernel::state::AppHandle>) {
        let _ = self.0.set(Arc::downgrade(&handle));
    }

    #[must_use]
    pub fn is_set(&self) -> bool {
        self.0.get().and_then(std::sync::Weak::upgrade).is_some()
    }
}

impl CredentialRead for AppCredentials {
    fn installed(&self) -> bool {
        self.0.get().and_then(std::sync::Weak::upgrade).is_some()
    }

    fn read(&self, kind: &str, id: &str) -> (Secret<String>, bool) {
        let Some(handle) = self.0.get().and_then(std::sync::Weak::upgrade) else {
            return (Secret::new(String::new()), false);
        };
        let app = handle.snapshot();
        let now = busbar_kernel::store::now();
        match app.governance.as_ref() {
            Some(gov) => gov.credential_secret(kind, id, now),

            None => (Secret::new(String::new()), false),
        }
    }
}

#[cfg(test)]
#[path = "tests/credentials.rs"]
mod tests;

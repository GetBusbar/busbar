// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::redacted::Secret;
use busbar_contract::services::CredentialRead;

/// Credential custody of one complete generation. Absence is permanent for this owner.
#[derive(Clone)]
pub struct AppCredentials(Option<Arc<busbar_kernel::governance::GovState>>);

impl AppCredentials {
    #[must_use]
    pub fn new(governance: Option<Arc<busbar_kernel::governance::GovState>>) -> Self {
        Self(governance)
    }
}

impl CredentialRead for AppCredentials {
    fn installed(&self) -> bool {
        self.0.is_some()
    }

    fn read(&self, kind: &str, id: &str) -> (Secret<String>, bool) {
        match &self.0 {
            Some(governance) => governance.credential_secret(kind, id, busbar_kernel::store::now()),
            None => (Secret::new(String::new()), false),
        }
    }
}

#[cfg(test)]
#[path = "tests/credentials.rs"]
mod tests;

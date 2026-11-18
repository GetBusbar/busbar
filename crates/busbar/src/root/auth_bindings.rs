// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The revocation set the admin door consults, bound to the governance state.
//!
//! The admin unit asks one question of the node's keys after the door identified a caller: has
//! this credential been taken away? [`AuthBindings`] carries the answer as a [`RevocationView`],
//! and [`GovernanceDirectory`] is the view for a node whose keys are busbar's own. Key
//! verification itself is the kernel auth chain's keys arm (`GovState::verify_token`).
//!
//! ## What an unbound node does
//!
//! [`AuthBindings::without_directory`] is a real posture and not a placeholder: a node that resolves
//! no busbar-minted keys has no revocation set to consult.
//!
//! ## No credential cache
//!
//! The kernel holds no verified-credential cache (THE DESIGN 11.11 R3): an auth plugin that caches
//! its verdicts does so inside itself, and the admin cache flush reaches it through its `refresh`.

use busbar_kernel_identity::RevocationView;
use std::sync::Arc;

pub struct AuthBindings {
    revocations: Option<Arc<dyn RevocationView>>,
}

impl AuthBindings {
    #[must_use]
    pub fn new(revocations: Arc<dyn RevocationView>) -> Self {
        AuthBindings {
            revocations: Some(revocations),
        }
    }

    #[must_use]
    pub(crate) fn without_directory() -> Self {
        AuthBindings { revocations: None }
    }

    #[must_use]
    pub fn revocations(&self) -> Option<&dyn RevocationView> {
        self.revocations.as_deref()
    }
}

impl std::fmt::Debug for AuthBindings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthBindings")
            .field("revocations", &self.revocations.is_some())
            .finish()
    }
}

pub struct GovernanceDirectory {
    state: Arc<busbar_kernel::governance::GovState>,
}

impl GovernanceDirectory {
    #[must_use]
    pub fn new(state: Arc<busbar_kernel::governance::GovState>) -> Self {
        GovernanceDirectory { state }
    }
}

impl RevocationView for GovernanceDirectory {
    fn is_revoked(&self, credential: &str) -> bool {
        self.state.is_revoked(credential)
    }
}

pub(crate) use crate::root::off_path::auth_bindings::{bind_from_planned, operator_binding};

#[cfg(test)]
#[path = "tests/auth_bindings.rs"]
mod tests;

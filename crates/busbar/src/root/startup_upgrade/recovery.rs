// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The migration verifier observes the retained serving candidate. It neither
//! builds another application nor shuts down the validated writer.

use std::sync::Arc;

use async_trait::async_trait;
use busbar_migrations::{self as migration, TargetRecoveryProbe};

use crate::root::startup_upgrade::continuation::StartupContinuation;

pub(super) struct Recovery {
    continuation: Arc<StartupContinuation>,
}

impl Recovery {
    pub(super) fn new(continuation: Arc<StartupContinuation>) -> Self {
        Self { continuation }
    }
}

#[async_trait]
impl TargetRecoveryProbe for Recovery {
    async fn verify_reopened_hydrated(
        &self,
        target: &migration::Identity,
    ) -> Result<migration::Digest32, migration::Error> {
        self.continuation.verify_target(target).await
    }
}

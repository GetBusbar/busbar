// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bind every fence check to a fresh live observation by the native owner.

use std::sync::Arc;

use super::{Error, FenceEvidence, Identity};
use busbar_contract::persistence::lifecycle;

struct NativeSession {
    prepared: lifecycle::Prepared,
    upgrade: lifecycle::UpgradeRef,
    source: lifecycle::SourceIdentity,
    snapshot: super::Id,
}

pub struct NativeSourceFence {
    source: Identity,
    native: NativeSession,
}

impl NativeSourceFence {
    /// Retained BeginOrResume authority; every check invokes the native owner.
    pub fn from_native(
        source: Identity,
        prepared: busbar_contract::persistence::lifecycle::Prepared,
        upgrade: &busbar_contract::persistence::lifecycle::Upgrade,
    ) -> Result<Self, Error> {
        if source.dataset != upgrade.source.dataset.0
            || source.artifact_digest == [0; 32]
            || upgrade.source.native_anchor == [0; 32]
            || upgrade.snapshot == [0; 16]
            || upgrade.reference.id == [0; 16]
        {
            return Err(Error::IdentityMismatch);
        }
        Ok(Self {
            source,
            native: NativeSession {
                prepared,
                upgrade: upgrade.reference.clone(),
                source: upgrade.source.clone(),
                snapshot: upgrade.snapshot,
            },
        })
    }

    /// A fresh live observation is mandatory on every call, including the final
    /// pre-activation check. Stable evidence excludes the observation itself.
    pub async fn verify(&self, source: &Identity) -> Result<FenceEvidence, Error> {
        if source != &self.source {
            return Err(Error::IdentityMismatch);
        }
        let NativeSession {
            prepared,
            upgrade,
            source: original,
            snapshot,
        } = &self.native;
        use busbar_contract::persistence::lifecycle::{Request, Response};
        let response = prepared
            .bootstrap(Arc::new(Request::CheckFence {
                upgrade: upgrade.clone(),
            }))
            .await
            .map_err(|error| match error {
                busbar_contract::persistence::lifecycle::Error::Pending
                | busbar_contract::persistence::lifecycle::Error::Busy
                | busbar_contract::persistence::lifecycle::Error::Unknown => Error::IntentPending,
                _ => super::startup::native_error(error),
            })?;
        let Response::Fence(fence) = response.as_ref() else {
            return Err(Error::Corrupt);
        };
        if fence.upgrade != upgrade.id
            || fence.source != *original
            || fence.snapshot != *snapshot
            || fence.enforcement_digest == [0; 32]
            || fence.observation_digest == [0; 32]
        {
            return Err(Error::FenceRequired);
        }
        Ok(FenceEvidence {
            source: source.dataset,
            native_anchor_digest: original.native_anchor,
            archive_digest: source.artifact_digest,
            enforcement_digest: fence.enforcement_digest,
            sender_quiescence_attestation: [0; 32],
            backend_quiescence_attestation: [0; 32],
            native_upgrade: Some(upgrade.id),
        })
    }
}

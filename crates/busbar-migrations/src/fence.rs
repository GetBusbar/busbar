// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bind independent operator quiescence statements to a live native probe.

use std::sync::Arc;

use busbar_contract::persistence::{
    archive,
    source_fence::{self, Attestation, ProbeRequest, Quiescence},
};

use super::{Digest32, Error, FenceEvidence, Identity, SourceFenceProbe};
use busbar_contract::persistence::lifecycle;

struct NativeSession {
    prepared: lifecycle::Prepared,
    upgrade: lifecycle::UpgradeRef,
    source: lifecycle::SourceIdentity,
    snapshot: super::Id,
}

pub struct NativeSourceFence {
    source: Identity,
    anchor: Digest32,
    writers: Vec<String>,
    sender: Digest32,
    backend: Digest32,
    probe: Option<Arc<dyn SourceFenceProbe>>,
    capture_policy: Digest32,
    native: Option<NativeSession>,
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
            anchor: upgrade.source.native_anchor,
            source,
            writers: Vec::new(),
            sender: [0; 32],
            backend: [0; 32],
            probe: None,
            capture_policy: [0; 32],
            native: Some(NativeSession {
                prepared,
                upgrade: upgrade.reference.clone(),
                source: upgrade.source.clone(),
                snapshot: upgrade.snapshot,
            }),
        })
    }
    pub fn new(
        source: Identity,
        header: &archive::Header,
        summary: archive::Summary,
        writers: Vec<String>,
        sender: &Attestation,
        backend: &Attestation,
        probe: Arc<dyn SourceFenceProbe>,
    ) -> Result<Self, Error> {
        let native_anchor = header.native_anchor_digest;
        let capture = header.capture.as_ref().ok_or(Error::FenceRequired)?;
        capture
            .validate(native_anchor)
            .map_err(|_| Error::FenceRequired)?;
        if native_anchor == [0; 32]
            || source.artifact_digest == [0; 32]
            || probe.implementation_digest() == [0; 32]
            || source.artifact_digest != summary.digest
            || source.schema_digest != summary.layout_digest
            || source.format.owner != header.owner
            || source.format.physical != header.physical
            || summary.content_digest == [0; 32]
            || !summary
                .post_observation_sha256
                .is_some_and(|value| value != [0; 32])
        {
            return Err(Error::FenceRequired);
        }
        let inventory =
            source_fence::writer_inventory_digest(&writers).map_err(|_| Error::FenceRequired)?;
        if inventory != capture.writer_inventory_sha256 {
            return Err(Error::FenceRequired);
        }
        let sender = sender
            .digest(
                Quiescence::Sender,
                native_anchor,
                source.artifact_digest,
                inventory,
            )
            .map_err(|_| Error::FenceRequired)?;
        let backend = backend
            .digest(
                Quiescence::Backend,
                native_anchor,
                source.artifact_digest,
                inventory,
            )
            .map_err(|_| Error::FenceRequired)?;
        Ok(Self {
            source,
            anchor: native_anchor,
            writers,
            sender,
            backend,
            probe: Some(probe),
            capture_policy: capture.enforcement_policy_sha256,
            native: None,
        })
    }

    /// A fresh live observation is mandatory on every call, including the final
    /// pre-activation check. Stable evidence excludes only the challenge itself.
    pub async fn verify(&self, source: &Identity) -> Result<FenceEvidence, Error> {
        if source != &self.source {
            return Err(Error::IdentityMismatch);
        }
        if let Some(session) = &self.native {
            let NativeSession {
                prepared,
                upgrade,
                source: original,
                snapshot,
            } = session;
            use busbar_contract::persistence::lifecycle::{Request, Response};
            let response = prepared
                .bootstrap(Arc::new(Request::CheckFence {
                    upgrade: upgrade.clone(),
                }))
                .await
                .map_err(|error| match error {
                    busbar_contract::persistence::lifecycle::Error::Pending
                    | busbar_contract::persistence::lifecycle::Error::Busy
                    | busbar_contract::persistence::lifecycle::Error::Unknown => {
                        Error::IntentPending
                    }
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
            return Ok(FenceEvidence {
                source: source.dataset,
                native_anchor_digest: original.native_anchor,
                archive_digest: source.artifact_digest,
                enforcement_digest: fence.enforcement_digest,
                sender_quiescence_attestation: [0; 32],
                backend_quiescence_attestation: [0; 32],
                native_upgrade: Some(upgrade.id),
            });
        }
        let mut challenge = [0; 32];
        getrandom::fill(&mut challenge).map_err(|_| Error::Entropy)?;
        if challenge == [0; 32] {
            return Err(Error::Entropy);
        }
        let request = ProbeRequest {
            version: source_fence::VERSION,
            source_owner: source.format.owner,
            source_physical: source.format.physical,
            archive_sha256: source.artifact_digest,
            native_anchor_sha256: self.anchor,
            old_writers: self.writers.clone(),
            sender_attestation_sha256: self.sender,
            backend_attestation_sha256: self.backend,
            challenge,
        };
        request.validate().map_err(|_| Error::FenceRequired)?;
        let probe = self.probe.as_ref().ok_or(Error::MissingCapability)?;
        let reply = probe.verify(&request).await?;
        if reply.enforcement_policy_sha256 != self.capture_policy {
            return Err(Error::FenceRequired);
        }
        let enforcement =
            source_fence::enforcement_digest(&request, &reply, probe.implementation_digest())
                .map_err(|_| Error::FenceRequired)?;
        Ok(FenceEvidence {
            source: source.dataset,
            native_anchor_digest: self.anchor,
            archive_digest: source.artifact_digest,
            enforcement_digest: enforcement,
            sender_quiescence_attestation: self.sender,
            backend_quiescence_attestation: self.backend,
            native_upgrade: None,
        })
    }
}

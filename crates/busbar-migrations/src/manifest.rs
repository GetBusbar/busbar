// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Error;

pub type Digest32 = [u8; 32];
pub type Id = [u8; 16];
pub const MANIFEST_VERSION: u32 = 1;
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_FAMILIES: usize = 64;
pub const MAX_EDGES: usize = 32;

/// Exact source format identity. Product SemVer is deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Format {
    pub owner: Id,
    pub logical: u32,
    pub physical: u32,
    pub codec: u32,
}

pub const CORE_FORMAT_OWNER: Id = *b"busbar.core.v1\0\0";
pub const CORE_FORMAT: Format = Format {
    owner: CORE_FORMAT_OWNER,
    logical: 1,
    physical: 1,
    codec: 1,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub dataset: Id,
    pub format: Format,
    pub artifact_digest: Digest32,
    pub schema_digest: Digest32,
    /// Informational release evidence, never used to select an edge.
    pub product_release: [u32; 3],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bounds {
    pub items: u32,
    pub bytes: u32,
}

impl Bounds {
    pub(super) fn validate(self) -> Result<(), Error> {
        if self.items == 0 || self.bytes == 0 || self.items > 65536 || self.bytes > 64 * 1024 * 1024
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Family {
    pub id: Id,
    pub source_schema: u32,
    pub target_schema: u32,
    pub target_namespace: Id,
}

/// Immutable released descriptor. Corrections register a new ID and digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub id: Id,
    pub source: Format,
    pub target: Format,
    pub code_digest: Digest32,
    pub preconditions_digest: Digest32,
    pub verification_rule_digest: Digest32,
    pub bounds: Bounds,
    pub families: Vec<Family>,
}

/// Construct once from compiled/trusted descriptors; manifests cannot add edges.
pub struct Registry {
    edges: Vec<Edge>,
}

impl Registry {
    pub fn new(edges: Vec<Edge>) -> Result<Self, Error> {
        if edges.len() > MAX_EDGES {
            return Err(Error::Bounds);
        }
        for (i, edge) in edges.iter().enumerate() {
            edge.bounds.validate()?;
            if edge.id == [0; 16]
                || edge.code_digest == [0; 32]
                || edge.preconditions_digest == [0; 32]
                || edge.verification_rule_digest == [0; 32]
                || edge.source == edge.target
                || edge.families.is_empty()
                || edge.families.len() > MAX_FAMILIES
                || edges[..i].iter().any(|old| old.id == edge.id)
            {
                return Err(Error::InvalidManifest);
            }
            for (j, family) in edge.families.iter().enumerate() {
                if family.id == [0; 16]
                    || family.target_namespace == [0; 16]
                    || super::coordinator::reserved(family.target_namespace)
                    || edge.families[..j].iter().any(|old| {
                        old.id == family.id || old.target_namespace == family.target_namespace
                    })
                {
                    return Err(Error::InvalidManifest);
                }
            }
        }
        Ok(Self { edges })
    }

    /// Explicit path validation, with no guessed semver or implicit bridge.
    pub fn plan(
        &self,
        migration: Id,
        source: Identity,
        target: Identity,
        path: &[Id],
    ) -> Result<Manifest, Error> {
        if path.is_empty() || path.len() > MAX_EDGES {
            return Err(Error::UnsupportedPath);
        }
        let mut format = source.format;
        let mut selected = Vec::new();
        for id in path {
            let edge = self
                .edges
                .iter()
                .find(|edge| edge.id == *id)
                .ok_or(Error::UnsupportedPath)?;
            if edge.source != format || selected.iter().any(|old: &Edge| old.id == edge.id) {
                return Err(Error::UnsupportedPath);
            }
            format = edge.target;
            selected.push(edge.clone());
        }
        if format != target.format {
            return Err(Error::UnsupportedPath);
        }
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            migration,
            source,
            target,
            edges: selected,
            state: State::Planned,
            fence: None,
            snapshot: None,
            checkpoints: Vec::new(),
            verification: None,
            readiness_digest: None,
            receipt_treatment: ReceiptTreatment::PreserveOriginalOrBlock,
            signing_key_ids: Vec::new(),
        };
        manifest.validate(self)?;
        Ok(manifest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Identified,
    Planned,
    SourceFenced,
    SnapshotVerified,
    Copying,
    TargetVerified,
    Activated,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptTreatment {
    PreserveOriginalOrBlock,
}

/// External enforcement and two operator attestations are separate evidence.
/// None of these digests alone proves fencing; the trusted verifier must check
/// the underlying credential/file fence and sender AND backend quiescence live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceEvidence {
    pub source: Id,
    pub native_anchor_digest: Digest32,
    pub archive_digest: Digest32,
    pub enforcement_digest: Digest32,
    pub sender_quiescence_attestation: Digest32,
    pub backend_quiescence_attestation: Digest32,
    /// Retained native lifecycle enforcement replaces operator attestations.
    #[serde(default)]
    pub native_upgrade: Option<Id>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEvidence {
    pub source: Id,
    pub snapshot: Id,
    pub content_digest: Digest32,
    pub coverage_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub family: Id,
    pub cursor: u64,
    pub source_count: u64,
    pub target_count: u64,
    pub source_bytes: u64,
    pub target_bytes: u64,
    pub source_digest: Digest32,
    pub target_digest: Digest32,
    pub complete: bool,
}

/// Evidence of decoded semantic checks and complete source coverage, not merely
/// the target's highest sequence or a hash of transformed output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedFamily {
    pub family: Id,
    pub source_count: u64,
    pub target_count: u64,
    pub source_digest: Digest32,
    pub target_digest: Digest32,
    pub decoded_invariants_digest: Digest32,
    pub source_coverage_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub cursor: u64,
    pub families: Vec<VerifiedFamily>,
    pub complete: bool,
    /// Unresolved imported debt requires explicit write-blocking verification.
    pub debt_write_blocks_digest: Digest32,
    #[serde(default)]
    pub partial: Option<VerificationCheckpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationCheckpoint {
    pub family: Id,
    pub after: u64,
    pub source_count: u64,
    pub target_count: u64,
    pub source_digest: Digest32,
    pub target_digest: Digest32,
    pub decoded_invariants_digest: Digest32,
}

/// Bounded, secret-free report. No SQL, filesystem paths, credentials or payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub migration: Id,
    pub source: Identity,
    pub target: Identity,
    pub edges: Vec<Edge>,
    pub state: State,
    pub fence: Option<FenceEvidence>,
    pub snapshot: Option<SnapshotEvidence>,
    pub checkpoints: Vec<Checkpoint>,
    pub verification: Option<Verification>,
    /// Actual retained live candidate's recovery/hydration proof, committed only
    /// in the final checkpoint before native serving admission.
    #[serde(default)]
    pub readiness_digest: Option<Digest32>,
    pub receipt_treatment: ReceiptTreatment,
    pub signing_key_ids: Vec<Id>,
}

impl Manifest {
    pub fn decode(bytes: &[u8], registry: &Registry) -> Result<Self, Error> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Bounds);
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|_| Error::InvalidManifest)?;
        manifest.validate(registry)?;
        Ok(manifest)
    }

    pub fn encode(&self, registry: &Registry) -> Result<Vec<u8>, Error> {
        self.validate(registry)?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::InvalidManifest)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Bounds);
        }
        Ok(bytes)
    }

    pub fn validate(&self, registry: &Registry) -> Result<(), Error> {
        if self.version != MANIFEST_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.migration == [0; 16]
            || self.source.dataset == [0; 16]
            || self.target.dataset == [0; 16]
            || self.source.dataset == self.target.dataset
            || self.edges.is_empty()
            || self.edges.len() > MAX_EDGES
            || self.checkpoints.len() > MAX_FAMILIES
            || self.signing_key_ids.len() > MAX_FAMILIES
        {
            return Err(Error::InvalidManifest);
        }
        for identity in [&self.source, &self.target] {
            if identity.format.owner == [0; 16]
                || identity.artifact_digest == [0; 32]
                || identity.schema_digest == [0; 32]
            {
                return Err(Error::IdentityMismatch);
            }
        }
        let mut format = self.source.format;
        for (i, edge) in self.edges.iter().enumerate() {
            if edge.source != format || self.edges[..i].iter().any(|old| old.id == edge.id) {
                return Err(Error::UnsupportedPath);
            }
            if !registry.edges.contains(edge) {
                return Err(Error::EdgeMismatch);
            }
            format = edge.target;
        }
        if format != self.target.format {
            return Err(Error::UnsupportedPath);
        }
        let fenced = !matches!(self.state, State::Identified | State::Planned);
        if (self.state == State::Retired) != self.readiness_digest.is_some()
            || self.readiness_digest == Some([0; 32])
        {
            return Err(Error::InvalidState);
        }
        if fenced != self.fence.is_some() {
            return Err(Error::InvalidState);
        }
        if let Some(fence) = &self.fence {
            if fence.source != self.source.dataset
                || fence.native_anchor_digest == [0; 32]
                || fence.archive_digest != self.source.artifact_digest
                || fence.enforcement_digest == [0; 32]
                || match fence.native_upgrade {
                    Some(id) => {
                        id != self.migration
                            || fence.sender_quiescence_attestation != [0; 32]
                            || fence.backend_quiescence_attestation != [0; 32]
                    }
                    None => {
                        fence.sender_quiescence_attestation == [0; 32]
                            || fence.backend_quiescence_attestation == [0; 32]
                    }
                }
            {
                return Err(Error::FenceRequired);
            }
        }
        let snapshotted = matches!(
            self.state,
            State::SnapshotVerified
                | State::Copying
                | State::TargetVerified
                | State::Activated
                | State::Retired
        );
        if snapshotted != self.snapshot.is_some() {
            return Err(Error::InvalidState);
        }
        if let Some(snapshot) = &self.snapshot {
            if snapshot.source != self.source.dataset
                || snapshot.snapshot == [0; 16]
                || snapshot.content_digest == [0; 32]
                || snapshot.coverage_digest == [0; 32]
            {
                return Err(Error::IdentityMismatch);
            }
        }
        if snapshotted {
            if self.edges.len() != 1 {
                return Err(Error::UnsupportedPath);
            }
            let families = &self.edges[0].families;
            if self.checkpoints.len() != families.len() {
                return Err(Error::InvalidManifest);
            }
            for (checkpoint, family) in self.checkpoints.iter().zip(families) {
                if checkpoint.family != family.id {
                    return Err(Error::InvalidManifest);
                }
            }
        } else if !self.checkpoints.is_empty() {
            return Err(Error::InvalidState);
        }
        if let Some(verification) = &self.verification {
            if !matches!(
                self.state,
                State::Copying | State::TargetVerified | State::Activated | State::Retired
            ) || !self.checkpoints.iter().all(|cp| cp.complete)
                || verification.families.len() > self.checkpoints.len()
            {
                return Err(Error::InvalidState);
            }
            for (index, family) in verification.families.iter().enumerate() {
                let cp = &self.checkpoints[index];
                if family.family != cp.family
                    || family.source_count != cp.source_count
                    || family.target_count != cp.target_count
                    || family.source_digest != cp.source_digest
                    || family.target_digest != cp.target_digest
                    || family.decoded_invariants_digest == [0; 32]
                    || family.source_coverage_digest == [0; 32]
                {
                    return Err(Error::Verification);
                }
            }
            if let Some(partial) = &verification.partial {
                let checkpoint = self
                    .checkpoints
                    .get(verification.families.len())
                    .ok_or(Error::Verification)?;
                if verification.complete
                    || partial.family != checkpoint.family
                    || partial.after > checkpoint.cursor
                    || partial.source_count > checkpoint.source_count
                    || partial.target_count > checkpoint.target_count
                    || partial.decoded_invariants_digest == [0; 32]
                {
                    return Err(Error::Verification);
                }
            }
            if verification.complete
                && (verification.families.len() != self.checkpoints.len()
                    || verification.partial.is_some()
                    || verification.debt_write_blocks_digest == [0; 32])
            {
                return Err(Error::Verification);
            }
        }
        if matches!(
            self.state,
            State::TargetVerified | State::Activated | State::Retired
        ) && !self.verification.as_ref().is_some_and(|v| v.complete)
        {
            return Err(Error::Verification);
        }
        Ok(())
    }

    /// Includes immutable source/target, the complete frozen edge path, key IDs,
    /// and receipt policy. Runtime progress and proofs are excluded.
    pub fn plan_digest(&self) -> Digest32 {
        let bytes = serde_json::to_vec(&(
            &self.version,
            &self.migration,
            &self.source,
            &self.target,
            &self.edges,
            &self.receipt_treatment,
            &self.signing_key_ids,
        ))
        .expect("fixed manifest fields serialize");
        let mut digest = Sha256::new();
        digest.update(b"busbar.migration.plan.v1\0");
        digest.update(bytes);
        digest.finalize().into()
    }
}

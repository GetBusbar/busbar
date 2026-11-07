// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Data-only protocol for explicitly invoked, trusted native source-fence probes.
//! Successful replies require real native enforcement checks. These types neither
//! disable accounts nor assert that an archive or an operator boolean is a fence.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current probe and attestation wire version.
pub const VERSION: u32 = 1;
/// Maximum encoded operator input or probe request size.
pub const MAX_INPUT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Content-free rejection of malformed, mismatched or unenforced evidence.
pub enum Error {
    /// Malformed or unsupported input.
    Invalid,
    /// Evidence belongs to another request, origin, archive or writer inventory.
    Scope,
    /// Required live native enforcement evidence is absent.
    Unfenced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Independent operator responsibility asserted by one cold statement.
pub enum Quiescence {
    /// Every old application sender has stopped issuing work.
    Sender,
    /// Already dispatched backend work has settled or been aborted.
    Backend,
}

/// Native evidence captured before opening the frozen read-only source snapshot.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFence {
    /// Exact old writers verified by the native capture helper.
    pub writer_inventory_sha256: [u8; 32],
    /// Stable native policy verified before and after the capture.
    pub enforcement_policy_sha256: [u8; 32],
    /// Fresh native observation before the snapshot was established.
    pub prefence_observation_sha256: [u8; 32],
}
impl CaptureFence {
    /// Require a real native origin and nonempty capture enforcement evidence.
    pub fn validate(&self, native_anchor: [u8; 32]) -> Result<(), Error> {
        if native_anchor == [0; 32]
            || self.writer_inventory_sha256 == [0; 32]
            || self.enforcement_policy_sha256 == [0; 32]
            || self.prefence_observation_sha256 == [0; 32]
        {
            return Err(Error::Unfenced);
        }
        Ok(())
    }
}
impl std::fmt::Debug for CaptureFence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureFence").finish_non_exhaustive()
    }
}

/// Live native capture observation. Before capture the challenge is a fresh
/// nonce; after capture it is the exact archive content-prefix digest, avoiding
/// a circular dependency on the final footer/artifact digest.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureObservation {
    /// Exact capture evidence protocol version.
    pub version: u32,
    /// Registered native source importer identity.
    pub source_owner: [u8; 16],
    /// Exact native physical source format.
    pub source_physical: u32,
    /// Actual complete native catalogue fingerprint.
    pub catalogue_digest: [u8; 32],
    /// Actual native instance and dataset origin.
    pub native_anchor_sha256: [u8; 32],
    /// Explicit old writer inventory checked by the native helper.
    pub writer_inventory_sha256: [u8; 32],
    /// Stable verified native enforcement policy.
    pub enforcement_policy_sha256: [u8; 32],
    /// Digest of the fresh successful live observations.
    pub observation_sha256: [u8; 32],
    /// Fresh nonce or the exact post-capture content-prefix digest.
    pub challenge: [u8; 32],
}
impl CaptureObservation {
    /// Check framing and nonempty bindings; native facts remain the trusted
    /// helper's responsibility and cannot be established by these hashes alone.
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION
            || self.source_owner == [0; 16]
            || self.source_physical == 0
            || self.catalogue_digest == [0; 32]
            || self.native_anchor_sha256 == [0; 32]
            || self.writer_inventory_sha256 == [0; 32]
            || self.enforcement_policy_sha256 == [0; 32]
            || self.observation_sha256 == [0; 32]
            || self.challenge == [0; 32]
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
impl std::fmt::Debug for CaptureObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureObservation").finish_non_exhaustive()
    }
}

/// Separate operator statements retain the existing cold-receipt conventions:
/// explicit epoch, actor, reason and independent sender/backend quiescence.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    /// Exact protocol version; unknown versions are rejected.
    pub version: u32,
    /// Which independent quiescence responsibility the operator attests.
    pub kind: Quiescence,
    /// Nonzero operator-issued statement identity.
    pub epoch: [u8; 16],
    /// Digest of the actual native instance and dataset origin.
    pub native_anchor_sha256: [u8; 32],
    /// SHA256 of the complete verified immutable source archive.
    pub archive_sha256: [u8; 32],
    /// Digest of the exact, explicitly supplied old-writer inventory.
    pub writer_inventory_sha256: [u8; 32],
    /// Operator assertion only; live native enforcement is separately required.
    pub quiesced: bool,
    /// Operator identity, retained in the statement digest and redacted from Debug.
    pub actor: String,
    /// Operator explanation, retained in the statement digest and redacted from Debug.
    pub reason: String,
}

impl Attestation {
    /// Validate the statement against its exact scope and hash its canonical encoding.
    pub fn digest(
        &self,
        kind: Quiescence,
        anchor: [u8; 32],
        archive: [u8; 32],
        writers: [u8; 32],
    ) -> Result<[u8; 32], Error> {
        if self.version != VERSION
            || self.kind != kind
            || self.epoch == [0; 16]
            || !self.quiesced
            || self.native_anchor_sha256 != anchor
            || self.archive_sha256 != archive
            || self.writer_inventory_sha256 != writers
            || !text(&self.actor, 256)
            || !text(&self.reason, 4096)
        {
            return Err(Error::Invalid);
        }
        hash(b"busbar.source.quiescence.v1\0", self)
    }
}

/// Fresh, data-only request sent to one explicitly trusted native probe.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    /// Exact protocol version; unknown versions are rejected.
    pub version: u32,
    /// Registered historical importer identity; not an executable selector.
    pub source_owner: [u8; 16],
    /// Exact source physical format understood by the native adapter.
    pub source_physical: u32,
    /// SHA256 of the complete verified immutable source archive.
    pub archive_sha256: [u8; 32],
    /// Digest of the actual native instance and dataset origin.
    pub native_anchor_sha256: [u8; 32],
    /// Exact native names, interpreted only by the selected trusted adapter.
    /// MySQL uses its canonical user@host spelling; never infer missing writers.
    pub old_writers: Vec<String>,
    /// Digest of the separately validated sender quiescence statement.
    pub sender_attestation_sha256: [u8; 32],
    /// Digest of the separately validated backend quiescence statement.
    pub backend_attestation_sha256: [u8; 32],
    /// Fresh per-invocation nonce bound into the request digest.
    pub challenge: [u8; 32],
}

/// Hash sorted exact writer names, rejecting an empty or duplicate inventory.
pub fn writer_inventory_digest(writers: &[String]) -> Result<[u8; 32], Error> {
    if writers.is_empty() || writers.iter().any(|writer| !text(writer, 1024)) {
        return Err(Error::Invalid);
    }
    let mut sorted: Vec<&str> = writers.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::Invalid);
    }
    hash(b"busbar.source.writers.v1\0", &sorted)
}

impl ProbeRequest {
    /// Validate version, nonzero bindings, explicit inventory and encoded size.
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION
            || self.source_owner == [0; 16]
            || self.source_physical == 0
            || self.archive_sha256 == [0; 32]
            || self.native_anchor_sha256 == [0; 32]
            || self.sender_attestation_sha256 == [0; 32]
            || self.backend_attestation_sha256 == [0; 32]
            || self.challenge == [0; 32]
        {
            return Err(Error::Invalid);
        }
        writer_inventory_digest(&self.old_writers)?;
        if serde_json::to_vec(self).map_err(|_| Error::Invalid)?.len() > MAX_INPUT_BYTES {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    /// Hash the validated canonical request, including its fresh challenge.
    pub fn digest(&self) -> Result<[u8; 32], Error> {
        self.validate()?;
        hash(b"busbar.source.probe.request.v1\0", self)
    }
}

/// Emitted only after checking disabled/locked old writers, no remaining native
/// sessions/commands/prepared work, correct native origin and stable enforcement.
/// The fresh request digest prevents accepting a saved response as a live probe.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeReply {
    /// Exact protocol version; unknown versions are rejected.
    pub version: u32,
    /// Digest of the complete fresh request, including its challenge.
    pub request_sha256: [u8; 32],
    /// Digest of the actual native instance and dataset origin.
    pub native_anchor_sha256: [u8; 32],
    /// SHA256 of the complete verified immutable source archive.
    pub archive_sha256: [u8; 32],
    /// Digest of the exact, explicitly supplied old-writer inventory.
    pub writer_inventory_sha256: [u8; 32],
    /// Stable digest of the actual verified native enforcement policy.
    pub enforcement_policy_sha256: [u8; 32],
    /// Digest of this invocation's live native observations.
    pub observation_sha256: [u8; 32],
}

impl ProbeReply {
    /// Require exact fresh-request scope and nonempty native policy/observation evidence.
    pub fn validate(&self, request: &ProbeRequest) -> Result<(), Error> {
        if self.version != VERSION
            || self.request_sha256 != request.digest()?
            || self.native_anchor_sha256 != request.native_anchor_sha256
            || self.archive_sha256 != request.archive_sha256
            || self.writer_inventory_sha256 != writer_inventory_digest(&request.old_writers)?
        {
            return Err(Error::Scope);
        }
        if self.enforcement_policy_sha256 == [0; 32] || self.observation_sha256 == [0; 32] {
            return Err(Error::Unfenced);
        }
        Ok(())
    }
}

/// Stable evidence excludes the per-call challenge/observation but includes the
/// trusted helper identity, native policy and both bound operator statements.
pub fn enforcement_digest(
    request: &ProbeRequest,
    reply: &ProbeReply,
    helper_sha256: [u8; 32],
) -> Result<[u8; 32], Error> {
    reply.validate(request)?;
    if helper_sha256 == [0; 32] {
        return Err(Error::Invalid);
    }
    hash(
        b"busbar.source.enforcement.v1\0",
        &(
            request.source_owner,
            request.source_physical,
            request.native_anchor_sha256,
            request.archive_sha256,
            writer_inventory_digest(&request.old_writers)?,
            request.sender_attestation_sha256,
            request.backend_attestation_sha256,
            reply.enforcement_policy_sha256,
            helper_sha256,
        ),
    )
}

fn text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn hash<T: Serialize + ?Sized>(domain: &[u8], value: &T) -> Result<[u8; 32], Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Invalid)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    Ok(digest.finalize().into())
}

impl std::fmt::Debug for Attestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attestation").finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ProbeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeRequest").finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ProbeReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeReply").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> ProbeRequest {
        ProbeRequest {
            version: VERSION,
            source_owner: [1; 16],
            source_physical: 6,
            archive_sha256: [2; 32],
            native_anchor_sha256: [3; 32],
            old_writers: vec!["legacy@localhost".into()],
            sender_attestation_sha256: [4; 32],
            backend_attestation_sha256: [5; 32],
            challenge: [6; 32],
        }
    }
    fn reply(request: &ProbeRequest) -> ProbeReply {
        ProbeReply {
            version: VERSION,
            request_sha256: request.digest().unwrap(),
            native_anchor_sha256: request.native_anchor_sha256,
            archive_sha256: request.archive_sha256,
            writer_inventory_sha256: writer_inventory_digest(&request.old_writers).unwrap(),
            enforcement_policy_sha256: [7; 32],
            observation_sha256: [8; 32],
        }
    }
    #[test]
    fn fresh_scope_rejects_saved_reply_and_changed_origin() {
        let mut current = request();
        let response = reply(&current);
        response.validate(&current).unwrap();
        current.challenge = [9; 32];
        assert_eq!(response.validate(&current), Err(Error::Scope));
        current = request();
        current.native_anchor_sha256 = [10; 32];
        assert_eq!(response.validate(&current), Err(Error::Scope));
    }
    #[test]
    fn inventory_is_explicit_unique_and_order_independent() {
        assert!(writer_inventory_digest(&[]).is_err());
        assert!(writer_inventory_digest(&["a".into(), "a".into()]).is_err());
        assert_eq!(
            writer_inventory_digest(&["a".into(), "b".into()]),
            writer_inventory_digest(&["b".into(), "a".into()])
        );
    }
    #[test]
    fn independent_attestations_bind_origin_archive_and_inventory() {
        let request = request();
        let writers = writer_inventory_digest(&request.old_writers).unwrap();
        let attestation = Attestation {
            version: VERSION,
            kind: Quiescence::Sender,
            epoch: [1; 16],
            native_anchor_sha256: request.native_anchor_sha256,
            archive_sha256: request.archive_sha256,
            writer_inventory_sha256: writers,
            quiesced: true,
            actor: "private actor marker".into(),
            reason: "private reason marker".into(),
        };
        attestation
            .digest(
                Quiescence::Sender,
                request.native_anchor_sha256,
                request.archive_sha256,
                writers,
            )
            .unwrap();
        assert!(attestation
            .digest(
                Quiescence::Backend,
                request.native_anchor_sha256,
                request.archive_sha256,
                writers
            )
            .is_err());
        assert!(!format!("{attestation:?}").contains("marker"));
    }
    #[test]
    fn capture_and_enforcement_require_real_origin_and_stable_policy() {
        let capture = CaptureFence {
            writer_inventory_sha256: [1; 32],
            enforcement_policy_sha256: [2; 32],
            prefence_observation_sha256: [3; 32],
        };
        assert_eq!(capture.validate([0; 32]), Err(Error::Unfenced));
        capture.validate([4; 32]).unwrap();
        let first = request();
        let first_reply = reply(&first);
        let mut second = request();
        second.challenge = [9; 32];
        let mut second_reply = reply(&second);
        second_reply.observation_sha256 = [10; 32];
        assert_eq!(
            enforcement_digest(&first, &first_reply, [11; 32]),
            enforcement_digest(&second, &second_reply, [11; 32])
        );
    }
}

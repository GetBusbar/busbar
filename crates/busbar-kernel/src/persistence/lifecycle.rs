// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-side verification of an activation proof, once, for every store
//! (STORE-TRANSACTIONS decision 185). The store returns raw facts (the checkpoint and
//! completion-marker bytes, read here through an ordinary coherent READ) and later
//! only compares digests and fills a write-once slot. It never judges the proof.

use busbar_contract::persistence::archive::digest;
use busbar_contract::persistence::lifecycle::{
    codec, ActivationReceipt, Bounds, CompletionPhase, Error, FinishDecision,
};
use busbar_contract::persistence::DatasetId;

/// The upgrade session the marker must name, exactly as core's coordinator wrote it
/// (`completion_marker`: manifest migration, source and target dataset ids), never a
/// store-native identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    pub upgrade: [u8; 16],
    pub source: DatasetId,
    pub target: DatasetId,
}

const MARKER_BOUNDS: Bounds = Bounds {
    items: 64,
    bytes: 1024 * 1024,
};

/// Verify `proof` against the stored checkpoint and completion marker and decide the
/// `Finish` the store must publish.
///
/// Both phases share the marker and checkpoint addresses. An Activation proof is
/// therefore also accepted against a later Complete marker naming the same
/// checkpoint address, provided the stored checkpoint hashes to that marker's digest
/// (the restart-after-Complete replay).
///
/// # Errors
/// `Refused` for a missing or mismatched checkpoint or marker, `SourceChanged` for
/// a marker of another upgrade, source or target, `Corrupt` for undecodable bytes.
pub fn verify_activation(
    proof: &ActivationReceipt,
    session: Session,
    checkpoint: Option<&[u8]>,
    marker: Option<&[u8]>,
) -> Result<FinishDecision, Error> {
    if proof.attempt.dataset != session.target {
        return Err(Error::SourceChanged);
    }
    let checkpoint = checkpoint.ok_or(Error::Refused)?;
    let marker_bytes = marker.ok_or(Error::Refused)?;
    let marker = codec::decode_completion_marker(marker_bytes, MARKER_BOUNDS)?;
    if marker.upgrade != session.upgrade
        || marker.source != session.source
        || marker.target != session.target
    {
        return Err(Error::SourceChanged);
    }
    if marker.checkpoint_address != proof.checkpoint_address {
        return Err(Error::Refused);
    }
    let stored = digest(checkpoint);
    let current = marker.phase == proof.phase
        && marker.checkpoint_value_digest == proof.checkpoint_value_digest
        && stored == proof.checkpoint_value_digest;
    let replay_after_complete = proof.phase == CompletionPhase::Activation
        && marker.phase == CompletionPhase::Complete
        && stored == marker.checkpoint_value_digest;
    if !current && !replay_after_complete {
        return Err(Error::Refused);
    }
    Ok(FinishDecision {
        phase: proof.phase,
        phase_digest: phase_digest(proof),
        checkpoint_address: proof.checkpoint_address.clone(),
        // Always the proof's digest: an Activation replay against a Complete marker
        // can then only succeed through the store's already-filled slot (step 1).
        checkpoint_value_digest: proof.checkpoint_value_digest,
        marker_value_digest: digest(marker_bytes),
    })
}

/// The write-once identity of a verified proof: computed from the proof alone, so a
/// retry, a restart and the live coordinator produce the same bytes.
#[must_use]
pub fn phase_digest(proof: &ActivationReceipt) -> [u8; 32] {
    let a = proof.attempt;
    let key = &proof.checkpoint_address.key;
    let mut bytes = Vec::with_capacity(160 + key.len());
    bytes.extend_from_slice(b"busbar.activation/1\0");
    bytes.push(match proof.phase {
        CompletionPhase::Activation => 0,
        CompletionPhase::Complete => 1,
    });
    bytes.extend_from_slice(&a.dataset.0);
    bytes.extend_from_slice(&a.writer_epoch.to_le_bytes());
    bytes.extend_from_slice(&a.writer);
    bytes.extend_from_slice(&a.execution_epoch.to_le_bytes());
    bytes.extend_from_slice(&a.operation);
    bytes.extend_from_slice(&proof.candidate_fingerprint);
    bytes.extend_from_slice(&proof.checkpoint_address.namespace);
    bytes.extend_from_slice(&(key.len() as u64).to_le_bytes());
    bytes.extend_from_slice(key);
    bytes.extend_from_slice(&proof.checkpoint_value_digest);
    digest(&bytes)
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;

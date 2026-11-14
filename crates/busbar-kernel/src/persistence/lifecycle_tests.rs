// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STORE-TRANSACTIONS decision-185 addendum: host-side activation verification.

use super::*;
use busbar_contract::persistence::lifecycle::{CompletionMarker, VERSION};
use busbar_contract::persistence::{Address, AttemptId};

const UPGRADE: [u8; 16] = [1; 16];
const SOURCE: DatasetId = DatasetId([2; 16]);
const TARGET: DatasetId = DatasetId([3; 16]);

fn session() -> Session {
    Session {
        upgrade: UPGRADE,
        source: SOURCE,
        target: TARGET,
    }
}

fn checkpoint_address() -> Address {
    Address {
        namespace: [4; 16],
        key: b"checkpoint".to_vec(),
    }
}

fn proof(phase: CompletionPhase, checkpoint: &[u8]) -> ActivationReceipt {
    ActivationReceipt {
        attempt: AttemptId {
            dataset: TARGET,
            writer_epoch: 1,
            writer: [5; 16],
            execution_epoch: 1,
            operation: [6; 16],
        },
        candidate_fingerprint: [7; 32],
        checkpoint_address: checkpoint_address(),
        checkpoint_value_digest: digest(checkpoint),
        phase,
    }
}

fn marker(
    phase: CompletionPhase,
    checkpoint: &[u8],
    edit: impl FnOnce(&mut CompletionMarker),
) -> Vec<u8> {
    let mut marker = CompletionMarker {
        version: VERSION,
        phase,
        upgrade: UPGRADE,
        source: SOURCE,
        target: TARGET,
        checkpoint_address: checkpoint_address(),
        checkpoint_value_digest: digest(checkpoint),
    };
    edit(&mut marker);
    codec::encode_completion_marker(&marker, MARKER_BOUNDS)
        .unwrap()
        .expose(&crate::seal::lend())
        .clone()
}

#[test]
fn a_matching_checkpoint_and_marker_decide_the_finish() {
    for phase in [CompletionPhase::Activation, CompletionPhase::Complete] {
        let proof = proof(phase, b"state");
        let marker = marker(phase, b"state", |_| {});
        let decision = verify_activation(&proof, session(), Some(b"state"), Some(&marker)).unwrap();
        assert_eq!(decision.phase, phase);
        assert_eq!(decision.phase_digest, phase_digest(&proof));
        assert_eq!(decision.checkpoint_address, checkpoint_address());
        assert_eq!(decision.checkpoint_value_digest, digest(b"state"));
        assert_eq!(decision.marker_value_digest, digest(&marker));
    }
}

#[test]
fn missing_or_mismatched_evidence_is_refused() {
    let activation = proof(CompletionPhase::Activation, b"state");
    let good = marker(CompletionPhase::Activation, b"state", |_| {});
    let refused = |checkpoint: Option<&[u8]>, marker: Option<&[u8]>| {
        verify_activation(&activation, session(), checkpoint, marker)
    };
    assert_eq!(refused(None, Some(&good)), Err(Error::Refused));
    assert_eq!(refused(Some(b"other"), Some(&good)), Err(Error::Refused));
    assert_eq!(refused(Some(b"state"), None), Err(Error::Refused));
    let other_digest = marker(CompletionPhase::Activation, b"other", |_| {});
    assert_eq!(
        refused(Some(b"state"), Some(&other_digest)),
        Err(Error::Refused)
    );
    let other_address = marker(CompletionPhase::Activation, b"state", |m| {
        m.checkpoint_address.key = b"elsewhere".to_vec();
    });
    assert_eq!(
        refused(Some(b"state"), Some(&other_address)),
        Err(Error::Refused)
    );
    // A Complete proof never accepts an Activation marker.
    let complete = proof(CompletionPhase::Complete, b"state");
    assert_eq!(
        verify_activation(&complete, session(), Some(b"state"), Some(&good)),
        Err(Error::Refused)
    );
    assert!(refused(Some(b"state"), Some(b"not a marker")).is_err());
}

#[test]
fn a_marker_of_another_session_is_source_changed() {
    let activation = proof(CompletionPhase::Activation, b"state");
    for edit in [
        (|m: &mut CompletionMarker| m.upgrade = [9; 16]) as fn(&mut CompletionMarker),
        |m| m.source = DatasetId([9; 16]),
        |m| m.target = DatasetId([9; 16]),
    ] {
        let marker = marker(CompletionPhase::Activation, b"state", edit);
        assert_eq!(
            verify_activation(&activation, session(), Some(b"state"), Some(&marker)),
            Err(Error::SourceChanged)
        );
    }
}

/// Restart after the Complete checkpoint committed: the Activation proof is replayed
/// against the current Complete marker; the decision still names the Activation
/// proof's checkpoint digest, so only an already-filled slot can accept it.
#[test]
fn activation_replays_against_the_later_complete_marker() {
    let activation = proof(CompletionPhase::Activation, b"activated");
    let complete = marker(CompletionPhase::Complete, b"completed", |_| {});
    let decision =
        verify_activation(&activation, session(), Some(b"completed"), Some(&complete)).unwrap();
    assert_eq!(decision.phase, CompletionPhase::Activation);
    assert_eq!(decision.phase_digest, phase_digest(&activation));
    assert_eq!(decision.checkpoint_value_digest, digest(b"activated"));
    // The current checkpoint must still match the Complete marker's digest.
    assert_eq!(
        verify_activation(&activation, session(), Some(b"tampered"), Some(&complete)),
        Err(Error::Refused)
    );
}

#[test]
fn the_phase_digest_is_stable_and_binds_every_proof_field() {
    let base = proof(CompletionPhase::Activation, b"state");
    // Two independently built copies (live and restart) give identical bytes.
    assert_eq!(
        phase_digest(&base),
        phase_digest(&proof(CompletionPhase::Activation, b"state"))
    );
    let edits: [fn(&mut ActivationReceipt); 9] = [
        |p| p.phase = CompletionPhase::Complete,
        |p| p.attempt.dataset = DatasetId([9; 16]),
        |p| p.attempt.writer_epoch = 2,
        |p| p.attempt.writer = [9; 16],
        |p| p.attempt.execution_epoch = 2,
        |p| p.attempt.operation = [9; 16],
        |p| p.candidate_fingerprint = [9; 32],
        |p| p.checkpoint_address.key = b"other".to_vec(),
        |p| p.checkpoint_value_digest = [9; 32],
    ];
    for edit in edits {
        let mut changed = base.clone();
        edit(&mut changed);
        assert_ne!(phase_digest(&changed), phase_digest(&base));
    }
}

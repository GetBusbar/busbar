// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::persistence::{AttemptId, DatasetId};

fn header() -> codec::Header {
    codec::Header {
        generation: 1,
        origin: AttemptId {
            dataset: DatasetId([1; 16]),
            writer_epoch: 2,
            writer: [3; 16],
            execution_epoch: 4,
            operation: [5; 16],
        },
        purpose: 1,
        transition: [6; 32],
    }
}

#[test]
fn recovery_header_preserves_the_original_authority_and_never_allocates_a_new_id() {
    let source = header();
    let bytes = source.encode();
    let restored = codec::Header::decode(&bytes).unwrap();
    assert_eq!(restored, source);
    assert_eq!(restored.origin.operation, [5; 16]);
    assert_eq!(restored.origin.execution_epoch, 4);
}

#[test]
fn malformed_or_future_intent_headers_are_refused_without_fallback() {
    let bytes = header().encode();
    for cut in 0..bytes.len() {
        assert!(codec::Header::decode(&bytes[..cut]).is_err());
    }
    let mut future = bytes.clone();
    future[7] = 2;
    assert!(codec::Header::decode(&future).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(codec::Header::decode(&trailing).is_err());
    for index in [8, 16, 40, 56, 64] {
        let mut invalid = header();
        match index {
            8 => invalid.generation = 0,
            16 => invalid.origin.dataset = DatasetId([0; 16]),
            40 => invalid.origin.writer = [0; 16],
            56 => invalid.origin.execution_epoch = 0,
            _ => invalid.origin.operation = [0; 16],
        }
        assert!(codec::Header::decode(&invalid.encode()).is_err());
    }
}

#[test]
fn terminal_outcomes_never_alias_pending_or_each_other() {
    assert_ne!(codec::Phase::Pending.tag(), codec::Phase::Applied.tag());
    assert_ne!(codec::Phase::Applied.tag(), codec::Phase::NoEffect.tag());
    for phase in [
        codec::Phase::Pending,
        codec::Phase::Applied,
        codec::Phase::NoEffect,
    ] {
        assert_eq!(codec::Phase::decode(phase.tag()).unwrap(), phase);
    }
    assert!(codec::Phase::decode(0).is_err());
    assert!(codec::Phase::decode(4).is_err());
}

#[test]
fn a_stale_generation_cannot_be_reused_as_a_new_preparation() {
    assert_eq!(next_generation(None).unwrap(), 1);
    assert_eq!(next_generation(Some(17)).unwrap(), 18);
    assert_eq!(next_generation(Some(u64::MAX)), Err(Error::Overflow));
}

#[test]
fn recovered_or_superseded_results_cannot_be_foreground_success() {
    assert_eq!(Outcome::Superseded, Outcome::Superseded);
    assert!(!Outcome::Superseded.applied());
    assert!(!Outcome::NoEffect.applied());
    assert!(!Outcome::Pending.applied());
    assert!(!Outcome::Reconcile.applied());
    assert!(Outcome::Applied.applied());
}

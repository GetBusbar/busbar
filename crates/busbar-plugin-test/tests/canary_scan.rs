// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Q24 memory scan proves itself (RT10): it is green when a secret was wiped and red when it was
//! not, and it refuses to say "absent" unless its two controls were found. Linux only (A23); the
//! process runs with `_RJEM_MALLOC_CONF=dirty_decay_ms:-1,muzzy_decay_ms:-1` (`.cargo/config.toml`).
#![cfg(target_os = "linux")]

use busbar_plugin_test::canary_scan::{WipeProof, CANARY_LEN, PAYLOAD_LEN};
use zeroize::Zeroizing;

#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[test]
fn a_secret_wiped_before_it_is_freed_is_absent() {
    let proof = WipeProof::new();
    {
        let staging = proof.payload();
        assert_eq!(staging.len(), PAYLOAD_LEN);
        let copy = Zeroizing::new(staging.to_vec());
        drop(staging);
        drop(copy);
    }
    proof.assert_absent("a wiped copy");
}

#[test]
fn a_secret_freed_without_a_wipe_is_found() {
    let proof = WipeProof::new();
    {
        let staging = proof.payload();
        let leaked = staging.to_vec();
        drop(staging);
        drop(leaked);
    }
    let copies = proof.canary_copies("an unwiped copy");
    assert!(copies >= 1, "the scan missed an unwiped, dropped canary");
}

#[test]
fn a_secret_still_held_is_found() {
    let proof = WipeProof::new();
    let mut held = Zeroizing::new(vec![0_u8; CANARY_LEN]);
    proof.write_canary(&mut held);
    let copies = proof.canary_copies("a live canary");
    assert!(copies >= 1, "the scan missed a live canary");
    drop(held);
}

#[test]
#[should_panic(expected = "copies of the canary are still in process memory")]
fn assert_absent_fails_when_the_canary_remains() {
    let proof = WipeProof::new();
    let mut held = vec![0_u8; CANARY_LEN];
    proof.write_canary(&mut held);
    proof.assert_absent("a held canary");
    drop(held);
}

#[test]
fn a_text_secret_wiped_before_it_is_freed_is_absent() {
    let proof = WipeProof::text();
    {
        let staging = proof.text_payload();
        assert_eq!(staging.len(), PAYLOAD_LEN);
        let copy = Zeroizing::new(String::clone(&staging));
        drop(staging);
        drop(copy);
    }
    proof.assert_absent("a wiped text copy");
}

#[test]
fn a_text_secret_freed_without_a_wipe_is_found() {
    let proof = WipeProof::text();
    {
        let staging = proof.text_payload();
        let leaked = String::clone(&staging);
        drop(staging);
        drop(leaked);
    }
    let copies = proof.canary_copies("an unwiped text copy");
    assert!(
        copies >= 1,
        "the scan missed an unwiped, dropped text canary"
    );
}

#[test]
#[should_panic(expected = "a text payload needs a proof made by WipeProof::text()")]
fn a_byte_proof_refuses_a_text_payload() {
    let proof = WipeProof::new();
    let _ = proof.text_payload();
}

#[test]
fn a_held_secret_passes_assert_held_and_its_wiped_drop_is_absent() {
    let mut proof = WipeProof::new();
    let held = proof.payload();
    let owner = Zeroizing::new(held.to_vec());
    drop(held);
    proof.assert_held("a live owner");
    drop(owner);
    proof.assert_absent("the owner wiped on drop");
}

#[test]
#[should_panic(expected = "the canary is not in memory while its owner should still hold it")]
fn assert_held_fails_once_the_secret_is_wiped() {
    let mut proof = WipeProof::new();
    drop(proof.payload());
    proof.assert_held("a wiped owner");
}

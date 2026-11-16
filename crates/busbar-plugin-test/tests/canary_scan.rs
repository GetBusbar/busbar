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

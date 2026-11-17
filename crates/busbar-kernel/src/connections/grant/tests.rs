// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use crate::governance::at_rest::AtRestKeys;
use std::sync::Arc;

fn records() -> GrantRecords {
    GrantRecords::new(
        Arc::new(
            AtRestKeys::new(&[7; 32], None)
                .caller_records(4096)
                .unwrap(),
        ),
        [1; 16],
        [2; 16],
    )
    .unwrap()
}
fn key() -> GrantKey {
    GrantKey::new("plane", "instance", "subject", "upstream").unwrap()
}

#[test]
fn grant_namespace_is_complete_and_unambiguous() {
    let baseline = key();
    for other in [
        GrantKey::new("other", "instance", "subject", "upstream").unwrap(),
        GrantKey::new("plane", "other", "subject", "upstream").unwrap(),
        GrantKey::new("plane", "instance", "other", "upstream").unwrap(),
        GrantKey::new("plane", "instance", "subject", "other").unwrap(),
    ] {
        assert_ne!(baseline.encoded(), other.encoded());
    }
    assert_ne!(
        GrantKey::new("a:b", "c", "s", "u").unwrap().encoded(),
        GrantKey::new("a", "b:c", "s", "u").unwrap().encoded()
    );
    assert!(!baseline.encoded().windows(7).any(|w| w == b"subject"));
    assert!(!format!("{baseline:?}").contains("subject"));
}

#[test]
fn mint_owner_is_bound_to_exact_grant_and_unknown_rotation_requires_reconnect() {
    let records = records();
    let key = key();
    let install = records.install(&key, None, b"\xffopaque-grant").unwrap();
    let live = records.decode(&key, install.successor()).unwrap();
    let start = records.start_mint(&live, [3; 16]).unwrap();
    let minting = records.decode(&key, start.successor()).unwrap();
    assert_eq!(minting.version().state, GrantState::Minting);
    assert!(records.start_mint(&minting, [4; 16]).is_err());
    assert!(records.delivery(&minting, live.version().epoch).is_err());
    assert!(records
        .finish_mint(&minting, [4; 16], Some(b"replacement"))
        .is_err());
    let failed = records.reconnect_required(&minting, [3; 16]).unwrap();
    let failed = records.decode(&key, failed.successor()).unwrap();
    assert_eq!(failed.version().state, GrantState::ReconnectRequired);
    assert!(failed.version().epoch > live.version().epoch);
    assert!(records.start_mint(&failed, [5; 16]).is_err());
    assert!(records.delivery(&failed, live.version().epoch).is_err());
}

#[test]
fn refresh_keeps_epoch_but_revoke_and_reconnect_advance_it() {
    let records = records();
    let key = key();
    let install = records.install(&key, None, b"grant").unwrap();
    let live = records.decode(&key, install.successor()).unwrap();
    let start = records.start_mint(&live, [3; 16]).unwrap();
    let minting = records.decode(&key, start.successor()).unwrap();
    let finish = records
        .finish_mint(&minting, [3; 16], Some(b"new-grant"))
        .unwrap();
    let refreshed = records.decode(&key, finish.successor()).unwrap();
    assert_eq!(refreshed.version().epoch, live.version().epoch);
    assert!(refreshed.version().revision > live.version().revision);
    let revoked = records.revoke(&key, Some(&refreshed)).unwrap();
    let revoked = records.decode(&key, revoked.successor()).unwrap();
    assert!(records.delivery(&revoked, live.version().epoch).is_err());
    let reconnected = records.install(&key, Some(&revoked), b"new-login").unwrap();
    let reconnected = records.decode(&key, reconnected.successor()).unwrap();
    assert!(reconnected.version().epoch > revoked.version().epoch);
    assert!(records
        .delivery(&reconnected, live.version().epoch)
        .is_err());
    assert!(records
        .delivery(&reconnected, reconnected.version().epoch)
        .is_ok());
}

#[test]
fn absent_revoke_creates_barrier_for_delayed_initial_login() {
    let records = records();
    let key = key();
    let delayed = records.install(&key, None, b"late-login").unwrap();
    let revoke = records.revoke(&key, None).unwrap();
    assert!(delayed.previous().is_none());
    let tombstone = records.decode(&key, revoke.successor()).unwrap();
    assert_eq!(tombstone.version().state, GrantState::Revoked);
    let fresh = records
        .install(&key, Some(&tombstone), b"new-login")
        .unwrap();
    assert!(fresh.previous().is_some());
    assert!(fresh.after().epoch > tombstone.version().epoch);
}

#[test]
fn grant_ciphertext_relocation_and_metadata_tampering_are_refused() {
    let records = records();
    let key = key();
    let install = records.install(&key, None, b"SECRET").unwrap();
    let other = GrantKey::new("other", "instance", "subject", "upstream").unwrap();
    assert!(records.decode(&other, install.successor()).is_err());
    let mut changed = install.successor().expose(&crate::seal::lend()).clone();
    changed[8] ^= 1;
    assert!(records
        .decode(&key, &busbar_contract::Secret::new(changed))
        .is_err());
}

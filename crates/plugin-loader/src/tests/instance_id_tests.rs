// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! INSTANCE NUMBERING NEVER MINTS `0`. `InstanceId(0)` is the composition root's own identity on
//! the one connector (the authorization server's needs, `root::connector::ROOT_OWNER`); a plugin
//! instance minted `0` would open and close connections on that table as the root.

use std::sync::atomic::{AtomicU64, Ordering};

use busbar_contract::conn::InstanceId;

use super::{mint_instance, NEXT_INSTANCE};

#[test]
fn the_process_counter_never_mints_zero() {
    for _ in 0..1000 {
        assert_ne!(mint_instance(&NEXT_INSTANCE), InstanceId(0));
    }
    assert_ne!(
        NEXT_INSTANCE.load(Ordering::Relaxed),
        0,
        "the counter starts past 0"
    );
}

#[test]
fn a_counter_from_its_start_mints_one_first() {
    let next = AtomicU64::new(1);
    assert_eq!(mint_instance(&next), InstanceId(1));
    assert_eq!(mint_instance(&next), InstanceId(2));
}

#[test]
fn a_wrapping_counter_skips_zero() {
    let next = AtomicU64::new(u64::MAX);
    assert_eq!(mint_instance(&next), InstanceId(u64::MAX));
    assert_eq!(
        mint_instance(&next),
        InstanceId(1),
        "past u64::MAX the counter wraps to 0, which is the root's and is skipped"
    );
}

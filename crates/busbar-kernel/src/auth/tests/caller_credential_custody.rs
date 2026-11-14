// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-AU6: the caller secret lives in one zeroising buffer that every holder shares;
//! it is wiped when its last holder drops, never before and never left behind in a copy.

use super::*;

fn wiped_on_drop<T: zeroize::ZeroizeOnDrop + ?Sized>(_: &T) {}

#[test]
fn the_caller_secret_is_wiped_when_its_last_holder_drops() {
    let held = CallerCredential::verified("sk-wipe-sentinel");
    wiped_on_drop(&*held.0);
    let buffer = std::sync::Arc::downgrade(&held.0);
    let shared = held.clone();
    drop(held);

    let alive = buffer
        .upgrade()
        .expect("a holder remains, so the one buffer is still held");
    assert_eq!(
        alive.as_slice(),
        b"sk-wipe-sentinel",
        "the sentinel stays readable while any holder lives"
    );
    drop(alive);

    drop(shared);
    assert!(
        buffer.upgrade().is_none(),
        "the last holder's drop released the one buffer, and its Zeroizing wrapper wiped it"
    );
}

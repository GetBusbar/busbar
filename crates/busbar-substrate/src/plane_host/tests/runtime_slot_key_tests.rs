// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Direct unit tests for [`super::runtime_slot_key`].
//!
//! Every real caller (the plane crates, and busbar-core's `appbuild`/`state`/`test_support`) uses
//! the returned `&'static str` as a `HashMap`/`BTreeMap` KEY into `App::plane_slots`, so its whole
//! contract rests on three properties none of those call sites individually proves in THIS crate:
//! the composed string is the documented `"<key>:runtime"` shape, repeated calls for the SAME plane
//! key return the identical interned string (not a fresh allocation each time — a caller comparing by
//! value would not notice a broken intern, only a caller comparing by pointer, or one that leaked
//! memory on every call, would), and distinct plane keys never collide onto the same slot.

use crate::plane_host::runtime_slot_key;

#[test]
fn composes_the_documented_key_colon_runtime_shape() {
    assert_eq!(runtime_slot_key("alpha"), "alpha:runtime");
    assert_eq!(runtime_slot_key("beta"), "beta:runtime");
}

#[test]
fn the_same_plane_key_interns_to_the_identical_static_str_every_call() {
    let first = runtime_slot_key("a-runtime-key-test-plane");
    let second = runtime_slot_key("a-runtime-key-test-plane");
    // Same VALUE (the weaker property another caller's `==` would already catch)...
    assert_eq!(first, second);
    // ...and the same underlying allocation: a re-leak on every call would still pass the `==`
    // check above but would grow the interned map's backing allocation forever and would let a
    // pointer-identity-sensitive caller (there is none today, but the doc comment promises this) see
    // two different addresses for what is supposed to be one process-lifetime string.
    assert_eq!(
        first.as_ptr(),
        second.as_ptr(),
        "the same plane key must intern to the SAME allocation, not a fresh leak per call"
    );
}

#[test]
fn distinct_plane_keys_never_collide_onto_the_same_slot() {
    let a = runtime_slot_key("runtime-key-test-plane-a");
    let b = runtime_slot_key("runtime-key-test-plane-b");
    assert_ne!(a, b, "distinct plane keys must resolve to distinct slots");
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NULL-EMPTY (ABI-MIN3-INTERFACE §14 round 17): `{ptr, 0}` is the empty value whatever `ptr` is. The safe
//! arm, every empty view a Rust producer can build, is W1-A1's (merged). A raw `{NULL, 0}` or `{misaligned, 0}`
//! has no safe producer (UNSAFE-MIN): the C fixture's arm (a) is W1-A13's, and the host-to-shim arm (b), with
//! (c)'s raw values under Miri and its `from_raw_parts` negative control, is the shim boundary's.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::types::{Bytes, Slice, Str};

#[test]
fn every_empty_view_reads_empty() {
    let tail = [1u8, 2, 3];
    assert!(Bytes::EMPTY.get().is_empty());
    assert!(Bytes::new(&[]).get().is_empty());
    assert!(Bytes::new(&tail[3..]).get().is_empty());
    assert_eq!(Str::EMPTY.get(), "");
    assert_eq!(Str::new("").get(), "");
    assert!(Slice::<'static, Bytes<'static>>::EMPTY.get().is_empty());
    let views = [Bytes::EMPTY];
    assert!(Slice::new(&views[1..]).get().is_empty());
}

#[test]
#[ignore = "owner: W1-A13"]
fn a_c_fixture_sends_null_zero_in_every_crypto_req_field() {
    todo!("owner: W1-A13 (C-NULL-EMPTY)")
}

#[test]
#[ignore = "owner: W1-A4"]
fn raw_null_zero_results_and_config_reach_a_rust_shim_as_empty() {
    todo!("owner: W1-A4 (C-NULL-EMPTY)")
}

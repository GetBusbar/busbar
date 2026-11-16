// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NO-LICENCE (ABI-MIN3-INTERFACE §14 round 28; AGREED 118). (b) and (c) are W1-T1's: the retired flag bits are
//! unknown flags, and the Rust stamp is 272 bytes with `_reserved` at 256 (the C header's `bb_stamp` asserts are
//! C-HEADER's). The scan refusal of (b) (`StampMalformed`) is the loader's `scan::stamp` (W1-L1); (a) is W1-X1's
//! source check.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use core::mem::{align_of, offset_of, size_of};

use busbar_plugin_abi::stamp::{Stamp, STAMP_FLAGS_KNOWN, STAMP_LOCAL_BUILD, STAMP_OUT_OF_PROCESS};

#[test]
fn the_retired_flag_bits_are_unknown_flags() {
    assert_eq!(STAMP_FLAGS_KNOWN, STAMP_LOCAL_BUILD | STAMP_OUT_OF_PROCESS);
    for retired in [2u32, 4] {
        assert_eq!(STAMP_FLAGS_KNOWN & retired, 0, "flag {retired}");
    }
}

#[test]
fn the_stamp_is_272_bytes_with_reserved_at_256() {
    assert_eq!(size_of::<Stamp>(), 272);
    assert_eq!(align_of::<Stamp>(), 8);
    assert_eq!(offset_of!(Stamp, crypto), 248);
    assert_eq!(offset_of!(Stamp, _reserved), 256);
}

#[test]
#[ignore = "owner: W1-L1"]
fn a_stamp_with_flag_2_or_4_format_1_or_size_320_is_stamp_malformed() {
    todo!("owner: W1-L1 (C-NO-LICENCE)")
}

#[test]
#[ignore = "owner: W1-X1"]
fn no_licence_word_in_the_abi_loader_header_or_ci_sources() {
    todo!("owner: W1-X1 (C-NO-LICENCE)")
}

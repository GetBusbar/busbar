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

/// W1-L1: the loader's scan refuses each retired shape at the byte it sits in, as StampMalformed.
#[test]
fn a_stamp_with_flag_2_or_4_format_1_or_size_320_is_stamp_malformed() {
    use busbar_plugin_abi::stamp::{emit, Spec};
    use busbar_plugin_abi::types::KindCode;
    use busbar_plugin_loader::refusal::RefusalCode;
    use busbar_plugin_loader::scan::{self, StampScanErr};

    let good = emit(&Spec {
        kind: KindCode::Secret,
        kind_abi: 2,
        layout: busbar_plugin_abi::secret::FP,
        out_of_process: false,
        engine_min: None,
        engine_max: None,
        name: "busbar-no-licence",
        version: "1.6.0",
        build_id: None,
        crypto: "host",
    })
    .0;
    let image = |stamp: &[u8]| {
        let mut image = vec![0u8; 40];
        image.extend_from_slice(stamp);
        image
    };
    assert!(
        scan::stamp(&image(&good)).is_ok(),
        "the format-2 stamp scans"
    );
    for (at, value) in [(36usize, 1u32 | 2), (36, 1 | 4), (16, 1), (20, 320)] {
        let mut stamp = good;
        stamp[at..at + 4].copy_from_slice(&value.to_le_bytes());
        match scan::stamp(&image(&stamp)) {
            Err(e @ StampScanErr::Malformed { byte, .. }) => {
                assert_eq!(byte as usize, at, "field at {at} = {value}");
                assert!(matches!(e.code(), RefusalCode::StampMalformed { .. }));
            }
            Err(other) => panic!("field at {at} = {value}: {other:?}"),
            Ok(_) => panic!("field at {at} = {value} scanned"),
        }
    }
}

#[test]
#[ignore = "blocked: arm (a) is X1's CI source-scan job (doc/identifier/literal lexer over abi, loader, header, CI sources); no scanner exists on dev and cannot be validated without a build; owner W1-X1"]
fn no_licence_word_in_the_abi_loader_header_or_ci_sources() {
    todo!("owner: W1-X1 (C-NO-LICENCE)")
}

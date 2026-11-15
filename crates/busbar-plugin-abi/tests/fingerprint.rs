// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fingerprint and versions (ABI-MIN3-INTERFACE §7.3, §7.5): `fp` is FNV-1a 64 over the non-whitespace
//! bytes, `fp_parts` folds parts with a 0xFF separator, and `CORE_FP` (the `mechanism!` blocks) is the value
//! `ci/abi.pin` pins on its `mechanism` line, so any token or doc change inside a block fails here until the pin
//! is moved in the same MR.

use busbar_plugin_abi as abi;

use abi::fp::{CORE_FP, fp, fp_parts};
use abi::versions::{ENGINE, MECHANISM};

#[test]
fn fp_is_fnv1a_64_over_the_non_whitespace_bytes() {
    assert_eq!(fp(b""), 0xcbf2_9ce4_8422_2325);
    // The published FNV-1a 64 vectors.
    assert_eq!(fp(b"a"), 0xaf63_dc4c_8601_ec8c);
    assert_eq!(fp(b"foobar"), 0x8594_4171_f739_67e8);
    // ASCII whitespace is skipped (r10 layout::ident), so formatting never moves a fingerprint.
    assert_eq!(fp(b" f o\to\nb\ra\x0Cr "), fp(b"foobar"));
}

#[test]
fn fp_parts_separates_its_parts() {
    assert_eq!(fp_parts(&[]), fp(b""));
    assert_eq!(fp_parts(&[b"foobar"]), fp(b"foobar"));
    assert_ne!(fp_parts(&[b"foo", b"bar"]), fp(b"foobar"));
    assert_ne!(fp_parts(&[b"foo", b"bar"]), fp_parts(&[b"fo", b"obar"]));
    assert_eq!(fp_parts(&[b"foo", b"bar"]), fp(b"foo\xFFbar"));
}

/// The FP pin test (W1-A1): `ci/abi.pin`'s `mechanism` line is `mechanism <MECHANISM> 0x<CORE_FP>`, and
/// CORE_FP is computed from the blocks, never the wave-0 stub value 0.
#[test]
fn the_core_fingerprint_is_pinned_in_ci_abi_pin() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ci/abi.pin");
    let pin = std::fs::read_to_string(path).expect("ci/abi.pin is readable");
    let line = pin
        .lines()
        .find(|line| line.starts_with("mechanism "))
        .expect("ci/abi.pin has a mechanism line");
    let want = format!("mechanism {MECHANISM} 0x{CORE_FP:016x}");
    assert_eq!(
        line, want,
        "ci/abi.pin must pin CORE_FP; move the pin with the block"
    );
    assert_ne!(
        CORE_FP, 0,
        "CORE_FP is the fingerprint of the mechanism! blocks"
    );
}

#[test]
fn the_engine_version_is_this_crate_version() {
    let version = format!("{}.{}.{}", ENGINE.major, ENGINE.minor, ENGINE.patch);
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
    assert_eq!(ENGINE._reserved, 0);
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-kind FP pin tests (IF §17 round 35, R1): `kind!` computes `<kind>::FP` from the block's header, docs,
//! four sections and method signatures, and `ci/abi.pin` pins it on the kind's line (`<kind> <ABI> 0x<FP>`), so a
//! token or doc change in a kind block fails here until the pin moves with it. A13 fills `BB_SECRET_FP` from the
//! secret line.

use busbar_plugin_abi::{auth, export, hook, plane, secret, store, transport};

fn pinned(word: &str, abi: u32, fp: u64) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ci/abi.pin");
    let pin = std::fs::read_to_string(path).expect("ci/abi.pin is readable");
    let line = pin
        .lines()
        .find(|line| line.split(' ').next() == Some(word))
        .unwrap_or_else(|| panic!("ci/abi.pin has a {word} line"));
    assert_ne!(fp, 0, "{word}::FP is computed by kind!, never the stub 0");
    assert_eq!(
        line,
        format!("{word} {abi} 0x{fp:016x}"),
        "ci/abi.pin must pin {word}::FP; set the line to the right-hand side above"
    );
}

#[test]
fn the_store_fp_is_pinned() {
    pinned("store", store::ABI, store::FP);
}
#[test]
fn the_secret_fp_is_pinned() {
    pinned("secret", secret::ABI, secret::FP);
}
#[test]
fn the_auth_fp_is_pinned() {
    pinned("auth", auth::ABI, auth::FP);
}
#[test]
fn the_hook_fp_is_pinned() {
    pinned("hook", hook::ABI, hook::FP);
}
#[test]
fn the_export_fp_is_pinned() {
    pinned("export", export::ABI, export::FP);
}
#[test]
fn the_plane_fp_is_pinned() {
    pinned("plane", plane::ABI, plane::FP);
}
#[test]
fn the_transport_fp_is_pinned() {
    pinned("transport", transport::ABI, transport::FP);
}

#[test]
fn no_two_kinds_share_a_fingerprint() {
    let mut all = [
        store::FP,
        secret::FP,
        auth::FP,
        hook::FP,
        export::FP,
        plane::FP,
        transport::FP,
    ];
    all.sort();
    assert!(all.windows(2).all(|w| w[0] != w[1]));
}

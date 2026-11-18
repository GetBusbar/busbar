// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stamp scan (r10 §2.3.1 step 3, round 28 format 2) and the error-code identity grammar (round 34).

use super::*;
use busbar_plugin_abi::stamp::{emit, Spec};
use busbar_plugin_abi::types::KindCode;

/// A stamp `plugin!` would write for a secret image.
fn good() -> [u8; STAMP_SIZE] {
    emit(&Spec {
        kind: KindCode::Secret,
        kind_abi: 2,
        layout: busbar_plugin_abi::secret::FP,
        out_of_process: false,
        engine_min: None,
        engine_max: None,
        name: "busbar-secret-scan",
        version: "1.6.0-rc.1+abc",
        build_id: None,
        crypto: "host",
    })
    .0
}

/// `stamp` bytes inside an image, with other bytes around it.
fn image(stamp: &[u8]) -> Vec<u8> {
    let mut image = vec![0x7fu8, b'E', b'L', b'F'];
    image.extend_from_slice(&[0xAB; 61]);
    image.extend_from_slice(stamp);
    image.extend_from_slice(b"BUSBAR but not the magic");
    image
}

fn put_u32(stamp: &mut [u8; STAMP_SIZE], at: usize, v: u32) {
    stamp[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn malformed_at(stamp: &[u8; STAMP_SIZE]) -> u32 {
    match super::stamp(&image(stamp)) {
        Err(StampScanErr::Malformed { byte, .. }) => byte,
        Err(other) => panic!("not malformed: {other:?}"),
        Ok(_) => panic!("a malformed stamp passed the scan"),
    }
}

#[test]
fn exactly_one_stamp_is_found_and_every_field_is_checked() {
    let stamp = super::stamp(&image(&good())).expect("the one good stamp");
    assert_eq!(stamp.kind, KindCode::Secret as u32);
    assert_eq!(text(&stamp.name), "busbar-secret-scan");
    assert_eq!(text(&stamp.version), "1.6.0-rc.1+abc");
    assert_eq!(text(&stamp.crypto), "host");
    assert_eq!(stamp.format, STAMP_FORMAT);
    assert_eq!(stamp.size as usize, STAMP_SIZE);
    // The typed view reads every offset the builder wrote.
    assert_eq!(
        check(&good()).map(|s| s.layout),
        Ok(busbar_plugin_abi::secret::FP)
    );
}

#[test]
fn no_stamp_is_missing_and_two_are_ambiguous() {
    assert_eq!(
        super::stamp(b"\x7fELF a 1.5.x library").err(),
        Some(StampScanErr::Missing)
    );
    let mut two = image(&good());
    two.extend_from_slice(&good());
    assert_eq!(
        super::stamp(&two).err(),
        Some(StampScanErr::Ambiguous { count: 2 })
    );
    let refusal = StampScanErr::Ambiguous { count: 2 }.refusal();
    assert_eq!(refusal.code, crate::refusal::RefusalCode::StampAmbiguous);
    assert_eq!(refusal.have, "2");
}

#[test]
fn a_stamp_cut_short_by_the_end_of_the_image_is_malformed() {
    let mut cut = vec![0u8; 8];
    cut.extend_from_slice(&good()[..100]);
    assert!(matches!(
        super::stamp(&cut),
        Err(StampScanErr::Malformed { byte: 20, .. })
    ));
}

/// Round 28: the retired flag bits 2 and 4, format 1 and size 320 are StampMalformed.
#[test]
fn retired_flags_format_1_and_size_320_are_malformed() {
    for retired in [2u32, 4] {
        let mut s = good();
        put_u32(&mut s, 36, 1 | retired);
        assert_eq!(malformed_at(&s), 36, "flag {retired}");
    }
    let mut s = good();
    put_u32(&mut s, 16, 1);
    assert_eq!(malformed_at(&s), 16);
    let mut s = good();
    put_u32(&mut s, 20, 320);
    assert_eq!(malformed_at(&s), 20);
}

/// One field rule's breach of a good stamp, and the byte the refusal must name.
type FieldCase = (fn(&mut [u8; STAMP_SIZE]), u32);

#[test]
fn each_field_rule_names_its_byte_and_never_echoes_the_bytes() {
    let cases: [FieldCase; 10] = [
        (|s| s[78] = 1, 78),                                     // engine_min._reserved
        (|s| s[86] = 1, 86),                                     // engine_max._reserved
        (|s| s[88] = b'_', 88),                                  // name charset
        (|s| s[88..152].fill(0), 88),                            // empty name
        (|s| s[88 + 40] = b'x', 128),                            // a byte after the name's NUL
        (|s| s[152] = b'\n', 152),                               // version charset
        (|s| s[184] = b'A', 184),                                // target charset
        (|s| s[216] = 1, 216),                                   // LOCAL_BUILD with a build id
        (|s| s[248..256].copy_from_slice(b"HOST\0\0\0\0"), 248), // crypto charset
        (|s| s[260] = 1, 260),                                   // reserved
    ];
    for (break_it, byte) in cases {
        let mut s = good();
        break_it(&mut s);
        assert_eq!(malformed_at(&s), byte);
        let refusal = super::stamp(&image(&s)).err().expect("malformed").refusal();
        assert_eq!(
            refusal.plugin, None,
            "a malformed stamp's name is never trusted"
        );
        assert!(!refusal.to_string().contains("busbar-secret-scan"));
    }
}

#[test]
fn the_identity_grammar_names_a_position_or_length_never_a_byte() {
    fn name(text: &[u8]) -> [u8; 64] {
        let mut n = [0u8; 64];
        n[..text.len()].copy_from_slice(text);
        n
    }
    assert_eq!(
        error_identity(&name(b"busbar-auth-oidc")),
        Ok("busbar-auth-oidc")
    );
    assert_eq!(error_identity(&name(b"a")), Ok("a"));
    assert_eq!(error_identity(&[b'a'; 64]).map(str::len), Ok(64));
    assert_eq!(error_identity(&name(b"")), Err(IdentityFault::Empty));
    assert_eq!(
        error_identity(&name(b"1password")),
        Err(IdentityFault::BadChar { byte: 0 })
    );
    assert_eq!(
        error_identity(&name(b"busbar_store")),
        Err(IdentityFault::BadChar { byte: 6 })
    );
    assert_eq!(
        error_identity(&name(b"busbar-")),
        Err(IdentityFault::TrailingDash)
    );
    assert_eq!(
        IdentityFault::BadChar { byte: 4 }.to_string(),
        "bad character at byte 4"
    );
    assert_eq!(
        IdentityFault::Length { len: 70 }.to_string(),
        "length 70 > 64"
    );
}

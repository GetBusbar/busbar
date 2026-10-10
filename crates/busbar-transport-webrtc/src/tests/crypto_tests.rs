// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SRTP IS AEAD-AES-GCM ONLY (THE DESIGN l.753): the provider's `AES_CM` cipher refuses every
//! packet, and the shim refuses keying material under any profile but the two GCM ones. The RED
//! arm beside each refusal is the same call under AEAD-AES-GCM, which goes through: the refusal is
//! the profile's, not a broken path.

use super::*;
use crate::framing::{PROFILE_AEAD_AES_128_GCM, PROFILE_AEAD_AES_256_GCM};
use crate::shim::Shim;

/// `SRTP_AES128_CM_HMAC_SHA1_80` (RFC 5764 §4.1.2).
const PROFILE_AES_CM_SHA1_80: u32 = 0x0001;
/// `SRTP_AES128_CM_HMAC_SHA1_32`.
const PROFILE_AES_CM_SHA1_32: u32 = 0x0002;

fn is_aes_cm_refusal(e: &CryptoError) -> bool {
    matches!(e, CryptoError::Other(why) if why == AES_CM_REFUSED)
}

#[test]
fn the_aes_cm_cipher_refuses_every_packet_both_ways() {
    for encrypt in [true, false] {
        let mut c = RING.aes_128_cm_sha1_80().create_cipher([9_u8; 16], encrypt);
        let mut out = [0_u8; 64];
        let sealed = c.encrypt(&[1_u8; 16], b"a protected payload", &mut out);
        assert!(sealed.as_ref().is_err_and(is_aes_cm_refusal), "{sealed:?}");
        assert_eq!(out, [0_u8; 64], "nothing was written");
        let opened = c.decrypt(&[1_u8; 16], b"a protected payload", &mut out);
        assert!(opened.as_ref().is_err_and(is_aes_cm_refusal), "{opened:?}");
    }
}

#[test]
fn red_arm_the_gcm_ciphers_of_the_same_provider_seal_and_open() {
    let (iv, aad, plain) = ([3_u8; 12], b"rtp header", b"an opus frame");
    let mut sealed = vec![0_u8; plain.len() + 16];
    let mut opened = vec![0_u8; plain.len()];
    let mut seal = RING.aead_aes_128_gcm().create_cipher([5_u8; 16], true);
    seal.encrypt(&iv, aad, plain, &mut sealed).expect("sealed");
    let mut open = RING.aead_aes_128_gcm().create_cipher([5_u8; 16], false);
    let n = open
        .decrypt(&iv, &[aad], &sealed, &mut opened)
        .expect("opened");
    assert_eq!(&opened[..n], plain);
    // A flipped tag bit fails authentication: the GCM path judges, it does not wave through.
    sealed[plain.len()] ^= 1;
    assert!(open.decrypt(&iv, &[aad], &sealed, &mut opened).is_err());

    let mut sealed = vec![0_u8; plain.len() + 16];
    let mut seal = RING.aead_aes_256_gcm().create_cipher([6_u8; 32], true);
    seal.encrypt(&iv, aad, plain, &mut sealed).expect("sealed");
    let mut open = RING.aead_aes_256_gcm().create_cipher([6_u8; 32], false);
    let n = open
        .decrypt(&iv, &[aad], &sealed, &mut opened)
        .expect("opened");
    assert_eq!(&opened[..n], plain);
}

#[test]
fn an_aes_cm_profile_is_refused_at_the_keying_material_and_nothing_is_held() {
    let material = [7_u8; 60];
    for profile in [
        PROFILE_AES_CM_SHA1_80,
        PROFILE_AES_CM_SHA1_32,
        0x0003,
        0xFFFF,
    ] {
        let shim = Shim::default();
        assert_eq!(shim.keyed(&material, profile), Err(AES_CM_REFUSED));
        assert!(!shim.holds_keying(), "profile {profile:#06x}: nothing held");
    }
    // RED arm: the two AEAD-AES-GCM profiles are taken.
    for profile in [PROFILE_AEAD_AES_128_GCM, PROFILE_AEAD_AES_256_GCM] {
        let shim = Shim::default();
        assert_eq!(shim.keyed(&material, profile), Ok(()));
        assert!(shim.holds_keying(), "profile {profile:#06x}: held");
    }
}

#[test]
fn the_srtp_key_derivation_block_is_aes() {
    // FIPS-197 Appendix C.1: AES-128 of 00112233445566778899aabbccddeeff under 000102…0f.
    let key: Vec<u8> = (0..16).collect();
    let input: Vec<u8> = (0..16).map(|i| i * 0x11).collect();
    let mut out = [0_u8; 16];
    RING.srtp_aes_128_ecb_round(&key, &input, &mut out);
    assert_eq!(
        out,
        [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a
        ]
    );
    // A key of the wrong length derives nothing (a zeroed block), and nothing panics.
    RING.srtp_aes_128_ecb_round(&key[..15], &input, &mut out);
    assert_eq!(out, [0_u8; 16]);
}

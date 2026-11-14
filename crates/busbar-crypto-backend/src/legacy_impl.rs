// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Legacy algorithms for protocol use only, over AWS-LC: MD5 (Postgres md5 authentication), SHA-1
//! and HMAC-SHA1 (webhook signatures), RSA-OAEP with SHA-1 (MySQL RSA password exchange).

use aws_lc_rs::rsa::{OaepPublicEncryptingKey, PublicEncryptingKey, OAEP_SHA1_MGF1SHA1};
use aws_lc_rs::{digest, hmac};

use crate::Error;

/// MD5 (RFC 1321) of `data`. aws-lc-rs has no MD5, so this is AWS-LC's `EVP_Digest` with
/// `EVP_md5()` directly (the `universal` bindings have no `MD5` function).
#[allow(unsafe_code)]
pub fn md5(data: &[u8]) -> Result<[u8; 16], Error> {
    let mut out = [0_u8; 16];
    let mut written: core::ffi::c_uint = 0;
    aws_lc_sys::init();
    // SAFETY: `data` is a live slice of `data.len()` bytes; `out` has room for MD5's 16-byte
    // digest; `EVP_md5()` returns a static descriptor; a null ENGINE is the documented default.
    // EVP_Digest keeps no pointer past the call and cleanses its stack context.
    let ok = unsafe {
        aws_lc_sys::EVP_Digest(
            data.as_ptr().cast(),
            data.len(),
            out.as_mut_ptr(),
            &mut written,
            aws_lc_sys::EVP_md5(),
            core::ptr::null_mut(),
        )
    };
    if ok != 1 || written != 16 {
        return Err(Error::Invalid("MD5"));
    }
    Ok(out)
}

/// SHA-1 (FIPS 180-4) of `data`.
pub fn sha1(data: &[u8]) -> Result<[u8; 20], Error> {
    let mut out = [0_u8; 20];
    out.copy_from_slice(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref());
    Ok(out)
}

/// HMAC-SHA1 (RFC 2104) of `msg` under `key`.
pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> Result<[u8; 20], Error> {
    let k = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
    let mut out = [0_u8; 20];
    out.copy_from_slice(hmac::sign(&k, msg).as_ref());
    Ok(out)
}

/// The DER `SubjectPublicKeyInfo` for a PKCS#1 `RSAPublicKey`.
fn spki_from_pkcs1(pkcs1: &[u8]) -> Vec<u8> {
    fn len(out: &mut Vec<u8>, n: usize) {
        if n < 0x80 {
            out.push(n as u8);
        } else {
            let bytes = n.to_be_bytes();
            let skip = bytes.iter().take_while(|b| **b == 0).count();
            out.push(0x80 | (bytes.len() - skip) as u8);
            out.extend_from_slice(&bytes[skip..]);
        }
    }
    // AlgorithmIdentifier { rsaEncryption (1.2.840.113549.1.1.1), NULL }.
    const ALG: [u8; 15] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut bits = vec![0x03];
    len(&mut bits, pkcs1.len() + 1);
    bits.push(0);
    bits.extend_from_slice(pkcs1);
    let mut out = vec![0x30];
    len(&mut out, ALG.len() + bits.len());
    out.extend_from_slice(&ALG);
    out.extend_from_slice(&bits);
    out
}

/// `msg` encrypted with RSAES-OAEP (SHA-1, MGF1-SHA-1, empty label; RFC 8017 7.1) to the RSA
/// public key `public_key_der`, a DER `SubjectPublicKeyInfo` or PKCS#1 `RSAPublicKey`.
pub fn rsa_oaep_sha1_encrypt(public_key_der: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    let key = PublicEncryptingKey::from_der(public_key_der)
        .or_else(|_| PublicEncryptingKey::from_der(&spki_from_pkcs1(public_key_der)))
        .map_err(|_| Error::Invalid("RSA public key"))?;
    let bits = key.key_size_bits();
    if !(2048..=8192).contains(&bits) {
        return Err(Error::Invalid("RSA modulus outside 2048..=8192 bits"));
    }
    let key = OaepPublicEncryptingKey::new(key).map_err(|_| Error::Invalid("RSA public key"))?;
    let mut out = vec![0_u8; key.ciphertext_size()];
    let n = key
        .encrypt(&OAEP_SHA1_MGF1SHA1, msg, &mut out, None)
        .map_err(|_| Error::Invalid("message too long for the RSA key"))?
        .len();
    out.truncate(n);
    Ok(out)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::ptr::NonNull;

use aws_lc_sys as lc;
use zeroize::Zeroizing;

// Preserve ring's accepted private-key sizes and public exponent bounds. Balanced
// factors make 2047 the smallest modulus with a 1024-bit half, despite byte rounding.
const MIN_MODULUS_BITS: u32 = 2047;
const MAX_MODULUS_BITS: u32 = 4096;
const PRIME_BITS_GRANULARITY: u32 = 512;
const MIN_PUBLIC_EXPONENT: u64 = 65537;
const PUBLIC_EXPONENT_LIMIT: u64 = 1_u64 << 33;
// RFC 5208 PrivateKeyInfo version and RFC 3279 rsaEncryption with explicit NULL.
const PKCS8_V1: u64 = 0;
const RSA_ENCRYPTION_WITH_NULL: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

pub(super) struct Key(NonNull<lc::RSA>);

impl Key {
    pub(super) fn from_pkcs8(der: &[u8]) -> Result<Self, ()> {
        lc::init();
        let mut input = lc::CBS::default();
        let mut sequence = lc::CBS::default();
        let mut algorithm = lc::CBS::default();
        let mut private = lc::CBS::default();
        let mut attributes = lc::CBS::default();
        let mut version = 0;
        // SAFETY: CBS only borrows the live DER slice. Each output CBS is read only after
        // its parser succeeds. No borrowed pointer escapes this function. The provider's
        // whole-input RSA parser returns an owned key, immediately guarded by Key.
        unsafe {
            lc::CBS_init(&mut input, der.as_ptr(), der.len());
            if lc::CBS_get_asn1(&mut input, &mut sequence, lc::CBS_ASN1_SEQUENCE as u32) != 1
                || lc::CBS_len(&input) != 0
                || lc::CBS_get_asn1_uint64(&mut sequence, &mut version) != 1
                || version != PKCS8_V1
                || lc::CBS_get_asn1(&mut sequence, &mut algorithm, lc::CBS_ASN1_SEQUENCE as u32)
                    != 1
                || lc::CBS_mem_equal(
                    &algorithm,
                    RSA_ENCRYPTION_WITH_NULL.as_ptr(),
                    RSA_ENCRYPTION_WITH_NULL.len(),
                ) != 1
                || lc::CBS_get_asn1(&mut sequence, &mut private, lc::CBS_ASN1_OCTETSTRING as u32)
                    != 1
            {
                return Err(());
            }
            if lc::CBS_len(&sequence) != 0
                && lc::CBS_get_asn1(
                    &mut sequence,
                    &mut attributes,
                    lc::CBS_ASN1_CONTEXT_SPECIFIC as u32 | lc::CBS_ASN1_CONSTRUCTED as u32,
                ) != 1
            {
                return Err(());
            }
            if lc::CBS_len(&sequence) != 0 {
                return Err(());
            }
            // This parser checks d and CRT consistency, consumes the entire inner DER,
            // and frees partial keys on failure. Guard its sole owned result at once.
            let key = Self(
                NonNull::new(lc::RSA_private_key_from_bytes(
                    lc::CBS_data(&private),
                    lc::CBS_len(&private),
                ))
                .ok_or(())?,
            );
            key.check_components()?;
            Ok(key)
        }
    }

    fn check_components(&self) -> Result<(), ()> {
        // SAFETY: self owns a successfully parsed, live RSA. The get0 pointers borrow
        // that key, are null-checked before use, and never escape this function.
        unsafe {
            let rsa = self.0.as_ptr();
            let n = lc::RSA_get0_n(rsa);
            let e = lc::RSA_get0_e(rsa);
            let d = lc::RSA_get0_d(rsa);
            let p = lc::RSA_get0_p(rsa);
            let q = lc::RSA_get0_q(rsa);
            let dp = lc::RSA_get0_dmp1(rsa);
            let dq = lc::RSA_get0_dmq1(rsa);
            let qi = lc::RSA_get0_iqmp(rsa);
            if [n, e, d, p, q, dp, dq, qi]
                .into_iter()
                .any(|part| part.is_null() || lc::BN_is_zero(part) != 0)
            {
                return Err(());
            }
            let bits = lc::BN_num_bits(n);
            let half = bits.div_ceil(2);
            let mut exponent = 0;
            if !(MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits)
                || !half.is_multiple_of(PRIME_BITS_GRANULARITY)
                || lc::BN_num_bits(p) != half
                || lc::BN_num_bits(q) != half
                || lc::BN_num_bits(d) <= half
                || lc::BN_cmp(d, n) >= 0
                || lc::BN_get_u64(e, &mut exponent) != 1
                || !(MIN_PUBLIC_EXPONENT..PUBLIC_EXPONENT_LIMIT).contains(&exponent)
            {
                return Err(());
            }
            Ok(())
        }
    }

    pub(super) fn sign(&mut self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, ()> {
        let mut digest = Zeroizing::new([0_u8; lc::SHA256_DIGEST_LENGTH as usize]);
        // SAFETY: the key is live and exclusively borrowed; RSA_size is the exact
        // output capacity required by RSA_sign. SHA256 writes 32 bytes and cleanses
        // its own context. Both caller-owned outputs remain guarded on every return.
        unsafe {
            let mut signature = Zeroizing::new(vec![0; lc::RSA_size(self.0.as_ptr()) as usize]);
            let mut written = 0;
            if lc::SHA256(input.as_ptr(), input.len(), digest.as_mut_ptr()).is_null()
                || lc::RSA_sign(
                    lc::NID_sha256,
                    digest.as_ptr(),
                    digest.len(),
                    signature.as_mut_ptr(),
                    &mut written,
                    self.0.as_ptr(),
                ) != 1
                || written as usize != signature.len()
            {
                return Err(());
            }
            Ok(signature)
        }
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: Key exclusively owns this provider allocation; no raw pointer escapes.
        // RSA_free destroys private/CRT limbs, Montgomery caches and blindings. The
        // provider's default OPENSSL_free cleanses allocations before freeing them.
        unsafe { lc::RSA_free(self.0.as_ptr()) }
    }
}

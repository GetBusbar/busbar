// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AES-GCM (NIST SP 800-38D) and the single AES block (FIPS 197) over AWS-LC. AWS-LC owns and
//! cleanses the key schedules.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};
use aws_lc_rs::cipher::{EncryptingKey, UnboundCipherKey, AES_128};
use zeroize::Zeroize as _;

use crate::Error;

/// GCM's longest message under one nonce, in bytes (2^39 - 256 bits).
const GCM_MAX: u64 = (1 << 36) - 32;

fn seal(
    key: &LessSafeKey,
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; 16], Error> {
    if buf.len() as u64 > GCM_MAX {
        return Err(Error::Invalid("AES-GCM message too long"));
    }
    let tag = key
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), buf)
        .map_err(|_| Error::Invalid("AES-GCM seal"))?;
    let mut out = [0_u8; 16];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

fn open(
    key: &LessSafeKey,
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), Error> {
    let r = key.open_in_place_separate_tag(
        Nonce::assume_unique_for_key(*nonce),
        Aad::from(aad),
        tag,
        buf,
    );
    if r.is_err() {
        // No unauthenticated plaintext survives a failed open.
        buf.zeroize();
        return Err(Error::Mismatch);
    }
    Ok(())
}

macro_rules! gcm {
    ($name:ident, $alg:expr, $n:literal, $label:literal) => {
        #[doc = concat!($label, " under one key.")]
        pub struct $name(LessSafeKey);

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl $name {
            /// A key from `key`'s bytes.
            pub fn new(key: &[u8; $n]) -> Result<Self, Error> {
                UnboundKey::new($alg, key)
                    .map(|k| Self(LessSafeKey::new(k)))
                    .map_err(|_| Error::Invalid(concat!($label, " key")))
            }

            /// Encrypt `buf` in place under the caller's `nonce`; return the tag. On `Err` the
            /// buffer is untouched.
            pub fn seal_in_place(
                &self,
                nonce: &[u8; 12],
                aad: &[u8],
                buf: &mut [u8],
            ) -> Result<[u8; 16], Error> {
                seal(&self.0, nonce, aad, buf)
            }

            /// Decrypt `buf` in place after checking `tag`. On `Err` the buffer is zeroed.
            pub fn open_in_place(
                &self,
                nonce: &[u8; 12],
                aad: &[u8],
                buf: &mut [u8],
                tag: &[u8; 16],
            ) -> Result<(), Error> {
                open(&self.0, nonce, aad, buf, tag)
            }

            /// Encrypt `buf` in place under a fresh random nonce; return the nonce and the tag.
            pub fn seal_random_nonce(
                &self,
                aad: &[u8],
                buf: &mut [u8],
            ) -> Result<([u8; 12], [u8; 16]), Error> {
                let mut nonce = [0_u8; 12];
                crate::rand::fill(&mut nonce)?;
                let tag = seal(&self.0, &nonce, aad, buf)?;
                Ok((nonce, tag))
            }
        }
    };
}

gcm!(Aes256Gcm, &AES_256_GCM, 32, "AES-256-GCM");
gcm!(Aes128Gcm, &AES_128_GCM, 16, "AES-128-GCM");

/// One AES-128 block encryption (SRTP's AES-CM keystream and header protection only).
pub fn aes_block_encrypt(key: &[u8; 16], block: &[u8; 16]) -> Result<[u8; 16], Error> {
    let k = UnboundCipherKey::new(&AES_128, key)
        .and_then(EncryptingKey::ecb)
        .map_err(|_| Error::Invalid("AES-128 key"))?;
    let mut out = *block;
    k.encrypt(&mut out)
        .map_err(|_| Error::Invalid("AES-128 block"))?;
    Ok(out)
}

/// AES-CTR (NIST SP 800-38A §6.5) under a 16- or 32-byte key, with a 128-bit big-endian counter
/// block: SRTP's AES-CM, and (one block of zeros under counter `x`) the single AES block `E_k(x)`.
pub mod aes_ctr {
    use crate::Error;

    /// `input` encrypted (or decrypted: CTR is its own inverse) under `key` from the counter block
    /// `iv`, into `out`, which must be exactly as long as `input`.
    pub fn apply(key: &[u8], iv: &[u8; 16], input: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let _ = (key, iv, input, out);
        Err(Error::Refused {
            alg: "AES-CTR",
            reason: "not provided yet",
        })
    }
}

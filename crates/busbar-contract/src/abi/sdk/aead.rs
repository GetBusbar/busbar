// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AES-128/256-GCM with provider-owned key state destroyed on drop.

use std::{fmt, ptr::NonNull};

use aws_lc_sys as lc;
use zeroize::{Zeroize as _, Zeroizing};

/// AES-128 key size in bytes (FIPS 197).
pub const AES_128_KEY_LEN: usize = 16;
/// AES-256 key size in bytes (FIPS 197).
pub const AES_256_KEY_LEN: usize = 32;
/// The 96-bit GCM nonce used by this provider (RFC 5116 §5.1).
pub const GCM_NONCE_LEN: usize = 12;
/// The 128-bit authentication tag used by this provider (RFC 5116 §5.1).
pub const GCM_TAG_LEN: usize = 16;

const AES_BLOCK_LEN: usize = 16;
const EVP_SUCCESS: i32 = 1;
const EVP_ENCRYPT: i32 = 1;
const EVP_GCM_TAG_LEN: i32 = GCM_TAG_LEN as i32;

/// An invalid key, buffer length, or authentication result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Refused;

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AES-GCM operation refused")
    }
}

impl std::error::Error for Refused {}

/// An opaque AES-GCM key and its provider-owned AES/GHASH state.

pub struct AesGcm(NonNull<lc::EVP_CIPHER_CTX>);

// SAFETY: the context owns its allocations, has no thread affinity, and no pointer escapes.
// Every operation that reads or mutates provider state requires an exclusive Rust borrow.
unsafe impl Send for AesGcm {}
// SAFETY: shared references expose only redacted Debug; provider operations require &mut self.
unsafe impl Sync for AesGcm {}

impl fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesGcm").finish_non_exhaustive()
    }
}

impl AesGcm {
    /// Initialize AES-128-GCM or AES-256-GCM from a borrowed key.

    pub fn new(key: &[u8]) -> Result<Self, Refused> {
        lc::init();
        // SAFETY: these descriptors have static lifetime. The key slice lives through
        // initialization, which copies its schedule into provider-owned cipher_data.
        // The allocated context is guarded before initialization can fail.
        unsafe {
            let cipher = match key.len() {
                AES_128_KEY_LEN => lc::EVP_aes_128_gcm(),
                AES_256_KEY_LEN => lc::EVP_aes_256_gcm(),
                _ => return Err(Refused),
            };
            let context = Self(NonNull::new(lc::EVP_CIPHER_CTX_new()).ok_or(Refused)?);
            if lc::EVP_CipherInit_ex(
                context.0.as_ptr(),
                cipher,
                std::ptr::null_mut(),
                key.as_ptr(),
                std::ptr::null(),
                EVP_ENCRYPT,
            ) != EVP_SUCCESS
            {
                return Err(Refused);
            }
            #[cfg(feature = "test-support")]
            test_support::created(&context);
            Ok(context)
        }
    }

    /// Write ciphertext followed by its 16-byte tag; return the bytes written.

    pub fn seal(
        &mut self,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Refused> {
        let result = (|| {
            let needed = input.len().checked_add(GCM_TAG_LEN).ok_or(Refused)?;
            let target = output.get_mut(..needed).ok_or(Refused)?;
            let (body, trailer) = target.split_at_mut(input.len());
            let mut tag = Zeroizing::new([0; GCM_TAG_LEN]);
            self.operate(true, nonce, aad, input, body, &mut tag)?;
            trailer.copy_from_slice(&*tag);
            Ok(needed)
        })();
        if result.is_err() {
            output.zeroize();
        }
        result
    }

    /// Authenticate ciphertext and its trailing 16-byte tag, then return plaintext length.

    pub fn open(
        &mut self,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, Refused> {
        let result = (|| {
            let len = input.len().checked_sub(GCM_TAG_LEN).ok_or(Refused)?;
            let target = output.get_mut(..len).ok_or(Refused)?;
            let (body, trailer) = input.split_at(len);
            let mut tag = Zeroizing::new([0; GCM_TAG_LEN]);
            tag.copy_from_slice(trailer);
            self.operate(false, nonce, aad, body, target, &mut tag)?;
            Ok(len)
        })();
        if result.is_err() {
            output.zeroize();
        }
        result
    }

    fn operate(
        &mut self,
        encrypt: bool,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: &mut [u8; GCM_TAG_LEN],
    ) -> Result<(), Refused> {
        let input_len = i32::try_from(input.len()).map_err(|_| Refused)?;
        let aad_len = i32::try_from(aad.len()).map_err(|_| Refused)?;
        let mut written = 0;
        let mut final_block = Zeroizing::new([0_u8; AES_BLOCK_LEN]);
        // SAFETY: this exclusively borrowed context is permanently AES-GCM, whose
        // update writes exactly input.len() bytes and final writes no payload. The
        // private callers supply equally sized input/output and a 16-byte tag.
        // Rust borrows ensure disjoint inputs/outputs. Reinitializing with null cipher
        // and key preserves the schedule while resetting the IV, direction and poison
        // flag after any previous authentication failure. Every pointer is call-local.
        unsafe {
            let ctx = self.0.as_ptr();
            if lc::EVP_CipherInit_ex(
                ctx,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                nonce.as_ptr(),
                i32::from(encrypt),
            ) != EVP_SUCCESS
                || (!encrypt
                    && lc::EVP_CIPHER_CTX_ctrl(
                        ctx,
                        lc::EVP_CTRL_AEAD_SET_TAG,
                        EVP_GCM_TAG_LEN,
                        tag.as_mut_ptr().cast(),
                    ) != EVP_SUCCESS)
                || lc::EVP_CipherUpdate(
                    ctx,
                    std::ptr::null_mut(),
                    &mut written,
                    aad.as_ptr(),
                    aad_len,
                ) != EVP_SUCCESS
                || lc::EVP_CipherUpdate(
                    ctx,
                    output.as_mut_ptr(),
                    &mut written,
                    input.as_ptr(),
                    input_len,
                ) != EVP_SUCCESS
                || written != input_len
                || lc::EVP_CipherFinal_ex(ctx, final_block.as_mut_ptr(), &mut written)
                    != EVP_SUCCESS
                || written != 0
                || (encrypt
                    && lc::EVP_CIPHER_CTX_ctrl(
                        ctx,
                        lc::EVP_CTRL_AEAD_GET_TAG,
                        EVP_GCM_TAG_LEN,
                        tag.as_mut_ptr().cast(),
                    ) != EVP_SUCCESS)
            {
                return Err(Refused);
            }
        }
        Ok(())
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        // SAFETY: this context is uniquely owned and no pointer escapes. Its AES-GCM
        // cleanup cleanses GCM state; the provider's default OPENSSL_free cleanses
        // cipher_data (including the AES schedule) and the context before deallocation.
        unsafe { lc::EVP_CIPHER_CTX_free(self.0.as_ptr()) }
    }
}

/// Test-only ownership metadata for observing the provider's real allocations.
#[cfg(feature = "test-support")]
pub mod test_support {
    use std::cell::Cell;

    type Observer = fn(usize, usize);

    thread_local! {
        static OBSERVER: Cell<Option<Observer>> = const { Cell::new(None) };
    }

    /// Observe newly initialized keys on this thread while `action` runs.

    pub fn with_owned_state_observer<T>(observer: Observer, action: impl FnOnce() -> T) -> T {
        struct Restore(Option<Observer>);
        impl Drop for Restore {
            fn drop(&mut self) {
                OBSERVER.with(|slot| slot.set(self.0));
            }
        }
        let _restore = Restore(OBSERVER.with(|slot| slot.replace(Some(observer))));
        action()
    }

    pub(super) fn created(key: &super::AesGcm) {
        OBSERVER.with(|slot| {
            if let Some(observer) = slot.get() {
                // SAFETY: initialization succeeded and key owns this live context.
                // cipher_data is a documented public EVP_CIPHER_CTX field. Only numeric
                // address metadata reaches the test; no opaque bytes are dereferenced.
                let data = unsafe { key.0.as_ref().cipher_data };
                observer(key.0.as_ptr().addr(), data.addr());
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_matches_ring_and_reuses_state_after_authentication_failure() {
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};
        for algorithm in [&AES_128_GCM, &AES_256_GCM] {
            let key = vec![0x53; algorithm.key_len()];
            let reference = LessSafeKey::new(UnboundKey::new(algorithm, &key).unwrap());
            let mut cipher = AesGcm::new(&key).unwrap();
            for (index, len) in [0, 1, 15, 16, 17, 64, 1031].into_iter().enumerate() {
                let nonce = [u8::try_from(index).unwrap(); 12];
                let plain = vec![0x62; len];
                let aad = vec![0x71; index * 263];
                let mut expected = plain.clone();
                reference
                    .seal_in_place_append_tag(
                        Nonce::assume_unique_for_key(nonce),
                        Aad::from(&aad),
                        &mut expected,
                    )
                    .unwrap();
                let mut sealed = vec![0; len + 16];
                assert_eq!(cipher.seal(&nonce, &aad, &plain, &mut sealed), Ok(len + 16));
                assert_eq!(sealed, expected);
                let mut opened = vec![0xa5; len + 7];
                let mut forged = sealed.clone();
                *forged.last_mut().unwrap() ^= 1;
                assert_eq!(
                    cipher.open(&nonce, &aad, &forged, &mut opened),
                    Err(Refused)
                );
                assert!(opened.iter().all(|byte| *byte == 0));
                assert_eq!(cipher.open(&nonce, &aad, &sealed, &mut opened), Ok(len));
                assert_eq!(&opened[..len], plain);
                let mut wrong_nonce = nonce;
                wrong_nonce[11] ^= 1;
                assert_eq!(
                    cipher.open(&wrong_nonce, &aad, &sealed, &mut opened),
                    Err(Refused)
                );
                assert!(opened.iter().all(|byte| *byte == 0));
            }
        }
    }

    #[test]
    fn gcm_refuses_invalid_keys_lengths_and_aad_without_returning_plaintext() {
        for len in [0, 15, 17, 24, 31, 33] {
            assert!(AesGcm::new(&vec![0; len]).is_err());
        }
        let mut cipher = AesGcm::new(&[0; 16]).unwrap();
        let mut short = [0xa5; 15];
        assert_eq!(cipher.seal(&[0; 12], &[], &[], &mut short), Err(Refused));
        assert_eq!(short, [0; 15]);
        let mut sealed = [0; 17];
        cipher
            .seal(&[0; 12], b"header", &[42], &mut sealed)
            .unwrap();
        assert_eq!(
            cipher.open(&[0; 12], b"header", &sealed, &mut []),
            Err(Refused)
        );
        let mut opened = [0xa5; 1];
        assert_eq!(
            cipher.open(&[0; 12], b"wrong", &sealed, &mut opened),
            Err(Refused)
        );
        assert_eq!(opened, [0]);
        assert_eq!(
            cipher.open(&[0; 12], b"header", &sealed[..15], &mut opened),
            Err(Refused)
        );
        assert_eq!(opened, [0]);
        assert_eq!(
            cipher.open(&[0; 12], b"header", &sealed, &mut opened),
            Ok(1)
        );
        assert_eq!(opened, [42]);
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AES-128/256-GCM over the crypto facade, with the facade's wiped key state.

use std::fmt;

use zeroize::Zeroize as _;

use crate::crypto::{Aes128Gcm, Aes256Gcm};

/// AES-128 key size in bytes (FIPS 197).
pub const AES_128_KEY_LEN: usize = 16;
/// AES-256 key size in bytes (FIPS 197).
pub const AES_256_KEY_LEN: usize = 32;
/// The 96-bit GCM nonce used by this provider (RFC 5116 §5.1).
pub const GCM_NONCE_LEN: usize = 12;
/// The 128-bit authentication tag used by this provider (RFC 5116 §5.1).
pub const GCM_TAG_LEN: usize = 16;

/// An invalid key, buffer length, or authentication result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Refused;

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AES-GCM operation refused")
    }
}

impl std::error::Error for Refused {}

enum Key {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

/// An opaque AES-GCM key and its facade-owned state.
pub struct AesGcm(Key);

impl fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesGcm").finish_non_exhaustive()
    }
}

impl AesGcm {
    /// Initialize AES-128-GCM or AES-256-GCM from a borrowed key.
    pub fn new(key: &[u8]) -> Result<Self, Refused> {
        match key.len() {
            AES_128_KEY_LEN => {
                let key: &[u8; AES_128_KEY_LEN] = key.try_into().map_err(|_| Refused)?;
                Aes128Gcm::new(key)
                    .map(|k| Self(Key::Aes128(k)))
                    .map_err(|_| Refused)
            }
            AES_256_KEY_LEN => {
                let key: &[u8; AES_256_KEY_LEN] = key.try_into().map_err(|_| Refused)?;
                Aes256Gcm::new(key)
                    .map(|k| Self(Key::Aes256(k)))
                    .map_err(|_| Refused)
            }
            _ => Err(Refused),
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
            body.copy_from_slice(input);
            let tag = match &self.0 {
                Key::Aes128(k) => k.seal_in_place(nonce, aad, body),
                Key::Aes256(k) => k.seal_in_place(nonce, aad, body),
            }
            .map_err(|_| Refused)?;
            trailer.copy_from_slice(&tag);
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
            let tag: &[u8; GCM_TAG_LEN] = trailer.try_into().map_err(|_| Refused)?;
            target.copy_from_slice(body);
            match &self.0 {
                Key::Aes128(k) => k.open_in_place(nonce, aad, target, tag),
                Key::Aes256(k) => k.open_in_place(nonce, aad, target, tag),
            }
            .map_err(|_| Refused)?;
            Ok(len)
        })();
        if result.is_err() {
            output.zeroize();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST GCM test cases 2 and 14 (zero key, zero nonce, one zero block).
    #[test]
    fn gcm_matches_the_published_known_answers() {
        for (key_len, ciphertext, tag) in [
            (
                16,
                "0388dace60b6a392f328c2b971b2fe78",
                "ab6e47d42cec13bdf53a67b21257bddf",
            ),
            (
                32,
                "cea7403d4d606b6e074ec5d3baf39d18",
                "d0d1c8a799996bf0265b98b5d48ab919",
            ),
        ] {
            let mut cipher = AesGcm::new(&vec![0; key_len]).unwrap();
            let mut sealed = [0xa5; 32];
            assert_eq!(cipher.seal(&[0; 12], &[], &[0; 16], &mut sealed), Ok(32));
            assert_eq!(hex::encode(sealed), format!("{ciphertext}{tag}"));
            let mut opened = [0xa5; 16];
            assert_eq!(cipher.open(&[0; 12], &[], &sealed, &mut opened), Ok(16));
            assert_eq!(opened, [0; 16]);
        }
    }

    #[test]
    fn gcm_round_trips_and_reuses_state_after_authentication_failure() {
        for key_len in [AES_128_KEY_LEN, AES_256_KEY_LEN] {
            let key = vec![0x53; key_len];
            let mut cipher = AesGcm::new(&key).unwrap();
            for (index, len) in [0, 1, 15, 16, 17, 64, 1031].into_iter().enumerate() {
                let nonce = [u8::try_from(index).unwrap(); 12];
                let plain = vec![0x62; len];
                let aad = vec![0x71; index * 263];
                let mut sealed = vec![0; len + 16];
                assert_eq!(cipher.seal(&nonce, &aad, &plain, &mut sealed), Ok(len + 16));
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

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ephemeral ECDH over P-256 (SEC 1) through AWS-LC.

/// Ephemeral ECDH over P-256.
pub mod ecdh_p256 {
    use aws_lc_rs::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};
    use aws_lc_rs::rand::SystemRandom;

    use crate::Error;

    /// One ephemeral P-256 private key and its uncompressed public point.
    pub struct EphemeralKey {
        key: EphemeralPrivateKey,
        public: [u8; 65],
    }

    impl core::fmt::Debug for EphemeralKey {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("EphemeralKey").finish_non_exhaustive()
        }
    }

    impl EphemeralKey {
        /// A fresh key.
        pub fn generate() -> Result<Self, Error> {
            let key = EphemeralPrivateKey::generate(&ECDH_P256, &SystemRandom::new())
                .map_err(|_| Error::Rng)?;
            let p = key.compute_public_key().map_err(|_| Error::Rng)?;
            let public: [u8; 65] = p
                .as_ref()
                .try_into()
                .map_err(|_| Error::Invalid("P-256 public point"))?;
            Ok(Self { key, public })
        }

        /// The uncompressed public point (65 bytes, SEC 1).
        #[must_use]
        pub fn public_key(&self) -> &[u8] {
            &self.public
        }
    }

    /// The shared secret (the x coordinate, 32 bytes) of `mine` and the uncompressed `peer` point.
    pub fn agree(mine: EphemeralKey, peer: &[u8]) -> Result<[u8; 32], Error> {
        let peer = UnparsedPublicKey::new(&ECDH_P256, peer);
        agreement::agree_ephemeral(mine.key, peer, Error::Invalid("P-256 peer key"), |k| {
            <[u8; 32]>::try_from(k).map_err(|_| Error::Invalid("P-256 shared secret"))
        })
    }
}

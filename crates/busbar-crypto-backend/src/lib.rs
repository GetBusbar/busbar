// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar's public software crypto backend (CRYPTO-SEAM §2.2-2.3), over AWS-LC through aws-lc-rs, the one
//! crypto and TLS provider (decision 229). Only `busbar-crypto` may depend on this crate; every other crate
//! reaches it as `busbar_contract::crypto`. A private build swaps a crate of the same name and API in with
//! `[patch]` (decision 152); `busbar-crypto`'s contract assertion fails to compile against a backend that
//! misses an item or changes a signature.
//!
//! This backend refuses nothing: `supports` is `true` for every algorithm and the `approve_*` hooks always
//! succeed. The error type is still fallible everywhere a backend may refuse (FIPS findings F1-F3).

#![deny(unsafe_code)]

mod aead;
mod ecdh;
mod hash;
mod legacy_impl;
mod mac;
mod rand;
mod sig;
mod weak;

#[cfg(feature = "test-support")]
pub mod testing;
#[cfg(feature = "tls")]
mod tls;

pub use aead::{aes_block_encrypt, Aes128Gcm, Aes256Gcm};
pub use ecdh::ecdh_p256;
pub use hash::{sha256, sha384, sha512, Sha256State};
pub use mac::{ct_eq, hmac_sha256, hmac_sha256_verify, hmac_sha512, HmacSha256Key};
pub use rand::{fill, hkdf_sha256, pbkdf2_hmac_sha256, u64};
pub use sig::{ecdsa_p256, ed25519, rsa};
#[cfg(feature = "tls")]
pub use tls::{
    approve_client_config, approve_server_config, ticketer, tls_provider, webpki_algs, TLS_VERSIONS,
};

/// The backend contract version `busbar-crypto` asserts. Raised on any breaking change to this API.
pub const API: u32 = 1;

/// This backend's name: `[a-z0-9-]`, 1..=8 bytes. Shown in `--version`, `/healthz` and the audit stamp.
pub const NAME: &str = "software";

/// A backend failure, as a plain value. `busbar-crypto` maps it with an exhaustive match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// This backend does not provide `alg`; `reason` says why, in a sentence with no material in it.
    Refused {
        /// The algorithm or parameter refused (`"MD5"`, `"HMAC-SHA256"`, ...).
        alg: &'static str,
        /// Why it is refused.
        reason: &'static str,
    },
    /// The random number generator failed.
    Rng,
    /// Malformed input: a wrong length, an unparsable key, an out-of-range parameter.
    Invalid(&'static str),
    /// A MAC, tag or signature did not verify.
    Mismatch,
    /// A start-up self-test failed.
    SelfTest(&'static str),
}

/// The module identity: `/healthz` `crypto_module` and the boot log.
#[must_use]
pub fn module_version() -> &'static str {
    concat!("software ", env!("CARGO_PKG_VERSION"))
}

/// Whether this backend provides `alg` (one of `busbar-crypto`'s `alg::*` names). The software
/// backend provides every algorithm.
#[must_use]
pub fn supports(alg: &str) -> bool {
    let _ = alg;
    true
}

/// Whether a signer outside this process (`external`, operator-`attested` or not) may sign audit
/// stamps under this backend. The software backend accepts every signer.
pub fn approve_signer(external: bool, attested: bool) -> Result<(), Error> {
    let _ = (external, attested);
    Ok(())
}

/// The backend's start-up checks: AWS-LC initialises, the RNG draws, and one SHA-256 known answer.
pub fn self_test() -> Result<(), Error> {
    let mut probe = [0_u8; 16];
    rand::fill(&mut probe)
        .map_err(|_| Error::SelfTest("the random number generator does not draw"))?;
    // FIPS 180-4 example: SHA-256("abc").
    const ABC: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    if sha256(b"abc") != ABC {
        return Err(Error::SelfTest("SHA-256 known answer"));
    }
    Ok(())
}

/// The audit-link hash (SEALING-FIX §3): BLAKE3 in this backend.
pub mod link {
    /// The recipe this backend's `Hasher` writes into each link.
    pub const RECIPE: &str = "busbar.audit.digest.v7";
    /// The SHA-256 variant a FIPS build writes; this backend verifies it too.
    pub const RECIPE_SHA256: &str = "busbar.audit.digest.v7-sha256";

    /// A link hash in progress.
    #[derive(Clone, Debug, Default)]
    pub struct Hasher(Inner);

    #[derive(Clone, Debug)]
    enum Inner {
        Blake3(Box<blake3::Hasher>),
        Sha256(super::Sha256State),
    }

    impl Default for Inner {
        fn default() -> Self {
            Self::Blake3(Box::default())
        }
    }

    impl Hasher {
        /// A hasher for `RECIPE`.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// A hasher that recomputes a link written under `recipe`, or `None` when this backend
        /// cannot recompute that recipe.
        #[must_use]
        pub fn verifier(recipe: &str) -> Option<Self> {
            match recipe {
                RECIPE => Some(Self::new()),
                RECIPE_SHA256 => Some(Self(Inner::Sha256(super::Sha256State::new()))),
                _ => None,
            }
        }

        /// Absorb `data`.
        pub fn update(&mut self, data: &[u8]) {
            match &mut self.0 {
                Inner::Blake3(h) => {
                    h.update(data);
                }
                Inner::Sha256(h) => h.update(data),
            }
        }

        /// The 32-byte link.
        #[must_use]
        pub fn finish(self) -> [u8; 32] {
            match self.0 {
                Inner::Blake3(h) => *h.finalize().as_bytes(),
                Inner::Sha256(h) => h.finish(),
            }
        }
    }
}

/// Legacy algorithms, for protocol use only (Postgres md5, MySQL RSA password exchange, webhook
/// SHA-1). Always available in this backend.
pub mod legacy {
    pub use crate::legacy_impl::{hmac_sha1, md5, rsa_oaep_sha1_encrypt, sha1};
}

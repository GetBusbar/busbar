// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A deny-list `busbar-crypto-backend` in the CRYPTO-SEAM style, for C-FIPS-GATE
//! (tests/fips_gate.rs). It states every contract item and performs no crypto: `supports` is false
//! for MD5, RSA_OAEP_SHA1 and DTLS_SRTP and true otherwise, `EXTERNAL_PLUGINS` is false, and every
//! operation is refused. Feature `api1` keeps the pre-H0b contract number; feature `silent` leaves
//! `EXTERNAL_PLUGINS` out. Either must fail to compile against the facade. `fill` answers what
//! `BUSBAR_STUB_FILL` asks for: `crngt` a self-test failure, `rng` a generator failure.

/// The contract version this stub states.
#[cfg(not(feature = "api1"))]
pub const API: u32 = 2;
/// The contract version a backend written before H0b states.
#[cfg(feature = "api1")]
pub const API: u32 = 1;

/// The stub's name.
pub const NAME: &str = "stub";

/// A deny-list backend refuses plugins that bring their own crypto.
#[cfg(not(feature = "silent"))]
pub const EXTERNAL_PLUGINS: bool = false;

/// A backend failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Refused.
    Refused {
        /// The algorithm.
        alg: &'static str,
        /// Why.
        reason: &'static str,
    },
    /// The generator failed.
    Rng,
    /// Malformed input.
    Invalid(&'static str),
    /// Did not verify.
    Mismatch,
    /// A self-test failed.
    SelfTest(&'static str),
}

type R<T> = Result<T, Error>;

const REFUSED: Error = Error::Refused {
    alg: "stub",
    reason: "the C-FIPS-GATE stub performs no crypto",
};

/// The module identity.
pub fn module_version() -> &'static str {
    "stub 0"
}

/// The CRYPTO-SEAM deny list.
pub fn supports(alg: &str) -> bool {
    !matches!(alg, "MD5" | "RSA_OAEP_SHA1" | "DTLS_SRTP")
}

/// Every signer is refused.
pub fn approve_signer(_external: bool, _attested: bool) -> R<()> {
    Err(REFUSED)
}

/// Never run.
pub fn self_test() -> R<()> {
    Err(REFUSED)
}

/// Not a hash.
pub fn sha256(_data: &[u8]) -> [u8; 32] {
    [0; 32]
}

/// Not a hash.
pub fn sha384(_data: &[u8]) -> [u8; 48] {
    [0; 48]
}

/// Not a hash.
pub fn sha512(_data: &[u8]) -> [u8; 64] {
    [0; 64]
}

/// Not a hash.
#[derive(Clone, Debug, Default)]
pub struct Sha256State;

impl Sha256State {
    /// Empty.
    pub fn new() -> Self {
        Self
    }

    /// Absorbs nothing.
    pub fn update(&mut self, _data: &[u8]) {}

    /// Zeros.
    pub fn finish(self) -> [u8; 32] {
        [0; 32]
    }
}

/// Not a link hash.
pub mod link {
    /// The recipe.
    pub const RECIPE: &str = "busbar.audit.link.v1";

    /// Not a hasher.
    #[derive(Clone, Debug, Default)]
    pub struct Hasher;

    impl Hasher {
        /// Empty.
        pub fn new() -> Self {
            Self
        }

        /// None.
        pub fn verifier(_recipe: &str) -> Option<Self> {
            None
        }

        /// Absorbs nothing.
        pub fn update(&mut self, _data: &[u8]) {}

        /// Zeros.
        pub fn finish(self) -> [u8; 32] {
            [0; 32]
        }
    }
}

/// Refused.
pub fn hmac_sha256(_key: &[u8], _msg: &[u8]) -> R<[u8; 32]> {
    Err(REFUSED)
}

/// Refused.
pub fn hmac_sha384(_key: &[u8], _msg: &[u8]) -> R<[u8; 48]> {
    Err(REFUSED)
}

/// Refused.
pub fn hmac_sha512(_key: &[u8], _msg: &[u8]) -> R<[u8; 64]> {
    Err(REFUSED)
}

/// Refused.
pub fn hmac_sha256_verify(_key: &[u8], _msg: &[u8], _tag: &[u8]) -> R<()> {
    Err(REFUSED)
}

/// Not a key.
#[derive(Clone, Debug)]
pub struct HmacSha256Key;

impl HmacSha256Key {
    /// Refused.
    pub fn new(_key: &[u8]) -> R<Self> {
        Err(REFUSED)
    }

    /// Zeros.
    pub fn sign(&self, _msg: &[u8]) -> [u8; 32] {
        [0; 32]
    }

    /// Zeros.
    pub fn sign_parts(&self, _parts: &[&[u8]]) -> [u8; 32] {
        [0; 32]
    }

    /// Refused.
    pub fn verify(&self, _msg: &[u8], _tag: &[u8]) -> R<()> {
        Err(REFUSED)
    }
}

/// Never equal.
pub fn ct_eq(_a: &[u8], _b: &[u8]) -> bool {
    false
}

/// `BUSBAR_STUB_FILL=crngt`: a self-test failure; `rng`: a generator failure; else a fixed byte.
pub fn fill(buf: &mut [u8]) -> R<()> {
    match std::env::var("BUSBAR_STUB_FILL").as_deref() {
        Ok("crngt") => Err(Error::SelfTest("crngt")),
        Ok("rng") => Err(Error::Rng),
        _ => {
            buf.fill(0x5a);
            Ok(())
        }
    }
}

/// Refused.
pub fn u64() -> R<u64> {
    Err(REFUSED)
}

/// Refused.
pub fn hkdf_sha256(_salt: &[u8], _ikm: &[u8], _info: &[u8], _out: &mut [u8]) -> R<()> {
    Err(REFUSED)
}

/// Refused.
pub fn pbkdf2_hmac_sha256(
    _password: &[u8],
    _salt: &[u8],
    _iterations: u32,
    _out: &mut [u8],
) -> R<()> {
    Err(REFUSED)
}

macro_rules! gcm {
    ($name:ident, $n:literal) => {
        /// Not a key.
        #[derive(Debug)]
        pub struct $name;

        impl $name {
            /// Refused.
            pub fn new(_key: &[u8; $n]) -> R<Self> {
                Err(REFUSED)
            }

            /// Refused.
            pub fn seal_in_place(
                &self,
                _nonce: &[u8; 12],
                _aad: &[u8],
                _buf: &mut [u8],
            ) -> R<[u8; 16]> {
                Err(REFUSED)
            }

            /// Refused.
            pub fn open_in_place(
                &self,
                _nonce: &[u8; 12],
                _aad: &[u8],
                _buf: &mut [u8],
                _tag: &[u8; 16],
            ) -> R<()> {
                Err(REFUSED)
            }

            /// Refused.
            pub fn seal_random_nonce(
                &self,
                _aad: &[u8],
                _buf: &mut [u8],
            ) -> R<([u8; 12], [u8; 16])> {
                Err(REFUSED)
            }
        }
    };
}

gcm!(Aes256Gcm, 32);
gcm!(Aes128Gcm, 16);

/// Refused.
pub fn aes_block_encrypt(_key: &[u8; 16], _block: &[u8; 16]) -> R<[u8; 16]> {
    Err(REFUSED)
}

/// Refused.
pub mod aes_ctr {
    use super::{R, REFUSED};

    /// Refused.
    pub fn apply(_key: &[u8], _iv: &[u8; 16], _input: &[u8], _out: &mut [u8]) -> R<()> {
        Err(REFUSED)
    }
}

/// Refused.
pub mod ed25519 {
    use super::{R, REFUSED};

    /// Refused.
    pub fn validate_public_key(_raw: &[u8; 32]) -> R<()> {
        Err(REFUSED)
    }

    /// Not a key.
    #[derive(Debug)]
    pub struct SigningKey([u8; 32]);

    impl SigningKey {
        /// Refused.
        pub fn generate() -> R<Self> {
            Err(REFUSED)
        }

        /// Refused.
        pub fn from_seed(_seed: &[u8; 32]) -> R<Self> {
            Err(REFUSED)
        }

        /// Refused.
        pub fn from_pkcs8(_pkcs8: &[u8]) -> R<Self> {
            Err(REFUSED)
        }

        /// The seed.
        pub fn seed(&self) -> &[u8; 32] {
            &self.0
        }

        /// Zeros.
        pub fn sign(&self, _msg: &[u8]) -> [u8; 64] {
            [0; 64]
        }

        /// The zero key.
        pub fn verifying_key(&self) -> VerifyingKey {
            VerifyingKey([0; 32])
        }
    }

    /// Not a key.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct VerifyingKey([u8; 32]);

    impl VerifyingKey {
        /// Refused.
        pub fn from_bytes(_bytes: &[u8; 32]) -> R<Self> {
            Err(REFUSED)
        }

        /// Refused.
        pub fn from_spki(_spki: &[u8]) -> R<Self> {
            Err(REFUSED)
        }

        /// The bytes.
        pub fn to_bytes(&self) -> [u8; 32] {
            self.0
        }

        /// Weak.
        pub fn is_weak(&self) -> bool {
            true
        }

        /// Refused.
        pub fn verify_strict(&self, _msg: &[u8], _sig: &[u8; 64]) -> R<()> {
            Err(REFUSED)
        }
    }
}

/// Refused.
pub mod ecdsa_p256 {
    use super::{R, REFUSED};

    /// Refused.
    pub fn generate_pkcs8() -> R<Vec<u8>> {
        Err(REFUSED)
    }

    /// Not a key.
    #[derive(Debug)]
    pub struct KeyPair;

    /// Refused.
    pub fn from_pkcs8(_pkcs8: &[u8]) -> R<KeyPair> {
        Err(REFUSED)
    }

    impl KeyPair {
        /// Refused.
        pub fn sign_fixed(&self, _msg: &[u8]) -> R<[u8; 64]> {
            Err(REFUSED)
        }

        /// Refused.
        pub fn sign_asn1(&self, _msg: &[u8]) -> R<Vec<u8>> {
            Err(REFUSED)
        }

        /// Zeros.
        pub fn public_key(&self) -> [u8; 65] {
            [0; 65]
        }
    }

    /// Refused.
    pub fn verify_fixed(_pk: &[u8], _msg: &[u8], _sig: &[u8]) -> R<()> {
        Err(REFUSED)
    }

    /// Refused.
    pub fn verify_asn1(_pk: &[u8], _msg: &[u8], _sig: &[u8]) -> R<()> {
        Err(REFUSED)
    }

    /// Refused.
    pub fn verify_fixed_spki(_spki: &[u8], _msg: &[u8], _sig: &[u8]) -> R<()> {
        Err(REFUSED)
    }
}

/// Refused.
pub mod ecdsa_p384 {
    use super::{R, REFUSED};

    /// Refused.
    pub fn verify_fixed(_pk: &[u8], _msg: &[u8], _sig: &[u8]) -> R<()> {
        Err(REFUSED)
    }

    /// Refused.
    pub fn verify_fixed_spki(_spki: &[u8], _msg: &[u8], _sig: &[u8]) -> R<()> {
        Err(REFUSED)
    }
}

/// Refused.
pub mod rsa {
    use super::{R, REFUSED};

    /// The schemes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Scheme {
        /// PKCS#1 v1.5 SHA-256.
        Pkcs1Sha256,
        /// PKCS#1 v1.5 SHA-384.
        Pkcs1Sha384,
        /// PKCS#1 v1.5 SHA-512.
        Pkcs1Sha512,
        /// PSS SHA-256.
        PssSha256,
        /// PSS SHA-384.
        PssSha384,
        /// PSS SHA-512.
        PssSha512,
    }

    /// Refused.
    pub fn verify(_scheme: Scheme, _pk: &[u8], _msg: &[u8], _sig: &[u8]) -> R<()> {
        Err(REFUSED)
    }

    /// Refused.
    pub fn verify_spki(_scheme: Scheme, _spki: &[u8], _msg: &[u8], _sig: &[u8]) -> R<()> {
        Err(REFUSED)
    }

    /// Refused.
    pub fn verify_components(
        _scheme: Scheme,
        _n: &[u8],
        _e: &[u8],
        _msg: &[u8],
        _sig: &[u8],
    ) -> R<()> {
        Err(REFUSED)
    }

    /// Refused.
    pub fn verify_pkcs1_sha256(_pk: &[u8], _msg: &[u8], _sig: &[u8]) -> R<()> {
        Err(REFUSED)
    }

    /// Refused.
    pub fn verify_pss_sha256(_pk: &[u8], _msg: &[u8], _sig: &[u8]) -> R<()> {
        Err(REFUSED)
    }

    /// Not a key.
    #[derive(Debug)]
    pub struct SigningKey;

    impl SigningKey {
        /// Refused.
        pub fn from_pkcs8(_pkcs8: &[u8]) -> R<Self> {
            Err(REFUSED)
        }

        /// Zero.
        pub fn modulus_len(&self) -> usize {
            0
        }

        /// Empty.
        pub fn public_key(&self) -> Vec<u8> {
            Vec::new()
        }

        /// Refused.
        pub fn sign_pkcs1_sha256(&self, _msg: &[u8]) -> R<Vec<u8>> {
            Err(REFUSED)
        }

        /// Refused.
        pub fn sign_pss_sha256(&self, _msg: &[u8]) -> R<Vec<u8>> {
            Err(REFUSED)
        }
    }

    /// Refused.
    pub fn sign_pkcs1_sha256(_pkcs8: &[u8], _msg: &[u8]) -> R<Vec<u8>> {
        Err(REFUSED)
    }
}

/// Refused.
pub mod ecdh_p256 {
    use super::{R, REFUSED};

    /// Not a key.
    #[derive(Debug)]
    pub struct EphemeralKey;

    impl EphemeralKey {
        /// Refused.
        pub fn generate() -> R<Self> {
            Err(REFUSED)
        }

        /// Empty.
        pub fn public_key(&self) -> &[u8] {
            &[]
        }
    }

    /// Refused.
    pub fn agree(_mine: EphemeralKey, _peer: &[u8]) -> R<[u8; 32]> {
        Err(REFUSED)
    }
}

/// Refused (MD5 and RSA-OAEP-SHA1 are on the deny list).
pub mod legacy {
    use super::{R, REFUSED};

    /// Refused.
    pub fn md5(_data: &[u8]) -> R<[u8; 16]> {
        Err(REFUSED)
    }

    /// Refused.
    pub fn sha1(_data: &[u8]) -> R<[u8; 20]> {
        Err(REFUSED)
    }

    /// Refused.
    pub fn hmac_sha1(_key: &[u8], _msg: &[u8]) -> R<[u8; 20]> {
        Err(REFUSED)
    }

    /// Refused.
    pub fn rsa_oaep_sha1_encrypt(_public_key_der: &[u8], _msg: &[u8]) -> R<Vec<u8>> {
        Err(REFUSED)
    }

    /// Refused.
    pub fn rsa_oaep_public_key_check(_public_key_der: &[u8]) -> R<()> {
        Err(REFUSED)
    }
}

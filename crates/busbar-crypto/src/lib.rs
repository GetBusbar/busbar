// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! busbar's one crypto API (CRYPTO-SEAM §2.3), re-exported as `busbar_contract::crypto`.
//!
//! This crate holds no primitive. Every call goes to exactly one crate, `busbar-crypto-backend`: core's
//! software backend over AWS-LC, or a private crate of the same name swapped in by `[patch]`. The
//! contract assertion (`contract.rs`) fails to compile against a backend that misses an item.
//!
//! Every operation a backend may refuse, or that draws randomness, returns `Result`. Only plain hashes,
//! `link::Hasher` and [`ct_eq`] are infallible. A refused algorithm is [`Error::Unsupported`] with a
//! reason; a bad MAC, tag or signature is [`Error::Mismatch`], never `Unsupported`.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

use busbar_crypto_backend as b;
use core::fmt;

#[cfg(feature = "test-support")]
pub mod conformance;
mod contract;
#[cfg(feature = "tls")]
pub mod dtls;
mod signer;
#[cfg(feature = "test-support")]
pub mod testing;
#[cfg(feature = "tls")]
pub mod tls;

pub use signer::{
    approve_signer, verify, Boundary, LocalSigner, PublicKey, SigAlg, SignError, Signer,
};

/// The crypto backend this binary was built with (`"software"` in core).
pub const BACKEND: &str = b::NAME;

/// Whether a plugin that brings its own crypto (stamp `crypto = "external"`) may load: the linked
/// backend's required answer (IF §5.2 round 13; `false` in a FIPS build). Admission reads this and
/// nothing else; [`supports`] answers `"EXTERNAL_PLUGINS"` from it, so there is no second answer.
pub const EXTERNAL_PLUGINS: bool = b::EXTERNAL_PLUGINS;

/// An algorithm or parameter the linked backend refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsupported {
    /// The algorithm or parameter (`"MD5"`, `"HMAC-SHA256"`, ...).
    pub alg: &'static str,
    /// The backend that refused it ([`BACKEND`]).
    pub backend: &'static str,
    /// Why, in a sentence with no material in it.
    pub reason: &'static str,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is not available in crypto backend {}: {}",
            self.alg, self.backend, self.reason
        )
    }
}

impl std::error::Error for Unsupported {}

/// The random number generator failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngError;

impl fmt::Display for RngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the random number generator failed")
    }
}

impl std::error::Error for RngError {}

/// Why a crypto operation did not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The linked backend does not provide this algorithm or parameter.
    Unsupported(Unsupported),
    /// The random number generator failed.
    Rng(RngError),
    /// Malformed input: a wrong length, an unparsable key, an out-of-range parameter.
    Invalid(&'static str),
    /// A MAC, tag or signature did not verify.
    Mismatch,
    /// A start-up self-test failed.
    SelfTest(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(u) => u.fmt(f),
            Self::Rng(r) => r.fmt(f),
            Self::Invalid(w) => write!(f, "invalid crypto input: {w}"),
            Self::Mismatch => f.write_str("verification failed"),
            Self::SelfTest(w) => write!(f, "crypto self-test failed: {w}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Unsupported> for Error {
    fn from(u: Unsupported) -> Self {
        Self::Unsupported(u)
    }
}

impl From<RngError> for Error {
    fn from(r: RngError) -> Self {
        Self::Rng(r)
    }
}

/// The backend's error as the facade's. Exhaustive: a new backend variant fails to compile here.
#[inline]
pub(crate) fn map(e: b::Error) -> Error {
    match e {
        b::Error::Refused { alg, reason } => Error::Unsupported(Unsupported {
            alg,
            backend: BACKEND,
            reason,
        }),
        b::Error::Rng => Error::Rng(RngError),
        b::Error::Invalid(w) => Error::Invalid(w),
        b::Error::Mismatch => Error::Mismatch,
        b::Error::SelfTest(w) => Error::SelfTest(w),
    }
}

/// The module identity for `/healthz` `crypto_module` and the boot log.
#[must_use]
pub fn module_version() -> &'static str {
    b::module_version()
}

/// The closed set of algorithm names [`supports`] answers for.
pub mod alg {
    /// MD5 (Postgres md5 authentication).
    pub const MD5: &str = "MD5";
    /// SHA-1 outside HMAC.
    pub const SHA1: &str = "SHA1";
    /// HMAC-SHA1 (webhook signatures).
    const HMAC_SHA1: &str = "HMAC_SHA1";
    /// RSA-OAEP with SHA-1 (MySQL RSA password exchange).
    pub const RSA_OAEP_SHA1: &str = "RSA_OAEP_SHA1";
    /// DTLS-SRTP (WebRTC).
    pub const DTLS_SRTP: &str = "DTLS_SRTP";
    /// HMAC keys shorter than 112 bits.
    pub const HMAC_KEY_SHORT: &str = "HMAC_KEY_SHORT";
    /// RSA keys longer than 4096 bits.
    const RSA_OVER_4096: &str = "RSA_OVER_4096";
    /// TLS ChaCha20-Poly1305 suites.
    const TLS_CHACHA20: &str = "TLS_CHACHA20";
    /// Plain X25519 key exchange in TLS.
    const TLS_X25519: &str = "TLS_X25519";
    /// TLS 1.2 without the extended master secret.
    const TLS12_NO_EMS: &str = "TLS12_NO_EMS";
    /// Not an algorithm: `supports` answers it from the `EXTERNAL_PLUGINS` const, never
    /// from the backend's `supports`. Not a gate (admission reads the const).
    pub(crate) const EXTERNAL_PLUGINS: &str = "EXTERNAL_PLUGINS";
    /// Every name, for `--validate` and tests.
    pub const ALL: &[&str] = &[
        MD5,
        SHA1,
        HMAC_SHA1,
        RSA_OAEP_SHA1,
        DTLS_SRTP,
        HMAC_KEY_SHORT,
        RSA_OVER_4096,
        TLS_CHACHA20,
        TLS_X25519,
        TLS12_NO_EMS,
    ];
}

/// Whether the linked backend provides `alg` (one of [`alg`]'s names). `"EXTERNAL_PLUGINS"` is
/// answered from [`EXTERNAL_PLUGINS`].
#[must_use]
pub fn supports(alg: &str) -> bool {
    if alg == alg::EXTERNAL_PLUGINS {
        EXTERNAL_PLUGINS
    } else {
        b::supports(alg)
    }
}

/// The start-up self-test: the backend's own checks, then four known answers through this API
/// (SHA-256, HMAC-SHA256, AES-256-GCM, Ed25519). `Err` means refuse to start.
pub fn self_test() -> Result<(), Error> {
    b::self_test().map_err(map)?;
    contract::known_answers()
}

// ---- Hashes -------------------------------------------------------------------------------------

/// SHA-256 of `data`.
#[inline]
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    b::sha256(data)
}

/// SHA-384 of `data`.
#[inline]
#[must_use]
pub fn sha384(data: &[u8]) -> [u8; 48] {
    b::sha384(data)
}

/// SHA-512 of `data`.
#[inline]
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    b::sha512(data)
}

/// SHA-256 of the concatenation of `parts`.
#[must_use]
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finish()
}

/// A streaming SHA-256.
#[derive(Clone, Debug, Default)]
pub struct Sha256(b::Sha256State);

impl Sha256 {
    /// An empty SHA-256.
    #[must_use]
    pub fn new() -> Self {
        Self(b::Sha256State::new())
    }

    /// Absorb `data`.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of everything absorbed.
    #[must_use]
    pub fn finish(self) -> [u8; 32] {
        self.0.finish()
    }
}

/// The audit-link hash (SEALING-FIX §3). SHA-256
/// (`busbar.audit.link.v1`) on every backend.
pub mod link {
    use super::{Unsupported, BACKEND};
    use busbar_crypto_backend as b;

    /// The recipe [`Hasher::new`] writes.
    pub const RECIPE: &str = b::link::RECIPE;

    /// A link hash in progress.
    #[derive(Clone, Debug, Default)]
    pub struct Hasher(b::link::Hasher);

    impl Hasher {
        /// A hasher for [`RECIPE`].
        #[must_use]
        pub fn new() -> Self {
            Self(b::link::Hasher::new())
        }

        /// Absorb `data`.
        #[inline]
        pub fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }

        /// The 32-byte link.
        #[must_use]
        pub fn finish(self) -> [u8; 32] {
            self.0.finish()
        }
    }

    /// A hasher that recomputes links written under `recipe`, or why this backend cannot.
    pub fn verifier(recipe: &str) -> Result<Hasher, Unsupported> {
        b::link::Hasher::verifier(recipe)
            .map(Hasher)
            .ok_or(Unsupported {
                alg: "audit link recipe",
                backend: BACKEND,
                reason: "this backend cannot recompute links written under that recipe",
            })
    }
}

// ---- MACs, comparison, randomness, KDFs ----------------------------------------------------------

/// HMAC-SHA256 of `msg` under `key`. A backend may refuse short keys.
#[inline]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<[u8; 32], Error> {
    b::hmac_sha256(key, msg).map_err(map)
}

/// HMAC-SHA384 of `msg` under `key`. A backend may refuse short keys.
#[inline]
pub fn hmac_sha384(key: &[u8], msg: &[u8]) -> Result<[u8; 48], Error> {
    b::hmac_sha384(key, msg).map_err(map)
}

/// HMAC-SHA512 of `msg` under `key`.
#[inline]
pub fn hmac_sha512(key: &[u8], msg: &[u8]) -> Result<[u8; 64], Error> {
    b::hmac_sha512(key, msg).map_err(map)
}

/// Verify `tag` as HMAC-SHA256 of `msg` under `key`, in constant time: `Err(Mismatch)` if not.
pub fn hmac_sha256_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), Error> {
    b::hmac_sha256_verify(key, msg, tag).map_err(map)
}

/// An HMAC-SHA256 key for many MACs (the key check happens once, in [`HmacSha256Key::new`]).
#[derive(Clone, Debug)]
pub struct HmacSha256Key(b::HmacSha256Key);

impl HmacSha256Key {
    /// A key from `key`'s bytes.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        b::HmacSha256Key::new(key).map(Self).map_err(map)
    }

    /// HMAC-SHA256 of `msg`.
    #[inline]
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; 32] {
        self.0.sign(msg)
    }

    /// HMAC-SHA256 of the concatenation of `parts`.
    #[must_use]
    pub fn sign_parts(&self, parts: &[&[u8]]) -> [u8; 32] {
        self.0.sign_parts(parts)
    }

    /// Verify `tag` over `msg` in constant time: `Err(Mismatch)` if not.
    pub fn verify(&self, msg: &[u8], tag: &[u8]) -> Result<(), Error> {
        self.0.verify(msg, tag).map_err(map)
    }
}

/// Whether `a` equals `b`, in time that depends only on the lengths.
#[inline]
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    b::ct_eq(a, b)
}

/// Fill `buf` with random bytes; the backend's error through `map` (Rng, SelfTest, ...), so a
/// failed DRBG self-test is told apart from a plain generator failure (IF §5.2 round 21, host_vt).
#[inline]
pub fn fill_checked(buf: &mut [u8]) -> Result<(), Error> {
    b::fill(buf).map_err(map)
}

/// Fill `buf` with random bytes.
#[inline]
pub fn fill(buf: &mut [u8]) -> Result<(), RngError> {
    fill_checked(buf).map_err(|_| RngError)
}

/// A random `u64`.
#[inline]
pub fn u64() -> Result<u64, RngError> {
    b::u64().map_err(|_| RngError)
}

/// `N` random bytes.
#[inline]
pub fn random<const N: usize>() -> Result<[u8; N], RngError> {
    let mut out = [0_u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// HKDF-SHA256 (RFC 5869) into `out`.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    b::hkdf_sha256(salt, ikm, info, out).map_err(map)
}

/// PBKDF2-HMAC-SHA256 (RFC 8018) into `out`. A backend may refuse parameters (SP 800-132).
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<(), Error> {
    b::pbkdf2_hmac_sha256(password, salt, iterations, out).map_err(map)
}

// ---- AEAD and the AES block ---------------------------------------------------------------------

macro_rules! gcm {
    ($name:ident, $n:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $name(b::$name);

        impl $name {
            /// A key from `key`'s bytes.
            pub fn new(key: &[u8; $n]) -> Result<Self, Error> {
                b::$name::new(key).map(Self).map_err(map)
            }

            /// Encrypt `buf` in place under the caller's unique `nonce`; return the tag. On `Err`
            /// the buffer is untouched. A backend may refuse caller nonces (use
            /// [`Self::seal_random_nonce`]).
            pub fn seal_in_place(
                &self,
                nonce: &[u8; 12],
                aad: &[u8],
                buf: &mut [u8],
            ) -> Result<[u8; 16], Error> {
                self.0.seal_in_place(nonce, aad, buf).map_err(map)
            }

            /// Decrypt `buf` in place after checking `tag`: `Err(Mismatch)` (buffer zeroed) if it
            /// does not authenticate.
            pub fn open_in_place(
                &self,
                nonce: &[u8; 12],
                aad: &[u8],
                buf: &mut [u8],
                tag: &[u8; 16],
            ) -> Result<(), Error> {
                self.0.open_in_place(nonce, aad, buf, tag).map_err(map)
            }

            /// Encrypt `buf` in place under a fresh random nonce; return the nonce and the tag.
            pub fn seal_random_nonce(
                &self,
                aad: &[u8],
                buf: &mut [u8],
            ) -> Result<([u8; 12], [u8; 16]), Error> {
                self.0.seal_random_nonce(aad, buf).map_err(map)
            }
        }
    };
}

gcm!(Aes256Gcm, 32, "AES-256-GCM under one key.");
gcm!(Aes128Gcm, 16, "AES-128-GCM under one key.");

/// One AES-128 block encryption (SRTP only).
pub fn aes_block_encrypt(key: &[u8; 16], block: &[u8; 16]) -> Result<[u8; 16], Error> {
    b::aes_block_encrypt(key, block).map_err(map)
}

/// AES-CTR (NIST SP 800-38A) under a 16- or 32-byte key, with a 128-bit big-endian counter block
/// (SRTP's AES-CM). One block of zeros under counter `x` gives the single AES block `E_k(x)`.
pub mod aes_ctr {
    use super::{map, Error};
    use busbar_crypto_backend as b;

    /// `input` encrypted (or decrypted: CTR is its own inverse) under `key` from the counter block
    /// `iv`, into `out`, which must be exactly as long as `input`: `Err(Invalid)` otherwise, or for
    /// a key that is not 16 or 32 bytes.
    pub fn apply(key: &[u8], iv: &[u8; 16], input: &[u8], out: &mut [u8]) -> Result<(), Error> {
        b::aes_ctr::apply(key, iv, input, out).map_err(map)
    }
}

// ---- Signatures and key agreement ---------------------------------------------------------------

/// Ed25519 (RFC 8032) with `verify_strict` semantics.
pub mod ed25519 {
    use super::{map, Error};
    use busbar_crypto_backend as b;

    /// An Ed25519 private key.
    #[derive(Debug)]
    pub struct SigningKey(b::ed25519::SigningKey);

    impl SigningKey {
        /// A fresh key.
        pub fn generate() -> Result<Self, Error> {
            b::ed25519::SigningKey::generate().map(Self).map_err(map)
        }

        /// The key whose RFC 8032 seed is `seed`.
        pub fn from_seed(seed: &[u8; 32]) -> Result<Self, Error> {
            b::ed25519::SigningKey::from_seed(seed)
                .map(Self)
                .map_err(map)
        }

        /// The key in the PKCS#8 (RFC 8410, v1 or v2) DER `pkcs8`.
        pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
            b::ed25519::SigningKey::from_pkcs8(pkcs8)
                .map(Self)
                .map_err(map)
        }

        /// The 32-byte seed, borrowed from the key (wiped when the key drops; no copy is made).
        #[must_use]
        pub fn seed(&self) -> &[u8; 32] {
            self.0.seed()
        }

        /// The signature of `msg`.
        #[must_use]
        pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
            self.0.sign(msg)
        }

        /// The public key.
        #[must_use]
        pub fn verifying_key(&self) -> VerifyingKey {
            VerifyingKey(self.0.verifying_key())
        }
    }

    /// An Ed25519 public key.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct VerifyingKey(b::ed25519::VerifyingKey);

    impl VerifyingKey {
        /// The key encoded as `bytes`.
        pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
            b::ed25519::VerifyingKey::from_bytes(bytes)
                .map(Self)
                .map_err(map)
        }

        /// The key in the DER `SubjectPublicKeyInfo` `spki` (RFC 8410): `Err(Invalid)` for anything
        /// else, the bare 32-byte key included.
        pub fn from_spki(spki: &[u8]) -> Result<Self, Error> {
            b::ed25519::VerifyingKey::from_spki(spki)
                .map(Self)
                .map_err(map)
        }

        /// The encoded key.
        #[must_use]
        pub fn to_bytes(&self) -> [u8; 32] {
            self.0.to_bytes()
        }

        /// Whether the key is a small-order point.
        #[must_use]
        pub fn is_weak(&self) -> bool {
            self.0.is_weak()
        }

        /// Verify `sig` over `msg`: `Err(Mismatch)` for a bad signature, a weak key, a small-order
        /// `R` or a non-canonical `S`.
        pub fn verify_strict(&self, msg: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
            self.0.verify_strict(msg, sig).map_err(map)
        }
    }
}

/// ECDSA P-256 with SHA-256: PKCS#8 keys, SEC 1 uncompressed public keys, fixed (`r || s`) or
/// ASN.1 signatures. General verification accepts both S forms; the signer seam requires low S.
pub mod ecdsa_p256 {
    use super::{map, Error};
    use busbar_crypto_backend as b;

    /// The group order n of P-256, big-endian.
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    /// floor(n / 2), big-endian.
    const HALF_N: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];

    /// A fresh key, PKCS#8 DER.
    pub fn generate_pkcs8() -> Result<Vec<u8>, Error> {
        b::ecdsa_p256::generate_pkcs8().map_err(map)
    }

    /// A P-256 private key.
    #[derive(Debug)]
    pub struct KeyPair(b::ecdsa_p256::KeyPair);

    /// The key in PKCS#8 DER `pkcs8`.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<KeyPair, Error> {
        b::ecdsa_p256::from_pkcs8(pkcs8).map(KeyPair).map_err(map)
    }

    impl KeyPair {
        /// A fixed `r || s` signature of `msg`.
        pub fn sign_fixed(&self, msg: &[u8]) -> Result<[u8; 64], Error> {
            self.0.sign_fixed(msg).map_err(map)
        }

        /// An ASN.1 DER signature of `msg`.
        pub fn sign_asn1(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
            self.0.sign_asn1(msg).map_err(map)
        }

        /// The SEC 1 uncompressed public key.
        #[must_use]
        pub fn public_key(&self) -> [u8; 65] {
            self.0.public_key()
        }
    }

    /// Verify a fixed `r || s` signature under the SEC 1 key `pk` (either S form).
    pub fn verify_fixed(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        b::ecdsa_p256::verify_fixed(pk, msg, sig).map_err(map)
    }

    /// Verify an ASN.1 DER signature under the SEC 1 key `pk` (either S form).
    pub fn verify_asn1(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        b::ecdsa_p256::verify_asn1(pk, msg, sig).map_err(map)
    }

    /// Verify a fixed `r || s` signature under the P-256 DER `SubjectPublicKeyInfo` `spki` (either
    /// S form): `Err(Invalid)` for a key that is not one (a bare point, another curve).
    pub fn verify_fixed_spki(spki: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        b::ecdsa_p256::verify_fixed_spki(spki, msg, sig).map_err(map)
    }

    /// Whether the fixed signature's `s` is at most n/2.
    #[must_use]
    pub fn is_low_s(sig: &[u8; 64]) -> bool {
        sig[32..] <= HALF_N[..]
    }

    /// Replace a high `s` (above n/2) by `n - s`, which verifies the same message.
    pub fn normalize_low_s(sig: &mut [u8; 64]) {
        if is_low_s(sig) {
            return;
        }
        let mut borrow = 0_i16;
        for i in (0..32).rev() {
            let d = i16::from(N[i]) - i16::from(sig[32 + i]) - borrow;
            borrow = i16::from(d < 0);
            sig[32 + i] = (d + (borrow << 8)) as u8;
        }
    }
}

/// ECDSA P-384 with SHA-384, verification only: SEC 1 uncompressed public keys (97 bytes) or a
/// DER `SubjectPublicKeyInfo`, fixed `r || s` signatures (96 bytes).
pub mod ecdsa_p384 {
    use super::{map, Error};
    use busbar_crypto_backend as b;

    /// Verify a fixed `r || s` signature under the SEC 1 key `pk`.
    pub fn verify_fixed(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        b::ecdsa_p384::verify_fixed(pk, msg, sig).map_err(map)
    }

    /// Verify a fixed `r || s` signature under the P-384 DER `SubjectPublicKeyInfo` `spki`:
    /// `Err(Invalid)` for a key that is not one (a bare point, another curve).
    pub fn verify_fixed_spki(spki: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        b::ecdsa_p384::verify_fixed_spki(spki, msg, sig).map_err(map)
    }
}

/// RSA signatures (RFC 8017).
pub mod rsa {
    use super::{map, Error};
    use busbar_crypto_backend as b;

    pub use b::rsa::Scheme;

    /// Verify `sig` over `msg` under the PKCS#1 `RSAPublicKey` DER `pk`.
    pub fn verify(scheme: Scheme, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        b::rsa::verify(scheme, pk, msg, sig).map_err(map)
    }

    /// Verify `sig` over `msg` under the RSA DER `SubjectPublicKeyInfo` `spki`: `Err(Invalid)` for
    /// a key that is not one (a PKCS#1 `RSAPublicKey` included).
    pub fn verify_spki(scheme: Scheme, spki: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        b::rsa::verify_spki(scheme, spki, msg, sig).map_err(map)
    }

    /// Verify `sig` over `msg` under the key with big-endian modulus `n` and exponent `e`.
    pub fn verify_components(
        scheme: Scheme,
        n: &[u8],
        e: &[u8],
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), Error> {
        b::rsa::verify_components(scheme, n, e, msg, sig).map_err(map)
    }

    /// Verify RSASSA-PKCS1-v1_5 SHA-256 under the PKCS#1 DER `pk`.
    pub fn verify_pkcs1_sha256(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        b::rsa::verify_pkcs1_sha256(pk, msg, sig).map_err(map)
    }

    /// Verify RSASSA-PSS SHA-256 under the PKCS#1 DER `pk`.
    pub fn verify_pss_sha256(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        b::rsa::verify_pss_sha256(pk, msg, sig).map_err(map)
    }

    /// An RSA private key.
    #[derive(Debug)]
    pub struct SigningKey(b::rsa::SigningKey);

    impl SigningKey {
        /// The key in PKCS#8 DER `pkcs8`.
        pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
            b::rsa::SigningKey::from_pkcs8(pkcs8).map(Self).map_err(map)
        }

        /// The modulus length in bytes.
        #[must_use]
        pub fn modulus_len(&self) -> usize {
            self.0.modulus_len()
        }

        /// The PKCS#1 `RSAPublicKey` DER.
        #[must_use]
        pub fn public_key(&self) -> Vec<u8> {
            self.0.public_key()
        }

        /// An RSASSA-PKCS1-v1_5 SHA-256 signature (RS256) of `msg`.
        pub fn sign_pkcs1_sha256(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
            self.0.sign_pkcs1_sha256(msg).map_err(map)
        }

        /// An RSASSA-PSS SHA-256 signature (PS256) of `msg`.
        pub fn sign_pss_sha256(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
            self.0.sign_pss_sha256(msg).map_err(map)
        }
    }

    /// An RS256 signature of `msg` under the PKCS#8 DER key `pkcs8`.
    pub fn sign_pkcs1_sha256(pkcs8: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        b::rsa::sign_pkcs1_sha256(pkcs8, msg).map_err(map)
    }
}

/// Ephemeral ECDH over P-256.
pub mod ecdh_p256 {
    use super::{map, Error};
    use busbar_crypto_backend as b;

    /// An ephemeral P-256 key.
    #[derive(Debug)]
    pub struct EphemeralKey(b::ecdh_p256::EphemeralKey);

    impl EphemeralKey {
        /// A fresh key.
        pub fn generate() -> Result<Self, Error> {
            b::ecdh_p256::EphemeralKey::generate()
                .map(Self)
                .map_err(map)
        }

        /// The SEC 1 uncompressed public point.
        #[must_use]
        pub fn public_key(&self) -> &[u8] {
            self.0.public_key()
        }
    }

    /// The 32-byte shared secret of `mine` and the uncompressed `peer` point.
    pub fn agree(mine: EphemeralKey, peer: &[u8]) -> Result<[u8; 32], Error> {
        b::ecdh_p256::agree(mine.0, peer).map_err(map)
    }
}

/// Legacy algorithms, for protocol use only: Postgres md5, MySQL RSA password exchange, webhook
/// SHA-1. Each may be refused by a backend ([`supports`] says which).
pub mod legacy {
    use super::{map, Error};
    use busbar_crypto_backend as b;

    /// MD5 of `data`.
    pub fn md5(data: &[u8]) -> Result<[u8; 16], Error> {
        b::legacy::md5(data).map_err(map)
    }

    /// SHA-1 of `data`.
    pub fn sha1(data: &[u8]) -> Result<[u8; 20], Error> {
        b::legacy::sha1(data).map_err(map)
    }

    /// HMAC-SHA1 of `msg` under `key`.
    pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> Result<[u8; 20], Error> {
        b::legacy::hmac_sha1(key, msg).map_err(map)
    }

    /// `msg` encrypted with RSAES-OAEP (SHA-1, MGF1-SHA-1) to the RSA key `public_key_der`
    /// (DER `SubjectPublicKeyInfo` or PKCS#1 `RSAPublicKey`).
    pub fn rsa_oaep_sha1_encrypt(public_key_der: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        b::legacy::rsa_oaep_sha1_encrypt(public_key_der, msg).map_err(map)
    }

    /// Whether `public_key_der` (DER `SubjectPublicKeyInfo` or PKCS#1 `RSAPublicKey`) is an RSA
    /// key [`rsa_oaep_sha1_encrypt`] encrypts to: the backend's own parse, so a key passes exactly
    /// when that encryption would accept it.
    pub fn rsa_oaep_public_key_check(public_key_der: &[u8]) -> Result<(), Error> {
        b::legacy::rsa_oaep_public_key_check(public_key_der).map_err(map)
    }
}

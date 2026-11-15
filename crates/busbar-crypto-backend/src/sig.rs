// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Signatures over AWS-LC: Ed25519 (RFC 8032), ECDSA P-256 and P-384 (FIPS 186-5) and RSA
//! (RFC 8017).

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::signature::{ParsedPublicKey, VerificationAlgorithm};

use crate::Error;

/// The public key in the DER `SubjectPublicKeyInfo` `spki`, parsed by AWS-LC for `alg`. AWS-LC
/// also takes a bare key (a SEC 1 point, a raw Ed25519 key, a PKCS#1 `RSAPublicKey`), so the key is
/// accepted only when AWS-LC's own SPKI encoding of it is `spki` byte for byte: `Err(Invalid)` for
/// a bare key, another curve or algorithm, trailing bytes or a non-canonical encoding.
fn spki_key(
    alg: &'static dyn VerificationAlgorithm,
    spki: &[u8],
    what: &'static str,
) -> Result<ParsedPublicKey, Error> {
    let key = ParsedPublicKey::new(alg, spki).map_err(|_| Error::Invalid(what))?;
    let der = key.as_der().map_err(|_| Error::Invalid(what))?;
    let canonical: &[u8] = (*der).as_ref();
    if canonical == spki {
        Ok(key)
    } else {
        Err(Error::Invalid(what))
    }
}

/// Ed25519 with `verify_strict` semantics: small-order keys and small-order `R` are refused and `S`
/// must be canonical (AWS-LC checks `S < L`; the small-order table is `weak.rs`).
pub mod ed25519 {
    use aws_lc_rs::encoding::AsBigEndian as _;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _, UnparsedPublicKey, ED25519};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    use crate::Error;

    /// An Ed25519 private key and its 32-byte seed.
    pub struct SigningKey {
        pair: Ed25519KeyPair,
        seed: [u8; 32],
    }

    impl Drop for SigningKey {
        fn drop(&mut self) {
            self.seed.zeroize();
        }
    }

    impl ZeroizeOnDrop for SigningKey {}

    impl core::fmt::Debug for SigningKey {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("SigningKey").finish_non_exhaustive()
        }
    }

    impl SigningKey {
        /// A fresh key from the random number generator.
        pub fn generate() -> Result<Self, Error> {
            let mut seed = [0_u8; 32];
            let key = crate::rand::fill(&mut seed[..]).and_then(|()| Self::from_seed(&seed));
            seed.zeroize();
            key
        }

        /// The key whose RFC 8032 seed is `seed`.
        pub fn from_seed(seed: &[u8; 32]) -> Result<Self, Error> {
            let pair = Ed25519KeyPair::from_seed_unchecked(seed)
                .map_err(|_| Error::Invalid("Ed25519 seed"))?;
            Ok(Self { pair, seed: *seed })
        }

        /// The key in the PKCS#8 (RFC 8410, v1 or v2) DER `pkcs8`.
        pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
            const WHAT: Error = Error::Invalid("Ed25519 PKCS#8 key");
            let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| WHAT)?;
            let bin = pair
                .seed()
                .and_then(|s| s.as_be_bytes())
                .map_err(|_| WHAT)?;
            let bytes: &[u8] = (*bin).as_ref();
            let mut seed = [0_u8; 32];
            if bytes.len() != seed.len() {
                return Err(WHAT);
            }
            seed.copy_from_slice(bytes);
            let key = Self { pair, seed };
            seed.zeroize();
            Ok(key)
        }

        /// The 32-byte seed, borrowed: no copy leaves the key (it is wiped when the key drops).
        #[must_use]
        pub fn seed(&self) -> &[u8; 32] {
            &self.seed
        }

        /// The signature of `msg`.
        #[must_use]
        pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
            let mut out = [0_u8; 64];
            out.copy_from_slice(self.pair.sign(msg).as_ref());
            out
        }

        /// The public key.
        #[must_use]
        pub fn verifying_key(&self) -> VerifyingKey {
            let mut b = [0_u8; 32];
            b.copy_from_slice(self.pair.public_key().as_ref());
            VerifyingKey(b)
        }
    }

    /// An Ed25519 public key (32 bytes).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct VerifyingKey([u8; 32]);

    impl VerifyingKey {
        /// The key encoded as `bytes`: `Err(Invalid)` unless the encoding is canonical (`y < p`, and no sign
        /// bit on the two `x = 0` points). Small-order points decode (see `is_weak`), and so does a `y` with
        /// no point on the curve: it verifies nothing, so it fails closed at the first verify.
        pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
            if crate::weak::decodes(bytes) {
                Ok(Self(*bytes))
            } else {
                Err(Error::Invalid(
                    "Ed25519 public key is not a canonical curve point",
                ))
            }
        }

        /// The key in the DER `SubjectPublicKeyInfo` `spki` (RFC 8410): `Err(Invalid)` for
        /// anything else, the bare 32-byte key included.
        pub fn from_spki(spki: &[u8]) -> Result<Self, Error> {
            const WHAT: &str = "Ed25519 SubjectPublicKeyInfo";
            super::spki_key(&ED25519, spki, WHAT)?;
            // RFC 8410 §4: the one DER encoding is a 12-byte header and the 32-byte key, which
            // `spki_key` has just matched byte for byte against AWS-LC's own encoding.
            let raw: [u8; 32] = spki
                .get(12..)
                .and_then(|k| k.try_into().ok())
                .ok_or(Error::Invalid(WHAT))?;
            Self::from_bytes(&raw)
        }

        /// The encoded key.
        #[must_use]
        pub fn to_bytes(&self) -> [u8; 32] {
            self.0
        }

        /// Whether the key is a small-order point (any signature would verify under such a key).
        #[must_use]
        pub fn is_weak(&self) -> bool {
            crate::weak::is_small_order(&self.0)
        }

        /// Verify `sig` over `msg`: `Err(Mismatch)` for a bad signature, a weak key, a small-order
        /// `R` or a non-canonical `S`.
        pub fn verify_strict(&self, msg: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
            let mut r = [0_u8; 32];
            r.copy_from_slice(&sig[..32]);
            if self.is_weak() || crate::weak::is_small_order(&r) {
                return Err(Error::Mismatch);
            }
            UnparsedPublicKey::new(&ED25519, &self.0)
                .verify(msg, sig)
                .map_err(|_| Error::Mismatch)
        }
    }
}

/// ECDSA over P-256 with SHA-256. Keys are PKCS#8; public keys SEC 1 uncompressed (65 bytes);
/// signatures fixed `r || s` (64 bytes) or ASN.1 DER. Verification accepts both S forms.
pub mod ecdsa_p256 {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        EcdsaKeyPair, KeyPair as _, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING,
    };

    use crate::Error;

    /// A fresh P-256 key, PKCS#8 DER.
    pub fn generate_pkcs8() -> Result<Vec<u8>, Error> {
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .map(|d| d.as_ref().to_vec())
            .map_err(|_| Error::Rng)
    }

    /// A P-256 private key.
    pub struct KeyPair {
        fixed: EcdsaKeyPair,
        asn1: EcdsaKeyPair,
    }

    impl core::fmt::Debug for KeyPair {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("KeyPair").finish_non_exhaustive()
        }
    }

    /// The key in PKCS#8 DER `pkcs8`.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<KeyPair, Error> {
        let load = |alg| {
            EcdsaKeyPair::from_pkcs8(alg, pkcs8).map_err(|_| Error::Invalid("P-256 PKCS#8 key"))
        };
        Ok(KeyPair {
            fixed: load(&ECDSA_P256_SHA256_FIXED_SIGNING)?,
            asn1: load(&ECDSA_P256_SHA256_ASN1_SIGNING)?,
        })
    }

    impl KeyPair {
        /// A fixed `r || s` signature of `msg`.
        pub fn sign_fixed(&self, msg: &[u8]) -> Result<[u8; 64], Error> {
            let s = self
                .fixed
                .sign(&SystemRandom::new(), msg)
                .map_err(|_| Error::Rng)?;
            let mut out = [0_u8; 64];
            out.copy_from_slice(s.as_ref());
            Ok(out)
        }

        /// An ASN.1 DER signature of `msg`.
        pub fn sign_asn1(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
            self.asn1
                .sign(&SystemRandom::new(), msg)
                .map(|s| s.as_ref().to_vec())
                .map_err(|_| Error::Rng)
        }

        /// The SEC 1 uncompressed public key.
        #[must_use]
        pub fn public_key(&self) -> [u8; 65] {
            let mut out = [0_u8; 65];
            out.copy_from_slice(self.fixed.public_key().as_ref());
            out
        }
    }

    /// Verify a fixed `r || s` signature under the SEC 1 public key `pk`.
    pub fn verify_fixed(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pk)
            .verify(msg, sig)
            .map_err(|_| Error::Mismatch)
    }

    /// Verify an ASN.1 DER signature under the SEC 1 public key `pk`.
    pub fn verify_asn1(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pk)
            .verify(msg, sig)
            .map_err(|_| Error::Mismatch)
    }

    /// Verify a fixed `r || s` signature under the P-256 DER `SubjectPublicKeyInfo` `spki`:
    /// `Err(Invalid)` for a key that is not one (a bare point, another curve).
    pub fn verify_fixed_spki(spki: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        super::spki_key(&ECDSA_P256_SHA256_FIXED, spki, "P-256 SubjectPublicKeyInfo")?
            .verify_sig(msg, sig)
            .map_err(|_| Error::Mismatch)
    }
}

/// ECDSA over P-384 with SHA-384 (FIPS 186-5), verification only: SEC 1 uncompressed public keys
/// (97 bytes) or a DER `SubjectPublicKeyInfo`; signatures fixed `r || s` (96 bytes).
pub mod ecdsa_p384 {
    use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P384_SHA384_FIXED};

    use crate::Error;

    /// Verify a fixed `r || s` signature under the SEC 1 public key `pk`.
    pub fn verify_fixed(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, pk)
            .verify(msg, sig)
            .map_err(|_| Error::Mismatch)
    }

    /// Verify a fixed `r || s` signature under the P-384 DER `SubjectPublicKeyInfo` `spki`:
    /// `Err(Invalid)` for a key that is not one (a bare point, another curve).
    pub fn verify_fixed_spki(spki: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        super::spki_key(&ECDSA_P384_SHA384_FIXED, spki, "P-384 SubjectPublicKeyInfo")?
            .verify_sig(msg, sig)
            .map_err(|_| Error::Mismatch)
    }
}

/// RSA signatures (RFC 8017): PKCS#1 v1.5 and PSS verification for 2048..=8192-bit keys, and
/// PKCS#1 v1.5 SHA-256 signing (RS256).
pub mod rsa {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        self, RsaKeyPair, RsaParameters, RsaPublicKeyComponents, UnparsedPublicKey,
    };

    use crate::Error;

    /// An RSA verification scheme.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Scheme {
        /// RSASSA-PKCS1-v1_5 with SHA-256.
        Pkcs1Sha256,
        /// RSASSA-PKCS1-v1_5 with SHA-384.
        Pkcs1Sha384,
        /// RSASSA-PKCS1-v1_5 with SHA-512.
        Pkcs1Sha512,
        /// RSASSA-PSS with SHA-256.
        PssSha256,
        /// RSASSA-PSS with SHA-384.
        PssSha384,
        /// RSASSA-PSS with SHA-512.
        PssSha512,
    }

    fn params(s: Scheme) -> &'static RsaParameters {
        match s {
            Scheme::Pkcs1Sha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            Scheme::Pkcs1Sha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            Scheme::Pkcs1Sha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            Scheme::PssSha256 => &signature::RSA_PSS_2048_8192_SHA256,
            Scheme::PssSha384 => &signature::RSA_PSS_2048_8192_SHA384,
            Scheme::PssSha512 => &signature::RSA_PSS_2048_8192_SHA512,
        }
    }

    /// Verify `sig` over `msg` under the PKCS#1 `RSAPublicKey` DER `pk`.
    pub fn verify(scheme: Scheme, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        UnparsedPublicKey::new(params(scheme), pk)
            .verify(msg, sig)
            .map_err(|_| Error::Mismatch)
    }

    /// Verify `sig` over `msg` under the RSA DER `SubjectPublicKeyInfo` `spki`: `Err(Invalid)` for
    /// a key that is not one (a PKCS#1 `RSAPublicKey` included).
    pub fn verify_spki(scheme: Scheme, spki: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        super::spki_key(params(scheme), spki, "RSA SubjectPublicKeyInfo")?
            .verify_sig(msg, sig)
            .map_err(|_| Error::Mismatch)
    }

    /// Verify `sig` over `msg` under the key with big-endian modulus `n` and exponent `e`.
    pub fn verify_components(
        scheme: Scheme,
        n: &[u8],
        e: &[u8],
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), Error> {
        RsaPublicKeyComponents { n, e }
            .verify(params(scheme), msg, sig)
            .map_err(|_| Error::Mismatch)
    }

    /// Verify an RSASSA-PKCS1-v1_5 SHA-256 signature under the PKCS#1 DER `pk`.
    pub fn verify_pkcs1_sha256(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        verify(Scheme::Pkcs1Sha256, pk, msg, sig)
    }

    /// Verify an RSASSA-PSS SHA-256 signature under the PKCS#1 DER `pk`.
    pub fn verify_pss_sha256(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        verify(Scheme::PssSha256, pk, msg, sig)
    }

    /// An RSA private key (validated on load).
    pub struct SigningKey(RsaKeyPair);

    impl core::fmt::Debug for SigningKey {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("SigningKey").finish_non_exhaustive()
        }
    }

    impl SigningKey {
        /// The key in PKCS#8 DER `pkcs8`.
        pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
            RsaKeyPair::from_pkcs8(pkcs8)
                .map(Self)
                .map_err(|_| Error::Invalid("RSA PKCS#8 key"))
        }

        /// The modulus length in bytes (the signature length).
        #[must_use]
        pub fn modulus_len(&self) -> usize {
            self.0.public_modulus_len()
        }

        /// The PKCS#1 `RSAPublicKey` DER.
        #[must_use]
        pub fn public_key(&self) -> Vec<u8> {
            use aws_lc_rs::signature::KeyPair as _;
            self.0.public_key().as_ref().to_vec()
        }

        /// An RSASSA-PKCS1-v1_5 SHA-256 signature of `msg`.
        pub fn sign_pkcs1_sha256(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
            let mut sig = vec![0_u8; self.modulus_len()];
            self.0
                .sign(
                    &signature::RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    msg,
                    &mut sig,
                )
                .map_err(|_| Error::Invalid("RSA signing"))?;
            Ok(sig)
        }
    }

    impl SigningKey {
        /// An RSASSA-PSS SHA-256 signature (PS256) of `msg`.
        pub fn sign_pss_sha256(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
            let mut sig = vec![0_u8; self.modulus_len()];
            self.0
                .sign(
                    &signature::RSA_PSS_SHA256,
                    &SystemRandom::new(),
                    msg,
                    &mut sig,
                )
                .map_err(|_| Error::Invalid("RSA signing"))?;
            Ok(sig)
        }
    }

    /// An RSASSA-PKCS1-v1_5 SHA-256 signature of `msg` under the PKCS#8 DER key `pkcs8`.
    pub fn sign_pkcs1_sha256(pkcs8: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        SigningKey::from_pkcs8(pkcs8)?.sign_pkcs1_sha256(msg)
    }
}

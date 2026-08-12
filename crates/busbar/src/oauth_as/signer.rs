// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ES256 FOR THE AUTHORIZATION SERVER, over the `ring` busbar already links.
//!
//! ## Why this file exists rather than a cargo feature
//!
//! `oauth-as` 0.9.0 split its `jwt` feature in two: `jwt` is the JWS surface plus the
//! [`Es256Signer`] and [`Es256Verifier`] TRAITS with no arithmetic behind them, and `jwt-p256` is
//! the built-in backend over RustCrypto's `p256`. Enabling `jwt-p256` would add a COMPLETE SECOND
//! elliptic-curve implementation — measured at twenty packages against that crate's own tree — to a
//! process that already links `ring` as rustls's crypto provider and already signs RS256 with it
//! (`egress_auth::jwt_bearer`). Two implementations of one algorithm on a security-critical path is
//! the same defect class as two SSRF guards or two trust gates: the one nobody reviews is the one
//! that is wrong. So busbar implements the seam.
//!
//! The measured result is that `oauth-as` adds exactly ONE package to `Cargo.lock`: itself.
//!
//! ## The two shapes, and why they differ
//!
//! [`Es256Signer::sign`] is async because the private key is allowed not to be in this process — a
//! cloud KMS or an HSM is a network round trip. [`Es256Verifier::verify`] is sync because it holds
//! only public keys, so there is nothing to externalise. busbar's signer today is local, so its
//! `sign` completes without ever yielding; the async shape is the trait's, and honouring it costs
//! nothing.
//!
//! ## `public_jwk()` is cached at construction, and it must be
//!
//! The trait's `public_jwk` is SYNC, so an implementation has nowhere to await. [`RingEs256Key`]
//! therefore derives the coordinates once, in its constructor, from the key pair it just loaded —
//! which is also what makes the RFC 7517 JWKS document serialisable once rather than per request.
//!
//! ## The encoding trap this file is most likely to fall into
//!
//! RFC 7518 section 3.4 requires the FIXED-WIDTH `r || s` concatenation: 64 bytes, 32 per
//! coordinate, leading zeros KEPT. It is NOT the ASN.1 DER `SEQUENCE { r, s }` that OpenSSL and
//! nearly every KMS emit by default. `ring` has both, and they differ by one constant:
//! `ECDSA_P256_SHA256_FIXED_SIGNING` is the correct one and `ECDSA_P256_SHA256_ASN1_SIGNING` is the
//! wrong one, and a build that picks the wrong one COMPILES, since both produce bytes. The
//! `[u8; 64]` return refuses the wrong LENGTH and cannot refuse the wrong ENCODING; the thing that
//! catches it is `oauth_as::signer_conformance`, driven from
//! `tests/signer_conformance_tests.rs` against the RFC 7515 appendix A.3 vector, which is a value
//! neither half of busbar produced.

use base64::Engine as _;
use oauth_as::jwt::{Es256Signer, Es256Verifier, Jwk, PublicJwk, SignerError};
use ring::signature::KeyPair as _;

/// The URL-safe unpadded base64 alphabet every JOSE member uses.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A P-256 signing key held by this process, signing through `ring`.
///
/// Not `Clone`: a signing key is the one secret whose compromise forges every token this deployment
/// will ever issue, so it is held once, behind an `Arc` when it must be shared, and never copied
/// around by value.
pub(crate) struct RingEs256Key {
    pair: ring::signature::EcdsaKeyPair,
    rng: ring::rand::SystemRandom,
    /// The PUBLIC half, derived once at construction. See the module note on why this is cached.
    jwk: Jwk,
}

/// Why a signing key could not be loaded or generated. Carries no key material, ever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyError {
    /// `ring` refused the PKCS#8 document.
    NotAP256Key(String),
    /// The platform RNG failed, which is not a condition a token endpoint may paper over.
    Rng(String),
    /// `ring` handed back a public key that is not the 65-byte uncompressed SEC1 point. Unreachable
    /// on `ring` 0.17 for a P-256 key and checked anyway: the derivation below indexes into it, and
    /// an index that is right by assumption is a panic waiting for a version bump.
    MalformedPublicKey { bytes: usize },
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::NotAP256Key(e) => write!(
                f,
                "the authorization server's signing key is not a PKCS#8 P-256 private key: {e}"
            ),
            KeyError::Rng(e) => write!(f, "the platform random number generator failed: {e}"),
            KeyError::MalformedPublicKey { bytes } => write!(
                f,
                "ring returned a {bytes}-byte public key where an uncompressed P-256 point is 65"
            ),
        }
    }
}

impl std::error::Error for KeyError {}

impl RingEs256Key {
    /// Load a key from a PKCS#8 v1 DER document — what `openssl pkcs8`, a KMS export and
    /// [`RingEs256Key::generate_pkcs8`] all produce.
    pub(crate) fn from_pkcs8_der(kid: impl Into<String>, der: &[u8]) -> Result<Self, KeyError> {
        let rng = ring::rand::SystemRandom::new();
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            der,
            &rng,
        )
        .map_err(|e| KeyError::NotAP256Key(e.to_string()))?;
        let jwk = public_jwk_of(&pair, kid.into())?;
        Ok(Self { pair, rng, jwk })
    }

    /// A fresh key as a PKCS#8 DER document, for a deployment that has not been given one.
    ///
    /// Returned as BYTES rather than as a loaded key so that the caller has to decide, in one
    /// visible place, whether it is persisting it. An authorization server whose key is regenerated
    /// on every boot invalidates every token it ever issued, and that is a property an operator must
    /// choose rather than inherit.
    pub(crate) fn generate_pkcs8() -> Result<Vec<u8>, KeyError> {
        let rng = ring::rand::SystemRandom::new();
        ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .map(|doc| doc.as_ref().to_vec())
        .map_err(|e| KeyError::Rng(e.to_string()))
    }
}

/// The RFC 7517 public half of a loaded key pair.
///
/// `ring` hands back the uncompressed SEC1 point of RFC 5480 section 2.2: `0x04 || X || Y`, 65
/// bytes for P-256. RFC 7518 section 6.2.1.2 wants the two coordinates separately, base64url, each
/// exactly 32 bytes with leading zeros kept — which is what slicing the point gives, and is why
/// nothing here trims.
fn public_jwk_of(pair: &ring::signature::EcdsaKeyPair, kid: String) -> Result<Jwk, KeyError> {
    let point = pair.public_key().as_ref();
    if point.len() != 65 || point[0] != 0x04 {
        return Err(KeyError::MalformedPublicKey { bytes: point.len() });
    }
    Ok(Jwk {
        kty: "EC",
        crv: "P-256",
        x: B64.encode(&point[1..33]),
        y: B64.encode(&point[33..65]),
        kid,
        use_: "sig",
        alg: "ES256",
    })
}

impl Es256Signer for RingEs256Key {
    fn sign(
        &self,
        signing_input: &[u8],
    ) -> impl std::future::Future<Output = Result<[u8; 64], SignerError>> + Send {
        // Computed EAGERLY, before the future is constructed: this signer is local, so there is
        // nothing to await, and pretending otherwise would put a suspension point on the token
        // endpoint's hot path for no gain. The `async move` below is the trait's shape, not work.
        //
        // `ECDSA_P256_SHA256_FIXED_SIGNING` — see the module note. `sign` hashes `signing_input`
        // itself, because ES256 IS ECDSA/P-256/SHA-256; pre-hashing here would sign the digest of a
        // digest and every signature would be rejected by every client.
        let signed = self
            .pair
            .sign(&self.rng, signing_input)
            .map_err(|_| SignerError::new("the platform random number generator failed"))
            .and_then(|sig| {
                <[u8; 64]>::try_from(sig.as_ref()).map_err(|_| {
                    SignerError::new(
                        "ring produced a signature that is not the 64-byte fixed-width r||s form",
                    )
                })
            });
        async move { signed }
    }

    fn public_jwk(&self) -> Jwk {
        self.jwk.clone()
    }
}

/// ES256 VERIFICATION over `ring`, for the credentials a client signs (RFC 9449 DPoP proofs,
/// RFC 9101 request objects, RFC 7523 client assertions).
///
/// A unit struct, because verification holds no state: every key arrives with the credential.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RingEs256Verifier;

impl Es256Verifier for RingEs256Verifier {
    /// `true` means, and may only mean, that `signature` is a valid ES256 signature over exactly
    /// `signing_input` under exactly `key`.
    ///
    /// Three refusals are load bearing and each is a named attack:
    ///
    /// * **Length.** Only the 64-byte fixed-width `r || s` is accepted. Accepting the ASN.1 DER
    ///   form as well would be signature malleability — two encodings of one signature — and a
    ///   value a deployment recorded as unique would stop being unique. `ECDSA_P256_SHA256_FIXED`
    ///   (not `..._ASN1`) is what enforces this, and the explicit length check in front of it makes
    ///   the refusal ours rather than a library's.
    /// * **On the curve.** `key` arrived from a client. `ring`'s `verify` rejects a point that is
    ///   not on P-256, which is exactly what an invalid-curve attack needs to find missing.
    /// * **One `false`.** A malformed key, a wrong-length signature and a signature that simply
    ///   does not verify all return `false`. Distinguishing them would invite a caller to treat one
    ///   as recoverable, and there is no recoverable failure to check a signature.
    fn verify(&self, key: &PublicJwk, signing_input: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let (Ok(x), Ok(y)) = (B64.decode(key.x()), B64.decode(key.y())) else {
            return false;
        };
        if x.len() != 32 || y.len() != 32 {
            return false;
        }
        // The uncompressed SEC1 point `ring` verifies against, rebuilt from the coordinates. 65
        // bytes exactly, so a coordinate that decoded short cannot silently shift the other one.
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(&x);
        point[33..65].copy_from_slice(&y);
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            point.as_slice(),
        )
        .verify(signing_input, signature)
        .is_ok()
    }
}

#[cfg(test)]
#[path = "tests/signer_tests.rs"]
mod signer_tests;

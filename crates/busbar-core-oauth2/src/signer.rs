// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use base64::Engine as _;
use oauth_as::jwt::{EcCurve, Jwk, JwsAlg, JwsSignature, JwsSigner, JwsVerifier, SignerError};
use ring::signature::KeyPair as _;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub(crate) struct RingEs256Key {
    pair: ring::signature::EcdsaKeyPair,
    rng: ring::rand::SystemRandom,

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

fn public_jwk_of(pair: &ring::signature::EcdsaKeyPair, kid: String) -> Result<Jwk, KeyError> {
    let point = pair.public_key().as_ref();
    if point.len() != 65 || point[0] != 0x04 {
        return Err(KeyError::MalformedPublicKey { bytes: point.len() });
    }

    Ok(Jwk::Ec {
        crv: EcCurve::P256,
        x: B64.encode(&point[1..33]),
        y: B64.encode(&point[33..65]),
        kid: Some(kid),
    })
}

impl JwsSigner for RingEs256Key {
    fn alg(&self) -> JwsAlg {
        JwsAlg::Es256
    }

    fn sign(
        &self,
        signing_input: &[u8],
    ) -> impl std::future::Future<Output = Result<JwsSignature, SignerError>> + Send {
        let signed = self
            .pair
            .sign(&self.rng, signing_input)
            .map_err(|_| SignerError::new("the platform random number generator failed"))
            .and_then(|sig| {
                <[u8; 64]>::try_from(sig.as_ref())
                    .map(JwsSignature::Es256)
                    .map_err(|_| {
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

impl JwsVerifier for RingEs256Verifier {
    fn alg(&self) -> JwsAlg {
        JwsAlg::Es256
    }

    fn verify(&self, key: &Jwk, signing_input: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let Jwk::Ec {
            crv: EcCurve::P256,
            x,
            y,
            ..
        } = key
        else {
            return false;
        };
        let (Ok(x), Ok(y)) = (B64.decode(x), B64.decode(y)) else {
            return false;
        };
        if x.len() != 32 || y.len() != 32 {
            return false;
        }

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

/// The PS256 verifier over `ring` (RSASSA-PSS, SHA-256, MGF1-SHA-256, RFC 7518 s3.5): FAPI 2.0
/// s5.4.1's other algorithm, for a client provisioned with an RSA key and for its DPoP proofs.
/// Installed into the PS256 slot only, so an RS256 credential finds no verifier and is refused.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RingPs256Verifier;

impl JwsVerifier for RingPs256Verifier {
    fn alg(&self) -> JwsAlg {
        JwsAlg::Ps256
    }

    fn verify(&self, key: &Jwk, signing_input: &[u8], signature: &[u8]) -> bool {
        let Jwk::Rsa { n, e, .. } = key else {
            return false;
        };
        let (Ok(n), Ok(e)) = (B64.decode(n), B64.decode(e)) else {
            return false;
        };
        ring::signature::RsaPublicKeyComponents { n, e }
            .verify(
                &ring::signature::RSA_PSS_2048_8192_SHA256,
                signing_input,
                signature,
            )
            .is_ok()
    }
}

#[cfg(test)]
#[path = "tests/signer_tests.rs"]
mod signer_tests;

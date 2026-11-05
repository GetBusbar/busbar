// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit cryptographic services for release verification. An unavailable service is never an
//! invalid signature and must abort the enclosing operation. Selecting a provider does not certify
//! that provider or the deployment. Native implementations own key validation and strict signature
//! acceptance; they must reject weak/noncanonical Ed25519 keys and preserve strict mixed-order
//! signature semantics, and use SHA-256 with ASN.1 DER signatures for P-256.

use crate::release_trust::ReleaseKey;

#[derive(Debug, Clone, Copy)]
pub enum PublicKey<'a> {
    Ed25519(&'a [u8; 32]),
    P256(&'a [u8; 65]),
}

/// Redacted service failure, distinct from an ordinary invalid key or signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoUnavailable;

impl std::fmt::Display for CryptoUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("release cryptographic service unavailable")
    }
}
impl std::error::Error for CryptoUnavailable {}

pub trait ReleaseCrypto {
    fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32], CryptoUnavailable>;
    fn validate_public_key(&self, key: PublicKey<'_>) -> Result<bool, CryptoUnavailable>;
    fn verify_ed25519_strict(
        &self,
        key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<bool, CryptoUnavailable>;
    fn verify_p256_sha256_asn1(
        &self,
        key: &[u8; 65],
        message: &[u8],
        signature_der: &[u8],
    ) -> Result<bool, CryptoUnavailable>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WithCryptoError<E> {
    Rejected(E),
    Unavailable(CryptoUnavailable),
}
impl<E> From<CryptoUnavailable> for WithCryptoError<E> {
    fn from(error: CryptoUnavailable) -> Self {
        Self::Unavailable(error)
    }
}
impl From<String> for WithCryptoError<String> {
    fn from(error: String) -> Self {
        Self::Rejected(error)
    }
}
impl From<&str> for WithCryptoError<String> {
    fn from(error: &str) -> Self {
        Self::Rejected(error.to_string())
    }
}
impl<E: std::fmt::Display> std::fmt::Display for WithCryptoError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(e) => e.fmt(f),
            Self::Unavailable(e) => e.fmt(f),
        }
    }
}
impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for WithCryptoError<E> {}
impl<E> WithCryptoError<E> {
    pub fn map_rejection<F>(self, f: impl FnOnce(E) -> F) -> WithCryptoError<F> {
        match self {
            Self::Rejected(e) => WithCryptoError::Rejected(f(e)),
            Self::Unavailable(e) => WithCryptoError::Unavailable(e),
        }
    }
}

/// Separate an ordinary policy refusal from a service failure before applying policy opt-ins.
pub(crate) fn policy_result<T, E>(
    result: Result<T, WithCryptoError<E>>,
) -> Result<Result<T, E>, CryptoUnavailable> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(WithCryptoError::Rejected(error)) => Ok(Err(error)),
        Err(WithCryptoError::Unavailable(error)) => Err(error),
    }
}
pub(crate) fn standard_result<T, E>(result: Result<T, WithCryptoError<E>>) -> Result<T, E> {
    policy_result(result).expect("StandardCrypto has no unavailable services")
}

/// Raw key storage: decoding this type never constructs a Dalek key. Public construction is
/// allowed, so every verification validates keys with the selected provider as well.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawReleaseKey {
    Ed25519([u8; 32]),
    P256([u8; 65]),
}
impl RawReleaseKey {
    pub fn public_key(&self) -> PublicKey<'_> {
        match self {
            Self::Ed25519(k) => PublicKey::Ed25519(k),
            Self::P256(k) => PublicKey::P256(k),
        }
    }
    pub fn retired_reason(&self) -> Option<&'static str> {
        let Self::Ed25519(key) = self else {
            return None;
        };
        crate::sign::RETIRED_RELEASE_KEYS
            .iter()
            .find_map(|(encoded, why)| {
                hex::decode(encoded)
                    .ok()
                    .filter(|bytes| bytes.as_slice() == key)
                    .map(|_| *why)
            })
    }
    pub(crate) fn into_standard(self) -> ReleaseKey {
        match self {
            Self::Ed25519(k) => ReleaseKey::Ed25519(
                ed25519_dalek::VerifyingKey::from_bytes(&k)
                    .expect("key already validated by StandardCrypto"),
            ),
            Self::P256(k) => ReleaseKey::P256(k),
        }
    }
}
impl From<&ReleaseKey> for RawReleaseKey {
    fn from(key: &ReleaseKey) -> Self {
        match key {
            ReleaseKey::Ed25519(k) => Self::Ed25519(*k.as_bytes()),
            ReleaseKey::P256(k) => Self::P256(*k),
        }
    }
}

/// The existing implementation. Its key parsing retains the historical Standard behavior;
/// native providers must apply their own documented canonical/nonweak key floor.
#[derive(Debug, Clone, Copy, Default)]
pub struct StandardCrypto;
impl ReleaseCrypto for StandardCrypto {
    fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32], CryptoUnavailable> {
        Ok(busbar_contract::abi::sdk::digest::sha256(bytes))
    }
    fn validate_public_key(&self, key: PublicKey<'_>) -> Result<bool, CryptoUnavailable> {
        Ok(match key {
            PublicKey::Ed25519(k) => {
                ed25519_dalek::VerifyingKey::from_bytes(k).is_ok_and(|key| !key.is_weak())
            }
            // Historically the Standard P-256 parser validates SEC1 syntax; ring checks the
            // curve point when verifying the signature. Preserve that behavior here.
            PublicKey::P256(k) => k[0] == 4,
        })
    }
    fn verify_ed25519_strict(
        &self,
        key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<bool, CryptoUnavailable> {
        Ok(
            ed25519_dalek::VerifyingKey::from_bytes(key).is_ok_and(|key| {
                key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
                    .is_ok()
            }),
        )
    }
    fn verify_p256_sha256_asn1(
        &self,
        key: &[u8; 65],
        message: &[u8],
        signature_der: &[u8],
    ) -> Result<bool, CryptoUnavailable> {
        Ok(
            ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, key)
                .verify(message, signature_der)
                .is_ok(),
        )
    }
}

#[cfg(test)]
#[path = "tests/release_crypto_tests.rs"]
mod tests;

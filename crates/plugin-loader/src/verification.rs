// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One verifier, with explicit authority around every cryptographic primitive.
use crate::{release_trust as release, sign};
use busbar_contract::crypto::verification::{Authority, Context, Failure};

/// Policy/input refusal is distinct from unavailable verification authority or provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError<E> {
    /// The proof, input, or trust policy refused the artifact.
    Refused(E),
    /// Verification could not be performed. No trust opt-in admits this outcome.
    Unavailable(Failure),
}
impl<E> From<E> for VerificationError<E> {
    fn from(error: E) -> Self {
        Self::Refused(error)
    }
}
impl From<&str> for VerificationError<String> {
    fn from(error: &str) -> Self {
        Self::Refused(error.to_string())
    }
}
impl<E> VerificationError<E> {
    pub(crate) fn map_refused<F>(self, map: impl FnOnce(E) -> F) -> VerificationError<F> {
        match self {
            Self::Refused(error) => VerificationError::Refused(map(error)),
            Self::Unavailable(error) => VerificationError::Unavailable(error),
        }
    }
}
impl<E: std::fmt::Display> std::fmt::Display for VerificationError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(error) => error.fmt(f),
            Self::Unavailable(error) => error.fmt(f),
        }
    }
}
impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for VerificationError<E> {}

/// Result that preserves operational unavailability separately from a proof refusal.
pub type Result<T, E = String> = std::result::Result<T, VerificationError<E>>;

/// Borrowed authority for the canonical release and publisher verification implementation.
#[derive(Debug, Clone, Copy)]
pub struct Verifier<'a> {
    pub(crate) crypto: Context<'a>,
}
impl<'a> Verifier<'a> {
    /// Bind current caller authority; cryptography remains compile-selected.
    pub fn new(authority: &'a dyn Authority) -> Self {
        Self {
            crypto: Context::new(authority),
        }
    }
    /// Explicit software caller policy with no additional authority restriction.
    pub fn unrestricted() -> Self {
        Self {
            crypto: Context::unrestricted(),
        }
    }
    /// Checked SHA-256, in the existing lowercase hexadecimal encoding.
    pub fn sha256_hex(&self, bytes: &[u8]) -> Result<String> {
        self.crypto
            .sha256(bytes)
            .map(hex::encode)
            .map_err(VerificationError::Unavailable)
    }
    /// Parse and validate configured roots under current authority.
    pub fn parse_release_keys(&self, spec: &str) -> Result<Vec<sign::FirstPartyKey>> {
        sign::parse_release_keys_guarded(self, spec)
    }
    /// Parse and validate an Ed25519 public key under current authority.
    pub fn public_key_from_hex(&self, text: &str) -> Result<sign::VerifyingKey> {
        sign::public_key_from_hex_guarded(self, text)
    }
    /// Compute the canonical release-key identity under current authority.
    pub fn key_id(&self, key: &release::ReleaseKey) -> Result<String> {
        let bytes = release::wire::canonical(&release::wire::key_object(key))?;
        self.sha256_hex(&bytes)
    }
    /// Read a keys document, including validated keys and checked key IDs.
    pub fn read_keys(&self, bytes: &[u8]) -> Result<release::Signed<release::KeysDoc>> {
        release::wire::read_keys_guarded(self, bytes)
    }
    /// Verify the complete release chain against the caller's explicit subject and checks.
    pub fn verify_release(
        &self,
        roots: &[sign::FirstPartyKey],
        seal: release::Seal<'_>,
        subject: release::Subject<'_>,
        checks: release::Checks,
    ) -> Result<release::Verified, release::SealRefusal> {
        release::verify_release_guarded(self, roots, seal, subject, checks)
    }
    /// Verify exact artifact bytes and find their authenticated first-party root.
    pub fn first_party_signer_for<'k>(
        &self,
        manifest: &sign::Manifest,
        bytes: &[u8],
        roots: &'k [sign::FirstPartyKey],
        checks: release::Checks,
        target: &str,
    ) -> Result<&'k sign::FirstPartyKey, sign::FirstPartyUnverified> {
        sign::first_party_signer_evidence(self, manifest, bytes, roots, checks, target)
            .map(|(root, _)| root)
    }
    /// Check structural and exact-byte integrity requirements.
    pub fn validate_structure(
        &self,
        manifest: &sign::Manifest,
        bytes: &[u8],
        supported_abi: &dyn Fn(&str) -> Option<u32>,
        host_identity: &str,
    ) -> Result<()> {
        sign::validate_structure_guarded(self, manifest, bytes, supported_abi, host_identity)
    }
    /// Evaluate trust, keeping operational failures outside every opt-in allowance.
    pub fn evaluate(
        &self,
        bytes: &[u8],
        manifest: &sign::Manifest,
        policy: &sign::TrustPolicy,
    ) -> Result<sign::Verdict, sign::Rejected> {
        self.evaluate_with_verification(bytes, manifest, policy)
            .map(|(verdict, _)| verdict)
    }
    /// Evaluate trust and retain the authenticated release evidence.
    pub fn evaluate_with_verification(
        &self,
        bytes: &[u8],
        manifest: &sign::Manifest,
        policy: &sign::TrustPolicy,
    ) -> Result<(sign::Verdict, sign::Verification), sign::Rejected> {
        sign::evaluate_against_with_evidence(
            self,
            bytes,
            manifest,
            policy,
            sign::RETIRED_RELEASE_KEYS,
        )
    }
    pub(crate) fn verify(
        &self,
        key: &release::ReleaseKey,
        message: &[u8],
        signature: &[u8],
    ) -> std::result::Result<bool, Failure> {
        let result = match key {
            release::ReleaseKey::Ed25519(key) => {
                let Ok(signature) = <&[u8; 64]>::try_from(signature) else {
                    return Ok(false);
                };
                self.crypto.verify_ed25519(&key.key, message, signature)
            }
            release::ReleaseKey::P256(key) => self.crypto.verify_p256(key, message, signature),
        };
        match result {
            Ok(()) => Ok(true),
            Err(error) if !error.is_unavailable() => Ok(false),
            Err(error) => Err(error),
        }
    }
    pub(crate) fn primitive<T>(&self, result: std::result::Result<T, Failure>) -> Result<T> {
        result.map_err(|error| {
            if error.is_unavailable() {
                VerificationError::Unavailable(error)
            } else {
                VerificationError::Refused(error.to_string())
            }
        })
    }
}

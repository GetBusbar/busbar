// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Authority authorizes operations; only the compile-selected backend performs them.
use crate::{ed25519, map, Error};
use busbar_crypto_backend as backend;

/// The primitive whose authority is being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// SHA-256 digest.
    Sha256,
    /// Ed25519 point validation.
    Ed25519Validate,
    /// Ed25519 key import.
    Ed25519Import,
    /// Strict Ed25519 signature verification.
    Ed25519Verify,
    /// P-256 point validation.
    P256Validate,
    /// P-256 SHA-256 ASN.1 signature verification.
    P256Verify,
}

/// The authority checkpoint around a primitive operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Before dispatch to the backend.
    Before,
    /// After completion, including a failed backend operation.
    After,
}

/// Current authority is unavailable; this is not invalid cryptographic proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unavailable;

/// Revocable permission to use the compile-selected cryptographic implementation.
pub trait Authority {
    /// Check current authority without performing the cryptographic operation.
    fn check(&self, operation: Operation, phase: Phase) -> Result<(), Unavailable>;
}

/// A primitive failure, preserving provider failure separately from invalid proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// A before/after authority check refused the operation or its result.
    AuthorityUnavailable,
    /// The selected backend's exact failure.
    Provider(Error),
}

impl Failure {
    /// Whether verification must stop instead of considering another signature.
    #[must_use]
    pub fn is_unavailable(self) -> bool {
        !matches!(self, Self::Provider(Error::Invalid(_) | Error::Mismatch))
    }
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AuthorityUnavailable => f.write_str("verification authority unavailable"),
            Self::Provider(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for Failure {}

struct Unrestricted;
impl Authority for Unrestricted {
    fn check(&self, _: Operation, _: Phase) -> Result<(), Unavailable> {
        Ok(())
    }
}
static UNRESTRICTED: Unrestricted = Unrestricted;

/// Borrowed authority applied separately to each primitive. It supplies no crypto implementation.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    authority: &'a dyn Authority,
}
impl core::fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Context").finish_non_exhaustive()
    }
}

impl<'a> Context<'a> {
    /// Bind caller-owned authority; this does not cache an admission decision.
    #[must_use]
    pub fn new(authority: &'a dyn Authority) -> Self {
        Self { authority }
    }

    /// Explicitly select callers with no additional runtime authority policy.
    #[must_use]
    pub fn unrestricted() -> Self {
        Self::new(&UNRESTRICTED)
    }

    fn guarded<T>(
        &self,
        operation: Operation,
        perform: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Failure> {
        self.authority
            .check(operation, Phase::Before)
            .map_err(|_| Failure::AuthorityUnavailable)?;
        let result = perform();
        self.authority
            .check(operation, Phase::After)
            .map_err(|_| Failure::AuthorityUnavailable)?;
        result.map_err(Failure::Provider)
    }

    /// SHA-256 with provider failures and before/after authority preserved.
    pub fn sha256(&self, bytes: &[u8]) -> Result<[u8; 32], Failure> {
        self.guarded(Operation::Sha256, || {
            backend::sha256_checked(bytes).map_err(map)
        })
    }

    /// Validate an Ed25519 public point.
    pub fn validate_ed25519(&self, bytes: &[u8; 32]) -> Result<(), Failure> {
        self.guarded(Operation::Ed25519Validate, || {
            ed25519::validate_public_key(bytes)
        })
    }

    /// Import an Ed25519 key without caching permission for subsequent operations.
    pub fn import_ed25519(&self, bytes: &[u8; 32]) -> Result<ed25519::VerifyingKey, Failure> {
        self.guarded(Operation::Ed25519Import, || {
            ed25519::VerifyingKey::from_bytes(bytes)
        })
    }

    /// Strictly verify Ed25519 under current authority.
    pub fn verify_ed25519(
        &self,
        key: &ed25519::VerifyingKey,
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), Failure> {
        self.guarded(Operation::Ed25519Verify, || {
            key.verify_strict(message, signature)
        })
    }

    /// Validate an exact uncompressed P-256 point using the selected backend.
    pub fn validate_p256(&self, key: &[u8; 65]) -> Result<(), Failure> {
        self.guarded(Operation::P256Validate, || {
            backend::ecdsa_p256::validate_public_key(key).map_err(map)
        })
    }

    /// Verify a P-256 SHA-256 ASN.1 signature under current authority.
    pub fn verify_p256(
        &self,
        key: &[u8; 65],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Failure> {
        self.guarded(Operation::P256Verify, || {
            crate::ecdsa_p256::verify_asn1(key, message, signature)
        })
    }
}

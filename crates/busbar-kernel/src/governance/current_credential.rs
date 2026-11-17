// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Retained signed credential authority for later checks against current hydrated policy.
//! This is credential evidence only; the auth owner must bind it to the original request.

use super::revocation::RevocationSync;
use super::signing::VerifiedToken;
use super::{GovState, VirtualKey};
use std::sync::Arc;

/// The actual branch that refused the retained credential. These are cached local decisions,
/// not backend failures; no refresh or verifier invocation runs while checking current standing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentCredentialRefusal {
    ForeignAuthority,
    /// No signing material is configured. Existing token refusal calls this credential_invalid,
    /// not a backend outage or a verifier that failed to produce a verdict.
    SigningUnavailable,
    Expired,
    AudienceMismatch,
    UntrustedSigner,
    Revoked,
    SubjectHeld,
    MissingKey,
    KeyExpired,
    DisabledKey,
    RotatedKey,
    DeletedKey,
}

impl CurrentCredentialRefusal {
    /// Use the existing native auth mapping. A foreign ownership join is an internal binding
    /// error, not an authentication judgment about a credential from this authority domain.
    pub fn auth_code(self) -> Option<u32> {
        use busbar_plugin_abi::auth::{BAD_CREDENTIAL, EXPIRED};
        match self {
            Self::ForeignAuthority => None,
            Self::Expired | Self::KeyExpired => Some(EXPIRED),
            Self::SigningUnavailable
            | Self::AudienceMismatch
            | Self::UntrustedSigner
            | Self::Revoked
            | Self::SubjectHeld
            | Self::MissingKey
            | Self::DisabledKey
            | Self::RotatedKey
            | Self::DeletedKey => Some(BAD_CREDENTIAL),
        }
    }
}

/// The exact signature, original key and identity-cache domain established at authentication.
/// There is no constructor from a key, subject, claims or caller-supplied verification result.
pub struct VerifiedKeyAuthority {
    token: VerifiedToken,
    original: Arc<VirtualKey>,
    domain: Arc<RevocationSync>,
}

impl VerifiedKeyAuthority {
    pub fn original_key(&self) -> &Arc<VirtualKey> {
        &self.original
    }

    pub(super) fn into_original_key(self) -> Arc<VirtualKey> {
        self.original
    }

    /// Preserve the exact identity-cache owner when joining the original request to money.
    pub(crate) fn belongs_to(&self, governance: &GovState) -> bool {
        Arc::ptr_eq(&self.domain, &governance.denylist)
    }

    /// Read current standing without verification, refresh, replay or monetary admission.
    /// The caller supplies the audience from its actual current route, and must separately
    /// establish the original request and current target binding before using this result.
    pub(crate) fn current_key(
        &self,
        current: &GovState,
        now: u64,
        expected_aud: Option<&str>,
    ) -> Result<Arc<VirtualKey>, CurrentCredentialRefusal> {
        if !self.belongs_to(current) {
            return Err(CurrentCredentialRefusal::ForeignAuthority);
        }
        let material = current
            .signing_material()
            .ok_or(CurrentCredentialRefusal::SigningUnavailable)?;
        self.token
            .check_current(&material.verifier, now, expected_aud)?;
        let key = current.standing_key_cached(self.token.claims(), now)?;
        if key.deleted_at.is_some() {
            return Err(CurrentCredentialRefusal::DeletedKey);
        }
        Ok(key)
    }
}

impl GovState {
    /// Schedule the existing bounded/coalesced refresh before entering the publication gate.
    pub(crate) fn refresh_current_credential(&self, now: u64) {
        self.denylist.refresh_if_stale(now);
    }

    /// Execute the existing signed verification and standing policy once, retaining its proof.
    /// The returned original key is the one to install in the original request admission.
    pub fn verify_token_authority(
        &self,
        token: &str,
        now: u64,
        expected_aud: Option<&str>,
    ) -> Option<VerifiedKeyAuthority> {
        let material = self.signing_material()?;
        let token = match material.verifier.verify_retained(token, now, expected_aud) {
            Ok(token) => token,
            Err(error) => {
                tracing::debug!(reason = %error, "signed-token verify rejected");
                return None;
            }
        };
        let original = self.standing_key(token.claims(), now)?;
        Some(VerifiedKeyAuthority {
            token,
            original,
            domain: Arc::clone(&self.denylist),
        })
    }
}

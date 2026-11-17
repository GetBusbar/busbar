// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Retained signed credential authority for later checks against current hydrated policy.
//! This is credential evidence only; the auth owner must bind it to the original request.

use super::revocation::RevocationSync;
use super::signing::VerifiedToken;
use super::{GovState, VirtualKey};
use std::sync::Arc;

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

    /// Read current standing without verification, refresh, replay or monetary admission.
    /// The caller supplies the audience from its actual current route, and must separately
    /// establish the original request and current target binding before using this result.
    pub(crate) fn current_key(
        &self,
        current: &GovState,
        now: u64,
        expected_aud: Option<&str>,
    ) -> Option<Arc<VirtualKey>> {
        if !Arc::ptr_eq(&self.domain, &current.denylist) {
            return None;
        }
        let material = current.signing_material()?;
        if !self.token.valid_with(&material.verifier, now, expected_aud) {
            return None;
        }
        current
            .standing_key_cached(self.token.claims(), now)
            .filter(|key| key.deleted_at.is_none())
    }
}

impl GovState {
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

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CALLER REFERENCE a plane may attribute a request with, in place of the principal.

use busbar_contract::crypto::{self, HmacSha256Key};

/// The HKDF label the reference key is expanded under.
pub const LABEL: &[u8] = b"busbar caller-ref v1";

/// The key caller references are computed under. No `Debug`, no `Clone`, no accessor.
pub struct CallerRefKey(HmacSha256Key);

impl std::fmt::Debug for CallerRefKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallerRefKey(..)")
    }
}

/// THE ONE SIGNING-KEY DERIVATION: an HMAC-SHA256 key expanded from the node's signing-key
/// material under `label` (HKDF-SHA256, empty salt). Every node that resolves the same signing key
/// derives the same key for the same label; distinct labels give independent keys.
#[must_use]
pub fn derive_hmac_key(material: &[u8], label: &[u8]) -> HmacSha256Key {
    let mut okm = [0_u8; 32];
    crypto::hkdf_sha256(&[], material, label, &mut okm)
        .expect("one HMAC-SHA256 key length is within HKDF-SHA256's output bound");
    // PANIC: `okm` is a fixed 32-byte derived key, never short, so the backend cannot refuse it.
    HmacSha256Key::new(&okm).expect("a 32-byte HMAC-SHA256 key is always accepted")
}

impl CallerRefKey {
    /// Derive the key from the node's signing-key material.
    #[must_use]
    pub fn derive(material: &[u8]) -> Self {
        CallerRefKey(derive_hmac_key(material, LABEL))
    }

    /// The reference for principal `principal_id`: 64 lowercase hex characters.
    #[must_use]
    pub fn caller_ref(&self, principal_id: &str) -> String {
        hex::encode(self.0.sign(principal_id.as_bytes()))
    }
}

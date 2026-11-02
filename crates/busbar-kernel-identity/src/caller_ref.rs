// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CALLER REFERENCE a plane may attribute a request with, in place of the principal.

use ring::{hkdf, hmac};

/// The HKDF label the reference key is expanded under.
pub const LABEL: &[u8] = b"busbar caller-ref v1";

/// The key caller references are computed under. No `Debug`, no `Clone`, no accessor.
pub struct CallerRefKey(hmac::Key);

impl std::fmt::Debug for CallerRefKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallerRefKey(..)")
    }
}

impl CallerRefKey {
    /// Derive the key from the node's signing-key material.
    #[must_use]
    pub fn derive(material: &[u8]) -> Self {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(material);
        let okm = prk
            .expand(&[LABEL], hmac::HMAC_SHA256)
            .expect("one HMAC-SHA256 key length is within HKDF-SHA256's output bound");
        CallerRefKey(hmac::Key::from(okm))
    }

    /// The reference for principal `principal_id`: 64 lowercase hex characters.
    #[must_use]
    pub fn caller_ref(&self, principal_id: &str) -> String {
        hex::encode(hmac::sign(&self.0, principal_id.as_bytes()).as_ref())
    }
}

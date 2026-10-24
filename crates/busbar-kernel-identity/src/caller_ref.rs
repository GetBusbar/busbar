// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CALLER REFERENCE a plane may attribute a request with, in place of the principal.
//!
//! A plane never sees the principal. Where its far end wants a stable per-caller identifier (an
//! abuse-attribution header, say), the kernel lends it a reference instead: an HMAC-SHA256 of the
//! principal id under a key derived from the node's signing-key material, in lowercase hex. The same
//! principal always gets the same reference, on every node that shares the key material and across
//! restarts, and the reference does not reveal the principal.
//!
//! The key is HKDF-SHA256 over the material, expanded under the label [`LABEL`]. The material is
//! the caller's to supply and to dispose of. This type keeps only the derived key and never prints it.

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

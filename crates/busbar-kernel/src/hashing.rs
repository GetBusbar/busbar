// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHA-256 for the kernel's framed preimages, through the crypto facade (`busbar_contract::crypto`).
//!
//! A thin adapter: it takes anything that is `AsRef<[u8]>` (the call sites feed it arrays,
//! integers' byte forms, `Vec`s and borrowed slices) and answers the 32-byte digest. It holds no
//! primitive; every byte goes to `crypto::Sha256`.

use busbar_contract::crypto;

/// A streaming SHA-256.
#[derive(Debug, Default)]
pub(crate) struct Sha256(crypto::Sha256);

impl Sha256 {
    /// A fresh hasher.
    pub(crate) fn new() -> Self {
        Self(crypto::Sha256::new())
    }

    /// Absorb `data`.
    pub(crate) fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    /// The digest of everything absorbed.
    pub(crate) fn finalize(self) -> [u8; 32] {
        self.0.finish()
    }

    /// The digest of everything absorbed, when that includes secret values: typed so it is never
    /// printed and only compared in constant time (PM ruling 2026-11-17).
    pub(crate) fn finalize_secret(self) -> SecretDigest {
        SecretDigest(self.0.finish())
    }

    /// The digest of `data` in one call.
    pub(crate) fn digest(data: impl AsRef<[u8]>) -> [u8; 32] {
        crypto::sha256(data.as_ref())
    }
}

/// A SHA-256 over secret values (PM ruling 2026-11-17). It is not the secret, but a low-entropy
/// secret can be guessed offline from it, so it is never printed (its Debug is redacted; it has no
/// Display) and is compared only in constant time. Only [`Sha256::finalize_secret`] builds one; the
/// credential typecheck recognises the type by name and holds it to this contract.
pub(crate) struct SecretDigest([u8; 32]);

impl SecretDigest {
    /// The 32 bytes, for the one place they are written: the durable record that carries them.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether `stored` (32 bytes read back from a durable record) is this digest, in constant time.
    pub(crate) fn matches(&self, stored: &[u8; 32]) -> bool {
        busbar_contract::constant_time_eq(&self.0, stored)
    }
}

impl std::fmt::Debug for SecretDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretDigest(..)")
    }
}

impl PartialEq for SecretDigest {
    fn eq(&self, other: &Self) -> bool {
        busbar_contract::constant_time_eq(&self.0, &other.0)
    }
}

impl Eq for SecretDigest {}

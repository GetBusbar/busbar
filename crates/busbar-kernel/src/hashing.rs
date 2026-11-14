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

    /// The digest of `data` in one call.
    pub(crate) fn digest(data: impl AsRef<[u8]>) -> [u8; 32] {
        crypto::sha256(data.as_ref())
    }
}

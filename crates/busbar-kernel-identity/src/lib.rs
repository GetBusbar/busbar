// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-identity — the identity types around the kernel's auth chain

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

/// The caller reference a plane attributes a request with, in place of the principal.
pub mod caller_ref;
pub mod operator;
pub mod principal;

pub use principal::ANONYMOUS;

/// The revocation set, as the kernel derives it from the journal tail.
pub trait RevocationView: Send + Sync {
    /// Whether this credential is revoked as of the current policy epoch.
    fn is_revoked(&self, credential: &str) -> bool;
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

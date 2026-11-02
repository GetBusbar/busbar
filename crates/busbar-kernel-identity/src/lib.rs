// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-identity — the chain walk and the identity types around it

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

/// The caller reference a plane attributes a request with, in place of the principal.
pub mod caller_ref;
pub mod chain;
pub mod module;
pub mod operator;
pub mod principal;

pub use chain::{AuthChain, ChainEntry, ChainVerdict, KeyVerifier, ResolvedKey, RevocationView};
pub use module::{AuthModule, AuthOutcome};
pub use principal::{Principal, ANONYMOUS};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

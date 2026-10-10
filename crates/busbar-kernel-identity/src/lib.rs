// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-identity — the chain walk and the identity types around it
//!
//! One question: **who is calling?** This crate holds the walk that answers it over a configured
//! chain of modules, the types a module and its answer are written in, the caller reference a plane
//! attributes a request with, and the operator credential's words. It is not an authenticate step:
//! the kernel's one chain serves that (BUSBAR-1.6.0.md THE DESIGN §11.11 R3).
//!
//! ## What it holds
//!
//! - **The chain.** Config order. The first module to identify admits. A reject stops the chain. A
//!   pass continues. The door is open only when the chain declares no module **and** no keys arm.
//!   All-pass with a keys arm runs the keys arm; all-pass without one denies.
//! - **No credential cache.** A verified credential is cached by the auth plugin that verified it,
//!   inside itself, and dropped on its `refresh` (BUSBAR-1.6.0.md THE DESIGN §11.11 R3, Q-INCACHE);
//!   the walk keeps none.
//! - **The module and the principal.** [`AuthModule`] and its three answers, [`AuthOutcome`]; and
//!   [`Principal`]. The anonymous principal has no bucket and renders its actor id as the literal
//!   word `anonymous` on every surface.
//! - **The caller reference.** What a plane sees in place of the principal ([`caller_ref`]).
//! - **The operator credential.** Its provider key, principal id and refusal words ([`operator`]).
//!
//! ## What the caller supplies
//!
//! Anything that would have pulled in an HTTP stack or a clock arrives as a trait: [`KeyVerifier`]
//! for the built-in signed-key arm, and [`RevocationView`] for the revocation set derived from the
//! journal tail.

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

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-identity — the identity words around the kernel's chain
//!
//! One question: **who is calling?** The kernel's one chain answers it (`busbar_kernel::auth`,
//! BUSBAR-1.6.0.md THE DESIGN §11.11 R3); this crate holds no walk of its own. It holds what that
//! chain and the planes around it are written in:
//!
//! - **The caller reference.** What a plane sees in place of the principal ([`caller_ref`]).
//! - **The operator credential.** Its provider key, principal id and refusal words, how its auth
//!   row's answer is read, and which admin-chain providers it answers for ([`operator`]).
//! - **The principal words.** The anonymous caller's literal, and the ids no auth module may hand
//!   back, which the kernel's chain refuses ([`principal`]).
//!
//! No credential cache lives here or in the kernel: a verified credential is cached by the auth
//! plugin that verified it, inside itself, and dropped on its `refresh` (THE DESIGN §11.11 R3,
//! Q-INCACHE).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

/// The caller reference a plane attributes a request with, in place of the principal.
pub mod caller_ref;
pub mod operator;
pub mod principal;

pub use principal::ANONYMOUS;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

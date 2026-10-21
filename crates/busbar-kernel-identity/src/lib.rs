// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-identity — the identity pieces the kernel's authenticate step is built from
//!
//! One question: **who is calling?** The kernel's one chain (`busbar_kernel::auth`) walks the
//! configured chain and answers it. This crate holds the pieces that walk and the composition root
//! are built from, and no walk of its own.
//!
//! ## What it holds
//!
//! - **The operator credential.** Its words ([`operator::OperatorWords`]), v1.5.5's refusal texts,
//!   and the judgement of one request: the auth axis's `verify` answer read as a verdict, the replay
//!   claim and the lines the transport strips ([`operator`]). The words and the linked auth rows are
//!   the composition root's, handed to the kernel on its install record; this crate keeps neither.
//! - **No credential cache.** A verified credential is cached by the auth plugin that verified it,
//!   inside itself, and dropped on its `refresh` (BUSBAR-1.6.0.md THE DESIGN §11.11 R3, Q-INCACHE).
//! - **The revocation view.** The set the authenticate step gates a NEW unit with
//!   ([`RevocationView`]), which the root implements over the node's governance state.
//! - **The anonymous caller.** [`ANONYMOUS`], the literal an unauthenticated caller renders as on
//!   every surface.
//! - **The caller reference.** What a plane sees in place of the principal ([`caller_ref`]).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

/// The caller reference a plane attributes a request with, in place of the principal.
pub mod caller_ref;
pub mod operator;
pub mod principal;
pub mod revocation;

pub use principal::ANONYMOUS;
pub use revocation::RevocationView;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

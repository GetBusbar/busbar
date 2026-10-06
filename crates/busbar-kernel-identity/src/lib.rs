// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-unit-auth — the authenticate step, as a unit
//!
//! One question, asked once per unit: **who is calling?** The kernel hands this unit the token for
//! the authenticate step and the claim's declared scheme; the unit hands back a sealed answer — a
//! principal, a refusal, or (inside a handshake unit only) a bounded challenge the client must
//! answer before the question can be settled.
//!
//! ## What moved here, and what did not change
//!
//! Every rule in this crate is the shipped 1.5.5 rule, relocated rather than rewritten:
//!
//! - **The chain.** Config order. The first module to identify admits. A reject stops the chain. A
//!   pass continues. The door is open only when the chain declares no module **and** no keys arm.
//!   All-pass with a keys arm runs the keys arm; all-pass without one denies.
//! - **Anonymous.** The anonymous principal has no bucket and renders its actor id as the literal
//!   word `anonymous` on every surface.
//! - **Revocation.** Gates NEW units only. A unit already in flight runs to its end.
//! - **Open admin.** With no admin chain configured, an absent principal is granted full scope.
//!
//! ## What the kernel supplies
//!
//! The crate takes nothing from the kernel: anything that would have pulled in an HTTP stack or a
//! clock arrives as a trait: [`KeyVerifier`] for the built-in signed-key arm, and [`RevocationView`]
//! for the revocation set the kernel derives from the journal tail.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod admin;
/// The caller reference a plane attributes a request with, in place of the principal.
pub mod caller_ref;
pub mod chain;
pub mod challenge;
pub mod egress_auth;
pub mod exchange;
pub mod ingress_sigv4;
pub mod module;
pub mod operator;
pub mod principal;
pub mod unit;

pub use admin::{admin_grants, kernel_verb_scope_satisfied, Grants, Scope};
pub use chain::{AuthChain, ChainEntry, ChainVerdict, KeyVerifier, ResolvedKey, RevocationView};
pub use challenge::{Challenge, ChallengeBounds};
pub use exchange::{BrowserAction, AUTH_TOKEN_PATH};
pub use module::{AuthModule, AuthOutcome};
pub use principal::{Principal, ANONYMOUS};
pub use unit::{Auth, AuthRequest};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

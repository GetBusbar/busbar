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
//! - **The credential cache.** Consulted only around modules that declare themselves cacheable
//!   (the trait default is *not* cacheable, so an external module that never says so is re-verified
//!   on every request). Keyed by the provider name and the credential digest. Identify entries take
//!   the module's own suggested lifetime clamped to an hour, defaulting to five minutes; pass
//!   entries take five seconds plus a deterministic jitter; a reject is never cached. Passes are
//!   buffered and committed only when the chain actually identifies, so unauthenticated traffic
//!   cannot churn a real identity out of a full cache. The keys arm is cache-exempt.
//! - **The carriers.** Bearer first, then the Anthropic key header, then the Google key header. A
//!   present-but-empty header is treated as absent; a non-bearer authorization header falls through
//!   to the next carrier rather than swallowing the request.
//! - **Anonymous.** The anonymous principal has no bucket and renders its actor id as the literal
//!   word `anonymous` on every surface.
//! - **Revocation.** Gates NEW units only. A unit already in flight runs to its end.
//! - **Open admin.** With no admin chain configured, an absent principal is granted full scope.
//!
//! ## The two things the kernel supplies
//!
//! The crate is dependency-free BY DEFAULT, so anything that would have pulled in an HTTP stack, a
//! hash, or a clock arrives as a trait: [`HeaderView`] for the request's headers, [`CredentialDigest`]
//! for the credential digest, [`KeyVerifier`] for the built-in signed-key arm, and [`RevocationView`]
//! for the revocation set the kernel derives from the journal tail. The `sha256` feature adds a
//! production [`cache::Sha256Digest`] for callers willing to take the `sha2`/`hex` dependency rather
//! than supplying their own.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod admin;
pub mod cache;
pub mod carrier;
pub mod chain;
pub mod challenge;
pub mod detect;
pub mod exchange;
pub mod module;
pub mod principal;
pub mod unit;

pub use admin::{admin_grants, kernel_verb_scope_satisfied, Grants, Scope};
pub use cache::{CacheGeneration, CredentialCache, CredentialDigest};
pub use carrier::{extract_bearer_token, extract_client_token, CallerToken, HeaderView};
pub use chain::{AuthChain, ChainEntry, ChainVerdict, KeyVerifier, ResolvedKey, RevocationView};
pub use challenge::{Challenge, ChallengeBounds};
pub use detect::{protocol_id, Rung, LADDER};
pub use exchange::{BrowserAction, AUTH_TOKEN_PATH};
pub use module::{AuthModule, AuthOutcome};
pub use principal::{Principal, ANONYMOUS};
pub use unit::{Auth, AuthRequest};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

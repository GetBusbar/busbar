// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! # busbar-kernel-identity — the identity types around the kernel's auth chain

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

/// The caller reference a plane attributes a request with, in place of the principal.
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod caller_ref;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod operator;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub mod principal;

// The identity modules' code that runs off the request path: once per build start or per
// configuration, never per request.
mod off_path;

pub use principal::ANONYMOUS;

/// The revocation set, as the kernel derives it from the journal tail.
pub trait RevocationView: Send + Sync {
    /// Whether this credential is revoked as of the current policy epoch.
    fn is_revoked(&self, credential: &str) -> bool;
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

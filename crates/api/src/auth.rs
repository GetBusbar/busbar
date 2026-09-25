// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The AUTH contract: one module, one verdict.
//!
//! The module, the verdict, the principal, the request-extension carriers and the browser-login
//! primitives LEFT THIS CRATE for `busbar_contract::auth` (DECISIONS #83/#84; the per-kind trait is
//! the contract's, #35(a)) and are re-exported from `lib.rs` under their original names. The verdict
//! is spelled `AuthVerdict` there, de-collided from `busbar_contract::kinds::AuthOutcome` (#35);
//! `lib.rs` aliases it back to `AuthOutcome`. `sha256_hex` LEFT too, last (DECISIONS #83,
//! ARCHITECT P68-0 residue (b)): the owner ruled `sha2 -> cpufeatures -> libc` tree-wide on
//! 2026-09-22, so the digest now lives beside the constant-time compare in
//! `busbar_contract::redacted` and is re-exported below under its historical path.

// `sha256_hex` is re-exported, not defined, here: every caller that spells `busbar_api::sha256_hex`
// keeps compiling, and a plugin that needs only the digest names the contract instead.
pub use busbar_contract::redacted::sha256_hex;

#[cfg(test)]
#[path = "tests/auth_tests.rs"]
mod tests;

// `UpstreamCreds` LEFT THIS CRATE and is re-exported, not defined, here. It is a config-grammar
// value — `own` / `passthrough`, two unit variants and two serde derives — and it is the ONE thing
// the jev decision plane needed from `busbar-api`. Keeping it here forced that pure plane's
// manifest to name this crate, and this crate carried `sha2` (for `sha256_hex`), so the plane
// inherited `sha2 -> cpufeatures -> libc`: a banned transitive source in a pure plugin kind, and the
// only plane with that edge. The definition now lives beside the other reserved model-serving
// member, `ModelCfg`, in the contract crate a plugin may name on its own. This line keeps
// `busbar_api::UpstreamCreds` resolving for every caller that already spells it that way.
pub use busbar_contract::config::UpstreamCreds;

// `constant_time_eq` LEFT THIS CRATE too, and for the same reason `UpstreamCreds` did: it is
// the primitive `busbar_contract::Redacted`'s `PartialEq` is built on, and a security control
// implemented twice is one that gets fixed once. It travelled WITH `Redacted`; its sibling
// `sha256_hex` followed once the `sha2 -> cpufeatures -> libc` edge was ruled. This line keeps
// `busbar_api::constant_time_eq` resolving for every caller that already spells it that way.
pub use busbar_contract::redacted::constant_time_eq;

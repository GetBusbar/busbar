// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The AUTH contract: one module, one verdict.
//!
//! The module, the verdict, the principal, the request-extension carriers and the browser-login
//! primitives LEFT THIS CRATE for `busbar_contract::auth` (DECISIONS #83/#84; the per-kind trait is
//! the contract's, #35(a)) and are re-exported from `lib.rs` under their original names. The verdict
//! is spelled `AuthVerdict` there, de-collided from `busbar_contract::kinds::AuthOutcome` (#35);
//! `lib.rs` aliases it back to `AuthOutcome`. What stays is `sha256_hex`: it is `sha2`, and
//! `sha2 -> cpufeatures -> libc` is an open owner ruling the contract does not take on its own.

use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 of `data` — THE digest facility credentials are compared under (a module
/// hashes both sides before [`constant_time_eq`]: every digest is 64 hex chars, so
/// `constant_time_eq`'s length early-exit never fires on a length difference driven by the raw
/// candidate, and candidate length leaks nothing). This is the pattern every auth module SHOULD
/// follow when comparing a caller-supplied credential against configured secret material — compare
/// raw only when the material's length is not itself sensitive.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
#[path = "tests/auth_tests.rs"]
mod tests;

// `UpstreamCreds` LEFT THIS CRATE and is re-exported, not defined, here. It is a config-grammar
// value — `own` / `passthrough`, two unit variants and two serde derives — and it is the ONE thing
// the jev decision plane needed from `busbar-api`. Keeping it here forced that pure plane's
// manifest to name this crate, and this crate carries `sha2` (for `sha256_hex` above), so the plane
// inherited `sha2 -> cpufeatures -> libc`: a banned transitive source in a pure plugin kind, and the
// only plane with that edge. The definition now lives beside the other reserved model-serving
// member, `ModelCfg`, in the contract crate a plugin may name on its own. This line keeps
// `busbar_api::UpstreamCreds` resolving for every caller that already spells it that way.
pub use busbar_contract::config::UpstreamCreds;

// `constant_time_eq` LEFT THIS CRATE too, and for the same reason `UpstreamCreds` did: it is
// the primitive `busbar_contract::Redacted`'s `PartialEq` is built on, and a security control
// implemented twice is one that gets fixed once. It travelled WITH `Redacted`; its sibling
// `sha256_hex` above did NOT, because that one is `sha2 -> cpufeatures -> libc` and the
// contract sits in every plugin's closure (#40(a)) — the open owner ruling. This line keeps
// `busbar_api::constant_time_eq` resolving for every caller that already spells it that way,
// and keeps it in scope for `sha256_hex`'s own doc link.
pub use busbar_contract::redacted::constant_time_eq;

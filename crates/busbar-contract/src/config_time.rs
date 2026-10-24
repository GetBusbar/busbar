// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONFIG-TIME PROOF (`BUSBAR-1.6.0.md` THE DESIGN Q-DISK R4 as the OWNER amended it,
//! 2026-10-13): the host-owned bounded disk lane serves the disk work of the store and export
//! kinds and the secret kind's source that reads a file — the last ONLY at config time (boot, a
//! config apply, a refresh), and NEVER from a request path.
//!
//! [`ConfigScope`] is that proof, as a TYPE: a call that may resolve a secret through a source that
//! reads the disk takes `&ConfigScope`, and only the host's boot, config-apply and refresh code
//! constructs one. It is not a static and holds no state; it is a value the config-time caller makes
//! and hands down. Its one field is private, and it is neither `Copy` nor `Default`, so every
//! construction is a visible call the `config-scope` gate (xtask) holds to its allow-list of files
//! and functions. A request path must never hold one.

/// A CONFIG-TIME PROOF: the caller is booting, applying a configuration or refreshing. A request
/// path must never hold one. Constructed only by [`ConfigScope::config_time`], which the
/// `config-scope` gate allows in the host's boot, config-apply and refresh functions alone.
#[derive(Debug)]
pub struct ConfigScope {
    _proof: (),
}

impl ConfigScope {
    /// The proof, for the host's boot, config-apply and refresh code ONLY (held to that by the
    /// `config-scope` gate). A request path must never construct or hold one.
    #[must_use]
    pub fn config_time() -> Self {
        Self { _proof: () }
    }
}

/// A secret source that reads the disk, asked to resolve without a [`ConfigScope`] (a request path
/// above all): refused before anything is read.
pub const RESOLVE_OFF_CONFIG_TIME: &str =
    "this secret source reads the disk, which the host allows \
     only at config time (boot, a config apply, a refresh), never on a request path";

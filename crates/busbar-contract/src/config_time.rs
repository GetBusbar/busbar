// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Proof that a caller is executing configuration-time work.

/// A CONFIG-TIME PROOF: the caller is booting, applying a configuration or refreshing. A request
/// path must never hold one. Constructed only by [`ConfigScope::config_time`], which the
/// `config-scope` gate allows in the host's boot, config-apply and refresh functions alone.
#[derive(Debug)]
pub struct ConfigScope {
    _proof: (),
}

impl ConfigScope {
    /// The proof, for the host's boot, config-apply and refresh code ONLY (held to that by the
    #[must_use]
    pub fn config_time() -> Self {
        Self { _proof: () }
    }
}

/// A secret source that reads the disk, asked to resolve without a [`ConfigScope`] (a request path
pub const RESOLVE_OFF_CONFIG_TIME: &str =
    "this secret source reads the disk, which the host allows \
     only at config time (boot, a config apply, a refresh), never on a request path";

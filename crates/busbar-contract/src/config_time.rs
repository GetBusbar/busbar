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

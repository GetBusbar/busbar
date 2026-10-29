// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The top-level `credentials:` block (1.6.0, additive): how a recoverable credential is kept at
//! rest.
//!
//! ```yaml
//! credentials:
//!   at_rest:
//!     key: { file: /run/secrets/busbar-at-rest.key }        # seals and opens
//!     previous: { file: /run/secrets/busbar-at-rest.old }   # optional: opens only
//! ```
//!
//! A 1.6.0 key that 1.5.5 refuses as unknown, so it is lifted off the document by the config
//! pre-pass (`prepass::LIFTED_TOP_LEVEL_KEYS`) and never becomes a field of the frozen top-level
//! struct.

use busbar_contract::secret_ref::SecretRef;
use serde::Deserialize;

/// The `credentials:` block. Absent: no at-rest key, so no recoverable credential can be minted.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialsCfg {
    /// The keys a recoverable credential is sealed under before the store sees it.
    #[serde(default)]
    pub at_rest: Option<AtRestCfg>,
}

/// `credentials.at_rest:`. Each key is a SECRET REFERENCE resolving to 32 random bytes (raw, or 64
/// hex characters: `openssl rand -hex 32`). It is fleet-shared: every node that reads the same
/// store resolves the same key.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtRestCfg {
    /// The key every credential is sealed under, and the first one a stored credential is opened
    /// with.
    pub key: SecretRef,
    /// The key before `key`, kept while a rotation completes: a credential sealed under it still
    /// opens, and the node re-seals it under `key` at boot and at reload.
    #[serde(default)]
    pub previous: Option<SecretRef>,
}

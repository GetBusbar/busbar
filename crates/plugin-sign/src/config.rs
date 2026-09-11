// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins.trust:` CONFIG GRAMMAR — the operator-facing half of [`crate::TrustPolicy`].
//!
//! A config section's grammar belongs with the face that gives its words meaning. `publishers`,
//! `allow_unsigned` and `allow_third_party` are not the config layer's vocabulary: they are this
//! crate's, and `TrustPolicy` two modules over is the resolved shape each of them lowers onto. The
//! engine parses a document and hands this crate the section spelled in this crate's own types,
//! rather than keeping a second spelling of them; it re-exports every item here at its historical
//! `config::` path, so its own call sites are unchanged.
//!
//! DECLARED IN ITS OWN FILE and not in `lib.rs`: `cargo xtask gate config-schema` fingerprints a
//! FIXED set of grammar sources, and `lib.rs` carries the signed-MANIFEST types, which are wire
//! shapes the 1.5.3 config freeze never covered. Tracking the file that holds the config section
//! keeps the freeze over exactly what it has always been over.

use serde::Deserialize;

/// `plugins.trust` — how the engine treats plugin signatures. A first-party (busbar-signed) plugin
/// verifies against the EMBEDDED release key; a third-party plugin verifies against `publishers`;
/// anything else (unsigned, tampered, unknown publisher) is UNTRUSTED and, by DEFAULT, logged and
/// SKIPPED (never `dlopen`ed) unless the matching opt-in flag is set.
#[derive(Deserialize, Clone, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct PluginsTrustCfg {
    /// THIRD-PARTY allowlist: publishers whose signatures mark a plugin TRUSTED. Each maps a
    /// publisher name to a hex ed25519 public key. The first-party `busbar` key is embedded in the
    /// binary and never configured here.
    #[serde(default)]
    pub publishers: Vec<PluginPublisher>,
    /// EXPLICIT opt-in: load plugins that carry NO valid signature (unsigned / tampered). Default
    /// `false` — an unsigned plugin found in `plugins.dir` is LOGGED and SKIPPED (never `dlopen`ed
    /// / executed), at boot and in the catalog the engine serves back.
    #[serde(default)]
    pub allow_unsigned: bool,
    /// EXPLICIT opt-in: load plugins that ARE validly signed but by a publisher NOT in
    /// `publishers`. Default `false` — a third-party-signed plugin is LOGGED and SKIPPED.
    #[serde(default)]
    pub allow_third_party: bool,
}

/// One allowlisted plugin publisher: a name and its hex ed25519 public key.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PluginPublisher {
    pub name: String,
    pub public_key: String,
}

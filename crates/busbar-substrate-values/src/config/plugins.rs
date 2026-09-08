// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins:` BLOCK — the ONLY configuration surface of the dynamic plugin subsystem, as pure
//! serde data.
//!
//! What is here is the GRAMMAR: what an operator may write and what a typo is. What is NOT here is
//! any RESOLUTION of it — the fetch list becomes `busbar_plugin_loader::FetchSpec`s and the trust
//! block becomes a `busbar_plugin_sign::TrustPolicy` in `busbar-plugin-loader`, which is where the
//! policy those types belong to already lives. The split is what lets the config layer state the
//! grammar without naming the loader, and lets the loader read an operator's block without naming
//! the config layer.

use serde::Deserialize;

/// The serde default for `plugins.dir:` — `plugins`, relative to the working directory.
pub fn default_plugins_dir() -> String {
    "plugins".to_string()
}

/// The top-level `plugins:` block — the ONLY configuration surface of the dynamic plugin subsystem.
/// A plugin is a plugin: store, auth, and hook plugins share this one block (one directory, one
/// trust model, one master switch); the manifest `kind` inside each signed tarball selects which
/// engine subsystem consumes it.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PluginsCfg {
    /// MASTER SWITCH, default FALSE. When false (or the whole `plugins:` block is absent), NO
    /// plugin is ever loaded — a tarball dropped into the directory is INERT. Referencing a plugin
    /// while disabled (`store.module:` other than `memory`) is a BOOT ERROR naming this flag.
    #[serde(default)]
    pub enabled: bool,
    /// Directory the signed plugin tarballs live in. Default `plugins` (relative to the working
    /// directory).
    #[serde(default = "default_plugins_dir")]
    pub dir: String,
    /// Trust policy for plugin signatures. busbar's OWN release key is EMBEDDED in the binary —
    /// first-party plugins verify with zero configuration; this block is for THIRD-PARTY keys and
    /// the explicit untrusted opt-ins.
    #[serde(default)]
    pub trust: PluginsTrustCfg,
    /// ANTI-DOWNGRADE floors: plugin canonical `name` -> minimum acceptable `version`. Applies to
    /// first- and third-party alike, and is SEPARATE from the automatic first-party floor (the
    /// per-name high-water mark maintained by `busbar_plugin_loader::HighWaterMarks`, which needs no
    /// configuration). A floored plugin must prove (trusted signature, version at/above the floor)
    /// that it meets the floor; nothing else loads it. Sibling of `trust` (a version axis, not a
    /// trust axis).
    #[serde(default)]
    pub min_versions: std::collections::BTreeMap<String, String>,
    /// RUNTIME-ONLY (never in config, `#[serde(skip)]`): PER-PLUGIN FIRST-PARTY anti-downgrade floor
    /// OVERRIDES for EXPLICIT operator rollbacks (1.5.0). Empty (the default, and the ONLY value the
    /// automatic boot/reload path ever sees) = every first-party plugin faces its own automatic
    /// floor, the per-name HIGH-WATER MARK (the highest version of that name this deployment has
    /// seen and loaded — `busbar_plugin_loader::HighWaterMarks`). An explicit, audited `POST /plugins/rollback` of a
    /// FIRST-PARTY plugin adds a `name -> pinned target version` entry so `busbar_plugin_sign::evaluate`
    /// admits the prior artifact for THAT NAME ONLY (an unpinned first-party plugin still faces the full
    /// floor — replacing the earlier single global floor). Derived from the persisted
    /// `plugin_versions` pins during a rebuild (`overlay::apply_plugin_versions_to_deploy`); it is
    /// never deserialized, so config parsing + `deny_unknown_fields` are unchanged.
    #[serde(skip)]
    pub first_party_floors: std::collections::BTreeMap<String, String>,
    /// Declarative plugin FETCH list (`plugins.fetch:`): tarballs busbar downloads into `dir` at
    /// boot (fatal-on-miss) and on `POST /plugins/reload` (warn-on-miss) BEFORE preflight. Each entry
    /// is a github release ref, a direct url, or an env var holding one — optionally sha256-pinned
    /// (integrity + download-skip cache key). NOT consulted by `--validate` (zero-network contract).
    /// Signature verification remains the trust gate; sha256 is integrity/cache only. Default empty.
    #[serde(default)]
    pub fetch: Vec<PluginFetch>,
}

impl Default for PluginsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: default_plugins_dir(),
            trust: PluginsTrustCfg::default(),
            min_versions: std::collections::BTreeMap::new(),
            first_party_floors: std::collections::BTreeMap::new(),
            fetch: Vec::new(),
        }
    }
}

/// One `plugins.fetch:` entry — an UNTAGGED enum discriminated by which key is present. `github` is a
/// `org/repo@tag` release ref (asset resolved by the loader); `url` is a direct tarball URL; `env`
/// names an environment variable holding a URL (or `url@sha256`). `sha256` (github/url) is the
/// lowercase-hex integrity pin: it is BOTH the download-skip cache key (a file in `dir` already
/// hashing to it ⇒ no network) and the verify-before-write gate. Per-variant `deny_unknown_fields`
/// so a typo'd key can't be silently reinterpreted as a different variant.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum PluginFetch {
    /// `- { github: "org/repo@v1.2.3", sha256?: "…" }`
    Github(GithubFetch),
    /// `- { url: "https://host/plugin.tar.gz", sha256?: "…" }`
    Url(UrlFetch),
    /// `- { env: "BUSBAR_PLUGIN_URL" }` (the VAR holds a url, or `url@sha256`)
    Env(EnvFetch),
}

/// The `{ github, sha256? }` fetch shape. `deny_unknown_fields` on each variant struct is what gives
/// the untagged enum real typo rejection: an entry with a stray key matches NO variant and errors,
/// rather than being silently reinterpreted.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GithubFetch {
    /// The `org/repo@tag` release ref.
    pub github: String,
    /// The lowercase-hex integrity pin, if the operator wrote one.
    #[serde(default)]
    pub sha256: Option<String>,
}

/// The `{ url, sha256? }` fetch shape.
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UrlFetch {
    /// The direct tarball URL.
    pub url: String,
    /// The lowercase-hex integrity pin, if the operator wrote one.
    #[serde(default)]
    pub sha256: Option<String>,
}

/// The `{ env }` fetch shape (the VAR's value is a url, optionally `url@sha256`).
#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvFetch {
    /// The environment variable's NAME. Its VALUE is read at fetch time, never at parse time.
    pub env: String,
}

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
    /// / executed), at boot and in the admin catalog.
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
    /// The publisher's name, as it appears in a plugin's signature.
    pub name: String,
    /// Its ed25519 public key, lowercase hex.
    pub public_key: String,
}

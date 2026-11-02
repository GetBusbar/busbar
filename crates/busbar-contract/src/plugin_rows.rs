// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN ROWS, AS THE KERNEL READS THEM (`BUSBAR-1.6.0.md` THE DESIGN, "One dispatcher" and

use std::any::Any;
use std::sync::Arc;

/// One axis of a hook manifest's declared intent — the SAME `no ⊂ ro ⊂ rw` ladder the operator
/// grant uses, so the core can compare "declared" against "granted" directly. `rw` is meaningful
/// only on the `prompt` axis (identity is never rewritten); on `user` it reads as "at least ro".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NeedLevel {
    /// Declares no need for this content (the default).
    #[default]
    No,
    /// Asks to READ this content.
    Ro,
    /// Asks to read AND rewrite (prompt axis only).
    Rw,
}

impl NeedLevel {
    /// Whether the plugin declared it needs to READ this axis (`ro` or `rw`).
    #[must_use]
    pub fn wants_read(self) -> bool {
        !matches!(self, NeedLevel::No)
    }

    /// Whether the plugin declared it needs to REWRITE (prompt axis; `rw`).
    #[must_use]
    pub fn wants_rewrite(self) -> bool {
        matches!(self, NeedLevel::Rw)
    }
}

/// How a row came to be admitted: a valid signature from a trusted key, or an explicit operator
/// opt-in (`plugins.trust`) for one that is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// A valid signature from a trusted key (a linked row is trusted as the build's own).
    Trusted {
        /// The publisher the signature names.
        publisher: String,
        /// Signed by the embedded busbar release key.
        first_party: bool,
    },
    /// Not trusted, permitted by an explicit opt-in: why, in the trust evaluator's words.
    Allowed {
        /// The opt-in's reason.
        reason: String,
    },
}

/// One admitted row, as its signed manifest states it (a linked row states what a release-signed
/// tarball of it would).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The tarball filename (diagnostics only; identity is the manifest). A linked row's is
    /// `(linked)`.
    pub file: String,
    /// The word the row is registered under: its alias for a row keyed by its alias, its canonical
    /// name otherwise. What a refusal names the row by, and the one key a secret module's open
    /// settings are filed under.
    pub key: String,
    /// The plugin's canonical name.
    pub name: String,
    /// The alias configuration may name it by.
    pub alias: String,
    /// Its kind word (`abi::mechanism::kind`).
    pub kind: String,
    /// Its version.
    pub version: String,
    /// Its kind's ABI version as the manifest states it.
    pub abi_version: u32,
    /// How it was admitted.
    pub trust: Trust,
    /// Whether what it holds is lost on restart (a store's own statement).
    pub ephemeral: bool,
    /// The build's in-process store: handed no configuration across a boundary.
    pub in_process: bool,
    /// Compiled into this build rather than dropped in.
    pub linked: bool,
    /// A hook's declared prompt need.
    pub needs_prompt: NeedLevel,
    /// A hook's declared caller-identity need.
    pub needs_user: NeedLevel,
    /// The settings schema the manifest states, as signed text (`None`: none stated).
    pub settings_schema: Option<String>,
}

/// A plugin present in the plugins directory but not admitted (the trust policy skipped it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The tarball filename.
    pub file: String,
    /// The canonical name its manifest states.
    pub name: String,
    /// The alias its manifest states.
    pub alias: String,
    /// Why it was skipped, in the trust evaluator's words. They embed manifest bytes, so nothing
    /// may parse them or put them on the audit chain: [`Skipped::code`] is the structured why.
    pub reason: String,
    /// Why it was skipped, as the trust evaluator's category: `unsigned`, `tampered`,
    /// `unknown_publisher`, `anti_downgrade`, `untrusted_floored`, `egress_grant` or `retired_key`.
    pub code: &'static str,
}

/// One build's plugin rows (see the module doc).
pub trait PluginRows: Send + Sync + std::fmt::Debug {
    /// The admitted row `name_or_alias` resolves to (canonical name first, then alias).
    fn resolve(&self, name_or_alias: &str) -> Option<Row>;

    /// SHA-256 of the exact admitted archive from which the retained native image was read.

    fn archive_sha256(&self, _name_or_alias: &str) -> Option<String> {
        None
    }

    /// Why `name_or_alias` resolves to nothing, when a SKIPPED plugin matches it.
    fn unresolved_reason(&self, name_or_alias: &str) -> Option<Skipped>;

    /// Every row the plugins DIRECTORY admitted, in scan order.
    fn loadable(&self) -> Vec<Row>;

    /// Every row this build links, in registration order.
    fn linked(&self) -> Vec<Row>;

    /// Every skipped plugin.
    fn skipped(&self) -> Vec<Skipped>;

    /// THE DOOR the store `name_or_alias` resolves to opens through

    fn store_door(&self, name_or_alias: &str) -> Result<crate::store_calls::StoreDoor, String>;

    /// Why no secret plugin answers `name_or_alias` on the secret axis, in the registry's words.
    fn secret_refusal(&self, name_or_alias: &str) -> String;

    /// Why no `kind` plugin answers `name_or_alias` on that kind's axis, in the registry's words:

    fn kind_refusal(&self, kind: &str, purpose: &str, name_or_alias: &str) -> String;

    /// The secret reference keys the row `name_or_alias` resolves to states in its Statement

    fn secret_slots(&self, name_or_alias: &str) -> Vec<String>;

    /// The REFERENCE-CAPABLE, NOT-SECRET settings paths the row `name_or_alias` resolves to states

    fn reference_slots(&self, name_or_alias: &str) -> Vec<String> {
        let _ = name_or_alias;
        Vec::new()
    }

    /// The rows as the composition root's own type, for the root's per-kind axes over them.
    fn as_any(&self) -> &dyn Any;

    /// [`Self::as_any`], owned.
    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
}

#[cfg(test)]
#[path = "tests/plugin_rows_tests.rs"]
mod tests;

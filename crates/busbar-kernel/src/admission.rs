// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN-ADMISSION SEAM the operator surface drives (upload, inspect, rollback, inventory):
//! what the composition root's loader answers about a plugin tarball, in words the kernel owns
//! (BUSBAR-1.6.0.md THE DESIGN l.322: the kernel never names the loader). The root implements
//! [`PluginAdmission`] over its one trust builder — the one boot admits plugins under — and
//! installs it ([`crate::preflight::RootInstall::admission`]); every snapshot carries it
//! ([`crate::state::App::plugin_admission`]), so the admin surface judges a plugin exactly as boot
//! does and names no loader type. Every judgement is MANIFEST-ONLY: nothing here loads a plugin.

/// What a plugin's signed manifest states, as the operator surface reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stated {
    /// The canonical name.
    pub name: String,
    /// The alias.
    pub alias: String,
    /// The kind word.
    pub kind: String,
    /// The version.
    pub version: String,
    /// The publisher.
    pub publisher: String,
    /// The kind's ABI version as the manifest states it.
    pub abi_version: u32,
    /// The settings schema the manifest states, as signed text.
    pub settings_schema: Option<String>,
}

/// How the trust policy judged a tarball.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Judged {
    /// A valid signature from a trusted key, naming its publisher.
    Trusted {
        /// The publisher the signature names.
        publisher: String,
    },
    /// Not trusted, permitted by an explicit `plugins.trust` opt-in.
    Allowed,
    /// Refused by the trust policy, in the evaluator's words.
    Rejected {
        /// Why.
        reason: String,
    },
}

/// Why an admission refused, in the class the operator surface answers it with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The request is malformed: the policy does not resolve, the tarball does not unpack, the
    /// manifest is incomplete (`400`).
    Validation(String),
    /// The request conflicts with the running posture or the installed set (`409`).
    Conflict(String),
}

/// One tarball of the plugins directory, as the manifest-only inventory reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inventoried {
    /// The tarball's file name.
    pub file: String,
    /// Its manifest, `None` when the tarball or manifest is invalid (see `status`).
    pub stated: Option<Stated>,
    /// The signature column: `first-party` / `publisher:<name>` / `unsigned (allowed)` / … .
    pub signature: String,
    /// The status column: `ready` / `SKIPPED: <reason>` / `REJECTED: <reason>` / `INVALID: …`.
    pub status: String,
}

/// An upload the admission accepted (structure, trust, conflict and the one-version rule).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// What the manifest states.
    pub stated: Stated,
    /// The trust verdict: [`Judged::Trusted`] or [`Judged::Allowed`].
    pub judged: Judged,
    /// The build links this plugin at this version and the linked build serves it: nothing is to
    /// be written.
    pub linked_serves: bool,
}

/// THE ADMISSION THE ROOT INSTALLS: the loader's tarball, signature and inventory machinery,
/// answered in the kernel's words. `cfg` is the running `plugins:` block; the policy every call
/// judges under is the root's one trust builder over it.
pub trait PluginAdmission: Send + Sync {
    /// Whether `file` names a plugin tarball (`.tar.gz` / `.tgz`).
    fn is_tarball(&self, file: &str) -> bool;

    /// The ceiling on a plugin tarball's size, in bytes.
    fn max_tarball_bytes(&self) -> u64;

    /// The binding lifecycle default: whether a settings change of a `kind` plugin needs a process
    /// restart.
    fn restart_default(&self, kind: &str) -> bool;

    /// Whether `cfg`'s trust resolves.
    ///
    /// # Errors
    /// The policy's refusal.
    fn policy_resolves(&self, cfg: &crate::config::PluginsCfg) -> Result<(), String>;

    /// The manifest-only inventory of `dir` under `cfg`'s trust.
    ///
    /// # Errors
    /// `cfg`'s trust does not resolve.
    fn inventory(
        &self,
        dir: &std::path::Path,
        cfg: &crate::config::PluginsCfg,
    ) -> Result<Vec<Inventoried>, String>;

    /// An UPLOAD of `tarball` as `file` into `dir`: structure, trust against the running posture,
    /// conflict with the installed set, and the one-version rule against the linked rows. Nothing
    /// is written.
    ///
    /// # Errors
    /// The refusal, classed.
    fn admit_upload(
        &self,
        dir: &std::path::Path,
        file: &str,
        tarball: &[u8],
        cfg: &crate::config::PluginsCfg,
    ) -> Result<Admitted, Refusal>;

    /// An INSPECT of `tarball`: its structure checked and its trust REPORTED, never refused.
    ///
    /// # Errors
    /// The policy or the structure refuses.
    fn inspect(
        &self,
        tarball: &[u8],
        cfg: &crate::config::PluginsCfg,
    ) -> Result<(Stated, Judged), Refusal>;

    /// A ROLLBACK target: `bytes` (the tarball `file` holds), its structure checked and its trust
    /// judged with this plugin's floor LOWERED to the target's own version.
    ///
    /// # Errors
    /// The structure refuses (`Validation`), or the target is not loadable even so (`Conflict`).
    fn rollback_target(
        &self,
        file: &str,
        bytes: &[u8],
        cfg: &crate::config::PluginsCfg,
    ) -> Result<Stated, Refusal>;
}

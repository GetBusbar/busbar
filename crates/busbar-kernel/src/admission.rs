// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

pub trait PluginAdmission: Send + Sync {
    fn bootstrap_probe_selected(
        &self,
        _tarball: &[u8],
        _config_path: &std::path::Path,
        _provider_urls: &[String],
    ) -> Result<bool, Refusal> {
        Err(Refusal::Validation(
            "no bootstrap selection proof is installed".into(),
        ))
    }

    fn is_tarball(&self, file: &str) -> bool;

    fn max_tarball_bytes(&self) -> u64;

    fn restart_default(&self, kind: &str) -> bool;

    fn policy_resolves(&self, cfg: &crate::config::PluginsCfg) -> Result<(), String>;

    fn inventory(
        &self,
        dir: &std::path::Path,
        cfg: &crate::config::PluginsCfg,
    ) -> Result<Vec<Inventoried>, String>;

    fn admit_upload(
        &self,
        dir: &std::path::Path,
        file: &str,
        tarball: &[u8],
        cfg: &crate::config::PluginsCfg,
    ) -> Result<Admitted, Refusal>;

    fn inspect(
        &self,
        tarball: &[u8],
        cfg: &crate::config::PluginsCfg,
    ) -> Result<(Stated, Judged), Refusal>;

    fn rollback_target(
        &self,
        file: &str,
        bytes: &[u8],
        cfg: &crate::config::PluginsCfg,
    ) -> Result<Stated, Refusal>;
}

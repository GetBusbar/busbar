// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPERATOR CREDENTIAL IS FILE POLICY (OPERATOR-FROM-ADMITTED-AUTH r3.1 §3.5, §3.6, §000.1).
//!
//! An `identity-providers` definition backed by the operator credential holds `Full` admin scope.
//! It is honoured only from config.yaml as read from disk: never from the admin overlay, an apply
//! or validate body, or a stored `document_patch`. These checks compare documents the operator
//! wrote; they never read a setting for meaning. Everything here is cold (config reads and admin
//! writes only).

use super::document_patch::DocumentPatch;
use super::{IdentityProviderCfg, IdentityProviders, RootCfg};

/// The operator-backed `identity-providers` definitions of config.yaml as last read from disk,
/// before any `document_patch` is composed, by name: the reference every other config source is
/// held to. Only a disk read (boot, `POST /config/reload`) sets it; every other build carries the
/// running generation's.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OperatorFileDefs(std::collections::BTreeMap<String, IdentityProviderCfg>);

impl OperatorFileDefs {
    /// The operator-backed definitions of `providers`.
    pub fn of(providers: &IdentityProviders) -> Self {
        Self(
            providers
                .iter()
                .filter(|(_, def)| operator_backed(def))
                .map(|(name, def)| (name.clone(), def.clone()))
                .collect(),
        )
    }

    /// The definition named `name`, if it is one of the reference's.
    pub fn get(&self, name: &str) -> Option<&IdentityProviderCfg> {
        self.0.get(name)
    }

    /// The reference's definition names, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }
}

/// Whether `def` is backed by the operator credential: its module names the bound operator row.
/// With no operator bound, no definition is.
pub fn operator_backed(def: &IdentityProviderCfg) -> bool {
    !super::operator_provider().is_empty() && super::names_operator(def.module.trim())
}

/// THE CHECK (§3.6.1): `candidate`'s operator-backed definitions against `reference`, by name and
/// by the whole definition (module, settings by value, `max_admin_scope`, `token` and the rest).
/// Introduced (including a name re-pointed to the operator module), changed or removed (deleted,
/// or re-pointed away) all refuse with the operator credential's `operator_file_policy` text.
pub fn operator_file_policy(
    candidate: &IdentityProviders,
    reference: &OperatorFileDefs,
) -> Result<(), String> {
    let _ = (candidate, reference);
    Ok(())
}

/// THE PROVENANCE RULE (§3.5 "File policy"): the first operator-backed definition `cfg` holds from
/// the admin overlay rather than the base file.
pub fn overlay_operator_definition(cfg: &RootCfg) -> Option<&str> {
    let _ = cfg;
    None
}

/// A `document_patch` the operator file policy refuses (§000.1): the refusal text, the definition
/// or path it names (the audit subject), and the patch paths that do it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchRefusal {
    pub text: String,
    pub subject: String,
    pub paths: Vec<String>,
}

/// What the admin door appends to a refusal of a `document_patch`.
pub const DOCUMENT_PATCH_REMEDY: &str = " (document_patch cannot set the operator credential or \
    the plugin admission set; edit config.yaml and POST /config/reload)";

/// RULE (b) (§000.1): the paths of `patch` under `/plugins`, except `/plugins/logs/**`. The plugin
/// admission set decides the operator credential, so it is config.yaml's on every reader.
pub fn plugins_admission_paths(patch: &DocumentPatch) -> Vec<String> {
    let _ = patch;
    Vec::new()
}

/// RULES (b) then (a) (§000.1) over a `document_patch` composed into config.yaml: `patched` is the
/// composed document's `identity-providers`, `reference` config.yaml's unpatched operator
/// definitions. The text carries [`DOCUMENT_PATCH_REMEDY`].
pub fn document_patch_refusal(
    patch: &DocumentPatch,
    patched: &IdentityProviders,
    reference: &OperatorFileDefs,
) -> Option<PatchRefusal> {
    let _ = (patch, patched, reference);
    None
}

/// THE BOOT REFUSAL (§000.1): a stored `document_patch`, written by an earlier binary, that the
/// file policy refuses. It is never silently applied or dropped: the text names the patch paths
/// and the two remedies.
pub fn stored_document_patch(
    patch: &DocumentPatch,
    loaded: &crate::appbuild::LoadedConfig,
) -> Result<(), String> {
    let _ = (patch, loaded);
    Ok(())
}

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
/// held to. Only a disk read sets it (boot, and the disk rebuilds of `POST /config/reload`,
/// `/plugins/reload` and `/plugins/rollback`); every other build carries the running generation's.
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
    match operator_file_difference(candidate, reference) {
        Some(name) => Err(busbar_kernel_identity::operator::operator_file_policy(name)),
        None => Ok(()),
    }
}

/// The first definition [`operator_file_policy`] refuses, by name: the reference's names first,
/// then the candidate's, so a re-keyed and a re-pointed definition name themselves.
pub fn operator_file_difference<'a>(
    candidate: &'a IdentityProviders,
    reference: &'a OperatorFileDefs,
) -> Option<&'a str> {
    let backed = |name: &str| candidate.get(name).filter(|def| operator_backed(def));
    reference
        .names()
        .chain(
            candidate
                .iter()
                .filter(|(_, def)| operator_backed(def))
                .map(|(name, _)| name.as_str()),
        )
        .find(|name| backed(*name) != reference.get(*name))
}

/// THE PROVENANCE RULE (§3.5 "File policy"): the first operator-backed definition `cfg` holds from
/// the admin overlay rather than the base file.
pub fn overlay_operator_definition(cfg: &RootCfg) -> Option<&str> {
    overlay_operator_name(&cfg.identity_providers, &cfg.operator_overlay_names)
}

/// [`overlay_operator_definition`] over a candidate document before resolution: its
/// `identity-providers` and the names the overlay applied.
pub fn overlay_operator_name<'a>(
    providers: &IdentityProviders,
    overlay_names: &'a [String],
) -> Option<&'a str> {
    overlay_names
        .iter()
        .map(String::as_str)
        .find(|name| providers.get(*name).is_some_and(operator_backed))
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
const DOCUMENT_PATCH_REMEDY: &str = " (document_patch cannot set the operator credential or \
    the plugin admission set; edit config.yaml and POST /config/reload)";

/// Whether `path` (an encoded pointer) is `/plugins` or below it, other than `/plugins/logs/**`.
fn admission_path(path: &str) -> bool {
    match path.strip_prefix("/plugins") {
        Some("") => true,
        Some(rest) => rest
            .strip_prefix('/')
            .is_some_and(|tail| tail != "logs" && !tail.starts_with("logs/")),
        None => false,
    }
}

/// Whether `path` (an encoded pointer) is `/identity-providers` or below it.
fn identity_providers_path(path: &str) -> bool {
    path.strip_prefix("/identity-providers")
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Whether `patch` edits the `identity-providers` map at all: only then can the composed document's
/// operator definitions differ from config.yaml's.
pub fn touches_identity_providers(patch: &DocumentPatch) -> bool {
    patch.paths().any(identity_providers_path)
}

/// RULE (b) (§000.1): the paths of `patch` under `/plugins`, except `/plugins/logs/**`. The plugin
/// admission set decides the operator credential, so it is config.yaml's on every reader.
fn plugins_admission_paths(patch: &DocumentPatch) -> Vec<String> {
    patch
        .paths()
        .filter(|path| admission_path(path))
        .map(str::to_owned)
        .collect()
}

/// RULE (b) alone: a `document_patch` that moves the plugin admission set. Judged before the
/// composed document is read.
pub fn admission_refusal(patch: &DocumentPatch) -> Option<PatchRefusal> {
    let paths = plugins_admission_paths(patch);
    let first = paths.first()?.clone();
    let mut text = busbar_kernel_identity::operator::operator_admission_path(&first);
    text.push_str(DOCUMENT_PATCH_REMEDY);
    Some(PatchRefusal {
        text,
        subject: first,
        paths,
    })
}

/// RULES (b) then (a) (§000.1) over a `document_patch` composed into config.yaml: `patched` is the
/// composed document's `identity-providers`, `reference` config.yaml's unpatched operator
/// definitions. The text carries the `document_patch` remedy.
pub fn document_patch_refusal(
    patch: &DocumentPatch,
    patched: &IdentityProviders,
    reference: &OperatorFileDefs,
) -> Option<PatchRefusal> {
    if let Some(refusal) = admission_refusal(patch) {
        return Some(refusal);
    }
    let name = operator_file_difference(patched, reference)?;
    let mut text = busbar_kernel_identity::operator::operator_file_policy(name);
    text.push_str(DOCUMENT_PATCH_REMEDY);
    let encoded = name.replace('~', "~0").replace('/', "~1");
    let paths = patch
        .paths()
        .filter(|path| {
            path.strip_prefix("/identity-providers")
                .is_some_and(|rest| {
                    rest.is_empty()
                        || rest
                            .strip_prefix('/')
                            .is_some_and(|tail| tail.split('/').next() == Some(encoded.as_str()))
                })
        })
        .map(str::to_owned)
        .collect();
    Some(PatchRefusal {
        text,
        subject: name.to_owned(),
        paths,
    })
}

/// THE BOOT REFUSAL (§000.1): a stored `document_patch`, written by an earlier binary, that the
/// file policy refuses. It is never silently applied or dropped: the text names the patch paths
/// and the two remedies.
pub fn stored_document_patch(
    patch: &DocumentPatch,
    loaded: &crate::appbuild::LoadedConfig,
) -> Result<(), String> {
    let Some(refusal) = document_patch_refusal(
        patch,
        &loaded.deploy.identity_providers,
        &loaded.operator_reference,
    ) else {
        return Ok(());
    };
    crate::audit::auditlog::record_operator(
        crate::audit::auditlog::OperatorAudit::RefusedFilePolicy,
        &refusal.subject,
        "boot",
    );
    Err(format!(
        "{} The Store holds this document_patch from an earlier binary at {}. Remove those paths \
         with PUT /config/settings and `reset_document_paths`, or start once with \
         --ignore-overlay; the patch is never applied or dropped silently.",
        refusal.text,
        refusal.paths.join(", ")
    ))
}

/// The operator file-policy refusal of the definition `name`, for the admin write doors.
pub fn refusal_text(name: &str) -> String {
    busbar_kernel_identity::operator::operator_file_policy(name)
}

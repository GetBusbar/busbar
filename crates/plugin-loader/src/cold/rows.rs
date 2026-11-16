// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::rows`: the owned registry rows that config validation and the admin
//! listing read.

use busbar_contract::plugin_rows::{Row, Skipped, Trust};

use crate::registry::{LoadablePlugin, PluginRegistry, SkippedPlugin};
use crate::sign::Verdict;

/// A registry row: an owned snapshot for config validation and the admin listing.
#[cold]
pub(crate) fn row(p: &LoadablePlugin) -> Row {
    let m = &p.manifest;
    Row {
        file: p.file.clone(),
        key: p.key().to_string(),
        name: m.name.clone(),
        alias: m.alias.clone(),
        kind: m.kind.clone(),
        version: m.version.clone(),
        abi_version: m.abi_version,
        trust: match &p.verdict {
            Verdict::Trusted {
                publisher,
                first_party,
            } => Trust::Trusted {
                publisher: publisher.clone(),
                first_party: *first_party,
            },
            Verdict::Allowed { reason, allow } => Trust::Allowed {
                reason: reason.clone(),
                setting: allow.setting(),
            },
        },
        ephemeral: p.ephemeral,
        in_process: p.in_process(),
        linked: p.linked(),
        needs_prompt: m.needs.prompt,
        needs_user: m.needs.user,
        settings_schema: p.settings_schema.clone(),
    }
}

/// A skipped row: an owned snapshot for config validation and the admin listing.
#[cold]
pub(crate) fn skipped(s: &SkippedPlugin) -> Skipped {
    Skipped {
        file: s.file.clone(),
        name: s.manifest.name.clone(),
        alias: s.manifest.alias.clone(),
        reason: s.reason.clone(),
        code: s.kind.code(),
    }
}

/// The archive digest, read when config names a plugin.
#[cold]
pub(crate) fn archive_sha256(p: &LoadablePlugin) -> Option<String> {
    p.archive_sha256.clone()
}

/// The registry's loadable rows, listed for config validation and the admin listing.
#[cold]
pub(crate) fn loadable_rows(registry: &PluginRegistry) -> Vec<Row> {
    PluginRegistry::loadable(registry).iter().map(row).collect()
}

/// The registry's linked rows, listed for config validation and the admin listing.
#[cold]
pub(crate) fn linked_rows(registry: &PluginRegistry) -> Vec<Row> {
    PluginRegistry::linked(registry).iter().map(row).collect()
}

/// The registry's skipped rows, listed for config validation and the admin listing.
#[cold]
pub(crate) fn skipped_rows(registry: &PluginRegistry) -> Vec<Skipped> {
    PluginRegistry::skipped(registry)
        .iter()
        .map(skipped)
        .collect()
}

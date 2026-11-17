// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeMap, HashSet};

use super::{named_map::NamedMapSection, overlay::OverlayDoc, DeployCfg};

/// Resource names in the composed base document, before typed Store overlays.
///
/// Guarded document patches have already been composed at this boundary. This is distinct from
/// the raw-file operator credential reference. Capture once per source read; never derive it
/// from the resolved registry, which already contains API-owned definitions.
#[derive(Clone, Debug)]
pub struct ResourceOwnership {
    hooks: HashSet<String>,
    groups: HashSet<String>,
    named: BTreeMap<String, HashSet<String>>,
}

impl ResourceOwnership {
    pub fn capture(deploy: &DeployCfg) -> Self {
        let named = NamedMapSection::sections()
            .into_iter()
            .map(|section| {
                let names = match section {
                    NamedMapSection::IdentityProviders => {
                        deploy.identity_providers.keys().cloned().collect()
                    }
                    NamedMapSection::Export => deploy.export.keys().cloned().collect(),
                    NamedMapSection::Plane(key) => deploy
                        .plane_section(key)
                        .map(|cfg| cfg.def_names().into_iter().map(str::to_owned).collect())
                        .unwrap_or_default(),
                };
                (section.key().to_owned(), names)
            })
            .collect();
        Self {
            hooks: deploy.hooks.keys().cloned().collect(),
            groups: deploy.groups.keys().cloned().collect(),
            named,
        }
    }

    pub fn hook_names(&self) -> &HashSet<String> {
        &self.hooks
    }

    pub fn group_names(&self) -> &HashSet<String> {
        &self.groups
    }

    /// Preflight the final candidate, after any requested section reset and before any overlay
    /// insertion. Equal or malformed stored definitions still collide by resource identity.
    /// Low-level overlay insertion remains repeatable and does not infer source ownership.
    pub fn validate_named_maps(&self, doc: &OverlayDoc) -> Result<(), String> {
        for (section, entries) in &doc.named_maps {
            let Some(base) = self.named.get(section) else {
                continue;
            };
            if let Some(name) = entries.keys().find(|name| base.contains(*name)) {
                return Err(format!(
                    "`{section}.{name}` is defined in both the base configuration and the Store \
                     overlay; correct the base source or reset the `{section}` overlay section \
                     before applying this configuration"
                ));
            }
        }
        Ok(())
    }
}

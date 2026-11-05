// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::plugin::Kind;
use busbar_kernel::admission::ConfigurationDeclaration;
use serde::Serialize;

/// Configuration ownership, not a replacement for the declaring parser's input grammar.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct PluginConfiguration {
    /// Kind::verb for non-planes; the declaring and other non-consumed Statement sections for planes.
    pub root_keys: Vec<String>,
    /// kind_verb, statement, or unavailable. A missing declaration never guesses a plane root.
    pub root_source: &'static str,
    /// linked_statement, loaded_manifest, installed_archive, manifest, or unavailable.
    pub declaration_source: &'static str,
    /// present, absent (legacy/no Statement), or unavailable (unreadable/refused/unresolved).
    pub declaration_availability: &'static str,
    /// Statement sections, including consumed sections which are not owned config roots.
    pub sections: Vec<PluginConfigurationSection>,
    /// Transport URL schemes from the Statement; empty is never inferred from a module name.
    pub claims: Vec<String>,
    /// Lifecycle settings only. Host-reserved fields and SecretRef transformations still apply.
    pub settings_schema_scope: &'static str,
    /// False: the lifecycle schema alone is not the complete authored configuration grammar.
    pub input_schema_complete: bool,
    /// Transport uses provider_catalog_and_deployment; other kinds use kind_root or declared_sections.
    pub configuration_shape: &'static str,
    /// Existing host inputs to TransportSettings, not arbitrary per-transport settings.
    pub host_policy_paths: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub struct PluginConfigurationSection {
    pub name: String,
    pub declaring: bool,
    pub consumed: bool,
    pub required: bool,
    pub selects: bool,
}

pub(crate) fn configuration(
    kind: &str,
    declaration: Option<&ConfigurationDeclaration>,
    source: &'static str,
    available: bool,
) -> PluginConfiguration {
    use busbar_contract::abi::mechanism::door::{
        SECTION_CONSUMED, SECTION_DECLARING, SECTION_REQUIRED, SECTION_SELECTS,
    };
    let kind = Kind::ALL.into_iter().find(|k| k.to_string() == kind);
    let available = available && declaration.is_none_or(|d| d.valid);
    let declaration = available.then_some(declaration).flatten();
    let sections: Vec<_> = declaration
        .into_iter()
        .flat_map(|d| &d.sections)
        .map(|(name, flags)| PluginConfigurationSection {
            name: name.clone(),
            declaring: flags & SECTION_DECLARING != 0,
            consumed: flags & SECTION_CONSUMED != 0,
            required: flags & SECTION_REQUIRED != 0,
            selects: flags & SECTION_SELECTS != 0,
        })
        .collect();
    let root = kind.and_then(Kind::root_key);
    let roots = match root {
        Some(root) => vec![root.to_string()],
        None if kind == Some(Kind::Plane) => sections
            .iter()
            .filter(|s| s.declaring || !s.consumed)
            .map(|s| s.name.clone())
            .collect(),
        None => Vec::new(),
    };
    PluginConfiguration {
        root_keys: roots,
        root_source: if root.is_some() {
            "kind_verb"
        } else if kind == Some(Kind::Plane) && declaration.is_some() {
            "statement"
        } else {
            "unavailable"
        },
        declaration_source: if declaration.is_some() {
            source
        } else {
            "unavailable"
        },
        declaration_availability: if !available {
            "unavailable"
        } else if declaration.is_some() {
            "present"
        } else {
            "absent"
        },
        sections,
        claims: if kind == Some(Kind::Transport) {
            declaration.map(|d| d.claims.clone()).unwrap_or_default()
        } else {
            Vec::new()
        },
        settings_schema_scope: "lifecycle_settings",
        input_schema_complete: false,
        configuration_shape: match kind {
            Some(Kind::Transport) => "provider_catalog_and_deployment",
            Some(Kind::Plane) => "declared_sections",
            _ => "kind_root",
        },
        host_policy_paths: if kind == Some(Kind::Transport) {
            vec![
                "/limits/pool_max_idle_per_host",
                "/limits/pool_idle_timeout_secs",
                "/limits/request_body_max_bytes",
                "/limits/upstream_request_timeout_secs",
                "/advanced/upstream_http1_only",
                "/advanced/upstream_h2_prior_knowledge",
            ]
        } else {
            Vec::new()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::abi::mechanism::door::{
        SECTION_CONSUMED, SECTION_DECLARING, SECTION_REQUIRED, SECTION_SELECTS,
    };

    #[test]
    fn plugin_configuration_plane_ownership_preserves_declared_and_consumed_roles() {
        let declaration = ConfigurationDeclaration {
            valid: true,
            sections: vec![
                ("fixture-root".into(), SECTION_DECLARING | SECTION_REQUIRED),
                ("fixture-owned".into(), SECTION_SELECTS),
                ("fixture-shared".into(), SECTION_CONSUMED),
            ],
            claims: Vec::new(),
        };
        let view = configuration("plane", Some(&declaration), "installed_archive", true);
        assert_eq!(view.root_keys, ["fixture-root", "fixture-owned"]);
        assert_eq!(view.root_source, "statement");
        assert_eq!(view.declaration_source, "installed_archive");
        assert_eq!(view.declaration_availability, "present");
        assert!(view.sections[0].declaring && view.sections[0].required);
        assert!(view.sections[1].selects);
        assert!(view.sections[2].consumed);
        assert!(!view.input_schema_complete);
    }

    #[test]
    fn plugin_configuration_refused_or_missing_statement_never_invents_plane_roots() {
        let declaration = ConfigurationDeclaration {
            valid: true,
            sections: vec![("untrusted-root".into(), SECTION_DECLARING)],
            claims: vec!["untrusted-scheme".into()],
        };
        for kind in ["plane", "transport"] {
            let view = configuration(kind, Some(&declaration), "installed_archive", false);
            assert!(view.sections.is_empty() && view.claims.is_empty());
            assert_eq!(view.declaration_availability, "unavailable");
            assert_eq!(view.declaration_source, "unavailable");
            if kind == "plane" {
                assert!(view.root_keys.is_empty());
            }
        }
        let view = configuration("plane", None, "manifest", true);
        assert!(view.root_keys.is_empty());
        assert_eq!(view.declaration_availability, "absent");
    }

    #[test]
    fn plugin_configuration_transport_uses_kind_root_and_actual_host_policy() {
        let declaration = ConfigurationDeclaration {
            valid: true,
            sections: Vec::new(),
            claims: vec!["fixture-wire".into()],
        };
        let view = configuration("transport", Some(&declaration), "linked_statement", true);
        assert_eq!(view.root_keys, [Kind::Transport.root()]);
        assert_eq!(view.claims, ["fixture-wire"]);
        assert_eq!(view.configuration_shape, "provider_catalog_and_deployment");
        assert!(view
            .host_policy_paths
            .contains(&"/advanced/upstream_http1_only"));
        assert!(!view
            .host_policy_paths
            .contains(&"/limits/upstream_http1_only"));
        for kind in Kind::ALL.into_iter().filter(|kind| *kind != Kind::Plane) {
            assert_eq!(
                configuration(&kind.to_string(), None, "manifest", true).root_keys,
                [kind.root()]
            );
        }
    }
}

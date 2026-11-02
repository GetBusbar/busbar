// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{DeployCfg, ExportDefCfg, IdentityProviderCfg};
use busbar_contract::plugin::Kind;

/// One 1.5.3 named-DEFINITION map section. The variant set is the ONLY thing a new section adds.
///
/// The two 1.5.3-native sections are in-core NAMES ([`NamedMapSection::IdentityProviders`],
/// [`NamedMapSection::Export`]). Every PLANE-owned named-map section — e.g. `tools:` or `agents:`
/// (1.6.0), and any registered plane's own named-definition map — is a single [`NamedMapSection::Plane`]
/// carrying its plane-declared config-section key: core's generic named-map machinery names NO plane
/// noun, and a section joins by its plane registering a decl whose `named_def_list` is set, not by a
/// new variant here. See [`NamedMapSection::sections`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NamedMapSection {
    /// `identity-providers:` — provider NAME → `{module, settings, max_admin_scope, token,
    /// browser_login}`, referenced by bare name from `auth.chain:` / `auth.admin_auth:` /
    /// `auth.role_bindings:`.
    IdentityProviders,
    /// `export:` — instance NAME → `{module, settings}`, the single telemetry-egress surface.
    Export,
    /// A PLANE-OWNED named-definition map, carrying the owning plane's declared config-section key
    /// ([`PlaneDeclaration::config_section`](crate::plane_driver::registry::PlaneDeclaration::config_section)) as OPAQUE
    /// DATA. `tools:` (server NAME → `{url, pin, tools_allow, …}`) and `agents:`
    /// (agent NAME → `{url, pin, reverify_ttl, …}`) are its two 1.6.0 instances, each declared by a
    /// different registered plane, and a registered plane declaring a `named_def_list` is another. The
    /// config key is LOCKED to the plane's section — its mere existence is what declares the plane, the
    /// way `pools:` declares its owning plane — and [`NamedMapSection::key`] is both the config key and
    /// the management-surface path segment, so the API mirrors the config grammar exactly. Core spells
    /// no `tools`/`agents` literal to build this: a plane's section reaches the chassis through
    /// [`NamedMapSection::sections`], folded from the plane registry.
    Plane(&'static str),
}

impl NamedMapSection {
    pub fn sections() -> Vec<NamedMapSection> {
        let mut out = vec![NamedMapSection::IdentityProviders, NamedMapSection::Export];
        for decl in crate::plane_driver::registry::plane_decls() {
            if decl.named_def_list.is_some() {
                out.push(NamedMapSection::Plane(decl.config_section));
            }
        }
        out
    }

    pub fn key(self) -> &'static str {
        match self {
            NamedMapSection::IdentityProviders => Kind::Auth.root(),
            NamedMapSection::Export => Kind::Export.root(),
            NamedMapSection::Plane(section) => section,
        }
    }

    pub fn path_root(self) -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Owned(format!("/{}", self.key()))
    }

    pub fn singular(self) -> &'static str {
        match self {
            NamedMapSection::IdentityProviders => "identity-provider",
            NamedMapSection::Export => "exporter",
            NamedMapSection::Plane(_) => {
                crate::plane_driver::registry::plane_decl_for_config_section(self.key())
                    .map(|d| d.admin_noun)
                    .unwrap_or_else(|| self.key())
            }
        }
    }

    pub fn requires_module(self) -> bool {
        !matches!(self, NamedMapSection::Plane(_))
    }

    pub fn has_trust_ceiling(self) -> bool {
        matches!(self, NamedMapSection::IdentityProviders)
    }

    #[cfg_attr(not(any(test, feature = "openapi-schema")), allow(dead_code))]
    pub fn parse_rel(rel: &str) -> Option<(NamedMapSection, NamedMapShape)> {
        for section in NamedMapSection::sections() {
            let root = section.path_root();
            if rel == root.as_ref() {
                return Some((section, NamedMapShape::Collection));
            }
            if let Some(tail) = rel.strip_prefix(root.as_ref()) {
                match tail {
                    "/{name}" => return Some((section, NamedMapShape::Item)),
                    "/{name}/settings" => return Some((section, NamedMapShape::Settings)),
                    _ => {}
                }
            }
        }
        None
    }

    pub fn contains(self, deploy: &DeployCfg, name: &str) -> bool {
        match self {
            NamedMapSection::IdentityProviders => deploy.identity_providers.contains_key(name),
            NamedMapSection::Export => deploy.export.contains_key(name),

            NamedMapSection::Plane(section) => deploy
                .plane_section(section)
                .is_some_and(|cfg| cfg.contains_def(name)),
        }
    }

    pub fn insert(
        self,
        deploy: &mut DeployCfg,
        name: &str,
        def: &serde_json::Value,
    ) -> Result<(), String> {
        self.parse_def(name, def)?.install(deploy, name)
    }

    pub fn parse_def(self, name: &str, def: &serde_json::Value) -> Result<NamedDef, String> {
        match self {
            NamedMapSection::IdentityProviders => serde_json::from_value(def.clone())
                .map_err(|e| format!("invalid `identity-providers.{name}` definition: {e}"))
                .and_then(|cfg: IdentityProviderCfg| {
                    if let Some(token) = cfg.max_admin_scope.as_deref() {
                        crate::config::parse::parse_ceiling(
                            &format!("`identity-providers.{name}`"),
                            token,
                        )?;
                    }

                    super::validate_token_placement(name, cfg.module.trim(), cfg.token.is_some())?;
                    Ok(NamedDef::IdentityProvider(cfg))
                }),
            NamedMapSection::Export => serde_json::from_value(def.clone())
                .map(NamedDef::Export)
                .map_err(|e| format!("invalid `export.{name}` definition: {e}")),

            NamedMapSection::Plane(_) => {
                if crate::plane_driver::registry::plane_decl_for_config_section(self.key())
                    .is_none()
                {
                    return Err(unknown_section(self.key()));
                }
                plane_config_validate(self, name, def)?;
                Ok(NamedDef::Plane {
                    section: self,
                    def: def.clone(),
                })
            }
        }
    }

    pub fn validate_def(self, name: &str, def: &serde_json::Value) -> Result<(), String> {
        self.parse_def(name, def).map(|_| ())
    }

    pub fn referents(self, deploy: &DeployCfg, name: &str) -> Vec<String> {
        let mut out = Vec::new();
        match self {
            NamedMapSection::IdentityProviders => {
                let Some(auth) = deploy.auth.as_ref() else {
                    return out;
                };
                if auth.chain.iter().any(|n| n == name) {
                    out.push("auth.chain".to_string());
                }
                if auth.admin_auth.iter().any(|n| n == name) {
                    out.push("auth.admin_auth".to_string());
                }
                if auth.role_bindings.contains_key(name) {
                    out.push(format!("auth.role_bindings.{name}"));
                }
            }
            NamedMapSection::Export => {}

            NamedMapSection::Plane(_) => {}
        }
        out
    }

    pub fn max_admin_scope(
        self,
        providers: &super::IdentityProviders,
        name: &str,
    ) -> Option<String> {
        match self {
            NamedMapSection::IdentityProviders => providers
                .get(name)
                .and_then(|def| def.max_admin_scope.clone()),
            NamedMapSection::Export => None,
            NamedMapSection::Plane(_) => None,
        }
    }
}

fn plane_config_validate(
    section: NamedMapSection,
    name: &str,
    def: &serde_json::Value,
) -> Result<(), String> {
    let Some(decl) = crate::plane_driver::registry::plane_decl_for_config_section(section.key())
    else {
        return Ok(());
    };

    let entry =
        serde_yaml::to_value(def).map_err(|e| format!("`{}.{name}`: {e}", section.key()))?;
    crate::config::plane_sections::validate_plane_entry(
        section.key(),
        name,
        &entry,
        decl.trust_keys,
        &crate::config::plane_sections::config_sections(),
    )?;

    crate::config::plane_sections::refuse_registration_forwarding_caller_credential(
        &format!("`{}.{name}`", section.key()),
        &entry,
        decl.caller_credential_refusal,
    )?;
    if let Some(f) = decl.config_validate {
        f(decl, name, def)?;
    }

    crate::trust::section::parse_entry(
        &format!("`{}.{name}`", section.key()),
        &entry,
        decl.trust_keys,
    )
    .map(|_| ())
}

pub enum NamedDef {
    IdentityProvider(IdentityProviderCfg),
    Export(ExportDefCfg),

    Plane {
        section: NamedMapSection,
        def: serde_json::Value,
    },
}

impl NamedDef {
    fn install(self, deploy: &mut DeployCfg, name: &str) -> Result<(), String> {
        match self {
            NamedDef::IdentityProvider(cfg) => {
                deploy.identity_providers.insert(name.to_string(), cfg);
                Ok(())
            }
            NamedDef::Export(cfg) => {
                deploy.export.insert(name.to_string(), cfg);
                Ok(())
            }
            NamedDef::Plane { section, def } => match section {
                NamedMapSection::Plane(key) => match deploy.plane_section_mut(key) {
                    Some(cfg) => cfg.insert_def(name, &def),
                    None => Err(unknown_section(key)),
                },

                NamedMapSection::IdentityProviders | NamedMapSection::Export => {
                    unreachable!("a core section never parses into NamedDef::Plane")
                }
            },
        }
    }
}

fn unknown_section(key: &str) -> String {
    format!("unknown field `{key}`")
}

/// Which of the three generic route SHAPES a path is. The error taxonomy declares ONE error set per
/// shape (not per section), which is what keeps a new section from needing a new taxonomy arm.
#[cfg_attr(not(any(test, feature = "openapi-schema")), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedMapShape {
    /// `GET <root>` — the collection read.
    Collection,
    /// `GET|PUT|DELETE <root>/{name}` — one definition.
    Item,
    /// `PATCH <root>/{name}/settings` — the opaque settings bag of one definition.
    Settings,
}

#[cfg(test)]
#[path = "tests/named_map_tests.rs"]
mod named_map_tests;

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NAMED-DEFINITION MAP SECTIONS — one description of the 1.5.3 universal config pattern.
//!
//! 1.5.3 froze the config grammar into ONE shape: every plugin-instance kind is a top-level NAMED
//! DEFINITION map (`name → {module, settings, …}`) referenced by bare name (audit-decisions §0). This
//! module is that shape expressed ONCE as data — which sections exist, where each lives on a
//! [`DeployCfg`], how a raw definition document is parsed into its typed config, and which other
//! config sites reference a name.
//!
//! Everything that serves the pattern is parameterized by [`NamedMapSection`] rather than written per
//! kind: the admin router mounts its five routes in a loop, the OpenAPI generator emits its path
//! items in a loop, the error taxonomy declares one set per route SHAPE, and the config overlay
//! stores every section in one `section → name → raw definition` map. Adding `tools:` (1.5.4 MCP) or
//! `agents:` (1.5.6 A2A) is therefore a ONE-VARIANT addition here plus its two accessors below — no
//! new route handler, no new overlay type, no new taxonomy arm, and no breaking change to anything
//! already shipped.
//!
//! `hooks:` and `store:` are deliberately NOT here: `hooks:` predates the generic path and keeps its
//! own richer surface (health/schema/status probes, grant immutability, the configure-ack settings
//! push), and `store:` is singular — there is no map to name into.

use super::{DeployCfg, ExportDefCfg, IdentityProviderCfg};

/// One 1.5.3 named-DEFINITION map section. The variant set is the ONLY thing a new section adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum NamedMapSection {
    /// `identity-providers:` — provider NAME → `{module, settings, max_admin_scope, token,
    /// browser_login}`, referenced by bare name from `auth.chain:` / `auth.admin_auth:` /
    /// `auth.role_bindings:`.
    IdentityProviders,
    /// `export:` — instance NAME → `{module, settings}`, the single telemetry-egress surface.
    Export,
    // 1.5.4: `Tools` (MCP server registry). 1.5.6: `Agents` (A2A agent registry). Both land as one
    // variant each plus their arms in the `match`es below.
}

impl NamedMapSection {
    /// Every section, in route/mount order. The router, the OpenAPI generator and the overlay
    /// applier all iterate THIS — so a new variant is live everywhere the moment it is added.
    pub(crate) const ALL: &'static [NamedMapSection] =
        &[NamedMapSection::IdentityProviders, NamedMapSection::Export];

    /// The config key AND the admin path segment — they are deliberately the same string, so the API
    /// mirrors the config grammar exactly (`export:` ⇄ `/export`).
    pub(crate) fn key(self) -> &'static str {
        match self {
            NamedMapSection::IdentityProviders => "identity-providers",
            NamedMapSection::Export => "export",
        }
    }

    /// The RELATIVE (post-`ADMIN_PREFIX`) collection path — `"/" + key()`.
    pub(crate) fn path_root(self) -> &'static str {
        match self {
            NamedMapSection::IdentityProviders => "/identity-providers",
            NamedMapSection::Export => "/export",
        }
    }

    /// Singular human noun for messages and audit resources (`identity-provider:corp-ad`).
    pub(crate) fn singular(self) -> &'static str {
        match self {
            NamedMapSection::IdentityProviders => "identity-provider",
            NamedMapSection::Export => "exporter",
        }
    }

    /// Whether this section's definitions carry a `max_admin_scope` TRUST CEILING — the one
    /// security-relevant asymmetry between the sections, kept as a predicate so the generic handler
    /// stays generic (see `admin::v1::json::named_map`'s ceiling guard).
    pub(crate) fn has_trust_ceiling(self) -> bool {
        matches!(self, NamedMapSection::IdentityProviders)
    }

    /// Parse a RELATIVE admin path into `(section, shape)` — the seam the error taxonomy and the
    /// OpenAPI/doc audits key off, so none of them hand-writes the five path strings per section.
    // Consumed by the error taxonomy + the doc audits, both of which are `test`/`openapi-schema`
    // gated; genuinely absent from a shipped build, so allow it there rather than deleting the seam.
    #[cfg_attr(not(any(test, feature = "openapi-schema")), allow(dead_code))]
    pub(crate) fn parse_rel(rel: &str) -> Option<(NamedMapSection, NamedMapShape)> {
        for section in NamedMapSection::ALL {
            let root = section.path_root();
            if rel == root {
                return Some((*section, NamedMapShape::Collection));
            }
            if let Some(tail) = rel.strip_prefix(root) {
                match tail {
                    "/{name}" => return Some((*section, NamedMapShape::Item)),
                    "/{name}/settings" => return Some((*section, NamedMapShape::Settings)),
                    _ => {}
                }
            }
        }
        None
    }

    /// Is `name` present in this section of `deploy`? Called on a FRESHLY disk-loaded (pre-overlay)
    /// `DeployCfg` to answer "is this entry base-config-defined?", the guard that stops the API
    /// silently shadowing operator file config (the same posture the hooks surface takes).
    pub(crate) fn contains(self, deploy: &DeployCfg, name: &str) -> bool {
        match self {
            NamedMapSection::IdentityProviders => deploy.identity_providers.contains_key(name),
            NamedMapSection::Export => deploy.export.contains_key(name),
        }
    }

    /// Parse a raw definition document into this section's typed config and insert it under `name`.
    /// The typed structs are `deny_unknown_fields`, so a typo'd key is rejected HERE — the API can
    /// never store a definition that config.yaml would refuse.
    pub(crate) fn insert(
        self,
        deploy: &mut DeployCfg,
        name: &str,
        def: &serde_json::Value,
    ) -> Result<(), String> {
        self.parse_def(name, def)?.install(deploy, name);
        Ok(())
    }

    /// THE ONE typed parse of a raw definition document — `deny_unknown_fields`, so a typo'd or
    /// unknown key is a loud reject exactly as `config.yaml` would give.
    ///
    /// Split out of [`NamedMapSection::insert`] so the ADMIN WRITE PATH can run the identical parse
    /// BEFORE it persists anything, without needing a `DeployCfg` to insert into. Both callers go
    /// through this one function precisely so the two paths can never disagree about the grammar:
    /// the API rejects exactly what the file rejects, because it runs the same `serde` parse against
    /// the same structs. (Before this existed the API only checked "is it an object with a
    /// non-empty `module`", accepted an unknown field, persisted it verbatim, and then DROPPED it at
    /// the next rebuild with only a log line — two paths, two grammars.)
    pub(crate) fn parse_def(self, name: &str, def: &serde_json::Value) -> Result<NamedDef, String> {
        match self {
            NamedMapSection::IdentityProviders => serde_json::from_value(def.clone())
                .map(NamedDef::IdentityProvider)
                .map_err(|e| format!("invalid `identity-providers.{name}` definition: {e}")),
            NamedMapSection::Export => serde_json::from_value(def.clone())
                .map(NamedDef::Export)
                .map_err(|e| format!("invalid `export.{name}` definition: {e}")),
        }
    }

    /// `Ok(())` iff `def` parses into this section's typed config — the write-path validation twin of
    /// [`NamedMapSection::parse_def`], which it delegates to so there is only ever one grammar.
    pub(crate) fn validate_def(self, name: &str, def: &serde_json::Value) -> Result<(), String> {
        self.parse_def(name, def).map(|_| ())
    }

    /// Every OTHER config site that still references `name` BY BARE NAME, as human path strings.
    /// Non-empty ⇒ removing the definition would leave a DANGLING REFERENCE, which the generic
    /// DELETE refuses as a terminal `conflict` (naming the referents) instead of letting `resolve`
    /// fail later with a less actionable message.
    ///
    /// `export:` names are referenced from nowhere in 1.5.3 (an exporter is a leaf), so it returns
    /// empty — the check is not skipped for it, it simply has nothing to find. `tools:`/`agents:`
    /// will add their own reference sites here.
    pub(crate) fn referents(self, deploy: &DeployCfg, name: &str) -> Vec<String> {
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
        }
        out
    }

    /// This entry's CURRENT `max_admin_scope` ceiling token, or `None` for a section that has no
    /// ceiling / an entry that names none (⇒ the most restrictive default applies). Read from the
    /// EFFECTIVE map so the ceiling guard compares against what is actually live.
    pub(crate) fn max_admin_scope(
        self,
        providers: &super::IdentityProviders,
        name: &str,
    ) -> Option<String> {
        match self {
            NamedMapSection::IdentityProviders => providers
                .get(name)
                .and_then(|def| def.max_admin_scope.clone()),
            NamedMapSection::Export => None,
        }
    }
}

/// One successfully-parsed named-map definition, still un-installed. The intermediate value of
/// [`NamedMapSection::parse_def`] — it exists so "did this parse?" and "install it" are the SAME
/// parse rather than two, which is what keeps the API's reject set identical to the file's.
pub(crate) enum NamedDef {
    IdentityProvider(IdentityProviderCfg),
    Export(ExportDefCfg),
}

impl NamedDef {
    /// Install this parsed definition into `deploy` under `name`. Infallible: the fallible half was
    /// the parse.
    fn install(self, deploy: &mut DeployCfg, name: &str) {
        match self {
            NamedDef::IdentityProvider(cfg) => {
                deploy.identity_providers.insert(name.to_string(), cfg);
            }
            NamedDef::Export(cfg) => {
                deploy.export.insert(name.to_string(), cfg);
            }
        }
    }
}

/// Which of the three generic route SHAPES a path is. The error taxonomy declares ONE error set per
/// shape (not per section), which is what keeps a new section from needing a new taxonomy arm.
// Same gating as `parse_rel`, which is its only producer.
#[cfg_attr(not(any(test, feature = "openapi-schema")), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NamedMapShape {
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

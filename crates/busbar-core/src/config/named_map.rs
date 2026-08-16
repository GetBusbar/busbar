// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NAMED-DEFINITION MAP SECTIONS — one description of the 1.5.3 universal config pattern.
//!
//! 1.5.3 froze the config grammar into ONE shape: every plugin-instance kind is a top-level NAMED
//! DEFINITION map (`name → {module, settings, …}`) referenced by bare name. This
//! module is that shape expressed ONCE as data — which sections exist, where each lives on a
//! [`DeployCfg`], how a raw definition document is parsed into its typed config, and which other
//! config sites reference a name.
//!
//! Everything that serves the pattern is parameterized by [`NamedMapSection`] rather than written per
//! kind: the admin router mounts its five routes in a loop, the OpenAPI generator emits its path
//! items in a loop, the error taxonomy declares one set per route SHAPE, and the config overlay
//! stores every section in one `section → name → raw definition` map. Adding `tools:` (1.6.0 MCP) or
//! `agents:` (1.6.0 A2A) is therefore a ONE-VARIANT addition here plus its two accessors below — no
//! new route handler, no new overlay type, no new taxonomy arm, and no breaking change to anything
//! already shipped.
//!
//! `hooks:` and `store:` are deliberately NOT here: `hooks:` predates the generic path and keeps its
//! own richer surface (health/schema/status probes, grant immutability, the configure-ack settings
//! push), and `store:` is singular — there is no map to name into.

use crate::a2a::config::AgentDefCfg;

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
    /// `tools:` — server NAME → `{url, pin, tools_allow, …}`, THE MCP PLANE: one registered external
    /// MCP server per entry. The admin path segment is `tools` and NOT `mcp`,
    /// deliberately: the config block is LOCKED as `tools:` — its mere existence is what declares
    /// the plane, the way `pools:` declares the LLM plane — and this table's whole discipline is
    /// that [`NamedMapSection::key`] is both the config key and the path segment, so the API mirrors
    /// the config grammar exactly. An earlier `/api/v1/admin/mcp/*` spelling of this same surface
    /// predates that lock and is superseded by it — a second spelling of one plane is the thing
    /// this table exists to prevent.
    Tools,
    /// `agents:` — agent NAME → `{url, pin, reverify_ttl, …}`, THE A2A plane: one registered
    /// external agent per entry, referenced by bare name. Sibling in shape to `pools:`, and no
    /// entry on it may reference an entry on another plane.
    Agents,
}

impl NamedMapSection {
    /// Every section, in route/mount order. The router, the OpenAPI generator and the overlay
    /// applier all iterate THIS — so a new variant is live everywhere the moment it is added.
    pub(crate) const ALL: &'static [NamedMapSection] = &[
        NamedMapSection::IdentityProviders,
        NamedMapSection::Export,
        NamedMapSection::Tools,
        NamedMapSection::Agents,
    ];

    /// The config key AND the admin path segment — they are deliberately the same string, so the API
    /// mirrors the config grammar exactly (`export:` ⇄ `/export`).
    pub(crate) fn key(self) -> &'static str {
        match self {
            NamedMapSection::IdentityProviders => "identity-providers",
            NamedMapSection::Export => "export",
            NamedMapSection::Tools => "tools",
            NamedMapSection::Agents => "agents",
        }
    }

    /// The RELATIVE (post-`ADMIN_PREFIX`) collection path — `"/" + key()`.
    pub(crate) fn path_root(self) -> &'static str {
        match self {
            NamedMapSection::IdentityProviders => "/identity-providers",
            NamedMapSection::Export => "/export",
            NamedMapSection::Tools => "/tools",
            NamedMapSection::Agents => "/agents",
        }
    }

    /// Singular human noun for messages and audit resources (`identity-provider:corp-ad`).
    pub(crate) fn singular(self) -> &'static str {
        match self {
            NamedMapSection::IdentityProviders => "identity-provider",
            NamedMapSection::Export => "exporter",
            NamedMapSection::Tools => "mcp-server",
            NamedMapSection::Agents => "agent",
        }
    }

    /// Whether a definition in this section is a PLUGIN INSTANCE, and therefore must name a backing
    /// `module:`.
    ///
    /// Every 1.5.3 section was one, so the generic write path simply demanded `module:`. The two
    /// PLANE sections are the ones that are NOT: a `tools:` entry and an `agents:` entry each
    /// describe a REMOTE ENDPOINT that somebody else runs, and there is no plugin behind either to
    /// name. That both planes landed on the same exception independently is the argument for it
    /// living here: the requirement is a per-section property in this table rather than a hardcoded
    /// rule in the handler, for the same reason [`NamedMapSection::has_trust_ceiling`] is — the
    /// handler stays generic and the asymmetry stays visible where a reader can find it.
    pub(crate) fn requires_module(self) -> bool {
        !matches!(self, NamedMapSection::Tools | NamedMapSection::Agents)
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
            NamedMapSection::Tools => deploy.tools.servers.contains_key(name),
            NamedMapSection::Agents => deploy.agents.agents.contains_key(name),
        }
    }

    /// This section's CURRENT entry for `name`, projected back to a raw definition document, or
    /// `None` when there is no such entry.
    ///
    /// The base half of the overlay's per-entry MERGE: an overlay entry is a PATCH
    /// ([`crate::config::patch::merge_entry`]), so the thing being patched has to be a document. The
    /// projection round-trips into the same struct it came from, so a field that survives the merge
    /// untouched parses back to exactly the value it had.
    pub(crate) fn entry_as_document(
        self,
        deploy: &DeployCfg,
        name: &str,
    ) -> Option<serde_json::Value> {
        match self {
            NamedMapSection::IdentityProviders => deploy
                .identity_providers
                .get(name)
                .and_then(|cfg| serde_json::to_value(cfg).ok()),
            NamedMapSection::Export => deploy
                .export
                .get(name)
                .and_then(|cfg| serde_json::to_value(cfg).ok()),
            NamedMapSection::Tools => deploy
                .tools
                .servers
                .get(name)
                .and_then(|cfg| serde_json::to_value(cfg).ok()),
            NamedMapSection::Agents => deploy
                .agents
                .agents
                .get(name)
                .and_then(|cfg| serde_json::to_value(cfg).ok()),
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
    ///
    /// `serde` alone is not the whole grammar: a field typed `Option<String>` accepts EVERY string,
    /// including tokens `config_validate` refuses to boot. So the VALUE-level rules that boot
    /// enforces run here too, through the same functions boot calls — see the `max_admin_scope`
    /// check below ([`Scope::parse_ceiling`](crate::admin::v1::contract::Scope::parse_ceiling)).
    pub(crate) fn parse_def(self, name: &str, def: &serde_json::Value) -> Result<NamedDef, String> {
        match self {
            NamedMapSection::IdentityProviders => serde_json::from_value(def.clone())
                .map_err(|e| format!("invalid `identity-providers.{name}` definition: {e}"))
                .and_then(|cfg: IdentityProviderCfg| {
                    // The CEILING TOKEN, checked with the very function `config_validate`'s
                    // chain-entry rule uses. `resolve_auth` copies this value onto every resolved
                    // `AuthChainEntry`, so an unknown token here is a HARD BOOT ERROR — without this
                    // the API answered 200 and the gateway then refused to start.
                    if let Some(token) = cfg.max_admin_scope.as_deref() {
                        crate::admin::v1::contract::Scope::parse_ceiling(
                            &format!("`identity-providers.{name}`"),
                            token,
                        )?;
                    }
                    // A MISPLACED SECRET, by the rule `resolve_auth` applies — which only ever sees
                    // providers already REFERENCED from a chain, so a definition written through the
                    // API and not yet referenced slipped past it.
                    super::validate_token_placement(name, cfg.module.trim(), cfg.token.is_some())?;
                    Ok(NamedDef::IdentityProvider(cfg))
                }),
            NamedMapSection::Export => serde_json::from_value(def.clone())
                .map(NamedDef::Export)
                .map_err(|e| format!("invalid `export.{name}` definition: {e}")),
            NamedMapSection::Tools => serde_json::from_value(def.clone())
                .map_err(|e| format!("invalid `tools.{name}` definition: {e}"))
                .and_then(|cfg: crate::mcp::config::McpServerDefCfg| {
                    // THE VALUE RULES, run through the very function the FILE path runs (the custom
                    // `Deserialize` for `ToolsCfg` calls the same `validate_server`). ONE GRAMMAR,
                    // TWO PATHS: the API rejects exactly what `config.yaml` rejects, because both
                    // reach this function. Without it the API would accept an `unpinned` server
                    // carrying key material, or a `stdio` transport nothing implements, persist it,
                    // and then have boot refuse the file it wrote.
                    crate::mcp::config::validate_server(name, &cfg)?;
                    Ok(NamedDef::Tool(Box::new(cfg)))
                }),
            NamedMapSection::Agents => serde_json::from_value(def.clone())
                .map_err(|e| format!("invalid `agents.{name}` definition: {e}"))
                .and_then(|cfg: AgentDefCfg| {
                    // THE SAME VALUE RULES BOOT APPLIES, through the same function boot calls: the
                    // pin's mechanism must match the material it carries, the durations must
                    // parse, and no hook reference may reach onto another plane. Without this the
                    // API would accept a `jws_issuer_key` pin with nothing to verify against, and
                    // the operator would read a registration as protected when it is not.
                    crate::a2a::config::validate_agent(name, &cfg)?;
                    Ok(NamedDef::Agent(cfg))
                }),
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
            // An MCP server is referenced from nowhere BY NAME in config: a `tools:` entry is a leaf
            // like an exporter. It IS named by a caller's `mcp_server`/`mcp_tool` key GRANTS, but a
            // grant lives on a key in the store, not in this config document, and a dangling grant
            // is fail-closed by construction (`scope_allowed` matches nothing) rather than a boot
            // error. So the check is not skipped for `tools:` — it has nothing here to find.
            NamedMapSection::Tools => {}
            // An agent is referenced from nowhere else in config: the catalogue is derived from
            // the registry rather than named from it, and cross-plane reference is refused
            // outright. So there is nothing to find here -- which is not the same as not looking.
            NamedMapSection::Agents => {}
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
            NamedMapSection::Tools => None,
            NamedMapSection::Agents => None,
        }
    }
}

/// One successfully-parsed named-map definition, still un-installed. The intermediate value of
/// [`NamedMapSection::parse_def`] — it exists so "did this parse?" and "install it" are the SAME
/// parse rather than two, which is what keeps the API's reject set identical to the file's.
pub(crate) enum NamedDef {
    IdentityProvider(IdentityProviderCfg),
    Export(ExportDefCfg),
    // BOXED because `McpServerDefCfg` carries three `IndexMap`s and is by far the largest variant;
    // an unboxed one would make every `NamedDef` — including the two small ones on the hot admin
    // write path — as wide as the widest.
    Tool(Box<crate::mcp::config::McpServerDefCfg>),
    Agent(AgentDefCfg),
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
            NamedDef::Tool(cfg) => {
                deploy.tools.servers.insert(name.to_string(), *cfg);
            }
            NamedDef::Agent(cfg) => {
                deploy.agents.agents.insert(name.to_string(), cfg);
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

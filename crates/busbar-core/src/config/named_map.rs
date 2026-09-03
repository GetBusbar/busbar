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

use super::{DeployCfg, ExportDefCfg, IdentityProviderCfg};

/// One 1.5.3 named-DEFINITION map section. The variant set is the ONLY thing a new section adds.
///
/// The two 1.5.3-native sections are in-core NAMES ([`NamedMapSection::IdentityProviders`],
/// [`NamedMapSection::Export`]). Every PLANE-owned named-map section — `tools:` (MCP), `agents:`
/// (A2A), and any registered plane's own named-definition map — is a single [`NamedMapSection::Plane`]
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
    /// ([`PlaneDecl::config_section`](crate::plane::registry::PlaneDecl::config_section)) as OPAQUE
    /// DATA. `tools:` (server NAME → `{url, pin, tools_allow, …}`, the MCP plane) and `agents:`
    /// (agent NAME → `{url, pin, reverify_ttl, …}`, the A2A plane) are its two 1.6.0 instances, and a
    /// registered plane declaring a `named_def_list` is another. The config key is LOCKED to the
    /// plane's section — its mere existence is what declares the plane, the way `pools:` declares the
    /// LLM plane — and [`NamedMapSection::key`] is both the config key and the admin path segment, so
    /// the API mirrors the config grammar exactly. Core spells no `tools`/`agents` literal to build
    /// this: a plane's section reaches the chassis through [`NamedMapSection::sections`], folded from
    /// the plane registry.
    Plane(&'static str),
}

impl NamedMapSection {
    /// Every section, in route/mount order. The router, the OpenAPI generator and the overlay
    /// applier all iterate THIS — so a section is live everywhere the moment it exists.
    ///
    /// FOLDED, not fixed: the two in-core sections ([`NamedMapSection::IdentityProviders`],
    /// [`NamedMapSection::Export`]) followed by one [`NamedMapSection::Plane`] per registered plane
    /// whose decl declares a `named_def_list` (its named-definition-map admin surface), in the
    /// registry's canonical layering order. So `tools:`/`agents:` appear here exactly when their
    /// planes are compiled in, and a registered plane's own named map joins with nothing written
    /// here. Under the default/test/openapi feature set the fold is
    /// `[identity-providers, export, tools, agents]` — the frozen 1.5.3 order.
    ///
    /// This is a REGISTRY-DERIVED list, so it goes EMPTY of plane sections when a plane is compiled
    /// out. It must NOT be the source the config deletion-gate reads (that would silently accept a
    /// `tools:` block for a compiled-out plane) — the gate reads the frozen static
    /// [`busbar_substrate::plane::config::NAMED_MAP_SECTIONS`] instead.
    pub fn sections() -> Vec<NamedMapSection> {
        let mut out = vec![NamedMapSection::IdentityProviders, NamedMapSection::Export];
        for decl in crate::plane::registry::plane_decls() {
            if decl.named_def_list.is_some() {
                out.push(NamedMapSection::Plane(decl.config_section));
            }
        }
        out
    }

    /// The config key AND the admin path segment — they are deliberately the same string, so the API
    /// mirrors the config grammar exactly (`export:` ⇄ `/export`).
    pub fn key(self) -> &'static str {
        match self {
            NamedMapSection::IdentityProviders => "identity-providers",
            NamedMapSection::Export => "export",
            NamedMapSection::Plane(section) => section,
        }
    }

    /// The RELATIVE (post-`ADMIN_PREFIX`) collection path — `"/" + key()`. A plane section synthesises
    /// its path from the registry-supplied section key, so this returns an OWNED `Cow` for the plane
    /// arm and a `'static` borrow for the two core arms.
    pub fn path_root(self) -> std::borrow::Cow<'static, str> {
        match self {
            NamedMapSection::IdentityProviders => std::borrow::Cow::Borrowed("/identity-providers"),
            NamedMapSection::Export => std::borrow::Cow::Borrowed("/export"),
            NamedMapSection::Plane(section) => std::borrow::Cow::Owned(format!("/{section}")),
        }
    }

    /// Singular human noun for messages and audit resources (`identity-provider:corp-ad`).
    ///
    /// The two 1.5.3-native sections carry their noun as a literal; a PLANE section reads it from the
    /// owning plane's [`PlaneDecl::admin_noun`](crate::plane::registry::PlaneDecl::admin_noun) via the
    /// registry, so core stamps a registered plane's audit/error noun without a hard-coded plane
    /// literal. With the owning plane compiled out (no registered decl) `singular` is never reached —
    /// a definition on an absent plane is refused before any noun is stamped — but it still answers
    /// the section key rather than panicking.
    pub(crate) fn singular(self) -> &'static str {
        match self {
            NamedMapSection::IdentityProviders => "identity-provider",
            NamedMapSection::Export => "exporter",
            NamedMapSection::Plane(_) => {
                crate::plane::registry::plane_decl_for_config_section(self.key())
                    .map(|d| d.admin_noun)
                    .unwrap_or_else(|| self.key())
            }
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
    pub fn requires_module(self) -> bool {
        !matches!(self, NamedMapSection::Plane(_))
    }

    /// Whether this section's definitions carry a `max_admin_scope` TRUST CEILING — the one
    /// security-relevant asymmetry between the sections, kept as a predicate so the generic handler
    /// stays generic (see `admin::v1::json::named_map`'s ceiling guard).
    pub fn has_trust_ceiling(self) -> bool {
        matches!(self, NamedMapSection::IdentityProviders)
    }

    /// Parse a RELATIVE admin path into `(section, shape)` — the seam the error taxonomy and the
    /// OpenAPI/doc audits key off, so none of them hand-writes the five path strings per section.
    // Consumed by the error taxonomy + the doc audits, both of which are `test`/`openapi-schema`
    // gated; genuinely absent from a shipped build, so allow it there rather than deleting the seam.
    #[cfg_attr(not(any(test, feature = "openapi-schema")), allow(dead_code))]
    pub(crate) fn parse_rel(rel: &str) -> Option<(NamedMapSection, NamedMapShape)> {
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

    /// Is `name` present in this section of `deploy`? Called on a FRESHLY disk-loaded (pre-overlay)
    /// `DeployCfg` to answer "is this entry base-config-defined?", the guard that stops the API
    /// silently shadowing operator file config (the same posture the hooks surface takes).
    pub(crate) fn contains(self, deploy: &DeployCfg, name: &str) -> bool {
        match self {
            NamedMapSection::IdentityProviders => deploy.identity_providers.contains_key(name),
            NamedMapSection::Export => deploy.export.contains_key(name),
            // A plane registry section reads through its always-present type-erased seam, resolved
            // by config section. With the owning plane compiled out the seam holds a
            // `RawPlaneSection`, whose `contains_def` is empty (a present section is refused at
            // resolve), so no name is base-config-defined on it — the same answer the per-plane
            // feature gate used to give, without naming a plane.
            NamedMapSection::Plane(section) => deploy
                .plane_section(section)
                .is_some_and(|cfg| cfg.contains_def(name)),
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
            // A plane registry section projects through its always-present seam, resolved by config
            // section; a compiled-out plane's `RawPlaneSection` has no entry document (`None`), the
            // same answer the feature gate gave.
            NamedMapSection::Plane(section) => deploy
                .plane_section(section)
                .and_then(|cfg| cfg.entry_document(name)),
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
        self.parse_def(name, def)?.install(deploy, name)
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
            // A PLANE REGISTRY SECTION (`tools:`/`agents:`), routed through the OWNING PLANE's
            // `config_validate` seam resolved by config section — so the write path enforces exactly
            // the grammar boot enforces (the plane's own `Deserialize`/boot reaches the identical
            // function) and core names no `crate::mcp`/`crate::a2a` validate function. Without this an
            // `unpinned` server carrying key material, a `stdio` transport nothing implements, or a
            // `jws_issuer_key` pin with nothing to verify against would be persisted and then refused
            // by boot. The typed parse that builds the object the overlay installs is deferred to
            // `install`'s `PlaneCfg::insert_def`, so core names no plane entry type here.
            //
            // With the section's owning plane compiled out there is no registered decl: a definition
            // then names a plane this build does not carry, refused HERE exactly as `resolve` refuses
            // a present `tools:`/`agents:` section — naming the SECTION (its plane-declared grammar
            // key), not a hard-coded plane.
            NamedMapSection::Plane(_) => {
                if crate::plane::registry::plane_decl_for_config_section(self.key()).is_none() {
                    let section = self.key();
                    return Err(format!(
                        "`{section}.{name}`: this build was compiled without the plane that owns the \
                         `{section}:` section, so it cannot register this definition."
                    ));
                }
                plane_config_validate(self, name, def)?;
                Ok(NamedDef::Plane {
                    section: self,
                    def: def.clone(),
                })
            }
        }
    }

    /// `Ok(())` iff `def` parses into this section's typed config — the write-path validation twin of
    /// [`NamedMapSection::parse_def`], which it delegates to so there is only ever one grammar.
    pub fn validate_def(self, name: &str, def: &serde_json::Value) -> Result<(), String> {
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
            // A plane-owned registration is referenced from nowhere else in config. An MCP server
            // (`tools:`) is a leaf like an exporter: it IS named by a caller's `mcp_server`/`mcp_tool`
            // key GRANTS, but a grant lives on a key in the store, not in this config document, and a
            // dangling grant is fail-closed by construction (`scope_allowed` matches nothing) rather
            // than a boot error. An agent (`agents:`) catalogue is derived from the registry rather
            // than named from it, and cross-plane reference is refused outright. So there is nothing
            // to find here — which is not the same as not looking.
            NamedMapSection::Plane(_) => {}
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
            NamedMapSection::Plane(_) => None,
        }
    }
}

/// Validate a named-definition write through the OWNING PLANE's
/// [`config_validate`](crate::plane::registry::PlaneDecl::config_validate) seam, resolved by config
/// section — so core routes a `tools:`/`agents:` write to the plane's own validator without naming a
/// `crate::mcp`/`crate::a2a` validate function. A section whose plane declares no validator (none of
/// the sections that reach this helper) validates vacuously; a section whose plane is compiled out is
/// refused by the caller before it reaches here.
fn plane_config_validate(
    section: NamedMapSection,
    name: &str,
    def: &serde_json::Value,
) -> Result<(), String> {
    match crate::plane::registry::plane_decl_for_config_section(section.key())
        .and_then(|d| d.config_validate)
    {
        Some(f) => f(name, def),
        None => Ok(()),
    }
}

/// One successfully-parsed named-map definition, still un-installed. The intermediate value of
/// [`NamedMapSection::parse_def`] — it exists so "did this parse?" and "install it" are the SAME
/// parse rather than two, which is what keeps the API's reject set identical to the file's.
pub(crate) enum NamedDef {
    IdentityProvider(IdentityProviderCfg),
    Export(ExportDefCfg),
    // A PLANE SECTION'S entry, kept as the VALIDATED RAW document rather than the plane's typed config
    // — so core names no `crate::mcp`/`crate::a2a` entry type. `parse_def` has already run the plane's
    // `config_validate` value rules (and its `deny_unknown_fields` parse) on `def`; `install` hands it
    // straight back to the section's `PlaneCfg::insert_def`, which does the typed parse and insert
    // byte-identically. Absent when NEITHER plane is compiled in (nothing parses a `tools:`/`agents:`
    // definition then — `parse_def` refuses with a compiled-out message before constructing this).
    Plane {
        section: NamedMapSection,
        def: serde_json::Value,
    },
}

impl NamedDef {
    /// Install this parsed definition into `deploy` under `name`. The two core sections are infallible
    /// (the fallible half was their parse); a plane section hands its validated document to the
    /// section's `PlaneCfg::insert_def`, which does the plane's typed parse — a fail-closed backstop
    /// that cannot fire on a definition that already passed `parse_def`'s `config_validate`.
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
                // The plane section installs through its always-present type-erased seam, resolved by
                // config section. `parse_def` already refused a compiled-out plane, so the accessor
                // is present here; a fail-closed `None` backstop keeps core from panicking if it is
                // not.
                NamedMapSection::Plane(key) => match deploy.plane_section_mut(key) {
                    Some(cfg) => cfg.insert_def(name, &def),
                    None => Err(format!(
                        "`{key}`: this build was compiled without the plane that owns this section, \
                         so it cannot install this definition."
                    )),
                },
                // Only the `Plane` arm of `parse_def` constructs `NamedDef::Plane`.
                NamedMapSection::IdentityProviders | NamedMapSection::Export => {
                    unreachable!("a core section never parses into NamedDef::Plane")
                }
            },
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

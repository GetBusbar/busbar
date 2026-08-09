// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CATALOGUE — the versioned snapshot every MCP answer is computed from, and the two checks that
//! ride it: the grant scope filter (owner ruling 2) and the dispatch-time re-validation (§3.9a as
//! restated by §14.2).
//!
//! ## One snapshot, one generation, an atomic swap
//!
//! §3.9a: the catalogue is a VERSIONED SNAPSHOT built once per config apply and swapped atomically,
//! and dispatch RE-VALIDATES the bound identity and hash pin against the CURRENT snapshot
//! immediately before the call goes out. The swap mechanism is the one the router already uses —
//! `AppHandle`'s `RwLock<Arc<App>>` — so this module does not invent a second hot-swap discipline;
//! it contributes the immutable value that rides in it, plus the monotonic generation that makes a
//! swap DETECTABLE from inside a request.
//!
//! [`PIN_GENERATION`] is process-global and monotonic rather than a field derived from config
//! content. That is deliberate: a content hash would compare equal after a change-and-revert, and
//! §14.2's rule is about whether the operator's approval was REPLACED, not about whether it happens
//! to look the same. A counter cannot compare equal to a previous value, so a call resolved under
//! generation N is refused under N+1 whatever the new snapshot says.
//!
//! ## The filter is AUTHORIZATION, not routing
//!
//! Owner ruling 2 (LOCKED): which tools a caller can see in the catalogue is decided by the caller's
//! KEY SCOPES — `mcp_server` and `mcp_tool` `ScopeRef` kinds — and by nothing else. There is no hook
//! on the catalogue path, no filter verb in the reply contract, no tag convention. TAGS GROUP,
//! IDENTITY IDENTIFIES; the catalogue names one specific thing, so it uses identity.
//!
//! Both grants must pass, and that is not belt-and-braces: `mcp_server` is "may this caller reach
//! this upstream at all" and `mcp_tool` is "may it reach this capability", and a key scoped to one
//! tool on a server must not acquire the rest by having been let through the door.
//!
//! ## Candidates are BOUND IDENTITIES, never descriptions
//!
//! §3.0. A catalogue entry is keyed on `(server-id, namespaced-name, schema-hash)`. The description
//! is carried for display, is markup-normalised on the way out (§3.5), and is never read by any
//! decision in this module — which is checkable rather than asserted, because [`ToolEntry::description`]
//! is the only place it appears and nothing in [`Catalogue`] calls it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use super::config::{McpServerDefCfg, ToolsCfg, NAMESPACE_SEP};

/// THE PIN GENERATION SOURCE. Monotonic, process-global, bumped once per snapshot BUILD.
///
/// Starts at 1 so that `0` is never a live generation and can therefore be used by a test (or a
/// future caller with nothing selected yet) as an unambiguous "no generation".
static PIN_GENERATION: AtomicU64 = AtomicU64::new(1);

/// ONE approved capability, as the bound identity §3.0 requires plus the inert display fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ToolEntry {
    /// The registered server id — the first half of the bound identity.
    pub(crate) server: String,
    /// The bare tool name as the upstream spells it.
    pub(crate) tool: String,
    /// `{server}_{tool}` — THE ROUTING KEY (§2.1, §3.0), and the value an `mcp_tool` grant names.
    pub(crate) namespaced: String,
    /// The APPROVED schema/description hash (§3.3). `None` means the operator has allowed the tool
    /// but approved no hash, which is `pending`: it is CATALOGUED (so an operator can see what is
    /// waiting) and it does NOT dispatch (there is no approved digest to compare against).
    pub(crate) schema_hash: Option<String>,
    /// Display only. Never read by a decision in this module — see the header.
    pub(crate) description: Option<String>,
    /// The tool's JSON Schema, echoed verbatim. Opaque to busbar.
    pub(crate) input_schema: Option<serde_json::Value>,
}

/// One exposed prompt. Sanitised at the edge (§3.5), never here — this is the store, not the writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PromptEntry {
    pub(crate) server: String,
    pub(crate) name: String,
    pub(crate) namespaced: String,
    pub(crate) description: Option<String>,
    pub(crate) template: Option<String>,
}

/// One exposed resource.
///
/// NAMESPACED like everything else, and that is a correction rather than a symmetry: keying the
/// catalogue by the upstream's raw URI let two registered servers exposing the SAME URI collide, and
/// the collision was SILENT — one entry simply replaced the other, so a caller granted the first
/// server read the second server's content. That is threat 3 (name overlap) arriving through a key
/// nobody thought of as a name. The wire `uri` is therefore `{server}_{uri}`, which a client treats
/// as the opaque identifier every MCP resource URI already is and hands back verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResourceEntry {
    pub(crate) server: String,
    /// The upstream's own URI, for display and for the eventual outbound call.
    pub(crate) uri: String,
    /// `{server}_{uri}` — what the wire carries and what a grant names.
    pub(crate) namespaced: String,
    pub(crate) name: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) mime_type: Option<String>,
    pub(crate) text: Option<String>,
}

/// One registered server's dispatch-relevant facts, carried alongside its capabilities so a call
/// never has to reach back into config to find out what it is allowed to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerEntry {
    pub(crate) id: String,
    pub(crate) url: String,
    /// The mechanism NAME. Operator-facing and audit-facing only; never interpreted, exactly as
    /// [`crate::trust::PinnedArtifact::mechanism`] is never interpreted.
    pub(crate) pin_mechanism: &'static str,
    /// Whether this registration has an authenticity root at all. `unpinned` is registrable and
    /// never servable (§3.2 / §5.5.2 "register → pending … cannot serve traffic").
    pub(crate) pinned: bool,
    /// The server-initiated request grants (§3.10 / §14.3). Deny-by-default by construction.
    pub(crate) grants: super::config::ServerRequestGrants,
    /// The hard cap on input-required rounds per logical dispatch (§14.3 part 3).
    pub(crate) max_input_required_rounds: u32,
}

/// THE VERSIONED SNAPSHOT. Immutable once built; replaced wholesale, never mutated in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Catalogue {
    /// The monotonic pin generation this snapshot was built under. Read by dispatch, compared
    /// against the generation selection saw, and never derived from content — see the header.
    generation: u64,
    servers: BTreeMap<String, ServerEntry>,
    /// Keyed by the NAMESPACED name, because that is the routing key and the grant value. A
    /// `BTreeMap` rather than a `Vec` so `tools/list` is deterministic and lookup is not a scan.
    tools: BTreeMap<String, ToolEntry>,
    prompts: BTreeMap<String, PromptEntry>,
    /// Keyed by the NAMESPACED uri — see [`ResourceEntry`] for why the raw one was not safe to key
    /// on.
    resources: BTreeMap<String, ResourceEntry>,
}

impl Default for Catalogue {
    /// The EMPTY catalogue of a deployment with no `tools:` block. It still takes a generation,
    /// because "MCP was configured and then the last server was removed" must be a generation MOVE
    /// and not a return to some timeless zero state.
    fn default() -> Self {
        Self {
            generation: PIN_GENERATION.fetch_add(1, Ordering::Relaxed),
            servers: BTreeMap::new(),
            tools: BTreeMap::new(),
            prompts: BTreeMap::new(),
            resources: BTreeMap::new(),
        }
    }
}

/// Why a dispatch was refused before it went out. Every arm is a refusal the caller is TOLD about:
/// §3.11 requires the rejection to be audited as a rejection, and an unnamed refusal cannot be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DispatchRefusal {
    /// The snapshot moved between selection and dispatch. §14.2's whole defence: an in-flight call
    /// cannot outlive a quarantine, because the generation it resolved under is not the live one.
    GenerationMoved { selected: u64, live: u64 },
    /// The named tool is not in the live catalogue at all.
    UnknownTool(String),
    /// The tool is catalogued, but the operator has approved no schema hash for it, so there is
    /// nothing to dispatch against. This is `pending`, and pending does not serve.
    NotApproved(String),
    /// The server has no locked pin, so it is `pending` in the trust sense and cannot serve traffic.
    NotPinned(String),
    /// The caller's grant does not reach this tool. Kept distinct from `UnknownTool` deliberately:
    /// the CATALOGUE hides what a caller may not see, so a caller who names a tool it cannot see
    /// gets the same shape of answer either way — but the AUDIT record must be able to tell the
    /// operator which of the two happened.
    NotGranted(String),
}

impl std::fmt::Display for DispatchRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchRefusal::GenerationMoved { selected, live } => write!(
                f,
                "the MCP registry changed between admission and dispatch (pin generation \
                 {selected} → {live}); this call is refused rather than dispatched against a \
                 snapshot the operator has already replaced. Retry."
            ),
            DispatchRefusal::UnknownTool(t) => {
                write!(f, "`{t}` is not a tool this server exposes")
            }
            DispatchRefusal::NotApproved(t) => write!(
                f,
                "`{t}` is registered but no schema hash has been approved for it, so it is pending \
                 and does not serve"
            ),
            DispatchRefusal::NotPinned(s) => write!(
                f,
                "MCP server `{s}` has no locked identity pin, so it is pending and cannot serve \
                 traffic"
            ),
            DispatchRefusal::NotGranted(t) => {
                write!(f, "`{t}` is not a tool this server exposes")
            }
        }
    }
}

impl DispatchRefusal {
    /// The AUDIT outcome word. Every arm is a rejection; the constant is named once so a new arm
    /// cannot quietly become an `applied` row.
    pub(crate) fn audit_reason(&self) -> &'static str {
        match self {
            DispatchRefusal::GenerationMoved { .. } => "generation_moved",
            DispatchRefusal::UnknownTool(_) => "unknown_tool",
            DispatchRefusal::NotApproved(_) => "not_approved",
            DispatchRefusal::NotPinned(_) => "not_pinned",
            DispatchRefusal::NotGranted(_) => "not_granted",
        }
    }
}

impl Catalogue {
    /// BUILD a snapshot from the operator's `tools:` intent, taking the next pin generation.
    ///
    /// Every capability of every registered server is catalogued, INCLUDING the ones that cannot
    /// serve: a tool with no approved hash and a server with no locked pin both appear, because an
    /// operator's view of "what is waiting for me" is the catalogue's job and hiding a pending entry
    /// makes the approval queue invisible. What they do NOT get is a dispatch — that is
    /// [`Catalogue::resolve`]'s decision and it is a separate one.
    pub(crate) fn build(cfg: &ToolsCfg) -> Self {
        let mut servers = BTreeMap::new();
        let mut tools = BTreeMap::new();
        let mut prompts = BTreeMap::new();
        let mut resources = BTreeMap::new();
        for (id, def) in &cfg.servers {
            servers.insert(id.clone(), server_entry(id, def));
            for (tool, allow) in &def.tools_allow {
                let namespaced = namespaced(id, tool);
                tools.insert(
                    namespaced.clone(),
                    ToolEntry {
                        server: id.clone(),
                        tool: tool.clone(),
                        namespaced,
                        schema_hash: allow.schema_hash.clone(),
                        description: allow.description.clone(),
                        input_schema: allow.input_schema.clone(),
                    },
                );
            }
            for (name, allow) in &def.prompts_allow {
                let namespaced = namespaced(id, name);
                prompts.insert(
                    namespaced.clone(),
                    PromptEntry {
                        server: id.clone(),
                        name: name.clone(),
                        namespaced,
                        description: allow.description.clone(),
                        template: allow.template.clone(),
                    },
                );
            }
            for (uri, allow) in &def.resources_allow {
                let namespaced = namespaced(id, uri);
                resources.insert(
                    namespaced.clone(),
                    ResourceEntry {
                        server: id.clone(),
                        uri: uri.clone(),
                        namespaced,
                        name: allow.name.clone(),
                        description: allow.description.clone(),
                        mime_type: allow.mime_type.clone(),
                        text: allow.text.clone(),
                    },
                );
            }
        }
        Self {
            generation: PIN_GENERATION.fetch_add(1, Ordering::Relaxed),
            servers,
            tools,
            prompts,
            resources,
        }
    }

    /// The generation this snapshot was built under. Captured at admission, re-read at dispatch.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether this deployment has any registered MCP server at all. `server/discover` uses it to
    /// tell an honest story about an MCP deployment with an empty registry.
    pub(crate) fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    pub(crate) fn server(&self, id: &str) -> Option<&ServerEntry> {
        self.servers.get(id)
    }

    /// THE GRANT-SCOPED TOOL CATALOGUE for one caller.
    ///
    /// `grant` answers `scope_allowed(kind, value)`. Passing the predicate rather than the key keeps
    /// this module free of the governance types (it is the same function whether the caller is a
    /// virtual key, a synthesised principal, or a test), and it makes the two-grant rule visible in
    /// one expression instead of spread across a struct.
    pub(crate) fn tools_for(&self, grant: &dyn Fn(&str, &str) -> bool) -> Vec<&ToolEntry> {
        self.tools
            .values()
            .filter(|t| granted(grant, &t.server, &t.namespaced))
            .collect()
    }

    /// The grant-scoped prompt catalogue. Scoped by the SAME two grants as tools: a prompt is a
    /// capability of a server, and a caller with no reach to the server has no reach to its prompts.
    pub(crate) fn prompts_for(&self, grant: &dyn Fn(&str, &str) -> bool) -> Vec<&PromptEntry> {
        self.prompts
            .values()
            .filter(|p| granted(grant, &p.server, &p.namespaced))
            .collect()
    }

    /// The grant-scoped resource catalogue.
    pub(crate) fn resources_for(&self, grant: &dyn Fn(&str, &str) -> bool) -> Vec<&ResourceEntry> {
        self.resources
            .values()
            .filter(|r| granted(grant, &r.server, &r.namespaced))
            .collect()
    }

    /// Look one prompt up under the caller's grant. `None` covers both "no such prompt" and "not
    /// yours", which is the correct answer to give a caller: a catalogue that distinguishes them
    /// leaks the existence of what it is hiding.
    pub(crate) fn prompt_for(
        &self,
        grant: &dyn Fn(&str, &str) -> bool,
        namespaced_name: &str,
    ) -> Option<&PromptEntry> {
        self.prompts
            .get(namespaced_name)
            .filter(|p| granted(grant, &p.server, &p.namespaced))
    }

    /// Look one resource up by its NAMESPACED uri under the caller's grant.
    pub(crate) fn resource_for(
        &self,
        grant: &dyn Fn(&str, &str) -> bool,
        namespaced_uri: &str,
    ) -> Option<&ResourceEntry> {
        self.resources
            .get(namespaced_uri)
            .filter(|r| granted(grant, &r.server, &r.namespaced))
    }

    /// ADMISSION: resolve a namespaced tool name to a bound identity under the caller's grant.
    ///
    /// This is the read SELECTION does. It returns the entry and the generation it was resolved
    /// under, and the pair is what [`Catalogue::revalidate`] is handed later.
    pub(crate) fn resolve(
        &self,
        grant: &dyn Fn(&str, &str) -> bool,
        namespaced_name: &str,
    ) -> Result<&ToolEntry, DispatchRefusal> {
        let Some(entry) = self.tools.get(namespaced_name) else {
            return Err(DispatchRefusal::UnknownTool(namespaced_name.to_string()));
        };
        if !granted(grant, &entry.server, &entry.namespaced) {
            return Err(DispatchRefusal::NotGranted(namespaced_name.to_string()));
        }
        let server = self
            .servers
            .get(&entry.server)
            .ok_or_else(|| DispatchRefusal::UnknownTool(namespaced_name.to_string()))?;
        if !server.pinned {
            return Err(DispatchRefusal::NotPinned(server.id.clone()));
        }
        if entry.schema_hash.is_none() {
            return Err(DispatchRefusal::NotApproved(namespaced_name.to_string()));
        }
        Ok(entry)
    }

    /// DISPATCH-TIME RE-VALIDATION (§3.9a, §14.2).
    ///
    /// `self` is the LIVE snapshot, re-read immediately before the call goes out; `selected` is what
    /// admission resolved and the generation it resolved under. Two things are checked and they are
    /// deliberately both checked:
    ///
    /// 1. The GENERATION. If it moved, refuse — without looking at anything else. This is the whole
    ///    of §14.2: a call that raced a quarantine, a de-approval or a re-pin is refused because the
    ///    approval it was admitted under has been replaced, whatever the replacement says. Checking
    ///    the identity instead would let a revert-then-re-approve slip a call through on a snapshot
    ///    the operator had already revoked.
    /// 2. The BOUND IDENTITY, re-derived from the live snapshot under the live grant. Redundant only
    ///    while the generation check is sufficient, and kept because "the generation is the only
    ///    check" is exactly the assumption a future caller that plumbs the generation wrongly would
    ///    silently rely on.
    pub(crate) fn revalidate(
        &self,
        grant: &dyn Fn(&str, &str) -> bool,
        selected: &ToolEntry,
        selected_generation: u64,
    ) -> Result<(), DispatchRefusal> {
        if selected_generation != self.generation {
            return Err(DispatchRefusal::GenerationMoved {
                selected: selected_generation,
                live: self.generation,
            });
        }
        let live = self.resolve(grant, &selected.namespaced)?;
        if live.schema_hash != selected.schema_hash {
            return Err(DispatchRefusal::NotApproved(selected.namespaced.clone()));
        }
        Ok(())
    }
}

/// BOTH grants, and the order is the one an operator reads: the server first (may this caller reach
/// this upstream at all), then the capability.
fn granted(grant: &dyn Fn(&str, &str) -> bool, server: &str, namespaced_name: &str) -> bool {
    grant("mcp_server", server) && grant("mcp_tool", namespaced_name)
}

/// `{server}_{tool}` — the routing key. One function so the catalogue, the grant value and every
/// operator-facing rendering are the same string by construction.
pub(crate) fn namespaced(server: &str, capability: &str) -> String {
    format!("{server}{NAMESPACE_SEP}{capability}")
}

fn server_entry(id: &str, def: &McpServerDefCfg) -> ServerEntry {
    ServerEntry {
        id: id.to_string(),
        url: def.url.clone(),
        pin_mechanism: def.pin.mechanism.token(),
        pinned: !matches!(def.pin.mechanism, super::config::PinMechanism::Unpinned),
        grants: def.grants,
        max_input_required_rounds: def
            .max_input_required_rounds
            .unwrap_or(super::config::DEFAULT_MAX_INPUT_REQUIRED_ROUNDS),
    }
}

#[cfg(test)]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;

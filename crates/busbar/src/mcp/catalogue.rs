// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CATALOGUE — the versioned snapshot every MCP answer is computed from, and the two checks that
//! ride it: the grant scope filter (owner ruling 2) and the dispatch-time re-validation that stops
//! an in-flight call from outliving the approval it was admitted under.
//!
//! ## One snapshot, one generation, an atomic swap
//!
//! The catalogue is a VERSIONED SNAPSHOT built once per config apply and swapped atomically,
//! and dispatch RE-VALIDATES the bound identity and hash pin against the CURRENT snapshot
//! immediately before the call goes out. The swap mechanism is the one the router already uses —
//! `AppHandle`'s `RwLock<Arc<App>>` — so this module does not invent a second hot-swap discipline;
//! it contributes the immutable value that rides in it, plus the monotonic generation that makes a
//! swap DETECTABLE from inside a request.
//!
//! [`PIN_GENERATION`] is process-global and monotonic rather than a field derived from config
//! content. That is deliberate: a content hash would compare equal after a change-and-revert, and
//! the rule is about whether the operator's approval was REPLACED, not about whether it happens
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
//! ## "May this artifact serve?" has ONE owner, and it is not this module
//!
//! The admission gate in [`Catalogue::resolve`] is [`crate::trust::Approval::serves`] — the shared
//! trust lifecycle's own comparison — and there is no second implementation of it here. A
//! registration becomes an [`crate::trust::Approval`] at BUILD time: the mechanism and key the
//! operator declared become the locked pin, and each capability's approved hash becomes that
//! capability's approved digest. Dispatch then asks the lifecycle, not the raw fields.
//!
//! That is a correctness rule rather than a tidiness one. The gate a call passes through must be
//! THE SAME COMPARISON the operator is looking at on the trust surfaces; two implementations of it
//! agree right up until they do not, the divergence is silent, and it fails OPEN in exactly the
//! case that matters — a de-approval the operator believes they made, honoured by the surface and
//! not by the gate. `tests/trust_gate_tests.rs` holds the invariant: an equivalence matrix over
//! every mechanism × approved-hash shape, and a source scan of this file that fails on any second
//! answer to the question.
//!
//! A registration with no authenticity root (`unpinned`) has no artifact to lock, so it cannot be
//! anything but [`crate::trust::Approval::registered`]: pending, inspectable, and serving nothing.
//! That is enforced by what is CONSTRUCTIBLE — `Approval::declared` takes a pin by value — rather
//! than by a check here that a later edit could relax.
//!
//! ## Candidates are BOUND IDENTITIES, never descriptions
//!
//! ROUTE ONLY ON BOUND IDENTITY. A catalogue entry is keyed on `(server-id, namespaced-name,
//! schema-hash)`. The description is carried for display, is markup-normalised on the way out, and
//! is never read by any decision in this module — which is checkable rather than asserted, because
//! [`ToolEntry::description`] is the only place it appears and nothing in [`Catalogue`] calls it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use super::client::catalogue::TransportPin;
use super::config::{McpServerDefCfg, PinMechanism, ServerPinCfg, ToolsCfg, NAMESPACE_SEP};
use crate::trust::Approval;

/// THE PIN GENERATION SOURCE. Monotonic, process-global, bumped once per snapshot BUILD.
///
/// Starts at 1 so that `0` is never a live generation and can therefore be used by a test (or a
/// future caller with nothing selected yet) as an unambiguous "no generation".
static PIN_GENERATION: AtomicU64 = AtomicU64::new(1);

/// ONE approved capability — the bound identity in full, plus the inert display fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ToolEntry {
    /// The registered server id — the first half of the bound identity.
    pub(crate) server: String,
    /// The bare tool name as the upstream spells it.
    pub(crate) tool: String,
    /// `{server}_{tool}` — THE ROUTING KEY, and the value an `mcp_tool` grant names.
    pub(crate) namespaced: String,
    /// The APPROVED schema/description hash — the pin every refresh is diffed against, which is how
    /// a rug-pull is caught. `None` means the operator has allowed the tool but approved no hash,
    /// which is `pending`: it is CATALOGUED (so an operator can see what is waiting) and it does
    /// NOT dispatch (there is no approved digest to compare against).
    pub(crate) schema_hash: Option<String>,
    /// Display only. Never read by a decision in this module — see the header.
    pub(crate) description: Option<String>,
    /// The tool's JSON Schema, echoed verbatim. Opaque to busbar.
    pub(crate) input_schema: Option<serde_json::Value>,
}

impl ToolEntry {
    /// The digest the dispatch gate compares AGAINST — the left operand it cannot be called without,
    /// not a decision of its own.
    ///
    /// An entry the operator approved no hash for has no digest, and the empty string stands in.
    /// That cannot admit anything: [`Catalogue::build`] records an approval only for a tool whose
    /// hash is PRESENT, so a tool with none is absent from the approval altogether and
    /// `Approval::serves` refuses it whatever it is handed — it never reaches a digest comparison at
    /// all.
    fn dispatch_digest(&self) -> &str {
        self.schema_hash.as_deref().unwrap_or_default()
    }
}

/// One exposed prompt. Markup-normalised at the edge, not here — this is the store, not the writer.
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
/// server read the second server's content. That is a NAME OVERLAP between two registered servers,
/// arriving through a key nobody thought of as a name. The wire `uri` is therefore `{server}_{uri}`, which a client treats
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
    /// THE OPERATOR'S STANDING DECISION about this registration — the locked identity pin and the
    /// per-capability approved digests — held in the shared lifecycle type rather than re-expressed
    /// as local booleans.
    ///
    /// This is the whole point: `may this artifact serve?` has ONE owner
    /// ([`crate::trust::Approval::serves`]), so the gate a call passes through and the state an
    /// operator reads are the SAME comparison. A second local answer would agree with it right up
    /// until it did not, and the divergence would be silent and fail OPEN — a de-approval the
    /// operator believes they made, honoured by the surface and not by the gate.
    ///
    /// A registration with no authenticity root is [`crate::trust::Approval::registered`]: no pin,
    /// nothing approved, serves nothing. It is `pending`, which is exactly the state that may be
    /// inspected but may not carry traffic.
    pub(crate) approval: Approval<TransportPin>,
    /// The grants for the asks an upstream can come back with — sampling, elicitation, roots.
    /// Deny-by-default by construction.
    pub(crate) grants: super::config::ServerRequestGrants,
    /// The hard cap on input-required rounds per logical dispatch. An upstream that can ask
    /// indefinitely can amplify cost indefinitely, so the bound is a number, not a heuristic.
    pub(crate) max_input_required_rounds: u32,
    /// THE OUTBOUND CREDENTIAL POSTURE, carried as the operator wrote it rather than as a resolved
    /// secret.
    ///
    /// Resolution happens at DISPATCH, not here, and that is deliberate on two counts. A snapshot is
    /// compared for equality on every config apply, and a snapshot holding resolved plaintext would
    /// be a snapshot that has to be compared without printing itself. And a secret that resolves at
    /// build time is a secret whose rotation needs a restart.
    pub(crate) upstream: UpstreamPosture,
}

/// Everything the upstream leg needs about ONE registration that is not already on [`ServerEntry`],
/// gathered so the dispatch path never reaches back into `ToolsCfg` to find out what it may do.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct UpstreamPosture {
    /// Whether this upstream may live on a private / loopback address. Fail-closed default.
    pub(crate) allow_private: bool,
    /// `own` (busbar's own credential) or `passthrough` (the caller's). Absent ⇒ `own`.
    pub(crate) credentials: Option<crate::auth::UpstreamCreds>,
    /// The RFC 8693 exchange, if the operator configured one. Absent ⇒ no credential is sent.
    pub(crate) token_exchange: Option<super::config::TokenExchangeCfg>,
    /// The RFC 8707 resource indicator — `tools.<server>.aud`. The exchanged token is bound to it.
    pub(crate) aud: Option<String>,
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
/// a rejected call must be audited AS a rejection, and an unnamed refusal cannot be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DispatchRefusal {
    /// The snapshot moved between selection and dispatch. This IS the whole defence: an in-flight
    /// call cannot outlive a quarantine, because the generation it resolved under is not the live
    /// one.
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
        // THE GATE, and the only one. It is not "is the registration pinned, and is a hash
        // configured" restated here; it is the shared lifecycle's own comparison, so the answer
        // dispatch gets is by construction the answer the operator's trust surfaces are computed
        // from.
        if !server.approval.serves(&entry.tool, entry.dispatch_digest()) {
            return Err(refusal_reason(server, entry));
        }
        Ok(entry)
    }

    /// DISPATCH-TIME RE-VALIDATION — the check that makes a revocation bite within one request.
    ///
    /// `self` is the LIVE snapshot, re-read immediately before the call goes out; `selected` is what
    /// admission resolved and the generation it resolved under. Two things are checked and they are
    /// deliberately both checked:
    ///
    /// 1. The GENERATION. If it moved, refuse — without looking at anything else. This is the whole
    ///    defence: a call that raced a quarantine, a de-approval or a re-pin is refused because the
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

/// WHY a dispatch was refused, derived AFTER the gate has ALREADY said no.
///
/// It names a reason and can never admit a call — there is no `Ok` arm to reach — which is what
/// keeps it a diagnostic rather than a second gate. The operator needs the distinction because the
/// two arms are two different actions: supply an authenticity root, or approve a digest.
fn refusal_reason(server: &ServerEntry, entry: &ToolEntry) -> DispatchRefusal {
    match server.approval.pin() {
        None => DispatchRefusal::NotPinned(server.id.clone()),
        Some(_) => DispatchRefusal::NotApproved(entry.namespaced.clone()),
    }
}

/// THE ARTIFACT this registration is pinned to, or `None` when the operator named no authenticity
/// root or supplied no material for the one they named.
///
/// Construction, not authorization. It answers only "is there a root to lock", and the answer feeds
/// the lifecycle rather than a dispatch decision: with no artifact there is nothing to hand
/// [`crate::trust::Approval::declared`], so the registration can only be
/// [`crate::trust::Approval::registered`] — pending, and serving nothing. That is a fact about what
/// is CONSTRUCTIBLE, which is why `unpinned` cannot be talked into serving by a later edit here.
fn declared_pin(pin: &ServerPinCfg) -> Option<TransportPin> {
    if matches!(pin.mechanism, PinMechanism::Unpinned) {
        return None;
    }
    let key = pin.key.as_deref().filter(|k| !k.trim().is_empty())?;
    Some(TransportPin::declared(pin.mechanism.token(), key))
}

fn server_entry(id: &str, def: &McpServerDefCfg) -> ServerEntry {
    // The registration read as the operator's standing INTENT: the identity they pinned out of
    // band, and the digest they approved for each capability. A capability they allowed without
    // approving a digest is absent from the map, which is `pending` — allowed is not approved.
    let approval = match declared_pin(&def.pin) {
        Some(pin) => Approval::declared(
            pin,
            def.tools_allow
                .iter()
                .filter_map(|(tool, allow)| allow.schema_hash.clone().map(|h| (tool.clone(), h)))
                .collect(),
        ),
        None => Approval::registered(),
    };
    ServerEntry {
        id: id.to_string(),
        url: def.url.clone(),
        pin_mechanism: def.pin.mechanism.token(),
        approval,
        grants: def.grants,
        max_input_required_rounds: def
            .max_input_required_rounds
            .unwrap_or(super::config::DEFAULT_MAX_INPUT_REQUIRED_ROUNDS),
        upstream: UpstreamPosture {
            allow_private: def.allow_private,
            credentials: def.upstream_credentials,
            token_exchange: def.token_exchange.clone(),
            aud: def.aud.clone(),
        },
    }
}

#[cfg(test)]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;

#[cfg(test)]
#[path = "tests/trust_gate_tests.rs"]
mod trust_gate_tests;

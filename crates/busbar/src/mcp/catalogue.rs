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

use super::client::catalogue::{LiveDigest, LiveSightings, TransportPin};
use super::config::{
    McpPinMechanism, McpServerDefCfg, PromptMessageCfg, ServerPinCfg, ToolsCfg, NAMESPACE_SEP,
};
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
    /// THE PUBLISHED WIRE NAME — the routing key, and the value an `mcp_tool` grant names.
    ///
    /// `{server}_{tool}` unless the operator wrote `tools_allow.<tool>.publish_as:`, which is the
    /// only thing that can make it anything else. Uniqueness across the whole registry is not this
    /// field's to keep: `config::validate_published_names` refuses boot on a duplicate, so a
    /// snapshot can only be built from a registry where every one of these is distinct.
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
    /// The tool's OUTPUT schema — published as `outputSchema`, and NOT opaque: it is the one schema
    /// on this entry busbar itself is held to, because publishing it makes conforming structured
    /// results a MUST. See [`super::config::ToolAllowCfg::output_schema`]. `None` ⇒ nothing is
    /// published and nothing is checked.
    pub(crate) output_schema: Option<serde_json::Value>,
    /// The rounds of input BUSBAR asks its own caller for before it dispatches this tool. EMPTY ⇒ no
    /// ask, which is deny-by-default by absence. Carried on the entry rather than re-read from the
    /// config at dispatch for the same reason everything else here is: the decision reads ONE
    /// snapshot, and a second source could disagree with the generation the request was admitted on.
    pub(crate) ask_caller: Vec<super::config::AskRoundCfg>,
    /// SEP-2663's REGISTRATION-TIME task declaration. Carried on the entry for the same reason
    /// `ask_caller` is: the `-32021` gate fires before the handler runs, so it has to read the same
    /// snapshot the request was admitted on rather than a second lookup that could disagree.
    pub(crate) task_support: super::config::TaskSupport,
    /// The rounds of input busbar asks its caller for from INSIDE the task. EMPTY ⇒ the task runs
    /// straight through. See `config::ToolAllowCfg::task_ask_caller` for why this is a separate list
    /// from `ask_caller` rather than a mode on it.
    pub(crate) task_ask_caller: Vec<super::config::AskRoundCfg>,
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
    /// The rounds of input busbar asks its caller for before it renders this prompt. Same grammar,
    /// same default, same path — see [`ToolEntry::ask_caller`].
    pub(crate) ask_caller: Vec<super::config::AskRoundCfg>,
    /// The TYPED message list, empty when the operator used the `template:` form. Carried verbatim
    /// from config: this is the store, and the markup strip happens at the edge, in the writer, on
    /// the same pass that substitutes the caller's arguments.
    pub(crate) messages: Vec<PromptMessageCfg>,
}

/// The answer to "which approval did this caller mean by this address".
///
/// Three arms rather than an `Option`, because the third is not an absence: two things the caller
/// can reach both answering one address is a question the registry genuinely cannot answer, and
/// collapsing it into `None` would report an ambiguity as a not-found.
///
/// GENERIC OVER WHAT WAS FOUND, and that is the fix rather than a tidy-up. There were two address
/// resolutions on this plane — the LITERAL one below and the PARAMETERISED one above it — and only
/// the literal one had the third arm. The parameterised one returned an `Option` filled by the first
/// hit of an ordered map walk, so a caller granted two upstreams whose templates both matched one
/// address was served one upstream's content under the other's name, decided silently by whichever
/// upstream identifier sorted first. One type with one set of arms means a second resolution cannot
/// be added without answering the ambiguity question, because there is no arm that means "pick one".
#[derive(Debug)]
pub(crate) enum ResourceLookup<T> {
    /// Exactly one, after the caller's grant narrowed the field.
    One(T),
    /// No such resource, OR the caller holds no grant for it. Deliberately one arm: a catalogue that
    /// distinguishes them leaks the existence of what it hides.
    NotFound,
    /// The caller is granted MORE THAN ONE thing answering this address. Carries the contending
    /// approvals, named the way an operator can act on them and SORTED, so that two runs of one
    /// ambiguity are never reported two different ways.
    Ambiguous(Vec<String>),
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
    /// The base64 form. Mutually exclusive with `text` — refused at config validation, so a
    /// catalogue entry can never carry both and the writer never has to choose.
    pub(crate) blob: Option<String>,
}

/// One exposed RESOURCE TEMPLATE — a parameterised URI and the content one expansion of it returns.
///
/// NAMESPACED on the same key as everything else on this plane, for the same reason: two registered
/// servers may legitimately publish the same template, and a catalogue keyed on the raw one would
/// let the second silently answer for the first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResourceTemplateEntry {
    pub(crate) server: String,
    /// The template as the operator wrote it.
    pub(crate) uri_template: String,
    /// `{server}_{uri_template}` — what `resources/templates/list` publishes and what a caller's
    /// EXPANDED uri is matched against.
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
    /// The endpoint, for a registration reached over the network. EMPTY on a stdio registration,
    /// which reaches no address — `mcp::config::validate_endpoint` refuses a `url:` on one, so the
    /// emptiness is a boot-time guarantee rather than a hope.
    pub(crate) url: String,
    /// THE CHANNEL this registration's calls ride, lifted from the operator's `transport:` key.
    ///
    /// It rides on the snapshot rather than being re-read from `ToolsCfg` at dispatch for the same
    /// reason every other field here does: the snapshot is what the engine holds, and a second
    /// reader of the operator's intent is a second answer that can disagree with the first.
    pub(crate) transport: crate::transport::Transport,
    /// The spawn recipe, present exactly when [`ServerEntry::transport`] is the child-process one.
    /// `None` otherwise, and the wire refuses rather than guesses if the two ever disagree.
    pub(crate) stdio: Option<super::client::stdio::StdioCommand>,
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
    /// The hard cap on rounds busbar may ask ITS OWN CALLER for. `0` disables every `ask_caller` on
    /// this server at once.
    pub(crate) max_caller_ask_rounds: u32,
    /// THE REFRESH CADENCE the operator wrote for this registration, lifted at build time.
    ///
    /// It rides on the entry rather than being re-read from `ToolsCfg` by the timer, for the same
    /// reason every other field here does: the snapshot is what the engine holds, and a sweep that
    /// reached back into the config document to find out how often to look would be a second reader
    /// of the operator's intent that could disagree with the first.
    pub(crate) refresh_policy: crate::trust::reverify::Policy,
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
    /// THE WALL-CLOCK BUDGET FOR ONE OUTBOUND LEG to this server. `None` ⇒
    /// [`super::upstream::DEFAULT_UPSTREAM_TIMEOUT`], which is the value every registration used
    /// before `tools.<server>.timeout:` existed.
    ///
    /// It rides on the snapshot rather than being re-read from `ToolsCfg` at dispatch, for the same
    /// reason `refresh_policy` does: the request was ADMITTED against one snapshot, and a second
    /// reader of the operator's intent could hand it a deadline from a different generation.
    pub(crate) timeout: Option<std::time::Duration>,
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
    /// Keyed by the NAMESPACED uri TEMPLATE. A separate map from `resources` on purpose: a
    /// concrete URI is found by lookup and a template by MATCHING, and merging the two would make
    /// every concrete read pay for a scan — and, worse, would let a template shadow a concrete
    /// resource the operator approved by name.
    resource_templates: BTreeMap<String, ResourceTemplateEntry>,
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
            resource_templates: BTreeMap::new(),
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
    /// The LAST LIVE TOOL LIST disagrees with what the operator approved, so this server is
    /// demoted and serves nothing until the change is worked. THIS IS THE RUG-PULL REFUSAL: an
    /// upstream that re-serves an approved tool name under a changed schema or description lands
    /// here, and it is the arm that cannot be reached by comparing config against itself.
    Quarantined { tool: String, why: &'static str },
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
            DispatchRefusal::Quarantined { tool, why } => write!(
                f,
                "`{tool}` is not served: {why}. The upstream's current tool list no longer matches \
                 what an operator approved, so this server is demoted until the change is reviewed."
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
            DispatchRefusal::Quarantined { .. } => "quarantined",
            // The word is core's (`crate::audit::vocab`), not this plane's: the refusal
            // vocabulary is shared across every stream of evidence, so a second stream cannot
            // spell the same refusal differently.
            DispatchRefusal::NotGranted(_) => crate::audit::vocab::REASON_NOT_GRANTED,
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
        let mut resource_templates = BTreeMap::new();
        for (id, def) in &cfg.servers {
            servers.insert(id.clone(), server_entry(id, def));
            for (tool, allow) in &def.tools_allow {
                // THE PUBLISHED NAME: the operator's `publish_as:` where they wrote one, the
                // `{server}_{tool}` default where they did not — which is every config that
                // predates the field, so nothing that exists today changes. Uniqueness across the
                // whole registry is `config::validate_published_names`, which has already refused
                // boot by the time a snapshot is built; this is the only place that decides which
                // of the two spellings a name IS.
                let namespaced = allow
                    .publish_as
                    .clone()
                    .unwrap_or_else(|| namespaced(id, tool));
                tools.insert(
                    namespaced.clone(),
                    ToolEntry {
                        server: id.clone(),
                        tool: tool.clone(),
                        namespaced,
                        schema_hash: allow.schema_hash.clone(),
                        description: allow.description.clone(),
                        input_schema: allow.input_schema.clone(),
                        output_schema: allow.output_schema.clone(),
                        ask_caller: allow.ask_caller.clone(),
                        task_support: allow.task_support,
                        task_ask_caller: allow.task_ask_caller.clone(),
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
                        ask_caller: allow.ask_caller.clone(),
                        messages: allow.messages.clone(),
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
                        blob: allow.blob.clone(),
                    },
                );
            }
            for (template, allow) in &def.resource_templates_allow {
                let namespaced = namespaced(id, template);
                resource_templates.insert(
                    namespaced.clone(),
                    ResourceTemplateEntry {
                        server: id.clone(),
                        uri_template: template.clone(),
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
            resource_templates,
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

    /// EVERY registration, in deterministic id order.
    ///
    /// The refresh timer's reach, and the reason it is a plain iterator over the whole map with no
    /// filter argument: a sweep that could be handed a subset is a sweep that can be handed an empty
    /// one, and "which servers get watched" is not a decision this plane wants spread across call
    /// sites. [`crate::mcp::connect::refresh_sweep`] asks
    /// [`crate::trust::reverify::due`] about every entry this yields and lets IT answer.
    pub(crate) fn servers(&self) -> impl Iterator<Item = &ServerEntry> {
        self.servers.values()
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

    /// The grant-scoped resource-TEMPLATE catalogue.
    pub(crate) fn resource_templates_for(
        &self,
        grant: &dyn Fn(&str, &str) -> bool,
    ) -> Vec<&ResourceTemplateEntry> {
        self.resource_templates
            .values()
            .filter(|t| granted(grant, &t.server, &t.namespaced))
            .collect()
    }

    /// MATCH a caller's EXPANDED uri against the grant-scoped templates.
    ///
    /// [`ResourceLookup::NotFound`] covers "no template matches" and "not yours" alike, which is the
    /// same answer [`Catalogue::resource_by_uri`] gives and for the same reason: distinguishing them
    /// would let a caller probe for the shape of an approval it does not hold.
    ///
    /// AND THE THIRD ARM IS THE POINT. This used to answer an `Option` filled by the first hit of an
    /// ordered map walk, and called the determinism a feature: the same process, the same config,
    /// the same winner every time. It is worse than a coin toss precisely because it is stable —
    /// the key walked is `{server}_{template}`, so whoever chooses an upstream's identifier chooses
    /// which of two contending approvals answers, silently, for as long as the config stands. That
    /// is the cross-trust-boundary content confusion the namespacing exists to prevent, arriving
    /// through the newer surface. More than one match is REFUSED and NAMED, exactly as the literal
    /// address is, because which one the caller meant is a question only the caller can answer.
    ///
    /// The candidates are named by their NAMESPACED approval rather than by their server, which is
    /// where this differs from the literal path and is not an inconsistency: two templates on ONE
    /// server can contend, and a refusal that named the server twice would tell the operator
    /// nothing.
    pub(crate) fn resource_template_for(
        &self,
        grant: &dyn Fn(&str, &str) -> bool,
        uri: &str,
    ) -> ResourceLookup<(
        &ResourceTemplateEntry,
        std::collections::BTreeMap<String, String>,
    )> {
        // Matched against the OPERATOR'S OWN template, not the namespaced spelling, for the same
        // reason a concrete resource is now addressed by its own URI: the caller expands the
        // template it was published, and it is published raw.
        let mut matches = self
            .resource_templates
            .values()
            .filter(|t| granted(grant, &t.server, &t.namespaced))
            .filter_map(|t| match_uri_template(&t.uri_template, uri).map(|p| (t, p)));
        let Some(first) = matches.next() else {
            return ResourceLookup::NotFound;
        };
        let rest: Vec<_> = matches.collect();
        if rest.is_empty() {
            return ResourceLookup::One(first);
        }
        let mut candidates: Vec<String> = std::iter::once(&first)
            .chain(rest.iter())
            .map(|(t, _)| t.namespaced.clone())
            .collect();
        candidates.sort();
        ResourceLookup::Ambiguous(candidates)
    }

    /// Look one resource up BY THE URI THE PROTOCOL DEFINES, under the caller's grant.
    ///
    /// A resource IS its URI in the MCP model, so that is what a caller addresses it by. The
    /// namespacing this catalogue was built on is NOT deleted — it stays as the grant value and the
    /// map key, both of which must remain unique per (server, uri) — but it is no longer what a
    /// client has to say.
    ///
    /// THE COLLISION IS RESOLVED BY THE CALLER'S GRANT, not by insertion order. The defect the
    /// namespacing fixed was two servers exposing one URI silently serving each other's content,
    /// decided by `BTreeMap::insert` over an insertion-ordered config. Narrowing by grant FIRST makes
    /// that impossible by construction: a server the caller cannot reach is filtered out before
    /// anything is selected, so a caller granted only A can never be served B whatever both expose.
    ///
    /// The residual case — a caller granted BOTH — is the only genuinely ambiguous one, and it is
    /// [`ResourceLookup::Ambiguous`], never a pick. The defect being fixed was a SILENT resolution;
    /// answering it with a loud refusal is categorically better than a quiet guess, even when the
    /// guess would usually be right.
    pub(crate) fn resource_by_uri(
        &self,
        grant: &dyn Fn(&str, &str) -> bool,
        uri: &str,
    ) -> ResourceLookup<&ResourceEntry> {
        let mut matches = self
            .resources
            .values()
            .filter(|r| r.uri == uri && granted(grant, &r.server, &r.namespaced));
        let Some(first) = matches.next() else {
            return ResourceLookup::NotFound;
        };
        let rest: Vec<&ResourceEntry> = matches.collect();
        if rest.is_empty() {
            return ResourceLookup::One(first);
        }
        // Ordered, because the refusal names them and an operator comparing two runs must not see
        // the same ambiguity reported two different ways.
        let mut servers: Vec<String> = std::iter::once(first)
            .chain(rest)
            .map(|r| r.server.clone())
            .collect();
        servers.sort();
        ResourceLookup::Ambiguous(servers)
    }

    /// ADMISSION: resolve a namespaced tool name to a bound identity under the caller's grant.
    ///
    /// This is the read SELECTION does. It returns the entry and the generation it was resolved
    /// under, and the pair is what [`Catalogue::revalidate`] is handed later.
    pub(crate) fn resolve(
        &self,
        grant: &dyn Fn(&str, &str) -> bool,
        live: LiveSightings<'_>,
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
        // THE DIGEST BEING DISPATCHED AGAINST. When a live tool list has been taken it is what the
        // UPSTREAM is serving right now; with no sighting it is the hash the operator wrote. That
        // choice is the whole rug-pull defence: comparing the approved hash against the configured
        // hash is comparing the operator's intent with itself and cannot, by construction, notice
        // an upstream changing its schema underneath.
        let observed = match live.digest_for(&entry.server, &entry.tool, &server.approval) {
            LiveDigest::Unsighted => entry.dispatch_digest().to_string(),
            LiveDigest::At(digest) => digest,
            LiveDigest::Quarantined(why) => {
                return Err(DispatchRefusal::Quarantined {
                    tool: entry.namespaced.clone(),
                    why,
                })
            }
        };
        // THE GATE, and the only one. It is not "is the registration pinned, and is a hash
        // configured" restated here; it is the shared lifecycle's own comparison, so the answer
        // dispatch gets is by construction the answer the operator's trust surfaces are computed
        // from.
        if !server.approval.serves(&entry.tool, &observed) {
            return Err(refusal_reason(server, entry));
        }
        Ok(entry)
    }

    /// IS THIS TOOL CURRENTLY DEMOTED? The question the ADVERTISEMENT path asks, answered off the
    /// same arm [`Self::resolve`] refuses on.
    ///
    /// One expression rather than a second opinion about what "quarantined" means, and that is the
    /// point of it living here beside `resolve` instead of in `method.rs`: the two paths disagreeing
    /// is the failure mode — busbar publishing a tool it will refuse, or hiding one it would have
    /// served. `LiveDigest` has exactly three answers and this names the one, so a fourth cannot be
    /// added without this call site being made to say what it does about it.
    ///
    /// Note what it deliberately does NOT do: it takes no grant. Whether a caller may SEE a tool and
    /// whether the tool is currently trustworthy are different questions with different answers, and
    /// the listing applies them in that order — scope first, then trust — so this never becomes a
    /// second place a grant is interpreted.
    pub(crate) fn is_quarantined(&self, live: LiveSightings<'_>, entry: &ToolEntry) -> bool {
        let Some(server) = self.servers.get(&entry.server) else {
            // A tool whose server is missing from the registry cannot be dispatched either
            // (`resolve` answers `UnknownTool`), so hiding it is the consistent answer rather than a
            // new judgement.
            return true;
        };
        matches!(
            live.digest_for(&entry.server, &entry.tool, &server.approval),
            LiveDigest::Quarantined(_)
        )
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
    ///
    /// The live sightings are re-read by the caller and passed in here too, so a refresh that
    /// landed a drifted tool list BETWEEN admission and dispatch is caught on the same request
    /// rather than on the next one.
    pub(crate) fn revalidate(
        &self,
        grant: &dyn Fn(&str, &str) -> bool,
        sightings: LiveSightings<'_>,
        selected: &ToolEntry,
        selected_generation: u64,
    ) -> Result<(), DispatchRefusal> {
        if selected_generation != self.generation {
            return Err(DispatchRefusal::GenerationMoved {
                selected: selected_generation,
                live: self.generation,
            });
        }
        let live = self.resolve(grant, sightings, &selected.namespaced)?;
        if live.schema_hash != selected.schema_hash {
            return Err(DispatchRefusal::NotApproved(selected.namespaced.clone()));
        }
        Ok(())
    }
}

/// MATCH one RFC 6570 level-1 URI template against a concrete URI, returning the bindings.
///
/// Level 1 only — the config grammar refuses everything else ([`super::config::validate_uri_template`]),
/// so this function never has to guess at an operator whose expansion rules it does not implement.
///
/// TWO RULES ABOUT WHAT A PARAMETER MAY SWALLOW, and both exist because a template is an APPROVAL of
/// a URI shape:
///
/// 1. A binding is NON-EMPTY. `test://template//data` is not an expansion of
///    `test://template/{id}/data`; treating it as one would make the approval cover a URI with a
///    missing segment.
/// 2. A binding contains NO `/`. Without that, `test://template/{id}/data` matches
///    `test://template/a/b/c/data` and one declaration silently approves an entire subtree — which
///    is precisely the "approval of a shape" the operator did not write.
///
/// The literal between two parameters is found at its FIRST occurrence, which with rule 2 makes the
/// match unique: a longer candidate binding would have to contain the separator that rule 2 forbids.
fn match_uri_template(
    template: &str,
    uri: &str,
) -> Option<std::collections::BTreeMap<String, String>> {
    let mut bindings = std::collections::BTreeMap::new();
    let mut t = template;
    let mut u = uri;
    loop {
        let Some(open) = t.find('{') else {
            // No parameter left: the rest must match exactly, or a template would match every URI
            // that merely starts the same way.
            return (t == u).then_some(bindings);
        };
        let literal = &t[..open];
        if !u.starts_with(literal) {
            return None;
        }
        u = &u[literal.len()..];
        let after = &t[open + 1..];
        let close = after.find('}')?;
        let name = &after[..close];
        t = &after[close + 1..];
        // The literal that ENDS this binding, up to the next parameter or the end of the template.
        let stop = &t[..t.find('{').unwrap_or(t.len())];
        let value = if stop.is_empty() {
            let v = u;
            u = "";
            v
        } else {
            let at = u.find(stop)?;
            let v = &u[..at];
            u = &u[at..];
            v
        };
        if value.is_empty() || value.contains('/') {
            return None;
        }
        bindings.insert(name.to_string(), value.to_string());
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
    if matches!(pin.mechanism, McpPinMechanism::Unpinned) {
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
    // `validate_endpoint` has already refused every mixture of the two halves, so this is a lift and
    // not a second decision: a registration that spawns carries a command and no url, and one that
    // does not carries a url and no command.
    let transport = def
        .transport
        .unwrap_or(super::config::Transport::StreamableHttp);
    let stdio = transport
        .spawns_child()
        .then(|| super::client::stdio::StdioCommand {
            program: def.command.clone().unwrap_or_default(),
            args: def.args.clone(),
            env: def.env.clone(),
            cwd: def.cwd.clone(),
        });
    ServerEntry {
        id: id.to_string(),
        url: def.url.clone(),
        transport: transport.axis(),
        stdio,
        pin_mechanism: def.pin.mechanism.token(),
        approval,
        grants: def.grants,
        max_input_required_rounds: def
            .max_input_required_rounds
            .unwrap_or(super::config::DEFAULT_MAX_INPUT_REQUIRED_ROUNDS),
        max_caller_ask_rounds: def
            .max_caller_ask_rounds
            .unwrap_or(super::config::DEFAULT_MAX_CALLER_ASK_ROUNDS),
        // `validate_server` already parsed this and refused a malformed one at boot, so the only way
        // to reach the fallback is a code path that skipped validation. Falling back to the default
        // cadence is the fail-CLOSED answer: a server that ends up unswept is a server whose drift
        // nobody would ever see.
        refresh_policy: super::config::refresh_policy_for(def).unwrap_or(
            crate::trust::reverify::Policy {
                ttl_ms: crate::admin::parse_duration_secs(super::config::DEFAULT_MCP_REFRESH_TTL)
                    .unwrap_or(6 * 60 * 60)
                    .saturating_mul(1_000),
                recovery_backoff_ms: 0,
            },
        ),
        upstream: UpstreamPosture {
            allow_private: def.allow_private,
            credentials: def.upstream_credentials,
            token_exchange: def.token_exchange.clone(),
            aud: def.aud.clone(),
            // `validate_server` already refused a malformed or zero value at BOOT, so a parse
            // failure here cannot be an operator's typo reaching the request path. It falls back to
            // the default rather than panicking, because a snapshot build is not a place to abort a
            // running deployment.
            timeout: def
                .timeout
                .as_deref()
                .and_then(|t| crate::admin::parse_duration_secs(t).ok())
                .map(std::time::Duration::from_secs),
        },
    }
}

#[cfg(test)]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;

#[cfg(test)]
#[path = "tests/trust_gate_tests.rs"]
mod trust_gate_tests;

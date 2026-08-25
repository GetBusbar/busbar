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
//! The generation source is [`busbar_core::trust::validate::next_generation`] — process-global, monotonic,
//! and shared with every other snapshot in the process rather than a counter per plane. It is a
//! counter rather than a field derived from config content, and that is deliberate: a content hash
//! would compare equal after a change-and-revert, and
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
//! THE WALK THAT APPLIES THEM IS CORE'S, NOT THIS MODULE'S. [`busbar_substrate::catalogue`] owns the mechanism
//! — walk the inventory, collect what each item requires, hand it to the ordered gate, keep the
//! entitled subset, render it — and this plane supplies only the ITEM: which grants each entry
//! requires ([`CatalogueItem::required_grants`]), WHICH QUESTION this plane's catalogue asks
//! ([`CatalogueItem::admit`]), and how an entry is written onto the MCP wire
//! ([`CatalogueItem::render`]). The two grants are stated once, in one `mcp_grants` for four entry
//! types, so `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`,
//! `prompts/get`, `resources/read` and `tools/call` cannot drift apart about who may see what.
//!
//! WHAT THIS PLANE'S CATALOGUE ASKS FOR is identity and grant — [`busbar_core::trust::validate::validate_visibility`]
//! — and deliberately not the artifact step, because the MCP catalogue LISTS what it will not
//! dispatch: a tool with no approved hash and a server with no locked pin both appear, so an
//! operator can see the approval queue. `tools/call` asks the FULL ordered gate, in
//! [`Catalogue::resolve`], which is why "listed" and "served" are two different answers here and one
//! answer on A2A. The listing gained the IDENTITY step it never had: a catalogue that enumerated
//! tools for a deleted key was answering a principal that no longer exists.
//!
//! ## "May this artifact serve?" has ONE owner, and it is not this module
//!
//! The admission gate in [`Catalogue::resolve`] is [`busbar_substrate::trust::Approval::serves`] — the shared
//! trust lifecycle's own comparison — and there is no second implementation of it here. A
//! registration becomes an [`busbar_substrate::trust::Approval`] at BUILD time: the mechanism and key the
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
//! anything but [`busbar_substrate::trust::Approval::registered`]: pending, inspectable, and serving nothing.
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

use busbar_core::trust::validate::Grant;
use busbar_substrate::catalogue::{Caller, CatalogueItem};

use super::client::catalogue::{LiveDigest, LiveSightings, TransportPin};
use super::config::{McpServerDefCfg, PromptMessageCfg, ToolsCfg, NAMESPACE_SEP};
use busbar_substrate::trust::Approval;

/// THE TWO SCOPE KINDS AN MCP CAPABILITY IS REACHED THROUGH.
///
/// Named once rather than spelt at each call site, because the LISTING and the DISPATCH must ask
/// about the same two kinds: a caller that could see a tool it would then be refused for, or be
/// refused for one it can see, is a catalogue and a gate that disagree. `mcp/client/egress.rs` names
/// the same two on the outbound leg and is that unification's business, not this one's.
pub(crate) const SCOPE_KIND_SERVER: &str = "mcp_server";
pub(crate) const SCOPE_KIND_TOOL: &str = "mcp_tool";

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
    pub(crate) transport: busbar_core::transport::Transport,
    /// The spawn recipe, present exactly when [`ServerEntry::transport`] is the child-process one.
    /// `None` otherwise, and the wire refuses rather than guesses if the two ever disagree.
    pub(crate) stdio: Option<super::client::stdio::StdioCommand>,
    /// The mechanism NAME. Operator-facing and audit-facing only; never interpreted, exactly as
    /// [`busbar_substrate::trust::PinnedArtifact::mechanism`] is never interpreted.
    pub(crate) pin_mechanism: &'static str,
    /// THE OPERATOR'S STANDING DECISION about this registration — the locked identity pin and the
    /// per-capability approved digests — held in the shared lifecycle type rather than re-expressed
    /// as local booleans.
    ///
    /// This is the whole point: `may this artifact serve?` has ONE owner
    /// ([`busbar_substrate::trust::Approval::serves`]), so the gate a call passes through and the state an
    /// operator reads are the SAME comparison. A second local answer would agree with it right up
    /// until it did not, and the divergence would be silent and fail OPEN — a de-approval the
    /// operator believes they made, honoured by the surface and not by the gate.
    ///
    /// A registration with no authenticity root is [`busbar_substrate::trust::Approval::registered`]: no pin,
    /// nothing approved, serves nothing. It is `pending`, which is exactly the state that may be
    /// inspected but may not carry traffic.
    pub(crate) approval: Approval<TransportPin>,
    /// The grants for the asks an upstream can come back with — sampling, elicitation, roots.
    /// Deny-by-default by construction.
    pub(crate) grants: super::config::ServerRequestGrants,
    /// The operator-declared filesystem roots this upstream may be told about when it asks
    /// `roots/list` — the satisfier behind `grants.roots`. Empty ⇒ a granted ask is refused as
    /// unsatisfiable, naming `tools.<server>.roots`.
    pub(crate) roots: Vec<super::config::RootCfg>,
    /// The operator-declared sampling policy for THIS upstream — the satisfier behind
    /// `grants.sampling`, as `roots` is the satisfier behind `grants.roots`. Absent ⇒ a granted
    /// sampling ask is refused as unsatisfiable, naming `tools.<server>.sampling`.
    pub(crate) sampling: Option<super::config::SamplingCfg>,
    /// The hard cap on input-required rounds per logical dispatch. An upstream that can ask
    /// indefinitely can amplify cost indefinitely, so the bound is a number, not a heuristic.
    pub(crate) max_input_required_rounds: u32,
    /// The hard cap on rounds busbar may ask ITS OWN CALLER for. `0` disables every `ask_caller` on
    /// this server at once.
    pub(crate) max_caller_ask_rounds: u32,
    /// THE MAX VERIFICATION STALENESS the operator wrote for this registration, lifted at build time.
    ///
    /// It rides on the entry rather than being re-read from `ToolsCfg` by the verify gate, for the
    /// same reason every other field here does: the snapshot is what the engine holds, and a re-read
    /// that reached back into the config document to find the bound would be a second reader of the
    /// operator's intent that could disagree with the first.
    pub(crate) verify_policy: busbar_substrate::trust::reverify::Policy,
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
    pub(crate) credentials: Option<busbar_core::auth::UpstreamCreds>,
    /// The RFC 8693 exchange, if the operator configured one. Absent ⇒ no credential is sent.
    pub(crate) token_exchange: Option<super::config::TokenExchangeCfg>,
    /// The RFC 8707 resource indicator — `tools.<server>.aud`. The exchanged token is bound to it.
    pub(crate) aud: Option<String>,
    /// THE WALL-CLOCK BUDGET FOR ONE OUTBOUND LEG to this server. `None` ⇒
    /// [`super::upstream::DEFAULT_UPSTREAM_TIMEOUT`], which is the value every registration used
    /// before `tools.<server>.timeout:` existed.
    ///
    /// It rides on the snapshot rather than being re-read from `ToolsCfg` at dispatch, for the same
    /// reason `verify_policy` does: the request was ADMITTED against one snapshot, and a second
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
            generation: busbar_core::trust::validate::next_generation(),
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
    /// The caller's PRINCIPAL is no longer live: deleted, disabled or expired. Its own arm rather
    /// than folded into `NotGranted`, for the same reason `NotGranted` is not folded into
    /// `UnknownTool`: the wire answer is deliberately identical and the AUDIT record must not be.
    /// "grant this key a scope" and "this key is gone" are two different things for an operator to
    /// do, and an ingress that had already authenticated is exactly where a stale principal is least
    /// expected and therefore worst to mislabel.
    IdentityNotLive(String),
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
            DispatchRefusal::NotGranted(t) | DispatchRefusal::IdentityNotLive(t) => {
                write!(f, "`{t}` is not a tool this server exposes")
            }
        }
    }
}

impl DispatchRefusal {
    /// The AUDIT outcome word. Every arm is a rejection; the constant is named once so a new arm
    /// cannot quietly become an `applied` row.
    ///
    /// THE SHARED WORDS ARE CORE'S, from [`busbar_substrate::audit::vocab`]: the refusal vocabulary is shared
    /// across every stream of evidence, so a second stream cannot spell the same refusal
    /// differently.
    ///
    /// The rest are this plane's own renderings of ONE core arm — `not_pinned`, `not_approved` and
    /// `quarantined` are three operator actions behind one `not_serving`, and keeping them apart is
    /// the opposite of flattening: core decides, and the plane says which of its shapes the decision
    /// took.
    pub(crate) fn audit_reason(&self) -> &'static str {
        use busbar_substrate::audit::vocab;
        match self {
            DispatchRefusal::GenerationMoved { .. } => vocab::REASON_GENERATION_MOVED,
            DispatchRefusal::UnknownTool(_) => "unknown_tool",
            DispatchRefusal::NotApproved(_) => "not_approved",
            DispatchRefusal::NotPinned(_) => "not_pinned",
            DispatchRefusal::Quarantined { .. } => "quarantined",
            DispatchRefusal::NotGranted(_) => vocab::REASON_NOT_GRANTED,
            DispatchRefusal::IdentityNotLive(_) => vocab::REASON_IDENTITY_NOT_LIVE,
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
            generation: busbar_core::trust::validate::next_generation(),
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

    /// The entry for one BARE tool name on one server — the lookup the failover route builder
    /// makes for a `tool_pools:` twin, where the caller named the tool on ONE member and the
    /// candidate set needs each member's own entry (its own `namespaced` name, its own approved
    /// digest). A linear scan: the map is keyed by published name, membership is bounded by
    /// `MAX_POOL_MEMBERS`, and this runs once per routed dispatch, not per candidate walk step.
    pub(crate) fn tool_on(&self, server: &str, bare: &str) -> Option<&ToolEntry> {
        self.tools
            .values()
            .find(|t| t.server == server && t.tool == bare)
    }

    pub(crate) fn server(&self, id: &str) -> Option<&ServerEntry> {
        self.servers.get(id)
    }

    /// THE SERVER A NAMESPACED TOOL NAME BELONGS TO, and the bound the verify-on-call gate re-verifies
    /// it under. `None` for a name no registration exposes — the same not-found `resolve` would give.
    ///
    /// Read on the `tools/call` path BEFORE admission so the server's advertised surface is freshened
    /// (within `verify_ttl`, single-flight) before the digest compare in [`Self::resolve`]. It does
    /// NOT read the caller's grant: freshening a snapshot reveals nothing to the caller and triggers
    /// at most one coalesced upstream fetch per `verify_ttl` per server — the same fetch any caller
    /// would trigger — while the grant refusal still lands, unchanged, inside `resolve`.
    pub(crate) fn verify_target(&self, namespaced_name: &str) -> Option<(&str, &ServerEntry)> {
        let tool = self.tools.get(namespaced_name)?;
        let server = self.servers.get(&tool.server)?;
        Some((server.id.as_str(), server))
    }

    /// EVERY registration, in deterministic id order. Read by `mcp_on_swap` to retire the stdio
    /// children of registrations a config apply removed — a plain iterator over the whole map because
    /// "which registrations exist" is not a decision this plane wants spread across call sites.
    pub(crate) fn servers(&self) -> impl Iterator<Item = &ServerEntry> {
        self.servers.values()
    }

    /// THE GRANT-SCOPED TOOL CATALOGUE for one caller.
    ///
    /// The WALK is [`busbar_substrate::catalogue::visible`] — core's, shared with every other plane — and the
    /// entitlement decision inside it is [`busbar_core::trust::validate`]'s, so what a caller may see is
    /// decided by one mechanism asking one gate. The two-grant rule this plane contributes is in
    /// `<ToolEntry as CatalogueItem>::required_grants`, once, for all four entry types.
    pub(crate) fn tools_for(&self, caller: &Caller<'_>) -> Vec<&ToolEntry> {
        busbar_substrate::catalogue::visible(self.tools.values(), caller, &())
    }

    /// The grant-scoped prompt catalogue. Scoped by the SAME two grants as tools: a prompt is a
    /// capability of a server, and a caller with no reach to the server has no reach to its prompts.
    pub(crate) fn prompts_for(&self, caller: &Caller<'_>) -> Vec<&PromptEntry> {
        busbar_substrate::catalogue::visible(self.prompts.values(), caller, &())
    }

    /// The grant-scoped resource catalogue.
    pub(crate) fn resources_for(&self, caller: &Caller<'_>) -> Vec<&ResourceEntry> {
        busbar_substrate::catalogue::visible(self.resources.values(), caller, &())
    }

    /// `prompts/list`'s answer for one caller: the SAME walk, rendered.
    ///
    /// One expression, so the entitlement decision and the rendering cannot be separated by an
    /// intervening edit at the call site — an item is rendered only once core has decided this
    /// caller may see it.
    pub(crate) fn prompts_rendered(&self, caller: &Caller<'_>) -> Vec<serde_json::Value> {
        busbar_substrate::catalogue::rendered(self.prompts.values(), caller, &())
    }

    /// `resources/list`'s answer for one caller.
    pub(crate) fn resources_rendered(&self, caller: &Caller<'_>) -> Vec<serde_json::Value> {
        busbar_substrate::catalogue::rendered(self.resources.values(), caller, &())
    }

    /// `resources/templates/list`'s answer for one caller.
    pub(crate) fn resource_templates_rendered(
        &self,
        caller: &Caller<'_>,
    ) -> Vec<serde_json::Value> {
        busbar_substrate::catalogue::rendered(self.resource_templates.values(), caller, &())
    }

    /// Look one prompt up under the caller's grant. `None` covers both "no such prompt" and "not
    /// yours", which is the correct answer to give a caller: a catalogue that distinguishes them
    /// leaks the existence of what it is hiding.
    pub(crate) fn prompt_for(
        &self,
        caller: &Caller<'_>,
        namespaced_name: &str,
    ) -> Option<&PromptEntry> {
        let entry = self.prompts.get(namespaced_name)?;
        busbar_substrate::catalogue::judge(entry, caller, &())
            .ok()
            .map(|e| e.item)
    }

    /// The grant-scoped resource-TEMPLATE catalogue.
    pub(crate) fn resource_templates_for(
        &self,
        caller: &Caller<'_>,
    ) -> Vec<&ResourceTemplateEntry> {
        busbar_substrate::catalogue::visible(self.resource_templates.values(), caller, &())
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
        caller: &Caller<'_>,
        uri: &str,
    ) -> ResourceLookup<(
        &ResourceTemplateEntry,
        std::collections::BTreeMap<String, String>,
    )> {
        // Matched against the OPERATOR'S OWN template, not the namespaced spelling, for the same
        // reason a concrete resource is now addressed by its own URI: the caller expands the
        // template it was published, and it is published raw.
        let entitled = self.resource_templates_for(caller);
        let mut matches = entitled
            .into_iter()
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
        caller: &Caller<'_>,
        uri: &str,
    ) -> ResourceLookup<&ResourceEntry> {
        let entitled = self.resources_for(caller);
        let mut matches = entitled.into_iter().filter(|r| r.uri == uri);
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
        principal: Option<&busbar_api::VirtualKey>,
        live: LiveSightings<'_>,
        namespaced_name: &str,
        generation: busbar_core::trust::validate::Generations,
        now: u64,
    ) -> Result<&ToolEntry, DispatchRefusal> {
        let Some(entry) = self.tools.get(namespaced_name) else {
            return Err(DispatchRefusal::UnknownTool(namespaced_name.to_string()));
        };
        let server = self
            .servers
            .get(&entry.server)
            .ok_or_else(|| DispatchRefusal::UnknownTool(namespaced_name.to_string()))?;
        // THE LAST SIGHTING, so the registration-level half of the artifact question is the
        // lifecycle's own derivation rather than a second one written here.
        let sighting = live.sighting_for(&entry.server);
        // THE FINGERPRINT, AND IT IS THIS PLANE'S ONLY CONTRIBUTION TO THE GATE. A closure, not a
        // value: the validator runs it at the artifact step and never before, which is what keeps a
        // caller with no grant from learning what the upstream is currently serving.
        //
        // With a live tool list it is what the UPSTREAM is serving right now; with no sighting it is
        // the hash the operator wrote. That choice is the whole rug-pull defence: comparing the
        // approved hash against the configured hash is comparing the operator's intent with itself
        // and cannot, by construction, notice an upstream changing its schema underneath.
        let observe = || match live.digest_for(&entry.server, &entry.tool, &server.approval) {
            LiveDigest::Unsighted => {
                busbar_core::trust::validate::Observed::At(entry.dispatch_digest().to_string())
            }
            LiveDigest::At(digest) => busbar_core::trust::validate::Observed::At(digest),
            LiveDigest::Quarantined(why) => busbar_core::trust::validate::Observed::Drifted(why),
        };
        // THE ONE ORDERED GATE, in core, reached identically by every plane. `Approval::serves` is
        // still the comparison it makes — the same one the operator's changes queue is rendered
        // from — but the ORDER around it is no longer this file's to decide.
        busbar_core::trust::validate::validate_request(&busbar_core::trust::validate::Ask {
            principal,
            now,
            // GRANT BEFORE DIGEST is now a property of the validator rather than of the order these
            // lines happen to be written in.
            grants: &[
                busbar_core::trust::validate::Grant::Scope {
                    kind: SCOPE_KIND_SERVER,
                    name: &entry.server,
                },
                busbar_core::trust::validate::Grant::Scope {
                    kind: SCOPE_KIND_TOOL,
                    name: &entry.namespaced,
                },
            ],
            approval: &server.approval,
            sighting: &sighting,
            capability: Some(busbar_core::trust::validate::Fingerprint {
                capability: &entry.tool,
                observe: &observe,
            }),
            generation,
        })
        .map_err(|refusal| as_dispatch_refusal(refusal, server, entry, &sighting))?;
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
        principal: Option<&busbar_api::VirtualKey>,
        sightings: LiveSightings<'_>,
        selected: &ToolEntry,
        selected_generation: u64,
        now: u64,
    ) -> Result<(), DispatchRefusal> {
        // THE GENERATION IS PART OF THE ONE CALL, not a check in front of it. It is compared LAST,
        // after identity, grant and artifact, because "something moved, retry" is a worse message
        // than any of the three and should only be reached when none of them applies.
        let live = self.resolve(
            principal,
            sightings,
            &selected.namespaced,
            busbar_core::trust::validate::Generations::since(selected_generation, self.generation),
            now,
        )?;
        if live.schema_hash != selected.schema_hash {
            return Err(DispatchRefusal::NotApproved(selected.namespaced.clone()));
        }
        Ok(())
    }
}

/// ADMISSION AND RE-VALIDATION AS THE UNIT BATTERIES DRIVE THEM: a fixed clock and, for admission,
/// a snapshot that is its own live one.
///
/// `cfg(test)` and nothing else — a production caller has a real clock and a real pair of
/// generations, and a shorthand that supplied either for it would be a shorthand for skipping a
/// step.
#[cfg(all(test, not(busbar_mcp_native)))]
impl Catalogue {
    pub(crate) fn resolve_now(
        &self,
        principal: Option<&busbar_api::VirtualKey>,
        live: LiveSightings<'_>,
        namespaced_name: &str,
    ) -> Result<&ToolEntry, DispatchRefusal> {
        self.resolve(
            principal,
            live,
            namespaced_name,
            busbar_core::trust::validate::Generations::at_admission(self.generation),
            0,
        )
    }

    pub(crate) fn revalidate_now(
        &self,
        principal: Option<&busbar_api::VirtualKey>,
        sightings: LiveSightings<'_>,
        selected: &ToolEntry,
        selected_generation: u64,
    ) -> Result<(), DispatchRefusal> {
        self.revalidate(principal, sightings, selected, selected_generation, 0)
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

/// RENDER the core refusal as this plane's own wire refusal.
///
/// The DECISION is core's and only the wording is this plane's, which is why every arm maps rather
/// than re-derives: a second derivation here could disagree with the gate at exactly the moment a
/// call races a quarantine. The words themselves are unchanged and stay PLURAL — `not_granted`,
/// `not_pinned`, `not_approved`, `quarantined` and `generation_moved` are five different things for
/// an operator to go and do.
fn as_dispatch_refusal(
    refusal: busbar_core::trust::validate::Refusal,
    server: &ServerEntry,
    entry: &ToolEntry,
    sighting: &busbar_substrate::trust::Sighting<TransportPin>,
) -> DispatchRefusal {
    use busbar_core::trust::validate::Refusal;
    match refusal {
        // THE CATALOGUE HIDES WHAT A CALLER MAY NOT SEE, so this renders identically to
        // `UnknownTool` on the wire; the audit word is what keeps the two apart for an operator.
        Refusal::NotGranted { .. } => DispatchRefusal::NotGranted(entry.namespaced.clone()),
        // THE PRINCIPAL WENT STALE BETWEEN INGRESS AND DISPATCH. The wire answer is the same one an
        // ungranted caller gets; the audit word is not.
        Refusal::IdentityNotLive { .. } => {
            DispatchRefusal::IdentityNotLive(entry.namespaced.clone())
        }
        // No egress list is consulted on this path. Answered rather than unwrapped because this is a
        // request path and "unreachable" is a claim about today's arguments.
        Refusal::EgressDenied { .. } => DispatchRefusal::NotGranted(entry.namespaced.clone()),
        // `Pending` IS "no locked identity pin" — the state's own definition — so this is a
        // rendering of the state rather than a second test of the approval's fields.
        Refusal::NotServing {
            state: busbar_substrate::trust::TrustState::Pending,
            ..
        } => DispatchRefusal::NotPinned(server.id.clone()),
        Refusal::NotServing { state, .. } => DispatchRefusal::Quarantined {
            tool: entry.namespaced.clone(),
            // THE SAME WORD THE ADVERTISEMENT PATH USES, asked of the sighting as well as the state
            // so a demotion replayed at boot says so here too rather than being re-described as
            // ordinary drift.
            why: super::client::catalogue::quarantine_word_for(sighting, state)
                .unwrap_or("this server is not serving"),
        },
        Refusal::Unobservable { why, .. } => DispatchRefusal::Quarantined {
            tool: entry.namespaced.clone(),
            why,
        },
        Refusal::ArtifactDrifted { .. } => refusal_reason(server, entry),
        Refusal::GenerationMoved { admitted, live } => DispatchRefusal::GenerationMoved {
            selected: admitted,
            live,
        },
    }
}

fn server_entry(id: &str, def: &McpServerDefCfg) -> ServerEntry {
    // The registration read as the operator's standing INTENT: the identity they pinned out of
    // band, and the digest they approved for each capability. A capability they allowed without
    // approving a digest is absent from the map, which is `pending` — allowed is not approved.
    //
    // THE READER IS `busbar_substrate::trust::declared`'s, for every plane. What this plane supplies is the
    // `Declares` impl beside `TransportPin` — which mechanisms are roots, and the artifact for each
    // reading. It supplies no sequence and no blank-key rule, so an operator's `key: "  "` is
    // refused here by the same line that refuses it on the sibling plane.
    let approval = match busbar_substrate::trust::declared::declared_pin::<TransportPin>(
        def.pin.declaration(),
    ) {
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
        roots: def.roots.clone(),
        sampling: def.sampling.clone(),
        max_input_required_rounds: def
            .max_input_required_rounds
            .unwrap_or(super::config::DEFAULT_MAX_INPUT_REQUIRED_ROUNDS),
        max_caller_ask_rounds: def
            .max_caller_ask_rounds
            .unwrap_or(super::config::DEFAULT_MAX_CALLER_ASK_ROUNDS),
        // `validate_server` already parsed this and refused a malformed one at boot, so the only way
        // to reach the fallback is a code path that skipped validation. Falling back to the default
        // bound is the fail-CLOSED answer: a server that ends up with a huge staleness bound is a
        // server whose drift a call would not re-verify.
        verify_policy: super::config::verify_policy_for(def).unwrap_or(
            busbar_substrate::trust::reverify::Policy {
                ttl_ms: busbar_substrate::duration::parse_duration_secs(
                    super::config::DEFAULT_MCP_VERIFY_TTL,
                )
                .unwrap_or(5)
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
                .and_then(|t| busbar_substrate::duration::parse_duration_secs(t).ok())
                .map(std::time::Duration::from_secs),
        },
    }
}

#[cfg(all(test, not(busbar_mcp_native)))]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;

#[cfg(all(test, not(busbar_mcp_native)))]
#[path = "tests/trust_gate_tests.rs"]
mod trust_gate_tests;

// ══ THE PLANE'S HALF OF THE CATALOGUE SEAM ═══════════════════════════════════════════════════════
//
// Core ([`busbar_substrate::catalogue`]) owns the walk, the fail-closed floor, the order in which entitlement
// and fitness are applied and the rule that nothing is rendered before it is entitled. The ordered
// gate ([`busbar_core::trust::validate`]) owns the entitlement decision itself. Everything below is what
// THIS PLANE contributes, and it is deliberately nothing but declarations: which grants an entry
// requires, which question this catalogue is asking, what a refusal is called here, and how an entry
// is written onto the MCP wire.
//
// THE SCOPE KINDS ARE WRITTEN ONCE FOR FOUR ENTRY TYPES. `mcp_server` is "may this caller reach this
// upstream at all" and `mcp_tool` is "may it reach this capability", and both are required for every
// capability an MCP registration exposes — a tool, a prompt, a resource and a template alike. A
// prompt is a capability of a server, so a caller with no reach to the server has no reach to its
// prompts; the alternative is a second scope kind per capability that operators would have to keep
// in agreement by hand.
//
// The four impls differ in exactly one thing — `render` — which is the point: the wire form is the
// protocol's and the entitlement rule is not per-capability.

/// The MCP grant pair, stated in ONE place so four entry types cannot drift about what "granted"
/// means. The order is the one an operator reads: the server first (may this caller reach this
/// upstream at all), then the capability.
///
/// SCOPE KIND CONSTANTS, not literals, so the listing and [`Catalogue::resolve`] name the same two
/// kinds by construction — a caller must never be able to see a tool it would then be refused for,
/// or be refused for one it can see.
fn mcp_grants<'g>(out: &mut Vec<Grant<'g>>, server: &'g str, namespaced_name: &'g str) {
    out.push(Grant::Scope {
        kind: SCOPE_KIND_SERVER,
        name: server,
    });
    out.push(Grant::Scope {
        kind: SCOPE_KIND_TOOL,
        name: namespaced_name,
    });
}

/// WHAT THIS PLANE'S CATALOGUE ASKS, and it is identity and grant and no more.
///
/// The artifact step is deliberately absent: the MCP catalogue LISTS what it will not dispatch, so
/// an operator can see the approval queue, and `tools/call` asks the full ordered gate in
/// [`Catalogue::resolve`]. That is a statement about what a listing MEANS on this wire, made at one
/// call site in this file, rather than a step some shared function decided to skip — see
/// [`busbar_core::trust::validate::validate_visibility`], which says the same thing from the other side.
///
/// Every refusal renders as `NotGranted`/`IdentityNotLive`, which are the two arms whose WIRE text
/// is identical to `UnknownTool`'s: a caller learns only that there is nothing there for it, and the
/// audit record keeps the three apart for the operator.
fn admit_listing(
    caller: &Caller<'_>,
    grants: &[Grant<'_>],
    name: &str,
) -> Result<(), DispatchRefusal> {
    busbar_core::trust::validate::validate_visibility(caller.key, caller.now, grants).map_err(|r| {
        match r {
            busbar_core::trust::validate::Refusal::IdentityNotLive { .. } => {
                DispatchRefusal::IdentityNotLive(name.to_string())
            }
            // No egress list is consulted on a listing, and the artifact and generation steps are
            // not asked at all. Answered rather than unwrapped because this is a request path and
            // "unreachable" is a claim about today's arguments.
            _ => DispatchRefusal::NotGranted(name.to_string()),
        }
    })
}

impl CatalogueItem for ToolEntry {
    type Excluded = DispatchRefusal;
    /// Nothing. A tool is addressed BY NAME and is either the caller's or not: there is no
    /// structural fitness question on this plane, which is precisely the difference from A2A, where
    /// an agent that cannot accept a shape of task is not a candidate for it.
    type Query = ();
    type Fit = ();
    type Wire<'a> = serde_json::Value;

    fn required_grants<'g>(&'g self, _query: &'g (), out: &mut Vec<Grant<'g>>) {
        mcp_grants(out, &self.server, &self.namespaced);
    }

    fn admit(&self, caller: &Caller<'_>, grants: &[Grant<'_>]) -> Result<(), DispatchRefusal> {
        admit_listing(caller, grants, &self.namespaced)
    }

    fn fit(&self, _query: &()) -> Result<(), DispatchRefusal> {
        Ok(())
    }

    fn ungranted(&self) -> DispatchRefusal {
        DispatchRefusal::NotGranted(self.namespaced.clone())
    }

    /// One catalogue entry as the wire carries it. The description is MARKUP-NORMALISED here: this
    /// is the moment it is shown or fed as context, and that moment is exactly where the strip
    /// belongs.
    fn render(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        // The NAMESPACED name is the wire name, because it is the routing key — the bound identity a
        // route is decided on, never the free-text description — and the value an `mcp_tool` grant
        // carries. Exposing the bare upstream name would let two servers collide in one caller's
        // catalogue, so one server's tool would silently answer for another's.
        obj.insert("name".into(), self.namespaced.clone().into());
        if let Some(d) = super::sanitize::normalise_opt(self.description.as_deref()) {
            obj.insert("description".into(), d.into());
        }
        obj.insert(
            "inputSchema".into(),
            self.input_schema
                .clone()
                // A tool with no declared schema still needs a schema-shaped answer: clients reject
                // a tool whose `inputSchema` is absent, and an empty object is the honest "no
                // constraints declared" rather than a fabricated one.
                .unwrap_or_else(|| serde_json::json!({ "type": "object" })),
        );
        // THE OUTPUT SCHEMA, when the operator approved one — and ONLY then. Unlike `inputSchema`
        // there is no schema-shaped stand-in for its absence: an absent `outputSchema` means "this
        // tool makes no promise about structured output", and `{}` would mean "it promises, and the
        // promise is vacuous". The spec reads the PRESENCE of this key, not its contents, to decide
        // whether conforming structured results are a MUST, so inventing one would invent an
        // obligation.
        //
        // Dropping it is the mirror-image defect: a client that would have validated the structured
        // result has nothing to validate against and cannot tell a conforming result from a
        // violating one. `mcp::method::tools_call` therefore also CHECKS what comes back — see
        // `structured_output_violation`.
        if let Some(s) = &self.output_schema {
            obj.insert("outputSchema".into(), s.clone());
        }
        // The approved schema hash is published because it is the operator's approval, not a secret,
        // and a client that pins what it saw is a client that notices a rug-pull too.
        if let Some(h) = &self.schema_hash {
            obj.insert(
                "_meta".into(),
                serde_json::json!({ "io.busbar/schemaHash": h }),
            );
        }
        serde_json::Value::Object(obj)
    }
}

impl CatalogueItem for PromptEntry {
    type Excluded = DispatchRefusal;
    type Query = ();
    type Fit = ();
    type Wire<'a> = serde_json::Value;

    fn required_grants<'g>(&'g self, _query: &'g (), out: &mut Vec<Grant<'g>>) {
        mcp_grants(out, &self.server, &self.namespaced);
    }

    fn admit(&self, caller: &Caller<'_>, grants: &[Grant<'_>]) -> Result<(), DispatchRefusal> {
        admit_listing(caller, grants, &self.namespaced)
    }

    fn fit(&self, _query: &()) -> Result<(), DispatchRefusal> {
        Ok(())
    }

    fn ungranted(&self) -> DispatchRefusal {
        DispatchRefusal::NotGranted(self.namespaced.clone())
    }

    fn render(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert("name".into(), self.namespaced.clone().into());
        if let Some(d) = super::sanitize::normalise_opt(self.description.as_deref()) {
            obj.insert("description".into(), d.into());
        }
        serde_json::Value::Object(obj)
    }
}

impl CatalogueItem for ResourceEntry {
    type Excluded = DispatchRefusal;
    type Query = ();
    type Fit = ();
    type Wire<'a> = serde_json::Value;

    fn required_grants<'g>(&'g self, _query: &'g (), out: &mut Vec<Grant<'g>>) {
        mcp_grants(out, &self.server, &self.namespaced);
    }

    fn admit(&self, caller: &Caller<'_>, grants: &[Grant<'_>]) -> Result<(), DispatchRefusal> {
        admit_listing(caller, grants, &self.namespaced)
    }

    fn fit(&self, _query: &()) -> Result<(), DispatchRefusal> {
        Ok(())
    }

    fn ungranted(&self) -> DispatchRefusal {
        DispatchRefusal::NotGranted(self.namespaced.clone())
    }

    fn render(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        // THE RAW URI, because that is what a client hands back on `resources/read`. The namespaced
        // form stays the grant value and the map key — both of which must remain unique per
        // (server, uri) — but it is not what a client has to say.
        obj.insert("uri".into(), self.uri.clone().into());
        if let Some(n) = super::sanitize::normalise_opt(self.name.as_deref()) {
            obj.insert("name".into(), n.into());
        }
        if let Some(d) = super::sanitize::normalise_opt(self.description.as_deref()) {
            obj.insert("description".into(), d.into());
        }
        if let Some(m) = &self.mime_type {
            obj.insert("mimeType".into(), m.clone().into());
        }
        serde_json::Value::Object(obj)
    }
}

impl CatalogueItem for ResourceTemplateEntry {
    type Excluded = DispatchRefusal;
    type Query = ();
    type Fit = ();
    type Wire<'a> = serde_json::Value;

    fn required_grants<'g>(&'g self, _query: &'g (), out: &mut Vec<Grant<'g>>) {
        mcp_grants(out, &self.server, &self.namespaced);
    }

    fn admit(&self, caller: &Caller<'_>, grants: &[Grant<'_>]) -> Result<(), DispatchRefusal> {
        admit_listing(caller, grants, &self.namespaced)
    }

    fn fit(&self, _query: &()) -> Result<(), DispatchRefusal> {
        Ok(())
    }

    fn ungranted(&self) -> DispatchRefusal {
        DispatchRefusal::NotGranted(self.namespaced.clone())
    }

    fn render(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        // The operator's own template: the caller expands what it is given.
        obj.insert("uriTemplate".into(), self.uri_template.clone().into());
        if let Some(n) = super::sanitize::normalise_opt(self.name.as_deref()) {
            obj.insert("name".into(), n.into());
        }
        if let Some(d) = super::sanitize::normalise_opt(self.description.as_deref()) {
            obj.insert("description".into(), d.into());
        }
        if let Some(m) = &self.mime_type {
            obj.insert("mimeType".into(), m.clone().into());
        }
        serde_json::Value::Object(obj)
    }
}

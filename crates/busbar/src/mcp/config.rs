// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `tools:` SECTION — the MCP plane's config grammar, and the one place its values are judged.
//!
//! ## The section IS the plane
//!
//! There is deliberately no `plane:`, `bind:` or `target:` selector anywhere in here.
//! `pools:`, `tools:` and `agents:` are SIBLINGS of one shape, and which plane an entry is on is
//! decided by which map it is written in. Hooks attach BY BARE NAME from the one top-level `hooks:`
//! map, exactly as they do on the pool plane.
//!
//! ## Two words are reserved at the section level, on every plane
//!
//! `hooks` and `upstream_credentials` are reserved here for the same reason they are on `pools:` —
//! so the word space is IDENTICAL across planes. An operator who learns the rule once should not
//! discover that a name legal on one plane is a section knob on another. Pinned to
//! [`crate::config::RESERVED_POOLS_SECTION_KEYS`] by a test.
//!
//! ## `tools_allow` is a MAP, and that is the whole bound-identity rule compressed into one field
//!
//! Tool identity is `(server, tool, schema-hash)` — the bound-identity rule everything else on this
//! plane hangs on — so every allowed tool needs a SLOT for its approved schema hash, and later for
//! its per-tool policy. A bare list has nowhere to put either, and
//! the two obvious repairs are both worse — a second sibling key makes "is this tool allowed"
//! ambiguous, and re-typing after publication breaks operators' files. So the shape is
//! `tools_allow: { <tool>: { schema_hash?: "sha256:…" } }`, where an empty value object means
//! "allowed, no hash approved yet" and the entry is filled in by `approve`.
//!
//! ## The pin is an OBJECT, not a scalar
//!
//! The earlier `spki_pin:` scalar spelling contradicted busbar's own admin API, which already
//! speaks `pin{mechanism,key?}`, and a scalar cannot express the sibling plane's root at all — an
//! A2A agent is pinned by a JWS issuer key plus a card fingerprint, not by a certificate SPKI. The
//! object form is canonical, and the mechanism is checked HERE against the material it requires: a
//! registration cannot claim `cert_spki` and carry nothing to verify with. `unpinned` is spelled
//! out loud rather than encoded as an absent field, because an operator reading a list of
//! registrations needs to SEE which entries have no root — and because the trust-root rule requires
//! the mechanism to be named "explicitly, and loudly", per server.
//!
//! ## The server-initiated grants are DENY-BY-DEFAULT, and that is a `Default` impl, not a comment
//!
//! `sampling`, `elicitation` and `roots` are grants on the registry entry — an upstream must not be
//! able to induce busbar to spend busbar's own authority (an LLM completion on busbar's pools and
//! budget, a user prompt, a filesystem-root disclosure) that the operator never granted it.
//! Absent means denied, and it means denied because [`ServerRequestGrants::default`] is three
//! `false`s — a field an operator forgets to write is a field that grants nothing.
//!
//! ## `publish_as` moves ONE invariant from construction to validation, and pays for it
//!
//! `{server}{NAMESPACE_SEP}{tool}` is the DEFAULT wire name and it is unchanged: every config that
//! never writes [`ToolAllowCfg::publish_as`] publishes byte-identical names, so there is no
//! migration and no grant to re-audit. What the override buys is the single-upstream deployment,
//! which today forces every client onto renamed tools for a namespace with exactly one occupant.
//!
//! The property `{server}_{tool}` exists to protect is **one wire name resolves to exactly one
//! `(server, tool)`**. That property is not negotiable; only its MECHANISM is. Today it holds BY
//! CONSTRUCTION. With an override it holds BY VALIDATION —
//! [`validate_published_names`], which builds the FULL published set (every namespaced name AND
//! every override) and refuses boot on any duplicate, naming both sides.
//!
//! **Per-TOOL and not per-server**, because `tools_allow.<tool>` is already the block where one
//! operator vouches for one tool — its approved digest, the description busbar publishes instead of
//! the upstream's, its input schema, its `ask_caller` gate. "And its wire name is X" is the same
//! kind of statement by the same person at the same moment. A per-server switch would rename every
//! tool that server exposes on one line; per-tool, the blast radius is exactly the name that was
//! typed.
//!
//! **The subtle collision is the whole reason the check is against the whole set.** A bare
//! `publish_as: foo_bar` collides with server `foo`'s tool `bar`, which namespaces to `foo_bar`.
//! An implementation that compared overrides only to each other would pass that config and let one
//! wire name resolve to two `(server, tool)` pairs — which, because `catalogue::granted` keys the
//! `mcp_tool` grant on the PUBLISHED name, would silently change who can call what. That is why a
//! collision is a LOUD BOOT REFUSAL and never an automatic rename.

use serde::{Deserialize, Serialize};

/// The two words reserved at the `tools:` section level. IDENTICAL to
/// [`crate::config::RESERVED_POOLS_SECTION_KEYS`] by design, and pinned to it by a test: the whole
/// point is that the reserved word space does not vary per plane.
pub(crate) const RESERVED_TOOLS_SECTION_KEYS: &[&str] = &["hooks", "upstream_credentials"];

/// The separator between a server id and a tool name in the `{server}_{tool}` namespaced routing
/// key. Stated once because it is the ROUTING KEY: the catalogue builds it, the scope
/// grant `mcp_tool` names it, and dispatch parses nothing back out of it.
pub(crate) const NAMESPACE_SEP: &str = "_";

/// `tools.<server>.pin.mechanism` — WHICH authenticity root this registration has.
///
/// Exactly four, because four is every root an MCP endpoint can actually offer: a signed manifest's
/// operator-pinned issuer key, the endpoint's certificate SPKI, mutual TLS, or nothing at all —
/// `pinned_pubkey | cert_spki | mtls | unpinned`.
///
/// ## WHY THE `Mcp` PREFIX, and why it is on THIS one and not on A2A's
///
/// [`crate::a2a::config::PinMechanism`] is the same concept for the other plane and used to share
/// this bare name. That was survivable only while the config-grammar fingerprint
/// (`scripts/config-schema.py`) did not track this file. Its snapshot is a FLAT map keyed by the
/// bare Rust ident with no module path, so two `PinMechanism`s occupy one key: the second file read
/// wins, and the first plane's grammar silently stops being covered. Adding `mcp/config.rs` to the
/// tracked set with the names still clashing produced exactly that —
/// `PinMechanism::jws_issuer_key: enum variant REMOVED`, a reported break in the A2A grammar from a
/// commit that did not touch A2A.
///
/// The prefix went on the MCP side, not the A2A side, for one reason: A2A's `PinMechanism` is
/// ALREADY FROZEN in the committed snapshot under that key, and the grammar is additive-only after
/// 1.5.3 — so renaming it would present to the classifier as a whole-section REMOVAL and would need
/// a waiver, i.e. laundering a real break to settle a naming argument. This type was in no snapshot
/// yet, so renaming it costs nothing and needs no waiver.
///
/// **No operator's config file changes.** The ident is not wire grammar: `rename_all` below decides
/// the spellings a document may use, and they are byte-identical before and after.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum McpPinMechanism {
    /// A signed tool manifest verified against an operator-supplied, out-of-band issuer public key.
    PinnedPubkey,
    /// No server-side signature exists, so the pin degrades to the endpoint's certificate SPKI hash
    /// — a real network-layer authenticity root, and still not trust-on-first-use.
    CertSpki,
    /// Mutual TLS; pinned on the peer certificate SPKI hash.
    Mtls,
    /// NO authenticity root. Registrable, never approvable — low-risk dev use has to be spelled out
    /// loud rather than inferred from an absent field.
    Unpinned,
}

impl McpPinMechanism {
    /// Does this mechanism require operator-supplied key material? Three of the four are meaningless
    /// without it, and the fourth is meaningless with it — which is the rule the object form exists
    /// to make expressible.
    fn needs_key(self) -> bool {
        !matches!(self, McpPinMechanism::Unpinned)
    }

    /// The config token, for diagnostics. Deliberately the same string `serde` accepts.
    pub(crate) fn token(self) -> &'static str {
        match self {
            McpPinMechanism::PinnedPubkey => "pinned_pubkey",
            McpPinMechanism::CertSpki => "cert_spki",
            McpPinMechanism::Mtls => "mtls",
            McpPinMechanism::Unpinned => "unpinned",
        }
    }
}

/// `tools.<server>.pin` — the out-of-band operator-supplied trust root.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerPinCfg {
    /// Which root this is. REQUIRED: a pin whose mechanism is inferred is a pin whose meaning
    /// changes when the code that infers it changes.
    pub(crate) mechanism: McpPinMechanism,
    /// The operator-supplied material: an issuer public key, or a certificate SPKI hash. Absent only
    /// for `unpinned`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) key: Option<String>,
}

/// `tools.<server>.tools_allow.<tool>` — one approved tool, and the slot its approved schema hash
/// lives in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolAllowCfg {
    /// The APPROVED schema/description hash — the value a background tool-list refresh diffs the
    /// observed one against, which is the whole rug-pull defence. An empty value object means
    /// "allowed, no hash approved yet", which is `pending` and does NOT serve — the dispatch gate
    /// compares the observed digest against an approved one, and there is no approved one to
    /// compare against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) schema_hash: Option<String>,
    /// The operator-facing description shown in the catalogue. NEVER an input to a routing
    /// decision — routing binds `(server, tool, schema-hash)`, never attacker-supplied free text.
    /// It is markup-normalised on the way out and is otherwise inert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// The tool's JSON Schema, echoed verbatim in `tools/list`. Opaque to busbar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) input_schema: Option<serde_json::Value>,
    /// THE WIRE NAME busbar publishes for this tool, overriding the default
    /// `{server}{NAMESPACE_SEP}{tool}`. OPTIONAL — absent means the namespaced default, exactly as
    /// before this field existed, which is why no existing config changes.
    ///
    /// It is the value `tools/list` emits as `name`, the value `tools/call` is dispatched on, and —
    /// because [`crate::mcp::catalogue`] keys authorization on the published name — the value an
    /// `mcp_tool:` scope grant must name. Setting it therefore CHANGES WHO CAN CALL THIS TOOL, which
    /// is precisely why it lives in `tools_allow.<tool>` beside the approved digest rather than on
    /// the server: the operator who vouches for the tool is the operator who names it.
    ///
    /// The uniqueness invariant is enforced by [`validate_published_names`] against the whole
    /// published set, so an override that shadows another server's namespaced name refuses boot.
    ///
    /// NOT the RFC 8693 refresh scope: `mcp::connect::refresh_scope` keeps asking for the namespaced
    /// spelling, because that scope is what busbar requests of an AUTHORIZATION SERVER about a
    /// registration, not what busbar publishes to its own callers. One field, one meaning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) publish_as: Option<String>,
    /// The input BUSBAR asks its own caller for before it dispatches this tool. ABSENT ⇒ no ask,
    /// which is deny-by-default and is every deployment that has not opted in. See [`AskEntryCfg`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) ask_caller: Vec<AskRoundCfg>,
    /// SEP-2663: whether a `tools/call` on this tool may — or must — be answered with a task rather
    /// than a result. A REGISTRATION-TIME declaration, not a runtime property, because that is what
    /// the `-32021` gate is keyed off: a client that did not declare the tasks extension has to be
    /// refused BEFORE the handler runs, and the only thing that can decide that before the handler
    /// runs is what the operator wrote here. See [`TaskSupport`].
    #[serde(default, skip_serializing_if = "TaskSupport::is_none")]
    pub(crate) task_support: TaskSupport,
    /// The input busbar asks its own caller for FROM INSIDE the task, surfaced on `tasks/get` as
    /// `inputRequests` and answered with `tasks/update`.
    ///
    /// A SEPARATE LIST from [`ask_caller`](Self::ask_caller) rather than a mode flag on it, because
    /// the two are different exchanges and the difference is visible on the wire. `ask_caller:` is
    /// the SEP-2322 synchronous loop: busbar answers `tools/call` with an `InputRequiredResult` and
    /// the caller retries. This one is the SEP-2663 loop: busbar answers with a `CreateTaskResult`,
    /// parks the task in `input_required`, and the caller answers out of band. A single list with a
    /// mode switch would let one edit silently change which shape an existing deployment's callers
    /// receive; two lists cannot.
    ///
    /// Requires [`task_support`](Self::task_support) other than `none` — see `validate_server`: a
    /// tool that never creates a task has no task for these to be asked inside of.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) task_ask_caller: Vec<AskRoundCfg>,
}

/// `tools.<server>.tools_allow.<tool>.task_support` — SEP-2663's registration-time declaration.
///
/// THREE VALUES AND NOT A BOOLEAN, because the extension distinguishes three postures and the
/// middle one is the common case:
///
/// - `none` (the DEFAULT, and every tool that predates this grammar) — this tool is answered
///   synchronously, always. A client that declared the tasks extension still gets a plain
///   `ToolResult`, which is exactly what the extension says a server may do.
/// - `optional` — busbar answers with a `CreateTaskResult` when the caller declared the extension,
///   and synchronously when it did not. No client is locked out by an operator turning this on.
/// - `required` — busbar CANNOT answer this tool synchronously, so a caller that did not declare
///   the extension is refused with `-32021` before the handler runs, naming the extension in
///   `data.requiredCapabilities`. This is the posture for a tool whose work genuinely outlives a
///   request, and it is the one an operator must opt into deliberately, because it makes the tool
///   invisible-in-practice to every client that has not implemented the extension.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TaskSupport {
    /// Answered synchronously, always. The default, so nothing changes for a config that says
    /// nothing.
    #[default]
    None,
    /// A task when the caller declared the extension; a synchronous result when it did not.
    Optional,
    /// A task always, and `-32021` for a caller that cannot receive one.
    Required,
}

impl TaskSupport {
    /// Serde skip predicate — `none` is the default, so writing it back out would put a key into
    /// every serialised tool that no operator typed.
    pub(crate) fn is_none(&self) -> bool {
        matches!(self, TaskSupport::None)
    }

    /// Whether a `tools/call` on this tool creates a task, given what the caller declared.
    ///
    /// The caller's declaration is read from the ONE place this revision puts it —
    /// `params._meta['io.modelcontextprotocol/clientCapabilities']` — so a session-level
    /// declaration and SEP-2575's per-request override are literally the same field and cannot
    /// disagree.
    pub(crate) fn creates_task(&self, client_declared: bool) -> bool {
        match self {
            TaskSupport::None => false,
            TaskSupport::Optional | TaskSupport::Required => client_declared,
        }
    }
}

/// `tools.<server>.prompts_allow.<name>` — one exposed prompt, markup-normalised on the way out.
///
/// The locked core keys name only `tools_allow`; prompts and resources belong to the MCP-SPECIFIC
/// superset an operator "may also set per entry". They take the same MAP shape as `tools_allow` for
/// the same reason: a capability needs a slot for what the operator approved about it.
///
/// TWO SPELLINGS, AND EXACTLY ONE PER PROMPT. `template:` is the text form and stays the documented
/// spelling for the common case — one `{type:"text"}` message, which is what almost every prompt is.
/// `messages:` is the TYPED form, and it exists because a text template cannot express an image, an
/// audio clip or an embedded resource at all: base64 in a `text` field is prose to every client that
/// reads it, so "put it in the template" is not a workaround, it is a different and wrong answer.
/// Declaring both is a config refusal — see [`validate_server`] — because two statements of what one
/// prompt says make the answer depend on which branch runs first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromptAllowCfg {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// The prompt TEMPLATE returned by `prompts/get`. Templates sit in the sanitization set
    /// alongside tool output, because a template is exactly as injectable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) template: Option<String>,
    /// The input BUSBAR asks its own caller for before it renders this prompt. Same grammar and
    /// same deny-by-default-by-absence as `tools_allow`'s — one grammar, two paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) ask_caller: Vec<AskRoundCfg>,
    /// The TYPED form: the `PromptMessage` list `prompts/get` returns verbatim. Absent ⇒ the
    /// `template:` form. Every text field in it is markup-normalised on the way out, exactly as
    /// `template:` is — a second way to put text into a model's context must not be a second way
    /// past the strip.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) messages: Vec<PromptMessageCfg>,
}

/// ONE ROUND of `ask_caller` — a map from the server-assigned key to the request busbar makes.
///
/// A MAP, keyed exactly as the `inputRequests` it becomes on the wire (`mrtr.mdx:132-180`), because
/// the key is not decoration: the caller addresses its answer to it, and it is what makes one round
/// answerable. A LIST OF ROUNDS, because a multi-round exchange is a real requirement and a single
/// map could not express order.
pub(crate) type AskRoundCfg = indexmap::IndexMap<String, AskEntryCfg>;

/// `tools.<server>.{tools,prompts}_allow.<name>.ask_caller[<round>].<key>` — ONE request busbar
/// makes OF ITS OWN CALLER before it will run this capability.
///
/// ## This is busbar asking, not busbar forwarding, and the distinction is the whole point
///
/// An upstream's `InputRequiredResult` TERMINATES at busbar ([`super::inputreq`]) — busbar either
/// satisfies it under a grant the operator gave that server, or fails the call. It is never handed
/// onward. What this grammar declares is different in kind: a demand busbar makes IN ITS OWN NAME,
/// composed from the operator's literal bytes.
///
/// **There is no templating and no substitution here, and that is structural rather than a
/// convention.** [`params`](Self::params) is cloned verbatim onto the wire. The moment a value could
/// flow from an upstream response into this field, busbar would be laundering an upstream's demand
/// for authority under its own name with extra steps — and it would look like a feature while it did
/// it. `mcp/callerask.rs` is scanned at test time for any reference to the modules an upstream's
/// values live in, precisely so that this stays true by construction.
///
/// ## What an operator is actually turning on
///
/// A declared `elicitation/create` is a human-in-the-loop confirmation gate, which is the case most
/// deployments want. A declared `sampling/createMessage` is busbar asking the CALLER'S model to run
/// a completion on the CALLER'S budget — the mirror image of what `grants:` protects busbar from,
/// pointed the other way. That is why this is per capability, operator-written, and absent by
/// default: nothing here happens to a deployment that did not ask for it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AskEntryCfg {
    /// `elicitation/create`, `sampling/createMessage` or `roots/list` — the closed set
    /// `mrtr.mdx:184-192` names. Anything else is never sent: it names no capability a caller could
    /// have declared, and `mrtr.mdx:246` forbids sending an ask the caller has not declared.
    pub(crate) method: String,
    /// The request `params`, EXACTLY as the operator wrote them. Opaque to busbar and never
    /// inspected; what validates them is the caller's own schema check on receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) params: Option<serde_json::Value>,
}

/// `tools.<server>.prompts_allow.<name>.messages[]` — ONE typed message.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromptMessageCfg {
    /// `user` or `assistant`, checked by [`validate_server`]. Defaulted to `user` because a prompt is
    /// what the operator is asking the model, and a field an operator must retype on every line is a
    /// field an operator eventually mistypes.
    #[serde(default = "default_prompt_role")]
    pub(crate) role: String,
    pub(crate) content: PromptContentCfg,
}

fn default_prompt_role() -> String {
    "user".to_string()
}

/// One content block, INTERNALLY TAGGED by `type` — which is both the MCP wire spelling and the only
/// discriminator that survives a typo. An untagged union would silently deserialise into whichever
/// arm happened to fit, so a misspelled `mime_type` on an image could land as something else
/// entirely and the operator would be told nothing.
///
/// No `deny_unknown_fields`: serde does not support it on an internally tagged enum, and asking for
/// it here would be a compile error rather than the guard it looks like. The variants' own fields
/// are all required or defaulted, so an unknown key is caught as a missing/duplicate field instead.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum PromptContentCfg {
    /// Plain text. The same thing `template:` produces, available inside the typed form so a prompt
    /// that carries an image can also carry the sentence that asks about it.
    Text { text: String },
    /// Base64 image data. `mime_type` is REQUIRED: a client cannot render bytes it has not been told
    /// the type of, and guessing one from the payload would be busbar deciding what the operator
    /// meant.
    Image { data: String, mime_type: String },
    /// Base64 audio data, same rule.
    Audio { data: String, mime_type: String },
    /// An EMBEDDED RESOURCE — content carried inline in the prompt rather than fetched.
    Resource { resource: PromptResourceCfg },
}

/// The resource a `type: resource` content block embeds.
///
/// Its `uri` is an IDENTIFIER the client may echo, not a promise that `resources/read` will serve it:
/// an embedded resource is content that has already arrived. Making it a promise would mean every
/// embedded URI had to be separately approved in `resources_allow`, which is an approval an operator
/// did not make by writing a prompt.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromptResourceCfg {
    pub(crate) uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) text: Option<String>,
    /// Base64, and mutually exclusive with `text` for the same reason [`ResourceAllowCfg`]'s pair is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) blob: Option<String>,
}

/// `tools.<server>.resources_allow.<uri>` — one exposed resource, markup-normalised on the way out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourceAllowCfg {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mime_type: Option<String>,
    /// The content `resources/read` returns. In the sanitization set for the same reason as prompt
    /// templates: it re-enters model context verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) text: Option<String>,
    /// The BASE64 content `resources/read` returns, for a resource that is not text.
    ///
    /// `ResourceContents` in the schema is a union of a text form and a blob form, and this registry
    /// answered only one half of it: an operator with a PNG had to declare it as `text` — handing a
    /// client base64 in a field every client renders as prose — or not expose it at all.
    ///
    /// MUTUALLY EXCLUSIVE with `text:`, refused at boot rather than resolved. The two are the
    /// schema's alternatives; accepting both and picking one would put the choice of what a client
    /// reads in whichever branch happens to run first.
    ///
    /// NOT markup-normalised, and that is not an exemption from the sanitization rule — it is the
    /// rule applied correctly. `normalise` strips markup from TEXT that re-enters model context; a
    /// blob is opaque bytes the client is told the type of, and running a text filter over base64
    /// would corrupt the payload while protecting nothing. What IS checked is that it decodes, at
    /// boot, so the operator finds out rather than the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) blob: Option<String>,
}

/// `tools.<server>.resource_templates_allow.<uri-template>` — one exposed RESOURCE TEMPLATE.
///
/// A template is a PARAMETERISED URI (`test://template/{id}/data`) that a client expands and then
/// reads. `resources/templates/list` answered `[]` unconditionally before this, and that was the
/// correct answer only while the registry had no concept of one: the empty list said "this
/// deployment exposes none", which was true. It stops being true the moment an operator can declare
/// one, and the difference is not cosmetic — that method is the ONLY way a client discovers a
/// template, so an unconditional `[]` makes a declared template unreachable.
///
/// The KEY is the template. Approval is still per-declaration and still the operator's: what changes
/// is that one declaration now approves a SHAPE rather than a single URI, which is a policy decision
/// the operator makes by writing it here and could not previously express at all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourceTemplateAllowCfg {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mime_type: Option<String>,
    /// The content, with the template's own `{param}` placeholders substituted from the URI the
    /// caller actually asked for. There is deliberately no `blob:` here: a blob cannot carry a
    /// substitution, so a parameterised blob would be a template whose parameter changes nothing —
    /// which is a concrete resource wearing a template's clothes, and `resources_allow` is where
    /// those go.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) text: Option<String>,
}

/// `tools.<server>.grants` — the SERVER-INITIATED request grants.
///
/// DENY-BY-DEFAULT is this type's `Default`, not a rule written down somewhere else. Under revision
/// `2026-07-28` a server cannot initiate a request at all; the ask arrives as an
/// `InputRequiredResult` in the RESULT of a call busbar made, and these three grants are consulted
/// at busbar's decision to satisfy it — on EVERY retry, because there is no handshake to consult
/// them once — a revocation has to bite on the NEXT retry, not at the end of a conversation that
/// has no end.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerRequestGrants {
    /// May this server induce busbar to run an LLM completion on busbar's pools and budget? When
    /// granted, that completion rides the SAME admission/budget/metering/audit plane as any other
    /// LLM request — never a free side channel.
    #[serde(default)]
    pub(crate) sampling: bool,
    /// May this server ask busbar to solicit user input?
    #[serde(default)]
    pub(crate) elicitation: bool,
    /// May this server ask busbar to disclose filesystem roots?
    #[serde(default)]
    pub(crate) roots: bool,
}

impl ServerRequestGrants {
    /// Whether the grant named by an `InputRequiredResult`'s kind is held. An UNKNOWN kind is
    /// refused: a grant table that answers `true` for a kind it has never heard of is a grant table
    /// that widens itself every time the protocol grows a verb.
    pub(crate) fn allows(&self, kind: &str) -> bool {
        match kind {
            "sampling" => self.sampling,
            "elicitation" => self.elicitation,
            "roots" => self.roots,
            _ => false,
        }
    }
}

/// The DEFAULT cap on input-required rounds per logical dispatch.
///
/// A hard cap, refused past it, not a warning. Three is chosen because it is enough for a real
/// elicitation exchange (ask, clarify, confirm) and small enough that a hostile upstream returning
/// `InputRequiredResult` forever amplifies cost by a bounded constant rather than an unbounded one.
pub(crate) const DEFAULT_MAX_INPUT_REQUIRED_ROUNDS: u32 = 3;

/// The DEFAULT cap on rounds busbar may ask ITS OWN CALLER for, per capability.
///
/// Three for the same reason as the upstream cap, and it bounds a different risk: every round is a
/// fresh inbound request that busbar charges and meters, so an unbounded caller-facing exchange is a
/// caller amplifying its own cost against its own budget — which its budget would stop, but a bound
/// that does not depend on the budget being configured is the one worth having. Deny-by-default here
/// is the ABSENCE of `ask_caller`, not this number: a capability that declares no ask never asks
/// whatever this says.
pub(crate) const DEFAULT_MAX_CALLER_ASK_ROUNDS: u32 = 3;

/// THE DEPLOYMENT-WIDE REFRESH CADENCE a registration gets when it spells no `refresh_ttl:`.
///
/// Deliberately the same `6h` as the sibling plane's [`crate::a2a::config::DEFAULT_REVERIFY_TTL`],
/// because the two are the same decision about the same risk — how long a hash-pinned upstream may
/// have drifted before anybody looks — and an operator who learns the number on one plane should not
/// find a different one on the other. If a reason ever emerges for them to differ, it goes in
/// writing next to whichever one moves.
///
/// A DEFAULT and not an opt-in: the whole point of A2.1 is that the rug-pull defence runs without an
/// operator present, and a cadence that has to be switched on per server is a defence that is off on
/// every registration whose author did not know to switch it on.
pub(crate) const DEFAULT_MCP_REFRESH_TTL: &str = "6h";

/// One entry in the top-level `tools:` NAMED-DEFINITION map — one registered external MCP server.
///
/// Operator INTENT only (owner ruling 3). Everything that ACCUMULATES — every observed tool list,
/// the drift queue, the quarantine queue, the approval trail — is store state and is deliberately
/// absent from this struct.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)] // a typo'd key must fail boot, not silently un-pin a server.
pub(crate) struct McpServerDefCfg {
    /// The real remote MCP endpoint. Never client-visible: callers reach it through busbar.
    pub(crate) url: String,
    /// The out-of-band trust root. REQUIRED, and required to be spelled even when it is `unpinned`.
    pub(crate) pin: ServerPinCfg,
    /// `<n><s|m|h|d>` — how long an observation stays fresh before the upstream's tool list is
    /// re-fetched and re-hashed by the refresh timer. Absent ⇒ [`DEFAULT_MCP_REFRESH_TTL`].
    ///
    /// This is the ONE cadence knob on this plane, and it is deliberately the only one. There is no
    /// key that slows DETECTION, none that delays a QUARANTINE, and no per-server "skip if it failed
    /// last time" — every one of those would be a window an upstream could open for itself by
    /// misbehaving, and choosing when to misbehave is entirely within its gift. See
    /// [`crate::mcp::scheduler`], which has no knob at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) refresh_ttl: Option<String>,
    /// The approved tools, as a MAP so each carries its approved schema hash.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    pub(crate) tools_allow: indexmap::IndexMap<String, ToolAllowCfg>,
    /// The exposed prompts — MCP-specific superset, not one of the locked core keys.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    pub(crate) prompts_allow: indexmap::IndexMap<String, PromptAllowCfg>,
    /// The exposed resources, keyed by URI — MCP-specific superset, likewise.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    pub(crate) resources_allow: indexmap::IndexMap<String, ResourceAllowCfg>,
    /// The exposed resource TEMPLATES, keyed by URI template. Separate from `resources_allow`
    /// deliberately: `resources/list` and `resources/templates/list` are two different methods
    /// answering two different questions, and a client that expanded a concrete URI as a template —
    /// or listed a template as a readable resource — would be acting on the wrong one.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    pub(crate) resource_templates_allow: indexmap::IndexMap<String, ResourceTemplateAllowCfg>,
    /// The transport generation this registration speaks. One value today, spelled because the
    /// MCP-specific superset carries it and because a second leg would be a second wire format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) transport: Option<Transport>,
    /// The RFC 8707 audience busbar asks for when minting an OUTBOUND token for this server. Not
    /// busbar's own audience — that is `mcp.canonical_uri`, and confusing the two is the
    /// confused-deputy bug this field's name has to keep distinct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) aud: Option<String>,
    /// The server-initiated request grants. Absent ⇒ all denied.
    #[serde(default)]
    pub(crate) grants: ServerRequestGrants,
    /// Whether this ONE upstream may live on a private / loopback / CGNAT address.
    ///
    /// Per server rather than plane-wide, because the answer genuinely differs per registration: an
    /// MCP server on the cluster's internal network is the normal case, and a global switch would
    /// extend that one decision to every other server at once. Cloud-metadata addresses stay refused
    /// whatever this says — an operator saying "this server is internal" has said nothing about IMDS.
    /// Absent ⇒ `false`, which is the fail-closed posture.
    #[serde(default)]
    pub(crate) allow_private: bool,
    /// RFC 8693 token exchange for this upstream: how busbar's OWN subject token is exchanged for a
    /// per-backend, audience-bound, DOWN-SCOPED access token.
    ///
    /// Absent ⇒ no credential is sent at all (a public or network-authenticated upstream). What the
    /// exchange asks FOR is deliberately not written here: the requested scope is DERIVED from the
    /// inbound caller's own grant at dispatch time, because a configured static scope list would be a
    /// second place the authority is written down and the two would drift.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) token_exchange: Option<TokenExchangeCfg>,
    /// The cap on input-required rounds per logical dispatch. Absent ⇒
    /// [`DEFAULT_MAX_INPUT_REQUIRED_ROUNDS`]. `0` is legal and means "never satisfy one".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_input_required_rounds: Option<u32>,
    /// The cap on rounds busbar may ask ITS OWN CALLER for, per capability of this server. Absent ⇒
    /// [`DEFAULT_MAX_CALLER_ASK_ROUNDS`]. `0` is legal and is an operator KILL SWITCH: it disables
    /// every `ask_caller` on this server at once, without editing each capability.
    ///
    /// A second, independent bound beside the length of the `ask_caller` list, and it is not
    /// redundant. The caller-facing loop is spread across INDEPENDENT requests with no session, so
    /// the round index rides inside the integrity-protected `requestState` rather than in any
    /// counter busbar holds — a counter held between requests would be a session by another name.
    /// This cap is what that index is compared against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_caller_ask_rounds: Option<u32>,
    /// Outbound credential mode. Same vocabulary as the pool plane's, and DISTINCT from it: every
    /// MCP server authenticates independently, so this plane deliberately has no all-plane
    /// `tools.upstream_credentials` default at all. The reserved word space is
    /// uniform across planes regardless, so the key is reserved at the section level and an
    /// entry-level value overrides it (SCALAR ⇒ OVERRIDE).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) upstream_credentials: Option<crate::auth::UpstreamCreds>,
    /// Hooks attached to THIS server, by bare name from the top-level `hooks:` map. ADDS to the
    /// section-level `tools.hooks:` list (LIST ⇒ ADDITIVE).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) hooks: Vec<String>,
}

/// `tools.<server>.token_exchange` — the RFC 8693 exchange busbar performs before it calls this
/// upstream.
///
/// Three fields and no fourth. In particular there is NO `scope:` here, and that absence is the
/// design: the scope busbar asks for is derived from the INBOUND caller's grant on this server (see
/// `crate::mcp::client::egress::downscope`). A configured scope list would be a second, independent
/// statement of what a caller may reach, and the moment the two disagree the wider one wins — which
/// is exactly the transitive confused deputy this plane exists to close.
///
/// The RFC 8707 `resource` is `tools.<server>.aud`, which already exists: the exchanged token is
/// audience-bound to this backend so it cannot be spent at another.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenExchangeCfg {
    /// The operator's authorization server token endpoint. Vetted at boot for scheme, so the failure
    /// lands on the operator who wrote it rather than on a tool call an hour later.
    pub(crate) token_url: String,
    /// BUSBAR'S OWN token — the SUBJECT of the exchange, never the caller's. A `SecretRef` rather
    /// than an inline string so the value follows the same resolution path (`env` / `file` / a
    /// trusted secret plugin) every other credential on this engine does.
    pub(crate) subject_token: crate::config::SecretRef,
    /// RFC 8693 §2.1 `subject_token_type`. Defaulted to an access token, which is what busbar's own
    /// ambient credential is.
    #[serde(default = "default_subject_token_type")]
    pub(crate) subject_token_type: String,
}

/// `Eq` is asserted rather than derived because [`crate::config::SecretRef`] derives only
/// `PartialEq`. The relation is still a true equivalence — every field compares structurally and
/// none of them is a float — and the snapshot types this is embedded in (`ToolsCfg`, `ServerEntry`,
/// `Catalogue`) require `Eq` so a config apply can be compared for a no-op.
impl Eq for TokenExchangeCfg {}

fn default_subject_token_type() -> String {
    "urn:ietf:params:oauth:token-type:access_token".to_string()
}

/// `tools.<server>.transport` — the MCP transport generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Transport {
    /// Streamable HTTP, the `2026-07-28` stateless shape. The only one busbar speaks.
    StreamableHttp,
    /// A locally spawned child process. Named because the transport set is designed for all three
    /// generations; refused at validation because
    /// nothing in this release supervises a child, and a config value that boots into an
    /// unimplemented path is a deployment that fails at first dispatch instead of at boot.
    Stdio,
}

/// The top-level `tools:` map, carrying [`RESERVED_TOOLS_SECTION_KEYS`] alongside the servers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ToolsCfg {
    /// The ALL-MCP attach list (the reserved `tools.hooks:` key). LIST ⇒ ADDITIVE.
    pub(crate) all_server_hooks: Vec<String>,
    /// The ALL-MCP `upstream_credentials:` default. SCALAR ⇒ OVERRIDE.
    pub(crate) all_server_upstream_credentials: Option<crate::auth::UpstreamCreds>,
    /// The registrations. Insertion-ordered, so catalogue construction and every operator-facing
    /// listing are deterministic rather than hash-ordered.
    pub(crate) servers: indexmap::IndexMap<String, McpServerDefCfg>,
}

impl ToolsCfg {
    // The two combine rules below have NO PRODUCTION CALLER YET, and that is a statement about what
    // this release builds rather than about the rules. Hooks attach on the DISPATCH path (owner
    // ruling 2 puts them nowhere else — the catalogue is authorization, not routing) and no hook
    // runs on it yet; the effective upstream-credential MODE is read off the catalogue snapshot's
    // `UpstreamPosture` rather than through `effective_upstream_credentials`, because the snapshot is
    // what dispatch holds and reaching back into `ToolsCfg` from a request path would be a second
    // reader of the operator's intent. They are written and pinned here because the ADDITIVE-list /
    // OVERRIDE-scalar combine is a rule of the config grammar itself, and a grammar rule discovered
    // at the moment its first caller lands is a grammar rule decided by that caller.
    #![cfg_attr(not(test), allow(dead_code))]

    /// The effective hook set for one server: `tools.hooks ∪ tools.<server>.hooks`, deduped, in
    /// declaration order (`hooks` is a LIST, and a LIST combines ADDITIVELY).
    pub(crate) fn effective_hooks(&self, server: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let own = self.servers.get(server).map(|d| d.hooks.as_slice());
        for h in self.all_server_hooks.iter().chain(own.unwrap_or(&[])) {
            if !out.iter().any(|e| e == h) {
                out.push(h.clone());
            }
        }
        out
    }

    /// The effective upstream-credential mode for one server (SCALAR ⇒ OVERRIDE).
    pub(crate) fn effective_upstream_credentials(
        &self,
        server: &str,
    ) -> Option<crate::auth::UpstreamCreds> {
        self.servers
            .get(server)
            .and_then(|d| d.upstream_credentials)
            .or(self.all_server_upstream_credentials)
    }
}

impl<'de> Deserialize<'de> for ToolsCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut raw: indexmap::IndexMap<String, serde_yaml::Value> =
            indexmap::IndexMap::deserialize(deserializer)?;

        // A reserved key holding a MAPPING is somebody trying to define a server by that name.
        // Caught before the typed lifts so the message names the real problem instead of surfacing
        // as "expected a sequence".
        for reserved in RESERVED_TOOLS_SECTION_KEYS {
            if raw
                .get(*reserved)
                .is_some_and(|v| matches!(v, serde_yaml::Value::Mapping(_)))
            {
                return Err(serde::de::Error::custom(format!(
                    "an MCP server may not be named `{reserved}`: that key is RESERVED at the \
                     `tools:` section level (the all-MCP `hooks:` attach list and \
                     `upstream_credentials:` default), on every plane. Rename the server."
                )));
            }
        }

        let all_server_hooks: Vec<String> = match raw.shift_remove("hooks") {
            None => Vec::new(),
            Some(v) => Vec::<String>::deserialize(v).map_err(|e| {
                serde::de::Error::custom(format!(
                    "the reserved `tools.hooks:` all-MCP attach must be a list of hook names: {e}"
                ))
            })?,
        };
        let all_server_upstream_credentials = match raw.shift_remove("upstream_credentials") {
            None => None,
            Some(v) => Some(crate::auth::UpstreamCreds::deserialize(v).map_err(|e| {
                serde::de::Error::custom(format!(
                    "the reserved `tools.upstream_credentials:` all-MCP default must be `own` or \
                     `passthrough`: {e}"
                ))
            })?),
        };

        let mut servers = indexmap::IndexMap::new();
        for (name, value) in raw {
            if RESERVED_TOOLS_SECTION_KEYS.contains(&name.as_str()) {
                return Err(serde::de::Error::custom(format!(
                    "an MCP server may not be named `{name}`: that key is RESERVED at the `tools:` \
                     section level, on every plane. Rename the server."
                )));
            }
            let def: McpServerDefCfg =
                McpServerDefCfg::deserialize(value).map_err(serde::de::Error::custom)?;
            // The VALUE rules, run through the same function the admin write path calls, so the API
            // rejects exactly what the file rejects.
            validate_server(&name, &def).map_err(serde::de::Error::custom)?;
            servers.insert(name, def);
        }

        Ok(ToolsCfg {
            all_server_hooks,
            all_server_upstream_credentials,
            servers,
        })
    }
}

/// THE VALUE-LEVEL RULES for one `tools:` entry.
///
/// Split out as a free function on purpose: `serde` types check SHAPE, and every rule below is about
/// a VALUE that is well-typed and still wrong. Boot calls it from the `Deserialize` above and the
/// admin write path calls it from
/// [`crate::config::named_map::NamedMapSection::parse_def`], so the two paths cannot drift into
/// different grammars — the ONE GRAMMAR, TWO PATHS rule.
/// THE OPERATOR'S REFRESH CADENCE for one registration, lifted into the plane-neutral
/// [`crate::trust::reverify::Policy`] the timer consumes.
///
/// Config in, policy out, no clock and no I/O — so the cadence an operator wrote and the cadence the
/// decision uses are provably the same value rather than two parallel readings of it. Deliberately
/// the same shape as [`crate::a2a::config::policy_for`], because it feeds the same `due`.
///
/// `recovery_backoff_ms` is **zero**, and that is a stated difference from the A2A plane rather than
/// an oversight. The backoff exists to disbelieve a CLEAN answer for a while after a drift, and
/// applying it needs a `settle` step that can decline to adopt an observation. The MCP cache's
/// [`crate::mcp::client::catalogue::ServerCatalogue::observe`] has no such arm — it adopts what it
/// saw — so a non-zero value here would be a number that is read and then ignored, which is worse
/// than no number at all. `due` does not consult it. Giving MCP the recovery hold is real work on
/// `observe`, and it is not what A2.1 is: A2.1 is that the DEMOTION happens with nobody watching,
/// and demotion is the half that is never held on either plane.
pub(crate) fn refresh_policy_for(
    def: &McpServerDefCfg,
) -> Result<crate::trust::reverify::Policy, String> {
    let ttl = def
        .refresh_ttl
        .as_deref()
        .unwrap_or(DEFAULT_MCP_REFRESH_TTL);
    let ttl_ms = crate::admin::parse_duration_secs(ttl)?.saturating_mul(1_000);
    Ok(crate::trust::reverify::Policy {
        ttl_ms,
        recovery_backoff_ms: 0,
    })
}

pub(crate) fn validate_server(name: &str, def: &McpServerDefCfg) -> Result<(), String> {
    let at = format!("`tools.{name}`");

    // THE SEPARATOR RULE, and it lands on the SERVER ID ALONE. This is a real tension in the spec
    // and it is resolved here rather than worked around, so the resolution is visible:
    //
    // `{server}_{tool}` is THE ROUTING KEY, and the locked config example writes
    // `tools_allow: { read_file: {} }` — a tool name containing the separator. Both cannot hold with
    // an unambiguous key unless one of the two halves is separator-free, and the spec constrains
    // neither. Constraining the SERVER ID is the choice that costs nothing and buys everything: a
    // server id is an operator-chosen registry label with no upstream to satisfy, so renaming
    // `my_server` to `my-server` is free — whereas a TOOL name is chosen by somebody else's server
    // and refusing `read_file` would make busbar unable to front the very example the grammar
    // ships.
    //
    // With the server id separator-free, `{server}_{tool}` splits at the FIRST separator and splits
    // exactly one way. Without the rule, `a_b` + `c` and `a` + `b_c` render the same string, and one
    // `mcp_tool` grant silently names two different (server, tool) pairs.
    if name.contains(NAMESPACE_SEP) {
        return Err(format!(
            "{at}: an MCP server id may not contain `{NAMESPACE_SEP}`. The id is the first half of \
             the `{{server}}{NAMESPACE_SEP}{{tool}}` namespaced routing key; with a \
             separator inside it, two different (server, tool) pairs render the SAME key and one \
             `mcp_tool` scope grant silently names both. Tool names may contain `{NAMESPACE_SEP}` \
             (the canonical `read_file` does) — only the id may not. Rename the server, e.g. \
             `{}`.",
            name.replace(NAMESPACE_SEP, "-")
        ));
    }

    if def.url.trim().is_empty() {
        return Err(format!("{at}: `url:` must name the MCP server's endpoint"));
    }
    // Scheme is checked here rather than at dispatch so the failure lands on the operator who wrote
    // it, at boot, rather than on a tool call an hour later.
    if !(def.url.starts_with("https://") || def.url.starts_with("http://")) {
        return Err(format!(
            "{at}: `url:` must be an http:// or https:// endpoint, got `{}`",
            def.url
        ));
    }

    // THE PIN, matched against the material its mechanism needs. This is the rule the object form
    // exists to make expressible.
    let has_key = def.pin.key.as_deref().is_some_and(|k| !k.trim().is_empty());
    if def.pin.mechanism.needs_key() && !has_key {
        return Err(format!(
            "{at}: `pin.mechanism: {}` needs `pin.key:` — the out-of-band material this \
             registration is verified against. A pin with nothing to verify with is not a pin.",
            def.pin.mechanism.token()
        ));
    }
    if !def.pin.mechanism.needs_key() && has_key {
        return Err(format!(
            "{at}: `pin.mechanism: unpinned` must not carry `pin.key:`. `unpinned` means there is \
             no authenticity root; key material that is never verified against reads to an operator \
             as protection that does not exist. Name the real mechanism, or drop the key."
        ));
    }

    // The cadence is parsed at BOOT, so a malformed `refresh_ttl:` lands on the operator who wrote
    // it rather than silently falling back to a default six hours later — a defence that quietly
    // uses a cadence the operator did not write is a defence whose behaviour nobody can predict.
    if let Some(ttl) = def.refresh_ttl.as_deref() {
        crate::admin::parse_duration_secs(ttl).map_err(|e| format!("{at}: `refresh_ttl:` {e}"))?;
    }

    if matches!(def.transport, Some(Transport::Stdio)) {
        return Err(format!(
            "{at}: `transport: stdio` is not implemented in this release. The stdio child \
             supervision state machine is net-new engine surface and nothing in this build \
             spawns or reaps a child, so a deployment that booted with it would fail at first \
             dispatch instead of here. Use `transport: streamable_http`."
        ));
    }

    for (tool, allow) in &def.tools_allow {
        validate_capability_name(&at, "tools_allow", tool)?;
        // A task-scoped ask on a tool that never creates a task has no task to be asked inside of,
        // so it would be silently unreachable: the caller would get a plain result and never see
        // the confirmation gate the operator wrote. Refused at boot, where the operator is, rather
        // than at a dispatch an hour later that simply does not ask.
        if !allow.task_ask_caller.is_empty() && allow.task_support.is_none() {
            return Err(format!(
                "{at}: `tools_allow.{tool}.task_ask_caller:` is the input busbar asks its caller for \
                 from INSIDE a task, and `task_support:` is absent or `none`, so this tool never \
                 creates one. The ask would never be emitted. Set `task_support: optional` (or \
                 `required`), or move the rounds to `ask_caller:` for the synchronous exchange."
            ));
        }
        // THE SHAPE of an override, not its uniqueness — uniqueness needs every OTHER server and is
        // therefore `validate_published_names`, which runs where the whole registry is in hand. A
        // blank or whitespace-padded wire name is refused here because it is wrong on its own
        // without reference to anything else: `tools/list` would publish a name no client can type
        // back, and `mcp_tool:` would grant on it.
        if let Some(publish_as) = &allow.publish_as {
            if publish_as.trim().is_empty() {
                return Err(format!(
                    "{at}: `tools_allow.{tool}.publish_as:` is empty. It is the wire name busbar \
                     publishes for this tool and the value an `mcp_tool:` grant names; an empty one \
                     can be neither called nor granted. Give it a name, or drop the key to publish \
                     the default `{name}{NAMESPACE_SEP}{tool}`."
                ));
            }
            if publish_as.trim() != publish_as.as_str() {
                return Err(format!(
                    "{at}: `tools_allow.{tool}.publish_as: {publish_as:?}` has leading or trailing \
                     whitespace. The published name is compared byte-for-byte against a caller's \
                     `tools/call` name and against an `mcp_tool:` grant, so padding that an operator \
                     cannot see would make both silently miss. Write it without the spaces."
                ));
            }
        }
    }
    for (prompt, allow) in &def.prompts_allow {
        validate_capability_name(&at, "prompts_allow", prompt)?;
        validate_prompt(&at, prompt, allow)?;
    }
    for (uri, allow) in &def.resources_allow {
        if uri.trim().is_empty() {
            return Err(format!("{at}: `resources_allow:` has an empty URI key"));
        }
        // THE TWO FORMS ARE ALTERNATIVES. See `ResourceAllowCfg::blob`.
        if allow.text.is_some() && allow.blob.is_some() {
            return Err(format!(
                "{at}: `resources_allow.{uri}` declares both `text:` and `blob:`. Those are the two \
                 ALTERNATIVE forms of one resource's contents, and a server that carried both would \
                 be leaving a client to choose which of the operator's two answers to believe. Keep \
                 one."
            ));
        }
        if let Some(blob) = &allow.blob {
            validate_base64(&at, &format!("resources_allow.{uri}.blob"), blob)?;
        }
    }
    for (template, allow) in &def.resource_templates_allow {
        validate_uri_template(&at, template)?;
        // A template whose CONTENT names no parameter is a template that answers the same bytes for
        // every expansion, which is a concrete resource with a wildcard in front of it. Refused,
        // because the wildcard is then an approval of a whole URI shape bought for nothing.
        if let Some(text) = &allow.text {
            let names = template_parameter_names(template);
            if !names.iter().any(|n| text.contains(&format!("{{{n}}}"))) {
                return Err(format!(
                    "{at}: `resource_templates_allow.{template}` has `text:` that substitutes none \
                     of its parameters ({names:?}), so every expansion answers identical bytes. That \
                     is a concrete resource behind a URI wildcard, and the wildcard approves a whole \
                     shape for no benefit — declare it in `resources_allow:` instead, or use the \
                     parameter."
                ));
            }
        }
    }

    if let Some(tx) = &def.token_exchange {
        // The same scheme rule the `url:` gets, and for a stronger reason: this endpoint receives
        // busbar's OWN subject token, so plaintext to a public host would put busbar's ambient
        // credential on the wire in the clear. Private/loopback is exempted only where the operator
        // has said this deployment's estate is internal.
        let private_ok = def.allow_private && tx.token_url.starts_with("http://");
        if !(tx.token_url.starts_with("https://") || private_ok) {
            return Err(format!(
                "{at}: `token_exchange.token_url:` must be https (it receives busbar's own subject \
                 token); plaintext http is permitted only on a registration that also sets \
                 `allow_private: true`. Got `{}`.",
                tx.token_url
            ));
        }
        // An exchange mints BUSBAR's credential. `passthrough` says the CALLER supplies the
        // credential. Configuring both is an operator asking for two different answers to one
        // question, and silently preferring either is how a deputy is created.
        if matches!(
            def.upstream_credentials,
            Some(crate::auth::UpstreamCreds::Passthrough)
        ) {
            return Err(format!(
                "{at}: `token_exchange:` mints BUSBAR's own down-scoped credential, and \
                 `upstream_credentials: passthrough` says the CALLER supplies one. Set one or the \
                 other."
            ));
        }
        // RFC 8707 is not optional on an exchange: without a resource indicator the issued token is
        // spendable at any backend the AS serves, which is the audience-confusion the exchange
        // exists to prevent.
        if def.aud.is_none() {
            return Err(format!(
                "{at}: `token_exchange:` requires `aud:` — the RFC 8707 resource indicator the \
                 exchanged token is audience-bound to. A token minted for one upstream must not be \
                 spendable at another."
            ));
        }
    }

    if let Some(aud) = def.aud.as_deref() {
        if !(aud.starts_with("https://") || aud.starts_with("http://")) {
            return Err(format!(
                "{at}: `aud:` is an RFC 8707 resource indicator and must be an absolute http(s) \
                 URI, got `{aud}`"
            ));
        }
    }

    for hook in &def.hooks {
        refuse_cross_plane_reference(&at, hook)?;
    }
    Ok(())
}

/// Where a published wire name CAME FROM, so a collision error can name both sides the way the
/// operator will have to fix them: one of them is a line they typed, the other may be a name nobody
/// typed at all.
struct PublishedName {
    server: String,
    tool: String,
    /// `true` when the name came from `publish_as:`, `false` when it is the `{server}_{tool}`
    /// default. Carried rather than re-derived, because re-deriving means comparing the name to
    /// `namespaced(server, tool)` and getting the wrong answer for the one config where it matters:
    /// `publish_as:` set to exactly the default.
    overridden: bool,
}

impl PublishedName {
    /// The half of the error message that describes ONE claimant.
    fn describe(&self) -> String {
        let Self {
            server,
            tool,
            overridden,
        } = self;
        if *overridden {
            format!("`tools.{server}.tools_allow.{tool}.publish_as:`")
        } else {
            format!(
                "the default `{{server}}{NAMESPACE_SEP}{{tool}}` name of \
                 `tools.{server}.tools_allow.{tool}`"
            )
        }
    }
}

/// THE UNIQUENESS INVARIANT, once, over the WHOLE registry: one published wire name resolves to
/// exactly one `(server, tool)`.
///
/// This is the validation that replaces the guarantee `{server}_{tool}` used to give by
/// construction, so it has to be TOTAL in both directions or it is not a replacement:
///
/// 1. It walks EVERY tool of EVERY server, building each one's published name — the `publish_as:`
///    override where there is one, the namespaced default where there is not.
/// 2. It compares against that whole set. **Not overrides against each other.** The collision that
///    a naive check misses is an override against a DEFAULT: `publish_as: foo_bar` on any server
///    collides with server `foo`'s tool `bar`, and nobody typed `foo_bar` on the `foo` side for the
///    naive check to compare it with. An implementation that only compared overrides to overrides
///    would accept that config and look correct doing it.
///
/// A collision is refused rather than resolved. Resolving it — last-writer-wins, or an automatic
/// suffix — would leave one wire name pointing at a `(server, tool)` the operator did not choose,
/// and because [`crate::mcp::catalogue`] keys the `mcp_tool` grant on the published name, that
/// silently moves an authorization decision. A boot refusal an operator reads is strictly better
/// than a dispatch an hour later that reaches the wrong upstream.
///
/// Called from [`crate::config::resolve`], which is the ONE point every path converges on: boot,
/// `busbar --validate`, the admin config-apply rebuild and the admin dry-run validate endpoint all
/// run it over the EFFECTIVE registry (file base + applied overlay). Deliberately NOT called from
/// `ToolsCfg`'s `Deserialize`: that sees only the file, so a server added through the API would
/// never be compared against it — a check that looked total and was not.
pub(crate) fn validate_published_names(cfg: &ToolsCfg) -> Result<(), String> {
    let mut published: std::collections::BTreeMap<String, PublishedName> =
        std::collections::BTreeMap::new();
    for (server, def) in &cfg.servers {
        for (tool, allow) in &def.tools_allow {
            // THE SAME TWO LINES `Catalogue::build` runs, through the SAME function, and that is
            // load-bearing rather than tidy: this check is only meaningful if the set it walks is
            // byte-identical to the set that is published. A second local `{server}_{tool}` formula
            // here would validate one set and publish another the day either changed.
            let overridden = allow.publish_as.is_some();
            let name = allow
                .publish_as
                .clone()
                .unwrap_or_else(|| super::catalogue::namespaced(server, tool));
            let claim = PublishedName {
                server: server.clone(),
                tool: tool.clone(),
                overridden,
            };
            if let Some(prior) = published.get(&name) {
                return Err(format!(
                    "`tools`: two tools would both be published as `{name}` — {} and {}. A \
                     published name is the wire name `tools/list` emits, the name `tools/call` \
                     dispatches on, AND the value an `mcp_tool:` grant names, so one name meaning \
                     two (server, tool) pairs would make one grant silently authorize both. busbar \
                     refuses to boot rather than pick one. Change one `publish_as:`, or remove it \
                     to publish the `{{server}}{NAMESPACE_SEP}{{tool}}` default.",
                    prior.describe(),
                    claim.describe(),
                ));
            }
            published.insert(name, claim);
        }
    }
    Ok(())
}

/// A capability name must be non-empty. It MAY contain the namespace separator, and that is a
/// deliberate asymmetry with the server id — see [`validate_server`] for the arithmetic.
fn validate_capability_name(at: &str, field: &str, name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err(format!("{at}: `{field}:` has an empty name key"));
    }
    Ok(())
}

/// The VALUE rules for one `prompts_allow` entry: one form, a legal role, and decodable media.
fn validate_prompt(at: &str, name: &str, allow: &PromptAllowCfg) -> Result<(), String> {
    if allow.template.is_some() && !allow.messages.is_empty() {
        return Err(format!(
            "{at}: `prompts_allow.{name}` declares both `template:` and `messages:`. Those are the \
             two ALTERNATIVE spellings of what one prompt says — `template:` is the single-text \
             form, `messages:` is the typed form — and honouring one silently would make the answer \
             depend on which branch runs first. Keep one."
        ));
    }
    for (i, message) in allow.messages.iter().enumerate() {
        // The schema names exactly two roles. An unrecognised one is refused rather than passed
        // through: a client that does not know the role has no way to place the message, and a
        // message with no place in a conversation is a message a model reads in the wrong voice.
        if !matches!(message.role.as_str(), "user" | "assistant") {
            return Err(format!(
                "{at}: `prompts_allow.{name}.messages[{i}].role` is `{}`; a PromptMessage role is \
                 `user` or `assistant`.",
                message.role
            ));
        }
        let field = format!("prompts_allow.{name}.messages[{i}]");
        match &message.content {
            PromptContentCfg::Text { .. } => {}
            PromptContentCfg::Image { data, .. } | PromptContentCfg::Audio { data, .. } => {
                validate_base64(at, &format!("{field}.data"), data)?;
            }
            PromptContentCfg::Resource { resource } => {
                if resource.uri.trim().is_empty() {
                    return Err(format!("{at}: `{field}.resource.uri` must not be empty"));
                }
                if resource.text.is_some() && resource.blob.is_some() {
                    return Err(format!(
                        "{at}: `{field}.resource` declares both `text:` and `blob:`; those are the \
                         two alternative forms of one resource's contents. Keep one."
                    ));
                }
                if let Some(blob) = &resource.blob {
                    validate_base64(at, &format!("{field}.resource.blob"), blob)?;
                }
            }
        }
    }
    Ok(())
}

/// A base64 value that does not decode is refused HERE, at boot, on the operator who typed it.
///
/// The alternative is a client receiving bytes it cannot decode, which surfaces hours later, in
/// somebody else's log, as "busbar sent me rubbish".
fn validate_base64(at: &str, field: &str, value: &str) -> Result<(), String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| {
            format!(
                "{at}: `{field}` is not valid standard base64 ({e}). A client is told these bytes \
                 are media of a declared type; bytes that do not decode are not media."
            )
        })?;
    Ok(())
}

/// THE URI-TEMPLATE RULES, and they are deliberately narrow.
///
/// Only RFC 6570 LEVEL 1 — `{name}`, simple string expansion — is accepted. The higher levels add
/// operators (`{+var}` reserved expansion, `{#var}` fragments, `{/var}` path segments, `{?var}` form
/// parameters) whose expansions and, crucially, whose MATCHING rules differ from one another. A
/// matcher that accepted the syntax of level 3 while implementing the semantics of level 1 would
/// resolve some URIs to the wrong template, silently, and a resource template IS an approval — so a
/// mis-match is content served under an approval nobody gave. Refusing the syntax we do not
/// implement is the only version of this that cannot be wrong.
fn validate_uri_template(at: &str, template: &str) -> Result<(), String> {
    if template.trim().is_empty() {
        return Err(format!(
            "{at}: `resource_templates_allow:` has an empty URI-template key"
        ));
    }
    let mut rest = template;
    let mut names: Vec<&str> = Vec::new();
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return Err(format!(
                "{at}: `resource_templates_allow.{template}` has a `{{` with no matching `}}`"
            ));
        };
        let name = &after[..close];
        if name.is_empty() {
            return Err(format!(
                "{at}: `resource_templates_allow.{template}` has an empty `{{}}` parameter"
            ));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        {
            return Err(format!(
                "{at}: `resource_templates_allow.{template}` uses `{{{name}}}`, which is not an RFC \
                 6570 LEVEL 1 parameter. busbar implements level 1 (simple string expansion) only: \
                 an operator (`+`, `#`, `/`, `?`, `&`, `*`) expands AND MATCHES differently, and a \
                 matcher that accepted the syntax without the semantics would resolve some URIs to \
                 the wrong template — which is content served under an approval nobody gave."
            ));
        }
        if names.contains(&name) {
            return Err(format!(
                "{at}: `resource_templates_allow.{template}` names `{{{name}}}` twice. Two \
                 occurrences of one parameter can be expanded with two different values, and this \
                 matcher would then have to decide which one the URI meant."
            ));
        }
        names.push(name);
        rest = &after[close + 1..];
    }
    if names.is_empty() {
        return Err(format!(
            "{at}: `resource_templates_allow.{template}` names no `{{parameter}}`, so it is a \
             concrete URI. Declare it in `resources_allow:`."
        ));
    }
    if rest.contains('}') {
        return Err(format!(
            "{at}: `resource_templates_allow.{template}` has a `}}` with no matching `{{`"
        ));
    }
    Ok(())
}

/// The parameter names of a template, in order. Only called on a template
/// [`validate_uri_template`] has already accepted, so the scan cannot be tricked by unbalanced
/// braces — and that ordering is why this returns a plain `Vec` rather than a `Result`.
pub(crate) fn template_parameter_names(template: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else { break };
        out.push(after[..close].to_string());
        rest = &after[close + 1..];
    }
    out
}

/// The all-MCP attach list is validated by the same rule as a per-server one.
pub(crate) fn validate_section_hooks(hooks: &[String]) -> Result<(), String> {
    for hook in hooks {
        refuse_cross_plane_reference("`tools.hooks`", hook)?;
    }
    Ok(())
}

/// REFUSE, rather than ignore, a reference that reaches onto another plane.
///
/// A hook reference is a bare name into the one top-level `hooks:` map. Dropping a dotted one
/// silently would leave an operator believing a control is attached that is not, which is worse than
/// the typo.
fn refuse_cross_plane_reference(at: &str, hook: &str) -> Result<(), String> {
    let hook = hook.trim();
    if hook.is_empty() {
        return Err(format!("{at}: `hooks:` contains an empty name"));
    }
    for plane in ["pools", "tools", "agents", "export", "identity-providers"] {
        if let Some(rest) = hook.strip_prefix(&format!("{plane}.")) {
            return Err(format!(
                "{at}: `hooks:` may only name hooks from the top-level `hooks:` map, by bare name. \
                 `{hook}` reaches onto the `{plane}:` plane, and no entry on one plane may \
                 reference an entry on another. Did you mean the hook `{rest}`?"
            ));
        }
    }
    if hook.contains('.') {
        return Err(format!(
            "{at}: `hooks:` may only name hooks from the top-level `hooks:` map, by bare name. \
             `{hook}` is not a bare name."
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/tools_config_tests.rs"]
mod tools_config_tests;

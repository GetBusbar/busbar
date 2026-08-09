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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PinMechanism {
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

impl PinMechanism {
    /// Does this mechanism require operator-supplied key material? Three of the four are meaningless
    /// without it, and the fourth is meaningless with it — which is the rule the object form exists
    /// to make expressible.
    fn needs_key(self) -> bool {
        !matches!(self, PinMechanism::Unpinned)
    }

    /// The config token, for diagnostics. Deliberately the same string `serde` accepts.
    pub(crate) fn token(self) -> &'static str {
        match self {
            PinMechanism::PinnedPubkey => "pinned_pubkey",
            PinMechanism::CertSpki => "cert_spki",
            PinMechanism::Mtls => "mtls",
            PinMechanism::Unpinned => "unpinned",
        }
    }
}

/// `tools.<server>.pin` — the out-of-band operator-supplied trust root.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerPinCfg {
    /// Which root this is. REQUIRED: a pin whose mechanism is inferred is a pin whose meaning
    /// changes when the code that infers it changes.
    pub(crate) mechanism: PinMechanism,
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
    /// The input BUSBAR asks its own caller for before it dispatches this tool. ABSENT ⇒ no ask,
    /// which is deny-by-default and is every deployment that has not opted in. See [`AskEntryCfg`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) ask_caller: Vec<AskRoundCfg>,
}

/// `tools.<server>.prompts_allow.<name>` — one exposed prompt, markup-normalised on the way out.
///
/// The locked core keys name only `tools_allow`; prompts and resources belong to the MCP-SPECIFIC
/// superset an operator "may also set per entry". They take the same MAP shape as `tools_allow` for
/// the same reason: a capability needs a slot for what the operator approved about it.
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
    /// The approved tools, as a MAP so each carries its approved schema hash.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    pub(crate) tools_allow: indexmap::IndexMap<String, ToolAllowCfg>,
    /// The exposed prompts — MCP-specific superset, not one of the locked core keys.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    pub(crate) prompts_allow: indexmap::IndexMap<String, PromptAllowCfg>,
    /// The exposed resources, keyed by URI — MCP-specific superset, likewise.
    #[serde(default, skip_serializing_if = "indexmap::IndexMap::is_empty")]
    pub(crate) resources_allow: indexmap::IndexMap<String, ResourceAllowCfg>,
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

    if matches!(def.transport, Some(Transport::Stdio)) {
        return Err(format!(
            "{at}: `transport: stdio` is not implemented in this release. The stdio child \
             supervision state machine is net-new engine surface and nothing in this build \
             spawns or reaps a child, so a deployment that booted with it would fail at first \
             dispatch instead of here. Use `transport: streamable_http`."
        ));
    }

    for tool in def.tools_allow.keys() {
        validate_capability_name(&at, "tools_allow", tool)?;
    }
    for prompt in def.prompts_allow.keys() {
        validate_capability_name(&at, "prompts_allow", prompt)?;
    }
    for uri in def.resources_allow.keys() {
        if uri.trim().is_empty() {
            return Err(format!("{at}: `resources_allow:` has an empty URI key"));
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

/// A capability name must be non-empty. It MAY contain the namespace separator, and that is a
/// deliberate asymmetry with the server id — see [`validate_server`] for the arithmetic.
fn validate_capability_name(at: &str, field: &str, name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err(format!("{at}: `{field}:` has an empty name key"));
    }
    Ok(())
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

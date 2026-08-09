// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JSON-RPC METHOD SURFACE — the CATALOGUE and the DISPATCH (owner ruling 4's vocabulary).
//!
//! The envelope is already settled by the time anything here runs: `ingress` has enforced `Origin`,
//! the mirrored headers, the protocol version and the JSON-RPC shape, and the auth middleware has
//! verified that the token's audience is this deployment. What is left is the two questions this
//! module answers.
//!
//! ## CATALOGUE — what a caller can SEE
//!
//! Owner ruling 2 (LOCKED): AUTHORIZATION, decided by the caller's key scopes, and by nothing else.
//! `mcp_server` and `mcp_tool` `ScopeRef` grants, checked through `scope_allowed`. No hook on the
//! catalogue path, no filter verb, no tags. Two callers with two different grants see two different
//! catalogues, and a caller with a grant that reaches nothing sees an empty one — not an error, an
//! EMPTY LIST, because "you may see nothing here" is a complete and correct catalogue.
//!
//! ## DISPATCH — what a caller can DO
//!
//! Ordered so that every refusal happens before anything is charged and before anything is
//! dispatched — validated before it is audited, and validated AGAIN at the moment of dispatch:
//!
//! 1. Resolve the namespaced name to a BOUND IDENTITY under the caller's grant, on the snapshot the
//!    request arrived on. Note the generation.
//! 2. Re-read the LIVE snapshot and re-validate against it. A call whose identity resolved under
//!    pin generation N is refused when the live generation is N+1. On a protocol with sessions this
//!    would be the backstop behind tombstoning the sessions a de-approved server was still being
//!    served over; on a stateless one there are no sessions to tombstone, so the per-request
//!    generation check is the whole of the defence — and the only part that was ever needed.
//! 3. Drive the input-required loop — bounded, metered, and re-gated on every round — charging the
//!    caller's own budget before each round, because an upstream that can ask for input forever is
//!    an upstream that can amplify cost forever.
//! 4. Audit the outcome — the VALIDATED decision, never a rejected call recorded as a successful
//!    route.
//!
//! ## THE UPSTREAM LEG, and the gate that sits in front of it
//!
//! Step 3's round trip is [`super::upstream::call`] — the real CLIENT direction: SSRF-checked,
//! address-pinned, connection-pooled, and carrying a credential minted for THIS backend. Before the
//! loop is entered at all, [`super::upstream::authorise`] binds outbound credential selection to the
//! INBOUND principal's grant. That call is synchronous and reaches nothing, which is the
//! ordering that matters: a caller whose grant does not cover this tool is refused without busbar
//! making a token-exchange round trip on its own authorization server.
//!
//! Two refusals therefore exist and they are deliberately DISTINGUISHABLE, because "it was refused"
//! proves nothing about which check refused it: `not_granted` lands at admission, BEFORE the
//! upstream; `egress_denied` lands at the credential gate; `upstream_failed` lands AFTER everything
//! else has passed. Each is a different audit word and a different operator remedy.

use axum::http::StatusCode;
use axum::response::Response;

use super::callerask::{self, AskDecision, Bind, Retry};
use super::catalogue::{DispatchRefusal, ToolEntry};
use super::client::catalogue::LiveSightings;
use super::inputreq::{self, Outcome, Refusal, RoundRecord};
use super::sanitize;

/// The methods this server implements. A method absent from here takes the ingress `-32601` / `404`
/// arm, which stays the correct answer for anything still unimplemented.
///
/// Exposed as a slice so `server/discover` advertises exactly what dispatch accepts: two lists that
/// can disagree is a client told it may call something it may not.
pub(crate) const IMPLEMENTED_METHODS: &[&str] = &[
    "server/discover",
    "tools/list",
    "tools/call",
    "prompts/list",
    "prompts/get",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "completion/complete",
];

/// `resultType` on every result this server returns: `complete`, never `input_required`.
///
/// This is an INVARIANT of the dispatch design, not a default. An upstream's `input_required` ask
/// TERMINATES at busbar — [`super::inputreq`] either satisfies it under the caller's grant or
/// refuses the call — so the caller is never handed a half-finished result to answer. There is
/// therefore no code path on which busbar has an incomplete result to describe, and the one place
/// that stamps this ([`result`]) is the one place that would have to change if that ever stopped
/// being true.
const RESULT_TYPE_COMPLETE: &str = "complete";

/// The one other `resultType` this server returns, and it is returned ONLY by
/// [`input_required_result`], only for an ask busbar itself composed from operator configuration.
/// An upstream's `input_required` never reaches this constant — see [`super::inputreq`].
const RESULT_TYPE_INPUT_REQUIRED: &str = "input_required";

/// `cacheScope` on every cacheable result: `private`, and it is the only value that is TRUE here,
/// not a cautious default.
///
/// Every answer this module computes is scoped to the CALLER'S GRANT (owner ruling 2): two callers
/// holding two different grants get two different catalogues from the same deployment, from the
/// same registry, at the same instant. `public` means precisely "any client or intermediary MAY
/// cache this and serve it ACROSS authorization contexts" — which for this server would mean a
/// shared proxy serving one caller's authorized catalogue to a caller who holds none of it. That is
/// the grant boundary being crossed by a cache, and a cache is not a place where authorization is
/// re-checked. So `private`, on every result, including the ones that happen to be empty today: a
/// value that is only correct while the registry is empty is a value that becomes wrong silently.
const CACHE_SCOPE: &str = "private";

/// `ttlMs` on every cacheable result: `0` — "consider this immediately stale; re-fetch when you
/// need it".
///
/// A POSITIVE ttl is a promise that the answer will still be true for that long, and this server
/// cannot make it. The registry is versioned and the operator can move it at any moment: an
/// approval revoked, a pin bumped, a rug-pull quarantine landing between two requests. There is
/// also no channel to correct a stale cache with — `listChanged` is advertised `false` because this
/// revision is stateless and there is no stream to notify over — so a client that cached for a
/// minute would keep OFFERING a de-approved tool for a minute. Dispatch would still refuse the
/// call it produced (the generation re-check is per request and does not consult any cache), so the
/// cost is a confusing refusal rather than an unauthorized call. That is exactly why the honest
/// answer is `0` and not a comfortable-looking `60000`: a cache hint that lies is worse than none,
/// and `0` is not the absence of a hint — it is the schema's own way of stating "no freshness
/// window", which is the true statement about a catalogue with no invalidation channel.
const CACHE_TTL_MS: i64 = 0;

/// Everything a method needs, gathered once so no handler reaches for a global.
pub(crate) struct Ctx<'a> {
    /// The snapshot this REQUEST arrived on. Selection reads it.
    pub(crate) app: &'a std::sync::Arc<crate::state::App>,
    /// The LIVE handle. Dispatch re-reads it, which is what makes the generation check a real
    /// re-read rather than a comparison of a value against itself.
    pub(crate) handle: &'a std::sync::Arc<crate::state::AppHandle>,
    /// The caller's resolved governance key. `None` when governance is disabled.
    pub(crate) gov: &'a crate::governance::GovCtx,
    /// The attributed principal, for the audit row.
    pub(crate) actor: &'a str,
    /// The CALLER'S DECLARED CAPABILITIES, exactly as they arrived in
    /// `params._meta['io.modelcontextprotocol/clientCapabilities']`.
    ///
    /// Bound at ingress, where the whole envelope is settled, and carried rather than re-read, so
    /// every handler decides against the same declaration this request actually made.
    /// `mrtr.mdx:246` forbids sending an ask the caller has not declared support for; this is the
    /// only thing that could tell busbar what those are.
    pub(crate) capabilities: &'a serde_json::Value,
}

impl Ctx<'_> {
    /// THE GRANT PREDICATE. One closure, built once, passed to every catalogue read, so the
    /// catalogue a caller sees and the tools it may dispatch are decided by the same function.
    ///
    /// A `None` key means governance is DISABLED for this deployment, and the answer is then "all
    /// scopes" — the same posture `pool_allowed` takes on the LLM plane for the same reason. That is
    /// not a fail-open on the MCP plane specifically: with governance off there is no key to carry a
    /// grant, and refusing everything would make an ungoverned deployment unable to serve at all.
    /// The deployment's signing secret, or `None`. Read through `Ctx` so the two call sites reach it
    /// the same way and neither reaches for a global.
    fn gov_signing_secret(&self) -> Option<[u8; 32]> {
        self.app
            .governance
            .as_ref()
            .and_then(|g| g.signing_secret())
    }

    fn grant(&self) -> impl Fn(&str, &str) -> bool + '_ {
        move |kind: &str, value: &str| {
            self.gov
                .key
                .as_ref()
                .is_none_or(|k| k.scope_allowed(kind, value))
        }
    }
}

/// DISPATCH one JSON-RPC method. `None` means "not implemented", which ingress renders as `404` +
/// `-32601`.
pub(crate) async fn dispatch(
    ctx: &Ctx<'_>,
    method: &str,
    params: Option<&serde_json::Value>,
    id: Option<serde_json::Value>,
) -> Option<Response> {
    match method {
        "server/discover" => Some(discover(ctx, id)),
        "tools/list" => Some(tools_list(ctx, id)),
        "tools/call" => Some(tools_call(ctx, params, id).await),
        "prompts/list" => Some(prompts_list(ctx, id)),
        "prompts/get" => Some(prompts_get(ctx, params, id)),
        "resources/list" => Some(resources_list(ctx, id)),
        "resources/templates/list" => Some(resources_templates_list(id)),
        "resources/read" => Some(resources_read(ctx, params, id)),
        "completion/complete" => Some(completion_complete(id)),
        _ => None,
    }
}

/// `completion/complete` — argument autocompletion, which for this server is always the EMPTY set.
///
/// The method is implemented and answers correctly; what it has to answer WITH is nothing, and that
/// is a fact about the registry rather than a stub. A completion is a set of candidate VALUES for a
/// named argument, and the only place busbar could get one is an operator declaring it: a prompt is
/// registered with a description and a template (`prompts_allow`), and neither states a value set.
/// There is nothing to proxy either — a completion is answered from the catalogue busbar itself
/// serves, and asking an upstream would be asking it to complete an argument of a prompt busbar
/// composed.
///
/// So the honest answer is `values: []` with `hasMore: false` and `total: 0`: not "I failed", not "I
/// do not implement this", but "there are no suggestions", which is a complete and correct answer
/// and is the same shape as the empty catalogue a caller whose grant reaches nothing receives. The
/// refs are deliberately NOT validated against the catalogue: a completion request that named a
/// prompt the caller may not see would otherwise get a different answer from one that named a
/// prompt that does not exist, and the difference is a probe for what is behind the grant.
///
/// This does NOT dispatch, charge or audit, and it takes no `Ctx`: it reads nothing the caller's
/// grant scopes, so there is nothing for a grant to narrow and nothing for an audit row to name.
fn completion_complete(id: Option<serde_json::Value>) -> Response {
    result(
        id,
        serde_json::json!({
            "completion": { "values": [], "hasMore": false, "total": 0 },
        }),
    )
}

/// Add the SEP-2549 caching hints to a result that is CACHEABLE. See [`CACHE_SCOPE`] and
/// [`CACHE_TTL_MS`] for the two values and why they are those values.
///
/// One function so the pair cannot drift apart across the six cacheable results, for the same
/// reason [`super::ingress::error_response`] is one function for the status/code pair: a hint that
/// says "private" in one place and "public" in another is a hint no client can act on.
fn cache_hints(value: serde_json::Value) -> serde_json::Value {
    let mut value = value;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("cacheScope".into(), CACHE_SCOPE.into());
        obj.insert("ttlMs".into(), CACHE_TTL_MS.into());
    }
    value
}

/// `server/discover` — the MERGED, GRANT-SCOPED catalogue advertisement.
///
/// Under `2026-07-28` there is no `initialize`, so this is the only capability advertisement there
/// is, and the rule that governs every other check under on-demand negotiation governs this one:
/// it is computed PER REQUEST from the caller's own grant, never once and then cached. Two callers
/// discover two different servers. That is the point — a discovery document that described the
/// deployment rather than the caller would enumerate every registered upstream to anyone who asked,
/// which is a map of the operator's internal estate handed out for the price of one token.
///
/// The counts are of what THIS caller can reach, and the `servers` list names only servers this
/// caller holds at least one capability on.
fn discover(ctx: &Ctx<'_>, id: Option<serde_json::Value>) -> Response {
    let cat = &ctx.app.mcp_catalogue;
    let grant = ctx.grant();
    let tools = cat.tools_for(&grant);
    let prompts = cat.prompts_for(&grant);
    let resources = cat.resources_for(&grant);
    let mut servers: Vec<&str> = tools
        .iter()
        .map(|t| t.server.as_str())
        .chain(prompts.iter().map(|p| p.server.as_str()))
        .chain(resources.iter().map(|r| r.server.as_str()))
        .collect();
    servers.sort_unstable();
    servers.dedup();

    result(
        id,
        cache_hints(serde_json::json!({
            "protocolVersion": super::ingress::PROTOCOL_VERSION,
            // The versions this server will ACCEPT, which is the mandatory field of a
            // `DiscoverResult` and is not the same statement as `protocolVersion` above (that one
            // names the revision this answer is written in). It is the SAME constant the ingress
            // refuses an unsupported version against, and it is that constant rather than a copy
            // for a reason the conformance suite checks directly: it correlates the `data.supported`
            // list on an `UnsupportedProtocolVersionError` against this list, so two lists that
            // could disagree would be a client told to retry with a version it will be refused for.
            "supportedVersions": super::ingress::SUPPORTED_PROTOCOL_VERSIONS,
            "serverInfo": { "name": "busbar", "version": env!("CARGO_PKG_VERSION") },
            // Advertised as present only when this caller can actually reach one. A capability
            // advertised to a caller who holds nothing under it is an invitation to a refusal.
            "capabilities": {
                "tools": { "listChanged": false },
                "prompts": { "listChanged": false },
                "resources": { "listChanged": false, "subscribe": false },
                // Present because `completion/complete` is IMPLEMENTED and answers correctly, which
                // is what the capability declares. It is not a claim that this deployment has
                // suggestions to give — see `completion_complete` for why the answer is the empty
                // set and why that is a complete answer rather than a stub.
                "completions": {},
            },
            "methods": IMPLEMENTED_METHODS,
            "servers": servers,
            "counts": {
                "tools": tools.len(),
                "prompts": prompts.len(),
                "resources": resources.len(),
            },
            // Honest, and deliberately advertised: an MCP deployment with an empty registry answers
            // every catalogue with an empty list, and a client that cannot tell "you may see
            // nothing" from "there is nothing" will retry for ever.
            "registryEmpty": cat.is_empty(),
        })),
    )
}

/// `tools/list` — the GOVERNANCE-SCOPED catalogue.
fn tools_list(ctx: &Ctx<'_>, id: Option<serde_json::Value>) -> Response {
    let grant = ctx.grant();
    let tools: Vec<serde_json::Value> = ctx
        .app
        .mcp_catalogue
        .tools_for(&grant)
        .into_iter()
        .map(render_tool)
        .collect();
    result(id, cache_hints(serde_json::json!({ "tools": tools })))
}

/// One catalogue entry as the wire carries it. The description is MARKUP-NORMALISED here: this is
/// the moment it is shown or fed as context, and that moment is exactly where the strip belongs.
fn render_tool(t: &ToolEntry) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    // The NAMESPACED name is the wire name, because it is the routing key — the bound identity a
    // route is decided on, never the free-text description — and the value an `mcp_tool` grant
    // carries. Exposing the bare upstream name would let two servers collide in one caller's
    // catalogue, so one server's tool would silently answer for another's.
    obj.insert("name".into(), t.namespaced.clone().into());
    if let Some(d) = sanitize::normalise_opt(t.description.as_deref()) {
        obj.insert("description".into(), d.into());
    }
    obj.insert(
        "inputSchema".into(),
        t.input_schema
            .clone()
            // A tool with no declared schema still needs a schema-shaped answer: clients reject a
            // tool whose `inputSchema` is absent, and an empty object is the honest "no constraints
            // declared" rather than a fabricated one.
            .unwrap_or_else(|| serde_json::json!({ "type": "object" })),
    );
    // The approved schema hash is published because it is the operator's approval, not a secret, and
    // a client that pins what it saw is a client that notices a rug-pull too.
    if let Some(h) = &t.schema_hash {
        obj.insert(
            "_meta".into(),
            serde_json::json!({ "io.busbar/schemaHash": h }),
        );
    }
    serde_json::Value::Object(obj)
}

/// `prompts/list`, with every description markup-normalised on the way out.
fn prompts_list(ctx: &Ctx<'_>, id: Option<serde_json::Value>) -> Response {
    let grant = ctx.grant();
    let prompts: Vec<serde_json::Value> = ctx
        .app
        .mcp_catalogue
        .prompts_for(&grant)
        .into_iter()
        .map(|p| {
            let mut obj = serde_json::Map::new();
            obj.insert("name".into(), p.namespaced.clone().into());
            if let Some(d) = sanitize::normalise_opt(p.description.as_deref()) {
                obj.insert("description".into(), d.into());
            }
            serde_json::Value::Object(obj)
        })
        .collect();
    result(id, cache_hints(serde_json::json!({ "prompts": prompts })))
}

/// Substitute `{arg}` placeholders in a prompt template from the caller's `params.arguments`.
///
/// The `{name}` spelling is the one the operator-facing templates already use; what was missing was
/// the substitution, so a client that sent arguments got the template back with its placeholders
/// intact and no indication that anything had been ignored.
///
/// TWO RULES, and both are about where the caller's text is allowed to reach.
///
/// 1. THE SUBSTITUTED TEXT IS NORMALISED, NOT THE TEMPLATE. Sanitising first and substituting after
///    would put caller-controlled bytes into a model's context having passed through no filter at
///    all — the argument value is exactly as injectable as the template it lands in, and it is more
///    attacker-controlled, because the template is the operator's and the argument is not. So this
///    function only builds the string; the single `normalise` at the call site runs over the
///    RESULT, after substitution.
/// 2. AN UNKNOWN PLACEHOLDER IS LEFT ALONE rather than emptied. `{arg1}` with no `arg1` supplied
///    stays `{arg1}`, which is visible to a human reading the output; silently substituting the
///    empty string would turn "you forgot an argument" into a prompt that reads as complete and
///    means something else.
///
/// Only string arguments substitute. A structured value has no single correct rendering into a
/// text template, and picking one (`JSON.stringify`, say) would let an argument's shape decide what
/// the prompt says.
fn substitute_arguments(template: &str, params: Option<&serde_json::Value>) -> String {
    let Some(args) = params
        .and_then(|p| p.get("arguments"))
        .and_then(|a| a.as_object())
    else {
        return template.to_string();
    };
    let mut out = template.to_string();
    for (key, value) in args {
        if let Some(text) = value.as_str() {
            out = out.replace(&format!("{{{key}}}"), text);
        }
    }
    out
}

/// `prompts/get` — the TEMPLATE, sanitized. Prompt templates are in the sanitization set
/// explicitly, because a template is exactly as injectable as tool output, and an early draft of
/// this design covered neither.
fn prompts_get(
    ctx: &Ctx<'_>,
    params: Option<&serde_json::Value>,
    id: Option<serde_json::Value>,
) -> Response {
    let Some(name) = string_param(params, "name") else {
        return invalid_params(id, "`params.name` is required and must be a string.");
    };
    let grant = ctx.grant();
    let Some(prompt) = ctx.app.mcp_catalogue.prompt_for(&grant, name) else {
        // Not-found and not-granted answer the same, deliberately: a catalogue that distinguishes
        // them tells an unauthorised caller what exists behind the grant it does not hold.
        return not_found(
            id,
            &format!("`{name}` is not a prompt this server exposes."),
        );
    };

    // THE CALLER-ASK DECISION, on the path where there is provably no other party in the exchange.
    //
    // A prompt is served ENTIRELY from the operator's config — no upstream round trip is made here
    // at all, which is why the header of `boot.sh`'s `prompts_allow` says a template "is the
    // operator's text by construction". An `InputRequiredResult` on this path therefore cannot have
    // been relayed from anywhere: there is nowhere for it to have come from.
    //
    // The arguments digest is over `params.arguments` — the values that get substituted into the
    // template — so state minted for one rendering cannot be spent on another.
    let prompt_args = params
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let cap = ctx
        .app
        .mcp_catalogue
        .server(&prompt.server)
        .map_or(0, |s| s.max_caller_ask_rounds);
    match caller_ask_decision(
        ctx,
        AskSite {
            method: "prompts/get",
            capability: &prompt.namespaced,
            rounds: &prompt.ask_caller,
            cap,
            generation: ctx.app.mcp_catalogue.generation(),
            arguments: &prompt_args,
        },
        params,
    ) {
        AskDecision::Proceed => {}
        AskDecision::Refuse(refusal) => {
            return refuse_ask(
                ctx,
                &format!("mcp_prompt:{}", prompt.namespaced),
                &refusal,
                id,
            )
        }
        AskDecision::Ask {
            asks,
            request_state,
            round,
        } => {
            let mut holds: Vec<crate::governance::AdmitGrant> = Vec::new();
            if let Err(reason) = charge_round(
                ctx,
                &prompt.namespaced,
                &RoundRecord {
                    round,
                    satisfied: None,
                },
                &mut holds,
            ) {
                return error(
                    StatusCode::TOO_MANY_REQUESTS,
                    id,
                    CODE_REFUSED,
                    &format!(
                        "this round of the input exchange for `{}` was refused by your budget: \
                         {reason}",
                        prompt.namespaced
                    ),
                    Some(serde_json::json!({ "reason": "budget_exhausted" })),
                );
            }
            crate::admin::audit::AUDIT.record_by(
                "mcp.caller_ask",
                &format!("mcp_prompt:{}", prompt.namespaced),
                crate::admin::audit::OUTCOME_APPLIED,
                ctx.actor,
            );
            return input_required_result(id, &asks, &request_state);
        }
    }
    // Substitute FIRST, normalise SECOND — see `substitute_arguments` rule 1. The caller's argument
    // values pass through the same markup strip the operator's template does.
    let text = sanitize::normalise(&substitute_arguments(
        prompt.template.as_deref().unwrap_or(""),
        params,
    ));
    result(
        id,
        serde_json::json!({
            "description": sanitize::normalise_opt(prompt.description.as_deref()),
            "messages": [{
                "role": "user",
                "content": { "type": "text", "text": text },
            }],
        }),
    )
}

/// `resources/list`, with every free-text field markup-normalised on the way out.
fn resources_list(ctx: &Ctx<'_>, id: Option<serde_json::Value>) -> Response {
    let grant = ctx.grant();
    let resources: Vec<serde_json::Value> = ctx
        .app
        .mcp_catalogue
        .resources_for(&grant)
        .into_iter()
        .map(|r| {
            let mut obj = serde_json::Map::new();
            // The NAMESPACED uri. Two registered servers may legitimately expose the same upstream
            // URI, and keying the catalogue on the raw one made the second silently replace the
            // first — a name overlap arriving through a key nobody thought of as a name.
            obj.insert("uri".into(), r.namespaced.clone().into());
            if let Some(n) = sanitize::normalise_opt(r.name.as_deref()) {
                obj.insert("name".into(), n.into());
            }
            if let Some(d) = sanitize::normalise_opt(r.description.as_deref()) {
                obj.insert("description".into(), d.into());
            }
            if let Some(m) = &r.mime_type {
                obj.insert("mimeType".into(), m.clone().into());
            }
            serde_json::Value::Object(obj)
        })
        .collect();
    result(
        id,
        cache_hints(serde_json::json!({ "resources": resources })),
    )
}

/// `resources/templates/list` — the URI-TEMPLATE catalogue, which for this server is EMPTY, and
/// says so rather than answering `-32601`.
///
/// A resource template is a parameterised URI (`file:///logs/{date}.log`) that a client expands and
/// then reads. busbar's registry has no such concept: `resources_allow:` names CONCRETE resources
/// the operator approved one at a time, by URI, and approval-by-URI is the whole basis on which a
/// resource is served at all. A template is an approval of a SHAPE — of every URI matching a
/// pattern — and granting that is a policy decision the operator has not been given a way to make,
/// so there is nothing here to enumerate and inventing one would enumerate an approval nobody gave.
///
/// The empty list is therefore the COMPLETE and correct answer, exactly as it is for a caller whose
/// grant reaches no tools, and it is a different answer from `-32601`: `-32601` says "this server
/// does not do templates and never will", which would be a claim about the roadmap, while `[]` says
/// "this deployment exposes none", which is a claim about the registry and is the one that is true.
/// It also takes no grant argument, because there is nothing to scope — an empty list is the same
/// empty list under every grant, and threading one would imply a filtering that does not happen.
fn resources_templates_list(id: Option<serde_json::Value>) -> Response {
    result(
        id,
        cache_hints(serde_json::json!({ "resourceTemplates": [] })),
    )
}

/// `resources/read` — the CONTENT, sanitized. The third injectable surface, beside tool output and
/// prompt templates, and no less injectable for arriving as "data".
fn resources_read(
    ctx: &Ctx<'_>,
    params: Option<&serde_json::Value>,
    id: Option<serde_json::Value>,
) -> Response {
    let Some(uri) = string_param(params, "uri") else {
        return invalid_params(id, "`params.uri` is required and must be a string.");
    };
    let grant = ctx.grant();
    let Some(res) = ctx.app.mcp_catalogue.resource_for(&grant, uri) else {
        return not_found(
            id,
            &format!("`{uri}` is not a resource this server exposes."),
        );
    };
    let mut content = serde_json::Map::new();
    content.insert("uri".into(), res.namespaced.clone().into());
    if let Some(m) = &res.mime_type {
        content.insert("mimeType".into(), m.clone().into());
    }
    content.insert(
        "text".into(),
        sanitize::normalise(res.text.as_deref().unwrap_or("")).into(),
    );
    result(
        id,
        cache_hints(serde_json::json!({ "contents": [serde_json::Value::Object(content)] })),
    )
}

/// `tools/call` — DISPATCH. See the module header for the ordering and why it is that ordering.
async fn tools_call(
    ctx: &Ctx<'_>,
    params: Option<&serde_json::Value>,
    id: Option<serde_json::Value>,
) -> Response {
    let Some(name) = string_param(params, "name") else {
        return invalid_params(id, "`params.name` is required and must be a string.");
    };
    let arguments = params
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    let grant = ctx.grant();
    let selected_gen = ctx.app.mcp_catalogue.generation();

    // THE LIVE TOOL-LIST SIGHTINGS as of admission. This is the right-hand side of the rug-pull
    // comparison: with one, the gate below compares the operator's approved digest against what the
    // upstream is CURRENTLY serving, so a schema changed under a live cache refuses the call.
    // Without one — no refresh has ever run — it compares against the configured hash, exactly as
    // before.
    let admitted_sightings = ctx.app.mcp_sightings.load();
    // (1) ADMISSION on the snapshot this request arrived on.
    let selected =
        match ctx
            .app
            .mcp_catalogue
            .resolve(&grant, LiveSightings::of(&admitted_sightings), name)
        {
            Ok(entry) => entry.clone(),
            Err(refusal) => return refuse(ctx, name, &refusal, id),
        };

    // (2) DISPATCH-TIME RE-VALIDATION against the LIVE snapshot. Re-read, not
    // re-use: `ctx.app` is the snapshot the request arrived on, and comparing it against itself
    // would be a check that cannot fail.
    let live = ctx.handle.load();
    // RE-READ the sightings too, not just the catalogue: a refresh that landed a drifted tool list
    // between admission and dispatch has to bite on THIS request. Re-reading only one of the two
    // would leave a window exactly as wide as the check it replaced.
    let live_sightings = live.mcp_sightings.load();
    if let Err(refusal) = live.mcp_catalogue.revalidate(
        &grant,
        LiveSightings::of(&live_sightings),
        &selected,
        selected_gen,
    ) {
        return refuse(ctx, name, &refusal, id);
    }
    let Some(server) = live.mcp_catalogue.server(&selected.server).cloned() else {
        return refuse(
            ctx,
            name,
            &DispatchRefusal::UnknownTool(name.to_string()),
            id,
        );
    };

    // (2a) THE CALLER-ASK DECISION — does busbar want something from ITS OWN CALLER before it will
    // run this at all?
    //
    // PLACED HERE, after admission and re-validation and BEFORE the egress gate, for the reason
    // step 3 gives about itself: an unsatisfied ask must cost no token exchange and no network I/O.
    // It is also after re-validation rather than before, which matters more: the generation the ask
    // is sealed under is the LIVE one, so a retry presenting state minted before an approval moved
    // is refused by the seal rather than served under the approval the operator withdrew.
    //
    // THE GRANT IS RE-CHECKED ON EVERY RETRY, and here that is free and total rather than
    // careful: each retry is a fresh inbound request, so steps 1 and 2 above have already run again
    // in full — audience, scopes, live generation, live sightings. That is a STRONGER re-check than
    // the upstream loop's per-round closure, which re-reads the registry but stays inside one
    // dispatch.
    match caller_ask_decision(
        ctx,
        AskSite {
            method: "tools/call",
            capability: &selected.namespaced,
            rounds: &selected.ask_caller,
            cap: server.max_caller_ask_rounds,
            generation: live.mcp_catalogue.generation(),
            arguments: &arguments,
        },
        params,
    ) {
        AskDecision::Proceed => {}
        AskDecision::Refuse(refusal) => {
            return refuse_ask(
                ctx,
                &format!("mcp_tool:{}", selected.namespaced),
                &refusal,
                id,
            )
        }
        AskDecision::Ask {
            asks,
            request_state,
            round,
        } => {
            // METERED BEFORE IT IS EMITTED, and this is the gap that would otherwise be silent.
            // `charge_round` runs inside `inputreq::drive`, i.e. per UPSTREAM round — and an ask
            // returns before the upstream leg is ever entered, so a caller-facing exchange would be
            // charged exactly ZERO without this. An ask loop that is free is precisely the
            // amplification the upstream cap exists to stop, pointed the other way.
            let mut holds: Vec<crate::governance::AdmitGrant> = Vec::new();
            if let Err(reason) = charge_round(
                ctx,
                &selected.namespaced,
                &RoundRecord {
                    round,
                    satisfied: None,
                },
                &mut holds,
            ) {
                return refuse(
                    ctx,
                    name,
                    &DispatchRefusal::NotGranted(format!(
                        "this round of the input exchange was refused by your budget: {reason}"
                    )),
                    id,
                );
            }
            crate::admin::audit::AUDIT.record_by(
                "mcp.caller_ask",
                &format!("mcp_tool:{}", selected.namespaced),
                crate::admin::audit::OUTCOME_APPLIED,
                ctx.actor,
            );
            return input_required_result(id, &asks, &request_state);
        }
    }

    // (3) THE EGRESS GATE — the transitive confused-deputy defence, and it runs BEFORE the loop and before any network I/O.
    //
    // The credential busbar would spend on the upstream is bound to the INBOUND principal's grant.
    // Refusing here rather than inside the loop is what makes "an unauthorised caller cannot even
    // cause a token-exchange round trip" true rather than merely likely: `authorise` is synchronous
    // and reaches nothing.
    let authorised =
        match super::upstream::authorise(&server, &selected, &arguments, ctx.gov.key.as_deref()) {
            Ok(a) => a,
            Err(denied) => return refuse_setup(ctx, &selected.namespaced, &denied, id),
        };

    // (4) THE BOUNDED, METERED, PER-ROUND-GATED LOOP.
    //
    // Every concurrency hold taken by `try_admit` is parked here so it lives exactly as long as the
    // dispatch does: an `AdmitGrant` releases its gauges on drop, and dropping it inside the loop
    // would return the slot while the round it guards is still running.
    let mut holds: Vec<crate::governance::AdmitGrant> = Vec::new();
    let server_id = selected.server.clone();
    let pool = ctx.app.mcp_pool.as_ref();
    let outcome = inputreq::drive(
        &server_id,
        server.max_input_required_rounds,
        // The JSON-RPC id busbar puts on the OUTBOUND request is the round number, not the inbound
        // caller's id. An id chosen by the caller and echoed onto an upstream is a caller-controlled
        // value crossing a trust boundary for no reason.
        |round, _satisfaction| {
            super::upstream::call(pool, &authorised, &arguments, u64::from(round))
        },
        // THE GRANT, RE-READ LIVE ON EVERY ROUND. There is no handshake to authorise once and then
        // trust, so a revocation between rounds has to bite on the next one — which is the only
        // thing "per-request check" can mean when one logical dispatch is several requests.
        || {
            ctx.handle
                .load()
                .mcp_catalogue
                .server(&server_id)
                .map(|s| s.grants)
                .unwrap_or_default()
        },
        // SATISFYING an ask is a separate unit from making the call. A granted `sampling` becomes a
        // real LLM request on busbar's own pools and budget, an `elicitation` needs a human, and
        // `roots` needs a filesystem policy; none of the three is built, and saying so is NOT the
        // same as refusing the grant — `Unsatisfiable` and `Ungranted` are different answers with
        // different operator remedies, which is why they are different arms. The ask still
        // TERMINATES here either way: the caller is told busbar declined, never handed the ask.
        |ask| {
            Err(format!(
                "busbar holds the `{}` grant for this server but has no satisfier for that ask in \
                 this release; the ask terminates here and is not proxied to you",
                ask.kind
            ))
        },
        |rec| charge_round(ctx, &selected.namespaced, rec, &mut holds),
    )
    .await;

    // (5) AUDIT the VALIDATED decision — the one that survived every check above, never a call that
    // got no further than a refusal.
    let resource = format!("mcp_tool:{}", selected.namespaced);
    match outcome {
        Outcome::Completed(value) => {
            // (5a) THE TERMINAL ASSERTION, and it is deliberately a SECOND mechanism rather than a
            // tidier version of the first.
            //
            // Whether an upstream's ask ever reaches this arm is decided by a PREDICATE
            // (`client::jsonrpc::input_required_kind`), and predicates drift: this one spent its
            // whole life matching a wire shape no conformant server emits, and everything
            // downstream of it — including a type with no arm capable of carrying an ask — was
            // correct and unreached. So the value is checked once more here, at the last point
            // before it becomes bytes, against the FIELDS rather than the discriminator.
            //
            // The fields and not just `resultType`, because scrubbing the discriminator alone would
            // leave `inputRequests` in place: the caller would still receive the upstream's demand
            // for its password, now labelled `complete`. And a REFUSAL rather than a scrub, because
            // a result that says it is unfinished is not a finished result, and handing the caller a
            // silently-truncated one would be answering a question nobody asked.
            if let Some(field) = upstream_ask_field(&value) {
                tracing::error!(
                    tool = %selected.namespaced,
                    field,
                    "an upstream's input-required result reached the terminal check: the ask \
                     recogniser did not catch it"
                );
                crate::admin::audit::AUDIT.record_by(
                    "mcp_tool.call",
                    &resource,
                    crate::admin::audit::OUTCOME_REJECTED,
                    ctx.actor,
                );
                return error(
                    StatusCode::FORBIDDEN,
                    id,
                    CODE_REFUSED,
                    &format!(
                        "MCP server `{}` answered with an input-required result (`{field}`), which \
                         is a request that YOU spend authority on its behalf. An upstream's ask \
                         terminates at busbar and is never forwarded to you.",
                        selected.server
                    ),
                    Some(serde_json::json!({ "reason": "ask_not_proxied" })),
                );
            }
            crate::admin::audit::AUDIT.record_by(
                "mcp_tool.call",
                &resource,
                crate::admin::audit::OUTCOME_APPLIED,
                ctx.actor,
            );
            // Tool OUTPUT is markup-normalised before it re-enters model context: an upstream's
            // RESULT is exactly as injectable as its description, and it arrives later, when the
            // operator has already approved the tool.
            result(id, sanitize::normalise_json(&value))
        }
        Outcome::Refused(refusal) => {
            crate::admin::audit::AUDIT.record_by(
                "mcp_tool.call",
                &resource,
                crate::admin::audit::OUTCOME_REJECTED,
                ctx.actor,
            );
            tracing::warn!(
                tool = %selected.namespaced,
                reason = refusal.audit_reason(),
                "mcp tools/call refused"
            );
            // Every arm is busbar-attributed. An upstream's ask is reported as busbar's refusal to
            // satisfy it, never handed onward for the caller to answer: an upstream's ask
            // TERMINATES at busbar, because proxying it would ask the caller to grant, on the
            // upstream's behalf, authority busbar itself just declined to spend.
            error(
                match refusal {
                    Refusal::BudgetExhausted { .. } => StatusCode::TOO_MANY_REQUESTS,
                    _ => StatusCode::FORBIDDEN,
                },
                id,
                CODE_REFUSED,
                &refusal.to_string(),
                Some(serde_json::json!({ "reason": refusal.audit_reason() })),
            )
        }
    }
}

/// Which MRTR ask field, if any, an upstream's supposedly-complete result still carries.
///
/// Named as a LIST rather than as a check on `resultType`, for the reason the call site gives: the
/// discriminator is one field and the ask's CONTENT is in the other two, so a check that read only
/// the discriminator would pass a result that still carried the upstream's `inputRequests`.
///
/// Returns the offending field so the refusal and the log can name it — an operator debugging this
/// needs to know which of the three arrived, because it tells them whether their upstream is
/// conformant, half-conformant, or something else entirely.
fn upstream_ask_field(value: &serde_json::Value) -> Option<&'static str> {
    let obj = value.as_object()?;
    if obj.get("resultType").and_then(|v| v.as_str()) == Some("input_required") {
        return Some("resultType");
    }
    ["inputRequests", "requestState"]
        .into_iter()
        .find(|field| obj.contains_key(*field))
}

/// CHARGE one round on the caller's own budget plane, then meter it.
///
/// The two halves are the LLM path's two halves, called the same way for the same reason: `try_admit`
/// is the hard cap (and charges the flat per-request fee), `record_metering` is the attributed
/// series. There is no MCP-specific budget and no MCP-specific meter: an inbound `tools/call`
/// authenticates with a busbar key exactly like an LLM request and the key's budget and governance
/// policy applies — a claim implemented by calling the same two functions rather than asserted.
///
/// The `pool` argument is the NAMESPACED TOOL. Pool-scoped budget buckets test it with
/// `applies_to_pool`, so an MCP call never matches a bucket an operator scoped to an LLM pool — the
/// key-level and group-level caps still apply, which is what "the same budget plane" means. Naming
/// the tool rather than a constant is what makes a future per-tool bucket expressible without
/// re-plumbing anything.
fn charge_round(
    ctx: &Ctx<'_>,
    namespaced: &str,
    rec: &RoundRecord,
    holds: &mut Vec<crate::governance::AdmitGrant>,
) -> Result<(), String> {
    let (Some(gov_state), Some(key)) = (ctx.app.governance.as_ref(), ctx.gov.key.as_ref()) else {
        // Governance disabled: no key, no budget, nothing to charge. The same posture the LLM path
        // takes, and the reason a deployment without governance still serves.
        return Ok(());
    };
    // The SAME clock the LLM request path charges against (`ingress::dispatch`'s `charged_at`), so a
    // tool call and a model call land in the same budget window rather than in two windows that
    // happen to be close.
    let now = crate::store::now();
    match gov_state.try_admit(&ctx.app.cost, key, namespaced, now) {
        Ok(grant) => holds.push(grant),
        Err(blocked) => return Err(format!("{blocked:?}")),
    }
    // ONE METERED, ATTRIBUTED EVENT PER ROUND. `model` carries the namespaced tool and `provider`
    // carries the plane, so an existing cost dashboard groups MCP traffic without knowing what MCP
    // is — which is the whole govern-first thesis in one call.
    gov_state.record_metering(
        &key.id,
        namespaced,
        crate::plane::Plane::Mcp.key(),
        None,
        now,
    );
    tracing::debug!(
        capability = %namespaced,
        round = rec.round,
        satisfied = ?rec.satisfied,
        "mcp round metered"
    );
    Ok(())
}

/// A refusal from the EGRESS gate — the outbound credential could not be bound to this caller — or
/// from the credential configuration behind it.
///
/// Rendered and audited separately from a catalogue refusal and from an upstream failure, because
/// all three are refusals and only distinct AUDIT WORDS make them distinguishable afterwards. The
/// operator remedies are a grant, a secret, and a network respectively.
fn refuse_setup(
    ctx: &Ctx<'_>,
    namespaced: &str,
    denied: &super::upstream::SetupRefusal,
    id: Option<serde_json::Value>,
) -> Response {
    crate::admin::audit::AUDIT.record_by(
        "mcp_tool.call",
        &format!("mcp_tool:{namespaced}"),
        crate::admin::audit::OUTCOME_REJECTED,
        ctx.actor,
    );
    tracing::warn!(
        tool = %namespaced,
        reason = denied.audit_reason(),
        "mcp tools/call refused before the upstream"
    );
    error(
        StatusCode::FORBIDDEN,
        id,
        CODE_REFUSED,
        &denied.to_string(),
        Some(serde_json::json!({ "reason": denied.audit_reason() })),
    )
}

/// A refusal from the catalogue, rendered and audited: the rejection is audited AS a rejection,
/// before anything could mistake it for a successful route to a server the operator revoked.
fn refuse(
    ctx: &Ctx<'_>,
    name: &str,
    refusal: &DispatchRefusal,
    id: Option<serde_json::Value>,
) -> Response {
    crate::admin::audit::AUDIT.record_by(
        "mcp_tool.call",
        &format!("mcp_tool:{name}"),
        crate::admin::audit::OUTCOME_REJECTED,
        ctx.actor,
    );
    // A caller that may not see a tool and a caller naming one that does not exist get the SAME
    // answer, so the catalogue does not leak what it hides. The audit row above carries the real
    // distinction, for the operator, who is entitled to it.
    let status = match refusal {
        DispatchRefusal::GenerationMoved { .. } => StatusCode::CONFLICT,
        DispatchRefusal::UnknownTool(_) | DispatchRefusal::NotGranted(_) => StatusCode::NOT_FOUND,
        // A QUARANTINE is `403` and not `404`: the tool exists and this caller may see it, and what
        // changed is the upstream. Answering `404` would tell an operator debugging a rug-pull that
        // their registration had vanished.
        DispatchRefusal::NotApproved(_)
        | DispatchRefusal::NotPinned(_)
        | DispatchRefusal::Quarantined { .. } => StatusCode::FORBIDDEN,
    };
    error(
        status,
        id,
        CODE_REFUSED,
        &refusal.to_string(),
        Some(serde_json::json!({ "reason": refusal.audit_reason() })),
    )
}

/// The JSON-RPC code busbar answers a governance refusal with.
///
/// `-32000` is the first code in JSON-RPC's implementation-defined server-error range, which is what
/// a refusal by policy is: the request was well formed, the method exists, and the server declined.
/// `-32602` would say the arguments were wrong and `-32601` would say the method was missing, and
/// both would send an operator debugging the wrong thing.
const CODE_REFUSED: i64 = -32000;
/// JSON-RPC standard: the params were structurally wrong.
const CODE_INVALID_PARAMS: i64 = -32602;

fn string_param<'a>(params: Option<&'a serde_json::Value>, key: &str) -> Option<&'a str> {
    params.and_then(|p| p.get(key)).and_then(|v| v.as_str())
}

fn invalid_params(id: Option<serde_json::Value>, message: &str) -> Response {
    error(
        StatusCode::BAD_REQUEST,
        id,
        CODE_INVALID_PARAMS,
        message,
        None,
    )
}

fn not_found(id: Option<serde_json::Value>, message: &str) -> Response {
    error(StatusCode::NOT_FOUND, id, CODE_REFUSED, message, None)
}

/// A JSON-RPC success envelope. `200`, always: a result is a result.
///
/// This is also the ONE place `resultType` is stamped, and it is stamped on every result rather
/// than at each handler, because `2026-07-28` makes it mandatory on all of them and a field that
/// each handler has to remember is a field a seventh handler forgets.
///
/// ## `insert`, not `or_insert`, and the reasoning that changed
///
/// This used to `or_insert`, on the stated grounds that `tools/call` passes an UPSTREAM's result
/// through here and "rewriting a statement the upstream made about its own result would be busbar
/// answering for it". That reasoning is INVERTED, and enumerating the cases is what shows it —
/// because the set of results where `or_insert` differs from a plain `insert` is exactly the set
/// where preserving the upstream's value is wrong:
///
/// | what the upstream said | what preserving it does |
/// |---|---|
/// | `"complete"` | nothing — `insert` writes the same value |
/// | `"input_required"` | THE LAUNDERING. Hands busbar's caller an upstream's demand for authority, under busbar's name and busbar's authentication |
/// | anything else | passes on a result type busbar cannot describe and did not vouch for |
///
/// There is no case in which deferring to the upstream is both different and right. And the premise
/// was wrong too: the value leaving here is not the upstream's statement being relayed, it is
/// BUSBAR'S OWN RESULT — busbar chose to dispatch, normalised the content
/// ([`sanitize::normalise_json`]), and signs for what it returns. `resultType` is therefore busbar's
/// sentence to write, and the only honest thing busbar can write on a result it is handing over as
/// finished is `complete`.
///
/// The one result busbar legitimately marks otherwise is an ask BUSBAR ITSELF composed, and that is
/// deliberately a DIFFERENT FUNCTION rather than a branch here: see [`input_required_result`]. Two
/// constructors mean the `resultType` a caller sees is always one busbar chose, and which one is
/// visible at the call site rather than dependent on what arrived from a third party.
fn result(id: Option<serde_json::Value>, value: serde_json::Value) -> Response {
    use axum::response::IntoResponse as _;
    let mut value = value;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("resultType".into(), RESULT_TYPE_COMPLETE.into());
    }
    let mut envelope = serde_json::Map::new();
    envelope.insert("jsonrpc".into(), "2.0".into());
    if let Some(id) = id {
        envelope.insert("id".into(), id);
    }
    envelope.insert("result".into(), value);
    (
        StatusCode::OK,
        axum::Json(serde_json::Value::Object(envelope)),
    )
        .into_response()
}

/// `resultType: "input_required"` — the ONE result busbar returns that is not `complete`, and the
/// ONE place it can be produced.
///
/// A SEPARATE FUNCTION from [`result`] rather than a branch inside it, and that is the structural
/// half of the termination rule. [`result`] stamps `complete` unconditionally, so an upstream's
/// value cannot arrive carrying a discriminator busbar did not choose; this one stamps
/// `input_required` and can only be called with a [`callerask::CallerAsk`], whose only constructor
/// takes operator configuration. Which of the two a caller receives is therefore always a busbar
/// decision, and which one was taken is visible at the call site rather than dependent on what a
/// third party sent.
///
/// `200`, like every other result: an ask is a successful answer to a well-formed request, and the
/// exchange is unfinished rather than failed.
fn input_required_result(
    id: Option<serde_json::Value>,
    asks: &[callerask::CallerAsk],
    request_state: &str,
) -> Response {
    use axum::response::IntoResponse as _;
    let mut requests = serde_json::Map::new();
    for ask in asks {
        requests.insert(
            ask.key.clone(),
            serde_json::json!({ "method": ask.method, "params": ask.params }),
        );
    }
    let mut value = serde_json::Map::new();
    value.insert("resultType".into(), RESULT_TYPE_INPUT_REQUIRED.into());
    value.insert("inputRequests".into(), serde_json::Value::Object(requests));
    value.insert("requestState".into(), request_state.into());
    let mut envelope = serde_json::Map::new();
    envelope.insert("jsonrpc".into(), "2.0".into());
    if let Some(id) = id {
        envelope.insert("id".into(), id);
    }
    envelope.insert("result".into(), serde_json::Value::Object(value));
    (
        StatusCode::OK,
        axum::Json(serde_json::Value::Object(envelope)),
    )
        .into_response()
}

/// A refusal from the CALLER-ASK decision, rendered and audited under its own reason word.
///
/// `-32602` rather than `-32000` for a state failure, because that is what the conformance suite's
/// `tampered-state` scenario documents servers answering and, more to the point, what it IS: the
/// caller sent a `requestState` parameter this server will not accept. Everything else here is a
/// policy refusal and takes the policy code.
fn refuse_ask(
    ctx: &Ctx<'_>,
    resource: &str,
    refusal: &callerask::Refusal,
    id: Option<serde_json::Value>,
) -> Response {
    crate::admin::audit::AUDIT.record_by(
        "mcp.caller_ask",
        resource,
        crate::admin::audit::OUTCOME_REJECTED,
        ctx.actor,
    );
    tracing::warn!(
        capability = %resource,
        reason = refusal.audit_reason(),
        "mcp caller-ask refused"
    );
    let (status, code) = match refusal {
        callerask::Refusal::StateRejected(_) => (StatusCode::BAD_REQUEST, CODE_INVALID_PARAMS),
        _ => (StatusCode::FORBIDDEN, CODE_REFUSED),
    };
    error(
        status,
        id,
        code,
        &refusal.to_string(),
        Some(serde_json::json!({ "reason": refusal.audit_reason() })),
    )
}

/// The ask decision for one request, with everything it binds to gathered in one place.
///
/// Returns `None` when the call may proceed. Factored out because `tools/call` and `prompts/get`
/// must make the SAME decision the SAME way — one grammar, two paths — and two copies of a
/// capability filter is two places for one of them to be forgotten.
struct AskSite<'a> {
    /// `tools/call` or `prompts/get`.
    method: &'a str,
    /// The namespaced capability.
    capability: &'a str,
    /// The operator's ordered rounds for this capability. EMPTY ⇒ no ask.
    rounds: &'a [super::config::AskRoundCfg],
    /// The per-server cap on caller-facing rounds.
    cap: u32,
    /// The LIVE catalogue generation, sealed into the state.
    generation: u64,
    /// The parameters the seal digests — `arguments` on both paths.
    arguments: &'a serde_json::Value,
}

fn caller_ask_decision(
    ctx: &Ctx<'_>,
    site: AskSite<'_>,
    params: Option<&serde_json::Value>,
) -> AskDecision {
    let AskSite {
        method,
        capability,
        rounds,
        cap,
        generation,
        arguments,
    } = site;
    // The SEALING KEY, derived per decision from the deployment's fleet-shared signing secret. No
    // key ⇒ no sealer ⇒ the decision refuses rather than asking with unprotected state.
    let sealer = ctx
        .gov_signing_secret()
        .map(|s| super::askstate::Sealer::derive(&s));
    callerask::decide(
        rounds,
        cap,
        ctx.capabilities,
        Retry {
            responses: params.and_then(|p| p.get("inputResponses")),
            state: params
                .and_then(|p| p.get("requestState"))
                .and_then(|v| v.as_str()),
        },
        Bind {
            // The AUTHENTICATED PRINCIPAL (`mrtr.mdx:235`), which is the key's stable id and not the
            // actor string: the actor is for reading, the key id is what a grant is bound to. With
            // governance disabled there is no key, and the constant below is honest about that —
            // such a deployment has one principal, so binding to it is a true statement rather than
            // a fake distinction.
            principal: ctx
                .gov
                .key
                .as_ref()
                .map_or("<ungoverned>", |k| k.id.as_str()),
            method,
            capability,
            generation,
            now: crate::store::now(),
        },
        &super::askstate::digest_arguments(arguments),
        sealer.as_ref(),
    )
}

/// Delegates to the ingress envelope builder so the status and the code cannot drift apart between
/// the transport refusals and the method refusals.
fn error(
    status: StatusCode,
    id: Option<serde_json::Value>,
    code: i64,
    message: &str,
    data: Option<serde_json::Value>,
) -> Response {
    super::ingress::error_response(status, id, code, message, data)
}

#[cfg(test)]
#[path = "tests/method_tests.rs"]
mod method_tests;

#[cfg(test)]
#[path = "tests/result_envelope_tests.rs"]
mod result_envelope_tests;

#[cfg(test)]
#[path = "tests/prompt_args_tests.rs"]
mod prompt_args_tests;

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

use crate::catalogue::CatalogueItem;

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
    // SEP-2663. The three v2 tasks methods, and ONLY the three: `tasks/result` and `tasks/list`
    // were REMOVED by the extension's v2 wire — the result is inlined on `tasks/get` and there is
    // no list — so their absence here is what makes them answer `-32601`, which is the conformant
    // answer and not a gap. See `super::tasks`.
    "tasks/get",
    "tasks/update",
    "tasks/cancel",
    // SEP-2575's replacement for the GET stream. It is a METHOD in this revision, so it belongs in
    // this list rather than in the route table — which is the whole difference the revision made,
    // and the reason `super::envelope::legacy_verb` can go on answering `405` without that being a
    // statement that busbar cannot notify a client. See `super::subscribe`.
    super::subscribe::METHOD_SUBSCRIPTIONS_LISTEN,
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

/// SEP-2663's discriminator, returned ONLY by [`task_result`] and only for a task busbar itself
/// just created. Like `input_required`, it can never carry an upstream's value: an upstream answers
/// busbar's own request, and busbar's decision to answer its caller asynchronously is taken before
/// the upstream is contacted at all.
const RESULT_TYPE_TASK: &str = "task";

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
/// approval revoked, a pin bumped, a rug-pull quarantine landing between two requests. The
/// invalidation channel that exists — `subscriptions/listen`, which is why `listChanged` is now
/// advertised `true` — is OPT-IN and per-caller: a client that never opened a stream has no
/// correction coming, so a positive ttl would be a promise kept only for the clients that
/// subscribed. A client that cached for a minute would keep OFFERING a de-approved tool for a
/// minute. Dispatch would still refuse the call it produced (the generation re-check is per
/// request and does not consult any cache), so the cost is a confusing refusal rather than an
/// unauthorized call. That is exactly why the honest answer is `0` and not a comfortable-looking
/// `60000`: a cache hint that lies is worse than none, and `0` is not the absence of a hint — it
/// is the schema's own way of stating "no freshness window", which is the true statement about a
/// catalogue whose only invalidation channel is one the caller may not have opened.
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
    /// THE REQUEST HEADERS, carried for exactly one reason: SEP-2243's `Mcp-Param-*` custom headers
    /// are validated against the tool's `x-mcp-header` annotations, and those annotations live in
    /// the OPERATOR's `input_schema` — which ingress cannot read, because reading it means resolving
    /// the tool under the caller's grant, and that is the catalogue's job and happens here.
    ///
    /// So the envelope checks that need no catalogue stay in ingress and the one that does lands
    /// here, rather than ingress growing a grant-scoped lookup or this module growing a second
    /// header parser. Both halves still answer `-32020` / `400`.
    pub(crate) headers: &'a axum::http::HeaderMap,
    /// THE SYNC LEG'S SHARED HOST [`DispatchScope`](crate::plane_host::DispatchScope) — the arena the
    /// `tools/call` breaker admit registers into and the leg settle folds through (CLUSTER-1). Opened
    /// once at the top of `rpc_dispatch` and held for the whole future, so a host handle is reachable
    /// at every downstream breaker admit/settle site and reclaims on any exit. `None` for the task
    /// path (which re-homes its probe into a `DurableScope`) and for unit tests that admit directly.
    pub(crate) scope: Option<&'a crate::plane_host::DispatchScope>,
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

    /// WHO IS ASKING, for every catalogue read on this request.
    ///
    /// One value, built once, passed to every catalogue read, so the catalogue a caller sees and the
    /// tools it may dispatch are decided by the same principal, the same clock and the same
    /// snapshot. It replaced a grant CLOSURE, which could only carry the grant: the identity and
    /// expiry steps had nowhere to arrive, so a listing served a deleted key.
    ///
    /// A `None` key means governance is DISABLED for this deployment. `crate::trust::validate`
    /// states that posture once for the whole tree — with no key there is no grant to narrow, and
    /// refusing everything would make an ungoverned deployment unable to serve at all — so this
    /// carries the `Option` rather than restating the rule.
    ///
    /// `at_admission`, because a listing IS its own admission: there is no earlier snapshot for it
    /// to have outlived. `tools/call` says [`crate::trust::validate::Generations::since`] instead,
    /// out loud, at its own call site.
    fn caller(&self) -> crate::catalogue::Caller<'_> {
        crate::catalogue::Caller {
            key: self.gov.key.as_deref(),
            now: crate::store::now(),
            generation: crate::trust::validate::Generations::at_admission(
                super::runtime(self.app).catalogue.generation(),
            ),
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
        "resources/templates/list" => Some(resources_templates_list(ctx, id)),
        "resources/read" => Some(resources_read(ctx, params, id)),
        "completion/complete" => Some(completion_complete(id)),
        "tasks/get" => Some(tasks_get(ctx, params, id)),
        "tasks/update" => Some(tasks_update(ctx, params, id)),
        "tasks/cancel" => Some(tasks_cancel(ctx, params, id)),
        // The one method whose answer is a STREAM rather than a document. It returns through the
        // same `Response` as every other arm — what makes it different is the `content-type`, which
        // is also what tells `super::envelope` not to re-frame it.
        super::subscribe::METHOD_SUBSCRIPTIONS_LISTEN => {
            Some(super::subscribe::listen(ctx, params, id))
        }
        _ => None,
    }
}

/// The `-32021` gate every tasks-namespace method sits behind.
///
/// SEP-2663 makes the whole task surface conditional on the client having declared the extension:
/// a client that did not is not merely uninterested, it is a client that cannot receive a
/// `CreateTaskResult`, so answering its `tasks/get` would be answering about a task it could never
/// have been given. `-32601` would be the wrong answer and busbar's old one — it says the method
/// does not exist, when what is true is that this caller has not asked for it.
///
/// Returns `Some(response)` when the request must be refused.
fn refuse_undeclared_tasks(
    ctx: &Ctx<'_>,
    id: &Option<serde_json::Value>,
) -> Option<axum::response::Response> {
    if super::tasks::client_declares_tasks(ctx.capabilities) {
        return None;
    }
    Some(missing_tasks_capability(id.clone()))
}

/// The `-32021` refusal itself, in one place so the code, the status and the `requiredCapabilities`
/// payload cannot drift between the two things that emit it — the tasks methods and a `tools/call`
/// on a `task_support: required` tool.
///
/// `400`, because `MissingRequiredClientCapabilityError` fixes the status: "For HTTP, the response
/// status code MUST be `400 Bad Request`."
fn missing_tasks_capability(id: Option<serde_json::Value>) -> Response {
    error(
        StatusCode::BAD_REQUEST,
        id,
        CODE_MISSING_CLIENT_CAPABILITY,
        &format!(
            "This request needs the `{}` extension, and it was not declared in \
             `params._meta.io.modelcontextprotocol/clientCapabilities.extensions`. Declare it — \
             per session or on this one request — and retry.",
            super::tasks::TASKS_EXTENSION_ID
        ),
        Some(serde_json::json!({
            "reason": "tasks_extension_not_declared",
            "requiredCapabilities": super::tasks::required_tasks_capability(),
        })),
    )
}

/// Resolve `params.taskId` for THIS caller, or the refusal that replaces it.
///
/// An unknown id is `-32602`, which SEP-2663 fixes for exactly this case, and an id belonging to
/// ANOTHER caller takes the identical arm rather than a `403`. That is deliberate: two different
/// answers would tell a caller which ids exist, and a task id is the only credential a poll
/// presents.
///
/// The error arm is BOXED because a `Response` is a large value and the success arm is one `Arc`:
/// an unboxed `Result` would make every caller of this function move the whole refusal envelope
/// around on the happy path.
fn resolve_task(
    ctx: &Ctx<'_>,
    params: Option<&serde_json::Value>,
    id: &Option<serde_json::Value>,
) -> Result<std::sync::Arc<super::tasks::McpTask>, Box<Response>> {
    let Some(task_id) = string_param(params, "taskId") else {
        return Err(Box::new(invalid_params(
            id.clone(),
            "`params.taskId` is required and must be a string.",
        )));
    };
    super::tasks::TASKS
        .get(task_id, task_principal(ctx))
        .ok_or_else(|| {
            Box::new(invalid_params(
                id.clone(),
                "No task with that `taskId` exists for this caller.",
            ))
        })
}

/// The principal a task is filed under. The KEY ID where there is one, and one honest constant
/// where governance is disabled — such a deployment has exactly one caller, so filing every task
/// under it is a true statement rather than a fabricated distinction. The same reasoning
/// `caller_ask_decision` uses to bind request state.
fn task_principal<'a>(ctx: &'a Ctx<'_>) -> &'a str {
    ctx.gov
        .key
        .as_ref()
        .map_or("<ungoverned>", |k| k.id.as_str())
}

/// `tasks/get` — the DetailedTask, with the tool result INLINED once the task is terminal.
///
/// There is no `tasks/result`: SEP-2663 removed it precisely so a client cannot observe a task as
/// complete and then fail to fetch what it completed with.
fn tasks_get(
    ctx: &Ctx<'_>,
    params: Option<&serde_json::Value>,
    id: Option<serde_json::Value>,
) -> Response {
    if let Some(refusal) = refuse_undeclared_tasks(ctx, &id) {
        return refusal;
    }
    match resolve_task(ctx, params, &id) {
        Ok(task) => result(id, task.detailed()),
        Err(refusal) => *refusal,
    }
}

/// `tasks/update` — deliver `inputResponses`, acked with an EMPTY `{resultType:"complete"}`.
///
/// The ack carries no task envelope, and that is the SEP-2322 discriminator rule rather than
/// terseness: a response carrying `taskId`/`status` would be a second, racing view of the task
/// beside `tasks/get`, and a client would have to decide which of the two to believe. One reader.
fn tasks_update(
    ctx: &Ctx<'_>,
    params: Option<&serde_json::Value>,
    id: Option<serde_json::Value>,
) -> Response {
    if let Some(refusal) = refuse_undeclared_tasks(ctx, &id) {
        return refusal;
    }
    let task = match resolve_task(ctx, params, &id) {
        Ok(task) => task,
        Err(refusal) => return *refusal,
    };
    // ABSENT is treated as empty rather than refused. The method's job is to deliver what the
    // client has; a client that has nothing yet has sent a well-formed, if pointless, request.
    let responses = params
        .and_then(|p| p.get("inputResponses"))
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    super::tasks::TASKS.update(&task.id, task_principal(ctx), &responses);
    result(id, serde_json::json!({}))
}

/// `tasks/cancel` — the same empty ack, and IDEMPOTENT on a task that has already settled.
///
/// Idempotent rather than `-32602`, because the alternative makes every client handle a race it
/// cannot avoid: a task can terminate between the poll that observed it running and the cancel
/// that followed. The spec reserves `-32602` for ids the server does not recognise, and a task it
/// finished a moment ago is one it recognises perfectly well.
fn tasks_cancel(
    ctx: &Ctx<'_>,
    params: Option<&serde_json::Value>,
    id: Option<serde_json::Value>,
) -> Response {
    if let Some(refusal) = refuse_undeclared_tasks(ctx, &id) {
        return refusal;
    }
    let task = match resolve_task(ctx, params, &id) {
        Ok(task) => task,
        Err(refusal) => return *refusal,
    };
    super::tasks::TASKS.cancel(&task.id, task_principal(ctx));
    crate::admin::audit::AUDIT.record_by(
        "mcp_task.cancel",
        &format!("mcp_task:{}", task.id),
        crate::admin::audit::OUTCOME_APPLIED,
        ctx.actor,
    );
    result(id, serde_json::json!({}))
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
/// reason [`super::envelope::error_response`] is one function for the status/code pair: a hint that
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
    let cat = &super::runtime(ctx.app).catalogue;
    let caller = ctx.caller();
    let tools = cat.tools_for(&caller);
    let prompts = cat.prompts_for(&caller);
    let resources = cat.resources_for(&caller);
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
            "protocolVersion": super::envelope::PROTOCOL_VERSION,
            // The versions this server will ACCEPT, which is the mandatory field of a
            // `DiscoverResult` and is not the same statement as `protocolVersion` above (that one
            // names the revision this answer is written in). It is the SAME constant the ingress
            // refuses an unsupported version against, and it is that constant rather than a copy
            // for a reason the conformance suite checks directly: it correlates the `data.supported`
            // list on an `UnsupportedProtocolVersionError` against this list, so two lists that
            // could disagree would be a client told to retry with a version it will be refused for.
            "supportedVersions": super::envelope::SUPPORTED_PROTOCOL_VERSIONS,
            "serverInfo": { "name": "busbar", "version": env!("CARGO_PKG_VERSION") },
            // Advertised as present only when this caller can actually reach one. A capability
            // advertised to a caller who holds nothing under it is an invitation to a refusal.
            "capabilities": {
                // `listChanged: true` on all three, because `subscriptions/listen` DELIVERS all
                // three: `super::subscribe` narrows a requested filter to exactly
                // {tools,prompts,resources}ListChanged and emits each on the caller's own stream
                // when the grant-scoped catalogue slice moves. This flag is the field a client
                // reads to decide whether change notifications exist AT ALL — advertising `false`
                // beside a working stream is an undeclared surface no conforming client will ever
                // open, and one that probed the method anyway was told by this very document to
                // expect `-32601`, so the stream response read as a hang. The declaration and the
                // delivery are pinned to each other by
                // `discover_declares_the_capabilities_the_listen_stream_delivers`.
                "tools": { "listChanged": true },
                "prompts": { "listChanged": true },
                // `subscribe: true` since the relay landed: `resourceSubscriptions` on
                // `subscriptions/listen` is DELIVERED now — an upstream's own
                // `notifications/resources/updated` is recorded by the client leg and relayed to
                // subscribers whose grant reaches the named resource. The old `false` was pinned
                // to the sentence "busbar is not told when a resource's contents change", and
                // that sentence stopped being true; a declaration and a delivery must keep
                // agreeing in BOTH directions, which is what
                // `discover_declares_the_capabilities_the_listen_stream_delivers` pins.
                "resources": { "listChanged": true, "subscribe": true },
                // Present because `completion/complete` is IMPLEMENTED and answers correctly, which
                // is what the capability declares. It is not a claim that this deployment has
                // suggestions to give — see `completion_complete` for why the answer is the empty
                // set and why that is a complete answer rather than a stub.
                "completions": {},
                // Present because busbar EMITS `notifications/message` records about its own
                // handling of a request, on the response stream of the request they describe. There
                // is deliberately no `logging/setLevel`: this revision has no session for a level to
                // live in, so the level is named per request in `_meta` — see `super::sse`.
                "logging": {},
                // SEP-2663, advertised UNCONDITIONALLY — unlike the counts below, which are scoped
                // to what this caller can reach.
                //
                // The asymmetry is deliberate and it is the difference between a CATALOGUE and a
                // PROTOCOL. `tools`/`prompts`/`resources` describe what this caller may see, and a
                // caller whose grant reaches nothing legitimately sees nothing. An extension
                // describes what the SERVER can do with the wire: `tasks/get`, `tasks/update` and
                // `tasks/cancel` are implemented, gated only on the caller's own declaration, and
                // answer correctly for every caller — including one who currently holds no
                // task-supporting tool, for whom the honest answer is "the surface exists, you have
                // nothing on it" rather than "the surface does not exist".
                //
                // It is advertised under `extensions` and NOT as a v1-style `capabilities.tasks`
                // slot, because the extension REPLACED that surface rather than living beside it,
                // and a server advertising both would be claiming two protocols at once.
                "extensions": { super::tasks::TASKS_EXTENSION_ID: {} },
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

/// `tools/list` — the GOVERNANCE-SCOPED catalogue, MINUS anything currently quarantined.
///
/// ## Why the listing consults the drift sightings and not only the grants
///
/// Refusing to DISPATCH to a demoted upstream was the safety property and it was already proven. It
/// is not the whole of it. A listing is not a neutral fact: it publishes the operator's APPROVED
/// schema and APPROVED hash, and for a quarantined server that is a description of a tool the
/// upstream has stopped serving that way. A planning client reads it, builds a call against a shape
/// that no longer exists, and spends a turn and a budget being refused — while busbar's own stated
/// position for every other field is that publishing something means the operator vouched for THIS
/// tool at THIS digest. It cannot vouch for one it has just demoted.
///
/// The filter answers on exactly the arm the dispatch gate refuses on, and deliberately not on the
/// other two. `Unsighted` — nobody has ever looked — still advertises, because that is the
/// declarative deployment every existing operator runs, and treating "never looked" as "it moved"
/// would empty the catalogue of all of them. Both halves are pinned by test beside each other.
fn tools_list(ctx: &Ctx<'_>, id: Option<serde_json::Value>) -> Response {
    let caller = ctx.caller();
    let sightings = super::runtime(ctx.app).sightings.load();
    let live = LiveSightings::of(&sightings);
    // ENTITLEMENT FIRST (core's walk, through the ordered gate), then trust, then render. The
    // quarantine filter sits between the two because it is not an entitlement question — see
    // `Catalogue::is_quarantined`, which takes no caller — so it cannot be folded into
    // `required_grants` without making trust a second place a grant is interpreted.
    let tools: Vec<serde_json::Value> = super::runtime(ctx.app)
        .catalogue
        .tools_for(&caller)
        .into_iter()
        .filter(|t| !super::runtime(ctx.app).catalogue.is_quarantined(live, t))
        .map(CatalogueItem::render)
        .collect();
    result(id, cache_hints(serde_json::json!({ "tools": tools })))
}

/// `prompts/list`, with every description markup-normalised on the way out.
fn prompts_list(ctx: &Ctx<'_>, id: Option<serde_json::Value>) -> Response {
    let caller = ctx.caller();
    let prompts: Vec<serde_json::Value> =
        super::runtime(ctx.app).catalogue.prompts_rendered(&caller);
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
    let caller = ctx.caller();
    let Some(prompt) = super::runtime(ctx.app).catalogue.prompt_for(&caller, name) else {
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
    let cap = super::runtime(ctx.app)
        .catalogue
        .server(&prompt.server)
        .map_or(0, |s| s.max_caller_ask_rounds);
    match caller_ask_decision(
        ctx,
        AskSite {
            method: "prompts/get",
            capability: &prompt.namespaced,
            rounds: &prompt.ask_caller,
            cap,
            generation: super::runtime(ctx.app).catalogue.generation(),
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
            // The govern grant rides the request-wide arena (`ctx.scope`, the same arena the breaker
            // admission registers into) so it releases when the request future ends — the lifetime
            // the caller-held `Vec<AdmitGrant>` had. A `None` scope (unit tests) falls back to a local
            // arena that drops at this fn's return, the same drop point.
            let fallback_scope = crate::plane_host::DispatchScope::new();
            let scope = ctx.scope.unwrap_or(&fallback_scope);
            if let Err(reason) = charge_round(
                ctx,
                &prompt.namespaced,
                &RoundRecord {
                    round,
                    satisfied: None,
                },
                scope,
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
    result(
        id,
        serde_json::json!({
            "description": sanitize::normalise_opt(prompt.description.as_deref()),
            "messages": render_prompt_messages(prompt, params),
        }),
    )
}

/// The `messages` array `prompts/get` returns, in whichever of the two forms the operator declared.
///
/// ONE FUNCTION FOR BOTH FORMS, and that is the point rather than tidiness: the text form and the
/// typed form must go through the SAME substitute-then-normalise pass. A second rendering path
/// would be a second place to forget the strip, and a new content type that skipped it would be a
/// hole opened by a feature nobody thought of as a text surface.
fn render_prompt_messages(
    prompt: &super::catalogue::PromptEntry,
    params: Option<&serde_json::Value>,
) -> Vec<serde_json::Value> {
    use super::config::PromptContentCfg;

    // SUBSTITUTE FIRST, NORMALISE SECOND — `substitute_arguments` rule 1. The caller's argument
    // values pass through the same markup strip the operator's own text does.
    let render = |s: &str| sanitize::normalise(&substitute_arguments(s, params));

    if prompt.messages.is_empty() {
        return vec![serde_json::json!({
            "role": "user",
            "content": {
                "type": "text",
                "text": render(prompt.template.as_deref().unwrap_or("")),
            },
        })];
    }

    prompt
        .messages
        .iter()
        .map(|m| {
            let content = match &m.content {
                PromptContentCfg::Text { text } => serde_json::json!({
                    "type": "text", "text": render(text),
                }),
                // The base64 payload is NOT normalised. `normalise` strips markup from text that
                // re-enters a model's instruction stream; a media payload is opaque bytes the client
                // was told the type of, and running a text filter over base64 would corrupt it while
                // protecting nothing. It is validated as decodable at BOOT instead.
                PromptContentCfg::Image { data, mime_type } => serde_json::json!({
                    "type": "image", "data": data, "mimeType": mime_type,
                }),
                PromptContentCfg::Audio { data, mime_type } => serde_json::json!({
                    "type": "audio", "data": data, "mimeType": mime_type,
                }),
                PromptContentCfg::Resource { resource } => {
                    let mut r = serde_json::Map::new();
                    // The URI substitutes: `test_prompt_with_embedded_resource` takes the URI to
                    // embed as an ARGUMENT, so a template that could not substitute here could not
                    // express the shape at all. It is normalised too — a URI carrying an HTML-like
                    // tag is not a URI, and this one is echoed into a model's context.
                    r.insert("uri".into(), render(&resource.uri).into());
                    if let Some(m) = &resource.mime_type {
                        r.insert("mimeType".into(), m.clone().into());
                    }
                    if let Some(t) = &resource.text {
                        r.insert("text".into(), render(t).into());
                    }
                    if let Some(b) = &resource.blob {
                        r.insert("blob".into(), b.clone().into());
                    }
                    serde_json::json!({ "type": "resource", "resource": r })
                }
            };
            serde_json::json!({ "role": m.role, "content": content })
        })
        .collect()
}

/// `resources/list`, with every free-text field markup-normalised on the way out.
fn resources_list(ctx: &Ctx<'_>, id: Option<serde_json::Value>) -> Response {
    let caller = ctx.caller();
    let resources: Vec<serde_json::Value> = super::runtime(ctx.app)
        .catalogue
        .resources_rendered(&caller);
    result(
        id,
        cache_hints(serde_json::json!({ "resources": resources })),
    )
}

/// `resources/templates/list` — the GRANT-SCOPED URI-TEMPLATE catalogue.
///
/// A resource template is a parameterised URI (`file:///logs/{date}.log`) that a client expands and
/// then reads. This method answered `[]` unconditionally, and that WAS the complete and correct
/// answer for as long as the registry had no concept of one: `resources_allow:` named concrete URIs
/// the operator approved one at a time, a template is an approval of a SHAPE, and the operator had
/// no way to make that decision. `resource_templates_allow:` is that way, so the empty list stopped
/// being a fact about the registry and became a fact about this function.
///
/// It is scoped by the same two grants as every other catalogue read, and it is scoped for the same
/// reason: a template names a capability of a server, and a caller with no reach to the server has
/// no reach to its templates. The empty list survives for a caller whose grant reaches none, which
/// is where the old answer was right all along.
fn resources_templates_list(ctx: &Ctx<'_>, id: Option<serde_json::Value>) -> Response {
    let caller = ctx.caller();
    let templates: Vec<serde_json::Value> = super::runtime(ctx.app)
        .catalogue
        .resource_templates_rendered(&caller);
    result(
        id,
        cache_hints(serde_json::json!({ "resourceTemplates": templates })),
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
    let caller = ctx.caller();
    // CONCRETE FIRST, TEMPLATE SECOND, and never the other way round. A URI the operator approved BY
    // NAME must not be answered by a template that happens to match it: the two are different
    // approvals, and letting the broader one win would let adding a template silently change what an
    // already-approved URI returns.
    let content = match super::runtime(ctx.app)
        .catalogue
        .resource_by_uri(&caller, uri)
    {
        super::catalogue::ResourceLookup::One(res) => concrete_resource_content(res),
        // NEVER A GUESS. Two servers this caller can reach both expose this URI, so which one was
        // meant is a question only the caller can answer. The whole reason the catalogue was
        // namespaced was that this case used to be resolved SILENTLY, by config order, and served
        // one server's content to a caller who had asked for the other's.
        super::catalogue::ResourceLookup::Ambiguous(candidates) => {
            return ambiguous_resource(id, uri, &candidates)
        }
        super::catalogue::ResourceLookup::NotFound => {
            match super::runtime(ctx.app)
                .catalogue
                .resource_template_for(&caller, uri)
            {
                super::catalogue::ResourceLookup::One((template, bindings)) => {
                    templated_resource_content(uri, template, &bindings)
                }
                // THE SAME REFUSAL, and it must be the same one. An operator who writes an approval
                // with a parameter in it has not thereby agreed that busbar may pick between two
                // upstreams on their behalf; a plane where the literal spelling refuses and the
                // parameterised spelling quietly resolves is a plane where the refusal is bypassed
                // by writing the approval differently.
                super::catalogue::ResourceLookup::Ambiguous(candidates) => {
                    return ambiguous_resource(id, uri, &candidates)
                }
                super::catalogue::ResourceLookup::NotFound => {
                    return not_found(
                        id,
                        &format!("`{uri}` is not a resource this server exposes."),
                    )
                }
            }
        }
    };
    result(
        id,
        cache_hints(serde_json::json!({ "contents": [content] })),
    )
}

/// THE ONE AMBIGUITY REFUSAL, shared by both address resolutions.
///
/// One function rather than one per resolution, because a second copy is a second place for one of
/// them to answer a `200`, which is precisely the defect this was written to close: the literal
/// address refused and the parameterised address did not, and nothing made the two agree.
fn ambiguous_resource(id: Option<serde_json::Value>, uri: &str, candidates: &[String]) -> Response {
    error(
        StatusCode::CONFLICT,
        id,
        CODE_REFUSED,
        &format!(
            "`{uri}` is answered by more than one approval you are granted ({}). \
             Narrow the grant so exactly one of them applies.",
            candidates.join(", ")
        ),
        Some(serde_json::json!({ "reason": "resource_ambiguous", "candidates": candidates })),
    )
}

/// The `ResourceContents` block for a CONCRETE resource.
///
/// `text` and `blob` are the schema's two ALTERNATIVES, and exactly one is emitted. Config
/// validation already refuses a declaration carrying both, so the `else` arm here is the honest
/// "neither was declared" — an approved resource with no content, which answers the empty text form
/// rather than an error, because the operator approving a URI and leaving it empty is a statement
/// about content, not a malformed request.
fn concrete_resource_content(res: &super::catalogue::ResourceEntry) -> serde_json::Value {
    let mut content = serde_json::Map::new();
    // ECHOED AS ASKED. A client correlates this block to its own request by this field.
    content.insert("uri".into(), res.uri.clone().into());
    if let Some(m) = &res.mime_type {
        content.insert("mimeType".into(), m.clone().into());
    }
    match &res.blob {
        // NOT normalised — see `ResourceAllowCfg::blob`. A markup strip over base64 corrupts the
        // payload and protects nothing; what protects the client is the boot-time decode check.
        Some(blob) => {
            content.insert("blob".into(), blob.clone().into());
        }
        None => {
            content.insert(
                "text".into(),
                sanitize::normalise(res.text.as_deref().unwrap_or("")).into(),
            );
        }
    }
    serde_json::Value::Object(content)
}

/// The `ResourceContents` block for one EXPANSION of a template.
///
/// The URI echoed is the one the CALLER ASKED FOR, not the template. A client correlates the content
/// it received with the URI it sent; answering with the unexpanded template would hand back an
/// identifier that names every expansion at once.
///
/// The bindings substitute into the content, and the substituted result is normalised — the
/// parameter values come from the caller's own URI, so they are exactly as attacker-controlled as a
/// prompt argument and go through exactly the same strip.
fn templated_resource_content(
    requested_uri: &str,
    template: &super::catalogue::ResourceTemplateEntry,
    bindings: &std::collections::BTreeMap<String, String>,
) -> serde_json::Value {
    let mut text = template.text.clone().unwrap_or_default();
    for (name, value) in bindings {
        text = text.replace(&format!("{{{name}}}"), value);
    }
    let mut content = serde_json::Map::new();
    content.insert("uri".into(), requested_uri.into());
    if let Some(m) = &template.mime_type {
        content.insert("mimeType".into(), m.clone().into());
    }
    content.insert("text".into(), sanitize::normalise(&text).into());
    serde_json::Value::Object(content)
}

/// THE PER-CALL RECORD UNDER CONSTRUCTION: what this dispatch knows about itself so far.
///
/// ## Why an accumulator and not one emit at the end
///
/// `tools_call` has fourteen terminals and they are not interchangeable — an unknown tool, a
/// revoked grant, a schema that drifted under a live cache, an exhausted budget and an upstream that
/// refused are five different operator remedies. A single emit at the bottom could only report the
/// HTTP status, which collapses all of them, and deriving the reason by re-inspecting the response
/// body would make the durable record depend on the wire format. So each terminal names its own
/// reason token, in the same statement that produces the response, and the compiler keeps them
/// paired: [`CallLog::refused`] takes the response BY VALUE, so a terminal cannot return without
/// going through it.
///
/// ## The fields are learned, not assumed
///
/// `tool` starts as the name the CALLER asked for, because a refusal that matched no registration
/// still has to say what was asked for; `server`, `tool_digest` and `pin_generation` are filled in
/// by [`CallLog::resolved`] once admission has produced a catalogue entry, and stay empty/zero on
/// every refusal that never reached one — which is exactly what `McpCallRecord` documents those
/// fields to mean.
struct CallLog<'a> {
    /// The AUTHENTICATED caller. The same string the admin audit row is attributed to, so a record
    /// and its audit row name one principal rather than two spellings of one.
    principal: &'a str,
    /// The request-spine join key, minted once per dispatch from the engine's own counter.
    request_id: String,
    tool: String,
    server: String,
    tool_digest: String,
    pin_generation: u64,
}

impl<'a> CallLog<'a> {
    fn open(ctx: &'a Ctx<'_>, requested: &str, generation: u64) -> Self {
        CallLog {
            principal: ctx.actor,
            request_id: ctx.app.next_request_id().to_string(),
            tool: requested.to_string(),
            server: String::new(),
            tool_digest: String::new(),
            pin_generation: generation,
        }
    }

    /// ADMISSION SUCCEEDED: bind the record to the entry the call actually resolved to, and to the
    /// digest the operator approved for it. That digest is what ties this call to the exact schema
    /// and description that were vouched for, so a later re-approval cannot be mistaken for the one
    /// this call rode.
    fn resolved(&mut self, selected: &ToolEntry, generation: u64) {
        self.tool = selected.namespaced.clone();
        self.server = selected.server.clone();
        self.tool_digest = selected.schema_hash.clone().unwrap_or_default();
        self.pin_generation = generation;
    }

    fn write(&self, outcome: &'static str, reason: &str) {
        crate::plane::calllog::emit(
            self.principal,
            crate::plane::calllog::CallInput {
                ts: crate::store::now(),
                server: self.server.clone(),
                tool: self.tool.clone(),
                outcome,
                reason: reason.to_string(),
                tool_digest: self.tool_digest.clone(),
                pin_generation: self.pin_generation,
                request_id: self.request_id.clone(),
            },
        );
    }

    /// Record a refusal and hand the response back. Takes the response BY VALUE so the record and
    /// the answer are produced in one statement and a terminal cannot quietly skip the record.
    fn refused(&self, reason: &str, response: Response) -> Response {
        self.write(crate::plane::calllog::OUTCOME_REFUSED, reason);
        response
    }

    /// Record a call that WENT OUT and was answered. `reason` is empty on a dispatch, per the store
    /// contract — the field is a refusal token, not a description.
    fn dispatched(&self, response: Response) -> Response {
        self.write(crate::plane::calllog::OUTCOME_DISPATCHED, "");
        response
    }

    /// Record a call that WENT OUT and came back BADLY.
    ///
    /// Still `dispatched`, because the store contract's `dispatched` means exactly "the call went
    /// out" and this one did — it was `refused` until this commit, which said the opposite of what
    /// happened. The `reason` field carries the token, and the store contract already documents it
    /// as free on a dispatch rather than forbidden: what it forbids is a DESCRIPTION, and
    /// `upstream_failed` is a stable, greppable token exactly like the refusal ones beside it.
    fn dispatched_with_reason(&self, reason: &'static str, response: Response) -> Response {
        self.write(crate::plane::calllog::OUTCOME_DISPATCHED, reason);
        response
    }
}

/// VERIFY-ON-CALL for one `tools/call`: freshen the named tool's server within `verify_ttl`,
/// single-flight, fail-closed. See the call site in [`tools_call`] for the ordering rationale.
///
/// The single-flight, the freshness bound and the fail-closed ordering are [`crate::trust::verify`]'s,
/// once, for every plane; what is here is this plane's FETCH — an async `tools/list` re-hash through
/// [`crate::mcp::connect::refresh`], stamped so the freshness clock records when it looked — and this
/// plane's ledger reader. A tool name no registration exposes is a no-op, and so is a fresh snapshot:
/// nothing is fetched between calls, and a server nobody calls is never fetched.
async fn verify_on_call(ctx: &Ctx<'_>, name: &str) {
    let Some((server_id, server)) = super::runtime(ctx.app).catalogue.verify_target(name) else {
        return;
    };
    let now_ms = crate::store::now_ms();
    let policy = server.verify_policy.clone();
    let server = server.clone();
    let subject = server_id.to_string();
    // Two handles to the one shared cache: the ledger reader BORROWS it (an `Fn`, called on each
    // freshness check), the fetch MOVES its own (an `async move`), so the two closures do not contend
    // over one binding.
    let cache = super::runtime(ctx.app).sightings.clone();
    let cache_fetch = cache.clone();
    let pool = super::runtime(ctx.app).pool.clone();
    let gate = ctx.app.mcp_verify.clone();
    let demotions = ctx.app.mcp_demotions.clone();
    // A peer's `list_changed` may only mark the snapshot STALE (never read its body): if this server
    // was signalled, clear its freshness clock so this call re-verifies even inside `verify_ttl`.
    if super::runtime(ctx.app)
        .pool
        .triggers
        .take_if_pending(&subject)
    {
        crate::mcp::connect::invalidate(&cache, &subject);
    }
    ctx.app
        .mcp_verify
        .ensure_fresh(
            &subject,
            &policy,
            now_ms,
            || crate::mcp::connect::ledger_of(&cache, &subject),
            || async move {
                match crate::mcp::connect::refresh(&pool, &cache_fetch, &server).await {
                    Ok(report) => {
                        // Record that verify-on-call LOOKED, whatever it saw, so reuse is bounded to
                        // `verify_ttl` and a failed contact is not re-fetched on every call within it.
                        crate::mcp::connect::stamp(
                            &cache_fetch,
                            &server.id,
                            now_ms,
                            !report.drift.is_empty(),
                        );
                        // WRITE THE DURABLE DEMOTION (or clear it when serving again), exactly as the
                        // sweep did: the request path is now what compares a live observation to the
                        // approval, so it is what must persist the result. The RULE lives in
                        // `quarantine::settle`, shared with the admin `connect` verb, so one call site
                        // cannot record a demotion the other never clears. It keeps a demoted tool
                        // UN-ADVERTISED across a restart (`tools/list` does not itself re-verify).
                        // Routed through the host drift veneer, the shared body the extern-C
                        // `drift_quarantine` slot also funnels through — one settle rule, one seam.
                        crate::plane_host::trust::quarantine_drift(
                            &demotions,
                            &server.id,
                            report.state,
                        );
                        if report.failure.is_some() {
                            // UNREACHABLE at verify → the gate below refuses fail-closed; latch the
                            // diagnostic so a persistent outage logs once.
                            gate.report(crate::plane::Plane::Mcp, &server.id, false, true);
                        } else if report.drift.is_empty() {
                            // A clean re-verification re-arms the latch so the NEXT drift is announced.
                            gate.report(crate::plane::Plane::Mcp, &server.id, false, false);
                        } else {
                            gate.report(crate::plane::Plane::Mcp, &server.id, true, false);
                        }
                    }
                    // NEVER ATTEMPTED (an unroutable id, or a `passthrough` credential the verify path
                    // has no caller for). Not stamped and not a fail-closed refusal on its own — the
                    // same case the daemon logged as `NotAttempted`; the configured-hash compare then
                    // applies exactly as before.
                    Err(_refusal) => {}
                }
            },
        )
        .await;
}

/// `tools/call` — DISPATCH. See the module header for the ordering and why it is that ordering.
async fn tools_call(
    ctx: &Ctx<'_>,
    params: Option<&serde_json::Value>,
    id: Option<serde_json::Value>,
) -> Response {
    let selected_gen = super::runtime(ctx.app).catalogue.generation();
    let Some(name) = string_param(params, "name") else {
        // THE CALLER IS ALREADY AUTHENTICATED HERE, so a malformed request is still one this
        // principal made and still belongs in their chain. `tool` and `server` stay empty, which is
        // what `McpCallRecord` documents as "a refusal that matched no registration".
        let log = CallLog::open(ctx, "", selected_gen);
        return log.refused(
            crate::plane::calllog::REASON_MALFORMED,
            invalid_params(id, "`params.name` is required and must be a string."),
        );
    };
    let mut log = CallLog::open(ctx, name, selected_gen);
    let mut arguments = params
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    // (0) VERIFY-ON-CALL. BEFORE the rug-pull digest compare below, ensure this tool's server has been
    // re-verified within `verify_ttl`: if the recorded observation is stale, single-flight a re-fetch
    // of the upstream's advertised tool list (concurrent stale-hits coalesce into one), fail-closed. A
    // fetch that fails records `Failed`, which the gate below refuses rather than serving past the
    // bound — verified BEFORE the call, not on some later tick. Keyed on the server the tool names,
    // ahead of the grant check because freshening a snapshot reveals nothing to the caller; the grant
    // refusal still lands, unchanged, in `resolve`. A `passthrough`-credential server cannot be
    // verified by this operator-style refresh (its credential is the caller's), so — exactly as the
    // old daemon did — that refusal leaves the snapshot as-is and the configured-hash compare applies.
    verify_on_call(ctx, name).await;

    // THE LIVE TOOL-LIST SIGHTINGS as of admission. This is the right-hand side of the rug-pull
    // comparison: with one, the gate below compares the operator's approved digest against what the
    // upstream is CURRENTLY serving, so a schema changed under a live cache refuses the call.
    // Without one — no refresh has ever run — it compares against the configured hash, exactly as
    // before.
    let admitted_sightings = super::runtime(ctx.app).sightings.load();
    // (1) ADMISSION on the snapshot this request arrived on.
    let selected = match super::runtime(ctx.app).catalogue.resolve(
        ctx.gov.key.as_deref(),
        LiveSightings::of(&admitted_sightings),
        name,
        crate::trust::validate::Generations::at_admission(selected_gen),
        crate::store::now(),
    ) {
        Ok(entry) => entry.clone(),
        Err(refusal) => {
            return log.refused(
                refusal.audit_reason(),
                refuse_catalogue(ctx, name, &refusal, id),
            )
        }
    };
    log.resolved(&selected, selected_gen);

    // (2) DISPATCH-TIME RE-VALIDATION against the LIVE snapshot. Re-read, not
    // re-use: `ctx.app` is the snapshot the request arrived on, and comparing it against itself
    // would be a check that cannot fail.
    let live = ctx.handle.load();
    // RE-READ the sightings too, not just the catalogue: a refresh that landed a drifted tool list
    // between admission and dispatch has to bite on THIS request. Re-reading only one of the two
    // would leave a window exactly as wide as the check it replaced.
    let live_sightings = super::runtime(&live).sightings.load();
    if let Err(refusal) = super::runtime(&live).catalogue.revalidate(
        ctx.gov.key.as_deref(),
        LiveSightings::of(&live_sightings),
        &selected,
        selected_gen,
        crate::store::now(),
    ) {
        return log.refused(
            refusal.audit_reason(),
            refuse_catalogue(ctx, name, &refusal, id),
        );
    }
    let Some(server) = super::runtime(&live)
        .catalogue
        .server(&selected.server)
        .cloned()
    else {
        let refusal = DispatchRefusal::UnknownTool(name.to_string());
        return log.refused(
            refusal.audit_reason(),
            refuse_catalogue(ctx, name, &refusal, id),
        );
    };

    // (2a-i) SEP-2243 CUSTOM PARAM HEADERS. Validated here, where the tool's approved `inputSchema`
    // is finally in hand, and BEFORE any decision that costs anything: a header/body disagreement is
    // a malformed request, and a malformed request must not be charged, dispatched or asked about.
    if let Some(refusal) = custom_param_mismatch(ctx, &selected, &arguments) {
        return log.refused("custom_param_mismatch", header_mismatch(id, &refusal));
    }

    // (2a-ii) THE TASKS GATE. A `task_support: required` tool CANNOT be answered synchronously, so a
    // caller that did not declare the extension is refused before the handler runs — which is what
    // makes the declaration a registration-time property rather than something busbar could work
    // out by trying. See `super::tasks`.
    if matches!(selected.task_support, super::config::TaskSupport::Required)
        && !super::tasks::client_declares_tasks(ctx.capabilities)
    {
        crate::admin::audit::AUDIT.record_by(
            "mcp_tool.call",
            &format!("mcp_tool:{}", selected.namespaced),
            crate::admin::audit::OUTCOME_REJECTED,
            ctx.actor,
        );
        return log.refused("tasks_capability_undeclared", missing_tasks_capability(id));
    }

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
            generation: super::runtime(&live).catalogue.generation(),
            arguments: &arguments,
        },
        params,
    ) {
        AskDecision::Proceed => {}
        AskDecision::Refuse(refusal) => {
            return log.refused(
                refusal.audit_reason(),
                refuse_ask(
                    ctx,
                    &format!("mcp_tool:{}", selected.namespaced),
                    &refusal,
                    id,
                ),
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
            // The govern grant rides the request-wide arena (`ctx.scope`) — released at request end,
            // the `Vec<AdmitGrant>` lifetime; a `None` scope (tests) uses a local arena dropped here.
            let fallback_scope = crate::plane_host::DispatchScope::new();
            let scope = ctx.scope.unwrap_or(&fallback_scope);
            if let Err(reason) = charge_round(
                ctx,
                &selected.namespaced,
                &RoundRecord {
                    round,
                    satisfied: None,
                },
                scope,
            ) {
                let refusal = DispatchRefusal::NotGranted(format!(
                    "this round of the input exchange was refused by your budget: {reason}"
                ));
                return log.refused(
                    "caller_ask_round_budget",
                    refuse_catalogue(ctx, name, &refusal, id),
                );
            }
            crate::admin::audit::AUDIT.record_by(
                "mcp.caller_ask",
                &format!("mcp_tool:{}", selected.namespaced),
                crate::admin::audit::OUTCOME_APPLIED,
                ctx.actor,
            );
            return log.refused(
                crate::plane::calllog::REASON_CALLER_ASK_PENDING,
                input_required_result(id, &asks, &request_state),
            );
        }
    }

    // (2b) THE ASK ANSWERS BECOME ARGUMENTS.
    //
    // An `ask_caller:` entry keyed `user_name` gathers a value, and the value is bound to the tool
    // argument of that name. That is what an operator writing the ask means by it: the point of
    // asking is that the answer reaches the tool. Discarding it — which is what busbar did — made
    // the whole exchange a gate with no output, and made it impossible to observe from the result
    // whether the round the caller answered had had any effect at all.
    //
    // AFTER `caller_ask_decision`, never before, and that ordering is load-bearing: the request
    // state is sealed over a digest of the arguments AS THE CALLER SENT THEM, so merging first
    // would make a retry's digest disagree with the seal minted on the previous round and every
    // multi-round exchange would fail verification on round two.
    //
    // AND THE MERGE IS BOUNDED BY WHAT THE OPERATOR ASKED FOR. This used to insert every key the
    // caller put in `inputResponses`, overwriting whatever was there — which meant the one thing the
    // seal covers, the arguments the confirmation was DISPLAYED about, could be rewritten on the way
    // past it. A caller shown "approve moving 10 to alice?" answered `{"amount": 1000000}` and the
    // upstream was told to move a million, with the digest check passing the whole way, because the
    // digest is taken over `arguments` and the rewrite arrived in a sibling field. An approval that
    // carries out a different call than the one it described is the same defect as an approval that
    // is not required at all.
    //
    // So: an answer may bind ONLY a key this capability's own `ask_caller:` rounds declared, and may
    // never name an argument the caller already sent. Anything else refuses the call rather than
    // being dropped — a caller whose answer is being ignored has to be told, or the next attacker to
    // try it learns nothing and the next honest client debugs a value that vanished.
    if let Some(responses) = params
        .and_then(|p| p.get("inputResponses"))
        .and_then(|v| v.as_object())
    {
        let declared: std::collections::BTreeSet<&str> = selected
            .ask_caller
            .iter()
            .flat_map(|round| round.keys().map(String::as_str))
            .collect();
        let sealed: std::collections::BTreeSet<String> = arguments
            .as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        if let Some(offending) = responses
            .keys()
            .find(|k| !declared.contains(k.as_str()) || sealed.contains(*k))
        {
            let refusal = DispatchRefusal::NotGranted(format!(
                "the answer named `{offending}`, which is not one of the inputs \
                 `{}` requested — an answer may only supply what was asked for, and may never \
                 rewrite an argument the confirmation was shown for.",
                selected.namespaced
            ));
            return log.refused(
                "caller_ask_answer_undeclared",
                refuse_catalogue(ctx, name, &refusal, id),
            );
        }
        if let Some(merged) = arguments.as_object_mut() {
            for (key, value) in responses {
                merged.insert(key.clone(), value.clone());
            }
        }
    }

    // (2b-i) THE OPERATOR'S HOOK GATE — `tools.hooks:` and `tools.<server>.hooks:`, fired here.
    //
    // ## Why HERE, and not three lines earlier or four lines later
    //
    // AFTER the ask answers are merged, because the gate must see the arguments THAT GO UPSTREAM.
    // Firing before the merge would screen the arguments the caller first sent and dispatch the
    // ones it supplied afterwards through `inputResponses` — a screen that inspects one payload
    // while a different one travels is the policy-enforcement-point bypass this release exists to
    // close, not a placement preference.
    //
    // BEFORE the task path, the egress gate and the loop, because a refusal must cost nothing: no
    // durable task row minted for work that will not happen, no token exchange, no socket. The same
    // ordering argument `authorise` makes about itself, one step earlier.
    //
    // AND ON THE DISPATCH PATH, never the catalogue — owner ruling 2. What a caller may SEE is
    // decided by its grants and by nothing else; a hook decides what a caller may DO.
    //
    // ZERO COST when nothing is attached: one hash lookup that misses.
    if let Some(gates) = ctx.app.mcp_server_gates.get(&selected.server) {
        // The IR this plane produces for an invocation, which is the ONLY thing the seam learns
        // about the request. The `arguments` clone is paid strictly behind an attached hook.
        let facts = crate::ir::invoke::InvokeReq {
            tool: selected.namespaced.clone(),
            arguments: arguments.clone(),
            extra: Default::default(),
        };
        let verdict = crate::hooks::gate::decide(
            gates,
            &crate::hooks::gate::GateSubject {
                facts: &facts,
                container: &selected.server,
                ingress_protocol: crate::plane::Plane::Mcp.key(),
                // The SAME id the per-call record carries, re-read rather than re-minted: a second
                // `next_request_id()` would hand the hook a number that joins to nothing.
                request_id: log.request_id.parse().unwrap_or_default(),
                key: ctx.gov.key.as_deref(),
                // Incremental scan (session substrate): screen only pieces this session has not
                // already had cleared for each hook. The session identity is the caller's
                // `x-session-id` — a neutral per-session convention, hashed by the core (store) hash,
                // never the LLM plane's affinity resolver. GATED: only when the operator opted in AND
                // a non-empty id is present; an ABSENT id must stay `None` (full re-scan), never a
                // constant key that would fold every sessionless caller into one shared cleared-set.
                incremental: {
                    let sid = ctx
                        .headers
                        .get("x-session-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    (ctx.app.incremental_scan && !sid.is_empty()).then(|| {
                        crate::hooks::gate::IncrementalScan {
                            store: &ctx.app.session_store,
                            session: crate::session::SessionKey(crate::store::fnv1a_u64(sid)),
                            now_ms: crate::store::now_ms(),
                        }
                    })
                },
            },
        )
        .await;
        if let crate::hooks::gate::GateVerdict::Reject {
            status,
            message,
            hook,
        } = verdict
        {
            crate::admin::audit::AUDIT.record_by(
                "mcp_tool.call",
                &format!("mcp_tool:{}", selected.namespaced),
                crate::admin::audit::OUTCOME_REJECTED,
                ctx.actor,
            );
            tracing::info!(
                tool = %selected.namespaced,
                hook,
                status,
                "mcp tools/call refused by a hook gate"
            );
            return log.refused(
                crate::plane::calllog::REASON_HOOK_REJECTED,
                error(
                    StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
                    id,
                    CODE_REFUSED,
                    &message,
                    Some(serde_json::json!({ "reason": crate::plane::calllog::REASON_HOOK_REJECTED, "hook": hook })),
                ),
            );
        }
    }

    // (2c) THE TASK PATH. Everything above has already decided that this call is admitted, current,
    // authorised to ask, and answered — so the only remaining question is whether the answer is a
    // RESULT or a TASK, and that is the operator's declaration crossed with the caller's.
    //
    // PLACED AFTER the ask loop deliberately, which is the SEP-2663 composition rule (commit
    // 451f5e1): a tool that gathers input synchronously and then escalates to async returns
    // `InputRequiredResult` on the early rounds — carrying no `taskId`, because no task exists yet
    // — and `CreateTaskResult` on the last. Creating the task first would mint an id for an
    // exchange that might never be answered, and would put a `requestState` and a `taskId` on the
    // wire together, which the extension separates precisely so a client need not deduplicate them.
    if selected
        .task_support
        .creates_task(super::tasks::client_declares_tasks(ctx.capabilities))
    {
        return create_task(ctx, &log, &server, &selected, arguments, id).await;
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
            Err(denied) => {
                return log.refused(
                    denied.audit_reason(),
                    refuse_setup(ctx, &selected.namespaced, &denied, id),
                )
            }
        };

    // (3b) THE BREAKER, THROUGH THE ONE SELECTION LOOP — `failover::walk` over this server's
    // candidate set, consulted BEFORE the loop and before any socket, exactly where the LLM walk
    // consults it before a lane. An un-pooled server is the degenerate single-member set (same
    // cell, same fast-fail, no reroute — the breaker unit's behaviour, unchanged); a `tool_pools:`
    // member walks its pool, so a tripped primary reroutes to its verified twin before the first
    // byte and the caller never learns. A pool with nothing admissible is refused HERE, in
    // milliseconds, as a JSON-RPC ERROR — the call never happened, so it is NEVER an `isError`
    // tool result (that shape says the tool ran, and the model would reason from a lie). The
    // outcome of each leg is recorded inside `upstream::call`, against the dispatched member's own
    // cell; the probe hold lives in the route and is released owner-checked when it drops.
    let breakers = std::sync::Arc::clone(&ctx.app.plane_breakers);
    let route = super::reroute::PoolRoute::build(
        &live,
        ctx.gov.key.as_deref(),
        &selected,
        authorised,
        &arguments,
    );
    if let Err(refused) = route.admit(&breakers, ctx.scope) {
        return log.refused(
            route_refusal_reason(&refused),
            refuse_route(id, &route, &refused),
        );
    }

    // (4) THE BOUNDED, METERED, PER-ROUND-GATED LOOP.
    //
    // Every concurrency hold `try_admit` takes now rides the request-wide dispatch arena (`ctx.scope`,
    // the SAME arena this `tools/call`'s breaker admission registers into) via the host
    // `govern_admit_reason` seam, so it lives exactly as long as the dispatch does and releases when
    // the request future ends — the lifetime the caller-held `Vec<AdmitGrant>` had, and never inside
    // the loop while the round it guards is still running. A `None` scope (unit tests) falls back to a
    // local arena that drops at this fn's return, the same drop point.
    let fallback_scope = crate::plane_host::DispatchScope::new();
    let scope = ctx.scope.unwrap_or(&fallback_scope);
    let server_id = selected.server.clone();
    let pool = super::runtime(ctx.app).pool.as_ref();
    let route_ref = &route;
    let outcome = inputreq::drive(
        &server_id,
        server.max_input_required_rounds,
        // The JSON-RPC id busbar puts on the OUTBOUND request is the round number, not the inbound
        // caller's id. An id chosen by the caller and echoed onto an upstream is a caller-controlled
        // value crossing a trust boundary for no reason.
        |round, satisfaction| {
            route_ref.dispatch(pool, &breakers, ctx.scope, &arguments, u64::from(round), satisfaction)
        },
        // THE GRANT, RE-READ LIVE ON EVERY ROUND. There is no handshake to authorise once and then
        // trust, so a revocation between rounds has to bite on the next one — which is the only
        // thing "per-request check" can mean when one logical dispatch is several requests.
        // Read for the member the route ACTUALLY dispatched to: a reroute moved the conversation
        // to the twin, and the twin's asks are judged against the twin's own operator grants.
        || {
            super::runtime(&ctx.handle.load())
                .catalogue
                .server(&route_ref.active_member())
                .map(|s| s.grants)
                .unwrap_or_default()
        },
        // SATISFYING an ask is a separate unit from making the call. A granted `roots` ask is
        // satisfied from the operator's own `tools.<server>.roots` declaration, and a granted
        // `sampling` ask from the operator's own `tools.<server>.sampling` policy — one governed
        // completion on the declared model, under THIS caller's key, budget and hooks, within the
        // per-upstream budget (see `super::sampling`). Both declarations are re-read LIVE off the
        // same snapshot the grant was. An `elicitation` needs a human busbar does not have and
        // keeps its refusal — and saying so is NOT the same as refusing the grant: `Unsatisfiable`
        // and `Ungranted` are different answers with different operator remedies, which is why
        // they are different arms. The ask still TERMINATES here in every arm: the caller is told
        // what busbar decided, never handed the ask.
        |ask| {
            // Satisfied for the member the route ACTUALLY dispatched to, not the selection's
            // nominal server: a reroute moved the conversation to the twin, and the twin's own
            // `roots`/`sampling` declarations are the ones its asks must be answered from.
            let member = route_ref.active_member();
            let live = ctx.handle.load();
            let entry = super::runtime(&live).catalogue.server(&member);
            let roots = entry.map(|s| s.roots.clone()).unwrap_or_default();
            let sampling = entry.and_then(|s| s.sampling.clone());
            let gov = ctx.gov.clone();
            async move {
                if ask.kind == "sampling" {
                    super::sampling::satisfy_upstream_ask(
                        &live,
                        &gov,
                        &ask,
                        &member,
                        sampling.as_ref(),
                    )
                    .await
                } else {
                    super::roots::satisfy_upstream_ask(&ask, &member, &roots)
                }
            }
        },
        |rec| charge_round(ctx, &selected.namespaced, rec, scope),
    )
    .await;
    // The route (and with it any un-consumed single-flight probe hold) drops at the end of this
    // function — or with the future, if the caller disconnected — releasing owner-checked either
    // way. A recorded outcome has already consumed it and the drop is then a no-op.

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
                crate::diagnostics::diag_error!(
                    crate::diagnostics::MCP_ASK_RECOGNISER_MISSED,
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
                return log.refused(
                    "ask_not_proxied",
                    error(
                        StatusCode::FORBIDDEN,
                        id,
                        CODE_REFUSED,
                        &format!(
                            "MCP server `{}` answered with an input-required result (`{field}`), \
                             which is a request that YOU spend authority on its behalf. An \
                             upstream's ask terminates at busbar and is never forwarded to you.",
                            selected.server
                        ),
                        Some(serde_json::json!({ "reason": "ask_not_proxied" })),
                    ),
                );
            }
            // (5b) THE OUTPUT SCHEMA busbar PUBLISHED, checked against what came back.
            //
            // Publishing an `outputSchema` makes conforming structured results a MUST for the
            // server that published it, and the caller only ever speaks to busbar — so a lying
            // upstream would put BUSBAR in violation, under busbar's name, with the caller unable
            // to attribute it. Relaying a structured result unchecked beneath a schema busbar
            // vouched for is the same mistake as republishing an upstream's description: it lets
            // the upstream edit what it was approved for.
            //
            // A VIOLATION IS A TOOL FAILURE, not a busbar refusal: the tool ran and did not do what
            // the operator approved it to do, and that is a fact about the run which the model has
            // to see. The check is one-sided by construction (`mcp::outputschema` ignores every
            // keyword it does not model), so this can only fire on a violation of the part of the
            // schema it does read.
            if let Some(schema) = &selected.output_schema {
                if let Some(structured) = value.get("structuredContent") {
                    if let Err(why) = super::outputschema::check(structured, schema) {
                        crate::diagnostics::diag_debug!(
                            crate::diagnostics::MCP_OUTPUT_SCHEMA_VIOLATION,
                            tool = %selected.namespaced,
                            why = %why,
                            "mcp upstream returned structuredContent violating the published outputSchema"
                        );
                        crate::admin::audit::AUDIT.record_by(
                            "mcp_tool.call",
                            &resource,
                            crate::admin::audit::OUTCOME_REJECTED,
                            ctx.actor,
                        );
                        return log.dispatched_with_reason(
                            crate::plane::calllog::REASON_UPSTREAM_FAILED,
                            result(
                                id,
                                upstream_failure_result(
                                    &selected.server,
                                    &format!(
                                        "it returned structured output that violates the \
                                         `outputSchema` this tool is published with ({why}). The \
                                         structured result was NOT served: a result that does not \
                                         conform to the schema busbar published for it would make \
                                         busbar's own answer unverifiable."
                                    ),
                                ),
                            ),
                        );
                    }
                }
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
            log.dispatched(result(id, sanitize::normalise_json(&value)))
        }
        Outcome::Refused(refusal) => {
            crate::admin::audit::AUDIT.record_by(
                "mcp_tool.call",
                &resource,
                crate::admin::audit::OUTCOME_REJECTED,
                ctx.actor,
            );
            crate::diagnostics::diag_debug!(
                crate::diagnostics::MCP_TOOLCALL_REFUSED,
                tool = %selected.namespaced,
                reason = refusal.audit_reason(),
                "mcp tools/call refused"
            );
            // Every arm is busbar-attributed. An upstream's ask is reported as busbar's refusal to
            // satisfy it, never handed onward for the caller to answer: an upstream's ask
            // TERMINATES at busbar, because proxying it would ask the caller to grant, on the
            // upstream's behalf, authority busbar itself just declined to spend.
            log.refused(
                refusal.audit_reason(),
                error(
                    match refusal {
                        Refusal::BudgetExhausted { .. } => StatusCode::TOO_MANY_REQUESTS,
                        _ => StatusCode::FORBIDDEN,
                    },
                    id,
                    CODE_REFUSED,
                    &refusal.to_string(),
                    Some(serde_json::json!({ "reason": refusal.audit_reason() })),
                ),
            )
        }
        // THE UPSTREAM FAILED, AND THAT IS A TOOL EXECUTION ERROR RATHER THAN BUSBAR'S REFUSAL.
        //
        // This arm used to be part of `Refused` above, and every one of its three consequences was
        // wrong about a different reader:
        //
        //   * THE MODEL was handed `-32000` / `403 FORBIDDEN` — busbar's refusal code — for a tool
        //     that had merely failed. The spec's own division is that protocol errors describe the
        //     REQUEST and tool execution errors describe the RUN, and that the latter are reported
        //     `in tool results with isError: true` precisely so the model can see the message and
        //     self-correct. A `403` says "you are not allowed to call this", which is false, and
        //     carries the failure text where nothing in the model's context will read it.
        //   * THE CALL LOG recorded `refused`, whose documented meaning is that THE CALL DID NOT GO
        //     OUT. It did go out. The record now says `dispatched` with the reason token
        //     `upstream_failed`, so the chain distinguishes a call busbar blocked from a call that
        //     was made and came back badly.
        //   * ANYTHING READING DISPOSITIONS could not tell a policy refusal from an upstream
        //     outage, so "we are being throttled" and "the far end is down" were one signal.
        //
        // The AUDIT row is still `OUTCOME_REJECTED`: the admin audit records whether the ACTION
        // succeeded, and this one did not.
        Outcome::UpstreamFailed(reason) => {
            crate::admin::audit::AUDIT.record_by(
                "mcp_tool.call",
                &resource,
                crate::admin::audit::OUTCOME_REJECTED,
                ctx.actor,
            );
            crate::diagnostics::diag_debug!(
                crate::diagnostics::MCP_TOOLCALL_UPSTREAM_FAILED,
                tool = %selected.namespaced,
                reason = %reason,
                "mcp tools/call upstream failed"
            );
            log.dispatched_with_reason(
                crate::plane::calllog::REASON_UPSTREAM_FAILED,
                result(id, upstream_failure_result(&selected.server, &reason)),
            )
        }
    }
}

/// The tool-execution-error RESULT busbar answers with when the upstream leg failed.
///
/// `isError: true` with the failure in a text content block, which is the shape the specification
/// names for a tool that ran and did not work, and the only shape a model ever reads. The text is
/// BUSBAR-ATTRIBUTED and names the server, because the caller needs to know which of busbar's
/// upstreams failed; it is not the upstream's own prose relayed as though it were busbar's, and it
/// is markup-normalised on the way out by the same rule every other upstream-influenced string is.
fn upstream_failure_result(server: &str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "resultType": "complete",
        "isError": true,
        "content": [{
            "type": "text",
            "text": sanitize::normalise(&format!(
                "The MCP server `{server}` did not complete this tool call: {reason}"
            )),
        }],
    })
}

/// CREATE a task for a `tools/call` that will be answered asynchronously.
///
/// The ordering here is the whole of `sep-2663-durable-create-strong-consistency`, and it is
/// stricter than "spawn then reply": the egress gate runs FIRST — so a caller with no grant is
/// refused synchronously and never learns a task id — then the row is written, then the runner is
/// attached, and only then is the id returned. A `tasks/get` issued with no delay after the
/// `CreateTaskResult` therefore always resolves, because the row existed before the id did.
async fn create_task(
    ctx: &Ctx<'_>,
    log: &CallLog<'_>,
    server: &super::catalogue::ServerEntry,
    selected: &ToolEntry,
    arguments: serde_json::Value,
    id: Option<serde_json::Value>,
) -> Response {
    // The SAME egress gate the synchronous path runs, in the same position relative to the network:
    // synchronous, reaching nothing, before anything is spent. A task must not be a way to get past
    // a check by being answered later.
    let authorised =
        match super::upstream::authorise(server, selected, &arguments, ctx.gov.key.as_deref()) {
            Ok(a) => a,
            Err(denied) => {
                return log.refused(
                    denied.audit_reason(),
                    refuse_setup(ctx, &selected.namespaced, &denied, id),
                )
            }
        };

    // THE BREAKER, at the same pre-network position the synchronous path consults it — through the
    // SAME walk, so a pooled tool's task is admitted to whichever verified twin is serving — and
    // BEFORE the task row is minted, because a pool with nothing admissible must be a refusal the
    // caller sees NOW, not a task id for work busbar already knows it will not dispatch. The
    // admitted member is FIXED for the task's whole life (`into_task_dispatch`): a task is one
    // conversation with one deployment, and its probe hold rides into the runner, which releases
    // it after its loop settles (a recorded outcome makes that a no-op).
    let breakers = std::sync::Arc::clone(&ctx.app.plane_breakers);
    let live_app = ctx.handle.load();
    let route = super::reroute::PoolRoute::build(
        &live_app,
        ctx.gov.key.as_deref(),
        selected,
        authorised,
        &arguments,
    );
    // The task path admits with NO sync scope: the won probe is held raw and then re-homed into the
    // runner's `DurableScope` by `into_task_dispatch`, where the detached leg settles it.
    if let Err(refused) = route.admit(&breakers, None) {
        return log.refused(
            route_refusal_reason(&refused),
            refuse_route(id, &route, &refused),
        );
    }
    let Some((authorised, cell, durable, admission_id, member_id)) =
        route.into_task_dispatch(&breakers)
    else {
        // Unreachable after a successful `admit`; refuse rather than panic on a caller's path.
        return log.refused(
            REASON_UPSTREAM_UNAVAILABLE,
            refuse_upstream_unavailable(id, &selected.server, 1),
        );
    };

    // CHARGED ONCE, HERE, and this is the only moment at which a refusal can still be reported to
    // the caller as a refusal. Once the `CreateTaskResult` is on the wire the request has been
    // answered, so a later budget failure could only be expressed by failing the task — which
    // reports a cost decision as an execution failure. See `tasks::run` for the other half.
    // The task path has NO sync `ctx.scope` (the request future ends the moment the task id is on the
    // wire), so the govern grant rides a SHORT-LIVED `DurableScope` opened just for this charge and
    // reclaimed immediately below — NOT the runner's durable scope, which holds the probe for the
    // task's whole life. The host `govern_admit_reason` seam registers the grant in this arena.
    let grant_scope = crate::plane_host::DurableScope::new();
    if let Err(reason) = charge_round(
        ctx,
        &selected.namespaced,
        &RoundRecord {
            round: 0,
            satisfied: None,
        },
        grant_scope.arena(),
    ) {
        // The budget said no AFTER the breaker admitted: the durable scope holding the probe drops on
        // this return, handing back a recovery probe this dispatch may have just won.
        let refusal =
            DispatchRefusal::NotGranted(format!("this task was refused by your budget: {reason}"));
        return log.refused(
            "task_budget",
            refuse_catalogue(ctx, &selected.namespaced, &refusal, id),
        );
    }
    // The admission hold is RELEASED rather than parked for the life of the task. A concurrency
    // slot models a request in flight, and the request ends here; holding it for a task that may
    // run for minutes would make the gauge report queue depth for something that is not queued. The
    // grant scope's reclaim releases the registered grant now — the old `drop(holds)`.
    drop(grant_scope);

    let task = super::tasks::TASKS.create(task_principal(ctx));
    let created = task.created();
    super::tasks::spawn(
        std::sync::Arc::clone(&task),
        super::tasks::Runner {
            pool: std::sync::Arc::clone(&super::runtime(ctx.app).pool),
            handle: std::sync::Arc::clone(ctx.handle),
            breakers,
            // The detached runner's host route: owns the app + the durable probe-hold + its id, so a
            // `breaker_settle` over `host.host_state()` reaches the durable admission, and the probe
            // releases owner-checked when the runner (and this guard) drop at task end.
            host: crate::plane_host::DurableHostDispatch::new(
                std::sync::Arc::clone(ctx.app),
                durable,
                admission_id,
            ),
            cell,
            authorised,
            arguments,
            // The ADMITTED member's id, not the caller-named one: the runner's per-round grant and
            // roots lookups must read the deployment the task actually runs against.
            server_id: member_id,
            max_rounds: server.max_input_required_rounds,
            task_asks: super::tasks::task_ask_rounds(selected, ctx.capabilities),
        },
    );
    crate::admin::audit::AUDIT.record_by(
        "mcp_tool.call",
        &format!("mcp_tool:{}", selected.namespaced),
        crate::admin::audit::OUTCOME_APPLIED,
        ctx.actor,
    );
    // RECORDED AS `refused`/`task_created`, and the module header for `calllog` says why: at the
    // moment this request is answered nothing has gone out. What the runner does next belongs to the
    // task's own provenance, not to a second per-call record under a request already answered.
    log.refused(
        crate::plane::calllog::REASON_TASK_CREATED,
        task_result(id, created),
    )
}

/// SEP-2243 §"Server Behavior for Custom Headers" — validate every `Mcp-Param-*` header this tool's
/// approved schema declares, against the body it is supposed to mirror.
///
/// Returns the refusal message, or `None` when the request is consistent.
///
/// ## What is being defended, and why it is not merely a formality
///
/// The header exists so an intermediary can route or shape on a parameter without parsing the body.
/// The moment the two can disagree, the intermediary and the executor are acting on two different
/// requests — the proxy rate-limits on `tenant: alpha` while the server runs the call for
/// `tenant: beta`. So a disagreement is not a nuisance to be reconciled by preferring one side; it
/// is a malformed request, and both sides being present and unequal is the case that matters.
///
/// The FOUR RULES, each of which the suite exercises separately:
///
/// 1. `=?base64?…?=` is decoded STRICTLY. Invalid padding or a non-alphabet character is a
///    rejection, not a best-effort decode — a lenient decoder makes two intermediaries disagree
///    about the same bytes.
/// 2. A value WITHOUT the complete wrapper is LITERAL. Not "looks like base64, try it": a value
///    that happens to be valid base64 must not be silently decoded into something else.
/// 3. The decoded value must equal the body's argument.
/// 4. A header OMITTED while the body carries the argument is a mismatch. The header is how the
///    intermediary sees the parameter, and a parameter it cannot see is one it cannot act on.
fn custom_param_mismatch(
    ctx: &Ctx<'_>,
    selected: &ToolEntry,
    arguments: &serde_json::Value,
) -> Option<String> {
    let properties = selected
        .input_schema
        .as_ref()?
        .get("properties")?
        .as_object()?;
    for (property, definition) in properties {
        let Some(suffix) = definition.get("x-mcp-header").and_then(|v| v.as_str()) else {
            continue;
        };
        let header_name = format!("mcp-param-{suffix}");
        let header = ctx
            .headers
            .get(&header_name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim);
        // The BODY value as a string. A non-string argument has no header rendering this revision
        // fixes, so it is left alone rather than stringified into a comparison busbar invented.
        let body = arguments.get(property).and_then(|v| v.as_str());
        match (header, body) {
            (None, None) => continue,
            (None, Some(_)) => {
                return Some(format!(
                    "`{property}` carries an `x-mcp-header` annotation, so a request whose body \
                     sets it must also carry the `Mcp-Param-{suffix}` header. Without it an \
                     intermediary routes on a parameter it cannot see."
                ))
            }
            (Some(_), None) => {
                return Some(format!(
                    "The `Mcp-Param-{suffix}` header is set but the body's `arguments.{property}` \
                     is absent or is not a string, so there is nothing for it to mirror."
                ))
            }
            (Some(header), Some(body)) => {
                let Some(decoded) = super::envelope::decode_param_sentinel(header) else {
                    return Some(format!(
                        "The `Mcp-Param-{suffix}` header carries a `=?base64?…?=` sentinel whose \
                         contents are not valid Base64. It is refused rather than decoded \
                         leniently: two intermediaries that disagree about the same bytes are two \
                         different requests."
                    ));
                };
                if decoded != body {
                    return Some(format!(
                        "The `Mcp-Param-{suffix}` header does not match the body's \
                         `arguments.{property}`."
                    ));
                }
            }
        }
    }
    None
}

/// The `HeaderMismatch` refusal, delegating to the ingress builder so the `-32020`/`400` pair
/// cannot drift between the envelope checks and this one.
fn header_mismatch(id: Option<serde_json::Value>, message: &str) -> Response {
    error(
        StatusCode::BAD_REQUEST,
        id,
        super::envelope::code::HEADER_MISMATCH,
        message,
        None,
    )
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
    scope: &crate::plane_host::DispatchScope,
) -> Result<(), String> {
    let (Some(_gov_state), Some(key)) = (ctx.app.governance.as_ref(), ctx.gov.key.as_ref()) else {
        // Governance disabled: no key, no budget, nothing to charge. The same posture the LLM path
        // takes, and the reason a deployment without governance still serves.
        return Ok(());
    };
    // ADMIT through the host `govern_admit_reason` seam (CLUSTER-4). The grant `try_admit` yields is
    // registered in `scope`'s dispatch arena (the request-wide arena the breaker admission already
    // rides, threaded through `Ctx::scope`), so it releases exactly when that arena reclaims — the
    // lifetime the caller-held `Vec<AdmitGrant>` had. The `Facts` carry this caller's REAL
    // `(key.id, key.group)`, so the host reconstructs the SAME enforcement chain
    // `try_admit(&ctx.app.cost, key, namespaced)` walks (`namespaced` is the pool); `tokens`/
    // `budget_remaining` are 0 so the POD gate is a no-op and the chain is the sole decider. On a
    // BLOCKED limit the host renders the SAME `format!("{blocked:?}")` bytes the in-place
    // `Err(format!("{blocked:?}"))` returned, so the operator-facing refusal is byte-identical.
    if let crate::plane_host::GovAdmit::Blocked { reason, .. } = crate::plane_host::govern_admit_reason_over(
        ctx.app,
        scope,
        namespaced.as_bytes(),
        key.id.as_bytes(),
        key.group.as_deref().map(str::as_bytes),
    ) {
        // Byte-identical to the in-place `Err(format!("{blocked:?}"))` the flip replaced.
        return Err(reason);
    }
    // ONE METERED, ATTRIBUTED EVENT PER ROUND, through the host `meter_charge` seam (CLUSTER-4). A
    // pure request meter with no token split (component `Queries` → `None`), so the recorded
    // `(key_id, model, provider)` row is byte-identical to the in-place
    // `record_metering(&key.id, namespaced, Plane::Mcp.key(), None, ..)`: `model` carries the
    // namespaced tool and `provider` the plane, so an existing cost dashboard groups MCP traffic
    // without knowing what MCP is. Fire-and-forget, exactly as the direct call was.
    let _ = crate::plane_host::with_borrowed_host(ctx.app, scope, |hctx, vt| {
        let usage = busbar_plugin::hot::Usage::with_attribution(
            busbar_plugin::hot::UsageComponent::Queries,
            0,
            0,
            busbar_plugin::hot::AdmissionId::NONE,
            key.id.as_bytes(),
            namespaced.as_bytes(),
            crate::plane::Plane::Mcp.key().as_bytes(),
        );
        (vt.meter_charge.unwrap())(hctx, &*usage as *const busbar_plugin::hot::Usage)
    });
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
    crate::diagnostics::diag_debug!(
        crate::diagnostics::MCP_TOOLCALL_REFUSED_PRE_UPSTREAM,
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
///
/// THE TRIPLE IS ASSEMBLED BY CORE and worded by `super::envelope::McpWords`. What is left here is
/// the two facts that were ever this plane's — which status each member of this taxonomy earns,
/// and the audit word that makes one refusal distinguishable from another afterwards. The sibling
/// plane's `refuse_admission` is the same two facts for its own taxonomy, which is what the
/// plane-coherence ledger's `refuse` row was pointing at: one shape, assembled twice.
fn refuse_catalogue(
    ctx: &Ctx<'_>,
    name: &str,
    refusal: &DispatchRefusal,
    id: Option<serde_json::Value>,
) -> Response {
    use crate::ingress::protocol::Words as _;
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
        // A PRINCIPAL THAT WENT STALE BETWEEN INGRESS AND DISPATCH is `401`: the caller is not being
        // told anything about the tool, it is being told to authenticate again. Folding it into the
        // `404` above would send a client re-checking its scopes when its credential is what expired.
        DispatchRefusal::IdentityNotLive(_) => StatusCode::UNAUTHORIZED,
        // A QUARANTINE is `403` and not `404`: the tool exists and this caller may see it, and what
        // changed is the upstream. Answering `404` would tell an operator debugging a rug-pull that
        // their registration had vanished.
        DispatchRefusal::NotApproved(_)
        | DispatchRefusal::NotPinned(_)
        | DispatchRefusal::Quarantined { .. } => StatusCode::FORBIDDEN,
    };
    super::envelope::McpWords.refuse(crate::ingress::protocol::CoreRefusal::Admission {
        id: id.unwrap_or(serde_json::Value::Null),
        status,
        message: refusal.to_string(),
        reason: Some(refusal.audit_reason()),
    })
}

/// The JSON-RPC code busbar answers a governance refusal with.
///
/// `-32000` is the first code in JSON-RPC's implementation-defined server-error range, which is what
/// a refusal by policy is: the request was well formed, the method exists, and the server declined.
/// `-32602` would say the arguments were wrong and `-32601` would say the method was missing, and
/// both would send an operator debugging the wrong thing.
pub(super) const CODE_REFUSED: i64 = -32000;

/// `MissingRequiredClientCapability` — the MCP-band sibling of `-32020` (header mismatch) and
/// `-32022` (unsupported protocol version). Emitted on ONE arm only; see the comment at its single
/// call site in `refuse_ask` for why this is one arm rather than a class.
const CODE_MISSING_CLIENT_CAPABILITY: i64 = -32021;
/// JSON-RPC standard: the params were structurally wrong.
const CODE_INVALID_PARAMS: i64 = -32602;

/// THE TRIPPED-UPSTREAM ERROR — the owner-agreed rendering for a tripped MCP upstream. In the
/// implementation-defined `-32000..-32099` band beside busbar's other extensions, because every
/// reserved code is wrong for a specific reason: `-32603` says busbar broke (it did not), `-32601`
/// says the tool does not exist (it does), `-32602` blames the caller. The call NEVER HAPPENED, so
/// this is a JSON-RPC error and never an `isError` tool result — see `refuse_upstream_unavailable`.
const CODE_UPSTREAM_UNAVAILABLE: i64 = -32030;

/// The call-log reason token for a breaker refusal. `refused` is exact here: the call did not go
/// out, which is precisely what that disposition documents.
const REASON_UPSTREAM_UNAVAILABLE: &str = "upstream_unavailable";

/// The tripped-server refusal: `503` + `Retry-After` (EXACT — the cell knows `until`, the same
/// shape budget uses with `429`) + [`CODE_UPSTREAM_UNAVAILABLE`], with structured `data` naming the
/// server and the wait. A JSON-RPC ERROR, never an `isError` result: `isError` says the tool RAN
/// and failed, and a model told that reasons from a lie.
fn refuse_upstream_unavailable(
    id: Option<serde_json::Value>,
    server: &str,
    retry_after_secs: u64,
) -> Response {
    let mut resp = error(
        StatusCode::SERVICE_UNAVAILABLE,
        id,
        CODE_UPSTREAM_UNAVAILABLE,
        &format!(
            "MCP server `{server}` is unavailable: its circuit breaker is open after repeated \
             failures; busbar did not dispatch this call. Retry after {retry_after_secs}s."
        ),
        Some(serde_json::json!({
            "reason": REASON_UPSTREAM_UNAVAILABLE,
            "server": server,
            "retry_after_ms": retry_after_secs.saturating_mul(1000),
        })),
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut()
            .insert(axum::http::header::RETRY_AFTER, v);
    }
    resp
}

/// Render a routed admission refusal. The availability shapes (`Empty`/`NoneAdmissible`) keep the
/// EXACT rendering the degenerate cell decided — 503 + `Retry-After` + `-32030` with structured
/// `data`, never an `isError` result — with `server` naming the pool when one is configured (the
/// pool is the unit the operator declared and the unit that has nothing left). A pin mismatch
/// (`NotInterchangeable`) is NOT an availability fact: it is the operator's same-deployment claim
/// failing busbar's check, so it carries the walk's own wording and its own reason token; 503 all
/// the same, because from the caller's seat the named tool cannot currently be served and nothing
/// was dispatched.
/// The per-call log's reason token for a routed admission refusal — the walk's own vocabulary for
/// a pin mismatch, the degenerate cell's established token for every availability shape (so the
/// un-pooled path's records are byte-identical to the breaker unit's).
fn route_refusal_reason(refused: &super::reroute::RouteRefused) -> &'static str {
    match &refused.refusal {
        crate::failover::Refusal::NotInterchangeable { .. } => refused.refusal.reason(),
        _ => REASON_UPSTREAM_UNAVAILABLE,
    }
}

fn refuse_route(
    id: Option<serde_json::Value>,
    route: &super::reroute::PoolRoute,
    refused: &super::reroute::RouteRefused,
) -> Response {
    if let crate::failover::Refusal::NotInterchangeable { .. } = &refused.refusal {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            id,
            CODE_UPSTREAM_UNAVAILABLE,
            &refused.refusal.to_string(),
            Some(serde_json::json!({
                "reason": refused.refusal.reason(),
                "server": route.display(),
            })),
        );
    }
    if route.pooled() {
        // The pooled wording in the log: every interchangeable member refused, not just "a server".
        tracing::info!(
            pool = %route.display(),
            refusal = %refused.refusal,
            "mcp tools/call refused: no pool member admissible"
        );
    }
    refuse_upstream_unavailable(id, route.display(), refused.retry_after_secs)
}

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
            ask.key().to_string(),
            serde_json::json!({ "method": ask.method(), "params": ask.params() }),
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

/// `resultType: "task"` — the THIRD and last discriminator busbar returns, and the third separate
/// constructor.
///
/// Three constructors rather than one with a parameter, for the reason [`result`] gives about the
/// second: which discriminator a caller receives is always a decision busbar took at a visible call
/// site, never a value that arrived from a third party and was passed through. [`result`] stamps
/// `complete` unconditionally, [`input_required_result`] can only be called with operator-composed
/// asks, and this one can only be called with a task busbar itself just created.
fn task_result(id: Option<serde_json::Value>, created: serde_json::Value) -> Response {
    use axum::response::IntoResponse as _;
    let mut value = created;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("resultType".into(), RESULT_TYPE_TASK.into());
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
    crate::diagnostics::diag_debug!(
        crate::diagnostics::MCP_CALLER_ASK_REFUSED,
        capability = %resource,
        reason = refusal.audit_reason(),
        "mcp caller-ask refused"
    );
    // `-32021` ON EXACTLY ONE ARM, and the narrowness is the whole correctness argument.
    //
    // `content_tests.rs` B6 records why this code is correctly WITHHELD when an UPSTREAM's ask is
    // refused: there the caller's capability is not what decides the outcome — the OPERATOR's grant
    // is — so a client that DOES declare the capability gets the byte-identical refusal, and an
    // earlier attempt that generalised the code turned a `403` policy refusal into a `400` blamed on
    // the caller. That path is `refuse_setup`, and it stays untouched.
    //
    // On THIS path the capability really is what stopped the request: busbar filtered its own minted
    // ask down to nothing, and sending an ask the caller cannot answer is exactly what
    // `PAT.MRTR.NO-UNDECLARED-CAPABILITY` forbids. So the caller IS the party who can act on it, and
    // naming the capability is the actionable answer rather than a leak of anything it could not
    // already infer from its own declaration.
    let (status, code, data) = match refusal {
        callerask::Refusal::StateRejected(_) => (
            StatusCode::BAD_REQUEST,
            CODE_INVALID_PARAMS,
            serde_json::json!({ "reason": refusal.audit_reason() }),
        ),
        callerask::Refusal::NoDeclaredCapability { required, .. } => {
            // A `ClientCapabilities` OBJECT, not a list of names: the schema defines the field as an
            // object of capability objects, and a client validating the error against that schema
            // cannot read an array. Same information, the shape the spec fixed for it.
            let caps: serde_json::Map<String, serde_json::Value> = required
                .iter()
                .map(|k| ((*k).to_string(), serde_json::json!({})))
                .collect();
            (
                StatusCode::BAD_REQUEST,
                CODE_MISSING_CLIENT_CAPABILITY,
                serde_json::json!({
                    "reason": refusal.audit_reason(),
                    "requiredCapabilities": caps,
                }),
            )
        }
        _ => (
            StatusCode::FORBIDDEN,
            CODE_REFUSED,
            serde_json::json!({ "reason": refusal.audit_reason() }),
        ),
    };
    error(status, id, code, &refusal.to_string(), Some(data))
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
        .map(|s| crate::plane::approvals::Sealer::derive(&s));
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
        {
            // The AUTHENTICATED PRINCIPAL (`mrtr.mdx:235`), which is the key's stable id and not
            // the actor string: the actor is for reading, the key id is what a grant is bound to.
            // With governance disabled there is no key, and the constant below is honest about
            // that — such a deployment has one principal, so binding to it is a true statement
            // rather than a fake distinction.
            let principal = ctx
                .gov
                .key
                .as_ref()
                .map_or("<ungoverned>", |k| k.id.as_str());
            Bind {
                principal,
                method,
                capability,
                generation,
                now: crate::store::now(),
                // The live roots epoch for THIS principal — the value a received
                // `notifications/roots/list_changed` moves, read under the same name the seal
                // binds. See `crate::mcp::roots`.
                roots_epoch: super::runtime(ctx.app).roots_epochs.current(principal),
            }
        },
        &crate::plane::approvals::digest_arguments(arguments),
        callerask::Approvals {
            sealer: sealer.as_ref(),
            spent: &ctx.app.plane_approvals,
        },
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
    super::envelope::error_response(status, id, code, message, data)
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

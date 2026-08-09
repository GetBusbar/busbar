// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JSON-RPC METHOD SURFACE — the CATALOGUE and the DISPATCH (owner ruling 4's vocabulary).
//!
//! The envelope is already settled by the time anything here runs: `ingress` has enforced `Origin`,
//! the mirrored headers, the protocol version and the JSON-RPC shape, and the auth middleware has
//! verified that the token's audience is this deployment (§15.2). What is left is the two questions
//! this module answers.
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
//! dispatched, per §3.11 (validate before audit) and §3.9a (re-validate at dispatch):
//!
//! 1. Resolve the namespaced name to a BOUND IDENTITY under the caller's grant, on the snapshot the
//!    request arrived on. Note the generation.
//! 2. Re-read the LIVE snapshot and re-validate against it (§14.2). A call whose identity was
//!    resolved under pin generation N is refused when the live generation is N+1 — this is the whole
//!    of the defence that §3.9b used to spell as session tombstoning, and under a stateless protocol
//!    it is the only one needed.
//! 3. Drive the bounded, metered, per-round-gated input-required loop (§14.3), charging the caller's
//!    own budget before each round.
//! 4. Audit the outcome — the VALIDATED decision, per §3.11, never a rejected call recorded as a
//!    successful route.
//!
//! ## What is honestly NOT here
//!
//! There is no upstream leg. The CLIENT direction (§2.1) is a separate unit and nothing in this
//! build opens a connection to an MCP server, so [`dispatch_upstream`] refuses with a
//! busbar-attributed error. Every step above it is real, runs, and is asserted on — admission,
//! grant scoping, generation re-validation, budget charging, metering, the ask gate and the audit
//! row all happen and are observable. What does not happen is the round trip. This is stated here
//! rather than hidden behind a stub that returns a plausible-looking result, because a fake result
//! would make every test above it pass for the wrong reason.

use axum::http::StatusCode;
use axum::response::Response;

use super::catalogue::{DispatchRefusal, ToolEntry};
use super::inputreq::{self, Outcome, Refusal, Round, RoundRecord};
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
    "resources/read",
];

/// Everything a method needs, gathered once so no handler reaches for a global.
pub(crate) struct Ctx<'a> {
    /// The snapshot this REQUEST arrived on. Selection reads it.
    pub(crate) app: &'a std::sync::Arc<crate::state::App>,
    /// The LIVE handle. Dispatch re-reads it, which is what makes §14.2's generation check a real
    /// re-read rather than a comparison of a value against itself.
    pub(crate) handle: &'a std::sync::Arc<crate::state::AppHandle>,
    /// The caller's resolved governance key. `None` when governance is disabled.
    pub(crate) gov: &'a crate::governance::GovCtx,
    /// The attributed principal, for the audit row.
    pub(crate) actor: &'a str,
}

impl Ctx<'_> {
    /// THE GRANT PREDICATE. One closure, built once, passed to every catalogue read, so the
    /// catalogue a caller sees and the tools it may dispatch are decided by the same function.
    ///
    /// A `None` key means governance is DISABLED for this deployment, and the answer is then "all
    /// scopes" — the same posture `pool_allowed` takes on the LLM plane for the same reason. That is
    /// not a fail-open on the MCP plane specifically: with governance off there is no key to carry a
    /// grant, and refusing everything would make an ungoverned deployment unable to serve at all.
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
pub(crate) fn dispatch(
    ctx: &Ctx<'_>,
    method: &str,
    params: Option<&serde_json::Value>,
    id: Option<serde_json::Value>,
) -> Option<Response> {
    match method {
        "server/discover" => Some(discover(ctx, id)),
        "tools/list" => Some(tools_list(ctx, id)),
        "tools/call" => Some(tools_call(ctx, params, id)),
        "prompts/list" => Some(prompts_list(ctx, id)),
        "prompts/get" => Some(prompts_get(ctx, params, id)),
        "resources/list" => Some(resources_list(ctx, id)),
        "resources/read" => Some(resources_read(ctx, params, id)),
        _ => None,
    }
}

/// `server/discover` — the MERGED, GRANT-SCOPED catalogue advertisement (§2.2).
///
/// Under `2026-07-28` there is no `initialize`, so this is the only capability advertisement there
/// is, and §14.4's rule applies to it like everything else: it is computed PER REQUEST from the
/// caller's own grant. Two callers discover two different servers. That is the point — a discovery
/// document that described the deployment rather than the caller would enumerate every registered
/// upstream to anyone who asked, which is a map of the operator's internal estate handed out for the
/// price of one token.
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
        serde_json::json!({
            "protocolVersion": super::ingress::PROTOCOL_VERSION,
            "serverInfo": { "name": "busbar", "version": env!("CARGO_PKG_VERSION") },
            // Advertised as present only when this caller can actually reach one. A capability
            // advertised to a caller who holds nothing under it is an invitation to a refusal.
            "capabilities": {
                "tools": { "listChanged": false },
                "prompts": { "listChanged": false },
                "resources": { "listChanged": false, "subscribe": false },
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
        }),
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
    result(id, serde_json::json!({ "tools": tools }))
}

/// One catalogue entry as the wire carries it. The description is MARKUP-NORMALISED here (§3.5):
/// this is the moment it is "shown or fed as context", which is exactly where §3.5 puts the strip.
fn render_tool(t: &ToolEntry) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    // The NAMESPACED name is the wire name, because it is the routing key (§3.0) and the value an
    // `mcp_tool` grant carries. Exposing the bare upstream name would let two servers collide in one
    // caller's catalogue, which is threat 3.
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
    // a client that pins what it saw is a client that notices a rug-pull too (§3.3).
    if let Some(h) = &t.schema_hash {
        obj.insert(
            "_meta".into(),
            serde_json::json!({ "io.busbar/schemaHash": h }),
        );
    }
    serde_json::Value::Object(obj)
}

/// `prompts/list`, sanitized per §3.5.
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
    result(id, serde_json::json!({ "prompts": prompts }))
}

/// `prompts/get` — the TEMPLATE, sanitized. §3.5 (auditor MCP-1 H9) adds prompt templates to the
/// sanitization set explicitly, because a template is exactly as injectable as tool output and the
/// prior draft covered neither.
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
    let text = sanitize::normalise(prompt.template.as_deref().unwrap_or(""));
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

/// `resources/list`, sanitized per §3.5.
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
            // first — threat 3 arriving through a key nobody thought of as a name.
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
    result(id, serde_json::json!({ "resources": resources }))
}

/// `resources/read` — the CONTENT, sanitized. The third member of §3.5's set.
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
        serde_json::json!({ "contents": [serde_json::Value::Object(content)] }),
    )
}

/// `tools/call` — DISPATCH. See the module header for the ordering and why it is that ordering.
fn tools_call(
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

    // (1) ADMISSION on the snapshot this request arrived on.
    let selected = match ctx.app.mcp_catalogue.resolve(&grant, name) {
        Ok(entry) => entry.clone(),
        Err(refusal) => return refuse(ctx, name, &refusal, id),
    };

    // (2) DISPATCH-TIME RE-VALIDATION against the LIVE snapshot (§3.9a / §14.2). Re-read, not
    // re-use: `ctx.app` is the snapshot the request arrived on, and comparing it against itself
    // would be a check that cannot fail.
    let live = ctx.handle.load();
    if let Err(refusal) = live
        .mcp_catalogue
        .revalidate(&grant, &selected, selected_gen)
    {
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

    // (3) THE BOUNDED, METERED, PER-ROUND-GATED LOOP.
    //
    // Every concurrency hold taken by `try_admit` is parked here so it lives exactly as long as the
    // dispatch does: an `AdmitGrant` releases its gauges on drop, and dropping it inside the loop
    // would return the slot while the round it guards is still running.
    let mut holds: Vec<crate::governance::AdmitGrant> = Vec::new();
    let server_id = selected.server.clone();
    let outcome = inputreq::drive(
        &server_id,
        server.max_input_required_rounds,
        |_round, _satisfaction| dispatch_upstream(&server.url, &selected, &arguments),
        // THE GRANT, RE-READ LIVE ON EVERY ROUND (§14.3 part 2). A revocation between rounds bites
        // on the next one, which is the only thing "per-request check" can mean when one logical
        // dispatch is several requests.
        || {
            ctx.handle
                .load()
                .mcp_catalogue
                .server(&server_id)
                .map(|s| s.grants)
                .unwrap_or_default()
        },
        // Satisfying an ask is the CLIENT direction's job (a granted `sampling` becomes a real LLM
        // request on busbar's pools). Nothing in this build can do it, and saying so is not the same
        // as refusing the grant — `Unsatisfiable` and `Ungranted` are different answers with
        // different operator remedies, which is why they are different arms.
        |ask| {
            Err(format!(
                "satisfying a `{}` ask requires the MCP client direction, which is not built in \
                 this release",
                ask.kind
            ))
        },
        |rec| charge_round(ctx, &selected, rec, &mut holds),
    );

    // (4) AUDIT the VALIDATED decision (§3.11).
    let resource = format!("mcp_tool:{}", selected.namespaced);
    match outcome {
        Outcome::Completed(value) => {
            crate::admin::audit::AUDIT.record_by(
                "mcp_tool.call",
                &resource,
                crate::admin::audit::OUTCOME_APPLIED,
                ctx.actor,
            );
            // Tool OUTPUT is markup-normalised before it re-enters model context (§3.5, threat 13).
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
            // satisfy it, never handed onward for the caller to answer — §14.3's termination rule.
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

/// CHARGE one round on the caller's own budget plane, then meter it.
///
/// The two halves are the LLM path's two halves, called the same way for the same reason: `try_admit`
/// is the hard cap (and charges the flat per-request fee), `record_metering` is the attributed
/// series. There is no MCP-specific budget and no MCP-specific meter — §2.2's "an inbound
/// `tools/call` authenticates with a busbar key exactly like an LLM request; the key's
/// budget/governance policy applies" is implemented by calling the same two functions.
///
/// The `pool` argument is the NAMESPACED TOOL. Pool-scoped budget buckets test it with
/// `applies_to_pool`, so an MCP call never matches a bucket an operator scoped to an LLM pool — the
/// key-level and group-level caps still apply, which is what "the same budget plane" means. Naming
/// the tool rather than a constant is what makes a future per-tool bucket expressible without
/// re-plumbing anything.
fn charge_round(
    ctx: &Ctx<'_>,
    selected: &ToolEntry,
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
    match gov_state.try_admit(&ctx.app.cost, key, &selected.namespaced, now) {
        Ok(grant) => holds.push(grant),
        Err(blocked) => return Err(format!("{blocked:?}")),
    }
    // ONE METERED, ATTRIBUTED EVENT PER ROUND. `model` carries the namespaced tool and `provider`
    // carries the plane, so an existing cost dashboard groups MCP traffic without knowing what MCP
    // is — which is the whole govern-first thesis in one call.
    gov_state.record_metering(
        &key.id,
        &selected.namespaced,
        crate::plane::Plane::Mcp.key(),
        None,
        now,
    );
    tracing::debug!(
        tool = %selected.namespaced,
        round = rec.round,
        satisfied = ?rec.satisfied,
        "mcp tools/call round metered"
    );
    Ok(())
}

/// THE UPSTREAM LEG, which does not exist in this release.
///
/// The CLIENT direction (§2.1) — transports, connection pooling, tool-list caching, credential
/// injection, RFC 8693 down-scoping — is a separate unit, and none of it is in this build. So this
/// refuses, with a reason that names the missing unit rather than a generic failure.
///
/// It is deliberately NOT a stub that returns a plausible result. A fake result would make the
/// admission, the generation re-validation, the grant gate, the budget charge and the audit row all
/// pass while proving nothing about any of them, which is precisely the false green a placeholder
/// buys.
fn dispatch_upstream(
    url: &str,
    selected: &ToolEntry,
    _arguments: &serde_json::Value,
) -> Result<Round, String> {
    let _ = (url, selected);
    Err("the MCP client direction (§2.1) is not built in this release, so busbar cannot reach the \
         registered upstream. Every governance check on this call ran and passed; the round trip is \
         what is missing."
        .to_string())
}

/// A refusal from the catalogue, rendered and audited. §3.11: the rejection is audited AS a
/// rejection, before anything could mistake it for a route.
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
        DispatchRefusal::NotApproved(_) | DispatchRefusal::NotPinned(_) => StatusCode::FORBIDDEN,
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
fn result(id: Option<serde_json::Value>, value: serde_json::Value) -> Response {
    use axum::response::IntoResponse as _;
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

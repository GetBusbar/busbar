// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RELAYED CALL, pure: one `tools/call` from the caller's request to the far end's answer, in the
//! served engine's order and words. Three steps, each a function the door calls on one piece:
//!
//! 1. [`admit`]: the caller's request judged against the generation's catalogue and the caller's
//!    grants (the `admit` predicate the door binds to the kernel's entitlement service), in the
//!    engine's order — the name, its length, the tool, the grant, the approval, the mirrored
//!    `Mcp-Param-*` headers, the tasks gate, and the answers to busbar's own asks. A refusal is the
//!    engine's status, envelope and call-log line.
//! 2. [`outbound`]: the request bound for the member the kernel's walk picked, built by the client
//!    dialect's own builder ([`crate::client::jsonrpc::tools_call`]). The credential is not here:
//!    the kernel's auth binding adds it when it sends.
//! 3. [`settle`]: the far end's answer read as the engine reads it — the last event of a streamed
//!    answer, the JSON-RPC correlation, an upstream's ask judged against the operator's grants and
//!    never forwarded, the published output schema, and the content normalised — into the
//!    caller's answer and its call-log line.
//!
//! What is not here is the kernel's: the trust lifecycle (pin, sightings, demotion), the hook gate
//! and rewrite, the outbound credential, the breaker and the pool walk, the budget and the meter.

use serde_json::{json, Map, Value};

use crate::catalogue::{granted, Catalogue, ToolEntry};
use crate::checks::decode_sentinel;
use crate::client::jsonrpc::{self as wire, AdvertisedCaps, RpcOutcome, ServerAsk};
use crate::codec::{
    CODE_HEADER_MISMATCH, CODE_INVALID_PARAMS, CODE_MISSING_CLIENT_CAPABILITY, CODE_REFUSED,
    META_CLIENT_CAPABILITIES,
};
use crate::identity::{ServerId, ToolKey};
use crate::jsonrpc::RESULT_TYPE_COMPLETE;
use crate::tool_arrival::Refusal;
use crate::tools_config::{
    McpServerDefCfg, RootCfg, TaskSupport, DEFAULT_MAX_INPUT_REQUIRED_ROUNDS,
};
use busbar_contract::vocab;

/// The audit reason of a call whose arguments the argument guard refused.
pub const REASON_TOOL_ARGUMENT_REFUSED: &str = "tool_argument_refused";

/// THE CEILING ON `params.name`, IN BYTES, checked before the per-call log opens: the name is
/// written verbatim into a durable, hash-chained record the instant any terminal fires, so an
/// oversized one is refused with no log line at all. Refused outright, never truncated: a truncated
/// name is a different tool.
pub const MAX_TOOL_NAME_BYTES: usize = 256;

/// The status of a successful answer.
const STATUS_OK: u32 = 200;
/// A malformed request.
const STATUS_BAD_REQUEST: u32 = 400;
/// A refusal by policy.
const STATUS_FORBIDDEN: u32 = 403;
/// Nothing there for this caller.
const STATUS_NOT_FOUND: u32 = 404;

/// The call-log reason of a call refused for a mirrored-header disagreement.
pub const REASON_CUSTOM_PARAM_MISMATCH: &str = "custom_param_mismatch";
/// The call-log reason of a `task_support: required` call from a caller that declared no tasks.
pub const REASON_TASKS_UNDECLARED: &str = "tasks_capability_undeclared";
/// The call-log reason of an answer naming an input busbar did not ask for.
pub const REASON_ANSWER_UNDECLARED: &str = "caller_ask_answer_undeclared";
/// The call-log reason of an upstream ask that reached the terminal check.
pub const REASON_ASK_NOT_PROXIED: &str = "ask_not_proxied";

/// The tasks extension's identifier.
pub const TASKS_EXTENSION_ID: &str = crate::answer::TASKS_EXTENSION_ID;

/// ONE LINE OF THE PER-CALL LOG, as the call ended: what it named, what it resolved to, and how it
/// ended. `server` and `tool_digest` stay empty on a refusal that never reached a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallLine {
    /// The server the call resolved to.
    pub server: String,
    /// The published tool name, or the name the caller asked for before resolution.
    pub tool: String,
    /// The approved digest the call rode.
    pub tool_digest: String,
    /// `dispatched` or `refused`.
    pub outcome: &'static str,
    /// The reason token; empty on a plain dispatch.
    pub reason: String,
}

impl CallLine {
    fn asked(name: &str, reason: &str) -> Self {
        CallLine {
            server: String::new(),
            tool: name.to_string(),
            tool_digest: String::new(),
            outcome: vocab::OUTCOME_REFUSED,
            reason: reason.to_string(),
        }
    }

    fn resolved(entry: &ToolEntry, outcome: &'static str, reason: &str) -> Self {
        CallLine {
            server: entry.server.clone(),
            tool: entry.namespaced.clone(),
            tool_digest: entry.schema_hash.clone().unwrap_or_default(),
            outcome,
            reason: reason.to_string(),
        }
    }
}

/// A call admitted: the entry it resolved to and the arguments that go upstream.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmittedCall {
    /// The catalogue entry.
    pub entry: ToolEntry,
    /// The arguments, with any declared answers merged in.
    pub arguments: Value,
    /// The caller's request id.
    pub id: Value,
    /// The caller's own `progressToken`, when it asked for progress.
    pub progress_token: Option<Value>,
}

/// What [`admit`] decided.
#[derive(Debug, Clone, PartialEq)]
pub enum Admission {
    /// AdmittedCall: the call goes to the far end.
    Go(AdmittedCall),
    /// Refused: the answer, and the call-log line (none for a name too long to record).
    Refused(Refusal, Option<CallLine>),
    /// Busbar asks its own caller first: the `input_required` answer and the call-log line.
    Asked(Vec<u8>, CallLine),
}

/// A JSON-RPC error answer.
fn error(status: u32, id: &Value, code: i64, message: String, data: Option<Value>) -> Refusal {
    Refusal {
        status,
        id: Some(id.clone()),
        code,
        message,
        data,
    }
}

/// A catalogue refusal: `-32000` with the audit reason in `data`.
fn catalogue_refusal(status: u32, id: &Value, message: String, reason: &str) -> Refusal {
    error(
        status,
        id,
        CODE_REFUSED,
        message,
        Some(json!({ "reason": reason })),
    )
}

/// The words of a tool the caller cannot reach: one sentence whether it does not exist or the
/// caller may not see it, so the catalogue does not leak what it hides.
fn not_exposed(name: &str) -> String {
    format!("`{name}` is not a tool this server exposes")
}

/// THE ANSWER TO A CALL THE CALLER IS NOT GRANTED, in the served engine's words: `404`, the same
/// sentence an unknown tool gets (the catalogue does not leak what it hides), its audit reason
/// `not_granted` in `data`. The kernel's grant check refuses such a call before the plane decides it
/// (`ScopeDenied`), and the plane renders that refusal as the served engine answered it.
#[must_use]
pub fn not_granted(id: &Value, name: &str) -> Refusal {
    catalogue_refusal(
        STATUS_NOT_FOUND,
        id,
        not_exposed(name),
        vocab::REASON_NOT_GRANTED,
    )
}

/// Whether the caller's `_meta` client capabilities declare the tasks extension.
#[must_use]
pub fn client_declares_tasks(capabilities: &Value) -> bool {
    capabilities
        .get("extensions")
        .and_then(|e| e.get(TASKS_EXTENSION_ID))
        .is_some_and(|v| !v.is_null())
}

/// The `-32021` refusal of a request that needs the tasks extension the caller did not declare:
/// `400`, which `MissingRequiredClientCapabilityError` fixes, naming what to add.
#[must_use]
pub fn missing_tasks_capability(id: &Value) -> Refusal {
    error(
        STATUS_BAD_REQUEST,
        id,
        CODE_MISSING_CLIENT_CAPABILITY,
        format!(
            "This request needs the `{TASKS_EXTENSION_ID}` extension, and it was not declared in \
             `params._meta.io.modelcontextprotocol/clientCapabilities.extensions`. Declare it — \
             per session or on this one request — and retry."
        ),
        Some(json!({
            "reason": "tasks_extension_not_declared",
            "requiredCapabilities": { "extensions": { TASKS_EXTENSION_ID: {} } },
        })),
    )
}

/// A TASKS VERB (`tasks/get`, `tasks/update`, `tasks/cancel`) on this plane: behind the `-32021`
/// gate, then `params.taskId`, then the task itself. The plane answers every call as a result and
/// holds no task (QUESTIONS FOLD-MCP-2-4), so every id names no task of this caller's: `-32602`, the one
/// answer for an id that does not exist and one that is another caller's.
#[must_use]
pub fn task_verb(id: &Value, params: Option<&Value>) -> Refusal {
    let capabilities = params
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(META_CLIENT_CAPABILITIES))
        .unwrap_or(&Value::Null);
    if !client_declares_tasks(capabilities) {
        return missing_tasks_capability(id);
    }
    let message = match params.and_then(|p| p.get("taskId")).and_then(Value::as_str) {
        None => "`params.taskId` is required and must be a string.",
        Some(_) => "No task with that `taskId` exists for this caller.",
    };
    error(
        STATUS_BAD_REQUEST,
        id,
        CODE_INVALID_PARAMS,
        message.to_string(),
        None,
    )
}

/// SEP-2243: the first disagreement between a tool's `x-mcp-header` properties and the caller's
/// `Mcp-Param-*` headers, in the engine's words. `header` reads a request head field by its
/// lower-case name.
#[must_use]
pub fn custom_param_mismatch(
    entry: &ToolEntry,
    arguments: &Value,
    header: &impl Fn(&str) -> Option<String>,
) -> Option<String> {
    let properties = entry
        .input_schema
        .as_ref()?
        .get("properties")?
        .as_object()?;
    for (property, definition) in properties {
        let Some(suffix) = definition.get("x-mcp-header").and_then(|v| v.as_str()) else {
            continue;
        };
        // The reader takes the lower-case name; the engine's head lookup was case-insensitive.
        let header_name = format!("mcp-param-{}", suffix.to_ascii_lowercase());
        let value = header(&header_name);
        let header_value = value.as_deref().map(str::trim);
        let body = arguments.get(property).and_then(|v| v.as_str());
        match (header_value, body) {
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
            (Some(header_value), Some(body)) => {
                let Some(decoded) = decode_sentinel(header_value) else {
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

/// ADMIT ONE CALL, in the engine's order. `header` reads a request head field by its lower-case
/// name; `admit` is the caller's grant predicate (scope kind, name); `ask` is busbar's own ask
/// decision for the resolved tool over the arguments as the caller sent them
/// ([`crate::ask::decide`]), made before any answer becomes an argument.
pub fn admit_call(
    catalogue: &Catalogue,
    id: &Value,
    params: Option<&Value>,
    header: &impl Fn(&str) -> Option<String>,
    admit: &impl Fn(&str, &str) -> bool,
    ask: &mut dyn FnMut(&ToolEntry, &Value) -> crate::ask::AskDecision,
) -> Admission {
    admit_trusted(
        catalogue,
        id,
        params,
        header,
        admit,
        &|_| None,
        &|_| false,
        ask,
    )
}

/// [`admit`], with THE TRUST GATE: `refused_as` answers, for the named tool, the trust state it is
/// refused as (`crate::trust::refused_as` over its registration's last sighting), or `None` when it
/// serves. Judged after the name, the grants and the approved digest, before the ask: a server that
/// is not approved serves nothing, and a refused dispatch never reaches the wire.
///
/// THE ARGUMENT GUARD ([`crate::argguard`]) judges the arguments that go out (the caller's, with
/// the operator-bounded answers merged) against the tool's approved input schema, under the
/// registration's `allow_private` (`allow_private` answers it for the tool): a URL or host the
/// call carries to an internal or metadata address is refused before the call is sent.
#[allow(clippy::too_many_arguments)] // `admit`'s five, the trust gate and the addressing policy
pub fn admit_trusted(
    catalogue: &Catalogue,
    id: &Value,
    params: Option<&Value>,
    header: &impl Fn(&str) -> Option<String>,
    admit: &impl Fn(&str, &str) -> bool,
    refused_as: &dyn Fn(&ToolEntry) -> Option<&'static str>,
    allow_private: &dyn Fn(&ToolEntry) -> bool,
    ask: &mut dyn FnMut(&ToolEntry, &Value) -> crate::ask::AskDecision,
) -> Admission {
    let Some(name) = params.and_then(|p| p.get("name")).and_then(Value::as_str) else {
        return Admission::Refused(
            error(
                STATUS_BAD_REQUEST,
                id,
                CODE_INVALID_PARAMS,
                "`params.name` is required and must be a string.".to_string(),
                None,
            ),
            Some(CallLine::asked("", vocab::REASON_MALFORMED)),
        );
    };
    if name.len() > MAX_TOOL_NAME_BYTES {
        return Admission::Refused(
            error(
                STATUS_BAD_REQUEST,
                id,
                CODE_INVALID_PARAMS,
                format!(
                    "`params.name` is {} bytes, longer than the {MAX_TOOL_NAME_BYTES} this \
                     deployment retains for a tool name. Refused before it reached the per-call \
                     log: a name this long would be written verbatim into a durable, hash-chained \
                     record.",
                    name.len()
                ),
                None,
            ),
            None,
        );
    }
    let mut arguments = params
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let Some(entry) = catalogue.tool(name) else {
        return Admission::Refused(
            catalogue_refusal(STATUS_NOT_FOUND, id, not_exposed(name), "unknown_tool"),
            Some(CallLine::asked(name, "unknown_tool")),
        );
    };
    if !granted(admit, &entry.server, &entry.namespaced) {
        return Admission::Refused(
            catalogue_refusal(
                STATUS_NOT_FOUND,
                id,
                not_exposed(name),
                vocab::REASON_NOT_GRANTED,
            ),
            Some(CallLine::asked(name, vocab::REASON_NOT_GRANTED)),
        );
    }
    // PENDING DOES NOT SERVE: a tool no digest was approved for is refused before it is sent. The
    // trust comparison proper (the approved digest against the live sighting, the pin) is the
    // kernel's; the approved digest is this section's own, so its absence is judged here
    // (QUESTIONS FOLD-MCP-2-1).
    let Some(_approved) = &entry.schema_hash else {
        return Admission::Refused(
            catalogue_refusal(
                STATUS_FORBIDDEN,
                id,
                format!(
                    "`{name}` is registered but no schema hash has been approved for it, so it is \
                     pending and does not serve"
                ),
                "not_approved",
            ),
            Some(CallLine::asked(name, "not_approved")),
        );
    };
    if let Some(state) = refused_as(entry) {
        return Admission::Refused(
            catalogue_refusal(
                STATUS_FORBIDDEN,
                id,
                format!(
                    "MCP server `{}` is {state}, so it serves nothing; work its changes queue and \
                     re-approve it",
                    entry.server
                ),
                state,
            ),
            Some(CallLine::resolved(entry, vocab::OUTCOME_REFUSED, state)),
        );
    }

    let line = |reason: &str| Some(CallLine::resolved(entry, vocab::OUTCOME_REFUSED, reason));
    let header_mismatch =
        |message: String| error(STATUS_BAD_REQUEST, id, CODE_HEADER_MISMATCH, message, None);
    if let Some(message) = custom_param_mismatch(entry, &arguments, header) {
        return Admission::Refused(header_mismatch(message), line(REASON_CUSTOM_PARAM_MISMATCH));
    }
    let meta = params.and_then(|p| p.get("_meta"));
    let capabilities = meta.and_then(|m| m.get(META_CLIENT_CAPABILITIES));
    if entry.task_support == TaskSupport::Required
        && !client_declares_tasks(capabilities.unwrap_or(&Value::Null))
    {
        return Admission::Refused(missing_tasks_capability(id), line(REASON_TASKS_UNDECLARED));
    }
    // BUSBAR'S OWN ASK, decided over the arguments as the caller sent them: the state is sealed over
    // their digest, so the answers are merged only after it.
    match ask(entry, &arguments) {
        crate::ask::AskDecision::Proceed => {}
        crate::ask::AskDecision::Refuse(refusal) => {
            return Admission::Refused(refusal.refusal(id), line(refusal.audit_reason()));
        }
        crate::ask::AskDecision::Ask {
            asks,
            request_state,
            ..
        } => {
            return Admission::Asked(
                crate::ask::input_required_result(id, &asks, &request_state),
                CallLine::resolved(
                    entry,
                    vocab::OUTCOME_REFUSED,
                    vocab::REASON_CALLER_ASK_PENDING,
                ),
            );
        }
    }
    // THE ANSWERS BECOME ARGUMENTS, bounded by what the operator asked for: an answer may bind only
    // a key this tool's own `ask_caller:` rounds declared, and never an argument the caller sent.
    if let Some(responses) = params
        .and_then(|p| p.get("inputResponses"))
        .and_then(Value::as_object)
    {
        let declared: std::collections::BTreeSet<&str> = entry
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
            return Admission::Refused(
                catalogue_refusal(
                    STATUS_NOT_FOUND,
                    id,
                    format!(
                        "the answer named `{offending}`, which is not one of the inputs `{}` \
                         requested — an answer may only supply what was asked for, and may never \
                         rewrite an argument the confirmation was shown for.",
                        entry.namespaced
                    ),
                    vocab::REASON_NOT_GRANTED,
                ),
                line(REASON_ANSWER_UNDECLARED),
            );
        }
        if let Some(merged) = arguments.as_object_mut() {
            for (key, value) in responses {
                merged.insert(key.clone(), value.clone());
            }
        }
        if let Some(message) = custom_param_mismatch(entry, &arguments, header) {
            return Admission::Refused(
                header_mismatch(message),
                line(REASON_CUSTOM_PARAM_MISMATCH),
            );
        }
    }
    // THE ARGUMENT GUARD, on the arguments that go out. A tool that declared no schema is walked
    // against `{"type": "object"}`: the walk is value-driven, so declaring no schema narrows what it
    // calls "declared" and nothing else.
    let schema = entry
        .input_schema
        .clone()
        .unwrap_or_else(|| json!({ "type": "object" }));
    let policy = crate::argguard::SsrfPolicy {
        allow_private: allow_private(entry),
    };
    if let Err(refused) = crate::argguard::guard(&schema, &arguments, policy) {
        return Admission::Refused(
            error(
                STATUS_FORBIDDEN,
                id,
                crate::codec::CODE_REFUSED,
                refused.to_string(),
                Some(json!({ "reason": REASON_TOOL_ARGUMENT_REFUSED })),
            ),
            line(REASON_TOOL_ARGUMENT_REFUSED),
        );
    }
    Admission::Go(AdmittedCall {
        entry: entry.clone(),
        arguments,
        id: id.clone(),
        progress_token: meta
            .and_then(|m| m.get("progressToken"))
            .filter(|v| !v.is_null())
            .cloned(),
    })
}

/// THE `{tool, arguments}` PROJECTION of a `tools/call` body, as the hook kind reads an invocation:
/// the published name and the arguments as the caller sent them. `None` for any other body.
#[must_use]
pub fn invocation(body: &[u8]) -> Option<busbar_contract::ir::invoke::InvokeReq> {
    let value: Value = serde_json::from_slice(body).ok()?;
    if value.get("method")?.as_str()? != crate::codec::METHOD_TOOLS_CALL {
        return None;
    }
    let params = value.get("params")?;
    Some(busbar_contract::ir::invoke::InvokeReq {
        tool: params.get("name")?.as_str()?.to_string(),
        arguments: params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({})),
        extra: busbar_contract::ir::SourceScopedExtra::default(),
    })
}

/// A REQUEST-STAGE HOOK'S REWRITE, APPLIED TO A `tools/call` (`project`'s `rewrite`; BUSBAR-1.6.0.md
/// Part 3 section 12, "Hooks": the plane applies it in its own dialect and re-projects). The hook
/// stage hands the plane the hook's reply as `{"messages": [...], "tools": ...}`; an invocation has
/// one untrusted content member, its `arguments` object, and the rewrite REPLACES it under the
/// served engine's invoke rewrite contract: a `messages` entry's `content` (an object verbatim, or a
/// JSON string that parses to an object) or, for an entry with no `role`, the entry itself; the LAST
/// entry that yields an object wins.
///
/// `None` = not applied (no usable object, a body that is not a `tools/call`, a reply that is not
/// JSON): the unit proceeds with the body it had, as a rewrite that cannot be applied left the
/// served engine's call untouched. `Some` is the rewritten request, whole, with every member the
/// caller sent but `params.arguments` as it was.
#[must_use]
pub fn rewritten(body: &[u8], rewrite: &[u8]) -> Option<Vec<u8>> {
    let reply: Value = serde_json::from_slice(rewrite).ok()?;
    let mut arguments: Option<Value> = None;
    for message in reply.get("messages")?.as_array()? {
        let candidate = match message.get("content") {
            Some(content) => content,
            None if message.get("role").is_none() => message,
            None => continue,
        };
        let resolved = match candidate {
            Value::Object(_) => Some(candidate.clone()),
            Value::String(text) => serde_json::from_str::<Value>(text)
                .ok()
                .filter(Value::is_object),
            _ => None,
        };
        if resolved.is_some() {
            arguments = resolved;
        }
    }
    let arguments = arguments?;
    let mut request: Value = serde_json::from_slice(body).ok()?;
    if request.get("method").and_then(Value::as_str) != Some(crate::codec::METHOD_TOOLS_CALL) {
        return None;
    }
    let params = request.get_mut("params")?.as_object_mut()?;
    params.insert("arguments".to_string(), arguments);
    serde_json::to_vec(&request).ok()
}

/// One request bound for the far end: the verb, the target path the kernel joins onto the
/// member's base URL, the dialect's head fields and the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundCall {
    /// The verb.
    pub verb: &'static str,
    /// The target: the path (and query) of the member's registered URL.
    pub target: String,
    /// The head fields, lower-case names, in the order they are written.
    pub fields: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// The path and query of `url`: everything from the first `/` after the authority, or `/`.
#[must_use]
pub fn path_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    match rest.find(['/', '?']) {
        Some(at) if rest[at..].starts_with('/') => rest[at..].to_string(),
        Some(at) => format!("/{}", &rest[at..]),
        None => "/".to_string(),
    }
}

/// THE REQUEST FOR ONE ROUND to `member`'s registration `def`, with the continuation that answers
/// the previous round's ask. `None` when the member has no URL this plane can reach it at.
#[must_use]
pub fn outbound(
    admitted: &AdmittedCall,
    member: &str,
    def: &McpServerDefCfg,
    round: u32,
    continuation: Option<&Value>,
) -> Option<OutboundCall> {
    if def.url.is_empty() {
        return None;
    }
    let key = ToolKey::new(ServerId::new(member).ok()?, &admitted.entry.tool).ok()?;
    let request = wire::tools_call(
        &def.url,
        &key,
        &admitted.arguments,
        wire::dispatch_request_id(round),
        None,
        AdvertisedCaps {
            roots: def.grants.roots && !def.roots.is_empty(),
            sampling: def.grants.sampling && def.sampling.is_some(),
            progress: admitted.progress_token.is_some(),
        },
        continuation,
    );
    Some(OutboundCall {
        verb: "POST",
        target: path_of(&request.url),
        fields: request.headers,
        body: request.body,
    })
}

/// A relayed call whose upstream leg failed before an answer (`reason`, in the previous release's
/// words): the caller is answered the upstream-failure result, the call log names it dispatched and
/// failed.
#[must_use]
pub fn upstream_failed(admitted: &AdmittedCall, reason: &str) -> Settled {
    Settled::Answer {
        status: STATUS_OK,
        body: result(
            &admitted.id,
            upstream_failure_result(&admitted.entry.server, reason),
        ),
        line: CallLine::resolved(
            &admitted.entry,
            vocab::OUTCOME_DISPATCHED,
            vocab::REASON_UPSTREAM_FAILED,
        ),
    }
}

/// The payload of the LAST `data:` field in an event-stream body: a POST answered as a stream may
/// carry progress ahead of the response, and the response is what the stream was opened to
/// deliver. Multi-line `data:` fields are joined with `\n`; a body with no `data:` is empty, which
/// the JSON-RPC reader then reports as malformed.
#[must_use]
pub fn last_sse_data(raw: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);
    let mut current: Option<Vec<String>> = None;
    let mut last: Option<Vec<String>> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            current
                .get_or_insert_with(Vec::new)
                .push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
        } else if line.is_empty() {
            if let Some(done) = current.take() {
                last = Some(done);
            }
        }
    }
    if let Some(done) = current.take() {
        last = Some(done);
    }
    last.map(|parts| parts.join("\n").into_bytes())
        .unwrap_or_default()
}

/// Every `notifications/progress` frame in an event-stream body, in arrival order: the one
/// server-originated frame busbar relays to its own caller.
#[must_use]
pub fn progress_frames(raw: &[u8]) -> Vec<Value> {
    use crate::client::peer::{NotificationEffect, ServerMessage};
    String::from_utf8_lossy(raw)
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
        .filter(|frame| {
            matches!(
                crate::client::peer::classify(frame),
                Some(ServerMessage::Notification(n)) if n.effect() == NotificationEffect::RelayProgress
            )
        })
        .collect()
}

/// Which MRTR ask field, if any, a supposedly complete result still carries: the discriminator, or
/// either member that carries an ask's content.
#[must_use]
pub fn upstream_ask_field(value: &Value) -> Option<&'static str> {
    let obj = value.as_object()?;
    if obj.get("resultType").and_then(|v| v.as_str()) == Some("input_required") {
        return Some("resultType");
    }
    ["inputRequests", "requestState"]
        .into_iter()
        .find(|field| obj.contains_key(*field))
}

/// The tool-execution-error RESULT for an upstream leg that failed: `isError: true` with the
/// failure, busbar-attributed and naming the server, in a normalised text block.
#[must_use]
pub fn upstream_failure_result(server: &str, reason: &str) -> Value {
    json!({
        "resultType": "complete",
        "isError": true,
        "content": [{
            "type": "text",
            "text": crate::sanitize::normalise(&format!(
                "The MCP server `{server}` did not complete this tool call: {reason}"
            )),
        }],
    })
}

/// A success envelope with `resultType: complete` stamped on the result.
#[must_use]
pub fn result(id: &Value, mut value: Value) -> Vec<u8> {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("resultType".into(), RESULT_TYPE_COMPLETE.into());
    }
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".into(), "2.0".into());
    envelope.insert("id".into(), id.clone());
    envelope.insert("result".into(), value);
    serde_json::to_vec(&Value::Object(envelope)).unwrap_or_default()
}

/// Why busbar declined to carry an upstream's ask, in the engine's words. Every arm is
/// busbar-attributed: the ask terminates at busbar and is never forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskRefusal {
    /// The operator granted this server nothing for this kind of ask.
    Ungranted {
        /// The server.
        server: String,
        /// The ask's kind.
        kind: String,
    },
    /// The hard cap on input-required rounds was reached.
    RoundCapExceeded {
        /// The server.
        server: String,
        /// The cap.
        cap: u32,
    },
    /// Busbar held the grant and still could not satisfy the ask.
    Unsatisfiable {
        /// The server.
        server: String,
        /// The ask's kind.
        kind: String,
        /// Why.
        reason: String,
    },
}

impl std::fmt::Display for AskRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AskRefusal::Ungranted { server, kind } => write!(
                f,
                "MCP server `{server}` asked busbar to satisfy a `{kind}` request, and that grant \
                 is not held. Server-initiated asks are deny-by-default: set \
                 `tools.{server}.grants.{kind}: true` if the operator intends this server to spend \
                 busbar's authority that way. The ask was not forwarded to you — an upstream's ask \
                 terminates at busbar."
            ),
            AskRefusal::RoundCapExceeded { server, cap } => write!(
                f,
                "MCP server `{server}` returned more than {cap} input-required rounds for one \
                 dispatch. The cap is hard: an upstream that can ask indefinitely can amplify cost \
                 indefinitely. Raise `tools.{server}.max_input_required_rounds` only if this \
                 exchange genuinely needs more rounds."
            ),
            AskRefusal::Unsatisfiable {
                server,
                kind,
                reason,
            } => write!(
                f,
                "busbar holds the `{kind}` grant for MCP server `{server}` but could not satisfy \
                 the ask: {reason}"
            ),
        }
    }
}

impl AskRefusal {
    /// The stable audit reason word.
    #[must_use]
    pub fn audit_reason(&self) -> &'static str {
        match self {
            AskRefusal::Ungranted { .. } => "ask_ungranted",
            AskRefusal::RoundCapExceeded { .. } => "ask_round_cap",
            AskRefusal::Unsatisfiable { .. } => "ask_unsatisfiable",
        }
    }
}

/// SATISFY a granted `roots` ask from the operator's declared roots: MRTR's continuation members,
/// `inputResponses` keyed as the ask keyed its entries and the upstream's `requestState` echoed.
/// Any other kind keeps the standing refusal.
///
/// # Errors
///
/// Why the ask cannot be satisfied, in the engine's words.
pub fn satisfy_roots(
    kind: &str,
    payload: &Value,
    server: &str,
    roots: &[RootCfg],
) -> Result<Value, String> {
    if kind != "roots" {
        return Err(format!(
            "busbar holds the `{kind}` grant for this server but has no satisfier for that ask in \
             this release; the ask terminates here and is not proxied to you"
        ));
    }
    if roots.is_empty() {
        return Err(format!(
            "busbar holds the `roots` grant for server `{server}` and no `tools.{server}.roots` \
             list is declared, so there is nothing busbar may disclose; the ask terminates here \
             and is not proxied to you. Declare `tools.{server}.roots:` if the operator intends \
             this server to be told about a workspace."
        ));
    }
    let Some(requests) = payload.get("inputRequests").and_then(Value::as_object) else {
        return Err(
            "the upstream's roots ask names no `inputRequests` entry to address an answer to; \
             the ask terminates here"
                .to_string(),
        );
    };
    let answer = json!({
        "roots": roots
            .iter()
            .map(|r| match &r.name {
                Some(name) => json!({ "uri": r.uri, "name": name }),
                None => json!({ "uri": r.uri }),
            })
            .collect::<Vec<_>>(),
    });
    let mut responses = Map::new();
    for (entry, request) in requests {
        if request.get("method").and_then(Value::as_str) != Some("roots/list") {
            return Err(format!(
                "the upstream's ask mixes `roots/list` with a method busbar has no satisfier \
                 for; the ask terminates here (entry `{entry}`)"
            ));
        }
        responses.insert(entry.clone(), answer.clone());
    }
    if responses.is_empty() {
        return Err(
            "the upstream's roots ask carries an empty `inputRequests` map; the ask terminates \
             here"
                .to_string(),
        );
    }
    let mut continuation = Map::new();
    continuation.insert("inputResponses".to_string(), Value::Object(responses));
    if let Some(state) = payload.get("requestState") {
        continuation.insert("requestState".to_string(), state.clone());
    }
    Ok(Value::Object(continuation))
}

/// What one far-end answer came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Settled {
    /// The caller's answer: the status, the body and the call-log line.
    Answer {
        /// The status.
        status: u32,
        /// The body.
        body: Vec<u8>,
        /// The call-log line.
        line: CallLine,
    },
    /// The upstream asked for something busbar grants and can satisfy: the next round's
    /// continuation, and the kind it satisfies.
    Next {
        /// The continuation the next round carries.
        continuation: Value,
        /// The ask's kind.
        kind: &'static str,
    },
    /// The upstream asked for a completion busbar grants: a nested unit answers it.
    Sample {
        /// The ask's payload: the upstream's result.
        payload: Value,
    },
}

/// The kind word of an ask.
fn kind_word(kind: ServerAsk) -> &'static str {
    match kind {
        ServerAsk::Sampling => "sampling",
        ServerAsk::Elicitation => "elicitation",
        ServerAsk::Roots => "roots",
    }
}

/// SETTLE ONE ROUND's far-end answer. `status` is the far end's, `sse` = its answer is an event
/// stream, `round` the round it answered and `def` the registration of the member that answered.
#[must_use]
pub fn settle_call(
    admitted: &AdmittedCall,
    def: Option<&McpServerDefCfg>,
    status: u32,
    raw: &[u8],
    sse: bool,
    round: u32,
) -> Settled {
    let sent_id = wire::dispatch_request_id(round);
    let entry = &admitted.entry;
    let id = &admitted.id;
    let body = if sse {
        last_sse_data(raw)
    } else {
        raw.to_vec()
    };
    let failed = |reason: String| Settled::Answer {
        status: STATUS_OK,
        body: result(id, upstream_failure_result(&entry.server, &reason)),
        line: CallLine::resolved(
            entry,
            vocab::OUTCOME_DISPATCHED,
            vocab::REASON_UPSTREAM_FAILED,
        ),
    };
    match wire::parse_response(&body, sent_id) {
        RpcOutcome::Result(value) => completed(admitted, value),
        failure @ (RpcOutcome::Error { .. }
        | RpcOutcome::Malformed(_)
        | RpcOutcome::Uncorrelated(_)) => {
            failed(failure_reason(status, &failure).unwrap_or_default())
        }
        RpcOutcome::InputRequired { kind } => {
            let kind = kind_word(kind);
            let payload = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|v| v.get("result").cloned())
                .unwrap_or_else(|| json!({}));
            match judge_ask(admitted, def, round, kind, &payload) {
                Ok(settled) => settled,
                Err(refusal) => ask_refused(admitted, &refusal),
            }
        }
    }
}

/// Why one round's answer is an UPSTREAM FAILURE (the call went out and the far end did not answer
/// it), in the engine's words; `None` for a result or an ask.
fn failure_reason(status: u32, outcome: &RpcOutcome) -> Option<String> {
    match outcome {
        RpcOutcome::Error { code, message } => Some(format!(
            "MCP upstream answered JSON-RPC error {code}: {message}"
        )),
        RpcOutcome::Malformed(reason) => Some(format!(
            "MCP upstream returned HTTP {status} and a body that is not a JSON-RPC response: \
             {reason}"
        )),
        RpcOutcome::Uncorrelated(reason) => Some(format!(
            "MCP upstream returned HTTP {status} and a JSON-RPC response busbar cannot correlate \
             to this call: {reason}"
        )),
        RpcOutcome::Result(_) | RpcOutcome::InputRequired { .. } => None,
    }
}

/// What one round's far-end answer is to a TASK (SEP-2663's statuses, the served engine's task
/// runner): the tool's own result, which the task inlines as it came; an upstream failure, which
/// fails the task; or an ask, which the rounds already judged.
#[derive(Debug, Clone, PartialEq)]
pub enum Leg {
    /// The far end answered a result: `completed`, `isError` and all.
    Done(Value),
    /// The call went out and the far end did not answer it: `failed`, in the engine's words.
    Failed(String),
    /// The far end asked for something: the rounds settled it, and their answer says how.
    Asked,
}

/// The far end's answer to round `round` (`status`, the raw answer, `sse` = an event stream), as a
/// task reads it ([`Leg`]).
#[must_use]
pub fn leg_of(status: u32, raw: &[u8], sse: bool, round: u32) -> Leg {
    let body = if sse {
        last_sse_data(raw)
    } else {
        raw.to_vec()
    };
    let outcome = wire::parse_response(&body, wire::dispatch_request_id(round));
    if let Some(reason) = failure_reason(status, &outcome) {
        return Leg::Failed(reason);
    }
    match outcome {
        RpcOutcome::Result(value) => Leg::Done(value),
        _ => Leg::Asked,
    }
}

/// The call-log line of a call answered on the task path under `reason`: `refused`, because at the
/// moment the caller is answered nothing has gone out (the served engine recorded a task it created
/// as `refused`/`task_created`).
#[must_use]
pub fn task_line(entry: &ToolEntry, reason: &str) -> CallLine {
    CallLine::resolved(entry, vocab::OUTCOME_REFUSED, reason)
}

/// The ask judged: the bound, then the grant, then the satisfier.
fn judge_ask(
    admitted: &AdmittedCall,
    def: Option<&McpServerDefCfg>,
    round: u32,
    kind: &'static str,
    payload: &Value,
) -> Result<Settled, AskRefusal> {
    let server = admitted.entry.server.clone();
    let cap = def
        .and_then(|d| d.max_input_required_rounds)
        .unwrap_or(DEFAULT_MAX_INPUT_REQUIRED_ROUNDS);
    if round >= cap {
        return Err(AskRefusal::RoundCapExceeded { server, cap });
    }
    let grants = def.map(|d| d.grants).unwrap_or_default();
    if !grants.allows(kind) {
        return Err(AskRefusal::Ungranted {
            server,
            kind: kind.to_string(),
        });
    }
    if kind == "sampling" {
        return Ok(Settled::Sample {
            payload: payload.clone(),
        });
    }
    let roots = def.map_or(&[][..], |d| d.roots.as_slice());
    match satisfy_roots(kind, payload, &server, roots) {
        Ok(continuation) => Ok(Settled::Next { continuation, kind }),
        Err(reason) => Err(AskRefusal::Unsatisfiable {
            server,
            kind: kind.to_string(),
            reason,
        }),
    }
}

/// An upstream ask busbar declined: `403`, `-32000`, the refusal's words and reason.
#[must_use]
pub fn ask_refused(admitted: &AdmittedCall, refusal: &AskRefusal) -> Settled {
    let reason = refusal.audit_reason();
    Settled::Answer {
        status: STATUS_FORBIDDEN,
        body: catalogue_refusal(STATUS_FORBIDDEN, &admitted.id, refusal.to_string(), reason).body(),
        line: CallLine::resolved(&admitted.entry, vocab::OUTCOME_REFUSED, reason),
    }
}

/// A finished result: the terminal ask check, the published output schema, then the normalised
/// content.
fn completed(admitted: &AdmittedCall, value: Value) -> Settled {
    let entry = &admitted.entry;
    let id = &admitted.id;
    if let Some(field) = upstream_ask_field(&value) {
        return Settled::Answer {
            status: STATUS_FORBIDDEN,
            body: catalogue_refusal(
                STATUS_FORBIDDEN,
                id,
                format!(
                    "MCP server `{}` answered with an input-required result (`{field}`), which is \
                     a request that YOU spend authority on its behalf. An upstream's ask \
                     terminates at busbar and is never forwarded to you.",
                    entry.server
                ),
                REASON_ASK_NOT_PROXIED,
            )
            .body(),
            line: CallLine::resolved(entry, vocab::OUTCOME_REFUSED, REASON_ASK_NOT_PROXIED),
        };
    }
    if let (Some(schema), Some(structured)) = (&entry.output_schema, value.get("structuredContent"))
    {
        if let Err(why) = crate::outputschema::check(structured, schema) {
            return Settled::Answer {
                status: STATUS_OK,
                body: result(
                    id,
                    upstream_failure_result(
                        &entry.server,
                        &format!(
                            "it returned structured output that violates the `outputSchema` this \
                             tool is published with ({why}). The structured result was NOT served: \
                             a result that does not conform to the schema busbar published for it \
                             would make busbar's own answer unverifiable."
                        ),
                    ),
                ),
                line: CallLine::resolved(
                    entry,
                    vocab::OUTCOME_DISPATCHED,
                    vocab::REASON_UPSTREAM_FAILED,
                ),
            };
        }
    }
    Settled::Answer {
        status: STATUS_OK,
        body: result(id, crate::sanitize::normalise_json(&value)),
        line: CallLine::resolved(entry, vocab::OUTCOME_DISPATCHED, ""),
    }
}

#[cfg(test)]
#[path = "tests/call.rs"]
mod tests;

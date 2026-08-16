// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP `RequestHandler` AND ITS CELLS — MCP as a protocol in the matrix, not a plane beside it.
//!
//! ## WHAT THIS FILE IS EVIDENCE FOR
//!
//! MCP was first built as a parallel ingress path: 13,069 implementation lines under `mcp/`, with
//! zero `ProtocolReader`/`ProtocolWriter` implementations and zero `IrBlock`. Every concern the core
//! already owned — the guarded fetch, ingress admission, outbound credentials, the hash-chained
//! audit, the config-section container — was written a second time in that directory, which is what
//! the plane ledger in `scripts/structure-lint.sh` counts.
//!
//! This file is the other way of doing it, and it is deliberately the same size and shape as
//! `responses.rs`: a protocol declares which operations it serves, and the operations it does not
//! serve return `None`, which is a `404` through the standard no-handler path. Being IN the matrix
//! is what makes governance, budgets, audit, metrics, the breaker and failover apply — not a second
//! wiring of each.
//!
//! ## THE ONE GENUINELY MCP-SHAPED THING
//!
//! MCP frames every call in a JSON-RPC 2.0 envelope: `{jsonrpc, id, method, params}` in, and
//! `{jsonrpc, id, result}` or `{jsonrpc, id, error}` back. That framing is this protocol's dialect,
//! exactly as `{"messages": [...]}` is OpenAI's and `{"contents": [...]}` is Gemini's, and it is the
//! codec's whole job. It is NOT a reason for the engine to know MCP exists.
//!
//! **The envelope is read by [`crate::ingress::jsonrpc`], not re-implemented here.** That module
//! exists because the envelope had previously been parsed in two places that disagreed — the A2A
//! reader checked no `jsonrpc` member at all, and a malformed envelope was relayed to a backend
//! agent. One reader, two protocols.
//!
//! ## THE WIRE VOCABULARY IS `rmcp`'s, NOT A SECOND COPY OF IT
//!
//! Every method name and every parameter shape below comes from `rmcp`, the specification authors'
//! own crate, pinned with `default-features = false`. A method name typed as a string literal here
//! would be a second statement of what the protocol calls something, and the two statements can
//! disagree — which is how a gateway ends up serving a name the specification retired. Taking the
//! name off the SDK's own const-string type means the compiler holds the pair together.
//!
//! **The pin stays narrow, and that is part of the design rather than a default.** `rmcp`'s auth
//! feature is a second OAuth implementation beside busbar's own authorization server and its
//! admission verifier, and its transport features are a second HTTP client beside the one that does
//! busbar's resolve-then-pin. Two implementations of one security concern that can disagree is the
//! shape this release has already paid for three times. What is taken from the crate is the
//! protocol vocabulary and nothing else.
//!
//! ## WHAT IS NOT BUILT HERE, STATED RATHER THAN DISCOVERED
//!
//! This cell reads and writes the `tools/call` and subscription shapes. It does NOT yet carry the
//! catalogue, the schema pinning, the per-call audit chain or the arguments guard — those live in
//! `mcp/` today and are ported onto the core separately, each proven against the conformance suite.
//! A cell that quietly reimplemented them would be the original mistake a second time.
//!
//! **And one limit that is real and is not papered over:** the subscription verbs below are a
//! CODEC. A subscription is only a capability once there is a channel to be notified over, and the
//! revision's server→client stream is a surface of its own, not something a codec can supply. The
//! notification vocabulary is here so that the channel, when it is mounted, frames the same bytes
//! this cell already reads — not so that the surface can be claimed before it exists.

use bytes::Bytes;
use rmcp::model::{
    CallToolRequestMethod, ConstString, ResourceUpdatedNotificationMethod,
    ResourceUpdatedNotificationParam, SubscribeRequestMethod, SubscribeRequestParams,
    ToolListChangedNotificationMethod, UnsubscribeRequestMethod, UnsubscribeRequestParams,
};

use crate::handlers::IngressReject;
use crate::handlers::{CodecError, EgressCtx, OperationHandler, RequestHandler, WireBody};
use crate::ir::invoke::{InvokeReq, InvokeResp};
use crate::ir::subscribe::{SubscribeIntent, SubscribeReq, SubscribeResp};
use crate::ir::variant::{IrReq, IrResp};
use crate::operation::Operation;

/// The single mount path. MCP names the operation in the BODY (`method`), not the path — the
/// opposite of OpenAI, and the reason [`McpRequestHandler::resolve_operation`] reads the body.
const PATH_MCP: &str = "/mcp";

/// The JSON-RPC method names this file serves, each read off `rmcp`'s own const-string type rather
/// than spelled again here. `ConstString::VALUE` is a `const`, so these are compile-time literals
/// with no runtime cost — and a name the SDK retires stops compiling instead of being served.
const METHOD_TOOLS_CALL: &str = CallToolRequestMethod::VALUE;
const METHOD_RESOURCES_SUBSCRIBE: &str = SubscribeRequestMethod::VALUE;
const METHOD_RESOURCES_UNSUBSCRIBE: &str = UnsubscribeRequestMethod::VALUE;
const METHOD_NOTIFY_TOOLS_LIST_CHANGED: &str = ToolListChangedNotificationMethod::VALUE;
const METHOD_NOTIFY_RESOURCES_UPDATED: &str = ResourceUpdatedNotificationMethod::VALUE;

pub(crate) struct McpRequestHandler;

/// MCP'S DECLARATION — and the asymmetry in it is the point. MCP declares a HANDLER and NO CODEC:
/// its IR is its own, there is no cross-dialect translation into or out of it, and it point-reads no
/// top-level body key on the pre-materialized path (its method lives in the JSON-RPC envelope, which
/// `ingress::jsonrpc` parses). A registry that could only hold six-of-a-kind would have had to grow
/// a special case for it; this one holds a declaration that says `None` four times.
///
/// It lives here rather than under `proto/` because MCP has no `proto/mcp/` module — it is a
/// protocol without a wire codec, and its cells are the only thing core resolves for it.
pub(crate) const DECL: crate::proto::ProtocolDecl = crate::proto::ProtocolDecl {
    name: "mcp",
    codec: None,
    handler: Some(&McpRequestHandler),
    verbs: &[
        crate::operation::Operation::INVOKE,
        crate::operation::Operation::SUBSCRIBE,
    ],
    head_keys: &[],
    streaming_content_type: None,
    array_stream_shim_key: None,
    native_tool_id_prefix: None,
    ingress_auth: crate::proto::IngressAuth::Bearer,
    // NO PATH INGRESS: this dialect keeps its model in the BODY, so the catch-all resolves the
    // operation through the `RequestHandler` and serves it on the universal ingress.
    path_ingress: None,
    stream_usage_requires_opt_in: false,
};

/// The `(mcp, Invoke)` cell. One protocol, one operation, one codec.
static INVOKE: InvokeOperation = InvokeOperation;

/// The `(mcp, Subscribe)` cell — `resources/subscribe` and `resources/unsubscribe`, which are one
/// operation because they are one shape.
static SUBSCRIBE: SubscribeOperation = SubscribeOperation;

/// MCP'S ROW OF THE SUPPORT MATRIX — the verbs this protocol speaks, as data.
///
/// **THIS IS THE "NO MCP TO CHAT" RULE, in the only place it needs to exist.** MCP does not serve
/// chat, so there is no cell to translate an invocation into a chat completion through; the pair is
/// UNREPRESENTABLE rather than refused at runtime. The six chat protocols say the mirror image
/// about `Invoke` by leaving it out of their own rows.
///
/// **THE FOUR ABSENT PROTOCOL VERBS ARE NOT A "NO": THEY ARE A "NOT YET", AND THE DIFFERENCE IS
/// DELIBERATE.** MCP genuinely speaks all four — `tools/list` is `Catalogue`, `resources/read` is
/// `Fetch`, `tasks/get` is `Task`, `initialize` is `Control` — and each gets a cell of its own,
/// proven against the conformance suite. Until that cell exists, absence is the honest answer and
/// it is the SAME answer the chat protocols give. Inventing a row here to make the matrix look
/// complete would be the original `mcp/` mistake (a plane beside the pipeline) in a smaller box,
/// and `resolve_operation` below still returns `None` for those methods, so nothing can reach a
/// handler that is not there.
///
/// **AND THIS IS THE DELETION TEST.** Deleting MCP deletes this table and its two codecs; no core
/// type names a single MCP verb, because the verbs are values in this file.
static CELLS: &[crate::handlers::Cell] = &[
    (Operation::INVOKE, &INVOKE),
    (Operation::SUBSCRIBE, &SUBSCRIBE),
];

impl RequestHandler for McpRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "mcp"
    }

    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        crate::handlers::cell_of(CELLS, op)
    }

    fn upstream_path(&self, _ctx: &EgressCtx) -> String {
        PATH_MCP.into()
    }

    /// THE OPERATION IS IN THE BODY, not the path — so this is one of the handlers that reads it.
    /// The signature already allowed for this (`body: &[u8]`); Bedrock and Cohere use it too.
    ///
    /// An unparseable body or an unknown method is `None`, which is the standard no-operation
    /// `404`. It is deliberately NOT a JSON-RPC error from here: this function answers "which
    /// operation is this", and a body that names no operation busbar serves has not yet reached the
    /// point where a protocol-shaped refusal would be meaningful.
    fn resolve_operation(&self, path: &str, body: &[u8]) -> Option<Operation> {
        if !path.ends_with(PATH_MCP) {
            return None;
        }
        let v: serde_json::Value = serde_json::from_slice(body).ok()?;
        match v.get("method")?.as_str()? {
            METHOD_TOOLS_CALL => Some(Operation::INVOKE),
            // BOTH DIRECTIONS OF ONE REGISTRATION ARE ONE OPERATION. The codec reads the intent
            // back off the method name; the engine never learns there were two names.
            METHOD_RESOURCES_SUBSCRIBE | METHOD_RESOURCES_UNSUBSCRIBE => Some(Operation::SUBSCRIBE),
            _ => None,
        }
    }
}

/// The `tools/call` codec. Feed it wire, assert the IR; feed it IR, assert the wire.
pub(crate) struct InvokeOperation;

impl OperationHandler for InvokeOperation {
    /// A tool call is one exchange, so every capability default (no streaming, no stream intent, no
    /// affinity, no usage tap) is already correct and none is overridden. That is the matrix
    /// working: the restrictive defaults mean a new cell cannot accidentally claim a behaviour.
    ///
    /// `taps_usage` stays FALSE deliberately. A tool server reports no tokens, so there is no usage
    /// to tap out of the body — a tool call is flat-metered, which `IrResp::usage` states.
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let v: serde_json::Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        // The envelope's own validity is `ingress::jsonrpc`'s business and has already been decided
        // before a body reaches a codec; what this reader owns is the `params` shape.
        let params = v.get("params").ok_or_else(|| {
            IngressReject::BadRequest("a tools/call carries a `params` member".to_string())
        })?;
        let tool = params
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                IngressReject::BadRequest(
                    "a tools/call names the tool in `params.name`".to_string(),
                )
            })?
            .to_string();
        Ok(IrReq::Invoke(InvokeReq {
            tool,
            // ABSENT ARGUMENTS ARE AN EMPTY OBJECT, not an error: a tool that takes none is called
            // with none, and rejecting that would refuse a legal call.
            arguments: params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
            extra: Default::default(),
        }))
    }

    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Invoke(r) = ir else {
            // A cell is only ever handed its own operation's IR — the matrix lookup is what
            // guarantees it. Reaching this arm means the matrix was bypassed, which is a bug in the
            // engine and not something to paper over with a plausible default.
            return Bytes::new();
        };
        // The `id` is the ENGINE's, not the caller's: correlation is decided on the way out and
        // read back by `ingress::jsonrpc::read_response`, which refuses an answer that names a
        // different request. A relay that echoed the caller's id would let a backend's reply to one
        // conversation be served as another's.
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": METHOD_TOOLS_CALL,
                "params": { "name": r.tool, "arguments": r.arguments },
            }))
            .unwrap_or_default(),
        )
    }

    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: serde_json::Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let result = v
            .get("result")
            .ok_or_else(|| CodecError::Malformed("no `result` member".to_string()))?;
        Ok(IrResp::Invoke(InvokeResp {
            content: result
                .get("content")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([])),
            // THE TOOL'S OWN VERDICT, and it is not the protocol's. `isError` on a successful
            // exchange means the tool ran and failed; a call that could not be made at all is a
            // refusal that never produces an `IrResp`. Collapsing the two tells a caller their
            // request was malformed when their tool merely returned an error.
            is_error: result
                .get("isError")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            structured: result.get("structuredContent").cloned(),
            extra: Default::default(),
        }))
    }

    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Invoke(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let mut result = serde_json::json!({ "content": r.content, "isError": r.is_error });
        // Carried, never synthesised: busbar models no output schema, so it emits structured
        // content only when the tool produced some.
        if let Some(s) = &r.structured {
            result["structuredContent"] = s.clone();
        }
        WireBody::json(Bytes::from(
            serde_json::to_vec(&serde_json::json!({ "jsonrpc": "2.0", "result": result }))
                .unwrap_or_default(),
        ))
    }
}

/// The subscription codec — `resources/subscribe` and `resources/unsubscribe`, on `rmcp`'s own
/// parameter types.
///
/// ## WHY THE TWO METHODS SHARE ONE CELL
///
/// They are the same request with the registration pointing the other way: the same target name,
/// the same acknowledgement, the same admission question. Two cells would be two places to decide
/// what a target name is, and the pair is meaningless the moment those two answers differ.
///
/// ## WHY THE PARAMS ARE DESERIALIZED INTO `rmcp`'s STRUCTS RATHER THAN READ FIELD BY FIELD
///
/// A hand-read `params["uri"]` accepts shapes the specification does not — a missing member read as
/// an empty string, a number read as a name — and each acceptance is a difference between what
/// busbar serves and what the specification says. Deserializing into the SDK's own parameter type
/// makes the SDK's schema the acceptance test, so a body busbar admits is a body the protocol
/// admits. The `_meta` member rides along on those types for the same reason.
pub(crate) struct SubscribeOperation;

impl SubscribeOperation {
    /// The wire method name for an intent. The pair is decided in exactly one place so the reader
    /// and the writer cannot come to disagree about which name means which direction.
    fn method_for(intent: SubscribeIntent) -> &'static str {
        match intent {
            SubscribeIntent::Register => METHOD_RESOURCES_SUBSCRIBE,
            SubscribeIntent::Deregister => METHOD_RESOURCES_UNSUBSCRIBE,
        }
    }
}

impl OperationHandler for SubscribeOperation {
    /// A registration is one exchange, so every capability default is already correct: no
    /// streaming, no stream intent, no affinity, no usage tap. `taps_usage` stays FALSE because
    /// there are no tokens to tap — the response is an acknowledgement, and `IrResp::usage` states
    /// the flat meter that applies instead.
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let v: serde_json::Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        // The envelope's own validity is `ingress::jsonrpc`'s business and is decided before a body
        // reaches a codec. What this reader owns is which of the two verbs was named, and the
        // `params` shape that goes with it.
        let method = v
            .get("method")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                IngressReject::BadRequest(
                    "a subscription request names its method in `method`".to_string(),
                )
            })?;
        let params = v.get("params").cloned().ok_or_else(|| {
            IngressReject::BadRequest(
                "a subscription request carries a `params` member".to_string(),
            )
        })?;
        // The SDK's parameter type IS the acceptance test — see the note on this struct. A body it
        // refuses is a body the protocol refuses, and the error it gives is the reason why.
        let (intent, target) = match method {
            METHOD_RESOURCES_SUBSCRIBE => {
                let p: SubscribeRequestParams = serde_json::from_value(params)
                    .map_err(|e| IngressReject::BadRequest(e.to_string()))?;
                (SubscribeIntent::Register, p.uri)
            }
            METHOD_RESOURCES_UNSUBSCRIBE => {
                let p: UnsubscribeRequestParams = serde_json::from_value(params)
                    .map_err(|e| IngressReject::BadRequest(e.to_string()))?;
                (SubscribeIntent::Deregister, p.uri)
            }
            other => {
                return Err(IngressReject::BadRequest(format!(
                    "`{other}` is not a subscription method"
                )))
            }
        };
        // AN EMPTY TARGET NAMES NOTHING. A subscription to the empty string is not a narrower
        // subscription, it is an unanswerable one, and admitting it would hand the admission layer
        // a name it cannot judge.
        if target.is_empty() {
            return Err(IngressReject::BadRequest(
                "a subscription request names a non-empty target in `params.uri`".to_string(),
            ));
        }
        Ok(IrReq::Subscribe(SubscribeReq {
            intent,
            target,
            extra: Default::default(),
        }))
    }

    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Subscribe(r) = ir else {
            // A cell is only ever handed its own operation's IR — the matrix lookup is what
            // guarantees it. Reaching this arm means the matrix was bypassed, which is a bug in the
            // engine and not something to paper over with a plausible default.
            return Bytes::new();
        };
        // Built through the SDK's own constructor, so the member names and the `_meta` handling are
        // the SDK's rather than a second spelling of them here.
        let params = match r.intent {
            SubscribeIntent::Register => {
                serde_json::to_value(SubscribeRequestParams::new(r.target.clone()))
            }
            SubscribeIntent::Deregister => {
                serde_json::to_value(UnsubscribeRequestParams::new(r.target.clone()))
            }
        }
        .unwrap_or_else(|_| serde_json::json!({ "uri": r.target }));
        // The `id` is the ENGINE's, not the caller's, for the reason the invocation codec states:
        // correlation is decided on the way out and read back by `ingress::jsonrpc::read_response`.
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": Self::method_for(r.intent),
                "params": params,
            }))
            .unwrap_or_default(),
        )
    }

    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: serde_json::Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let result = v
            .get("result")
            .ok_or_else(|| CodecError::Malformed("no `result` member".to_string()))?;
        // AN EMPTY RESULT IS THE ACKNOWLEDGEMENT, NOT A MISSING ONE. MCP answers both verbs with an
        // empty object; a peer whose wire returns a registration record gets that record carried
        // through untouched. The two are kept distinct so neither has to be inferred later.
        let empty = result.as_object().is_some_and(serde_json::Map::is_empty) || result.is_null();
        Ok(IrResp::Subscribe(SubscribeResp {
            registration: (!empty).then(|| result.clone()),
            extra: Default::default(),
        }))
    }

    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Subscribe(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        WireBody::json(Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                // Carried, never synthesised: a peer that returned no record does not acquire one
                // by passing through busbar, and the empty object is what the protocol asks for.
                "result": r.registration.clone().unwrap_or_else(|| serde_json::json!({})),
            }))
            .unwrap_or_default(),
        ))
    }
}

// ══ THE NOTIFICATION HALF ════════════════════════════════════════════════════════════════════════

/// THE SERVER-ORIGINATED NOTIFICATIONS THIS PROTOCOL CARRIES, and the reason a subscription is worth
/// registering at all.
///
/// ## WHY THIS IS NOT AN `OperationHandler`
///
/// A notification has no id, no answer and no correlation: JSON-RPC 2.0 section 4.1 forbids replying
/// to one. It is therefore not a request/response codec and modelling it as one would give it a
/// response half that must never be produced. It sits beside the codecs, in the protocol's own
/// file, because the thing it is specific to is the DIALECT — the same reason the JSON-RPC envelope
/// itself is read once, in one place, for every plane that speaks it.
///
/// ## BOTH DIRECTIONS READ THE SAME BYTES
///
/// When busbar is the server it EMITS these to its caller; when busbar is the client it RECEIVES
/// them from an upstream. That is one wire message and two directions of travel, so it is one
/// reader and one writer here rather than a pair per direction — which is exactly the arrangement
/// that stopped the JSON-RPC envelope from being parsed two ways that disagreed.
///
/// ## WHAT A RECEIVED `notifications/tools/list_changed` MAY AND MAY NOT DO
///
/// It is a HINT, and it arrives from a party whose timing and content are not busbar's to trust. It
/// may prompt a re-read of a catalogue through the ordinary approval path; it may never itself
/// install, approve or promote anything, because that would let the party being catalogued decide
/// when its own catalogue is believed. This type carries the message and takes no such action, which
/// is what keeps that decision at the call site that has the approval context.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum McpNotification {
    /// The peer's tool list is no longer what it was.
    ToolsListChanged,
    /// A subscribed resource changed. The delivery half of [`SubscribeOperation`].
    ResourceUpdated {
        /// The resource that changed, in the peer's vocabulary.
        uri: String,
    },
}

#[cfg_attr(not(test), allow(dead_code))]
impl McpNotification {
    /// The wire method name, off `rmcp`'s const-string types.
    pub(crate) fn method(&self) -> &'static str {
        match self {
            McpNotification::ToolsListChanged => METHOD_NOTIFY_TOOLS_LIST_CHANGED,
            McpNotification::ResourceUpdated { .. } => METHOD_NOTIFY_RESOURCES_UPDATED,
        }
    }

    /// Read a notification that has ALREADY been established as a JSON-RPC notification envelope by
    /// [`crate::ingress::jsonrpc`]. `None` means "a notification this protocol does not carry",
    /// which is the correct answer to give and the correct thing to do nothing about: section 4.1
    /// forbids replying, so an unknown notification is dropped rather than refused.
    pub(crate) fn read(method: &str, params: Option<&serde_json::Value>) -> Option<Self> {
        match method {
            METHOD_NOTIFY_TOOLS_LIST_CHANGED => Some(McpNotification::ToolsListChanged),
            METHOD_NOTIFY_RESOURCES_UPDATED => {
                // The SDK's parameter type is the acceptance test here too: a notification that
                // names no resource says a resource changed without saying which, and acting on it
                // would mean guessing.
                let p: ResourceUpdatedNotificationParam =
                    serde_json::from_value(params?.clone()).ok()?;
                (!p.uri.is_empty()).then_some(McpNotification::ResourceUpdated { uri: p.uri })
            }
            _ => None,
        }
    }

    /// The complete JSON-RPC notification envelope for this message.
    ///
    /// **There is no `id` member and there must never be one.** Section 4.1 makes the absence of
    /// `id` the definition of a notification; an id would make this a request, and a request obliges
    /// the receiver to answer something busbar is not waiting for.
    pub(crate) fn write(&self) -> Bytes {
        let mut envelope = serde_json::json!({ "jsonrpc": "2.0", "method": self.method() });
        if let McpNotification::ResourceUpdated { uri } = self {
            // `params` is emitted only where the message has any, so the notification that carries
            // none stays byte-identical to what the specification describes.
            envelope["params"] =
                serde_json::to_value(ResourceUpdatedNotificationParam::new(uri.clone()))
                    .unwrap_or_else(|_| serde_json::json!({ "uri": uri }));
        }
        Bytes::from(serde_json::to_vec(&envelope).unwrap_or_default())
    }
}

#[cfg(test)]
#[path = "tests/mcp_tests.rs"]
mod tests;

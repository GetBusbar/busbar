// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP `RequestHandler` AND ITS CELLS — MCP as a protocol in the matrix, not a plane beside it.
//!
//! ## WHAT THIS FILE IS EVIDENCE FOR
//!
//! MCP was first built as a parallel ingress path: 13,069 implementation lines under
//! `busbar-core/src/mcp/`, with zero `ProtocolReader`/`ProtocolWriter` implementations and zero
//! `IrBlock`. Every concern the core already owned — the guarded fetch, ingress admission, outbound
//! credentials, the hash-chained audit, the config-section container — was written a second time in
//! that directory, which is what the plane ledger in `scripts/structure-lint.sh` counts.
//!
//! This file is the other way of doing it, and it is deliberately the same size and shape as the
//! LLM dialects' handlers: a protocol declares which operations it serves, and the operations it
//! does not serve return `None`, which is a `404` through the standard no-handler path. Being IN the
//! matrix is what makes governance, budgets, audit, metrics, the breaker and failover apply — not a
//! second wiring of each.
//!
//! ## THE ONE GENUINELY MCP-SHAPED THING
//!
//! MCP frames every call in a JSON-RPC 2.0 envelope: `{jsonrpc, id, method, params}` in, and
//! `{jsonrpc, id, result}` or `{jsonrpc, id, error}` back. That framing is this protocol's dialect,
//! exactly as `{"messages": [...]}` is OpenAI's and `{"contents": [...]}` is Gemini's, and it is the
//! codec's whole job. It is NOT a reason for the engine to know MCP exists.
//!
//! **The envelope is read by `busbar_substrate::ingress::jsonrpc`, not re-implemented here.** That module
//! exists because the envelope had previously been parsed in two places that disagreed — the A2A
//! reader checked no `jsonrpc` member at all, and a malformed envelope was relayed to a backend
//! agent. One reader, two protocols.
//!
//! ## WHAT IS NOT BUILT HERE, STATED RATHER THAN DISCOVERED
//!
//! These cells read and write the `tools/call` and subscription shapes. They do NOT carry the
//! catalogue, the schema pinning, the per-call audit chain or the arguments guard — those live in
//! the `mcp/` PLANE in core today (see the crate docs in `lib.rs` for why the plane did not travel
//! with this crate). A cell that quietly reimplemented them would be the original mistake a second
//! time.
//!
//! **And one limit that is real and is not papered over:** the subscription verbs are a CODEC. A
//! subscription is only a capability once there is a channel to be notified over, and the revision's
//! server→client stream is a surface of its own, not something a codec can supply. The notification
//! vocabulary is in `lib.rs` so that the channel, when it is mounted, frames the same bytes these
//! cells already read — not so that the surface can be claimed before it exists.

use busbar_api::operation::Operation;
use busbar_core::handlers::{Cell, OperationHandler, RequestHandler};

use super::invoke::InvokeOperation;
use super::subscribe::SubscribeOperation;
use super::{
    METHOD_RESOURCES_SUBSCRIBE, METHOD_RESOURCES_UNSUBSCRIBE, METHOD_TOOLS_CALL, PATH_MCP,
};

/// The protocol's request handler — the type [`super::DECL`] names.
pub struct McpRequestHandler;

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
/// **AND THIS IS THE DELETION TEST.** Deleting MCP the protocol deletes this table and its two
/// codecs; no core type names a single MCP verb, because the verbs are values in this file.
static CELLS: &[Cell] = &[
    (Operation::INVOKE, &INVOKE),
    (Operation::SUBSCRIBE, &SUBSCRIBE),
];

impl RequestHandler for McpRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "mcp"
    }

    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        busbar_core::handlers::cell_of(CELLS, op)
    }

    fn upstream_path(&self, _ctx: &busbar_substrate::wire::EgressCtx) -> String {
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

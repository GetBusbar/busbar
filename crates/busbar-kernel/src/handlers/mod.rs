// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol handlers — the design's middle, in one module:
//!
//! `Router → RequestHandler → OperationHandler → IR`
//!
//! - [`RequestHandler`](busbar_contract::codec::RequestHandler) — ONE per protocol (`openai.rs`, `anthropic.rs`, …). Dumb and
//!   protocol-specific: reads path+body to decide WHICH operation a request asks for
//!   (`resolve_operation`), owns the `(protocol, operation) → path template` (`upstream_path`), and
//!   holds its row of the support matrix (`operation_handler`; `None` = the no-handler 404).
//! - [`OperationHandler`](busbar_contract::codec::OperationHandler) — ONE per (protocol × operation). A pure codec: wire ↔ IR, both
//!   directions, plus the operation-capability surface the engine reads. It never routes, fails
//!   over, checks auth, bills, or knows another protocol exists.
//! - [`OpDispatch`] — the thin `(operation, transport, OperationHandler)` handle the streaming
//!   engine threads: the framed cell, built by [`crate::handlers::frame`] and by
//!   nothing else. It mostly delegates to the `RequestHandler` vtable; its one bit of logic is
//!   honoring a per-lane `path` override in `upstream_path` before falling back to the protocol
//!   default. [`request_handler`] is the registry the catch-all dispatch resolves through.
//!
//! Adding a protocol: a Router ID line, a `RequestHandler` impl here, its OperationHandlers, and a
//! `CELLS` table naming the verbs it speaks. Adding an OPERATION: an OperationHandler plus a row in
//! the `CELLS` table of each protocol that speaks it — a row, not a match arm, and only in the
//! protocols that speak it, because a verb is that protocol's vocabulary and not a core enum's
//! variant (see [`Cell`](busbar_contract::codec::Cell), and `operation.rs` for what the core kept: the SHAPE). Adding a
//! TRANSPORT: a variant in `transport.rs` and an arrival that frames these same codecs — no codec
//! changes, because a codec never learns which channel it is speaking over. Nothing else moves.
//!
//! THE CODEC-CELL SHAPES LIVE IN THE CONTRACT (`busbar_contract::codec`, #83a SD-2b): the
//! `OperationHandler` / `RequestHandler` traits, the `Cell` / `cell_of` / `path_of` row helpers and
//! the `IngressReject` / `CodecError` reject enums, named there by every caller. The translate
//! pipeline ([`TranslateCodec`] and its value enums) stays in `busbar_substrate_values::handlers` and
//! is re-exported below at its historical `busbar_kernel::handlers::…` paths. What STAYS in core is the engine dispatch
//! handle [`OpDispatch`] and the registry-resolved [`chat`] / [`op_for`] / [`protocol_error`]
//! resolvers — those name the core registry singleton.

// EVERY LLM DIALECT'S HANDLER LIVES IN THE `busbar-llm` PLUGIN CRATE — anthropic, openai-chat,
// gemini, bedrock, cohere and openai-responses — each in its own dialect module's `handler.rs`.
// They are reachable in the builds that compile the dialects back in as
// `crate::proto::<dialect>::handler`, and in production only through the registry's
// `ProtocolDecl::handler`, which is the point. `ChatOperation` RELOCATED to the plugin too at the
// G6 A4b dissolve (`busbar-llm/src/chat_handle.rs`, netted as `crate::proto::chat_handle`): once
// `IrReq`/`IrResp` dissolved onto `Box<dyn IrHandle>`, the chat codec names the concrete chat IR
// that now lives in the plugin, so it cannot stay in core. Core names no chat codec in production;
// chat resolves through the registry like every other operation (see `chat` below).
// THE EXTRACTED MCP PROTOCOL CODEC lives wholly in the `busbar-mcp` plugin crate
// (`crates/busbar-mcp/src/codec`). Its `#[path]` witness re-include into core (which let the
// pre-extraction fixture surface reach the real MCP codec from inside core's own test binary, back
// when a `ProtocolDecl` was a `busbar-core` type an external crate could not hand to the registry)
// was DELETED: `ProtocolDecl` now lives in `busbar-substrate`, so core's test binary reads
// `busbar_mcp::PROTO_DECL` directly (dev-dependency). NOTE THE SCOPE: this was MCP the PROTOCOL; the
// `mcp/` PLANE (`crate::mcp`) never travelled with the codec and is still core's.

// THE TRANSLATE PIPELINE, relocated to `busbar-substrate` (`busbar_substrate_values::handlers`) and
// re-exported here at its historical `busbar_kernel::handlers::…` paths. `usage_tap_decode_fail_should_warn` (the usage-tap
// warn-once latch) travels with the `extract_usage` default that calls it; the
// `busbar_kernel::metrics::BILLING_TAP_DECODE_FAIL_TOTAL` metric name it increments moved with it and
// is re-exported from `metrics.rs`.
pub use busbar_substrate_values::handlers::{
    usage_tap_decode_fail_should_warn, TranslateCodec, TranslateReqInput, TranslateReqReject,
    TranslateRespInput, TranslatedRequest,
};

/// The protocol's `RequestHandler`, by name (matches `router` / `proto::Protocol::name()`). A
/// registered handler may still return `None` from `operation_handler` for an op it lacks — that IS
/// the no-handler 404.
///
/// THIS WAS THE SECOND MATCH ON A PROTOCOL NAME IN CORE, and it was the one on the DISPATCH path:
/// `match protocol { "openai" => …, "mcp" => … }`, seven arms, each naming a protocol core had to
/// have been edited to know about. It is now a read of `ProtocolDecl::handler` — the cell a protocol
/// DECLARES, beside the codec, the verbs and the head keys it declares in the same struct.
// RELOCATED DOWN to `busbar_substrate_values::handlers` (the dialect crates resolve it through the neutral
// ABI); re-exported here at its historical `busbar_kernel::handlers::request_handler` path.
pub use busbar_substrate_values::handlers::request_handler;

// The dispatch surface these named at module scope RELOCATED to `busbar_substrate_values::handlers`; core's
// own `#[path]`-netted handler test modules (`use super::*`) still name them, so keep the vocabulary
// in test scope only (production core no longer references either directly).
#[cfg(test)]
use crate::operation::OpVerb;

// `WireBody`, `EgressCtx`, `EgressWire` and `TranslatedResponse` are codec-cell SHAPES
// (`busbar_contract::codec`, #83a SD-2b) that every caller names through the contract or its
// substrate re-export; this module no longer re-exports them.

#[cfg(test)]
#[path = "tests/contract_tests.rs"]
mod contract_tests;

// THE ENGINE DISPATCH HANDLE `OpDispatch` (+ the `Op` alias, the `frame` framing ctor, and its
// inherent-method surface) RELOCATED DOWN to `busbar_substrate_values::handlers`: every dependency
// (`Transport`, `RawUpstreamError`, `Operation`/`OpShape`, `TokenUsage`, `TEXT_EVENT_STREAM`, the
// registry `decl_for`) already lives on the substrate, so the dialect crates thread the handle
// through the neutral ABI rather than reaching BACK into `busbar-core`. Re-exported here at their
// historical `busbar_kernel::handlers::{OpDispatch, Op, frame}` paths so core's own call sites and the
// netted dual-compile test build are unchanged. `busbar_llm`'s `OpEgressExt::upstream_path` extension
// over this `Op` (the REFERENCE `(protocol × operation)` path composition) is unaffected — it reads
// the `pub operation` field.
pub use busbar_substrate_values::handlers::{frame, Op, OpDispatch};

// The former `#[cfg(test)]` `CHAT` const (a hand-framed cell over the plugin's chat handler type,
// defined in a `tests/chat_fixture.rs` that named the plugin crate) is GONE: its one reader,
// `dispatch_tests`, resolves the same cell the way production does — [`op_for`] over the registry —
// so core's test binary names no plugin handler type to build a chat cell.

/// Resolve the chat dispatch THROUGH the registry — the same path every other operation takes:
/// `request_handler(protocol).operation_handler(Chat)`. This is how "the RequestHandler decides which
/// OperationHandler handles the request" is honored for chat too, not just the JSON ops.
///
/// Post-G6-A4b the chat codec lives in the `busbar-llm` plugin, so this resolves it through the
/// registry the composition root populated — there is no in-core const fallback to name anymore (that
/// codec is gone from core's production build). The `expect` can only fire in a build that links no
/// chat-serving protocol at all, which no shipped configuration is: the LLM plugin registers `openai`
/// and its five siblings, and the sole production caller (`mcp::sampling`) asks for `openai`. The one
/// caller that used the old const fallback purely for a chat cell's error vocabulary (`health.rs`)
/// now calls the neutral `protocol_error` directly (byte-identical to `ChatOperation::extract_error`).
///
/// The TRANSPORT is the caller's to state, not this resolver's: which channel an exchange arrived on
/// is a fact about the arrival, and a protocol has no opinion about it (that is what A2A's three
/// bindings of one agent mean). So it is a parameter, and every caller decides.
// RELOCATED DOWN to `busbar_substrate_values::handlers` (it resolves through the registry `op_for` and the
// residual-default protocol, both now on the substrate); re-exported here at its historical
// `busbar_kernel::handlers::chat` path so the production caller (`mcp::sampling`) is unchanged.
pub use busbar_substrate_values::handlers::chat;

/// THE FRAMED CELL FOR ONE EXCHANGE — `(protocol, operation)` resolved through the registry and
/// framed by the channel it rides. `None` when the protocol does not serve the operation: on the
/// ingress side that is the no-handler 404, and on the egress side it is a pair that never dispatched.
///
/// This is what a site holding an upstream RESPONSE reaches for. The engine and the health prober
/// both use it to find the codec that will read what came back, so neither has to know that a `Lane`
/// is where an LLM upstream's protocol happens to be recorded.
/// A verb a protocol did NOT declare is refused here, and that is the registry's rule rather than a
/// new one: `ProtocolDecl::verbs` is what the protocol advertises (bounded at load, enumerable at
/// boot, and therefore safe as a metric label), so a cell reachable through a verb the declaration
/// does not name would be a capability core could not have known about from the declaration alone.
/// It is not a second answer to "does this protocol serve this operation" — the declaration and the
/// handler are pinned EQUAL in both directions by
/// `registry_tests::the_declared_verbs_are_the_verbs_the_handler_serves`, so this check can only
/// ever fire on a decl that is lying, never on a legitimate route.
// RELOCATED DOWN to `busbar_substrate_values::handlers`; re-exported here at its historical path.
pub use busbar_substrate_values::handlers::op_for;

/// ONE HTTP LLM PROTOCOL'S ERROR ENVELOPE, SHARED BY EVERY OPERATION IT SERVES.
///
/// The six LLM protocols wrap every operation's failure in the same provider envelope — an OpenAI
/// 429 on `/v1/embeddings` carries the `{"error": {…}}` shape it carries on `/v1/chat/completions`
/// — so that vocabulary is a fact about the PROTOCOL, stated once in its `proto::ProtocolReader`,
/// and each of that protocol's cells answers [`busbar_contract::codec::OperationHandler::extract_error`] through here. A
/// protocol whose operations do NOT share one envelope never calls this and keeps the status-only
/// default, which is why the capability belongs to the cell even though these six answer it alike.
///
/// Falls back to the status alone when the name resolves to no protocol: claiming a provider
/// vocabulary busbar could not read would be worse than saying only what is known.
// RELOCATED DOWN to `busbar_substrate_values::handlers`; re-exported here at its historical path.
pub use busbar_substrate_values::handlers::protocol_error;

#[cfg(test)]
#[path = "tests/dispatch_tests.rs"]
mod dispatch_tests;

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM WIRE CODECS — six dialects, one IR, and nothing that opens anything.
//!
//! Anthropic Messages, OpenAI Chat Completions, Google Gemini, AWS Bedrock Converse, OpenAI
//! Responses and Cohere v2 are six ways of saying the same thing, and busbar translates between any
//! pair of them through one neutral IR. That translation is what lives here: the readers, the
//! writers, the IR, the stream translator and the answer-normalization pass every ingress runs
//! between reading an answer and writing it.
//!
//! WHAT IS NOT HERE. The engine that carries these codecs over the network — attempt, exhaustion,
//! lane select, native ingress, the path-model arrivals, the plane declaration, the inbound webhook
//! receiver — stayed in `busbar-llm`, which depends on this crate. That split is the whole point:
//! the LLM PLANE (`busbar-plane-llm`) is a pure kind, and a pure kind may not carry `hyper`,
//! `reqwest` or a socket-capable `tokio` in its transitive closure. It names this crate and gets the
//! codecs without the stack.
//!
//! WHAT EACH DIALECT MODULE OWNS: its `ProtocolDecl`, its wire codec (`reader.rs`/`writer.rs`), its
//! `RequestHandler` and operation cells (`handler.rs`), its own wire constant bank, and its tests.
//! A seventh dialect is a seventh module here — not a seventh crate and not a seventh feature flag.
//!
//! WHAT IS DELIBERATELY *NOT* HERE, SECOND SENSE. `busbar_substrate::proto::openai_family` — the
//! `ERR_TYPE_*` bank, `bearer_error_code`, `tool_arguments_to_string`, `MESSAGE_NAMES_SENTINEL` —
//! reads like it should have travelled with the OpenAI dialects, and it must not: `busbar-core`
//! itself consumes it in PRODUCTION. It stays in the substrate and every dialect reaches it there.
//!
//! SIBLING PATHS ARE RELATIVE. A dialect referring to a SIBLING dialect does it RELATIVELY —
//! `super::gemini::…` from a `mod.rs`, `super::super::…` from one file deeper. That convention
//! predates this crate (it made the dual `#[path]` compile into `busbar-core` work) and is kept
//! because it is correct either way and because keeping it makes this split a pure move.

/// The concrete chat IR + leaf-op IR. The substrate keeps the neutral `ir::facts` trait /
/// `ir::handle` / `ir::invoke` / `ir::subscribe`; the concrete shapes are here.
pub mod ir;

/// The chat `IrHandle` (`ChatReqHandle`/`ChatRespHandle`) + its `prepare_for_egress`/`_ingress`/
/// `usage` bodies; the handle writes itself onto the egress dialect by protocol string.
///
/// THIS IS THE ANSWER-NORMALIZATION PASS the LLM plane needs to reproduce a reference answer
/// byte-for-byte: [`chat_handle::chat_prepare_for_ingress`], [`chat_handle::chat_prepare_for_egress`]
/// and [`chat_handle::chat_usage`] are the cross-protocol pass the forward path runs between reading
/// an answer and writing it. They were `pub(crate)` while the plane and the codecs shared a crate;
/// they are public here because the plane is a different crate and cannot otherwise name them.
pub mod chat_handle;

/// The six leaf-op `IrHandle`s (embeddings/image/rerank/moderation/transcription/speech), writing
/// themselves onto the peer dialect via the `leaf_codec` `(op,proto)` dispatchers.
pub mod leaf_handles;

pub mod anthropic;
pub mod bedrock;
pub mod cohere;
pub mod gemini;
pub mod openai_chat;
pub mod openai_responses;

/// Thread-local OS-entropy pool shared by the writers' synthesized-wire-id paths.
///
/// PUBLIC because the plane needs the same source the reference path uses when it mints a wire id
/// the codec would otherwise mint for it — and because the anthropic ERROR envelope, which is the
/// one minted value on a refusal, takes its entropy as an INPUT (see
/// [`anthropic::error_envelope_with_request_id`]) rather than drawing from here.
pub mod synth_rng;

/// The dialect-neutral tail-usage isolation helper shared by every reader's
/// `recover_truncated_usage` override. PUBLIC: the plane's metering locators name the same
/// isolation the reference path performs.
pub mod usage_tail;

/// The OpenAI-family citation `annotations` mapping shared by the Chat and Responses codecs.
pub mod openai_annotations;

/// IR → wire encode helpers (image source, tool-result detection, strict-drop warn) shared by the
/// dialect writers.
pub mod ir_encode;

/// The per-`(operation, egress-protocol)` leaf-op writer dispatch — the non-chat twin of chat's
/// `protocol_for(proto).writer()`.
pub mod leaf_codec;

/// The concrete wire-codec surface (`ProtocolReader`/`ProtocolWriter`/`StreamFraming`/`Protocol`/
/// `protocol_for`/`DialectRef`/`ToolIdRemap`).
pub mod proto_codec;

/// The concrete streaming byte-translator (`StreamTranslate`) behind the neutral
/// `busbar_substrate::proto::StreamTranslator`.
pub mod proto_stream;

/// The two body-shaping helpers a caller needs on either side of a translate, kept here because
/// they are pure over the protocol registry and the neutral billing carrier — and because the
/// suites that pin them are codec suites.
pub mod wire_shim;

/// A dialect's own error envelope, with the entropy for any minted identifier supplied.
///
/// One of the six dialects — anthropic — puts a freshly minted `request_id` at the top of its error
/// envelope, because a native envelope carries one and an envelope without one is a tell. That is
/// the only minted value on a refusal, and a caller that may not read a random source cannot use
/// the writer's own form. So this takes the entropy as an argument: the caller hands the bytes, the
/// id is built from them, and the same bytes produce the same envelope. The other five dialects
/// mint nothing here and ignore the argument entirely.
///
/// Returns `None` for a protocol name the registry does not know.
#[must_use]
pub fn write_error_envelope(
    ingress_protocol: &str,
    status: u16,
    kind: &str,
    message: &str,
    entropy: &[u8],
) -> Option<serde_json::Value> {
    let protocol = proto_codec::protocol_for(ingress_protocol)?;
    let mut envelope = protocol.writer().write_error(status, kind, message);
    // The writer built the whole document, including a drawn id. Replace ONLY that member, and only
    // where the writer put one, with the id the caller's entropy produces — so the envelope this
    // returns is the writer's envelope in every other byte.
    if let Some(obj) = envelope.as_object_mut() {
        if obj.contains_key(ANTHROPIC_REQUEST_ID_MEMBER) {
            obj.insert(
                ANTHROPIC_REQUEST_ID_MEMBER.to_string(),
                serde_json::Value::String(anthropic::request_id_from_entropy(entropy)),
            );
        }
    }
    Some(envelope)
}

/// The member the anthropic error envelope carries its minted identifier under.
const ANTHROPIC_REQUEST_ID_MEMBER: &str = "request_id";

/// PUBLISH THIS PLUGIN'S DIALECT DECLARATIONS into the SHARED substrate test registry, ONCE — the
/// lazy, self-installing counterpart of the composition root's `install_protocols`, for the test
/// surface where no `main` runs a composition root.
///
/// A codec that resolves a protocol fact through `busbar_substrate::proto::decl_for` (the
/// `Protocol` reader/writer resolution, `protocol_for`, the tool-id remap's
/// `native_tool_id_prefix`) must first ensure this plugin's declarations are registered. Calling it
/// at those few entry points makes every codec-exercising test order-independent without a per-test
/// install. `Once`-guarded, so it is a single atomic load after the first call — off any
/// allocation-gated path. In a build with a real composition root the set is already present and
/// the fold dedupes by name.
#[cfg(any(test, feature = "test-support"))]
pub fn ensure_test_protocols_registered() {
    static REGISTER: std::sync::Once = std::sync::Once::new();
    REGISTER.call_once(|| busbar_substrate::proto::register_test_protocols(DECLS));
}

/// EVERY DIALECT THIS PLUGIN DECLARES, in the order an operator sees.
///
/// THE ORDER IS LOAD-BEARING AND IT IS NOT ALPHABETICAL. The composition root hands this slice to
/// the registry's `install_protocols`, which folds it AHEAD of whatever built-in declarations core
/// still carries; the resulting sequence is what `known_protocols()` reports (the "must be one of:"
/// tail an operator reads on a bad `protocol:`) and what `telemetry` banks its per-protocol metric
/// families against — it finds a family again by POSITION in that list. So this order reproduces,
/// exactly, the operator-visible list from before the dialects were plugins:
/// `anthropic, gemini, openai, bedrock, responses, cohere`. A dialect appended here rather than
/// inserted keeps every existing family's index; inserting one silently renumbers all of them.
pub static DECLS: &[&busbar_substrate::proto::ProtocolDecl] = &[
    &anthropic::DECL,
    &gemini::DECL,
    &openai_chat::DECL,
    &bedrock::DECL,
    &openai_responses::DECL,
    &cohere::DECL,
];

/// THE DETECTION TESTS: they exercise the generic detection fold through THIS plugin's registered
/// `claims` / `residual_claims` predicates.
#[cfg(test)]
#[path = "tests/detect_tests.rs"]
mod detect_tests;

#[cfg(test)]
#[path = "tests/write_error_frame_tests.rs"]
mod write_error_frame_tests;

#[cfg(test)]
#[path = "tests/decode_native_tool_id_tests.rs"]
mod decode_native_tool_id_tests;

#[cfg(test)]
#[path = "tests/leaf_write_dispatch_tests.rs"]
mod leaf_write_dispatch_tests;

/// THE CODEC/IR TEST SUITES: the detection, translate-parity, streaming, round-trip and IR goldens
/// that name the dialects and the concrete wire codecs. See the module header for the `super::*`
/// prelude reconstruction.
#[cfg(test)]
#[path = "tests/proto/mod.rs"]
mod relocated_proto_tests;

/// The bedrock buffered-response → native ConverseStream eventstream synthesis suite: it drives
/// `bedrock::bedrock_response_to_eventstream`, a witnessed codec fn.
#[cfg(test)]
#[path = "tests/bedrock_eventstream_tests.rs"]
mod bedrock_eventstream_tests;

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
//! WHAT THE DIALECTS SHARE, AND WHERE IT LIVES (#83a SD-3). Two kinds of shared name, two homes.
//! The vocabulary BOTH sides of the plane seam must spell alike — the declaration a dialect fills,
//! the codec-cell traits, the IR shapes, the error-`type` bank, the billing and wire carriers — is
//! the contract's (`busbar_contract::…`), and the crate names it there. The machinery only this
//! plane's dialects speak — the event-stream framing, the JSON seam, the SSE and OpenAI-family wire
//! helpers, the cross-dialect translate pipeline and the plane's coded diagnostics — is the plane's
//! own, in the modules below. Nothing here names the host crate: what the plane needs from its host
//! (entropy, the wall clock, the translation cap, the usage-tap count) it reaches through the
//! host services the contract carries, which the host installs where it installs the protocols.
//!
//! A DIALECT NEVER NAMES A SIBLING DIALECT (design F3 SELF-CONTAINED). What two dialects share
//! is a wire mechanism, and it lives in a shared module named for the mechanism (`rerank_wire`,
//! `logprob_wire`, the bearer-envelope helpers in `dialect`), never in one dialect for another to
//! import. A seventh dialect is a seventh module plus its one registration line.

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

/// ONE LEAF OPERATION'S `OperationHandler`, written once for every dialect.
///
/// Every leaf cell answers the same three things the same way: its error envelope is its
/// protocol's (the same vocabulary the chat cell reports, read from the same upstream), and its
/// reads wrap the dialect's own `read_<op>_request`/`read_<op>_response` in the op's leaf handle.
/// Only the dialect label and the two reads differ per cell; anything else a cell says (a usage
/// tap, an egress content type) follows the `;` verbatim.
macro_rules! leaf_op {
    ($op:ident: $dialect:expr, $req:ident = $read_req:ident, $resp:ident = $read_resp:ident; $($extra:tt)*) => {
        impl busbar_contract::codec::OperationHandler for $op {
            fn extract_error(
                &self,
                status: u16,
                body: &[u8],
            ) -> busbar_contract::upstream::RawUpstreamError {
                $crate::codec::proto_codec::protocol_error($dialect, status, body)
            }
            fn read_request(
                &self,
                body: &[u8],
                content_type: &str,
            ) -> Result<Box<dyn busbar_contract::ir::handle::IrHandle>, busbar_contract::codec::IngressReject>
            {
                Ok(Box::new($crate::codec::leaf_handles::$req($read_req(body, content_type)?)))
            }
            fn read_response(
                &self,
                wire: &[u8],
            ) -> Result<Box<dyn busbar_contract::ir::handle::IrHandle>, busbar_contract::codec::CodecError>
            {
                Ok(Box::new($crate::codec::leaf_handles::$resp($read_resp(wire)?)))
            }
            $($extra)*
        }
    };
}

/// A dialect's neutral codec facade as a STATIC, so its `DECL` hands out a `&'static dyn` borrow
/// (pure memory, zero alloc per `dialect()` call) — the seam's perf contract.
macro_rules! dialect_codec {
    ($name:expr) => {{
        static CODEC: $crate::codec::proto_codec::DialectRef =
            $crate::codec::proto_codec::dialect_ref($name);
        Some(&CODEC)
    }};
}

/// The two `RequestHandler` answers every dialect gives alike: its protocol name, and the leaf
/// cell for an operation from its `CELLS` table.
macro_rules! dialect_identity {
    ($name:expr) => {
        fn protocol_name(&self) -> &'static str {
            $name
        }
        fn operation_handler(
            &self,
            op: busbar_contract::operation::OpVerb,
        ) -> Option<&dyn busbar_contract::codec::OperationHandler> {
            busbar_contract::codec::cell_of(CELLS, op)
        }
    };
}

pub mod anthropic;
pub mod bedrock;
pub mod cohere;
pub mod gemini;
pub mod openai_chat;
pub mod openai_responses;

/// The flat field carry: the slot schema, the per-dialect field-table types and the one walker.
pub mod carry;

/// The wire words two or more dialects spell alike, one const each.
pub mod keys;

/// The plane's own CRC-32 (the event-stream framing checksum).
pub mod crc32;

/// The dialects' shared wire helpers: the OpenAI-family error helpers, the SSE `[DONE]` terminator
/// and frame probe/parse/write, the base62 id alphabet, the `usage` stripper.
pub mod dialect;

/// The plane's own coded diagnostics, and the slice the composition root installs.
pub mod diagnostics;

/// The AWS event-stream framing codec the signing dialect streams in.
pub mod eventstream;

/// The plane's own hex codec for synthesized wire ids.
pub mod hex;

/// The plane's own depth-guarded JSON seam.
pub mod json;

/// The cross-dialect translate pipeline (`TranslateCodec`).
pub mod translate;

/// Thread-local entropy pool (filled from the host's source) shared by the writers' synthesized-wire-id paths.
///
/// PUBLIC because the plane needs the same source the reference path uses when it mints a wire id
/// the codec would otherwise mint for it — and because the anthropic ERROR envelope, which is the
/// one minted value on a refusal, takes its entropy as an INPUT (see
/// [`anthropic::error_envelope_with_request_id`]) rather than drawing from here.
pub mod synth_rng;

/// The dialect-neutral tail-usage isolation helper shared by every reader's
/// `recover_truncated_usage` override. PUBLIC: the plane's metering locators name the same
/// isolation the reference path performs.
pub mod usage_count;

pub mod usage_tail;

/// The OpenAI-family citation `annotations` mapping shared by the Chat and Responses codecs.
pub mod openai_annotations;

/// The per-token logprob wire object (`{content: [{token, logprob, bytes, top_logprobs}]}`) the
/// Chat and Responses dialects read and write alike.
pub mod logprob_wire;

/// The rerank wire shape (`documents[]`, `results[]`) the rerank dialects read alike.
pub mod rerank_wire;

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
/// `busbar_contract::protocol::StreamTranslator`.
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

/// THE REGISTRY KEY THE LLM PLANE IS KNOWN BY — the string the composition root flips onto the
/// unified kernel loop ([`busbar_kernel::plane_host::register_gauntlet_runner`]) and the same
/// string the LLM native plane reports from its `GauntletPlane::capability_key`.
///
/// Named ONCE, here, on the pure side of the split, because the plane's `capability_key` and the
/// composition-root FLIP must reference the SAME literal or a swap could drift onto two. It agrees
/// with `busbar-llm`'s `PLANE_DECL.key` (`"llm"`, the fallback plane's identity). `busbar-llm`
/// re-exports it as `busbar_llm::PLANE_KEY`, the one stable path the `busbar` binary names.
pub const PLANE_KEY: &str = "llm";

/// THIS PLANE'S OWN DECLARATION OF `name`, read off [`DECLS`]. Every fact the codecs look up about a
/// dialect by name — the path-model shape, the array-stream shim key, the native tool-id prefix, the
/// provider-metadata reporter — is a fact about one of THESE six dialects, so the lookup reads this
/// plane's own table (Law 5), never the host's registry. `None` for a name this plane does not
/// declare.
#[must_use]
pub fn decl_of(name: &str) -> Option<&'static busbar_contract::protocol::ProtocolDecl> {
    DECLS.iter().copied().find(|d| d.name == name)
}

/// THIS CRATE'S TEST HOST (#83a SD-3: the test registration and the classifier are dev-only): the
/// host services a composition root arms behind the contract seams, armed for this crate's test
/// binary by the test itself, so the codec's tests prove the codec's own seam and never reach the
/// host crate.
#[cfg(test)]
#[path = "tests/test_host.rs"]
pub(crate) mod test_host;
#[cfg(test)]
pub(crate) use test_host::ensure_test_protocols_registered;

/// EVERY DIALECT THIS PLUGIN DECLARES, in the order an operator sees.
///
/// THE ORDER IS LOAD-BEARING AND IT IS NOT ALPHABETICAL. The composition root hands this slice to
/// the registry's `install_protocols`, which folds it AHEAD of whatever built-in declarations core
/// still carries; the resulting sequence is what `known_protocols()` reports (the "must be one of:"
/// tail an operator reads on a bad `protocol:`) and what `telemetry` banks its per-protocol metric
/// families against — it finds a family again by POSITION in that list. So this order reproduces,
/// exactly, the operator-visible list the PUBLISHED 1.5.5 binary prints:
/// `anthropic, openai, gemini, bedrock, responses, cohere`. A dialect appended here rather than
/// inserted keeps every existing family's index; inserting one silently renumbers all of them.
///
/// THE ORDER IS PINNED AGAINST THE RELEASED BINARY, NOT AGAINST A BELIEF ABOUT IT. `gemini` sat
/// ahead of `openai` here for one release cycle of plugin work, on the stated ground that the
/// pre-plugin shipped order was `anthropic, gemini, openai`. It was not: 1.5.5's
/// `proto::KNOWN_PROTOCOLS` reads `anthropic, openai, gemini, bedrock, responses, cohere`, and the
/// published 1.5.5 binary prints that tail on a bad `protocol:` (shadow-oracle
/// `boot.refusal|BOOT-020|validate`). The swap was therefore an unannounced move of an
/// operator-visible list and of every metric-family index behind it, and it is undone here.
pub static DECLS: &[&busbar_contract::protocol::ProtocolDecl] = &[
    &anthropic::DECL,
    &openai_chat::DECL,
    &gemini::DECL,
    &bedrock::DECL,
    &openai_responses::DECL,
    &cohere::DECL,
];

#[cfg(test)]
#[path = "tests/write_error_frame_tests.rs"]
mod write_error_frame_tests;

#[cfg(test)]
#[path = "tests/decode_native_tool_id_tests.rs"]
mod decode_native_tool_id_tests;

#[cfg(test)]
#[path = "tests/leaf_write_dispatch_tests.rs"]
mod leaf_write_dispatch_tests;

/// THE CACHE-TIER READ TESTS, anchored to the REAL recorded upstream bodies committed under
/// `testing/shadow-oracle/golden/1.5.5/cells/` and `testing/llm-conformance/fixtures/`. Crate-level
/// rather than per-dialect because the four providers share one loader for that recorded evidence,
/// and the point of the suite is that the four are the SAME defect.
#[cfg(test)]
#[path = "tests/cache_tier_capture_tests.rs"]
mod cache_tier_capture_tests;

/// TODO 585: the operator warning when an image's `detail` is dropped for a dialect with no slot.
#[cfg(test)]
#[path = "tests/image_detail_warn_tests.rs"]
mod image_detail_warn_tests;

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

/// IR mapping Q57 — what the cross-protocol seam keeps and what it normalizes (IR-CORE).
#[cfg(test)]
#[path = "tests/ir_seam_tests.rs"]
mod ir_seam_tests;

/// IR mapping Q57 — the typed slots through the shared stream machinery (IR-CORE).
#[cfg(test)]
#[path = "tests/ir_slot_carry_tests.rs"]
mod ir_slot_carry_tests;

/// The members CARRY-TABLE parked: what crosses the seam is still the typed slot.
#[cfg(test)]
#[path = "tests/parked_rows_cross_dialect_tests.rs"]
mod parked_rows_cross_dialect_tests;

/// The usage-tap count pin (#83a SD-3, R-USAGE): every same-protocol tap fault counts once on the
/// host's counter, under its reason, whichever cell or direct call raised it.
#[cfg(test)]
#[path = "tests/usage_tap_count_tests.rs"]
mod usage_tap_count_tests;

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol seam: a protocol-agnostic core, with each wire dialect's specifics confined to a
//! `Reader` (wire → signal/IR) and a `Writer` (IR/intent → wire). `Protocol` bundles a Reader and
//! Writer; a string-keyed registry maps a provider's protocol name to its `Protocol`.

use axum::http::{header::HeaderValue, HeaderName};

// StatusClass and CanonicalSignal are defined in breaker.rs and re-exported here for compatibility.
// The `CanonicalSignal` re-export is consumed only by the per-protocol `classify` test helpers (which
// are themselves `#[cfg(test)]`), so it is gated to test builds to avoid an unused-import warning in
// the 1.0 binary; production code refers to the canonical `crate::breaker::CanonicalSignal` directly.
#[cfg(any(test, feature = "test-support"))]
pub use crate::breaker::CanonicalSignal;
pub(crate) use crate::breaker::StatusClass;

// Import types needed for response/stream IR
// Consumed via `use super::*` by the proto test modules only, since the dialect that used them in
// production moved out with the anthropic extraction.

// Neutral protocol atoms RELOCATED DOWN to `busbar-substrate` (`busbar_substrate::proto`) so the
// `busbar-llm` dialect crate names them without reaching into `busbar-core` (reverse-edge rule,
// plane-extraction §6.2). Re-exported here at their historical `busbar_core::proto::…` paths so every
// in-core / plugin / witness-build caller compiles unchanged; the values are byte-identical.
//
// - `SIGNAL_IR_PARSE`     — busbar-internal IR-parse `provider_signal` label.
// - `SSE_DONE_SENTINEL` / `SSE_DONE_FRAME` — the OpenAI-style SSE terminator (bare token + framed bytes).
// - `HDR_AUTHORIZATION`   — the canonical lowercase `Authorization` header name.
// - `IrError`             — the IR-level error alias (`breaker::CanonicalSignal`).
// - `bearer_auth_headers` — the shared `Authorization: Bearer <key>` builder (warn+OMIT on bad bytes).
pub use busbar_substrate::proto::{
    bearer_auth_headers, IrError, HDR_AUTHORIZATION, SIGNAL_IR_PARSE, SSE_DONE_FRAME,
    SSE_DONE_SENTINEL,
};

/// Signal the RESPONSE-side provider metadata that this egress dialect carries and no ingress
/// dialect can express, so it does not vanish from a translated response with nothing in the logs.
///
/// The request side has had this since `IrReq::prepare_for_egress` started naming every cleared
/// `extra` key; the response side had no equivalent, so a Gemini backend's `safetyRatings` and a
/// Bedrock backend's guardrail `trace` disappeared on every cross-protocol hop in silence. That
/// mattered most for the Bedrock trace: an operator running Bedrock Guardrails for COMPLIANCE
/// EVIDENCE got no assessment record back and nothing said it had been dropped.
///
/// These are true target-protocol limits, not unmodelled IR gaps: a guardrail assessment is an AWS
/// account artifact and a Gemini harm-category rating uses Google's own category vocabulary — no
/// other protocol in the matrix has a field of that shape to receive them. So the fix is the signal,
/// not a carrier. (Gemini's OTHER response-side metadata, `groundingMetadata`, IS expressible
/// everywhere — it is citations — and is now read into `IrCitation`s rather than named here.)
///
/// Called ONLY from the cross-protocol response seam, so a same-protocol route — where every one of
/// these fields survives byte-for-byte — never logs a word about them.
pub(crate) fn warn_untranslatable_response_metadata(
    egress: &str,
    ingress: &str,
    body: &serde_json::Value,
) {
    // WHICH fields are present, and the SHAPE of the lookup (Gemini reads `candidates[].k`, Bedrock a
    // top-level key), are the egress dialect's own knowledge — declared on its
    // `ProtocolDecl::vendor_response_metadata` and read here by name so core spells no dialect. A
    // dialect with no such vendor-scoped artifact declares `None` and reports nothing.
    let present: Vec<&str> = decl_for(egress)
        .and_then(|d| d.vendor_response_metadata)
        .map(|report| report(body))
        .unwrap_or_default();
    if present.is_empty() {
        return;
    }
    crate::diagnostics::diag_debug!(
        crate::diagnostics::PROTO_DROP_PROVIDER_METADATA,
        egress = %egress,
        ingress = %ingress,
        fields = %present.join(","),
        "dropping response-side provider metadata on the cross-protocol seam: the field(s) named \
         here are vendor-scoped artifacts (a guardrail assessment is an AWS account resource; a \
         harm-category rating uses Google's own vocabulary) and the caller's protocol has no shape \
         to receive them. If this metadata is compliance evidence, route the request to a \
         same-protocol lane, where the upstream body reaches the client verbatim"
    );
}

/// Conservative fallback for the `max_tokens` injected at a translation boundary when the source
/// protocol omitted it (legal for OpenAI) but the target REQUIRES it (Anthropic, Bedrock — see
/// `ProtocolWriter::requires_max_tokens`). Used only when the lane has no configured
/// `default_max_tokens`. 4096 is a safe output ceiling across current chat models — large enough
/// not to truncate typical completions, small enough not to be refused.
pub const DEFAULT_MAX_TOKENS: u32 = 4096;

/// Mixed-case base62 alphabet (digits + lowercase + uppercase, no `-`/`_`) and the rejection-sampling
/// threshold used when synthesizing opaque ids for protocols whose native ids are flat random tokens
/// (Gemini `responseId`, Responses `msg_`/`fc_`/`resp_` suffixes). Hoisted here as the single source
/// of truth so the two id generators cannot drift on the character set or the bias-elimination cutoff
/// — `REJECT_THRESHOLD` is the largest multiple of 62 that fits in a `u8` (62 × 4 = 248); a draw in
/// `0..248` maps uniformly via `% 62`, a draw `>= 248` is rejected and redrawn.
// Relocated DOWN to `busbar_substrate::proto`; re-exported here (see the neutral-atoms block above).
pub use busbar_substrate::proto::{BASE62_ALPHABET, BASE62_REJECT_THRESHOLD};

/// Client-visible detail string for a mid-stream abort (the upstream connection dropped or a
/// translate step failed after first byte). Lives in the proto layer — the lowest common ancestor —
/// because BOTH `proxy engine` (SSE/forward abort path) and the Bedrock-eventstream reassembler in this
/// module emit it, and `proxy engine → proto` is the only legal dependency direction. Single source of
/// truth so the abort text a client sees is identical on every framing.
pub const STREAM_ABORT_DETAIL: &str = "The response stream was interrupted.";

/// THE RESIDUAL ARM of the ingress resolver: which wire dialect a path names, from its shape alone.
/// `None` when it names none.
///
/// ## This is not the whole answer, and it must not be called as if it were
///
/// The whole answer is [`crate::plane::PlaneDispatch::ingress_of`], and this function is the arm it
/// reaches only AFTER the mount table has declined the path. That ordering is the fix for a shipped
/// defect: while this was the canonical classifier, it was consulted for paths a plane had been
/// MOUNTED on, knew nothing of mounts, and answered a dialect for every one of them — so an oversized
/// POST to `/mcp` came back in an LLM envelope an MCP client cannot decode. A path shape can only ever
/// answer for the residual, because a mount is a fact about the deployment and no amount of looking at
/// a URL will reveal it. `ingress_of` is therefore the only caller.
///
/// ## There is no `else { <default dialect> }` any more, and that is the point
///
/// The old tail arm claimed every unclassifiable path for one dialect, which read as a harmless
/// default and was in fact the resolver asserting a protocol identity for paths that carry none. What
/// to say to a caller whose dialect is unknown is a decision — a real one, taken in
/// `ingress::native_error`, where the alternatives are visible — not something a classifier should
/// smuggle in as a fallthrough.
///
/// ## The ladder is DATA now, and core names no dialect
///
/// This once held a hand-ordered `if`-ladder naming every dialect; it is now a fold over the
/// registered protocols' own [`ProtocolDecl::residual_claims`] predicates
/// ([`registry::residual_protocol_for_path`]), so each dialect owns its arm (the `/v1/models/{id}`
/// colon disambiguation, the `/model/…/converse[-stream]` Bedrock guard, …) and core spells none of
/// them. Byte-identical to the old ladder — the claim strengths ARE the ladder positions.
pub fn residual_dialect_for_path(path: &str) -> Option<&'static str> {
    registry::residual_protocol_for_path(path)
}

/// THE ROUTER: `(path, headers)` → which wire dialect a request speaks, or `None` for a path that
/// names none. A public re-export of the generic detection fold ([`registry::detect_protocol`]) so
/// the protocol plugin can exercise the byte-identical detection contract from its own tests.
pub fn detect_protocol(path: &str, headers: &axum::http::HeaderMap) -> Option<&'static str> {
    registry::detect_protocol(path, headers)
}

/// THE REGISTRY-SUPPLIED RESIDUAL DEFAULT dialect — the name core falls back to when no dialect
/// claims a request yet one must be named. `None` when no residual-default protocol is installed.
/// Reads [`ProtocolDecl::residual_default`], so the literal default dialect name leaves core.
pub(crate) fn residual_default_dialect() -> Option<&'static str> {
    registry::residual_default_protocol()
}

/// The vendor-plausible auth-failure wire MESSAGE for an ingress protocol. This string lands verbatim
/// in the native error body (`error.message` for anthropic/openai/gemini/responses, the bare
/// top-level `message` for cohere, the `message` beside `__type` for bedrock). It MUST read like the
/// copy the REAL vendor returns for a bad/missing credential and carry NO busbar-internal vocabulary
/// ("lane", "virtual key", "passthrough", …): any such word is a deterministic protocol tell that
/// also discloses busbar's auth model. Canonical source of truth; `auth.rs::vendor_auth_failure_message`
/// is a thin delegation wrapper to this, not a copy. Strings sampled from real 401/403 bodies:
///   anthropic → "invalid x-api-key"; openai/responses → "Incorrect API key provided.";
///   gemini → "API key not valid. Please pass a valid API key."; cohere → "invalid api token";
///   bedrock → "" (AWS conveys AccessDenied via __type / x-amzn-errortype, not message prose).
///
/// Thin wrapper: dispatches through `ProtocolWriter::auth_failure_message` so the per-vendor copy
/// lives in the writer vtable, not in this agnostic function. An unknown future proto falls back to
/// the default generic copy.
pub(crate) fn vendor_auth_failure_message(proto: &str) -> &'static str {
    registry::decl_for(proto)
        .map(|d| d.auth_failure_message)
        .unwrap_or("authentication failed")
}

// Per-request signing context. RELOCATED DOWN to the neutral `busbar_substrate::proto` leaf so the
// substrate `ProtocolDecl`'s `egress_auth_headers` builder names it without depending on
// `busbar-core`; re-exported here at its historical `busbar_core::proto::SigningContext` path so
// every in-core / plugin caller (`egress_auth`, `proxy::egress`, `health`, the walk/engine forward
// paths, the netted dialect writers) is unchanged. Its only non-primitive field is
// `busbar_api::UpstreamCreds`, so the move carries no core-only machinery.
pub use busbar_substrate::proto::SigningContext;

/// ProtocolWriter rewrites intents for the upstream wire format.
/// Extract `(role, text)` pairs from a hook's rewrite reply for a dialect that must RE-FRAME the
/// turns rather than insert them verbatim. `None` means at least one reply message does not carry
/// plain-string content — the re-framing dialects cannot render that faithfully, so their
/// [`ProtocolWriter::apply_rewrite_to_ingress_body`] aborts and leaves the body untouched rather
/// than shipping a half-applied rewrite.
// Relocated DOWN to `busbar_substrate::proto`; re-exported here (see the neutral-atoms block above).
pub use busbar_substrate::proto::rewrite_text_pairs;

// `ArrayStreamFramer` (the streaming JSON-array reframer the SSE seam drives) and `DialectCodec` (the
// 4th neutral per-PROTOCOL computed-codec seam the operation-blind driver reads) RELOCATED to
// `busbar-substrate` (`busbar_substrate::proto`) so the `busbar-llm` dialect crate implements them
// without reaching into `busbar-core`; re-exported here at their historical `busbar_core::proto::…`
// paths so core's call sites and the netted dual-compile test build are unchanged. Both name only the
// neutral surface (bytes / `Value` / `bool` / `TokenUsage` / `RawUpstreamError` / `CanonicalSignal`),
// so the relocation carries no core-only machinery. `DialectCodec::make_array_stream_framer` returns a
// `Box<dyn ArrayStreamFramer>`, so the two travel together. Reached via `decl_for(name).dialect()`.
pub use busbar_substrate::proto::{ArrayStreamFramer, DialectCodec};

/// The set of streaming `Content-Type` values across every declared protocol. A registry aggregate,
/// folded once at boot from `ProtocolDecl::streaming_content_type` — where it used to be an
/// `OnceLock` sweep that built a `Protocol` per known name to read one `&'static` off its writer.
pub(crate) fn streaming_content_types() -> &'static [&'static str] {
    registry::registry().streaming_content_types()
}

/// The set of array-stream shim keys across every declared protocol (only Gemini declares one).
/// The same aggregate, from `ProtocolDecl::array_stream_shim_key`, and the reason
/// `proxy::strip_router_shim_keys` can remove every protocol's marker while naming none of them.
pub(crate) fn array_stream_shim_keys() -> &'static [&'static str] {
    registry::registry().array_stream_shim_keys()
}

/// The array-stream shim key the NAMED protocol declares, or `None` if it declares none (most
/// don't) or is not registered. The INJECTION site (`ingress::ingress_path_model`) reads it by name
/// so it names no protocol submodule: delete a protocol and the marker is simply never injected.
pub(crate) fn array_stream_shim_key_for(protocol_name: &str) -> Option<&'static str> {
    registry::decl_for(protocol_name).and_then(|d| d.array_stream_shim_key)
}

/// The NEUTRAL streaming-translator seam (`StreamTranslator` trait + the fn-ptr factory) — STAYS in
/// core (names zero concrete stream IR). See `stream_translator.rs`.
pub(crate) mod stream_translator;
pub(crate) use stream_translator::new_stream_translator;
// `pub` (not `pub(crate)`): the plugin's `proto_stream::StreamTranslate` implements this neutral
// byte-in/byte-out seam, and busbar-llm compiles standalone (workspace build), so it must reach the
// trait cross-crate as `busbar_core::proto::StreamTranslator`.
pub use stream_translator::install_stream_translator_factory;
pub use stream_translator::StreamTranslator;

/// THE EXTRACTED CONCRETE STREAM TRANSLATOR (`StreamTranslate` + factory + frame helpers), compiled
/// back in for TEST BUILDS ONLY (G6 A4b). Sources live in `crates/busbar-llm/src/proto_stream.rs`
/// (it names `IrStreamEvent`/`IrUsage`/`StreamDecodeState`, so it relocated to the plugin); same
/// `#[path]` dual-compile mechanism as the dialects. Production reaches it via the installed factory.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/proto_stream.rs"]
pub(crate) mod stream;
// The production forward path constructs translators through `new_stream_translator` and holds them
// behind `dyn StreamTranslator`, so the concrete translator is named only by the proto / proxy test
// suites (the streaming witnesses drive it directly). Glob re-export (not an explicit `use`, which
// would name `StreamTranslate` — a witness TYPE) so those suites reach it at `crate::proto::StreamTranslate`
// as before; core names it nowhere in production (freeze witness → 0).
#[cfg(any(test, feature = "test-support"))]
#[allow(unused_imports)]
// glob re-export; `crate::proto::StreamTranslate` reached by the proxy witnesses
pub(crate) use stream::*;

/// THE EXTRACTED CONCRETE WIRE-CODEC SURFACE (`ProtocolReader`/`ProtocolWriter`/`StreamFraming`/
/// `Protocol`/`protocol_for`/`DialectRef`/`ToolIdRemap`), compiled back in for TEST BUILDS ONLY (G6
/// A4b). Sources live in `crates/busbar-llm/src/proto_codec.rs` — it names the concrete LLM IR types,
/// so it relocated to the plugin; production core drives translation through the neutral `DialectCodec`
/// seam + the per-cell `TranslateCodec` and names none of these. Netted here (module name matches the
/// plugin root file so the dialect files' `super::super::proto_codec` resolves in both shapes) so the
/// pre-extraction fixture surface (`Protocol::anthropic()`, `protocol_for(p).reader()/.writer()`, the
/// stream-translate + identity suites) keeps resolving. Same `#[path]` dual-compile mechanism.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/proto_codec.rs"]
pub(crate) mod proto_codec;
// Glob re-export (not an explicit list) so the pre-extraction call surface reaches these at their old
// `crate::proto::<Item>` paths WITHOUT this line textually naming a concrete-family type the freeze
// witness would count (`StreamFraming` is on its TYPES list).
#[cfg(any(test, feature = "test-support"))]
pub use proto_codec::*;

/// Find the first SSE frame terminator (a blank line) in `buf`, returning `(offset, terminator_len)`
/// where `offset` is the byte index of the first terminator byte. Recognizes both the LF-LF (`\n\n`,
/// 2 bytes) and the spec-legal CRLF (`\r\n\r\n`, 4 bytes) blank-line terminators per WHATWG SSE.
/// Returns `None` if no complete terminator is present yet.
pub fn find_frame_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'\n' {
            // LF-LF: `\n\n` — the blank-line terminator begins at this `\n` and is 2 bytes long.
            if buf.get(i + 1) == Some(&b'\n') {
                return Some((i, 2));
            }
            // CRLF-CRLF: `\r\n\r\n` — the full spec-legal terminator is 4 bytes. We anchor the scan
            // on the `\n` that ENDS the preceding line's CRLF, then confirm the blank line's own
            // `\r\n` follows (`...\n` + `\r\n`). The terminator proper begins at the trailing `\r`
            // of the preceding line (one byte BEFORE this `\n`), so report `offset = i - 1` and
            // `len = 4`. (`i >= 1` is guaranteed here: a leading `\n` at index 0 cannot match this
            // arm, since the preceding `\r` it requires would have to sit at index -1.)
            if i >= 1
                && buf[i - 1] == b'\r'
                && buf.get(i + 1) == Some(&b'\r')
                && buf.get(i + 2) == Some(&b'\n')
            {
                return Some((i - 1, 4));
            }
        }
        i += 1;
    }
    None
}

/// Parse one SSE frame into `(event_type, data_payload)`. `event_type` is "" when the frame has
/// no `event:` line (OpenAI style). Multiple `data:` lines in a single frame are concatenated with
/// `\n` per the SSE spec. Returns `None` if the frame carries no `data:` line (including a
/// frame with only an `event:` line) or is invalid UTF-8.
pub fn parse_sse_frame(frame: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(frame).ok()?;
    let mut event_type = String::new();
    let mut data_lines: Vec<&str> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("event:") {
            event_type = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("data:") {
            // Per the SSE spec a single leading space after the colon is stripped; the rest of the
            // value is preserved verbatim so multi-line JSON payloads survive intact.
            data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
    if data_lines.is_empty() {
        // No `data:` line at all (e.g. an `event:`-only frame) — nothing to translate.
        return None;
    }
    Some((event_type, data_lines.join("\n")))
}

/// The `event:` name of one SSE frame, BORROWED from the frame bytes — the cheap probe for a
/// consumer that only needs the event TYPE to decide whether a frame is worth parsing at all.
/// [`parse_sse_frame`] pays three heap allocations per call (the event-type `String`, the
/// `data:`-line `Vec`, the joined-payload `String`), which is exactly what a skip decision must
/// not. Returns `""` when the frame carries no `event:` line (OpenAI style) or the name is not
/// UTF-8 — the same value `parse_sse_frame` reports for those shapes — and, like it, the LAST
/// `event:` line wins when a frame illegally carries several.
// Relocated DOWN to `busbar_substrate::proto`; re-exported here (see the neutral-atoms block above).
pub use busbar_substrate::proto::sse_event_type;

// `strip_top_level_usage_member` (and its two private JSON span scanners) RELOCATED DOWN to
// `busbar_substrate::proto`; re-exported here at its historical path.
pub use busbar_substrate::proto::strip_top_level_usage_member;

/// Append an IR-derived `(event_type, data)` to `out` as INGRESS SSE bytes. A non-empty
/// `event_type` yields Anthropic-style `event:`/`data:` frames; an empty one yields OpenAI-style
/// bare `data:`. Writes THROUGH the caller's buffer, not into a returned `String`: this is the
/// per-chunk streaming path (`stream.rs`'s `emit_ir_event`), and every call site immediately threw
/// the returned `String` away into its own `out: &mut Vec<u8>` — one allocation per translated
/// frame for nothing. Serializes via `crate::json::to_vec` (the sonic seam), not `Value`'s
/// `Display`-via-`format!`: this function used to bypass that seam even though `json.rs`'s own
/// module doc claims every body-JSON path, including the SSE-event paths, goes through it.
pub fn write_sse_frame(out: &mut Vec<u8>, event_type: &str, data: &serde_json::Value) {
    if !event_type.is_empty() {
        out.extend_from_slice(b"event: ");
        out.extend_from_slice(event_type.as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(b"data: ");
    // `unwrap_or_default()` matches the identical decision already made one call site up
    // (`stream.rs`'s `crate::json::to_vec(&out_data).unwrap_or_default()`): a `Value` that fails to
    // serialise is not a condition this emitter can report, and diverging here would be gratuitous.
    out.extend_from_slice(&crate::json::to_vec(data).unwrap_or_default());
    out.extend_from_slice(b"\n\n");
}

/// THE EXTRACTED ANTHROPIC DIALECT, compiled back in for TEST BUILDS ONLY. The sources live in
/// `crates/busbar-llm/src/anthropic` (a module of the ONE LLM plugin crate; the `busbar`
/// binary registers every dialect's `DECL` through `registry::install_protocols`), and core's PRODUCTION build knows nothing of
/// them — this decl exists so the pre-extraction fixture surface (the `Protocol::anthropic()`
/// fixtures and `protocol: anthropic` configs across the core suite) keeps exercising the real
/// codec from inside this crate's test binary, where an externally-linked copy could not reach the
/// registry (its `ProtocolDecl` would be a different crate's type). The dialect's sources are
/// written against `busbar_core::` paths, which the `extern crate self as busbar_core` alias in
/// lib.rs resolves here.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/anthropic/mod.rs"]
pub mod anthropic;
/// THE EXTRACTED BEDROCK DIALECT, compiled back in for TEST BUILDS ONLY. Sources live in
/// `crates/busbar-llm/src/bedrock`; see the `mod anthropic` doc above — same mechanism, same crate,
/// a different dialect module of it.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/bedrock/mod.rs"]
pub mod bedrock;
/// THE EXTRACTED COHERE DIALECT, compiled back in for TEST BUILDS ONLY. Sources live in
/// `crates/busbar-llm/src/cohere`; see the `mod anthropic` doc above — same mechanism, same crate,
/// a different dialect module of it.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/cohere/mod.rs"]
pub mod cohere;
/// Wire-dialect detection: `protocol_id(path, headers)` sniffs which protocol a request speaks.
pub(crate) mod detect;
/// THE EXTRACTED GEMINI DIALECT, compiled back in for TEST BUILDS ONLY. Sources live in
/// `crates/busbar-llm/src/gemini`; see the `mod anthropic` doc above for the full rationale —
/// same mechanism, same crate, a different dialect module of it.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/gemini/mod.rs"]
pub mod gemini;
/// THE EXTRACTED OPENAI CHAT DIALECT, compiled back in for TEST BUILDS ONLY. Sources live in
/// `crates/busbar-llm/src/openai_chat`; see the `mod anthropic` doc above for the full
/// rationale — same mechanism, same crate, a different dialect module of it.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/openai_chat/mod.rs"]
pub mod openai_chat;
pub mod openai_family;
/// THE EXTRACTED OPENAI RESPONSES DIALECT, compiled back in for TEST BUILDS ONLY. Sources live in
/// `crates/busbar-llm/src/openai_responses`; see the `mod anthropic` doc above — same mechanism,
/// same crate, a different dialect module of it.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/openai_responses/mod.rs"]
pub mod openai_responses;
/// THE REGISTRY: `ProtocolDecl`, the built-in declaration table, and the by-name lookup that
/// replaced `protocol_for`'s match.
pub mod registry;

/// THE EXTRACTED TAIL-USAGE ISOLATION HELPER, compiled back in for TEST BUILDS ONLY. Sources live in
/// `crates/busbar-llm/src/usage_tail.rs` (the dialect readers' `recover_truncated_usage` overrides
/// call it via `super::super::usage_tail`); see the `mod anthropic` doc above — same mechanism, same
/// crate. Production core drives the readers through the vtable and never names this module directly.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/usage_tail.rs"]
pub mod usage_tail;

/// THE THREAD-LOCAL OS-ENTROPY POOL for synthesized wire ids, compiled back in for TEST BUILDS ONLY.
/// Sources live in `crates/busbar-llm/src/synth_rng.rs` (the dialect writers reach it via
/// `super::synth_rng` from a `mod.rs`); same `#[path]` dual-compile mechanism as `usage_tail` above.
/// Production core drives the writers through the vtable and never names this module directly.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/synth_rng.rs"]
pub mod synth_rng;

/// THE EXTRACTED OPENAI-FAMILY CITATION MAPPING, compiled back in for TEST BUILDS ONLY. Sources live
/// in `crates/busbar-llm/src/openai_annotations.rs` (the openai Chat/Responses codecs call it via
/// `super::super::openai_annotations`); same `#[path]` dual-compile mechanism as `mod anthropic` and
/// `usage_tail` above. Production core drives the codecs through the vtable and never names it.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/openai_annotations.rs"]
pub mod openai_annotations;

/// THE EXTRACTED IR→WIRE ENCODE HELPERS, compiled back in for TEST BUILDS ONLY. Sources live in
/// `crates/busbar-llm/src/ir_encode.rs` (the dialect writers call it via `super::ir_encode` from a
/// `mod.rs` and `super::super::ir_encode` from a `writer.rs`); same `#[path]` dual-compile mechanism
/// as `usage_tail`/`openai_annotations`. Production core drives the codecs through the vtable.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/ir_encode.rs"]
pub mod ir_encode;

/// THE EXTRACTED LEAF-OP WRITER DISPATCH, compiled back in for TEST BUILDS ONLY (G6 A4b option-a).
/// Sources live in `crates/busbar-llm/src/leaf_codec.rs` — the per-`(operation, egress-protocol)`
/// writer dispatcher the dialect leaf-op handlers route their writes through (they call it via
/// `super::super::leaf_codec`, and it reaches each dialect's write body via `super::<dialect>::…`);
/// same `#[path]` dual-compile mechanism as `ir_encode`/`usage_tail`. Production core drives the
/// codecs through the vtable and never names this module directly.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/leaf_codec.rs"]
pub mod leaf_codec;

/// THE EXTRACTED CHAT `IrHandle` + `ChatOperation`, compiled back in for TEST BUILDS ONLY (G6 A4b
/// dissolve). Sources live in `crates/busbar-llm/src/chat_handle.rs`. `ChatOperation` is the shared
/// chat cell the LLM dialects parameterize by protocol name (each dialect's `handler.rs` reaches it
/// via `super::super::chat_handle::ChatOperation`); the handle writes ITSELF onto the egress dialect
/// by protocol string. Netted here (a sibling of the dialects/`leaf_codec`) so the dialect handlers'
/// `super::super::chat_handle` resolves; `crate::ir` inside it resolves to core's root `ir`. Same
/// `#[path]` dual-compile mechanism as `leaf_codec`; production core names no chat codec.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/chat_handle.rs"]
pub mod chat_handle;

/// THE EXTRACTED SIX LEAF-OP `IrHandle`s, compiled back in for TEST BUILDS ONLY (G6 A4b dissolve).
/// Sources live in `crates/busbar-llm/src/leaf_handles.rs`; each dialect's leaf-op cell yields these
/// from `read_request`/`read_response` (reached via `super::super::leaf_handles`), and each handle
/// writes itself via the `super::leaf_codec` `(op, protocol)` dispatchers. Same `#[path]` mechanism.
#[cfg(any(test, feature = "test-support"))]
#[path = "../../../busbar-llm/src/leaf_handles.rs"]
pub mod leaf_handles;

// Private imports (NOT re-exports) for the symbols mod.rs references by bare name: the registry
// constructs each Reader/Writer below, and a test synthesizes an Anthropic request id. Every other
// caller references these at their owning module path (e.g. `crate::proto::bedrock::...`).
// The extracted dialect's codec structs, in scope for the same test surface that predates the
// extraction (the proto test modules construct them bare via `use super::*`). Present only in the
// builds that compile the dialect back in; production core has no such names.
#[cfg(test)]
use anthropic::{AnthropicReader, AnthropicWriter};
// `synth_anthropic_request_id` lives in `anthropic.rs`; mod.rs references it only from its own test
// module (production callers use `crate::proto::anthropic::synth_anthropic_request_id`). Private,
// test-gated import — NOT a re-export.
#[cfg(test)]
use anthropic::synth_anthropic_request_id;
// The extracted Bedrock and Cohere codec structs, in scope for the same test surface that predates
// the extraction. Present only in the builds that compile the dialects back in.
#[cfg(any(test, feature = "test-support"))]
#[allow(unused_imports)] // test-surface scaffolding for the netted dialect fixtures
use bedrock::{BedrockReader, BedrockWriter};
#[cfg(any(test, feature = "test-support"))]
#[allow(unused_imports)] // test-surface scaffolding for the netted dialect fixtures
use cohere::{CohereReader, CohereWriter};
// The extracted Gemini dialect's codec structs, in scope for the same test surface that predates
// the extraction. Present only in the builds that compile the dialect back in.
#[cfg(any(test, feature = "test-support"))]
#[allow(unused_imports)] // test-surface scaffolding for the netted dialect fixtures
use gemini::{GeminiReader, GeminiWriter};
// `GeminiJsonArrayFramer` lives in `gemini.rs`; mod.rs references it only from its own test module
// (production callers use `crate::proto::gemini::GeminiJsonArrayFramer`). Private, test-gated import
// — NOT a re-export.
#[cfg(test)]
use gemini::GeminiJsonArrayFramer;
// The extracted OpenAI Chat dialect's codec structs, in scope for the same test surface that
// predates the extraction. Present only in the builds that compile the dialect back in — and on the
// `test-support` gate, not bare `cfg(test)`, because `Protocol::openai()` (which names them) is on
// that gate for a sibling dialect crate's test build.
#[cfg(any(test, feature = "test-support"))]
#[allow(unused_imports)] // test-surface scaffolding for the netted dialect fixtures
use openai_chat::{OpenAiReader, OpenAiWriter};
// The extracted OpenAI Responses codec structs, in scope for the same test surface that predates
// the extraction. Present only in the builds that compile the dialect back in.
#[cfg(any(test, feature = "test-support"))]
#[allow(unused_imports)] // test-surface scaffolding for the netted dialect fixtures
use openai_responses::{ResponsesReader, ResponsesWriter};
// The declaration vocabulary, re-exported at `crate::proto::…` so every protocol module (each of
// which does `use super::*`) can state its `DECL` without importing the registry by path.
pub use registry::{
    decl_for, ClaimStrength, ClaimsFn, IngressAuth, ProtocolDecl, ResidualClaimsFn,
    VendorResponseMetadataFn,
};

/// Canonical protocol-id vocabulary. Every PRODUCTION comparison / match arm / registry insertion on
/// a protocol name goes through these consts so the router, dispatch, projections, and registry
/// cannot drift on a typo'd literal. Tests keep raw literals by convention (golden-value checks).
pub const PROTO_ANTHROPIC: &str = "anthropic";
pub const PROTO_OPENAI: &str = "openai";
pub const PROTO_GEMINI: &str = "gemini";
pub const PROTO_BEDROCK: &str = "bedrock";
pub const PROTO_COHERE: &str = "cohere";
pub const PROTO_RESPONSES: &str = "responses";

// The LLM chat dialects' shared head-key set (`model`/`stream`/`stream_options`/`system`) RELOCATED
// to the LLM plugin (`busbar_llm::proto_codec::LLM_CHAT_HEAD_KEYS`) — it is LLM vocabulary, so it
// belongs with the dialects that declare it, not in this neutral crate. Core unions whatever
// `ProtocolDecl::head_keys` each registered protocol declares (see `registry::Registry::new`) and
// names none of the keys itself.

/// Every protocol name busbar ships a wire CODEC for — the set a provider's `protocol:` may name,
/// and what the config validator rejects against so an unknown protocol is COLLECTED with every
/// other config error rather than escaping to a lone `die()` at lane construction.
///
/// DERIVED from the declarations (`ProtocolDecl::codec`), not maintained beside them. It used to be
/// a hand-written const that a `debug_assert` compared against the constructor match it had to agree
/// with — two lists and an assertion to keep them equal, where there is now one list and nothing to
/// drift from.
///
/// DECLARATION ORDER IS PRESERVED, AND IT IS LOAD-BEARING: `telemetry` indexes its per-protocol
/// metric families by POSITION in this slice — `AppSlots::build` banks one family per entry in
/// order, and `request_family` finds it again with `.position()`. That stays sound for the reason it
/// always did, now stated rather than assumed: the slice is folded ONCE, from a `&'static`
/// declaration table, inside a `OnceLock`, and no path appends to it afterwards — so the list a
/// family was banked against and the list an index is computed from are the same list. A name that
/// is not in it MISSES and falls through to `metrics.rs`'s cached-handle path, which renders a
/// byte-identical series, so even a miss is not an operator-visible change.
///
/// THE EMPTY ANSWER IS A REAL ANSWER and `config_validate` has an arm for it: this was a
/// compile-time const that could not be empty, and a derived list can be, so the site that refuses
/// operator config on it names that cause once rather than refusing every provider with an empty
/// "must be one of:" tail. `registry_tests::the_derived_protocol_list_is_not_empty` pins the other
/// half.
// `pub` (not `pub(crate)`): the LLM `PLANE_DECL` — which relocated to the `busbar-llm` plugin with
// the rest of the plane's vocabulary — declares `wire_format_names: busbar_core::proto::known_protocols`
// (the model plane's wire formats ARE the registered codec protocols). The plane crate names this fn
// cross-crate to point the field at it, so it must be reachable outside core. Still a pure read of the
// registry aggregate; no protocol vocabulary crosses here, only the neutral derived list.
pub fn known_protocols() -> &'static [&'static str] {
    registry::registry().codec_protocols()
}

// THE LLM PLANE'S VOCABULARY DECLARATION RELOCATED to the `busbar-llm` plugin (`busbar_llm::PLANE_DECL`)
// — it is the LLM plane's statement about ITSELF, so it leaves core with the plane exactly as the MCP
// and A2A `PLANE_DECL`s live in their own crates. The composition root installs it via
// `register_planes` (`crates/busbar/src/main.rs`, behind `proto-llm`); core's own test binary names it
// through the `#[cfg(test)]` row in `plane::registry::BUILTIN_PLANE_DECLS` (the honest crate boundary,
// the plane's PUBLIC decl), so both shapes boot the same `[llm, mcp, a2a]` plane list. Its
// `wire_format_names` field still points at [`known_protocols`] here (now `pub`) — the model plane's
// wire formats ARE the registered codec protocols, wherever the declaration itself lives.

/// Resolve a provider's configured protocol NAME to the registry's interned `&'static str` for the
/// lane-build path, or `None` for an unknown name or one that declares no wire codec (MCP/A2A are not
/// lane protocols). Post-G6-A4b a lane stores this name, not a constructed `Protocol` (the concrete
/// codec lives in the plugin and core reaches it via `decl_for(name).dialect()`), so the old
/// `ProtocolRegistry` `Arc<Protocol>` cache is gone — this is the whole of what lane-build needed from it.
pub(crate) fn lane_protocol_name(name: &str) -> Option<&'static str> {
    registry::decl_for(name)
        .filter(|d| d.codec.is_some())
        .map(|d| d.name)
}

pub(crate) fn convert_headers(headers: Vec<(HeaderName, HeaderValue)>) -> http::header::HeaderMap {
    let mut map = http::header::HeaderMap::new();
    for (name, value) in headers {
        map.insert(name, value);
    }
    map
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

/// THE REGISTRY'S OWN TESTS, including the acceptance test for the whole step: a protocol nobody
/// wrote resolves, dispatches and is observable with no edit to core.
#[cfg(test)]
#[path = "tests/registry_tests.rs"]
mod registry_tests;

#[cfg(test)]
#[path = "tests/stream_fanout_tests.rs"]
mod stream_fanout_tests;

#[cfg(test)]
#[path = "tests/stream_translate_tests.rs"]
mod stream_translate_tests;

/// Change B step 2 — SAME-PROTOCOL FIDELITY PROOF. For each of the 6 protocols, replay captured
/// native streaming frames through a `StreamTranslate::new_same_proto` translator and assert the
/// concatenated `feed` + `finish` output is BYTE-FOR-BYTE identical to the input frames (the verbatim
/// short-circuit must never re-serialize). Also asserts the IR-derived `usage()` (the A-tap billing
/// value) matches the token counts embedded in the captured frames. The three HIGHEST-RISK paths
/// (bedrock binary eventstream, gemini non-`?alt=sse` JSON-array source frames, openai bare `data:`)
/// get dedicated frame-for-frame assertions.
#[cfg(test)]
#[path = "tests/same_proto_fidelity_tests.rs"]
mod same_proto_fidelity_tests;

#[cfg(test)]
#[path = "tests/gemini_tests.rs"]
mod gemini_tests;

#[cfg(test)]
#[path = "tests/context_length_tests.rs"]
mod context_length_tests;

#[cfg(test)]
#[path = "tests/gemini_integration_tests.rs"]
mod gemini_integration_tests;

#[cfg(test)]
#[path = "tests/response_format_matrix_tests.rs"]
mod response_format_matrix_tests;

#[cfg(test)]
#[path = "tests/stop_reason_matrix_tests.rs"]
mod stop_reason_matrix_tests;

#[cfg(test)]
#[path = "tests/image_source_matrix_tests.rs"]
mod image_source_matrix_tests;

#[cfg(test)]
#[path = "tests/translate_parity_golden_tests.rs"]
mod translate_parity_golden_tests;

/// Cross-protocol translate-path byte-parity goldens for the OTHER high-traffic dialect pairs
/// (anthropic/openai/gemini/responses), extending the single anthropic⇄openai pair above with the
/// same bless-mode generation and id-normalization discipline.
#[cfg(test)]
#[path = "tests/translate_parity_cross_pairs_tests.rs"]
mod translate_parity_cross_pairs_tests;

/// READ → WRITE round-trip fidelity per protocol, with an EXACT allow-list of accepted divergences.
/// The complement to `same_proto_fidelity_tests` (which covers the byte-verbatim short-circuit that
/// never enters the IR at all); this one drives the readers and writers that CAN lose.
#[cfg(test)]
#[path = "tests/roundtrip_fidelity_tests.rs"]
mod roundtrip_fidelity_tests;

/// ADVERSARIAL / HOSTILE-BODY matrix for the LLM cross-protocol path: drives all six readers (and
/// the `StreamTranslate` seam) through non-object bodies, wrong-typed structural arrays, unknown
/// terminal enums, hostile stream events (u64::MAX index / wrong-typed delta+usage / empty-type
/// frames), over-deep nesting, truncated + garbage SSE, and oversized-but-valid bodies — asserting
/// the CURRENT post-hardening contract of clean refusal or clean degrade, never a panic/hang/leak.
#[cfg(test)]
#[path = "tests/adversarial_tests.rs"]
mod adversarial_tests;

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral protocol vocabulary relocated DOWN from `busbar-core` (Batch A).
//!
//! These are dependency-free protocol atoms — a wire error-`type` string and the declared inbound
//! auth scheme — that a plane/plugin crate (`busbar-mcp`) names WITHOUT needing `busbar-core`.
//! `busbar-core` re-exports each from its original home (`proto::openai_family` / `proto::registry`)
//! so every existing in-core and plugin caller compiles unchanged. Values are byte-identical to the
//! pre-move definitions.

/// OpenAI error `type` for a missing or invalid API key.
pub const ERR_TYPE_AUTHENTICATION: &str = "authentication_error";

/// WHICH INBOUND AUTH SCHEME a protocol's clients present. DECLARED metadata, never a branch: the
/// verification itself stays in the auth layer, which has the governance key lookup and the shared
/// signing helpers. This replaces `ProtocolReader::uses_sigv4_ingress_auth()`, which was the same
/// fact answered through a vtable — and answering it through a vtable meant allocating a reader to
/// ask a `&'static` question.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IngressAuth {
    /// A bearer token / API key in a header (every protocol but Bedrock).
    Bearer,
    /// An AWS SigV4 request signature (Bedrock's ingress shape).
    SigV4,
}

/// A streaming JSON-array reframer: consumes a protocol's SSE response bytes and re-emits them as one
/// streaming JSON array (`[{...},{...}]`), the body shape a non-SSE streaming request expects. The
/// agnostic forward path holds one `Box<dyn ArrayStreamFramer>` (built via
/// `ProtocolWriter::make_array_stream_framer`) and drives it, so it names no protocol's framer type.
/// The sole implementor is `gemini::GeminiJsonArrayFramer` (Gemini `:streamGenerateContent` without
/// `?alt=sse`). The trait exposes only the SUBSET of that type's API the agnostic core needs (`feed`,
/// `finish_for_translate`, `finish_with_server_error`); the type's raw `finish` and its low-level
/// `finish_with_error(code, status, …)` are absent, since the core never passes a wire status code.
///
/// RELOCATED DOWN from `busbar-core` (`proto`) so the dialect crate names it without reaching into
/// `busbar-core`; core re-exports it from `busbar_core::proto::ArrayStreamFramer`.
pub trait ArrayStreamFramer: Send {
    /// Feed a chunk of SSE bytes; return JSON-array bytes for whatever complete frames are now
    /// available (empty if only a partial frame is buffered).
    fn feed(&mut self, chunk: &[u8]) -> Vec<u8>;

    /// Close the array at end-of-stream when this framer sits DOWNSTREAM of a cross-protocol
    /// `StreamTranslate`; pass `translate_aborted = StreamTranslate::aborted()` so a translate-side
    /// abort surfaces as a trailing error element instead of a silent truncation. Idempotent.
    fn finish_for_translate(&mut self, translate_aborted: bool) -> Vec<u8>;

    /// Terminate the array with a trailing protocol-shaped SERVER-ERROR element, then the closing `]`.
    /// Used on a mid-stream upstream transport failure (and on internal abort). The agnostic caller
    /// supplies only the human-readable `message`; the implementor owns the wire status/code shape (e.g.
    /// Gemini emits a `google.rpc.Status` with HTTP 500 / gRPC `INTERNAL`), so the core names no
    /// protocol wire value. Idempotent.
    fn finish_with_server_error(&mut self, message: &str) -> Vec<u8>;
}

/// **THE 4TH NEUTRAL SEAM (G6 A4b, owner-ruled 2026-08-20).** The per-PROTOCOL computed-codec facade
/// the operation-blind driver reads, so core names ZERO concrete LLM IR and zero `ProtocolReader`/
/// `ProtocolWriter` at its call sites. Every method here has a NEUTRAL signature (bytes / `Value` /
/// `bool` / `TokenUsage` / neutral tuples — `IrError` is `breaker::CanonicalSignal`); the concrete
/// codec lives behind the implementor.
///
/// This is the sibling of the per-CELL `TranslateCodec` — these are the ~10 computed methods the
/// engine/wire/health/hooks/response_body driver called through the `Protocol` bundle
/// (`protocol_for(name).writer()/.reader().X()`) that are protocol-level, not operation-level, and so
/// have no home on `TranslateCodec`. Reached via `decl_for(name).dialect()`. Its sole implementor
/// (`DialectRef`) lives in `busbar-llm` and forwards to that crate's writer/reader.
///
/// RELOCATED DOWN from `busbar-core` (`proto`) so the dialect crate names it without reaching into
/// `busbar-core`; core re-exports it from `busbar_core::proto::DialectCodec`.
pub trait DialectCodec: Send + Sync {
    fn probe_body(&self, model: &str) -> Vec<u8>;
    fn apply_rewrite_to_ingress_body(
        &self,
        obj: &mut serde_json::Map<String, serde_json::Value>,
        messages: &[serde_json::Value],
        tools: &[serde_json::Value],
    ) -> bool;
    fn recover_truncated_usage(&self, tail: &[u8]) -> Option<crate::billing::TokenUsage>;
    fn ingress_response_request_id(
        &self,
        upstream_request_id: Option<&str>,
    ) -> Option<(&'static str, String)>;
    fn write_error(&self, status: u16, kind: &str, message: &str) -> serde_json::Value;
    fn requested_candidate_count(&self, body: &serde_json::Value) -> Option<u64>;
    fn write_response_exception(
        &self,
        err: &crate::breaker::CanonicalSignal,
    ) -> Option<(String, String)>;
    fn write_error_frame(
        &self,
        err: &crate::breaker::CanonicalSignal,
    ) -> Option<(String, serde_json::Value)>;
    fn wants_array_stream(&self, body: &serde_json::Value) -> bool;
    fn inject_response_metrics(&self, value: &mut serde_json::Value, elapsed_ms: Option<u64>);
    fn attach_error_response_headers(
        &self,
        headers: &mut axum::http::HeaderMap,
        kind: &str,
        envelope: &serde_json::Value,
    );
    /// This protocol's upstream-error vocabulary (the reader's `extract_error`), reached by name so
    /// `handlers::protocol_error` names no concrete reader. `status` is the raw HTTP code.
    fn extract_error(&self, status: u16, body: &[u8]) -> crate::breaker::RawUpstreamError;
    /// The dialect's array-stream framer for a Gemini-style JSON-array ingress client, or `None` when
    /// this protocol frames no array stream — the writer method reached by name at the SSE seam.
    fn make_array_stream_framer(&self) -> Option<Box<dyn ArrayStreamFramer>>;
    /// The upstream request path for a (streaming) request against this dialect — the health probe's
    /// URL builder reaches it here rather than through the concrete writer.
    fn upstream_path_for_stream(&self, model: &str, stream: bool) -> String;
    /// Install the authoritative lane model into a same-protocol passthrough body if the dialect
    /// requires it; returns whether the body changed (a pristine-passthrough invalidator).
    fn rewrite_model_if_needed(&self, body: &mut serde_json::Value, model: &str) -> bool;
    /// Reshape a path-base (URL-model) lane's body for this dialect (e.g. Claude-on-Vertex drops
    /// `model`, adds `anthropic_version`); returns whether the body changed.
    fn reshape_for_path_base(&self, body: &mut serde_json::Value) -> bool;
}

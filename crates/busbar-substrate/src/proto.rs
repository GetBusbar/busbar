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

/// Per-request signing context. Most protocols' `auth_headers` ignore this; protocols that
/// sign the whole request (AWS SigV4 for Bedrock) need the method/host/path/body/time.
///
/// RELOCATED DOWN from `busbar-core` (`proto`) so the substrate `ProtocolDecl`'s
/// `egress_auth_headers` builder names it without reaching into `busbar-core`; core re-exports it
/// from `busbar_core::proto::SigningContext` so every in-core / plugin caller is unchanged. Its only
/// non-primitive field is `busbar_api::UpstreamCreds` (a `busbar-api` leaf type), so the relocation
/// carries no core-only machinery.
pub struct SigningContext<'a> {
    /// Upstream host (no scheme), e.g. `bedrock-runtime.us-east-1.amazonaws.com`. Borrowed from the
    /// lane's precomputed `signing_host` on the forward path (no per-request allocation); only the
    /// Bedrock SigV4 writer reads it.
    pub host: &'a str,
    /// URI-encoded request path (no query), e.g. `/model/anthropic.claude%3A0/converse`. Borrowed
    /// (like `host`): on the forward path it comes from the lane's boot-precomputed egress target,
    /// so building the context allocates nothing; only the Bedrock SigV4 writer reads it.
    pub canonical_uri: &'a str,
    /// The exact request body bytes that will be sent.
    pub body: &'a [u8],
    /// Unix epoch seconds at signing time.
    pub timestamp_epoch: u64,
    /// The UPSTREAM-credential mode for this request. Lets a writer resolve a credential whose scheme
    /// is otherwise ambiguous (e.g. Anthropic's API-key-vs-Bearer choice) to the single native header
    /// the mode implies — `Passthrough` forwards the caller's Bearer token; `Own` presents the
    /// configured-key shape. Without it, an ambiguous credential must emit BOTH headers, which is an
    /// upstream-distinguishability tell no native client produces. (The upstream-credential concern,
    /// split out of the front-door auth mode in slice 2d.)
    pub upstream_creds: busbar_api::UpstreamCreds,
}

/// A protocol's declared egress credential-header builder: the resolved per-request credential
/// plus the signing context in, the header pairs to attach out. See
/// [`ProtocolDecl::egress_auth_headers`].
///
/// RELOCATED DOWN from `busbar-core` (`proto::registry`) with [`ProtocolDecl`]; it now names only
/// substrate/`axum` types (`SigningContext`, `axum::http`), so the decl carries no core edge. Core
/// re-exports it from `busbar_core::proto::registry::EgressAuthHeaders`.
pub type EgressAuthHeaders =
    fn(&str, &SigningContext) -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)>;

/// EVERYTHING CORE KNOWS ABOUT A PROTOCOL, declared once by the protocol itself.
///
/// Core routes, mounts, labels and bounds from this and from nothing else. Each field replaces
/// either a `match` on a protocol name or a vtable sweep that allocated to read a constant; the
/// doc on each says which.
///
/// RELOCATED DOWN from `busbar-core` (`proto::registry`) so an extracted protocol crate (`busbar-mcp`,
/// and the `busbar-llm` dialects) names it WITHOUT reaching into `busbar-core`: every field type is
/// now substrate/`busbar-api`/`axum`/`std`. The registry singleton (`Registry` / `BUILTIN_DECLS` /
/// `install_protocols` / `decl_for`) stays in core and holds this type through the re-export at
/// `busbar_core::proto::ProtocolDecl`. The `path_ingress` field it once carried (which named the
/// core-only `Arrival`) is SPLIT OFF into a core-owned, protocol-name-keyed side-registration
/// (`busbar_core::ingress::path_ingress`), so the decl names zero core types.
pub struct ProtocolDecl {
    /// The registry key, and the metrics label. **OPERATOR-VISIBLE:** a protocol name appears in
    /// dashboards and in `providers.*.protocol` config, so renaming one re-bases a metric series
    /// and invalidates a config file. Replaces the `match name` arm.
    pub name: &'static str,

    /// This protocol's NEUTRAL computed-codec facade ([`DialectCodec`]), or `None` for a protocol
    /// that serves operations without a cross-dialect codec (MCP, whose IR is its own). Presence
    /// alone is the "declares a codec" fact the fields below let a caller read without touching it.
    ///
    /// `&'static dyn`, EXACTLY like the sibling [`Self::handler`], and that shape is the seam's
    /// perf contract: the facade is stateless, so handing out a static borrow is a pure-memory
    /// read. The `fn() -> Box<dyn DialectCodec>` this replaced minted a fresh heap allocation on
    /// EVERY `dialect()` call — and `dialect()` sits on the per-request egress/response path (UA,
    /// accept, request-id attach, pristine-head checks), so the plane seam that was designed to
    /// cost nanoseconds was paying an allocator round-trip per touch instead.
    pub codec: Option<&'static dyn DialectCodec>,

    /// The cell that serves one exchange on this protocol. Replaces `handlers::request_handler`'s
    /// match. `None` would be a protocol that declares itself and serves nothing; every declaration
    /// in the tree today has one.
    pub handler: Option<&'static dyn crate::handlers::RequestHandler>,

    /// THE VERBS this protocol serves — one [`busbar_api::operation::Operation`] (`Verb { op, name }`
    /// pair) per operation its handler answers. Bounded at load and enumerable at boot (never
    /// request-derived), which is what makes their names safe as metric labels.
    pub verbs: &'static [busbar_api::operation::Operation],

    /// TOP-LEVEL body keys the pre-materialized path may point-read, DOM-free. The registry unions
    /// these with [`Self::array_stream_shim_key`] once, at boot.
    pub head_keys: &'static [&'static str],

    /// The `Content-Type` this protocol's writer emits on a STREAMING response, or `None` for a
    /// protocol that does not stream.
    pub streaming_content_type: Option<&'static str>,

    /// The router's array-stream shim key for this protocol (only Gemini has one: a marker injected
    /// into a non-`alt=sse` request body and stripped before egress).
    pub array_stream_shim_key: Option<&'static str>,

    /// This protocol's NATIVE tool-call id prefix, or `None` when it carries no tool id on the wire
    /// (Gemini correlates by name) or uses free-form ids with no canonical prefix (Cohere).
    pub native_tool_id_prefix: Option<&'static str>,

    /// Which inbound auth scheme this protocol's clients present.
    pub ingress_auth: IngressAuth,

    /// This protocol's NATIVE egress credential-header builder, or `None` for a protocol whose
    /// scheme is one of the shared ones the auth layer keeps (`egress_auth::resolve`'s bearer /
    /// api-key-header / SigV4 arms). The builder receives the resolved per-request credential and the
    /// [`SigningContext`] (`Own | Passthrough` mode plus what a signer needs) and returns
    /// the header pairs to attach — the exact `CredentialProvider::headers_for` shape, as declared
    /// data instead of a core `match`.
    pub egress_auth_headers: Option<EgressAuthHeaders>,

    /// Whether a STREAMING response on this protocol reports token usage only when the request
    /// explicitly opted in (OpenAI Chat Completions' `stream_options.include_usage`). `false` — the
    /// default answer for every other dialect — means the stream reports usage unconditionally.
    pub stream_usage_requires_opt_in: bool,

    // ── PROMOTED WRITER FACTS (G6 step A1) ─────────────────────────────────────────────────────────
    // Constant, no-argument, IR-free facts that used to be answered off the `ProtocolWriter` vtable.
    /// Replaces `ProtocolWriter::requires_max_tokens()`. Whether this dialect hard-rejects a request
    /// with no `max_tokens` (Anthropic Messages 400s; the forward path injects the lane default).
    pub requires_max_tokens: bool,

    /// Replaces `ProtocolWriter::stop_sequence_cap()`. The published cap on stop sequences and the
    /// display name to cite in a rejection, or `None` when the dialect enforces none.
    pub stop_sequence_cap: Option<(usize, &'static str)>,

    /// Replaces `ProtocolWriter::cache_markers_model_gated()`. Whether this dialect's native cache
    /// marker is model-gated (Bedrock `cachePoint`), so the cross-protocol seam clears the cache ask
    /// unless the lane declares `prompt_caching`.
    pub cache_markers_model_gated: bool,

    /// Replaces `ProtocolWriter::fills_thought_signature()`. Whether egress fills the Gemini 3
    /// `thoughtSignature` sentinel on a translated request.
    pub fills_thought_signature: bool,

    /// Replaces `ProtocolWriter::frame_after_message_start()`. A framed wire frame this dialect emits
    /// immediately after `message_start` on a translated stream (Anthropic's `event: ping`), or `None`.
    pub frame_after_message_start: Option<&'static [u8]>,

    /// Replaces `ProtocolWriter::reshapes_body_at_path_base()` (the PREDICATE only). Whether this
    /// dialect's body must be reshaped when the lane carries a `path_base` (Claude-on-Vertex).
    pub reshapes_body_at_path_base: bool,

    /// Replaces `ProtocolWriter::max_cache_control_breakpoints()`. The maximum `cache_control`
    /// breakpoints this dialect accepts on one request, or `None` when the vendor publishes no cap.
    pub max_cache_control_breakpoints: Option<usize>,

    /// Replaces `ProtocolWriter::quota_exceeded_status()`. The native HTTP status a quota/budget
    /// exhaustion maps to (429 for most; Bedrock's `ServiceQuotaExceededException` is 400).
    pub quota_exceeded_status: axum::http::StatusCode,

    /// Replaces `ProtocolWriter::ingress_is_eventstream()`. True when this protocol's ingress client
    /// decodes a binary `application/vnd.amazon.eventstream` body (native AWS SDK Bedrock).
    pub ingress_is_eventstream: bool,

    /// Replaces `ProtocolWriter::emits_sse_done_terminator()`. True when this protocol's streamed
    /// response ends with the literal `data: [DONE]` terminator (OpenAI Chat Completions).
    pub emits_sse_done_terminator: bool,

    /// Replaces `ProtocolWriter::max_citations_per_delta()`. The maximum citations one streamed
    /// `citations_delta`-equivalent event may carry (Anthropic frames exactly one), or `None`.
    pub max_citations_per_delta: Option<usize>,

    /// Replaces `ProtocolWriter::egress_user_agent()`. The plausible native-SDK `User-Agent` for THIS
    /// egress protocol (a backend-facing fingerprint guard).
    pub egress_user_agent: &'static str,

    /// Replaces `ProtocolWriter::has_model_in_url()`. True when this protocol carries the model in the
    /// URL path rather than the body (Gemini, Bedrock), so a same-protocol passthrough strips body
    /// `model`. A protocol declaring `true` MUST register a `path_ingress` (see
    /// `busbar_core::ingress::path_ingress`); the composition root asserts this at boot.
    pub has_model_in_url: bool,

    /// Replaces `ProtocolWriter::auth_failure_status_and_kind()`. The HTTP status and error `kind` a
    /// bad/missing credential yields, matched to what the genuine vendor returns.
    pub auth_failure_status_and_kind: (axum::http::StatusCode, &'static str),

    /// Replaces `ProtocolWriter::ingress_relays_amzn_headers()`. True when this protocol's ingress
    /// client expects `x-amzn-RequestId` (and `x-amzn-errortype` on errors) on every response.
    pub ingress_relays_amzn_headers: bool,

    /// Replaces `ProtocolWriter::ingress_relayed_response_header_names()`. The upstream response
    /// header names a same-protocol passthrough forwards verbatim.
    pub ingress_relayed_response_header_names: &'static [&'static str],

    /// Replaces `ProtocolWriter::auth_failure_message()`. The vendor-plausible auth-failure wire
    /// message this dialect lands verbatim in the native error body.
    pub auth_failure_message: &'static str,

    /// Replaces `ProtocolWriter::uses_array_stream_shim()`. True when this protocol's ingress client
    /// expects a JSON-array (non-SSE) streamed body (Gemini without `?alt=sse`).
    pub uses_array_stream_shim: bool,

    /// Replaces `ProtocolWriter::has_native_path_not_found()`. True when this protocol has a native
    /// path-not-found envelope with a protocol-specific message format (Gemini).
    pub has_native_path_not_found: bool,

    /// Replaces `ProtocolWriter::egress_accept()` (the STREAMING half of it). The native-SDK `Accept`
    /// header value THIS egress protocol sends on a STREAMING request — `text/event-stream` for every
    /// SSE-framed dialect, `application/vnd.amazon.eventstream` for Bedrock. The NON-streaming value
    /// is universally `application/json`, so the caller reads
    /// `if wants_stream { decl.egress_stream_accept } else { APPLICATION_JSON }`.
    pub egress_stream_accept: &'static str,

    /// This protocol's `GET /v1(beta)/models` (list-models) response ENVELOPE builder, or `None`
    /// for a protocol that serves no model-discovery surface. Given the visible model/pool names
    /// (already governance-filtered and ordered by core), it returns the dialect-shaped JSON body.
    pub models_list_envelope: Option<fn(&[&str]) -> serde_json::Value>,
}

impl ProtocolDecl {
    /// True when this protocol authenticates INBOUND requests with AWS SigV4 rather than a bearer
    /// token. The auth layer's one consumer of [`ProtocolDecl::ingress_auth`], kept as a predicate
    /// so the front door reads a QUESTION rather than comparing an enum it would then have to
    /// exhaust. `pub` (not `pub(crate)` as in its core home) so core's auth layer names it across the
    /// crate boundary after the relocation.
    pub fn uses_sigv4_ingress_auth(&self) -> bool {
        matches!(self.ingress_auth, IngressAuth::SigV4)
    }

    /// This protocol's neutral computed-codec facade ([`DialectCodec`]) — the 4th seam the
    /// operation-blind driver reads instead of `protocol_for(name).writer()/.reader()`. `None` for a
    /// protocol that declares no codec (MCP/A2A). A pure-memory read of the declaration's static
    /// borrow: no allocation, no construction — see [`Self::codec`] for why that is load-bearing.
    pub fn dialect(&self) -> Option<&'static dyn DialectCodec> {
        self.codec
    }
}

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

/// Busbar-internal `provider_signal` label for an IR-parse failure (the LANE label the breaker/metrics
/// layer reads to classify a translation/parse error). A busbar-internal signal, NOT a wire shape, so
/// it lives in the agnostic proto layer; the per-protocol readers reference it rather than re-spelling
/// the literal.
pub const SIGNAL_IR_PARSE: &str = "ir_parse";

/// The OpenAI-style SSE stream terminator sentinel (`data: [DONE]`). The bare token is matched by the
/// cross-protocol streaming core and several readers; the full framed bytes are emitted on egress.
/// Shared here so no reader/writer re-spells either form.
pub const SSE_DONE_SENTINEL: &str = "[DONE]";
pub const SSE_DONE_FRAME: &[u8] = b"data: [DONE]\n\n";

/// The HTTP `Authorization` header name (lowercase, canonical). Emitted by the bearer/SigV4 auth-header
/// builders across protocols; named once so no builder re-spells it.
pub const HDR_AUTHORIZATION: &str = "authorization";

/// An IR-level error, currently an alias for `CanonicalSignal` (the normalized error signal).
pub type IrError = crate::breaker::CanonicalSignal;

/// Build the `Authorization: Bearer <key>` header pair for the pure-Bearer protocol writers
/// (OpenAI, `/v1/responses`, Gemini's `x-goog`… aside, Cohere). Shared so the warn+OMIT policy lives
/// in ONE place rather than being copy-pasted (and drifting) per writer.
///
/// `HeaderValue::from_str` rejects ASCII control bytes (a stray CR/LF/NUL a config system may have
/// injected). The previous per-writer `unwrap_or_else(HeaderValue::from_static(""))` SILENTLY emitted
/// a syntactically empty `Authorization: ` header — the upstream then 401s every request on the lane
/// with no proxy-side signal, and the empty-Bearer form is itself a fingerprinting tell a backend can
/// compare against well-formed tokens. Instead we surface a coded diagnostic (BUSBAR-7087, naming the
/// protocol so the operator can locate the misconfigured lane) and OMIT the header entirely (empty
/// Vec). The request is still sent (the trait can't refuse it here) and the upstream answers 401, but
/// the log line tells the operator the lane's credential bytes are invalid. The key is NEVER logged (it is the
/// secret); only the protocol name and the fact that the bytes are malformed.
pub fn bearer_auth_headers(proto: &str, key: &str) -> Vec<(HeaderName, HeaderValue)> {
    match HeaderValue::from_str(&format!("Bearer {key}")) {
        Ok(value) => vec![(HeaderName::from_static(HDR_AUTHORIZATION), value)],
        Err(_) => {
            crate::diagnostics::diag_debug!(
                crate::diagnostics::PROTO_AUTH_INVALID_HEADER_BYTES,
                protocol = proto,
                "authorization credential contains invalid header bytes (ASCII control character); \
                 omitting auth header — upstream will reject with 401"
            );
            Vec::new()
        }
    }
}

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
    let present: Vec<&str> = match egress {
        PROTO_GEMINI => ["safetyRatings"]
            .into_iter()
            .filter(|k| {
                body.get("candidates")
                    .and_then(|c| c.as_array())
                    .is_some_and(|cands| cands.iter().any(|c| c.get(k).is_some()))
            })
            .collect(),
        // Bedrock Converse returns the guardrail assessment under a top-level `trace`
        // (`trace.guardrail`), present only when the request asked for it.
        PROTO_BEDROCK => ["trace"]
            .into_iter()
            .filter(|k| body.get(k).is_some())
            .collect(),
        _ => Vec::new(),
    };
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
pub const BASE62_ALPHABET: &[u8; 62] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const BASE62_REJECT_THRESHOLD: u8 = 248;

/// Client-visible detail string for a mid-stream abort (the upstream connection dropped or a
/// translate step failed after first byte). Lives in the proto layer — the lowest common ancestor —
/// because BOTH `proxy engine` (SSE/forward abort path) and the Bedrock-eventstream reassembler in this
/// module emit it, and `proxy engine → proto` is the only legal dependency direction. Single source of
/// truth so the abort text a client sees is identical on every framing.
pub const STREAM_ABORT_DETAIL: &str = "The response stream was interrupted.";

/// THE RESIDUAL ARM of the ingress resolver: which LLM wire dialect a path names, from its shape
/// alone. `None` when it names none.
///
/// ## This is not the whole answer, and it must not be called as if it were
///
/// The whole answer is [`crate::plane::PlaneDispatch::ingress_of`], and this function is the arm it
/// reaches only AFTER the mount table has declined the path. That ordering is the fix for a shipped
/// defect: while this was the canonical classifier, it was consulted for paths a plane had been
/// MOUNTED on, knew nothing of mounts, and answered `openai` for every one of them — so an
/// oversized POST to `/mcp` came back in an OpenAI envelope an MCP client cannot decode. A path
/// shape can only ever answer for the residual, because a mount is a fact about the deployment and
/// no amount of looking at a URL will reveal it. `ingress_of` is therefore the only caller.
///
/// ## There is no `else { openai }` any more, and that is the point
///
/// The old tail arm claimed every unclassifiable path for OpenAI, which read as a harmless default
/// and was in fact the resolver asserting a protocol identity for paths that carry none. What to
/// say to a caller whose dialect is unknown is a decision — a real one, taken in
/// `ingress::native_error`, where the alternatives are visible — not something a classifier should
/// smuggle in as a fallthrough.
///
/// Check order is significant: the more specific Gemini/Bedrock surfaces are tested before the
/// generic `/v1/messages` / `/v1/chat/completions` suffixes.
///
/// The `/model/...` arm REQUIRES the `/converse` or `/converse-stream` suffix before classifying as
/// bedrock: Bedrock's Converse API is `/model/<id>/converse[-stream]`, so a non-Converse `/model/...`
/// path (e.g. `/model/foo/bar`, or a pool literally named "model" hitting `/model/v1/messages`) must
/// NOT be handed a Bedrock-shaped envelope — it falls through to the `/v1/messages` (anthropic) arm
/// or the OpenAI default, matching what a real client speaking that protocol expects.
pub(crate) fn residual_dialect_for_path(path: &str) -> Option<&'static str> {
    Some(if path.starts_with("/v1beta/models") {
        // `/v1beta/models/...` is a Gemini-only surface (OpenAI has no v1beta), so always Gemini.
        PROTO_GEMINI
    } else if path.starts_with("/v1/models/") {
        // `/v1/models/...` is ambiguous: Gemini packs a `:<action>` into the LAST path segment
        // (`/v1/models/gemini-pro:generateContent`), whereas the OpenAI SDK's `model.retrieve`
        // issues `GET /v1/models/{id}`. A naive `contains(':')` mis-classifies OpenAI model ids that
        // legitimately contain colons (fine-tuned `ft:gpt-3.5-turbo:my-org::abc123`, deployment-style
        // `gpt-4o:deployment`) as Gemini, handing a real OpenAI `model.retrieve` an undecodable Gemini
        // error envelope. Distinguish the Gemini `:<action>` form by matching ONLY the known Gemini
        // method suffixes; anything else (including colon-bearing OpenAI model ids) → OpenAI.
        let last_segment = path.rsplit('/').next().unwrap_or("");
        const GEMINI_ACTIONS: [&str; 7] = [
            ":generateContent",
            ":streamGenerateContent",
            ":countTokens",
            ":embedContent",
            ":batchGenerateContent",
            ":generateAnswer",
            ":batchEmbedContents",
        ];
        if GEMINI_ACTIONS.iter().any(|a| last_segment.ends_with(a)) {
            PROTO_GEMINI
        } else {
            PROTO_OPENAI
        }
    } else if path.starts_with("/model/")
        && (path.ends_with("/converse") || path.ends_with("/converse-stream"))
    {
        PROTO_BEDROCK
    } else if path == "/v1/messages" || path.ends_with("/v1/messages") {
        PROTO_ANTHROPIC
    } else if path == "/v1/chat/completions" {
        PROTO_OPENAI
    } else if path == "/v2/chat" {
        PROTO_COHERE
    } else if path == "/v1/responses" {
        PROTO_RESPONSES
    } else {
        // NAMES NO DIALECT. Not "openai by default": the path carries no evidence either way, and
        // saying so is the whole reason this returns an `Option`.
        return None;
    })
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

/// Per-request signing context. Most protocols' `auth_headers` ignore this; protocols that
/// sign the whole request (AWS SigV4 for Bedrock) need the method/host/path/body/time.
pub struct SigningContext<'a> {
    /// Upstream host (no scheme), e.g. `bedrock-runtime.us-east-1.amazonaws.com`. Borrowed from the
    /// lane's precomputed `signing_host` on the forward path (no per-request allocation); only the
    /// Bedrock SigV4 writer reads it.
    pub host: &'a str,
    /// URI-encoded request path (no query), e.g. `/model/anthropic.claude%3A0/converse`.
    pub canonical_uri: String,
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
    pub upstream_creds: crate::auth::UpstreamCreds,
}

/// ProtocolWriter rewrites intents for the upstream wire format.
/// Extract `(role, text)` pairs from a hook's rewrite reply for a dialect that must RE-FRAME the
/// turns rather than insert them verbatim. `None` means at least one reply message does not carry
/// plain-string content — the re-framing dialects cannot render that faithfully, so their
/// [`ProtocolWriter::apply_rewrite_to_ingress_body`] aborts and leaves the body untouched rather
/// than shipping a half-applied rewrite.
pub fn rewrite_text_pairs(messages: &[serde_json::Value]) -> Option<Vec<(String, String)>> {
    messages
        .iter()
        .map(|m| {
            let role = m
                .get("role")
                .and_then(serde_json::Value::as_str)?
                .to_string();
            let text = m
                .get("content")
                .and_then(serde_json::Value::as_str)?
                .to_string();
            Some((role, text))
        })
        .collect()
}

/// A streaming JSON-array reframer: consumes a protocol's SSE response bytes and re-emits them as one
/// streaming JSON array (`[{...},{...}]`), the body shape a non-SSE streaming request expects. The
/// agnostic forward path holds one `Box<dyn ArrayStreamFramer>` (built via
/// [`ProtocolWriter::make_array_stream_framer`]) and drives it, so it names no protocol's framer type.
/// The sole implementor is `gemini::GeminiJsonArrayFramer` (Gemini `:streamGenerateContent` without
/// `?alt=sse`). The trait exposes only the SUBSET of that type's API the agnostic core needs (`feed`,
/// `finish_for_translate`, `finish_with_server_error`); the type's raw `finish` and its low-level
/// `finish_with_error(code, status, …)` are absent, since the core never passes a wire status code.
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
/// have no home on `TranslateCodec`. Reached via `decl_for(name).dialect()`. Today its sole
/// implementor ([`DialectRef`]) forwards to the in-core writer/reader; at the A4b relocation the
/// implementor moves to busbar-llm with those codecs and this call surface does not change.
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
    fn write_response_exception(&self, err: &IrError) -> Option<(String, String)>;
    fn write_error_frame(&self, err: &IrError) -> Option<(String, serde_json::Value)>;
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
pub(crate) use proto_codec::*;

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

/// Byte-level removal of a TOP-LEVEL `"usage"` member from a JSON object string, preserving every
/// other byte exactly. Returns `Some(stripped)` when a single top-level `"usage"` member was found
/// and removed (with the correct adjacent comma and no other reshaping), or `None` when a safe
/// byte-level edit is NOT possible for this input - a malformed/non-object body, a `"usage"` that
/// only appears nested inside a value or inside a string, more than one top-level `"usage"`, or any
/// shape the scanner does not fully understand. On `None` the caller falls back to parse-reserialize
/// for THAT frame only (correctness over speed for the rare shape).
///
/// This exists for the same-protocol OpenAI verbatim path: busbar forces `include_usage` UPSTREAM to
/// bill, so an OpenAI upstream stamps `"usage":null` on EVERY intermediate `chat.completion.chunk`.
/// A native OpenAI stream for a client that did NOT request `include_usage` omits the `usage` key
/// entirely on those chunks, so re-emitting the `"usage":null` verbatim is a wire-shape TELL. This
/// deletes exactly that key without a full DOM re-serialize of the (common, non-suppressed) frame.
///
/// SAFETY: the scan is a structural single pass that tracks JSON string state (honoring `\`-escapes)
/// and brace/bracket nesting depth, so the `"usage"` KEY is only matched when it appears as a member
/// name at object depth 1 - never when the literal text `"usage"` (or even `"usage":null`) appears
/// inside a string VALUE or a nested object. A key match is confirmed only when the identifier is a
/// complete quoted string `"usage"` immediately followed (modulo whitespace) by a `:`. Anything the
/// scanner cannot classify with certainty yields `None` (fall back), never a blind splice.
pub fn strip_top_level_usage_member(json: &str) -> Option<String> {
    let bytes = json.as_bytes();
    let n = bytes.len();
    // Skip leading whitespace; the body must be a JSON object.
    let mut i = 0usize;
    while i < n && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= n || bytes[i] != b'{' {
        return None;
    }
    let obj_open = i;
    i += 1;

    // Scan the top-level object's members. `depth` counts nesting BELOW the top object (0 == directly
    // inside the top object). We only inspect keys at depth 0. `member_start` marks the byte offset
    // where the current member begins (the first non-whitespace, non-comma byte after `{` or `,`), so
    // a matched `usage` member can be removed together with its trailing/leading comma.
    let mut depth = 0usize;
    // Byte range of the top-level `usage` member to remove, if found: [start, end) where `start` is
    // the first byte of the key's opening quote and `end` is one past the member's value.
    let mut usage_range: Option<(usize, usize)> = None;
    // `true` once we are positioned at the start of a member (just after `{` or a top-level `,`) and
    // expect a key next; used to only treat a string at depth 0 as a KEY, never a value.
    let mut expect_key = true;

    while i < n {
        let b = bytes[i];
        match b {
            b'"' => {
                // A string. At depth 0 with `expect_key`, this is a member KEY - capture its span and
                // check whether it is exactly `usage`. Otherwise skip the string body.
                let key_start = i;
                let str_end = scan_json_string_end(bytes, i)?; // one past the closing quote
                if depth == 0 && expect_key {
                    let is_usage = &bytes[key_start..str_end] == b"\"usage\"";
                    // Advance past the string, then whitespace, then the mandatory `:`.
                    let mut j = str_end;
                    while j < n && bytes[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j >= n || bytes[j] != b':' {
                        return None; // not a well-formed member - bail to reserialize
                    }
                    j += 1;
                    // Find the end of this member's value (a full scan that respects nesting/strings).
                    let value_end = scan_json_value_end(bytes, j)?;
                    if is_usage {
                        if usage_range.is_some() {
                            return None; // duplicate top-level usage - refuse to guess
                        }
                        usage_range = Some((key_start, value_end));
                    }
                    i = value_end;
                    expect_key = false;
                    continue;
                }
                // A nested string (value or below top level) - already fully consumed.
                i = str_end;
            }
            b'{' | b'[' => {
                depth += 1;
                expect_key = false;
                i += 1;
            }
            b'}' | b']' => {
                if depth == 0 {
                    // Closing the top-level object. Done scanning.
                    if b == b']' {
                        return None; // shape mismatch - top level was not an object after all
                    }
                    break;
                }
                depth -= 1;
                i += 1;
            }
            b',' => {
                if depth == 0 {
                    expect_key = true;
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    let (start, end) = usage_range?;
    // Remove the member together with exactly ONE adjacent comma so the object stays well-formed:
    // prefer the comma BEFORE the member (and any whitespace between that comma and the key); if the
    // member is the FIRST one, take the comma AFTER it instead. Whitespace immediately around the
    // removed span is trimmed so no dangling `, ` or `  ` is left, matching a native chunk's shape.
    let mut cut_start = start;
    let mut cut_end = end;
    // Look left for a preceding comma (skipping whitespace back to it).
    let mut k = start;
    while k > obj_open + 1 && bytes[k - 1].is_ascii_whitespace() {
        k -= 1;
    }
    if k > obj_open + 1 && bytes[k - 1] == b',' {
        // There is a preceding comma: remove from it through the member's value.
        cut_start = k - 1;
    } else {
        // `usage` is the first member: remove the member through a trailing comma (and its whitespace).
        let mut m = end;
        while m < n && bytes[m].is_ascii_whitespace() {
            m += 1;
        }
        if m < n && bytes[m] == b',' {
            cut_end = m + 1;
        }
        // If there is NO trailing comma either, `usage` was the sole member - removing just the member
        // leaves `{}` (with whatever interior whitespace remained), which is still valid.
    }

    let mut out = String::with_capacity(n - (cut_end - cut_start));
    out.push_str(&json[..cut_start]);
    out.push_str(&json[cut_end..]);
    Some(out)
}

/// Given `bytes` and the index of an opening `"`, return the index ONE PAST the matching closing
/// quote, honoring `\`-escapes. `None` if the string is unterminated.
fn scan_json_string_end(bytes: &[u8], open_quote: usize) -> Option<usize> {
    debug_assert_eq!(bytes[open_quote], b'"');
    let n = bytes.len();
    let mut i = open_quote + 1;
    while i < n {
        match bytes[i] {
            b'\\' => i += 2, // skip the escaped byte
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// Given `bytes` and the index of the first byte of a JSON value (after any whitespace), return the
/// index ONE PAST the value, respecting nested objects/arrays and strings. `None` if the value is
/// malformed/unterminated. Leading whitespace before the value is tolerated.
fn scan_json_value_end(bytes: &[u8], start: usize) -> Option<usize> {
    let n = bytes.len();
    let mut i = start;
    while i < n && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= n {
        return None;
    }
    match bytes[i] {
        b'"' => scan_json_string_end(bytes, i),
        b'{' | b'[' => {
            // Balanced-nesting scan that skips over strings so a `}`/`]` inside a string never closes
            // the structure.
            let mut depth = 0usize;
            while i < n {
                match bytes[i] {
                    b'"' => i = scan_json_string_end(bytes, i)?,
                    b'{' | b'[' => {
                        depth += 1;
                        i += 1;
                    }
                    b'}' | b']' => {
                        depth -= 1;
                        i += 1;
                        if depth == 0 {
                            return Some(i);
                        }
                    }
                    _ => i += 1,
                }
            }
            None
        }
        _ => {
            // A scalar: number / true / false / null. It ends at the next structural byte
            // (`,`, `}`, `]`) or whitespace at this level.
            let value_start = i;
            while i < n {
                match bytes[i] {
                    b',' | b'}' | b']' => break,
                    c if c.is_ascii_whitespace() => break,
                    _ => i += 1,
                }
            }
            if i == value_start {
                None
            } else {
                Some(i)
            }
        }
    }
}

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
pub use registry::{decl_for, IngressAuth, ProtocolDecl};

/// Canonical protocol-id vocabulary. Every PRODUCTION comparison / match arm / registry insertion on
/// a protocol name goes through these consts so the router, dispatch, projections, and registry
/// cannot drift on a typo'd literal. Tests keep raw literals by convention (golden-value checks).
pub const PROTO_ANTHROPIC: &str = "anthropic";
pub const PROTO_OPENAI: &str = "openai";
pub const PROTO_GEMINI: &str = "gemini";
pub const PROTO_BEDROCK: &str = "bedrock";
pub const PROTO_COHERE: &str = "cohere";
pub const PROTO_RESPONSES: &str = "responses";

/// The TOP-LEVEL body keys the six LLM dialects point-read on the pre-materialized path: `model`
/// (ingress model resolution + the pristine model-rewrite check), `stream` (chat's `wants_stream`),
/// `stream_options` (the OpenAI streaming-usage opt-in, read without forcing a DOM) and `system`
/// (chat's body affinity key). Declared ONCE and referenced by all six `ProtocolDecl`s rather than
/// spelled six times: they are one shared fact about the chat body shape, and a protocol that reads
/// a different set (MCP reads none) declares its own.
pub const LLM_HEAD_KEYS: &[&str] = &["model", "stream", "stream_options", "system"];

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
pub(crate) fn known_protocols() -> &'static [&'static str] {
    registry::registry().codec_protocols()
}

/// THE LLM PLANE'S VOCABULARY DECLARATION, beside the protocol registry it reads. Folded into
/// `plane::registry::BUILTIN_PLANE_DECLS`; every arm replaces one arm of a `Plane::Llm` `match`.
///
/// `wire_format_names` is [`known_protocols`] itself — the model plane's dialects are the registered
/// protocols, so a seventh dialect moves that list with nothing edited here. It is the one field
/// that is a function rather than a slice, and it is the reason the field is a function at all.
pub(crate) const PLANE_DECL: crate::plane::registry::PlaneDecl =
    crate::plane::registry::PlaneDecl {
        key: "llm",
        config_section: "pools",
        scope_kinds: &["pool"],
        subject_noun: "pool",
        audit_kind: "pool",
        wire_format_names: known_protocols,
        // THE RESIDUAL MOUNTS NOTHING. It is the catch-all every unclaimed path falls through to, so
        // it claims no path and binds no audience: a plain data-plane busbar key carries none, and an
        // audience on the residual would make every unclaimed path an OAuth resource server.
        claims: |_| Vec::new(),
        admission: |_| None,
        // NO SLOT. The LLM plane's runtime state is the many other `App` fields the data plane
        // already reads directly (lanes, pools, cost, …), not one object this seam can erase —
        // see `PlaneDecl::build`'s doc for why that is the right answer here rather than a gap.
        build: |_| None,
        // NO SURFACE CONTRIBUTION. The LLM plane's data routes ARE the protocol catch-all (mounted
        // in `base_data_router` directly, not through this seam), it adds no admin trust verb on top
        // of the generic `pools` CRUD, and it documents no admin path of its own.
        mount: None,
        routes: None,
        admin_routes: None,
        openapi: None,
        // NO DURABLE STATE, NO BACKGROUND WORK. The LLM plane's state is the many `App` fields the
        // data plane reads directly (lanes, pools, cost, …), restored by nothing here; its reliability
        // state is RAM-only and re-learned from live traffic. So it hydrates nothing and starts no job.
        hydrate: None,
        start: None,
        // NO NAMED-DEFINITION WRITE GRAMMAR. `pools:` predates the 1.5.3 generic named-map path and
        // keeps its own richer validation elsewhere, so there is no per-entry document for the admin
        // write path to validate through this seam.
        config_validate: None,
        card_signing_domain: None,
        card_kid_prefix: None,
        named_def_list: None,
        named_def_get: None,
        registry_contains: None,
        reresolve_gates: None,
        #[cfg(feature = "openapi-schema")]
        openapi_schemas: None,
        // NOTHING TO CARRY ACROSS A SWAP. The LLM plane holds no engine-owned object that outlives an
        // apply through this seam — its reliability/breaker state rides the `App` fields the data
        // plane reads directly, not reconciled here.
        on_swap: None,
        // NO CONFIG SECTION TO PARSE OR LOWER, NO RUNTIME TO BUILD, NO VERIFY GATE TO PRUNE. `pools:`
        // predates the neutral section seam and is read by `config::resolve` directly; the LLM plane
        // has no endpoint block, no single runtime object, and no verify-on-call coalescing state.
        parse_section: None,
        parse_endpoint: None,
        lower_endpoint: None,
        build_runtime: None,
        retain_verify_gates: None,
        default_section: None,
    };

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

pub(crate) fn convert_headers(
    headers: Vec<(HeaderName, HeaderValue)>,
) -> reqwest::header::HeaderMap {
    let mut map = reqwest::header::HeaderMap::new();
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

/// READ → WRITE round-trip fidelity per protocol, with an EXACT allow-list of accepted divergences.
/// The complement to `same_proto_fidelity_tests` (which covers the byte-verbatim short-circuit that
/// never enters the IR at all); this one drives the readers and writers that CAN lose.
#[cfg(test)]
#[path = "tests/roundtrip_fidelity_tests.rs"]
mod roundtrip_fidelity_tests;

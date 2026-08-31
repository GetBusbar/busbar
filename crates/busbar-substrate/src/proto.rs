// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral protocol vocabulary relocated DOWN from `busbar-core` (Batch A).
//!
//! These are dependency-free protocol atoms — a wire error-`type` string and the declared inbound
//! auth scheme — that a plane/plugin crate (`busbar-mcp`) names WITHOUT needing `busbar-core`.
//! `busbar-core` re-exports each from its original home (`proto::openai_family` / `proto::registry`)
//! so every existing in-core and plugin caller compiles unchanged. Values are byte-identical to the
//! pre-move definitions.

// ── CANONICAL error-`type` vocabulary home. The forward-layer KIND_* bank (`proxy::KIND_*`), the
//    admin API's not-found/invalid-request types, the anthropic writer's private ERR_TYPE_* bank, and
//    the OpenAI-family writers all alias these consts, so the shared string values are single-sourced
//    HERE (the neutral substrate) so every consumer — core, admin, and the `busbar-llm` dialects —
//    names them without reaching into `busbar-core`. Relocated DOWN from `busbar-core`'s
//    `proto::openai_family`, which now re-exports them so its callers are unchanged. (`proxy::KIND_OVERLOADED`
//    = "overloaded" and anthropic's "timeout_error" are DELIBERATELY different values and stay at
//    their own sites.)
/// OpenAI error `type` for a missing or invalid API key.
pub const ERR_TYPE_AUTHENTICATION: &str = "authentication_error";
/// OpenAI error `type` for a malformed / bad-argument request.
pub const ERR_TYPE_INVALID_REQUEST: &str = "invalid_request_error";
/// OpenAI error `type` for a permission / access-control denial.
pub const ERR_TYPE_PERMISSION: &str = "permission_error";
/// OpenAI error `type` for a resource that does not exist.
pub const ERR_TYPE_NOT_FOUND: &str = "not_found_error";
/// OpenAI error `type` for a rate-limit / throttle response.
pub const ERR_TYPE_RATE_LIMIT: &str = "rate_limit_error";
/// OpenAI error `type` for a transient upstream failure.
pub const ERR_TYPE_SERVER_ERROR: &str = "server_error";
/// OpenAI error `type` for a billing-quota exhaustion (HTTP 429).
pub const ERR_TYPE_INSUFFICIENT_QUOTA: &str = "insufficient_quota";
/// Anthropic/busbar internal kind for an overloaded upstream; mapped to `server_error` on the
/// OpenAI wire (OpenAI has no `overloaded_error` type).
pub const ERR_TYPE_OVERLOADED: &str = "overloaded_error";
/// Anthropic-vocabulary error `type` for a generic upstream/API failure; also the agnostic
/// forward-layer kind (`proxy::KIND_API_ERROR` aliases this).
pub const ERR_TYPE_API_ERROR: &str = "api_error";
/// Error `type` for an oversized request (HTTP 413); shared by the forward KIND bank and the
/// anthropic writer.
pub const ERR_TYPE_REQUEST_TOO_LARGE: &str = "request_too_large";

// ── Neutral protocol atoms relocated DOWN from `busbar-core` (`proto`) so the `busbar-llm` dialect
//    crate names them WITHOUT reaching into `busbar-core` (the reverse-edge rule, plane-extraction
//    §6.2). Each is dependency-free (a busbar-internal label, an SSE sentinel, a header name, a pure
//    byte/JSON helper) or names only substrate types (`breaker::CanonicalSignal`, `axum::http`, the
//    substrate diagnostics catalog). `busbar-core` re-exports each from its historical
//    `proto::…` path so every in-core / plugin caller compiles unchanged; values are byte-identical
//    to the pre-move definitions.

/// Busbar-internal `provider_signal` label for an IR-parse failure (the LANE label the breaker/metrics
/// layer reads to classify a translation/parse error). A busbar-internal signal, NOT a wire shape, so
/// it lives in the agnostic proto layer; the per-protocol readers reference it rather than re-spelling
/// the literal.
pub const SIGNAL_IR_PARSE: &str = "ir_parse";

/// The OpenAI-style SSE stream terminator sentinel (`data: [DONE]`). The bare token is matched by the
/// cross-protocol streaming core and several readers; the full framed bytes are emitted on egress.
/// Shared here so no reader/writer re-spells either form.
pub const SSE_DONE_SENTINEL: &str = "[DONE]";
/// The full framed `data: [DONE]\n\n` bytes emitted on egress. See [`SSE_DONE_SENTINEL`].
pub const SSE_DONE_FRAME: &[u8] = b"data: [DONE]\n\n";

/// The HTTP `Authorization` header name (lowercase, canonical). Emitted by the bearer/SigV4 auth-header
/// builders across protocols; named once so no builder re-spells it.
pub const HDR_AUTHORIZATION: &str = "authorization";

/// An IR-level error, currently an alias for `CanonicalSignal` (the normalized error signal).
pub type IrError = crate::breaker::CanonicalSignal;

/// Mixed-case base62 alphabet (digits + lowercase + uppercase, no `-`/`_`) and the rejection-sampling
/// threshold used when synthesizing opaque ids for protocols whose native ids are flat random tokens
/// (Gemini `responseId`, Responses `msg_`/`fc_`/`resp_` suffixes). Hoisted here as the single source
/// of truth so the two id generators cannot drift on the character set or the bias-elimination cutoff
/// — `REJECT_THRESHOLD` is the largest multiple of 62 that fits in a `u8` (62 × 4 = 248); a draw in
/// `0..248` maps uniformly via `% 62`, a draw `>= 248` is rejected and redrawn.
pub const BASE62_ALPHABET: &[u8; 62] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// The rejection-sampling threshold paired with [`BASE62_ALPHABET`]; see its docs.
pub const BASE62_REJECT_THRESHOLD: u8 = 248;

/// Build the `Authorization: Bearer <key>` header pair for the pure-Bearer protocol writers
/// (OpenAI, `/v1/responses`, Gemini's `x-goog`… aside, Cohere). Shared so the warn+OMIT policy lives
/// in ONE place rather than being copy-pasted (and drifting) per writer.
///
/// `HeaderValue::from_str` rejects ASCII control bytes (a stray CR/LF/NUL a config system may have
/// injected). We surface a coded diagnostic (naming the protocol so the operator can locate the
/// misconfigured lane) and OMIT the header entirely (empty Vec) rather than emitting a syntactically
/// empty `Authorization: ` header (a fingerprinting tell). The key is NEVER logged (it is the secret);
/// only the protocol name and the fact that the bytes are malformed.
pub fn bearer_auth_headers(
    proto: &str,
    key: &str,
) -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)> {
    match axum::http::HeaderValue::from_str(&format!("Bearer {key}")) {
        Ok(value) => vec![(
            axum::http::HeaderName::from_static(HDR_AUTHORIZATION),
            value,
        )],
        Err(_) => {
            crate::diag_debug!(
                crate::diagnostics::PROTO_AUTH_INVALID_HEADER_BYTES,
                protocol = proto,
                "authorization credential contains invalid header bytes (ASCII control character); \
                 omitting auth header — upstream will reject with 401"
            );
            Vec::new()
        }
    }
}

/// Project each message's `(role, content)` into a `(String, String)` pair when BOTH are plain
/// strings, or `None` if any message is missing a string role/content. A neutral serde_json projection
/// with no protocol knowledge.
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

/// The `event:` name of one SSE frame, BORROWED from the frame bytes — the cheap probe for a
/// consumer that only needs the event TYPE to decide whether a frame is worth parsing at all.
/// Returns `""` when the frame carries no `event:` line (OpenAI style) or the name is not UTF-8, and
/// the LAST `event:` line wins when a frame illegally carries several.
pub fn sse_event_type(frame: &[u8]) -> &str {
    let mut name = "";
    for line in frame.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(rest) = line.strip_prefix(b"event:") {
            name = std::str::from_utf8(rest).map(str::trim).unwrap_or("");
        }
    }
    name
}

/// Render an IR ToolUse `input` value as a wire tool-call `arguments` string. Neutral JSON
/// projection: a `Value::String` is emitted VERBATIM (the reader stores not-valid-JSON upstream
/// arguments as `Value::String(raw)`, and re-`to_string`-ing that would double-encode it into an
/// escaped quoted blob); any other `Value` is serialized normally via the sonic `crate::json` seam.
/// Relocated DOWN here so the OpenAI-family and Cohere dialect writers name it without reaching into
/// `busbar-core`; it carries no dialect knowledge, only the string-passthrough rule.
pub fn tool_arguments_to_string(input: &serde_json::Value) -> String {
    match input {
        serde_json::Value::String(s) => s.clone(),
        other => crate::json::to_string(other).unwrap_or_else(|_| "{}".to_string()),
    }
}

/// Client-visible detail string for a mid-stream abort (the upstream connection dropped or a
/// translate step failed after first byte). Relocated DOWN here so BOTH `busbar-core`'s proxy
/// engine (SSE/forward abort path) and the `busbar-llm` Bedrock-eventstream reassembler emit it
/// without either re-spelling the literal or the plugin reaching into core. Single source of truth
/// so the abort text a client sees is identical on every framing.
pub const STREAM_ABORT_DETAIL: &str = "The response stream was interrupted.";

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

/// Append an IR-derived `(event_type, data)` to `out` as INGRESS SSE bytes. A non-empty
/// `event_type` yields Anthropic-style `event:`/`data:` frames; an empty one yields OpenAI-style
/// bare `data:`. Writes THROUGH the caller's buffer, not into a returned `String`. Serializes via
/// `crate::json::to_vec` (the sonic seam), not `Value`'s `Display`-via-`format!`.
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

/// Neutral streaming byte-in/byte-out translator seam. The WHOLE concrete `StreamTranslate` (in the
/// `busbar-llm` plugin) sits behind this trait so emission ORDER is preserved verbatim — the
/// streaming forward path holds an `Option<Box<dyn StreamTranslator>>` and never names the concrete
/// translator. `usage()` returns an OWNED [`crate::billing::TokenUsage`] (the billing consumers read
/// the four token totals, not the concrete `&IrUsage` borrow), so the seam names zero concrete IR.
/// Relocated DOWN here so the plugin implements it without reaching into `busbar-core`.
pub trait StreamTranslator: Send {
    /// Feed a chunk of EGRESS bytes; return the translated INGRESS bytes for whatever COMPLETE frames
    /// are now available (empty if only a partial frame is buffered).
    fn feed(&mut self, chunk: &[u8]) -> Vec<u8>;
    /// Call once at end-of-stream; returns the INGRESS terminator plus any deferred terminal frames.
    fn finish(&mut self) -> Vec<u8>;
    /// The terminal token usage accumulated for this stream, projected to the neutral billing total,
    /// or `None` if no usage-bearing terminal event was seen. The streaming billing arm reads this
    /// for the per-request token fee.
    fn usage(&self) -> Option<crate::billing::TokenUsage>;
    /// The terminal stream ERROR message, or `None` for a clean stream — the breaker/billing gate.
    fn terminal_error(&self) -> Option<&str>;
    /// True once this translator abandoned its stream (reassembly overflow / malformed prelude).
    fn aborted(&self) -> bool;
    /// Record whether the ORIGINAL client request opted into streaming usage.
    fn set_client_include_usage(&mut self, include: bool);
}

/// How tightly a protocol CLAIMS an inbound request, for the generic detection fold. A LOWER value
/// binds TIGHTER — it names an earlier rung of the historical detection ladder (a mandatory-unique
/// auth header binds tighter than a path verb, which binds tighter than a bare path suffix). The
/// fold picks the tightest claim across the registered protocols; a tie breaks by registration
/// order. Opaque to core: only the relative order is meaningful, and each protocol owns the rungs it
/// claims. This is the datum that let the hand-ordered `if`-ladder in `busbar-core`'s
/// `proto::detect::protocol_id` become a fold over per-decl predicates — each dialect's specific
/// header/path sniff now states its own rungs on [`ProtocolDecl::claims`], and core names no dialect.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ClaimStrength(pub u16);

/// The ROUTER detection predicate a protocol supplies: `(headers, path) -> Option<ClaimStrength>`,
/// `Some` at the tightest rung this protocol claims for that request, `None` when it does not claim
/// it at all. The generic fold in `busbar-core` folds every registered protocol's predicate in
/// registration order and keeps the tightest claim. Relocated here with [`ProtocolDecl`] so a
/// dialect crate names it without reaching into `busbar-core`.
pub type ClaimsFn = fn(&axum::http::HeaderMap, &str) -> Option<ClaimStrength>;

/// The RESIDUAL detection predicate a protocol supplies: `path -> Option<ClaimStrength>`, from the
/// path SHAPE ALONE (no headers). Narrower than [`ClaimsFn`] — it is the arm the mount table falls
/// through to when deciding which native error envelope an UNMOUNTED path should wear, and it owns
/// its dialect's slice of the `/v1/models/{id}` colon disambiguation. `None` when the protocol names
/// no residual for that path.
pub type ResidualClaimsFn = fn(&str) -> Option<ClaimStrength>;

/// A protocol's RESPONSE-side vendor-metadata reporter: given a response body, the vendor-scoped
/// field names present that NO other protocol in the matrix can express (a Gemini `safetyRatings`, a
/// Bedrock guardrail `trace`). Core calls it on the cross-protocol response seam to LOG the drop; the
/// per-dialect lookup SHAPE (Gemini reads `candidates[].k`, Bedrock a top-level key) stays with the
/// dialect. `None` for a protocol that carries no such artifact.
pub type VendorResponseMetadataFn = fn(&serde_json::Value) -> Vec<&'static str>;

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

    /// Whether [`Self::egress_auth_headers`]'s output is LANE-CONSTANT: a pure function of the
    /// resolved credential string and the `Own`/`Passthrough` mode, reading NOTHING else from the
    /// [`SigningContext`] (not the body, not the timestamp, not the path). `true` lets the boot
    /// path prebuild the exact header set once per lane and hand the request path a clone
    /// (anthropic's api-key-vs-bearer shaping and openai's plain bearer qualify); a signer that
    /// covers the request bytes (bedrock SigV4 reads body + timestamp + canonical URI) MUST stay
    /// `false` — prebuilding it would sign one request and send that signature on every other.
    /// Meaningless (and `false`) when `egress_auth_headers` is `None`.
    pub egress_auth_lane_constant: bool,

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

    /// THE ROUTER detection predicate — how (and how tightly) this protocol claims an inbound
    /// `(headers, path)`. `None` for a protocol identified by its explicit mount rather than a wire
    /// fingerprint (MCP). The generic fold in `busbar_core::proto::detect` folds this over every
    /// registered protocol in registration order and keeps the tightest [`ClaimStrength`], which is
    /// exactly what the old `busbar-core`-resident `protocol_id` if-ladder computed by hand. Each
    /// dialect states only ITS OWN rungs here, so the router names no dialect.
    pub claims: Option<ClaimsFn>,

    /// THE RESIDUAL detection predicate — how (and how tightly) this protocol claims a path from its
    /// SHAPE ALONE, the arm `busbar_core::proto::residual_dialect_for_path` folds when the mount
    /// table has declined a path and a native error envelope must still be chosen. `None` when this
    /// protocol names no residual path. Replaces this dialect's arm of the core-resident
    /// `residual_dialect_for_path` ladder.
    pub residual_claims: Option<ResidualClaimsFn>,

    /// TRUE for the ONE protocol core falls back to when NO dialect claims a request yet a dialect
    /// must still be named — the OpenAI-compatible residual the ecosystem defaults to (`GET
    /// /v1/models` with no fingerprint, an un-resolved ingress on the degraded response path). At
    /// most one registered protocol sets this; core reads it through the registry so the literal
    /// default dialect name leaves core entirely.
    pub residual_default: bool,

    /// THE RESPONSE-side vendor-metadata reporter — the fields this protocol's upstream returns that
    /// no other protocol can express, reported per response body so the cross-protocol seam can LOG
    /// the drop. `None` for a protocol with no such vendor-scoped artifact. Replaces the hard-coded
    /// per-dialect key lists (and their differing lookup shapes) in
    /// `warn_untranslatable_response_metadata`.
    pub vendor_response_metadata: Option<VendorResponseMetadataFn>,
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

// Byte-level top-level `usage`-member stripper + its two JSON span scanners, RELOCATED DOWN
// from `busbar-core` (`proto`) so the OpenAI same-protocol verbatim writer in `busbar-llm` names
// them without reaching into `busbar-core`. Pure byte scanners (no protocol knowledge); `busbar-core`
// re-exports `strip_top_level_usage_member` at its historical path. Byte-identical.
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

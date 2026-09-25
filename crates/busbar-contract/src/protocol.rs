// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROTOCOL-SEAM SHAPES (DECISIONS #83: contract = shapes) — the vocabulary and the traits a
//! dialect IMPLEMENTS and the kernel's driver reads back, which both sides must spell identically:
//!
//! - the error-`type` / error-KIND / disposition / provider-code vocabulary that crosses a dialect's
//!   `write_error(kind)` and the kernel's `error_map`;
//! - the media-type and user-agent literals a protocol declaration defaults to;
//! - the SSE frame-boundary scan every SSE-reading plane shares (the SSE wire encoding itself);
//! - the neutral codec traits a dialect implements — [`StreamTranslator`], [`ArrayStreamFramer`],
//!   [`DialectCodec`] — the detection-predicate shapes a declaration carries, and the per-request
//!   [`SigningContext`].
//!
//! Relocated, module-path-only and byte-identical in every value, from `busbar-substrate-values`
//! (`proto` and `proxy`), which re-exports each item under its historical path so every caller
//! compiles unchanged. The protocol DECLARATION itself (`ProtocolDecl`, its inbound-auth and egress
//! credential fields) stays there until it lands in the O7-ruled shape; the registry and the
//! dialect-specific helpers are not shapes and stay there too.

// ── THE CANONICAL error-`type` VOCABULARY. The forward layer's error-KIND bank below, the admin
//    API's not-found/invalid-request types and every dialect writer alias these, so each shared
//    string value has ONE definition every side of the seam spells identically. (`KIND_OVERLOADED`
//    = "overloaded" and one dialect's "timeout_error" are DELIBERATELY different values and stay at
//    their own sites.)
/// Error `type` for a missing or invalid API key.
pub const ERR_TYPE_AUTHENTICATION: &str = "authentication_error";
/// Error `type` for a malformed / bad-argument request.
pub const ERR_TYPE_INVALID_REQUEST: &str = "invalid_request_error";
/// Error `type` for a permission / access-control denial.
pub const ERR_TYPE_PERMISSION: &str = "permission_error";
/// Error `type` for a resource that does not exist.
pub const ERR_TYPE_NOT_FOUND: &str = "not_found_error";
/// Error `type` for a rate-limit / throttle response.
pub const ERR_TYPE_RATE_LIMIT: &str = "rate_limit_error";
/// Error `type` for a transient upstream failure.
pub const ERR_TYPE_SERVER_ERROR: &str = "server_error";
/// Error `type` for a billing-quota exhaustion (HTTP 429).
pub const ERR_TYPE_INSUFFICIENT_QUOTA: &str = "insufficient_quota";
/// Internal kind for an overloaded upstream; a dialect whose wire has no overloaded type maps it to
/// `server_error`.
pub const ERR_TYPE_OVERLOADED: &str = "overloaded_error";
/// Error `type` for a generic upstream/API failure; also the agnostic forward-layer kind
/// ([`KIND_API_ERROR`] aliases this).
pub const ERR_TYPE_API_ERROR: &str = "api_error";
/// Error `type` for an oversized request (HTTP 413); shared by the forward KIND bank and the
/// dialect writers.
pub const ERR_TYPE_REQUEST_TOO_LARGE: &str = "request_too_large";

// ── THE AGNOSTIC error-KIND tokens the forward layer produces and hands a dialect's error writer as
//    the `kind` argument — the protocol-agnostic discriminant each writer maps to its native error
//    category. The values shared with the error-`type` vocabulary alias it above, so the spelling has
//    ONE definition and cannot drift; the two forward-specific tokens (`overloaded`, `timeout`) are
//    defined here.
/// Agnostic forward kind for a generic upstream/API failure.
pub const KIND_API_ERROR: &str = ERR_TYPE_API_ERROR;
/// Bare `overloaded` — DELIBERATELY distinct from [`ERR_TYPE_OVERLOADED`] ("overloaded_error", one
/// dialect's wire spelling): this is busbar's own agnostic kind for a relayed upstream 503.
pub const KIND_OVERLOADED: &str = "overloaded";
/// Bare `timeout` — distinct from one dialect's `timeout_error` wire spelling.
pub const KIND_TIMEOUT: &str = "timeout";
/// Transient upstream-failure forward kind (aliases the `server_error` type).
pub const KIND_SERVER_ERROR: &str = ERR_TYPE_SERVER_ERROR;
/// Caller-authentication failure forward kind (aliases the `authentication_error` type).
pub const KIND_AUTHENTICATION: &str = ERR_TYPE_AUTHENTICATION;
/// Caller-permission failure forward kind (aliases the `permission_error` type).
pub const KIND_PERMISSION: &str = ERR_TYPE_PERMISSION;
/// Rate-limit forward kind (aliases the `rate_limit_error` type).
pub const KIND_RATE_LIMIT: &str = ERR_TYPE_RATE_LIMIT;
/// Malformed/invalid-request forward kind (aliases the `invalid_request_error` type).
pub const KIND_INVALID_REQUEST: &str = ERR_TYPE_INVALID_REQUEST;
/// Unknown-model / not-found forward kind (aliases the `not_found_error` type).
pub const KIND_NOT_FOUND: &str = ERR_TYPE_NOT_FOUND;
/// Quota-exhausted forward kind (aliases the `insufficient_quota` type).
pub const KIND_INSUFFICIENT_QUOTA: &str = ERR_TYPE_INSUFFICIENT_QUOTA;
/// Oversized-request forward kind (aliases the `request_too_large` type).
pub const KIND_REQUEST_TOO_LARGE: &str = ERR_TYPE_REQUEST_TOO_LARGE;

/// The failure-DISPOSITION metric-label value for a context-length result — the label a dialect's
/// context-length refusal and the kernel's failover accounting both key on.
pub const DISPOSITION_CONTEXT_LENGTH: &str = crate::upstream::Disposition::ContextLength.label();

/// Provider error-code token emitted when a request exceeds the model's context-window limit.
/// Returned for `StatusClass::ContextLength` and drives the per-protocol writer to emit the native
/// context-length error category.
pub const PROVIDER_CODE_CONTEXT_LENGTH: &str = "context_length_exceeded";

// ── THE MEDIA-TYPE AND USER-AGENT LITERALS a declaration defaults to and a codec writes.
/// The `application/json` media type — the default `Content-Type`/`Accept` for the JSON REST
/// surfaces. One const so the literal isn't repeated across egress/health/observability.
pub const APPLICATION_JSON: &str = "application/json";

/// Streaming MIME type for SSE (Server-Sent Events) responses — the `Content-Type` value that
/// signals an open event-stream to the client.
pub const TEXT_EVENT_STREAM: &str = "text/event-stream";

/// Unknown/foreign egress protocol default `User-Agent`: a generic-but-present UA still beats
/// sending none. A codec-less protocol declaration states it as its egress user-agent default.
pub const EGRESS_UA_DEFAULT: &str = "okhttp/4.12.0";

/// Busbar-internal `provider_signal` label for an IR-parse failure (the LANE label the breaker/metrics
/// layer reads to classify a translation/parse error). A busbar-internal signal, NOT a wire shape, so
/// it lives in the agnostic proto layer; the per-protocol readers reference it rather than re-spelling
/// the literal.
pub const SIGNAL_IR_PARSE: &str = "ir_parse";

/// An IR-level error, currently an alias for [`CanonicalSignal`](crate::upstream::CanonicalSignal)
/// (the normalized error signal).
pub type IrError = crate::upstream::CanonicalSignal;

/// Client-visible detail string for a mid-stream abort (the upstream connection dropped or a
/// translate step failed after first byte). BOTH the kernel's forward engine (SSE/forward abort
/// path) and a plane's binary event-stream reassembler emit it without either re-spelling the
/// literal. Single source of truth so the abort text a client sees is identical on every framing.
pub const STREAM_ABORT_DETAIL: &str = "The response stream was interrupted.";

/// The length of the line terminator starting at `i`, or `None` when `i` does not begin one.
///
/// The event-stream grammar names three: CRLF, a lone LF, and a lone CR. A CR at the very end of
/// the buffer is not yet knowable — the LF that would make it a CRLF may still be in flight — so it
/// reads as "no terminator here", which is the answer that makes a caller wait for more bytes
/// rather than split a CRLF down the middle.
fn terminator_len(buf: &[u8], i: usize) -> Option<usize> {
    match buf.get(i)? {
        b'\n' => Some(1),
        b'\r' => match buf.get(i + 1) {
            Some(b'\n') => Some(2),
            Some(_) => Some(1),
            None => None,
        },
        _ => None,
    }
}

/// Find the first SSE frame terminator (a blank line) in `buf`, returning `(offset, terminator_len)`
/// where `offset` is the byte index of the first terminator byte and the length spans BOTH line
/// terminators that make the blank line. All three of the spec's terminators are recognised, in
/// every pairing: `\n\n` and `\r\n\r\n` are the two the providers emit, and `\r\r`, `\n\r`,
/// `\r\n\r` and `\r\r\n` are the rest of the grammar. Returns `None` if no complete blank line is
/// present yet.
pub fn find_frame_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    loop {
        let at = i + memchr::memchr2(b'\r', b'\n', &buf[i..])?;
        let first = terminator_len(buf, at)?;
        if let Some(second) = terminator_len(buf, at + first) {
            return Some((at, first + second));
        }
        // A line ended here but the next one is not blank: resume past the terminator itself, so a
        // CRLF is never re-read as a bare CR followed by a bare LF.
        i = at + first;
    }
}

/// Split SSE frame text into lines on the event-stream grammar's own line-terminator rule — CRLF, a
/// lone LF, **or** a lone CR each end a line — rather than `str::lines()`, which recognizes only
/// LF/CRLF. Shared by the SSE frame parser and the SSE line reader, which both used
/// `str::lines()` and so silently produced no fields at all on a frame framed by a bare-CR
/// terminator (a frame `find_frame_terminator` above correctly frames).
pub fn sse_lines(text: &str) -> Vec<&str> {
    sse_line_spans(text.as_bytes())
        .into_iter()
        .map(|(start, end)| &text[start..end])
        .collect()
}

/// The `(start, end)` byte span of each line in `bytes` under the event-stream line-terminator rule.
/// The single walk both [`sse_lines`] (which projects the spans back onto the `&str`) and the
/// byte-level SSE event-type probe share, so the two cannot disagree about where a line ends.
/// Every terminator byte is ASCII, so a span taken from valid UTF-8 always lands on a char boundary.
pub fn sse_line_spans(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match terminator_len(bytes, i) {
            Some(len) => {
                spans.push((start, i));
                i += len;
                start = i;
            }
            None => i += 1,
        }
    }
    if start < bytes.len() {
        spans.push((start, bytes.len()));
    }
    spans
}

/// Neutral streaming byte-in/byte-out translator seam. The WHOLE concrete stream translator (in the
/// plane that owns it) sits behind this trait so emission ORDER is preserved verbatim — the
/// streaming forward path holds an `Option<Box<dyn StreamTranslator>>` and never names the concrete
/// translator. `usage()` returns an OWNED [`crate::billing::TokenUsage`] (the billing consumers read
/// the four token totals, not the concrete `&IrUsage` borrow), so the seam names zero concrete IR.
/// A shape: the plane implements it and the kernel drives it, naming only this crate.
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
    /// The NON-TOKEN billing the body reported beside [`Self::usage`] — a rerank's counted search
    /// units (item 134) — or `None`. Default `None`: a translator that reads tokens only reports none.
    fn open_billing(&self) -> Option<crate::billing::Billing> {
        None
    }
    /// The terminal stream ERROR message, or `None` for a clean stream — the breaker/billing gate.
    fn terminal_error(&self) -> Option<&str>;
    /// True once this translator abandoned its stream (reassembly overflow / malformed prelude).
    fn aborted(&self) -> bool;
    /// Record whether the ORIGINAL client request opted into streaming usage.
    fn set_client_include_usage(&mut self, include: bool);
    /// Capture the ORIGINAL ingress request body so an ingress writer whose spec requires certain
    /// response members to MIRROR client-set request values (e.g. `temperature`, `top_p`,
    /// `instructions`, `metadata`, `tool_choice`, `parallel_tool_calls`, `tools`) can answer
    /// with the caller's actual values instead of the spec's bare defaults. Called once, before the
    /// first `feed`, on a CROSS-PROTOCOL stream — same-protocol never reaches this (the ingress
    /// writer never runs; the original bytes are relayed verbatim). Default no-op: every ingress
    /// writer without such a requirement ignores it.
    fn set_request_echo(&mut self, _ingress_request_body: &serde_json::Value) {}
    /// Frame a TERMINAL mid-stream error through the ingress writer THIS translator has been driving
    /// all stream, rather than through a freshly-resolved dialect writer. A writer that carries
    /// per-stream identity (a writer that latches the response id, `created_at`, `model` and a
    /// monotonic `sequence_number`) produces a frame that CORRELATES with the frames the client
    /// already received; a fresh writer restarts every one of those from its default, so the failure
    /// event arrives with `sequence_number: 0` and an unrelated response id — a stream a strict SDK
    /// cannot reconcile with the `response.created` it opened on. `None` when this translator has no
    /// in-band error frame to offer, in which case the caller falls back to the dialect seam.
    fn terminal_error_frame(&mut self, _err: &IrError) -> Option<(String, serde_json::Value)> {
        None
    }
}

/// How tightly a protocol CLAIMS an inbound request, for the generic detection fold. A LOWER value
/// binds TIGHTER — it names an earlier rung of the historical detection ladder (a mandatory-unique
/// auth header binds tighter than a path verb, which binds tighter than a bare path suffix). The
/// fold picks the tightest claim across the registered protocols; a tie breaks by registration
/// order. Opaque to core: only the relative order is meaningful, and each protocol owns the rungs it
/// claims. This is the datum that let a hand-ordered `if`-ladder in the kernel become a fold over
/// per-declaration predicates — each dialect's specific header/path sniff now states its own rungs
/// on its declaration's `claims`, and the kernel names no dialect.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ClaimStrength(pub u16);

/// The ROUTER detection predicate a protocol supplies: `(headers, path) -> Option<ClaimStrength>`,
/// `Some` at the tightest rung this protocol claims for that request, `None` when it does not claim
/// it at all. The kernel's generic fold folds every registered protocol's predicate in
/// registration order and keeps the tightest claim. A shape: a dialect names it through this crate
/// alone.
pub type ClaimsFn = fn(&http::HeaderMap, &str) -> Option<ClaimStrength>;

/// The RESIDUAL detection predicate a protocol supplies: `path -> Option<ClaimStrength>`, from the
/// path SHAPE ALONE (no headers). Narrower than [`ClaimsFn`] — it is the arm the mount table falls
/// through to when deciding which native error envelope an UNMOUNTED path should wear, and it owns
/// its dialect's slice of the `/v1/models/{id}` colon disambiguation. `None` when the protocol names
/// no residual for that path.
pub type ResidualClaimsFn = fn(&str) -> Option<ClaimStrength>;

/// A protocol's RESPONSE-side vendor-metadata reporter: given a response body, the vendor-scoped
/// field names present that NO other protocol in the matrix can express (a safety-rating array, a
/// guardrail trace). The kernel calls it on the cross-protocol response seam to LOG the drop; the
/// per-dialect lookup SHAPE (a per-candidate key, a top-level key) stays with the dialect. `None` for a protocol that carries no such artifact.
pub type VendorResponseMetadataFn = fn(&serde_json::Value) -> Vec<&'static str>;

/// A streaming JSON-array reframer: consumes a protocol's SSE response bytes and re-emits them as one
/// streaming JSON array (`[{...},{...}]`), the body shape a non-SSE streaming request expects. The
/// agnostic forward path holds one `Box<dyn ArrayStreamFramer>` (built via
/// `ProtocolWriter::make_array_stream_framer`) and drives it, so it names no protocol's framer type.
/// Implemented by a dialect whose streaming endpoint answers a non-SSE client with a JSON array.
/// The trait exposes only the SUBSET of that type's API the agnostic core needs (`feed`,
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
    /// supplies only the human-readable `message`; the implementor owns the wire status/code shape (e.g. a
    /// status object with HTTP 500 / an `INTERNAL` code), so the core names no protocol wire value. Idempotent.
    fn finish_with_server_error(&mut self, message: &str) -> Vec<u8>;
}

/// **THE 4TH NEUTRAL SEAM (G6 A4b, owner-ruled 2026-08-20).** The per-PROTOCOL computed-codec facade
/// the operation-blind driver reads, so the kernel names ZERO concrete IR and zero `ProtocolReader`/
/// `ProtocolWriter` at its call sites. Every method here has a NEUTRAL signature (bytes / `Value` /
/// `bool` / `TokenUsage` / neutral tuples — `IrError` is `upstream::CanonicalSignal`); the concrete
/// codec lives behind the implementor.
///
/// This is the sibling of the per-CELL `TranslateCodec` — these are the ~10 computed methods the
/// engine/wire/health/hooks/response_body driver called through the `Protocol` bundle
/// (`protocol_for(name).writer()/.reader().X()`) that are protocol-level, not operation-level, and so
/// have no home on `TranslateCodec`. Reached via `decl_for(name).dialect()`. Its implementor lives in
/// the plane that owns the dialects and forwards to that plane's writer/reader.
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
        err: &crate::upstream::CanonicalSignal,
    ) -> Option<(String, String)>;
    fn write_error_frame(
        &self,
        err: &crate::upstream::CanonicalSignal,
    ) -> Option<(String, serde_json::Value)>;
    fn wants_array_stream(&self, body: &serde_json::Value) -> bool;
    fn inject_response_metrics(&self, value: &mut serde_json::Value, elapsed_ms: Option<u64>);
    fn attach_error_response_headers(
        &self,
        headers: &mut http::HeaderMap,
        kind: &str,
        envelope: &serde_json::Value,
    );
    /// This protocol's upstream-error vocabulary (the reader's `extract_error`), reached by name so
    /// `handlers::protocol_error` names no concrete reader. `status` is the raw HTTP code.
    fn extract_error(&self, status: u16, body: &[u8]) -> crate::upstream::RawUpstreamError;
    /// The dialect's array-stream framer for a JSON-array ingress client, or `None` when
    /// this protocol frames no array stream — the writer method reached by name at the SSE seam.
    fn make_array_stream_framer(&self) -> Option<Box<dyn ArrayStreamFramer>>;
    /// The upstream request path for a (streaming) request against this dialect — the health probe's
    /// URL builder reaches it here rather than through the concrete writer.
    fn upstream_path_for_stream(&self, model: &str, stream: bool) -> String;
    /// Install the authoritative lane model into a same-protocol passthrough body if the dialect
    /// requires it; returns whether the body changed (a pristine-passthrough invalidator).
    fn rewrite_model_if_needed(&self, body: &mut serde_json::Value, model: &str) -> bool;
    /// Reshape a path-base (URL-model) lane's body for this dialect (e.g. drop the body `model`,
    /// add a version member the path-base host requires); returns whether the body changed.
    fn reshape_for_path_base(&self, body: &mut serde_json::Value) -> bool;
}

/// Per-request signing context. Most protocols' `auth_headers` ignore this; protocols that
/// sign the whole request (a request-signing scheme) need the method/host/path/body/time.
///
/// A shape (DECISIONS #83): relocated, module-path-only, from `busbar-substrate-values::proto`, which
/// re-exports it under its historical path. Its only non-primitive field is
/// [`UpstreamCreds`](crate::config::UpstreamCreds), a contract config value.
pub struct SigningContext<'a> {
    /// Upstream host (no scheme), e.g. `runtime.region-1.example.com`. Borrowed from the lane's
    /// precomputed `signing_host` on the forward path (no per-request allocation); only a
    /// request-signing writer reads it.
    pub host: &'a str,
    /// URI-encoded request path (no query), e.g. `/model/vendor.model%3A0/invoke`. Borrowed (like
    /// `host`): on the forward path it comes from the lane's boot-precomputed egress target, so
    /// building the context allocates nothing; only a request-signing writer reads it.
    pub canonical_uri: &'a str,
    /// The exact request body bytes that will be sent.
    pub body: &'a [u8],
    /// Unix epoch seconds at signing time.
    pub timestamp_epoch: u64,
    /// The UPSTREAM-credential mode for this request. Lets a writer resolve a credential whose scheme
    /// is otherwise ambiguous (e.g. an API-key-vs-Bearer choice) to the single native header
    /// the mode implies — `Passthrough` forwards the caller's Bearer token; `Own` presents the
    /// configured-key shape. Without it, an ambiguous credential must emit BOTH headers, which is an
    /// upstream-distinguishability tell no native client produces. (The upstream-credential concern,
    /// split out of the front-door auth mode in slice 2d.)
    pub upstream_creds: crate::config::UpstreamCreds,
}

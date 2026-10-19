// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL WIRE VOCABULARY every plane and the kernel spell identically:
//!
//! - the error-`type` / error-KIND / disposition / provider-code bank that crosses a plane's error
//!   writer and the kernel's own refusals;
//! - the media-type literals;
//! - the SSE frame-boundary scan and line walkers every SSE-reading plane shares (the SSE wire
//!   encoding itself, not any dialect's use of it);
//! - the head-field view a plane reads a request head as, and the per-request
//!   [`SigningContext`] the kernel's outbound credential presentation is handed.
//!
//! NO DIALECT LIVES HERE. The protocol declaration, the dialect codec facade, the stream
//! translator and array reframer shapes, the detection predicates and the declared egress scheme
//! moved into the plane that owns the dialects (THE DESIGN §9; Q128 contract p11 finding 1), and
//! the kernel reads none of them.

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

// ── THE MEDIA-TYPE LITERALS a plane and the kernel write.
/// The `application/json` media type — the default `Content-Type`/`Accept` for the JSON REST
/// surfaces. One const so the literal isn't repeated across egress/health/observability.
pub const APPLICATION_JSON: &str = "application/json";

/// Streaming MIME type for SSE (Server-Sent Events) responses — the `Content-Type` value that
/// signals an open event-stream to the client.
pub const TEXT_EVENT_STREAM: &str = "text/event-stream";

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

/// A request head as a plane receives it: its fields in order, each name and value as bytes (the
/// plane ABI's head fields, borrowed). A plane is transport-blind, so it reads a head as this and
/// never as a transport's header type.
/// TRANSITIONAL: drains at codec-seam (c).
pub type HeadFields<'a> = &'a [(&'a [u8], &'a [u8])];

/// The value of the FIRST field in `fields` named `name` (in any case) whose value is a legal header
/// value (every byte `>= 0x20` but DEL, or a tab), or `None` when no such field is present. A field
/// whose value is not legal is passed over, never read, so a predicate sees exactly the first value
/// a header map built from the same fields would hold.
#[must_use]
pub fn head_field<'a>(fields: HeadFields<'a>, name: &str) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|(n, v)| {
            n.eq_ignore_ascii_case(name.as_bytes())
                && v.iter().all(|b| (*b >= 0x20 && *b != 0x7f) || *b == b'\t')
        })
        .map(|(_, v)| *v)
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

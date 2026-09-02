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
//    crate names them WITHOUT reaching into `busbar-core` (the reverse-edge rule). Each atom is
//    dependency-free (a busbar-internal label, an SSE sentinel, a header name, a pure
//    byte/JSON helper) or names only substrate types (`breaker::CanonicalSignal`, `axum::http`, the
//    substrate diagnostics catalog). `busbar-core` re-exports each from its historical
//    `proto::…` path so every in-core / plugin caller compiles unchanged; values are byte-identical
//    to the pre-move definitions.

// ── OpenAI-family error helpers, RELOCATED DOWN from `busbar-core` (`proto::openai_family`) so the
//    `busbar-llm` OpenAI-family dialect writers/readers name them WITHOUT reaching into `busbar-core`.
//    `bearer_error_code` names the canonical error-`type` vocabulary directly (the substrate
//    `ERR_TYPE_*` consts — byte-identical to the `proxy::KIND_*` aliases it named before the move).
//    `busbar-core` re-exports each from its historical `proto::openai_family::…` path so every
//    in-core / plugin caller compiles unchanged; values are byte-identical to the pre-move definitions.

/// Machine-readable `code` field emitted in a bad-key 401 OpenAI-family error envelope.
/// Used in [`bearer_error_code`] to mirror the native `authentication_error` → `invalid_api_key`
/// pairing that official SDKs surface as `error.code`. Also matched by the Responses stream
/// classifier (`class_for_response_failed`) when the provider signal echoes this code back.
pub const CODE_INVALID_API_KEY: &str = "invalid_api_key";

/// Busbar-internal `provider_signal` label for a context-length result (the LANE label, not the
/// OpenAI wire code). Distinct from `proxy::PROVIDER_CODE_CONTEXT_LENGTH` ("context_length_exceeded"),
/// which is the provider-facing code extracted from the request body. Gated the same as
/// [`openai_classify`], its only referent, a test-only single-source mirror of the production
/// classifier — visible to a dependent crate's test builds too via the `test-support` feature.
#[cfg(any(test, feature = "test-support"))]
pub const PROVIDER_SIGNAL_CONTEXT_LENGTH: &str = "context_length";

/// Busbar-internal `extra` key parking OpenAI Chat's per-message `messages[].name` (the optional
/// participant name that disambiguates several speakers in one role).
///
/// WHY A SENTINEL AND NOT AN `IrMessage` FIELD: `name` has NO representation in ANY other protocol in
/// the matrix — Anthropic, Gemini, Bedrock, Cohere and even Responses all model a turn as
/// (role, content) with no participant name — so a first-class IR field would be a field only one
/// dialect could ever read or write. It rides `extra` instead, which gives exactly the right scope:
///
/// * SAME-PROTOCOL (including a pool-alias route that re-serializes rather than forwarding bytes):
///   the writer reads it back and re-emits `name` on each message, so a participant name no longer
///   disappears the moment a route rewrites the model. That was a real same-protocol loss.
/// * CROSS-PROTOCOL: `extra` is cleared at the seam and `ir/variant.rs` names this key in its
///   dropped-keys warn, so the loss is signalled instead of silent.
///
/// Value shape: an object keyed by the message's index in `IrRequest.messages` (as a decimal string)
/// → the name. Keyed by index rather than positional array so a request where only message 7 has a
/// name costs one entry, and so the writer's lookup cannot be thrown off by a `null` hole.
pub const MESSAGE_NAMES_SENTINEL: &str = "__busbar_openai_message_names";

/// Precise context-length prose scan shared by `OpenAiReader::extract_error` and
/// `ResponsesReader::extract_error` — the message scan was duplicated. The scan must be PRECISE:
/// a naive OR of weak tokens (`token`/`maximum`) misclassifies unrelated errors (e.g. a quota body
/// like "maximum number of tokens allowed per day" — a rate-limit, not oversized). Require a
/// CO-LOCATED context-length phrase: a self-contained canonical phrase, or `exceeds` paired
/// specifically with `context`/`token limit`. The caller supplies its own lowercased source
/// (openai scans `error.message`; responses scans the whole body) and applies the
/// `oversized_status` (400/413) GATE itself — that gate is NOT part of this helper.
pub fn openai_context_length_prose_scan(text: &str) -> bool {
    text.contains("maximum context length")
        || text.contains("context length exceeded")
        || text.contains("reduce the length")
        || (text.contains("exceeds") && (text.contains("context") || text.contains("token limit")))
}

/// Map an OpenAI-family error `type` string onto its canonical machine-readable `code`, shared by
/// the OpenAI Chat Completions and `/v1/responses` writers (both emit the identical OpenAI error
/// envelope). A real bad-key 401 returns `{"type":"authentication_error", ..., "code":"invalid_api_key"}`
/// and the official SDKs surface `error.code` to callers, so emitting `code: null` on an auth (or
/// over-quota) failure is a deterministic proxy tell that contradicts the total-indistinguishability
/// promise — we mirror the native pairing for those two types. Every other modeled type, plus any
/// caller-supplied passthrough type, keeps `null`: the shape OpenAI uses when no machine-readable
/// code applies. There is no `_ =>` catch-all hiding an unhandled case; the final arm binds `other`
/// explicitly and emits `null`, the correct native value for those types.
pub fn bearer_error_code(error_type: &str) -> serde_json::Value {
    match error_type {
        ERR_TYPE_AUTHENTICATION => serde_json::Value::String(CODE_INVALID_API_KEY.to_string()),
        // Real OpenAI quota-exhaustion errors carry BOTH `type` and `code` set to
        // `insufficient_quota` (HTTP 429). The over-budget governance path
        // (ingress `ingress_error(..., KIND_INSUFFICIENT_QUOTA, ...)`) reaches these writers with that
        // type; emitting `code: null` for it is an SDK-visible mismatch (the official client surfaces
        // `error.code == "insufficient_quota"`) and a proxy tell, so we mirror the native pairing.
        ERR_TYPE_INSUFFICIENT_QUOTA => {
            serde_json::Value::String(ERR_TYPE_INSUFFICIENT_QUOTA.to_string())
        }
        ERR_TYPE_INVALID_REQUEST
        | ERR_TYPE_PERMISSION
        | ERR_TYPE_NOT_FOUND
        | ERR_TYPE_RATE_LIMIT
        | ERR_TYPE_SERVER_ERROR
        | ERR_TYPE_API_ERROR => serde_json::Value::Null,
        other => {
            // A caller-supplied passthrough type we model no code for: OpenAI carries no
            // machine-readable code for these, so `null` matches the native shape. Named binding
            // (not `_`) keeps the arm explicit per the no-catch-all rule.
            let _ = other;
            serde_json::Value::Null
        }
    }
}

/// Canonical OpenAI-family error classification, shared verbatim by `OpenAiReader::classify` and
/// `ResponsesReader::classify` (the two were word-for-word identical). Both surfaces emit the same
/// OpenAI error envelope, so the mapping — context-length-exceeded (fail over without penalty) first,
/// then 429→RateLimit, 401/403→Auth, 5xx→ServerError, other 4xx→ClientError — is single-sourced here.
#[cfg(any(test, feature = "test-support"))]
pub fn openai_classify(
    status: axum::http::StatusCode,
    body: &[u8],
) -> crate::breaker::CanonicalSignal {
    use crate::breaker::StatusClass;
    use axum::http::StatusCode;
    // context-length-exceeded — the lane is healthy; this must fail over (to a larger-context
    // model), not penalize the breaker. Detect by OpenAI code/message first.
    let code_is_context = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|j| {
            j.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_str())
                .map(|s| s.to_string())
        })
        .as_deref()
        == Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH);
    // Mirror production `extract_error`: the prose message scan is GATED to the HTTP statuses an
    // oversized request actually uses (400 invalid_request_error; 413 payload-too-large). Without the
    // gate a 401/429/5xx whose prose happens to contain "maximum context length" would reclassify as
    // ContextLength — letting a genuine auth/rate-limit/server failure escape fault attribution. The
    // structured `code: "context_length_exceeded"` path is NOT gated (it is unambiguous).
    let oversized = status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE;
    let body_lower = String::from_utf8_lossy(body).to_lowercase();
    if code_is_context || (oversized && body_lower.contains("maximum context length")) {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::ContextLength,
            provider_signal: Some(PROVIDER_SIGNAL_CONTEXT_LENGTH.to_string()),
            retry_after: None,
        };
    }

    if status == StatusCode::TOO_MANY_REQUESTS {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::RateLimit,
            provider_signal: Some("429".to_string()),
            retry_after: None,
        };
    }

    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::Auth,
            provider_signal: Some("auth".to_string()),
            retry_after: None,
        };
    }

    if status.is_server_error() {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::ServerError,
            provider_signal: Some("5xx".to_string()),
            retry_after: None,
        };
    }

    if status.is_client_error() {
        return crate::breaker::CanonicalSignal {
            class: StatusClass::ClientError,
            provider_signal: Some(format!("{}", status.as_u16())),
            retry_after: None,
        };
    }

    crate::breaker::CanonicalSignal {
        class: StatusClass::ClientError,
        provider_signal: None,
        retry_after: None,
    }
}

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

/// Build the static custom-header egress credential (`api-key` / `x-goog-api-key`) carrying the raw
/// key. An un-encodable key (an ASCII control byte a config system may have injected) yields NO header
/// (empty Vec — the upstream then 401s) plus one coded diagnostic naming the header; the key bytes are
/// NEVER logged. Shared so the warn+OMIT policy lives in ONE place.
///
/// RELOCATED DOWN here so the Gemini dialect crate (`x-goog-api-key` scheme) names it WITHOUT reaching
/// into `busbar-core`; `busbar-core`'s `egress_auth::api_key_headers` (the config-`api-key` override
/// path) delegates here so both share one implementation and cannot drift.
pub fn api_key_auth_headers(
    header: &'static str,
    key: &str,
) -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)> {
    match axum::http::HeaderValue::from_str(key) {
        Ok(v) => vec![(axum::http::HeaderName::from_static(header), v)],
        Err(_) => {
            crate::diag_warn!(
                crate::diagnostics::EGRESS_APIKEY_INVALID_BYTES,
                header,
                "egress credential contains invalid header bytes (ASCII control character); \
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

    /// THE WIRE-FINGERPRINT HEADERS this dialect declares as SAFE disambiguators of the SHARED
    /// `GET /v1(beta)/models` list-models surface — the header names whose PRESENCE alone identifies
    /// this dialect's caller on that endpoint (Anthropic's `anthropic-version`, Gemini's
    /// `x-goog-api-key`). `&[]` for a protocol with no such header fingerprint (the OpenAI residual,
    /// and any protocol that serves no model-discovery surface).
    ///
    /// This is DELIBERATELY NARROWER than [`Self::claims`]: the router's full predicate also claims on
    /// a dialect's CREDENTIAL header (Anthropic's `x-api-key`, Bedrock's `AWS4-HMAC-SHA256`
    /// `authorization`) and on PATHS, but an incidental credential header on a models-list GET must NOT
    /// steer the response envelope. `busbar_core`'s list-models handler copies only these declared
    /// headers into the map it hands the detection fold, so it names no dialect while staying
    /// byte-identical to the prior hand-coded two-header sniff.
    pub list_models_fingerprint_headers: &'static [&'static str],
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

// ── TEST-SUPPORT PROTOCOL REGISTRATION (the neutral seam) ──────────────────────────────────────────
// A protocol crate's test-kit registers its `&'static ProtocolDecl` here — a SUBSTRATE type — exactly
// as production's composition root `install_protocols` does, so the extracted protocol crates
// (`busbar-llm`, `busbar-mcp`) reach the neutral ABI (`busbar_substrate::proto::register_test_protocol`)
// rather than back into `busbar_core::proto::registry`. `busbar-core`'s test-support `registry()` folds
// this list ahead of its built-ins on every read, so a protocol registered by any test before it reads
// the registry is visible regardless of test order. This is the exact analogue of the plane axis's
// `busbar_substrate::plane::registry::register_test_plane`, and it is what let the `#[path]` witness
// re-includes of the dialect sources into `busbar-core` be deleted: the externally-linked crate's
// `&DECL` is now the SAME `ProtocolDecl` type (this one), so core no longer needs a re-compiled copy.
#[cfg(any(test, feature = "test-support"))]
static TEST_REGISTERED_PROTOCOLS: std::sync::Mutex<Vec<&'static ProtocolDecl>> =
    std::sync::Mutex::new(Vec::new());

/// TEST-SUPPORT SEAM — register an extracted protocol's declaration into the process registry, the way
/// the composition root's `install_protocols` does in production. Idempotent by protocol name; a
/// protocol crate's test setup calls it (eagerly, and/or from its App-building finalizer) so the
/// fixture registry matches a shipped "busbar with this protocol" binary. The storage lives HERE, on
/// the neutral substrate, so a protocol crate names no `busbar_core::` implementation to register
/// itself.
#[cfg(any(test, feature = "test-support"))]
pub fn register_test_protocol(decl: &'static ProtocolDecl) {
    let mut reg = TEST_REGISTERED_PROTOCOLS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if !reg.iter().any(|d| d.name == decl.name) {
        reg.push(decl);
    }
}

/// TEST-SUPPORT SEAM — register a whole SLICE of an extracted protocol crate's declarations at once
/// (the LLM protocol contributes six dialect declarations). Idempotent per name, order-preserving.
#[cfg(any(test, feature = "test-support"))]
pub fn register_test_protocols(decls: &[&'static ProtocolDecl]) {
    for d in decls {
        register_test_protocol(d);
    }
}

/// TEST-SUPPORT SEAM — the protocols registered through [`register_test_protocol`], snapshot in
/// registration order. `busbar-core`'s test-support `registry()` reads this to fold the extracted
/// protocols into the process registry.
#[cfg(any(test, feature = "test-support"))]
pub fn test_registered_protocols() -> Vec<&'static ProtocolDecl> {
    TEST_REGISTERED_PROTOCOLS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// TEST-SUPPORT SEAM — the COUNT of registered protocols, without cloning the list. `busbar-core`'s
/// test-support `registry()` reads this on its memoized fast path (the one `decl_for` drives several
/// times per request) so resolving a registry that has NOT grown allocates nothing — the alloc-gated
/// hot-path invariant the production `OnceLock` had, preserved under the re-folding test surface.
#[cfg(any(test, feature = "test-support"))]
pub fn test_registered_protocols_len() -> usize {
    TEST_REGISTERED_PROTOCOLS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len()
}

// ── THE PROTOCOL REGISTRY SINGLETON — RELOCATED DOWN from `busbar_core::proto::registry` ───────────
// The declarations, the boot-time aggregates, and the process singleton, moved onto the neutral
// substrate so an extracted protocol crate (`busbar-llm`) resolves `decl_for` / `known_protocols`
// through the neutral ABI rather than reaching BACK into `busbar-core` implementation (the
// reverse-edge rule). `busbar-core` re-exports every item below at its historical
// `busbar_core::proto::registry::…` path, so every in-core / plugin caller compiles unchanged and the
// values are byte-identical. The one item that could NOT travel is the built-in table: production
// carries none (every protocol is a plugin the composition root installs through `install_protocols`),
// and core's OWN test binary names its shipped set in a `tests/` file the neutral-purity lint excludes,
// which reaches this singleton through the [`set_test_builtins`] hook below — so the neutral source here
// spells no protocol crate. `install_protocols_with_path_ingress` (which names the core-only `Arrival`)
// stays in `busbar-core`.

/// THE REGISTRY: the declarations, plus the aggregates that used to be three separate `OnceLock`
/// sweeps. Built once; every field is derived from the declarations and from nothing else, so there
/// is no second place a protocol fact can be stated.
pub struct Registry {
    decls: Vec<&'static ProtocolDecl>,
    /// Absorbed `proxy::lazy_body::captured_head_keys()`: every declared head key, plus every
    /// declared shim key (the shim marker is point-read on the pre-materialized path exactly like a
    /// head key), sorted and deduped so the interning scan is stable.
    head_keys: &'static [&'static str],
    /// Absorbed `proto::streaming_content_types()`.
    streaming_content_types: &'static [&'static str],
    /// Absorbed `proto::array_stream_shim_keys()`.
    array_stream_shim_keys: &'static [&'static str],
    /// The names of the protocols that ship a wire CODEC — the set a provider lane's `protocol:`
    /// may name, and what `KNOWN_PROTOCOLS` used to state as a hand-maintained second list beside
    /// the constructors it had to agree with.
    codec_protocols: &'static [&'static str],
    /// EVERY VERB ANY DECLARED PROTOCOL SERVES, in declaration order, deduped. The half of the
    /// operation vocabulary that is DECLARED rather than owned by the core: `Operation::ALL` holds
    /// the six shape verbs core itself defines, and this holds whatever the registered protocols
    /// brought with them (the seven LLM words today). Deleting a protocol deletes its verbs from
    /// this list with it.
    #[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
    declared_verbs: &'static [busbar_api::operation::Operation],
}

impl Registry {
    /// Build a registry from declarations. Production hands it the built-ins plus anything loaded;
    /// a test hands it the built-ins plus a protocol nobody wrote. THE CONSTRUCTOR IS THE SAME ONE,
    /// which is the property being claimed: joining costs a declaration and nothing else.
    pub fn new(decls: impl IntoIterator<Item = &'static ProtocolDecl>) -> Self {
        let decls: Vec<&'static ProtocolDecl> = decls.into_iter().collect();
        let mut head_keys: Vec<&'static str> = Vec::new();
        let mut streaming_content_types: Vec<&'static str> = Vec::new();
        let mut array_stream_shim_keys: Vec<&'static str> = Vec::new();
        let mut codec_protocols: Vec<&'static str> = Vec::new();
        // Declaration order, deduped BY VALUE (not sorted): the verb vocabulary is operator-visible
        // the same way the protocol list is, so it keeps the deterministic order the declarations
        // state rather than an alphabetical one nobody declared.
        let mut declared_verbs: Vec<busbar_api::operation::Operation> = Vec::new();
        for d in &decls {
            head_keys.extend_from_slice(d.head_keys);
            head_keys.extend(d.array_stream_shim_key);
            streaming_content_types.extend(d.streaming_content_type);
            array_stream_shim_keys.extend(d.array_stream_shim_key);
            if d.codec.is_some() {
                codec_protocols.push(d.name);
            }
            for v in d.verbs {
                if !declared_verbs.contains(v) {
                    declared_verbs.push(*v);
                }
            }
        }
        for v in [
            &mut head_keys,
            &mut streaming_content_types,
            &mut array_stream_shim_keys,
        ] {
            v.sort_unstable();
            v.dedup();
        }
        assert!(
            {
                let mut names: Vec<&str> = decls.iter().map(|d| d.name).collect();
                names.sort_unstable();
                let before = names.len();
                names.dedup();
                names.len() == before
            },
            "two protocol declarations claim the same name: one of them would be unroutable"
        );
        // `Vec::leak` rather than a stored `Vec` + a lifetime cast: the registry is a process
        // singleton built once, so the "leak" is the same allocation a `static` would have held,
        // and it lets every accessor hand out the `&'static [&'static str]` its callers already
        // expect with no `unsafe` anywhere.
        Self {
            decls,
            head_keys: head_keys.leak(),
            streaming_content_types: streaming_content_types.leak(),
            array_stream_shim_keys: array_stream_shim_keys.leak(),
            codec_protocols: codec_protocols.leak(),
            declared_verbs: declared_verbs.leak(),
        }
    }

    /// Resolve a declaration by name. A linear scan over a handful of interned `&'static str`s —
    /// the same comparison chain the `match` compiled to, with the arms as data.
    pub fn decl(&self, name: &str) -> Option<&'static ProtocolDecl> {
        // Interned-name fast path: hot callers hold the registry's own `&'static` name, so pointer
        // identity settles the row without a byte compare; a foreign string falls through to the
        // equality arm of the same pass. Same result either way.
        self.decls
            .iter()
            .copied()
            .find(|d| d.name.as_ptr() == name.as_ptr() || d.name == name)
    }

    /// Every declaration, in declaration order.
    #[allow(dead_code)] // used by the netted dialect test crates; unused in the core target
    pub fn decls(&self) -> &[&'static ProtocolDecl] {
        &self.decls
    }

    /// The complete set of top-level body keys the head projection captures.
    pub fn head_keys(&self) -> &'static [&'static str] {
        self.head_keys
    }

    /// The streaming `Content-Type` set across every declared protocol.
    pub fn streaming_content_types(&self) -> &'static [&'static str] {
        self.streaming_content_types
    }

    /// The array-stream shim keys across every declared protocol.
    pub fn array_stream_shim_keys(&self) -> &'static [&'static str] {
        self.array_stream_shim_keys
    }

    /// The names of every protocol that ships a wire codec.
    pub fn codec_protocols(&self) -> &'static [&'static str] {
        self.codec_protocols
    }

    /// Every verb any declared protocol serves, in declaration order, deduped. See the field doc.
    #[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
    pub fn declared_verbs(&self) -> &'static [busbar_api::operation::Operation] {
        self.declared_verbs
    }
}

/// THE VERBS THE REGISTERED PROTOCOLS DECLARE — the declared half of the operation vocabulary
/// (`Operation::ALL`, the six shape verbs, is the core-owned half).
#[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
pub fn declared_verbs() -> &'static [busbar_api::operation::Operation] {
    registry().declared_verbs()
}

/// The process registry, built on first read from the built-ins plus anything installed. Production
/// only: under the test-support surface [`registry`] re-folds on every read, so there is no frozen
/// memo there — the FIRST-READ witness [`install_protocols`] asserts on is [`TEST_REGISTRY_MEMO`].
#[cfg(not(any(test, feature = "test-support")))]
static REGISTRY: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();

/// Declarations the COMPOSITION ROOT installed before the registry was first read — the protocol
/// crates' entry point. Set once by [`install_protocols`]; folded ahead of the built-ins by
/// [`registry`]'s initializer.
static INSTALLED: std::sync::OnceLock<Vec<&'static ProtocolDecl>> = std::sync::OnceLock::new();

/// INSTALL PROTOCOL DECLARATIONS — the composition root's one write into the protocol axis, and the
/// seam an extracted protocol crate registers through. The `busbar` binary calls this from `main`,
/// before any config read, with the `&DECL` of every protocol crate it links.
///
/// ORDER: installed declarations are folded AHEAD of the built-ins, and the caller's own order is
/// preserved within them.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
/// - if called after the registry was first read.
#[allow(dead_code)] // pub-widened and called by the busbar binary once the first protocol crate registers through it
pub fn install_protocols(decls: Vec<&'static ProtocolDecl>) {
    assert!(
        INSTALLED.set(decls).is_ok(),
        "install_protocols called twice: there is one composition root, and it registers once"
    );
    // The "install before first read" invariant is enforced by the production memo.
    #[cfg(not(any(test, feature = "test-support")))]
    assert!(
        REGISTRY.get().is_none(),
        "install_protocols called after the protocol registry was first read; register in main \
         before any config load or validation touches a protocol"
    );
    #[cfg(any(test, feature = "test-support"))]
    assert!(
        TEST_REGISTRY_MEMO
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none(),
        "install_protocols called after the protocol registry was first read; register in main \
         before any config load or validation touches a protocol"
    );
}

/// THE BOOT PARITY RULE, as a pure function so a test can drive it without touching the process
/// singletons: the NAME of the first declaration whose model is in the URL (`has_model_in_url`) that
/// has NO arrival among `path_ingress_names`, or `None` when every URL-model protocol has one.
pub fn first_path_model_without_arrival(
    decls: &[&'static ProtocolDecl],
    path_ingress_names: &[&str],
) -> Option<&'static str> {
    decls
        .iter()
        .find(|d| d.has_model_in_url && !path_ingress_names.contains(&d.name))
        .map(|d| d.name)
}

/// THE BOOT FOLD: installed declarations ahead of built-ins, one entry per NAME, later same-name
/// registrations skipped audibly. Split from [`registry`]'s `OnceLock` so its order and skip
/// semantics are a function a test can drive.
pub fn merged_boot_decls(
    installed: &[&'static ProtocolDecl],
    builtins: &[&'static ProtocolDecl],
) -> Vec<&'static ProtocolDecl> {
    let mut decls: Vec<&'static ProtocolDecl> = Vec::new();
    for d in installed.iter().chain(builtins) {
        if decls.iter().any(|p| p.name == d.name) {
            tracing::info!(
                protocol = d.name,
                "skipping a later registration of an already-declared protocol \
                 (composition-root copy and built-in copy of one dialect)"
            );
            continue;
        }
        decls.push(d);
    }
    decls
}

/// The process registry. One acquire-load once initialized. Production carries no built-in rows.
#[cfg(not(any(test, feature = "test-support")))]
pub fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| {
        let installed: &[&'static ProtocolDecl] = INSTALLED.get().map(Vec::as_slice).unwrap_or(&[]);
        Registry::new(merged_boot_decls(installed, &[]))
    })
}

// ── TEST-SUPPORT PROCESS REGISTRY ─────────────────────────────────────────────────────────────────
// Under the test-support surface `registry` re-folds the registered set (and any `install_protocols`
// set) ahead of the built-ins on every read, recomputing (and leaking once) only when the set GROWS —
// so a protocol registered by any test before it reads the registry is visible regardless of test
// order, and the `&'static` contract holds. Bounded: at most one leak per distinct registered-set size.
#[cfg(any(test, feature = "test-support"))]
static TEST_REGISTRY_MEMO: std::sync::Mutex<Option<(usize, &'static Registry)>> =
    std::sync::Mutex::new(None);

/// CORE'S OWN-TEST-BINARY BUILT-IN HOOK. Core's `cfg(test)` build names its shipped protocol set
/// (`busbar_llm::DECLS` + the MCP protocol) in a `tests/` file the neutral-purity lint excludes, and
/// installs it here as the stable TAIL of the boot fold — exactly as the pre-relocation core registry
/// folded `builtin_decls()`. The neutral substrate spells no protocol crate; it only holds the fn
/// pointer core hands it. Unset in every other build (busbar-llm's own test binary registers its
/// dialects through [`register_test_protocol`] and needs no core tail).
#[cfg(any(test, feature = "test-support"))]
static TEST_BUILTINS_HOOK: std::sync::OnceLock<fn() -> &'static [&'static ProtocolDecl]> =
    std::sync::OnceLock::new();

/// Install the core-test built-in provider (idempotent). Called by `busbar-core`'s `cfg(test)`
/// registry accessors so the shipped protocol set (and its operator-visible ORDER) is folded as the
/// boot-fold tail. Setting it GROWS the memo's target size, so a registry already folded without the
/// tail re-folds WITH it on the next read — the read is self-healing regardless of call order.
#[cfg(any(test, feature = "test-support"))]
pub fn set_test_builtins(f: fn() -> &'static [&'static ProtocolDecl]) {
    let _ = TEST_BUILTINS_HOOK.set(f);
}

#[cfg(any(test, feature = "test-support"))]
fn test_builtins() -> &'static [&'static ProtocolDecl] {
    TEST_BUILTINS_HOOK.get().map(|f| f()).unwrap_or(&[])
}

#[cfg(any(test, feature = "test-support"))]
pub fn registry() -> &'static Registry {
    // THE MEMOIZED FAST PATH IS ALLOCATION-FREE: the registered-set SIZE (plus the installed set and
    // the core-test built-in tail) is read without cloning any list, and a set that has not grown
    // returns the memoized `&'static Registry` with no fold and no allocation.
    let want = test_registered_protocols_len()
        + INSTALLED.get().map(Vec::len).unwrap_or(0)
        + test_builtins().len();
    let mut memo = TEST_REGISTRY_MEMO.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((n, reg)) = *memo {
        if n == want {
            return reg;
        }
    }
    // SLOW PATH (the set GREW): fold explicit `install_protocols` registrations AND
    // `register_test_protocol` registrations ahead of the built-in tail, then leak ONCE for this
    // grown set — the same `Vec::leak`-shaped process-singleton allocation `Registry::new` relies on.
    let installed: &[&'static ProtocolDecl] = INSTALLED.get().map(Vec::as_slice).unwrap_or(&[]);
    let mut all: Vec<&'static ProtocolDecl> = installed.to_vec();
    all.extend(test_registered_protocols().iter().copied());
    let reg: &'static Registry = Box::leak(Box::new(Registry::new(merged_boot_decls(
        &all,
        test_builtins(),
    ))));
    *memo = Some((want, reg));
    reg
}

// RESOLVE A PROTOCOL BY NAME is [`Registry::decl`] (above). The single free-fn wrapper `decl_for` —
// the ONE by-name resolution the `structure-lint` census pins — stays in `busbar-core`
// (`proto::registry::decl_for`) so it can seed core's OWN-test built-in tail before it reads; every
// other crate (`busbar-llm`) resolves through `registry().decl(name)` directly on this neutral ABI.

/// THE GENERIC ROUTER DETECTION FOLD — `(path, headers)` → which registered protocol a request
/// speaks, or `None` for a path that names none. Folds every registered protocol's
/// [`ProtocolDecl::claims`] predicate in REGISTRATION ORDER and keeps the TIGHTEST claim (lowest
/// [`ClaimStrength`]); a tie breaks by registration order. Byte-identical to the old ladder.
pub fn detect_protocol(path: &str, headers: &axum::http::HeaderMap) -> Option<&'static str> {
    registry()
        .decls()
        .iter()
        .filter_map(|d| d.claims.and_then(|c| c(headers, path)).map(|s| (s, d.name)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
}

/// THE GENERIC RESIDUAL DETECTION FOLD — which registered protocol a path names FROM ITS SHAPE ALONE
/// (no headers), the arm the mount table falls through to. Byte-identical to the old ladder.
pub fn residual_protocol_for_path(path: &str) -> Option<&'static str> {
    registry()
        .decls()
        .iter()
        .filter_map(|d| d.residual_claims.and_then(|c| c(path)).map(|s| (s, d.name)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
}

/// THE REGISTRY-SUPPLIED RESIDUAL DEFAULT — the ONE protocol name core falls back to when no dialect
/// claimed a request yet a dialect must still be named. Reads [`ProtocolDecl::residual_default`], so
/// the literal default dialect name leaves core entirely; `None` when no residual-default protocol is
/// installed (the all-planes-off deletion configuration).
pub fn residual_default_protocol() -> Option<&'static str> {
    registry()
        .decls()
        .iter()
        .find(|d| d.residual_default)
        .map(|d| d.name)
}

/// Every protocol name busbar ships a wire CODEC for — the set a provider's `protocol:` may name.
/// DERIVED from the declarations (`ProtocolDecl::codec`), not maintained beside them.
pub fn known_protocols() -> &'static [&'static str] {
    registry().codec_protocols()
}

// ── THE REGISTRY-RESOLVED PROTO ACCESSORS — RELOCATED DOWN from `busbar_core::proto` ───────────────
// Thin reads of the registry singleton above, moved onto the neutral substrate so an extracted
// protocol crate (`busbar-llm`) resolves a protocol fact through the neutral ABI rather than reaching
// BACK into `busbar-core` (the reverse-edge rule). `busbar-core` re-exports each at its historical
// `busbar_core::proto::…` path, so every in-core / plugin caller compiles unchanged and the values are
// byte-identical. They read the SAME singleton `registry()` returns, so — exactly as `known_protocols`
// already does — under core's own test binary they observe the core-test built-in tail once any core
// accessor has seeded the substrate hook (idempotent, self-healing).

// ── THE NEUTRAL STREAMING-TRANSLATOR FACTORY — RELOCATED DOWN from `busbar_core::proto` ────────────
// The plugin-provided fn-ptr factory that builds a concrete stream translator for an ingress→egress
// pair, and the single construction seam both forward paths call. Moved onto the neutral substrate so
// the `busbar-llm` plugin installs its factory and drives the seam through the neutral ABI rather than
// reaching BACK into `busbar-core`. The `OnceLock` moving DOWN to the single-compiled substrate is a
// strict improvement for the "one instance" invariant (core is dual-compilable). `busbar-core` keeps
// its `#[cfg(test)]` fixture-routing arm (its own test binary routes straight to the netted concrete
// factory) and re-exports the production arm + the installer at their historical paths.

/// The plugin-provided factory that builds a concrete stream translator for an ingress→egress pair.
type StreamTranslatorFactory = fn(&str, &str, bool) -> Option<Box<dyn StreamTranslator>>;

static STREAM_TRANSLATOR_FACTORY: std::sync::OnceLock<StreamTranslatorFactory> =
    std::sync::OnceLock::new();

/// Install the plugin's streaming-translator factory. Idempotent-by-first-write (the composition root
/// registers once); a second install is ignored so a test harness cannot clobber a live pointer.
pub fn install_stream_translator_factory(f: StreamTranslatorFactory) {
    let _ = STREAM_TRANSLATOR_FACTORY.set(f);
}

/// THE SINGLE streaming-translator construction seam the forward paths call. Neutral in and out. It
/// routes to the installed pointer (returns `None` — legacy raw passthrough — when no plugin installed
/// one, e.g. a core-only build with no dialects).
pub fn new_stream_translator(
    ingress: &str,
    egress: &str,
    is_sse: bool,
) -> Option<Box<dyn StreamTranslator>> {
    STREAM_TRANSLATOR_FACTORY
        .get()
        .and_then(|f| f(ingress, egress, is_sse))
}

/// RESOLVE A PROTOCOL BY NAME through the substrate registry singleton. A pure read of a
/// `&'static ProtocolDecl`; allocates nothing. `busbar-core` keeps its own `decl_for` wrapper (which
/// additionally seeds the core-test built-in hook under `#[cfg(test)]`); this is the plane-facing
/// entry, behaviorally identical for any consumer that compiles `busbar-core` as a non-test dependency.
pub fn decl_for(name: &str) -> Option<&'static ProtocolDecl> {
    registry().decl(name)
}

/// The set of streaming `Content-Type` values across every declared protocol — a registry aggregate
/// folded once at boot from `ProtocolDecl::streaming_content_type`.
pub fn streaming_content_types() -> &'static [&'static str] {
    registry().streaming_content_types()
}

/// The set of array-stream shim keys across every declared protocol (only Gemini declares one), the
/// aggregate `proxy::strip_router_shim_keys` reads to remove every protocol's marker while naming none.
pub fn array_stream_shim_keys() -> &'static [&'static str] {
    registry().array_stream_shim_keys()
}

/// The array-stream shim key the NAMED protocol declares, or `None` if it declares none or is not
/// registered. The injection site reads it by name so it names no protocol submodule.
pub fn array_stream_shim_key_for(protocol_name: &str) -> Option<&'static str> {
    decl_for(protocol_name).and_then(|d| d.array_stream_shim_key)
}

/// The vendor-plausible auth-failure wire MESSAGE for an ingress protocol, dispatched through
/// `ProtocolDecl::auth_failure_message` so the per-vendor copy lives in the declaration, not here. An
/// unknown protocol falls back to the default generic copy.
pub fn vendor_auth_failure_message(proto: &str) -> &'static str {
    decl_for(proto)
        .map(|d| d.auth_failure_message)
        .unwrap_or("authentication failed")
}

/// Resolve a provider's configured protocol NAME to the registry's interned `&'static str` for the
/// lane-build path, or `None` for an unknown name or one that declares no wire codec (MCP/A2A are not
/// lane protocols).
pub fn lane_protocol_name(name: &str) -> Option<&'static str> {
    decl_for(name).filter(|d| d.codec.is_some()).map(|d| d.name)
}

/// Collect `(HeaderName, HeaderValue)` pairs into an axum `HeaderMap`. A dependency-free neutral
/// helper (no protocol vocabulary), used by the dialect crates on the egress-header path.
pub fn convert_headers(
    headers: Vec<(axum::http::HeaderName, axum::http::HeaderValue)>,
) -> axum::http::HeaderMap {
    let mut map = axum::http::HeaderMap::new();
    for (name, value) in headers {
        map.insert(name, value);
    }
    map
}

/// Signal the RESPONSE-side provider metadata that an egress dialect carries and no ingress dialect
/// can express, so it does not vanish from a translated response with nothing in the logs. WHICH
/// fields are present, and the SHAPE of the lookup, are the egress dialect's own knowledge — declared
/// on `ProtocolDecl::vendor_response_metadata` and read here by name so the substrate spells no
/// dialect. A dialect with no such vendor-scoped artifact declares `None` and reports nothing. Called
/// ONLY from the cross-protocol response seam, so a same-protocol route never logs a word about them.
pub fn warn_untranslatable_response_metadata(
    egress: &str,
    ingress: &str,
    body: &serde_json::Value,
) {
    let present: Vec<&str> = decl_for(egress)
        .and_then(|d| d.vendor_response_metadata)
        .map(|report| report(body))
        .unwrap_or_default();
    if present.is_empty() {
        return;
    }
    crate::diag_debug!(
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

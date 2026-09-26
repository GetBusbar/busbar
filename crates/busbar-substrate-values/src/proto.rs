// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral protocol vocabulary relocated DOWN from `busbar-core` (Batch A).
//!
//! These are dependency-free protocol atoms — a wire error-`type` string and the declared inbound
//! auth scheme — that a plane/plugin crate (`busbar-mcp`) names WITHOUT needing `busbar-core`.
//! `busbar-core` re-exports each from its original home (`proto::openai_family` / `proto::registry`)
//! so every existing in-core and plugin caller compiles unchanged. Values are byte-identical to the
//! pre-move definitions.

// ── THE PROTOCOL-SEAM SHAPES live in `busbar_contract::protocol` (DECISIONS #83: contract = shapes;
//    SD-1 of the #83a split): the canonical error-`type` vocabulary, the IR-parse signal label, the
//    stream-abort detail, the `IrError` alias, the SSE frame-boundary scan, and the neutral codec
//    traits (`StreamTranslator`, `ArrayStreamFramer`, `DialectCodec`), the detection-predicate shapes
//    and `SigningContext`. Re-exported here under their historical paths, so every caller compiles
//    unchanged. What stays below is the declaration itself (`ProtocolDecl` and its inbound-auth and
//    egress-credential fields, pending the O7-ruled shape), the registry, and dialect helpers.
// The two SSE line walkers were crate-private here and stay so: the dialect helpers below share them.
pub use busbar_contract::protocol::{
    find_frame_terminator, ArrayStreamFramer, ClaimStrength, ClaimsFn, DialectCodec, IrError,
    ResidualClaimsFn, SigningContext, StreamTranslator, VendorResponseMetadataFn,
    ERR_TYPE_API_ERROR, ERR_TYPE_AUTHENTICATION, ERR_TYPE_INSUFFICIENT_QUOTA,
    ERR_TYPE_INVALID_REQUEST, ERR_TYPE_NOT_FOUND, ERR_TYPE_OVERLOADED, ERR_TYPE_PERMISSION,
    ERR_TYPE_RATE_LIMIT, ERR_TYPE_REQUEST_TOO_LARGE, ERR_TYPE_SERVER_ERROR, SIGNAL_IR_PARSE,
    STREAM_ABORT_DETAIL,
};
pub(crate) use busbar_contract::protocol::{sse_line_spans, sse_lines};

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
/// which is the provider-facing code extracted from the request body. Its referent, the OpenAI-family
/// classifier test mirror, relocated to the LLM plane's `openai_chat` wire module
/// (`openai_classify`); this const stays here (neutral — it names no vendor) and that classifier
/// reaches it at this substrate path, visible to a dependent crate's test builds too via the
/// `test-support` feature.
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
pub const MESSAGE_NAMES_SENTINEL: &str = "__busbar_message_names";

/// Precise context-length prose scan shared by `OpenAiReader::extract_error` and
/// `ResponsesReader::extract_error` — the message scan was duplicated. The scan must be PRECISE:
/// a naive OR of weak tokens (`token`/`maximum`) misclassifies unrelated errors (e.g. a quota body
/// like "maximum number of tokens allowed per day" — a rate-limit, not oversized). Require a
/// CO-LOCATED context-length phrase: a self-contained canonical phrase, or `exceeds` paired
/// specifically with `context`/`token limit`. The caller supplies its own lowercased source
/// (openai scans `error.message`; responses scans the whole body) and applies the
/// `oversized_status` (400/413) GATE itself — that gate is NOT part of this helper.
pub fn context_length_prose_scan(text: &str) -> bool {
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

/// The OpenAI-style SSE stream terminator sentinel (`data: [DONE]`). The bare token is matched by the
/// cross-protocol streaming core and several readers; the full framed bytes are emitted on egress.
/// Shared here so no reader/writer re-spells either form.
pub const SSE_DONE_SENTINEL: &str = "[DONE]";
/// The full framed `data: [DONE]\n\n` bytes emitted on egress. See [`SSE_DONE_SENTINEL`].
pub const SSE_DONE_FRAME: &[u8] = b"data: [DONE]\n\n";

/// The HTTP `Authorization` header name (lowercase, canonical). Emitted by the bearer/SigV4 auth-header
/// builders across protocols; named once so no builder re-spells it.
pub const HDR_AUTHORIZATION: &str = "authorization";

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
pub fn bearer_auth_headers(proto: &str, key: &str) -> Vec<(http::HeaderName, http::HeaderValue)> {
    match http::HeaderValue::from_str(&format!("Bearer {key}")) {
        Ok(value) => vec![(http::HeaderName::from_static(HDR_AUTHORIZATION), value)],
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
) -> Vec<(http::HeaderName, http::HeaderValue)> {
    match http::HeaderValue::from_str(key) {
        Ok(v) => vec![(http::HeaderName::from_static(header), v)],
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
///
/// Walks the SAME line grammar as [`sse_lines`] / [`find_frame_terminator`] — CRLF, a lone LF, **or**
/// a lone CR each end a line — rather than splitting on LF alone. Splitting on LF alone made a
/// bare-CR frame read as ONE line, so the whole frame body came back as the event name
/// (`message_start\rdata: …`); the Anthropic same-protocol fast path matches that name against its
/// usage-bearing event set, so every usage frame of such a stream was skipped and the request billed
/// zero tokens. One grammar here means the probe and the parse can no longer disagree about where a
/// line ends.
pub fn sse_event_type(frame: &[u8]) -> &str {
    let mut name = "";
    for (start, end) in sse_line_spans(frame) {
        if let Some(rest) = frame[start..end].strip_prefix(b"event:") {
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

/// Parse one SSE frame into `(event_type, data_payload)`. `event_type` is "" when the frame has
/// no `event:` line (OpenAI style). Multiple `data:` lines in a single frame are concatenated with
/// `\n` per the SSE spec. Returns `None` if the frame carries no `data:` line (including a
/// frame with only an `event:` line) or is invalid UTF-8.
pub fn parse_sse_frame(frame: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(frame).ok()?;
    let mut event_type = String::new();
    let mut data_lines: Vec<&str> = Vec::new();
    for line in sse_lines(text) {
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

#[cfg(test)]
#[path = "tests/proto_2.rs"]
mod frame_terminator_tests;

/// THE PROTOCOL DECLARATION and its two auth fields' types — [`ProtocolDecl`], the inbound
/// [`IngressAuth`], the plane-built [`EgressAuthHeaders`] builder and the DECLARED egress
/// [`EgressScheme`] (with its credential-family table rows). SHAPES: defined in
/// `busbar_contract::protocol` (DECISIONS #83, SD-2b of the #83a split) and re-exported here under
/// their historical paths.
pub use busbar_contract::protocol::{
    CredentialFamily, CredentialHeader, EgressAuthHeaders, EgressScheme, IngressAuth, ProtocolDecl,
};

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
    // Did the scan actually reach the top-level object's closing `}`? The loop below has TWO exits
    // and only ONE of them is well-formed: the `depth == 0` `break` on `}`, and falling off the end
    // of the buffer. Nothing downstream distinguished them, so a TRUNCATED object whose members all
    // parsed — `{"a":1,"usage":{"x":1}`, exactly the shape a cut-off upstream SSE chunk has, and
    // busbar forces `include_usage` upstream so `usage` is on every chunk — produced a `usage_range`
    // and spliced, returning `Some("{\"a\":1")`: an unclosed object the verbatim writer emits to
    // the client as valid framing over invalid JSON. The doc above promises `None` for "any shape
    // the scanner does not fully understand", which is what routes the caller to its
    // parse-reserialize fallback (and, when that also fails, to the untouched original bytes).
    let mut closed = false;

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
                    closed = true;
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

    if !closed {
        return None; // ran off the end of a truncated object - never splice an unclosed shape
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
// (`busbar-llm`, `busbar-mcp`) reach the neutral ABI (`busbar_kernel::proto::register_test_protocol`)
// rather than back into `busbar_kernel::proto::registry`. `busbar-core`'s test-support `registry()` folds
// this list ahead of its built-ins on every read, so a protocol registered by any test before it reads
// the registry is visible regardless of test order. This is the exact analogue of the plane axis's
// `busbar_kernel::plane::registry::register_test_plane`, and it is what let the `#[path]` witness
// re-includes of the dialect sources into `busbar-core` be deleted: the externally-linked crate's
// `&DECL` is now the SAME `ProtocolDecl` type (this one), so core no longer needs a re-compiled copy.
#[cfg(any(test, feature = "test-support"))]
static TEST_REGISTERED_PROTOCOLS: std::sync::Mutex<Vec<&'static ProtocolDecl>> =
    std::sync::Mutex::new(Vec::new());

/// TEST-SUPPORT SEAM — register an extracted protocol's declaration into the process registry, the way
/// the composition root's `install_protocols` does in production. Idempotent by protocol name; a
/// protocol crate's test setup calls it (eagerly, and/or from its App-building finalizer) so the
/// fixture registry matches a shipped "busbar with this protocol" binary. The storage lives HERE, on
/// the neutral substrate, so a protocol crate names no `busbar_kernel::` implementation to register
/// itself.
#[cfg(any(test, feature = "test-support"))]
pub fn register_test_protocol(decl: &'static ProtocolDecl) {
    arm_host_services();
    // A name the composition root already installed is declared: this seam stands in for a root
    // in binaries that have none, and re-declaring behind a real root would make the boot fold
    // report a duplicate the operator never caused (a test-built binary would then carry boot
    // lines the shipped one does not).
    let installed_already = INSTALLED
        .get()
        .is_some_and(|installed| installed.iter().any(|d| d.name == decl.name));
    if installed_already {
        return;
    }
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

// ── THE PROTOCOL REGISTRY SINGLETON — RELOCATED DOWN from `busbar_kernel::proto::registry` ───────────
// The declarations, the boot-time aggregates, and the process singleton, moved onto the neutral
// substrate so an extracted protocol crate (`busbar-llm`) resolves `decl_for` / `known_protocols`
// through the neutral ABI rather than reaching BACK into `busbar-core` implementation (the
// reverse-edge rule). `busbar-core` re-exports every item below at its historical
// `busbar_kernel::proto::registry::…` path, so every in-core / plugin caller compiles unchanged and the
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
    declared_verbs: &'static [busbar_contract::operation::OpVerb],
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
        let mut declared_verbs: Vec<busbar_contract::operation::OpVerb> = Vec::new();
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
        //
        // A `&str` is a POINTER *and* a LENGTH — the fast path must compare both. A subslice of an
        // interned name (e.g. a caller stripping a suffix off an already-resolved name) starts at
        // the SAME address as the name it was sliced from, so a data-pointer match alone would
        // answer "root" with the declaration filed under "rooted": a protocol name nothing declared,
        // resolved to another protocol's codec, auth scheme and verbs.
        self.decls.iter().copied().find(|d| {
            (d.name.as_ptr() == name.as_ptr() && d.name.len() == name.len()) || d.name == name
        })
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
    pub fn declared_verbs(&self) -> &'static [busbar_contract::operation::OpVerb] {
        self.declared_verbs
    }
}

/// THE VERBS THE REGISTERED PROTOCOLS DECLARE — the declared half of the operation vocabulary
/// (`Operation::ALL`, the six shape verbs, is the core-owned half).
#[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
pub fn declared_verbs() -> &'static [busbar_contract::operation::OpVerb] {
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

/// Arm the HOST SERVICES a protocol cell reaches through the contract: the usage-tap fault reporter
/// (`handlers::report_usage_tap_decode_failure`) a cell's default usage tap reports through, the
/// usage-tap fault latch (`handlers::usage_tap_decode_fail_should_warn`) a codec whose tap reads a
/// body more than one way counts each way through, the translate-body cap reader
/// (`proxy::max_translate_body_bytes`, the live operator knob), the host entropy source (the OS
/// CSPRNG) and the host wall clock (`store::now`). Called wherever protocols become reachable —
/// [`install_protocols`] and the test registration seams — so no cell can be dispatched before they
/// are armed. Idempotent.
fn arm_host_services() {
    busbar_contract::codec::install_usage_tap_fault_reporter(
        crate::handlers::report_usage_tap_decode_failure,
    );
    busbar_contract::codec::install_usage_tap_fault_latch(
        crate::handlers::usage_tap_decode_fail_should_warn,
    );
    busbar_contract::codec::install_translate_cap_reader(crate::proxy::max_translate_body_bytes);
    busbar_contract::codec::install_entropy_source(os_entropy);
    busbar_contract::codec::install_wall_clock(crate::store::now);
}

/// The host entropy source: the OS CSPRNG, one `getrandom` fill per call.
fn os_entropy(out: &mut [u8]) -> bool {
    getrandom::fill(out).is_ok()
}

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
    arm_host_services();
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
    arm_host_services();
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
pub fn detect_protocol(path: &str, headers: &http::HeaderMap) -> Option<&'static str> {
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

// ── THE REGISTRY-RESOLVED PROTO ACCESSORS — RELOCATED DOWN from `busbar_kernel::proto` ───────────────
// Thin reads of the registry singleton above, moved onto the neutral substrate so an extracted
// protocol crate (`busbar-llm`) resolves a protocol fact through the neutral ABI rather than reaching
// BACK into `busbar-core` (the reverse-edge rule). `busbar-core` re-exports each at its historical
// `busbar_kernel::proto::…` path, so every in-core / plugin caller compiles unchanged and the values are
// byte-identical. They read the SAME singleton `registry()` returns, so — exactly as `known_protocols`
// already does — under core's own test binary they observe the core-test built-in tail once any core
// accessor has seeded the substrate hook (idempotent, self-healing).

// ── THE NEUTRAL STREAMING-TRANSLATOR FACTORY — RELOCATED DOWN from `busbar_kernel::proto` ────────────
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
pub fn convert_headers(headers: Vec<(http::HeaderName, http::HeaderValue)>) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
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

#[cfg(test)]
#[path = "tests/proto.rs"]
mod boot_fold_tests;

#[cfg(test)]
#[path = "tests/proto_strip_tests.rs"]
mod proto_strip_tests;

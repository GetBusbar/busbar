// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM DIALECTS' SHARED WIRE HELPERS (#83a SD-3: dialect machinery). The OpenAI-family error
//! helpers, the SSE `[DONE]` terminator, the SSE frame probe/parse/write the stream translator and
//! the readers share, the base62 id alphabet, the busbar-internal message-name sentinel, the
//! top-level `usage` stripper of the same-protocol verbatim writer, and the dropped provider-metadata
//! report. Every one of them is spoken only by this plane's dialects, so they are the plane's own;
//! the contract carries only the vocabulary both sides of the seam must spell alike
//! (`busbar_contract::protocol`: the error-`type` bank, the SSE frame-boundary scan and line walkers).

use busbar_contract::protocol::{
    sse_line_spans, sse_lines, ERR_TYPE_API_ERROR, ERR_TYPE_AUTHENTICATION,
    ERR_TYPE_INSUFFICIENT_QUOTA, ERR_TYPE_INVALID_REQUEST, ERR_TYPE_NOT_FOUND, ERR_TYPE_PERMISSION,
    ERR_TYPE_RATE_LIMIT, ERR_TYPE_SERVER_ERROR,
};

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
#[cfg(test)]
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
/// Walks the SAME line grammar as [`sse_lines`] / [`busbar_contract::protocol::find_frame_terminator`] — CRLF, a lone LF, **or**
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
    let present: Vec<&str> = crate::decl_of(egress)
        .and_then(|d| d.vendor_response_metadata)
        .map(|report| report(body))
        .unwrap_or_default();
    if present.is_empty() {
        return;
    }
    busbar_contract::diag_debug!(
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
#[path = "tests/dialect_drift_tests.rs"]
mod drift_tests;

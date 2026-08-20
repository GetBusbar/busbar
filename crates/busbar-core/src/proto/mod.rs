// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol seam: a protocol-agnostic core, with each wire dialect's specifics confined to a
//! `Reader` (wire → signal/IR) and a `Writer` (IR/intent → wire). `Protocol` bundles a Reader and
//! Writer; a string-keyed registry maps a provider's protocol name to its `Protocol`.

use axum::http::{header::HeaderValue, HeaderName, StatusCode};
use std::sync::Arc;

// StatusClass and CanonicalSignal are defined in breaker.rs and re-exported here for compatibility.
// The `CanonicalSignal` re-export is consumed only by the per-protocol `classify` test helpers (which
// are themselves `#[cfg(test)]`), so it is gated to test builds to avoid an unused-import warning in
// the 1.0 binary; production code refers to the canonical `crate::breaker::CanonicalSignal` directly.
#[cfg(any(test, feature = "test-support"))]
pub use crate::breaker::CanonicalSignal;
pub(crate) use crate::breaker::StatusClass;

// Import types needed for response/stream IR
use crate::ir::IrStreamEvent;
// Consumed via `use super::*` by the proto test modules only, since the dialect that used them in
// production moved out with the anthropic extraction.
#[cfg(test)]
use crate::ir::IrBlockMeta;

/// Busbar-internal `provider_signal` label for an IR-parse failure (the LANE label the breaker/metrics
/// layer reads to classify a translation/parse error). A busbar-internal signal, NOT a wire shape, so
/// it lives in the agnostic proto layer; the per-protocol readers reference it rather than re-spelling
/// the literal.
pub const SIGNAL_IR_PARSE: &str = "ir_parse";

/// The OpenAI-style SSE stream terminator sentinel (`data: [DONE]`). The bare token is matched by the
/// cross-protocol streaming core and several readers; the full framed bytes are emitted on egress.
/// Shared here so no reader/writer re-spells either form.
pub const SSE_DONE_SENTINEL: &str = "[DONE]";
pub(crate) const SSE_DONE_FRAME: &[u8] = b"data: [DONE]\n\n";

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
/// compare against well-formed tokens. Instead we surface a `tracing::warn!` (naming the protocol so
/// the operator can locate the misconfigured lane) and OMIT the header entirely (empty Vec). The
/// request is still sent (the trait can't refuse it here) and the upstream answers 401, but the warn
/// line tells the operator the lane's credential bytes are invalid. The key is NEVER logged (it is the
/// secret); only the protocol name and the fact that the bytes are malformed.
pub fn bearer_auth_headers(proto: &str, key: &str) -> Vec<(HeaderName, HeaderValue)> {
    match HeaderValue::from_str(&format!("Bearer {key}")) {
        Ok(value) => vec![(HeaderName::from_static(HDR_AUTHORIZATION), value)],
        Err(_) => {
            tracing::warn!(
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
    tracing::warn!(
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
pub(crate) const DEFAULT_MAX_TOKENS: u32 = 4096;

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

/// ProtocolReader extracts signals from wire responses (Stage 1a + 1b).
/// Methods are provider-specific normalizers that feed the breaker's Stage 2 classifier.
pub trait ProtocolReader: Send + Sync {
    /// Extract raw error info from HTTP response without classifying.
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError;

    /// Classify a response into a canonical signal in one call (convenience over
    /// `extract_error` + `normalize_raw_error`). The release path runs those two stages explicitly
    /// (so it can apply the lane's `error_map`); this all-in-one form has no production caller and
    /// exists solely to back the per-protocol classification unit tests, so it is compiled only
    /// under test builds (`test`, and `test-support` so an extracted dialect crate's own test
    /// build — whose busbar-core dependency is not itself under `cfg(test)` — sees the same trait
    /// member its classification tests drive) and kept out of the 1.0 binary.
    /// DEFAULT provided (the two release-path stages with an empty `error_map`) so a dialect
    /// whose own `classify` override is test-gated still satisfies the trait when it is compiled
    /// as a production dependency inside a build where core's `test-support` feature happens to be
    /// unified on.
    #[cfg(any(test, feature = "test-support"))]
    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal {
        crate::breaker::normalize_raw_error(
            &self.extract_error(status, body),
            &std::collections::HashMap::new(),
        )
    }

    /// Read an IR request from wire JSON.
    fn read_request(&self, body: &serde_json::Value) -> Result<crate::ir::IrRequest, IrError>;

    /// Recover neutral token totals from a HEAD-truncated non-stream response tail. The retained
    /// slice is NOT a well-formed document (its opening structure — or a string it cut through — is
    /// gone), so the normal full-document parse reliably fails on it; instead isolate the
    /// self-contained trailing `usage` object and map THIS dialect's fields onto the neutral
    /// [`crate::billing::TokenUsage`]. Returns `None` for a dialect/tail without a recognizable usage
    /// object (the caller treats that as "bill zero, counted+warned"). Defaulted to `None` so a
    /// non-LLM dialect need not implement it.
    fn recover_truncated_usage(&self, _tail: &[u8]) -> Option<crate::billing::TokenUsage> {
        None
    }

    /// Read a single response/stream event from already-de-framed SSE data.
    ///
    /// Default: delegate to the canonical fan-out [`read_response_events`] over a fresh decode
    /// state and surface its FIRST IR event. Every protocol whose live translation path is the
    /// plural fan-out (OpenAI, Gemini, Cohere, Responses, Bedrock) inherits this default — the
    /// singular form exists only to satisfy the trait and has no production caller on those
    /// protocols. Delegating (rather than a dead `None` stub) guarantees that if the call-path
    /// invariant is ever broken, an event degrades to 1:1 rather than being SILENTLY swallowed — a
    /// silent drop is both a correctness failure and hard to diagnose. A chunk that maps to several
    /// IR events loses the trailing ones through this 1:1 adapter (exactly why production uses the
    /// plural path), but nothing is dropped wholesale. Never panics on the request path:
    /// `StreamDecodeState::default()` is infallible and the fan-out is total. Anthropic overrides
    /// this with its native 1:1 singular implementation (its plural form wraps the singular).
    fn read_response_event(
        &self,
        event_type: &str,
        data: &serde_json::Value,
    ) -> Option<IrStreamEvent> {
        let mut state = crate::ir::StreamDecodeState::default();
        self.read_response_events(event_type, data, &mut state)
            .into_iter()
            .next()
    }

    /// Fan-out variant: one wire event/chunk → 0..n IR stream events, threading
    /// per-request decode state. Anthropic is 1:1 (wraps the singular, ignores state); OpenAI's
    /// flat stream synthesizes block boundaries via the state. This is the general translation
    /// API the live response-translation path calls.
    fn read_response_events(
        &self,
        event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent>;

    /// Read a whole (non-streaming) response from wire JSON.
    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError>;

    /// Clone this reader as a trait object.
    fn clone_box(&self) -> Box<dyn ProtocolReader>;
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

pub trait ProtocolWriter: Send + Sync {
    /// Returns the upstream path suffix (e.g., "/v1/messages").
    fn upstream_path(&self) -> &str;

    /// the upstream path for a specific model. Most protocols ignore the model and
    /// return a fixed path (the default); Gemini's path embeds the model
    /// (`/v1beta/models/{model}:generateContent`). `forward` uses this to build the URL.
    fn upstream_path_for(&self, _model: &str) -> String {
        self.upstream_path().to_string()
    }

    /// Per-request upstream path that also knows whether the caller wants a streamed response.
    /// Defaults to `upstream_path_for` (most protocols use one path for both stream and non-stream).
    /// Gemini overrides it: streaming uses `:streamGenerateContent?alt=sse`, non-streaming
    /// `:generateContent`.
    fn upstream_path_for_stream(&self, model: &str, _stream: bool) -> String {
        self.upstream_path_for(model)
    }

    // Outbound auth moved OFF the protocol writer (protocol is post-auth): a lane's credential is
    // resolved by `crate::egress_auth` and called via `lane.credential.headers_for`. Per-scheme logic
    // lives in `pub(crate)` free fns (`bearer_auth_headers`, `anthropic::anthropic_auth_headers`,
    // `bedrock::sigv4_sign_headers`).

    /// Rewrites the model field in the request body, returning whether the body actually CHANGED.
    ///
    /// The default inserts/overwrites a top-level `"model"` string — the shape every JSON-body
    /// protocol (Anthropic, Cohere, OpenAI, Gemini, Responses) needs. `BedrockWriter` overrides
    /// this with a no-op (returns `false`) because the target model is carried in the request URL,
    /// not the body.
    ///
    /// The return value is the structural coupling that drives request pristine-tracking (Change B):
    /// it reports `true` ONLY when the value truly changes (the existing `model` differs from the
    /// authoritative lane model, or no `model` was present), so a same-protocol passthrough whose
    /// client already sent the canonical model name stays pristine and can short-circuit.
    fn rewrite_model_if_needed(&self, body: &mut serde_json::Value, model: &str) -> bool {
        if let Some(obj) = body.as_object_mut() {
            // Only an ACTUAL change counts: if the body already carries exactly this model string,
            // the insert is a no-op and the body is unchanged (stays pristine).
            if obj.get("model").and_then(|m| m.as_str()) == Some(model) {
                return false;
            }
            obj.insert("model".to_string(), serde_json::json!(model));
            return true;
        }
        false
    }

    /// Write an IR request to wire JSON.
    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value;

    /// Apply a hook's `rewrite` reply to an INGRESS body of THIS dialect, in place. Returns whether
    /// the body actually changed; `false` leaves it untouched (fail-safe — never a corrupted
    /// request).
    ///
    /// # Why this is a writer method
    ///
    /// A rewrite reply carries `{role, content}` messages in the canonical vocabulary the hook was
    /// projected in, and each dialect frames conversation content differently. That framing is
    /// WRITE-SIDE dialect knowledge, so it belongs to the writer that already owns every other
    /// write-side framing decision — not to a `match ingress_protocol` on the hook seam, where it
    /// lived until this method existed and where a seventh protocol would have needed a new arm.
    /// With the framing here, a protocol gets a correct write-back by REGISTERING.
    ///
    /// The default is the shape three dialects share: the reply IS their message shape, so its
    /// `messages` array is inserted verbatim (nothing is re-derived, so nothing can be lost), and
    /// abstract `tools` definitions are appended. A dialect whose conversation container is spelled
    /// differently, or whose turns are not `{role, content}`, overrides this and re-frames.
    ///
    /// LOSSY WRITE-BACK (pre-existing, unchanged by the move, and out of scope to fix here): a
    /// re-framing dialect renders each reply message into a single text turn, so a hook that echoes
    /// a projection verbatim promotes non-prose content — including the opaque-content marker — into
    /// a visible text turn shipped upstream. The behaviour is pinned by
    /// `apply_rewrite_to_body_echoes_redacted_marker_as_visible_text` so a future change cannot
    /// regress this note into a stale claim.
    fn apply_rewrite_to_ingress_body(
        &self,
        obj: &mut serde_json::Map<String, serde_json::Value>,
        messages: &[serde_json::Value],
        tools: &[serde_json::Value],
    ) -> bool {
        if !obj.get("messages").is_some_and(serde_json::Value::is_array) {
            return false;
        }
        obj.insert(
            "messages".to_string(),
            serde_json::Value::Array(messages.to_vec()),
        );
        if !tools.is_empty() {
            match obj
                .get_mut("tools")
                .and_then(serde_json::Value::as_array_mut)
            {
                Some(existing) => existing.extend(tools.iter().cloned()),
                None => {
                    obj.insert(
                        "tools".to_string(),
                        serde_json::Value::Array(tools.to_vec()),
                    );
                }
            }
        }
        true
    }

    /// The caller controls this writer will DROP for `req` on cross-protocol egress because the target
    /// dialect has no native representation (audit-and-allow: the request still forwards, but each drop
    /// is recorded as a first-class audit event by the cross-protocol seam). Default: none.
    fn dropped_egress_controls(&self, _req: &crate::ir::IrRequest) -> Vec<&'static str> {
        Vec::new()
    }

    /// PERFORM the `path_base` body reshape `ProtocolDecl::reshapes_body_at_path_base` promised, returning
    /// whether the body changed. The mutation is the protocol's own wire knowledge and lives with
    /// the writer, so the agnostic forward path applies "whatever this dialect needs at a path-model
    /// URL" without knowing that anything named `anthropic_version` exists. Default: no-op, `false`.
    fn reshape_for_path_base(&self, _body: &mut serde_json::Value) -> bool {
        false
    }

    /// Write a response/stream event to wire (event_type, data).
    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)>;

    /// Map a mid-stream `IrError` to a MODELED-EXCEPTION pair `(exception_name, message)` for
    /// protocols whose native stream signals errors with an out-of-band exception frame rather than a
    /// normal event. Only the AWS Bedrock event-stream wire distinguishes this: a native AWS SDK
    /// dispatches errors off the `:message-type: exception` / `:exception-type` headers, which can only
    /// be produced by `eventstream::encode_exception_frame` — NOT by `write_response_event`, whose
    /// `(event_type, json)` pair is always framed `:message-type: event`. `StreamTranslate` calls this
    /// for a Bedrock-INGRESS stream when the IR event is `IrStreamEvent::Error`, so the client receives
    /// the typed Converse exception it expects instead of a silently-dropped `event`-typed frame.
    ///
    /// Returns `None` by default: every SSE-framed protocol (openai/anthropic/gemini/cohere/responses)
    /// carries its error in-band via `write_response_event`, so the StreamTranslate caller falls back
    /// to the normal event path for them. Only `BedrockWriter` overrides this.
    fn write_response_exception(&self, _err: &IrError) -> Option<(String, String)> {
        None
    }

    /// Frame a mid-stream terminal `IrError` as this protocol's NATIVE in-band SSE STREAM-error event
    /// — the streaming sibling of [`Self::write_error`] (which renders the non-stream HTTP envelope).
    /// The pair is `(event_type, data)`, framed by the caller exactly like a normal event: a non-empty
    /// `event_type` becomes an `event:` line, an empty one a bare `data:` frame. The two shapes are
    /// genuinely different for some protocols (Responses' `response.failed` wraps the error in a
    /// `response` object the SDK's stream decoder locates via `event.response`, NOT the top-level
    /// `{"error":...}` HTTP body), so a native SDK on a stream must receive THIS shape.
    ///
    /// This is the NEUTRAL seam for [`crate::proxy::wire`]'s mid-stream error framer: core frames the
    /// returned pair without naming any concrete stream-event type, so the concrete `IrStreamEvent`
    /// need not exist in core at all. Every SSE-framed writer overrides this to reproduce, byte for
    /// byte, what its `write_response_event` produces for an error event.
    ///
    /// Returns `None` by default so a future protocol without an override falls back to core's
    /// dialect-free terminal frame — the same fallback the caller already applies when a writer
    /// declines to frame an error in-band.
    fn write_error_frame(&self, _err: &IrError) -> Option<(String, serde_json::Value)> {
        None
    }

    /// Write a whole (non-streaming) response to wire JSON.
    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value;

    /// Render a router/forward/auth-layer error as this protocol's NATIVE error envelope, so a
    /// client on the vendor's official SDK gets the typed exception it expects instead of a
    /// plain-text body it cannot decode. `status` is the HTTP
    /// status to be sent (informational; the envelope body may also embed it, e.g. Gemini's
    /// `error.code`); `kind` is a protocol-appropriate error type/category string (e.g.
    /// `"invalid_request_error"`, `"not_found"`); `message` is the human-readable detail.
    ///
    /// Regardless of protocol, the returned JSON MUST be served with
    /// `content-type: application/json` (every vendor's error envelope is JSON — OpenAI, Anthropic,
    /// Gemini, Cohere, Responses, and the Bedrock Converse error shape alike).
    ///
    /// All six registered protocols (OpenAI `{"error":{"message","type","code"}}`, Anthropic
    /// `{"type":"error","error":{"type","message"}}`, Gemini `{"error":{"code","message","status"}}`,
    /// Cohere, Responses, Bedrock `{"__type","message"}`) OVERRIDE this default with their native
    /// envelope. The default returns a generic `{"error":{"message":message,"type":kind}}` and is the
    /// catch-all only for a future 7th protocol that omits an override (a maintainer adding one should
    /// supply a native envelope, or a client on that protocol gets this generic — non-native — shape).
    ///
    /// This method IS on the live request path: it is dispatched via the writer vtable from the
    /// router/auth/forward error sites (`ingress::ingress_error`, `auth`, `proxy::ingress_error`).
    /// Only the default *body* is unreachable in release (every concrete writer overrides it), so no
    /// dead-code suppression is needed here.
    fn write_error(&self, _status: u16, kind: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "error": {
                "message": message,
                "type": kind,
            }
        })
    }

    /// Attach any protocol-specific RESPONSE HEADERS a native endpoint always carries on an error
    /// response, given the already-built error `envelope` and canonical `kind`. Default no-op (most
    /// protocols carry the error entirely in the body). Bedrock attaches `x-amzn-RequestId` +
    /// `x-amzn-errortype`; Anthropic mirrors the body `request_id` into the `request-id` header. The
    /// agnostic error path (`proxy::ingress_error`) calls this through the writer vtable instead of
    /// branching on the protocol name, so the main/degraded/auth/route error paths cannot drift.
    fn attach_error_response_headers(
        &self,
        _headers: &mut axum::http::HeaderMap,
        _kind: &str,
        _envelope: &serde_json::Value,
    ) {
    }

    /// Native-SDK `Accept` header for THIS EGRESS protocol, given the caller's stream intent.
    /// A native SDK always sends one; omitting it is a backend-side proxy fingerprint, especially on
    /// the Bedrock egress where botocore sends `application/vnd.amazon.eventstream` on a
    /// ConverseStream call. The agnostic forward path calls this through the writer vtable instead of
    /// the name-match in `egress_accept`, so the core never branches on `"bedrock"`.
    ///
    /// Default: `text/event-stream` when streaming, `application/json` otherwise (the shape shared
    /// by anthropic/openai/responses/gemini/cohere). `BedrockWriter` overrides: eventstream when
    /// streaming, `application/json` otherwise.
    fn egress_accept(&self, wants_stream: bool) -> &'static str {
        if wants_stream {
            crate::proxy::TEXT_EVENT_STREAM
        } else {
            crate::proxy::APPLICATION_JSON
        }
    }

    /// When a Bedrock-ingress client requested a STREAMING response (`wants_stream`) but the upstream
    /// answered with a BUFFERED (non-SSE) 2xx body, the single translated `IrResponse` must be
    /// re-emitted as native binary eventstream frames rather than `application/json` — a Bedrock SDK's
    /// `ConverseStream` decoder expects binary-framed events and cannot parse a bare JSON body (hard
    /// SDK decode failure and a deterministic proxy tell).
    ///
    /// Returns `Some(bytes)` when this writer needs the buffered-to-stream synthesis path, `None` when
    /// the plain translated JSON body is correct (all non-Bedrock ingress protocols). The returned bytes
    /// are the complete binary eventstream payload; the caller emits them under
    /// `writer.streaming_content_type()` so the Content-Type header matches the framing.
    ///
    /// Default: `None` (every SSE-framed protocol — a plain JSON body is acceptable).
    /// `BedrockWriter` overrides: returns `Some(bedrock_response_to_eventstream(ir, elapsed_ms))`.
    fn wrap_buffered_as_stream(
        &self,
        _ir: &crate::ir::IrResponse,
        _elapsed_ms: Option<u64>,
    ) -> Option<Vec<u8>> {
        None
    }

    /// Inject any protocol-required per-response metrics into a translated buffered response body
    /// (a `serde_json::Value` produced by `write_response`), if timing is available.
    ///
    /// Bedrock's non-stream `Converse` response ALWAYS carries `metrics.latencyMs` (the AWS SDK
    /// surfaces it via `ConverseOutput::metrics().latency_ms()`). The bedrock writer's `write_response`
    /// deliberately omits it (the writer is unaware of wall-clock time); the agnostic forward path
    /// injects it here — matching the live streaming path which injects it into the `metadata` frame.
    /// OMIT rather than fabricate a tell-tale `0` when timing is unavailable.
    ///
    /// Default: no-op (all non-Bedrock protocols carry no timing field in the response body).
    /// `BedrockWriter` overrides: inserts `metrics: { latencyMs: ms }` when both `elapsed_ms` is
    /// `Some` AND `value` is a JSON object (same double-`Some` guard the original inline branches use).
    fn inject_response_metrics(&self, _value: &mut serde_json::Value, _elapsed_ms: Option<u64>) {}

    /// The request-id RESPONSE HEADER (name + value) to ATTACH to a 2xx/relay response on THIS
    /// protocol's INGRESS path, or `None` when no header is attached. This is the SUCCESS-path analog
    /// of `attach_error_response_headers`, dispatched through the writer vtable so the agnostic forward
    /// path (`maybe_attach_response_request_id`) names no protocol module for request-id synthesis.
    ///
    /// Both bedrock and anthropic do `upstream_request_id.map(String::from).or_else(synth)`: the
    /// captured UPSTREAM id is preferred (so a same-protocol passthrough forwards the real native id),
    /// else a shape-correct one is synthesized (the cross-protocol case, where the caller passes `None`).
    /// - `BedrockWriter` → `(HDR_AMZN_REQUEST_ID, upstream-or-synth UUID)` — a real ConverseStream
    ///   always carries `x-amzn-RequestId`.
    /// - `AnthropicWriter` → `(HDR_REQUEST_ID, upstream-or-synth req_…)` — a real Anthropic response
    ///   always carries `request-id` (the SDK reads it into `APIError.request_id`).
    ///
    /// Default: `None` (no other protocol attaches a request-id header on the success path).
    fn ingress_response_request_id(
        &self,
        _upstream_request_id: Option<&str>,
    ) -> Option<(&'static str, String)> {
        None
    }

    /// Serialize the one-token "ping" probe request through THIS dialect's own `write_request`, as a
    /// wire `Value`. The concrete ping IR is built by the owning plugin (busbar-llm's `ir_encode`),
    /// so core's `probe_body` orchestration below names no concrete IR. The model is stamped
    /// afterward by [`Self::rewrite_model_if_needed`], so the ping itself carries none.
    fn probe_request(&self) -> serde_json::Value;

    /// Build a minimal, protocol-correct request body for an active health probe of `model`.
    /// Serializes a one-token "ping" through this protocol's own [`Self::probe_request`], so every
    /// protocol gets a valid probe body for free — no per-protocol probe code, no extra dependency.
    fn probe_body(&self, model: &str) -> Vec<u8> {
        let mut body = self.probe_request();
        let _ = self.rewrite_model_if_needed(&mut body, model);
        crate::json::to_vec(&body).unwrap_or_default()
    }

    /// Build the per-stream framing state for THIS protocol as an INGRESS (client-facing) writer.
    ///
    /// `StreamTranslate` calls this ONCE per stream on its ingress writer and holds the result as a
    /// `Box<dyn StreamFraming>`, then routes every protocol-specific stream-shape decision through it
    /// — so the translator names NO protocol's wire quirk. The framing is keyed to the
    /// INGRESS writer because it is what produces the client-facing bytes: the OpenAI per-chunk
    /// identity replay + include_usage trailing-usage un-fold is OpenAI-INGRESS only; the Bedrock
    /// messageStop/metadata two-frame deferral (and its finish-time flush) is Bedrock-INGRESS only.
    ///
    /// Default: a no-op [`PassthroughFraming`] (every SSE-framed protocol with no per-stream framing
    /// quirk). `OpenAiWriter` and `BedrockWriter` override it with their stateful impls (defined in
    /// their own modules), so deleting `proto/openai_chat.rs` or `proto/bedrock.rs` needs ZERO changes to
    /// the translator here.
    fn new_stream_framing(&self) -> Box<dyn StreamFraming> {
        Box::new(PassthroughFraming)
    }

    /// Build this protocol's array-stream framer (the JSON-array reframer engaged for a streaming
    /// response that must be delivered as a `[{...},{...}]` document instead of SSE), as a
    /// `Box<dyn JsonArrayFramer>`, or `None` when this protocol has no such framing. The agnostic
    /// forward path constructs the framer through this vtable method — gated by `uses_array_stream_shim()`
    /// — so it never names the gemini framer type. Default `None`; `GeminiWriter` overrides → `Some`.
    fn make_array_stream_framer(&self) -> Option<Box<dyn JsonArrayFramer>> {
        None
    }

    /// True when THIS ingress writer's client wants its streamed response reframed as a JSON array
    /// (rather than SSE) for the given request `body`. The forward path consults this — together with
    /// `uses_array_stream_shim()` — instead of reading any protocol-specific body key itself, so the
    /// core names no shim key. Default `false`; `GeminiWriter` overrides to read its router shim key
    /// from the body.
    fn wants_array_stream(&self, _body: &serde_json::Value) -> bool {
        false
    }

    /// The number of response candidates THIS ingress request asks the backend to generate, when the
    /// protocol expresses one and the caller set it above the single-candidate default. OpenAI-family
    /// reads `n`; Gemini reads `candidateCount` / `candidate_count`. Returns `None` when the field is
    /// absent, unparseable, or `<= 1` — i.e. `Some(k)` ONLY for a genuine `k > 1` ask.
    ///
    /// The engine consults this at the CROSS-PROTOCOL request seam. The busbar IR (`IrResponse`)
    /// models exactly ONE assistant turn, so any response forced through it (every cross-protocol hop,
    /// streaming or buffered) can carry only candidate `[0]` — the rest would be silently dropped with
    /// an HTTP 200, the least-observable data loss in a security/audit product. Rather than return
    /// 1-of-N, the engine REJECTS such a request up front (4xx). Same-protocol routes relay the
    /// backend body verbatim and never touch the IR, so this is not consulted for them and an `n > 1`
    /// same-protocol request keeps working unchanged.
    fn requested_candidate_count(&self, _body: &serde_json::Value) -> Option<u64> {
        None
    }

    /// Clone this writer as a trait object.
    fn clone_box(&self) -> Box<dyn ProtocolWriter>;
}

/// A streaming JSON-array reframer: consumes a protocol's SSE response bytes and re-emits them as one
/// streaming JSON array (`[{...},{...}]`), the body shape a non-SSE streaming request expects. The
/// agnostic forward path holds one `Box<dyn JsonArrayFramer>` (built via
/// [`ProtocolWriter::make_array_stream_framer`]) and drives it, so it names no protocol's framer type.
/// The sole implementor is `gemini::GeminiJsonArrayFramer` (Gemini `:streamGenerateContent` without
/// `?alt=sse`). The trait exposes only the SUBSET of that type's API the agnostic core needs (`feed`,
/// `finish_for_translate`, `finish_with_server_error`); the type's raw `finish` and its low-level
/// `finish_with_error(code, status, …)` are absent, since the core never passes a wire status code.
pub trait JsonArrayFramer: Send {
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

/// Per-stream, INGRESS-keyed framing state for the shared [`StreamTranslate`] translator. This is the
/// vtable seam that keeps the agnostic-core translator from naming any protocol's wire shape:
/// every protocol-specific streaming decision the translator used to make inline — the OpenAI per-chunk
/// identity replay + include_usage trailing-usage un-fold, and the Bedrock messageStop/metadata
/// two-frame deferral with its finish-time flush — lives BEHIND this trait, implemented in the owning
/// protocol's module. The translator holds ONE `Box<dyn StreamFraming>` (built via
/// [`ProtocolWriter::new_stream_framing`] from the ingress writer) and consults it; it never branches
/// on a protocol name. The default [`PassthroughFraming`] impl is inert, so a protocol with no
/// per-stream framing quirk needs no override.
///
/// The translator keeps `emit_ir_event` as the emission primitive: the framing methods return WHAT to
/// emit (mutating a chunk in place, or returning the IR events / trailing chunk to frame), and the
/// translator does the actual framing. This preserves the exact byte-level emission order.
pub trait StreamFraming: Send {
    /// EGRESS-CHUNK seam (OpenAI ingress). Called for every reframed SSE `chat.completion.chunk` body
    /// the ingress writer produced, just before it is framed. Does two things, BOTH byte-shape-critical:
    /// (a) replays the latched stream identity (`id`/`created`/`model`) onto `chunk` in place — the
    /// opening chunk latches them, every later chunk (which the writer emits without them) gets them
    /// injected, so the whole stream shares ONE id like a genuine OpenAI stream; and (b) returns
    /// `Some(trailing)` when `chunk` is a usage-bearing finish chunk, having REMOVED the folded `usage`
    /// from `chunk` and re-homed it onto a separate trailing usage-only chunk (the include_usage
    /// un-fold). The translator then frames `chunk` and, if `Some`, the trailing chunk after it.
    ///
    /// Default ([`PassthroughFraming`]): no mutation, returns `None`.
    fn on_egress_chunk(&mut self, _chunk: &mut serde_json::Value) -> Option<serde_json::Value> {
        None
    }

    /// COMBINED-STOP-DELTA seam (Bedrock ingress). Called when the translator sees a combined
    /// `MessageDelta{stop_reason: Some, usage}`. Returns the IR events the translator must emit (via
    /// `emit_ir_event`) IN ORDER to reproduce a native ConverseStream's two-frame stop/metadata split,
    /// while updating internal state so EXACTLY ONE `metadata` frame is ever emitted for the stream. The
    /// returned vec is: always a stop-only delta (→ `messageStop`); plus a usage-only delta (→
    /// `metadata`) IFF real usage rode with the stop (else the metadata is DEFERRED to a trailing
    /// usage-only delta, or to `on_finish`). When this returns `Some`, the translator emits each event
    /// and consumes the original event (the inline path `continue`s).
    ///
    /// Default ([`PassthroughFraming`]): `None` — the translator falls through to its normal path.
    fn on_combined_stop_delta(
        &mut self,
        _stop_reason: crate::ir::IrStopReason,
        _stop_sequence: Option<String>,
        _usage: &crate::ir::IrUsage,
    ) -> Option<Vec<crate::ir::IrStreamEvent>> {
        None
    }

    /// USAGE-ONLY-DELTA seam (Bedrock ingress). Called for a trailing `MessageDelta{stop_reason: None}`
    /// (the OpenAI include_usage usage chunk, or a native usage frame). Returns `true` if the translator
    /// should EMIT this delta as the stream's single `metadata` frame, or `false` to SUPPRESS it (a
    /// `metadata` already rode with the stop). Updates internal state so the one-metadata invariant
    /// holds and resolves any pending deferral.
    ///
    /// Default ([`PassthroughFraming`]): returns `None` — the translator falls through to its normal
    /// path (this delta is not special-cased).
    fn on_usage_only_delta(&mut self) -> Option<bool> {
        None
    }

    /// FINISH seam (Bedrock ingress). Called once at end-of-stream. Returns `Some(event)` when a
    /// `metadata` frame was DEFERRED (a zero-usage stop with no trailing usage delta — the default
    /// OpenAI streaming case) and never resolved, so the translator must flush a single best-effort
    /// zero-usage `metadata` frame to honor the always-one-metadata invariant. Returns `None` when no
    /// flush is owed.
    ///
    /// Default ([`PassthroughFraming`]): `None`.
    fn on_finish(&mut self) -> Option<crate::ir::IrStreamEvent> {
        None
    }

    /// METADATA-METRICS seam (Bedrock ingress). Called in the eventstream-framing branch for each
    /// emitted frame with the frame's event-type, its just-built data object, and the stream's start
    /// instant. A native ConverseStream `metadata` frame carries `metrics.latencyMs`; the Bedrock impl
    /// injects the elapsed wall-clock into that one frame (omitting `metrics` entirely if timing is
    /// unavailable, rather than emitting a tell-tale `0`), mutating `data` in place. Keeps the wire
    /// event-type literal and the latency shape in the Bedrock module, out of the agnostic translator.
    ///
    /// Default ([`PassthroughFraming`]): no-op (no event-type is special).
    fn inject_streaming_metrics(
        &self,
        _event_type: &str,
        _data: &mut serde_json::Value,
        _started_at: Option<std::time::Instant>,
    ) {
    }

    /// STREAM-ABORT seam (eventstream ingress). The protocol-shaped error TYPE NAME this ingress emits
    /// as the terminal frame on an ABORTED stream (reassembly-buffer overflow / malformed prelude).
    /// `Some(name)` means "this ingress frames aborts as an eventstream exception of this type"
    /// (Bedrock → `InternalServerException`); the agnostic translator then emits a well-formed
    /// exception frame WITHOUT naming the wire type itself. `None` (default / every SSE protocol) →
    /// the translator takes its SSE-abort path instead. Keeps the wire exception name in the owning
    /// protocol module, out of the agnostic translator.
    fn abort_exception_type(&self) -> Option<&'static str> {
        None
    }

    /// TERMINAL-USAGE-FOLD seam (the plain SSE ingresses: Anthropic/Gemini/Cohere/Responses). These
    /// protocols carry token usage IN their single terminal `message_delta` frame. When the EGRESS
    /// reports usage in a SEPARATE trailing usage-only chunk that arrives AFTER the finish chunk (the
    /// OpenAI `include_usage` convention), the terminal frame would otherwise ship with zeros and the
    /// real usage would be dropped by the translator's post-stop ordering guard. Returning `true` tells
    /// the translator to DEFER the terminal `MessageDelta`/`MessageStop`, merge any trailing usage into
    /// it, and flush at end-of-stream — so the client's terminal frame reports the real token counts.
    /// (This is delivered uniformly because the response body now feeds `finish()`'s content through the
    /// json-array framer too, not only the SSE path — see `proxy::response_body`.)
    ///
    /// Default (`true`, via [`PassthroughFraming`]): the four SSE ingresses fold. OpenAI overrides to
    /// `false` (it UN-folds — its client expects the separate usage chunk, re-emitted via
    /// `on_egress_chunk`); Bedrock overrides to `false` (it carries usage in a separate `metadata`
    /// frame handled by `on_combined_stop_delta`/`on_usage_only_delta`).
    fn folds_terminal_usage(&self) -> bool {
        true
    }

    /// CLIENT-INTENT seam (OpenAI ingress). Records whether the ORIGINAL client request
    /// carried `stream_options.include_usage == true`. Busbar always injects `include_usage` on the
    /// UPSTREAM request so it can bill streaming calls, which makes the upstream emit a
    /// trailing usage chunk; but a native OpenAI stream only emits that usage-bearing trailing chunk
    /// when the CLIENT opted in. A client that did NOT opt in and receives an unsolicited
    /// `{choices:[], usage}` chunk hits `choices[0]` IndexError. So when this is `false`, the OpenAI
    /// framing STRIPS the folded usage entirely (no trailing chunk) rather than un-folding it;
    /// when `true` it un-folds to the native separate trailing chunk. Billing is unaffected either
    /// way — it reads the IR-side `last_usage` A-tap, not the client-facing chunk.
    ///
    /// Default ([`PassthroughFraming`] and every non-OpenAI ingress): no-op — the flag is meaningless
    /// for protocols without the `include_usage` convention.
    fn set_client_include_usage(&mut self, _include: bool) {}

    /// SAME-PROTOCOL VERBATIM-STRIP seam (OpenAI ingress). On the
    /// same-protocol universal-translate path the translator re-emits each upstream frame BYTE-FOR-BYTE
    /// and NEVER routes it through [`on_egress_chunk`], so the `include_usage` strip that protects an
    /// opted-out client from the unsolicited trailing usage chunk never fires. Busbar forces
    /// `stream_options.include_usage` on the UPSTREAM request (to bill), so an OpenAI upstream emits a
    /// NATIVE trailing usage-only chunk (`{... "choices":[], "usage":{...}}`) even when the CLIENT did
    /// not opt in - which a strict SDK `choices[0]`-IndexErrors on. Returning `true` for that exact
    /// frame tells the same-proto feed loop to DROP it from the client-facing bytes (billing is
    /// unaffected: the A-tap already read the usage from the parsed frame). Every other frame - and the
    /// opted-in case - returns `false` and is re-emitted verbatim.
    ///
    /// Default ([`PassthroughFraming`] and every non-OpenAI ingress): `false` - no frame is suppressed
    /// on the verbatim path (those protocols carry no unsolicited-usage-chunk convention).
    fn suppress_same_proto_frame(&self, _data: &serde_json::Value) -> bool {
        false
    }

    /// SAME-PROTOCOL INTERMEDIATE-USAGE STRIP seam (OpenAI ingress). On the same-protocol verbatim path
    /// busbar re-emits each upstream frame BYTE-FOR-BYTE. Because busbar forces
    /// `stream_options.include_usage` on the UPSTREAM request (to bill), an OpenAI upstream stamps
    /// `"usage":null` on EVERY intermediate `chat.completion.chunk` (and the finish chunk). A native
    /// OpenAI stream for a client that did NOT request `include_usage` OMITS the `usage` key entirely on
    /// those content chunks, so re-emitting `"usage":null` on every chunk is a wire-shape TELL that
    /// distinguishes a busbar-proxied stream from a direct one. Returning `true` for a content/finish
    /// chunk that carries a `usage` field tells the same-proto feed loop to STRIP the top-level `usage`
    /// member from that frame's bytes before re-emitting it (a targeted byte-level edit, NOT a full DOM
    /// re-serialize of the fast path). Billing is unaffected - the A-tap read the frame's usage before
    /// the strip. The trailing usage-ONLY chunk (empty `choices`) is handled by
    /// [`suppress_same_proto_frame`] (dropped whole), not here; the opted-IN client sees every frame
    /// verbatim. Distinct from `suppress_same_proto_frame` (which drops a whole frame) - this one KEEPS
    /// the frame and only removes its `usage` member.
    ///
    /// Default ([`PassthroughFraming`] and every non-OpenAI ingress): `false` - no frame is rewritten
    /// on the verbatim path.
    fn strip_same_proto_usage(&self, _data: &serde_json::Value) -> bool {
        false
    }
}

/// Inert default [`StreamFraming`]: every method takes the trait's no-op default. Used by every
/// protocol whose INGRESS stream carries no per-stream framing quirk (Anthropic/Gemini/Cohere/
/// Responses). Holds no state.
struct PassthroughFraming;

impl StreamFraming for PassthroughFraming {}

/// Bundled Protocol with name + reader + writer.
pub struct Protocol {
    name: &'static str,
    reader: Box<dyn ProtocolReader>,
    writer: Box<dyn ProtocolWriter>,
}

impl Clone for Box<dyn ProtocolReader> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl Clone for Box<dyn ProtocolWriter> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl Clone for Protocol {
    fn clone(&self) -> Self {
        Protocol {
            name: self.name,
            reader: self.reader.clone(),
            writer: self.writer.clone(),
        }
    }
}

impl Protocol {
    pub fn new<R, W>(name: &'static str, reader: R, writer: W) -> Self
    where
        R: ProtocolReader + 'static,
        W: ProtocolWriter + 'static,
    {
        Self {
            name,
            reader: Box::new(reader),
            writer: Box::new(writer),
        }
    }

    /// Returns the protocol name ("anthropic", "openai", etc.).
    pub(crate) fn name(&self) -> &str {
        self.name
    }

    /// The protocol name as the registry's INTERNED `&'static str` (the `name` field is `&'static`).
    /// Lets a caller that must OUTLIVE the borrowed lookup key (e.g. a streaming response body that
    /// stores the ingress protocol for the life of the stream) hold the name without allocating an
    /// owned copy — the value points into the process-lifetime protocol table, not the request.
    pub(crate) fn name_static(&self) -> &'static str {
        self.name
    }

    /// This protocol's DECLARATION — the promoted constant facts (`ProtocolDecl`) core now reads by
    /// FIELD rather than through the writer vtable (G6 step A1). Always `Some` for a registered codec
    /// protocol (every `Protocol` resolves from a declaration); the `Option` mirrors [`decl_for`]'s
    /// signature so a caller holding a `Protocol` reads a fact exactly as a by-name caller does.
    pub(crate) fn decl(&self) -> Option<&'static registry::ProtocolDecl> {
        registry::decl_for(self.name)
    }

    /// Returns the reader for this protocol.
    pub fn reader(&self) -> &dyn ProtocolReader {
        self.reader.as_ref()
    }

    /// Returns the writer for this protocol.
    pub fn writer(&self) -> &dyn ProtocolWriter {
        self.writer.as_ref()
    }

    /// Construct an Anthropic protocol instance — TEST FIXTURE SHIM. The dialect is an extracted
    /// module of the LLM plugin crate (`busbar-llm`); production resolves it through the registry after the
    /// composition root installs its declaration, and core has no production path that could name
    /// it. The pre-extraction fixture surface calls this constructor by name in hundreds of tests,
    /// so it survives for the builds that compile the dialect back in (see the `mod anthropic`
    /// decl) rather than rewriting every fixture to a registry lookup in the extraction commit.
    #[cfg(test)]
    pub(crate) fn anthropic() -> Self {
        Self::new(
            PROTO_ANTHROPIC,
            anthropic::AnthropicReader,
            anthropic::AnthropicWriter,
        )
    }

    /// Construct an OpenAI protocol instance — TEST FIXTURE SHIM, same rationale as
    /// [`Protocol::anthropic`]: the dialect is a module of the LLM plugin crate (`busbar-llm`);
    /// production resolves it through the registry after the composition root installs its
    /// declaration.
    // `test-support`, not bare `cfg(test)`: a SIBLING dialect crate's own test build reaches this
    // fixture shim (busbar-llm's gemini logprobs carry tests translate gemini ↔ openai), and that
    // build sees core through the `test-support` feature, not through core's `cfg(test)`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn openai() -> Self {
        Self::new(PROTO_OPENAI, OpenAiReader, OpenAiWriter)
    }

    /// Construct a Gemini protocol instance — TEST FIXTURE SHIM, same rationale as
    /// [`Protocol::anthropic`]: the dialect is a module of the LLM plugin crate (`busbar-llm`);
    /// production resolves it through the registry after the composition root installs its
    /// declaration.
    #[cfg(any(test, feature = "test-support"))]
    pub fn gemini() -> Self {
        Self::new(PROTO_GEMINI, GeminiReader, GeminiWriter)
    }

    /// Construct an OpenAI Responses protocol instance — TEST FIXTURE SHIM, same rationale as
    /// [`Protocol::anthropic`]: the dialect is a module of the LLM plugin crate (`busbar-llm`);
    /// production resolves it through the registry after the composition root installs its
    /// declaration.
    #[cfg(any(test, feature = "test-support"))]
    pub fn responses() -> Self {
        Self::new(PROTO_RESPONSES, ResponsesReader, ResponsesWriter)
    }

    /// Construct a Bedrock protocol instance — TEST FIXTURE SHIM, same rationale as
    /// [`Protocol::anthropic`]: the dialect is a module of the LLM plugin crate (`busbar-llm`).
    #[cfg(any(test, feature = "test-support"))]
    pub fn bedrock() -> Self {
        Self::new(PROTO_BEDROCK, BedrockReader, BedrockWriter)
    }

    /// Construct a Cohere (v2 chat) protocol instance — TEST FIXTURE SHIM, same rationale as
    /// [`Protocol::anthropic`]: the dialect is a module of the LLM plugin crate (`busbar-llm`).
    #[cfg(any(test, feature = "test-support"))]
    pub fn cohere() -> Self {
        Self::new(PROTO_COHERE, CohereReader, CohereWriter)
    }
}

/// BUILD this protocol's wire CODEC, by name — a `Protocol` INSTANCE, for the paths that translate.
///
/// The name resolution is the registry's ([`registry::decl_for`], which allocates nothing); what
/// still allocates here, and must, is the codec itself: a fresh instance is REQUIRED per resolution
/// because `GeminiWriter`, `CohereWriter` and `ResponsesWriter` carry per-STREAM mutable state
/// (`Mutex<Vec<…>>`, `AtomicU64`) and must not be shared across concurrent requests. Callers that
/// hold a resolution for the life of a stream resolve once and keep it (see `FirstByteBody::new`).
///
/// **A caller that wants a by-name CONSTANT must not come here.** Every such fact — the streaming
/// content type, the shim key, the tool-id prefix, the ingress auth scheme — is a field on
/// [`ProtocolDecl`], read through `decl_for` with no allocation at all. That distinction is the
/// whole of what the registry bought: this function used to be the only way to ask, and asking it a
/// `&'static` question cost two `Box`es.
///
/// `None` for a name no protocol declares, and for a protocol that declares no codec (MCP).
pub(crate) fn protocol_for(name: &str) -> Option<Protocol> {
    registry::decl_for(name)
        .and_then(|d| d.codec)
        .map(|new| new())
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

/// The INGRESS protocol's NATIVE tool-call id prefix, used by [`ToolIdRemap`] to reshape a foreign
/// egress tool id into the ingress client's expected form. `None` means the protocol either carries
/// no tool id on the wire (Gemini correlates `functionCall`s by name) or uses a free-form id with NO
/// canonical prefix (Cohere) — for both, the foreign egress id passes through verbatim, which is the
/// correct no-op. DECLARED by each protocol; this was the last `match` on a protocol name left in
/// `proto/mod.rs` after `protocol_for` became a lookup.
fn native_tool_id_prefix(protocol_name: &str) -> Option<&'static str> {
    registry::decl_for(protocol_name).and_then(|d| d.native_tool_id_prefix)
}

/// Marker segment embedded in a busbar-minted tool id so the reverse (request) translation can tell a
/// busbar-reshaped id from one the client itself authored, and recover the original egress id without
/// any cross-request state. Chosen to be alphanumeric (valid inside every native id shape) and
/// vanishingly unlikely to prefix a genuine client tool id. The original egress id follows as lower
/// hex, making the whole transform a pure, deterministic bijection: the SAME egress id always maps to
/// the SAME native id, so a `tool_use` and the `tool_result` that later references it stay consistent
/// WITHIN a request AND across rounds (the client echoes the native id back; the request path decodes
/// it to the original before the egress backend sees it).
const TOOL_ID_REMAP_MARKER: &str = "bb1";

/// Per-request / per-stream tool-id remap applied ONLY at the cross-protocol seam (ingress != egress).
/// Same-protocol passthrough never constructs one, so native ids pass through verbatim there.
///
/// Forward (egress → ingress, on a response): each foreign egress tool id is reshaped to the ingress
/// protocol's native form — `<prefix><MARKER><hex(egress_id)>` — so e.g. an OpenAI backend's `call_…`
/// never reaches an Anthropic client as a foreign `call_…` (an immediate proxy tell), it arrives as a
/// native `toolu_…`. The in-request map memoizes so a repeated egress id maps stably (and the encoding
/// is deterministic regardless, so the map is an optimization, not a correctness crutch).
///
/// Reverse (ingress → egress, on the next request): the client echoes the native id back inside a
/// `tool_result`; [`decode_native_tool_id`] strips the marker and hex-decodes it to the ORIGINAL
/// egress id so the backend sees the id it actually issued. An id WITHOUT the marker is client-authored
/// (or same-protocol) and passes through untouched.
#[derive(Default)]
pub(crate) struct ToolIdRemap {
    map: std::collections::HashMap<String, String>,
}

impl ToolIdRemap {
    /// Reshape one egress tool id into the ingress protocol's native form. Deterministic + memoized.
    /// A `None` ingress prefix (Gemini, Cohere) returns the id unchanged — Gemini drops tool ids
    /// outright, and Cohere ids are free-form (no canonical prefix to make the reshape reversible
    /// without colliding with client-authored ids), so both pass through verbatim.
    fn native_for(&mut self, ingress_protocol: &str, egress_id: &str) -> String {
        let Some(prefix) = native_tool_id_prefix(ingress_protocol) else {
            return egress_id.to_string();
        };
        if let Some(existing) = self.map.get(egress_id) {
            return existing.clone();
        }
        let native = format!("{prefix}{TOOL_ID_REMAP_MARKER}{}", hex::encode(egress_id));
        self.map.insert(egress_id.to_string(), native.clone());
        native
    }

    /// Rewrite every tool id in a non-stream `IrResponse` to the ingress-native form (in place).
    pub(crate) fn remap_response(
        &mut self,
        ingress_protocol: &str,
        ir: &mut crate::ir::IrResponse,
    ) {
        for block in &mut ir.content {
            self.remap_block(ingress_protocol, block);
        }
    }

    /// Rewrite every tool id in a streaming `IrStreamEvent` to the ingress-native form (in place).
    fn remap_event(&mut self, ingress_protocol: &str, event: &mut crate::ir::IrStreamEvent) {
        if let crate::ir::IrStreamEvent::BlockStart {
            block: crate::ir::IrBlockMeta::ToolUse { id, .. },
            ..
        } = event
        {
            *id = self.native_for(ingress_protocol, id);
        }
    }

    fn remap_block(&mut self, ingress_protocol: &str, block: &mut crate::ir::IrBlock) {
        match block {
            crate::ir::IrBlock::ToolUse { id, .. } => {
                *id = self.native_for(ingress_protocol, id);
            }
            crate::ir::IrBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => {
                *tool_use_id = self.native_for(ingress_protocol, tool_use_id);
                for inner in content {
                    self.remap_block(ingress_protocol, inner);
                }
            }
            crate::ir::IrBlock::Text { .. }
            | crate::ir::IrBlock::Thinking { .. }
            | crate::ir::IrBlock::Image { .. }
            | crate::ir::IrBlock::Media { .. }
            | crate::ir::IrBlock::Json(_) => {}
        }
    }
}

/// Recover the ORIGINAL egress tool id from a busbar-reshaped native id (the EXACT reverse of
/// [`ToolIdRemap::native_for`]). Returns `Some(original)` when `id` carries the busbar marker after
/// the INGRESS protocol's OWN native prefix AND the hex tail decodes to valid UTF-8; otherwise `None`
/// (a client-authored id — pass it through verbatim). Pure and stateless, so the reverse needs no
/// shared map across rounds.
///
/// The decode is gated on the SAME `native_tool_id_prefix(ingress_protocol)` the encode used — NOT a
/// best-effort scan over every known prefix. Trying foreign prefixes would mis-detect a genuine
/// CLIENT-authored id of the colliding shape (`<any-known-prefix>bb1<even-len-hex>`) as
/// busbar-reshaped and silently hex-decode it, corrupting the tool_use/tool_result correlation for
/// that turn. Restricting to the ingress's own prefix makes this the precise inverse of the encode.
/// A prefix-less ingress (Cohere, Gemini) returns `None` here, so its ids are never decoded — the
/// matching no-op for a protocol whose ids are never reshaped on the response.
fn decode_native_tool_id(ingress_protocol: &str, id: &str) -> Option<String> {
    // The ingress protocol's own native prefix — exactly what `native_for` prepended on encode.
    // Gemini (and any protocol without a prefix) never has ids reshaped, so nothing to decode.
    let prefix = native_tool_id_prefix(ingress_protocol)?;
    let rest = id.strip_prefix(prefix)?;
    let hexpart = rest.strip_prefix(TOOL_ID_REMAP_MARKER)?;
    // A marker-only id (empty hex tail) is NOT a busbar id — `native_for` always hex-encodes the
    // egress id, so an empty tail can only come from a client-authored `<prefix>bb1`. Decoding it
    // would yield an empty string and break the exact-inverse round-trip, so pass it through verbatim.
    if hexpart.is_empty() {
        return None;
    }
    // A valid busbar id has an even-length lowercase-hex tail; reject anything else so a genuine
    // client id that merely happens to start with `<prefix>bb1` is not mangled.
    let bytes = hex::decode(hexpart).ok()?;
    String::from_utf8(bytes).ok()
}

/// Walk a request-body IR (messages → blocks, recursing into `ToolResult.content`) and decode any
/// busbar-reshaped tool id back to the original egress id, so a `tool_result` the client echoes after a
/// cross-protocol response references the id the egress backend actually issued. A no-op for ids that
/// carry no busbar marker (client-authored / same-protocol). Applied at the request seam (ingress !=
/// egress) AFTER `read_request`, BEFORE the egress `write_request`.
pub(crate) fn decode_request_tool_ids(
    ingress_protocol: &str,
    messages: &mut [crate::ir::IrMessage],
) {
    fn walk(ingress_protocol: &str, block: &mut crate::ir::IrBlock) {
        match block {
            crate::ir::IrBlock::ToolUse { id, .. } => {
                if let Some(orig) = decode_native_tool_id(ingress_protocol, id) {
                    *id = orig;
                }
            }
            crate::ir::IrBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => {
                if let Some(orig) = decode_native_tool_id(ingress_protocol, tool_use_id) {
                    *tool_use_id = orig;
                }
                for inner in content {
                    walk(ingress_protocol, inner);
                }
            }
            crate::ir::IrBlock::Text { .. }
            | crate::ir::IrBlock::Thinking { .. }
            | crate::ir::IrBlock::Image { .. }
            | crate::ir::IrBlock::Media { .. }
            | crate::ir::IrBlock::Json(_) => {}
        }
    }
    for msg in messages {
        for block in &mut msg.content {
            walk(ingress_protocol, block);
        }
    }
}

pub(crate) mod stream;
pub(crate) use stream::{new_stream_translator, StreamTranslator};
// The production forward path now constructs translators through `new_stream_translator` and holds
// them behind `dyn StreamTranslator`, so the concrete `StreamTranslate` is named only by the proto /
// proxy test suites (the streaming witnesses drive it directly). Re-export it for those.
#[cfg(test)]
pub(crate) use stream::StreamTranslate;

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
pub(crate) fn strip_top_level_usage_member(json: &str) -> Option<String> {
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
fn write_sse_frame(out: &mut Vec<u8>, event_type: &str, data: &serde_json::Value) {
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
use bedrock::{BedrockReader, BedrockWriter};
#[cfg(any(test, feature = "test-support"))]
use cohere::{CohereReader, CohereWriter};
// The extracted Gemini dialect's codec structs, in scope for the same test surface that predates
// the extraction. Present only in the builds that compile the dialect back in.
#[cfg(any(test, feature = "test-support"))]
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
use openai_chat::{OpenAiReader, OpenAiWriter};
// The extracted OpenAI Responses codec structs, in scope for the same test surface that predates
// the extraction. Present only in the builds that compile the dialect back in.
#[cfg(any(test, feature = "test-support"))]
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
        admin_routes: None,
        openapi: None,
        // NO DURABLE STATE, NO BACKGROUND WORK. The LLM plane's state is the many `App` fields the
        // data plane reads directly (lanes, pools, cost, …), restored by nothing here; its reliability
        // state is RAM-only and re-learned from live traffic. So it hydrates nothing and starts no job.
        hydrate: None,
        start: None,
        // NOTHING TO CARRY ACROSS A SWAP. The LLM plane holds no engine-owned object that outlives an
        // apply through this seam — its reliability/breaker state rides the `App` fields the data
        // plane reads directly, not reconciled here.
        on_swap: None,
    };

/// String-keyed registry mapping a provider's protocol name to a shared `Protocol` INSTANCE, built
/// once at boot. Distinct from the declaration registry (`proto::registry`): this holds constructed
/// codecs for the config/lane-build path, which wants one instance per protocol rather than a fresh
/// one per request. It no longer knows any protocol's name — it builds whatever declared a codec.
#[derive(Default)]
pub(crate) struct ProtocolRegistry {
    map: std::collections::HashMap<String, Arc<Protocol>>,
}

impl ProtocolRegistry {
    /// Create a new registry holding every protocol that DECLARED a codec.
    pub(crate) fn with_builtins() -> Self {
        Self {
            map: registry::registry()
                .decls()
                .iter()
                .filter_map(|d| Some((d.name.to_string(), Arc::new((d.codec?)()))))
                .collect(),
        }
    }

    /// Get a protocol by name.
    pub(crate) fn get(&self, name: &str) -> Option<Arc<Protocol>> {
        self.map.get(name).cloned()
    }
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

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **G6 A4b relocation.** The concrete wire-codec surface that names LLM IR types — `ProtocolReader`
//! / `ProtocolWriter` / `StreamFraming` / `PassthroughFraming`, the `Protocol` bundle + `protocol_for`,
//! the neutral-seam forwarder `DialectRef`, and the cross-protocol tool-id remap — moved out of
//! `busbar-core/src/proto/mod.rs` so core's PRODUCTION build names zero concrete LLM IR. Core keeps
//! the neutral seams (`DialectCodec`, `ArrayStreamFramer`, `SigningContext`, the registry-aggregate
//! fns) and re-includes THIS file under `crate::proto::codec` via `#[path]` for its test/`test-support`
//! build so the pre-extraction fixture surface (`Protocol::anthropic()`, `protocol_for(p).reader()`,
//! …) keeps resolving. Same dual-compile mechanism as the dialects; `busbar_core::` addresses core
//! (the `extern crate self as busbar_core` alias resolves it), `crate::ir::` is the concrete IR (this
//! crate's own; core nets it at its root). Byte-identical to the pre-move definitions — path prefixes
//! only.

use axum::http::StatusCode;
use busbar_core::proto::registry;
use busbar_core::proto::{
    ArrayStreamFramer, DialectCodec, IrError, PROTO_ANTHROPIC, PROTO_BEDROCK, PROTO_COHERE,
    PROTO_GEMINI, PROTO_OPENAI, PROTO_RESPONSES,
};

use crate::ir::IrStreamEvent;
#[cfg(any(test, feature = "test-support"))]
use busbar_core::breaker::CanonicalSignal;

// The dialect reader/writer structs the `Protocol::<dialect>()` test-fixture shims below construct.
// Reached via `super::` so the path resolves in BOTH compile shapes (busbar-llm root standalone,
// `core::proto` when netted). These `use`s carried over from `proto/mod.rs` with the fixtures.
#[cfg(any(test, feature = "test-support"))]
use super::bedrock::{BedrockReader, BedrockWriter};
#[cfg(any(test, feature = "test-support"))]
use super::cohere::{CohereReader, CohereWriter};
#[cfg(any(test, feature = "test-support"))]
use super::gemini::{GeminiReader, GeminiWriter};
#[cfg(any(test, feature = "test-support"))]
use super::openai_chat::{OpenAiReader, OpenAiWriter};
#[cfg(any(test, feature = "test-support"))]
use super::openai_responses::{ResponsesReader, ResponsesWriter};

/// ProtocolReader extracts signals from wire responses (Stage 1a + 1b).
/// Methods are provider-specific normalizers that feed the breaker's Stage 2 classifier.
pub trait ProtocolReader: Send + Sync {
    /// Extract raw error info from HTTP response without classifying.
    fn extract_error(
        &self,
        status: StatusCode,
        body: &[u8],
    ) -> busbar_core::breaker::RawUpstreamError;

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
        busbar_core::breaker::normalize_raw_error(
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
    /// [`busbar_core::billing::TokenUsage`]. Returns `None` for a dialect/tail without a recognizable usage
    /// object (the caller treats that as "bill zero, counted+warned"). Defaulted to `None` so a
    /// non-LLM dialect need not implement it.
    fn recover_truncated_usage(&self, _tail: &[u8]) -> Option<busbar_core::billing::TokenUsage> {
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
    // resolved by `busbar_core::egress_auth` and called via `lane.credential.headers_for`. Per-scheme logic
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

    /// Write ONE IR stream event to wire as an ORDERED sequence of frames, allowing a dialect to
    /// emit MORE than one wire frame per IR event.
    ///
    /// The default preserves the historical one-frame-per-event behavior every writer had before this
    /// method existed: it wraps [`Self::write_response_event`] into a 0-or-1-element `Vec`. Only a
    /// dialect whose native wire brackets a single IR event with intermediate sub-frames overrides it.
    ///
    /// `ResponsesWriter` is the sole override: a native `/v1/responses` text stream frames one IR
    /// `BlockStart`/`BlockStop` as several ordered events — `output_item.added` is followed by
    /// `content_part.added` (which a strict Responses SDK REQUIRES to establish the active content
    /// part before the first `output_text.delta`), and the closing `output_text.done` /
    /// `content_part.done` precede `output_item.done`. A single `(event_type, data)` cannot carry
    /// that bracket, so the seam drives streaming through this method.
    fn write_response_events(&self, ev: &IrStreamEvent) -> Vec<(String, serde_json::Value)> {
        self.write_response_event(ev).into_iter().collect()
    }

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
    /// This is the NEUTRAL seam for [`busbar_core::proxy::wire`]'s mid-stream error framer: core frames the
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
        busbar_core::json::to_vec(&body).unwrap_or_default()
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
    /// `Box<dyn ArrayStreamFramer>`, or `None` when this protocol has no such framing. The agnostic
    /// forward path constructs the framer through this vtable method — gated by `uses_array_stream_shim()`
    /// — so it never names the gemini framer type. Default `None`; `GeminiWriter` overrides → `Some`.
    fn make_array_stream_framer(&self) -> Option<Box<dyn ArrayStreamFramer>> {
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
pub struct PassthroughFraming;

impl StreamFraming for PassthroughFraming {}

/// Bundled Protocol with name + reader + writer.
pub struct Protocol {
    name: &'static str,
    // `pub(crate)` so the fidelity/round-trip test suites reach the reader/writer by FIELD as they did
    // when `Protocol` lived in `proto/mod.rs` (an ancestor of `proto::tests`); the `.reader()`/`.writer()`
    // accessors remain the public surface. In both compile shapes `pub(crate)` scopes to the crate the
    // test lives in (busbar-core when netted, busbar-llm standalone).
    pub(crate) reader: Box<dyn ProtocolReader>,
    pub(crate) writer: Box<dyn ProtocolWriter>,
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
    #[allow(dead_code)] // used by the netted-core test surface; unused in some plugin build shapes
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
            super::anthropic::AnthropicReader,
            super::anthropic::AnthropicWriter,
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
pub fn protocol_for(name: &str) -> Option<Protocol> {
    // Post-A4b the `ProtocolDecl.codec` field is the NEUTRAL `DialectCodec` factory (core names no
    // `Protocol`), so the name→codec map lives here in the plugin that owns the six dialects. A fresh
    // instance per resolution, exactly as the registry field doc required (the writers carry per-stream
    // state). MCP declares no codec and is absent here → `None`, as before. Reached both standalone
    // (`crate::<dialect>`) and netted-into-core (`core::proto::<dialect>`) via the relative `super::`.
    match name {
        PROTO_ANTHROPIC => Some(super::anthropic::protocol()),
        PROTO_BEDROCK => Some(super::bedrock::protocol()),
        PROTO_COHERE => Some(super::cohere::protocol()),
        PROTO_GEMINI => Some(super::gemini::protocol()),
        PROTO_OPENAI => Some(super::openai_chat::protocol()),
        PROTO_RESPONSES => Some(super::openai_responses::protocol()),
        _ => None,
    }
}

/// The sole [`DialectCodec`] implementor today: a name-keyed forwarder to this protocol's in-core
/// `Protocol` writer/reader (a fresh instance per call, exactly as every driver call site did before
/// — these neutral methods carry no per-stream state). At A4b it relocates to busbar-llm alongside
/// `ProtocolReader`/`ProtocolWriter`, so the driver's `decl_for(name).dialect().X()` calls are stable
/// across the move. Constructed only via [`ProtocolDecl::dialect`], so `protocol_for(self.0)` is
/// always `Some`.
struct DialectRef(&'static str);

/// Build the neutral [`DialectCodec`] facade for a named dialect — the constructor each dialect's
/// `ProtocolDecl::codec` field now points at (post-A4b `codec` yields the neutral seam, not a concrete
/// `Protocol`). Core calls it through `decl_for(name).dialect()` and names nothing concrete.
pub fn dialect_ref(name: &'static str) -> Box<dyn DialectCodec> {
    Box::new(DialectRef(name))
}

impl DialectCodec for DialectRef {
    fn probe_body(&self, model: &str) -> Vec<u8> {
        protocol_for(self.0)
            .map(|p| p.writer().probe_body(model))
            .unwrap_or_default()
    }
    fn apply_rewrite_to_ingress_body(
        &self,
        obj: &mut serde_json::Map<String, serde_json::Value>,
        messages: &[serde_json::Value],
        tools: &[serde_json::Value],
    ) -> bool {
        protocol_for(self.0)
            .map(|p| {
                p.writer()
                    .apply_rewrite_to_ingress_body(obj, messages, tools)
            })
            .unwrap_or(false)
    }
    fn recover_truncated_usage(&self, tail: &[u8]) -> Option<busbar_core::billing::TokenUsage> {
        protocol_for(self.0).and_then(|p| p.reader().recover_truncated_usage(tail))
    }
    fn ingress_response_request_id(
        &self,
        upstream_request_id: Option<&str>,
    ) -> Option<(&'static str, String)> {
        protocol_for(self.0)
            .and_then(|p| p.writer().ingress_response_request_id(upstream_request_id))
    }
    fn write_error(&self, status: u16, kind: &str, message: &str) -> serde_json::Value {
        protocol_for(self.0)
            .map(|p| p.writer().write_error(status, kind, message))
            .unwrap_or_default()
    }
    fn requested_candidate_count(&self, body: &serde_json::Value) -> Option<u64> {
        protocol_for(self.0).and_then(|p| p.writer().requested_candidate_count(body))
    }
    fn write_response_exception(&self, err: &IrError) -> Option<(String, String)> {
        protocol_for(self.0).and_then(|p| p.writer().write_response_exception(err))
    }
    fn write_error_frame(&self, err: &IrError) -> Option<(String, serde_json::Value)> {
        protocol_for(self.0).and_then(|p| p.writer().write_error_frame(err))
    }
    fn wants_array_stream(&self, body: &serde_json::Value) -> bool {
        protocol_for(self.0)
            .map(|p| p.writer().wants_array_stream(body))
            .unwrap_or(false)
    }
    fn inject_response_metrics(&self, value: &mut serde_json::Value, elapsed_ms: Option<u64>) {
        if let Some(p) = protocol_for(self.0) {
            p.writer().inject_response_metrics(value, elapsed_ms);
        }
    }
    fn attach_error_response_headers(
        &self,
        headers: &mut axum::http::HeaderMap,
        kind: &str,
        envelope: &serde_json::Value,
    ) {
        if let Some(p) = protocol_for(self.0) {
            p.writer()
                .attach_error_response_headers(headers, kind, envelope);
        }
    }
    fn extract_error(&self, status: u16, body: &[u8]) -> busbar_core::breaker::RawUpstreamError {
        match protocol_for(self.0) {
            Some(p) => p.reader().extract_error(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                body,
            ),
            None => busbar_core::breaker::RawUpstreamError::from_status(status),
        }
    }
    fn make_array_stream_framer(&self) -> Option<Box<dyn ArrayStreamFramer>> {
        protocol_for(self.0).and_then(|p| p.writer().make_array_stream_framer())
    }
    fn upstream_path_for_stream(&self, model: &str, stream: bool) -> String {
        protocol_for(self.0)
            .map(|p| p.writer().upstream_path_for_stream(model, stream))
            .unwrap_or_default()
    }
    fn rewrite_model_if_needed(&self, body: &mut serde_json::Value, model: &str) -> bool {
        protocol_for(self.0)
            .map(|p| p.writer().rewrite_model_if_needed(body, model))
            .unwrap_or(false)
    }
    fn reshape_for_path_base(&self, body: &mut serde_json::Value) -> bool {
        protocol_for(self.0)
            .map(|p| p.writer().reshape_for_path_base(body))
            .unwrap_or(false)
    }
}

/// The INGRESS protocol's NATIVE tool-call id prefix, used by [`ToolIdRemap`] to reshape a foreign
/// egress tool id into the ingress client's expected form. `None` means the protocol either carries
/// no tool id on the wire (Gemini correlates `functionCall`s by name) or uses a free-form id with NO
/// canonical prefix (Cohere) — for both, the foreign egress id passes through verbatim, which is the
/// correct no-op. DECLARED by each protocol; this was the last `match` on a protocol name left in
/// `proto/mod.rs` after `protocol_for` became a lookup.
pub(crate) fn native_tool_id_prefix(protocol_name: &str) -> Option<&'static str> {
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
pub(crate) const TOOL_ID_REMAP_MARKER: &str = "bb1";

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
pub struct ToolIdRemap {
    map: std::collections::HashMap<String, String>,
}

impl ToolIdRemap {
    /// Reshape one egress tool id into the ingress protocol's native form. Deterministic + memoized.
    /// A `None` ingress prefix (Gemini, Cohere) returns the id unchanged — Gemini drops tool ids
    /// outright, and Cohere ids are free-form (no canonical prefix to make the reshape reversible
    /// without colliding with client-authored ids), so both pass through verbatim.
    pub(crate) fn native_for(&mut self, ingress_protocol: &str, egress_id: &str) -> String {
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
    pub(crate) fn remap_event(
        &mut self,
        ingress_protocol: &str,
        event: &mut crate::ir::IrStreamEvent,
    ) {
        if let crate::ir::IrStreamEvent::BlockStart {
            block: crate::ir::IrBlockMeta::ToolUse { id, .. },
            ..
        } = event
        {
            *id = self.native_for(ingress_protocol, id);
        }
    }

    pub(crate) fn remap_block(&mut self, ingress_protocol: &str, block: &mut crate::ir::IrBlock) {
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
pub(crate) fn decode_native_tool_id(ingress_protocol: &str, id: &str) -> Option<String> {
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

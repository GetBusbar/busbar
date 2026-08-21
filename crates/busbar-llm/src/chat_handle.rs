// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The CHAT `IrHandle` — the request/response handle `ChatOperation` yields once `IrReq`/`IrResp`
//! dissolved (G6 A4b). Wraps the concrete `crate::ir::{IrRequest,IrResponse}` (relocated here) and
//! carries chat's cross-protocol prep + write, keyed by the peer PROTOCOL STRING: the handle writes
//! ITSELF onto the target dialect via `super::proto_codec::protocol_for(proto).writer()` — no
//! downcast. The `prepare_for_egress`/`prepare_for_ingress` bodies are lifted VERBATIM from the
//! former `IrReq::Chat`/`IrResp::Chat` arms (only `crate::` -> `busbar_core::` re-pathing); the
//! warn strings and their order are unchanged.

use crate::ir::{IrRequest, IrResponse};
use busbar_core::billing::{Billing, TokenUsage};
use busbar_core::handlers::{
    CodecError, EgressWire, IngressReject, OperationHandler, TranslatedResponse,
};
use busbar_core::ir::egress_prep::EgressPrep;
use busbar_core::ir::facts::IrFacts;
use busbar_core::ir::handle::sealed::Sealed;
use busbar_core::ir::handle::IrHandle;
use busbar_core::operation::Operation;
use bytes::Bytes;
use serde_json::Value;

/// Google's documented dummy `thoughtSignature` sentinel — relocated with chat from `ir::variant`.
pub const GEMINI_SKIP_THOUGHT_SIGNATURE: &str = "skip_thought_signature_validator";

/// Chat cross-protocol EGRESS preparation (verbatim from the former `IrReq::Chat` arm).
pub(crate) fn chat_prepare_for_egress(ir: &mut IrRequest, prep: &EgressPrep) {
    if ir.max_tokens.is_none() && prep.egress_requires_max_tokens {
        ir.max_tokens = Some(
            prep.lane_default_max_tokens
                .unwrap_or(prep.global_default_max_tokens),
        );
    }
    super::proto_codec::decode_request_tool_ids(prep.ingress_protocol, &mut ir.messages);
    // n>1 clamp on the cross-protocol seam. `n` asks the backend for N candidate
    // completions, but the neutral `IrResponse` models exactly ONE candidate (`role` +
    // one `content` vec) — there is no place to carry choices 1..N. Forwarding `n>1` to a
    // cross-protocol backend made it generate (and BILL for) N candidates while the
    // translation kept only choice 0 and silently discarded the rest: wasted spend plus a
    // response that does not match the request. IR cannot round-trip multiple choices, so
    // the honest behavior is to clamp `n` to 1 before the egress writer emits it, so the
    // backend generates exactly the one candidate the translated response can carry. A
    // SAME-protocol passthrough never reaches here (the body is forwarded verbatim), so
    // `n>1` still works end-to-end where the response is not funneled through the IR.
    if ir.n.is_some_and(|n| n > 1) {
        ::tracing::debug!(diag = %busbar_core::diagnostics::IR_CLAMP_N_TO_1.banner(),
            ingress = %prep.ingress_protocol,
            "clamping n>1 to 1 on the cross-protocol seam: the neutral response IR carries \
             a single candidate, so extra choices would be generated, billed, and then \
             dropped; the backend is asked for exactly one candidate"
        );
        ir.n = Some(1);
    }
    // The reasoning gate. A lane that did not claim the capability never receives a
    // thinking param (a non-reasoning model would 400 on it); the request still
    // proceeds, thinking at the backend's default level.
    if ir.reasoning.is_some() {
        if prep.reasoning_allowed {
            ir.reasoning_budgets = Some(prep.reasoning_budgets);
        } else {
            ::tracing::debug!(diag = %busbar_core::diagnostics::IR_DROP_REASONING.banner(),
                ingress = %prep.ingress_protocol,
                "dropping cross-protocol reasoning/thinking ask: the target lane does \
                 not declare the capability; set `reasoning: true` on the model (or \
                 pool member) if this backend accepts thinking params"
            );
            ir.reasoning = None;
        }
    }
    // The prompt-cache gate — the cache twin of the reasoning gate above. Fires only
    // when the EGRESS writer's cache marker is model-gated (Bedrock `cachePoint`) and
    // the lane did not assert `prompt_caching`: the breakpoints are cleared so the
    // writer emits no marker a model like Amazon Nova would 400 on. The request still
    // proceeds, uncached — fail-safe over fail-hard.
    if !prep.prompt_caching_allowed {
        let mut cleared = false;
        let mut clear_blocks = |blocks: &mut [crate::ir::IrBlock]| {
            for b in blocks {
                let cc = match b {
                    crate::ir::IrBlock::Text { cache_control, .. }
                    | crate::ir::IrBlock::Thinking { cache_control, .. }
                    | crate::ir::IrBlock::ToolUse { cache_control, .. }
                    | crate::ir::IrBlock::ToolResult { cache_control, .. }
                    | crate::ir::IrBlock::Image { cache_control, .. }
                    | crate::ir::IrBlock::Media { cache_control, .. } => cache_control,
                    // A raw JSON tool-result block carries no cache breakpoint.
                    crate::ir::IrBlock::Json(_) => continue,
                };
                cleared |= cc.take().is_some();
            }
        };
        clear_blocks(&mut ir.system);
        for m in &mut ir.messages {
            clear_blocks(&mut m.content);
        }
        for t in &mut ir.tools {
            cleared |= t.cache_control.take().is_some();
        }
        if cleared {
            ::tracing::debug!(diag = %busbar_core::diagnostics::IR_DROP_PROMPT_CACHE.banner(),
                ingress = %prep.ingress_protocol,
                "dropping cross-protocol prompt-cache breakpoints: the target lane's \
                 dialect gates its cache marker per model and the lane does not \
                 declare the capability; set `prompt_caching: true` on the model if \
                 this backend accepts cache markers (e.g. Claude on Bedrock)"
            );
        }
    }
    // Anthropic cache_control CAP: "A maximum of 4 blocks with
    // cache_control may be provided". Reachable ONLY cross-protocol — same-protocol
    // Anthropic is a verbatim byte passthrough that never reaches a writer, so this
    // can never clamp a request that is legal for its own backend. Walk in Anthropic's
    // own prefix order (system -> every message's content -> every tool), `.take()`ing
    // every breakpoint past the cap so the writer emits at most `cap` of them, and warn
    // once with the count actually dropped.
    if let Some(cap) = prep.cache_control_cap {
        let mut seen = 0usize;
        let mut dropped = 0usize;
        let mut walk_take = |blocks: &mut [crate::ir::IrBlock]| {
            for b in blocks {
                let cc = match b {
                    crate::ir::IrBlock::Text { cache_control, .. }
                    | crate::ir::IrBlock::Thinking { cache_control, .. }
                    | crate::ir::IrBlock::ToolUse { cache_control, .. }
                    | crate::ir::IrBlock::ToolResult { cache_control, .. }
                    | crate::ir::IrBlock::Image { cache_control, .. }
                    | crate::ir::IrBlock::Media { cache_control, .. } => cache_control,
                    crate::ir::IrBlock::Json(_) => continue,
                };
                if cc.is_some() {
                    if seen < cap {
                        seen += 1;
                    } else {
                        *cc = None;
                        dropped += 1;
                    }
                }
            }
        };
        walk_take(&mut ir.system);
        for m in &mut ir.messages {
            walk_take(&mut m.content);
        }
        for t in &mut ir.tools {
            if t.cache_control.is_some() {
                if seen < cap {
                    seen += 1;
                } else {
                    t.cache_control = None;
                    dropped += 1;
                }
            }
        }
        if dropped > 0 {
            ::tracing::debug!(diag = %busbar_core::diagnostics::IR_DROP_CACHE_CONTROL_OVER_CAP.banner(),
                ingress = %prep.ingress_protocol,
                cap,
                dropped,
                "dropping {dropped} cache_control breakpoint(s) past the egress \
                 dialect's cap of {cap}: the target vendor 400s past this count and \
                 the IR carries breakpoints unbounded"
            );
        }
    }
    // HOSTED-TOOL cross-protocol drop. A Responses hosted tool
    // (`{"type":"web_search"}` → `IrTool{ name:"", hosted:Some(..) }`) has NO function-tool
    // analog: ONLY the Responses writer honors `hosted`; every other egress writer projects
    // an `IrTool` as a function tool keyed on `name`, so a hosted tool becomes a malformed
    // empty-name `{"type":"function","name":""}` the backend 400s on. `prepare_for_egress`
    // runs ONLY on the cross-protocol seam (a same-protocol Responses->Responses passthrough
    // never reaches here - its body is forwarded verbatim, so hosted tools pass through
    // intact), so DROPPING every hosted tool here is exactly the "keep same-proto, drop
    // cross-proto" contract. Retain the count for the warn before draining.
    let hosted_dropped = ir.tools.iter().filter(|t| t.hosted.is_some()).count();
    if hosted_dropped > 0 {
        ir.tools.retain(|t| t.hosted.is_none());
        ::tracing::debug!(diag = %busbar_core::diagnostics::IR_DROP_HOSTED_TOOLS.banner(),
            ingress = %prep.ingress_protocol,
            dropped = hosted_dropped,
            "dropping cross-protocol hosted (built-in) tool(s): a Responses hosted tool \
             has no function-tool equivalent for a non-Responses backend; forwarding it \
             would emit a malformed empty-name function tool the upstream rejects (400). \
             Route hosted-tool requests to a Responses lane to use them"
        );
    }
    // Gemini `cachedContent` references a server-side context cache at
    // Google that busbar cannot project into `contents` — it has no handle on the
    // cached turns' text. `extra` is about to be wiped wholesale below (this is the
    // cross-protocol-only seam; same-protocol Gemini->Gemini never reaches here), so a
    // `cachedContent` key silently disappears with TWO invisible consequences: the
    // backend answers on the VISIBLE history only (the cached turns are ABSENT, not
    // summarized), and the caller is billed FULL UNCACHED input. Fail-closed here would
    // be TERMINAL (both `proxy/wire.rs` callers do `Err => return`, pre-empting
    // failover to a same-pool Gemini lane later), so — matching the two warns just
    // above that already guard this same clear — degrade with a LOUD warn naming both
    // consequences; that is the contract this codebase already applies at this seam.
    // Gemini 3 thoughtSignature sentinel fill. Real production outage: an
    // OpenAI/Anthropic/etc. client's tool-call history, replayed cross-protocol against a
    // Gemini 3 AI-Studio backend, carries `ToolUse` blocks whose `thought_signature` is
    // `None` (no foreign protocol has this concept to read). Gemini 3 REQUIRES a
    // `thoughtSignature` echoed on every `functionCall` part or the backend 400s
    // ("missing a thought_signature"). `thought_signature_fill` is resolved by the caller
    // (true only for a Gemini AI-Studio egress lane, never Vertex — see the field's doc)
    // so this stays the one place the gate lives, matching `reasoning_allowed` /
    // `prompt_caching_allowed` above. A real signature (e.g. same-protocol-shaped history
    // that genuinely carries one) is NEVER overwritten — only a `None` gets the sentinel.
    if prep.thought_signature_fill {
        let fill_blocks = |blocks: &mut [crate::ir::IrBlock]| {
            for b in blocks {
                if let crate::ir::IrBlock::ToolUse {
                    thought_signature, ..
                } = b
                {
                    if thought_signature.is_none() {
                        *thought_signature = Some(GEMINI_SKIP_THOUGHT_SIGNATURE.to_string());
                    }
                }
            }
        };
        for m in &mut ir.messages {
            fill_blocks(&mut m.content);
        }
    }
    // OpenAI `messages[].name` — the per-message participant name, parked by the OpenAI
    // Chat reader under its own sentinel (see `MESSAGE_NAMES_SENTINEL`). No other
    // protocol in the matrix models a participant name at all: Anthropic, Gemini,
    // Bedrock, Cohere and Responses each frame a turn as (role, content) and nothing
    // else. So this is a genuine target-protocol limit rather than an unmodelled IR gap
    // — but it was crossing SILENTLY, and a multi-speaker transcript losing its speaker
    // labels changes what the model is being asked. The generic dropped-keys warn below
    // would name it only as an opaque `__busbar_…` key; name it in the caller's own
    // vocabulary here, exactly as `cachedContent` is named just below.
    // Keyed off the OpenAI module's OWN const, not a copy of its string: a rename that
    // did not update a duplicated literal here would silently switch this warn off, and a
    // signal that can stop signalling without failing to compile is the failure class
    // this whole section exists to remove.
    if let Some(n) = ir
        .extra
        .get(busbar_core::proto::openai_family::MESSAGE_NAMES_SENTINEL)
        .and_then(|v| v.as_object())
        .map(serde_json::Map::len)
    {
        ::tracing::debug!(diag = %busbar_core::diagnostics::IR_DROP_MESSAGE_NAME.banner(),
            ingress = %prep.ingress_protocol,
            messages = n,
            "dropping OpenAI `messages[].name` on the cross-protocol seam: no target \
             protocol models a per-message participant name, so a multi-speaker \
             transcript reaches the backend with its speaker labels removed. Put the \
             speaker in the message TEXT, or route to an openai lane"
        );
    }
    if ir.extra.contains_key("cachedContent") {
        ::tracing::debug!(diag = %busbar_core::diagnostics::IR_DROP_CACHED_CONTENT.banner(),
            ingress = %prep.ingress_protocol,
            key = "cachedContent",
            "dropping Gemini `cachedContent` on the cross-protocol seam: the referenced \
             context cache lives server-side at Google and cannot be projected into \
             `contents`, so (1) the backend answers on the VISIBLE history only — the \
             cached turns are absent, not summarized — and (2) the caller is billed FULL \
             UNCACHED input for this request. Route cachedContent requests to a Gemini \
             lane."
        );
    }
    // EVERY remaining unmodeled request key dies here, and until this warn existed it
    // died SILENTLY: exactly two keys (Gemini `cachedContent` above, Cohere `documents`
    // at its reader) named themselves, and the other ~40 — OpenAI `logit_bias` /
    // `store` / `metadata` / `service_tier` / `stream_options` / `prediction` /
    // `modalities` / `audio` / `web_search_options`, Anthropic `metadata` / `container` /
    // `mcp_servers` / `betas`, Gemini `safetySettings` / `labels`, Bedrock
    // `guardrailConfig` / `promptVariables` / `requestMetadata` / `performanceConfig`,
    // Cohere `citation_options` / `safety_mode` / `strict_tools` / `logprobs`, Responses
    // `previous_response_id` / `conversation` / `truncation` / `include` / `prompt` /
    // `prompt_cache_key` / `safety_identifier` / `background` — vanished with nothing in
    // the logs. Most of them are correctly untranslatable (they name machinery that
    // exists at exactly one vendor); the DEFECT was the silence, not the drop. Naming the
    // actual key set of THIS request moves the whole class from "dropped silently" to
    // "dropped with a signal" without guessing at an inventory that would go stale.
    //
    // Emitted only when there is something to clear, and the keys are sorted so the line
    // is stable/greppable across requests. `extra` is a flat map of the SOURCE dialect's
    // unmodeled top-level keys, so the key names alone are the diagnostic — values are
    // deliberately NOT logged (they carry caller payload).
    if !ir.extra.is_empty() {
        let mut cleared: Vec<&str> = ir.extra.keys().map(String::as_str).collect();
        cleared.sort_unstable();
        ::tracing::debug!(diag = %busbar_core::diagnostics::IR_DROP_UNMODELED_KEYS.banner(),
            ingress = %prep.ingress_protocol,
            keys = %cleared.join(","),
            count = cleared.len(),
            "dropping unmodeled request keys on the cross-protocol seam: `extra` carries \
             the SOURCE dialect's unmodeled top-level fields and no target writer can \
             re-emit a foreign dialect's key, so every key named here is NOT forwarded \
             to the backend. Route these requests to a same-protocol lane (which \
             forwards the caller's original bytes verbatim) if the field is load-bearing."
        );
    }
    ir.extra.clear();
}

/// Chat cross-protocol INGRESS preparation (verbatim from the former `IrResp::Chat` arm).
pub(crate) fn chat_prepare_for_ingress(
    ir: &mut IrResponse,
    ingress_protocol: &str,
    now_epoch: u64,
) {
    ir.id = None;
    ir.system_fingerprint = None;
    ir.stop_sequence = None;
    if ir.created.is_none() {
        ir.created = Some(now_epoch);
    }
    super::proto_codec::ToolIdRemap::default().remap_response(ingress_protocol, ir);
}

/// Chat token-usage billing projection (from the former `IrResp::Chat` `usage()` arm).
pub(crate) fn chat_usage(r: &IrResponse) -> Option<Billing> {
    Some(Billing::Tokens(TokenUsage {
        input: r.usage.input_tokens,
        output: r.usage.output_tokens,
        cache_read: r.usage.cache_read_input_tokens,
        cache_creation: r.usage.cache_creation_input_tokens,
        ..Default::default()
    }))
}

// ─────────────────────────────── the handles ───────────────────────────────

/// The chat REQUEST handle.
pub struct ChatReqHandle(pub IrRequest);
/// The chat RESPONSE handle.
pub struct ChatRespHandle(pub IrResponse);

impl Sealed for ChatReqHandle {}
impl Sealed for ChatRespHandle {}

impl IrHandle for ChatReqHandle {
    fn verb(&self) -> Operation {
        Operation::CHAT
    }
    fn wants_stream(&self) -> bool {
        self.0.stream
    }
    fn facts(&self) -> Box<dyn IrFacts + Send + Sync> {
        Box::new(self.0.clone())
    }
    fn prepare_for_egress(&mut self, prep: &EgressPrep) {
        chat_prepare_for_egress(&mut self.0, prep);
    }
    fn egress_dropped_controls(&self, egress_proto: &str) -> Vec<&'static str> {
        super::proto_codec::protocol_for(egress_proto)
            .map(|p| p.writer().dropped_egress_controls(&self.0))
            .unwrap_or_default()
    }
    fn write_egress_request(&mut self, egress_proto: &str, _model: &str) -> EgressWire {
        // Chat is always a JSON body the router post-shapes (write_request_value == Some).
        super::proto_codec::protocol_for(egress_proto)
            .map(|p| EgressWire::Json(p.writer().write_request(&self.0)))
            .unwrap_or_else(|| EgressWire::Bytes(Bytes::new()))
    }
}

impl IrHandle for ChatRespHandle {
    fn verb(&self) -> Operation {
        Operation::CHAT
    }
    fn billing(&self) -> Option<Billing> {
        chat_usage(&self.0)
    }
    fn prepare_for_ingress(&mut self, ingress_protocol: &str, now_epoch: u64) {
        chat_prepare_for_ingress(&mut self.0, ingress_protocol, now_epoch);
    }
    fn wrap_buffered_as_stream(
        &self,
        ingress_protocol: &str,
        elapsed_ms: Option<u64>,
    ) -> Option<Vec<u8>> {
        super::proto_codec::protocol_for(ingress_protocol)
            .and_then(|p| p.writer().wrap_buffered_as_stream(&self.0, elapsed_ms))
    }
    fn write_ingress_response(
        &self,
        ingress_protocol: &str,
        ingress_serves_op: bool,
    ) -> TranslatedResponse {
        if !ingress_serves_op {
            return TranslatedResponse::IngressUnsupported;
        }
        // Chat write_response_value == Some(Value) => Json.
        match super::proto_codec::protocol_for(ingress_protocol) {
            Some(p) => TranslatedResponse::Json(p.writer().write_response(&self.0)),
            None => TranslatedResponse::IngressUnsupported,
        }
    }
}

// ─────────────────────────── the chat OperationHandler ───────────────────────────

/// A protocol's chat operation — RELOCATED from `busbar-core/src/handlers/chat.rs` at the G6 A4b
/// dissolve. The field names the protocol whose `busbar_core::proto::` reader/writer are this
/// instance's codec; `read_request`/`read_response` now yield `Box<dyn IrHandle>` (a
/// `ChatReqHandle`/`ChatRespHandle`), and the WRITE half inverted onto those handles (they write
/// themselves by egress-protocol string). One TYPE, six per-protocol instances registered by each
/// dialect's `operation_handler(Operation::CHAT)`.
pub struct ChatOperation(pub &'static str);

impl ChatOperation {
    fn proto(&self) -> Option<super::proto_codec::Protocol> {
        super::proto_codec::protocol_for(self.0)
    }
}

impl OperationHandler for ChatOperation {
    fn extract_error(&self, status: u16, body: &[u8]) -> busbar_core::breaker::RawUpstreamError {
        busbar_core::handlers::protocol_error(self.0, status, body)
    }

    fn streaming(&self) -> bool {
        true
    }
    fn taps_usage(&self) -> bool {
        true
    }
    fn wants_stream(&self, body: &Value) -> bool {
        body.get("stream")
            .and_then(|s| s.as_bool())
            .unwrap_or(false)
    }
    fn body_affinity_key<'a>(&self, body: &'a Value) -> Option<&'a str> {
        body.get("system")
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
    }
    fn extract_usage(
        &self,
        ingress_protocol: &str,
        body: &[u8],
    ) -> Option<busbar_core::billing::TokenUsage> {
        // Same-protocol usage tap (verbatim from the former `ChatOperation`; `crate::` re-pathed).
        let Some(p) = super::proto_codec::protocol_for(ingress_protocol) else {
            if busbar_core::handlers::usage_tap_decode_fail_should_warn(
                ingress_protocol,
                "unknown_protocol",
            ) {
                ::tracing::warn!(diag = %busbar_core::diagnostics::USAGE_TAP_UNKNOWN_PROTOCOL.banner(),
                    protocol = ingress_protocol,
                    "usage tap: unknown ingress protocol for a same-protocol 2xx body; \
                     billing 0 tokens for this request"
                );
            } else {
                ::tracing::debug!(diag = %busbar_core::diagnostics::USAGE_TAP_UNKNOWN_PROTOCOL.banner(),
                    protocol = ingress_protocol,
                    "usage tap: unknown ingress protocol for a same-protocol 2xx body; \
                     billing 0 tokens for this request"
                );
            }
            return None;
        };
        let v = match busbar_core::json::parse::<Value>(body) {
            Ok(v) => v,
            Err(_e) => {
                if busbar_core::handlers::usage_tap_decode_fail_should_warn(
                    ingress_protocol,
                    "bad_json",
                ) {
                    ::tracing::warn!(diag = %busbar_core::diagnostics::USAGE_TAP_BAD_JSON.banner(),
                        protocol = ingress_protocol,
                        error = %busbar_core::json::parse_err_log(body.len()),
                        "usage tap: failed to parse a same-protocol 2xx body as JSON; \
                         billing 0 tokens for this request"
                    );
                } else {
                    ::tracing::debug!(diag = %busbar_core::diagnostics::USAGE_TAP_BAD_JSON.banner(),
                        protocol = ingress_protocol,
                        error = %busbar_core::json::parse_err_log(body.len()),
                        "usage tap: failed to parse a same-protocol 2xx body as JSON; \
                         billing 0 tokens for this request"
                    );
                }
                return None;
            }
        };
        match p.reader().read_response(&v) {
            Ok(ir) => Some(ir.usage.to_token_usage()),
            Err(e) => {
                if busbar_core::handlers::usage_tap_decode_fail_should_warn(
                    ingress_protocol,
                    "decode",
                ) {
                    ::tracing::warn!(diag = %busbar_core::diagnostics::USAGE_TAP_DECODE_FAILED.banner(),
                        protocol = ingress_protocol,
                        error = ?e,
                        "usage tap: read_response failed to decode a same-protocol 2xx body; \
                         billing 0 tokens for this request"
                    );
                } else {
                    ::tracing::debug!(diag = %busbar_core::diagnostics::USAGE_TAP_DECODE_FAILED.banner(),
                        protocol = ingress_protocol,
                        error = ?e,
                        "usage tap: read_response still failing to decode a same-protocol 2xx body; \
                         billing 0 tokens for this request"
                    );
                }
                None
            }
        }
    }

    fn read_request_value(&self, v: &Value) -> Result<Box<dyn IrHandle>, IngressReject> {
        let p = self
            .proto()
            .ok_or_else(|| IngressReject::BadRequest(format!("unknown protocol {}", self.0)))?;
        p.reader()
            .read_request(v)
            .map(|r| Box::new(ChatReqHandle(r)) as Box<dyn IrHandle>)
            .map_err(|e| IngressReject::BadRequest(format!("{e:?}")))
    }
    fn read_response_value(&self, v: &Value) -> Result<Box<dyn IrHandle>, CodecError> {
        let p = self
            .proto()
            .ok_or_else(|| CodecError::Malformed(format!("unknown protocol {}", self.0)))?;
        p.reader()
            .read_response(v)
            .map(|r| Box::new(ChatRespHandle(r)) as Box<dyn IrHandle>)
            .map_err(|e| CodecError::Malformed(format!("{e:?}")))
    }
    fn read_request(
        &self,
        body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        let v: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let p = self
            .proto()
            .ok_or_else(|| IngressReject::BadRequest(format!("unknown protocol {}", self.0)))?;
        p.reader()
            .read_request(&v)
            .map(|r| Box::new(ChatReqHandle(r)) as Box<dyn IrHandle>)
            .map_err(|e| IngressReject::BadRequest(format!("{e:?}")))
    }
    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let p = self
            .proto()
            .ok_or_else(|| CodecError::Malformed(format!("unknown protocol {}", self.0)))?;
        p.reader()
            .read_response(&v)
            .map(|r| Box::new(ChatRespHandle(r)) as Box<dyn IrHandle>)
            .map_err(|e| CodecError::Malformed(format!("{e:?}")))
    }
}

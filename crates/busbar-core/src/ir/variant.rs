// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-operation IR enums: `IrReq` / `IrResp`, one variant per operation. A single `enum Ir`
//! would not fit: the engine already splits request from
//! response (`IrRequest`/`IrResponse`). The inherent methods here ARE the surface the operation-blind
//! middle sees; each exhaustive `match` is the removability / symmetry gate — adding the next
//! operation (an 8th, past the current seven Chat..Rerank) is a compile error at every one.
//!
//! `affinity_key` and cross-protocol drop accounting are not built as of 1.5.0: they are not wired
//! through the request/response IR split.

use super::audio::{SpeechReq, SpeechResp, TranscriptionReq, TranscriptionResp};
use super::embeddings::{EmbeddingsReq, EmbeddingsResp};
use super::image::{ImageReq, ImageResp};
use super::moderation::{ModerationReq, ModerationResp};
use super::{IrRequest, IrResponse};
use crate::billing::{Billing, TokenUsage};
use crate::handlers::{EgressWire, OperationHandler, TranslatedResponse};
use crate::operation::Operation;
use bytes::Bytes;

/// Google's documented dummy `thoughtSignature` value that "skips validation" for a function-call
/// part — the officially sanctioned escape hatch for migrating conversation history from another
/// model (exactly busbar's cross-protocol case: an OpenAI/Anthropic/etc. client's tool-call history
/// replayed against a Gemini 3 backend, which never had a real signature to echo back). Per Google's
/// own docs: "you can set the following dummy signatures of either
/// 'context_engineering_is_the_way_to_go' or 'skip_thought_signature_validator' in the thought
/// signature field to skip validation". Also independently confirmed live by LiteLLM's production
/// Gemini-3 integration doing the same substitution.
///
/// MUST be emitted as a literal JSON string, never as SDK-typed `bytes` — some Google client SDKs
/// model `thoughtSignature` as `bytes` and silently base64-encode it, which breaks the bypass since
/// the backend then sees the base64 encoding of this string, not the string itself. busbar builds
/// raw JSON directly (see `proto::gemini::writer`), so this is correct by construction; a typed
/// representation would reintroduce the encoding hazard.
pub const GEMINI_SKIP_THOUGHT_SIGNATURE: &str = "skip_thought_signature_validator";

/// Request-side IR — one variant per operation. `Chat` reuses the existing `IrRequest` verbatim.
#[derive(Debug, Clone)]
pub enum IrReq {
    Chat(IrRequest),
    Embeddings(EmbeddingsReq),
    Moderation(ModerationReq),
    Image(ImageReq),
    Transcription(TranscriptionReq),
    Speech(SpeechReq),
    Rerank(crate::ir::rerank::RerankReq),
    /// The EIGHTH, and the first that did not come from the LLM surface. See
    /// [`crate::ir::invoke`] for why an invocation is an operation rather than a plane.
    ///
    /// The variant landed FIRST and deliberately, because its arrival is what makes every exhaustive
    /// match in this file a compile error until it has an answer — which is the whole mechanism.
    #[cfg_attr(not(test), allow(dead_code))]
    Invoke(crate::ir::invoke::InvokeReq),
    /// The NINTH, and the second from the protocol surface. A caller names a thing and asks to start
    /// or stop being told when it changes. See [`crate::ir::subscribe`] for why register and
    /// deregister are one variant carrying an intent rather than two variants.
    Subscribe(crate::ir::subscribe::SubscribeReq),
}

impl IrReq {
    /// Which operation this is (the coarse tag the middle carries). Called only from this module's
    /// own tests today; kept for the exhaustive-match compile-time guarantee (adding an `IrReq`
    /// variant without a routing story is a compile error here).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn operation(&self) -> Operation {
        match self {
            IrReq::Chat(_) => Operation::CHAT,
            IrReq::Embeddings(_) => Operation::EMBEDDINGS,
            IrReq::Moderation(_) => Operation::MODERATION,
            IrReq::Image(_) => Operation::IMAGE,
            IrReq::Transcription(_) => Operation::TRANSCRIPTION,
            IrReq::Speech(_) => Operation::SPEECH,
            IrReq::Rerank(_) => Operation::RERANK,
            IrReq::Invoke(_) => Operation::INVOKE,
            IrReq::Subscribe(_) => Operation::SUBSCRIBE,
        }
    }

    /// Did the caller ask to stream? Only chat and audio can (1.2); the JSON ops never stream.
    /// Called only from this module's own tests today; kept for the exhaustive-match guarantee.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn wants_stream(&self) -> bool {
        match self {
            IrReq::Chat(r) => r.stream,
            IrReq::Transcription(r) => r.stream,
            IrReq::Speech(r) => r.stream,
            IrReq::Rerank(_) => false,
            // A tool call is a request/response exchange: the tool runs and answers. Progress
            // notifications are a separate channel, not an incremental rendering of THIS result.
            IrReq::Invoke(_) => false,
            // REGISTERING IS NOT THE STREAM. A subscription request is answered once, with an
            // acknowledgement; the events that follow travel on the channel the transport already
            // provides. Treating the registration as a streaming request would make the engine hold
            // a response open for a body that is never coming.
            IrReq::Subscribe(_) => false,
            IrReq::Embeddings(_) | IrReq::Moderation(_) | IrReq::Image(_) => false,
        }
    }

    /// Neutral CROSS-PROTOCOL egress preparation — each operation applies ITS OWN semantics before
    /// its IR is written into a foreign egress dialect; the engine calls this without knowing which
    /// operation it holds. Chat: default `max_tokens` when the egress requires one, decode the
    /// client-echoed tool ids back to the backend's originals, and clear source-only `extra` keys
    /// (the foreign-format leak guard). The other operations' extras are source-scoped by
    /// construction, so they need no clearing.
    pub fn prepare_for_egress(&mut self, prep: &EgressPrep) {
        match self {
            IrReq::Chat(ir) => {
                if ir.max_tokens.is_none() && prep.egress_requires_max_tokens {
                    ir.max_tokens = Some(
                        prep.lane_default_max_tokens
                            .unwrap_or(prep.global_default_max_tokens),
                    );
                }
                crate::proto::decode_request_tool_ids(prep.ingress_protocol, &mut ir.messages);
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
                    crate::diagnostics::diag_debug!(
                        crate::diagnostics::IR_CLAMP_N_TO_1,
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
                        crate::diagnostics::diag_debug!(
                            crate::diagnostics::IR_DROP_REASONING,
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
                        crate::diagnostics::diag_debug!(
                            crate::diagnostics::IR_DROP_PROMPT_CACHE,
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
                        crate::diagnostics::diag_debug!(
                            crate::diagnostics::IR_DROP_CACHE_CONTROL_OVER_CAP,
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
                    crate::diagnostics::diag_debug!(
                        crate::diagnostics::IR_DROP_HOSTED_TOOLS,
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
                                    *thought_signature =
                                        Some(GEMINI_SKIP_THOUGHT_SIGNATURE.to_string());
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
                    .get(crate::proto::openai_family::MESSAGE_NAMES_SENTINEL)
                    .and_then(|v| v.as_object())
                    .map(serde_json::Map::len)
                {
                    crate::diagnostics::diag_debug!(
                        crate::diagnostics::IR_DROP_MESSAGE_NAME,
                        ingress = %prep.ingress_protocol,
                        messages = n,
                        "dropping OpenAI `messages[].name` on the cross-protocol seam: no target \
                         protocol models a per-message participant name, so a multi-speaker \
                         transcript reaches the backend with its speaker labels removed. Put the \
                         speaker in the message TEXT, or route to an openai lane"
                    );
                }
                if ir.extra.contains_key("cachedContent") {
                    crate::diagnostics::diag_debug!(
                        crate::diagnostics::IR_DROP_CACHED_CONTENT,
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
                    crate::diagnostics::diag_debug!(
                        crate::diagnostics::IR_DROP_UNMODELED_KEYS,
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
            IrReq::Embeddings(_)
            | IrReq::Moderation(_)
            | IrReq::Image(_)
            | IrReq::Transcription(_)
            | IrReq::Speech(_)
            | IrReq::Rerank(_)
            // A tool call carries no sampling controls, no `max_tokens` and no tool-id echo, so
            // none of chat's cross-protocol preparation has a subject here. Its `extra` is
            // source-scoped by construction like its siblings', so there is nothing to clear
            // either. Enumerated rather than swept into a `_` so that if this operation ever grows
            // a control that must be prepared before a foreign egress, this is a compile error
            // rather than a silent omission.
            | IrReq::Invoke(_)
            // A subscription request carries a target name and an intent. Neither is a sampling
            // control, neither is a tool id and neither needs a default filled in before a foreign
            // egress, so there is nothing here to prepare. Enumerated rather than swept into a `_`
            // so that if this operation ever grows a member that must be prepared, this is a
            // compile error rather than a silent omission.
            | IrReq::Subscribe(_) => {}
        }
    }

    /// Set the model — the ROUTING layer's injection point, operation-blind. Two callers:
    /// path-model ingress dialects (gemini/bedrock carry the model in the URL, so the OperationHandler parses an
    /// empty body model and routing fills it), and the cross-protocol egress hop (the egress wire must
    /// carry the LANE's wire model, not the caller's busbar model name). Chat is a no-op: `IrRequest`
    /// carries no model field (chat's model lives at the routing/rewrite layer, as today).
    pub fn set_model(&mut self, model: &str) {
        match self {
            IrReq::Chat(_) => {}
            IrReq::Embeddings(r) => r.model = model.to_string(),
            IrReq::Moderation(r) => r.model = model.to_string(),
            IrReq::Image(r) => r.model = model.to_string(),
            IrReq::Transcription(r) => r.model = model.to_string(),
            IrReq::Speech(r) => r.model = model.to_string(),
            IrReq::Rerank(r) => r.model = model.to_string(),
            // THE TARGET IDENTIFIER ON THIS OPERATION IS THE TOOL, and routing does not choose it:
            // the caller named it and the catalogue bound it. The published-to-upstream rename is
            // the WRITER's business (`rewrite_model`), which is where a lane's spelling belongs on
            // every operation. So routing's injection point is a no-op here, as it is for chat.
            IrReq::Invoke(_) => {}
            // THE TARGET ON THIS OPERATION IS NOT A MODEL AND ROUTING DOES NOT CHOOSE IT. The
            // caller named the thing it wants to follow; a lane's spelling of that name is the
            // writer's business, exactly as it is on an invocation.
            IrReq::Subscribe(_) => {}
        }
    }
}

/// A4b PRE-STEP 1 — the handle-owned EGRESS-REQUEST write entrypoints (the write-inversion SHAPE).
/// The `IrReq` (the handle-to-be) OWNS the write, delegating to the egress codec's existing
/// `write_request_value`/`write_request` so the pipeline stays byte-identical. At A4b the
/// `egress: &dyn OperationHandler` param becomes an `egress_protocol: &str` and each body selects the
/// writer internally (no downcast — owner ruling 2026-08-20); these methods then move onto
/// `IrHandle` in busbar-llm. Named here so `TranslateCodec` routes writes through the handle before
/// the irreversible dissolve.
impl IrReq {
    /// JSON egress path: value-first (a JSON body the router still post-shapes) else `set_model` +
    /// final bytes. Byte-identical to the pre-cutover inline write in `TranslateCodec::translate_request`.
    pub fn write_egress_request(
        &mut self,
        egress: &dyn OperationHandler,
        model: &str,
    ) -> EgressWire {
        match egress.write_request_value(self) {
            Some(written) => EgressWire::Json(written),
            None => {
                self.set_model(model);
                EgressWire::Bytes(egress.write_request(self))
            }
        }
    }

    /// OPAQUE egress path (multipart transcription / audio speech): `set_model` then the egress
    /// codec's final bytes, no JSON post-shape. Byte-identical to the pre-cutover inline opaque write;
    /// folds into the same `IrHandle` entrypoint at A4b.
    pub fn write_egress_request_bytes(
        &mut self,
        egress: &dyn OperationHandler,
        model: &str,
    ) -> Bytes {
        self.set_model(model);
        egress.write_request(self)
    }
}

/// THE OPERATION-BLIND PROJECTION DISPATCH — the hook/gate/tap seam reads a request through
/// [`crate::ir::facts::IrFacts`], and this is the one place the parent enum forwards to the inner
/// family's walk. Every arm is enumerated with NO catch-all, deliberately: a `_ =>` would silently
/// re-blind the next operation added to the tree (the exact hole this change closes), so a new
/// `IrReq` variant is a compile error here until it has projected its screenable content — the same
/// forcing-function every other exhaustive match in this file relies on.
impl crate::ir::facts::IrFacts for IrReq {
    fn verb(&self) -> Operation {
        match self {
            IrReq::Chat(r) => r.verb(),
            IrReq::Embeddings(r) => r.verb(),
            IrReq::Moderation(r) => r.verb(),
            IrReq::Image(r) => r.verb(),
            IrReq::Transcription(r) => r.verb(),
            IrReq::Speech(r) => r.verb(),
            IrReq::Rerank(r) => r.verb(),
            IrReq::Invoke(r) => r.verb(),
            IrReq::Subscribe(r) => r.verb(),
        }
    }

    fn wants_stream(&self) -> bool {
        match self {
            IrReq::Chat(r) => crate::ir::facts::IrFacts::wants_stream(r),
            IrReq::Embeddings(r) => crate::ir::facts::IrFacts::wants_stream(r),
            IrReq::Moderation(r) => crate::ir::facts::IrFacts::wants_stream(r),
            IrReq::Image(r) => crate::ir::facts::IrFacts::wants_stream(r),
            IrReq::Transcription(r) => crate::ir::facts::IrFacts::wants_stream(r),
            IrReq::Speech(r) => crate::ir::facts::IrFacts::wants_stream(r),
            IrReq::Rerank(r) => crate::ir::facts::IrFacts::wants_stream(r),
            IrReq::Invoke(r) => crate::ir::facts::IrFacts::wants_stream(r),
            IrReq::Subscribe(r) => crate::ir::facts::IrFacts::wants_stream(r),
        }
    }

    fn end_user(&self) -> Option<&str> {
        match self {
            IrReq::Chat(r) => r.end_user(),
            IrReq::Embeddings(r) => r.end_user(),
            IrReq::Moderation(r) => r.end_user(),
            IrReq::Image(r) => r.end_user(),
            IrReq::Transcription(r) => r.end_user(),
            IrReq::Speech(r) => r.end_user(),
            IrReq::Rerank(r) => r.end_user(),
            IrReq::Invoke(r) => r.end_user(),
            IrReq::Subscribe(r) => r.end_user(),
        }
    }

    fn shape(&self) -> crate::ir::facts::Shape {
        match self {
            IrReq::Chat(r) => r.shape(),
            IrReq::Embeddings(r) => r.shape(),
            IrReq::Moderation(r) => r.shape(),
            IrReq::Image(r) => r.shape(),
            IrReq::Transcription(r) => r.shape(),
            IrReq::Speech(r) => r.shape(),
            IrReq::Rerank(r) => r.shape(),
            IrReq::Invoke(r) => r.shape(),
            IrReq::Subscribe(r) => r.shape(),
        }
    }

    fn content(&self) -> Vec<crate::ir::facts::ContentItem<'_>> {
        match self {
            IrReq::Chat(r) => r.content(),
            IrReq::Embeddings(r) => r.content(),
            IrReq::Moderation(r) => r.content(),
            IrReq::Image(r) => r.content(),
            IrReq::Transcription(r) => r.content(),
            IrReq::Speech(r) => r.content(),
            IrReq::Rerank(r) => r.content(),
            IrReq::Invoke(r) => r.content(),
            IrReq::Subscribe(r) => r.content(),
        }
    }
}

/// Response-side IR — one variant per operation. `Chat` reuses the existing `IrResponse` verbatim.
#[derive(Debug, Clone)]
pub enum IrResp {
    Chat(IrResponse),
    Embeddings(EmbeddingsResp),
    Moderation(ModerationResp),
    Image(ImageResp),
    Transcription(TranscriptionResp),
    Speech(SpeechResp),
    Rerank(crate::ir::rerank::RerankResp),
    /// The EIGHTH. See [`crate::ir::invoke`] and [`IrReq::Invoke`].
    #[cfg_attr(not(test), allow(dead_code))]
    Invoke(crate::ir::invoke::InvokeResp),
    /// The NINTH. See [`crate::ir::subscribe`] and [`IrReq::Subscribe`].
    Subscribe(crate::ir::subscribe::SubscribeResp),
}

/// Resolved primitives for [`IrReq::prepare_for_egress`] — never a `Lane` or config handle.
pub struct EgressPrep<'a> {
    pub ingress_protocol: &'a str,
    pub egress_requires_max_tokens: bool,
    pub lane_default_max_tokens: Option<u32>,
    pub global_default_max_tokens: u32,
    /// The per-lane reasoning capability gate: the effective `reasoning` flag for THIS attempt's
    /// lane (pool-member override wins over the model-level flag). When false and the request
    /// carries a reasoning ask, the ask is CLEARED here with a warn — the one place the gate
    /// lives, so no writer can ever send a thinking param to a lane that did not claim it.
    pub reasoning_allowed: bool,
    /// The resolved effort-word → budget table (limits.reasoning_effort_budgets), stamped onto the
    /// IR for writers to project words ↔ numbers with the operator's numbers.
    pub reasoning_budgets: [u32; 4],
    /// The prompt-cache gate: `lane.prompt_caching || !writer.cache_markers_model_gated()`,
    /// resolved by the caller. When false and the request carries `cache_control` breakpoints,
    /// they are CLEARED here with a warn — the one place the gate lives, so no writer can emit a
    /// model-gated cache marker (Bedrock `cachePoint`) to a lane that did not claim it.
    pub prompt_caching_allowed: bool,
    /// The egress writer's `max_cache_control_breakpoints()` (`Some(4)` for Anthropic, `None`
    /// elsewhere — see that method's doc for why Bedrock is deliberately excluded). Anthropic 400s
    /// past this count; the IR carries breakpoints unbounded, so a cross-protocol request can
    /// exceed it. `None` means "no cap to enforce here" — the cap walk below is a no-op.
    pub cache_control_cap: Option<usize>,
    /// True only for a Gemini AI-Studio egress lane — NEVER for Vertex. When true, every
    /// `IrBlock::ToolUse` with no `thought_signature` gets Google's documented sentinel
    /// (`GEMINI_SKIP_THOUGHT_SIGNATURE`) injected so a cross-protocol `functionCall` part (whose
    /// history never had a real signature to echo) doesn't 400 the Gemini 3 backend. Vertex AI's
    /// Gemini surface is NOT confirmed to honor the same sentinel-bypass value — there are real
    /// reports of Vertex rejecting it with a 400 — so excluding Vertex lanes here is a safety
    /// requirement, not a nicety. The caller resolves this from lane config (protocol == Gemini AND
    /// no `path_base` override, i.e. not a Vertex-style URL-model lane) before constructing
    /// `EgressPrep`, matching how `reasoning_allowed`/`prompt_caching_allowed` are resolved.
    pub thought_signature_fill: bool,
}

impl IrResp {
    /// Neutral CROSS-PROTOCOL ingress preparation — each operation reshapes ITS OWN response IR for
    /// delivery in the caller's dialect; the engine calls this blind. Chat: strip the backend's
    /// native-format identity (`id`/`system_fingerprint`/`stop_sequence`) so the ingress writer
    /// mints CLIENT-format values, stamp a synthesized `created` when the egress reader left it
    /// empty (the protocol-agnostic boundary signal identity-gating writers key on), and remap tool
    /// ids to the caller's native shape. The other operations' responses carry no cross-protocol
    /// identity to reshape.
    pub fn prepare_for_ingress(&mut self, ingress_protocol: &str, now_epoch: u64) {
        match self {
            IrResp::Chat(ir) => {
                ir.id = None;
                ir.system_fingerprint = None;
                ir.stop_sequence = None;
                if ir.created.is_none() {
                    ir.created = Some(now_epoch);
                }
                crate::proto::ToolIdRemap::default().remap_response(ingress_protocol, ir);
            }
            IrResp::Embeddings(_)
            | IrResp::Moderation(_)
            | IrResp::Image(_)
            | IrResp::Transcription(_)
            | IrResp::Speech(_)
            | IrResp::Rerank(_)
            // Nothing to re-encode on the way back to a tool caller: the ids a tool call carries
            // are the caller's own, not backend-issued ones busbar had to translate.
            | IrResp::Invoke(_)
            // An acknowledgement carries no backend-issued identity to strip and no ids busbar had
            // to translate, so there is nothing to reshape on the way back.
            | IrResp::Subscribe(_) => {}
        }
    }

    /// Buffered-2xx-to-native-stream synthesis (bedrock ConverseStream answered by a non-SSE
    /// upstream): operations that can stream delegate to the ingress writer's frame synthesizer;
    /// the rest have no stream wire. Engine stays operation-blind.
    pub fn wrap_buffered_as_stream(
        &self,
        writer: &dyn crate::proto::ProtocolWriter,
        elapsed_ms: Option<u64>,
    ) -> Option<Vec<u8>> {
        match self {
            IrResp::Chat(ir) => writer.wrap_buffered_as_stream(ir, elapsed_ms),
            IrResp::Embeddings(_)
            | IrResp::Moderation(_)
            | IrResp::Image(_)
            | IrResp::Transcription(_)
            | IrResp::Speech(_)
            | IrResp::Rerank(_)
            // A tool call has one answer; there is no buffered stream to re-frame as an
            // incremental one, and pretending otherwise would invent frames the caller never
            // asked for.
            | IrResp::Invoke(_)
            // There is no buffered stream to re-frame: the answer to a subscription request is a
            // single acknowledgement, and the events it enables are not this response.
            | IrResp::Subscribe(_) => None,
        }
    }

    /// Called only from this module's own tests today; kept for the exhaustive-match guarantee.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn operation(&self) -> Operation {
        match self {
            IrResp::Chat(_) => Operation::CHAT,
            IrResp::Embeddings(_) => Operation::EMBEDDINGS,
            IrResp::Moderation(_) => Operation::MODERATION,
            IrResp::Image(_) => Operation::IMAGE,
            IrResp::Transcription(_) => Operation::TRANSCRIPTION,
            IrResp::Speech(_) => Operation::SPEECH,
            IrResp::Rerank(_) => Operation::RERANK,
            IrResp::Invoke(_) => Operation::INVOKE,
            IrResp::Subscribe(_) => Operation::SUBSCRIBE,
        }
    }

    /// The billable item for this response. Chat maps the existing `IrUsage` into
    /// `Billing::Tokens` (preserving the uncached-input + additive-cache convention); moderation is
    /// flat; the rest project their own usage. Exhaustive match = the symmetry gate.
    pub fn usage(&self) -> Option<Billing> {
        match self {
            IrResp::Chat(r) => Some(Billing::Tokens(TokenUsage {
                input: r.usage.input_tokens,
                output: r.usage.output_tokens,
                cache_read: r.usage.cache_read_input_tokens,
                cache_creation: r.usage.cache_creation_input_tokens,
                ..Default::default()
            })),
            IrResp::Embeddings(r) => r.billing(),
            IrResp::Moderation(_) => Some(Billing::Flat),
            IrResp::Image(r) => r.billing(),
            IrResp::Transcription(r) => r.billing(),
            IrResp::Speech(r) => r.billing(),
            IrResp::Rerank(r) => r.billing(),
            // A TOOL CALL IS NOT TOKEN-METERED. The upstream is a tool server, not a model: it
            // reports no token counts and there are none to infer. `Flat` is the honest meter —
            // one call, one unit — and it is what lets a tool call be CHARGED against the same
            // budget tree as a chat completion rather than being invisible to it, which is the
            // whole reason this arm exists rather than returning `None`.
            IrResp::Invoke(_) => Some(Billing::Flat),
            // A SUBSCRIPTION REQUEST IS A CALL, AND AN UNMETERED CALL IS AN AMPLIFIER. Nothing here
            // is token-metered — no model runs — but a caller that can register and deregister
            // without touching a budget can drive a peer as hard as it likes for free. `Flat` is the
            // same honest meter an invocation takes, one request one unit, and it is what keeps the
            // registration visible to the budget tree rather than invisible to it.
            IrResp::Subscribe(_) => Some(Billing::Flat),
        }
    }

    /// The token usage for this response as the neutral [`crate::billing::TokenUsage`], if it is
    /// token-metered. Used by the same-protocol non-stream usage tap
    /// (`OperationHandler::extract_usage`) so a token-metered non-chat op (embeddings) bills its
    /// virtual key's TPM/spend the same way chat does — and the same way the cross-protocol path
    /// already bills. Flat/duration/character meters return `None`. This IS the neutral projection
    /// (`usage()`) with the token variant unwrapped; it names no concrete IR (G6 inversion).
    pub fn token_usage(&self) -> Option<TokenUsage> {
        match self.usage() {
            Some(Billing::Tokens(t)) => Some(t),
            _ => None,
        }
    }

    /// A4b PRE-STEP 1 — the handle-owned INGRESS-RESPONSE write entrypoint for the JSON path (the
    /// write-inversion SHAPE). The `IrResp` OWNS the delivery choice — ingress-absent =>
    /// `IngressUnsupported`, else value-first (`write_response_value` `Some` => `Json`) else the
    /// ingress codec's `write_response` (`Typed`) — delegating to the ingress codec's existing
    /// methods, so it is byte-identical to the pre-cutover inline write in
    /// `TranslateCodec::translate_response`. At A4b `ingress: &dyn OperationHandler` becomes an
    /// `ingress_protocol: &str` and this moves onto `IrHandle` in busbar-llm.
    pub fn write_ingress_response(
        &self,
        ingress: Option<&dyn OperationHandler>,
    ) -> TranslatedResponse {
        let Some(h) = ingress else {
            return TranslatedResponse::IngressUnsupported;
        };
        match h.write_response_value(self) {
            Some(written) => TranslatedResponse::Json(written),
            None => TranslatedResponse::Typed(h.write_response(self)),
        }
    }

    /// A4b PRE-STEP 1 — the handle-owned INGRESS-RESPONSE write entrypoint for the OPAQUE path (audio
    /// / the opaque egress->ingress bridge): ingress-present => `Typed(write_response)`, absent =>
    /// `Untranslatable`. Byte-identical to the pre-cutover inline opaque write; folds into the same
    /// `IrHandle` entrypoint at A4b.
    pub fn write_ingress_response_bytes(
        &self,
        ingress: Option<&dyn OperationHandler>,
    ) -> TranslatedResponse {
        match ingress {
            Some(h) => TranslatedResponse::Typed(h.write_response(self)),
            None => TranslatedResponse::Untranslatable,
        }
    }
}

#[cfg(test)]
#[path = "tests/variant_tests.rs"]
mod tests;

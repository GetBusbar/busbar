use super::*;

/// AWS Converse `usage.totalTokens`: EVERY token the call consumed, cache tokens INCLUDED.
///
/// Under prompt caching AWS reports `inputTokens` as the NON-cached input only and documents the
/// full input as `inputTokens + cacheReadInputTokens + cacheWriteInputTokens`; its own worked
/// example totals `inputTokens: 16, outputTokens: 4, cacheWriteInputTokens: 695` as
/// `totalTokens: 715`. Since `write_cache_usage` emits the two cache counts as ADDITIVE siblings
/// (the IR's normalized convention, which matches Bedrock's wire shape), leaving them out of the
/// total would publish parts that sum PAST the stated total — and `totalTokens` is exactly the
/// field an accounting consumer reads, so those tokens would vanish from its books. The Bedrock
/// reader never reads `totalTokens` (it is derived here on write), so this is the only place the
/// wire total is decided, for both the buffered body and the streamed `metadata` frame.
///
/// All adds are `saturating_add`: the operands are UPSTREAM-CONTROLLED counts
/// (`as_u64().unwrap_or(0)` in the reader), so a bare `+` on a pathological/hostile set near
/// `u64::MAX` would panic this request-path code under overflow-checks (all debug builds, opt-in
/// release) or silently wrap to a nonsense total in plain release. Mirrors the Gemini writer.
fn converse_total_tokens(usage: &crate::ir::IrUsage) -> u64 {
    usage
        .input_tokens
        .saturating_add(usage.output_tokens)
        .saturating_add(usage.cache_read_input_tokens.unwrap_or(0))
        .saturating_add(usage.cache_creation_input_tokens.unwrap_or(0))
}

/// AWS SigV4 signing for a Bedrock Converse request — the egress credential for `bedrock` lanes
/// (dispatched via `busbar_substrate_values::egress_auth`, and called by the Bedrock auth tests). Lane key encodes
/// `ACCESS:SECRET[:SESSION]`; region parsed from the host; service=`bedrock`. A misconfigured key or
/// un-encodable byte yields an empty header set (AWS 403, surfaced as auth) rather than panicking.
pub fn sigv4_sign_headers(
    key: &str,
    ctx: &busbar_substrate_values::proto::SigningContext,
) -> Vec<(HeaderName, HeaderValue)> {
    let mut parts = key.splitn(3, ':');
    let (access, secret, token) = match (parts.next(), parts.next(), parts.next()) {
        (Some(a), Some(s), tok) if !a.is_empty() && !s.is_empty() => (a, s, tok),
        _ => return vec![],
    };
    let region = match derive_sigv4_region(ctx.host) {
        Some(r) => r,
        None => {
            tracing::warn!(host = %ctx.host, "could not derive AWS region from Bedrock endpoint host; defaulting SigV4 scope to us-east-1 (set a bedrock-runtime[-fips].<region>.amazonaws.com host)");
            "us-east-1"
        }
    };
    let service = "bedrock";
    let (amzdate, datestamp) = busbar_substrate_values::sigv4::format_amz_time(ctx.timestamp_epoch);
    let payload_hash = busbar_substrate_values::sigv4::sha256_hex(ctx.body);
    let token_header = match token {
        Some(t) => match HeaderValue::from_str(t) {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::warn!("Bedrock lane session token contains a byte rejected by HeaderValue; skipping signing to avoid a signed-but-absent x-amz-security-token header.");
                return vec![];
            }
        },
        None => None,
    };
    let mut signed = vec![
        (
            "content-type".to_string(),
            busbar_substrate_values::proxy::APPLICATION_JSON.to_string(),
        ),
        ("host".to_string(), ctx.host.to_string()),
        (
            busbar_substrate_values::sigv4::X_AMZ_CONTENT_SHA256.to_string(),
            payload_hash.clone(),
        ),
        (
            busbar_substrate_values::sigv4::X_AMZ_DATE.to_string(),
            amzdate.clone(),
        ),
    ];
    if let Some(t) = token {
        signed.push((
            busbar_substrate_values::sigv4::X_AMZ_SECURITY_TOKEN.to_string(),
            t.to_string(),
        ));
    }
    let (signature, signed_headers) = busbar_substrate_values::sigv4::sign_v4(
        secret,
        region,
        service,
        "POST",
        ctx.canonical_uri,
        "",
        &signed,
        &payload_hash,
        &amzdate,
        &datestamp,
    );
    let authorization = {
        use busbar_substrate_values::sigv4::{SIGV4_ALGORITHM, SIGV4_TERMINATION};
        format!(
            "{SIGV4_ALGORITHM} Credential={access}/{datestamp}/{region}/{service}/{SIGV4_TERMINATION}, SignedHeaders={signed_headers}, Signature={signature}"
        )
    };
    let (Ok(authorization_val), Ok(amzdate_val), Ok(payload_hash_val)) = (
        HeaderValue::from_str(&authorization),
        HeaderValue::from_str(&amzdate),
        HeaderValue::from_str(&payload_hash),
    ) else {
        return vec![];
    };
    let mut out = vec![
        (
            HeaderName::from_static(busbar_substrate_values::proto::HDR_AUTHORIZATION),
            authorization_val,
        ),
        (
            HeaderName::from_static(busbar_substrate_values::sigv4::X_AMZ_DATE),
            amzdate_val,
        ),
        (
            HeaderName::from_static(busbar_substrate_values::sigv4::X_AMZ_CONTENT_SHA256),
            payload_hash_val,
        ),
    ];
    if let Some(v) = token_header {
        out.push((
            HeaderName::from_static(busbar_substrate_values::sigv4::X_AMZ_SECURITY_TOKEN),
            v,
        ));
    }
    out
}

impl ProtocolWriter for BedrockWriter {
    fn probe_request(&self) -> serde_json::Value {
        // The ping IR is built by the plugin (ir_encode::ping_request); this dialect serializes it
        // through its own write_request, so the probe body matches a real request on this wire.
        self.write_request(&super::super::ir_encode::ping_request())
    }

    fn upstream_path(&self) -> &str {
        "/model"
    }

    fn upstream_path_for(&self, model: &str) -> String {
        format!("/model/{}/converse", model)
    }

    fn upstream_path_for_stream(&self, model: &str, stream: bool) -> String {
        // streaming uses ConverseStream (binary application/vnd.amazon.eventstream response).
        if stream {
            format!("/model/{}/converse-stream", model)
        } else {
            format!("/model/{}/converse", model)
        }
    }

    // Bedrock carries the target model in the request URL, not the body, so this is a no-op and
    // never changes the body → always reports `false` for pristine-tracking (a same-protocol Bedrock
    // passthrough is never made non-pristine by model rewriting).
    fn rewrite_model_if_needed(&self, _body: &mut serde_json::Value, _model: &str) -> bool {
        false
    }

    // NOTE: Bedrock Converse treats `inferenceConfig.maxTokens` as OPTIONAL (it applies the model's
    // default when omitted, and this writer omits an empty `inferenceConfig` entirely). So Bedrock
    // does NOT override `requires_max_tokens` — injecting a default here would silently cap output.

    /// Converse frames a turn as `{role, content: [{text}]}`. A verbatim insert of the reply's
    /// `{role, content: "…"}` messages would corrupt that block shape — Converse also spells its
    /// container `messages`, so this override is load-bearing rather than cosmetic.
    fn apply_rewrite_to_ingress_body(
        &self,
        obj: &mut serde_json::Map<String, serde_json::Value>,
        messages: &[serde_json::Value],
        _tools: &[serde_json::Value],
    ) -> bool {
        if !obj.get("messages").is_some_and(serde_json::Value::is_array) {
            return false;
        }
        let Some(pairs) = busbar_substrate_values::proto::rewrite_text_pairs(messages) else {
            return false;
        };
        let framed: Vec<serde_json::Value> = pairs
            .into_iter()
            .map(|(role, text)| serde_json::json!({ "role": role, "content": [{ "text": text }] }))
            .collect();
        obj.insert("messages".to_string(), serde_json::Value::Array(framed));
        true
    }

    fn dropped_egress_controls(&self, req: &crate::ir::IrRequest) -> Vec<&'static str> {
        self.dropped_egress_controls_for_lane(req, &LaneCaps::default())
    }

    fn dropped_egress_controls_for_lane(
        &self,
        req: &crate::ir::IrRequest,
        caps: &LaneCaps,
    ) -> Vec<&'static str> {
        // Mirrors the `write_request` warns: every control this writer drops for this lane.
        let mut dropped = Vec::new();
        // BED-08: a JSON-schema directive projects onto `outputConfig.textFormat` on a lane that
        // declares native structured outputs; any other directive, and every directive on a lane
        // that does not declare them, is dropped.
        if req.response_format.as_ref().is_some_and(|rf| {
            !caps.native_structured_output || super::write_bedrock_text_format(rf).is_none()
        }) {
            dropped.push("response_format");
        }
        if matches!(req.tool_choice, Some(crate::ir::IrToolChoice::None)) {
            dropped.push("tool_choice=none");
        }
        dropped.extend(bedrock_unrepresentable_slots(req));
        dropped
    }

    /// The production write: the lane's wire `model` gates the Claude-only spellings, and its
    /// declared [`LaneCaps`] choose the reasoning and structured-output forms (see
    /// `write_request_with`).
    ///
    /// BED-06 family gate. The reasoning ask is written into `additionalModelRequestFields` in
    /// CLAUDE's spelling (`thinking`, `output_config.effort`); another Converse family (Amazon Nova's
    /// `reasoningConfig`, and others) rejects or ignores it. The model id is the only place the
    /// family is visible — the Converse body carries none — so a cross-protocol ask reaches the wire
    /// only when the lane model names Claude (`anthropic.` / `claude`, which covers the bare model
    /// id, the regional and global inference profiles and their ARNs). Any other model, including an
    /// opaque application-inference-profile ARN, has the ask dropped with a warn rather than risk a
    /// 400.
    fn write_request_for_lane(
        &self,
        req: &crate::ir::IrRequest,
        model: &str,
        caps: &LaneCaps,
    ) -> serde_json::Value {
        if req.reasoning.is_some() && !bedrock_model_is_claude(model) {
            tracing::warn!(
                model,
                "dropping cross-protocol reasoning/thinking ask on Bedrock egress: the lane model \
                 is not a Claude model, and Converse's `thinking` field is Claude's spelling"
            );
            let mut without = req.clone();
            without.reasoning = None;
            return self.write_request_with(&without, caps);
        }
        self.write_request_with(req, caps)
    }

    fn write_request_for_model(
        &self,
        req: &crate::ir::IrRequest,
        model: &str,
    ) -> serde_json::Value {
        self.write_request_for_lane(req, model, &LaneCaps::default())
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        self.write_request_with(req, &LaneCaps::default())
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart { .. } => Some((
                ET_MESSAGE_START.to_string(),
                serde_json::json!({ "role": "assistant" }),
            )),

            IrStreamEvent::BlockStart {
                index,
                block,
                refusal: _,
            } => match block {
                // A TEXT block has NO `contentBlockStart` on the AWS Bedrock ConverseStream wire.
                // `ContentBlockStart$start` is a UNION whose members are `toolUse` (plus
                // `image`/`toolResult` in newer API revisions) — there is NO text member (AWS
                // Bedrock Runtime API reference, ContentBlockStart). A real ConverseStream therefore
                // opens a text block IMPLICITLY with its first `contentBlockDelta` carrying `text` and
                // closes it with `contentBlockStop`; the reader mirrors this (it lazily opens a Text
                // block on the first text delta). Emitting an empty `start: {}` frame here was an
                // off-spec frame no native endpoint sends — a detectable proxy tell. Still
                // `mark_block_open` so the matching `BlockStop` emits the (spec-required)
                // `contentBlockStop`, but emit NO start frame.
                crate::ir::IrBlockMeta::Text => {
                    self.mark_block_open(*index);
                    None
                }
                crate::ir::IrBlockMeta::ToolUse { id, name } => {
                    self.mark_block_open(*index);
                    Some((
                        ET_CONTENT_BLOCK_START.to_string(),
                        serde_json::json!({
                            "contentBlockIndex": index,
                            "start": { "toolUse": { "toolUseId": id, "name": name } }
                        }),
                    ))
                }
                // A reasoning (extended-thinking) block has NO `contentBlockStart` either.
                // `ContentBlockStart$start` models ONLY `toolUse` (no `reasoningContent` member —
                // AWS Bedrock Runtime API reference, ContentBlockStart). Reasoning is streamed
                // ENTIRELY through `contentBlockDelta.delta.reasoningContent` — the
                // `ReasoningContentBlockDelta` union (`text` / `signature` / `redactedContent`) — and
                // closed with `contentBlockStop`; the reader mirrors this (it lazily opens a Thinking
                // block on the first `reasoningContent` delta). Emitting a
                // `start.reasoningContent` frame was off-spec — a detectable proxy tell. Still
                // `mark_block_open` so the matching `BlockStop` emits `contentBlockStop`, but emit NO
                // start frame. (Image likewise has no streaming-start projection on Bedrock, so it
                // stays None — but is NOT marked open, so it emits no orphan stop either.)
                // Plaintext AND redacted reasoning: Bedrock streams BOTH through
                // `contentBlockDelta.reasoningContent` (plaintext `text`/`signature`, or opaque
                // `redactedContent`) with NO dedicated `contentBlockStart`. So a `RedactedThinking`
                // start behaves exactly like a `Thinking` start — emit no start frame but STILL
                // `mark_block_open` so the matching `BlockStop` emits `contentBlockStop`; the opaque
                // bytes ride the following `RedactedReasoningDelta`, re-emitted under `redactedContent`.
                crate::ir::IrBlockMeta::Thinking | crate::ir::IrBlockMeta::RedactedThinking => {
                    self.mark_block_open(*index);
                    None
                }
                crate::ir::IrBlockMeta::Image => None,
            },

            IrStreamEvent::BlockDelta { index, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) => Some((
                    ET_CONTENT_BLOCK_DELTA.to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "delta": { "text": text }
                    }),
                )),

                crate::ir::IrDelta::InputJsonDelta(json_str) => Some((
                    ET_CONTENT_BLOCK_DELTA.to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "delta": { "toolUse": { "input": json_str } }
                    }),
                )),

                // Streamed extended-thinking. The Bedrock `ReasoningContentBlockDelta` union carries
                // EITHER a `text` (plaintext reasoning) OR a `signature` (the opaque reasoning token)
                // OR a `redactedContent` (opaque encrypted bytes) per frame — each IR delta maps to
                // exactly ONE ConverseStream frame, so the single-frame-per-event constraint holds.
                // This is the streaming inverse of `bedrock_reasoning_block`'s buffered logic.
                crate::ir::IrDelta::ThinkingDelta(text) => Some((
                    ET_CONTENT_BLOCK_DELTA.to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "delta": { "reasoningContent": { "text": text } }
                    }),
                )),

                // A genuine reasoning signature token re-emits under `signature`.
                crate::ir::IrDelta::SignatureDelta(sig) => Some((
                    ET_CONTENT_BLOCK_DELTA.to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "delta": { "reasoningContent": { "signature": sig } }
                    }),
                )),
                // A streamed redacted-reasoning delta re-emits the opaque bytes under `redactedContent`
                // (never as a plaintext `signature`) — the streaming inverse of `bedrock_reasoning_block`.
                crate::ir::IrDelta::RedactedReasoningDelta(redacted) => Some((
                    ET_CONTENT_BLOCK_DELTA.to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "delta": { "reasoningContent": { "redactedContent": redacted } }
                    }),
                )),
                // Streamed grounding citations. Bedrock ConverseStream's `ContentBlockDelta` union
                // DOES have a `citation` member (a `CitationsDelta` with the same
                // `{title, sourceContent, location}` field set as the buffered `Citation`), arriving
                // interleaved with `text` deltas at the SAME `contentBlockIndex` — so this arm used to
                // suppress a frame the protocol defines, and the SAME request against the SAME backend
                // returned sources at `stream: false` and none at `stream: true`. Nothing about the
                // request explained that difference to the caller.
                //
                // A native `citation` delta carries ONE citation, so this SINGLE-frame arm frames the
                // FIRST of the batch; `write_response_events` is what walks a multi-citation delta,
                // re-entering here once per citation. A caller reaching this method directly (a
                // stream driven outside the framing seam's `max_citations_per_delta` fan-out)
                // therefore still gets a well-formed frame rather than a dropped or malformed one.
                crate::ir::IrDelta::CitationsDelta(cits) => {
                    let c = cits.first()?;
                    match super::write_bedrock_citation(c) {
                        Some(citation) => Some((
                            ET_CONTENT_BLOCK_DELTA.to_string(),
                            serde_json::json!({
                                "contentBlockIndex": index,
                                "delta": { "citation": citation }
                            }),
                        )),
                        // Every neutral field was empty, so there is no member to put in the union
                        // and an empty `{}` would be a malformed frame. Drop it, but say so.
                        None => {
                            tracing::warn!(
                                "dropping a streamed citation on a bedrock egress: it carried no \
                                 title, url, quoted text or resolvable character location, so there \
                                 is no populated member for the Converse `citation` delta union"
                            );
                            None
                        }
                    }
                }
                // Bedrock Converse has no logprobs shape; dropped.
                crate::ir::IrDelta::LogprobsDelta(_) => None,
            },

            // An untracked index is a block whose start had no Bedrock projection (Image); closing
            // it would orphan a `contentBlockStop` a real client never saw a start for.
            IrStreamEvent::BlockStop { index } => {
                if self.take_block_open(*index) {
                    Some((
                        ET_CONTENT_BLOCK_STOP.to_string(),
                        serde_json::json!({ "contentBlockIndex": index }),
                    ))
                } else {
                    None
                }
            }

            // The native Bedrock ConverseStream wire carries `stopReason` in a `messageStop` frame
            // and token `usage` in a SEPARATE `metadata` frame that FOLLOWS it. The IR, however,
            // carries ONE combined `MessageDelta{stop_reason, usage}` (the reader collapses the two
            // native frames into one so a cross-protocol ingress sees a single `message_delta`/usage
            // event). A single `(event_type, json)` return cannot emit two frames, so the two-frame
            // FAN-OUT for a Bedrock INGRESS lives in `StreamTranslate::translate_event` (proto/mod.rs),
            // which splits a combined delta into a stop-only delta (→ here, `messageStop`) and a
            // usage-only delta (→ here, `metadata`) before calling this writer, and injects the real
            // `metrics.latencyMs` onto the `metadata` frame.
            //
            // This arm therefore maps each (already-split) MessageDelta to its single native frame:
            //   - stop_reason = Some(...)  → `messageStop` (the stop discriminant; usage ignored)
            //   - stop_reason = None       → `metadata` carrying the real token usage (no `metrics`
            //                                here — the StreamTranslate fan-out adds it with the real
            //                                elapsed wall-clock, or omits it when timing is absent;
            //                                fabricating a `latencyMs: 0` was itself a detectable tell).
            // Bedrock has no stop_sequence field in its stream, so `stop_sequence` is ignored here.
            // IR-16 (BED-10): a context-window stop detail is written as Converse's own
            // `model_context_window_exceeded`.
            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
                stop_detail,
            } => match stop_reason {
                Some(reason) => Some((
                    ET_MESSAGE_STOP.to_string(),
                    serde_json::json!({
                        "stopReason": stop_reason_reverse_detailed(*reason, stop_detail.as_ref())
                    }),
                )),
                None => {
                    let mut usage_obj = serde_json::Map::new();
                    usage_obj.insert("inputTokens".to_string(), usage.input_tokens.into());
                    usage_obj.insert("outputTokens".to_string(), usage.output_tokens.into());
                    // Cache-inclusive and saturating — see `converse_total_tokens`.
                    usage_obj.insert(
                        "totalTokens".to_string(),
                        converse_total_tokens(usage).into(),
                    );
                    write_cache_usage(&mut usage_obj, usage);
                    Some((
                        ET_METADATA.to_string(),
                        serde_json::json!({ "usage": usage_obj }),
                    ))
                }
            },

            IrStreamEvent::MessageStop => None,

            // A mid-stream error on the Bedrock-ingress path. The fully native representation is an
            // AWS modeled-exception EVENT-STREAM frame (`:message-type: exception` +
            // `:exception-type: <ExceptionName>`), which `StreamTranslate` now emits via
            // `write_response_exception` + `eventstream::encode_exception_frame` BEFORE reaching this
            // arm (a Bedrock-ingress stream never routes an `Error` through `write_response_event`).
            // This arm therefore only fires if a non-eventstream consumer ever drives a Bedrock
            // writer with an `Error` event; it falls back to a normal `event`-typed frame naming a
            // real ConverseStream-output exception (via `bedrock_stream_exception_for`, the five-member
            // stream union — NOT the request-level HTTP set) so the type token is still a genuine AWS
            // stream-event name rather than the literal `"error"` or a non-stream request shape.
            IrStreamEvent::Error(err) => {
                let (exception_name, message) = bedrock_stream_exception_for(err);
                Some((
                    exception_name.to_string(),
                    serde_json::json!({ "message": message }),
                ))
            }
        }
    }

    /// A Converse `citation` delta carries ONE citation, so a delta holding several must frame as
    /// several events at the same `contentBlockIndex` — which is exactly how a native ConverseStream
    /// interleaves them. The framing seam splits multi-citation deltas on their way to the writer
    /// (`max_citations_per_delta`), but it is not the only caller (the plane codec drives
    /// `write_response_events` directly), and a batch that arrives whole here must emit all of its
    /// citations rather than silently keep the first. Each is framed by re-entering the single-frame
    /// arm with a one-citation delta, so that arm stays the ONE source of truth for the `citation`
    /// delta's shape. Every other event keeps the base wrapper's one-frame behaviour.
    fn write_response_events(&self, ev: &IrStreamEvent) -> Vec<(String, serde_json::Value)> {
        if let IrStreamEvent::BlockDelta {
            index,
            delta: crate::ir::IrDelta::CitationsDelta(cits),
        } = ev
        {
            if cits.len() > 1 {
                return cits
                    .iter()
                    .filter_map(|c| {
                        self.write_response_event(&IrStreamEvent::BlockDelta {
                            index: *index,
                            delta: crate::ir::IrDelta::CitationsDelta(vec![c.clone()]),
                        })
                    })
                    .collect();
            }
        }
        self.write_response_event(ev).into_iter().collect()
    }

    /// A Bedrock-ingress stream signals a mid-stream error with a MODELED-EXCEPTION event-stream
    /// frame (`:message-type: exception`), which `StreamTranslate` emits via
    /// `eventstream::encode_exception_frame`. This maps the IR error to that frame's
    /// `(exception_name, message)` using `bedrock_stream_exception_for` — the FIVE-member
    /// ConverseStream output-union (`InternalServerException`, `ModelStreamErrorException`,
    /// `ValidationException`, `ThrottlingException`, `ServiceUnavailableException`), NOT the larger
    /// request-level HTTP exception set — so a native AWS SDK stream decoder always recognizes the
    /// `:exception-type` as a modeled stream event. Shares the mapping with the (fallback)
    /// `write_response_event` Error arm so both stay consistent.
    fn write_response_exception(
        &self,
        err: &busbar_substrate_values::proto::IrError,
    ) -> Option<(String, String)> {
        let (exception_name, message) = bedrock_stream_exception_for(err);
        Some((exception_name.to_string(), message))
    }

    fn write_error_frame(
        &self,
        err: &busbar_substrate_values::proto::IrError,
    ) -> Option<(String, serde_json::Value)> {
        // The streaming-error seam. A Bedrock-INGRESS stream never reaches here — its mid-stream
        // error is a modeled-exception event-stream frame emitted via `write_response_exception`
        // before the SSE framer runs. This override exists for a non-eventstream consumer driving a
        // Bedrock writer, and delegates to the `write_response_event` Error arm (the documented
        // fallback) so the two stay byte-identical.
        self.write_response_event(&IrStreamEvent::Error(err.clone()))
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let _t = busbar_timing::timeit!("bedrock_write_response");
        let mut content_arr: Vec<serde_json::Value> = Vec::new();

        for block in &resp.content {
            match block {
                crate::ir::IrBlock::Text {
                    text, citations, ..
                } => {
                    if text.is_empty() {
                        continue;
                    }
                    // Grounding citations, in Converse's native `citationsContent` slot — the
                    // BUFFERED twin of the `contentBlockDelta.citation` frame the streaming arm
                    // emits. Without it a Bedrock-ingress client got sources when it asked to stream
                    // and none when it did not, which is the same request-shape-dependent asymmetry
                    // the streaming gap was, only inverted.
                    //
                    // `citationsContent` REPLACES the plain `text` member for this block (the union
                    // carries the text INSIDE it, alongside the citations), so it is emitted only
                    // when at least one citation actually projects — a text block with no citations
                    // keeps the plain `{"text": …}` shape every existing consumer expects.
                    let cits: Vec<serde_json::Value> = citations
                        .iter()
                        .filter_map(super::write_bedrock_citation)
                        .collect();
                    if cits.is_empty() {
                        if !citations.is_empty() {
                            tracing::warn!(
                                dropped = citations.len(),
                                "dropping citation(s) on a bedrock response egress: none carried a \
                                 title, url, quoted text or resolvable character location, so there \
                                 is no populated member for the Converse `Citation` shape"
                            );
                        }
                        content_arr.push(serde_json::json!({ "text": text }));
                    } else {
                        content_arr.push(serde_json::json!({
                            "citationsContent": {
                                "content": [{ "text": text }],
                                "citations": cits
                            }
                        }));
                    }
                }

                // A model does not emit an attachment back on the Converse response surface.
                crate::ir::IrBlock::Media { .. } => {}

                crate::ir::IrBlock::ToolUse {
                    id, name, input, ..
                } => {
                    content_arr.push(serde_json::json!({
                        "toolUse": {
                            "toolUseId": id,
                            "name": name,
                            "input": input
                        }
                    }));
                }

                crate::ir::IrBlock::Image { source, .. } => {
                    // An assistant response CAN legitimately carry an Image block (e.g. a
                    // cross-protocol egress whose source emitted an image in the model turn).
                    // Bedrock Converse natively represents it as an `{"image": ...}` content block.
                    // A source kind with no native Bedrock projection (URL / file_id) returns `None`
                    // and is omitted with a trace by the helper, never corrupting the block.
                    if let Some(image_block) = bedrock_image_block(source) {
                        content_arr.push(serde_json::json!({ "image": image_block }));
                    }
                }
                crate::ir::IrBlock::Json(_) => {
                    // Structured-json content has no top-level Bedrock response shape (it is only a
                    // tool-result content member); omit it from an assistant response turn.
                }

                crate::ir::IrBlock::Thinking {
                    text,
                    signature,
                    redacted,
                    ..
                } => {
                    // Re-emit the model's reasoning as a native Converse `reasoningContent` block
                    // (the inverse of `read_response`'s reasoningContent decode), instead of silently
                    // dropping it. A same-protocol passthrough reproduces the thinking block, and a
                    // cross-protocol egress that carried reasoning into the IR can surface it. The
                    // redacted-signature sentinel re-emits `redactedContent`; any other Thinking
                    // re-emits `reasoningText`.
                    content_arr.push(bedrock_reasoning_block(text, signature, *redacted));
                }

                // A `toolResult` is a USER-turn content block in Bedrock Converse; it has no place
                // in an ASSISTANT response message, so it is the only genuine no-op here. Handled
                // explicitly — no catch-all.
                crate::ir::IrBlock::ToolResult { .. } => {}
            }
        }

        // Bedrock Converse rejects an assistant message with an empty `content` array
        // (ValidationException), exactly as `write_request` guards every turn. A response whose
        // blocks were ALL non-representable here (e.g. thinking-only, or a stray toolResult) would
        // otherwise emit `content: []`. Mirror the request-side guard with a minimal placeholder
        // text block so the body stays valid.
        if content_arr.is_empty() {
            content_arr.push(serde_json::json!({ "text": "" }));
        }

        // IR-16 (BED-10): a context-window detail is Converse's own `model_context_window_exceeded`.
        let reverse_reason = stop_reason_reverse_detailed(
            resp.stop_reason.unwrap_or(crate::ir::IrStopReason::EndTurn),
            resp.stop_detail.as_ref(),
        );

        // Identity emission. The native AWS Converse response body (the shape the official SDK
        // deserializes — `output` / `stopReason` / `usage` / optional `metrics`) carries NO id or
        // `created` field; AWS returns the request id only in the `x-amzn-RequestId` HTTP header.
        // Injecting a synthesized `id`/`created` into the JSON body would therefore be a
        // proxy-tell, not fidelity — so we deliberately do NOT add one. (The inverse direction — a
        // Bedrock egress feeding an OpenAI/Anthropic ingress that DOES require a body id — is the
        // job of that ingress writer, not this one; no Bedrock-side id synthesizer is wired into the
        // production path, so none is shipped.) `stopReason` and `usage` (the only identity-bearing
        // fields Bedrock emits) are reproduced exactly from the captured IR below, so a
        // same-protocol round-trip is byte-identical.
        let mut usage_obj = serde_json::Map::new();
        usage_obj.insert("inputTokens".to_string(), resp.usage.input_tokens.into());
        usage_obj.insert("outputTokens".to_string(), resp.usage.output_tokens.into());
        // Cache-inclusive and saturating, same as the streaming `metadata` frame — see
        // `converse_total_tokens`. This is what keeps the same-protocol round-trip promised just
        // above byte-identical when the upstream reported cache tokens.
        usage_obj.insert(
            "totalTokens".to_string(),
            converse_total_tokens(&resp.usage).into(),
        );
        write_cache_usage(&mut usage_obj, &resp.usage);

        serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": content_arr
                }
            },
            "stopReason": reverse_reason,
            "usage": usage_obj
        })
    }

    /// Native AWS Bedrock Converse error envelope. The Converse error model (REST-JSON protocol)
    /// serializes every modeled exception as a flat body whose human-readable detail lives in a
    /// lowercase `"message"` member, with the machine-readable exception name in `"__type"` (the
    /// exact two fields `BedrockReader::extract_error` reads back). A native AWS SDK deserializes
    /// the typed exception from `__type` and surfaces the text from `message`; serving the generic
    /// `{"error":{...}}` envelope here would make a Bedrock SDK fail to decode the error. We map
    /// busbar's generic `kind` to the closed AWS exception set via `error_kind_to_bedrock_type` so
    /// the `__type` is always a real Converse exception name. Served as `application/json`.
    fn write_error(&self, _status: u16, kind: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "__type": error_kind_to_bedrock_type(kind),
            "message": message,
        })
    }

    fn attach_error_response_headers(
        &self,
        headers: &mut http::HeaderMap,
        kind: &str,
        _envelope: &serde_json::Value,
    ) {
        // A real AWS Bedrock runtime response ALWAYS carries `x-amzn-RequestId` (the only request-id
        // surface the AWS SDK exposes via `*Output::request_id()`) and `x-amzn-errortype` == the body
        // `__type`. Omitting them was distinguishable from native Bedrock and left the SDK request id
        // empty on the most-exercised failover error surface.
        attach_bedrock_error_headers(headers, kind);
    }

    fn new_stream_framing(&self) -> Box<dyn super::StreamFraming> {
        // Bedrock-ingress per-stream framing: the messageStop/metadata two-frame deferral and the
        // exactly-one-metadata invariant. Lives here, in the Bedrock module, so the agnostic
        // translator names no Bedrock wire shape.
        Box::<BedrockStreamFraming>::default()
    }

    fn wrap_buffered_as_stream(
        &self,
        ir: &crate::ir::IrResponse,
        elapsed_ms: Option<u64>,
    ) -> Option<Vec<u8>> {
        // A Bedrock-ingress client that requested ConverseStream but received a buffered (non-SSE)
        // 2xx response from the upstream must get a native binary eventstream frame sequence, not a
        // bare `application/json` Converse body that the SDK's eventstream decoder cannot parse
        // (hard decode failure and a deterministic proxy tell). Delegate to the module-local free fn
        // which synthesizes the full frame sequence through this same writer — the call sites now
        // dispatch through the vtable instead of branching on `ingress_protocol == "bedrock"`.
        Some(bedrock_response_to_eventstream(ir, elapsed_ms))
    }

    fn inject_response_metrics(&self, value: &mut serde_json::Value, elapsed_ms: Option<u64>) {
        // A native AWS Bedrock Converse (non-stream) response ALWAYS populates `metrics.latencyMs`
        // (the SDK surfaces it via `ConverseOutput::metrics().latency_ms()`, and the service model
        // marks the member required). The bedrock writer's `write_response` deliberately omits it
        // (timing is unknown at that layer); inject the real request elapsed wall-clock here. A
        // body that already carries a well-formed `metrics` keeps it, and the member is emitted
        // even when timing is unavailable — the same policy as the streaming `metadata` frame.
        super::ensure_metrics(value, elapsed_ms);
    }

    fn same_protocol_buffered_response_translator(
        &self,
    ) -> Option<Box<dyn busbar_substrate_values::proto::StreamTranslator>> {
        // A Bedrock -> Bedrock non-stream response used to relay verbatim, so a Converse body whose
        // upstream omitted `metrics` reached the client without its required member (the only
        // Converse response busbar served that way; every cross-protocol lane injects it above).
        // The translator buffers the body and completes it at end-of-stream.
        Some(Box::new(super::BedrockConverseBodyTranslator::new()))
    }

    fn ingress_response_request_id(
        &self,
        upstream_request_id: Option<&str>,
    ) -> Option<(&'static str, String)> {
        // A real ConverseStream/Converse response carries `x-amzn-RequestId`. Forward the captured
        // upstream id verbatim on a same-protocol passthrough (the streaming path captures one);
        // synthesize otherwise (the non-stream/cross-protocol case supplies `None`). Identical to the
        // prior inline `upstream_amzn_id.or_else(synth_amzn_request_id)` / synth-only attaches.
        // Synthesis failure (no entropy) omits the header rather than panicking.
        upstream_request_id
            .map(String::from)
            .or_else(synth_amzn_request_id)
            .map(|id| (HDR_AMZN_REQUEST_ID, id))
    }

    /// IR-18: a Converse `reasoningText.signature` is read back as Claude's or the Bedrock model's
    /// own (the reader tells the two apart by the conversation's model id).
    fn reads_signature_origin_as_own(&self, origin: crate::ir::IrSignatureOrigin) -> bool {
        matches!(
            origin,
            crate::ir::IrSignatureOrigin::Anthropic | crate::ir::IrSignatureOrigin::BedrockOther
        )
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}

impl BedrockWriter {
    /// The request write for a lane with the declared [`LaneCaps`] (the model gate has already
    /// run — see `write_request_for_lane`). `write_request` is this with the default capabilities.
    fn write_request_with(&self, req: &crate::ir::IrRequest, caps: &LaneCaps) -> serde_json::Value {
        let _t = busbar_timing::timeit!("bedrock_write_request");
        let mut out = serde_json::Map::new();

        // The captured native `cachePoint` markers (see `CACHE_POINTS_SENTINEL`). On a same-protocol
        // passthrough this carries the prompt-cache markers the reader stashed; on cross-protocol
        // egress `extra` is cleared so this is absent and no Bedrock-only marker leaks onto a foreign
        // wire. Borrowed once here; the `system`/`messages` sub-arrays are spliced back below and the
        // sentinel is then SKIPPED by the trailing extra-merge so it never reaches the wire.
        let cache_points = req
            .extra
            .get(CACHE_POINTS_SENTINEL)
            .and_then(|v| v.as_object());
        let system_cache_points = cache_points
            .and_then(|cp| cp.get("system"))
            .and_then(|v| v.as_array());
        let message_cache_points = cache_points
            .and_then(|cp| cp.get("messages"))
            .and_then(|v| v.as_array());

        // The captured native `guardContent` markers (see `GUARD_CONTENT_SENTINEL`); same stash
        // shape as the cachePoint markers and spliced back via the same shared helper. Consumed here
        // and SKIPPED by the trailing extra-merge so the sentinel never reaches the wire.
        let guard_content = req
            .extra
            .get(GUARD_CONTENT_SENTINEL)
            .and_then(|v| v.as_object());
        let system_guard_content = guard_content
            .and_then(|gc| gc.get("system"))
            .and_then(|v| v.as_array());
        let message_guard_content = guard_content
            .and_then(|gc| gc.get("messages"))
            .and_then(|v| v.as_array());

        // The captured native top-level `document` / `video` markers (see `DOC_VIDEO_SENTINEL`);
        // same positional stash shape as the guardContent markers and spliced back via the same
        // shared helper. Consumed here and SKIPPED by the trailing extra-merge so the sentinel never
        // reaches the wire. Only messages carry document/video (no `system` sub-array).
        let doc_video = req
            .extra
            .get(DOC_VIDEO_SENTINEL)
            .and_then(|v| v.as_object());
        let message_doc_video = doc_video
            .and_then(|dv| dv.get("messages"))
            .and_then(|v| v.as_array());

        // When the positional cachePoint stash is present (same-protocol Bedrock passthrough) it is
        // the authority for cachePoint placement (spliced below at the recorded indices for a
        // byte-identical round-trip), so the inline `cache_control`-driven emission is SUPPRESSED to
        // avoid emitting the same marker twice. On the cross-protocol seam `extra` is cleared, so the
        // stash is absent and the inline emission (from the first-class IR `cache_control`) is the
        // sole carrier — projecting an Anthropic cache breakpoint onto a native Bedrock cachePoint.
        let emit_inline_system_cache = system_cache_points.is_none();
        if !req.system.is_empty() || system_cache_points.is_some() || system_guard_content.is_some()
        {
            let mut text_arr: Vec<serde_json::Value> = Vec::new();
            // System blocks the reader MODELLED out of a stashed `guardContent` (BED-02): the stash
            // splice below re-emits the verbatim block, so the modelled copy is not written.
            let guard_modelled = stashed_ir_indices([system_guard_content], None);
            for (sys_idx, block) in req.system.iter().enumerate() {
                if guard_modelled.contains(&sys_idx) {
                    continue;
                }
                if let crate::ir::IrBlock::Text {
                    text,
                    cache_control,
                    ..
                } = block
                {
                    text_arr.push(serde_json::json!({ "text": text }));
                    // Emit a Bedrock `cachePoint` AFTER the block that carries the IR
                    // `cache_control` boundary (the position Bedrock expects — the breakpoint closes
                    // the prefix before it). Suppressed when the positional stash owns placement.
                    if emit_inline_system_cache && cache_control.is_some() {
                        text_arr.push(bedrock_cache_point());
                    }
                }
            }

            // Re-emit any captured `cachePoint` / `guardContent` markers at their original
            // positions so prompt caching and inline guardrails survive a same-protocol round-trip
            // instead of being silently dropped. BOTH marker classes recorded indices against the
            // SAME original array, so they must be spliced as ONE sorted batch (the helper sorts by
            // index): splicing them in two passes would let the first pass's insertions shift the
            // second pass's recorded indices off by one. `merge_marker_entries` concatenates the two
            // `{ "i", "block" }` lists for a single ascending splice.
            let merged = merge_marker_entries(system_cache_points, system_guard_content);
            splice_cache_points(&mut text_arr, &merged);

            if !text_arr.is_empty() {
                out.insert("system".to_string(), serde_json::Value::Array(text_arr));
            }
        }

        // Same suppression gate as the system array (above): when the positional message-cachePoint
        // stash is present it owns placement (byte-identical same-protocol round-trip), so inline
        // `cache_control`-driven emission is suppressed; cross-protocol (stash cleared) it is the sole
        // carrier of the prompt-cache boundary.
        let emit_inline_message_cache = message_cache_points.is_none();
        let mut msgs_arr: Vec<serde_json::Value> = Vec::new();
        for (msg_idx, msg) in req.messages.iter().enumerate() {
            let role_str = match msg.role {
                crate::ir::IrRole::User => "user",
                crate::ir::IrRole::Assistant => "assistant",
                // A Tool-role IR message carries `toolResult` blocks; Bedrock Converse has no
                // freestanding "tool" role — a tool result is a `toolResult` content block inside a
                // USER-turn message, so mapping Tool → "user" is the correct native wire shape.
                crate::ir::IrRole::Tool => "user",
                // System text is extracted by the caller into `req.system` (emitted as the top-level
                // `system` array above), so a System-role MESSAGE should never reach the Bedrock
                // wire. If one somehow escapes extraction, skip it rather than silently mislabeling
                // it as a "user" turn (which would inject system instructions as a user message and
                // corrupt the conversation). Each role is handled explicitly — no catch-all.
                crate::ir::IrRole::System => continue,
            };

            let mut content_arr: Vec<serde_json::Value> = Vec::new();
            // IR blocks the reader MODELLED out of a wire block it ALSO parked verbatim (a
            // `document` / `video` / `guardContent`), keyed by the reader's IR index `b`.
            let stashed_here =
                stashed_ir_indices([message_doc_video, message_guard_content], Some(msg_idx));
            for (block_idx, block) in msg.content.iter().enumerate() {
                // A block the READER also parked verbatim (under `DOC_VIDEO_SENTINEL` or
                // `GUARD_CONTENT_SENTINEL`) at this exact (message, block) position. The stash is
                // spliced back below, so writing the modelled projection here TOO would emit it twice.
                // Suppress the modelled emit and let the verbatim raw block win — that is what keeps
                // a Bedrock->Bedrock round-trip byte-identical (every sub-field, `citations` /
                // `context` / guard `qualifiers` included, survives) while a CROSS-protocol IR, whose
                // `extra` the seam cleared, has no stash and so takes the modelled path.
                // Matched on `b`, the IR block index the reader recorded, NOT on `i`, which is the
                // WIRE slot the raw block is spliced back at. The two differ by however many
                // wire-only blocks (`cachePoint`) came first in this message, so comparing the wire
                // index against `block_idx` here missed the match and emitted the attachment twice
                // — modelled AND spliced. `i` remains the splice position below.
                if stashed_here.contains(&block_idx) {
                    continue;
                }
                // The prompt-cache boundary carried on this block, if any. Emitted as a
                // `cachePoint` block IMMEDIATELY AFTER the block below (the position Bedrock expects).
                // Suppressed when the positional stash owns placement (same-protocol passthrough).
                // BED-07: Thinking / Image / Media carry a boundary too (an Anthropic breakpoint on a
                // reasoning block or an attachment), so they project a `cachePoint` like Text does.
                let block_cache_control = match block {
                    crate::ir::IrBlock::Text { cache_control, .. }
                    | crate::ir::IrBlock::ToolUse { cache_control, .. }
                    | crate::ir::IrBlock::ToolResult { cache_control, .. }
                    | crate::ir::IrBlock::Thinking { cache_control, .. }
                    | crate::ir::IrBlock::Image { cache_control, .. }
                    | crate::ir::IrBlock::Media { cache_control, .. } => cache_control.as_ref(),
                    crate::ir::IrBlock::Json(_) => None,
                };
                // The block's projection may be NOTHING (an image with no Converse source, an audio
                // attachment); a cachePoint is only placed after a block that was actually written.
                let written_before = content_arr.len();
                match block {
                    crate::ir::IrBlock::Text {
                        text, citations, ..
                    } => {
                        // BED-13: a cited (assistant-history) text block is Converse's
                        // `citationsContent` — the answer text INSIDE it beside its citations, the
                        // same projection the response writer uses. Uncited text keeps `{text}`.
                        let cits: Vec<serde_json::Value> = citations
                            .iter()
                            .filter_map(super::write_bedrock_citation)
                            .collect();
                        if cits.is_empty() {
                            content_arr.push(serde_json::json!({ "text": text }));
                        } else {
                            content_arr.push(serde_json::json!({
                                "citationsContent": {
                                    "content": [{ "text": text }],
                                    "citations": cits
                                }
                            }));
                        }
                    }
                    crate::ir::IrBlock::ToolUse {
                        id, name, input, ..
                    } => {
                        content_arr.push(serde_json::json!({"toolUse": {"toolUseId": id, "name": name, "input": input}}));
                    }
                    crate::ir::IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                        ..
                    } => {
                        let mut inner_content: Vec<serde_json::Value> = Vec::new();
                        for inner_block in content {
                            match inner_block {
                                crate::ir::IrBlock::Text { text, .. } => {
                                    inner_content.push(serde_json::json!({ "text": text }));
                                }
                                // Bedrock Converse natively supports structured tool-result content
                                // via a `{"json": <value>}` block (the inverse of what `read_request`
                                // decodes). Preserve the actual content instead of collapsing it to
                                // the constant string `"{}"`: a JSON-string Text-equivalent or a
                                // structured result that arrives via the IR is re-encoded faithfully.
                                crate::ir::IrBlock::Json(value) => {
                                    // A structured-json tool-result block re-emits as a native
                                    // `{"json": <value>}` block, restoring same-protocol fidelity.
                                    inner_content.push(serde_json::json!({ "json": value }));
                                }
                                crate::ir::IrBlock::Image { source, .. } => {
                                    if let Some(image_block) = bedrock_image_block(source) {
                                        inner_content
                                            .push(serde_json::json!({ "image": image_block }));
                                    }
                                }
                                crate::ir::IrBlock::ToolUse {
                                    id, name, input, ..
                                } => {
                                    // Nested ToolUse inside a tool result has no native Bedrock
                                    // tool-result shape; carry it as a structured `json` block rather
                                    // than discarding the call identity.
                                    inner_content.push(serde_json::json!({
                                        "json": { "toolUseId": id, "name": name, "input": input }
                                    }));
                                }
                                crate::ir::IrBlock::ToolResult {
                                    tool_use_id,
                                    is_error,
                                    ..
                                } => {
                                    // A tool result nested inside another tool result is not a native
                                    // Bedrock shape; preserve its identity as a `json` block instead
                                    // of emitting a meaningless `"{}"` placeholder.
                                    inner_content.push(serde_json::json!({
                                        "json": { "toolUseId": tool_use_id, "isError": is_error }
                                    }));
                                }
                                // Thinking blocks have no representable Bedrock tool-result shape and
                                // carry no result data; omit them entirely (with a trace) rather than
                                // emitting a misleading placeholder block.
                                crate::ir::IrBlock::Thinking { .. } => {
                                    tracing::warn!(
                                        "dropping non-representable Thinking block inside a Bedrock toolResult"
                                    );
                                }
                                // Converse's `ToolResultContentBlock` union is
                                // {json, text, image, document, video} — the SAME document/video
                                // members the top-level content block has, so an attachment returned
                                // BY a tool projects natively here too.
                                crate::ir::IrBlock::Media {
                                    kind,
                                    source,
                                    name,
                                    citations,
                                    context,
                                    ..
                                } => {
                                    if let Some(b) = bedrock_media_content_block(
                                        *kind,
                                        source,
                                        name.as_deref(),
                                        *citations,
                                        context.as_deref(),
                                    ) {
                                        inner_content.push(b);
                                    }
                                }
                            }
                        }

                        let status_str = if *is_error { "error" } else { "success" };
                        content_arr.push(serde_json::json!({"toolResult": {"toolUseId": tool_use_id, "content": inner_content, "status": status_str}}));
                    }
                    crate::ir::IrBlock::Image { source, .. } => {
                        if let Some(image_block) = bedrock_image_block(source) {
                            content_arr.push(serde_json::json!({ "image": image_block }));
                        }
                    }
                    crate::ir::IrBlock::Thinking {
                        text,
                        signature,
                        redacted,
                        signature_origin,
                        ..
                    } => {
                        // Re-emit the assistant turn's reasoning as a native Converse
                        // `reasoningContent` block (the inverse of `read_request`'s reasoningContent
                        // decode). The old writer dropped every Thinking block here, so a
                        // bedrock->bedrock passthrough lost the signed reasoning Bedrock requires
                        // echoed back on a follow-up turn. The redacted-signature sentinel re-emits
                        // `redactedContent`; any other Thinking re-emits `reasoningText`.
                        // IR-18: a signature another family minted (Gemini `thoughtSignature`,
                        // OpenAI `encrypted_content`) is a foreign blob a Bedrock model rejects, so
                        // only a Claude or Bedrock-minted (or unknown-origin) one is sent.
                        let foreign = matches!(
                            signature_origin,
                            Some(
                                crate::ir::IrSignatureOrigin::Gemini
                                    | crate::ir::IrSignatureOrigin::OpenAi
                            )
                        );
                        if foreign && signature.is_some() {
                            tracing::warn!(
                                origin = ?signature_origin,
                                "dropping a reasoning signature on Bedrock egress: another model \
                                 family minted it"
                            );
                        }
                        let signature = if foreign { &None } else { signature };
                        content_arr.push(bedrock_reasoning_block(text, signature, *redacted));
                    }
                    crate::ir::IrBlock::Media {
                        kind,
                        source,
                        name,
                        citations,
                        context,
                        ..
                    } => {
                        if let Some(b) = bedrock_media_content_block(
                            *kind,
                            source,
                            name.as_deref(),
                            *citations,
                            context.as_deref(),
                        ) {
                            content_arr.push(b);
                        }
                    }
                    crate::ir::IrBlock::Json(_) => {
                        // Structured-json content is only a tool-result content member; it has no
                        // top-level message-content shape, so omit it from a message turn.
                    }
                }
                // Emit the prompt-cache boundary as a `cachePoint` block right after the block it
                // applies to; a block whose write produced nothing (e.g. a dropped Image) emits none.
                // Suppressed when the positional stash owns placement (same-protocol round-trip).
                if emit_inline_message_cache
                    && block_cache_control.is_some()
                    && content_arr.len() > written_before
                {
                    content_arr.push(bedrock_cache_point());
                }
            }

            // Re-emit any captured `cachePoint` / `guardContent` / `document` / `video` markers for
            // THIS message at their original positions so prompt caching, inline guardrails and
            // document/video attachments survive a same-protocol round-trip. Spliced BEFORE the
            // empty-content placeholder below so a message whose only block was one of these re-emits
            // the marker rather than a bare `""` placeholder. `msg_idx` matches the reader's recorded
            // message index on the Bedrock passthrough path (the Bedrock reader only emits
            // User/Assistant turns, so no System-role `continue` desyncs the count). ALL classes are
            // collected for this message and spliced as ONE sorted batch (they recorded indices
            // against the SAME original content array) so one class's insertions cannot shift
            // another's recorded indices.
            let for_this_msg: Vec<serde_json::Value> = message_cache_points
                .into_iter()
                .chain(message_guard_content)
                .chain(message_doc_video)
                .flatten()
                .filter(|e| e.get("m").and_then(|v| v.as_u64()) == Some(msg_idx as u64))
                .cloned()
                .collect();
            if !for_this_msg.is_empty() {
                splice_cache_points(&mut content_arr, &for_this_msg);
            }

            // Bedrock Converse requires strictly ALTERNATING user/assistant turns — two
            // consecutive messages of the same role are a 400 ValidationException. After the
            // Tool→"user" role mapping above, common IR shapes produce consecutive "user" turns: a
            // Tool-result turn followed by a real user turn, or several tool results that arrived as
            // separate Tool messages ([Assistant(tool_use…), Tool(result1), Tool(result2)] →
            // assistant,user,user). Coalesce this turn INTO the previous emitted message when they
            // share a role, so the wire conversation always alternates. On a same-protocol Bedrock
            // passthrough the input already alternates, so this never fires and byte-identity holds.
            if let Some(prev_content) = msgs_arr
                .last_mut()
                .filter(|last| last.get("role").and_then(|r| r.as_str()) == Some(role_str))
                .and_then(|last| last.get_mut("content"))
                .and_then(|c| c.as_array_mut())
            {
                // Merge: append this turn's blocks to the previous same-role message. An empty
                // content_arr appends nothing (no stray placeholder needed — the turn is absorbed).
                prev_content.append(&mut content_arr);
                continue;
            }

            // A user/assistant/tool turn whose blocks were ALL non-representable (e.g. a
            // thinking-only assistant message, or a block kind that produced nothing above)
            // would otherwise yield an empty `content_arr`. Dropping the whole message loses
            // turn structure and can break strict user/assistant alternation that Bedrock
            // Converse enforces (a 400 ValidationException). Mirror the Anthropic writer
            // (`write_message`/`write_block`, which emit `""` for an empty content body) by
            // substituting a minimal placeholder text block so the turn survives the seam.
            // System-role messages never reach here (they `continue` during role mapping).
            if content_arr.is_empty() {
                content_arr.push(serde_json::json!({ "text": "" }));
            }
            let mut msg_obj = serde_json::Map::new();
            msg_obj.insert("role".to_string(), serde_json::json!(role_str));
            msg_obj.insert("content".to_string(), serde_json::Value::Array(content_arr));
            msgs_arr.push(serde_json::Value::Object(msg_obj));
        }

        if !msgs_arr.is_empty() {
            out.insert("messages".to_string(), serde_json::Value::Array(msgs_arr));
        }

        // Rebuild `inferenceConfig` by OVERLAYING the two typed fields (`maxTokens`/`temperature`)
        // onto the RAW `inferenceConfig` object the reader captured into `extra`. This preserves
        // every sub-field the reader does not model (`stopSequences`, `topP`, `topK`, `stopCriteria`,
        // future AWS additions) on a same-protocol passthrough while still letting a cross-protocol
        // egress (where `extra` carries no `inferenceConfig`) emit a config built purely from the
        // typed IR. The typed fields WIN over any same-named raw entry so the structured IR remains
        // the source of truth for the values it models. `extra`'s raw `inferenceConfig` is consumed
        // here (not re-emitted by the trailing extra-merge), so there is no double-emit.
        // BED-06: the reasoning ASK projects onto `additionalModelRequestFields` in the
        // Anthropic-on-Bedrock spelling (Claude is the Converse family whose reasoning a
        // cross-protocol caller reaches; `write_request_for_lane` strips the ask for any other
        // family). A raw native ask already in `extra` (a same-protocol body: `thinking`,
        // `output_config.effort` or Nova `reasoningConfig`) is authoritative and re-emitted verbatim
        // below, so nothing is synthesized over it. The forms mirror the Anthropic writer:
        //   * a WORD ask (or "model decides") on a lane declaring adaptive thinking
        //     (`LaneCaps::anthropic_adaptive_thinking` — the only on-mode the newest Claude models
        //     accept; `budget_tokens` 400s there) → `thinking: {type: "adaptive"}` plus
        //     `output_config.effort` (no effort word is invented for "model decides");
        //   * `Off` (IR-09) → `thinking: {type: "disabled"}`, matched BEFORE any budget projection
        //     (which would read it as the smallest ENABLE ask);
        //   * every other ask → `{type: "enabled", budget_tokens}`, clamped to leave 1024 answer
        //     tokens under `maxTokens`, floored at the 1024 minimum, and dropped with a warn when
        //     `maxTokens` has no room for it.
        let native_reasoning_present = req
            .extra
            .get("additionalModelRequestFields")
            .and_then(|v| v.as_object())
            .is_some_and(|a| {
                a.contains_key("thinking")
                    || a.contains_key("reasoningConfig")
                    || a.get("output_config")
                        .is_some_and(|c| c.get("effort").is_some())
            });
        let mut thinking: Option<serde_json::Value> = None;
        let mut effort_word: Option<&'static str> = None;
        let mut thinking_disabled = false;
        match req.reasoning.filter(|_| !native_reasoning_present) {
            None => {}
            // A lane whose Claude model cannot switch thinking off (`LaneCaps::thinking_always_on`,
            // round 3 item 12) rejects `{type:"disabled"}`: omitted with a warn.
            Some(crate::ir::IrReasoningAsk::Off) if caps.thinking_always_on => {
                tracing::warn!(
                    "omitting reasoning OFF on Bedrock egress: this lane's model cannot switch \
                     thinking off (thinking_always_on) and rejects thinking.type \"disabled\""
                );
            }
            Some(crate::ir::IrReasoningAsk::Off) => thinking_disabled = true,
            Some(crate::ir::IrReasoningAsk::Effort(effort)) if caps.anthropic_adaptive_thinking => {
                thinking = Some(serde_json::json!({ "type": super::THINKING_TYPE_ADAPTIVE }));
                effort_word = Some(super::bedrock_claude_effort_word(effort));
            }
            Some(crate::ir::IrReasoningAsk::Dynamic) if caps.anthropic_adaptive_thinking => {
                thinking = Some(serde_json::json!({ "type": super::THINKING_TYPE_ADAPTIVE }));
            }
            Some(ask) => {
                let table = req
                    .reasoning_budgets
                    .unwrap_or(crate::ir::REASONING_BUDGET_DEFAULTS);
                let want = ask.to_budget(table);
                let cap = req.max_tokens.map(|mt| mt.saturating_sub(1024));
                let budget = cap.map_or(want, |c| want.min(c));
                if budget >= 1024 {
                    if budget != want {
                        tracing::warn!(
                            requested_budget = want,
                            clamped_budget = budget,
                            max_tokens = ?req.max_tokens,
                            "thinking budget clamped to fit under maxTokens on Bedrock egress"
                        );
                    }
                    thinking =
                        Some(serde_json::json!({"type": "enabled", "budget_tokens": budget}));
                } else {
                    tracing::warn!(
                        max_tokens = ?req.max_tokens,
                        "dropping reasoning ask on Bedrock egress: maxTokens leaves no room for the \
                         1024-token thinking minimum"
                    );
                }
            }
        }
        let thinking_emitted = thinking.is_some();

        let mut inference_config = req
            .extra
            .get("inferenceConfig")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(max_tokens) = req.max_tokens {
            inference_config.insert("maxTokens".to_string(), serde_json::json!(max_tokens));
        }
        if thinking_emitted && req.temperature.is_some_and(|t| t != 1.0) {
            // Claude rejects a temperature != 1 alongside thinking; the think-ask wins, observably.
            tracing::warn!(
                temperature = ?req.temperature,
                "omitting temperature on Bedrock egress: not compatible with thinking"
            );
        }
        if let Some(temperature) = req.temperature.filter(|_| !thinking_emitted) {
            // Clamp to Bedrock's native [0.0, 1.0]. OpenAI / Responses accept temperature up
            // to 2.0, so a cross-protocol request can carry a value Bedrock's API rejects with a hard
            // 400 ValidationException; clamping forwards the closest valid value instead. NON-SILENT
            // (mirrors the Anthropic writer): warn ONLY when the clamp actually changed the value, so
            // the divergence is visible in logs rather than silently rewriting a caller's temperature.
            let (clamped, was_clamped) = clamp_temperature_for_bedrock(temperature);
            if was_clamped {
                tracing::warn!(
                    requested_temperature = temperature,
                    clamped_temperature = clamped,
                    "clamping temperature to Bedrock's [0.0, 1.0] range; the requested value was \
                     out of range and would be rejected with a 400 ValidationException",
                );
            }
            inference_config.insert("temperature".to_string(), serde_json::json!(clamped));
        }
        // Promoted sampling controls overlaid in Bedrock's inferenceConfig shape (typed IR wins over
        // the raw captured value, so same-protocol round-trips re-emit the identical value and
        // cross-protocol egress emits the value carried in the IR). `top_k` has no inferenceConfig
        // home — it is emitted below via `additionalModelRequestFields` (fidelity fix).
        if let Some(top_p) = req.top_p {
            if thinking_emitted {
                tracing::warn!(
                    top_p,
                    "omitting topP on Bedrock egress: not compatible with thinking"
                );
            } else {
                inference_config.insert("topP".to_string(), serde_json::json!(top_p));
            }
        }
        if !req.stop.is_empty() {
            inference_config.insert("stopSequences".to_string(), serde_json::json!(req.stop));
        }

        if !inference_config.is_empty() {
            out.insert(
                "inferenceConfig".to_string(),
                serde_json::Value::Object(inference_config),
            );
        }

        // response_format: Bedrock Converse has NO native top-level `response_format` /
        // structured-output field (structured output is model-specific and rides in
        // `additionalModelRequestFields`, which we do not synthesize here). The reader never sets
        // `response_format` on the same-protocol (Bedrock→Bedrock) path — same-protocol relays the raw
        // upstream body and never reaches this writer — so this only fires for a CROSS-PROTOCOL IR
        // (e.g. an OpenAI/Responses request carrying `response_format`) reaching the Bedrock egress.
        // Dropping it silently is exactly the lossy mutation busbar exists to avoid, so emit a `warn!`
        // so the divergence is observable rather than invisible (mirrors the Anthropic egress). The
        // directive is dropped, not forwarded: there is no native key to carry it on Converse.
        // BED-08: Converse DOES carry structured output natively — `outputConfig.textFormat`
        // (`{type: "json_schema", structure: {jsonSchema: {schema: "<string>", name,
        // description}}}`). A JSON-schema directive projects onto it, overlaid onto any raw
        // `outputConfig` in `extra` (a same-protocol body's own `textFormat` wins — it is what the
        // typed field was read from). Only the forms the `json_schema`-only enum cannot express
        // (schema-less JSON mode, plain text) are dropped, observably.
        let mut output_config = req
            .extra
            .get("outputConfig")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        // Whether that native form may be SENT is a lane capability
        // (`LaneCaps::native_structured_output`, declared per provider / model in the catalog):
        // Converse accepts `outputConfig.textFormat` only on the models AWS lists for structured
        // outputs and rejects it on the rest (a 400 for a request that worked). A lane that does not
        // declare it keeps the pre-structured-output form — the directive is dropped, observably,
        // exactly as 1.5.5 did.
        if let Some(rf) = &req.response_format {
            match super::write_bedrock_text_format(rf) {
                // A same-protocol body's own raw `textFormat` (what the typed field was read
                // from) is already in place and wins.
                _ if output_config.contains_key("textFormat") => {}
                Some(tf) if caps.native_structured_output => {
                    output_config.entry("textFormat").or_insert(tf);
                }
                Some(_) => {
                    tracing::warn!(
                        parameter = "response_format",
                        "dropping response_format on Bedrock egress: the lane does not declare \
                         native structured outputs (`native_structured_output`), and Converse \
                         rejects `outputConfig.textFormat` on a model without them"
                    );
                }
                None => {
                    tracing::warn!(
                        parameter = "response_format",
                        "dropping response_format on Bedrock egress: Converse's \
                         `outputConfig.textFormat` models only a JSON schema, and this directive \
                         carries none (schema-less JSON mode or plain text)"
                    );
                }
            }
        }
        if !output_config.is_empty() {
            out.insert(
                "outputConfig".to_string(),
                serde_json::Value::Object(output_config),
            );
        }

        // Rebuild `toolConfig` by OVERLAYING the typed `tools` array onto the RAW `toolConfig` object
        // the reader captured into `extra`. This preserves every sub-field the reader does not model —
        // notably `toolChoice` (`{auto:{}}` / `{any:{}}` / `{tool:{name:...}}`, the force-tool-use
        // control) and any future AWS addition — on a same-protocol passthrough while still letting a
        // cross-protocol egress (where `extra` carries no `toolConfig`) emit a config built purely from
        // the typed IR `tools`. The typed `tools` array WINS over any same-named raw entry so the
        // structured IR remains the source of truth for the tools it models. `extra`'s raw `toolConfig`
        // is consumed here (not re-emitted by the trailing extra-merge), so there is no double-emit.
        //
        // The whole `toolConfig` is emitted only when there is something to emit — either typed tools
        // OR a non-empty raw object (e.g. a `toolChoice` with no tools). AWS rejects a `toolConfig`
        // with an empty `tools` array, so we never write a bare `{}`/`{tools:[]}` shape.
        let mut tool_config = req
            .extra
            .get("toolConfig")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        // IR-10: an allowed-tools subset has no Converse directive; the same constraint is
        // expressed by OMISSION — only the listed tools are sent, and the mode rides `toolChoice`
        // (`Auto` → `auto`, `Required` → `any`) below.
        let sent_tools: Vec<&crate::ir::IrTool> = match &req.allowed_tools {
            Some(allowed) => req
                .tools
                .iter()
                .filter(|t| allowed.contains(&t.name))
                .collect(),
            None => req.tools.iter().collect(),
        };
        if !sent_tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in sent_tools {
                let mut tool_spec = serde_json::Map::new();
                tool_spec.insert("name".to_string(), serde_json::json!(tool.name));

                if let Some(desc) = &tool.description {
                    tool_spec.insert("description".to_string(), serde_json::json!(desc));
                }
                // BED-08: Converse `toolSpec.strict` — the per-tool structured-output switch.
                if let Some(strict) = tool.strict {
                    tool_spec.insert("strict".to_string(), serde_json::json!(strict));
                }

                let mut input_schema = serde_json::Map::new();
                input_schema.insert("json".to_string(), tool.input_schema.clone());
                tool_spec.insert(
                    "inputSchema".to_string(),
                    serde_json::Value::Object(input_schema),
                );

                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("toolSpec".to_string(), serde_json::Value::Object(tool_spec));
                tools_arr.push(serde_json::Value::Object(tool_obj));

                // A tool-definition prompt-cache boundary is emitted as a `cachePoint` element in
                // the `toolConfig.tools` array right after the tool it closes (the prefix of tool
                // schemas up to here is cached). Unlike the system/message arrays there is no
                // positional tools-cachePoint stash, so the typed `cache_control` field is the SOLE
                // carrier on BOTH the same-protocol path (the raw `toolConfig.tools` is clobbered by
                // this typed rebuild) and the cross-protocol path — no suppression gate needed.
                if tool.cache_control.is_some() {
                    tools_arr.push(bedrock_cache_point());
                }
            }

            tool_config.insert("tools".to_string(), serde_json::Value::Array(tools_arr));
        }
        // Emit `toolChoice` from the typed IR union. The reader promoted a native `toolChoice`
        // into `req.tool_choice`, but the RAW `toolConfig` cloned from `extra` (same-protocol Bedrock
        // passthrough) still carries the original `toolChoice` key — drop it first so the typed value
        // is the single source of truth and there is no stale duplicate. `IrToolChoice::None` has no
        // native Bedrock representation, so `write_bedrock_tool_choice` returns `None` and no
        // `toolChoice` is emitted in that case.
        tool_config.remove("toolChoice");
        // `toolChoice` is only valid alongside a non-empty `tools` array: Bedrock Converse rejects a
        // `toolConfig` that carries a `toolChoice` with no tools (F3 — ValidationException). So emit
        // the typed tool-choice ONLY when tools are present (typed `req.tools` above, or a raw
        // `toolConfig.tools` preserved from same-protocol `extra`). A tool_choice that arrives with no
        // surviving tools (e.g. a cross-protocol request whose tools could not be projected) is
        // dropped with a warn rather than emitted into an invalid body.
        if tool_config.contains_key("tools") {
            if let Some(tc) = &req.tool_choice {
                match write_bedrock_tool_choice(tc) {
                    // Claude rejects a FORCED/TARGETED tool choice alongside thinking (only auto is
                    // allowed); the think-ask wins and the choice degrades to `auto`, observably —
                    // the Anthropic writer's rule, for the same model.
                    Some(_)
                        if thinking_emitted
                            && matches!(
                                tc,
                                crate::ir::IrToolChoice::Required
                                    | crate::ir::IrToolChoice::Tool { .. }
                            ) =>
                    {
                        tracing::warn!(
                            "downgrading forced/targeted toolChoice to auto on Bedrock egress: not \
                             compatible with thinking"
                        );
                        tool_config
                            .insert("toolChoice".to_string(), serde_json::json!({"auto": {}}));
                    }
                    Some(v) => {
                        tool_config.insert("toolChoice".to_string(), v);
                    }
                    // `IrToolChoice::None` ("do NOT call a tool") has no native Converse directive,
                    // so it degrades to omitting `toolChoice` (the backend applies its own default,
                    // which may still call a tool). Previously SILENT; warn so it is observable.
                    None => {
                        tracing::warn!(
                            "dropping tool_choice=None: Bedrock Converse has no 'do not call a tool' \
                             directive, so toolChoice is omitted and the backend may still call a tool"
                        );
                    }
                }
            }
        } else if req.tool_choice.is_some() {
            tracing::warn!(
                "dropping tool_choice with no accompanying tools: Bedrock Converse rejects a \
                 toolConfig whose toolChoice has no tools array, so it is omitted"
            );
        }
        // Emit `toolConfig` only when it carries a `tools` array. AWS rejects a bare `{}`/`{tools:[]}`
        // and a `{toolChoice:…}` with no tools, so a config that ended up with neither typed nor raw
        // tools (only a now-dropped toolChoice) must not be emitted at all.
        if tool_config.contains_key("tools") {
            out.insert(
                "toolConfig".to_string(),
                serde_json::Value::Object(tool_config),
            );
        }
        // Egress: Bedrock Converse models no parallelism control. `is_some()` gates this
        // to requests that actually carried the flag (owner decision 4: no per-request noise).
        if req.parallel_tool_calls.is_some() {
            tracing::warn!(
                "dropping parallel_tool_calls on Bedrock egress: Converse has no parallelism \
                 control, so the backend's default parallelism applies"
            );
        }

        // Emit `top_k` (fidelity fix). Bedrock's Converse API has no `inferenceConfig` slot for
        // top_k; it rides in the model-specific `additionalModelRequestFields` escape hatch. OVERLAY
        // the typed IR `top_k` (as `top_k`) onto the RAW `additionalModelRequestFields` the reader
        // captured into `extra` — same pattern as `inferenceConfig`/`toolConfig`. This re-emits a
        // same-protocol Bedrock->Bedrock top_k faithfully AND carries a cross-protocol top_k (e.g.
        // from Anthropic, where `extra` is cleared) onto the wire instead of dropping it. The raw
        // `additionalModelRequestFields` is consumed here (skipped in the trailing extra-merge) to
        // avoid a double-emit. The typed `top_k` WINS over any same-named raw entry.
        let mut additional_fields = req
            .extra
            .get("additionalModelRequestFields")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(t) = thinking {
            additional_fields.insert("thinking".to_string(), t);
        } else if thinking_disabled {
            additional_fields.insert(
                "thinking".to_string(),
                serde_json::json!({ "type": super::THINKING_TYPE_DISABLED }),
            );
        }
        if let Some(word) = effort_word {
            // Claude's effort word rides `output_config` inside `additionalModelRequestFields`
            // (Converse's own `outputConfig` is a different, top-level member).
            let oc = additional_fields
                .entry("output_config")
                .or_insert_with(|| serde_json::json!({}));
            if let Some(map) = oc.as_object_mut() {
                map.insert("effort".to_string(), serde_json::json!(word));
            }
        }
        if let Some(top_k) = req.top_k.filter(|_| {
            if thinking_emitted {
                tracing::warn!("omitting top_k on Bedrock egress: not compatible with thinking");
            }
            !thinking_emitted
        }) {
            // Preserve the source spelling on a same-protocol passthrough: re-emit camelCase `topK`
            // when the reader stamped the sentinel (the body arrived as `topK`), else the canonical
            // snake_case `top_k`. The sentinel only survives on the same-protocol path (`extra` is
            // cleared cross-protocol), so cross-protocol egress always takes the `top_k` branch.
            let key = if req.extra.contains_key(TOP_K_CAMEL_SENTINEL) {
                "topK"
            } else {
                "top_k"
            };
            additional_fields.insert(key.to_string(), serde_json::json!(top_k));
        }
        if !additional_fields.is_empty() {
            out.insert(
                "additionalModelRequestFields".to_string(),
                serde_json::Value::Object(additional_fields),
            );
        }

        // IR-03: the typed metadata is Converse's `requestMetadata`, same keys. A same-protocol
        // body's own raw object (in `extra`, re-emitted verbatim below) is what it was read from and
        // wins.
        if let Some(pairs) = req
            .metadata
            .as_deref()
            .filter(|_| !req.extra.contains_key(super::FIELD_REQUEST_METADATA))
        {
            if let Some(m) = super::write_bedrock_request_metadata(pairs) {
                out.insert(super::FIELD_REQUEST_METADATA.to_string(), m);
            }
        }
        // The Q57 request slots with no Converse form — the same set `dropped_egress_controls`
        // reports for the seam's audit.
        for control in bedrock_unrepresentable_slots(req) {
            tracing::warn!(
                control = control,
                "dropping a request control on Bedrock egress: Converse has no form for it"
            );
        }

        for (key, value) in &req.extra {
            // `inferenceConfig` and `toolConfig` were already consumed above (typed fields overlaid
            // onto the raw object); re-inserting the raw copy here would clobber that overlay and drop
            // the typed `maxTokens`/`temperature` (inferenceConfig) or `tools` (toolConfig). Every
            // other unmodeled field passes through verbatim.
            if key == "inferenceConfig" || key == "toolConfig" || key == "outputConfig" {
                continue;
            }
            // `additionalModelRequestFields` was already consumed above (typed `top_k` overlaid onto
            // the raw object); re-inserting the raw copy here would clobber that overlay and drop the
            // typed `top_k`. Skip it to avoid the double-emit (mirrors inferenceConfig/toolConfig).
            if key == "additionalModelRequestFields" {
                continue;
            }
            // The cachePoint stash is a busbar-internal sentinel, NOT a real Bedrock top-level
            // field — it was already consumed above (spliced back into `system`/`messages`). Emitting
            // it verbatim would leak the sentinel object onto the wire (an invalid body and a proxy
            // tell), so skip it here. Mirrors the inferenceConfig/toolConfig consume-don't-re-emit.
            if key == CACHE_POINTS_SENTINEL {
                continue;
            }
            // The guardContent stash is likewise a busbar-internal sentinel, already consumed above
            // (spliced back into `system`/`messages`). Skip it so it never leaks onto the wire.
            if key == GUARD_CONTENT_SENTINEL {
                continue;
            }
            // The document/video stash is likewise a busbar-internal sentinel, already consumed above
            // (spliced back into `messages`). Skip it so it never leaks onto the wire.
            if key == DOC_VIDEO_SENTINEL {
                continue;
            }
            // The top_k source-spelling hint is a busbar-internal sentinel, already consumed above
            // (it selected the `topK`/`top_k` key emitted into `additionalModelRequestFields`). Skip
            // it so it never leaks onto the wire (an invalid body and a proxy tell).
            if key == TOP_K_CAMEL_SENTINEL {
                continue;
            }
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }
}

/// The typed request slots (Q57) a Converse body has no member for — each is dropped with a warn by
/// `write_request` and reported by `dropped_egress_controls`, so the seam audits the degradation:
/// `store`, `safety_identifier`, `prompt_cache_key`, `verbosity`, `service_tier` (the IR-04 contract
/// names no Converse spelling), a non-text output modality (Converse answers in text), and every
/// provider-hosted tool kind (Converse has no hosted web search / code execution / web fetch).
fn bedrock_unrepresentable_slots(req: &crate::ir::IrRequest) -> Vec<&'static str> {
    let mut dropped = Vec::new();
    if req.service_tier.is_some() {
        dropped.push("service_tier");
    }
    if req.store.is_some() {
        dropped.push("store");
    }
    if req.safety_identifier.is_some() {
        dropped.push("safety_identifier");
    }
    if req.prompt_cache_key.is_some() {
        dropped.push("prompt_cache_key");
    }
    if req.verbosity.is_some() {
        dropped.push("verbosity");
    }
    if req
        .output_modalities
        .as_ref()
        .is_some_and(|m| m.iter().any(|m| *m != crate::ir::IrModality::Text))
    {
        dropped.push("output_modalities");
    }
    dropped.extend(req.hosted_tools.iter().map(|h| h.kind_str()));
    dropped
}

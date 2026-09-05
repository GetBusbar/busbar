use super::*;

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
        // Mirrors the two `write_request` warns: Bedrock Converse has no native `response_format`
        // field, and no "do NOT call a tool" (`IrToolChoice::None`) directive — a cross-protocol
        // request carrying either has that control dropped on egress.
        let mut dropped = Vec::new();
        if req.response_format.is_some() {
            dropped.push("response_format");
        }
        if matches!(req.tool_choice, Some(crate::ir::IrToolChoice::None)) {
            dropped.push("tool_choice=none");
        }
        dropped
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let _t = busbar_timing::timeit!("bedrock_write_request");
        // The reasoning carry has no Bedrock Converse shape in this pass; dropped observably (matching
        // the penalties/top_k convention) rather than silently.
        if req.reasoning.is_some() {
            tracing::warn!(
                "dropping cross-protocol reasoning/thinking ask: no Bedrock Converse mapping in this release"
            );
        }
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
            for block in &req.system {
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
            for (block_idx, block) in msg.content.iter().enumerate() {
                // A `document` / `video` block the READER also parked verbatim under
                // `DOC_VIDEO_SENTINEL` at this exact (message, block) position. The stash is spliced
                // back below, so writing the modelled `Media` projection here TOO would emit the
                // attachment twice. Suppress the modelled emit and let the verbatim raw block win —
                // that is what keeps a Bedrock->Bedrock round-trip byte-identical (every document
                // sub-field, `citations`/`context` included, survives) while a CROSS-protocol IR,
                // whose `extra` the seam cleared, has no stash and so takes the modelled path.
                let raw_doc_video_stashed =
                    message_doc_video.iter().flat_map(|v| v.iter()).any(|e| {
                        e.get("m").and_then(|v| v.as_u64()) == Some(msg_idx as u64)
                            && e.get("i").and_then(|v| v.as_u64()) == Some(block_idx as u64)
                    });
                // The prompt-cache boundary carried on this block, if any. Emitted as a
                // `cachePoint` block IMMEDIATELY AFTER the block below (the position Bedrock expects).
                // Suppressed when the positional stash owns placement (same-protocol passthrough).
                let block_cache_control = match block {
                    crate::ir::IrBlock::Text { cache_control, .. }
                    | crate::ir::IrBlock::ToolUse { cache_control, .. }
                    | crate::ir::IrBlock::ToolResult { cache_control, .. } => {
                        cache_control.as_ref()
                    }
                    crate::ir::IrBlock::Thinking { .. }
                    | crate::ir::IrBlock::Image { .. }
                    | crate::ir::IrBlock::Media { .. }
                    | crate::ir::IrBlock::Json(_) => None,
                };
                match block {
                    crate::ir::IrBlock::Text { text, .. } => {
                        content_arr.push(serde_json::json!({ "text": text }));
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
                                    kind, source, name, ..
                                } => {
                                    if let Some(b) =
                                        bedrock_media_content_block(*kind, source, name.as_deref())
                                    {
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
                        ..
                    } => {
                        // Re-emit the assistant turn's reasoning as a native Converse
                        // `reasoningContent` block (the inverse of `read_request`'s reasoningContent
                        // decode). The old writer dropped every Thinking block here, so a
                        // bedrock->bedrock passthrough lost the signed reasoning Bedrock requires
                        // echoed back on a follow-up turn. The redacted-signature sentinel re-emits
                        // `redactedContent`; any other Thinking re-emits `reasoningText`.
                        content_arr.push(bedrock_reasoning_block(text, signature, *redacted));
                    }
                    crate::ir::IrBlock::Media {
                        kind, source, name, ..
                    } => {
                        if !raw_doc_video_stashed {
                            if let Some(b) =
                                bedrock_media_content_block(*kind, source, name.as_deref())
                            {
                                content_arr.push(b);
                            }
                        }
                    }
                    crate::ir::IrBlock::Json(_) => {
                        // Structured-json content is only a tool-result content member; it has no
                        // top-level message-content shape, so omit it from a message turn.
                    }
                }
                // Emit the prompt-cache boundary as a `cachePoint` block right after the block it
                // applies to. Only Text/ToolUse/ToolResult carry `cache_control` (see
                // `block_cache_control`); a block whose write produced nothing (e.g. a dropped Image)
                // still emits no cachePoint here because such kinds carry no `cache_control` field.
                // Suppressed when the positional stash owns placement (same-protocol round-trip).
                if emit_inline_message_cache && block_cache_control.is_some() {
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
        let mut inference_config = req
            .extra
            .get("inferenceConfig")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(max_tokens) = req.max_tokens {
            inference_config.insert("maxTokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temperature) = req.temperature {
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
            inference_config.insert("topP".to_string(), serde_json::json!(top_p));
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
        if req.response_format.is_some() {
            tracing::warn!(
                parameter = "response_format",
                "dropping response_format on Bedrock egress: Converse has no native \
                 response_format field, so the structured-output directive from a cross-protocol \
                 request is NOT forwarded"
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
        super::super::ir_encode::warn_dropped_tool_strict(&req.tools, "bedrock");
        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut tool_spec = serde_json::Map::new();
                tool_spec.insert("name".to_string(), serde_json::json!(tool.name));

                if let Some(desc) = &tool.description {
                    tool_spec.insert("description".to_string(), serde_json::json!(desc));
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
        if let Some(top_k) = req.top_k {
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

        for (key, value) in &req.extra {
            // `inferenceConfig` and `toolConfig` were already consumed above (typed fields overlaid
            // onto the raw object); re-inserting the raw copy here would clobber that overlay and drop
            // the typed `maxTokens`/`temperature` (inferenceConfig) or `tools` (toolConfig). Every
            // other unmodeled field passes through verbatim.
            if key == "inferenceConfig" || key == "toolConfig" {
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

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart { .. } => Some((
                ET_MESSAGE_START.to_string(),
                serde_json::json!({ "role": "assistant" }),
            )),

            IrStreamEvent::BlockStart { index, block } => match block {
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
                // `max_citations_per_delta()` is overridden to `Some(1)` for this writer, so
                // `StreamTranslate` has already fanned a multi-citation delta out to one citation per
                // event by the time it reaches here; `first()` is therefore the whole delta, and the
                // debug_assert pins the invariant rather than silently truncating if the seam changes.
                crate::ir::IrDelta::CitationsDelta(cits) => {
                    debug_assert!(
                        cits.len() <= 1,
                        "bedrock writer expects the citation fan-out to have split multi-citation \
                         deltas (max_citations_per_delta() == Some(1))"
                    );
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
            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
            } => match stop_reason {
                Some(reason) => Some((
                    ET_MESSAGE_STOP.to_string(),
                    serde_json::json!({ "stopReason": stop_reason_reverse(*reason) }),
                )),
                None => {
                    let mut usage_obj = serde_json::Map::new();
                    usage_obj.insert("inputTokens".to_string(), usage.input_tokens.into());
                    usage_obj.insert("outputTokens".to_string(), usage.output_tokens.into());
                    // Saturating add: token counts arrive from an untrusted upstream
                    // (`as_u64().unwrap_or(0)` in the reader); a pathological/hostile pair
                    // near `u64::MAX` would panic this request-path code under
                    // overflow-checks (all debug builds, opt-in release) or silently wrap to
                    // a nonsense `totalTokens` in plain release. Mirror the Gemini writer's
                    // explicit `saturating_add` so the total clamps at `u64::MAX` instead.
                    usage_obj.insert(
                        "totalTokens".to_string(),
                        usage
                            .input_tokens
                            .saturating_add(usage.output_tokens)
                            .into(),
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

        let reverse_reason =
            stop_reason_reverse(resp.stop_reason.unwrap_or(crate::ir::IrStopReason::EndTurn));

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
        // Saturating add, same rationale as the streaming `metadata` frame: token counts are
        // upstream-derived and unbounded, so a bare `u64 + u64` here is an overflow-panic
        // (overflow-checks) / silent-wrap (release) hazard on the buffered Converse body.
        usage_obj.insert(
            "totalTokens".to_string(),
            resp.usage
                .input_tokens
                .saturating_add(resp.usage.output_tokens)
                .into(),
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

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}

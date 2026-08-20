use super::*;

/// A representative `mimeType` for a media kind whose source is a bare URL and therefore carries no
/// mime of its own (an Anthropic `document.source.url`, an OpenAI `image_url`-style file URL).
///
/// Gemini's `fileData` requires a `mimeType` to decode the referenced file, so omitting it is worse
/// than a well-formed generic: `application/pdf` is the document form Gemini's own docs use in the
/// `fileData` example, and the audio/video generics are the standard container-agnostic types. This
/// is a WRITE-side default, never a claim about the referenced bytes — a source that knows its real
/// mime (every `Base64` one) never routes through here.
fn gemini_mime_for_kind(kind: busbar_core::ir::IrMediaKind) -> &'static str {
    match kind {
        busbar_core::ir::IrMediaKind::Document => "application/pdf",
        busbar_core::ir::IrMediaKind::Audio => "audio/mpeg",
        busbar_core::ir::IrMediaKind::Video => "video/mp4",
    }
}

impl ProtocolWriter for GeminiWriter {
    fn probe_request(&self) -> serde_json::Value {
        // The ping IR is built by the plugin (ir_encode::ping_request); this dialect serializes it
        // through its own write_request, so the probe body matches a real request on this wire.
        self.write_request(&super::super::ir_encode::ping_request())
    }

    fn upstream_path(&self) -> &str {
        // Model-independent fallback; the real per-request path comes from upstream_path_for().
        GEMINI_PATH_BASE
    }

    /// Gemini expresses the candidate count as `generationConfig.candidateCount` (the snake_case
    /// `candidate_count` is also tolerated). `Some(k)` only for a genuine `k > 1` ask. See the trait
    /// doc for why the engine rejects `k > 1` on a cross-protocol route (the single-candidate IR would
    /// drop candidates `1..k`).
    fn requested_candidate_count(&self, body: &serde_json::Value) -> Option<u64> {
        body.pointer("/generationConfig/candidateCount")
            .or_else(|| body.pointer("/generationConfig/candidate_count"))
            .and_then(|v| v.as_u64())
            .filter(|&k| k > 1)
    }

    /// Gemini's URL embeds the model AND the stream mode. Streaming requests go to
    /// `:streamGenerateContent?alt=sse` (the gemini reader already decodes those SSE chunks);
    /// non-streaming to `:generateContent`.
    fn upstream_path_for_stream(&self, model: &str, stream: bool) -> String {
        if stream {
            // SSE streaming endpoint. `alt=sse` yields `data:`-framed chunks the gemini
            // reader's read_response_events already decodes.
            format!("{GEMINI_PATH_BASE}/{model}:streamGenerateContent?alt=sse")
        } else {
            format!("{GEMINI_PATH_BASE}/{model}:generateContent")
        }
    }

    fn upstream_path_for(&self, model: &str) -> String {
        format!("{GEMINI_PATH_BASE}/{model}:generateContent")
    }

    /// Gemini carries turns in `contents` as `{role, parts: [{text}]}`, and spells the assistant
    /// role `model`. BOTH the canonical `assistant` and the native `model` are accepted on the reply
    /// so a hook that echoes the role it was projected — and one written to Gemini's own vocabulary
    /// — round-trip to `model` rather than falling through to `user` and corrupting every assistant
    /// turn.
    fn apply_rewrite_to_ingress_body(
        &self,
        obj: &mut serde_json::Map<String, serde_json::Value>,
        messages: &[serde_json::Value],
        _tools: &[serde_json::Value],
    ) -> bool {
        if !obj.get("contents").is_some_and(serde_json::Value::is_array) {
            return false;
        }
        let Some(pairs) = busbar_core::proto::rewrite_text_pairs(messages) else {
            return false;
        };
        let framed: Vec<serde_json::Value> = pairs
            .into_iter()
            .map(|(role, text)| {
                let g_role = if role == "assistant" || role == "model" {
                    "model"
                } else {
                    "user"
                };
                serde_json::json!({ "role": g_role, "parts": [{ "text": text }] })
            })
            .collect();
        obj.insert("contents".to_string(), serde_json::Value::Array(framed));
        true
    }

    fn write_request(&self, req: &busbar_core::ir::IrRequest) -> serde_json::Value {
        let mut out = serde_json::Map::new();

        // systemInstruction.parts[] from IrRequest.system
        if !req.system.is_empty() {
            let parts: Vec<_> = req
                .system
                .iter()
                .filter_map(|block| match block {
                    busbar_core::ir::IrBlock::Text { text, .. } => {
                        Some(serde_json::json!({ "text": text }))
                    }
                    // Gemini's systemInstruction.parts carries text only. Drop any non-Text system
                    // block WITH a warn (matching cohere's warn for the same case) rather than
                    // vanishing silently — a system array with a non-text block is degenerate.
                    _ => {
                        tracing::warn!(
                            "dropping non-text system block on Gemini egress: systemInstruction \
                             carries text only"
                        );
                        None
                    }
                })
                .collect();
            if !parts.is_empty() {
                out.insert(
                    "systemInstruction".to_string(),
                    serde_json::json!({ "parts": parts }),
                );
            }
        }

        // Cross-protocol tool-id → function-name map for `functionResponse.name` correlation.
        //
        // Gemini correlates a `functionResponse` to its `functionCall` strictly BY NAME — the wire
        // format carries no call ids. On a SAME-protocol (Gemini→Gemini) turn the reader already sets
        // each ToolResult's `tool_use_id` to the function name (Gemini's only result-side handle), so
        // round-tripping it straight into `functionResponse.name` is correct. But on a CROSS-protocol
        // seam (Anthropic/OpenAI ingress → Gemini egress) the IR's ToolUse blocks carry a SYNTHETIC
        // `call_<hash>` id and the matching ToolResult's `tool_use_id` carries that SAME synthetic id
        // — NOT the real function name. Emitting that hash as `functionResponse.name` while
        // `functionCall.name` stays the real `get_weather` left the backend unable to correlate, so
        // every cross-protocol→Gemini multi-turn tool call broke.
        //
        // Build a `tool_use_id -> function_name` map from ALL ToolUse blocks across the whole request
        // (a later turn's result references an earlier turn's call), then resolve the real name in the
        // ToolResult arm below, FALLING BACK to the `tool_use_id` itself when it is not in the map —
        // which preserves the same-protocol case where `tool_use_id` already IS the function name.
        let mut tool_name_by_id: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::new();
        for msg in &req.messages {
            for block in &msg.content {
                if let busbar_core::ir::IrBlock::ToolUse { id, name, .. } = block {
                    if !id.is_empty() {
                        tool_name_by_id.insert(id.as_str(), name.as_str());
                    }
                }
            }
        }

        // messages → contents (Assistant→"model", User→"user")
        let mut contents_arr: Vec<serde_json::Value> = Vec::new();
        for msg in &req.messages {
            let role_str = match msg.role {
                busbar_core::ir::IrRole::User => "user",
                busbar_core::ir::IrRole::Assistant => "model",
                // A Tool-role IR message carries `ToolResult` blocks, emitted below as Gemini
                // `functionResponse` parts. In the native Gemini GenerateContentRequest schema a
                // `functionResponse` MUST be sent under a `user`-side turn: the `model` role is
                // exclusively the assistant's turn (which produces `functionCall`s, never
                // `functionResponse`s). Emitting a `functionResponse` under `role:"model"` is a
                // non-native shape the real Gemini API / google-genai SDK rejects. Map Tool →
                // "user" (matching the Bedrock writer's `toolResult` handling).
                busbar_core::ir::IrRole::Tool => "user",
                busbar_core::ir::IrRole::System => continue, // Already in systemInstruction
            };

            let mut parts_arr: Vec<serde_json::Value> = Vec::new();
            for block in &msg.content {
                match block {
                    busbar_core::ir::IrBlock::Text { text, .. } => {
                        parts_arr.push(serde_json::json!({ "text": text }))
                    }
                    busbar_core::ir::IrBlock::ToolUse {
                        id: _,
                        name,
                        input,
                        thought_signature,
                        ..
                    } => {
                        // ToolUse → functionCall{name, args}. `args` MUST be a JSON OBJECT (Gemini
                        // Struct); coerce any non-object input (array/scalar/null/unparseable string)
                        // the same way `functionResponse.response` is coerced below.
                        let args_val = coerce_tool_args(input);
                        let mut fc_obj = serde_json::Map::new();
                        fc_obj.insert("name".to_string(), serde_json::json!(name));
                        fc_obj.insert("args".to_string(), args_val);
                        let mut part_obj = serde_json::Map::new();
                        part_obj.insert(
                            FIELD_FUNCTION_CALL.to_string(),
                            serde_json::Value::Object(fc_obj),
                        );
                        // `thoughtSignature` is a sibling of `functionCall` on the `Part` object, NOT
                        // nested inside it — same placement as the Thinking block's signature below.
                        // Gemini 3 REQUIRES this echoed back verbatim on the next turn or the backend
                        // 400s. By the time this writer runs, `thought_signature` already carries the
                        // right value — either a real one captured by Gemini's own reader, or a
                        // sentinel injected upstream by `IrReq::prepare_for_egress` for cross-protocol
                        // traffic — so this writer stays dumb and just emits what it's given. Omit the
                        // key entirely when absent rather than emit an empty string.
                        if let Some(sig) = thought_signature {
                            part_obj.insert("thoughtSignature".to_string(), serde_json::json!(sig));
                        }
                        parts_arr.push(serde_json::Value::Object(part_obj))
                    }
                    busbar_core::ir::IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    } => {
                        // ToolResult → functionResponse{name, response}. Resolve the REAL function
                        // name from the cross-protocol id→name map built above so the emitted
                        // `functionResponse.name` matches the `functionCall.name` Gemini correlates
                        // against. Fall back to the `tool_use_id` itself when it is not a synthetic
                        // mapped id — that preserves the same-protocol Gemini→Gemini case where
                        // `tool_use_id` already equals the function name.
                        let name: &str = tool_name_by_id
                            .get(tool_use_id.as_str())
                            .copied()
                            .unwrap_or(tool_use_id.as_str());
                        let response_text = content
                            .iter()
                            .filter_map(|b| match b {
                                busbar_core::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                                // A non-Text ToolResult block is a Bedrock json-tool-result sentinel
                                // with no Gemini analog. Drop WITH a warn (drop-with-warn convention)
                                // instead of vanishing silently.
                                other => {
                                    if super::super::ir_encode::is_json_tool_result_block(other) {
                                        tracing::warn!(
                                            "dropping structured json tool-result block on Gemini \
                                             egress: a Bedrock `{{\"json\":...}}` tool-result has no \
                                             cross-protocol analog and is NOT emitted"
                                        );
                                    }
                                    None
                                }
                            })
                            .collect::<Vec<_>>()
                            .join(" ");
                        // If the joined text is valid JSON, forward it as the structured response.
                        // Otherwise (e.g. multiple plain-text chunks) wrap the raw text in
                        // `{"output": <text>}` — the Gemini functionResponse convention for
                        // plain-text tool output — rather than silently discarding the content
                        // with an empty `{}` object.
                        //
                        // Gemini's `functionResponse.response` is a protobuf Struct: it MUST be a JSON
                        // OBJECT. A non-object parse result — a JSON `null` (e.g. upstream omitted the
                        // response object and a literal "null" arrived), a bare scalar ("42", "true",
                        // "\"text\""), or an array ("[1,2]") — would be emitted verbatim and rejected by
                        // the backend (400). Coerce any non-object parsed value into a valid Struct:
                        // `null` becomes `{}` (an empty-but-valid response), and any other non-object
                        // scalar/array is wrapped under `{"output": <value>}` so its content survives.
                        let parsed: serde_json::Value =
                            busbar_core::json::parse_str(&response_text)
                                .unwrap_or_else(|_| serde_json::json!({ "output": response_text }));
                        let response_val: serde_json::Value = if parsed.is_object() {
                            parsed
                        } else if parsed.is_null() {
                            serde_json::json!({})
                        } else {
                            serde_json::json!({ "output": parsed })
                        };
                        parts_arr.push(serde_json::json!({
                            "functionResponse": { "name": name, "response": response_val }
                        }))
                    }
                    busbar_core::ir::IrBlock::Image { source, .. } => match source {
                        // A remote URL → Gemini's native `fileData{fileUri}` (URL reference, not base64).
                        busbar_core::ir::IrImageSource::Url(uri) => {
                            parts_arr.push(serde_json::json!({
                                "fileData": { "fileUri": uri }
                            }))
                        }
                        // Inline base64 → `inlineData{mimeType, data}`.
                        busbar_core::ir::IrImageSource::Base64 { media_type, data } => parts_arr
                            .push(serde_json::json!({
                                "inlineData": { "mimeType": media_type, "data": data }
                            })),
                        // A Responses `file_id` / Bedrock `s3Location` reference has no Gemini
                        // projection — emitting it would corrupt the part. Drop with a warn.
                        busbar_core::ir::IrImageSource::Vendor { .. } => {
                            tracing::warn!(
                                "dropping unresolvable vendor-scoped image reference on Gemini \
                                 egress: a file_id / s3Location has no cross-vendor analog"
                            );
                        }
                    },
                    // Gemini is the ONE dialect in the matrix whose attachment slots are
                    // mime-generic: `inlineData{mimeType,data}` and `fileData{fileUri,mimeType}`
                    // carry a PDF, an audio clip and a video with no per-kind wire shape. So every
                    // `Media` kind projects natively here — this writer is why the attachment gap
                    // was never an untranslatable-concept problem, only an unmodelled-IR one.
                    busbar_core::ir::IrBlock::Media { kind, source, .. } => match source {
                        busbar_core::ir::IrImageSource::Url(uri) => {
                            // Re-emit the `mimeType` the reader used to route this block. A bare
                            // container guess is better than omitting it: Gemini uses `mimeType` to
                            // decide how to decode the referenced file.
                            parts_arr.push(serde_json::json!({
                                "fileData": { "fileUri": uri, "mimeType": gemini_mime_for_kind(*kind) }
                            }))
                        }
                        busbar_core::ir::IrImageSource::Base64 { media_type, data } => parts_arr
                            .push(serde_json::json!({
                                "inlineData": { "mimeType": media_type, "data": data }
                            })),
                        busbar_core::ir::IrImageSource::Vendor { .. } => {
                            tracing::warn!(
                                media_kind = kind.as_str(),
                                "dropping attachment on Gemini egress: the source is a vendor-scoped \
                                 file handle (an OpenAI/Anthropic file_id, a Bedrock s3Location) that \
                                 Gemini's backend cannot resolve; the block is NOT emitted"
                            );
                        }
                    },
                    busbar_core::ir::IrBlock::Json(_) => {
                        // Structured-json (Bedrock tool-result content) has no Gemini part shape.
                    }
                    // A REDACTED reasoning block holds opaque encrypted bytes with no Gemini analog —
                    // drop it (its `text` is not plaintext reasoning).
                    busbar_core::ir::IrBlock::Thinking { redacted: true, .. } => {}
                    busbar_core::ir::IrBlock::Thinking {
                        text, signature, ..
                    } => {
                        // Thinking → Gemini `{text, thought:true, thoughtSignature?}`. Gemini
                        // DOES carry reasoning parts; round-trip the text and the opaque resumable
                        // `thoughtSignature`. `thoughtSignature` is emitted only when present.
                        let mut part = serde_json::Map::new();
                        part.insert("text".to_string(), serde_json::json!(text));
                        part.insert("thought".to_string(), serde_json::json!(true));
                        if let Some(sig) = signature {
                            part.insert("thoughtSignature".to_string(), serde_json::json!(sig));
                        }
                        parts_arr.push(serde_json::Value::Object(part));
                    }
                }
            }

            // A turn whose IR blocks were ALL non-representable here leaves `parts_arr` empty.
            // SKIPPING the whole contents entry drops the turn and can break Gemini's strict
            // user/model alternation — two same-role turns then land adjacent and the API rejects the
            // request with 400 INVALID_ARGUMENT. Mirror the Bedrock writer (bedrock.rs, empty
            // `content_arr` → minimal placeholder): substitute an empty text part so the turn survives
            // the seam and alternation is preserved. System-role messages never reach here (they
            // `continue` during role mapping).
            if parts_arr.is_empty() {
                parts_arr.push(serde_json::json!({ "text": "" }));
            }
            let mut content_obj = serde_json::Map::new();
            content_obj.insert("role".to_string(), serde_json::json!(role_str));
            content_obj.insert("parts".to_string(), serde_json::Value::Array(parts_arr));
            contents_arr.push(serde_json::Value::Object(content_obj));
        }

        // Write contents to output after building all messages
        if !contents_arr.is_empty() {
            out.insert(
                "contents".to_string(),
                serde_json::Value::Array(contents_arr),
            );
        }

        // tools → tools[0].functionDeclarations[]
        super::super::ir_encode::warn_dropped_tool_strict(
            &req.tools,
            busbar_core::proto::PROTO_GEMINI,
        );
        if !req.tools.is_empty() {
            let func_decls: Vec<_> = req
                .tools
                .iter()
                .map(|tool| {
                    let mut obj = serde_json::Map::new();
                    obj.insert("name".to_string(), serde_json::json!(tool.name));
                    if let Some(desc) = &tool.description {
                        obj.insert("description".to_string(), serde_json::json!(desc));
                    }
                    // Gemini's tool `parameters` accept only a strict OpenAPI-3.0 Schema subset,
                    // NOT full JSON Schema. A cross-protocol tool def (OpenAI/Anthropic) routinely
                    // carries draft keywords (`$schema`, a schema-valued `additionalProperties`, …)
                    // that Gemini 400-rejects, and a `$ref`/`$defs` nested-model shape (what every
                    // Pydantic/Zod-generated tool schema uses) that the live API does not reliably
                    // resolve on its own — see the research note on `GEMINI_SCHEMA_REJECTED_KEYS`.
                    // `resolve_gemini_schema_refs` inlines `$ref` against `$defs` first so nested
                    // structure survives, then `sanitize_gemini_schema` strips the rest recursively;
                    // same-protocol Gemini schemas (which never carry these) are unaffected.
                    obj.insert(
                        "parameters".to_string(),
                        sanitize_gemini_schema(&resolve_gemini_schema_refs(&tool.input_schema)),
                    );
                    serde_json::Value::Object(obj)
                })
                .collect();
            out.insert(
                "tools".to_string(),
                serde_json::json!([{"functionDeclarations": func_decls}]),
            );
        }

        // ToolConfig{functionCallingConfig{mode, allowedFunctionNames}}.
        //
        // Start from the RAW `toolConfig` the reader preserved in `extra` (same-protocol Gemini→Gemini
        // byte-identity), then OVERLAY a fresh `functionCallingConfig` built from the typed
        // `req.tool_choice`. Same map key, so the overlay REPLACES (never duplicates) any preserved
        // `functionCallingConfig`. On cross-protocol egress `extra` is already cleared, so this object
        // holds only the typed `functionCallingConfig` and no foreign Gemini sub-field leaks. Mirrors
        // the `generationConfig` overlay below. Emitted only when there is something to say.
        let mut tool_config = req
            .extra
            .get("toolConfig")
            .and_then(|tc| tc.as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(tc) = &req.tool_choice {
            // A `functionCallingConfig` with no accompanying `tools` is meaningless (there is
            // nothing to force/allow) and, like every sibling protocol's equivalent guard, the
            // reachable case is a cross-protocol request whose hosted tools `prepare_for_egress`
            // stripped (`ir/variant.rs`) while the tool_choice directive survived. Drop with a warn
            // rather than emitting a directive over an empty tool set.
            if req.tools.is_empty() {
                tracing::warn!(
                    "dropping tool_choice on Gemini egress: a functionCallingConfig with no \
                     accompanying tools is meaningless (likely because the hosted tools that \
                     carried it were stripped on the cross-protocol seam)"
                );
            } else {
                tool_config.insert(
                    "functionCallingConfig".to_string(),
                    write_gemini_tool_choice(tc),
                );
            }
        }
        if !tool_config.is_empty() {
            out.insert(
                "toolConfig".to_string(),
                serde_json::Value::Object(tool_config),
            );
        }
        // Egress: `generateContent` models no parallelism control at all — `None` is
        // NOT touched here (owner decision 4: a warn on EVERY request would be noise). The
        // `is_some()` gate means this can only fire on a request that actually carried the flag.
        if req.parallel_tool_calls.is_some() {
            tracing::warn!(
                "dropping parallel_tool_calls on Gemini egress: generateContent has no parallelism \
                 control, so the backend's default parallelism applies"
            );
        }

        // generationConfig{maxOutputTokens, temperature, topP, topK, stopSequences, …}
        //
        // Start from the RAW `generationConfig` the reader preserved in `extra` (if any) so any
        // unmodeled sub-field — `responseMimeType` (JSON mode), `thinkingConfig` (extended-thinking
        // budget), `candidateCount`, `seed`, `presencePenalty`, `frequencyPenalty`,
        // `responseModalities`, `speechConfig`, `routingConfig`, … — survives, then OVERLAY the 5
        // typed IR fields on top. This mirrors `BedrockWriter`'s `inferenceConfig` overlay. On
        // same-protocol Gemini→Gemini the overlay reproduces the original values byte-for-byte; on
        // cross-protocol egress `extra` is already cleared at the forward seam, so this object holds
        // only the 5 typed fields and no foreign Gemini sub-field leaks to a non-Gemini backend.
        let mut gen_config = req
            .extra
            .get("generationConfig")
            .and_then(|gc| gc.as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(max_tokens) = req.max_tokens {
            gen_config.insert("maxOutputTokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temperature) = req.temperature {
            gen_config.insert("temperature".to_string(), serde_json::json!(temperature));
        }
        // Promoted sampling controls in Gemini's native generationConfig shape.
        if let Some(top_p) = req.top_p {
            gen_config.insert("topP".to_string(), serde_json::json!(top_p));
        }
        if let Some(top_k) = req.top_k {
            gen_config.insert("topK".to_string(), serde_json::json!(top_k));
        }
        if !req.stop.is_empty() {
            // v1.5.4 silent-degrade (restored): a cross-protocol request whose stop list exceeds
            // Gemini's cap of 5 is CLAMPED to the cap here (with a `warn!` naming what was dropped)
            // and forwarded at HTTP 200, rather than rejected up front with a 400. A same-protocol
            // Gemini->Gemini request never rebuilds its body from the IR (verbatim relay), so it
            // never reaches this writer and is never clamped. The published cap in the declaration
            // (`stop_sequence_cap`) is retained for other planes.
            gen_config.insert(
                "stopSequences".to_string(),
                serde_json::json!(busbar_core::ir::clamp_stop(&req.stop, 5, "Gemini")),
            );
        }
        // Promoted sampling controls in Gemini's native generationConfig shape (cross-protocol
        // survival, inverse of the reader's promotion). `n` → `candidateCount` (Gemini's name).
        // Omitted when None so a request that never carried them gains nothing.
        if let Some(frequency_penalty) = req.frequency_penalty {
            gen_config.insert(
                "frequencyPenalty".to_string(),
                serde_json::json!(frequency_penalty),
            );
        }
        // The logprobs ask in Gemini's native spellings (an OpenAI `logprobs`/`top_logprobs`
        // arrives here via the IR): boolean `responseLogprobs`, top-count `logprobs`.
        // Gemini requires `responseLogprobs: true` for the `logprobs` top-count to be valid. Force
        // it whenever the count is present (even if the source only set the count), or Gemini 400s.
        if req.top_logprobs.is_some() {
            gen_config.insert("responseLogprobs".to_string(), serde_json::json!(true));
        } else if let Some(logprobs) = req.logprobs {
            gen_config.insert("responseLogprobs".to_string(), serde_json::json!(logprobs));
        }
        if let Some(top_logprobs) = req.top_logprobs {
            // Gemini's `logprobs` top-count caps at 5 on most models (OpenAI allows up to 20).
            // Clamp to the safe floor rather than 400 a cross-protocol request that asked for more;
            // busbar can't know the target model's exact cap, and 5 is universally accepted.
            const GEMINI_MAX_TOP_LOGPROBS: u32 = 5;
            let clamped = top_logprobs.min(GEMINI_MAX_TOP_LOGPROBS);
            if clamped != top_logprobs {
                tracing::warn!(
                    requested = top_logprobs,
                    clamped,
                    "clamping top_logprobs to Gemini's max (5)"
                );
            }
            // Gemini's `logprobs` top-count is valid only in 1..=5. OpenAI's `top_logprobs: 0`
            // ("chosen token, no alternatives") must NOT emit `logprobs: 0` — Gemini 400s on it.
            // `responseLogprobs: true` (forced above) still returns the chosen token's logprob, so
            // omit the alternatives count entirely for 0 rather than send an invalid value.
            if clamped >= 1 {
                gen_config.insert("logprobs".to_string(), serde_json::json!(clamped));
            }
        }
        // The reasoning carry in Gemini's native spelling: `thinkingConfig.thinkingBudget`.
        // Dynamic round-trips as Gemini's own -1; effort words go through the table. (Only present
        // when the seam's per-lane capability gate allowed the ask through.)
        if let Some(ask) = req.reasoning {
            let table = req
                .reasoning_budgets
                .unwrap_or(busbar_core::ir::REASONING_BUDGET_DEFAULTS);
            let budget: i64 = match ask {
                busbar_core::ir::IrReasoningAsk::Dynamic => -1,
                other => i64::from(other.to_budget(table)),
            };
            // Only SYNTHESIZE a thinkingConfig when the request did not already carry a native
            // Gemini one (i.e. this is a CROSS-protocol ask — `extra` is cleared at the seam, so
            // `gen_config` has no thinkingConfig). A Gemini-native request keeps its original
            // thinkingConfig verbatim (seeded from `extra`), so same-protocol stays byte-exact.
            // On the synthesized (cross-protocol) path, `includeThoughts: true` is REQUIRED or
            // Gemini spends the budget thinking but returns NO thought parts — the carry would come
            // back empty. We always want the thoughts back to translate them to the caller.
            if !gen_config.contains_key("thinkingConfig") {
                gen_config.insert(
                    "thinkingConfig".to_string(),
                    serde_json::json!({"thinkingBudget": budget, "includeThoughts": true}),
                );
            }
        }
        if let Some(presence_penalty) = req.presence_penalty {
            gen_config.insert(
                "presencePenalty".to_string(),
                serde_json::json!(presence_penalty),
            );
        }
        if let Some(seed) = req.seed {
            gen_config.insert("seed".to_string(), serde_json::json!(seed));
        }
        if let Some(n) = req.n {
            gen_config.insert("candidateCount".to_string(), serde_json::json!(n));
        }
        // response_format: map the IR's normalized object back into Gemini's
        // `responseMimeType` / `responseSchema` (overlaying any raw copy preserved in `extra`). The
        // schema is sanitized of JSON-Schema keywords Gemini rejects so a cross-protocol structured
        // output definition does not 400.
        if let Some(rf) = &req.response_format {
            write_gemini_response_format(&mut gen_config, rf);
        }
        if !gen_config.is_empty() {
            out.insert(
                "generationConfig".to_string(),
                serde_json::Value::Object(gen_config),
            );
        }

        // NB: the native Gemini GenerateContentRequest schema has NO top-level `stream` field —
        // streaming is selected entirely by the URL endpoint (`:generateContent` vs
        // `:streamGenerateContent?alt=sse`, produced by `upstream_path_for_stream`). This writer
        // therefore NEVER synthesizes a `stream` member from `req.stream`; the streaming intent is
        // read only by path selection. The ONLY way a `stream` key appears on the egress body is if
        // the SOURCE request carried one and it was preserved verbatim through `extra` (the reader
        // does NOT model `stream`, mirroring how it round-trips `model` for byte-identity). For a
        // NATIVE Gemini request `extra` carries no `stream`, so the egress body carries none either.
        // On same-protocol passthrough `proxy::strip_router_shim_keys` removes any router-injected
        // `stream` before the upstream call. (An earlier version of this comment wrongly claimed the
        // reader excludes `stream` via `modeled_keys`; it does not — the accurate behavior is here.)

        // Merge extra fields (may override, but that's expected behavior). `generationConfig` AND
        // `toolConfig` are SKIPPED here: their raw `extra` copies were already folded into the
        // typed-overlay `gen_config` / `tool_config` objects emitted above, so re-inserting the raw
        // copy would CLOBBER the overlay and silently revert `req.tool_choice`/the 5 typed
        // generationConfig fields back to whatever the source request originally carried — the exact
        // failure mode when a caller (e.g. a post-read governance/routing hook) mutates
        // `IrRequest.tool_choice` without also touching `IrRequest.extra["toolConfig"]`: the typed
        // override would build correctly above, then get overwritten right back to the stale raw
        // value by this loop. Every OTHER unmodeled top-level key still round-trips verbatim.
        for (key, value) in &req.extra {
            if key == "generationConfig" || key == "toolConfig" {
                continue;
            }
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    /// Native Gemini error envelope: `{"error":{"code":<int>,"message":<msg>,"status":<UPPER_SNAKE>}}`.
    /// This mirrors the google.rpc.Status shape every Gemini/Google AI Generative Language API error
    /// uses (and that `extract_error` above already parses on the read side: `error.code` /
    /// `error.status`). The official `google-genai` SDK raises `APIError` whose `.code`/`.status`
    /// read straight off these fields, so a native client gets its typed exception. Served as
    /// application/json (the trait contract; every vendor error envelope is JSON).
    ///
    /// `status` is mapped to the canonical google.rpc.Code name for the HTTP status; the generic
    /// `kind` is mapped onto that vocabulary where a known busbar/router category exists, otherwise
    /// the HTTP-status-derived name wins (so an unrecognized `kind` never produces a non-canonical
    /// `status` string a native SDK would choke on). No `_ =>` catch-all is used on `kind`; the
    /// final fallback is the explicit HTTP-status mapping.
    fn write_error(&self, status: u16, kind: &str, message: &str) -> serde_json::Value {
        // google.rpc.Code name for an HTTP status (the canonical Generative Language API mapping).
        fn status_name_for_http(status: u16) -> &'static str {
            match status {
                400 => GRPC_INVALID_ARGUMENT,
                401 => GRPC_UNAUTHENTICATED,
                403 => GRPC_PERMISSION_DENIED,
                404 => GRPC_NOT_FOUND,
                409 => "ABORTED",
                429 => GRPC_RESOURCE_EXHAUSTED,
                499 => "CANCELLED",
                500 => GRPC_INTERNAL,
                501 => GRPC_UNIMPLEMENTED,
                503 => GRPC_UNAVAILABLE,
                504 => GRPC_DEADLINE_EXCEEDED,
                s if (400..500).contains(&s) => GRPC_INVALID_ARGUMENT,
                s if (500..600).contains(&s) => GRPC_INTERNAL,
                _ => "UNKNOWN",
            }
        }

        // Map busbar/router `kind` categories onto google.rpc.Code names where one exists. An
        // unknown `kind` yields `None` so the HTTP-status mapping (always defined) is authoritative.
        // `overloaded` (no `_error` suffix) is the bare alias `proxy engine::cross_protocol_error_kind`
        // emits for a relayed upstream 503 — it MUST map to UNAVAILABLE alongside `overloaded_error`,
        // otherwise a cross-protocol 503 fell through to `None` and (when the status arm below was
        // bypassed) could surface the wrong code/status pairing.
        fn status_name_for_kind(kind: &str) -> Option<&'static str> {
            match kind {
                ERR_TYPE_INVALID_REQUEST | "invalid_argument" | "bad_request" => {
                    Some(GRPC_INVALID_ARGUMENT)
                }
                ERR_TYPE_AUTHENTICATION | "unauthenticated" | "auth" => Some(GRPC_UNAUTHENTICATED),
                ERR_TYPE_PERMISSION | "permission_denied" | "forbidden" => {
                    Some(GRPC_PERMISSION_DENIED)
                }
                ERR_TYPE_NOT_FOUND | "not_found" => Some(GRPC_NOT_FOUND),
                ERR_TYPE_RATE_LIMIT | "resource_exhausted" | "rate_limit" => {
                    Some(GRPC_RESOURCE_EXHAUSTED)
                }
                ERR_TYPE_OVERLOADED | busbar_core::proxy::KIND_OVERLOADED | "unavailable" => {
                    Some(GRPC_UNAVAILABLE)
                }
                "deadline_exceeded" | busbar_core::proxy::KIND_TIMEOUT => {
                    Some(GRPC_DEADLINE_EXCEEDED)
                }
                busbar_core::proxy::KIND_API_ERROR
                | "internal"
                | busbar_core::proxy::KIND_SERVER_ERROR => Some(GRPC_INTERNAL),
                "unimplemented" | "not_implemented" => Some(GRPC_UNIMPLEMENTED),
                _ => None,
            }
        }

        // Canonical HTTP status a google.rpc.Code name pairs with — the inverse of
        // `status_name_for_http`. Used to detect a code/status DISAGREEMENT: the real Generative
        // Language API never emits, e.g., `code:503` with `status:INTERNAL` (INTERNAL pairs with
        // 500; UNAVAILABLE pairs with 503). Exhaustive over the names `status_name_for_kind` can
        // return (no `_ =>` collapse) so a new kind→name arm forces a conscious choice here.
        fn http_for_status_name(name: &str) -> Option<u16> {
            match name {
                GRPC_INVALID_ARGUMENT => Some(400),
                GRPC_UNAUTHENTICATED => Some(401),
                GRPC_PERMISSION_DENIED => Some(403),
                GRPC_NOT_FOUND => Some(404),
                GRPC_RESOURCE_EXHAUSTED => Some(429),
                GRPC_UNAVAILABLE => Some(503),
                GRPC_DEADLINE_EXCEEDED => Some(504),
                GRPC_INTERNAL => Some(500),
                GRPC_UNIMPLEMENTED => Some(501),
                _ => None,
            }
        }

        // Prefer the `kind`-derived google.rpc.Code name ONLY when it is internally CONSISTENT with
        // the emitted `code` (the HTTP status). On a cross-protocol upstream 5xx the relay collapses
        // distinct subtypes onto a single `kind` (e.g. a 503 relayed as `api_error`→INTERNAL), which
        // would emit a `code:503 / status:INTERNAL` pair the real API never produces — a
        // distinguishability tell. When the kind-derived name's canonical HTTP status disagrees with
        // `status`, the HTTP status drives the code/status pairing so the two always stay consistent.
        let status_str = match status_name_for_kind(kind) {
            Some(name) if http_for_status_name(name) == Some(status) => name,
            _ => status_name_for_http(status),
        };

        // The real Generative Language API's bad/missing-key 400 ALWAYS carries an
        // `error.details[]` array with a single google.rpc.ErrorInfo whose `reason` is
        // `API_KEY_INVALID` (domain `googleapis.com`, service metadata
        // `generativelanguage.googleapis.com`). The `google-genai` SDK and many clients key their
        // auth-error handling off `details[].reason == "API_KEY_INVALID"`, so omitting the array on
        // our auth-failure envelope (produced by `auth.rs::unauthorized_response` for a
        // Gemini-inferred path) is a deterministic proxy tell on exactly the auth-failure surface.
        //
        // The Gemini auth-failure path (`auth.rs::auth_failure_status_and_kind`) calls this with
        // status 400, kind `invalid_request_error` (→ INVALID_ARGUMENT), and the distinctive
        // canonical bad-key message `"API key not valid. Please pass a valid API key."`
        // (`proto::vendor_auth_failure_message("gemini")`). We gate the `details[]` array on that
        // exact triple so ONLY the bad-key 400 grows the ErrorInfo — a generic malformed-request
        // 400/INVALID_ARGUMENT (which carries a DIFFERENT message and does NOT carry API_KEY_INVALID
        // at real Google) is left untouched, so we neither under-fill the auth surface nor over-fill
        // an unrelated 400 with a reason it should not carry.
        let is_auth_bad_key = status == 400
                && status_str == "INVALID_ARGUMENT" // golden wire-contract literal (kept bare on purpose)
                && message == GEMINI_BAD_KEY_MESSAGE;
        if is_auth_bad_key {
            serde_json::json!({
                "error": {
                    "code": status,
                    "message": message,
                    "status": status_str,
                    "details": [{
                        "@type": GEMINI_ERROR_INFO_TYPE_URL,
                        "reason": GEMINI_ERROR_REASON_API_KEY_INVALID,
                        "domain": "googleapis.com",
                        "metadata": {
                            "service": "generativelanguage.googleapis.com"
                        }
                    }]
                }
            })
        } else {
            serde_json::json!({
                "error": {
                    "code": status,
                    "message": message,
                    "status": status_str,
                }
            })
        }
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            // MessageStart → a leading identity-bearing chunk, ALWAYS emitted (this arm never returns
            // `None`). Native Gemini SSE chunks carry top-level `responseId`/`modelVersion`; the
            // official `google-genai` SDK reads `chunk.response_id`/`chunk.model_version` off the
            // stream. A native Gemini stream ALWAYS carries `responseId` on its first chunk, so we
            // always emit a leading frame that carries one: when the egress captured an `id` we pass it
            // through (a Gemini→Gemini stream is indistinguishable on that field); when `id` is `None`
            // (the post-strip state on a cross-protocol stream — `StreamTranslate` zeroes the foreign
            // id) we SYNTHESIZE a native-shaped `responseId` via `synth_response_id()` rather than
            // omitting it, matching the non-stream `write_response` synth-on-strip behavior. `model`,
            // when present, is added as `modelVersion`; when `None` it is simply omitted, so a `(None,
            // None)` MessageStart still emits a frame carrying a synthesized `responseId` and no
            // `modelVersion`. `created` has no Gemini stream analogue and is never emitted.
            IrStreamEvent::MessageStart { id, model, .. } => {
                let mut frame = serde_json::Map::new();
                match (id, model) {
                    (Some(id), _) => {
                        frame.insert(FIELD_RESPONSE_ID.to_string(), serde_json::json!(id));
                    }
                    // Cross-protocol stream: `StreamTranslate` strips the foreign `id` to `None`
                    // before this writer runs (it does NOT strip `model` — that is the lane's model
                    // name, emitted as `modelVersion` below). A native google-genai SDK reads
                    // `chunk.response_id` off the FIRST chunk (for observability/tracing), so emitting
                    // no identity frame at all is a detectable fidelity gap from a native Gemini stream
                    // (which always carries `responseId` in the first chunk). Synthesize one —
                    // matching the non-stream `write_response` behavior — rather than dropping it.
                    (None, _) => {
                        frame.insert(
                            FIELD_RESPONSE_ID.to_string(),
                            serde_json::json!(synth_response_id()),
                        );
                    }
                }
                // A native Gemini SSE stream ALWAYS carries `modelVersion` in the first chunk (the
                // official google-genai SDK reads `chunk.model_version`). `StreamTranslate` now
                // preserves the lane's `model` across the cross-protocol boundary, so this is
                // populated on cross-protocol streams (not just same-protocol passthrough) and the
                // SDK no longer sees an empty model on every cross-protocol response.
                if let Some(model) = model {
                    frame.insert(FIELD_MODEL_VERSION.to_string(), serde_json::json!(model));
                }
                Some(("".to_string(), serde_json::Value::Object(frame)))
            }

            // BlockStart → for a tool block, OPEN a buffer holding the tool name and an empty args
            // accumulator, and emit NO frame. A native Gemini SSE stream carries a tool call as a
            // SINGLE `functionCall` part `{name, args}`; the IR carries the name here and the
            // arguments on the following InputJsonDelta fragment(s). We accumulate name + every arg
            // fragment per block and emit the one native `{name, args}` part on BlockStop, so a
            // multi-chunk streamed `arguments` JSON reassembles into one valid functionCall (and a
            // zero-arg tool call still flushes `{name, args:{}}`). Re-opening the SAME index resets
            // its accumulator; a NEW index appends a fresh entry so parallel tool blocks (whose
            // BlockStarts are not strictly interleaved with their BlockStops) never clobber each
            // other. Text blocks have no Gemini block-start frame (inline parts) → None.
            IrStreamEvent::BlockStart { index, block } => match block {
                busbar_core::ir::IrBlockMeta::ToolUse { name, .. } => {
                    if let Ok(mut guard) = self.open_tools.lock() {
                        match guard.iter_mut().find(|(idx, _, _)| idx == index) {
                            Some(entry) => {
                                entry.1 = name.clone();
                                entry.2.clear();
                            }
                            None => guard.push((*index, name.clone(), String::new())),
                        }
                    }
                    None
                }
                busbar_core::ir::IrBlockMeta::Text
                | busbar_core::ir::IrBlockMeta::Thinking
                | busbar_core::ir::IrBlockMeta::Image => None,
            },

            // TextDelta → chunk with text part
            IrStreamEvent::BlockDelta { index, delta } => match delta {
                busbar_core::ir::IrDelta::TextDelta(text) => Some((
                    "".to_string(),
                    serde_json::json!({
                        "candidates": [{
                            "content": {
                                "role": "model",
                                "parts": [{"text": text}]
                            }
                        }]
                    }),
                )),

                // InputJsonDelta → ACCUMULATE this fragment into the open tool block's arg buffer and
                // emit NO frame. A cross-protocol backend streams `arguments` as MULTIPLE partial-JSON
                // fragments (`{"lo`, `c":"SF"}`); parsing each fragment independently here (as before)
                // failed on the partials (→ `args:{}`) AND emitted one nameless/partial `functionCall`
                // part per fragment — data loss plus a multi-part split a native Gemini client never
                // sees. Concatenating the fragments and emitting once on BlockStop yields the single
                // native `{name, args}` part with the FULLY reassembled arguments. If no matching open
                // block is tracked (no tool BlockStart seen, or a poisoned lock) the fragment is
                // dropped silently rather than panicking on the request path — the same degraded
                // outcome the stateless arm produced, never a crash.
                //
                // Bound how large this ONE block's buffer can grow across the life of the stream:
                // nothing previously capped it, a hostile/buggy upstream streaming an unbounded run of
                // fragments against one open index could grow this `String` without bound (a
                // per-connection memory-amplification DoS distinct from `MAX_GEMINI_TOOL_FRAMES`, which
                // only bounds the COUNT of distinct open blocks, not one block's accumulated size).
                //
                // The cap is `busbar_core::limits::translate_body_max_bytes()` — the SAME operator-tunable,
                // live-reconfigurable limit (default 32 MiB, coupled to `limits.request_body_max_bytes`)
                // that already bounds a buffered cross-protocol NON-STREAM completion body elsewhere
                // (`proxy::wire::max_translated_body_bytes`), whose own doc comment names "big tool-call
                // arguments" as exactly why that cap must be generous. Reusing it here — rather than a
                // new hardcoded constant — means an operator who raises the one knob to admit larger
                // tool payloads gets that same headroom on this streaming path too, instead of the two
                // paths silently diverging. A read per fragment is cheap (an uncontended `RwLock` read),
                // matching every other `busbar_core::limits` call site's per-use-site read.
                //
                // Once appending a fragment would cross the cap, that fragment (and every subsequent one
                // for this block) is dropped whole rather than sliced at the boundary: the buffer is
                // already guaranteed-unparseable JSON at that point either way, so a partial fragment
                // buys nothing — this mirrors `MAX_GEMINI_TOOL_FRAMES`'s own stop-growing (not abort)
                // policy. The resulting truncated buffer fails to parse as JSON on `BlockStop` and
                // degrades to the pre-existing `args: {}` fallback there (established for ANY
                // unparseable accumulation, cap-truncated or not) — the call is never lost and its name
                // always survives, so this introduces no new failure mode.
                busbar_core::ir::IrDelta::InputJsonDelta(json_str) => {
                    if let Ok(mut guard) = self.open_tools.lock() {
                        if let Some((_, _, args)) =
                            guard.iter_mut().find(|(idx, _, _)| idx == index)
                        {
                            let cap = busbar_core::limits::translate_body_max_bytes();
                            if args.len().saturating_add(json_str.len()) <= cap {
                                args.push_str(json_str);
                            }
                        }
                    }
                    None
                }

                // ThinkingDelta → a streamed Gemini thought part `{text, thought:true}`. Gemini
                // models reasoning as a `thought:true` content part (see the non-stream
                // read/write_response handling), and its stream framing carries each incremental
                // reasoning fragment as exactly such a part in a `candidates[].content.parts[]` chunk —
                // the same per-chunk shape used for a `TextDelta`, just flagged `thought:true`. So we
                // emit one chunk per fragment, mirroring the non-stream `{text, thought:true}` shape.
                // Previously this returned None, silently dropping a cross-protocol reasoning stream.
                busbar_core::ir::IrDelta::ThinkingDelta(thinking) => Some((
                    "".to_string(),
                    serde_json::json!({
                        "candidates": [{
                            "content": {
                                "role": "model",
                                "parts": [{"text": thinking, "thought": true}]
                            }
                        }]
                    }),
                )),

                // SignatureDelta → a streamed thought part carrying the opaque resumable
                // `thoughtSignature`. Gemini attaches the signature to a `thought:true` part
                // (non-stream emits `{text, thought:true, thoughtSignature}`); on the stream the
                // signature arrives as its own IR delta, so emit a minimal thought part bearing the
                // signature (empty text, `thought:true`) — the closest faithful streamed form, since a
                // bare signature has no accompanying incremental text. Previously dropped (None).
                busbar_core::ir::IrDelta::SignatureDelta(sig) => Some((
                    "".to_string(),
                    serde_json::json!({
                        "candidates": [{
                            "content": {
                                "role": "model",
                                "parts": [{"text": "", "thought": true, "thoughtSignature": sig}]
                            }
                        }]
                    }),
                )),
                // A streamed redacted-reasoning delta (opaque encrypted bytes) has no Gemini analog —
                // drop it rather than emit a non-native part.
                busbar_core::ir::IrDelta::RedactedReasoningDelta(_) => None,

                // STREAMING citations → emit a candidate-level `citationMetadata.citationSources`
                // chunk, mirroring the non-stream `read_response`/`write_response` shape (Gemini
                // carries citations at the candidate level, not per part). `write_gemini_citation`
                // re-emits a byte-exact Gemini source verbatim when `raw` is Gemini-shaped (uri /
                // startIndex / endIndex present — the same-protocol path) and synthesizes one from the
                // neutral fields otherwise (e.g. an Anthropic-sourced citation on an Anthropic→Gemini
                // hop), so a foreign `raw` never leaks through this writer. An EMPTY citation vec
                // carries nothing → emit no chunk (None) rather than a stray empty `citationMetadata`.
                busbar_core::ir::IrDelta::CitationsDelta(citations) => {
                    if citations.is_empty() {
                        None
                    } else {
                        // STREAMING egress has no accumulated full response text to convert a
                        // foreign (non-Gemini-sourced) citation's character offsets back to bytes
                        // against — the same limitation the streaming READER documents (the
                        // conversion is scoped to the non-stream path on both sides). The `raw`
                        // short-circuit inside `write_gemini_citation` still makes the common
                        // same-protocol case byte-exact regardless.
                        let sources: Vec<serde_json::Value> = citations
                            .iter()
                            .map(|c| write_gemini_citation(c, "", 0))
                            .collect();
                        Some((
                            "".to_string(),
                            serde_json::json!({
                                "candidates": [{
                                    "citationMetadata": { "citationSources": sources }
                                }]
                            }),
                        ))
                    }
                }
                busbar_core::ir::IrDelta::LogprobsDelta(lps) => {
                    // Streamed logprobs (e.g. an OpenAI backend's per-chunk `logprobs.content[]`)
                    // in Gemini's native chunk shape: a candidate carrying only `logprobsResult`.
                    // An empty vec carries nothing and emits no frame.
                    if lps.is_empty() {
                        None
                    } else {
                        Some((
                            "".to_string(),
                            serde_json::json!({
                                "candidates": [{
                                    "logprobsResult": write_gemini_logprobs_result(lps)
                                }]
                            }),
                        ))
                    }
                }
            },

            // BlockStop → FLUSH the open tool block as a single native `{name, args}` part. This is
            // the ONLY point a functionCall frame is written: by here every arg fragment has been
            // accumulated, so the buffered arg string is the COMPLETE `arguments` JSON and parses
            // once into the args object (a multi-chunk stream reassembles correctly; a zero-arg call
            // — empty buffer — flushes `args:{}`, so the call is never lost). A non-tool BlockStop
            // (text block, or an index with no tracked tool) finds no entry and emits no frame. The
            // matched entry is REMOVED so parallel tool blocks each flush exactly once. A poisoned
            // lock degrades to no frame rather than panicking on the request path.
            IrStreamEvent::BlockStop { index } => {
                let flushed = match self.open_tools.lock() {
                    Ok(mut guard) => guard
                        .iter()
                        .position(|(idx, _, _)| idx == index)
                        .map(|pos| {
                            let (_, name, args) = guard.remove(pos);
                            (name, args)
                        }),
                    Err(_) => None,
                };
                flushed.map(|(name, args_str)| {
                    // Parse the fully reassembled arg string. An empty buffer (zero-arg call) or an
                    // unparseable accumulation degrades to `{}` rather than panicking — the args are
                    // best-effort, but the single-part `{name, ...}` shape and the name are always
                    // preserved.
                    let args: serde_json::Value = if args_str.is_empty() {
                        serde_json::json!({})
                    } else {
                        busbar_core::json::parse_str(&args_str)
                            .unwrap_or_else(|_| serde_json::json!({}))
                    };
                    let mut fc_obj = serde_json::Map::new();
                    fc_obj.insert("name".to_string(), serde_json::json!(name));
                    fc_obj.insert("args".to_string(), args);
                    let mut part_obj = serde_json::Map::new();
                    part_obj.insert(
                        FIELD_FUNCTION_CALL.to_string(),
                        serde_json::Value::Object(fc_obj),
                    );
                    (
                        "".to_string(),
                        serde_json::json!({
                            "candidates": [{
                                "content": {
                                    "role": "model",
                                    "parts": [serde_json::Value::Object(part_obj)]
                                }
                            }]
                        }),
                    )
                })
            }

            // MessageDelta → chunk with finishReason + usageMetadata
            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
            } => {
                let finish_reason = stop_reason
                    .map(write_gemini_stop_reason)
                    .unwrap_or(GEMINI_FINISH_STOP);

                // Native Gemini SSE carries `usageMetadata` (incl. `totalTokenCount`) on the final
                // chunk; a strict google-genai client computing totals reads `totalTokenCount`.
                // Emit it (= prompt + candidates, saturating) alongside the component counts so the
                // streamed usage frame matches the native final-chunk shape. This path runs only on
                // cross-protocol egress (same-protocol Gemini streams pass through byte-for-byte and
                // never reach this writer), so emitting the total here cannot disturb a same-protocol
                // round-trip. Saturating add avoids an overflow panic on the request path for
                // pathological/garbage counts.
                // RECONSTRUCT the native WIRE shape from the normalized IR: the IR stores UNCACHED
                // input, but Gemini's `promptTokenCount` is a TOTAL that includes the cached prefix,
                // so add `cache_read` back. Emit `cachedContentTokenCount` only when a cache read is
                // present (native shape — no spurious field otherwise). `totalTokenCount` is the
                // full prompt total + candidates.
                let cache_read = usage.cache_read_input_tokens.unwrap_or(0);
                // cache_creation is ALSO part of the TOTAL prompt count (cross-protocol ingress only).
                let prompt_total = usage
                    .input_tokens
                    .saturating_add(cache_read)
                    .saturating_add(usage.cache_creation_input_tokens.unwrap_or(0));
                let total = prompt_total.saturating_add(usage.output_tokens);
                let mut usage_metadata = serde_json::Map::new();
                usage_metadata.insert(
                    FIELD_PROMPT_TOKEN_COUNT.to_string(),
                    serde_json::json!(prompt_total),
                );
                usage_metadata.insert(
                    FIELD_CANDIDATES_TOKEN_COUNT.to_string(),
                    serde_json::json!(usage.output_tokens),
                );
                usage_metadata.insert(
                    FIELD_TOTAL_TOKEN_COUNT.to_string(),
                    serde_json::json!(total),
                );
                if usage.cache_read_input_tokens.is_some() {
                    usage_metadata.insert(
                        FIELD_CACHED_CONTENT_TOKEN_COUNT.to_string(),
                        serde_json::json!(cache_read),
                    );
                }
                let mut candidate_obj = serde_json::Map::new();
                candidate_obj.insert(
                    FIELD_FINISH_REASON.to_string(),
                    serde_json::json!(finish_reason),
                );
                let mut out_obj = serde_json::Map::new();
                out_obj.insert(
                    "candidates".to_string(),
                    serde_json::Value::Array(vec![serde_json::Value::Object(candidate_obj)]),
                );
                out_obj.insert(
                    FIELD_USAGE_METADATA.to_string(),
                    serde_json::Value::Object(usage_metadata),
                );
                Some(("".to_string(), serde_json::Value::Object(out_obj)))
            }

            // MessageStop → None (no frame needed)
            IrStreamEvent::MessageStop => None,

            // Error → full google.rpc.Status envelope `{"error":{"code","message","status"}}`.
            // Real Gemini stream errors carry an HTTP `code` (int) and an UPPER_SNAKE `status`
            // (e.g. INTERNAL, UNAVAILABLE, RESOURCE_EXHAUSTED); a Gemini SDK branches on
            // `error.status`/`error.code`. Emitting only `message` (as before) was detectable and
            // left SDK retry-decision code reading null. We derive `code`/`status` from the
            // canonical `StatusClass`; an untyped/unknown class falls back to 500 / INTERNAL.
            IrStreamEvent::Error(err) => {
                let (code, status_name) = gemini_stream_error_code_status(err.class);
                let message = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "error".to_string());
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "error": {
                            "code": code,
                            "message": message,
                            "status": status_name,
                        }
                    }),
                ))
            }
        }
    }

    fn write_error_frame(&self, err: &IrError) -> Option<(String, serde_json::Value)> {
        // The streaming-error seam: delegate to this dialect's own event writer so the mid-stream
        // error frame is byte-for-byte what an `Error` event produces on this wire.
        self.write_response_event(&IrStreamEvent::Error(err.clone()))
    }

    fn write_response(&self, resp: &busbar_core::ir::IrResponse) -> serde_json::Value {
        // Build candidates array (Gemini whole-response format)
        let mut parts_arr: Vec<serde_json::Value> = Vec::new();

        // Collect citations from every Text block to re-emit at the candidate level
        // (`candidates[].citationMetadata.citationSources[]`) — Gemini carries citations there, not
        // per content-part. The reader anchors them to a Text block, with indices relative to THAT
        // block's own text (see `attach_gemini_citations_to_text_blocks`); here we hoist them back
        // out to candidate level and un-shift each converted (non-`raw`) index by `byte_prefix` — the
        // BYTE length of every text block already emitted — so a citation whose block is not the
        // first text part still lands on the correct candidate-wide wire offset.
        let mut citation_sources: Vec<serde_json::Value> = Vec::new();
        let mut byte_prefix: i64 = 0;

        for block in &resp.content {
            match block {
                busbar_core::ir::IrBlock::Text {
                    text, citations, ..
                } => {
                    for c in citations {
                        citation_sources.push(write_gemini_citation(c, text, byte_prefix));
                    }
                    byte_prefix += text.len() as i64;
                    if !text.is_empty() {
                        parts_arr.push(serde_json::json!({"text": text}));
                    }
                }

                // ToolUse → functionCall{name, args}. `args` MUST be a JSON OBJECT (Gemini Struct);
                // coerce any non-object input (array/scalar/null/unparseable string) the same way
                // `write_request` does.
                busbar_core::ir::IrBlock::ToolUse {
                    id: _,
                    name,
                    input,
                    thought_signature,
                    ..
                } => {
                    let args_val = coerce_tool_args(input);
                    let mut fc_obj = serde_json::Map::new();
                    fc_obj.insert("name".to_string(), serde_json::json!(name));
                    fc_obj.insert("args".to_string(), args_val);
                    let mut part_obj = serde_json::Map::new();
                    part_obj.insert(
                        FIELD_FUNCTION_CALL.to_string(),
                        serde_json::Value::Object(fc_obj),
                    );
                    // `thoughtSignature` sibling of `functionCall`, mirroring `write_request`. This
                    // writer talks to a real client and `prepare_for_egress` is request-side only, so
                    // this path never gets sentinel-injected — it only ever carries a real value, when
                    // Gemini was the response SOURCE and its own reader captured one. Never fabricate
                    // one here; omit the key when absent.
                    if let Some(sig) = thought_signature {
                        part_obj.insert("thoughtSignature".to_string(), serde_json::json!(sig));
                    }
                    parts_arr.push(serde_json::Value::Object(part_obj));
                }

                // Thinking → Gemini `{text, thought:true, thoughtSignature?}`. Gemini DOES
                // surface reasoning as a `thought:true` content part with an opaque resumable
                // `thoughtSignature`; emit it so reasoning + signature round-trip on the response
                // path instead of being dropped.
                // A REDACTED reasoning block holds opaque encrypted bytes with no Gemini analog —
                // drop it (emitting its `text` would leak the encrypted bytes as visible reasoning).
                busbar_core::ir::IrBlock::Thinking { redacted: true, .. } => {}
                busbar_core::ir::IrBlock::Thinking {
                    text, signature, ..
                } => {
                    let mut part = serde_json::Map::new();
                    part.insert("text".to_string(), serde_json::json!(text));
                    part.insert("thought".to_string(), serde_json::json!(true));
                    if let Some(sig) = signature {
                        part.insert("thoughtSignature".to_string(), serde_json::json!(sig));
                    }
                    parts_arr.push(serde_json::Value::Object(part));
                }

                // Image/Media/ToolResult not supported in response OUTPUT (a model does not emit
                // an attachment back on this surface), so nothing is lost by omitting them here.
                busbar_core::ir::IrBlock::Image { .. }
                | busbar_core::ir::IrBlock::Media { .. }
                | busbar_core::ir::IrBlock::ToolResult { .. }
                | busbar_core::ir::IrBlock::Json(_) => {}
            }
        }

        let finish_reason = resp
            .stop_reason
            .map(write_gemini_stop_reason)
            .unwrap_or(GEMINI_FINISH_STOP);

        // A native Gemini `generateContent` response ALWAYS carries
        // `usageMetadata.totalTokenCount` (= promptTokenCount + candidatesTokenCount); the
        // google-genai SDK surfaces it as `usage_metadata.total_token_count` for billing/accounting.
        // On the CROSS-protocol egress path a native Gemini client therefore expects the sum, and the
        // value is a faithfully DERIVED total from the IR counts — not a fabricated field — so we emit
        // it (mirroring the stream final-chunk frame), closing a concrete token-accounting gap and a
        // distinguishability tell. `saturating_add` avoids an overflow panic on the request path.
        //
        // We gate emission on a cross-protocol BOUNDARY signal: `resp.created.is_some()` OR
        // `resp.model.is_some()`. Gemini bodies carry no `created`, so a populated `created` means a
        // non-Gemini backend reader set it (the OpenAI reader does) — but the Anthropic, Bedrock, and
        // Cohere readers all return `created: None`, so `created` ALONE missed three of the five
        // foreign backends, dropping `totalTokenCount` for a Gemini client routed to them (the
        // google-genai SDK then read `usage_metadata.total_token_count` as None, breaking billing).
        // The Anthropic and Cohere readers DO populate `model` from the upstream body (a real
        // Anthropic `Message` / Cohere response always names its model), so OR-ing `model.is_some()`
        // closes the gap for those two as well. Bedrock's Converse body carries no body-level model
        // or timestamp, so its IR was identity-field-empty here — the residual that this gate alone
        // could not distinguish from a minimal native body. That residual is now closed UPSTREAM at
        // the cross-protocol seam (`proxy engine`), which stamps a synthesized `created` on any
        // identity-empty egress IR before this writer runs, so a Bedrock→Gemini hop arrives with
        // `created.is_some()` and emits `totalTokenCount` here just like the other backends. The OR
        // on `model` stays as defense-in-depth for any caller of this writer that bypasses the seam.
        //
        // This still keeps a SAME-protocol read→write idempotent on the in-IR identity invariant that
        // `src/proto/mod.rs::test_gemini_read_write_response_roundtrip` guards: that fixture is a
        // native Gemini body with neither `modelVersion` nor a timestamp, so `model`/`created` are
        // BOTH `None` and no `totalTokenCount` is injected — the round-trip stays byte-identical.
        // (`write_response` only ever runs on cross-protocol egress in production — same-protocol
        // passthrough is byte-exact and bypasses the writer — so this gate is conservative there.)
        // RECONSTRUCT the native WIRE shape from the normalized IR: the IR stores UNCACHED input,
        // but Gemini's `promptTokenCount` is a TOTAL that includes the cached prefix, so add
        // `cache_read` back. Emit `cachedContentTokenCount` only when a cache read is present (native
        // shape — no spurious field on a no-cache roundtrip).
        let cache_read = resp.usage.cache_read_input_tokens.unwrap_or(0);
        // cache_creation is ALSO part of the TOTAL prompt count (cross-protocol ingress only).
        let prompt_total = resp
            .usage
            .input_tokens
            .saturating_add(cache_read)
            .saturating_add(resp.usage.cache_creation_input_tokens.unwrap_or(0));
        let mut usage_metadata = serde_json::Map::new();
        usage_metadata.insert(
            FIELD_PROMPT_TOKEN_COUNT.to_string(),
            serde_json::json!(prompt_total),
        );
        usage_metadata.insert(
            FIELD_CANDIDATES_TOKEN_COUNT.to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );
        if resp.usage.cache_read_input_tokens.is_some() {
            usage_metadata.insert(
                FIELD_CACHED_CONTENT_TOKEN_COUNT.to_string(),
                serde_json::json!(cache_read),
            );
        }
        if resp.created.is_some() || resp.model.is_some() {
            let total = prompt_total.saturating_add(resp.usage.output_tokens);
            usage_metadata.insert(
                FIELD_TOTAL_TOKEN_COUNT.to_string(),
                serde_json::json!(total),
            );
        }
        let mut candidate = serde_json::json!({
            "content": {
                "role": "model",
                "parts": parts_arr
            }
        });
        candidate[FIELD_FINISH_REASON] = serde_json::json!(finish_reason);
        // Re-emit candidate-level citationMetadata when the IR carried citations (grounding /
        // web-search). Only emitted when non-empty so a normal response stays byte-identical.
        if !citation_sources.is_empty() {
            candidate["citationMetadata"] = serde_json::json!({
                "citationSources": citation_sources
            });
        }
        // Carried per-token logprobs (e.g. from an OpenAI backend's `choices[].logprobs`) in
        // Gemini's native candidate shape. Only emitted when the backend produced them, matching
        // Gemini's own omission when `responseLogprobs` was not requested.
        if !resp.logprobs.is_empty() {
            candidate["logprobsResult"] = write_gemini_logprobs_result(&resp.logprobs);
        }
        let mut out = serde_json::json!({
            "candidates": [candidate]
        });
        out[FIELD_USAGE_METADATA] = serde_json::Value::Object(usage_metadata);
        // model that served the response (preserved across cross-protocol translation)
        if let Some(ref model) = resp.model {
            out[FIELD_MODEL_VERSION] = serde_json::json!(model);
        }
        // Response identity. This mirrors the Anthropic writer's id rule, keying synthesis off
        // "did we cross a protocol boundary" (proxied by `created` being populated) rather than off
        // `id` alone, so same-protocol round-trips stay idempotent. Three cases:
        //   * Same-protocol passthrough: the Gemini reader set `id` from the upstream `responseId`
        //     (and `created == None`, since Gemini bodies carry no timestamp), so it is re-emitted
        //     verbatim — `(Some(id), _)`.
        //   * Cross-protocol with a foreign id present: the non-Gemini backend reader set `id` to
        //     that protocol's response id (OpenAI `chatcmpl-…`, Anthropic `msg_…`); the id is opaque
        //     to the Gemini SDK (Gemini ids carry no documented prefix it could reject), so we
        //     surface it verbatim — `(Some(id), _)`.
        //   * Cross-protocol with NO foreign id: `proxy engine` strips `id` to `None` on every
        //     cross-protocol response but LEAVES `created` populated as the boundary signal, so
        //     `(None, Some(_))` — synthesize a Gemini-shaped `responseId` so a native `google-genai`
        //     client reading `GenerateContentResponse.response_id` always sees a value (real Gemini
        //     responses carry one). Previously this case omitted `responseId` on EVERY
        //     cross-protocol response, a distinguishability signal; the old comment wrongly claimed a
        //     value was "always present", contradicting `proxy engine` which sets `ir.id = None`.
        //   * Minimal same-protocol IR with neither id nor created: a native body that legitimately
        //     omitted `responseId` yields `(None, None)` — omit it rather than fabricate, since
        //     `responseId` is `Optional` in the Gemini schema / SDK and fabricating one would make a
        //     read→write round-trip distinguishable from the native response.
        // Gemini bodies carry no `created`, so none is emitted in the wire shape.
        match (&resp.id, resp.created) {
            (Some(id), _) => {
                out[FIELD_RESPONSE_ID] = serde_json::json!(id);
            }
            (None, Some(_)) => {
                out[FIELD_RESPONSE_ID] = serde_json::json!(synth_response_id());
            }
            (None, None) => {}
        }
        out
    }

    fn make_array_stream_framer(&self) -> Option<Box<dyn busbar_core::proto::JsonArrayFramer>> {
        // Gemini `:streamGenerateContent` WITHOUT `?alt=sse` expects a JSON-array streamed body; this
        // builds the framer that reframes the (gemini-shape) SSE bytes into that array. The forward
        // path engages it only when `uses_array_stream_shim()` AND `wants_array_stream(body)` hold.
        Some(Box::new(GeminiJsonArrayFramer::new()))
    }

    fn wants_array_stream(&self, body: &serde_json::Value) -> bool {
        // The gemini ingress route injects `GEMINI_JSON_ARRAY_SHIM_KEY: true` when the client sent a
        // streaming `:streamGenerateContent` request WITHOUT `?alt=sse`. Read it here (the only site
        // that knows this shim key) so the forward core stays shim-key-agnostic.
        body.get(GEMINI_JSON_ARRAY_SHIM_KEY)
            .and_then(|b| b.as_bool())
            .unwrap_or(false)
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}

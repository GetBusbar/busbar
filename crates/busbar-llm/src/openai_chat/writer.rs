use super::*;

impl ProtocolWriter for OpenAiWriter {
    fn upstream_path(&self) -> &str {
        PATH_UPSTREAM
    }

    /// OpenAI chat completions express the candidate count as top-level `n`. `Some(k)` only for a
    /// genuine `k > 1` ask; absent/1/unparseable → `None`. See the trait doc for why the engine
    /// rejects `n > 1` on a cross-protocol route (the single-candidate IR would drop candidates
    /// `1..n`).
    fn requested_candidate_count(&self, body: &serde_json::Value) -> Option<u64> {
        body.get("n").and_then(|v| v.as_u64()).filter(|&k| k > 1)
    }

    fn write_request(&self, req: &busbar_core::ir::IrRequest) -> serde_json::Value {
        let mut messages_array: Vec<serde_json::Value> = Vec::new();

        // Prepend system message as first message if present. OpenAI system messages carry plain
        // text only, so every system block is projected to text EXPLICITLY here rather than via a
        // silent `if let Text` that would drop non-text blocks without a trace (the prior behavior).
        // Text and Thinking both carry textual system guidance and are forwarded; the structurally
        // text-less variants (ToolUse / ToolResult / Image) have no OpenAI system representation and
        // are projected to empty text — a documented lossy projection, not a silent drop. The match
        // is exhaustive (no `_ =>` catch-all) so a future IrBlock variant forces a compile error.
        for block in &req.system {
            let text: &str = match block {
                busbar_core::ir::IrBlock::Text { text, .. } => text,
                busbar_core::ir::IrBlock::Thinking { text, .. } => text,
                busbar_core::ir::IrBlock::ToolUse { .. }
                | busbar_core::ir::IrBlock::ToolResult { .. }
                | busbar_core::ir::IrBlock::Image { .. }
                | busbar_core::ir::IrBlock::Media { .. }
                | busbar_core::ir::IrBlock::Json(_) => "",
            };
            messages_array.push(serde_json::json!({
                "role": "system",
                "content": text
            }));
        }

        // Per-message participant names parked by this protocol's own reader (see
        // `MESSAGE_NAMES_SENTINEL`). Present only on a SAME-protocol path — the cross-protocol seam
        // clears `extra` — which is exactly the scope `name` can survive in, since no other protocol
        // models it.
        let message_names = req
            .extra
            .get(MESSAGE_NAMES_SENTINEL)
            .and_then(|v| v.as_object());

        // Add regular messages
        for (msg_idx, msg) in req.messages.iter().enumerate() {
            let role_str = match msg.role {
                busbar_core::ir::IrRole::User => "user",
                busbar_core::ir::IrRole::Assistant => "assistant",
                busbar_core::ir::IrRole::Tool => "tool",
                busbar_core::ir::IrRole::System => "system",
            };

            let content_val: serde_json::Value = if msg.content.is_empty() {
                serde_json::json!("")
            } else {
                let mut content_arr: Vec<serde_json::Value> = Vec::new();

                for block in &msg.content {
                    match block {
                        busbar_core::ir::IrBlock::Text { text, .. } => {
                            content_arr.push(serde_json::json!({ "type": "text", "text": text }));
                        }
                        busbar_core::ir::IrBlock::Image { source, .. } => {
                            // A URL is emitted verbatim, a base64 image re-wrapped as a data URI. A
                            // Responses `file_id` / Bedrock `s3Location` reference has no `image_url`
                            // projection (image_url_from_ir returns None) — SKIP it with a warn rather
                            // than corrupt the block.
                            match busbar_core::proto::image_url_from_ir(source) {
                                Some(url) => content_arr.push(serde_json::json!({
                                    "type": "image_url",
                                    "image_url": { "url": url }
                                })),
                                None => tracing::warn!(
                                    "dropping unresolvable vendor-scoped image reference on OpenAI \
                                     egress: a Responses input_image.file_id or a Bedrock s3Location \
                                     has no cross-vendor analog; the block is NOT emitted"
                                ),
                            }
                        }
                        busbar_core::ir::IrBlock::Media {
                            kind, source, name, ..
                        } => {
                            if let Some(part) =
                                super::media_part_from_ir(*kind, source, name.as_deref())
                            {
                                content_arr.push(part);
                            }
                        }
                        busbar_core::ir::IrBlock::ToolUse { .. } => {
                            // ToolUse is not OpenAI message content; it is surfaced via the
                            // `tool_calls` array built for this message below (any role).
                        }
                        busbar_core::ir::IrBlock::ToolResult { .. } => {
                            // ToolResult is not OpenAI message *content*; for a Tool-role message it
                            // is rendered as a standalone `{"role":"tool","tool_call_id":...}` entry
                            // by the tool-result path below. On a non-tool message it has no OpenAI
                            // content representation, so it is intentionally not emitted here.
                        }
                        busbar_core::ir::IrBlock::Thinking { .. } => {
                            // Lossy-by-necessity: OpenAI Chat Completions has no thinking/reasoning
                            // content block on request input, so a Thinking block is dropped here.
                        }
                        busbar_core::ir::IrBlock::Json(_) => {
                            // Structured-json (a Bedrock tool-result content member) has no OpenAI
                            // message-content shape; dropped here.
                        }
                    }
                }

                // A message carrying only ToolUse blocks (a tool-call-only assistant turn) yields an
                // empty content_arr: ToolUse is surfaced via `tool_calls`, not `content`. The OpenAI
                // Chat Completions API expects such messages to have `content: null`, not `[]` — some
                // validators reject an empty array alongside `tool_calls`. Emit Null in that case.
                if content_arr.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::Array(content_arr)
                }
            };

            let mut msg_obj = serde_json::json!({
                "role": role_str,
                "content": content_val,
            });

            // Re-emit the participant `name` this message arrived with. Without this a pool-alias
            // route (which rewrites the model and therefore re-serializes instead of forwarding the
            // caller's bytes) silently stripped `name` from every message on an otherwise
            // same-protocol OpenAI→OpenAI hop.
            if let Some(name) = message_names
                .and_then(|m| m.get(&msg_idx.to_string()))
                .and_then(|v| v.as_str())
            {
                if let Some(o) = msg_obj.as_object_mut() {
                    o.insert("name".to_string(), serde_json::json!(name));
                }
            }

            // Emit tool_calls for ANY message carrying ToolUse blocks, not only assistant ones.
            // A ToolUse on a non-assistant role is unusual but legal in the IR; gating this on the
            // assistant role silently dropped such tool calls. Building tool_calls for the block's
            // own message is non-lossy and keeps the id/arguments round-tripping.
            {
                let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();
                for block in &msg.content {
                    if let busbar_core::ir::IrBlock::ToolUse {
                        id, name, input, ..
                    } = block
                    {
                        // Serialize input to JSON string
                        let args_str =
                            busbar_core::proto::openai_family::tool_arguments_to_string(input);
                        // Preserve the original tool_call id verbatim — it must round-trip so the
                        // assistant tool_call correlates with the tool-result `tool_call_id`.
                        tool_calls_arr.push(serde_json::json!({
                            "type": TOOL_TYPE_FUNCTION,
                            "id": id,
                            "function": {
                                "name": name,
                                "arguments": args_str
                            }
                        }));
                    }
                }

                if !tool_calls_arr.is_empty() {
                    msg_obj["tool_calls"] = serde_json::Value::Array(tool_calls_arr);
                }
            }

            // Handle tool results. Emit a flat `{"role":"tool",...}` entry for ANY message whose
            // content carries ToolResult blocks, REGARDLESS of the message role — not only
            // IrRole::Tool. A Gemini `functionResponse` decodes to an IrRole::User message carrying a
            // ToolResult block (and an Anthropic tool_result lives on a User-role message too); gating
            // this on IrRole::Tool SILENTLY DROPPED that tool result on Gemini→OpenAI / Anthropic→OpenAI
            // (the ToolResult arm in the content loop above is a no-op, and `tool_calls` only carries
            // ToolUse). Keying on the presence of a ToolResult block — the writer-side, source-agnostic
            // fix — surfaces it correctly for every source protocol.
            let has_tool_result = msg
                .content
                .iter()
                .any(|b| matches!(b, busbar_core::ir::IrBlock::ToolResult { .. }));
            if has_tool_result {
                let mut emitted_tool_result = false;
                for block in &msg.content {
                    if let busbar_core::ir::IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    } = block
                    {
                        let mut tool_result_obj = serde_json::json!({
                            "role": "tool",
                            "tool_call_id": tool_use_id,
                            "content": "",
                        });

                        // Concatenate text content with NO separator, matching the OpenAI READ path
                        // (which uses `push_str` with no separator at the symmetric site). Joining
                        // with a space injected spurious spaces between adjacent text blocks on an
                        // Anthropic→OpenAI ToolResult hop (`["A","B"]` → `"A B"`), corrupting content
                        // that is boundary-sensitive (base64, JSON split across blocks). `concat()`
                        // keeps the cross-protocol round-trip lossless.
                        if !content.is_empty() {
                            let text_parts: Vec<String> = content
                                .iter()
                                .filter_map(|b| {
                                    if let busbar_core::ir::IrBlock::Text { text, .. } = b {
                                        Some(text.clone())
                                    } else {
                                        // A non-Text ToolResult block is a Bedrock json-tool-result
                                        // sentinel (structured `{"json":...}` data) with no OpenAI
                                        // analog. Drop it WITH a warn so the loss is observable
                                        // (matches the drop-with-warn convention) rather than vanishing
                                        // silently.
                                        if super::is_json_tool_result_block(b) {
                                            tracing::warn!(
                                                "dropping structured json tool-result block on \
                                                 OpenAI egress: a Bedrock `{{\"json\":...}}` \
                                                 tool-result has no cross-protocol analog and is NOT \
                                                 emitted"
                                            );
                                        }
                                        None
                                    }
                                })
                                .collect();

                            tool_result_obj["content"] = serde_json::json!(text_parts.concat());
                        }

                        messages_array.push(tool_result_obj);
                        emitted_tool_result = true;
                    }
                }

                // A well-formed tool-result message carries ONLY ToolResult blocks, each emitted
                // above as a standalone `{"role":"tool",...}` entry; `msg_obj` is intentionally NOT
                // added for that case. But the message can ALSO carry non-ToolResult content (Text/
                // Image projected into `content_val`, or ToolUse projected into `msg_obj["tool_calls"]`)
                // — e.g. a Gemini turn that pairs a functionResponse with narration text. Previously
                // that content was silently dropped because `msg_obj` was never pushed on this path.
                // Surface it instead: push `msg_obj` when it carries any non-ToolResult payload
                // (non-null `content` or a `tool_calls` array), or when the message had NO ToolResult
                // block at all (so an otherwise-empty message is not lost). This never duplicates a
                // ToolResult — those are the standalone entries above and never appear in `content_val`.
                let msg_has_payload = msg_obj.get("content").is_some_and(|c| !c.is_null())
                    || msg_obj.get("tool_calls").is_some();
                if msg_has_payload || !emitted_tool_result {
                    messages_array.push(msg_obj);
                }
            } else {
                // No ToolResult content: add the message to the array directly (tool results are
                // handled in the branch above, keyed on the presence of a ToolResult block).
                messages_array.push(msg_obj);
            }
        }

        let mut out = serde_json::Map::new();

        // Add model from extra if present (since IrRequest doesn't have a model field)
        if let Some(model_val) = req.extra.get("model") {
            out.insert("model".to_string(), model_val.clone());
        }

        out.insert(
            "messages".to_string(),
            serde_json::Value::Array(messages_array),
        );

        // Emit the modeled output-token cap. The reader promotes BOTH `max_tokens` and the modern
        // `max_completion_tokens` into this one IR field (so a caller's limit survives the
        // cross-protocol seam). Re-emit under the SOURCE spelling when the sentinel says the cap
        // arrived as `max_completion_tokens` — OpenAI's o1/o3 reasoning models REQUIRE
        // `max_completion_tokens` and 400 on `max_tokens`, so an OpenAI->OpenAI passthrough to such a
        // model must preserve the modern key. The sentinel only survives the same-protocol path (extra
        // is cleared cross-protocol), so a cross-protocol egress falls back to the canonical
        // `max_tokens` (other protocols have no `max_completion_tokens`). For the common
        // (non-reasoning) same-protocol case the sentinel is absent and we emit `max_tokens`.
        if let Some(max_tokens) = req.max_tokens {
            let key = if req
                .extra
                .get(MAX_COMPLETION_TOKENS_SENTINEL)
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                "max_completion_tokens"
            } else {
                "max_tokens"
            };
            out.insert(key.to_string(), serde_json::json!(max_tokens));
        }

        if let Some(temperature) = req.temperature {
            out.insert("temperature".to_string(), serde_json::json!(temperature));
        }

        // Promoted sampling controls: emit `top_p` and `stop` in OpenAI's native shape. OpenAI has NO
        // top_k parameter, so `req.top_k` is intentionally NOT emitted (lossy-by-target — a source
        // protocol's top_k cannot be honored by the OpenAI API). `stop` serializes as the array form
        // (OpenAI accepts both a string and an array; the array is always valid).
        if let Some(top_p) = req.top_p {
            out.insert("top_p".to_string(), serde_json::json!(top_p));
        }
        if !req.stop.is_empty() {
            // NEVER truncate here: an over-cap `req.stop` is rejected up front, at the
            // cross-protocol seam, by `ChatOperation::egress_representable` consulting
            // `stop_sequence_cap()` below — before `write_request` ever runs. A same-protocol
            // OpenAI->OpenAI request never rebuilds its body from the IR (verbatim relay), so it
            // never reaches this writer either. By the time this line runs, `req.stop.len()` is
            // guaranteed `<= 4`; forward it whole rather than re-deriving a silent, partial cap
            // here that could drift from the reject's cap.
            out.insert("stop".to_string(), serde_json::json!(req.stop));
        }

        // First-class sampling/output controls. Emitted in OpenAI's native top-level shape and
        // omitted entirely when None. `response_format` is written back verbatim (the raw Value read in).
        if let Some(frequency_penalty) = req.frequency_penalty {
            out.insert(
                "frequency_penalty".to_string(),
                serde_json::json!(frequency_penalty),
            );
        }
        if let Some(presence_penalty) = req.presence_penalty {
            out.insert(
                "presence_penalty".to_string(),
                serde_json::json!(presence_penalty),
            );
        }
        if let Some(seed) = req.seed {
            out.insert("seed".to_string(), serde_json::json!(seed));
        }
        if let Some(n) = req.n {
            out.insert("n".to_string(), serde_json::json!(n));
        }
        // The Anthropic-analog carries, re-emitted in OpenAI's native spelling (an Anthropic
        // `metadata.user_id` arrives here as `user`; `disable_parallel_tool_use` arrives inverted).
        if let Some(user) = &req.user {
            out.insert("user".to_string(), serde_json::json!(user));
        }
        // OpenAI rejects `parallel_tool_calls` when no tools are present ("only allowed when 'tools'
        // are specified"). An Anthropic source can carry the flag (via `disable_parallel_tool_use`)
        // on a tool-less request, so gate the emission on tools — matching the Anthropic writer,
        // which only emits its equivalent when tools are present.
        if let (Some(parallel), false) = (req.parallel_tool_calls, req.tools.is_empty()) {
            out.insert(
                "parallel_tool_calls".to_string(),
                serde_json::json!(parallel),
            );
        }
        // The reasoning carry in chat-completions spelling: `reasoning_effort`. A numeric budget
        // (Anthropic/Gemini source) is bucketized through the effort table.
        if let Some(ask) = req.reasoning {
            let table = req
                .reasoning_budgets
                .unwrap_or(busbar_core::ir::REASONING_BUDGET_DEFAULTS);
            out.insert(
                "reasoning_effort".to_string(),
                serde_json::json!(ask.to_effort(table).as_openai_reasoning_effort()),
            );
        }
        // The logprobs ask in OpenAI's native spelling (a Gemini `responseLogprobs`/`logprobs`
        // arrives here via the IR).
        // OpenAI requires `logprobs: true` for `top_logprobs` to be valid. Force the enabling flag
        // whenever the count is present, even if the source protocol only carried the count (a
        // Gemini request with `logprobs: N` but no `responseLogprobs`) — otherwise OpenAI 400s.
        if let Some(top_logprobs) = req.top_logprobs {
            out.insert("logprobs".to_string(), serde_json::json!(true));
            out.insert("top_logprobs".to_string(), serde_json::json!(top_logprobs));
        } else if let Some(logprobs) = req.logprobs {
            out.insert("logprobs".to_string(), serde_json::json!(logprobs));
        }
        if let Some(response_format) = &req.response_format {
            out.insert(
                "response_format".to_string(),
                write_openai_response_format(response_format),
            );
        }

        out.insert("stream".to_string(), serde_json::json!(req.stream));

        // Add tools if present. The Chat Completions API requires the NESTED tool shape
        // `{"type":"function","function":{"name":...,"description":...,"parameters":...}}` — name,
        // description, and parameters live INSIDE the `function` sub-object, not at the top level.
        // Emitting the flat `{"type":"function","name":...,"parameters":...}` shape is rejected with a
        // 400 by every native Chat Completions backend and SDK since late 2023, and the off-spec shape
        // is itself a proxy tell. `read_openai_tool` already reads from the nested `function` object,
        // so this writer is the inverse of the reader.
        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut function_obj = serde_json::Map::new();
                function_obj.insert("name".to_string(), serde_json::json!(tool.name));

                if let Some(desc) = &tool.description {
                    function_obj.insert("description".to_string(), serde_json::json!(desc));
                }

                // Map OpenAI's "parameters" to our input_schema
                let params = if !tool.input_schema.is_null() {
                    tool.input_schema.clone()
                } else {
                    serde_json::json!({})
                };
                function_obj.insert("parameters".to_string(), params);

                // STRICT function calling, in its native nested slot. Emitted only when the source
                // actually stated it — `None` means "the caller said nothing", and materializing
                // that as `strict: false` would be busbar inventing an explicit opt-out the caller
                // never wrote.
                if let Some(strict) = tool.strict {
                    function_obj.insert("strict".to_string(), serde_json::json!(strict));
                }

                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("type".to_string(), serde_json::json!(TOOL_TYPE_FUNCTION));
                tool_obj.insert(
                    "function".to_string(),
                    serde_json::Value::Object(function_obj),
                );

                tools_arr.push(serde_json::Value::Object(tool_obj));
            }
            out.insert("tools".to_string(), serde_json::Value::Array(tools_arr));
        }

        // Emit `tool_choice` in OpenAI's native shape when present so a forced/targeted tool
        // directive translated from another protocol round-trips instead of degrading to `auto`.
        // OpenAI's own 400 is `"tool_choice" is only allowed when "tools" are specified` (the same
        // reason the parallelism-carry guard just above already checks `!req.tools.is_empty()`), so
        // a tool_choice with no accompanying tools — e.g. a cross-protocol request whose hosted
        // tools `prepare_for_egress` stripped (`ir/variant.rs`) — must degrade with a warn, not ship
        // a guaranteed 400.
        if let Some(tc) = &req.tool_choice {
            if req.tools.is_empty() {
                tracing::warn!(
                    "dropping tool_choice on OpenAI egress: \"tool_choice\" is only allowed when \
                     \"tools\" are specified (likely because the hosted tools that carried it were \
                     stripped on the cross-protocol seam)"
                );
            } else {
                let v = match tc {
                    busbar_core::ir::IrToolChoice::Auto => serde_json::json!("auto"),
                    busbar_core::ir::IrToolChoice::None => serde_json::json!("none"),
                    busbar_core::ir::IrToolChoice::Required => serde_json::json!("required"),
                    busbar_core::ir::IrToolChoice::Tool { name } => {
                        serde_json::json!({"type": TOOL_TYPE_FUNCTION, "function": {"name": name}})
                    }
                };
                out.insert("tool_choice".to_string(), v);
            }
        }

        // Add extra fields
        for (key, value) in &req.extra {
            // The max-completion-tokens sentinel is a busbar-internal marker consumed above
            // (it selected the cap's emitted key); it is NOT a real OpenAI field, so skip it here so
            // it never leaks onto the wire (which would be an invalid body and a proxy tell).
            // Both busbar-internal markers are consumed above (one selected the cap's emitted key,
            // the other re-attached `messages[].name`); neither is a real OpenAI field, so neither
            // may reach the wire — that would be an invalid body AND a proxy tell.
            if key == MAX_COMPLETION_TOKENS_SENTINEL || key == MESSAGE_NAMES_SENTINEL {
                continue;
            }
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart {
                role,
                id,
                created,
                model,
                ..
            } => {
                let openai_role = match role {
                    busbar_core::ir::IrRole::Assistant => "assistant",
                    busbar_core::ir::IrRole::User
                    | busbar_core::ir::IrRole::System
                    | busbar_core::ir::IrRole::Tool => return None,
                };
                let delta_obj = serde_json::json!({ "role": openai_role });
                // The opening chunk carries the stream's identity (`id`, `created`, `model`); an
                // official OpenAI stream repeats these on every chunk, but emitting them on the first
                // (role) chunk is sufficient for the SDKs, which latch the id/created/model from the
                // first chunk that supplies them. When the backend supplied none (cross-protocol),
                // SYNTHESIZE a protocol-correct id/created so a native SDK accepts the stream.
                let chunk_id = id.clone().unwrap_or_else(synth_completion_id);
                let chunk_created = created.unwrap_or_else(busbar_core::store::now);
                // `model` is REQUIRED and non-nullable in the OpenAI chunk schema. A cross-protocol
                // backend (e.g. Bedrock) whose IR carries `model: None` must not yield a model-less
                // first chunk — that fails strict SDK (Pydantic) deserialisation and is a proxy tell —
                // so fall back to DEFAULT_MODEL rather than omitting the field.
                let chunk_model = model_or_default(model.as_deref());
                let chunk = serde_json::json!({
                    "id": chunk_id,
                    "object": OBJ_CHUNK,
                    "created": chunk_created,
                    "model": chunk_model,
                    "choices": [{
                        "index": 0,
                        "delta": delta_obj,
                        "finish_reason": null
                    }]
                });
                Some(("".to_string(), chunk))
            }
            IrStreamEvent::BlockStart { index, block } => match block {
                busbar_core::ir::IrBlockMeta::Text => None,
                busbar_core::ir::IrBlockMeta::ToolUse { id, name } => {
                    // Stamp the CANONICAL IR block index here so parallel tool calls keep distinct,
                    // stable keys and each call's BlockStart + BlockDeltas share ONE value. This is
                    // NOT necessarily 0-based (a source stream can open the first tool_use at a
                    // non-zero block index, e.g. text at block 0 then tool_use at block 1). OpenAI's
                    // streaming contract requires `tool_calls[].index` to ENUMERATE the calls from 0,
                    // so the OpenAI-ingress framing seam (`OpenAiStreamFraming::remap_tool_call_index`)
                    // remaps each distinct raw index to its 0-based ordinal on egress — keyed on the
                    // value emitted here. The writer stays 1:1 and stateless; the per-stream ordinal
                    // assignment lives in the framing, which is the only seam that sees the whole
                    // stream.
                    let delta_obj = serde_json::json!({
                        "tool_calls": [{
                            "index": index,
                            "id": id,
                            "type": TOOL_TYPE_FUNCTION,
                            "function": { "name": name, "arguments": "" }
                        }]
                    });
                    let chunk_obj = serde_json::json!({
                        "object": OBJ_CHUNK,
                        "choices": [{
                            "index": 0,
                            "delta": delta_obj,
                            "finish_reason": null
                        }]
                    });
                    Some(("".to_string(), chunk_obj))
                }
                busbar_core::ir::IrBlockMeta::Thinking | busbar_core::ir::IrBlockMeta::Image => {
                    None
                }
            },
            IrStreamEvent::BlockDelta { index, delta } => match delta {
                busbar_core::ir::IrDelta::TextDelta(text) => {
                    let delta_obj = serde_json::json!({ "content": text });
                    let chunk_obj = serde_json::json!({
                        "object": OBJ_CHUNK,
                        "choices": [{
                            "index": 0,
                            "delta": delta_obj,
                            "finish_reason": null
                        }]
                    });
                    Some(("".to_string(), chunk_obj))
                }
                busbar_core::ir::IrDelta::InputJsonDelta(json) => {
                    // Mirror the CANONICAL raw index emitted by the matching BlockStart so argument
                    // fragments route to the correct parallel tool call; the framing seam remaps this
                    // to the same 0-based ordinal it assigned the BlockStart.
                    let delta_obj = serde_json::json!({
                        "tool_calls": [{
                            "index": index,
                            "function": { "arguments": json }
                        }]
                    });
                    let chunk_obj = serde_json::json!({
                        "object": OBJ_CHUNK,
                        "choices": [{
                            "index": 0,
                            "delta": delta_obj,
                            "finish_reason": null
                        }]
                    });
                    Some(("".to_string(), chunk_obj))
                }
                busbar_core::ir::IrDelta::ThinkingDelta(_) => {
                    // Lossy-by-necessity: OpenAI has no thinking stream equivalent.
                    None
                }
                busbar_core::ir::IrDelta::SignatureDelta(_)
                | busbar_core::ir::IrDelta::RedactedReasoningDelta(_) => {
                    // Lossy-by-necessity: OpenAI has no signature/redacted-reasoning stream analog.
                    None
                }
                busbar_core::ir::IrDelta::CitationsDelta(cits) => {
                    // A `chat.completion.chunk` DOES carry `choices[].delta.annotations` — it is the
                    // same `url_citation` shape the NON-stream writer builds at `message.annotations`
                    // (see `write_response`), which is the proof the shape exists: this arm used to
                    // decline it, so the SAME request against the SAME backend returned sources at
                    // `stream:false` and no sources at `stream:true`. Nothing about the request
                    // explains that difference to the caller, which is what made it the worst shape
                    // of this loss rather than merely the largest.
                    //
                    // Offsets: the streamed text is not yet assembled here, so a citation whose
                    // span cannot be resolved is emitted WITHOUT one rather than with a fabricated
                    // one — `url_annotations`' span requirement is a non-stream, whole-text rule.
                    let annotations: Vec<serde_json::Value> = cits
                        .iter()
                        .filter_map(|c| {
                            let url = c.url.as_deref().filter(|u| !u.is_empty())?;
                            let mut uc = serde_json::Map::new();
                            uc.insert("url".to_string(), serde_json::json!(url));
                            uc.insert(
                                "title".to_string(),
                                serde_json::json!(c
                                    .title
                                    .as_deref()
                                    .filter(|t| !t.is_empty())
                                    .unwrap_or(url)),
                            );
                            if let (Some(s), Some(e)) = (c.start_index, c.end_index) {
                                if s >= 0 && e >= s {
                                    uc.insert("start_index".to_string(), serde_json::json!(s));
                                    uc.insert("end_index".to_string(), serde_json::json!(e));
                                }
                            }
                            Some(serde_json::json!({
                                "type": "url_citation",
                                "url_citation": serde_json::Value::Object(uc)
                            }))
                        })
                        .collect();
                    if annotations.is_empty() {
                        return None;
                    }
                    Some((
                        "".to_string(),
                        serde_json::json!({
                            "object": OBJ_CHUNK,
                            "choices": [{
                                "index": 0,
                                "delta": { "annotations": annotations },
                                "finish_reason": null
                            }]
                        }),
                    ))
                }
                busbar_core::ir::IrDelta::LogprobsDelta(lps) => {
                    // Streamed logprobs (e.g. a Gemini backend's per-chunk `logprobsResult`) in
                    // OpenAI's native chunk shape: `choices[].logprobs.content[]` alongside an
                    // empty delta. The SDK accumulates logprobs from chunks independently of
                    // content text, so a logprobs-only chunk parses cleanly. An empty vec carries
                    // nothing and emits no chunk.
                    if lps.is_empty() {
                        None
                    } else {
                        let chunk_obj = serde_json::json!({
                            "object": OBJ_CHUNK,
                            "choices": [{
                                "index": 0,
                                "delta": {},
                                "logprobs": write_openai_logprobs(lps),
                                "finish_reason": null
                            }]
                        });
                        Some(("".to_string(), chunk_obj))
                    }
                }
            },
            IrStreamEvent::BlockStop { .. } => None,
            IrStreamEvent::MessageDelta {
                stop_reason, usage, ..
            } => {
                // Map the IR stop_reason onto OpenAI's finish_reason enum. A non-terminal delta with
                // no stop_reason must serialize finish_reason as JSON `null` — NOT the empty string.
                // OpenAI chat.completion.chunk uses null for in-progress chunks and a valid enum
                // string ("stop"/"length"/"tool_calls"/"content_filter") only on the final chunk; an
                // empty string is not a valid enum value and fails strict SDK (Pydantic) validation.
                // A non-terminal delta carries no stop_reason → finish_reason is JSON `null` (an empty
                // string is not a valid enum value and fails strict SDK validation). A terminal delta
                // projects the typed reason into OpenAI's closed enum via the codec.
                let finish_reason: serde_json::Value = match stop_reason {
                    Some(r) => serde_json::json!(write_openai_stop_reason(*r)),
                    None => serde_json::Value::Null,
                };
                let delta_obj = serde_json::json!({});
                let mut chunk_obj = serde_json::json!({
                    "object": OBJ_CHUNK,
                    "choices": [{
                        "index": 0,
                        "delta": delta_obj,
                        "finish_reason": finish_reason
                    }]
                });
                // Carry real token usage on the terminal chunk. On a cross-protocol egress (e.g.
                // Anthropic/Bedrock -> OpenAI ingress) the IR's terminal MessageDelta holds the true
                // prompt/completion counts; the prior code discarded `usage` entirely, so an
                // OpenAI-ingress client that requested `stream_options:{include_usage:true}` received
                // ZERO usage data — both a token-accounting loss and a distinguishability tell, since a
                // native include_usage stream ALWAYS ends with a usage-bearing chunk. We attach a
                // top-level `usage:{prompt_tokens, completion_tokens, total_tokens}` object here.
                //
                // Native OpenAI carries this on a SEPARATE trailing `{choices:[], usage:{...}}` chunk
                // after the finish chunk; emitting that second chunk would require returning two events
                // from this 1:1 `write_response_event`, which the `ProtocolWriter` trait (shared, not
                // owned here) does not allow. So we FOLD `usage` onto the finish chunk here, and the
                // framing seam (`StreamTranslate::emit_ir_event` via `split_openai_trailing_usage`)
                // UN-folds it back into a native-shape trailing usage-only chunk — that seam can
                // append two frames where this 1:1 writer cannot. Folding here recovers the accounting
                // even on any path that bypasses the seam, and the SDK still surfaces `chunk.usage`.
                // We emit it only when a count is
                // nonzero (a same-protocol passthrough without include_usage carries zeroed usage in
                // the IR; suppressing the field there avoids stamping a usage object onto a stream that
                // never asked for one). `total_tokens` is the prompt+completion sum, the native shape.
                // RECONSTRUCT the native WIRE shape from the normalized IR: the IR stores UNCACHED
                // input, but OpenAI's `prompt_tokens` is a TOTAL that includes the cached prefix, so
                // add `cache_read` back. Emit `prompt_tokens_details.cached_tokens` only when a cache
                // read is present (matching the native shape — no spurious details object otherwise).
                let cache_read = usage.cache_read_input_tokens.unwrap_or(0);
                // cache_creation is ALSO part of OpenAI's TOTAL prompt count (it is None on every
                // same-protocol OpenAI path; present only on cross-protocol Anthropic/Bedrock ingress).
                let prompt_tokens = usage
                    .input_tokens
                    .saturating_add(cache_read)
                    .saturating_add(usage.cache_creation_input_tokens.unwrap_or(0));
                let completion_tokens = usage.output_tokens;
                if prompt_tokens != 0 || completion_tokens != 0 {
                    if let Some(obj) = chunk_obj.as_object_mut() {
                        let mut usage_obj = serde_json::json!({
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "total_tokens": prompt_tokens.saturating_add(completion_tokens),
                        });
                        if usage.cache_read_input_tokens.is_some() {
                            if let Some(uo) = usage_obj.as_object_mut() {
                                uo.insert(
                                    "prompt_tokens_details".to_string(),
                                    serde_json::json!({ "cached_tokens": cache_read }),
                                );
                            }
                        }
                        // The reasoning SUB-BUCKET, in OpenAI's native
                        // `completion_tokens_details.reasoning_tokens` slot — the same field the
                        // buffered writer emits. Emitted only when the source actually reported it
                        // (`None` means "this provider said nothing", which is NOT `Some(0)`), so a
                        // non-reasoning stream carries no fabricated details object.
                        if let Some(rt) = usage.detail.reasoning_tokens {
                            if let Some(uo) = usage_obj.as_object_mut() {
                                uo.insert(
                                    "completion_tokens_details".to_string(),
                                    serde_json::json!({ "reasoning_tokens": rt }),
                                );
                            }
                        }
                        obj.insert("usage".to_string(), usage_obj);
                    }
                }
                Some(("".to_string(), chunk_obj))
            }
            IrStreamEvent::MessageStop => None,
            IrStreamEvent::Error(err) => {
                let message = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "error".to_string());
                // Map the IR error class onto OpenAI's enumerated error `type` vocabulary. The prior
                // hardcoded "error" is not a valid OpenAI error type — SDK clients that switch on
                // `error.type` would fall through to an unhandled default, and the bogus value is a
                // detectable proxy tell. The match is exhaustive over StatusClass (no `_ =>`), so a
                // new class forces an explicit decision; `server_error` is the safe fallback bucket.
                let error_type = match err.class {
                    busbar_core::breaker::StatusClass::RateLimit => ERR_TYPE_RATE_LIMIT,
                    busbar_core::breaker::StatusClass::Auth => ERR_TYPE_AUTHENTICATION,
                    // Billing exhaustion is OpenAI's `insufficient_quota` (HTTP 429), NOT
                    // `permission_error`. Real OpenAI reserves `permission_error` for access-control
                    // denials (feature/org restrictions); an over-quota error carries
                    // `type:"insufficient_quota"` AND `code:"insufficient_quota"`. Emitting
                    // `permission_error` for a billing class made a client switch-casing on
                    // `error.type` misroute quota errors as permission denials, and is a detectable
                    // protocol tell. `bearer_error_code` pairs the matching `code` below. This mirrors
                    // the non-stream `write_error` path, which already maps the `"insufficient_quota"`
                    // kind to this type + code.
                    busbar_core::breaker::StatusClass::Billing => ERR_TYPE_INSUFFICIENT_QUOTA,
                    busbar_core::breaker::StatusClass::ContextLength
                    | busbar_core::breaker::StatusClass::ClientError => ERR_TYPE_INVALID_REQUEST,
                    busbar_core::breaker::StatusClass::Overloaded
                    | busbar_core::breaker::StatusClass::ServerError
                    | busbar_core::breaker::StatusClass::Timeout
                    | busbar_core::breaker::StatusClass::Network => ERR_TYPE_SERVER_ERROR,
                };
                // Include `code` and `param` as JSON null, matching BOTH the native OpenAI error
                // shape and this writer's own non-stream `write_error` envelope. Omitting them made
                // an in-stream error structurally different from a non-stream error (a detectable
                // proxy tell) and broke clients that destructure `error.code` / `error.param`.
                let error_obj = serde_json::json!({
                    "error": {
                        "message": message,
                        "type": error_type,
                        "code": bearer_error_code(error_type),
                        "param": serde_json::Value::Null,
                    }
                });
                Some(("".to_string(), error_obj))
            }
        }
    }

    fn egress_user_agent(&self) -> &'static str {
        // OpenAI Python SDK UA shape — pinned, see `EGRESS_UA_OPENAI` in proxy engine.
        busbar_core::proxy::EGRESS_UA_OPENAI
    }

    fn emits_sse_done_terminator(&self) -> bool {
        // OpenAI Chat Completions SSE ends with a literal `data: [DONE]` frame; busbar reproduces it
        // when emitting an openai-format stream to an openai-ingress client.
        true
    }

    fn new_stream_framing(&self) -> Box<dyn super::StreamFraming> {
        // OpenAI INGRESS per-stream framing: replays the latched stream identity onto every
        // `chat.completion.chunk` and un-folds the include_usage trailing-usage chunk. Lives here, in
        // the OpenAI module, so the agnostic translator names no OpenAI wire shape.
        Box::<OpenAiStreamFraming>::default()
    }

    fn auth_failure_message(&self) -> &'static str {
        AUTH_FAILURE_MSG
    }

    /// OpenAI Chat Completions caps `stop` at 4 and 400s on more. See `stop_sequence_cap`'s doc on
    /// `ProtocolWriter` for why an over-cap request is REJECTED at the cross-protocol seam rather
    /// than silently truncated.
    fn stop_sequence_cap(&self) -> Option<(usize, &'static str)> {
        Some((4, "OpenAI"))
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }

    /// Native OpenAI error envelope, served as `application/json`:
    /// `{"error":{"message":<msg>,"type":<type>,"param":null,"code":null}}`. This is the exact shape
    /// the official OpenAI SDKs decode (`openai.APIError` reads `error.message`/`error.type`/
    /// `error.code`/`error.param`), so a client on the native SDK gets a typed exception rather than
    /// an undecodable body. The generic `kind` is mapped onto OpenAI's own error-`type` vocabulary
    /// where one exists; otherwise it is passed through verbatim (still a valid string `type`).
    fn write_error(&self, status: u16, kind: &str, message: &str) -> serde_json::Value {
        // Map the protocol-agnostic `kind` onto OpenAI's documented error `type` values. OpenAI's
        // vocabulary: "invalid_request_error", "authentication_error", "permission_error",
        // "not_found_error", "rate_limit_error", "server_error", "api_error". HTTP 401/403/404/429
        // categories and common generic kinds are normalized; anything unrecognized falls back to a
        // status-derived bucket (4xx → invalid_request_error, 5xx → server_error) so the emitted
        // `type` is always a real OpenAI type. No `_ =>` catch-all on the kind match: each known
        // kind is listed, with the status-based fallback handled explicitly afterwards.
        let error_type = match kind {
            ERR_TYPE_INVALID_REQUEST | "invalid_request" | "bad_request" => {
                ERR_TYPE_INVALID_REQUEST
            }
            ERR_TYPE_AUTHENTICATION | "unauthorized" | "auth" => ERR_TYPE_AUTHENTICATION,
            ERR_TYPE_PERMISSION | "permission_denied" | "forbidden" => ERR_TYPE_PERMISSION,
            ERR_TYPE_NOT_FOUND => ERR_TYPE_NOT_FOUND,
            ERR_TYPE_RATE_LIMIT | "rate_limit" | "too_many_requests" => ERR_TYPE_RATE_LIMIT,
            ERR_TYPE_SERVER_ERROR | "internal_error" | "internal_server_error" => {
                ERR_TYPE_SERVER_ERROR
            }
            busbar_core::proxy::KIND_API_ERROR => busbar_core::proxy::KIND_API_ERROR,
            // Quota exhaustion is a first-class native OpenAI type (HTTP 429); preserve it so the
            // over-budget governance path keeps the real `insufficient_quota` type AND its matching
            // `code` (set in `bearer_error_code`).
            ERR_TYPE_INSUFFICIENT_QUOTA => ERR_TYPE_INSUFFICIENT_QUOTA,
            // The all-lanes-exhausted 503 path and the request-timeout 503 path pass the
            // Anthropic-vocabulary kind `overloaded` to EVERY ingress writer. `overloaded` is not an
            // OpenAI error type — real OpenAI reports a 503 / transient upstream failure as
            // `server_error` — so emitting `type:"overloaded"` is both a conformance break (the
            // official SDK's typed-exception mapping fails on an unknown type) and a cross-protocol
            // vocabulary leak. Map every transient/unavailable spelling onto OpenAI's native 5xx type.
            busbar_core::proxy::KIND_OVERLOADED
            | ERR_TYPE_OVERLOADED
            | "service_unavailable"
            | "unavailable"
            | "transient"
            | "timeout"
            | "network"
            | "5xx" => ERR_TYPE_SERVER_ERROR,
            busbar_core::proxy::PROVIDER_CODE_CONTEXT_LENGTH => ERR_TYPE_INVALID_REQUEST,
            // Empty kind: derive a valid OpenAI type from the HTTP status bucket rather than emitting
            // an empty `type`, so the SDK still sees a real error type.
            "" => {
                if (500..600).contains(&status) {
                    ERR_TYPE_SERVER_ERROR
                } else {
                    ERR_TYPE_INVALID_REQUEST
                }
            }
            // Any other caller-supplied kind (including the generic `not_found`) is passed through
            // verbatim: OpenAI has no single canonical `type` for it (model-not-found is reported as
            // `invalid_request_error` + `code: "model_not_found"` on some endpoints and
            // `not_found_error` on others), so we preserve the caller's token rather than guess.
            other => other,
        };

        serde_json::json!({
            "error": {
                "message": message,
                "type": error_type,
                "param": serde_json::Value::Null,
                "code": bearer_error_code(error_type),
            }
        })
    }

    fn write_error_frame(&self, err: &IrError) -> Option<(String, serde_json::Value)> {
        // The streaming-error seam: delegate to this dialect's own event writer so the mid-stream
        // error frame is byte-for-byte what an `Error` event produces on this wire.
        self.write_response_event(&IrStreamEvent::Error(err.clone()))
    }

    fn write_response(&self, resp: &busbar_core::ir::IrResponse) -> serde_json::Value {
        let mut obj = serde_json::Map::new();

        // Collect the assistant text parts exactly once: their presence decides whether
        // `content` is null, and their join is the content string. (Previously a parallel Vec of
        // discarded JSON objects was built solely to test emptiness — a dead allocation that
        // duplicated the extraction logic.)
        let text_parts: Vec<&str> = resp
            .content
            .iter()
            .filter_map(|b| match b {
                busbar_core::ir::IrBlock::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();

        // ToolUse blocks become tool_calls (not in content)
        let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();
        for block in &resp.content {
            if let busbar_core::ir::IrBlock::ToolUse {
                id, name, input, ..
            } = block
            {
                // Serialize input to JSON string
                let args_str = busbar_core::proto::openai_family::tool_arguments_to_string(input);
                tool_calls_arr.push(serde_json::json!({
                    "type": TOOL_TYPE_FUNCTION,
                    "id": id,
                    "function": {
                        "name": name,
                        "arguments": args_str
                    }
                }));
            }
        }

        // Thinking blocks are DROPPED on OpenAI write (lossy-by-necessity; OpenAI has no thinking)
        // They are not collapsed into content.

        let mut message_obj = serde_json::json!({
            "role": "assistant",
            "content": if text_parts.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::json!(text_parts.concat())
            },
        });

        // Add tool_calls only if present
        if !tool_calls_arr.is_empty() {
            message_obj["tool_calls"] = serde_json::Value::Array(tool_calls_arr);
        }

        // Grounding sources. Chat joins every text block into ONE content string, so a citation's
        // offsets are shifted by where its block starts in that join. Emitted only when non-empty:
        // an absent `annotations` key is what OpenAI returns for a completion with no sources, so a
        // hardcoded `[]` would be a proxy tell in the other direction.
        let mut base = 0usize;
        let mut annotations: Vec<serde_json::Value> = Vec::new();
        for block in &resp.content {
            if let busbar_core::ir::IrBlock::Text {
                text, citations, ..
            } = block
            {
                annotations.extend(super::super::openai_annotations::url_annotations(
                    text, base, citations,
                ));
                // CHARACTERS, not bytes: the IR citation contract (`IrCitation::start_index`/
                // `end_index`, `ir/mod.rs`) is characters. `text.len()` is a byte length — every
                // citation in block 2+ would be shifted by that block's byte-vs-char delta on any
                // non-ASCII text.
                base += text.chars().count();
            }
        }
        if !annotations.is_empty() {
            message_obj["annotations"] = serde_json::Value::Array(annotations);
        }

        let mut choices_array: Vec<serde_json::Value> = Vec::new();
        // The OpenAI chat.completion spec requires `finish_reason` to ALWAYS be present in a choice
        // object — a valid enum string ("stop"/"length"/"tool_calls"/...) or JSON `null` when the
        // upstream provided no stop reason (e.g. a cross-protocol Bedrock response whose
        // `read_response` yields `stop_reason: None`). The prior code mapped `None` to "" and then
        // omitted the key entirely; a missing `finish_reason` is not a valid choice shape and the
        // Python SDK's Pydantic model raises a validation error on it. Emit null instead.
        let finish_reason: serde_json::Value = match resp.stop_reason {
            Some(r) => serde_json::json!(write_openai_stop_reason(r)),
            None => serde_json::Value::Null,
        };

        let mut choice_obj = serde_json::Map::new();
        choice_obj.insert("index".to_string(), serde_json::json!(0));
        choice_obj.insert("message".to_string(), message_obj);
        // Carried per-token logprobs (e.g. from a Gemini backend's `logprobsResult`) in OpenAI's
        // native choice shape. Only emitted when the backend actually produced them: an absent
        // `logprobs` key matches what OpenAI returns when they were not requested.
        if !resp.logprobs.is_empty() {
            choice_obj.insert(
                "logprobs".to_string(),
                write_openai_logprobs(&resp.logprobs),
            );
        }
        choice_obj.insert("finish_reason".to_string(), finish_reason);
        choices_array.push(serde_json::Value::Object(choice_obj));

        // Identity fields, in the order an official OpenAI chat.completion object carries them
        // ({"id","object","created","model","system_fingerprint","choices","usage"}). The Python and
        // Node SDKs require `id` (str), `object` == "chat.completion", `created` (int), `model` (str),
        // `choices`, and `usage`; `system_fingerprint` is optional. When the IR field is `None`
        // (cross-protocol: the backend never minted one) we SYNTHESIZE a protocol-correct value so a
        // native SDK can't tell this was translated.
        let id = resp.id.clone().unwrap_or_else(synth_completion_id);
        obj.insert("id".to_string(), serde_json::json!(id));
        obj.insert("object".to_string(), serde_json::json!(OBJ_COMPLETION));
        let created = resp.created.unwrap_or_else(busbar_core::store::now);
        obj.insert("created".to_string(), serde_json::json!(created));
        // model that served the response. `model` is a REQUIRED non-nullable string in the OpenAI
        // chat.completion schema; a cross-protocol backend whose `read_response` yields `model: None`
        // (e.g. Bedrock egress -> OpenAI ingress) would otherwise produce a model-less completion that
        // fails strict SDK deserialisation and is a proxy tell. Preserve the upstream value on a
        // same-protocol passthrough; fall back to DEFAULT_MODEL when none was supplied.
        obj.insert(
            "model".to_string(),
            serde_json::json!(model_or_default(resp.model.as_deref())),
        );
        // system_fingerprint is only emitted when the upstream supplied one (same-protocol
        // passthrough); we do not fabricate an opaque backend marker on cross-protocol responses.
        if let Some(ref fp) = resp.system_fingerprint {
            obj.insert("system_fingerprint".to_string(), serde_json::json!(fp));
        }
        obj.insert(
            "choices".to_string(),
            serde_json::Value::Array(choices_array),
        );

        // Build usage, including the `total_tokens` an SDK expects (prompt + completion).
        // RECONSTRUCT the native WIRE shape from the normalized IR: the IR stores UNCACHED input,
        // but OpenAI's `prompt_tokens` is a TOTAL that includes the cached prefix, so add
        // `cache_read` back. Emit `prompt_tokens_details.cached_tokens` only when a cache read is
        // present (matching the native shape — no spurious details object otherwise).
        let cache_read = resp.usage.cache_read_input_tokens.unwrap_or(0);
        // cache_creation is ALSO part of OpenAI's TOTAL prompt count (None on same-protocol OpenAI;
        // present only on cross-protocol Anthropic/Bedrock ingress).
        let prompt_tokens = resp
            .usage
            .input_tokens
            .saturating_add(cache_read)
            .saturating_add(resp.usage.cache_creation_input_tokens.unwrap_or(0));
        let mut usage_map = serde_json::Map::new();
        usage_map.insert(
            "prompt_tokens".to_string(),
            serde_json::json!(prompt_tokens),
        );
        usage_map.insert(
            "completion_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );
        usage_map.insert(
            "total_tokens".to_string(),
            serde_json::json!(prompt_tokens.saturating_add(resp.usage.output_tokens)),
        );
        if resp.usage.cache_read_input_tokens.is_some() {
            usage_map.insert(
                "prompt_tokens_details".to_string(),
                serde_json::json!({ "cached_tokens": cache_read }),
            );
        }
        // Reasoning attribution, in OpenAI's native spelling. Emitted only when the backend actually
        // reported it: a hardcoded `0` is a CLAIM that the model did no thinking, and inventing that
        // claim on a non-reasoning response is exactly the failure this field exists to end.
        if let Some(rt) = resp.usage.detail.reasoning_tokens {
            usage_map.insert(
                "completion_tokens_details".to_string(),
                serde_json::json!({ "reasoning_tokens": rt }),
            );
        }
        obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));

        serde_json::Value::Object(obj)
    }
}

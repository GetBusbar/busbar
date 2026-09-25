use super::*;

impl ProtocolWriter for CohereWriter {
    fn probe_request(&self) -> serde_json::Value {
        // The ping IR is built by the plugin (ir_encode::ping_request); this dialect serializes it
        // through its own write_request, so the probe body matches a real request on this wire.
        self.write_request(&super::super::ir_encode::ping_request())
    }

    fn upstream_path(&self) -> &str {
        PATH_UPSTREAM
    }

    /// The Q57 request slots Cohere v2 `/chat` has no form for (ir-slots-landed.md "N" for Cohere):
    /// each one a request carries is dropped by [`Self::write_request`] with a warn and reported
    /// here, so the seam audits the degradation. `service_tier` included: Cohere's `priority` is an
    /// integer queue order, a different concept, so no tier is written.
    fn dropped_egress_controls(&self, req: &crate::ir::IrRequest) -> Vec<&'static str> {
        let mut dropped = Vec::new();
        if req.metadata.is_some() {
            dropped.push("metadata");
        }
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
        if cohere_drops_output_modalities(req) {
            dropped.push("output_modalities");
        }
        dropped.extend(req.hosted_tools.iter().map(|h| h.kind_str()));
        dropped
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let _t = busbar_timing::timeit!("cohere_write_request");
        let mut out = serde_json::Map::new();
        let mut messages_arr: Vec<serde_json::Value> = Vec::new();

        // Cohere v2 carries the system prompt as a leading system-role message.
        let system_text: String = req
            .system
            .iter()
            .filter_map(|b| {
                if let crate::ir::IrBlock::Text { text, .. } = b {
                    Some(text.as_str())
                } else {
                    // A non-text system block (image/thinking/tool/…) has no Cohere v2 analog — the
                    // system prompt carries text only. WARN on the drop so the loss is operator-
                    // visible in observability, mirroring the Gemini writer's warn for the same case.
                    tracing::warn!(
                        "dropping non-text system block on Cohere egress: Cohere v2 system prompt carries text only"
                    );
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        if !system_text.is_empty() {
            messages_arr.push(serde_json::json!({ "role": "system", "content": system_text }));
        }

        // Text documents lifted out of message content into the request's top-level `documents`
        // (COH-18), in the order they were attached.
        let mut documents: Vec<serde_json::Value> = Vec::new();
        for msg in &req.messages {
            let role_str = match msg.role {
                crate::ir::IrRole::System => "system",
                crate::ir::IrRole::User => "user",
                crate::ir::IrRole::Assistant => "assistant",
                crate::ir::IrRole::Tool => "tool",
            };

            // Cohere v2 multimodal output: an image block is written as an
            // `{"type":"image_url","image_url":{"url":"<data-uri|https>"}}` content part — the SAME
            // shape OpenAI v1 chat uses and this file's reader consumes. `image_url_from_ir` re-wraps
            // the IR (media_type, data) pair into the original URL (a base64 image becomes a
            // `data:<mime>;base64,<payload>` URI; an "image_url"-sentinel image emits its raw URL
            // verbatim). When ANY image is present the message MUST use the array content shape (a
            // bare string cannot carry an image part). ASSUMPTION (see report): the wire shape is
            // OpenAI-style `image_url`; no Cohere v2 image fixture exists in-repo to confirm it.
            //
            // The parts are emitted in the IR's order (COH-19): all text used to go first and all
            // images after, so "look at this [image] and compare it to [image]" reached the model
            // as "look at this and compare it to [image] [image]".
            let mut parts: Vec<serde_json::Value> = Vec::new();
            let mut has_image = false;
            for b in &msg.content {
                match b {
                    crate::ir::IrBlock::Text { text, .. } => {
                        parts.push(serde_json::json!({ "type": "text", "text": text }));
                    }
                    // A URL/base64 image projects to an `image_url`; a Responses `file_id` or
                    // Bedrock `s3Location` reference has no Cohere projection (returns None) and is
                    // skipped with a warn rather than corrupting the block.
                    crate::ir::IrBlock::Image { source, detail, .. } => {
                        match super::super::ir_encode::image_url_from_ir(source) {
                            Some(url) => {
                                has_image = true;
                                let mut image_url = serde_json::Map::new();
                                image_url.insert("url".to_string(), serde_json::json!(url));
                                // IR-08: the requested fidelity, Cohere's own `image_url.detail`.
                                if let Some(d) = detail {
                                    image_url.insert(
                                        "detail".to_string(),
                                        serde_json::json!(d.as_str()),
                                    );
                                }
                                parts.push(serde_json::json!({
                                    "type": "image_url", "image_url": image_url
                                }));
                            }
                            None => tracing::warn!(
                                "dropping unresolvable vendor-scoped image reference on Cohere \
                                 egress: a file_id / s3Location has no cross-vendor analog"
                            ),
                        }
                    }
                    // A top-level `Media` attachment has NO Cohere v2 `/chat` message-content slot:
                    // v2 message content carries text and `image_url` parts only. A TEXT document
                    // (or this dialect's own document) does have a Cohere home, though — the
                    // request's top-level `documents`, Cohere's grounding documents — so it is
                    // lifted there (COH-18) instead of dropped. Anything else (a PDF's bytes,
                    // audio, video, a URL or a foreign handle) has no Cohere form and is dropped
                    // WITH the standard drop-with-warn, so the loss is operator-visible. Media
                    // carried INSIDE a ToolResult is not a direct `msg.content` block, so it is not
                    // caught (or double-warned) here.
                    crate::ir::IrBlock::Media {
                        kind, source, name, ..
                    } => match (*kind == crate::ir::IrMediaKind::Document)
                        .then(|| write_cohere_document(source, name.as_deref()))
                        .flatten()
                    {
                        Some(doc) => documents.push(doc),
                        None => tracing::warn!(
                            media_kind = kind.as_str(),
                            "dropping attachment on Cohere egress: Cohere v2 /chat message \
                             content carries text and image parts only, and this attachment is \
                             not a text document the request's `documents` can carry — it is NOT \
                             emitted"
                        ),
                    },
                    _ => {}
                }
            }
            let text_blocks: Vec<&String> = msg
                .content
                .iter()
                .filter_map(|b| {
                    if let crate::ir::IrBlock::Text { text, .. } = b {
                        Some(text)
                    } else {
                        None
                    }
                })
                .collect();

            // A single text block is sent as a bare string (Cohere's preferred shape); several text
            // blocks, or any image, become a parts array. A message whose only block(s) are non-Text
            // (e.g. a sole ToolUse, surfaced separately via `tool_calls`) must NOT emit
            // `content: []` — Cohere may reject that — so the `content` key is omitted then.
            let content_val: Option<serde_json::Value> = match text_blocks.as_slice() {
                _ if has_image => Some(serde_json::Value::Array(parts)),
                [] => None,
                [single] => Some(serde_json::Value::String((*single).clone())),
                _ => Some(serde_json::Value::Array(parts)),
            };

            // A `ToolResult` block can land on a `Tool`-role message (OpenAI/Cohere source) OR on a
            // `User`-role message (Anthropic/Gemini carry tool_results on the user turn in the IR).
            // Cohere v2 `/chat` represents EVERY tool result as its own `role:"tool"` message with a
            // `tool_call_id`; a Cohere user message cannot carry tool results. So the emission must
            // gate on the PRESENCE of a ToolResult block, not on the carrying role; otherwise
            // Anthropic/Gemini -> Cohere silently drops tool results and breaks multi-turn tool use.
            let has_tool_result = msg
                .content
                .iter()
                .any(|b| matches!(b, crate::ir::IrBlock::ToolResult { .. }));
            if msg.role == crate::ir::IrRole::Tool || has_tool_result {
                // Anthropic/Gemini put tool_results on the USER turn, and such a user message can
                // bundle a tool_result block TOGETHER WITH genuine new user text (e.g.
                // `[{tool_result...}, {text:"and now also do X"}]`). Cohere v2 `/chat` has no way to
                // carry user text on a tool message; a tool message is `role:"tool"` +
                // `tool_call_id` + `content` (the result), and a user message is its own
                // `role:"user"` message. So on a USER-role carrier we must NOT fold that text into
                // the tool `content` (that would mislabel user speech as tool output) nor drop it;
                // we emit the tool_result(s) as tool message(s) and preserve the user text/other
                // content as a separate `role:"user"` message below.
                //
                // On a genuine TOOL-role carrier there is no user text; any text is degenerate
                // tool-channel text, so it is still folded onto the first tool result (or emitted
                // as a standalone tool message) to stay lossless, as before.
                let carrier_is_user = msg.role == crate::ir::IrRole::User;
                let fold_text_into_tool = !carrier_is_user;
                let mut emitted_tool_result = false;
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    } = block
                    {
                        let mut tool_result_obj = serde_json::Map::new();
                        tool_result_obj.insert("role".to_string(), serde_json::json!("tool"));
                        tool_result_obj.insert(
                            "tool_call_id".to_string(),
                            serde_json::Value::String(tool_use_id.clone()),
                        );
                        let mut text_parts: Vec<String> = content
                            .iter()
                            .filter_map(|b| match b {
                                crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                                // A structured-JSON tool result (Bedrock `{"json": …}`) is the
                                // tool's output as JSON; Cohere tool content is text, and JSON
                                // serialized is that same output as text. It used to be dropped,
                                // leaving the model an empty tool result (COH-20).
                                crate::ir::IrBlock::Json(v) => {
                                    busbar_substrate_values::json::to_string(v).ok()
                                }
                                _ => None,
                            })
                            .collect();
                        // Prepend any message-level text onto the first tool result so it survives,
                        // ONLY on a genuine Tool-role carrier. On a User-role carrier the text is
                        // genuine user speech and is preserved as its own `user` message below, so it
                        // must NOT be folded here.
                        if fold_text_into_tool && !emitted_tool_result {
                            for t in text_blocks.iter().rev() {
                                text_parts.insert(0, (*t).clone());
                            }
                        }
                        // Native `document` parts, re-emitted STRUCTURALLY. The reader captures a
                        // Cohere tool-result document as a `Media` block on the opaque `Vendor`
                        // escape precisely so it can come back here as an object rather than as the
                        // JSON STRING the old text-join produced (which the model read as escaped
                        // syntax). A FOREIGN vendor handle cannot be re-emitted and is dropped with
                        // a warn.
                        let mut doc_parts: Vec<serde_json::Value> = Vec::new();
                        for b in content {
                            let crate::ir::IrBlock::Media { kind, source, .. } = b else {
                                continue;
                            };
                            match source {
                                crate::ir::IrImageSource::Vendor { vendor, value }
                                    if *vendor == VENDOR_NAME =>
                                {
                                    doc_parts.push(serde_json::json!({
                                        "type": "document",
                                        "document": value
                                    }));
                                }
                                _ => tracing::warn!(
                                    media_kind = kind.as_str(),
                                    "dropping attachment inside a tool result on Cohere egress: \
                                     Cohere v2 tool content carries text and native `document` \
                                     parts only, and this source has no Cohere document form"
                                ),
                            }
                        }
                        // Cohere accepts a bare string OR a typed-part array. Keep the bare string
                        // when there is no document (the historical shape, and what the reader's
                        // `.join("")` inverts); switch to the array form only when a document part
                        // has to be carried structurally.
                        let joined = text_parts.join("");
                        let content_value = if doc_parts.is_empty() {
                            // Concatenate with NO separator, matching `read_request`'s `.join("")`:
                            // a block boundary is not a semantic space, and a " " here inserts a
                            // phantom space at each former boundary on a Cohere->X->Cohere
                            // round-trip (corrupting base64 / split-JSON tool-result payloads).
                            serde_json::Value::String(joined)
                        } else {
                            let mut parts: Vec<serde_json::Value> = Vec::new();
                            if !joined.is_empty() {
                                parts.push(serde_json::json!({"type": "text", "text": joined}));
                            }
                            parts.extend(doc_parts);
                            serde_json::Value::Array(parts)
                        };
                        tool_result_obj.insert("content".to_string(), content_value);
                        messages_arr.push(serde_json::Value::Object(tool_result_obj));
                        emitted_tool_result = true;
                    }
                }
                if carrier_is_user {
                    // USER-role carrier: preserve any genuine user content (text and/or images)
                    // that rode alongside the tool_result(s) as its OWN `role:"user"` message, so
                    // user speech is neither dropped nor mislabeled as tool output. `content_val`
                    // already carries the correct user-message shape (bare string for a single text
                    // block, a text/image parts array otherwise); emit it only when there IS such
                    // content (a pure tool_result user turn has `content_val == None` and adds no
                    // user message).
                    if let Some(user_content) = content_val {
                        let mut user_obj = serde_json::Map::new();
                        user_obj.insert("role".to_string(), serde_json::json!("user"));
                        user_obj.insert("content".to_string(), user_content);
                        messages_arr.push(serde_json::Value::Object(user_obj));
                    }
                } else if !emitted_tool_result && !text_blocks.is_empty() {
                    // Degenerate Tool turn with text but no ToolResult: emit the text as a tool
                    // message rather than dropping it entirely. Cohere tool message `content` must be
                    // a string, so we stringify the text blocks (join with "") exactly like the
                    // ToolResult path: forwarding `content_val` here would emit a JSON array for
                    // multi-block turns, producing an invalid Cohere request.
                    let mut tool_obj = serde_json::Map::new();
                    tool_obj.insert("role".to_string(), serde_json::json!("tool"));
                    tool_obj.insert(
                        "content".to_string(),
                        serde_json::Value::String(
                            text_blocks
                                .iter()
                                .map(|t| t.as_str())
                                .collect::<Vec<&str>>()
                                .join(""),
                        ),
                    );
                    messages_arr.push(serde_json::Value::Object(tool_obj));
                }
                continue;
            }

            let mut msg_obj = serde_json::Map::new();
            msg_obj.insert("role".to_string(), serde_json::json!(role_str));
            if let Some(content_val) = content_val {
                msg_obj.insert("content".to_string(), content_val);
            }

            // Replay a request-history assistant message's pre-tool-call plan in Cohere's native
            // `tool_plan` slot. The reader reads request `tool_plan` into a LEADING Thinking block
            // (so it is not shown as content), and this is its inverse — folding every Thinking
            // block's text back into `tool_plan`. Assistant-only: no other role carries a plan.
            //
            // `tool_plan` is the plan that PRECEDES tool calls, so it is only the right slot on a turn
            // that carries them. A turn with no tool calls replays its reasoning the way a Cohere
            // reasoning model returned it: `{"type":"thinking"}` content parts ahead of the answer
            // (COH-07). Writing that reasoning as a `tool_plan` on a turn with no tool call told the
            // model it had planned a call it never made.
            if msg.role == crate::ir::IrRole::Assistant {
                let thinking: Vec<&str> = msg
                    .content
                    .iter()
                    .filter_map(|b| match b {
                        crate::ir::IrBlock::Thinking {
                            text,
                            redacted: false,
                            ..
                        } if !text.is_empty() => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                let has_tool_calls = msg
                    .content
                    .iter()
                    .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { .. }));
                if has_tool_calls {
                    let plan: String = thinking.concat();
                    if !plan.is_empty() {
                        msg_obj.insert("tool_plan".to_string(), serde_json::json!(plan));
                    }
                } else if !thinking.is_empty() {
                    let mut parts: Vec<serde_json::Value> = thinking
                        .iter()
                        .map(|t| serde_json::json!({ "type": "thinking", "thinking": t }))
                        .collect();
                    match msg_obj.remove("content") {
                        Some(serde_json::Value::String(text)) => {
                            parts.push(serde_json::json!({ "type": "text", "text": text }));
                        }
                        Some(serde_json::Value::Array(rest)) => parts.extend(rest),
                        _ => {}
                    }
                    msg_obj.insert("content".to_string(), serde_json::Value::Array(parts));
                }
            }

            // Replay any grounding citations carried on this message's text blocks into Cohere's
            // native `citations` slot — the request-history inverse of `read_cohere_citations`. A
            // citation this protocol itself read re-emits verbatim via its `raw`; a cross-protocol
            // one is synthesized from the neutral fields. Emitted only when non-empty so an
            // ungrounded message does not gain a spurious `citations: []`.
            let msg_citations: Vec<serde_json::Value> = msg
                .content
                .iter()
                .filter_map(|b| match b {
                    crate::ir::IrBlock::Text { citations, .. } => Some(citations),
                    _ => None,
                })
                .flatten()
                .map(write_cohere_citation)
                .collect();
            if !msg_citations.is_empty() {
                msg_obj.insert(
                    "citations".to_string(),
                    serde_json::Value::Array(msg_citations),
                );
            }

            if msg.role == crate::ir::IrRole::Assistant {
                let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolUse {
                        id, name, input, ..
                    } = block
                    {
                        // Emit a raw Value::String (unparseable/streaming-partial args) verbatim rather
                        // than JSON-encoding it a second time (double-encoding) — same as the OpenAI/
                        // Responses writers.
                        let args_str =
                            busbar_substrate_values::proto::tool_arguments_to_string(input);
                        tool_calls_arr.push(serde_json::json!({ "id": id, "type": "function", "function": { "name": name, "arguments": args_str }}));
                    }
                }
                if !tool_calls_arr.is_empty() {
                    msg_obj.insert(
                        "tool_calls".to_string(),
                        serde_json::Value::Array(tool_calls_arr),
                    );
                }
            }

            messages_arr.push(serde_json::Value::Object(msg_obj));
        }

        out.insert(
            "messages".to_string(),
            serde_json::Value::Array(messages_arr),
        );

        // Per-tool `strict` renders as Cohere's request-level `strict_tools` when every tool agrees
        // (COH-12) — the same guarantee, spelled once. Tools that disagree have no Cohere form (the
        // switch cannot be set for some tools and not others), so that case stays a drop-with-warn.
        //
        // IR-10: an allowed-tools SUBSET has no Cohere form of its own, so it is expressed by
        // omission — only the listed tools are sent, and `tool_choice` carries the mode (`Required`
        // → REQUIRED, `Auto` → Cohere's default). The same constraint, spelled the way Cohere can.
        let tools: Vec<&crate::ir::IrTool> = match &req.allowed_tools {
            Some(allowed) => req
                .tools
                .iter()
                .filter(|t| allowed.contains(&t.name))
                .collect(),
            None => req.tools.iter().collect(),
        };
        let strict: Vec<Option<bool>> = tools.iter().map(|t| t.strict).collect();
        match strict.first() {
            Some(Some(first)) if strict.iter().all(|s| *s == Some(*first)) => {
                out.insert("strict_tools".to_string(), serde_json::json!(first));
            }
            _ => super::super::ir_encode::warn_dropped_tool_strict(&req.tools, "cohere"),
        }
        if !tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &tools {
                let mut func_obj = serde_json::Map::new();
                func_obj.insert("name".to_string(), serde_json::json!(tool.name));
                if let Some(desc) = &tool.description {
                    func_obj.insert("description".to_string(), serde_json::json!(desc));
                }
                let params = if !tool.input_schema.is_null() {
                    tool.input_schema.clone()
                } else {
                    serde_json::json!({})
                };
                func_obj.insert("parameters".to_string(), params);
                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("type".to_string(), serde_json::json!("function"));
                tool_obj.insert("function".to_string(), serde_json::Value::Object(func_obj));
                tools_arr.push(serde_json::Value::Object(tool_obj));
            }
            out.insert("tools".to_string(), serde_json::Value::Array(tools_arr));
        }

        // Cohere v2 `tool_choice` is a top-level enum string with only REQUIRED/NONE — there is NO
        // single-tool targeting in the Cohere v2 API. `Auto` is Cohere's default (omit the field).
        //
        // A targeted single tool (`IrToolChoice::Tool { name }`) therefore has NO faithful Cohere
        // representation, so we degrade it to REQUIRED — force *some* tool — rather than silently
        // dropping to `auto`: this preserves the caller's "must call a tool" intent, which is the
        // load-bearing half of the request. What is lost is the *target* (the specific tool name):
        // Cohere may pick any tool, not the one the caller named. This is the ONE documented
        // tool_choice degradation in the codebase — lossy-by-target, intentional, and unavoidable
        // until/unless the Cohere v2 API gains a named-tool choice.
        // Cohere v2 documents `tool_choice` as only meaningful alongside `tools` (there is nothing
        // to force/forbid otherwise) — the same shape as every sibling protocol's guard. The
        // reachable case is a cross-protocol request whose hosted tools `prepare_for_egress`
        // stripped (`ir/variant.rs`) while the tool_choice directive survived.
        if let Some(tc) = &req.tool_choice {
            if tools.is_empty() {
                tracing::warn!(
                    "dropping tool_choice on Cohere egress: tool_choice has no accompanying tools \
                     (likely because the hosted tools that carried it were stripped on the \
                     cross-protocol seam)"
                );
            } else {
                let v = match tc {
                    crate::ir::IrToolChoice::Required | crate::ir::IrToolChoice::Tool { .. } => {
                        Some(COHERE_TOOL_CHOICE_REQUIRED)
                    }
                    crate::ir::IrToolChoice::None => Some(COHERE_TOOL_CHOICE_NONE),
                    crate::ir::IrToolChoice::Auto => None,
                };
                if let Some(s) = v {
                    out.insert("tool_choice".to_string(), serde_json::json!(s));
                }
            }
        }
        // Egress: Cohere v2 `/v2/chat` models no parallelism control. `is_some()` gates
        // this to requests that actually carried the flag (owner decision 4: no per-request noise).
        if req.parallel_tool_calls.is_some() {
            tracing::warn!(
                "dropping parallel_tool_calls on Cohere egress: /v2/chat has no parallelism \
                 control, so the backend's default parallelism applies"
            );
        }
        // The Q57 request slots with no Cohere form — the same set `dropped_egress_controls`
        // reports for the seam's audit.
        for control in self.dropped_egress_controls(req) {
            tracing::warn!(
                control = control,
                "dropping a request control on Cohere egress: Cohere v2 /chat has no form for it"
            );
        }

        if let Some(max_tokens) = req.max_tokens {
            out.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temperature) = req.temperature {
            // Clamp to Cohere's native [0.0, 1.0] — see `clamp_temperature_for_cohere`.
            // NON-SILENT clamp (the fidelity fix): the writer previously clamped SILENTLY, exactly
            // the lossy mutation busbar exists to avoid. We keep the clamp (Cohere 400s on >1.0) but
            // emit a `warn!` whenever it ACTUALLY changes the value so an operator can detect the
            // divergence in logs. Mirrors the anthropic/bedrock writers' non-silent clamp.
            let (clamped, was_clamped) = clamp_temperature_for_cohere(temperature);
            if was_clamped {
                tracing::warn!(
                    requested_temperature = temperature,
                    clamped_temperature = clamped,
                    parameter = "temperature",
                    "clamping temperature to Cohere's [0.0, 1.0] range; the requested value was \
                     outside it (e.g. an OpenAI/Responses value up to 2.0) and would 400 — the \
                     forwarded value diverges from the caller's request"
                );
            }
            out.insert("temperature".to_string(), serde_json::json!(clamped));
        }
        // Promoted sampling controls in Cohere v2's native names: `p` (top_p), `k` (top_k),
        // `stop_sequences`. Emitted before the `extra` overlay (the reader pulled these keys out of
        // extra, so there is no double-emit on a same-protocol passthrough).
        if let Some(top_p) = req.top_p {
            out.insert("p".to_string(), serde_json::json!(top_p));
        }
        if let Some(top_k) = req.top_k {
            out.insert("k".to_string(), serde_json::json!(top_k));
        }
        if !req.stop.is_empty() {
            // v1.5.4 silent-degrade (restored): a cross-protocol request whose stop list exceeds
            // Cohere's cap of 5 is CLAMPED to the cap here (with a `warn!` naming what was dropped)
            // and forwarded at HTTP 200, rather than rejected up front with a 400. A same-protocol
            // Cohere->Cohere request never rebuilds its body from the IR (verbatim relay), so it
            // never reaches this writer and is never clamped. The published cap in the declaration
            // (`stop_sequence_cap`) is retained for other planes.
            out.insert(
                "stop_sequences".to_string(),
                serde_json::json!(crate::ir::clamp_stop(&req.stop, 5, "Cohere")),
            );
        }
        // Sampling/output controls in Cohere v2's native (OpenAI-shaped) names. Emitted
        // before the `extra` overlay (the reader pulled these keys out of extra, so there is no
        // double-emit on a same-protocol passthrough).
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
        // Cohere v2 chat supports a top-level integer `seed`. Emit it when present so deterministic
        // sampling survives the seam (the reader models it as a modeled key, so no double-emit).
        if let Some(seed) = req.seed {
            out.insert("seed".to_string(), serde_json::json!(seed));
        }
        // Cohere v2 chat's request `logprobs` is a boolean ask (return per-token log probs?), the
        // same shape OpenAI/Gemini model. Emit it when the IR carries the ask so it survives the
        // seam (the reader models it as a modeled key, so there is no double-emit via `extra`).
        if let Some(logprobs) = req.logprobs {
            out.insert("logprobs".to_string(), serde_json::json!(logprobs));
        }
        // `response_format` (structured output): a Cohere-native object passes through verbatim; a
        // foreign shape (OpenAI `type:"json_schema"` with a nested `json_schema.schema`, or Gemini
        // `responseMimeType`/`responseSchema`) is mapped into Cohere's native `{type:"json_object",
        // json_schema:<schema>}` so a Cohere backend accepts it instead of 400-ing on the off-shape.
        if let Some(response_format) = &req.response_format {
            out.insert(
                "response_format".to_string(),
                write_cohere_response_format(response_format),
            );
        }
        // Only emit `stream` when streaming is requested. A native Cohere client omitting `stream`
        // (relying on the `false` default) produces a body WITHOUT the field; always injecting
        // `"stream": false` is a proxy tell and a same-protocol passthrough fidelity break (the
        // reader treats `stream` as a modeled key, so it is never echoed via `extra`). The Gemini
        // writer likewise never emits `stream` in the body.
        if req.stream {
            out.insert("stream".to_string(), serde_json::json!(true));
        }
        // The reasoning ASK in Cohere v2's native `thinking` param (COH-06). It used to be dropped
        // with a warn, as if Cohere had no reasoning control; it has `thinking.token_budget`.
        if let Some(ask) = req.reasoning {
            out.insert(
                "thinking".to_string(),
                write_cohere_reasoning(
                    ask,
                    req.reasoning_budgets
                        .unwrap_or(crate::ir::REASONING_BUDGET_DEFAULTS),
                ),
            );
        }
        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }
        // The lifted documents join any `documents` still riding `extra` (the reader promotes an
        // array `documents` into the IR — IR-13 — so only an unreadable one is left there), after
        // them.
        if !documents.is_empty() {
            match out.get_mut("documents").and_then(|d| d.as_array_mut()) {
                Some(existing) => existing.extend(documents),
                None => {
                    out.insert("documents".to_string(), serde_json::Value::Array(documents));
                }
            }
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart { role, id, .. } => {
                let cohere_role = match role {
                    crate::ir::IrRole::Assistant => "assistant",
                    crate::ir::IrRole::System
                    | crate::ir::IrRole::User
                    | crate::ir::IrRole::Tool => return None,
                };
                // Cohere v2 streams carry the response `id` on the message-start frame. Preserve a
                // captured id; synthesize a shape-valid one for the cross-protocol case so the
                // emitted stream is indistinguishable from a native Cohere stream.
                // The FIRST `message-start` decides this stream's id; a duplicate replays it rather
                // than announcing the same message under a second identity.
                let id = self.carried_stream_id(|| id.clone().unwrap_or_else(synthesize_cohere_id));
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "id": id,
                        "type": ET_MESSAGE_START,
                        "delta": { "message": { "role": cohere_role } }
                    }),
                ))
            }

            IrStreamEvent::BlockStart {
                index,
                block,
                refusal: _,
            } => match block {
                crate::ir::IrBlockMeta::Text => {
                    // Record the open text index so its matching `BlockStop` emits `content-end`. A
                    // cross-protocol block that carries NO opening frame (redacted thinking / Image, below)
                    // is never recorded, so its `BlockStop` stays silent rather than emitting an
                    // orphan `content-end` — see `open_text_indices`.
                    self.mark_text_open(*index);
                    Some((
                        "".to_string(),
                        serde_json::json!({
                            "type": ET_CONTENT_START,
                            "index": index,
                            "delta": {
                                "message": {
                                    "content": { "type": "text", "text": "" }
                                }
                            }
                        }),
                    ))
                }
                // Cross-protocol streaming tool use (e.g. Anthropic/Gemini → Cohere-ingress) must
                // surface a native `tool-call-start` frame mirroring the shape this file's own
                // reader consumes (delta.message.tool_calls.{id,type,function.{name,arguments}}).
                // Omitting it made streamed tool calls invisible to a Cohere client. The reader
                // expects `function.arguments` to be a (possibly empty) string and accumulates
                // tool-call-delta argument fragments onto it, so we open with an empty string.
                crate::ir::IrBlockMeta::ToolUse { id, name } => {
                    // Record the open tool index so the matching `BlockStop` closes it with
                    // `tool-call-end` (the native Cohere v2 close event for a tool block) rather
                    // than `content-end` (the text-block close event) — see `open_tool_indices`.
                    self.mark_tool_open(*index);
                    Some((
                        "".to_string(),
                        serde_json::json!({
                            "type": ET_TOOL_CALL_START,
                            "index": index,
                            "delta": {
                                "message": {
                                    "tool_calls": {
                                        "id": id,
                                        "type": "function",
                                        "function": { "name": name, "arguments": "" }
                                    }
                                }
                            }
                        }),
                    ))
                }
                // A reasoning block opens as a Cohere reasoning model streams one: a `content-start`
                // whose content part is `{"type":"thinking"}`, closed by the matching `content-end`
                // (recorded like a text block so its `BlockStop` emits it). It used to open nothing
                // and stream its deltas as `tool-plan-delta` — the frame for the plan that precedes a
                // tool call — so a foreign model's reasoning reached a Cohere client as a plan
                // (COH-09).
                crate::ir::IrBlockMeta::Thinking { .. } => {
                    self.mark_text_open(*index);
                    Some((
                        "".to_string(),
                        serde_json::json!({
                            "type": ET_CONTENT_START,
                            "index": index,
                            "delta": {
                                "message": {
                                    "content": { "type": "thinking", "thinking": "" }
                                }
                            }
                        }),
                    ))
                }
                // Cohere v2 has no streamed redacted-thinking or image block shape. Emitting a
                // fabricated frame would be a non-native proxy tell, so these IR block kinds carry no
                // opening frame.
                crate::ir::IrBlockMeta::RedactedThinking | crate::ir::IrBlockMeta::Image => None,
            },

            IrStreamEvent::BlockDelta { index, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) => Some((
                    "".to_string(),
                    // Native Cohere v2 content-delta frames carry the text at
                    // delta.message.content.text (an object), matching the content-start shape and
                    // this reader's object path. A bare string here is non-native and a client that
                    // reads content.text would accumulate nothing.
                    //
                    // NO `type` key inside `content` here (verified against Cohere's own API
                    // reference): a real content-delta's `content` object is `{ "text": "…" }` only
                    // -- `type` is carried ONLY by content-START (see the `BlockStart` arm above),
                    // never repeated on every delta. Emitting one here was an extra field no native
                    // Cohere client emits, which a strict parser -- or anyone fingerprinting streams
                    // for the indistinguishability property this protocol's docs promise -- could
                    // use to tell a busbar-translated stream from a native one. The reader already
                    // accepts BOTH shapes (this one and the real one) for exactly this reason; this
                    // is the writer catching up to match the real wire, not a breaking change to the
                    // read side.
                    serde_json::json!({
                        "type": ET_CONTENT_DELTA,
                        "index": index,
                        "delta": { "message": { "content": { "text": text } } }
                    }),
                )),
                // Streamed tool-call argument fragments map to a native `tool-call-delta` frame
                // carrying the argument chunk at delta.message.tool_calls.function.arguments — the
                // exact path this file's reader reads. Without this arm, cross-protocol tool-call
                // arguments never reached a Cohere-ingress client.
                crate::ir::IrDelta::InputJsonDelta(args) => Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": ET_TOOL_CALL_DELTA,
                        "index": index,
                        "delta": {
                            "message": {
                                "tool_calls": { "function": { "arguments": args } }
                            }
                        }
                    }),
                )),
                // A reasoning delta streams into its thinking content block exactly as a Cohere
                // reasoning model streams it: a `content-delta` whose content is
                // `{ "thinking": "<chunk>" }` (no `type`, like the text delta above) — the buffered
                // writer's `{"type":"thinking"}` part, streamed (COH-09).
                crate::ir::IrDelta::ThinkingDelta(text) => Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": ET_CONTENT_DELTA,
                        "index": index,
                        "delta": { "message": { "content": { "thinking": text } } }
                    }),
                )),
                // IR-21: Cohere has no streamed media member.
                crate::ir::IrDelta::SignatureDelta(_)
                | crate::ir::IrDelta::RedactedReasoningDelta(_)
                | crate::ir::IrDelta::MediaDelta(_) => None,
                // Cohere v2's SSE vocabulary DOES include `citation-start` (paired with
                // `citation-end`), so a streamed citation re-emits natively instead of being
                // suppressed. Suppressing it made the SAME request against the SAME backend return
                // sources at `stream:false` and no sources at `stream:true` — the worst shape of a
                // loss, because nothing about the request explains the difference.
                //
                // WIRE SHAPE (docs.cohere.com/v2/docs/streaming): a `citation-start` event carries a
                // SINGLE Citation object at `delta.message.citations` — NOT an array. The reference
                // event is `CitationStartEventDeltaMessage(citations=Citation(...))`, one Citation per
                // event. Emitting a JSON array here was off-spec: a native Cohere v2 SDK deserializes
                // `delta.message.citations` into ONE `Citation`, so an array body is a decode error
                // (and a proxy tell). This SINGLE-frame arm therefore frames the FIRST citation only;
                // `write_response_events` is what walks a multi-citation delta, re-entering here once
                // per citation, so a caller reaching this method directly still gets a well-formed
                // (if partial) frame rather than an off-spec array. An empty batch emits nothing.
                crate::ir::IrDelta::CitationsDelta(cits) if !cits.is_empty() => {
                    let c = cits.first()?;
                    Some((
                        "".to_string(),
                        serde_json::json!({
                            "type": ET_CITATION_START,
                            "index": index,
                            "delta": {
                                "message": {
                                    "citations": write_cohere_citation(c)
                                }
                            }
                        }),
                    ))
                }
                crate::ir::IrDelta::CitationsDelta(_) => None,
                // Cohere v2 has no cross-protocol logprobs shape (token IDs only); dropped.
                crate::ir::IrDelta::LogprobsDelta(_) => None,
            },

            IrStreamEvent::BlockStop { index } => {
                // The IR `BlockStop` carries only the integer index, not the block kind. A native
                // Cohere v2 stream closes a tool-call block with `tool-call-end` and a text-content
                // block with `content-end`. Emitting `content-end` for BOTH — as a prior revision
                // did — closed a tool-call block with the text close event, so a native Cohere SDK
                // (which keys on event type to track tool-call state) mis-decoded the stream and the
                // tool block was never properly terminated. So consult the
                // per-stream open-tool set: a tool-call index (recorded by its `tool-call-start`)
                // closes with `tool-call-end`, consuming the marker; any other index (a text block)
                // closes with `content-end`.
                // A tool-call index (recorded by its `tool-call-start`) closes with `tool-call-end`,
                // consuming its marker. A text index (recorded by its `content-start`) closes with
                // `content-end`, consuming its marker. An UNTRACKED index — a cross-protocol block
                // that emitted no opening frame (redacted thinking / Image, whose `BlockStart` maps to `None`)
                // — emits NOTHING: previously it fell through to an unconditional `content-end`,
                // producing an orphan close with no matching `content-start`. This
                // mirrors the Gemini writer's no-frame-for-untracked-index behavior.
                if self.take_tool_open(*index) {
                    Some((
                        "".to_string(),
                        serde_json::json!({ "type": ET_TOOL_CALL_END, "index": index }),
                    ))
                } else if self.take_text_open(*index) {
                    Some((
                        "".to_string(),
                        serde_json::json!({ "type": ET_CONTENT_END, "index": index }),
                    ))
                } else {
                    None
                }
            }

            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
                stop_detail: _,
            } => {
                let cohere_finish_reason = stop_reason
                    .map(write_cohere_stop_reason)
                    .unwrap_or(COHERE_FINISH_COMPLETE);
                // Native Cohere v2 message-end frames carry token usage inside
                // delta.usage.tokens.{input_tokens,output_tokens}. Surface it so a Cohere SDK
                // client tracking billing/rate-limit data from the stream is not silently zeroed.
                // IrUsage is always present (not Option); when upstream supplied nothing it is
                // zero-valued, which serializes here as a safe `{input_tokens:0,output_tokens:0}`.
                // Cohere's `tokens.input_tokens` is the WHOLE prompt, cached share included, with the
                // cache hit reported beside it as `cached_tokens` — see `cohere_prompt_tokens`.
                let mut usage_obj = serde_json::json!({
                    "tokens": {
                        "input_tokens": cohere_prompt_tokens(usage),
                        "output_tokens": usage.output_tokens
                    }
                });
                if let (Some(cached), Some(uo)) =
                    (usage.cache_read_input_tokens, usage_obj.as_object_mut())
                {
                    uo.insert("cached_tokens".to_string(), serde_json::json!(cached));
                }
                // The separately-billed search units, in Cohere's native `billed_units` slot — the
                // same field the buffered writer emits. `search_units` is not a token count at all,
                // so its absence is invisible in a token total that reconciles perfectly; emitting
                // it only on the buffered path meant a streamed RAG call under-reported the charge.
                // Emitted only when the source reported it, so no stream acquires a fabricated
                // `billed_units` object.
                let mut billed_units = serde_json::Map::new();
                if let Some(v) = usage.detail.billed_input_tokens {
                    billed_units.insert("input_tokens".to_string(), serde_json::json!(v));
                }
                if let Some(v) = usage.detail.billed_output_tokens {
                    billed_units.insert("output_tokens".to_string(), serde_json::json!(v));
                }
                if let Some(su) = usage.detail.search_units {
                    billed_units.insert("search_units".to_string(), serde_json::json!(su));
                }
                if let Some(v) = usage.detail.billed_classifications {
                    billed_units.insert("classifications".to_string(), serde_json::json!(v));
                }
                if !billed_units.is_empty() {
                    if let Some(uo) = usage_obj.as_object_mut() {
                        uo.insert(
                            "billed_units".to_string(),
                            serde_json::Value::Object(billed_units),
                        );
                    }
                }
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": ET_MESSAGE_END,
                        "delta": {
                            "finish_reason": cohere_finish_reason,
                            "usage": usage_obj
                        }
                    }),
                ))
            }

            IrStreamEvent::MessageStop => None,
            IrStreamEvent::Error(err) => {
                // Cohere v2 has NO `type: "error"` out-of-band stream event. A native v2 stream
                // signals a mid-stream error by terminating with a `message-end` frame whose
                // `finish_reason` is `ERROR` (infrastructure failure) or `ERROR_TOXIC` (content
                // moderation). Emitting a `type: "error"` frame was both non-native (a strict Cohere
                // SDK ignores or rejects an unknown event type, silently dropping the error) and a
                // protocol-indistinguishability tell. We therefore emit the native `message-end`
                // termination instead. The reader maps `ERROR_TOXIC` back to IR `safety` and the
                // generic `ERROR` to IR `error` (the lowercase passthrough), so this round-trips: a
                // content-moderation signal in the provider_signal maps to `ERROR_TOXIC`, everything
                // else to the generic `ERROR`.
                let toxic = err
                    .provider_signal
                    .as_deref()
                    .is_some_and(cohere_error_is_content_moderation);
                let finish_reason = if toxic {
                    COHERE_FINISH_ERROR_TOXIC
                } else {
                    COHERE_FINISH_ERROR
                };
                // Emit the native `message-end` shape EXACTLY — `type` + `delta.{finish_reason,
                // usage}` — and nothing else. A native Cohere v2 `message-end` frame (the one the
                // normal MessageDelta arm above produces) carries ONLY `type` and `delta`; it never
                // carries a top-level `message`, and it ALWAYS includes `delta.usage`. A prior
                // revision added a top-level `"message": <detail>` field and omitted `delta.usage`,
                // both of which diverge from the native wire shape and let a client (or passive
                // observer) fingerprint the proxy — and a strict v2 SDK may reject the unexpected
                // field. The load-bearing discriminant is
                // `finish_reason` (`ERROR`/`ERROR_TOXIC`), which the reader maps back to IR
                // (`error`/`safety` respectively), so the detail string carries no protocol value on
                // the wire; surface it server-side instead so operators are not left with an opaque
                // error.
                if let Some(detail) = err.provider_signal.as_deref() {
                    tracing::warn!(
                        finish_reason,
                        detail,
                        "cohere: mid-stream error terminating with native message-end frame"
                    );
                }
                Some((
                    "".to_string(),
                    serde_json::json!({
                        "type": ET_MESSAGE_END,
                        "delta": {
                            "finish_reason": finish_reason,
                            "usage": {
                                "tokens": { "input_tokens": 0, "output_tokens": 0 }
                            }
                        }
                    }),
                ))
            }
        }
    }

    fn write_response_events(&self, ev: &IrStreamEvent) -> Vec<(String, serde_json::Value)> {
        // Cohere v2's native SSE brackets EACH citation with a `citation-start` (which carries the
        // Citation object) AND a matching `citation-end` (a bare structural close) — see
        // docs.cohere.com/v2/docs/streaming. `write_response_event` can only return ONE frame, so on
        // its own it emits the `citation-start` and DROPS the `citation-end`, leaving an unbalanced
        // lone-start a native Cohere SDK (or a passive fingerprinter) can tell from a real stream.
        // Override the multi-frame seam (the same one `ResponsesWriter` uses) to emit the native
        // PAIR. The `citation-start` itself is still built by the single-frame arm above, so there is
        // ONE source of truth for its shape; this only appends the paired close. Every other event
        // keeps the historical one-frame behavior via the base wrapper.
        if let IrStreamEvent::BlockDelta {
            index,
            delta: crate::ir::IrDelta::CitationsDelta(cits),
        } = ev
        {
            let mut frames = Vec::with_capacity(cits.len() * 2);
            // One native start/end PAIR per citation. The framing seam fans a multi-citation delta
            // out to one citation per delta (`max_citations_per_delta`) on its way here, but it is
            // not the only caller — the plane codec drives `write_response_events` directly — and a
            // delta that arrives with several citations must emit all of them, not silently keep the
            // first. Each citation is framed by re-entering the single-frame arm with a one-citation
            // delta, so that arm stays the ONE source of truth for the `citation-start` shape.
            for c in cits {
                let one = IrStreamEvent::BlockDelta {
                    index: *index,
                    delta: crate::ir::IrDelta::CitationsDelta(vec![c.clone()]),
                };
                if let Some(start) = self.write_response_event(&one) {
                    frames.push(start);
                    frames.push((
                        "".to_string(),
                        serde_json::json!({ "type": ET_CITATION_END, "index": index }),
                    ));
                }
            }
            return frames;
        }
        self.write_response_event(ev).into_iter().collect()
    }

    fn write_error_frame(&self, err: &IrError) -> Option<(String, serde_json::Value)> {
        // The streaming-error seam: delegate to this dialect's own event writer so the mid-stream
        // error frame is byte-for-byte what an `Error` event produces on this wire.
        self.write_response_event(&IrStreamEvent::Error(err.clone()))
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let _t = busbar_timing::timeit!("cohere_write_response");
        let mut out = serde_json::Map::new();
        let mut content_arr: Vec<serde_json::Value> = Vec::new();
        let mut tool_calls_arr: Vec<serde_json::Value> = Vec::new();

        for block in &resp.content {
            match block {
                crate::ir::IrBlock::Text { text, .. } => {
                    content_arr.push(serde_json::json!({ "type": "text", "text": text }));
                }
                crate::ir::IrBlock::ToolUse {
                    id, name, input, ..
                } => {
                    // Verbatim for a raw Value::String (avoid double-encoding), same as OpenAI/Responses.
                    let args_str = busbar_substrate_values::proto::tool_arguments_to_string(input);
                    // Accumulate every tool call. Inserting per-iteration would overwrite the
                    // key and silently drop all but the last call on parallel tool use.
                    tool_calls_arr.push(serde_json::json!({ "id": id, "type": "function", "function": { "name": name, "arguments": args_str }}));
                }
                // A reasoning block is the model's reasoning, and a Cohere reasoning model returns
                // that as a `{"type":"thinking"}` content part, in place, ahead of the answer — the
                // shape this dialect's reader reads and the streamed `content-start {thinking}`
                // frames carry. It used to be written into `message.tool_plan`, the slot for the plan
                // that precedes a tool call, so a foreign model's reasoning reached a Cohere client
                // as a plan (COH-08). A REDACTED block is opaque ciphertext with no Cohere analog and
                // is dropped.
                crate::ir::IrBlock::Thinking {
                    text,
                    redacted: false,
                    ..
                } => {
                    if !text.is_empty() {
                        content_arr
                            .push(serde_json::json!({ "type": "thinking", "thinking": text }));
                    }
                }
                crate::ir::IrBlock::Thinking { .. } => {}
                crate::ir::IrBlock::Image { .. }
                | crate::ir::IrBlock::Media { .. }
                | crate::ir::IrBlock::ToolResult { .. }
                | crate::ir::IrBlock::Json(_) => {}
            }
        }

        let cohere_finish_reason = resp
            .stop_reason
            .map(write_cohere_stop_reason)
            .unwrap_or(COHERE_FINISH_COMPLETE);

        // A Cohere `LogprobItem` is keyed by the token ids the text decodes from, which no other
        // dialect reports, so a foreign backend's log probabilities have no Cohere form. Dropped,
        // observably.
        if !resp.logprobs.is_empty() {
            tracing::warn!(
                "dropping response logprobs on Cohere egress: a Cohere logprobs item needs the token \
                 ids, which the source dialect has no field for"
            );
        }

        // Cohere format: usage.tokens.input_tokens, usage.tokens.output_tokens
        let mut tokens_map = serde_json::Map::new();
        // The WHOLE prompt, cached share included — see `cohere_prompt_tokens`.
        tokens_map.insert(
            "input_tokens".to_string(),
            serde_json::json!(cohere_prompt_tokens(&resp.usage)),
        );
        tokens_map.insert(
            "output_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );

        // Emit the response identity. Same-protocol passthrough preserves the captured upstream
        // `id` exactly; the cross-protocol case (a non-Cohere backend that never supplied one)
        // hits `None` and we synthesize a shape-valid Cohere id so a native SDK always reads a
        // non-empty `.id` string.
        let id = resp.id.clone().unwrap_or_else(synthesize_cohere_id);
        out.insert("id".to_string(), serde_json::Value::String(id));
        // model that served the response (preserved across cross-protocol translation)
        if let Some(ref model) = resp.model {
            out.insert("model".to_string(), serde_json::json!(model));
        }
        out.insert(
            "finish_reason".to_string(),
            serde_json::json!(cohere_finish_reason),
        );
        // Native Cohere v2 carries tool calls INSIDE the message object (response.message
        // .tool_calls) — exactly where this file's own read_response reads them from. Nesting them
        // here (rather than at the top level) keeps the body native for a real Cohere SDK and lets
        // a Cohere -> Cohere passthrough round-trip every parallel tool call.
        let mut message_obj = serde_json::Map::new();
        message_obj.insert("role".to_string(), serde_json::json!("assistant"));
        message_obj.insert("content".to_string(), serde_json::Value::Array(content_arr));
        // Grounding citations, in Cohere's native `message.citations` slot. A citation READ from a
        // Cohere response carries the source object verbatim in `raw`, so a same-protocol path
        // re-emits it unchanged; a cross-protocol citation is synthesized from the neutral fields.
        // Emitted only when non-empty — an absent key is what Cohere returns for an ungrounded
        // answer, so a hardcoded `[]` would be a proxy tell in the other direction.
        let citations_arr: Vec<serde_json::Value> = resp
            .content
            .iter()
            .filter_map(|b| match b {
                crate::ir::IrBlock::Text { citations, .. } => Some(citations),
                _ => None,
            })
            .flatten()
            .map(write_cohere_citation)
            .collect();
        if !citations_arr.is_empty() {
            message_obj.insert(
                "citations".to_string(),
                serde_json::Value::Array(citations_arr),
            );
        }
        if !tool_calls_arr.is_empty() {
            message_obj.insert(
                "tool_calls".to_string(),
                serde_json::Value::Array(tool_calls_arr),
            );
        }
        out.insert(
            "message".to_string(),
            serde_json::Value::Object(message_obj),
        );
        // Wrap tokens under "tokens" key per Cohere API spec
        let mut usage_map = serde_json::Map::new();
        usage_map.insert("tokens".to_string(), serde_json::Value::Object(tokens_map));
        // The prompt-cache hit, in Cohere's native `usage.cached_tokens` slot (beside `tokens`, the
        // same member this dialect's reader reads it from). Emitted only when the source reported a
        // cache read, so an uncached response does not acquire a fabricated `cached_tokens: 0`.
        if let Some(cached) = resp.usage.cache_read_input_tokens {
            usage_map.insert("cached_tokens".to_string(), serde_json::json!(cached));
        }
        // Cohere's native `billed_units` slot: the separately-metered BILLED attribution, distinct
        // from the raw `tokens` bucket above. Each member is emitted only when the source actually
        // reported it (so a plain chat response does not acquire a fabricated `billed_units` object,
        // and a partial bucket is not padded with invented zeros). `input_tokens`/`output_tokens`
        // are the billed token counts, `search_units`/`classifications` are non-token billed units.
        let mut billed_units = serde_json::Map::new();
        if let Some(v) = resp.usage.detail.billed_input_tokens {
            billed_units.insert("input_tokens".to_string(), serde_json::json!(v));
        }
        if let Some(v) = resp.usage.detail.billed_output_tokens {
            billed_units.insert("output_tokens".to_string(), serde_json::json!(v));
        }
        if let Some(su) = resp.usage.detail.search_units {
            billed_units.insert("search_units".to_string(), serde_json::json!(su));
        }
        if let Some(v) = resp.usage.detail.billed_classifications {
            billed_units.insert("classifications".to_string(), serde_json::json!(v));
        }
        if !billed_units.is_empty() {
            usage_map.insert(
                "billed_units".to_string(),
                serde_json::Value::Object(billed_units),
            );
        }
        out.insert("usage".to_string(), serde_json::Value::Object(usage_map));

        serde_json::Value::Object(out)
    }

    /// NATIVE Cohere v2 error envelope. The Cohere v2 chat API conveys the error *category* via the
    /// HTTP status (400/401/404/429/5xx) and carries only a human-readable `{"message": <detail>}`
    /// body — it has no typed `error.type`/`code` field the way OpenAI/Anthropic do. So the generic
    /// `kind` is intentionally NOT surfaced in the body (it would be a field a native SDK never
    /// sees); it is dropped here and conveyed solely by the caller's HTTP status. Real Cohere v2
    /// error bodies are a bare `{"message": "..."}` and do NOT carry a synthesized id; this reader's
    /// own `extract_error` reads only `message`/`error_type` and never `id`, so emitting an `id`
    /// here was both a proxy tell and internally inconsistent with the reader. Served as
    /// `application/json` per the trait contract.
    ///
    /// This is a LIVE production code path, not test-only scaffolding: it is reached at runtime via
    /// the `ProtocolWriter` trait object on every Cohere-ingress error response (e.g. ingress,
    /// proxy engine, and auth.rs all dispatch `p.writer().write_error(...)`). It carries no
    /// `allow(dead_code)` suppression — matching every other protocol writer — because the
    /// dead-code lint never fires on vtable-dispatched trait method implementations.
    fn write_error(&self, _status: u16, _kind: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "message": message,
        })
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}

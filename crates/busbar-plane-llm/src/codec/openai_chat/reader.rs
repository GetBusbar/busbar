use super::*;
use crate::codec::dialect::ir_parse_error;

impl ProtocolReader for OpenAiReader {
    fn recover_truncated_usage(&self, tail: &[u8]) -> Option<busbar_contract::billing::TokenUsage> {
        let v = super::super::usage_tail::isolate_tail_usage_object(tail, b"\"usage\"")?;
        // Every count is read through the dialect's usage table (`USAGE`): an unreadable one yields
        // NO recovered usage, never a zero one (#42). A truncated body reads the cache tiers an
        // untruncated one does.
        Some(read_openai_usage(Some(&v), None).ok()?.to_token_usage())
    }

    fn extract_error(
        &self,
        status: StatusCode,
        body: &[u8],
    ) -> busbar_contract::upstream::RawUpstreamError {
        // Parse the error body exactly once and derive both fields from the single tree, mirroring
        // the single-parse pattern in AnthropicReader::extract_error. The previous code parsed the
        // same bytes twice (once per field), doubling alloc/CPU on every non-2xx response.
        let json = crate::codec::json::parse::<serde_json::Value>(body).ok();
        let error_obj = json
            .as_ref()
            .and_then(|j| j.get(keys::ERROR_WORD))
            .and_then(|e| e.as_object());
        let provider_code = error_obj
            .and_then(|e_obj| e_obj.get(keys::CODE))
            .and_then(|c| c.as_str())
            .map(String::from);
        let structured_type = error_obj
            .and_then(|e_obj| e_obj.get(keys::TYPE))
            .and_then(|t| t.as_str())
            .map(String::from);

        // Make the derivation MESSAGE-AWARE, mirroring openai_responses.rs / anthropic.rs. OpenAI (and many
        // OpenAI-compatible backends) signal a context-length overflow with a structured
        // `code: "context_length_exceeded"`, which the parse above captures. But some upstreams send
        // a null/absent `code` and carry the condition only in the prose `message` — e.g.
        // `This model's maximum context length is 8192 tokens, however you requested 9000 tokens...`.
        // Without a message scan that body would normalize to a generic client error and PENALIZE the
        // lane instead of triggering oversized-request failover. When no canonical code was parsed,
        // scan the lowercased message for the context-length signal and synthesize the canonical code.
        //
        // The scan must be PRECISE. A naive `(token|context) && (too long|exceeds|maximum)`
        // OR-of-weak-tokens misclassifies unrelated errors — e.g. a quota body like
        // `You have reached the maximum number of tokens allowed per day` (rate-limit, not oversized)
        // pairs a stray `maximum` with a stray `token` and would falsely fail over with no penalty.
        // Require a CO-LOCATED context-length phrase, mirroring the openai_responses.rs / anthropic.rs
        // siblings: either a self-contained canonical phrase, or `exceeds` paired specifically with
        // `context`/`token limit` (not a bare `token`/`maximum`). Gate to the HTTP statuses OpenAI
        // actually uses for an oversized request (400 invalid_request_error; 413 payload-too-large)
        // so a 429/5xx that happens to mention tokens can never be reclassified as ContextLength.
        let provider_code = provider_code.or_else(|| {
            let oversized_status =
                status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE;
            if !oversized_status {
                return None;
            }
            let message = error_obj
                .and_then(|e_obj| e_obj.get(keys::MESSAGE))
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_lowercase();
            if context_length_prose_scan(&message) {
                Some(busbar_contract::protocol::PROVIDER_CODE_CONTEXT_LENGTH.to_string())
            } else {
                None
            }
        });

        busbar_contract::upstream::RawUpstreamError {
            http_status: status.as_u16(),
            provider_code,
            structured_type,
            retry_after_secs: None,
        }
    }

    #[cfg(test)]
    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal {
        // Both bearer-envelope dialects classify alike: single-sourced in the shared dialect module.
        crate::codec::dialect::bearer_error_classify(status.as_u16(), body)
    }

    fn read_request(
        &self,
        body: &serde_json::Value,
    ) -> Result<crate::codec::ir::IrRequest, IrError> {
        let obj = body.as_object().ok_or_else(ir_parse_error)?;

        let mut extra = serde_json::Map::new();
        let mut system_blocks: Vec<crate::codec::ir::IrBlock> = Vec::new();
        // Count of `system`/`developer`-role entries folded out of `messages` below — restores the
        // 1.5.5 `message_count` semantics (the raw wire array length) onto `IrFacts::shape()`.
        let mut system_turns_folded: usize = 0;
        // IR-14: which role the folded system entries were written in — `(saw system, saw developer)`.
        let mut system_roles_seen = (false, false);
        // Where each folded entry stood, for the hook view (`IrRequest::system_folds`).
        let mut system_folds: Vec<crate::codec::ir::IrSystemFold> = Vec::new();

        // Extract scalar fields and extra
        let _model = obj
            .get(keys::MODEL)
            .and_then(|v| v.as_str())
            .map(String::from);

        // Read the caller's output-token cap. `max_tokens` is the legacy field; `max_completion_tokens`
        // is the current Chat Completions parameter and is MANDATORY for reasoning models (o1/o3/...),
        // which REJECT `max_tokens`. Fall back to `max_completion_tokens` when `max_tokens` is absent so
        // a request carrying only the modern field still populates the modeled IR `max_tokens`. Without
        // this, the value stays only in `extra` and is stripped at the cross-protocol seam (extra is
        // cleared there), silently dropping the caller's explicit limit on e.g. OpenAI -> Anthropic.
        // Narrow with `u32::try_from` (NOT a bare `as u32`): a value above `u32::MAX` (or negative)
        // would otherwise wrap/truncate silently into a tiny or nonsensical token cap. `as_u64`
        // already rejects negatives and non-integers, `try_from` rejects > u32::MAX, and the final
        // `> 0` filter rejects a zero cap (an invalid limit, not a real bound). This matches the
        // hardened sibling readers (gemini/anthropic/cohere/bedrock) while preserving the existing
        // non-positive-rejection contract.
        let max_tokens = obj
            .get(keys::MAX_TOKENS)
            .or_else(|| obj.get(MAX_COMPLETION_TOKENS))
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .filter(|&v| v > 0);
        // Remember whether the cap arrived as `max_completion_tokens` (and NOT `max_tokens`) so a
        // same-protocol OpenAI passthrough to an o1/o3 reasoning model re-emits `max_completion_tokens`
        // (which those models require) rather than the canonical `max_tokens` (which they 400 on). Only
        // record when `max_tokens` is genuinely absent — if both are present the writer's canonical
        // `max_tokens` is correct. The sentinel rides `extra` and is cleared on the cross-protocol seam,
        // so it scopes to same-protocol exactly.
        let max_completion_tokens_was_source =
            !obj.contains_key(keys::MAX_TOKENS) && obj.contains_key(MAX_COMPLETION_TOKENS);
        // The sampling controls (temperature, top_p, the penalties, seed, n, stop) are rows of the
        // mapping file, read below. `response_format` is the raw object (json_object /
        // json_schema), stored verbatim so the writer can re-emit it unchanged.
        let response_format = obj
            .get(keys::RESPONSE_FORMAT)
            .and_then(read_openai_response_format);
        let stream = obj
            .get(keys::STREAM)
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Handle messages array
        let mut messages: Vec<crate::codec::ir::IrMessage> = Vec::new();
        // Per-message participant names, collected during the loop and parked in `extra` afterwards
        // (see `MESSAGE_NAMES_SENTINEL`).
        let mut message_names = serde_json::Map::new();
        // Per-message PROVIDER-SPECIFIC fields with no cross-protocol analog (an assistant history
        // turn's `audio` reference, the legacy `function_call`, and any future message-level key),
        // parked verbatim by IR-message index under `MESSAGE_EXTRAS_SENTINEL` so a same-protocol
        // pool-alias re-serialize preserves them; `extra` is cleared on the cross-protocol seam, so
        // they drop there (named in the generic dropped-keys warn) — the correct scope, since no other
        // dialect models them. See that const for the full rationale.
        let mut message_extras = serde_json::Map::new();
        // Legacy function calling (OAI-07): every assistant `function_call` gets a synthesized
        // `call_…` id, and a later `role:"function"` result pairs with the most recent UNMATCHED
        // call of the same name — the legacy wire correlates by name alone.
        let mut legacy_calls: Vec<(String, String, bool)> = Vec::new();
        if let Some(messages_val) = obj.get(keys::MESSAGES) {
            let msgs_arr = messages_val.as_array().ok_or_else(ir_parse_error)?;

            for msg_val in msgs_arr.iter() {
                let role_str = msg_val
                    .get(keys::ROLE)
                    .and_then(|r| r.as_str())
                    .unwrap_or("");
                let content_val = msg_val.get(keys::CONTENT);

                // EDGE-VALIDATE the per-message `content` TYPE. OpenAI chat `content` is legally a
                // string, an array of content parts, or absent/`null` (an assistant turn carrying
                // only `tool_calls`). A present number/bool/object is a genuine TYPE violation that
                // the lenient str/array projection below would silently coerce to an empty turn —
                // reject it with the same 400 the top-level `messages` array uses. Absent/null/empty
                // stay lenient (forward-compat).
                if let Some(cv) = content_val {
                    if !cv.is_null() && !cv.is_string() && !cv.is_array() {
                        return Err(ir_parse_error());
                    }
                }

                let role = match role_str {
                    // OpenAI's o1/o3 reasoning models replace "system" with "developer" (the
                    // Responses API reader already treats them as equivalent). Map both to the IR
                    // System role so a developer-role turn flows through the existing
                    // System-promotion path below rather than being 400ed by the catch-all.
                    keys::DEVELOPER | keys::SYSTEM => crate::codec::ir::IrRole::System,
                    keys::USER => crate::codec::ir::IrRole::User,
                    keys::ASSISTANT => crate::codec::ir::IrRole::Assistant,
                    // The legacy function-result turn (`{"role":"function","name","content"}`) is a
                    // tool result correlated by name (OAI-07); it is read as one below.
                    keys::TOOL | keys::FUNCTION => crate::codec::ir::IrRole::Tool,
                    _ => return Err(ir_parse_error()),
                };

                // Promote EVERY system-role message to the top-level system field, regardless of
                // position. OpenAI permits system turns anywhere in the array, but Anthropic (and
                // the IR contract) require system content to live in the top-level `system` field —
                // a System-role IrMessage placed inside the messages array would be rendered as
                // `"role": "system"` by the Anthropic writer and rejected with a 400. We therefore
                // never push a System IrMessage; we accumulate its content into system_blocks.
                if role == crate::codec::ir::IrRole::System {
                    system_turns_folded += 1;
                    if role_str == keys::DEVELOPER {
                        system_roles_seen.1 = true;
                    } else {
                        system_roles_seen.0 = true;
                    }
                    let blocks_before = system_blocks.len();
                    if let Some(content) = content_val {
                        if let Some(text) = content.as_str() {
                            system_blocks.push(crate::codec::ir::IrBlock::Text {
                                text: text.to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                                refusal: false,
                            });
                        } else if let Some(arr) = content.as_array() {
                            for block_val in arr {
                                system_blocks.extend(read_openai_part(block_val)?);
                            }
                        }
                    }
                    // A present-but-degenerate system message (e.g. content omitted, null, or an
                    // empty array) must not silently vanish: emit an empty Text block so the system
                    // turn is preserved rather than dropped. `content_val.is_none()` (key absent)
                    // also lands here, which matches treating an empty system turn as present.
                    // A turn whose parts were all of kinds the reader does not model is NOT empty:
                    // those parts are dropped (named at a translate seam) and nothing is put in
                    // their place (design F3 "Drops").
                    let had_parts = content_val
                        .and_then(|c| c.as_array())
                        .is_some_and(|a| !a.is_empty());
                    if system_blocks.len() == blocks_before && !had_parts {
                        system_blocks.push(crate::codec::ir::IrBlock::Text {
                            text: String::new(),
                            cache_control: None,
                            citations: Vec::new(),
                            refusal: false,
                        });
                    }
                    crate::codec::ir::IrSystemFold::record(
                        &mut system_folds,
                        messages.len(),
                        if role_str == "developer" {
                            crate::codec::ir::IrSystemRole::Developer
                        } else {
                            crate::codec::ir::IrSystemRole::System
                        },
                        blocks_before,
                        system_blocks.len(),
                    );
                } else {
                    let mut msg_content = Vec::new();

                    // For a Tool-role message the `content` payload is the tool RESULT: it is
                    // captured below as the `ToolResult` block's inner content (mirroring the native
                    // shape). Pushing it ALSO as a standalone Text block here duplicated the tool
                    // output into two IR blocks — and on a Tool->OpenAI write that surfaced as a
                    // spurious extra `{"role":"tool"}` message carrying the same text. So skip the
                    // standalone-content projection for Tool-role messages; the ToolResult path owns
                    // the tool content. User/assistant/system content is projected as before.
                    if role != crate::codec::ir::IrRole::Tool {
                        if let Some(cv) = content_val {
                            if let Some(text) = cv.as_str() {
                                msg_content.push(crate::codec::ir::IrBlock::Text {
                                    text: text.to_string(),
                                    cache_control: None,
                                    citations: Vec::new(),
                                    refusal: false,
                                });
                            } else if let Some(arr) = cv.as_array() {
                                for block_val in arr {
                                    msg_content.extend(read_openai_part(block_val)?);
                                }
                            }
                        }
                    }

                    // Handle tool_calls for assistant messages
                    if role == crate::codec::ir::IrRole::Assistant {
                        if let Some(tool_calls) = msg_val.get(keys::TOOL_CALLS) {
                            if let Some(tc_arr) = tool_calls.as_array() {
                                for tc_val in tc_arr {
                                    // A replayed CUSTOM-tool call (`{"type":"custom","custom":{name,
                                    // input}}`, free-text input) has no IR tool-call form: it is a
                                    // valid native message the reader must not refuse (design F2,
                                    // reader tolerance). It is dropped, observably.
                                    if tc_val.get(keys::TYPE).and_then(|t| t.as_str())
                                        == Some(keys::CUSTOM)
                                    {
                                        tracing::warn!(
                                            "dropping a replayed custom-tool call on translate: the \
                                             IR carries function tool calls only (no-equivalent)"
                                        );
                                        continue;
                                    }
                                    // A present tool call MUST carry a non-empty string `id`: it is
                                    // the correlation key an egress dialect emits back to pair the
                                    // eventual tool result. An absent/blank/wrong-typed id yields an
                                    // empty IR id that silently breaks that pairing downstream, so
                                    // reject the malformed call rather than inventing an id.
                                    let id = tc_val
                                        .get(keys::ID)
                                        .and_then(|v| v.as_str())
                                        .filter(|s| !s.is_empty())
                                        .ok_or_else(ir_parse_error)?
                                        .to_string();
                                    let func =
                                        tc_val.get(keys::FUNCTION).ok_or_else(ir_parse_error)?;
                                    let name = func
                                        .get(keys::NAME)
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let input =
                                        tool_input_from_arguments(func.get(keys::ARGUMENTS));

                                    msg_content.push(crate::codec::ir::IrBlock::ToolUse {
                                        id,
                                        name,
                                        input,
                                        cache_control: None,
                                        thought_signature: None,
                                    });
                                }
                            }
                        }
                    }

                    // The legacy single call on an assistant turn, `function_call{name, arguments}`
                    // (pre-`tool_calls` API): a ToolUse with a synthesized id (OAI-07), so a legacy
                    // conversation replayed to another dialect keeps its call. The raw member also
                    // stays in this message's extras stash, which is what an OpenAI-origin
                    // re-serialize writes back instead of `tool_calls`.
                    if role == crate::codec::ir::IrRole::Assistant
                        && msg_val.get(keys::TOOL_CALLS).is_none()
                    {
                        if let Some(fc) = msg_val.get(keys::FUNCTION_CALL).filter(|f| f.is_object())
                        {
                            let name = fc
                                .get(keys::NAME)
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let id = synth_response_tool_call_id(legacy_calls.len(), &name);
                            legacy_calls.push((name.clone(), id.clone(), false));
                            msg_content.push(crate::codec::ir::IrBlock::ToolUse {
                                id,
                                name,
                                input: tool_input_from_arguments(fc.get(keys::ARGUMENTS)),
                                cache_control: None,
                                thought_signature: None,
                            });
                        }
                    }

                    // Handle tool results
                    if role == crate::codec::ir::IrRole::Tool {
                        let tool_call_id = if role_str == keys::FUNCTION {
                            // Legacy result: pair by name with the latest unmatched legacy call; a
                            // result with no such call keeps a synthesized id of its own.
                            let fname = msg_val
                                .get(keys::NAME)
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            match legacy_calls
                                .iter_mut()
                                .rev()
                                .find(|(n, _, matched)| n == fname && !matched)
                            {
                                Some((_, id, matched)) => {
                                    *matched = true;
                                    id.clone()
                                }
                                None => synth_response_tool_call_id(legacy_calls.len(), fname),
                            }
                        } else {
                            msg_val
                                .get(keys::TOOL_CALL_ID)
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string()
                        };
                        // OpenAI tool-message `content` may be EITHER a plain string OR an array of
                        // content parts (e.g. `[{"type":"text","text":"..."}]`), both legal per the
                        // current Chat Completions spec. The prior `as_str().unwrap_or("")` handled
                        // only the string form and silently collapsed array-form tool output to an
                        // empty string, dropping the tool result on the cross-protocol path. We now
                        // mirror the user/assistant content handling: a string is used verbatim; an
                        // array is parsed part-by-part via `read_openai_block` and its text parts are
                        // concatenated. Non-text parts (which carry no textual payload) contribute
                        // nothing, matching how a native backend would render the same array.
                        let content_text = match content_val {
                            Some(serde_json::Value::String(s)) => s.clone(),
                            Some(serde_json::Value::Array(parts)) => {
                                let mut acc = String::new();
                                for part in parts {
                                    if let Ok(Some(crate::codec::ir::IrBlock::Text {
                                        text, ..
                                    })) = read_openai_part(part)
                                    {
                                        acc.push_str(&text);
                                    }
                                }
                                acc
                            }
                            Some(_) | None => String::new(),
                        };

                        msg_content.push(crate::codec::ir::IrBlock::ToolResult {
                            tool_use_id: tool_call_id,
                            content: vec![crate::codec::ir::IrBlock::Text {
                                text: content_text,
                                cache_control: None,
                                citations: Vec::new(),
                                refusal: false,
                            }],
                            is_error: false,
                            cache_control: None,
                        });
                    }

                    // A message-level `refusal` string (an assistant turn OpenAI echoes into replayed
                    // history) carries the same content as a `refusal` content PART. Map it to a Text
                    // block flagged as a refusal (IR-02) so it survives a CROSS-protocol hop (plain
                    // assistant text where the target has no refusal part), mirroring
                    // `read_openai_block`'s `"refusal"` content-part arm and the response reader's
                    // `message.refusal` handling. A same-protocol re-serialize writes it back as a
                    // `refusal` content part (value preserved).
                    if let Some(refusal) = msg_val
                        .get(keys::REFUSAL)
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    {
                        msg_content.push(crate::codec::ir::IrBlock::Text {
                            text: refusal.to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                            refusal: true,
                        });
                    }

                    // OpenAI's optional per-message participant `name`. Parked under
                    // `MESSAGE_NAMES_SENTINEL` keyed by the IR message index (see that const for why
                    // this is not an `IrMessage` field): it survives a same-protocol re-serialize and
                    // is NAMED in the cross-protocol dropped-keys warn instead of vanishing.
                    if let Some(name) = msg_val
                        .get(keys::NAME)
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty() && role_str != keys::FUNCTION)
                    {
                        message_names.insert(messages.len().to_string(), serde_json::json!(name));
                    }

                    // Capture any message-level field this reader does NOT model into a per-message
                    // extras stash (keyed by IR-message index), so a provider-specific construct —
                    // an assistant `audio` reference, the legacy `function_call`, or a future key —
                    // survives a same-protocol re-serialize verbatim rather than vanishing. The keys
                    // already projected into typed IR (`content`/`tool_calls`/`name`/`refusal`) and the
                    // structural `role`/`tool_call_id` are EXCLUDED so the writer never double-emits.
                    if let Some(mo) = msg_val.as_object() {
                        let mut this_extras = serde_json::Map::new();
                        for (k, v) in mo {
                            if !matches!(
                                k.as_str(),
                                keys::ROLE
                                    | keys::CONTENT
                                    | keys::NAME
                                    | keys::TOOL_CALLS
                                    | keys::TOOL_CALL_ID
                                    | keys::REFUSAL
                            ) {
                                this_extras.insert(k.clone(), v.clone());
                            }
                        }
                        // A legacy `role:"function"` turn is remembered as one (its function
                        // `name` included), so an OpenAI-origin re-serialize writes it back in the
                        // legacy shape rather than as a `tool` message.
                        if role_str == keys::FUNCTION {
                            this_extras.insert(
                                LEGACY_FUNCTION_ROLE_KEY.to_string(),
                                msg_val
                                    .get(keys::NAME)
                                    .cloned()
                                    .unwrap_or(serde_json::Value::Null),
                            );
                        }
                        if !this_extras.is_empty() {
                            message_extras.insert(
                                messages.len().to_string(),
                                serde_json::Value::Object(this_extras),
                            );
                        }
                    }
                    messages.push(crate::codec::ir::IrMessage {
                        role,
                        content: msg_content,
                    });
                }
            }
        }

        // Handle tools array
        let mut tools: Vec<crate::codec::ir::IrTool> = Vec::new();
        let mut custom_tools: Vec<crate::codec::ir::IrHostedTool> = Vec::new();
        if let Some(tools_val) = obj.get(keys::TOOLS) {
            // A PRESENT `tools` that is not an array is a malformed request — reject it (mirroring the
            // `messages` type-check) rather than coercing to empty, which would forward a tool-less
            // request upstream at HTTP 200 and silently strip the caller's tools.
            let tools_arr = tools_val.as_array().ok_or_else(ir_parse_error)?;
            for tool_val in tools_arr {
                // OAI-09: a `custom` tool (free-text / grammar input) crosses in
                // the typed hosted-tool slot, so a Responses lane receives it; one carrying a member
                // the IR cannot hold stays the raw same-protocol tool.
                if let Some(custom) = super::slots::read_custom_tool(tool_val) {
                    custom_tools.push(custom);
                    continue;
                }
                tools.push(read_openai_tool(tool_val)?);
            }
        } else if let Some(functions) = obj.get(FUNCTIONS).and_then(|f| f.as_array()) {
            // The legacy `functions` array (pre-`tools` API): each entry IS the body of a modern
            // function tool, so it is read as one (OAI-07). `functions` also stays in `extra`, which
            // is what an OpenAI-origin re-serialize writes back instead of `tools`.
            for f in functions {
                tools.push(read_openai_tool(&serde_json::json!({
                    (keys::TYPE): TOOL_TYPE_FUNCTION,
                    (keys::FUNCTION): f,
                }))?);
            }
        }

        // Collect unmodeled top-level keys into extra (excluding modeled ones). The fields the IR
        // models as first-class — model, messages, tools, max_tokens, temperature, top_p, stop, stream,
        // tool_choice, frequency_penalty, presence_penalty, seed, n, response_format — are
        // excluded; everything else (logit_bias, …) flows through `extra` verbatim so a SAME-protocol
        // OpenAI passthrough reaches the upstream unchanged.
        //
        // frequency_penalty / presence_penalty / seed / n / response_format are promoted to
        // first-class IR fields (read above) and excluded here, so they no longer linger in `extra` —
        // otherwise the writer would double-emit them (once from the typed field, once from the extra
        // sweep). Cross-protocol mapping of these to Gemini/Anthropic/Bedrock analogs is handled by the
        // translate seam (`proxy engine`).
        //
        // The modelled keys are the mapping file's top-level rows.
        crate::codec::carry::keep_unmodelled(super::map::REQUEST, obj, &mut extra);

        // Stamp the source-key sentinel when the cap arrived as `max_completion_tokens` (and
        // only when it produced a usable value, so we never claim a phantom cap). Same-protocol only:
        // `extra` is cleared on the cross-protocol seam.
        if max_completion_tokens_was_source && max_tokens.is_some() {
            extra.insert(
                MAX_COMPLETION_TOKENS_SENTINEL.to_string(),
                serde_json::Value::Bool(true),
            );
        }
        // Park the per-message participant names, only when at least one message carried one, so an
        // ordinary request's `extra` (and therefore its cross-protocol dropped-keys warn) is
        // untouched.
        if !message_names.is_empty() {
            extra.insert(
                MESSAGE_NAMES_SENTINEL.to_string(),
                serde_json::Value::Object(message_names),
            );
        }
        // Park the per-message provider-specific extras (only when some message carried one) so an
        // ordinary request's `extra` is untouched. Same same-protocol-only scope as the names sentinel.
        if !message_extras.is_empty() {
            extra.insert(
                MESSAGE_EXTRAS_SENTINEL.to_string(),
                serde_json::Value::Object(message_extras),
            );
        }

        // `tool_choice` is a first-class IR control so a forced/targeted directive survives
        // the cross-protocol seam instead of degrading to `auto`. Read it from the native shape here.
        // The legacy `function_call` directive (`"auto"` / `"none"` / `{"name":X}`) is the
        // pre-`tools` spelling of `tool_choice` (OAI-07); read it when `tool_choice` is absent.
        let tool_choice = read_openai_tool_choice(obj.get(keys::TOOL_CHOICE)).or_else(|| match obj
            .get(
            keys::FUNCTION_CALL,
        )? {
            serde_json::Value::String(s) if s == keys::AUTO => {
                Some(crate::codec::ir::IrToolChoice::Auto)
            }
            serde_json::Value::String(s) if s == keys::NONE_WORD => {
                Some(crate::codec::ir::IrToolChoice::None)
            }
            serde_json::Value::Object(o) => {
                o.get(keys::NAME).and_then(|n| n.as_str()).map(|name| {
                    crate::codec::ir::IrToolChoice::Tool {
                        name: name.to_string(),
                    }
                })
            }
            _ => None,
        });

        // Cross-protocol carries with an Anthropic analog: `user` <-> `metadata.user_id`,
        // `parallel_tool_calls` <-> `!tool_choice.disable_parallel_tool_use`.
        let user = obj
            .get(keys::USER)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let parallel_tool_calls = obj.get(keys::PARALLEL_TOOL_CALLS).and_then(|v| v.as_bool());

        // The reasoning ASK in chat-completions spelling: a top-level `reasoning_effort` word.
        // Promoted so it carries to Anthropic/Gemini thinking budgets via the effort table.
        let reasoning_effort_raw = obj.get(REASONING_EFFORT).and_then(|v| v.as_str());
        // IR-09 (OAI-10): `xhigh` (the gpt-5 family's step above `high`) is the IR's `XHigh`, and
        // `none` is reasoning switched OFF (`IrReasoningAsk::Off` — not "the caller said nothing"),
        // so a cross-protocol lane gets the top effort / thinking disabled instead of losing the ask.
        // (`max` is not a Chat word and stays unmapped.) The raw word still rides `extra` (below) so
        // an OpenAI-origin re-serialize writes it back verbatim.
        let reasoning = reasoning_effort_raw.and_then(|raw| match raw {
            keys::NONE_WORD => Some(crate::codec::ir::IrReasoningAsk::Off),
            "xhigh" => Some(crate::codec::ir::IrReasoningAsk::Effort(
                crate::codec::ir::IrReasoningEffort::XHigh,
            )),
            other => crate::codec::ir::IrReasoningEffort::parse(other)
                .map(crate::codec::ir::IrReasoningAsk::Effort),
        });
        // `reasoning_effort` is a MODELED key (in `modeled_request_keys()` below), so it is
        // excluded from the generic `extra` sweep — an unrecognised value (e.g. a `gpt-5`-family
        // spelling this build's `IrReasoningEffort::parse` doesn't know, like "none"/"xhigh")
        // would otherwise be stripped and LOST entirely, even OpenAI->OpenAI same-lane. The
        // `OnceLock<HashSet>` behind `modeled_request_keys()` cannot be varied per request, so
        // re-inserting here — the reader's own escape hatch — is the only implementable rescue.
        if let Some(raw) = reasoning_effort_raw {
            if crate::codec::ir::IrReasoningEffort::parse(raw).is_none() {
                if reasoning.is_none() {
                    tracing::warn!(
                        reasoning_effort = raw,
                        "reasoning_effort value has no IR word; preserving it verbatim in extra so \
                         a same-protocol OpenAI egress still carries it (a cross-protocol hop \
                         carries no ask)"
                    );
                }
                extra.insert(
                    REASONING_EFFORT.to_string(),
                    serde_json::Value::String(raw.to_string()),
                );
            }
        }

        // Logprobs ask, carried first-class so it reaches a Gemini backend as
        // `generationConfig.responseLogprobs`/`logprobs` (and back).
        let logprobs = obj.get(keys::LOGPROBS).and_then(|v| v.as_bool());
        let top_logprobs = obj
            .get(keys::TOP_LOGPROBS)
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());

        let mut ir = crate::codec::ir::IrRequest {
            reasoning,
            logprobs,
            top_logprobs,
            user,
            parallel_tool_calls,
            system: system_blocks,
            system_turns_folded,
            system_folds,
            messages,
            tools,
            max_tokens,
            tool_choice,
            stream,
            response_format,
            extra,
            hosted_tools: custom_tools,
            // IR-14: `developer` only when EVERY folded entry was one, `system` only when every one
            // was; mixed (or none) says nothing.
            system_role: match system_roles_seen {
                (true, false) => Some(crate::codec::ir::IrSystemRole::System),
                (false, true) => Some(crate::codec::ir::IrSystemRole::Developer),
                _ => None,
            },
            ..Default::default()
        };
        // The flat request fields (`map.gen.rs`), then the allowed-tools subset of `tool_choice`.
        crate::codec::carry::read_fields(super::map::REQUEST, obj, &mut ir);
        super::slots::read_tool_choice_slots(obj, &mut ir);
        Ok(ir)
    }

    /// OpenAI's flat stream → IR block-structured events. One chat.completion.chunk
    /// may carry role + content + finish at once → up to several IR events. State synthesizes the
    /// block boundaries OpenAI doesn't have.
    fn read_response_events(
        &self,
        _event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::codec::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        let mut out: Vec<IrStreamEvent> = Vec::new();

        // [DONE] sentinel (or any non-object) carries no IR events.
        if data.as_str() == Some(crate::codec::dialect::SSE_DONE_SENTINEL) {
            return out;
        }

        // 0. Inline error envelope. An OpenAI-compatible upstream (OpenAI, Azure, vLLM, OpenRouter)
        //    that fails AFTER the 200 headers are on the wire delivers the failure as a data chunk
        //    carrying `{"error":{"message","type","code"}}` and NO `choices`. Every guard below keys
        //    off `choices`, so without this arm the chunk decodes to nothing at all and the stream
        //    ends as a clean success: no `IrStreamEvent::Error`, so `terminal_error()` stays None,
        //    the breaker records no fault, the partial completion is BILLED as a finished one, and a
        //    cross-protocol client receives balanced block-stops plus a normal terminator with no
        //    hint that the answer was truncated by an upstream failure. The proxy engine only
        //    converts HTTP-status-level errors, so a 200-status inline error bypasses that path
        //    entirely. Mirror the gemini/bedrock/anthropic/openai_responses readers: map the
        //    envelope's own vocabulary to a canonical `StatusClass` and push a single
        //    `IrStreamEvent::Error` so the downstream writer terminates with a native error frame.
        //
        //    Handled BEFORE the MessageStart block so an error-only chunk never emits a stray start
        //    frame (matching the gemini sibling); on a stream that already started, MessageStart has
        //    long since been emitted and the Error simply terminates it.
        if let Some(error_obj) = data.get(keys::ERROR_WORD).and_then(|e| e.as_object()) {
            let error_type = error_obj.get(keys::TYPE).and_then(|t| t.as_str());
            let code = error_obj.get(keys::CODE).and_then(|c| c.as_str());
            // Carry the most specific upstream token through as the provider signal (`code` when
            // present, else `type`, else the prose `message`), so a same-protocol egress can round
            // trip it and the breaker's observability names the real fault. `None` only when the
            // envelope carries none of the three.
            let provider_signal = code
                .filter(|c| !c.is_empty())
                .or(error_type)
                .or_else(|| error_obj.get(keys::MESSAGE).and_then(|m| m.as_str()))
                .map(String::from);
            out.push(IrStreamEvent::Error(busbar_contract::protocol::IrError {
                class: stream_inline_error_class(error_type, code),
                provider_signal,
                retry_after: None,
            }));
            return out;
        }

        // 1. MessageStart exactly once (on the first chunk, regardless of delta.role). Capture the
        //    chunk's top-level identity (`id` = "chatcmpl-...", `created` = unix secs, `model`) so a
        //    same-protocol passthrough stream re-emits it verbatim. Every OpenAI chunk carries these;
        //    we read them off whichever chunk happens to be first.
        if !state.started {
            state.started = true;
            out.push(IrStreamEvent::MessageStart {
                role: crate::codec::ir::IrRole::Assistant,
                usage: None,
                id: data
                    .get(keys::ID)
                    .and_then(|v| v.as_str())
                    .map(String::from),
                created: data.get(CREATED).and_then(|v| v.as_u64()),
                model: data
                    .get(keys::MODEL)
                    .and_then(|v| v.as_str())
                    .map(String::from),
            });
        }

        let choices_arr = data.get(CHOICES).and_then(|c| c.as_array());
        // A client can legally request n>1 (OpenAI `n`). This reader collapses to choices[0], which
        // is all a CROSS-PROTOCOL (IR-rebuilt) hop can carry — the rest are dropped there. A
        // same-protocol relay re-emits the upstream bytes verbatim and preserves all N; this reader is
        // still invoked on that path as a usage side-channel, so the message is scoped to the
        // cross-protocol case rather than asserting an unconditional drop. Warn ONCE per stream.
        // Defense-in-depth: the engine now rejects n>1 up front on cross-protocol routes.
        if let Some(arr) = choices_arr {
            if arr.len() > 1 && !state.multi_candidate_warned {
                state.multi_candidate_warned = true;
                tracing::warn!(
                    choices = arr.len(),
                    "openai stream chunk carried multiple choices; only choices[0] survives IR translation — a cross-protocol hop drops the rest (a same-protocol relay preserves all)"
                );
            }
        }
        let choice0 = choices_arr.and_then(|a| a.first());
        let delta = choice0.and_then(|c| c.get(keys::DELTA));

        // 2. Reasoning (chain-of-thought) → a Thinking block. Reasoning that arrives before any
        //    answer block opens at index 0, ahead of the answer, and `reasoning_seen` reserves that
        //    slot (the claim counter starts at 1 after it).
        //
        //    Reasoning that arrives AFTER the answer phase began (a text or tool block already
        //    opened — interleaved reasoning from OpenAI-compatible backends) is no longer dropped
        //    (OAI-14): it closes an open text block and opens a NEW Thinking block at the next free
        //    index from the monotone counter, so no already-opened index ever shifts. Its index is
        //    recorded under `LATE_THINKING_KEY` so every later delta and its stop replay it.
        if let Some(reasoning) = delta
            .and_then(|d| d.get(REASONING_CONTENT).or_else(|| d.get(keys::REASONING)))
            .and_then(|r| r.as_str())
            .filter(|r| !r.is_empty())
        {
            if !state.thinking_block_open {
                let answer_started = state.text_block_open
                    || state.text_block_closed
                    || state.text_index.is_some()
                    || !state.open_tools.is_empty()
                    || state.next_ir_index > 0;
                let index = if answer_started {
                    close_text_block(state, &mut out);
                    let i = state.claim_ir_index();
                    state.tool_ir_index.insert(LATE_THINKING_KEY, i);
                    i
                } else {
                    state.reasoning_seen = true;
                    state.tool_ir_index.remove(&LATE_THINKING_KEY);
                    0
                };
                state.thinking_block_open = true;
                out.push(IrStreamEvent::BlockStart {
                    index,
                    block: crate::codec::ir::IrBlockMeta::Thinking { kind: None },
                    refusal: false,
                });
            }
            out.push(IrStreamEvent::BlockDelta {
                index: thinking_index(state),
                delta: crate::codec::ir::IrDelta::ThinkingDelta(reasoning.to_string()),
            });
        }

        // 3. Text content → close any open thinking block first, then open the text block + a
        //    TextDelta. Text claims its index from the monotone counter (`claim_ir_index`), which
        //    reserves index 0 for a thinking block via `reasoning_seen` — see its own docs.
        // `delta.refusal` carries a structured-outputs / safety refusal in the SAME incremental
        // string shape as `delta.content`, and the two are mutually exclusive on a chunk. Route it
        // through the same text block: Anthropic/Bedrock/Gemini have no distinct refusal part, so a
        // refusal is plain assistant text there. Reading only `content` produced a stream with no
        // text at all and an end_turn finish — an empty 200 the client could not tell from a model
        // that said nothing. `refusal_seen` promotes the stop reason on the terminal frame.
        let refusal_delta = delta
            .and_then(|d| d.get(keys::REFUSAL))
            .and_then(|c| c.as_str())
            .filter(|s| !s.is_empty());
        if refusal_delta.is_some() {
            state.refusal_seen = true;
        }
        let content_delta = delta
            .and_then(|d| d.get(keys::CONTENT))
            .and_then(|c| c.as_str());
        // IR-02: the refusal rides its OWN text block, opened with `refusal: true`, so a writer with a
        // refusal slot (Chat `delta.refusal`, Responses refusal events) carries it exactly. A
        // non-empty refusal wins over an empty `content` on the same chunk.
        let (text_delta, is_refusal) = match (content_delta, refusal_delta) {
            (Some(c), _) if !c.is_empty() => (Some(c), false),
            (_, Some(r)) => (Some(r), true),
            (c, None) => (c, false),
        };
        // A non-empty delta of the OTHER kind than the open text block closes it, so a refusal and
        // ordinary content never share one block.
        if state.text_block_open
            && text_delta.is_some_and(|t| !t.is_empty())
            && is_refusal != open_text_is_refusal(state)
        {
            close_text_block(state, &mut out);
        }
        if let Some(content) = text_delta
            // An EMPTY delta after the text block closed carries nothing and must not open a new,
            // empty text block.
            .filter(|c| !(state.text_block_closed && c.is_empty()))
        {
            close_thinking_block(state, &mut out);
            // Text that RESUMES after its block was closed (by a `tool_calls` chunk, or by late
            // reasoning) opens a NEW text block at the next free index (OAI-14) — never a second
            // `BlockStart` at the closed index, and never a silent drop of the model's answer.
            if state.text_block_closed {
                state.text_block_closed = false;
                state.text_index = None;
            }
            let ti = match state.text_index {
                Some(i) => i,
                None => {
                    // Claim the next free IR index BY ORDER OF FIRST APPEARANCE, not a recomputed
                    // base — a tool that arrived before this text chunk already claimed its own
                    // slot from the SAME counter, so text can never land on it regardless of the
                    // upstream tool_calls[].index values (see the MONOTONE counter's own docs).
                    let i = state.claim_ir_index();
                    state.text_index = Some(i);
                    i
                }
            };
            if !state.text_block_open {
                state.text_block_open = true;
                if is_refusal {
                    state.tool_ir_index.insert(REFUSAL_TEXT_KEY, ti);
                }
                out.push(IrStreamEvent::BlockStart {
                    index: ti,
                    block: crate::codec::ir::IrBlockMeta::Text,
                    refusal: is_refusal,
                });
            }
            out.push(IrStreamEvent::BlockDelta {
                index: ti,
                delta: crate::codec::ir::IrDelta::TextDelta(content.to_string()),
            });
        }

        // 3b. Per-chunk logprobs ride the CHOICE (not the delta): `choices[].logprobs.content[]`
        //     alongside the content delta. Carry them as a LogprobsDelta on the text block's index
        //     so a foreign-dialect stream (e.g. a Gemini client) can re-emit them natively. A
        //     logprobs-only chunk (no content) still opens the text block so the delta has a block
        //     to attach to.
        // Gate on `!text_block_closed` for the same reason as step 3: a logprobs chunk arriving after
        // `tool_calls` closed the text block must not reopen it (duplicate `BlockStart` at a closed
        // index) — drop the stray logprobs rather than un-balance the stream.
        let lp_entries = if state.text_block_closed {
            Vec::new()
        } else {
            crate::codec::logprob_wire::read_token_logprobs(
                choice0.and_then(|c| c.get(keys::LOGPROBS)),
            )
        };
        if !lp_entries.is_empty() {
            if !state.text_block_open {
                // Close any still-open thinking block FIRST (a logprobs-only chunk can arrive while
                // the thinking block is open — e.g. a reasoning backend that streams logprobs). Without
                // this the text block opens at `text_index` while the thinking block at 0 stays open,
                // leaving two blocks open and an unbalanced IR stream — the same guard steps 3 and 4 have.
                close_thinking_block(state, &mut out);
                state.text_block_open = true;
                let ti = state.text_index.unwrap_or_else(|| {
                    let i = state.claim_ir_index();
                    state.text_index = Some(i);
                    i
                });
                out.push(IrStreamEvent::BlockStart {
                    index: ti,
                    block: crate::codec::ir::IrBlockMeta::Text,
                    refusal: false,
                });
            }
            out.push(IrStreamEvent::BlockDelta {
                index: state
                    .text_index
                    .expect("text_index set above when block opens"),
                delta: crate::codec::ir::IrDelta::LogprobsDelta(lp_entries),
            });
        }

        // 3c. Grounding sources stream as `choices[].delta.annotations` (`url_citation` entries,
        //     the same shape the buffered `message.annotations` carries and this dialect's own
        //     stream writer emits). They annotate the answer text, so they ride a CitationsDelta on
        //     the text block (OAI-02) — opening it when none has opened yet, exactly as a
        //     logprobs-only chunk does. Offsets are not carried, for the reason
        //     `read_url_annotations` gives (the buffered path drops them the same way).
        let citations = delta
            .and_then(|d| d.get(keys::ANNOTATIONS))
            .map(super::super::url_citation_wire::read_url_annotations)
            .unwrap_or_default();
        if !citations.is_empty() {
            if state.text_block_closed && !state.text_block_open {
                // The text these sources annotate is already closed (a tool call intervened), and
                // a CitationsDelta at a closed index would un-balance the stream. Say so rather
                // than detach the sources into a new, empty text block.
                tracing::warn!(
                    citations = citations.len(),
                    "dropping streamed url_citation annotations that arrived after their text \
                     block closed; they are NOT forwarded on this cross-protocol stream"
                );
            } else {
                if !state.text_block_open {
                    close_thinking_block(state, &mut out);
                    state.text_block_open = true;
                    let ti = state.text_index.unwrap_or_else(|| {
                        let i = state.claim_ir_index();
                        state.text_index = Some(i);
                        i
                    });
                    out.push(IrStreamEvent::BlockStart {
                        index: ti,
                        block: crate::codec::ir::IrBlockMeta::Text,
                        refusal: false,
                    });
                }
                if let Some(ti) = state.text_index {
                    out.push(IrStreamEvent::BlockDelta {
                        index: ti,
                        delta: crate::codec::ir::IrDelta::CitationsDelta(citations),
                    });
                }
            }
        }

        // 4. Tool calls → IR block index claimed from the MONOTONE counter, by order of first
        //    appearance, exactly like the text block above. `oai_idx` (the upstream `tool_calls[].
        //    index`) is a JOIN KEY that pairs this tool's id/name chunk with its later `arguments`
        //    chunks — NOT an index space we may project into: a backend that streams
        //    `tool_calls[{index:1}]` with no index 0 (vLLM / Azure / OpenRouter re-index) would
        //    otherwise collide with, or leave a gap before, the text block. BlockStart on first
        //    sight (id+name present), InputJsonDelta for streamed arguments.
        //    The legacy single-call shape `delta.function_call{name, arguments}` (the pre-`tool_calls`
        //    API, still spoken by older OpenAI-compatible backends) streams exactly like one tool call
        //    with no id: it rides the same path under the reserved `LEGACY_FUNCTION_CALL_KEY` join key
        //    with a synthesized `call_…` id (OAI-08), so its name and arguments reach the IR instead
        //    of vanishing while `finish_reason: "function_call"` reports a tool use with no block.
        let tool_items: Vec<(usize, Option<&str>, Option<&serde_json::Value>)> = match delta
            .and_then(|d| d.get(keys::TOOL_CALLS))
            .and_then(|t| t.as_array())
        {
            Some(tcs) => tcs
                .iter()
                .map(|tc| {
                    // Bound the upstream-supplied tool-call index before it touches `open_tools` /
                    // `tool_ir_index` as a key. A crafted/proxied chunk can carry `"index":
                    // u64::MAX`; OpenAI documents at most 128 parallel tool calls, so any larger
                    // index is malformed. `claim_ir_index()` increments by 1 from 0 and is bounded by
                    // the number of blocks the stream actually opens, so `oai_idx` no longer enters
                    // index arithmetic and the old overflow hazard is structurally gone — this clamp
                    // now exists solely to bound `oai_idx` as a map/set key.
                    let oai_idx = tc
                        .get(keys::INDEX)
                        .and_then(|i| i.as_u64())
                        .map_or(0, |v| v.min(MAX_TOOL_INDEX) as usize);
                    (
                        oai_idx,
                        tc.get(keys::ID).and_then(|i| i.as_str()),
                        tc.get(keys::FUNCTION),
                    )
                })
                .collect(),
            None => delta
                .and_then(|d| d.get(keys::FUNCTION_CALL))
                .filter(|f| f.is_object())
                .map(|f| vec![(LEGACY_FUNCTION_CALL_KEY, None, Some(f))])
                .unwrap_or_default(),
        };
        if !tool_items.is_empty() {
            // A tool call means the answer phase has begun; close any still-open thinking block.
            close_thinking_block(state, &mut out);
            // Also close a still-open TEXT block (a preamble-then-tool stream): otherwise the tool
            // block opens while the text block is still open, leaving two content blocks open at once
            // — overlapping blocks that violate the strict bracketing asserted downstream. The close
            // LATCHES the text index (`text_block_closed`), so text that resumes after the tool calls
            // (vLLM/Azure/OpenRouter stream preamble→tool_calls→more text) opens a NEW text block at
            // the next free index instead of a second `BlockStart` at the closed one (OAI-14).
            close_text_block(state, &mut out);
            for (oai_idx, tc_id, func) in tool_items {
                if let Some(name) = func
                    .and_then(|f| f.get(keys::NAME))
                    .and_then(|n| n.as_str())
                {
                    // Cap the number of DISTINCT open tool calls per stream. Without this, a
                    // pathological backend emitting unbounded unique indices would grow `open_tools`
                    // (and the emitted BlockStart count) without limit — a per-request memory-
                    // exhaustion DoS. The cap matches OpenAI's documented parallel-tool-call limit;
                    // an index beyond it that is not already open is treated as argument deltas for
                    // an already-open block (its BlockStart is suppressed) rather than opening a new
                    // one. An already-open index is always honored so in-flight blocks keep flowing.
                    let already_open = state.open_tools.contains(&oai_idx);
                    if !already_open && state.open_tools.len() < MAX_OPEN_TOOLS {
                        let id = match tc_id {
                            Some(id) => id.to_string(),
                            None if oai_idx == LEGACY_FUNCTION_CALL_KEY => {
                                synth_response_tool_call_id(0, name)
                            }
                            None => String::new(),
                        };
                        let ir_idx = state.claim_ir_index();
                        state.open_tools.insert(oai_idx);
                        // Record the IR index this tool's BlockStart was emitted with so every
                        // later reference (arg deltas, the finish-path BlockStop) replays THIS
                        // index verbatim — the monotone counter never revisits a claimed slot, so
                        // there is nothing to recompute at close time.
                        state.tool_ir_index.insert(oai_idx, ir_idx);
                        out.push(IrStreamEvent::BlockStart {
                            index: ir_idx,
                            block: crate::codec::ir::IrBlockMeta::ToolUse {
                                id,
                                name: name.to_string(),
                            },
                            refusal: false,
                        });
                    }
                }
                if let Some(args) = func
                    .and_then(|f| f.get(keys::ARGUMENTS))
                    .and_then(|a| a.as_str())
                {
                    // Only route argument deltas to an index we actually opened a BlockStart for.
                    // `open_tools.contains(&oai_idx)` implies a recorded `tool_ir_index` entry
                    // (both inserted together above under one guard; the over-cap path inserts
                    // neither), so a missing entry means there was no BlockStart and the correct
                    // action is to emit nothing.
                    let Some(&index) = state.tool_ir_index.get(&oai_idx) else {
                        continue;
                    };
                    out.push(IrStreamEvent::BlockDelta {
                        index,
                        delta: crate::codec::ir::IrDelta::InputJsonDelta(args.to_string()),
                    });
                }
            }
        }

        // Read top-level `usage` INDEPENDENTLY of finish_reason. With
        // `stream_options: {include_usage: true}` the OpenAI API emits usage in a SEPARATE trailing
        // chunk whose `choices` array is EMPTY and which carries NO finish_reason — for that chunk
        // `choice0` is None, so the finish_reason branch below never runs. Reading usage here (rather
        // than only inside the finish_reason block, as the prior code did) ensures the trailing
        // usage chunk is not silently discarded, preserving token accounting across translated /
        // passthrough OpenAI streams that follow the spec'd trailing-usage convention.
        //
        // CRITICAL: under `include_usage` the OpenAI API sets `usage: null` on EVERY non-final chunk.
        // `serde_json::Value::get("usage")` returns `Some(Value::Null)` for a present-but-null key,
        // so a naive `.map(...)` would synthesize `Some(IrUsage{0,0,..})` on every content chunk and
        // (via the trailing-usage branch below) emit a spurious mid-stream `MessageDelta` per chunk.
        // Filter to a real usage OBJECT so `usage: null` reads as `None`.
        //
        // BILLED COUNTS: absent is zero, a present-but-UNREADABLE count REFUSES (#42) — the stream
        // ends in an error instead of ledgering zero tokens.
        // The sub-buckets ride the STREAM's usage chunk too (a `stream_options:
        // {include_usage: true}` stream's final chunk carries the identical `usage` object the
        // buffered response does), so the one table reads them here as well; the serving tier rides
        // the chunk's top level, beside `usage` (OAI-03).
        let chunk_usage = data
            .get(keys::USAGE)
            .filter(|u| u.is_object())
            .map(|u| read_openai_usage(Some(u), data.get(keys::SERVICE_TIER)));
        let chunk_usage = match chunk_usage.transpose() {
            Ok(usage) => usage,
            Err(refusal) => {
                out.push(IrStreamEvent::Error(refusal));
                return out;
            }
        };

        // 5. finish_reason → close open blocks (text first, then tools ascending), MessageDelta, MessageStop.
        let finish_reason = choice0
            .and_then(|c| c.get(keys::FINISH_REASON))
            .and_then(|r| r.as_str());
        if let Some(fr) = finish_reason {
            // Close in order: thinking (if it never yielded to text), then text, then tools.
            close_thinking_block(state, &mut out);
            if state.text_block_open {
                state.text_block_open = false;
                // `text_block_open == true` implies `text_index.is_some()` (both are set together
                // at the two open sites above), so no index is ever fabricated here.
                if let Some(ti) = state.text_index {
                    out.push(IrStreamEvent::BlockStop { index: ti });
                }
            }
            // Replay each tool's BlockStop at the EXACT IR index its BlockStart was emitted with,
            // read back from `tool_ir_index`. Under monotone allocation the index was claimed ONCE
            // at open time and never recomputed, so there is no divergent "close-time base" to
            // reconcile — unlike the old `text_index.is_some()`-derived base, which changed value
            // once text arrived after a tool had already opened. `open_tools`/`tool_ir_index` are
            // taken (not just read) here — `next_ir_index` is the only monotone state carried
            // forward, so a post-finish chunk claims a genuinely fresh slot (see its own docs).
            let tool_ir_index = std::mem::take(&mut state.tool_ir_index);
            for oai_idx in std::mem::take(&mut state.open_tools) {
                if let Some(&index) = tool_ir_index.get(&oai_idx) {
                    out.push(IrStreamEvent::BlockStop { index });
                }
            }
            let stop_reason = match read_openai_stop_reason(fr) {
                // A refusal reports `finish_reason: "stop"`. Only EndTurn is overridden — a refusal
                // that also hit the length cap keeps MaxTokens.
                crate::codec::ir::IrStopReason::EndTurn if state.refusal_seen => {
                    Some(crate::codec::ir::IrStopReason::Refusal)
                }
                other => Some(other),
            };
            let usage = chunk_usage.unwrap_or(IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
                // A finish chunk without usage still names the serving tier (OAI-03).
                detail: crate::codec::ir::IrUsageDetail {
                    service_tier: crate::codec::carry::read_word(
                        super::map::WORDS_SERVED_TIER,
                        data.get(keys::SERVICE_TIER),
                    ),
                    ..Default::default()
                },
            });
            out.push(IrStreamEvent::MessageDelta {
                stop_reason,
                // OpenAI has no stop_sequence analog in its stream.
                stop_sequence: None,
                usage,
                stop_detail: None,
            });
            out.push(IrStreamEvent::MessageStop);
        } else if let Some(usage) = chunk_usage {
            // Trailing usage-only chunk (include_usage convention): no finish_reason and (per the
            // null-filter above) a REAL top-level `usage` object with an EMPTY `choices` array. Emit a
            // MessageDelta carrying the late usage so consumers that fold it (Bedrock ingress builds
            // its single `metadata` frame from this) see real token counts instead of zeros.
            //
            // `choice0.is_none()` guards the genuine usage-only chunk shape: a normal content chunk
            // (which still carries a finish-less choice) never reaches this branch even if some
            // non-standard intermediary attached a real usage object to it. This reader is ingress-
            // AGNOSTIC, so it always emits the faithful IR; the cross-protocol ORDERING concern (this
            // delta arrives after the finish chunk's MessageStop, which would be an invalid
            // `message_delta`-after-`message_stop` frame for non-Bedrock SSE ingress) is handled where
            // the ingress IS known — `StreamTranslate::translate_event` drops a terminal-class
            // MessageDelta that arrives after MessageStop for non-eventstream ingress.
            if choice0.is_none() {
                out.push(IrStreamEvent::MessageDelta {
                    stop_reason: None,
                    stop_sequence: None,
                    usage,
                    stop_detail: None,
                });
            }
        }

        out
    }

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }

    fn request_map(&self) -> crate::codec::carry::Table {
        super::map::REQUEST
    }

    fn parked(&self) -> &'static [crate::codec::drops::Parked] {
        super::PARKED
    }

    fn request_blocks(&self) -> &'static [crate::codec::drops::Blocks] {
        super::REQUEST_BLOCKS
    }

    fn response_blocks(&self) -> &'static [crate::codec::drops::Blocks] {
        super::RESPONSE_BLOCKS
    }

    fn read_response(
        &self,
        body: &serde_json::Value,
    ) -> Result<crate::codec::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or_else(ir_parse_error)?;

        // Get choices array
        let choices_val = obj.get(CHOICES).ok_or_else(ir_parse_error)?;
        let choices = choices_val.as_array().ok_or_else(ir_parse_error)?;

        if choices.is_empty() {
            return Err(ir_parse_error());
        }

        // A client can legally request n>1 (OpenAI `n`). This reader collapses to choices[0], which
        // is all a CROSS-PROTOCOL (IR-rebuilt) hop can carry — the rest are dropped there. A
        // same-protocol relay re-emits the upstream body verbatim and preserves all N; this reader is
        // still invoked on that path as a usage side-channel, so the message is scoped to the
        // cross-protocol case rather than asserting an unconditional drop. Defense-in-depth: the
        // engine now rejects n>1 up front on cross-protocol routes.
        if choices.len() > 1 {
            tracing::warn!(
                choices = choices.len(),
                "openai response carried multiple choices; only choices[0] survives IR translation — a cross-protocol hop drops the rest (a same-protocol relay preserves all)"
            );
        }

        let choice = &choices[0];

        // Parse role (should be "assistant")
        let message_val = choice.get(keys::MESSAGE).ok_or_else(ir_parse_error)?;
        let _role_str = message_val
            .get(keys::ROLE)
            .and_then(|r| r.as_str())
            .unwrap_or("");

        // Parse content (may be null)
        let mut content: Vec<crate::codec::ir::IrBlock> = Vec::new();

        // Reasoning models on OpenAI-compatible providers (e.g. GLM, DeepSeek) emit the
        // chain-of-thought in a separate `reasoning_content` (or `reasoning`) field. Map it to a
        // Thinking block — ahead of the answer — so it survives translation to protocols that have
        // one (e.g. Anthropic). (Protocols without a thinking concept drop it on write, as before.)
        for key in [REASONING_CONTENT, keys::REASONING] {
            if let Some(r) = message_val.get(key).and_then(|v| v.as_str()) {
                if !r.is_empty() {
                    content.push(crate::codec::ir::IrBlock::Thinking {
                        text: r.to_string(),
                        signature: None,
                        redacted: false,
                        cache_control: None,
                        kind: None,
                        signature_origin: None,
                    });
                    break;
                }
            }
        }

        if let Some(content_val) = message_val.get(keys::CONTENT) {
            if let Some(text) = content_val.as_str() {
                if !text.is_empty() {
                    // `annotations` is a sibling of `content` on the `message` object (not nested
                    // per content-part, since `content` is a plain string here). See
                    // `read_url_annotations` for why offsets are deliberately not carried.
                    let citations = message_val
                        .get(keys::ANNOTATIONS)
                        .map(super::super::url_citation_wire::read_url_annotations)
                        .unwrap_or_default();
                    content.push(crate::codec::ir::IrBlock::Text {
                        text: text.to_string(),
                        cache_control: None,
                        citations,
                        refusal: false,
                    });
                }
            } else if let Some(arr) = content_val.as_array() {
                for block_val in arr {
                    let Some(block) = read_openai_part(block_val)? else {
                        continue;
                    };
                    // An image part in a RESPONSE message array has no Chat Completions response
                    // representation (the completion `message.content` carries no image output), so it
                    // is dropped — but OBSERVABLY: `warn!` instead of the prior silent skip, so a
                    // dropped image part in a model's array-content response is visible in logs.
                    if matches!(block, crate::codec::ir::IrBlock::Image { .. }) {
                        tracing::warn!(
                            "dropping an image content part from an OpenAI Chat response message: the \
                             completion response shape carries no image output; the block is NOT \
                             emitted"
                        );
                    } else {
                        content.push(block);
                    }
                }
            }
        }

        // A structured-outputs / safety refusal arrives as `content: null` plus a `refusal` string,
        // with `finish_reason: "stop"` — so neither the content nor the stop reason carries the
        // signal. Reading only `content` produced an empty IR response, which the cross-protocol
        // writers emit as a 200 with `content: []`: indistinguishable from a model that returned
        // nothing, and an index error for any SDK consumer reading `content[0]`. Carry the text as
        // assistant Text (Anthropic/Bedrock/Gemini have no distinct refusal part) and promote the
        // stop reason below, matching what the sibling Responses reader already does.
        let mut saw_refusal = false;
        if let Some(text) = message_val.get(keys::REFUSAL).and_then(|v| v.as_str()) {
            if !text.is_empty() {
                saw_refusal = true;
                // Flagged as the refusal message (IR-02), so a dialect with a refusal slot carries it
                // exactly; everywhere else it is plain assistant text.
                content.push(crate::codec::ir::IrBlock::Text {
                    text: text.to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                    refusal: true,
                });
            }
        }

        // Parse tool_calls
        if let Some(tool_calls_val) = message_val.get(keys::TOOL_CALLS) {
            if let Some(tc_arr) = tool_calls_val.as_array() {
                for (tc_ordinal, tc_val) in tc_arr.iter().enumerate() {
                    // A response tool-call id is the correlation key a later `tool` message pairs
                    // against, and cross-protocol (e.g. →Anthropic `tool_use.id`) a BLANK id is
                    // rejected by the target reader. The request path already forbids a blank id; on
                    // the RESPONSE path, rather than fail an otherwise-good upstream body, SYNTHESIZE a
                    // deterministic `call_…` id when the backend supplied none — so the correlation key
                    // is never blank. (`unwrap_or("")` previously let an empty id through to egress.)
                    let raw_id = tc_val.get(keys::ID).and_then(|v| v.as_str()).unwrap_or("");
                    let func = tc_val.get(keys::FUNCTION).ok_or_else(ir_parse_error)?;
                    let name = func
                        .get(keys::NAME)
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let id = if raw_id.is_empty() {
                        synth_response_tool_call_id(tc_ordinal, &name)
                    } else {
                        raw_id.to_string()
                    };
                    let input = tool_input_from_arguments(func.get(keys::ARGUMENTS));

                    content.push(crate::codec::ir::IrBlock::ToolUse {
                        id,
                        name,
                        input,
                        cache_control: None,
                        thought_signature: None,
                    });
                }
            }
        }

        // The legacy single-call shape `message.function_call{name, arguments}` (pre-`tool_calls`,
        // still returned by older OpenAI-compatible backends with `finish_reason: "function_call"`)
        // is a tool use exactly like a `tool_calls` entry, minus the id: read it as a ToolUse with
        // a synthesized `call_…` id (OAI-08), so the call is not lost behind a ToolUse stop reason
        // that has no block. Read only when there are no `tool_calls` (the two never coexist).
        if !content
            .iter()
            .any(|b| matches!(b, crate::codec::ir::IrBlock::ToolUse { .. }))
        {
            if let Some(fc) = message_val
                .get(keys::FUNCTION_CALL)
                .filter(|f| f.is_object())
            {
                let name = fc
                    .get(keys::NAME)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                content.push(crate::codec::ir::IrBlock::ToolUse {
                    id: synth_response_tool_call_id(0, &name),
                    input: tool_input_from_arguments(fc.get(keys::ARGUMENTS)),
                    name,
                    cache_control: None,
                    thought_signature: None,
                });
            }
        }

        // Parse finish_reason → stop_reason mapping
        let finish_reason = choice
            .get(keys::FINISH_REASON)
            .and_then(|r| r.as_str())
            .unwrap_or("");
        let mut stop_reason = if finish_reason.is_empty() {
            None
        } else {
            Some(read_openai_stop_reason(finish_reason))
        };
        // A refusal reports `finish_reason: "stop"`, so the signal only survives if it is promoted
        // here. Only EndTurn is overridden — a refusal that also hit the length cap keeps MaxTokens.
        if saw_refusal && stop_reason == Some(crate::codec::ir::IrStopReason::EndTurn) {
            stop_reason = Some(crate::codec::ir::IrStopReason::Refusal);
        }

        // Parse usage. Treat an absent `usage` object leniently — fall back to zero counts rather
        // than hard-erroring. A missing `usage` is an upstream response-format quirk (a
        // mock/staging/proxy OpenAI-compatible backend that omits it on an otherwise valid 200
        // completion), NOT a client mistake: returning a `ClientError` here mislabels the cause and
        // makes proxy engine discard a valid 200 body and emit a spurious 500. The sibling Gemini and
        // Cohere readers tolerate the same condition with a zero-usage fallback. `usage_val` is an
        // `Option`, so each token lookup below already defaults to 0.
        let usage_val = obj.get(keys::USAGE);
        //
        // Absent is zero, a present-but-UNREADABLE count REFUSES (#42). See `USAGE` for the cache
        // normalization and the attribution sub-buckets; the serving tier is a top-level member
        // beside `usage` (OAI-03).
        let usage = read_openai_usage(usage_val, obj.get(keys::SERVICE_TIER))?;

        let model = obj
            .get(keys::MODEL)
            .and_then(|m| m.as_str())
            .map(String::from);

        // Capture the upstream's response identity so same-protocol (OpenAI→OpenAI) passthrough
        // preserves it exactly: `id` ("chatcmpl-..."), `created` (unix secs), `system_fingerprint`.
        // (`object` is fixed "chat.completion" and re-emitted by the writer; `usage.total_tokens` is
        // derivable from prompt+completion, so it is recomputed on write rather than stored.)
        let id = obj.get(keys::ID).and_then(|v| v.as_str()).map(String::from);
        let created = obj.get(CREATED).and_then(|v| v.as_u64());
        let system_fingerprint = obj
            .get(SYSTEM_FINGERPRINT)
            .and_then(|v| v.as_str())
            .map(String::from);

        // Per-token logprobs from the first choice, carried neutrally so a foreign-dialect caller
        // (e.g. Gemini) receives them in its own shape.
        let logprobs =
            crate::codec::logprob_wire::read_token_logprobs(choices[0].get(keys::LOGPROBS));

        Ok(crate::codec::ir::IrResponse {
            logprobs,
            role: crate::codec::ir::IrRole::Assistant,
            content,
            stop_reason,
            usage,
            model,
            id,
            created,
            system_fingerprint,
            stop_sequence: None,

            request_echo: None,
            stop_detail: None,
            safety: super::read_moderation(obj.get(MODERATION)),
            audio: super::read_message_audio(
                choice.get(keys::MESSAGE).and_then(|m| m.get(super::AUDIO)),
            ),
        })
    }
}

/// The top-level moderation results of a Chat completion.
const MODERATION: &str = "moderation";

/// The `tool_ir_index` key that records the IR index of a Thinking block opened AFTER the answer
/// phase began (OAI-14). Tool keys are upstream `tool_calls[].index` values clamped to
/// `MAX_TOOL_INDEX`, so this key can never collide with a tool.
const LATE_THINKING_KEY: usize = usize::MAX;

/// The `open_tools` / `tool_ir_index` join key of a streamed legacy `delta.function_call` (OAI-08).
/// Real tool keys are clamped to `MAX_TOOL_INDEX`, so this can never collide with one.
const LEGACY_FUNCTION_CALL_KEY: usize = usize::MAX - 1;

/// The `tool_ir_index` key that records the IR index of the text block opened for `delta.refusal`
/// (IR-02). Never an `open_tools` member, so no tool close replays it.
const REFUSAL_TEXT_KEY: usize = usize::MAX - 2;

/// Is the open text block the refusal block?
fn open_text_is_refusal(state: &crate::codec::ir::StreamDecodeState) -> bool {
    state.text_block_open
        && state.text_index.is_some()
        && state.tool_ir_index.get(&REFUSAL_TEXT_KEY).copied() == state.text_index
}

/// The IR index of the open (or last) Thinking block: the recorded late index, else the reserved 0.
fn thinking_index(state: &crate::codec::ir::StreamDecodeState) -> usize {
    state
        .tool_ir_index
        .get(&LATE_THINKING_KEY)
        .copied()
        .unwrap_or(0)
}

/// Close the Thinking block if it is open, at the index it was opened with.
fn close_thinking_block(
    state: &mut crate::codec::ir::StreamDecodeState,
    out: &mut Vec<IrStreamEvent>,
) {
    if state.thinking_block_open {
        state.thinking_block_open = false;
        out.push(IrStreamEvent::BlockStop {
            index: thinking_index(state),
        });
    }
}

/// Close the text block if it is open and latch it closed, so later text opens a fresh block.
fn close_text_block(state: &mut crate::codec::ir::StreamDecodeState, out: &mut Vec<IrStreamEvent>) {
    if state.text_block_open {
        state.text_block_open = false;
        state.text_block_closed = true;
        if let Some(ti) = state.text_index {
            out.push(IrStreamEvent::BlockStop { index: ti });
        }
    }
}

/// Synthesize a deterministic, non-empty `call_…` tool-call id for a RESPONSE tool call whose
/// upstream body carried a blank/absent `id`. A blank id becomes an empty `tool_use.id`/`tool_call_id`
/// that the cross-protocol target reader (Anthropic) rejects and that breaks `tool`/`tool_result`
/// correlation. Derived from `(ordinal, name)` via the stdlib fixed-seed `DefaultHasher` (SipHash-1-3,
/// no new dependency, stable within a run) so repeated function names in one response stay distinct;
/// the `call_` prefix matches OpenAI's native tool-id shape and keeps it visibly synthetic. Mirrors
/// the gemini reader's `synth_tool_call_id` discipline for the same never-blank-correlation-key reason.
fn synth_response_tool_call_id(ordinal: usize, name: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    ordinal.hash(&mut hasher);
    name.hash(&mut hasher);
    format!("call_{:016x}", hasher.finish())
}

/// Decode a tool-call `arguments` field into the IR tool-input `Value`. OpenAI's native shape is a
/// JSON STRING (parsed to a value; a malformed string is preserved verbatim as a `String` rather than
/// dropped, so no arguments are lost). But some OpenAI-compatible backends emit `arguments` as an
/// already-parsed JSON OBJECT (or other non-string value); the prior `as_str().unwrap_or("{}")`
/// COLLAPSED that to an empty object, silently discarding the caller's tool arguments. Use a non-string
/// value directly instead. Absent `arguments` yields `{}` (a no-arg call).
fn tool_input_from_arguments(v: Option<&serde_json::Value>) -> serde_json::Value {
    match v {
        Some(serde_json::Value::String(s)) => crate::codec::json::parse_str(s)
            .unwrap_or_else(|_| serde_json::Value::String(s.clone())),
        Some(other) => other.clone(),
        None => serde_json::json!({}),
    }
}

#[cfg(test)]
#[path = "tests/unreadable_count_refusal_tests.rs"]
mod unreadable_count_refusal_tests;

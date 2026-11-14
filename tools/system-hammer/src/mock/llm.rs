// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The six LLM dialects a mock provider answers: whole, streamed and tool-call bodies.
//!
//! The shapes are the oracle mock's (`busbar-release-oracle` `mock_upstream/bodies.rs`, which the
//! upgrade harness `tests/upgrade` vendors byte-for-byte): the same ids, the same 11-in / 7-out
//! usage, the same tool (`get_weather {"city":"paris"}`) and the same AWS event-stream framing
//! for bedrock. What differs is only what a load mock needs: every body is built ONCE at start
//! (no per-request JSON work), the answer text can be padded to a configured size, and a stream
//! carries `chunks` content deltas instead of one so a gateway relays a realistic number of
//! frames.

use bytes::Bytes;
use serde_json::{json, Value};

pub const IN_TOK: i64 = 11;
pub const OUT_TOK: i64 = 7;
pub const MODEL: &str = "mock";
pub const TOOL_NAME: &str = "get_weather";
const TOOL_ID_ANTHROPIC: &str = "toolu_hammer0001";
const TOOL_ID_OPENAI: &str = "call_hammer0001";
const TOOL_ID_BEDROCK: &str = "tooluse_hammer0001";
/// Every answer's text starts with this marker (a driver checks sampled bodies for it).
pub const MARKER: &str = "hammer-ok";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dialect {
    Openai,
    Responses,
    Anthropic,
    Gemini,
    Cohere,
    Bedrock,
}

impl Dialect {
    pub const ALL: [Dialect; 6] = [
        Dialect::Openai,
        Dialect::Responses,
        Dialect::Anthropic,
        Dialect::Gemini,
        Dialect::Cohere,
        Dialect::Bedrock,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Dialect::Openai => "openai",
            Dialect::Responses => "responses",
            Dialect::Anthropic => "anthropic",
            Dialect::Gemini => "gemini",
            Dialect::Cohere => "cohere",
            Dialect::Bedrock => "bedrock",
        }
    }

    pub fn parse(s: &str) -> Option<Dialect> {
        Dialect::ALL.into_iter().find(|d| d.name() == s)
    }

    /// Which dialect an upstream request path speaks.
    pub fn of_path(path: &str) -> Option<(Dialect, bool)> {
        let p = path.split('?').next().unwrap_or(path);
        if p.ends_with("/chat/completions") {
            Some((Dialect::Openai, false))
        } else if p.ends_with("/responses") {
            Some((Dialect::Responses, false))
        } else if p.ends_with("/messages") {
            Some((Dialect::Anthropic, false))
        } else if p.contains(":streamGenerateContent") {
            Some((Dialect::Gemini, true))
        } else if p.contains(":generateContent") {
            Some((Dialect::Gemini, false))
        } else if p.ends_with("/converse-stream") {
            Some((Dialect::Bedrock, true))
        } else if p.ends_with("/converse") {
            Some((Dialect::Bedrock, false))
        } else if p.ends_with("/v2/chat") {
            Some((Dialect::Cohere, false))
        } else {
            None
        }
    }

    /// The ingress path a client of this dialect calls for `model`.
    pub fn path(self, model: &str, stream: bool) -> String {
        match (self, stream) {
            (Dialect::Openai, _) => "/v1/chat/completions".into(),
            (Dialect::Responses, _) => "/v1/responses".into(),
            (Dialect::Anthropic, _) => "/v1/messages".into(),
            (Dialect::Gemini, false) => format!("/v1beta/models/{model}:generateContent"),
            (Dialect::Gemini, true) => {
                format!("/v1beta/models/{model}:streamGenerateContent?alt=sse")
            }
            (Dialect::Cohere, _) => "/v2/chat".into(),
            (Dialect::Bedrock, false) => format!("/model/{model}/converse"),
            (Dialect::Bedrock, true) => format!("/model/{model}/converse-stream"),
        }
    }

    /// The client auth headers of this dialect.
    pub fn auth_headers(self, key: &str) -> Vec<(String, String)> {
        match self {
            Dialect::Anthropic => vec![
                ("x-api-key".into(), key.into()),
                ("anthropic-version".into(), "2023-06-01".into()),
            ],
            Dialect::Gemini => vec![("x-goog-api-key".into(), key.into())],
            _ => vec![("authorization".into(), format!("Bearer {key}"))],
        }
    }

    /// A client request body: one user message of `text`, optionally streamed, optionally
    /// declaring the `get_weather` tool.
    pub fn request_body(self, model: &str, text: &str, stream: bool, tools: bool) -> String {
        let schema =
            json!({"type":"object","properties":{"city":{"type":"string"}},"required":["city"]});
        let mut v = match self {
            Dialect::Openai => json!({"model": model, "max_tokens": 16,
                "messages": [{"role":"user","content": text}]}),
            Dialect::Responses => json!({"model": model, "input": text}),
            Dialect::Anthropic => json!({"model": model, "max_tokens": 64,
                "messages": [{"role":"user","content": text}]}),
            Dialect::Gemini => json!({"contents":[{"role":"user","parts":[{"text": text}]}]}),
            Dialect::Cohere => json!({"model": model,
                "messages": [{"role":"user","content": text}]}),
            Dialect::Bedrock => json!({"messages":[{"role":"user","content":[{"text": text}]}]}),
        };
        if stream
            && matches!(
                self,
                Dialect::Openai | Dialect::Responses | Dialect::Anthropic | Dialect::Cohere
            )
        {
            v["stream"] = json!(true);
        }
        if tools {
            match self {
                Dialect::Openai => {
                    v["tools"] = json!([{"type":"function","function":{"name":TOOL_NAME,
                        "description":"Weather for a city","parameters":schema}}])
                }
                Dialect::Responses => {
                    v["tools"] = json!([{"type":"function","name":TOOL_NAME,
                        "description":"Weather for a city","parameters":schema}])
                }
                Dialect::Anthropic => {
                    v["tools"] = json!([{"name":TOOL_NAME,"description":"Weather for a city",
                        "input_schema":schema}])
                }
                Dialect::Gemini => {
                    v["tools"] = json!([{"functionDeclarations":[{"name":TOOL_NAME,
                        "description":"Weather for a city","parameters":schema}]}])
                }
                Dialect::Cohere => {
                    v["tools"] = json!([{"type":"function","function":{"name":TOOL_NAME,
                        "description":"Weather for a city","parameters":schema}}])
                }
                Dialect::Bedrock => {
                    v["toolConfig"] = json!({"tools":[{"toolSpec":{"name":TOOL_NAME,
                        "description":"Weather for a city","inputSchema":{"json":schema}}}]})
                }
            }
        }
        v.to_string()
    }

    /// What every successful answer of this dialect (as the CLIENT sees it) contains.
    pub fn answer_marker(self, tools: bool) -> &'static str {
        if tools {
            TOOL_NAME
        } else {
            MARKER
        }
    }
}

fn j(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("json")
}

fn tool_args() -> Value {
    json!({"city": "paris"})
}

fn tool_args_json() -> String {
    tool_args().to_string()
}

fn anthropic_usage() -> Value {
    json!({"input_tokens": IN_TOK, "output_tokens": OUT_TOK, "cache_creation_input_tokens": null,
           "cache_read_input_tokens": null})
}

fn whole(d: Dialect, text: &str) -> Value {
    match d {
        Dialect::Openai => json!({"id": "chatcmpl-hammer", "object": "chat.completion",
            "created": 0, "model": MODEL,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text,
                "refusal": null}, "finish_reason": "stop", "logprobs": null}],
            "usage": {"prompt_tokens": IN_TOK, "completion_tokens": OUT_TOK,
                "total_tokens": IN_TOK + OUT_TOK}}),
        Dialect::Responses => json!({"id": "resp_hammer", "object": "response",
            "status": "completed", "model": MODEL, "created_at": 0, "error": null,
            "incomplete_details": null, "instructions": null, "metadata": null,
            "parallel_tool_calls": true, "temperature": null, "top_p": null,
            "tool_choice": "auto", "tools": [],
            "output": [{"type": "message", "id": "msg_hammer", "role": "assistant",
                "status": "completed", "content": [{"type": "output_text", "text": text,
                "annotations": [], "logprobs": []}]}],
            "usage": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK,
                "total_tokens": IN_TOK + OUT_TOK,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens_details": {"reasoning_tokens": 0}}}),
        Dialect::Anthropic => json!({"id": "msg_hammer", "type": "message",
            "role": "assistant", "model": MODEL,
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn", "stop_sequence": null, "usage": anthropic_usage()}),
        Dialect::Gemini => json!({"candidates": [{"content": {"role": "model",
            "parts": [{"text": text}]}, "finishReason": "STOP", "index": 0}],
            "usageMetadata": {"promptTokenCount": IN_TOK, "candidatesTokenCount": OUT_TOK,
                "totalTokenCount": IN_TOK + OUT_TOK}, "modelVersion": MODEL}),
        Dialect::Cohere => json!({"id": "cohere-hammer", "finish_reason": "COMPLETE",
            "message": {"role": "assistant", "content": [{"type": "text", "text": text}]},
            "usage": {"billed_units": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK},
                "tokens": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK}}}),
        Dialect::Bedrock => json!({"output": {"message": {"role": "assistant",
            "content": [{"text": text}]}}, "stopReason": "end_turn",
            "usage": {"inputTokens": IN_TOK, "outputTokens": OUT_TOK,
                "totalTokens": IN_TOK + OUT_TOK}, "metrics": {"latencyMs": 0}}),
    }
}

fn tool_call(d: Dialect) -> Value {
    let mut v = whole(d, MARKER);
    match d {
        Dialect::Openai => {
            v["choices"][0]["message"] = json!({"role": "assistant", "content": null,
                "refusal": null, "tool_calls": [{"id": TOOL_ID_OPENAI, "type": "function",
                "function": {"name": TOOL_NAME, "arguments": tool_args_json()}}]});
            v["choices"][0]["finish_reason"] = json!("tool_calls");
        }
        Dialect::Responses => {
            v["output"] = json!([{"type": "function_call", "id": "fc_hammer",
                "call_id": TOOL_ID_OPENAI, "name": TOOL_NAME, "arguments": tool_args_json(),
                "status": "completed"}]);
        }
        Dialect::Anthropic => {
            v["content"] = json!([{"type": "tool_use", "id": TOOL_ID_ANTHROPIC,
                "name": TOOL_NAME, "input": tool_args()}]);
            v["stop_reason"] = json!("tool_use");
        }
        Dialect::Gemini => {
            v["candidates"][0]["content"]["parts"] =
                json!([{"functionCall": {"name": TOOL_NAME, "args": tool_args()}}]);
        }
        Dialect::Cohere => {
            v["message"] = json!({"role": "assistant", "tool_plan": "Look up the weather.",
                "content": [], "tool_calls": [{"id": TOOL_ID_OPENAI, "type": "function",
                "function": {"name": TOOL_NAME, "arguments": tool_args_json()}}]});
            v["finish_reason"] = json!("TOOL_CALL");
        }
        Dialect::Bedrock => {
            v["output"]["message"]["content"] = json!([{"toolUse": {
                "toolUseId": TOOL_ID_BEDROCK, "name": TOOL_NAME, "input": tool_args()}}]);
            v["stopReason"] = json!("tool_use");
        }
    }
    v
}

fn sse_data(v: &Value) -> Bytes {
    let mut out = b"data: ".to_vec();
    out.extend_from_slice(&j(v));
    out.extend_from_slice(b"\n\n");
    Bytes::from(out)
}

fn sse_event(t: &str, v: &Value) -> Bytes {
    let mut out = format!("event: {t}\ndata: ").into_bytes();
    out.extend_from_slice(&j(v));
    out.extend_from_slice(b"\n\n");
    Bytes::from(out)
}

fn es_header(name: &str, value: &str) -> Vec<u8> {
    let v = value.as_bytes();
    let mut out = vec![name.len() as u8];
    out.extend_from_slice(name.as_bytes());
    out.push(0x07);
    out.extend_from_slice(&(v.len() as u16).to_be_bytes());
    out.extend_from_slice(v);
    out
}

/// One AWS event-stream (`application/vnd.amazon.eventstream`) event frame.
fn es_event(event_type: &str, payload: &Value) -> Bytes {
    let payload = j(payload);
    let mut headers = es_header(":event-type", event_type);
    headers.extend_from_slice(&es_header(":content-type", "application/json"));
    headers.extend_from_slice(&es_header(":message-type", "event"));
    let total = 12 + headers.len() as u32 + payload.len() as u32 + 4;
    let mut frame = Vec::with_capacity(total as usize);
    frame.extend_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&(headers.len() as u32).to_be_bytes());
    let prelude_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&prelude_crc.to_be_bytes());
    frame.extend_from_slice(&headers);
    frame.extend_from_slice(&payload);
    let crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&crc.to_be_bytes());
    Bytes::from(frame)
}

/// The streamed answer of `d`: frames of `chunks` content deltas whose texts concatenate to
/// `text`.
fn stream(d: Dialect, text: &str, chunks: usize) -> Vec<Bytes> {
    let chunks = chunks.max(1);
    let pieces: Vec<String> = split(text, chunks);
    let mut f = Vec::new();
    match d {
        Dialect::Openai => {
            for (i, p) in pieces.iter().enumerate() {
                let delta = if i == 0 {
                    json!({"role": "assistant", "content": p})
                } else {
                    json!({"content": p})
                };
                f.push(sse_data(&json!({"id": "chatcmpl-hammer",
                    "object": "chat.completion.chunk", "created": 0, "model": MODEL,
                    "choices": [{"index": 0, "delta": delta, "finish_reason": null}]})));
            }
            f.push(sse_data(
                &json!({"id": "chatcmpl-hammer", "object": "chat.completion.chunk",
                "created": 0, "model": MODEL,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": IN_TOK, "completion_tokens": OUT_TOK,
                    "total_tokens": IN_TOK + OUT_TOK}}),
            ));
            f.push(Bytes::from_static(b"data: [DONE]\n\n"));
        }
        Dialect::Anthropic => {
            let mut usage = anthropic_usage();
            usage["output_tokens"] = json!(0);
            f.push(sse_event(
                "message_start",
                &json!({"type": "message_start",
                "message": {"id": "msg_hammer", "type": "message", "role": "assistant",
                "model": MODEL, "content": [], "stop_reason": null, "stop_sequence": null,
                "usage": usage}}),
            ));
            f.push(sse_event(
                "content_block_start",
                &json!({"type": "content_block_start",
                "index": 0, "content_block": {"type": "text", "text": ""}}),
            ));
            for p in &pieces {
                f.push(sse_event(
                    "content_block_delta",
                    &json!({"type": "content_block_delta",
                    "index": 0, "delta": {"type": "text_delta", "text": p}}),
                ));
            }
            f.push(sse_event(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ));
            f.push(sse_event(
                "message_delta",
                &json!({"type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                "usage": {"output_tokens": OUT_TOK}}),
            ));
            f.push(sse_event("message_stop", &json!({"type": "message_stop"})));
        }
        Dialect::Responses => {
            let base = json!({"id": "resp_hammer", "object": "response", "model": MODEL,
                "created_at": 0, "error": null, "incomplete_details": null,
                "instructions": null, "metadata": null, "parallel_tool_calls": true,
                "temperature": null, "tool_choice": "auto", "tools": [], "top_p": null});
            let mut created = base.clone();
            created["status"] = json!("in_progress");
            created["output"] = json!([]);
            f.push(sse_event(
                "response.created",
                &json!({"type": "response.created",
                "sequence_number": 0, "response": created}),
            ));
            for (i, p) in pieces.iter().enumerate() {
                f.push(sse_event(
                    "response.output_text.delta",
                    &json!({
                    "type": "response.output_text.delta", "sequence_number": i + 1,
                    "item_id": "msg_hammer", "output_index": 0, "content_index": 0,
                    "delta": p}),
                ));
            }
            let mut done = base;
            done["status"] = json!("completed");
            done["output"] = json!([{"type": "message", "id": "msg_hammer",
                "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": text, "annotations": [],
                    "logprobs": []}]}]);
            done["usage"] = json!({"input_tokens": IN_TOK, "output_tokens": OUT_TOK,
                "total_tokens": IN_TOK + OUT_TOK});
            f.push(sse_event(
                "response.completed",
                &json!({"type": "response.completed",
                "sequence_number": pieces.len() + 1, "response": done}),
            ));
        }
        Dialect::Gemini => {
            let n = pieces.len();
            for (i, p) in pieces.iter().enumerate() {
                let mut c = json!({"candidates": [{"content": {"role": "model",
                    "parts": [{"text": p}]}, "index": 0}], "modelVersion": MODEL});
                if i + 1 == n {
                    c["candidates"][0]["finishReason"] = json!("STOP");
                    c["usageMetadata"] = json!({"promptTokenCount": IN_TOK,
                        "candidatesTokenCount": OUT_TOK, "totalTokenCount": IN_TOK + OUT_TOK});
                }
                f.push(sse_data(&c));
            }
        }
        Dialect::Cohere => {
            f.push(sse_data(
                &json!({"type": "message-start", "id": "cohere-hammer",
                "delta": {"message": {"role": "assistant", "content": []}}}),
            ));
            for p in &pieces {
                f.push(sse_data(&json!({"type": "content-delta", "index": 0,
                    "delta": {"message": {"content": {"type": "text", "text": p}}}})));
            }
            f.push(sse_data(
                &json!({"type": "message-end", "delta": {"finish_reason": "COMPLETE",
                "usage": {"tokens": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK}}}}),
            ));
        }
        Dialect::Bedrock => {
            f.push(es_event("messageStart", &json!({"role": "assistant"})));
            for p in &pieces {
                f.push(es_event(
                    "contentBlockDelta",
                    &json!({"contentBlockIndex": 0, "delta": {"text": p}}),
                ));
            }
            f.push(es_event(
                "contentBlockStop",
                &json!({"contentBlockIndex": 0}),
            ));
            f.push(es_event("messageStop", &json!({"stopReason": "end_turn"})));
            f.push(es_event(
                "metadata",
                &json!({"usage": {"inputTokens": IN_TOK,
                "outputTokens": OUT_TOK, "totalTokens": IN_TOK + OUT_TOK},
                "metrics": {"latencyMs": 0}}),
            ));
        }
    }
    f
}

/// Split `text` into `n` non-empty pieces on char boundaries (fewer when it is shorter).
fn split(text: &str, n: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let n = n.min(chars.len()).max(1);
    let per = chars.len().div_ceil(n);
    chars.chunks(per).map(|c| c.iter().collect()).collect()
}

/// Every prepared answer of one dialect.
pub struct DialectBodies {
    pub whole: Bytes,
    pub tool: Bytes,
    pub stream: Vec<Bytes>,
    pub stream_ctype: &'static str,
}

/// Every dialect's prepared answers.
pub struct Bodies {
    by: Vec<DialectBodies>,
}

impl Bodies {
    /// `pad` extra answer bytes, `chunks` content deltas per stream.
    pub fn build(pad: usize, chunks: usize) -> Self {
        let mut text = MARKER.to_string();
        text.extend(std::iter::repeat_n('x', pad));
        let by = Dialect::ALL
            .iter()
            .map(|&d| DialectBodies {
                whole: Bytes::from(j(&whole(d, &text))),
                tool: Bytes::from(j(&tool_call(d))),
                stream: stream(d, &text, chunks),
                stream_ctype: if d == Dialect::Bedrock {
                    "application/vnd.amazon.eventstream"
                } else {
                    "text/event-stream"
                },
            })
            .collect();
        Self { by }
    }

    pub fn of(&self, d: Dialect) -> &DialectBodies {
        &self.by[Dialect::ALL
            .iter()
            .position(|x| *x == d)
            .expect("every dialect built")]
    }
}

/// Whether a request body asks for a stream (`"stream":true`, with or without a space).
pub fn wants_stream(body: &[u8]) -> bool {
    memfind(body, b"\"stream\":true") || memfind(body, b"\"stream\": true")
}

/// Whether a request body declares tools.
pub fn wants_tools(body: &[u8]) -> bool {
    memfind(body, b"\"tools\"") || memfind(body, b"\"toolConfig\"")
}

pub fn memfind(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_dialect_is_parseable_json_and_carries_the_marker() {
        let b = Bodies::build(100, 4);
        for d in Dialect::ALL {
            let x = b.of(d);
            let v: Value = serde_json::from_slice(&x.whole).unwrap();
            assert!(v.to_string().contains(MARKER), "{d:?}");
            assert!(
                String::from_utf8_lossy(&x.tool).contains(TOOL_NAME),
                "{d:?}"
            );
            assert!(x.stream.len() >= 4, "{d:?} has its deltas");
        }
    }

    #[test]
    fn a_stream_concatenates_to_the_text() {
        let pieces = split("hammer-okxxxx", 4);
        assert_eq!(pieces.concat(), "hammer-okxxxx");
        assert_eq!(pieces.len(), 4);
    }

    #[test]
    fn path_dialects_round_trip() {
        for d in Dialect::ALL {
            for s in [false, true] {
                let (got, _) = Dialect::of_path(&d.path("m", s)).unwrap();
                assert_eq!(got, d);
            }
        }
        assert!(wants_stream(br#"{"stream": true}"#));
        assert!(!wants_stream(br#"{"stream":false}"#));
    }

    #[test]
    fn eventstream_frames_carry_valid_lengths() {
        let f = es_event("messageStop", &json!({"stopReason":"end_turn"}));
        let total = u32::from_be_bytes(f[0..4].try_into().unwrap()) as usize;
        assert_eq!(total, f.len());
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HARNESS'S OWN READING OF THE WIRES: the two duplex dialects read, written and governed by
//! this harness from their PUBLISHED formats, never by the plane's code (the plane's only public
//! item is its door, `BUSBAR-1.6.0.md` l.3567 and the `door-only` gate, l.3875).
//!
//! * OpenAI Realtime: one JSON event per WebSocket message, tagged by `type`
//!   (<https://platform.openai.com/docs/api-reference/realtime-client-events> and
//!   `realtime-server-events`).
//! * Gemini Live (`BidiGenerateContent`): one JSON message per WebSocket message whose one
//!   top-level key names its kind (<https://ai.google.dev/api/live>).
//!
//! What the harness reads a frame into is a dialect-neutral concept ([`Norm`]); what it writes is
//! the other dialect's published frame for a concept (the cross-dialect map's bridge,
//! `qa/evidence/voice-cross-dialect-map.json`); what it governs is the session lock the spec states
//! for a caller frame (Part 2 #45, the browser trust boundary; Law 5, a same-dialect relay with
//! governed splices). Every expectation a leg holds the door to is computed here, from the wire.

use serde_json::{json, Map, Value};

use busbar_contract::media::{base64_decode, base64_encode};

use crate::codec_legs::{Dialect, Norm};

// ── the published protocol facts the harness reads with ─────────────────────────────────────────

/// The socket an OpenAI Realtime session dials, under the provider's base URL: OpenAI's published
/// realtime endpoint, `wss://api.openai.com/v1/realtime`.
pub const REALTIME_SOCKET_PATH: &str = "/v1/realtime";

/// The socket a Gemini Live session dials, under the provider's base URL: Google's published Live
/// API endpoint,
/// `wss://generativelanguage.googleapis.com/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent`.
pub const GEMINI_SOCKET_PATH: &str =
    "/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent";

/// OpenAI Realtime's far-end credential style: `Authorization: Bearer <key>` (OpenAI API
/// reference, "Authentication").
pub const REALTIME_STYLE: &str = "bearer";

/// Gemini Live's far-end credential style: the `x-goog-api-key` header (Gemini API reference,
/// "API keys").
pub const LIVE_STYLE: &str = "x-goog-api-key";

/// The error code OpenAI Realtime closes a session that reached its maximum duration with (its
/// published `error` server event, `code: "session_expired"`).
pub const SESSION_EXPIRED_CODE: &str = "session_expired";

/// The WebSocket transport, by the name busbar's framers claim it under (`BUSBAR-1.6.0.md` l.583:
/// the framers are `http` and `ws`).
pub const WS_TRANSPORT: &str = "ws";

/// The request/response transport, by the same line's name (`http`).
pub const HTTP_TRANSPORT: &str = "http";

/// The inbound auth scheme Twilio signs its WebSocket upgrade under: `busbar-auth-webhook-signature`,
/// scheme `webhook-signature`, variant Twilio (`BUSBAR-1.6.0.md` l.849).
pub const SIGNATURE_AUTH: &str = "webhook-signature";

/// The dialect registry key of OpenAI Realtime, as the legs hold the door's Statement to name it.
pub const OPENAI_REALTIME: &str = "openai_realtime";

/// The dialect registry key of Gemini Live, as the legs hold the door's Statement to name it.
pub const GEMINI_LIVE: &str = "gemini_live";

/// The dialect name of Twilio Media Streams, as the legs hold the door's Statement to name it.
pub const TWILIO_MEDIA_STREAMS: &str = "twilio-media-streams";

/// The mime of 24 kHz signed-16 PCM in a Gemini Live blob: the rate OpenAI Realtime's `pcm16` is
/// (OpenAI: "pcm16, 24kHz, mono, little-endian"; Gemini: `audio/pcm;rate=24000`).
const PCM_24K_MIME: &str = "audio/pcm;rate=24000";

/// What a caller frame in OpenAI Realtime may never author (#45: the caller "never authors tools or
/// instructions"; a stored `prompt` is instructions by reference).
const REALTIME_CUT: &[&str] = &["instructions", "tools", "prompt"];

/// What a caller frame in Gemini Live may never author (#45): its `setup`'s system instruction and
/// tools.
const LIVE_CUT: &[&str] = &["systemInstruction", "tools"];

/// The roles an OpenAI Realtime item instructs the model in (`system`, `developer`): never the
/// caller's to author (#45).
const INSTRUCTING_ROLES: &[&str] = &["system", "developer"];

/// A JSON `null` to read an absent member as.
static NULL: Value = Value::Null;

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn unb64(text: &str) -> Option<Vec<u8>> {
    base64_decode(text).map(|b| b.to_vec())
}

/// A JSON text parsed, else JSON `null` (a tool's arguments or output that is not JSON yet).
fn parsed(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or(Value::Null)
}

/// The bytes of a JSON value.
pub fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

// ── the session config, both dialects ───────────────────────────────────────────────────────────

/// The survivable session configuration a configuring frame states.
#[derive(Clone, Debug, Default, PartialEq)]
struct Cfg {
    instructions: Option<String>,
    voice: Option<String>,
    tools: Vec<Value>,
    /// A stated output cap; OpenAI's `"inf"` and an absent cap are both no cap.
    max: Option<u64>,
    modalities: Vec<String>,
}

impl Cfg {
    fn norms(&self) -> Vec<Norm> {
        vec![
            Norm::Config(format!(
                "{:?}|{:?}|{}|{:?}",
                self.instructions,
                self.voice,
                self.tools.len(),
                self.max
            )),
            Norm::ConfigModalities(self.modalities.clone()),
        ]
    }

    /// OpenAI Realtime's `session` object: the legacy top-level members and the GA nested ones
    /// (`audio.output.voice`, `output_modalities`, `max_output_tokens`).
    fn of_realtime(session: &Value) -> Cfg {
        let voice = session
            .get("voice")
            .and_then(Value::as_str)
            .or_else(|| {
                session
                    .pointer("/audio/output/voice")
                    .and_then(Value::as_str)
            })
            .map(str::to_string);
        let max = session
            .get("max_response_output_tokens")
            .or_else(|| session.get("max_output_tokens"))
            .and_then(Value::as_u64);
        let modalities = session
            .get("modalities")
            .or_else(|| session.get("output_modalities"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_ascii_lowercase)
                    .collect()
            })
            .unwrap_or_default();
        Cfg {
            instructions: session
                .get("instructions")
                .and_then(Value::as_str)
                .map(str::to_string),
            voice,
            tools: session
                .get("tools")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            max,
            modalities,
        }
    }

    /// Gemini Live's `setup` object.
    fn of_setup(setup: &Value) -> Cfg {
        let instructions = setup
            .pointer("/systemInstruction/parts")
            .and_then(Value::as_array)
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect::<String>()
            })
            .filter(|t| !t.is_empty());
        let gc = setup.get("generationConfig").unwrap_or(&NULL);
        Cfg {
            instructions,
            voice: gc
                .pointer("/speechConfig/voiceConfig/prebuiltVoiceConfig/voiceName")
                .and_then(Value::as_str)
                .map(str::to_string),
            tools: setup
                .get("tools")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            max: gc.get("maxOutputTokens").and_then(Value::as_u64),
            modalities: gc
                .get("responseModalities")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_ascii_lowercase)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    fn to_realtime(&self) -> Value {
        let mut session = Map::new();
        if !self.modalities.is_empty() {
            session.insert("modalities".into(), json!(self.modalities));
        }
        if let Some(i) = &self.instructions {
            session.insert("instructions".into(), json!(i));
        }
        if let Some(v) = &self.voice {
            session.insert("voice".into(), json!(v));
        }
        if !self.tools.is_empty() {
            session.insert("tools".into(), Value::Array(self.tools.clone()));
        }
        if let Some(n) = self.max {
            session.insert("max_response_output_tokens".into(), json!(n));
        }
        json!({"type": "session.update", "session": Value::Object(session)})
    }

    fn to_setup(&self) -> Map<String, Value> {
        let mut setup = Map::new();
        let mut gc = Map::new();
        if !self.modalities.is_empty() {
            let upper: Vec<String> = self
                .modalities
                .iter()
                .map(|m| m.to_ascii_uppercase())
                .collect();
            gc.insert("responseModalities".into(), json!(upper));
        }
        if let Some(v) = &self.voice {
            gc.insert(
                "speechConfig".into(),
                json!({"voiceConfig": {"prebuiltVoiceConfig": {"voiceName": v}}}),
            );
        }
        if let Some(n) = self.max {
            gc.insert("maxOutputTokens".into(), json!(n));
        }
        if !gc.is_empty() {
            setup.insert("generationConfig".into(), Value::Object(gc));
        }
        if let Some(i) = &self.instructions {
            setup.insert("systemInstruction".into(), json!({"parts": [{"text": i}]}));
        }
        if !self.tools.is_empty() {
            setup.insert("tools".into(), Value::Array(self.tools.clone()));
        }
        setup
    }
}

// ── usage ───────────────────────────────────────────────────────────────────────────────────────

/// A billed count: absent or `null` is none; an integral number is the count.
fn count(v: Option<&Value>) -> u64 {
    match v {
        Some(n) => n
            .as_u64()
            .or_else(|| {
                n.as_f64()
                    .filter(|f| *f >= 0.0 && f.fract() == 0.0)
                    .map(|f| f as u64)
            })
            .unwrap_or(0),
        None => 0,
    }
}

/// A per-modality breakdown refines the stated total and is never its sole source: when the
/// breakdown names nothing, the stated total is the turn's count, read as text (`BUSBAR-1.6.0.md`
/// #42: a count the provider reported is never metered at zero).
fn split(audio: u64, text: u64, total: u64) -> (u64, u64) {
    if audio.saturating_add(text) == 0 {
        (0, total)
    } else {
        (audio, text)
    }
}

/// OpenAI Realtime's `response.done.response.usage`.
fn realtime_usage(u: &Value) -> Norm {
    let (ai, ti) = split(
        count(u.pointer("/input_token_details/audio_tokens")),
        count(u.pointer("/input_token_details/text_tokens")),
        count(u.get("input_tokens")),
    );
    let (ao, to) = split(
        count(u.pointer("/output_token_details/audio_tokens")),
        count(u.pointer("/output_token_details/text_tokens")),
        count(u.get("output_tokens")),
    );
    Norm::Usage(ai, ao, ti, to)
}

/// One modality's count in a Gemini `*TokensDetails` array (`[{modality, tokenCount}]`).
fn modality(details: Option<&Value>, which: &str) -> u64 {
    count(
        details
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|d| {
                d.get("modality")
                    .and_then(Value::as_str)
                    .is_some_and(|m| m.eq_ignore_ascii_case(which))
            })
            .and_then(|d| d.get("tokenCount")),
    )
}

/// Gemini Live's `usageMetadata`.
fn live_usage(u: &Value) -> Norm {
    let (pd, rd) = (u.get("promptTokensDetails"), u.get("responseTokensDetails"));
    let (ai, ti) = split(
        modality(pd, "AUDIO"),
        modality(pd, "TEXT"),
        count(u.get("promptTokenCount")),
    );
    let (ao, to) = split(
        modality(rd, "AUDIO"),
        modality(rd, "TEXT"),
        count(u.get("responseTokenCount")),
    );
    Norm::Usage(ai, ao, ti, to)
}

// ── the reader ──────────────────────────────────────────────────────────────────────────────────

/// An OpenAI Realtime conversation item, neutral: a message is its role and its text parts; any
/// other item is itself.
fn realtime_item(item: &Value) -> Norm {
    if s(item, "type") != "message" {
        return Norm::Item(item.clone());
    }
    let parts: Vec<String> = item
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|c| c.get("text").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    Norm::Item(json!({"role": s(item, "role"), "parts": parts}))
}

/// One Gemini Live content turn, neutral: its role (`model` is the assistant) and its text parts.
fn live_turn(turn: &Value) -> Norm {
    let role = match s(turn, "role") {
        "model" => "assistant",
        other => other,
    };
    let parts: Vec<String> = turn
        .get("parts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|p| p.get("text").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    Norm::Item(json!({"role": role, "parts": parts}))
}

/// A caller frame's concepts, by `dialect`'s published client messages. A frame that is not JSON,
/// or names no client message, reads as nothing.
pub fn read_up(dialect: Dialect, frame: &[u8]) -> Vec<Norm> {
    let Ok(v) = serde_json::from_slice::<Value>(frame) else {
        return Vec::new();
    };
    match dialect {
        Dialect::OpenAi => match s(&v, "type") {
            "session.update" => Cfg::of_realtime(v.get("session").unwrap_or(&NULL)).norms(),
            "input_audio_buffer.append" => unb64(s(&v, "audio"))
                .map(Norm::AudioUp)
                .into_iter()
                .collect(),
            "input_audio_buffer.commit" => vec![Norm::Commit],
            "input_audio_buffer.clear" => vec![Norm::Clear],
            "conversation.item.create" => {
                let item = v.get("item").unwrap_or(&NULL);
                if s(item, "type") == "function_call_output" {
                    vec![Norm::ToolResult(
                        s(item, "call_id").to_string(),
                        parsed(s(item, "output")),
                    )]
                } else {
                    vec![realtime_item(item)]
                }
            }
            "conversation.item.truncate" => vec![Norm::Truncate(
                v.get("audio_end_ms").and_then(Value::as_u64).unwrap_or(0),
            )],
            "conversation.item.delete" => vec![Norm::ItemDelete],
            "response.create" => vec![Norm::ResponseCreate],
            "response.cancel" => vec![Norm::ResponseCancel],
            _ => Vec::new(),
        },
        Dialect::Gemini => {
            if let Some(setup) = v.get("setup") {
                return Cfg::of_setup(setup).norms();
            }
            if let Some(cc) = v.get("clientContent") {
                return cc
                    .get("turns")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(live_turn)
                    .collect();
            }
            if let Some(ri) = v.get("realtimeInput") {
                let mut out = Vec::new();
                let mut blob = |b: &Value| {
                    if s(b, "mimeType")
                        .to_ascii_lowercase()
                        .starts_with("audio/pcm")
                    {
                        out.extend(unb64(s(b, "data")).map(Norm::AudioUp));
                    }
                };
                if let Some(audio) = ri.get("audio") {
                    blob(audio);
                } else {
                    ri.get("mediaChunks")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .for_each(&mut blob);
                }
                if ri.get("audioStreamEnd").is_some() {
                    out.push(Norm::Commit);
                }
                return out;
            }
            if let Some(tr) = v.get("toolResponse") {
                return tr
                    .get("functionResponses")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|r| {
                        Norm::ToolResult(
                            s(r, "id").to_string(),
                            r.get("response").cloned().unwrap_or(Value::Null),
                        )
                    })
                    .collect();
            }
            Vec::new()
        }
    }
}

/// A far-end frame's concepts, by `dialect`'s published server messages. A frame that is not JSON,
/// or names no concept both dialects share (Gemini's transcriptions, `goAway`,
/// `toolCallCancellation`: the map's documented drops), reads as nothing.
pub fn read_down(dialect: Dialect, frame: &[u8]) -> Vec<Norm> {
    let Ok(v) = serde_json::from_slice::<Value>(frame) else {
        return Vec::new();
    };
    match dialect {
        Dialect::OpenAi => match s(&v, "type") {
            "session.created" => vec![Norm::Connect],
            "input_audio_buffer.speech_started" => vec![Norm::SpeechStart],
            "input_audio_buffer.speech_stopped" => vec![Norm::SpeechStop],
            "response.output_audio.delta" | "response.audio.delta" => unb64(s(&v, "delta"))
                .map(Norm::AudioDown)
                .into_iter()
                .collect(),
            "response.output_audio.done" | "response.audio.done" => vec![Norm::AudioDone],
            "response.output_item.added" => {
                let item = v.get("item").unwrap_or(&NULL);
                if s(item, "type") == "function_call" {
                    vec![Norm::ToolOpen(
                        s(item, "call_id").to_string(),
                        s(item, "name").to_string(),
                    )]
                } else {
                    Vec::new()
                }
            }
            "response.function_call_arguments.delta" => vec![Norm::ToolArgs(
                s(&v, "call_id").to_string(),
                parsed(s(&v, "delta")),
            )],
            "response.function_call_arguments.done" => {
                let id = s(&v, "call_id").to_string();
                let mut out = Vec::new();
                if !s(&v, "arguments").is_empty() {
                    out.push(Norm::ToolArgs(id.clone(), parsed(s(&v, "arguments"))));
                }
                out.push(Norm::ToolClose(id));
                out
            }
            "response.done" => v
                .pointer("/response/usage")
                .map(realtime_usage)
                .into_iter()
                .collect(),
            "rate_limits.updated" => vec![Norm::RateLimits],
            "error" => {
                let e = v.get("error").unwrap_or(&NULL);
                vec![Norm::Error(
                    s(e, "code").to_string(),
                    s(e, "message").to_string(),
                )]
            }
            _ => Vec::new(),
        },
        Dialect::Gemini => {
            if v.get("setupComplete").is_some() {
                return vec![Norm::Connect];
            }
            let mut out = Vec::new();
            if let Some(sc) = v.get("serverContent") {
                for p in sc
                    .pointer("/modelTurn/parts")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(inline) = p.get("inlineData") {
                        if s(inline, "mimeType")
                            .to_ascii_lowercase()
                            .starts_with("audio/pcm")
                        {
                            out.extend(unb64(s(inline, "data")).map(Norm::AudioDown));
                        }
                    }
                }
                if sc.get("interrupted").and_then(Value::as_bool) == Some(true) {
                    out.push(Norm::SpeechStart);
                }
                if sc.get("turnComplete").and_then(Value::as_bool) == Some(true) {
                    out.push(Norm::AudioDone);
                }
            } else if let Some(tc) = v.get("toolCall") {
                for c in tc
                    .get("functionCalls")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let id = s(c, "id").to_string();
                    out.push(Norm::ToolOpen(id.clone(), s(c, "name").to_string()));
                    out.push(Norm::ToolArgs(
                        id.clone(),
                        c.get("args").cloned().unwrap_or(Value::Null),
                    ));
                    out.push(Norm::ToolClose(id));
                }
            }
            // `usageMetadata` may ride on any server message.
            if let Some(um) = v.get("usageMetadata") {
                out.push(live_usage(um));
            }
            out
        }
    }
}

// ── the bridge (the cross-dialect map's writer) ─────────────────────────────────────────────────

/// A tool call being bridged toward Gemini Live, which delivers a call whole (`toolCall`) where
/// OpenAI Realtime streams it.
#[derive(Default)]
pub struct Bridge {
    /// Per call id: its name and its arguments so far.
    calls: Vec<(String, String, Value)>,
}

impl Bridge {
    fn call(&mut self, id: &str) -> &mut (String, String, Value) {
        if let Some(i) = self.calls.iter().position(|c| c.0 == id) {
            return &mut self.calls[i];
        }
        self.calls
            .push((id.to_string(), String::new(), Value::Null));
        let last = self.calls.len() - 1;
        &mut self.calls[last]
    }

    /// The caller concept `n` as `to`'s published client frame; `None` where `to` has no verb for
    /// it (the map's documented drops toward Gemini: clear, truncate, cancel, per-response
    /// overrides, item delete).
    pub fn up(&mut self, to: Dialect, n: &Norm) -> Option<Value> {
        match (to, n) {
            (Dialect::OpenAi, Norm::AudioUp(b)) => {
                Some(json!({"type": "input_audio_buffer.append", "audio": base64_encode(b)}))
            }
            (Dialect::Gemini, Norm::AudioUp(b)) => Some(json!({"realtimeInput": {"audio": {
                // The uplink bridges at its true rate: the resample to Gemini's 16 kHz input is
                // not performed (the map's `openai_uplink_rate` row).
                "mimeType": PCM_24K_MIME, "data": base64_encode(b)}}})),
            (Dialect::OpenAi, Norm::Commit) => Some(json!({"type": "input_audio_buffer.commit"})),
            (Dialect::Gemini, Norm::Commit) => {
                Some(json!({"realtimeInput": {"audioStreamEnd": true}}))
            }
            (Dialect::OpenAi, Norm::Clear) => Some(json!({"type": "input_audio_buffer.clear"})),
            (Dialect::OpenAi, Norm::Truncate(ms)) => Some(json!({
                "type": "conversation.item.truncate", "content_index": 0, "audio_end_ms": ms})),
            (Dialect::OpenAi, Norm::ResponseCreate) => Some(json!({"type": "response.create"})),
            (Dialect::OpenAi, Norm::ResponseCancel) => Some(json!({"type": "response.cancel"})),
            (Dialect::OpenAi, Norm::ItemDelete) => {
                Some(json!({"type": "conversation.item.delete"}))
            }
            (Dialect::OpenAi, Norm::Item(item)) => {
                let content: Vec<Value> = item["parts"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|t| json!({"type": "input_text", "text": t}))
                    .collect();
                Some(json!({"type": "conversation.item.create", "item": {
                    "type": "message", "role": item["role"], "content": content}}))
            }
            (Dialect::Gemini, Norm::Item(item)) => {
                let role = match item["role"].as_str() {
                    Some("assistant") => "model",
                    Some(r) => r,
                    None => "user",
                };
                let parts: Vec<Value> = item["parts"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|t| json!({"text": t}))
                    .collect();
                Some(json!({"clientContent": {
                    "turns": [{"role": role, "parts": parts}], "turnComplete": true}}))
            }
            (Dialect::OpenAi, Norm::ToolResult(id, out)) => Some(json!({
                "type": "conversation.item.create",
                "item": {"type": "function_call_output", "call_id": id,
                         "output": serde_json::to_string(out).unwrap_or_default()}})),
            (Dialect::Gemini, Norm::ToolResult(id, out)) => {
                let mut r = Map::new();
                r.insert("id".into(), json!(id));
                let name = self.call(id).1.clone();
                if !name.is_empty() {
                    r.insert("name".into(), json!(name));
                }
                r.insert("response".into(), out.clone());
                Some(json!({"toolResponse": {"functionResponses": [Value::Object(r)]}}))
            }
            _ => None,
        }
    }

    /// The far-end concept `n` as `to`'s published server frame; `None` where `to` has no message
    /// for it on its own (a streamed argument fragment held for the whole call Gemini delivers,
    /// OpenAI's speech-stopped and structured error, which Gemini does not frame).
    pub fn down(&mut self, to: Dialect, n: &Norm) -> Option<Value> {
        match (to, n) {
            (Dialect::OpenAi, Norm::Connect) => {
                Some(json!({"type": "session.created", "session": {}}))
            }
            (Dialect::Gemini, Norm::Connect) => Some(json!({"setupComplete": {}})),
            (Dialect::OpenAi, Norm::AudioDown(b)) => {
                Some(json!({"type": "response.output_audio.delta", "delta": base64_encode(b)}))
            }
            (Dialect::Gemini, Norm::AudioDown(b)) => Some(json!({"serverContent": {"modelTurn": {
                "role": "model",
                "parts": [{"inlineData": {"mimeType": PCM_24K_MIME, "data": base64_encode(b)}}]}}})),
            (Dialect::OpenAi, Norm::AudioDone) => {
                Some(json!({"type": "response.output_audio.done"}))
            }
            (Dialect::Gemini, Norm::AudioDone) => {
                Some(json!({"serverContent": {"turnComplete": true}}))
            }
            (Dialect::OpenAi, Norm::SpeechStart) => {
                Some(json!({"type": "input_audio_buffer.speech_started"}))
            }
            (Dialect::Gemini, Norm::SpeechStart) => {
                Some(json!({"serverContent": {"interrupted": true}}))
            }
            (Dialect::OpenAi, Norm::SpeechStop) => {
                Some(json!({"type": "input_audio_buffer.speech_stopped"}))
            }
            (Dialect::OpenAi, Norm::Error(code, message)) => Some(json!({
                "type": "error", "error": {"type": "server_error", "code": code,
                                           "message": message}})),
            (Dialect::OpenAi, Norm::RateLimits) => {
                Some(json!({"type": "rate_limits.updated", "rate_limits": []}))
            }
            (Dialect::OpenAi, Norm::Usage(ai, ao, ti, to)) => Some(json!({
                "type": "response.done", "response": {"usage": {
                    "input_tokens": ai + ti, "output_tokens": ao + to,
                    "total_tokens": ai + ti + ao + to,
                    "input_token_details": {"audio_tokens": ai, "text_tokens": ti},
                    "output_token_details": {"audio_tokens": ao, "text_tokens": to}}}})),
            (Dialect::Gemini, Norm::Usage(ai, ao, ti, to)) => Some(json!({"usageMetadata": {
                "promptTokenCount": ai + ti, "responseTokenCount": ao + to,
                "totalTokenCount": ai + ti + ao + to,
                "promptTokensDetails": [{"modality": "AUDIO", "tokenCount": ai},
                                        {"modality": "TEXT", "tokenCount": ti}],
                "responseTokensDetails": [{"modality": "AUDIO", "tokenCount": ao},
                                          {"modality": "TEXT", "tokenCount": to}]}})),
            (Dialect::OpenAi, Norm::ToolOpen(id, name)) => {
                self.call(id).1.clone_from(name);
                Some(json!({"type": "response.output_item.added",
                    "item": {"type": "function_call", "call_id": id, "name": name}}))
            }
            (Dialect::OpenAi, Norm::ToolArgs(id, args)) => {
                self.call(id).2 = args.clone();
                Some(
                    json!({"type": "response.function_call_arguments.delta", "call_id": id,
                    "delta": serde_json::to_string(args).unwrap_or_default()}),
                )
            }
            (Dialect::OpenAi, Norm::ToolClose(id)) => {
                let (_, name, args) = self.call(id).clone();
                Some(
                    json!({"type": "response.function_call_arguments.done", "call_id": id,
                    "name": name, "arguments": serde_json::to_string(&args).unwrap_or_default()}),
                )
            }
            (Dialect::Gemini, Norm::ToolOpen(id, name)) => {
                if !name.is_empty() {
                    self.call(id).1.clone_from(name);
                }
                None
            }
            (Dialect::Gemini, Norm::ToolArgs(id, args)) => {
                if !args.is_null() {
                    self.call(id).2 = args.clone();
                }
                None
            }
            (Dialect::Gemini, Norm::ToolClose(id)) => {
                let (_, name, args) = self.call(id).clone();
                if args.is_null() {
                    return None;
                }
                let mut fc = Map::new();
                fc.insert("id".into(), json!(id));
                if !name.is_empty() {
                    fc.insert("name".into(), json!(name));
                }
                fc.insert("args".into(), args);
                Some(json!({"toolCall": {"functionCalls": [Value::Object(fc)]}}))
            }
            _ => None,
        }
    }
}

/// The configuring caller frame `frame` (`from`'s `session.update` or `setup`), bridged toward `to`
/// as `to`'s configuring frame: the survivable config carried, every dialect-only member dropped
/// (the map's `session / setup configuration` row).
pub fn bridge_config(from: Dialect, to: Dialect, frame: &[u8]) -> Option<Value> {
    let v: Value = serde_json::from_slice(frame).ok()?;
    let cfg = match from {
        Dialect::OpenAi if s(&v, "type") == "session.update" => {
            Cfg::of_realtime(v.get("session").unwrap_or(&NULL))
        }
        Dialect::Gemini => Cfg::of_setup(v.get("setup")?),
        Dialect::OpenAi => return None,
    };
    Some(match to {
        Dialect::OpenAi => cfg.to_realtime(),
        Dialect::Gemini => json!({"setup": Value::Object(cfg.to_setup())}),
    })
}

// ── the session lock (Part 2 #45; Law 5's governed splice) ──────────────────────────────────────

/// The session section a leg opens under, read by the harness: its locked `session` object.
pub fn locked_session(section: &[u8]) -> Map<String, Value> {
    serde_json::from_slice::<Value>(section)
        .ok()
        .and_then(|v| v.get("session").and_then(Value::as_object).cloned())
        .unwrap_or_default()
}

/// The locked session as Gemini Live `setup` members: `model`, and the survivable config.
fn locked_setup(locked: &Map<String, Value>) -> Map<String, Value> {
    let session = Value::Object(locked.clone());
    let mut setup = Cfg::of_realtime(&session).to_setup();
    if let Some(model) = locked.get("model") {
        setup.insert("model".into(), model.clone());
    }
    setup
}

/// `theirs` with `cut` removed and `set` put over it, an object over an object merged member by
/// member.
fn govern(theirs: &mut Map<String, Value>, cut: &[&str], set: &Map<String, Value>) {
    for key in cut {
        theirs.remove(*key);
    }
    for (key, value) in set {
        if let Value::Object(locked) = value {
            if let Some(Value::Object(mine)) = theirs.get_mut(key) {
                govern(mine, &[], locked);
                continue;
            }
        }
        theirs.insert(key.clone(), value.clone());
    }
}

/// An uplink format token OpenAI Realtime publishes and the session lock carries (`pcm16`,
/// `g711_ulaw`); `Err` for one it cannot count the caller's audio in.
fn legacy_format(v: &Value) -> Result<Option<&'static str>, ()> {
    match v {
        Value::Null => Ok(None),
        Value::String(t) if t == "pcm16" => Ok(Some("pcm16")),
        Value::String(t) if t == "g711_ulaw" => Ok(Some("g711_ulaw")),
        _ => Err(()),
    }
}

/// OpenAI Realtime GA's format object (`{"type": "audio/pcm", "rate": 24000}`,
/// `{"type": "audio/pcmu"}`), or a legacy token in its place.
fn ga_format(v: &Value) -> Result<Option<&'static str>, ()> {
    let Some(o) = v.as_object() else {
        return legacy_format(v);
    };
    match o.get("type").and_then(Value::as_str) {
        Some("audio/pcm") => match o.get("rate") {
            None => Ok(Some("pcm16")),
            Some(r) if r.as_u64() == Some(24_000) => Ok(Some("pcm16")),
            Some(_) => Err(()),
        },
        Some("audio/pcmu") => Ok(Some("g711_ulaw")),
        _ => Err(()),
    }
}

/// Whether an OpenAI Realtime caller frame configures an uplink format the session cannot count
/// its audio in, or two that disagree, or one other than the locked one.
fn unmeterable(v: &Map<String, Value>, locked: &Map<String, Value>) -> bool {
    let Some(session) = v.get("session").and_then(Value::as_object) else {
        return false;
    };
    let mut named: Vec<&'static str> = Vec::new();
    if let Some(f) = session.get("input_audio_format") {
        match legacy_format(f) {
            Ok(Some(f)) => named.push(f),
            Ok(None) => {}
            Err(()) => return true,
        }
    }
    if let Some(f) = session
        .get("audio")
        .and_then(|a| a.pointer("/input/format"))
    {
        match ga_format(f) {
            Ok(Some(f)) => named.push(f),
            Ok(None) => {}
            Err(()) => return true,
        }
    }
    if named.windows(2).any(|w| w[0] != w[1]) {
        return true;
    }
    let lock = locked
        .get("input_audio_format")
        .and_then(Value::as_str)
        .filter(|f| !f.is_empty());
    matches!((lock, named.first()), (Some(l), Some(n)) if l != *n)
}

/// Whether an OpenAI Realtime caller frame authors an item in a role that instructs the model: a
/// conversation `item`, or a `response.input` item.
fn authors_instructions(v: &Map<String, Value>) -> bool {
    let instructs = |item: &Value| {
        item.get("role").and_then(Value::as_str).is_some_and(|r| {
            INSTRUCTING_ROLES
                .iter()
                .any(|i| i.eq_ignore_ascii_case(r.trim()))
        })
    };
    v.get("item").is_some_and(instructs)
        || v.get("response")
            .and_then(|r| r.get("input"))
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(instructs))
}

/// THE CALLER FRAME AS THE SESSION LOCK LEAVES IT: what a door relaying `frame` toward the far end
/// must send (as JSON), or `None` where it must send nothing. A frame that is not one JSON object
/// goes nowhere. In OpenAI Realtime a frame authoring an instructing item goes nowhere, and so does
/// one configuring an uplink format the session cannot count its audio in. Otherwise every
/// configuring object (`session`, `setup`) has the caller's instructions and tools cut and the
/// locked keys put in their place, and every per-response object (`response`) has the caller's
/// instructions and tools cut; every other member is as the caller wrote it.
pub fn governed(dialect: Dialect, locked: &Map<String, Value>, frame: &[u8]) -> Option<Value> {
    let Ok(Value::Object(mut v)) = serde_json::from_slice::<Value>(frame) else {
        return None;
    };
    let rules: Vec<(&str, &[&str], Map<String, Value>)> = match dialect {
        Dialect::OpenAi => {
            if unmeterable(&v, locked) || authors_instructions(&v) {
                return None;
            }
            vec![
                ("session", REALTIME_CUT, locked.clone()),
                ("response", REALTIME_CUT, Map::new()),
            ]
        }
        Dialect::Gemini => vec![("setup", LIVE_CUT, locked_setup(locked))],
    };
    for (at, cut, set) in &rules {
        if let Some(Value::Object(obj)) = v.get_mut(*at) {
            govern(obj, cut, set);
        }
    }
    Some(Value::Object(v))
}

// ── the OpenAI REST error envelope ──────────────────────────────────────────────────────────────

/// OpenAI's published REST error envelope for an HTTP `status` and `message`
/// (<https://platform.openai.com/docs/guides/error-codes>): the status read as the error's
/// `type`, `param` and `code` null.
pub fn openai_error(status: u16, message: &str) -> Value {
    let kind = match status {
        401 => "authentication_error",
        403 => "permission_error",
        404 => "not_found_error",
        429 => "rate_limit_error",
        400..=499 => "invalid_request_error",
        _ => "server_error",
    };
    json!({"error": {"message": message, "type": kind, "param": null, "code": null}})
}

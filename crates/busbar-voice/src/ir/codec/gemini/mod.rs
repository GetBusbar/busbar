// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECOND DIALECT — Google **Gemini Live** (`BidiGenerateContent`), mapped to/from the SAME
//! shared voice IR that [`super::OpenAiRealtimeCodec`] targets. Design `plane4-duplex-session.md` §1.4 / §2.6.
//!
//! This is the codec that turns busbar-voice into a real voice *translator*: a Gemini-Live wire event
//! is decoded into the plane-owned IR ([`IrClientEvent`] / [`IrServerEvent`]), and the OpenAI codec
//! (or this one) re-frames that IR onto its own wire. Earning a cross-dialect superset IR is exactly
//! what a SECOND dialect does — the A2A discipline (a plane earns a superset at its second wire format,
//! not before).
//!
//! WIRE SHAPE. Gemini Live is a JSON duplex where each message is an object with ONE top-level key
//! naming its kind (`setup` / `clientContent` / `realtimeInput` / `toolResponse` client→server;
//! `setupComplete` / `serverContent` / `toolCall` / `toolCallCancellation` / `usageMetadata`
//! server→client). The reader dispatches on that key and hand-maps to the shared IR — the same
//! convention the OpenAI codec uses on its `type` tag. One wire event maps to 0..n IR events; an
//! unrecognized or malformed frame degrades to an EMPTY vec (never an error).
//!
//! STRUCTURAL DELTAS vs OpenAI Realtime (the asymmetries the cross-parity verdict reads):
//!  * Gemini delivers a tool call ATOMICALLY (`toolCall.functionCalls[]` with `id`/`name`/`args`),
//!    where OpenAI STREAMS it (announce → arg-deltas → done). The reader expands each atomic Gemini
//!    call into the shared streamed triple ([`IrDuplexTool::CallOpen`] → `CallArgs` → `CallClose`) so
//!    the correlation moat is identical; the stateless writer re-frames one Gemini `toolCall` frame
//!    per IR tool event (coalescing back into a single atomic frame is the runtime pump's job).
//!  * Gemini's `setup` is structurally unlike OpenAI's `session` object, so setup translation is
//!    inherently lossy at the BYTE level (it is a genuine cross-dialect map, not verbatim carriage):
//!    it is a FIXPOINT at the IR level (wire→IR→wire→IR is stable) but not byte-for-byte.
//!  * Gemini's `interrupted` (the model's generation was cut off by a barge-in) maps onto the shared
//!    barge-in signal [`IrServerEvent::SpeechStarted`]; `turnComplete` maps onto [`IrServerEvent::AudioDone`].
//!
//! DROP+WARN (Gemini concepts with NO shared-IR home): input/output transcription side-channels,
//! `toolCallCancellation`, `goAway` / session-resumption, and non-audio model-turn parts. Following
//! the OpenAI codec's own degrade discipline, "warn" is realized as the silent drop (this plane crate
//! links no logging surface) — the frame yields no IR and is noted in the asymmetry list.

use super::{decode_audio, encode_audio, parse, str_at, wire_of, DecodeState};
use super::{DuplexReader, DuplexWriter, WireEvent};
use crate::ir::config::{MaxOutputTokens, SessionConfig};
use crate::ir::control::{IrDuplexControl, IrVad};
use crate::ir::event::{IrClientEvent, IrServerEvent};
use crate::ir::media::{AudioFormat, IrAudioFrame, UpDown};
use crate::ir::tool::IrDuplexTool;
use crate::ir::usage::IrDuplexUsage;
use bytes::Bytes;
use serde_json::{json, Value};

/// The Gemini Live top-level message keys — named once so the reader's dispatch and the writer's
/// framing never drift. These are the plane's OWN vocabulary for the second dialect.
mod wire {
    // client → server
    pub const SETUP: &str = "setup";
    pub const CLIENT_CONTENT: &str = "clientContent";
    pub const REALTIME_INPUT: &str = "realtimeInput";
    pub const TOOL_RESPONSE: &str = "toolResponse";
    // server → client
    pub const SETUP_COMPLETE: &str = "setupComplete";
    pub const SERVER_CONTENT: &str = "serverContent";
    pub const TOOL_CALL: &str = "toolCall";
    pub const TOOL_CALL_CANCELLATION: &str = "toolCallCancellation";
    pub const USAGE_METADATA: &str = "usageMetadata";
}

/// The canonical Gemini Live PCM mime types: 16 kHz signed-16 LE for the UPLINK (the required input
/// rate) and 24 kHz for the DOWNLINK (the model's synthesis rate). Named so the writer frames a
/// consistent mime and the reader's format probe agrees.
const UPLINK_MIME: &str = "audio/pcm;rate=16000";
const DOWNLINK_MIME: &str = "audio/pcm;rate=24000";

/// THE Gemini Live DIALECT CODEC — the plane's SECOND dialect. A unit struct: all per-session state
/// lives in the shared [`DecodeState`], so the codec is stateless and shareable, exactly like
/// [`super::OpenAiRealtimeCodec`].
#[derive(Debug, Default, Clone, Copy)]
pub struct GeminiLiveCodec;

// ── mime / audio-format helpers ───────────────────────────────────────────────────────────────────

/// Map a Gemini audio `mimeType` to the shared [`AudioFormat`]. Gemini's downlink is 24 kHz signed-16
/// PCM — exactly the shared `Pcm16` (the truncate math measures against this). Anything else the plane
/// does not model returns `None`.
#[must_use]
pub fn audio_format_from_mime(mime: &str) -> Option<AudioFormat> {
    let m = mime.to_ascii_lowercase();
    if !m.starts_with("audio/pcm") {
        return None;
    }
    // The downlink synthesis rate is the one the barge-in truncate math measures against.
    if m.contains("rate=24000") || !m.contains("rate=") {
        Some(AudioFormat::Pcm16)
    } else if m.contains("rate=16000") {
        // Uplink PCM: still signed-16 LE; the shared enum carries the 24 kHz constant, and uplink
        // never feeds the (downlink-only) truncate math, so `Pcm16` is the faithful shared token.
        Some(AudioFormat::Pcm16)
    } else {
        None
    }
}

// ── setup ↔ SessionConfig ─────────────────────────────────────────────────────────────────────────

/// Join a Gemini `systemInstruction` (`{ parts: [{ text }] }`) into a single instruction string.
fn system_instruction_text(si: &Value) -> Option<String> {
    let parts = si.get("parts")?.as_array()?;
    let joined: String = parts
        .iter()
        .filter_map(|p| p.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("");
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

/// Map Gemini `realtimeInputConfig.automaticActivityDetection` to the shared VAD IR. `disabled: true`
/// (or an absent config) means the client drives turns → `None`. Gemini's sensitivity enums have no
/// shared home (dropped); OpenAI-only knobs (`threshold` / `create_response` / `interrupt_response`)
/// take their shared defaults.
fn vad_from_realtime_input_config(ric: &Value) -> Option<IrVad> {
    let aad = ric.get("automaticActivityDetection")?;
    if aad.get("disabled").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    Some(IrVad::ServerVad {
        threshold: 0.5,
        prefix_padding_ms: aad
            .get("prefixPaddingMs")
            .and_then(Value::as_u64)
            .unwrap_or(300) as u32,
        silence_duration_ms: aad
            .get("silenceDurationMs")
            .and_then(Value::as_u64)
            .unwrap_or(200) as u32,
        create_response: true,
        interrupt_response: true,
    })
}

/// Decode a Gemini `setup` object into the shared [`SessionConfig`] (the cross-dialect superset).
fn session_config_from_setup(setup: &Value) -> SessionConfig {
    let gc = setup
        .get("generationConfig")
        .cloned()
        .unwrap_or(Value::Null);
    let modalities = gc
        .get("responseModalities")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default();
    let voice = gc
        .get("speechConfig")
        .and_then(|s| s.get("voiceConfig"))
        .and_then(|s| s.get("prebuiltVoiceConfig"))
        .and_then(|s| s.get("voiceName"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let max_output_tokens = gc
        .get("maxOutputTokens")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .map(MaxOutputTokens::Limit);
    SessionConfig {
        model: setup
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string),
        modalities,
        instructions: setup
            .get("systemInstruction")
            .and_then(system_instruction_text),
        voice,
        input_audio_format: None,
        output_audio_format: None,
        turn_detection: setup
            .get("realtimeInputConfig")
            .and_then(vad_from_realtime_input_config),
        tools: setup
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        tool_choice: None,
        max_output_tokens,
    }
}

/// Re-frame a shared [`SessionConfig`] back onto a Gemini `setup` object. The inverse of
/// [`session_config_from_setup`] at the IR level (byte-lossy by design — cross-dialect setup is a
/// genuine map, not verbatim carriage). Modalities are re-UPPERCASED to Gemini's enum tokens; the
/// OpenAI-only VAD knobs and Gemini-only sensitivities do not survive.
fn setup_from_session_config(cfg: &SessionConfig) -> Value {
    let mut setup = serde_json::Map::new();
    if let Some(model) = &cfg.model {
        setup.insert("model".into(), json!(model));
    }
    let mut gc = serde_json::Map::new();
    if !cfg.modalities.is_empty() {
        let mods: Vec<Value> = cfg
            .modalities
            .iter()
            .map(|m| json!(m.to_ascii_uppercase()))
            .collect();
        gc.insert("responseModalities".into(), Value::Array(mods));
    }
    if let Some(voice) = &cfg.voice {
        gc.insert(
            "speechConfig".into(),
            json!({ "voiceConfig": { "prebuiltVoiceConfig": { "voiceName": voice } } }),
        );
    }
    if let Some(MaxOutputTokens::Limit(n)) = cfg.max_output_tokens {
        // The `"inf"` sentinel has no Gemini equivalent — Gemini simply omits the cap.
        gc.insert("maxOutputTokens".into(), json!(n));
    }
    if !gc.is_empty() {
        setup.insert("generationConfig".into(), Value::Object(gc));
    }
    if let Some(instr) = &cfg.instructions {
        setup.insert(
            "systemInstruction".into(),
            json!({ "parts": [{ "text": instr }] }),
        );
    }
    if !cfg.tools.is_empty() {
        setup.insert("tools".into(), Value::Array(cfg.tools.clone()));
    }
    if let Some(IrVad::ServerVad {
        prefix_padding_ms,
        silence_duration_ms,
        ..
    }) = &cfg.turn_detection
    {
        setup.insert(
            "realtimeInputConfig".into(),
            json!({ "automaticActivityDetection": {
                "prefixPaddingMs": prefix_padding_ms,
                "silenceDurationMs": silence_duration_ms,
            }}),
        );
    } else if let Some(IrVad::SemanticVad { .. }) = &cfg.turn_detection {
        // Semantic VAD has no Gemini knob set; enable automatic detection generically.
        setup.insert(
            "realtimeInputConfig".into(),
            json!({ "automaticActivityDetection": {} }),
        );
    }
    json!({ wire::SETUP: Value::Object(setup) })
}

// ── usage ↔ usageMetadata ─────────────────────────────────────────────────────────────────────────

/// Pull a per-modality token count out of a Gemini `*TokensDetails` array (`[{modality, tokenCount}]`).
fn modality_tokens(details: Option<&Value>, modality: &str) -> u64 {
    details
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|d| {
            d.get("modality")
                .and_then(Value::as_str)
                .map(str::to_ascii_uppercase)
                == Some(modality.to_string())
        })
        .and_then(|d| d.get("tokenCount").and_then(Value::as_u64))
        .unwrap_or_default()
}

/// Extract the split token classes from a Gemini `usageMetadata` object (`plane4-duplex-session.md` §2.5 — audio vs text are
/// SEPARATE classes; extraction-only, never client-translated).
fn usage_from_metadata(u: &Value) -> IrDuplexUsage {
    let pd = u.get("promptTokensDetails");
    let rd = u.get("responseTokensDetails");
    IrDuplexUsage {
        audio_in: modality_tokens(pd, "AUDIO"),
        text_in: modality_tokens(pd, "TEXT"),
        audio_out: modality_tokens(rd, "AUDIO"),
        text_out: modality_tokens(rd, "TEXT"),
        cached: u
            .get("cachedContentTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
    }
}

/// Re-frame the extracted token classes back onto a Gemini `usageMetadata` object (inverse of
/// [`usage_from_metadata`]).
fn usage_to_metadata(u: &IrDuplexUsage) -> Value {
    json!({
        "promptTokenCount": u.audio_in + u.text_in,
        "responseTokenCount": u.audio_out + u.text_out,
        "totalTokenCount": u.audio_in + u.text_in + u.audio_out + u.text_out,
        "cachedContentTokenCount": u.cached,
        "promptTokensDetails": [
            { "modality": "AUDIO", "tokenCount": u.audio_in },
            { "modality": "TEXT", "tokenCount": u.text_in },
        ],
        "responseTokensDetails": [
            { "modality": "AUDIO", "tokenCount": u.audio_out },
            { "modality": "TEXT", "tokenCount": u.text_out },
        ],
    })
}

// ── reader ──────────────────────────────────────────────────────────────────────────────────────

impl DuplexReader for GeminiLiveCodec {
    fn read_up(&self, evt: WireEvent, st: &mut DecodeState) -> Vec<IrClientEvent> {
        let Some(v) = parse(&evt) else {
            return Vec::new();
        };

        if let Some(setup) = v.get(wire::SETUP) {
            let cfg = session_config_from_setup(setup);
            // Gemini's downlink synthesis is 24 kHz PCM — the format the truncate math measures.
            if cfg.modalities.iter().any(|m| m == "audio") || cfg.modalities.is_empty() {
                st.set_output_format(AudioFormat::Pcm16);
            }
            return vec![IrClientEvent::Control(IrDuplexControl::SessionConfigure {
                config: cfg,
            })];
        }

        if let Some(cc) = v.get(wire::CLIENT_CONTENT) {
            // A client turn (`turns` + `turnComplete`) is injected VERBATIM as a conversation item —
            // the plane locks/reconciles it but never reshapes the content bytes.
            return vec![IrClientEvent::Control(IrDuplexControl::ItemCreate {
                item: cc.clone(),
            })];
        }

        if let Some(ri) = v.get(wire::REALTIME_INPUT) {
            // Uplink audio arrives in TWO Gemini spellings, both decoded to `IrAudioFrame{dir:Up}` with
            // a monotonic seq: the GA (`v1beta`) `realtimeInput.audio` SINGLE inline blob, and the
            // legacy `realtimeInput.mediaChunks[]` ARRAY. A `{mimeType,data}` blob whose mime is not a
            // modeled audio format has no shared frame (drop).
            let mut out = Vec::new();
            let mut push_blob = |blob: &Value, out: &mut Vec<IrClientEvent>| {
                if audio_format_from_mime(str_at(blob, "mimeType")).is_none() {
                    return; // non-audio realtime input has no shared frame (drop).
                }
                let media = decode_audio(str_at(blob, "data"));
                out.push(IrClientEvent::AudioFrame(IrAudioFrame {
                    dir: UpDown::Up,
                    seq: st.next_up_seq(),
                    media,
                }));
            };
            // Prefer the GA single blob when present so a GA peer never double-decodes; else fall back
            // to the legacy per-chunk array (one frame each).
            if let Some(audio) = ri.get("audio") {
                push_blob(audio, &mut out);
            } else if let Some(chunks) = ri.get("mediaChunks").and_then(Value::as_array) {
                for chunk in chunks {
                    push_blob(chunk, &mut out);
                }
            }
            // `realtimeInput.audioStreamEnd` is a manual end-of-stream marker with no shared IR home
            // (drop+warn): the cross-dialect map aspires to a commit-mapping, but the asymmetry table
            // exercises it as a documented drop, so it yields no IR here.
            return out;
        }

        if let Some(tr) = v.get(wire::TOOL_RESPONSE) {
            let mut out = Vec::new();
            if let Some(rs) = tr.get("functionResponses").and_then(Value::as_array) {
                for r in rs {
                    let call_id = str_at(r, "id");
                    let call_ref = st.ref_for_call_id(call_id);
                    // The `response` object is the tool's opaque output payload (the moat normalizes
                    // correlation, not the bytes). `functionResponse.name` is redundant with `id`
                    // and has no CallResult slot (dropped).
                    let output = Bytes::from(
                        serde_json::to_vec(r.get("response").unwrap_or(&Value::Null))
                            .unwrap_or_default(),
                    );
                    out.push(IrClientEvent::Tool(IrDuplexTool::CallResult {
                        call_ref,
                        call_id: call_id.to_string(),
                        output,
                    }));
                }
            }
            return out;
        }

        Vec::new()
    }

    fn read_down(&self, evt: WireEvent, st: &mut DecodeState) -> Vec<IrServerEvent> {
        let Some(v) = parse(&evt) else {
            return Vec::new();
        };

        if let Some(sc) = v.get(wire::SETUP_COMPLETE) {
            return vec![IrServerEvent::SessionCreated {
                session: sc.clone(),
            }];
        }

        if let Some(sc) = v.get(wire::SERVER_CONTENT) {
            let mut out = Vec::new();
            if let Some(parts) = sc
                .get("modelTurn")
                .and_then(|mt| mt.get("parts"))
                .and_then(Value::as_array)
            {
                for p in parts {
                    if let Some(inline) = p.get("inlineData") {
                        let mime = str_at(inline, "mimeType");
                        if audio_format_from_mime(mime).is_none() {
                            continue;
                        }
                        let media = decode_audio(str_at(inline, "data"));
                        st.record_played(media.len() as u64);
                        out.push(IrServerEvent::AudioFrame(IrAudioFrame {
                            dir: UpDown::Down,
                            seq: st.next_down_seq(),
                            media,
                        }));
                    }
                    // A `text` part / transcription side-channel has no shared IR home (drop+warn).
                }
            }
            // `interrupted` = the model's generation was cut off by a barge-in → the shared barge-in
            // signal. `turnComplete` = the model turn's audio is complete → AudioDone.
            if sc.get("interrupted").and_then(Value::as_bool) == Some(true) {
                out.push(IrServerEvent::SpeechStarted {
                    audio_start_ms: 0,
                    item_id: String::new(),
                });
            }
            if sc.get("turnComplete").and_then(Value::as_bool) == Some(true) {
                out.push(IrServerEvent::AudioDone {
                    item_id: String::new(),
                });
            }
            return out;
        }

        if let Some(tc) = v.get(wire::TOOL_CALL) {
            let mut out = Vec::new();
            if let Some(calls) = tc.get("functionCalls").and_then(Value::as_array) {
                for c in calls {
                    let call_id = str_at(c, "id");
                    let call_ref = st.ref_for_call_id(call_id);
                    // Gemini delivers the call ATOMICALLY; expand it into the shared STREAMED triple
                    // (open → args → close) so the correlation moat matches the OpenAI codec exactly.
                    out.push(IrServerEvent::Tool(IrDuplexTool::CallOpen {
                        call_ref,
                        call_id: call_id.to_string(),
                        name: str_at(c, "name").to_string(),
                    }));
                    let json_delta = Bytes::from(
                        serde_json::to_vec(c.get("args").unwrap_or(&Value::Null))
                            .unwrap_or_default(),
                    );
                    out.push(IrServerEvent::Tool(IrDuplexTool::CallArgs {
                        call_ref,
                        call_id: call_id.to_string(),
                        json_delta,
                    }));
                    out.push(IrServerEvent::Tool(IrDuplexTool::CallClose {
                        call_ref,
                        call_id: call_id.to_string(),
                    }));
                }
            }
            return out;
        }

        if let Some(um) = v.get(wire::USAGE_METADATA) {
            return vec![IrServerEvent::Usage(usage_from_metadata(um))];
        }

        // `toolCallCancellation`, `goAway`, `sessionResumptionUpdate` and any unknown frame have no
        // shared IR home — degrade to empty (drop+warn).
        let _ = wire::TOOL_CALL_CANCELLATION;
        Vec::new()
    }
}

// ── writer ──────────────────────────────────────────────────────────────────────────────────────

/// Frame one Gemini `toolCall` around a single `functionCall` object.
fn tool_call_frame(fc: Value) -> Value {
    json!({ wire::TOOL_CALL: { "functionCalls": [fc] } })
}

impl DuplexWriter for GeminiLiveCodec {
    fn write_up(&self, ev: IrClientEvent) -> WireEvent {
        let v = match ev {
            IrClientEvent::AudioFrame(f) => json!({
                wire::REALTIME_INPUT: {
                    "mediaChunks": [ { "mimeType": UPLINK_MIME, "data": encode_audio(&f.media) } ]
                }
            }),
            IrClientEvent::Control(c) => match c {
                IrDuplexControl::SessionConfigure { config } => setup_from_session_config(&config),
                IrDuplexControl::ItemCreate { item } => json!({ wire::CLIENT_CONTENT: item }),
                // The Gemini uplink has no discrete commit/clear/cancel/delete/truncate verbs; the
                // model turn is driven by `clientContent.turnComplete` and activity detection. Frame
                // these OpenAI-shaped controls as an empty realtime-input marker rather than panic —
                // they are dropped cross-dialect (asymmetry).
                IrDuplexControl::ResponseCreate { .. }
                | IrDuplexControl::ResponseCancel
                | IrDuplexControl::InputAudioCommit
                | IrDuplexControl::InputAudioClear
                | IrDuplexControl::ItemDelete { .. }
                | IrDuplexControl::ItemTruncate { .. } => {
                    json!({ wire::REALTIME_INPUT: {} })
                }
            },
            IrClientEvent::Tool(t) => match t {
                IrDuplexTool::CallResult {
                    call_id, output, ..
                } => json!({
                    wire::TOOL_RESPONSE: {
                        "functionResponses": [ {
                            "id": call_id,
                            "response": serde_json::from_slice::<Value>(&output).unwrap_or(Value::Null),
                        } ]
                    }
                }),
                // The other tool variants are server→client; a client-side writer never authors them,
                // but frame them symmetrically rather than panic.
                IrDuplexTool::CallOpen { call_id, name, .. } => {
                    tool_call_frame(json!({ "id": call_id, "name": name }))
                }
                IrDuplexTool::CallArgs {
                    call_id,
                    json_delta,
                    ..
                } => tool_call_frame(json!({
                    "id": call_id,
                    "args": serde_json::from_slice::<Value>(&json_delta).unwrap_or(Value::Null),
                })),
                IrDuplexTool::CallClose { call_id, .. } => {
                    tool_call_frame(json!({ "id": call_id }))
                }
            },
        };
        wire_of(&v)
    }

    fn write_down(&self, ev: IrServerEvent) -> WireEvent {
        let v = match ev {
            IrServerEvent::SessionCreated { session } => json!({ wire::SETUP_COMPLETE: session }),
            IrServerEvent::Tool(t) => match t {
                IrDuplexTool::CallOpen { call_id, name, .. } => {
                    tool_call_frame(json!({ "id": call_id, "name": name }))
                }
                IrDuplexTool::CallArgs {
                    call_id,
                    json_delta,
                    ..
                } => tool_call_frame(json!({
                    "id": call_id,
                    "args": serde_json::from_slice::<Value>(&json_delta).unwrap_or(Value::Null),
                })),
                IrDuplexTool::CallClose { call_id, .. } => {
                    tool_call_frame(json!({ "id": call_id }))
                }
                IrDuplexTool::CallResult {
                    call_id, output, ..
                } => json!({
                    wire::TOOL_RESPONSE: {
                        "functionResponses": [ {
                            "id": call_id,
                            "response": serde_json::from_slice::<Value>(&output).unwrap_or(Value::Null),
                        } ]
                    }
                }),
            },
            // Gemini's barge-in signal is `serverContent.interrupted`; the shared SpeechStarted maps
            // onto it. SpeechStopped has no Gemini wire event → an empty serverContent (dropped).
            IrServerEvent::SpeechStarted { .. } => json!({
                wire::SERVER_CONTENT: { "interrupted": true }
            }),
            IrServerEvent::SpeechStopped { .. } => json!({ wire::SERVER_CONTENT: {} }),
            IrServerEvent::AudioFrame(f) => json!({
                wire::SERVER_CONTENT: {
                    "modelTurn": { "parts": [ { "inlineData": {
                        "mimeType": DOWNLINK_MIME, "data": encode_audio(&f.media)
                    } } ] }
                }
            }),
            IrServerEvent::AudioDone { .. } => json!({
                wire::SERVER_CONTENT: { "turnComplete": true }
            }),
            IrServerEvent::Usage(u) => json!({ wire::USAGE_METADATA: usage_to_metadata(&u) }),
            // Gemini has no discrete rate-limit event; frame an empty usage-metadata marker.
            IrServerEvent::RateLimits => json!({ wire::USAGE_METADATA: {} }),
            // Gemini has no first-class error frame; surface it inside serverContent for the client.
            IrServerEvent::Error { code, message } => json!({
                wire::SERVER_CONTENT: { "error": { "code": code, "message": message } }
            }),
        };
        wire_of(&v)
    }
}

#[cfg(test)]
mod tests;

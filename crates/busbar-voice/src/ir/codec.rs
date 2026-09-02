// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE READER / WRITER PAIR — the bidirectional analog of the LLM plane's
//! `ProtocolReader`/`ProtocolWriter`. Design §2.6.
//!
//! The single design delta vs the LLM `ProtocolReader` is that Plane 4 needs a client→server event
//! vocabulary, so the plane defines TWO DIRECTIONS over one wire schema (the MCP "one reader, one
//! writer, both directions" discipline).
//!
//! The dialect is OpenAI Realtime GA: every wire event is a JSON object tagged on a `type` field. The
//! reader parses `WireEvent` bytes to a `serde_json::Value` and hand-maps by `type` (the LLM-plane
//! convention — serde-derive is reserved for the [`crate::ir::config::SessionConfig`] object); the
//! writer builds the JSON back. One wire event maps to 0..n IR events; a malformed / unrecognized
//! frame yields an EMPTY vec (the streaming-decode discipline — degrade, don't error), except a
//! dialect `error` event, which surfaces as [`IrServerEvent::Error`].
//!
//! STATE THREADING: unlike the LLM reader (whose request path is stateless whole-JSON), BOTH
//! directions here thread [`DecodeState`] — uplink needs the monotonic frame `seq` and `CallRef`
//! minting just as downlink does. The writers stay STATELESS: each tool IR variant carries its raw
//! `call_id`, so re-framing a `function_call_output` never consults the session map.

use crate::ir::config::SessionConfig;
use crate::ir::control::IrDuplexControl;
use crate::ir::event::{IrClientEvent, IrServerEvent};
use crate::ir::media::{AudioFormat, IrAudioFrame, UpDown};
use crate::ir::tool::{CallRef, IrDuplexTool};
use crate::ir::usage::IrDuplexUsage;
use bytes::Bytes;
use serde_json::{json, Value};
use std::collections::HashMap;

/// The dialect wire `type` tokens — named once here so the reader's dispatch and the writer's framing
/// never drift. These are the plane's OWN vocabulary (it owns 100% of its protocol nouns, §7.2).
mod wire {
    // client → server
    pub const SESSION_UPDATE: &str = "session.update";
    pub const INPUT_AUDIO_APPEND: &str = "input_audio_buffer.append";
    pub const INPUT_AUDIO_COMMIT: &str = "input_audio_buffer.commit";
    pub const INPUT_AUDIO_CLEAR: &str = "input_audio_buffer.clear";
    pub const ITEM_CREATE: &str = "conversation.item.create";
    pub const ITEM_TRUNCATE: &str = "conversation.item.truncate";
    pub const ITEM_DELETE: &str = "conversation.item.delete";
    pub const RESPONSE_CREATE: &str = "response.create";
    pub const RESPONSE_CANCEL: &str = "response.cancel";
    // server → client
    pub const SESSION_CREATED: &str = "session.created";
    pub const SPEECH_STARTED: &str = "input_audio_buffer.speech_started";
    pub const SPEECH_STOPPED: &str = "input_audio_buffer.speech_stopped";
    pub const OUTPUT_AUDIO_DELTA: &str = "response.output_audio.delta";
    pub const OUTPUT_AUDIO_DELTA_LEGACY: &str = "response.audio.delta";
    pub const OUTPUT_AUDIO_DONE: &str = "response.output_audio.done";
    pub const OUTPUT_AUDIO_DONE_LEGACY: &str = "response.audio.done";
    pub const OUTPUT_ITEM_ADDED: &str = "response.output_item.added";
    pub const FN_ARGS_DELTA: &str = "response.function_call_arguments.delta";
    pub const FN_ARGS_DONE: &str = "response.function_call_arguments.done";
    pub const RESPONSE_DONE: &str = "response.done";
    pub const RATE_LIMITS_UPDATED: &str = "rate_limits.updated";
    pub const ERROR: &str = "error";
    // shared item nouns
    pub const ITEM_FN_CALL_OUTPUT: &str = "function_call_output";
    pub const ITEM_FN_CALL: &str = "function_call";
}

/// ONE WIRE EVENT — the opaque, dialect-shaped message a reader parses / a writer produces: the JSON
/// bytes of one OpenAI Realtime event. Kept deliberately opaque so the reader/writer own all framing
/// knowledge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireEvent(pub bytes::Bytes);

/// PER-SESSION DECODE STATE threaded through the reader — the analog of the LLM reader's
/// `StreamDecodeState`. Holds what is per-session, not per-frame: monotonic frame sequencing, the
/// `CallRef ↔ call_id` correlation table (§2.2), the negotiated output format, and the barge-in
/// playback-position bookkeeping (§2.3 — the plane tracks bytes played because the upstream emits
/// audio faster than realtime).
#[derive(Debug)]
pub struct DecodeState {
    up_seq: u64,
    down_seq: u64,
    next_call_ref: u64,
    call_ids: HashMap<String, CallRef>,
    /// Downlink audio bytes played out for the CURRENT item — reset on flush / new item.
    played_bytes: u64,
    /// Negotiated OUTPUT format the truncate math measures against.
    output_fmt: AudioFormat,
}

impl Default for DecodeState {
    fn default() -> Self {
        DecodeState {
            up_seq: 0,
            down_seq: 0,
            next_call_ref: 0,
            call_ids: HashMap::new(),
            played_bytes: 0,
            output_fmt: AudioFormat::Pcm16,
        }
    }
}

impl DecodeState {
    /// The next uplink frame sequence number (monotonic per session).
    pub fn next_up_seq(&mut self) -> u64 {
        let s = self.up_seq;
        self.up_seq += 1;
        s
    }

    /// The next downlink frame sequence number (monotonic per session).
    pub fn next_down_seq(&mut self) -> u64 {
        let s = self.down_seq;
        self.down_seq += 1;
        s
    }

    /// The [`CallRef`] for a wire `call_id`, minting a fresh monotonic handle the first time the id is
    /// seen and returning the SAME handle on every later sighting (open → args → close → result all
    /// correlate to one ref).
    pub fn ref_for_call_id(&mut self, call_id: &str) -> CallRef {
        if let Some(r) = self.call_ids.get(call_id) {
            return *r;
        }
        let r = CallRef(self.next_call_ref);
        self.next_call_ref += 1;
        self.call_ids.insert(call_id.to_string(), r);
        r
    }

    /// The negotiated output format (defaults to `pcm16` until a `session.update` sets it).
    #[must_use]
    pub fn output_format(&self) -> AudioFormat {
        self.output_fmt
    }

    /// Adopt the negotiated output audio format (from a `session.update` / `session.created`).
    pub fn set_output_format(&mut self, fmt: AudioFormat) {
        self.output_fmt = fmt;
    }

    /// Account `n` bytes of downlink audio as PLAYED OUT to the client (barge-in bookkeeping).
    pub fn record_played(&mut self, n: u64) {
        self.played_bytes += n;
    }

    /// The audio the user has ACTUALLY heard so far, in ms — the barge-in truncate point. Pure read of
    /// the tracked playback position against the negotiated format (§2.3).
    #[must_use]
    pub fn played_ms(&self) -> u64 {
        crate::ir::media::truncate_point_ms(self.played_bytes, self.output_fmt)
    }

    /// FLUSH the queued/played downlink audio on `speech_started` (barge-in): returns the just-heard
    /// duration (ms) — the value an [`IrDuplexControl::ItemTruncate`] carries — and zeroes the
    /// playback counter for the next item. This is the DATA move; the runtime that cancels the
    /// in-flight response and emits the truncate is the next layer.
    pub fn flush_playback(&mut self) -> u64 {
        let ms = self.played_ms();
        self.played_bytes = 0;
        ms
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────────────────────────

fn parse(evt: &WireEvent) -> Option<Value> {
    serde_json::from_slice::<Value>(&evt.0).ok()
}

fn wire_of(v: &Value) -> WireEvent {
    // serde_json::to_vec on an owned Value cannot fail.
    WireEvent(Bytes::from(serde_json::to_vec(v).unwrap_or_default()))
}

fn str_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn u64_at(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or_default()
}

/// base64-decode a wire audio string to opaque media bytes (the identity IR is the decoded bytes).
fn decode_audio(b64: &str) -> Bytes {
    busbar_substrate::media::base64_decode(b64).unwrap_or_default()
}

/// base64-encode opaque media bytes back to a wire audio string.
fn encode_audio(media: &Bytes) -> String {
    busbar_substrate::media::base64_encode(media)
}

// ── reader ──────────────────────────────────────────────────────────────────────────────────────

/// WIRE → IR. Reads a dialect's wire events into the plane's neutral IR, in both directions.
///
/// One wire event maps to 0..n IR events (the `read_response_events` shape). Both directions thread
/// per-session [`DecodeState`] (seq, `CallRef`, playback position).
pub trait DuplexReader {
    /// Client→server events (the net-new vocabulary): audio uplink, config, tool results.
    fn read_up(&self, evt: WireEvent, st: &mut DecodeState) -> Vec<IrClientEvent>;

    /// Server→client events, threading per-session decode state (barge-in position, `CallRef` map).
    fn read_down(&self, evt: WireEvent, st: &mut DecodeState) -> Vec<IrServerEvent>;
}

/// IR → WIRE. Re-frames the plane's neutral IR back onto a dialect's wire, in both directions.
/// Stateless — every field needed to frame is carried in the IR (tool `call_id`, audio `media`).
pub trait DuplexWriter {
    /// Re-frame a client→server event onto the UPSTREAM dialect's wire.
    fn write_up(&self, ev: IrClientEvent) -> WireEvent;

    /// Re-frame a server→client event onto the CLIENT dialect's wire.
    fn write_down(&self, ev: IrServerEvent) -> WireEvent;
}

/// THE OpenAI Realtime GA DIALECT CODEC — the plane's sole dialect today (`codec: None`, one wire
/// format, §1.4). A unit struct: all per-session state lives in [`DecodeState`], so the codec itself
/// is stateless and shareable.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenAiRealtimeCodec;

impl DuplexReader for OpenAiRealtimeCodec {
    fn read_up(&self, evt: WireEvent, st: &mut DecodeState) -> Vec<IrClientEvent> {
        let Some(v) = parse(&evt) else {
            return Vec::new();
        };
        let ty = str_at(&v, "type");
        match ty {
            wire::SESSION_UPDATE => {
                let cfg: SessionConfig = v
                    .get("session")
                    .and_then(|s| serde_json::from_value(s.clone()).ok())
                    .unwrap_or_default();
                if let Some(fmt) = cfg.output_audio_format {
                    st.set_output_format(fmt);
                }
                vec![IrClientEvent::Control(IrDuplexControl::SessionConfigure {
                    config: cfg,
                })]
            }
            wire::INPUT_AUDIO_APPEND => {
                let media = decode_audio(str_at(&v, "audio"));
                vec![IrClientEvent::AudioFrame(IrAudioFrame {
                    dir: UpDown::Up,
                    seq: st.next_up_seq(),
                    media,
                })]
            }
            wire::INPUT_AUDIO_COMMIT => {
                vec![IrClientEvent::Control(IrDuplexControl::InputAudioCommit)]
            }
            wire::INPUT_AUDIO_CLEAR => {
                vec![IrClientEvent::Control(IrDuplexControl::InputAudioClear)]
            }
            wire::ITEM_CREATE => {
                let item = v.get("item").cloned().unwrap_or(Value::Null);
                if str_at(&item, "type") == wire::ITEM_FN_CALL_OUTPUT {
                    let call_id = str_at(&item, "call_id");
                    let call_ref = st.ref_for_call_id(call_id);
                    let output = Bytes::from(str_at(&item, "output").to_owned().into_bytes());
                    vec![IrClientEvent::Tool(IrDuplexTool::CallResult {
                        call_ref,
                        call_id: call_id.to_string(),
                        output,
                    })]
                } else {
                    vec![IrClientEvent::Control(IrDuplexControl::ItemCreate { item })]
                }
            }
            wire::ITEM_TRUNCATE => {
                vec![IrClientEvent::Control(IrDuplexControl::ItemTruncate {
                    item_ref: str_at(&v, "item_id").to_string(),
                    content_index: u64_at(&v, "content_index") as u32,
                    audio_played_ms: u64_at(&v, "audio_end_ms"),
                })]
            }
            wire::ITEM_DELETE => {
                vec![IrClientEvent::Control(IrDuplexControl::ItemDelete {
                    item_ref: str_at(&v, "item_id").to_string(),
                })]
            }
            wire::RESPONSE_CREATE => {
                let response = v.get("response").cloned();
                vec![IrClientEvent::Control(IrDuplexControl::ResponseCreate {
                    response,
                })]
            }
            wire::RESPONSE_CANCEL => {
                vec![IrClientEvent::Control(IrDuplexControl::ResponseCancel)]
            }
            _ => Vec::new(),
        }
    }

    fn read_down(&self, evt: WireEvent, st: &mut DecodeState) -> Vec<IrServerEvent> {
        let Some(v) = parse(&evt) else {
            return Vec::new();
        };
        let ty = str_at(&v, "type");
        match ty {
            wire::SESSION_CREATED => {
                let session = v.get("session").cloned().unwrap_or(Value::Null);
                if let Some(fmt) = session
                    .get("output_audio_format")
                    .and_then(Value::as_str)
                    .and_then(AudioFormat::from_wire)
                {
                    st.set_output_format(fmt);
                }
                vec![IrServerEvent::SessionCreated { session }]
            }
            wire::SPEECH_STARTED => vec![IrServerEvent::SpeechStarted {
                audio_start_ms: u64_at(&v, "audio_start_ms"),
                item_id: str_at(&v, "item_id").to_string(),
            }],
            wire::SPEECH_STOPPED => vec![IrServerEvent::SpeechStopped {
                audio_end_ms: u64_at(&v, "audio_end_ms"),
                item_id: str_at(&v, "item_id").to_string(),
            }],
            wire::OUTPUT_AUDIO_DELTA | wire::OUTPUT_AUDIO_DELTA_LEGACY => {
                let media = decode_audio(str_at(&v, "delta"));
                st.record_played(media.len() as u64);
                vec![IrServerEvent::AudioFrame(IrAudioFrame {
                    dir: UpDown::Down,
                    seq: st.next_down_seq(),
                    media,
                })]
            }
            wire::OUTPUT_AUDIO_DONE | wire::OUTPUT_AUDIO_DONE_LEGACY => {
                vec![IrServerEvent::AudioDone {
                    item_id: str_at(&v, "item_id").to_string(),
                }]
            }
            wire::OUTPUT_ITEM_ADDED => {
                let item = v.get("item").cloned().unwrap_or(Value::Null);
                if str_at(&item, "type") == wire::ITEM_FN_CALL {
                    let call_id = str_at(&item, "call_id");
                    let call_ref = st.ref_for_call_id(call_id);
                    vec![IrServerEvent::Tool(IrDuplexTool::CallOpen {
                        call_ref,
                        call_id: call_id.to_string(),
                        name: str_at(&item, "name").to_string(),
                    })]
                } else {
                    Vec::new()
                }
            }
            wire::FN_ARGS_DELTA => {
                let call_id = str_at(&v, "call_id");
                let call_ref = st.ref_for_call_id(call_id);
                let json_delta = Bytes::from(str_at(&v, "delta").to_owned().into_bytes());
                vec![IrServerEvent::Tool(IrDuplexTool::CallArgs {
                    call_ref,
                    call_id: call_id.to_string(),
                    json_delta,
                })]
            }
            wire::FN_ARGS_DONE => {
                let call_id = str_at(&v, "call_id");
                let call_ref = st.ref_for_call_id(call_id);
                vec![IrServerEvent::Tool(IrDuplexTool::CallClose {
                    call_ref,
                    call_id: call_id.to_string(),
                })]
            }
            wire::RESPONSE_DONE => {
                let usage = v
                    .get("response")
                    .and_then(|r| r.get("usage"))
                    .map(extract_usage)
                    .unwrap_or_default();
                vec![IrServerEvent::Usage(usage)]
            }
            wire::RATE_LIMITS_UPDATED => vec![IrServerEvent::RateLimits],
            wire::ERROR => {
                let err = v.get("error").cloned().unwrap_or(Value::Null);
                vec![IrServerEvent::Error {
                    code: str_at(&err, "code").to_string(),
                    message: str_at(&err, "message").to_string(),
                }]
            }
            _ => Vec::new(),
        }
    }
}

/// Extract the split token classes from a `response.done.usage` object (§2.5 — audio vs text are
/// SEPARATE classes; extraction-only, never client-translated).
fn extract_usage(u: &Value) -> IrDuplexUsage {
    let ind = u.get("input_token_details");
    let outd = u.get("output_token_details");
    let field = |o: Option<&Value>, k: &str| {
        o.and_then(|x| x.get(k))
            .and_then(Value::as_u64)
            .unwrap_or_default()
    };
    IrDuplexUsage {
        audio_in: field(ind, "audio_tokens"),
        audio_out: field(outd, "audio_tokens"),
        text_in: field(ind, "text_tokens"),
        text_out: field(outd, "text_tokens"),
        cached: field(ind, "cached_tokens"),
    }
}

// ── writer ──────────────────────────────────────────────────────────────────────────────────────

impl DuplexWriter for OpenAiRealtimeCodec {
    fn write_up(&self, ev: IrClientEvent) -> WireEvent {
        let v = match ev {
            IrClientEvent::AudioFrame(f) => json!({
                "type": wire::INPUT_AUDIO_APPEND,
                "audio": encode_audio(&f.media),
            }),
            IrClientEvent::Control(c) => match c {
                IrDuplexControl::SessionConfigure { config } => json!({
                    "type": wire::SESSION_UPDATE,
                    "session": config,
                }),
                IrDuplexControl::ResponseCreate { response } => {
                    let mut o = json!({ "type": wire::RESPONSE_CREATE });
                    if let Some(r) = response {
                        o["response"] = r;
                    }
                    o
                }
                IrDuplexControl::ResponseCancel => json!({ "type": wire::RESPONSE_CANCEL }),
                IrDuplexControl::InputAudioCommit => json!({ "type": wire::INPUT_AUDIO_COMMIT }),
                IrDuplexControl::InputAudioClear => json!({ "type": wire::INPUT_AUDIO_CLEAR }),
                IrDuplexControl::ItemCreate { item } => json!({
                    "type": wire::ITEM_CREATE,
                    "item": item,
                }),
                IrDuplexControl::ItemDelete { item_ref } => json!({
                    "type": wire::ITEM_DELETE,
                    "item_id": item_ref,
                }),
                IrDuplexControl::ItemTruncate {
                    item_ref,
                    content_index,
                    audio_played_ms,
                } => json!({
                    "type": wire::ITEM_TRUNCATE,
                    "item_id": item_ref,
                    "content_index": content_index,
                    "audio_end_ms": audio_played_ms,
                }),
            },
            IrClientEvent::Tool(t) => match t {
                IrDuplexTool::CallResult {
                    call_id, output, ..
                } => json!({
                    "type": wire::ITEM_CREATE,
                    "item": {
                        "type": wire::ITEM_FN_CALL_OUTPUT,
                        "call_id": call_id,
                        "output": String::from_utf8_lossy(&output),
                    },
                }),
                // The other tool variants are server→client; a client-side writer never authors them,
                // but frame them symmetrically rather than panic.
                IrDuplexTool::CallOpen { call_id, name, .. } => json!({
                    "type": wire::OUTPUT_ITEM_ADDED,
                    "item": { "type": wire::ITEM_FN_CALL, "call_id": call_id, "name": name },
                }),
                IrDuplexTool::CallArgs {
                    call_id,
                    json_delta,
                    ..
                } => json!({
                    "type": wire::FN_ARGS_DELTA,
                    "call_id": call_id,
                    "delta": String::from_utf8_lossy(&json_delta),
                }),
                IrDuplexTool::CallClose { call_id, .. } => json!({
                    "type": wire::FN_ARGS_DONE,
                    "call_id": call_id,
                }),
            },
        };
        wire_of(&v)
    }

    fn write_down(&self, ev: IrServerEvent) -> WireEvent {
        let v = match ev {
            IrServerEvent::SessionCreated { session } => json!({
                "type": wire::SESSION_CREATED,
                "session": session,
            }),
            IrServerEvent::Tool(t) => match t {
                IrDuplexTool::CallOpen { call_id, name, .. } => json!({
                    "type": wire::OUTPUT_ITEM_ADDED,
                    "item": { "type": wire::ITEM_FN_CALL, "call_id": call_id, "name": name },
                }),
                IrDuplexTool::CallArgs {
                    call_id,
                    json_delta,
                    ..
                } => json!({
                    "type": wire::FN_ARGS_DELTA,
                    "call_id": call_id,
                    "delta": String::from_utf8_lossy(&json_delta),
                }),
                IrDuplexTool::CallClose { call_id, .. } => json!({
                    "type": wire::FN_ARGS_DONE,
                    "call_id": call_id,
                }),
                IrDuplexTool::CallResult {
                    call_id, output, ..
                } => json!({
                    "type": wire::ITEM_CREATE,
                    "item": {
                        "type": wire::ITEM_FN_CALL_OUTPUT,
                        "call_id": call_id,
                        "output": String::from_utf8_lossy(&output),
                    },
                }),
            },
            IrServerEvent::SpeechStarted {
                audio_start_ms,
                item_id,
            } => json!({
                "type": wire::SPEECH_STARTED,
                "audio_start_ms": audio_start_ms,
                "item_id": item_id,
            }),
            IrServerEvent::SpeechStopped {
                audio_end_ms,
                item_id,
            } => json!({
                "type": wire::SPEECH_STOPPED,
                "audio_end_ms": audio_end_ms,
                "item_id": item_id,
            }),
            IrServerEvent::AudioFrame(f) => json!({
                "type": wire::OUTPUT_AUDIO_DELTA,
                "delta": encode_audio(&f.media),
            }),
            IrServerEvent::AudioDone { item_id } => json!({
                "type": wire::OUTPUT_AUDIO_DONE,
                "item_id": item_id,
            }),
            IrServerEvent::Usage(u) => json!({
                "type": wire::RESPONSE_DONE,
                "response": { "usage": usage_to_wire(&u) },
            }),
            IrServerEvent::RateLimits => json!({
                "type": wire::RATE_LIMITS_UPDATED,
                "rate_limits": [],
            }),
            IrServerEvent::Error { code, message } => json!({
                "type": wire::ERROR,
                "error": { "code": code, "message": message },
            }),
        };
        wire_of(&v)
    }
}

/// Re-frame the extracted token classes back onto a `usage` object (the inverse of [`extract_usage`]).
fn usage_to_wire(u: &IrDuplexUsage) -> Value {
    json!({
        "total_tokens": u.audio_in + u.audio_out + u.text_in + u.text_out,
        "input_token_details": {
            "audio_tokens": u.audio_in,
            "text_tokens": u.text_in,
            "cached_tokens": u.cached,
        },
        "output_token_details": {
            "audio_tokens": u.audio_out,
            "text_tokens": u.text_out,
        },
    })
}

/// THE SECOND DIALECT — Gemini Live (`BidiGenerateContent`). Its codec maps the Gemini wire to/from
/// the SAME shared IR this file's [`OpenAiRealtimeCodec`] targets; earning the superset IR is exactly
/// what a second dialect does (§1.4). See [`gemini::GeminiLiveCodec`].
pub mod gemini;

#[cfg(test)]
mod tests;

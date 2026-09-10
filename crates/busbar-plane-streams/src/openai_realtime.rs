//! The OpenAI Realtime GA dialect: its wire reader/writer over the shared duplex IR.
//!
//! Every wire event of this dialect is a JSON object tagged on a `type` field. The reader parses a
//! frame to a `serde_json::Value` and hand-maps by `type` (serde-derive is reserved for the
//! `SessionConfig` object the IR holds); the writer builds the JSON back. One wire event maps to
//! 0..n IR events; a malformed or unrecognized frame yields an EMPTY vec (degrade, don't error),
//! except the dialect's own `error` event, which surfaces as `IrServerEvent::Error`.
//!
//! This module is the reader/writer that used to sit beside the IR in the codec crate. It moved here
//! BY IDENTITY — no arm, token or helper changed crossing the boundary — because the IR is what
//! every dialect maps into and this is one dialect's vocabulary: an instance named beside the IR was
//! the IR wearing that instance's shape. The IR, the reader/writer contract (`DuplexReader` /
//! `DuplexWriter`), the per-session `DecodeState` and the JSON/base64 helpers all stay in
//! `busbar_streams_codec::ir::codec`; this module names them and adds only its own event tokens.
//! Its home is this plane's dialect module — the sibling of [`crate::twilio`] — until the dialect
//! crate for it is minted, when it moves again by the same identity.

use busbar_streams_codec::ir::codec::{
    decode_media, encode_media, parse, session_config_lenient, str_at, wire_of, DecodeState,
    DuplexReader, DuplexWriter, WireEvent, WireRef,
};
use busbar_streams_codec::ir::control::IrDuplexControl;
use busbar_streams_codec::ir::event::{IrClientEvent, IrServerEvent};
use busbar_streams_codec::ir::media::{IrMediaFrame, IrMediaRef, MediaFormat, UpDown};
use busbar_streams_codec::ir::tool::IrDuplexTool;
use busbar_streams_codec::ir::usage::IrDuplexUsage;
use bytes::Bytes;
use serde_json::{json, Value};

/// The dialect wire `type` tokens — named once here so the reader's dispatch and the writer's framing
/// never drift. These are the plane's OWN vocabulary (it owns 100% of its protocol nouns, `plane4-duplex-session.md`).
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

/// The `u64` at `key`, or zero when absent or not a number.
fn u64_at(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or_default()
}

/// Read the item correlation this dialect states on a downlink audio event. Each field is carried only
/// when the wire actually said it — an absent field stays absent rather than becoming an empty string
/// or a zero index, which name a different (real) item.
fn audio_ref_of(v: &Value) -> IrMediaRef {
    let text = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let index = |k: &str| {
        v.get(k)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
    };
    IrMediaRef {
        response_id: text("response_id"),
        item_id: text("item_id"),
        output_index: index("output_index"),
        content_index: index("content_index"),
    }
}

/// THE OpenAI Realtime GA DIALECT CODEC — the plane's sole dialect today (`codec: None`, one wire
/// format, `plane4-duplex-session.md`). A unit struct: all per-session state lives in [`DecodeState`], so the codec itself
/// is stateless and shareable.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenAiRealtimeCodec;

impl DuplexReader for OpenAiRealtimeCodec {
    fn read_up_ref(&self, wire: WireRef<'_>, st: &mut DecodeState) -> Vec<IrClientEvent> {
        let Some(v) = parse(wire) else {
            return Vec::new();
        };
        let ty = str_at(&v, "type");
        match ty {
            wire::SESSION_UPDATE => {
                let cfg = v
                    .get("session")
                    .map(|s| session_config_lenient(s, st))
                    .unwrap_or_default();
                if let Some(fmt) = cfg.output_audio_format {
                    st.set_output_format(fmt);
                }
                vec![IrClientEvent::Control(IrDuplexControl::SessionConfigure {
                    config: cfg,
                })]
            }
            wire::INPUT_AUDIO_APPEND => {
                let Some(media) = decode_media(str_at(&v, "audio")) else {
                    return Vec::new();
                };
                vec![IrClientEvent::MediaFrame(IrMediaFrame {
                    dir: UpDown::Up,
                    seq: st.next_up_seq(),
                    media,
                    // The uplink append names no item — the item does not exist until the server
                    // makes one.
                    origin: IrMediaRef::default(),
                })]
            }
            wire::INPUT_AUDIO_COMMIT => {
                vec![IrClientEvent::Control(IrDuplexControl::UplinkCommit)]
            }
            wire::INPUT_AUDIO_CLEAR => {
                vec![IrClientEvent::Control(IrDuplexControl::UplinkClear)]
            }
            wire::ITEM_CREATE => {
                let item = v.get("item").cloned().unwrap_or(Value::Null);
                if str_at(&item, "type") == wire::ITEM_FN_CALL_OUTPUT {
                    let call_id = str_at(&item, "call_id");
                    let call_ref = st.ref_for_call_id(call_id);
                    let output = Bytes::from(str_at(&item, "output").to_owned().into_bytes());
                    // The dialect's own result item carries no tool name; the one the model announced
                    // is remembered per call id, for the dialects that require it.
                    let name = st.call_name(call_id).to_string();
                    vec![IrClientEvent::Tool(IrDuplexTool::CallResult {
                        call_ref,
                        call_id: call_id.to_string(),
                        name,
                        output,
                    })]
                } else {
                    vec![IrClientEvent::Control(IrDuplexControl::ItemInject { item })]
                }
            }
            wire::ITEM_TRUNCATE => {
                vec![IrClientEvent::Control(IrDuplexControl::ItemTruncate {
                    item_ref: str_at(&v, "item_id").to_string(),
                    // A wire value that does not fit takes the field's documented default (`0`),
                    // the same answer an ABSENT `content_index` gets. Narrowing with `as` would
                    // instead hand back a different, perfectly valid index into different content.
                    content_index: u32::try_from(u64_at(&v, "content_index")).unwrap_or(0),
                    played_ms: u64_at(&v, "audio_end_ms"),
                })]
            }
            wire::ITEM_DELETE => {
                vec![IrClientEvent::Control(IrDuplexControl::ItemRemove {
                    item_ref: str_at(&v, "item_id").to_string(),
                })]
            }
            wire::RESPONSE_CREATE => {
                let overrides = v.get("response").cloned();
                vec![IrClientEvent::Control(IrDuplexControl::TurnRequest {
                    overrides,
                })]
            }
            wire::RESPONSE_CANCEL => {
                vec![IrClientEvent::Control(IrDuplexControl::TurnCancel)]
            }
            _ => Vec::new(),
        }
    }

    fn read_down_ref(&self, wire: WireRef<'_>, st: &mut DecodeState) -> Vec<IrServerEvent> {
        let Some(v) = parse(wire) else {
            return Vec::new();
        };
        let ty = str_at(&v, "type");
        match ty {
            wire::SESSION_CREATED => {
                let session = v.get("session").cloned().unwrap_or(Value::Null);
                if let Some(fmt) = session
                    .get("output_audio_format")
                    .and_then(Value::as_str)
                    .and_then(MediaFormat::from_wire)
                {
                    st.set_output_format(fmt);
                }
                vec![IrServerEvent::SessionOpened { session }]
            }
            wire::SPEECH_STARTED => vec![IrServerEvent::ActivityStarted {
                at_ms: u64_at(&v, "audio_start_ms"),
                item_id: str_at(&v, "item_id").to_string(),
            }],
            wire::SPEECH_STOPPED => vec![IrServerEvent::ActivityStopped {
                at_ms: u64_at(&v, "audio_end_ms"),
                item_id: str_at(&v, "item_id").to_string(),
            }],
            wire::OUTPUT_AUDIO_DELTA | wire::OUTPUT_AUDIO_DELTA_LEGACY => {
                let Some(media) = decode_media(str_at(&v, "delta")) else {
                    return Vec::new();
                };
                st.record_played(media.len() as u64);
                vec![IrServerEvent::MediaFrame(IrMediaFrame {
                    dir: UpDown::Down,
                    seq: st.next_down_seq(),
                    media,
                    origin: audio_ref_of(&v),
                })]
            }
            wire::OUTPUT_AUDIO_DONE | wire::OUTPUT_AUDIO_DONE_LEGACY => {
                // THE ITEM BOUNDARY: this item's audio is complete, so the played-out position starts
                // over. Carrying it forward would truncate the NEXT turn at the running session total.
                st.reset_playback();
                vec![IrServerEvent::MediaDone {
                    item_id: str_at(&v, "item_id").to_string(),
                }]
            }
            wire::OUTPUT_ITEM_ADDED => {
                let item = v.get("item").cloned().unwrap_or(Value::Null);
                if str_at(&item, "type") == wire::ITEM_FN_CALL {
                    let call_id = str_at(&item, "call_id");
                    let call_ref = st.ref_for_call_id(call_id);
                    let name = str_at(&item, "name").to_string();
                    // Remember the name for the RESULT leg: OpenAI's `function_call_output` carries
                    // none, and a Gemini `functionResponse` requires one.
                    st.remember_call_name(call_id, &name);
                    // A tool-call item is NOT the playing audio item's boundary — it can be added
                    // while that item is still playing — so the playback position stands.
                    vec![IrServerEvent::Tool(IrDuplexTool::CallOpen {
                        call_ref,
                        call_id: call_id.to_string(),
                        name,
                    })]
                } else {
                    // A new AUDIO-BEARING output item begins: its playback starts at zero, even if the
                    // previous item's `…audio.done` never arrived.
                    st.reset_playback();
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
                let mut out = Vec::new();
                // THE COMPLETE ARGUMENTS THE CLOSE STATES. This dialect repeats the whole argument
                // string on the done event; a dialect that delivers the call atomically needs exactly
                // that, and a peer whose deltas were never seen (a session joined mid-call) has
                // nothing else. Dropping it dispatched the call with no arguments at all.
                let arguments = str_at(&v, "arguments");
                if !arguments.is_empty() {
                    out.push(IrServerEvent::Tool(IrDuplexTool::CallArgs {
                        call_ref,
                        call_id: call_id.to_string(),
                        json_delta: Bytes::from(arguments.to_owned().into_bytes()),
                    }));
                }
                out.push(IrServerEvent::Tool(IrDuplexTool::CallClose {
                    call_ref,
                    call_id: call_id.to_string(),
                }));
                out
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

/// Extract the split token classes from a `response.done.usage` object (`plane4-duplex-session.md` — audio vs text are
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
    /// The OpenAI Realtime dialect is the one every shared-IR concept was named from, so it frames
    /// EVERY client event — this writer never drops. It is also the dialect the shared IR's STREAMED
    /// tool call was named from, so it never accumulates: each fragment is already a frame here.
    fn write_up(&self, ev: IrClientEvent, _st: &mut DecodeState) -> Option<WireEvent> {
        let v = match ev {
            IrClientEvent::MediaFrame(f) => json!({
                "type": wire::INPUT_AUDIO_APPEND,
                "audio": encode_media(&f.media),
            }),
            IrClientEvent::Control(c) => match c {
                IrDuplexControl::SessionConfigure { config } => json!({
                    "type": wire::SESSION_UPDATE,
                    "session": config,
                }),
                IrDuplexControl::TurnRequest { overrides } => {
                    let mut o = json!({ "type": wire::RESPONSE_CREATE });
                    if let Some(r) = overrides {
                        o["response"] = r;
                    }
                    o
                }
                IrDuplexControl::TurnCancel => json!({ "type": wire::RESPONSE_CANCEL }),
                IrDuplexControl::UplinkCommit => json!({ "type": wire::INPUT_AUDIO_COMMIT }),
                IrDuplexControl::UplinkClear => json!({ "type": wire::INPUT_AUDIO_CLEAR }),
                IrDuplexControl::ItemInject { item } => json!({
                    "type": wire::ITEM_CREATE,
                    "item": item,
                }),
                IrDuplexControl::ItemRemove { item_ref } => json!({
                    "type": wire::ITEM_DELETE,
                    "item_id": item_ref,
                }),
                IrDuplexControl::ItemTruncate {
                    item_ref,
                    content_index,
                    played_ms,
                } => json!({
                    "type": wire::ITEM_TRUNCATE,
                    "item_id": item_ref,
                    "content_index": content_index,
                    "audio_end_ms": played_ms,
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
        Some(wire_of(&v))
    }

    /// Every server event is a frame in this dialect — the streamed shapes ARE its own — so this
    /// writer never answers `None`.
    fn write_down(&self, ev: IrServerEvent, _st: &mut DecodeState) -> Option<WireEvent> {
        let v = match ev {
            IrServerEvent::SessionOpened { session } => json!({
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
            IrServerEvent::ActivityStarted { at_ms, item_id } => json!({
                "type": wire::SPEECH_STARTED,
                "audio_start_ms": at_ms,
                "item_id": item_id,
            }),
            IrServerEvent::ActivityStopped { at_ms, item_id } => json!({
                "type": wire::SPEECH_STOPPED,
                "audio_end_ms": at_ms,
                "item_id": item_id,
            }),
            IrServerEvent::MediaFrame(f) => {
                // The item correlation the source dialect named rides back out — the client relays
                // through this writer even same-dialect, and a client that cannot name the item it is
                // hearing cannot truncate it when the user interrupts. What no source named is not
                // invented here.
                let mut o = json!({
                    "type": wire::OUTPUT_AUDIO_DELTA,
                    "delta": encode_media(&f.media),
                });
                if let Some(id) = &f.origin.response_id {
                    o["response_id"] = json!(id);
                }
                if let Some(id) = &f.origin.item_id {
                    o["item_id"] = json!(id);
                }
                if let Some(i) = f.origin.output_index {
                    o["output_index"] = json!(i);
                }
                if let Some(i) = f.origin.content_index {
                    o["content_index"] = json!(i);
                }
                o
            }
            IrServerEvent::MediaDone { item_id } => json!({
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
        Some(wire_of(&v))
    }
}

/// Re-frame the extracted token classes back onto a `usage` object (the inverse of [`extract_usage`]).
///
/// The sums SATURATE, matching `IrDuplexUsage::to_billing_usage`'s stated discipline ("a runaway
/// turn pins the count, never wraps small"): these counts came off an upstream `usage` object, and
/// a wrapped total is a small, believable number that is false.
fn usage_to_wire(u: &IrDuplexUsage) -> Value {
    json!({
        "total_tokens": u.audio_in
            .saturating_add(u.audio_out)
            .saturating_add(u.text_in)
            .saturating_add(u.text_out),
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

#[cfg(test)]
mod tests;

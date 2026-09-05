// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CODEC UNIT TESTS — the OpenAI Realtime GA dialect, round-tripped through the neutral IR.
//!
//! Each event family is exercised as wire JSON → IR → wire JSON and asserted STABLE at the
//! `serde_json::Value` level (field order irrelevant). Fixtures use captured-shape GA literals.

use super::*;
use crate::ir::config::MaxOutputTokens;
use crate::ir::control::{Eagerness, IrVad};
use crate::ir::media::UpDown;

// ── helpers ──────────────────────────────────────────────────────────────────────────────────────

fn wire(s: &str) -> WireEvent {
    WireEvent(Bytes::from(s.as_bytes().to_vec()))
}

fn as_value(w: &WireEvent) -> Value {
    serde_json::from_slice(&w.0).expect("codec emitted valid JSON")
}

fn b64(bytes: &[u8]) -> String {
    busbar_substrate_values::media::base64_encode(bytes)
}

/// Decode one client wire event, re-encode it, and assert the JSON is stable.
fn roundtrip_up(src: &Value) -> Vec<IrClientEvent> {
    let codec = OpenAiRealtimeCodec;
    let mut st = DecodeState::default();
    let ir = codec.read_up(wire(&src.to_string()), &mut st);
    assert_eq!(ir.len(), 1, "expected exactly one IR event from {src}");
    let back = codec.write_up(ir[0].clone());
    assert_eq!(as_value(&back), *src, "up round-trip not stable");
    ir
}

/// Decode one server wire event, re-encode it, and assert the JSON is stable.
fn roundtrip_down(src: &Value) -> Vec<IrServerEvent> {
    let codec = OpenAiRealtimeCodec;
    let mut st = DecodeState::default();
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    assert_eq!(ir.len(), 1, "expected exactly one IR event from {src}");
    let back = codec.write_down(ir[0].clone());
    assert_eq!(as_value(&back), *src, "down round-trip not stable");
    ir
}

// ── control: the GA session config shape ─────────────────────────────────────────────────────────

fn ga_session_server_vad() -> Value {
    json!({
        "type": "session.update",
        "session": {
            "modalities": ["audio", "text"],
            "instructions": "You are a helpful voice agent.",
            "voice": "marin",
            "input_audio_format": "pcm16",
            "output_audio_format": "g711_ulaw",
            "turn_detection": {
                "type": "server_vad",
                "threshold": 0.5,
                "prefix_padding_ms": 300,
                "silence_duration_ms": 200,
                "create_response": true,
                "interrupt_response": true
            },
            "tools": [{ "type": "function", "name": "lookup", "parameters": { "type": "object" } }],
            "tool_choice": "auto",
            "max_output_tokens": 4096
        }
    })
}

#[test]
fn session_update_server_vad_roundtrips_and_types() {
    let src = ga_session_server_vad();
    let ir = roundtrip_up(&src);
    let IrClientEvent::Control(IrDuplexControl::SessionConfigure { config }) = &ir[0] else {
        panic!("expected SessionConfigure, got {:?}", ir[0]);
    };
    assert_eq!(config.modalities, vec!["audio", "text"]);
    assert_eq!(
        config.instructions.as_deref(),
        Some("You are a helpful voice agent.")
    );
    assert_eq!(config.voice.as_deref(), Some("marin"));
    assert_eq!(config.input_audio_format, Some(AudioFormat::Pcm16));
    assert_eq!(config.output_audio_format, Some(AudioFormat::G711Ulaw));
    assert_eq!(config.max_output_tokens, Some(MaxOutputTokens::Limit(4096)));
    assert_eq!(config.tools.len(), 1);
    assert_eq!(
        config.tool_choice.as_ref().and_then(Value::as_str),
        Some("auto")
    );
    match &config.turn_detection {
        Some(IrVad::ServerVad {
            threshold,
            prefix_padding_ms,
            silence_duration_ms,
            create_response,
            interrupt_response,
        }) => {
            assert!((threshold - 0.5).abs() < f32::EPSILON);
            assert_eq!(*prefix_padding_ms, 300);
            assert_eq!(*silence_duration_ms, 200);
            assert!(create_response);
            assert!(interrupt_response);
        }
        other => panic!("expected server_vad, got {other:?}"),
    }
}

#[test]
fn session_update_semantic_vad_roundtrips() {
    let src = json!({
        "type": "session.update",
        "session": {
            "instructions": "hi",
            "turn_detection": { "type": "semantic_vad", "eagerness": "high" },
            "max_output_tokens": "inf"
        }
    });
    let ir = roundtrip_up(&src);
    let IrClientEvent::Control(IrDuplexControl::SessionConfigure { config }) = &ir[0] else {
        panic!("expected SessionConfigure");
    };
    assert_eq!(
        config.turn_detection,
        Some(IrVad::SemanticVad {
            eagerness: Eagerness::High
        })
    );
    assert_eq!(config.max_output_tokens, Some(MaxOutputTokens::Inf));
}

#[test]
fn session_update_null_turn_detection_disables_vad() {
    let src = json!({
        "type": "session.update",
        "session": { "instructions": "x", "turn_detection": null }
    });
    let ir = roundtrip_up(&src);
    let IrClientEvent::Control(IrDuplexControl::SessionConfigure { config }) = &ir[0] else {
        panic!();
    };
    assert_eq!(config.turn_detection, None);
}

#[test]
fn session_update_sets_decode_output_format() {
    let codec = OpenAiRealtimeCodec;
    let mut st = DecodeState::default();
    assert_eq!(st.output_format(), AudioFormat::Pcm16);
    let _ = codec.read_up(wire(&ga_session_server_vad().to_string()), &mut st);
    assert_eq!(
        st.output_format(),
        AudioFormat::G711Ulaw,
        "output_audio_format adopted"
    );
}

// ── control: the small verbs ─────────────────────────────────────────────────────────────────────

#[test]
fn control_small_verbs_roundtrip() {
    roundtrip_up(&json!({ "type": "input_audio_buffer.commit" }));
    roundtrip_up(&json!({ "type": "input_audio_buffer.clear" }));
    roundtrip_up(&json!({ "type": "response.cancel" }));
    roundtrip_up(&json!({ "type": "conversation.item.delete", "item_id": "item_7" }));
    roundtrip_up(&json!({
        "type": "response.create",
        "response": { "modalities": ["audio"], "instructions": "answer briefly" }
    }));
    roundtrip_up(&json!({
        "type": "conversation.item.create",
        "item": { "type": "message", "role": "user", "content": [{ "type": "input_text", "text": "hi" }] }
    }));
}

// ── media: audio framing (seq monotonic, base64) ─────────────────────────────────────────────────

#[test]
fn uplink_audio_append_decodes_base64_and_frames_up() {
    let payload = b"pretend-uplink-audio-bytes";
    let src = json!({ "type": "input_audio_buffer.append", "audio": b64(payload) });
    let ir = roundtrip_up(&src);
    let IrClientEvent::AudioFrame(f) = &ir[0] else {
        panic!("expected AudioFrame")
    };
    assert_eq!(f.dir, UpDown::Up);
    assert_eq!(&f.media[..], payload, "base64 decoded to the exact bytes");
}

#[test]
fn uplink_seq_is_monotonic_across_frames() {
    let codec = OpenAiRealtimeCodec;
    let mut st = DecodeState::default();
    let mk = |n: u8| {
        wire(&json!({ "type": "input_audio_buffer.append", "audio": b64(&[n]) }).to_string())
    };
    let seqs: Vec<u64> = (0..3)
        .map(|n| {
            let ir = codec.read_up(mk(n), &mut st);
            match &ir[0] {
                IrClientEvent::AudioFrame(f) => f.seq,
                _ => panic!(),
            }
        })
        .collect();
    assert_eq!(seqs, vec![0, 1, 2]);
}

#[test]
fn downlink_audio_delta_frames_down_tracks_playback_and_bumps_seq() {
    let codec = OpenAiRealtimeCodec;
    let mut st = DecodeState::default();
    st.set_output_format(AudioFormat::Pcm16); // 48 bytes/ms
    let payload = vec![0u8; 96]; // 96 bytes -> 2 ms
    let src = json!({ "type": "response.output_audio.delta", "delta": b64(&payload) });
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    let IrServerEvent::AudioFrame(f) = &ir[0] else {
        panic!("expected AudioFrame")
    };
    assert_eq!(f.dir, UpDown::Down);
    assert_eq!(f.seq, 0);
    assert_eq!(f.media.len(), 96);
    assert_eq!(st.played_ms(), 2, "96 bytes of pcm16 @ 24kHz is 2 ms");

    // A second delta advances the downlink seq and accumulates playback.
    let ir2 = codec.read_down(wire(&src.to_string()), &mut st);
    let IrServerEvent::AudioFrame(f2) = &ir2[0] else {
        panic!()
    };
    assert_eq!(f2.seq, 1);
    assert_eq!(st.played_ms(), 4);
}

#[test]
fn downlink_audio_delta_legacy_alias_decodes() {
    let codec = OpenAiRealtimeCodec;
    let mut st = DecodeState::default();
    let src = json!({ "type": "response.audio.delta", "delta": b64(b"x") });
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    assert!(matches!(&ir[0], IrServerEvent::AudioFrame(f) if f.dir == UpDown::Down));
}

// ── barge-in truncate math ───────────────────────────────────────────────────────────────────────

#[test]
fn audio_format_math() {
    assert_eq!(AudioFormat::Pcm16.bytes_per_ms(), 48);
    assert_eq!(AudioFormat::G711Ulaw.bytes_per_ms(), 8);
    assert_eq!(AudioFormat::Pcm16.bytes_to_ms(480), 10);
    assert_eq!(AudioFormat::Pcm16.ms_to_bytes(10), 480);
    assert_eq!(AudioFormat::G711Ulaw.bytes_to_ms(80), 10);
    assert_eq!(
        crate::ir::media::truncate_point_ms(480, AudioFormat::Pcm16),
        10
    );
}

#[test]
fn flush_playback_returns_heard_ms_and_resets() {
    let mut st = DecodeState::default();
    st.set_output_format(AudioFormat::Pcm16);
    st.record_played(48 * 500); // 500 ms played
    assert_eq!(st.played_ms(), 500);
    let heard = st.flush_playback();
    assert_eq!(heard, 500);
    assert_eq!(st.played_ms(), 0, "flush zeroes the playback counter");
}

#[test]
fn item_truncate_roundtrips_end_ms() {
    let src = json!({
        "type": "conversation.item.truncate",
        "item_id": "item_42",
        "content_index": 0,
        "audio_end_ms": 500
    });
    let ir = roundtrip_up(&src);
    let IrClientEvent::Control(IrDuplexControl::ItemTruncate {
        item_ref,
        content_index,
        audio_played_ms,
    }) = &ir[0]
    else {
        panic!("expected ItemTruncate");
    };
    assert_eq!(item_ref, "item_42");
    assert_eq!(*content_index, 0);
    assert_eq!(
        *audio_played_ms, 500,
        "wire audio_end_ms maps to plane audio_played_ms"
    );
}

/// A CONTENT INDEX THAT DOES NOT FIT MUST NOT BECOME A DIFFERENT, VALID INDEX.
///
/// `content_index` arrives from a CLIENT, which is untrusted input. Narrowing the wire `u64` with
/// `as u32` turns `4294967296` into `0` — a silently different, perfectly plausible index into a
/// different piece of content. Out of range means the field was not usable, and the honest answer
/// is the field's own documented default (`0`), reached deliberately rather than by wrap-around.
#[test]
fn an_out_of_range_content_index_falls_back_to_the_documented_default() {
    let codec = OpenAiRealtimeCodec;
    let mut st = DecodeState::default();
    for (wire_value, expect) in [(4_294_967_296u64, 0u32), (u64::MAX, 0), (7, 7)] {
        let ir = codec.read_up(
            wire(
                &json!({
                    "type": "conversation.item.truncate",
                    "item_id": "item_42",
                    "content_index": wire_value,
                    "audio_end_ms": 500
                })
                .to_string(),
            ),
            &mut st,
        );
        let IrClientEvent::Control(IrDuplexControl::ItemTruncate { content_index, .. }) = &ir[0]
        else {
            panic!("expected ItemTruncate");
        };
        assert_eq!(
            *content_index, expect,
            "content_index {wire_value} must not be truncated into a different valid index"
        );
    }
}

/// TOKEN SUMS SATURATE, THEY DO NOT WRAP.
///
/// The four counts come from an upstream `usage` object — untrusted bytes. The crate already states
/// this discipline in `IrDuplexUsage::to_billing_usage` ("a runaway turn pins the count, never
/// wraps small"); the client-facing re-frame must not answer differently, because a wrapped total
/// is a small, believable number that is simply false.
#[test]
fn usage_totals_saturate_rather_than_wrap() {
    let u = IrDuplexUsage {
        audio_in: u64::MAX,
        audio_out: 1,
        text_in: 1,
        text_out: 1,
        cached: 0,
    };
    let wire = usage_to_wire(&u);
    assert_eq!(
        wire["total_tokens"].as_u64(),
        Some(u64::MAX),
        "a total that cannot be represented pins at the ceiling; it never wraps to a small number"
    );
}

/// AUDIO THAT DOES NOT DECODE IS NOT SILENCE.
///
/// `base64_decode` returns `Option` deliberately — the substrate's own comment calls it the
/// fail-loud contract. Turning a `None` into an empty frame relays and meters a zero-length audio
/// frame that is indistinguishable from a caller saying nothing, which is the one thing a voice
/// plane must not confuse. No frame is the honest answer, exactly as the Twilio arm in this crate
/// already gives (`BadPayload` rather than an empty payload).
#[test]
fn an_undecodable_audio_payload_emits_no_frame() {
    let codec = OpenAiRealtimeCodec;
    let mut st = DecodeState::default();
    let up = codec.read_up(
        wire(&json!({ "type": "input_audio_buffer.append", "audio": "!!!!" }).to_string()),
        &mut st,
    );
    assert!(
        up.is_empty(),
        "an uplink audio payload that is not base64 must yield no IR frame, got {up:?}"
    );
    let down = codec.read_down(
        wire(&json!({ "type": "response.output_audio.delta", "delta": "!!!!" }).to_string()),
        &mut st,
    );
    assert!(
        down.is_empty(),
        "a downlink audio delta that is not base64 must yield no IR frame, got {down:?}"
    );
    assert_eq!(
        st.played_ms(),
        0,
        "a payload that never decoded must not advance the barge-in playback clock"
    );
    // Well-formed audio still flows, in both directions.
    assert_eq!(
        codec
            .read_up(
                wire(
                    &json!({ "type": "input_audio_buffer.append", "audio": b64(&[1, 2, 3, 4]) })
                        .to_string()
                ),
                &mut st,
            )
            .len(),
        1
    );
}

/// THE CALL-ID CORRELATION TABLE HAS A CEILING.
///
/// Nothing removes from it within a session — not even `conversation.item.delete` — so a client
/// that mints distinct `call_id`s grows it for as long as the call lasts. The table is a
/// correlation convenience, not a ledger: past the documented ceiling the OLDEST entry goes, and a
/// re-sighting of an evicted id correlates as a new call rather than keeping the map growing.
#[test]
fn the_call_id_table_is_capped_and_evicts_the_oldest() {
    let mut st = DecodeState::default();
    let first = st.ref_for_call_id("call-0");
    for i in 1..=MAX_TRACKED_CALL_IDS {
        st.ref_for_call_id(&format!("call-{i}"));
    }
    assert_eq!(
        st.call_ids.len(),
        MAX_TRACKED_CALL_IDS,
        "the table stays at its ceiling however many distinct call ids arrive"
    );
    assert!(
        !st.call_ids.contains_key("call-0"),
        "the OLDEST id is the one evicted"
    );
    assert_ne!(
        st.ref_for_call_id("call-0"),
        first,
        "an evicted id correlates as a new call rather than resurrecting its old handle"
    );
    // The most recent ids are still correlated, which is the whole point of keeping the table.
    let newest = format!("call-{MAX_TRACKED_CALL_IDS}");
    let handle = st.ref_for_call_id(&newest);
    assert_eq!(st.ref_for_call_id(&newest), handle);
}

// ── tools: correlation across the call loop ──────────────────────────────────────────────────────

#[test]
fn tool_call_loop_correlates_by_call_id() {
    let codec = OpenAiRealtimeCodec;
    let mut st = DecodeState::default();

    let open = codec.read_down(
        wire(
            &json!({
                "type": "response.output_item.added",
                "item": { "type": "function_call", "call_id": "call_abc", "name": "get_weather" }
            })
            .to_string(),
        ),
        &mut st,
    );
    let IrServerEvent::Tool(IrDuplexTool::CallOpen { call_ref, name, .. }) = &open[0] else {
        panic!("expected CallOpen");
    };
    let ref_open = *call_ref;
    assert_eq!(name, "get_weather");

    let args = codec.read_down(
        wire(
            &json!({
                "type": "response.function_call_arguments.delta",
                "call_id": "call_abc",
                "delta": "{\"city\":"
            })
            .to_string(),
        ),
        &mut st,
    );
    let IrServerEvent::Tool(IrDuplexTool::CallArgs {
        call_ref,
        json_delta,
        ..
    }) = &args[0]
    else {
        panic!("expected CallArgs");
    };
    assert_eq!(*call_ref, ref_open, "same call_id => same CallRef");
    assert_eq!(&json_delta[..], b"{\"city\":");

    let done = codec.read_down(
        wire(
            &json!({
                "type": "response.function_call_arguments.done",
                "call_id": "call_abc",
                "arguments": "{\"city\":\"SF\"}"
            })
            .to_string(),
        ),
        &mut st,
    );
    let IrServerEvent::Tool(IrDuplexTool::CallClose { call_ref, .. }) = &done[0] else {
        panic!("expected CallClose");
    };
    assert_eq!(*call_ref, ref_open);

    // A DISTINCT call_id mints a distinct ref.
    let other = codec.read_down(
        wire(
            &json!({
                "type": "response.function_call_arguments.delta",
                "call_id": "call_zzz",
                "delta": "{}"
            })
            .to_string(),
        ),
        &mut st,
    );
    let IrServerEvent::Tool(t) = &other[0] else {
        panic!()
    };
    assert_ne!(
        t.call_ref(),
        ref_open,
        "different call_id => different CallRef"
    );
}

#[test]
fn function_call_output_authoring_roundtrips() {
    // The plane authors a result (client->server) and it re-frames to function_call_output.
    let codec = OpenAiRealtimeCodec;
    let result = IrClientEvent::Tool(IrDuplexTool::CallResult {
        call_ref: CallRef(0),
        call_id: "call_abc".into(),
        output: Bytes::from_static(b"{\"temp\":72}"),
    });
    let w = codec.write_up(result);
    let v = as_value(&w);
    assert_eq!(v["type"], "conversation.item.create");
    assert_eq!(v["item"]["type"], "function_call_output");
    assert_eq!(v["item"]["call_id"], "call_abc");
    assert_eq!(v["item"]["output"], "{\"temp\":72}");

    // And decoding it back yields a CallResult with the same call_id.
    let mut st = DecodeState::default();
    let back = codec.read_up(w, &mut st);
    let IrClientEvent::Tool(IrDuplexTool::CallResult {
        call_id, output, ..
    }) = &back[0]
    else {
        panic!("expected CallResult");
    };
    assert_eq!(call_id, "call_abc");
    assert_eq!(&output[..], b"{\"temp\":72}");
}

// ── usage extraction (`plane4-duplex-session.md`) ──────────────────────────────────────────────────────────────────────

#[test]
fn response_done_usage_extracts_split_token_classes() {
    let codec = OpenAiRealtimeCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "type": "response.done",
        "response": {
            "usage": {
                "total_tokens": 150,
                "input_tokens": 100,
                "output_tokens": 50,
                "input_token_details": { "audio_tokens": 80, "text_tokens": 15, "cached_tokens": 5 },
                "output_token_details": { "audio_tokens": 40, "text_tokens": 10 }
            }
        }
    });
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    let IrServerEvent::Usage(u) = &ir[0] else {
        panic!("expected Usage")
    };
    assert_eq!(u.audio_in, 80);
    assert_eq!(u.text_in, 15);
    assert_eq!(u.cached, 5);
    assert_eq!(u.audio_out, 40);
    assert_eq!(u.text_out, 10);
}

// ── barge-in signals & session lifecycle ─────────────────────────────────────────────────────────

#[test]
fn speech_signals_roundtrip() {
    roundtrip_down(&json!({
        "type": "input_audio_buffer.speech_started",
        "audio_start_ms": 120,
        "item_id": "item_1"
    }));
    roundtrip_down(&json!({
        "type": "input_audio_buffer.speech_stopped",
        "audio_end_ms": 900,
        "item_id": "item_1"
    }));
}

#[test]
fn session_created_roundtrips_verbatim() {
    let src = json!({
        "type": "session.created",
        "session": { "id": "sess_1", "object": "realtime.session", "model": "gpt-realtime", "output_audio_format": "pcm16" }
    });
    let ir = roundtrip_down(&src);
    assert!(matches!(&ir[0], IrServerEvent::SessionCreated { .. }));
}

#[test]
fn audio_done_and_error_roundtrip() {
    roundtrip_down(&json!({ "type": "response.output_audio.done", "item_id": "item_9" }));
    roundtrip_down(&json!({
        "type": "error",
        "error": { "code": "rate_limit_exceeded", "message": "slow down" }
    }));
}

#[test]
fn error_event_maps_to_error_ir() {
    let codec = OpenAiRealtimeCodec;
    let mut st = DecodeState::default();
    let ir = codec.read_down(
        wire(&json!({ "type": "error", "error": { "code": "x", "message": "boom" } }).to_string()),
        &mut st,
    );
    assert!(
        matches!(&ir[0], IrServerEvent::Error { code, message } if code == "x" && message == "boom")
    );
}

// ── degrade, don't error ─────────────────────────────────────────────────────────────────────────

#[test]
fn malformed_or_unknown_frames_yield_empty_vec() {
    let codec = OpenAiRealtimeCodec;
    let mut st = DecodeState::default();
    assert!(codec.read_up(wire("not json"), &mut st).is_empty());
    assert!(codec.read_down(wire("{ broken"), &mut st).is_empty());
    assert!(codec
        .read_up(
            wire(&json!({ "type": "never.heard.of.it" }).to_string()),
            &mut st
        )
        .is_empty());
    assert!(codec
        .read_down(
            wire(&json!({ "type": "some.server.only.thing" }).to_string()),
            &mut st
        )
        .is_empty());
}

#[test]
fn usage_extraction_survives_reencode() {
    // Usage is extraction-only, but the writer can still frame a canonical response.done.
    let codec = OpenAiRealtimeCodec;
    let u = IrDuplexUsage {
        audio_in: 3,
        audio_out: 4,
        text_in: 1,
        text_out: 2,
        cached: 0,
    };
    let w = codec.write_down(IrServerEvent::Usage(u));
    let mut st = DecodeState::default();
    let ir = codec.read_down(w, &mut st);
    assert_eq!(ir[0], IrServerEvent::Usage(u));
}

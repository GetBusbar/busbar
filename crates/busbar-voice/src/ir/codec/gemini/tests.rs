// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CODEC UNIT TESTS — the Gemini Live (`BidiGenerateContent`) dialect, mapped through the SHARED
//! voice IR. Mirrors the OpenAI codec's suite: each event family is exercised wire JSON → IR → wire
//! JSON, asserted STABLE at the `serde_json::Value` level where the shapes permit byte carriage, and
//! FIXPOINT-STABLE at the IR level where the map is inherently lossy (setup). Fixtures use
//! captured-shape Gemini Live literals.

use super::*;
use crate::ir::config::MaxOutputTokens;
use crate::ir::control::IrVad;
use crate::ir::media::UpDown;
use crate::ir::tool::CallRef;

// ── helpers ──────────────────────────────────────────────────────────────────────────────────────

fn wire(s: &str) -> WireEvent {
    WireEvent(Bytes::from(s.as_bytes().to_vec()))
}

fn as_value(w: &WireEvent) -> Value {
    serde_json::from_slice(&w.0).expect("codec emitted valid JSON")
}

fn b64(bytes: &[u8]) -> String {
    busbar_substrate::media::base64_encode(bytes)
}

/// Decode one client wire event, re-encode it, and assert the JSON is BYTE-stable (one IR event).
fn roundtrip_up(src: &Value) -> Vec<IrClientEvent> {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let ir = codec.read_up(wire(&src.to_string()), &mut st);
    assert_eq!(ir.len(), 1, "expected exactly one IR event from {src}");
    let back = codec.write_up(ir[0].clone());
    assert_eq!(as_value(&back), *src, "up round-trip not stable");
    ir
}

/// Decode one server wire event, re-encode it, and assert the JSON is BYTE-stable (one IR event).
fn roundtrip_down(src: &Value) -> Vec<IrServerEvent> {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    assert_eq!(ir.len(), 1, "expected exactly one IR event from {src}");
    let back = codec.write_down(ir[0].clone());
    assert_eq!(as_value(&back), *src, "down round-trip not stable");
    ir
}

// ── setup ↔ SessionConfig (cross-dialect map: IR-fixpoint, not byte-stable) ───────────────────────

fn gemini_setup() -> Value {
    json!({
        "setup": {
            "model": "models/gemini-2.0-flash-exp",
            "generationConfig": {
                "responseModalities": ["AUDIO"],
                "speechConfig": {
                    "voiceConfig": { "prebuiltVoiceConfig": { "voiceName": "Puck" } }
                },
                "maxOutputTokens": 2048
            },
            "systemInstruction": { "parts": [{ "text": "You are a helpful voice agent." }] },
            "tools": [ { "functionDeclarations": [ { "name": "lookup", "parameters": { "type": "object" } } ] } ],
            "realtimeInputConfig": {
                "automaticActivityDetection": { "prefixPaddingMs": 300, "silenceDurationMs": 200 }
            }
        }
    })
}

#[test]
fn setup_maps_to_session_config_fields() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let ir = codec.read_up(wire(&gemini_setup().to_string()), &mut st);
    let IrClientEvent::Control(IrDuplexControl::SessionConfigure { config }) = &ir[0] else {
        panic!("expected SessionConfigure, got {:?}", ir[0]);
    };
    assert_eq!(config.model.as_deref(), Some("models/gemini-2.0-flash-exp"));
    assert_eq!(
        config.modalities,
        vec!["audio"],
        "AUDIO normalized to lowercase"
    );
    assert_eq!(config.voice.as_deref(), Some("Puck"));
    assert_eq!(
        config.instructions.as_deref(),
        Some("You are a helpful voice agent.")
    );
    assert_eq!(config.max_output_tokens, Some(MaxOutputTokens::Limit(2048)));
    assert_eq!(
        config.tools.len(),
        1,
        "Gemini functionDeclarations carried verbatim"
    );
    match &config.turn_detection {
        Some(IrVad::ServerVad {
            prefix_padding_ms,
            silence_duration_ms,
            ..
        }) => {
            assert_eq!(*prefix_padding_ms, 300);
            assert_eq!(*silence_duration_ms, 200);
        }
        other => panic!("expected ServerVad, got {other:?}"),
    }
}

#[test]
fn setup_is_ir_fixpoint_across_reencode() {
    // Setup is a genuine cross-dialect map (not verbatim), so it is a FIXPOINT at the IR level:
    // wire → IR → wire → IR yields the same SessionConfig.
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let ir = codec.read_up(wire(&gemini_setup().to_string()), &mut st);
    let IrClientEvent::Control(IrDuplexControl::SessionConfigure { config: cfg1 }) = &ir[0] else {
        panic!();
    };
    let back = codec.write_up(ir[0].clone());
    let ir2 = codec.read_up(back, &mut DecodeState::default());
    let IrClientEvent::Control(IrDuplexControl::SessionConfigure { config: cfg2 }) = &ir2[0] else {
        panic!();
    };
    assert_eq!(cfg1, cfg2, "setup is an IR fixpoint");
}

#[test]
fn setup_reencode_produces_gemini_shape() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let ir = codec.read_up(wire(&gemini_setup().to_string()), &mut st);
    let back = as_value(&codec.write_up(ir[0].clone()));
    let s = &back["setup"];
    assert_eq!(s["model"], "models/gemini-2.0-flash-exp");
    assert_eq!(
        s["generationConfig"]["responseModalities"][0], "AUDIO",
        "modalities re-uppercased to Gemini tokens"
    );
    assert_eq!(
        s["generationConfig"]["speechConfig"]["voiceConfig"]["prebuiltVoiceConfig"]["voiceName"],
        "Puck"
    );
    assert_eq!(s["generationConfig"]["maxOutputTokens"], 2048);
    assert_eq!(
        s["systemInstruction"]["parts"][0]["text"],
        "You are a helpful voice agent."
    );
    assert_eq!(
        s["realtimeInputConfig"]["automaticActivityDetection"]["prefixPaddingMs"],
        300
    );
}

#[test]
fn setup_adopts_pcm16_output_format() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let _ = codec.read_up(wire(&gemini_setup().to_string()), &mut st);
    assert_eq!(
        st.output_format(),
        AudioFormat::Pcm16,
        "Gemini downlink is 24kHz PCM"
    );
}

#[test]
fn setup_drops_unmapped_generation_params() {
    // Sampling knobs (temperature/topP/topK) have no shared home — the map drops them (asymmetry).
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "setup": {
            "model": "models/gemini-2.0-flash-exp",
            "generationConfig": { "responseModalities": ["AUDIO"], "temperature": 0.7, "topP": 0.9 }
        }
    });
    let ir = codec.read_up(wire(&src.to_string()), &mut st);
    let back = as_value(&codec.write_up(ir[0].clone()));
    assert!(back["setup"]["generationConfig"]
        .get("temperature")
        .is_none());
    assert!(back["setup"]["generationConfig"].get("topP").is_none());
}

#[test]
fn setup_disabled_activity_detection_maps_to_no_vad() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "setup": {
            "model": "m",
            "realtimeInputConfig": { "automaticActivityDetection": { "disabled": true } }
        }
    });
    let ir = codec.read_up(wire(&src.to_string()), &mut st);
    let IrClientEvent::Control(IrDuplexControl::SessionConfigure { config }) = &ir[0] else {
        panic!();
    };
    assert_eq!(
        config.turn_detection, None,
        "disabled AAD ⇒ client-driven turns"
    );
}

// ── clientContent (verbatim conversation turn) ────────────────────────────────────────────────────

#[test]
fn client_content_roundtrips_verbatim() {
    roundtrip_up(&json!({
        "clientContent": {
            "turns": [ { "role": "user", "parts": [ { "text": "hello" } ] } ],
            "turnComplete": true
        }
    }));
}

// ── realtimeInput (uplink audio framing) ──────────────────────────────────────────────────────────

#[test]
fn realtime_input_audio_decodes_and_frames_up() {
    let payload = b"pretend-uplink-audio-bytes";
    let src = json!({
        "realtimeInput": {
            "mediaChunks": [ { "mimeType": "audio/pcm;rate=16000", "data": b64(payload) } ]
        }
    });
    let ir = roundtrip_up(&src);
    let IrClientEvent::AudioFrame(f) = &ir[0] else {
        panic!("expected AudioFrame");
    };
    assert_eq!(f.dir, UpDown::Up);
    assert_eq!(&f.media[..], payload, "base64 decoded to the exact bytes");
}

#[test]
fn realtime_input_uplink_seq_is_monotonic() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let mk = |n: u8| {
        wire(
            &json!({ "realtimeInput": { "mediaChunks": [ { "mimeType": "audio/pcm;rate=16000", "data": b64(&[n]) } ] } })
                .to_string(),
        )
    };
    let seqs: Vec<u64> = (0..3)
        .map(|n| match &codec.read_up(mk(n), &mut st)[0] {
            IrClientEvent::AudioFrame(f) => f.seq,
            _ => panic!(),
        })
        .collect();
    assert_eq!(seqs, vec![0, 1, 2]);
}

#[test]
fn realtime_input_multiple_chunks_frame_each() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "realtimeInput": { "mediaChunks": [
            { "mimeType": "audio/pcm;rate=16000", "data": b64(b"a") },
            { "mimeType": "audio/pcm;rate=16000", "data": b64(b"b") }
        ] }
    });
    let ir = codec.read_up(wire(&src.to_string()), &mut st);
    assert_eq!(ir.len(), 2, "one frame per media chunk");
    assert!(matches!(&ir[1], IrClientEvent::AudioFrame(f) if f.seq == 1));
}

#[test]
fn realtime_input_ga_audio_blob_decodes_and_frames_up() {
    // GA (`v1beta`) shape: realtimeInput.audio is a SINGLE inline blob (not the legacy mediaChunks[]).
    let payload = b"ga-uplink-audio-bytes";
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "realtimeInput": { "audio": { "mimeType": "audio/pcm;rate=16000", "data": b64(payload) } }
    });
    let ir = codec.read_up(wire(&src.to_string()), &mut st);
    assert_eq!(ir.len(), 1, "one uplink frame from the GA audio blob");
    let IrClientEvent::AudioFrame(f) = &ir[0] else {
        panic!("expected AudioFrame");
    };
    assert_eq!(f.dir, UpDown::Up);
    assert_eq!(f.seq, 0);
    assert_eq!(&f.media[..], payload, "base64 decoded to the exact bytes");
}

#[test]
fn realtime_input_ga_audio_is_ir_fixpoint() {
    // The codec's uplink-audio guarantee is IR-fixpoint: decode GA audio → write → decode yields the
    // same frame (the stateless writer frames a universally-accepted realtimeInput shape).
    let payload = b"ga-fixpoint-audio";
    let codec = GeminiLiveCodec;
    let ir1 = codec.read_up(
        wire(
            &json!({ "realtimeInput": { "audio": { "mimeType": "audio/pcm;rate=16000", "data": b64(payload) } } })
                .to_string(),
        ),
        &mut DecodeState::default(),
    );
    let back = codec.write_up(ir1[0].clone());
    let ir2 = codec.read_up(back, &mut DecodeState::default());
    let (IrClientEvent::AudioFrame(f1), IrClientEvent::AudioFrame(f2)) = (&ir1[0], &ir2[0]) else {
        panic!("expected AudioFrame on both decodes");
    };
    assert_eq!(f1.dir, UpDown::Up);
    assert_eq!(
        f1.media, f2.media,
        "uplink audio survives the IR round-trip"
    );
    assert_eq!(&f2.media[..], payload);
}

#[test]
fn realtime_input_prefers_ga_audio_over_media_chunks() {
    // When BOTH spellings are present the GA single blob wins (one frame), so a GA peer never
    // double-decodes the same audio.
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "realtimeInput": {
            "audio": { "mimeType": "audio/pcm;rate=16000", "data": b64(b"ga") },
            "mediaChunks": [ { "mimeType": "audio/pcm;rate=16000", "data": b64(b"legacy") } ]
        }
    });
    let ir = codec.read_up(wire(&src.to_string()), &mut st);
    assert_eq!(
        ir.len(),
        1,
        "GA audio blob is preferred; mediaChunks not additionally decoded"
    );
    let IrClientEvent::AudioFrame(f) = &ir[0] else {
        panic!("expected AudioFrame");
    };
    assert_eq!(&f.media[..], b"ga");
}

#[test]
fn realtime_input_audio_stream_end_yields_no_ir() {
    // A GA manual end-of-stream marker has no shared IR home (documented drop+warn), even though the
    // realtimeInput envelope is recognized.
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let ir = codec.read_up(
        wire(&json!({ "realtimeInput": { "audioStreamEnd": true } }).to_string()),
        &mut st,
    );
    assert!(
        ir.is_empty(),
        "audioStreamEnd is dropped (no shared IR home)"
    );
}

// ── serverContent (downlink audio, turn/interrupt) ───────────────────────────────────────────────

#[test]
fn server_content_audio_frames_down_tracks_playback() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    st.set_output_format(AudioFormat::Pcm16); // 48 bytes/ms
    let payload = vec![0u8; 96]; // 2 ms
    let src = json!({
        "serverContent": { "modelTurn": { "parts": [
            { "inlineData": { "mimeType": "audio/pcm;rate=24000", "data": b64(&payload) } }
        ] } }
    });
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    let IrServerEvent::AudioFrame(f) = &ir[0] else {
        panic!("expected AudioFrame");
    };
    assert_eq!(f.dir, UpDown::Down);
    assert_eq!(f.seq, 0);
    assert_eq!(f.media.len(), 96);
    assert_eq!(st.played_ms(), 2, "96 bytes of pcm16 @24kHz is 2 ms");
}

#[test]
fn server_content_single_audio_part_roundtrips() {
    roundtrip_down(&json!({
        "serverContent": { "modelTurn": { "parts": [
            { "inlineData": { "mimeType": "audio/pcm;rate=24000", "data": b64(b"pcm") } }
        ] } }
    }));
}

#[test]
fn server_content_turn_complete_maps_audio_done() {
    let src = json!({ "serverContent": { "turnComplete": true } });
    let ir = roundtrip_down(&src);
    assert!(matches!(&ir[0], IrServerEvent::AudioDone { .. }));
}

#[test]
fn server_content_interrupted_maps_speech_started() {
    let src = json!({ "serverContent": { "interrupted": true } });
    let ir = roundtrip_down(&src);
    assert!(matches!(&ir[0], IrServerEvent::SpeechStarted { .. }));
}

#[test]
fn server_content_audio_then_turn_complete_is_multi_event() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "serverContent": {
            "modelTurn": { "parts": [
                { "inlineData": { "mimeType": "audio/pcm;rate=24000", "data": b64(b"aa") } },
                { "inlineData": { "mimeType": "audio/pcm;rate=24000", "data": b64(b"bb") } }
            ] },
            "turnComplete": true
        }
    });
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    assert_eq!(ir.len(), 3, "two audio frames + AudioDone");
    assert!(matches!(&ir[0], IrServerEvent::AudioFrame(_)));
    assert!(matches!(&ir[1], IrServerEvent::AudioFrame(_)));
    assert!(matches!(&ir[2], IrServerEvent::AudioDone { .. }));
}

// ── setupComplete ↔ SessionCreated ────────────────────────────────────────────────────────────────

#[test]
fn setup_complete_maps_session_created() {
    let src = json!({ "setupComplete": {} });
    let ir = roundtrip_down(&src);
    assert!(matches!(&ir[0], IrServerEvent::SessionCreated { .. }));
}

// ── tools: correlation across the expanded call loop ─────────────────────────────────────────────

#[test]
fn tool_call_expands_atomic_call_and_correlates() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "toolCall": { "functionCalls": [
            { "id": "fc_1", "name": "get_weather", "args": { "city": "SF" } }
        ] }
    });
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    assert_eq!(ir.len(), 3, "atomic Gemini call expands to open/args/close");

    let IrServerEvent::Tool(IrDuplexTool::CallOpen { call_ref, name, .. }) = &ir[0] else {
        panic!("expected CallOpen");
    };
    let ref_open = *call_ref;
    assert_eq!(name, "get_weather");

    let IrServerEvent::Tool(IrDuplexTool::CallArgs {
        call_ref,
        json_delta,
        ..
    }) = &ir[1]
    else {
        panic!("expected CallArgs");
    };
    assert_eq!(*call_ref, ref_open, "same id => same CallRef");
    let args: Value = serde_json::from_slice(json_delta).unwrap();
    assert_eq!(args, json!({ "city": "SF" }));

    let IrServerEvent::Tool(IrDuplexTool::CallClose { call_ref, .. }) = &ir[2] else {
        panic!("expected CallClose");
    };
    assert_eq!(*call_ref, ref_open);
}

#[test]
fn distinct_tool_call_ids_mint_distinct_refs() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "toolCall": { "functionCalls": [
            { "id": "fc_1", "name": "a", "args": {} },
            { "id": "fc_2", "name": "b", "args": {} }
        ] }
    });
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    // 2 calls × (open/args/close) = 6 events.
    assert_eq!(ir.len(), 6);
    let ref1 = match &ir[0] {
        IrServerEvent::Tool(t) => t.call_ref(),
        _ => panic!(),
    };
    let ref2 = match &ir[3] {
        IrServerEvent::Tool(t) => t.call_ref(),
        _ => panic!(),
    };
    assert_ne!(ref1, ref2, "different id => different CallRef");
}

#[test]
fn tool_call_open_writer_shape() {
    let codec = GeminiLiveCodec;
    let w = codec.write_down(IrServerEvent::Tool(IrDuplexTool::CallOpen {
        call_ref: CallRef(0),
        call_id: "fc_9".into(),
        name: "lookup".into(),
    }));
    let v = as_value(&w);
    assert_eq!(v["toolCall"]["functionCalls"][0]["id"], "fc_9");
    assert_eq!(v["toolCall"]["functionCalls"][0]["name"], "lookup");
}

#[test]
fn tool_response_maps_to_call_result_and_roundtrips() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "toolResponse": { "functionResponses": [
            { "id": "fc_1", "response": { "temp": 72 } }
        ] }
    });
    let ir = codec.read_up(wire(&src.to_string()), &mut st);
    let IrClientEvent::Tool(IrDuplexTool::CallResult {
        call_id, output, ..
    }) = &ir[0]
    else {
        panic!("expected CallResult");
    };
    assert_eq!(call_id, "fc_1");
    let payload: Value = serde_json::from_slice(output).unwrap();
    assert_eq!(payload, json!({ "temp": 72 }));

    // And it re-frames back to a Gemini toolResponse with the same id + payload.
    let back = as_value(&codec.write_up(ir[0].clone()));
    assert_eq!(back, src, "toolResponse round-trip is byte-stable");
}

// ── usageMetadata extraction (`plane4-duplex-session.md` §2.5) ──────────────────────────────────────────────────────────────

#[test]
fn usage_metadata_extracts_split_token_classes() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "usageMetadata": {
            "promptTokenCount": 95,
            "responseTokenCount": 50,
            "totalTokenCount": 145,
            "cachedContentTokenCount": 5,
            "promptTokensDetails": [
                { "modality": "AUDIO", "tokenCount": 80 },
                { "modality": "TEXT", "tokenCount": 15 }
            ],
            "responseTokensDetails": [
                { "modality": "AUDIO", "tokenCount": 40 },
                { "modality": "TEXT", "tokenCount": 10 }
            ]
        }
    });
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    let IrServerEvent::Usage(u) = &ir[0] else {
        panic!("expected Usage");
    };
    assert_eq!(u.audio_in, 80);
    assert_eq!(u.text_in, 15);
    assert_eq!(u.audio_out, 40);
    assert_eq!(u.text_out, 10);
    assert_eq!(u.cached, 5);
    // Re-encode is byte-stable against the canonical Gemini shape.
    let back = as_value(&codec.write_down(ir[0].clone()));
    assert_eq!(back, src);
}

// ── audio-format mime probe ──────────────────────────────────────────────────────────────────────

#[test]
fn audio_format_from_mime_probe() {
    assert_eq!(
        audio_format_from_mime("audio/pcm;rate=24000"),
        Some(AudioFormat::Pcm16)
    );
    assert_eq!(
        audio_format_from_mime("audio/pcm;rate=16000"),
        Some(AudioFormat::Pcm16)
    );
    assert_eq!(audio_format_from_mime("text/plain"), None);
    assert_eq!(audio_format_from_mime("video/mp4"), None);
}

// ── degrade, don't error (drop+warn asymmetries) ─────────────────────────────────────────────────

#[test]
fn transcription_and_unknown_frames_yield_empty_vec() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    // Output transcription is a side-channel with no shared IR home (drop).
    assert!(codec
        .read_down(
            wire(
                &json!({ "serverContent": { "outputTranscription": { "text": "hi" } } })
                    .to_string()
            ),
            &mut st
        )
        .is_empty());
    // toolCallCancellation, goAway have no shared IR home (drop).
    assert!(codec
        .read_down(
            wire(&json!({ "toolCallCancellation": { "ids": ["fc_1"] } }).to_string()),
            &mut st
        )
        .is_empty());
    assert!(codec
        .read_down(
            wire(&json!({ "goAway": { "timeLeft": "5s" } }).to_string()),
            &mut st
        )
        .is_empty());
    // Malformed / unknown top-level keys degrade to empty in both directions.
    assert!(codec.read_up(wire("not json"), &mut st).is_empty());
    assert!(codec.read_down(wire("{ broken"), &mut st).is_empty());
    assert!(codec
        .read_up(wire(&json!({ "neverHeardOfIt": {} }).to_string()), &mut st)
        .is_empty());
}

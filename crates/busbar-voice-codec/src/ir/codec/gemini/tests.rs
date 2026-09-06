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
use crate::ir::media::{IrAudioRef, UpDown};
use crate::ir::tool::CallRef;

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

/// Frame one client→server event, insisting the dialect HAS a verb for it. The uplink writer drops the
/// concepts Gemini has no word for; every use of this helper is a concept it does frame.
fn up<W: DuplexWriter>(codec: &W, ev: IrClientEvent) -> WireEvent {
    codec
        .write_up(ev, &mut DecodeState::default())
        .expect("the dialect frames this concept")
}

/// Frame one server→client event, insisting this event IS a frame. The downlink writer answers
/// nothing for a streamed tool-argument fragment (it is held for the atomic call); every use of this
/// helper is an event that frames on its own.
fn down<W: DuplexWriter>(codec: &W, ev: IrServerEvent) -> WireEvent {
    codec
        .write_down(ev, &mut DecodeState::default())
        .expect("the dialect frames this event")
}

/// Decode one client wire event, re-encode it, and assert the JSON is BYTE-stable (one IR event).
fn roundtrip_up(src: &Value) -> Vec<IrClientEvent> {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let ir = codec.read_up(wire(&src.to_string()), &mut st);
    assert_eq!(ir.len(), 1, "expected exactly one IR event from {src}");
    let back = up(&codec, ir[0].clone());
    assert_eq!(as_value(&back), *src, "up round-trip not stable");
    ir
}

/// Decode one server wire event, re-encode it, and assert the JSON is BYTE-stable (one IR event).
fn roundtrip_down(src: &Value) -> Vec<IrServerEvent> {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    assert_eq!(ir.len(), 1, "expected exactly one IR event from {src}");
    let back = down(&codec, ir[0].clone());
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
    let back = up(&codec, ir[0].clone());
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
    let back = as_value(&up(&codec, ir[0].clone()));
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

/// VAD TIMINGS THAT DO NOT FIT MUST NOT BECOME DIFFERENT, PLAUSIBLE TIMINGS.
///
/// `prefixPaddingMs` / `silenceDurationMs` come off an upstream `setup` — untrusted bytes. `as u32`
/// turns `4294967296` into `0`, i.e. "no padding at all", which is a working configuration that
/// nobody asked for. A value that does not fit is a value that was not usable, so it takes the same
/// documented default an ABSENT field takes.
#[test]
fn out_of_range_vad_timings_fall_back_to_their_documented_defaults() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let mut setup = gemini_setup();
    setup["setup"]["realtimeInputConfig"]["automaticActivityDetection"]["prefixPaddingMs"] =
        json!(4_294_967_296u64);
    setup["setup"]["realtimeInputConfig"]["automaticActivityDetection"]["silenceDurationMs"] =
        json!(u64::MAX);
    let ir = codec.read_up(wire(&setup.to_string()), &mut st);
    let IrClientEvent::Control(IrDuplexControl::SessionConfigure { config }) = &ir[0] else {
        panic!("expected SessionConfigure");
    };
    let Some(IrVad::ServerVad {
        prefix_padding_ms,
        silence_duration_ms,
        ..
    }) = config.turn_detection
    else {
        panic!("expected server VAD");
    };
    assert_eq!(
        prefix_padding_ms, 300,
        "an unrepresentable prefixPaddingMs takes the documented default, not a wrapped 0"
    );
    assert_eq!(
        silence_duration_ms, 200,
        "an unrepresentable silenceDurationMs takes the documented default, not a wrapped 0"
    );
}

/// The Gemini `usageMetadata` sums add the same untrusted upstream counts the OpenAI re-frame does,
/// and must pin at the ceiling for the same reason: a wrapped total is a small number that is false.
#[test]
fn usage_metadata_totals_saturate_rather_than_wrap() {
    let u = IrDuplexUsage {
        audio_in: u64::MAX,
        audio_out: u64::MAX,
        text_in: 1,
        text_out: 1,
        cached: 0,
    };
    let meta = usage_to_metadata(&u);
    assert_eq!(meta["promptTokenCount"].as_u64(), Some(u64::MAX));
    assert_eq!(meta["responseTokenCount"].as_u64(), Some(u64::MAX));
    assert_eq!(meta["totalTokenCount"].as_u64(), Some(u64::MAX));
}

/// Gemini's two audio read paths — the uplink `realtimeInput` blob and the downlink
/// `serverContent.modelTurn` inline data — must drop an undecodable payload rather than relay an
/// empty frame, the same answer the OpenAI paths give.
#[test]
fn an_undecodable_gemini_audio_payload_emits_no_frame() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let up = codec.read_up(
        wire(
            &json!({
                "realtimeInput": { "audio": { "mimeType": "audio/pcm;rate=16000", "data": "!!!!" } }
            })
            .to_string(),
        ),
        &mut st,
    );
    assert!(up.is_empty(), "expected no uplink frame, got {up:?}");
    let down = codec.read_down(
        wire(
            &json!({
                "serverContent": { "modelTurn": { "parts": [
                    { "inlineData": { "mimeType": "audio/pcm;rate=24000", "data": "!!!!" } }
                ] } }
            })
            .to_string(),
        ),
        &mut st,
    );
    assert!(
        !down
            .iter()
            .any(|e| matches!(e, IrServerEvent::AudioFrame(_))),
        "expected no downlink audio frame, got {down:?}"
    );
    assert_eq!(
        st.played_ms(),
        0,
        "a payload that never decoded must not advance the barge-in playback clock"
    );
}

#[test]
fn an_unreadable_output_token_cap_is_a_recorded_drop_not_a_lifted_cap() {
    // A cap that does not fit is not "no cap". Silently dropping it hands the session an UNBOUNDED
    // response where the client asked for a bounded one — the one direction a limit must never move.
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let mut setup = gemini_setup();
    setup["setup"]["generationConfig"]["maxOutputTokens"] = json!(5_000_000_000u64);
    let ir = codec.read_up(wire(&setup.to_string()), &mut st);
    let IrClientEvent::Control(IrDuplexControl::SessionConfigure { config }) = &ir[0] else {
        panic!("expected SessionConfigure");
    };
    assert_eq!(config.max_output_tokens, None, "the cap does not survive");
    assert!(
        st.dropped_fields().contains(&"maxOutputTokens"),
        "and its loss is recorded, not silent: {:?}",
        st.dropped_fields()
    );
    // The rest of the session still stands — one field is dropped, never the whole setup.
    assert_eq!(config.voice.as_deref(), Some("Puck"));
    assert_eq!(
        config.instructions.as_deref(),
        Some("You are a helpful voice agent.")
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
    let back = as_value(&up(&codec, ir[0].clone()));
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
    // The LEGACY `mediaChunks[]` spelling is still read (a peer may speak it); it re-frames onto the
    // GA `realtimeInput.audio` blob, so the guarantee here is IR-fixpoint, not byte carriage.
    let payload = b"pretend-uplink-audio-bytes";
    let codec = GeminiLiveCodec;
    let src = json!({
        "realtimeInput": {
            "mediaChunks": [ { "mimeType": "audio/pcm;rate=16000", "data": b64(payload) } ]
        }
    });
    let ir = codec.read_up(wire(&src.to_string()), &mut DecodeState::default());
    assert_eq!(ir.len(), 1);
    let IrClientEvent::AudioFrame(f) = &ir[0] else {
        panic!("expected AudioFrame");
    };
    assert_eq!(f.dir, UpDown::Up);
    assert_eq!(&f.media[..], payload, "base64 decoded to the exact bytes");
    let ir2 = codec.read_up(up(&codec, ir[0].clone()), &mut DecodeState::default());
    let IrClientEvent::AudioFrame(f2) = &ir2[0] else {
        panic!("expected AudioFrame");
    };
    assert_eq!(f.media, f2.media, "the audio survives the re-frame");
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
    let back = up(&codec, ir1[0].clone());
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
fn uplink_audio_is_framed_as_the_ga_blob_stating_its_true_rate() {
    // The writer frames the GA `realtimeInput.audio` SINGLE blob (the shape this codec's own reader
    // prefers), not the legacy `mediaChunks[]` array — and the mime states the rate the bytes are
    // ACTUALLY in (the session's negotiated pcm16 = 24 kHz), never a rate they are not.
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    st.set_output_format(AudioFormat::Pcm16);
    let w = codec
        .write_up(
            IrClientEvent::AudioFrame(IrAudioFrame {
                dir: UpDown::Up,
                seq: 0,
                media: Bytes::from_static(b"uplink-pcm"),
                origin: IrAudioRef::default(),
            }),
            &mut st,
        )
        .expect("uplink audio frames");
    let ri = &as_value(&w)["realtimeInput"];
    assert!(ri["audio"].is_object(), "the GA single blob: {ri}");
    assert!(ri["mediaChunks"].is_null(), "not the legacy array: {ri}");
    let mime = ri["audio"]["mimeType"].as_str().unwrap_or_default();
    assert!(
        !mime.contains("rate=16000"),
        "pcm16 bytes are 24 kHz; the mime must not claim 16 kHz: {mime}"
    );
    assert_eq!(mime, "audio/pcm;rate=24000");
    // And the codec reads its own frame back to the same bytes.
    let ir = codec.read_up(w, &mut DecodeState::default());
    let IrClientEvent::AudioFrame(f) = &ir[0] else {
        panic!("expected AudioFrame");
    };
    assert_eq!(&f.media[..], b"uplink-pcm");
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
fn realtime_input_audio_stream_end_maps_to_input_audio_commit() {
    // Gemini's manual end-of-uplink marker is the cross-dialect twin of OpenAI's discrete
    // `input_audio_buffer.commit`; it maps to the shared `IrDuplexControl::InputAudioCommit` so the
    // "end the buffered uplink turn" concept survives cross-dialect rather than dropping.
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let ir = codec.read_up(
        wire(&json!({ "realtimeInput": { "audioStreamEnd": true } }).to_string()),
        &mut st,
    );
    assert_eq!(
        ir.len(),
        1,
        "audioStreamEnd yields exactly the commit control"
    );
    assert!(
        matches!(
            &ir[0],
            IrClientEvent::Control(IrDuplexControl::InputAudioCommit)
        ),
        "audioStreamEnd maps to InputAudioCommit, got {:?}",
        ir[0]
    );
}

#[test]
fn realtime_input_audio_and_stream_end_yields_frame_then_commit() {
    // A frame carrying BOTH an audio blob and the end marker decodes to the audio frame followed by
    // the commit — the audio is buffered, then the turn is ended.
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let ir = codec.read_up(
        wire(
            &json!({ "realtimeInput": {
                "audio": { "mimeType": "audio/pcm;rate=16000", "data": b64(b"hi") },
                "audioStreamEnd": true
            } })
            .to_string(),
        ),
        &mut st,
    );
    assert_eq!(ir.len(), 2, "expected audio frame then commit, got {ir:?}");
    assert!(matches!(&ir[0], IrClientEvent::AudioFrame(_)));
    assert!(matches!(
        &ir[1],
        IrClientEvent::Control(IrDuplexControl::InputAudioCommit)
    ));
}

#[test]
fn input_audio_commit_round_trips_to_audio_stream_end() {
    // The encode side is the mirror: InputAudioCommit → `realtimeInput.audioStreamEnd` → decode back
    // to InputAudioCommit (IR-fixpoint stable), the property the conformance harness now asserts.
    let codec = GeminiLiveCodec;
    let framed = up(
        &codec,
        IrClientEvent::Control(IrDuplexControl::InputAudioCommit),
    );
    let mut st = DecodeState::default();
    let back = codec.read_up(framed, &mut st);
    assert_eq!(back.len(), 1);
    assert!(matches!(
        &back[0],
        IrClientEvent::Control(IrDuplexControl::InputAudioCommit)
    ));
}

#[test]
fn the_uplink_verbs_gemini_has_no_word_for_frame_nothing() {
    // The map's asymmetry rows: cancel/clear/delete/truncate/per-response-overrides are DROPPED toward
    // Gemini. An empty `realtimeInput` frame is not a drop — it is a real message that carries none of
    // the cancel semantics and would be sent upstream as if the concept had survived.
    let codec = GeminiLiveCodec;
    for ev in [
        IrDuplexControl::ResponseCancel,
        IrDuplexControl::InputAudioClear,
        IrDuplexControl::ItemDelete {
            item_ref: "item_1".into(),
        },
        IrDuplexControl::ItemTruncate {
            item_ref: "item_1".into(),
            content_index: 0,
            audio_played_ms: 240,
        },
        IrDuplexControl::ResponseCreate { response: None },
    ] {
        assert!(
            codec
                .write_up(
                    IrClientEvent::Control(ev.clone()),
                    &mut DecodeState::default()
                )
                .is_none(),
            "{ev:?} has no Gemini verb and must frame nothing"
        );
    }
    // The concepts Gemini DOES have still frame.
    assert!(codec
        .write_up(
            IrClientEvent::Control(IrDuplexControl::InputAudioCommit),
            &mut DecodeState::default()
        )
        .is_some());
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

#[test]
fn the_gemini_turn_boundary_resets_the_playback_position() {
    // `turnComplete` IS Gemini's item boundary; the next turn's barge-in must truncate at the audio of
    // THAT turn, not at the session's running total.
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    st.set_output_format(AudioFormat::Pcm16); // 48 bytes/ms
    let turn = |ms: usize| {
        json!({
            "serverContent": {
                "modelTurn": { "parts": [ { "inlineData": {
                    "mimeType": "audio/pcm;rate=24000", "data": b64(&vec![0u8; 48 * ms])
                } } ] }
            }
        })
        .to_string()
    };
    let _ = codec.read_down(wire(&turn(1000)), &mut st);
    let _ = codec.read_down(
        wire(&json!({ "serverContent": { "turnComplete": true } }).to_string()),
        &mut st,
    );
    assert_eq!(st.played_ms(), 0, "turnComplete zeroes the played position");
    let _ = codec.read_down(wire(&turn(240)), &mut st);
    assert_eq!(st.flush_playback(), 240, "this turn's audio only");
}

#[test]
fn a_downlink_blob_at_the_uplink_rate_is_not_counted_as_playback() {
    // The playback position is BYTES ÷ the negotiated format's bytes-per-ms, and `pcm16` means
    // 24 kHz (48 B/ms). A downlink blob tagged 16 kHz is not that format: counted at 48 B/ms it
    // reports two thirds of the audio it is, and the barge-in truncate cuts the user off mid-word.
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "serverContent": { "modelTurn": { "parts": [
            { "inlineData": { "mimeType": "audio/pcm;rate=16000", "data": b64(&vec![0u8; 480]) } }
        ] } }
    });
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    assert!(
        ir.is_empty(),
        "a downlink blob at a rate this dialect does not synthesize has no frame: {ir:?}"
    );
    assert_eq!(
        st.played_ms(),
        0,
        "and nothing it carried was accounted as played"
    );
    // The 24 kHz downlink the dialect DOES synthesize still counts.
    let ok = json!({
        "serverContent": { "modelTurn": { "parts": [
            { "inlineData": { "mimeType": "audio/pcm;rate=24000", "data": b64(&vec![0u8; 480]) } }
        ] } }
    });
    assert_eq!(codec.read_down(wire(&ok.to_string()), &mut st).len(), 1);
    assert_eq!(st.played_ms(), 10, "480 bytes at 48 B/ms");
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
fn a_result_bridged_to_gemini_names_the_originating_call() {
    // Gemini REQUIRES `functionResponse.name`; OpenAI's `function_call_output` does not carry one, so
    // the name is remembered from the call that opened and travels on the result.
    let oa = crate::ir::codec::OpenAiRealtimeCodec;
    let ge = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let _ = oa.read_down(
        wire(
            &json!({
                "type": "response.output_item.added",
                "item": { "type": "function_call", "call_id": "call_abc", "name": "get_weather" }
            })
            .to_string(),
        ),
        &mut st,
    );
    let ir = oa.read_up(
        wire(
            &json!({
                "type": "conversation.item.create",
                "item": {
                    "type": "function_call_output",
                    "call_id": "call_abc",
                    "output": "{\"temp\":72}"
                }
            })
            .to_string(),
        ),
        &mut st,
    );
    let bridged = as_value(&up(&ge, ir[0].clone()));
    let fr = &bridged["toolResponse"]["functionResponses"][0];
    assert_eq!(fr["id"], "call_abc");
    assert_eq!(
        fr["name"], "get_weather",
        "the originating tool name rides the result"
    );
    assert_eq!(fr["response"], json!({ "temp": 72 }));
}

#[test]
fn a_gemini_tool_response_keeps_its_name_across_the_round_trip() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "toolResponse": { "functionResponses": [
            { "id": "fc_1", "name": "get_weather", "response": { "temp": 72 } }
        ] }
    });
    let ir = codec.read_up(wire(&src.to_string()), &mut st);
    let IrClientEvent::Tool(IrDuplexTool::CallResult { name, .. }) = &ir[0] else {
        panic!("expected CallResult");
    };
    assert_eq!(name, "get_weather");
    assert_eq!(
        as_value(&up(&codec, ir[0].clone())),
        src,
        "name survives the re-frame"
    );
}

#[test]
fn tool_call_open_writer_shape() {
    let codec = GeminiLiveCodec;
    let w = down(
        &codec,
        IrServerEvent::Tool(IrDuplexTool::CallOpen {
            call_ref: CallRef(0),
            call_id: "fc_9".into(),
            name: "lookup".into(),
        }),
    );
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
    let back = as_value(&up(&codec, ir[0].clone()));
    assert_eq!(back, src, "toolResponse round-trip is byte-stable");
}

#[test]
fn a_tool_that_answered_a_non_object_still_answers_an_object_on_this_wire() {
    // Gemini's `functionResponse.response` is a STRUCT — an object — while the dialect the shared IR
    // was named from carries a tool's output as a free-form string. So a tool that answered a bare
    // JSON scalar has to be wrapped, and the literal `null` is the case that matters most: written
    // straight through it tells the model the tool returned NOTHING, which is a different answer from
    // the one the tool gave, and it is the confusion this seam's own contract refuses.
    let codec = GeminiLiveCodec;
    for (output, expected) in [
        (&b"null"[..], json!({ "result": Value::Null })),
        (&b"72"[..], json!({ "result": 72 })),
        (&b"true"[..], json!({ "result": true })),
        (&b"[1,2]"[..], json!({ "result": [1, 2] })),
        (&b"\"ok\""[..], json!({ "result": "ok" })),
    ] {
        let w = up(
            &codec,
            IrClientEvent::Tool(IrDuplexTool::CallResult {
                call_ref: CallRef(0),
                call_id: "fc_1".into(),
                name: String::new(),
                output: Bytes::from(output.to_vec()),
            }),
        );
        let response = as_value(&w)["toolResponse"]["functionResponses"][0]["response"].clone();
        assert!(
            response.is_object(),
            "this dialect's response member is an object, got {response}"
        );
        assert_eq!(response, expected);
    }
}

// ── usageMetadata extraction (`plane4-duplex-session.md`) ──────────────────────────────────────────────────────────────

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
    let back = as_value(&down(&codec, ir[0].clone()));
    assert_eq!(back, src);
}

#[test]
fn a_gemini_turn_that_reports_only_totals_is_still_metered() {
    // `promptTokensDetails` breaks `promptTokenCount` out by modality; it is a detail OF that count,
    // not the count itself. A `usageMetadata` that states the counts and omits the breakdown has still
    // said what the turn cost, and reading only the breakdown meters it at zero. Same rule as the
    // sibling dialect, so a turn prices the same whichever wire carried it.
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "usageMetadata": {
            "promptTokenCount": 95,
            "responseTokenCount": 50,
            "totalTokenCount": 145
        }
    });
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    let IrServerEvent::Usage(u) = &ir[0] else {
        panic!("expected Usage");
    };
    let billed = u.to_billing_usage();
    assert_eq!(
        billed.usage_units.get(busbar_api::UNIT_INPUT).copied(),
        Some(95),
        "the reported prompt total bills, breakdown or no breakdown"
    );
    assert_eq!(
        billed.usage_units.get(busbar_api::UNIT_OUTPUT).copied(),
        Some(50)
    );
}

#[test]
fn a_partial_gemini_breakdown_is_not_topped_up_from_the_totals() {
    // Present breakdown wins, even where it does not sum to the stated count: reconciling the two
    // means picking which of the provider's own numbers is true, and picking high bills a caller for
    // tokens no modality claims.
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "usageMetadata": {
            "promptTokenCount": 500,
            "responseTokenCount": 50,
            "promptTokensDetails": [ { "modality": "AUDIO", "tokenCount": 80 } ],
            "responseTokensDetails": [ { "modality": "AUDIO", "tokenCount": 40 } ]
        }
    });
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    let IrServerEvent::Usage(u) = &ir[0] else {
        panic!("expected Usage");
    };
    assert_eq!(u.audio_in, 80);
    assert_eq!(
        u.text_in, 0,
        "the detail stands; the count does not top it up"
    );
    assert_eq!(u.audio_out, 40);
    assert_eq!(u.text_out, 0);
}

#[test]
fn cached_content_tokens_are_not_billed_twice() {
    // Gemini reports `cachedContentTokenCount` as a SUBSET of `promptTokenCount` (cached content IS
    // part of the prompt), and `promptTokensDetails` is that same prompt broken out by modality. So
    // the billing fold must bill the UNCACHED remainder as `input` and the cached portion as
    // `cache_read` — the same netting the OpenAI dialect needs, not a per-dialect divergence.
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let src = json!({
        "usageMetadata": {
            "promptTokenCount": 1000,
            "responseTokenCount": 0,
            "totalTokenCount": 1000,
            "cachedContentTokenCount": 800,
            "promptTokensDetails": [
                { "modality": "AUDIO", "tokenCount": 1000 },
                { "modality": "TEXT", "tokenCount": 0 }
            ],
            "responseTokensDetails": []
        }
    });
    let ir = codec.read_down(wire(&src.to_string()), &mut st);
    let IrServerEvent::Usage(u) = &ir[0] else {
        panic!("expected Usage");
    };
    // Extraction stays wire-faithful.
    assert_eq!(u.audio_in, 1000);
    assert_eq!(u.cached, 800);
    let billed = u.to_billing_usage();
    assert_eq!(
        billed.usage_units.get(busbar_api::UNIT_INPUT).copied(),
        Some(200),
        "input bills the UNCACHED remainder of the prompt (1000 - 800)"
    );
    assert_eq!(
        billed.usage_units.get(busbar_api::UNIT_CACHE_READ).copied(),
        Some(800),
        "the cached subset bills once, on the cache-read lane"
    );
    assert_eq!(
        billed.usage_units.values().sum::<u64>(),
        1000,
        "the billed lanes sum to the turn's prompt, never to 1800"
    );
}

// ── audio-format mime probe ──────────────────────────────────────────────────────────────────────

#[test]
fn audio_format_from_mime_probe() {
    // Uplink: either PCM rate is the shared token (no millisecond count is taken from the uplink).
    assert_eq!(
        audio_format_from_mime("audio/pcm;rate=24000", UpDown::Up),
        Some(AudioFormat::Pcm16)
    );
    assert_eq!(
        audio_format_from_mime("audio/pcm;rate=16000", UpDown::Up),
        Some(AudioFormat::Pcm16)
    );
    // Downlink: only the rate the shared token actually means — the truncate math divides by it.
    assert_eq!(
        audio_format_from_mime("audio/pcm;rate=24000", UpDown::Down),
        Some(AudioFormat::Pcm16)
    );
    assert_eq!(
        audio_format_from_mime("audio/pcm;rate=16000", UpDown::Down),
        None,
        "a 16 kHz downlink blob is not the 24 kHz format the position is measured in"
    );
    // An untagged `audio/pcm` is the direction's own rate.
    assert_eq!(
        audio_format_from_mime("audio/pcm", UpDown::Down),
        Some(AudioFormat::Pcm16)
    );
    for dir in [UpDown::Up, UpDown::Down] {
        assert_eq!(audio_format_from_mime("text/plain", dir), None);
        assert_eq!(audio_format_from_mime("video/mp4", dir), None);
    }
}

#[test]
fn the_media_type_is_matched_whole_not_as_a_prefix() {
    // `audio/PCMU` is G.711 µ-law's OWN registered media type, and it begins with `audio/pcm`. Admitted
    // as the shared `Pcm16` token, its bytes are measured at 48 bytes per millisecond instead of 8 —
    // six times short — so the next barge-in truncates a turn the caller is still six-sevenths of the
    // way through. `audio/pcma` (A-law) is the same trap.
    for dir in [UpDown::Up, UpDown::Down] {
        assert_eq!(
            audio_format_from_mime("audio/PCMU", dir),
            None,
            "µ-law is not the 24 kHz PCM the truncate math measures in"
        );
        assert_eq!(audio_format_from_mime("audio/pcma", dir), None);
        assert_eq!(audio_format_from_mime("audio/pcm-whatever", dir), None);
    }
}

#[test]
fn the_rate_is_read_as_a_parameter_not_looked_for_as_a_substring() {
    // `rate=240000` CONTAINS `rate=24000` and is a different rate — ten times the samples per
    // millisecond, so a downlink blob admitted on that spelling meters ten times long and the truncate
    // point runs past the end of what was heard.
    assert_eq!(
        audio_format_from_mime("audio/pcm;rate=240000", UpDown::Down),
        None
    );
    assert_eq!(
        audio_format_from_mime("audio/pcm;rate=160000", UpDown::Up),
        None
    );
    // A parameter list with the rate somewhere other than first still resolves, and whitespace after
    // the separator is a parameter list, not a different type.
    assert_eq!(
        audio_format_from_mime("audio/pcm; codecs=x; rate=24000", UpDown::Down),
        Some(AudioFormat::Pcm16)
    );
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

#[test]
fn a_streamed_argument_fragment_never_dispatches_a_call_without_its_arguments() {
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let call = st.ref_for_call_id("fc_frag");
    let frag = |s: &str| {
        IrServerEvent::Tool(IrDuplexTool::CallArgs {
            call_ref: call,
            call_id: "fc_frag".into(),
            json_delta: Bytes::from(s.as_bytes().to_vec()),
        })
    };
    let mut frames = Vec::new();
    for piece in [r#"{"loc"#, r#"ation":"SF"}"#] {
        // A FRAGMENT IS NOT A FRAME: parsed alone it is not JSON, and framing it dispatched the tool
        // with `args: null` — arguments the model never asked for.
        assert!(
            codec.write_down(frag(piece), &mut st).is_none(),
            "an argument fragment frames nothing on its own"
        );
    }
    frames.push(as_value(
        &codec
            .write_down(
                IrServerEvent::Tool(IrDuplexTool::CallClose {
                    call_ref: call,
                    call_id: "fc_frag".into(),
                }),
                &mut st,
            )
            .expect("the closed call frames once, whole"),
    ));
    assert_eq!(frames.len(), 1, "exactly one toolCall for the whole call");
    let fc = &frames[0]["toolCall"]["functionCalls"][0];
    assert_eq!(fc["id"], "fc_frag");
    assert_eq!(fc["args"], json!({ "location": "SF" }));
    assert!(!fc["args"].is_null(), "never a null argument list");
}

#[test]
fn a_free_form_tool_output_reaches_the_wire_carrying_its_text() {
    // The OpenAI dialect's `function_call_output.output` is a FREE-FORM STRING: a tool that answers
    // `OK` is answering. Relayed as `response: null` the model was told the tool returned nothing.
    let codec = GeminiLiveCodec;
    let w = up(
        &codec,
        IrClientEvent::Tool(IrDuplexTool::CallResult {
            call_ref: CallRef(0),
            call_id: "fc_plain".into(),
            name: "restart".into(),
            output: Bytes::from_static(b"OK"),
        }),
    );
    let fr = &as_value(&w)["toolResponse"]["functionResponses"][0];
    assert!(
        !fr["response"].is_null(),
        "the tool's answer is not nothing"
    );
    assert_eq!(fr["response"], json!({ "result": "OK" }));
}

#[test]
fn a_json_tool_output_still_rides_as_the_object_it_is() {
    let codec = GeminiLiveCodec;
    let w = up(
        &codec,
        IrClientEvent::Tool(IrDuplexTool::CallResult {
            call_ref: CallRef(0),
            call_id: "fc_json".into(),
            name: "get_weather".into(),
            output: Bytes::from_static(br#"{"temp":72}"#),
        }),
    );
    let fr = &as_value(&w)["toolResponse"]["functionResponses"][0];
    assert_eq!(fr["response"], json!({ "temp": 72 }));
}

#[test]
fn a_tool_call_whose_arguments_never_parse_frames_nothing() {
    // The other half of the same rule: when the accumulated whole is still not readable JSON, the
    // call is not dispatched at all — an unreadable argument list is not an empty one.
    let codec = GeminiLiveCodec;
    let mut st = DecodeState::default();
    let call = st.ref_for_call_id("fc_torn");
    assert!(codec
        .write_down(
            IrServerEvent::Tool(IrDuplexTool::CallArgs {
                call_ref: call,
                call_id: "fc_torn".into(),
                json_delta: Bytes::from_static(br#"{"location":"S"#),
            }),
            &mut st
        )
        .is_none());
    assert!(
        codec
            .write_down(
                IrServerEvent::Tool(IrDuplexTool::CallClose {
                    call_ref: call,
                    call_id: "fc_torn".into(),
                }),
                &mut st
            )
            .is_none(),
        "a call whose arguments never became whole frames nothing"
    );
}

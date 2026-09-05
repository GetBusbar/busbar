//! Codec-path tests: fixtures decode to the expected turn units, interrupt facts and pacing facts.
//!
//! The OpenAI `session.update` fixture below restates (does not literally `include!`, because the
//! entry point shape differs — busbar-voice's own test calls `OpenAiRealtimeCodec::read_up`
//! directly, this one calls `VoicePlane::decode_ingress`) the fixture at
//! `crates/busbar-voice/src/ir/codec/tests.rs::ga_session_server_vad` (lines 52-74 at the time of
//! writing). The audio-frame and `session.created`/usage fixtures are built from the same wire
//! `type` tokens `crates/busbar-voice/src/ir/codec/mod.rs`'s `wire` module names
//! (`input_audio_buffer.append`, `session.created`, `response.done`).

use busbar_contract::bounded::{Facts, Labels};
use busbar_contract::ids::LaneId;
use busbar_contract::plane::{Ingress, Plane, PlaneSessionState, Progress, SessionPlane};
use busbar_contract::wire::FrameCursor;
use serde_json::json;

use crate::claims::Dialect;
use crate::tests::harness::{ctx, destination, frame, EmptyConfig, LeakArena, WsStack};
use crate::{Upstream, VoicePlane};

fn openai_plane() -> VoicePlane {
    static UPSTREAMS: &[Upstream] = &[Upstream {
        lane: LaneId::new("realtime"),
        host: "api.openai.com",
        dialect: Dialect::OpenaiRealtime,
    }];
    VoicePlane::new(UPSTREAMS)
}

fn open_client_session(
    plane: &VoicePlane,
    ctx: &busbar_contract::unit::Ctx<'_>,
) -> PlaneSessionState {
    SessionPlane::open_session(plane, ctx)
}

fn client_wire(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

/// The `session.update` fixture restated from `busbar-voice`'s own `ga_session_server_vad` fixture
/// (`crates/busbar-voice/src/ir/codec/tests.rs`, lines 52-74).
fn session_update_fixture() -> Vec<u8> {
    serde_json::to_vec(&json!({
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
    }))
    .expect("fixture serializes")
}

#[test]
fn session_update_opens_a_turn_and_names_the_dialect() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut state = open_client_session(&plane, &c);

    let bytes = client_wire(&session_update_fixture());
    let frames = [frame(&bytes)];
    let mut cursor = FrameCursor::new(&frames);

    let ingress = plane
        .decode_ingress(&mut cursor, Some(&mut state), &c)
        .expect("session.update decodes");
    let Ingress::Open(draft) = ingress else {
        panic!("expected Ingress::Open, got {ingress:?}");
    };
    assert_eq!(draft.op.as_str(), "duplex_turn");
    assert_eq!(
        draft.facts.get(crate::meta::FACT_DIALECT),
        Some(busbar_contract::bounded::FactValue::Str("openai-realtime"))
    );
    assert!(draft.correlation_out.is_some());
}

#[test]
fn a_second_frame_of_the_same_turn_relays_rather_than_reopens() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut state = open_client_session(&plane, &c);

    let first = client_wire(&session_update_fixture());
    let frames1 = [frame(&first)];
    let mut cursor1 = FrameCursor::new(&frames1);
    let ingress1 = plane
        .decode_ingress(&mut cursor1, Some(&mut state), &c)
        .expect("first frame decodes");
    assert!(matches!(ingress1, Ingress::Open(_)));

    let audio = serde_json::to_vec(&json!({
        "type": "input_audio_buffer.append",
        "audio": "AAAA",
    }))
    .expect("audio fixture serializes");
    let frames2 = [frame(&audio)];
    let mut cursor2 = FrameCursor::new(&frames2);
    let ingress2 = plane
        .decode_ingress(&mut cursor2, Some(&mut state), &c)
        .expect("second frame decodes");
    let Ingress::Frame { for_, .. } = ingress2 else {
        panic!("expected Ingress::Frame, got {ingress2:?}");
    };
    assert!(
        for_.is_some(),
        "the relay frame must carry the turn's correlation"
    );
}

#[test]
fn client_truncate_writes_the_declared_interrupt_fact() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut state = open_client_session(&plane, &c);

    let truncate = serde_json::to_vec(&json!({
        "type": "conversation.item.truncate",
        "item_id": "item_1",
        "content_index": 0,
        "audio_end_ms": 640,
    }))
    .expect("truncate fixture serializes");
    let frames = [frame(&truncate)];
    let mut cursor = FrameCursor::new(&frames);
    let ingress = plane
        .decode_ingress(&mut cursor, Some(&mut state), &c)
        .expect("truncate decodes");
    let Ingress::Open(draft) = ingress else {
        panic!("expected Ingress::Open (first frame of the turn), got {ingress:?}");
    };
    assert_eq!(
        draft
            .facts
            .get(<VoicePlane as busbar_contract::plane::PlaneMeta>::INTERRUPT_FACT.unwrap()),
        Some(busbar_contract::bounded::FactValue::Int(640))
    );
}

#[test]
fn upstream_speech_started_synthesizes_the_interrupt_fact_from_playback_position() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut upstream_state = SessionPlane::open_upstream(
        &plane,
        &destination("api.openai.com", LaneId::new("realtime")),
        &c,
    );

    // Two downlink audio deltas totalling 96 bytes of pcm16 (48 bytes/ms) = 2 ms played, then a
    // speech-started barge-in signal.
    let delta = serde_json::to_vec(&json!({
        "type": "response.output_audio.delta",
        "delta": base64_of(&[0u8; 96]),
    }))
    .unwrap();
    let started = serde_json::to_vec(&json!({
        "type": "input_audio_buffer.speech_started",
        "audio_start_ms": 0,
        "item_id": "item_1",
    }))
    .unwrap();

    let frames1 = [frame(&delta)];
    let mut cursor1 = FrameCursor::new(&frames1);
    let _ = plane
        .decode_response(
            &mut cursor1,
            &destination("api.openai.com", LaneId::new("realtime")),
            Some(&mut upstream_state),
            &c,
        )
        .expect("audio delta decodes");

    let frames2 = [frame(&started)];
    let mut cursor2 = FrameCursor::new(&frames2);
    let progress = plane
        .decode_response(
            &mut cursor2,
            &destination("api.openai.com", LaneId::new("realtime")),
            Some(&mut upstream_state),
            &c,
        )
        .expect("speech_started decodes");
    let Progress::Frame { r, .. } = progress else {
        panic!("expected Progress::Frame, got {progress:?}");
    };
    assert_eq!(
        r.facts
            .get(<VoicePlane as busbar_contract::plane::PlaneMeta>::INTERRUPT_FACT.unwrap()),
        Some(busbar_contract::bounded::FactValue::Int(2))
    );
}

#[test]
fn downlink_audio_frames_carry_the_declared_pacing_fact() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut upstream_state = SessionPlane::open_upstream(
        &plane,
        &destination("api.openai.com", LaneId::new("realtime")),
        &c,
    );

    let delta = serde_json::to_vec(&json!({
        "type": "response.output_audio.delta",
        "delta": base64_of(&[0u8; 48]),
    }))
    .unwrap();
    let frames = [frame(&delta)];
    let mut cursor = FrameCursor::new(&frames);
    let progress = plane
        .decode_response(
            &mut cursor,
            &destination("api.openai.com", LaneId::new("realtime")),
            Some(&mut upstream_state),
            &c,
        )
        .expect("audio delta decodes");
    let Progress::Frame { r, .. } = progress else {
        panic!("expected Progress::Frame, got {progress:?}");
    };
    assert_eq!(
        r.facts
            .get(<VoicePlane as busbar_contract::plane::PlaneMeta>::EGRESS_PACING_FACT.unwrap()),
        Some(busbar_contract::bounded::FactValue::Int(1))
    );
}

#[test]
fn a_tool_call_open_surfaces_as_progress_one_shot() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut upstream_state = SessionPlane::open_upstream(
        &plane,
        &destination("api.openai.com", LaneId::new("realtime")),
        &c,
    );

    let opened = serde_json::to_vec(&json!({
        "type": "response.output_item.added",
        "item": { "type": "function_call", "call_id": "call_1", "name": "lookup" },
    }))
    .unwrap();
    let frames = [frame(&opened)];
    let mut cursor = FrameCursor::new(&frames);
    let progress = plane
        .decode_response(
            &mut cursor,
            &destination("api.openai.com", LaneId::new("realtime")),
            Some(&mut upstream_state),
            &c,
        )
        .expect("tool-call open decodes");
    let Progress::OneShot(draft) = progress else {
        panic!("expected Progress::OneShot, got {progress:?}");
    };
    assert_eq!(draft.op.as_str(), "tool_call");
    assert_eq!(
        draft.facts.get(crate::meta::FACT_TOOL_NAME),
        Some(busbar_contract::bounded::FactValue::Str("lookup"))
    );
}

#[test]
fn usage_closes_the_turn_and_meter_reads_every_declared_class() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut upstream_state = SessionPlane::open_upstream(
        &plane,
        &destination("api.openai.com", LaneId::new("realtime")),
        &c,
    );

    let done = serde_json::to_vec(&json!({
        "type": "response.done",
        "response": {
            "usage": {
                "input_token_details": { "audio_tokens": 10, "text_tokens": 3, "cached_tokens": 1 },
                "output_token_details": { "audio_tokens": 20, "text_tokens": 4 },
            }
        }
    }))
    .unwrap();
    let frames = [frame(&done)];
    let mut cursor = FrameCursor::new(&frames);
    let unit_dest = destination("api.openai.com", LaneId::new("realtime"));
    let progress = plane
        .decode_response(&mut cursor, &unit_dest, Some(&mut upstream_state), &c)
        .expect("response.done decodes");
    let Progress::Terminal { r, .. } = progress else {
        panic!("expected Progress::Terminal, got {progress:?}");
    };
    assert_eq!(r.finish, busbar_contract::unit::FinishClass::TurnComplete);

    let body = Facts::new();
    let _ = body;
    let unit =
        crate::tests::harness::unit(busbar_contract::ids::OpClassId::new("duplex_turn"), r.ir);
    let locators = plane.meter(&unit, &r, &c);
    let classes: Vec<&str> = locators
        .lines
        .as_slice()
        .iter()
        .map(|l| l.class.as_str())
        .collect();
    for expected in [
        "audio_tokens_in",
        "audio_tokens_out",
        "text_tokens",
        "cached_tokens",
        "audio_seconds_in",
    ] {
        assert!(
            classes.contains(&expected),
            "expected meter class {expected} in {classes:?}"
        );
    }
}

#[test]
fn twilio_media_after_start_admits_a_ulaw_audio_frame() {
    static UPSTREAMS: &[Upstream] = &[Upstream {
        lane: LaneId::new("realtime"),
        host: "api.openai.com",
        dialect: Dialect::OpenaiRealtime,
    }];
    let plane = VoicePlane::new(UPSTREAMS);
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/twilio/call-123");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut state = SessionPlane::open_session(&plane, &c);

    let start = serde_json::to_vec(&json!({
        "event": "start",
        "start": {
            "streamSid": "MZ123",
            "callSid": "CA123",
            "mediaFormat": { "encoding": "audio/x-mulaw", "sampleRate": 8000, "channels": 1 },
        },
    }))
    .unwrap();
    let frames1 = [frame(&start)];
    let mut cursor1 = FrameCursor::new(&frames1);
    let ingress1 = plane
        .decode_ingress(&mut cursor1, Some(&mut state), &c)
        .expect("start decodes");
    assert!(matches!(ingress1, Ingress::Discard { .. }));

    let media = serde_json::to_vec(&json!({
        "event": "media",
        "streamSid": "MZ123",
        "media": { "payload": base64_of(&[0xFFu8; 4]) },
    }))
    .unwrap();
    let frames2 = [frame(&media)];
    let mut cursor2 = FrameCursor::new(&frames2);
    let ingress2 = plane
        .decode_ingress(&mut cursor2, Some(&mut state), &c)
        .expect("media decodes");
    assert!(matches!(ingress2, Ingress::Open(_)));
}

#[test]
fn twilio_media_with_a_forged_stream_sid_is_discarded() {
    static UPSTREAMS: &[Upstream] = &[Upstream {
        lane: LaneId::new("realtime"),
        host: "api.openai.com",
        dialect: Dialect::OpenaiRealtime,
    }];
    let plane = VoicePlane::new(UPSTREAMS);
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/twilio/call-123");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut state = SessionPlane::open_session(&plane, &c);

    let start = serde_json::to_vec(&json!({
        "event": "start",
        "start": {
            "streamSid": "MZ-bound",
            "callSid": "CA123",
            "mediaFormat": { "encoding": "audio/x-mulaw", "sampleRate": 8000, "channels": 1 },
        },
    }))
    .unwrap();
    let frames1 = [frame(&start)];
    let mut cursor1 = FrameCursor::new(&frames1);
    let _ = plane
        .decode_ingress(&mut cursor1, Some(&mut state), &c)
        .expect("start decodes");

    let media = serde_json::to_vec(&json!({
        "event": "media",
        "streamSid": "MZ-forged",
        "media": { "payload": base64_of(&[0xFFu8; 4]) },
    }))
    .unwrap();
    let frames2 = [frame(&media)];
    let mut cursor2 = FrameCursor::new(&frames2);
    let ingress2 = plane
        .decode_ingress(&mut cursor2, Some(&mut state), &c)
        .expect("media decodes");
    assert!(matches!(
        ingress2,
        Ingress::Discard {
            reason: busbar_contract::wire::DiscardCode::ForgedSource
        }
    ));
}

/// A tiny standard base64 encoder, independent of the one this crate's `twilio` module carries, so
/// the test fixtures above do not depend on that module's own correctness to construct their input.
fn base64_of(bytes: &[u8]) -> String {
    use base64_stdlib::encode;
    encode(bytes)
}

mod base64_stdlib {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = u32::from(chunk[0]);
            let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
            let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[((n >> 6) & 63) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(n & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }
}

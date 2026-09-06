//! Codec-path tests: fixtures decode to the expected turn units, interrupt facts and pacing facts.
//!
//! The OpenAI `session.update` fixture below restates (does not literally `include!`, because the
//! entry point shape differs — busbar-voice's own test calls `OpenAiRealtimeCodec::read_up`
//! directly, this one calls `VoicePlane::decode_ingress`) the fixture at
//! `crates/busbar-voice/src/ir/codec/tests.rs::ga_session_server_vad` (lines 52-74 at the time of
//! writing). The audio-frame and `session.created`/usage fixtures are built from the same wire
//! `type` tokens `crates/busbar-voice/src/ir/codec/mod.rs`'s `wire` module names
//! (`input_audio_buffer.append`, `session.created`, `response.done`).

use busbar_contract::bounded::{FactValue, Facts, Labels};
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

/// Two tool calls open at once are two different things to wait on.
///
/// A turn that asks for two tools opens two units, and each waits for its own reply. The reply leg
/// used to name the constant zero for every one of them, so the two were indistinguishable: the
/// first reply satisfied whichever leg was found first, and the second call waited out its whole
/// deadline against an answer that had already been delivered elsewhere.
///
/// What the leg names is the declared KEY; what tells the two calls apart is the identifier the
/// draft mints under it, in the unit's own arena, as itself. This plane states neither twice — it
/// no longer folds the identifier into a number to get a copy of it onto the sealed leg.
#[test]
fn two_open_tool_calls_wait_on_two_different_correlations() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let dest = destination("api.openai.com", LaneId::new("realtime"));
    let mut upstream_state = SessionPlane::open_upstream(&plane, &dest, &c);

    let open_call = |call_id: &str| {
        serde_json::to_vec(&json!({
            "type": "response.output_item.added",
            "item": { "type": "function_call", "call_id": call_id, "name": "lookup" },
        }))
        .unwrap()
    };

    let mut waits_on = |call_id: &str| {
        let opened = open_call(call_id);
        let frames = [frame(&opened)];
        let mut cursor = FrameCursor::new(&frames);
        let Progress::OneShot(draft) = plane
            .decode_response(&mut cursor, &dest, Some(&mut upstream_state), &c)
            .expect("tool-call open decodes")
        else {
            panic!("a tool-call open is its own unit");
        };
        let out = draft
            .correlation_out
            .expect("a tool call mints a correlation");
        // The draft's own correlation carries the identifier itself, not a fold of it.
        assert_eq!(
            out.value,
            busbar_contract::ids::CorrelationValue::Str(call_id)
        );
        let unit = crate::tests::harness::unit(draft.op, draft.body_ir, draft.facts);
        match plane.verify(&unit, &c) {
            busbar_contract::dest::DestinationFacts::Client {
                mode:
                    busbar_contract::dest::ClientMode::AwaitReply {
                        correlation_key, ..
                    },
                ..
            } => {
                // The leg names the key the draft minted under. If those two ever disagreed the
                // kernel would have a wait it could never satisfy.
                assert_eq!(correlation_key, out.fact_key);
                format!("{:?}", out.value)
            }
            other => panic!("a tool call is delivered to the client, got {other:?}"),
        }
    };

    let first = waits_on("call_1");
    let second = waits_on("call_2");
    assert_ne!(
        first, second,
        "two open tool calls waited on the same correlation"
    );
    assert_eq!(
        second,
        waits_on("call_2"),
        "the same call named two different correlations"
    );
}

/// A tool reply names the call it answers, not the turn it arrived on.
///
/// The reply is the other half of the leg the call planned. Decoded as an ordinary frame of the
/// open turn it named the turn's correlation, so the identifier the waiting unit was entered under
/// never reached the frame at all — the wait and its answer went past each other on one session,
/// and the call expired holding a reservation for an answer that had already come back.
#[test]
fn a_client_tool_reply_names_the_call_it_answers() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut state = open_client_session(&plane, &c);

    // The turn is open first, so "it relayed onto the turn" is a live alternative rather than
    // something the fixture ruled out.
    let opening = client_wire(&session_update_fixture());
    let frames = [frame(&opening)];
    let mut cursor = FrameCursor::new(&frames);
    let opened = plane
        .decode_ingress(&mut cursor, Some(&mut state), &c)
        .expect("the turn opens");
    let Ingress::Open(turn) = opened else {
        panic!("expected Ingress::Open, got {opened:?}");
    };
    let turn_correlation = turn.correlation_out.expect("a turn correlates");

    let reply = serde_json::to_vec(&json!({
        "type": "conversation.item.create",
        "item": {
            "type": "function_call_output",
            "call_id": "call_2",
            "output": "{\"tide\":\"out\"}",
        },
    }))
    .expect("the reply fixture serializes");
    let frames = [frame(&reply)];
    let mut cursor = FrameCursor::new(&frames);
    let answered = plane
        .decode_ingress(&mut cursor, Some(&mut state), &c)
        .expect("a tool reply decodes");
    let Ingress::Frame { for_, facts, .. } = answered else {
        panic!("expected Ingress::Frame, got {answered:?}");
    };
    let for_ = for_.expect("a reply carries the correlation it answers");
    assert_eq!(
        for_.fact_key,
        crate::plane::FACT_TOOL_CORRELATION,
        "under the key the call's own leg named"
    );
    assert_eq!(
        for_.value,
        busbar_contract::ids::CorrelationValue::Str("call_2"),
        "and carrying the identifier itself"
    );
    assert_ne!(
        for_.value, turn_correlation.value,
        "a reply that named the turn would wake no tool call at all"
    );
    assert_eq!(
        facts.get(crate::meta::FACT_CALL_ID),
        Some(FactValue::Str("call_2"))
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

    let unit = crate::tests::harness::unit(
        busbar_contract::ids::OpClassId::new("duplex_turn"),
        r.ir,
        Facts::new(),
    );
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
        "text_tokens_in",
        "text_tokens_out",
        "cached_tokens",
        "audio_seconds_in",
    ] {
        assert!(
            classes.contains(&expected),
            "expected meter class {expected} in {classes:?}"
        );
    }

    // The point of the split, asserted as a quantity and not just as a label: the fixture reports
    // three text tokens consumed and four emitted, and the two land on different classes at their
    // reported figures. Summed into one input-direction class -- which is what this plane used to do
    // -- the emitted four would have priced at the input rate.
    let quantity = |class: &str| {
        locators
            .lines
            .as_slice()
            .iter()
            .find(|l| l.class.as_str() == class)
            .and_then(|l| l.quantity)
    };
    assert_eq!(quantity("text_tokens_in"), Some(3));
    assert_eq!(quantity("text_tokens_out"), Some(4));
    // The audio split is the one that moves real money -- audio prices well above text on every
    // realtime rate card -- so it is asserted the same way: the fixture reports ten audio tokens
    // consumed and twenty emitted, and swapping the two directions has to be a failure here rather
    // than a label that still reads as present.
    assert_eq!(quantity("audio_tokens_in"), Some(10));
    assert_eq!(quantity("audio_tokens_out"), Some(20));
    // The cached figure is a DISCOUNT, so a class reported at the wrong figure overcharges a caller
    // for input it was already billed for.
    assert_eq!(quantity("cached_tokens"), Some(1));
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
    // The dialect is bound directly rather than resolved from the path. The telephony CLAIM is
    // gone — its transport has no crate — so no selector maps `/twilio/...` onto this dialect any
    // more; the CODEC is what this cell is about and it is untouched. Binding the state here is
    // what an arrival on a registered telephony transport would do.
    let mut state = PlaneSessionState::new(crate::session::VoiceSessionState::for_dialect(
        Dialect::TwilioMediaStreams,
    ));

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
    // The dialect is bound directly rather than resolved from the path. The telephony CLAIM is
    // gone — its transport has no crate — so no selector maps `/twilio/...` onto this dialect any
    // more; the CODEC is what this cell is about and it is untouched. Binding the state here is
    // what an arrival on a registered telephony transport would do.
    let mut state = PlaneSessionState::new(crate::session::VoiceSessionState::for_dialect(
        Dialect::TwilioMediaStreams,
    ));

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

#[test]
fn twilio_dtmf_decodes_and_is_discarded_as_unsupported() {
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
    let mut state = PlaneSessionState::new(crate::session::VoiceSessionState::for_dialect(
        Dialect::TwilioMediaStreams,
    ));

    let dtmf = serde_json::to_vec(&json!({
        "event": "dtmf",
        "streamSid": "MZ123",
        "sequenceNumber": "5",
        "dtmf": { "track": "inbound_track", "digit": "5" },
    }))
    .unwrap();
    let frames = [frame(&dtmf)];
    let mut cursor = FrameCursor::new(&frames);
    let ingress = plane
        .decode_ingress(&mut cursor, Some(&mut state), &c)
        .expect("dtmf decodes, not malformed");
    assert!(matches!(
        ingress,
        Ingress::Discard {
            reason: busbar_contract::wire::DiscardCode::Unsupported
        }
    ));
}

#[test]
fn twilio_unknown_event_fails_closed() {
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
    let mut state = PlaneSessionState::new(crate::session::VoiceSessionState::for_dialect(
        Dialect::TwilioMediaStreams,
    ));

    let unknown = serde_json::to_vec(&json!({
        "event": "teleport",
        "streamSid": "MZ123",
    }))
    .unwrap();
    let frames = [frame(&unknown)];
    let mut cursor = FrameCursor::new(&frames);
    assert!(plane
        .decode_ingress(&mut cursor, Some(&mut state), &c)
        .is_err());
}

/// A turn the upstream ends with an error consumed exactly as much of the caller's time and ran
/// exactly as many tools as one it ends with a usage report, and the two counters this plane derives
/// itself are the only record of either. Forty seconds of uplink and two tool calls, then an error
/// frame: both figures must still reach the meter.
#[test]
fn an_upstream_error_still_meters_the_turn_it_ended() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut state = open_client_session(&plane, &c);

    // PCM16 at 24 kHz is 48 bytes per millisecond, so a second of uplink is 48 000 bytes. Forty of
    // them is the forty seconds the caller spoke.
    let one_second = vec![0u8; 48_000];
    let relay_unit = crate::tests::harness::unit(
        busbar_contract::ids::OpClassId::new("duplex_turn"),
        busbar_contract::bounded::Ir::empty(),
        Facts::new(),
    );
    for _ in 0..40 {
        let append = serde_json::to_vec(&json!({
            "type": "input_audio_buffer.append",
            "audio": base64_of(&one_second),
        }))
        .expect("audio fixture serializes");
        let frames = [frame(&append)];
        let mut cursor = FrameCursor::new(&frames);
        plane
            .decode_ingress(&mut cursor, Some(&mut state), &c)
            .expect("an uplink audio frame decodes");
        // And then relays, which is where the caller's seconds are counted.
        plane
            .encode_ingress_frame(
                &relay_unit,
                &frames[0],
                &destination("api.openai.com", LaneId::new("realtime")),
                Some(&mut state),
                &c,
            )
            .expect("an uplink audio frame relays");
    }

    for call_id in ["call_1", "call_2"] {
        let opened = serde_json::to_vec(&json!({
            "type": "response.output_item.added",
            "item": { "type": "function_call", "call_id": call_id, "name": "lookup" },
        }))
        .expect("tool-call fixture serializes");
        let frames = [frame(&opened)];
        let mut cursor = FrameCursor::new(&frames);
        plane
            .decode_response(
                &mut cursor,
                &destination("api.openai.com", LaneId::new("realtime")),
                Some(&mut state),
                &c,
            )
            .expect("a tool-call open decodes");
    }

    let err = serde_json::to_vec(&json!({
        "type": "error",
        "error": { "code": "rate_limit_exceeded", "message": "slow down" },
    }))
    .expect("error fixture serializes");
    let frames = [frame(&err)];
    let mut cursor = FrameCursor::new(&frames);
    let unit_dest = destination("api.openai.com", LaneId::new("realtime"));
    let progress = plane
        .decode_response(&mut cursor, &unit_dest, Some(&mut state), &c)
        .expect("an error frame decodes");
    let Progress::Terminal { r, .. } = progress else {
        panic!("expected Progress::Terminal, got {progress:?}");
    };
    assert_eq!(r.finish, busbar_contract::unit::FinishClass::Error);

    let unit = crate::tests::harness::unit(
        busbar_contract::ids::OpClassId::new("duplex_turn"),
        r.ir,
        Facts::new(),
    );
    let locators = plane.meter(&unit, &r, &c);
    let quantity = |class: &str| {
        locators
            .lines
            .as_slice()
            .iter()
            .find(|l| l.class.as_str() == class)
            .and_then(|l| l.quantity)
    };
    // Forty seconds of admitted audio, metered in the seconds the class is denominated in.
    assert_eq!(quantity("audio_seconds_in"), Some(40));
    assert_eq!(quantity("tool_calls"), Some(2));
}

/// The caller's audio is metered on the half the answer comes back on.
///
/// A session holds one state per CONNECTION: the client's, and one per upstream it dials. The
/// uplink counter used to be taken at decode, against the client's half, and read back at the
/// response step, against the upstream's — a different value entirely, and always zero. Every
/// second a customer spoke on a duplex turn metered at nothing.
#[test]
fn uplink_audio_meters_on_the_half_the_upstream_answer_arrives_on() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let dest = destination("api.openai.com", LaneId::new("realtime"));
    let mut client = open_client_session(&plane, &c);
    let mut upstream = SessionPlane::open_upstream(&plane, &dest, &c);

    // The turn opens on a control event, so the audio that follows is a relayed frame rather than
    // the unit's own body: the frame under test is the ordinary one, of which a call carries fifty
    // a second.
    let opening = client_wire(&session_update_fixture());
    let frames = [frame(&opening)];
    let mut cursor = FrameCursor::new(&frames);
    let Ingress::Open(draft) = plane
        .decode_ingress(&mut cursor, Some(&mut client), &c)
        .expect("the turn opens")
    else {
        panic!("the first client event opens the turn");
    };
    let unit = crate::tests::harness::unit(draft.op, draft.body_ir, draft.facts);

    // One second of PCM16 at 24 kHz.
    let append = serde_json::to_vec(&json!({
        "type": "input_audio_buffer.append",
        "audio": base64_of(&vec![0u8; 48_000]),
    }))
    .expect("audio fixture serializes");
    let frames = [frame(&append)];
    let mut cursor = FrameCursor::new(&frames);
    plane
        .decode_ingress(&mut cursor, Some(&mut client), &c)
        .expect("an uplink audio frame decodes");
    plane
        .encode_ingress_frame(&unit, &frames[0], &dest, Some(&mut upstream), &c)
        .expect("an uplink audio frame relays to the provider");

    let done = serde_json::to_vec(&json!({
        "type": "response.done",
        "response": { "usage": { "input_token_details": { "audio_tokens": 1 } } }
    }))
    .expect("usage fixture serializes");
    let frames = [frame(&done)];
    let mut cursor = FrameCursor::new(&frames);
    let Progress::Terminal { r, .. } = plane
        .decode_response(&mut cursor, &dest, Some(&mut upstream), &c)
        .expect("the usage report decodes")
    else {
        panic!("a usage report ends the turn");
    };

    let seconds = plane
        .meter(&unit, &r, &c)
        .lines
        .as_slice()
        .iter()
        .find(|l| l.class.as_str() == "audio_seconds_in")
        .and_then(|l| l.quantity);
    assert_eq!(
        seconds,
        Some(1),
        "the second the caller spoke was relayed to the provider and must be metered"
    );
}

/// The duration class is denominated in seconds, and the counter behind it is in milliseconds.
///
/// The design names the class `audio_seconds_in`. This plane counts milliseconds, because that is
/// what a frame's byte count divides down to. Pushed through verbatim, three seconds of admitted
/// audio settled as three thousand seconds -- a thousandfold over-report on a duration-priced class.
#[test]
fn admitted_milliseconds_meter_as_seconds() {
    let plane = openai_plane();
    let arena = LeakArena;
    let cfg = EmptyConfig;
    let stack = WsStack::new("/v1/realtime");
    let labels = Labels::default();
    let c = ctx(&arena, &cfg, &stack, &labels);

    let seconds_line = |ms: i64| {
        let mut facts = Facts::new();
        facts
            .set(crate::meta::FACT_AUDIO_MS_IN, FactValue::Int(ms))
            .expect("fits");
        let response = busbar_contract::plane::Response {
            ir: busbar_contract::bounded::Ir::new(b"{}", &[]),
            finish: busbar_contract::unit::FinishClass::TurnComplete,
            facts,
        };
        let unit = crate::tests::harness::unit(
            busbar_contract::ids::OpClassId::new("duplex_turn"),
            response.ir,
            Facts::new(),
        );
        plane
            .meter(&unit, &response, &c)
            .lines
            .as_slice()
            .iter()
            .find(|l| l.class.as_str() == "audio_seconds_in")
            .and_then(|l| l.quantity)
    };

    assert_eq!(seconds_line(3_000), Some(3));
    // A part-second rounds up rather than vanishing: audio that arrived is not audio that cost
    // nothing, and a zero line settles exactly as an absent one.
    assert_eq!(seconds_line(1), Some(1));
    assert_eq!(seconds_line(1_500), Some(2));
    assert_eq!(seconds_line(0), Some(0));
}

/// A one-shot request sees its own answer, and the unit meters what it was priced on.
///
/// A transcribe or speech unit is admitted with no session, because it is one request and one
/// answer. The response step demanded a session anyway, so the answer was a decode refusal and the
/// unit metered nothing at all: a whole operation class billed at zero.
#[test]
fn a_one_shot_text_to_speech_unit_meters_the_text_it_was_asked_to_speak() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/audio/speech");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);

    let request =
        serde_json::to_vec(&json!({ "input": "eight chars of text here", "voice": "marin" }))
            .expect("request fixture serializes");
    let frames = [frame(&request)];
    let mut cursor = FrameCursor::new(&frames);
    let Ingress::OneShot(draft) = plane
        .decode_ingress(&mut cursor, None, &c)
        .expect("a speech request is one whole unit")
    else {
        panic!("a one-shot request admits as one unit");
    };
    assert_eq!(draft.op.as_str(), "tts");

    // The answer is audio, and it arrives with no session because there never was one.
    let audio = [0u8; 64];
    let answers = [frame(&audio)];
    let mut answer_cursor = FrameCursor::new(&answers);
    let Progress::Terminal { r, .. } = plane
        .decode_response(
            &mut answer_cursor,
            &destination("api.openai.com", LaneId::new("realtime")),
            None,
            &c,
        )
        .expect("a one-shot answer decodes without a session")
    else {
        panic!("a one-shot answer ends the unit");
    };

    let unit = crate::tests::harness::unit(draft.op, draft.body_ir, draft.facts);
    let locators = plane.meter(&unit, &r, &c);
    let quantity = |class: &str| {
        locators
            .lines
            .as_slice()
            .iter()
            .find(|l| l.class.as_str() == class)
            .and_then(|l| l.quantity)
    };
    // "eight chars of text here" is 24 bytes, six tokens at the class's own declared divisor.
    assert_eq!(quantity("text_tokens_in"), Some(6));
}

/// A one-shot transcription's answer states the text it produced, and that is what it prices at.
#[test]
fn a_one_shot_transcription_meters_the_text_it_returned() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/audio/transcriptions");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);

    let audio = [0u8; 64];
    let frames = [frame(&audio)];
    let mut cursor = FrameCursor::new(&frames);
    let Ingress::OneShot(draft) = plane
        .decode_ingress(&mut cursor, None, &c)
        .expect("a transcription request is one whole unit")
    else {
        panic!("a one-shot request admits as one unit");
    };
    assert_eq!(draft.op.as_str(), "transcribe");

    let answer = serde_json::to_vec(&json!({ "text": "twelve bytes" })).unwrap();
    let answers = [frame(&answer)];
    let mut answer_cursor = FrameCursor::new(&answers);
    let Progress::Terminal { r, .. } = plane
        .decode_response(
            &mut answer_cursor,
            &destination("api.openai.com", LaneId::new("realtime")),
            None,
            &c,
        )
        .expect("a one-shot answer decodes without a session")
    else {
        panic!("a one-shot answer ends the unit");
    };

    let unit = crate::tests::harness::unit(draft.op, draft.body_ir, draft.facts);
    let quantity = |class: &str| {
        plane
            .meter(&unit, &r, &c)
            .lines
            .as_slice()
            .iter()
            .find(|l| l.class.as_str() == class)
            .and_then(|l| l.quantity)
    };
    // "twelve bytes" is twelve bytes, three tokens at the class's own declared divisor.
    assert_eq!(quantity("text_tokens_out"), Some(3));
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

#[test]
fn ws_frame_with_invalid_utf8_fails_closed_rather_than_hanging_on_need_more() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut state = open_client_session(&plane, &c);

    let invalid_utf8: &[u8] = &[0x74, 0x79, 0x70, 0x65, 0xff, 0xfe];
    let frames = [frame(invalid_utf8)];
    let mut cursor = FrameCursor::new(&frames);
    let err = plane
        .decode_ingress(&mut cursor, Some(&mut state), &c)
        .expect_err("a frame that cannot be read as UTF-8 is a refusal, not a partial read");
    assert!(matches!(err, busbar_contract::wire::Decode::Malformed));
}

#[test]
fn ws_frame_with_an_unrecognised_event_is_dropped_never_left_pending() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut state = open_client_session(&plane, &c);

    let unrecognised = serde_json::to_vec(&json!({
        "type": "teleport.now",
        "destination": "mars",
    }))
    .unwrap();
    let frames = [frame(&unrecognised)];
    let mut cursor = FrameCursor::new(&frames);
    let ingress = plane
        .decode_ingress(&mut cursor, Some(&mut state), &c)
        .expect("an unrecognised event decodes to a discard, not an error");
    assert!(matches!(
        ingress,
        Ingress::Discard {
            reason: busbar_contract::wire::DiscardCode::Unsupported
        }
    ));
}

#[test]
fn ws_frame_carrying_no_bytes_yet_is_genuinely_need_more() {
    let plane = openai_plane();
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/v1/realtime");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut state = open_client_session(&plane, &c);

    let frames = [frame(&[])];
    let mut cursor = FrameCursor::new(&frames);
    let ingress = plane
        .decode_ingress(&mut cursor, Some(&mut state), &c)
        .expect("an empty frame is a partial read, not a refusal");
    assert!(matches!(ingress, Ingress::NeedMore));
}

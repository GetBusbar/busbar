//! THE DIALECT, THROUGH THE PLANE THAT SERVES IT.
//!
//! These cells were the carrier slice of the plane's own codec and projection tests. They moved
//! with the code they are about, unchanged in what they assert: the same fixtures, the same
//! byte-for-byte µ-law lock, the same forged-`streamSid` discard, the same unknown-event drop.
//! What changed is the crate they live in and one spelling — the dialect row is this crate's own
//! rather than a module of the plane's.
//!
//! A COST, STATED. `harness.rs` beside this file is a copy of the plane's test harness. The
//! alternative is the plane taking a dev-dependency on this crate, which is the plane naming a
//! dialect — the one edge the kind gate says can never exist, in the one half (tests) the matrix
//! does not exempt. A duplicated test harness is the cheaper of the two, and it is duplicated
//! rather than shared because a shared one would be a crate of its own with no kind.

use busbar_contract::bounded::Labels;
use busbar_contract::ids::LaneId;
use busbar_contract::plane::{Ingress, Plane, PlaneSessionState, SessionPlane};
use busbar_contract::wire::FrameCursor;
use busbar_plane_streams::{dialect, Upstream, VoicePlane};
use busbar_voice_codec::ir::config;
use serde_json::json;

use crate::tests::harness::{ctx, frame, EmptyConfig, LeakArena, WsStack};

/// A plane with no upstream table: the projection reads none.
fn plane() -> VoicePlane {
    VoicePlane::new(&[])
}

/// One half of a session's state, already bound to the dialect under test.
fn opened(dialect: &'static dialect::Dialect) -> PlaneSessionState {
    PlaneSessionState::new(busbar_plane_streams::session::VoiceSessionState::for_dialect(dialect))
}

#[test]
fn twilio_media_after_start_admits_a_ulaw_audio_frame() {
    static UPSTREAMS: &[Upstream] = &[Upstream {
        lane: LaneId::new("realtime"),
        host: "api.openai.com",
        dialect: &dialect::OPENAI_REALTIME,
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
    let mut state = PlaneSessionState::new(
        busbar_plane_streams::session::VoiceSessionState::for_dialect(&crate::TWILIO_MEDIA_STREAMS),
    );

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

    // AND BYTES THAT ARE NOT THIS ENVELOPE AT ALL are refused at the step that read them, with no
    // unit to have been given a class. This assertion used to live in the composition root's own
    // tests for this plane, where it named a vendor variant of a plane enum — a root cell spelling
    // an INSTANCE. What it asserts is a property of the dialect's own reader, so it is asserted
    // where that reader is.
    let frames3 = [frame(b"not this envelope at all")];
    let mut cursor3 = FrameCursor::new(&frames3);
    assert_eq!(
        plane.decode_ingress(&mut cursor3, Some(&mut state), &c),
        Err(busbar_contract::wire::Decode::Malformed)
    );
}

#[test]
fn twilio_media_with_a_forged_stream_sid_is_discarded() {
    static UPSTREAMS: &[Upstream] = &[Upstream {
        lane: LaneId::new("realtime"),
        host: "api.openai.com",
        dialect: &dialect::OPENAI_REALTIME,
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
    let mut state = PlaneSessionState::new(
        busbar_plane_streams::session::VoiceSessionState::for_dialect(&crate::TWILIO_MEDIA_STREAMS),
    );

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
        dialect: &dialect::OPENAI_REALTIME,
    }];
    let plane = VoicePlane::new(UPSTREAMS);
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/twilio/call-123");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut state = PlaneSessionState::new(
        busbar_plane_streams::session::VoiceSessionState::for_dialect(&crate::TWILIO_MEDIA_STREAMS),
    );

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

/// An event this carrier adds tomorrow is dropped, and the frame that is not this carrier's shape
/// at all is still refused.
///
/// The carrier publishes new event names over the life of the protocol and tells its clients to
/// ignore the ones they do not recognise; the transport under this session already discards what it
/// cannot place. Refusing the frame ended a live call on the day a new lifecycle event shipped —
/// for a message that carries no audio and asks for nothing.
#[test]
fn twilio_unknown_event_is_dropped_and_a_non_carrier_frame_is_still_refused() {
    static UPSTREAMS: &[Upstream] = &[Upstream {
        lane: LaneId::new("realtime"),
        host: "api.openai.com",
        dialect: &dialect::OPENAI_REALTIME,
    }];
    let plane = VoicePlane::new(UPSTREAMS);
    let arena = LeakArena;
    let config = EmptyConfig;
    let transport = WsStack::new("/twilio/call-123");
    let labels = Labels::new();
    let c = ctx(&arena, &config, &transport, &labels);
    let mut state = PlaneSessionState::new(
        busbar_plane_streams::session::VoiceSessionState::for_dialect(&crate::TWILIO_MEDIA_STREAMS),
    );

    let unknown = serde_json::to_vec(&json!({
        "event": "teleport",
        "streamSid": "MZ123",
    }))
    .unwrap();
    let frames = [frame(&unknown)];
    let mut cursor = FrameCursor::new(&frames);
    let ingress = plane
        .decode_ingress(&mut cursor, Some(&mut state), &c)
        .expect("an event this reader does not model is dropped, not refused");
    assert!(matches!(
        ingress,
        Ingress::Discard {
            reason: busbar_contract::wire::DiscardCode::Unsupported
        }
    ));

    // The line the discard does not cross: bytes that are not this carrier's JSON at all.
    let garbage = [frame(b"not a carrier frame at all")];
    let mut cursor = FrameCursor::new(&garbage);
    assert_eq!(
        plane.decode_ingress(&mut cursor, Some(&mut state), &c),
        Err(busbar_contract::wire::Decode::Malformed)
    );
}

/// THE CARRIER LEG opens on the µ-law lock, byte for byte.
///
/// The whole of the hook wire's payload for a carrier open is these bytes. Equality is against the
/// shared constructor rather than against a hand-written literal, because a literal here would be a
/// second opinion about the lock and the two would drift apart silently.
#[test]
fn a_carrier_session_projects_the_mu_law_lock_byte_for_byte() {
    let arena = LeakArena;
    let cfg = EmptyConfig;
    let stack = WsStack::new("/telephony/call-1");
    let labels = Labels::default();
    let c = ctx(&arena, &cfg, &stack, &labels);

    let mut st = opened(&crate::TWILIO_MEDIA_STREAMS);
    let params =
        SessionPlane::session_params(&plane(), &mut st, &c).expect("a carrier leg projects");

    assert_eq!(
        params.declared,
        serde_json::to_vec(&config::g711_config()).unwrap(),
        "a carrier session's declared parameters must be the µ-law lock BYTE FOR BYTE — this is the \
         payload an operator's configured gate matches on"
    );
    assert_eq!(
        (params.container, params.operation),
        ("streams", "session.open"),
        "the container and the method name are the hook wire's own, not this plane's operation class"
    );
}

/// A tiny standard base64 encoder, independent of the one this crate's own reader carries, so
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

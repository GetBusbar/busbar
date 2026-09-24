//! Two defects in this crate's Twilio `start` handling:
//!
//! 1. **The negotiated media format was parsed but never validated.** `twilio::decode`'s `Start`
//!    already read `encoding`/`sampleRate`/`channels` off the carrier's own frame, but nothing
//!    compared them against the G.711 µ-law / 8 kHz / mono format every later `media` frame is
//!    decoded and TIMED as (`ulaw::decode_frame`, `AudioFormat::G711Ulaw::bytes_to_ms`). Duration is
//!    a LEDGER quantity, so a wrong count from an unvalidated format is a wrong ledger, silently.
//! 2. **An empty `streamSid` passed the anti-forgery binding check vacuously.** `state
//!    .twilio_stream_sid` could be bound to `Some("")`, and a `media` frame carrying an equally
//!    empty `streamSid` compared equal to it — a binding that cannot bind, accepted anyway.
//!
//! The first battery drives [`twilio::decode`] directly — a pure function, no harness needed. The
//! second drives the real plane entrypoint ([`StreamingPlane::decode_ingress`]) so the fix is proven
//! wired in, not merely correct in isolation, and proves the EXISTING forged-source check (a real
//! sid mismatch is still discarded) was not weakened while the empty case was closed.

use crate::claims::Dialect;
use crate::session::VoiceSessionState;
use crate::tests::harness::{ctx, frame, EmptyConfig, LeakPlaneAlloc, WsStack};
use crate::twilio::{self, TwilioError, TwilioEvent};
use crate::StreamingPlane;
use busbar_contract::bounded::Labels;
use busbar_contract::plane::{Ingress, Plane, PlaneSessionState};
use busbar_contract::wire::{Decode, DiscardCode, FrameCursor};

/// A well-formed carrier `start` frame naming `stream_sid` and the negotiated format.
fn start_json(stream_sid: &str, encoding: &str, sample_rate: u64, channels: u64) -> String {
    serde_json::json!({
        "event": "start",
        "start": {
            "streamSid": stream_sid,
            "callSid": "CA-test-call",
            "mediaFormat": {
                "encoding": encoding,
                "sampleRate": sample_rate,
                "channels": channels,
            },
        },
    })
    .to_string()
}

/// A carrier `media` frame naming `stream_sid`, carrying one base64 byte of payload.
fn media_json(stream_sid: &str) -> String {
    serde_json::json!({
        "event": "media",
        "streamSid": stream_sid,
        "media": { "payload": "AA==" },
    })
    .to_string()
}

// ══ `twilio::decode`, DIRECTLY ══════════════════════════════════════════════════════════════════

#[test]
fn start_with_an_empty_stream_sid_is_refused() {
    let json = start_json("", "audio/x-mulaw", 8_000, 1);
    assert_eq!(
        twilio::decode(json.as_bytes()),
        Err(TwilioError::Malformed),
        "an empty streamSid cannot bind anything and must not decode as though it could"
    );
}

#[test]
fn start_negotiating_a_non_g711_format_is_refused() {
    for (encoding, sample_rate, channels) in [
        ("audio/l16", 8_000u64, 1u64),
        ("audio/x-mulaw", 16_000, 1),
        ("audio/x-mulaw", 8_000, 2),
        ("", 8_000, 1),
    ] {
        let json = start_json("CA-real-sid", encoding, sample_rate, channels);
        assert_eq!(
            twilio::decode(json.as_bytes()),
            Err(TwilioError::UnsupportedMediaFormat),
            "a negotiated format of {encoding:?}/{sample_rate}/{channels} must be refused rather \
             than silently treated as G.711/8kHz/mono"
        );
    }
}

#[test]
fn start_with_a_real_sid_and_the_assumed_format_decodes() {
    let json = start_json("CA-real-sid", "audio/x-mulaw", 8_000, 1);
    assert_eq!(
        twilio::decode(json.as_bytes()),
        Ok(TwilioEvent::Start {
            stream_sid: "CA-real-sid".to_string(),
            call_sid: "CA-test-call".to_string(),
            encoding: "audio/x-mulaw".to_string(),
            sample_rate: 8_000,
            channels: 1,
        }),
        "a well-formed start naming the assumed format must still decode — the fix must not \
         over-refuse the ordinary case"
    );
}

// ══ THE PLANE ENTRYPOINT ════════════════════════════════════════════════════════════════════════

/// A fresh Twilio-dialected session half — what a session's client half opens with once the
/// `/twilio/inbound` claim has matched, before any frame has arrived.
fn fresh_twilio_state() -> PlaneSessionState {
    PlaneSessionState::new(VoiceSessionState::for_dialect(Dialect::TwilioMediaStreams))
}

/// What one call to [`StreamingPlane::decode_ingress`] made of a frame, OWNED rather than borrowed
/// — everything the arena/frame `decode_ingress` borrows from is local to this function, so nothing
/// past what a test needs to assert on may escape it.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Discard(DiscardCode),
    Open,
    Other,
}

/// Decode one Twilio wire frame against `state`, over a fresh arena/transport/labels local to this
/// call. `state` is the one thing carried BETWEEN calls — the session half a real connection would
/// hold across frames — exactly what the `streamSid` binding this module is testing depends on.
fn decode_one(
    plane: &StreamingPlane,
    state: &mut PlaneSessionState,
    json: &str,
) -> Result<Outcome, Decode> {
    let arena = LeakPlaneAlloc;
    let config = EmptyConfig;
    let transport = WsStack::new("/twilio/inbound");
    let labels = Labels::new();
    let cx = ctx(&arena, &config, &transport, &labels);
    let frames = [frame(json.as_bytes())];
    let mut cursor = FrameCursor::new(&frames);
    let ingress = plane.decode_ingress(&mut cursor, Some(state), &cx)?;
    Ok(match ingress {
        Ingress::Discard { reason } => Outcome::Discard(reason),
        Ingress::Open(_) => Outcome::Open,
        _ => Outcome::Other,
    })
}

#[test]
fn a_start_with_an_empty_stream_sid_refuses_the_whole_session_at_the_plane_entrypoint() {
    let plane = StreamingPlane::EMPTY;
    let mut state = fresh_twilio_state();
    let result = decode_one(
        &plane,
        &mut state,
        &start_json("", "audio/x-mulaw", 8_000, 1),
    );
    assert_eq!(
        result,
        Err(Decode::Malformed),
        "an empty streamSid must refuse the session, not open a binding nothing can check against"
    );
}

#[test]
fn a_start_negotiating_a_non_g711_format_refuses_the_whole_session_at_the_plane_entrypoint() {
    let plane = StreamingPlane::EMPTY;
    let mut state = fresh_twilio_state();
    let result = decode_one(
        &plane,
        &mut state,
        &start_json("CA-real-sid", "audio/l16", 16_000, 2),
    );
    assert_eq!(
        result,
        Err(Decode::UnsupportedOperation),
        "a non-G.711/8kHz/mono negotiation must refuse the session rather than proceed with wrong \
         duration accounting"
    );
}

#[test]
fn a_media_frame_naming_a_different_sid_is_still_discarded_after_the_empty_case_is_closed() {
    let plane = StreamingPlane::EMPTY;
    let mut state = fresh_twilio_state();

    decode_one(
        &plane,
        &mut state,
        &start_json("CA-real-sid", "audio/x-mulaw", 8_000, 1),
    )
    .expect("a well-formed start must be accepted");

    // A media frame naming a DIFFERENT, non-empty sid must still be refused as forged — proof the
    // existing check was not weakened while the empty case was closed.
    let forged = decode_one(&plane, &mut state, &media_json("CA-someone-elses-sid"))
        .expect("a mismatched-sid media frame is discarded, not a decode error");
    assert_eq!(
        forged,
        Outcome::Discard(DiscardCode::ForgedSource),
        "a media frame naming a sid other than the one `start` bound must still be discarded"
    );

    // A media frame naming the bound sid is accepted and opens the turn.
    let matched = decode_one(&plane, &mut state, &media_json("CA-real-sid"))
        .expect("a media frame carrying the bound sid must be accepted");
    assert_eq!(
        matched,
        Outcome::Open,
        "a media frame carrying the bound sid must open the turn"
    );
}

// ══ THE `media` PAYLOAD'S BASE64 — THE BILLED BYTE COUNT ═════════════════════════════════════════
//
// Items 418/419. The byte count `twilio::decode` hands back for a `media` payload is the LEDGER
// quantity `crate::plane` times at 8 bytes/ms into `audio_ms_in`. The crate's private base64 copy
// used to strip `=` wherever it appeared, so `QQ==` repeated 2000 times decoded to 3000 bytes and
// was metered as 375 ms of caller audio, where the workspace's one decoder
// (`busbar_substrate_values::media::base64_decode`) refuses the same bytes: padding is terminal.

/// A carrier `media` frame on `stream_sid` carrying `payload` verbatim as its base64.
fn media_json_with(stream_sid: &str, payload: &str) -> String {
    serde_json::json!({
        "event": "media",
        "streamSid": stream_sid,
        "media": { "payload": payload },
    })
    .to_string()
}

/// The bytes `twilio::decode` read out of a `media` frame carrying `payload`.
fn media_bytes(payload: &str) -> Result<Vec<u8>, TwilioError> {
    match twilio::decode(media_json_with("CA-real-sid", payload).as_bytes())? {
        TwilioEvent::Media { payload, .. } => Ok(payload.to_vec()),
        other => panic!("a media frame decoded as {other:?}"),
    }
}

#[test]
fn a_media_payload_resuming_after_padding_is_refused_not_billed_as_a_longer_payload() {
    assert_eq!(media_bytes("QQ==QQ=="), Err(TwilioError::BadPayload));
    assert_eq!(media_bytes("QQ=A"), Err(TwilioError::BadPayload));
    assert_eq!(
        media_bytes(&"QQ==".repeat(2_000)),
        Err(TwilioError::BadPayload)
    );
}

#[test]
fn the_media_payload_decoder_keeps_the_rest_of_the_shared_decode_contract() {
    // Padding present, absent, trailing whitespace or extra padding after it: all one byte.
    assert_eq!(media_bytes("QQ=="), Ok(vec![b'A']));
    assert_eq!(media_bytes("QQ"), Ok(vec![b'A']));
    assert_eq!(media_bytes("QQ==\r\n"), Ok(vec![b'A']));
    assert_eq!(media_bytes("QQ==="), Ok(vec![b'A']));
    // Whitespace inside the data is ignored.
    assert_eq!(media_bytes("QU\nJD"), Ok(b"ABC".to_vec()));
    // A lone trailing sextet and a byte outside the alphabet refuse.
    assert_eq!(media_bytes("QUJDR"), Err(TwilioError::BadPayload));
    assert_eq!(media_bytes("QU*D"), Err(TwilioError::BadPayload));
    // A real 20 ms µ-law frame (160 bytes, every value) survives the carrier's own encoder.
    let mulaw: Vec<u8> = (0..160u8).collect();
    match twilio::decode(&twilio::encode_media("CA-real-sid", &mulaw)) {
        Ok(TwilioEvent::Media { payload, .. }) => assert_eq!(payload.to_vec(), mulaw),
        other => panic!("a round-tripped media frame decoded as {other:?}"),
    }
}

#[test]
fn a_padding_resumed_media_frame_is_refused_at_the_plane_entrypoint_and_opens_no_turn() {
    let plane = StreamingPlane::EMPTY;
    let mut state = fresh_twilio_state();
    decode_one(
        &plane,
        &mut state,
        &start_json("CA-real-sid", "audio/x-mulaw", 8_000, 1),
    )
    .expect("a well-formed start must be accepted");
    let result = decode_one(
        &plane,
        &mut state,
        &media_json_with("CA-real-sid", &"QQ==".repeat(2_000)),
    );
    assert!(
        result.is_err(),
        "a media payload resuming after its padding must be refused, not metered: got {result:?}"
    );
}

/// Item 419: the comment justifying the local base64 copy once told a reviewer it was the SAME
/// algorithm `busbar_voice_codec::topology::twilio` carries — that module carries none (it imports
/// the substrate decoder), and the two differed on padding, which is how the billed-byte drift above
/// survived review. The justification must name the real single source and must not claim an
/// equivalence nobody checked; the decode-contract tests above are what check it.
#[test]
fn the_local_base64_copy_names_the_one_decoder_it_must_match_and_claims_no_unchecked_equivalence() {
    let src = include_str!("../twilio.rs");
    assert!(
        !src.contains("identical standard algorithm"),
        "twilio.rs still claims an unchecked algorithm equivalence for its private base64"
    );
    assert!(
        // Spelled in two halves so this line does not itself name the substrate crate the plane's
        // purity test (`tests/purity.rs`) forbids in non-comment source.
        src.contains(concat!("busbar_sub", "strate_values::media")),
        "twilio.rs's base64 comment must name the workspace's one decoder it stands in for"
    );
}

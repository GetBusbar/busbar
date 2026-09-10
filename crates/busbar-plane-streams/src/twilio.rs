//! A minimal Twilio Media Streams wire reader/writer, written independently for this crate.
//!
//! Twilio's Media Streams protocol is a JSON-framed message-per-WS-frame wire: lifecycle events
//! (`connected`, `start`, `mark`, `dtmf`, `stop`) and a per-chunk `media` event whose `payload` is
//! base64 8 kHz G.711 µ-law audio — `{"event":"media","media":{"payload":"<base64>"},"streamSid":"..."}`.
//!
//! `busbar-voice` has no dialect codec for this wire (it is not one of its two duplex dialects), and
//! the one Twilio-shaped module that exists in that crate's source tree
//! (`busbar_voice_codec::topology::twilio`) is gated behind busbar-voice's `runtime` cargo feature, which
//! this crate's manifest never turns on — so it is not in this crate's dependency closure at all,
//! and cannot be named from here. This module is therefore written from the wire shape alone
//! (confirmed against `docs/design/plane4-voice-dialect-landscape.md` and the public Twilio Media
//! Streams reference, both cited in this crate's design notes) rather than adapted from that
//! runtime-gated module; any structural resemblance is the two independently converging on the same
//! public wire format, not a copy.
//!
//! The events this module models onto the shared [`busbar_voice_codec::ir`] vocabulary: a `media`
//! event becomes an [`IrAudioFrame`] (direction `Up`, format [`AudioFormat::G711Ulaw`]) carrying
//! the base64-decoded µ-law bytes
//! verbatim — the µ-law↔PCM16 transform happens at the plane's `encode_ingress_frame` seam
//! ([`crate::plane`]), never here. The lifecycle events carry no audio and are surfaced as their own
//! variant so the plane can track (or ignore) them without guessing at a synthetic IR event for a
//! wire message with no IR home.

use bytes::Bytes;

/// One decoded Twilio Media Streams event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwilioEvent {
    /// The one-time handshake event, first on the socket. Carries nothing.
    Connected,
    /// The stream opened. Carries the identifiers later frames repeat and the negotiated format.
    Start {
        /// The `streamSid` Twilio minted for this connection, repeated on every later frame.
        stream_sid: String,
        /// Twilio's `callSid` for the underlying PSTN call.
        call_sid: String,
        /// The negotiated media encoding string (`audio/x-mulaw` for the passthrough carrier).
        encoding: String,
        /// The negotiated sample rate in Hz (`8000` for the passthrough carrier).
        sample_rate: u64,
        /// The negotiated channel count (`1`, mono).
        channels: u64,
    },
    /// A ~20 ms audio chunk. `payload` is the base64-decoded, still µ-law-encoded audio.
    Media {
        /// The connection's `streamSid`, to check against the value bound at admission.
        stream_sid: String,
        /// The raw µ-law bytes.
        payload: Bytes,
    },
    /// A playback-position acknowledgement Twilio echoes back for a `mark` this plane sent.
    Mark {
        /// The connection's `streamSid`.
        stream_sid: String,
        /// The mark name the outbound side chose.
        name: String,
    },
    /// A touch-tone keypress heard on the inbound track — sent only when the stream has DTMF
    /// enabled. It carries no session audio and is discarded exactly like [`Self::Mark`].
    Dtmf {
        /// The connection's `streamSid`.
        stream_sid: String,
        /// The key that was pressed (`0`-`9`, `*`, `#`, `A`-`D`), or empty when Twilio omits it.
        digit: String,
    },
    /// The terminal event.
    Stop,
}

/// Why an inbound Twilio frame could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwilioError {
    /// The frame was not well-formed JSON, or a field this reader requires was absent.
    Malformed,
    /// The frame named an `event` this reader does not model.
    UnknownEvent(String),
    /// A `media` payload was not valid base64.
    BadPayload,
}

/// Decode one inbound Twilio Media Streams WS frame.
///
/// # Errors
/// Returns [`TwilioError`] when the frame is not well-formed Twilio JSON, names an event this
/// reader does not model, or carries a `media` payload that is not valid base64.
pub fn decode(frame: &[u8]) -> Result<TwilioEvent, TwilioError> {
    let v: serde_json::Value = serde_json::from_slice(frame).map_err(|_| TwilioError::Malformed)?;
    let event = v
        .get("event")
        .and_then(serde_json::Value::as_str)
        .ok_or(TwilioError::Malformed)?;
    match event {
        "connected" => Ok(TwilioEvent::Connected),
        "start" => {
            let start = v.get("start").ok_or(TwilioError::Malformed)?;
            let stream_sid = str_field(start, "streamSid")
                .or_else(|| str_field(&v, "streamSid"))
                .ok_or(TwilioError::Malformed)?;
            let call_sid = str_field(start, "callSid").unwrap_or_default();
            let mf = start.get("mediaFormat").ok_or(TwilioError::Malformed)?;
            Ok(TwilioEvent::Start {
                stream_sid,
                call_sid,
                encoding: str_field(mf, "encoding").unwrap_or_default(),
                sample_rate: mf
                    .get("sampleRate")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default(),
                channels: mf
                    .get("channels")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default(),
            })
        }
        "media" => {
            let stream_sid = str_field(&v, "streamSid").unwrap_or_default();
            let payload_b64 = v
                .get("media")
                .and_then(|m| m.get("payload"))
                .and_then(serde_json::Value::as_str)
                .ok_or(TwilioError::Malformed)?;
            let payload = base64_decode(payload_b64).ok_or(TwilioError::BadPayload)?;
            Ok(TwilioEvent::Media {
                stream_sid,
                payload: Bytes::from(payload),
            })
        }
        "mark" => Ok(TwilioEvent::Mark {
            stream_sid: str_field(&v, "streamSid").unwrap_or_default(),
            name: v
                .get("mark")
                .and_then(|m| m.get("name"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }),
        "dtmf" => Ok(TwilioEvent::Dtmf {
            stream_sid: str_field(&v, "streamSid").unwrap_or_default(),
            digit: v
                .get("dtmf")
                .and_then(|d| d.get("digit"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }),
        "stop" => Ok(TwilioEvent::Stop),
        other => Err(TwilioError::UnknownEvent(other.to_string())),
    }
}

fn str_field(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Encode raw µ-law bytes into a Twilio outbound `media` envelope for a given `stream_sid`.
#[must_use]
pub fn encode_media(stream_sid: &str, mulaw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_media_into(&mut out, stream_sid, mulaw);
    out
}

/// The same envelope, rendered into a buffer the caller already has.
///
/// This is the shape the downlink writes in. The envelope is FIXED — three members, in the one
/// order this dialect's documents are written in — and everything about it except the identifier
/// and the payload was known when the crate was compiled. Building a document to describe it, and
/// a string to hold the payload, and then serializing the document, spends three allocations per
/// AUDIO FRAME to reach bytes that could have been appended. A call carries fifty frames a second.
///
/// The buffer is CLEARED, not appended to, so a caller may hand the same one back frame after frame
/// and pay for its growth once.
pub fn encode_media_into(out: &mut Vec<u8>, stream_sid: &str, mulaw: &[u8]) {
    out.clear();
    // An identifier that would have to be escaped is not one this dialect mints, but it is one this
    // function may be handed. Rather than carry an escaper that would almost never run — and would
    // be the one part of this rendering nothing exercises — the rare case goes back through the
    // serializer, which is the authority on what those bytes are.
    if !is_bare_json_string(stream_sid) {
        let doc = serde_json::json!({
            "event": "media",
            "streamSid": stream_sid,
            "media": { "payload": base64_encode(mulaw) },
        });
        out.extend_from_slice(&serde_json::to_vec(&doc).unwrap_or_default());
        return;
    }
    const HEAD: &[u8] = br#"{"event":"media","media":{"payload":""#;
    const MIDDLE: &[u8] = br#""},"streamSid":""#;
    const TAIL: &[u8] = br#""}"#;
    out.reserve(
        HEAD.len() + base64_len(mulaw.len()) + MIDDLE.len() + stream_sid.len() + TAIL.len(),
    );
    out.extend_from_slice(HEAD);
    base64_encode_into(mulaw, out);
    out.extend_from_slice(MIDDLE);
    out.extend_from_slice(stream_sid.as_bytes());
    out.extend_from_slice(TAIL);
}

/// Whether a string is its own JSON body — nothing in it a serializer would rewrite.
///
/// Printable ASCII with neither of the two characters a JSON string cannot carry raw. Everything
/// else, including every non-ASCII byte, is left to the serializer.
fn is_bare_json_string(s: &str) -> bool {
    s.bytes()
        .all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\')
}

/// Encode a named playback-position mark for a given `stream_sid`.
///
/// Used as the provisional wire rendering for a server event this dialect's own vocabulary has no
/// audio-bearing counterpart for (see `crate::plane`'s `encode_response` documentation) — an
/// acknowledged no-op frame rather than silently dropping the event.
#[must_use]
pub fn encode_mark(stream_sid: &str, name: &str) -> Vec<u8> {
    let out = serde_json::json!({
        "event": "mark",
        "streamSid": stream_sid,
        "mark": { "name": name },
    });
    serde_json::to_vec(&out).unwrap_or_default()
}

// ── standard base64 (RFC 4648), self-contained so this module pulls no new dependency ──────────────
//
// Written independently for this crate; `busbar_voice_codec::topology::twilio` (runtime-gated, not in this
// crate's dependency closure) happens to carry the identical standard algorithm for the identical
// reason it states for itself: pulling in a dependency for one well-known, easily-verified transform
// is not worth the closure weight.

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// How many characters this many bytes encode to.
const fn base64_len(bytes: usize) -> usize {
    bytes.div_ceil(3) * 4
}

fn base64_encode(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(base64_len(data.len()));
    base64_encode_into(data, &mut out);
    // Every byte appended below is one of the alphabet's, `=` included, so this is ASCII.
    String::from_utf8(out).unwrap_or_default()
}

/// The same encoding, appended to a buffer the caller already has.
fn base64_encode_into(data: &[u8], out: &mut Vec<u8>) {
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 63) as usize]);
        out.push(B64_ALPHABET[((n >> 12) & 63) as usize]);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((n >> 6) & 63) as usize]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 63) as usize]
        } else {
            b'='
        });
    }
}

fn base64_sextet(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let sextets: Vec<u8> = s
        .bytes()
        .filter(|&b| b != b'=' && !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(sextets.len() / 4 * 3);
    for chunk in sextets.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        let mut n = 0u32;
        for &c in chunk {
            n = (n << 6) | base64_sextet(c)?;
        }
        let missing = 4 - chunk.len();
        n <<= 6 * missing as u32;
        let be = n.to_be_bytes();
        for byte in be.iter().take(1 + (chunk.len() - 1)).skip(1) {
            out.push(*byte);
        }
    }
    Some(out)
}

// ------------------------------------------------------------------------------------------------
// THE DIALECT ROW — this carrier's implementation of the plane's own dialect face.
// ------------------------------------------------------------------------------------------------

use busbar_contract::bounded::Facts;
use busbar_contract::plane::Ingress;
use busbar_contract::unit::Ctx;
use busbar_contract::wire::{Decode, DiscardCode, Encode, FrameCursor};
use busbar_voice_codec::ir::{
    config::g711_config,
    event::IrClientEvent,
    media::{AudioFormat, IrAudioFrame, IrAudioRef, UpDown},
};

use crate::dialect::{Dialect, Envelope};
use crate::session::VoiceSessionState;

/// The carrier's own name for itself, which is also the name of the crate that will own this file.
pub const NAME: &str = "twilio-media-streams";

/// This carrier's envelope: its JSON reader, its relay seam, and its downlink renderer.
pub static ENVELOPE: Envelope = Envelope {
    decode_ingress,
    relay_ingress,
    render_downlink_audio,
};

/// THE ROW. Four facts and one envelope; nothing here is a branch in the plane.
///
/// It meters its own uplink because what the caller spoke is µ-law on this carrier's wire, and it
/// locks a G.711 session posture because the leg is µ-law end to end and nothing may resample it.
pub static TWILIO_MEDIA_STREAMS: Dialect = Dialect {
    name: NAME,
    // Ingress only: this plane serves callers arriving on this carrier and never dials one.
    duplex_upstream: false,
    authenticates_from_session: true,
    meters_own_uplink: true,
    envelope: Some(&ENVELOPE),
    locked_session_config: Some(g711_config),
};

/// This dialect's own row, for the two places its reader has to name it.
const SELF_ROW: &Dialect = &TWILIO_MEDIA_STREAMS;

/// Read one frame of a session carried on this dialect.
fn decode_ingress<'u>(
    frames: &mut FrameCursor<'u>,
    state: &mut VoiceSessionState,
    ctx: &Ctx<'u>,
) -> Result<Ingress<'u>, Decode> {
    let frame = frames.next_frame().ok_or(Decode::Malformed)?;
    let event = match decode(frame.bytes.as_slice()) {
        Ok(event) => event,
        // An event name this reader does not model is not a broken frame: this carrier adds events
        // over time and tells its clients to ignore the ones they do not know, and the transport
        // under this session already discards what it cannot place. Refusing the session over one
        // would drop a live call the day the carrier ships a new lifecycle event. A frame that is
        // not this carrier's JSON at all is still a refusal.
        Err(TwilioError::UnknownEvent(_)) => {
            return Ok(Ingress::Discard {
                reason: DiscardCode::Unsupported,
            })
        }
        Err(_) => return Err(Decode::Malformed),
    };
    match event {
        // Lifecycle events with no audio and nothing left to bind: consumed, no unit, no state
        // change beyond what `Start` below records.
        TwilioEvent::Connected => Ok(Ingress::Discard {
            reason: DiscardCode::Unsupported,
        }),
        TwilioEvent::Start { stream_sid, .. } => {
            state.envelope_id = Some(stream_sid);
            state.dialect = Some(SELF_ROW);
            Ok(Ingress::Discard {
                reason: DiscardCode::Unsupported,
            })
        }
        TwilioEvent::Media {
            stream_sid,
            payload,
        } => {
            // The forgery/replay guard the architecture note for this dialect names: a `media`
            // frame naming a `streamSid` other than the one `start` bound is discarded, not
            // refused — it costs nothing and ends no unit, exactly what a discard is for.
            if state.envelope_id.as_deref() != Some(stream_sid.as_str()) {
                return Ok(Ingress::Discard {
                    reason: DiscardCode::ForgedSource,
                });
            }
            // Counted at the relay seam, not here: see `relay_ingress`. A frame that OPENS the turn
            // is the one exception — it becomes the unit's own egress body and never reaches that
            // seam — so its milliseconds travel on the draft the unit is minted from.
            let ms = AudioFormat::G711Ulaw.bytes_to_ms(payload.len() as u64);
            let arena_bytes = ctx
                .arena()
                .alloc_bytes(&payload)
                .map_err(|_| Decode::Oversize)?;
            crate::plane::open_or_relay(state, SELF_ROW, arena_bytes, None, Some(ms), ctx)
        }
        TwilioEvent::Mark { .. } => Ok(Ingress::Discard {
            reason: DiscardCode::Unsupported,
        }),
        TwilioEvent::Dtmf { .. } => Ok(Ingress::Discard {
            reason: DiscardCode::Unsupported,
        }),
        TwilioEvent::Stop => {
            let for_ = state.turn_correlation;
            let _ = state.close_turn();
            Ok(Ingress::Close {
                for_,
                facts: Box::new(Facts::new()),
            })
        }
    }
}

/// Relay one arriving frame onward, and take this dialect's own uplink meter while the payload is
/// still the carrier's own µ-law.
///
/// The documented seam: the µ-law -> PCM16 transform happens HERE, never at decode.
fn relay_ingress(
    bytes: &[u8],
    state: &mut VoiceSessionState,
) -> Result<Option<IrClientEvent>, Encode> {
    let event = match decode(bytes) {
        Ok(event) => event,
        // The same forward-compatibility rule the decode step takes: an event this reader does not
        // model carries no audio to relay, and is not a reason to end the call.
        Err(TwilioError::UnknownEvent(_)) => return Ok(None),
        Err(_) => return Err(Encode::Unrepresentable),
    };
    match event {
        TwilioEvent::Media { payload, .. } => {
            // Priced from the raw carrier payload, before the transform below widens it: what the
            // caller spoke is µ-law on this dialect's wire.
            let ms = AudioFormat::G711Ulaw.bytes_to_ms(payload.len() as u64);
            state.turn.audio_ms_in = state.turn.audio_ms_in.saturating_add(ms);
            let pcm = crate::ulaw::decode_frame(&payload);
            Ok(Some(IrClientEvent::AudioFrame(IrAudioFrame {
                dir: UpDown::Up,
                seq: state.codec.next_up_seq(),
                media: Bytes::from(pcm),
                // A carrier media frame names no conversation item.
                origin: IrAudioRef::default(),
            })))
        }
        // Lifecycle events (`connected`/`start`/`mark`/`stop`) carry no audio and are fully handled
        // at decode; nothing is relayed onward for them.
        _ => Ok(None),
    }
}

/// Render one downlink audio frame into the session's held buffer, in this carrier's envelope.
///
/// Taken and handed straight back, because the identifier beside it is borrowed from the same
/// state.
fn render_downlink_audio(state: &mut VoiceSessionState, media: &[u8]) {
    let mulaw = crate::ulaw::encode_frame(media);
    let mut out = core::mem::take(&mut state.render_buf);
    let sid = state.envelope_id.as_deref().unwrap_or_default();
    encode_media_into(&mut out, sid, &mulaw);
    state.render_buf = out;
}

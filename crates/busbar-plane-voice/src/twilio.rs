//! A minimal Twilio Media Streams wire reader/writer, written independently for this crate.
//!
//! Twilio's Media Streams protocol is a JSON-framed message-per-WS-frame wire: lifecycle events
//! (`connected`, `start`, `mark`, `stop`) and a per-chunk `media` event whose `payload` is base64
//! 8 kHz G.711 µ-law audio — `{"event":"media","media":{"payload":"<base64>"},"streamSid":"..."}`.
//!
//! `busbar-voice` has no dialect codec for this wire (it is not one of its two duplex dialects), and
//! the one Twilio-shaped module that exists in that crate's source tree
//! (`busbar_voice::topology::twilio`) is gated behind busbar-voice's `runtime` cargo feature, which
//! this crate's manifest never turns on — so it is not in this crate's dependency closure at all,
//! and cannot be named from here. This module is therefore written from the wire shape alone
//! (confirmed against `docs/design/plane4-voice-dialect-landscape.md` and the public Twilio Media
//! Streams reference, both cited in this crate's design notes) rather than adapted from that
//! runtime-gated module; any structural resemblance is the two independently converging on the same
//! public wire format, not a copy.
//!
//! The events this module models onto the shared [`busbar_voice::ir`] vocabulary: a `media` event
//! becomes an [`busbar_voice::ir::media::IrAudioFrame`] (direction `Up`, format
//! [`busbar_voice::ir::media::AudioFormat::G711Ulaw`]) carrying the base64-decoded µ-law bytes
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
    let out = serde_json::json!({
        "event": "media",
        "streamSid": stream_sid,
        "media": { "payload": base64_encode(mulaw) },
    });
    serde_json::to_vec(&out).unwrap_or_default()
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
// Written independently for this crate; `busbar_voice::topology::twilio` (runtime-gated, not in this
// crate's dependency closure) happens to carry the identical standard algorithm for the identical
// reason it states for itself: pulling in a dependency for one well-known, easily-verified transform
// is not worth the closure weight.

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
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

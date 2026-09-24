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
//! The events this module models onto the shared [`busbar_voice_codec::ir`] vocabulary: a `media` event
//! becomes an [`busbar_voice_codec::ir::media::IrAudioFrame`] (direction `Up`, format
//! [`busbar_voice_codec::ir::media::AudioFormat::G711Ulaw`]) carrying the base64-decoded µ-law bytes
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

/// THE ASSUMED NEGOTIATED FORMAT — the one this reader hands `media` payloads on as (raw µ-law
/// bytes, see the module doc) and the one every later consumer treats them as: the µ-law→PCM16
/// widen ([`crate::ulaw::decode_frame`]) and the duration [`crate::plane`] derives from a byte
/// count (`AudioFormat::G711Ulaw::bytes_to_ms`, which IS a LEDGER quantity — a call's billed
/// duration rolls up from exactly this count). Twilio's own default and near-universal choice for
/// this carrier, and the only shape the rest of this crate's Twilio path is written against.
const ASSUMED_ENCODING: &str = "audio/x-mulaw";
const ASSUMED_SAMPLE_RATE_HZ: u64 = 8_000;
const ASSUMED_CHANNELS: u64 = 1;

/// Why an inbound Twilio frame could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwilioError {
    /// The frame was not well-formed JSON, or a field this reader requires was absent.
    Malformed,
    /// The frame named an `event` this reader does not model.
    UnknownEvent(String),
    /// A `media` payload was not valid base64.
    BadPayload,
    /// `start` negotiated a `mediaFormat` other than [`ASSUMED_ENCODING`] /
    /// [`ASSUMED_SAMPLE_RATE_HZ`] / [`ASSUMED_CHANNELS`] — the format every later frame on this
    /// stream would otherwise be decoded and TIMED under. Refused rather than served on a wrong
    /// assumption: a duration derived from a mismatched format is a wrong ledger entry, silently,
    /// since nothing about a mis-decoded byte count looks broken on its own.
    UnsupportedMediaFormat,
}

/// Decode one inbound Twilio Media Streams WS frame.
///
/// # Errors
/// Returns [`TwilioError`] when the frame is not well-formed Twilio JSON, names an event this
/// reader does not model, carries a `media` payload that is not valid base64, binds an empty or
/// absent `streamSid` (which cannot BIND anything — see [`TwilioEvent::Start`]), or negotiates a
/// media format other than the one this crate's Twilio path assumes throughout.
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
            // AN EMPTY ID IS NOT A BINDING. `stream_sid` is what every later `media` frame is
            // checked against (`crate::plane`'s per-connection anti-forgery guard). If this reader
            // ever handed one back empty, an attacker's own `media` frame carrying an equally empty
            // (or simply omitted — the same empty default) `streamSid` would compare EQUAL to the
            // "bound" value and the check that exists to refuse an unbound source would pass
            // vacuously. Refused HERE, at the one place that can still say why, rather than let a
            // binding that cannot bind reach `decode_twilio_frame`.
            if stream_sid.is_empty() {
                return Err(TwilioError::Malformed);
            }
            let call_sid = str_field(start, "callSid").unwrap_or_default();
            let mf = start.get("mediaFormat").ok_or(TwilioError::Malformed)?;
            let encoding = str_field(mf, "encoding").unwrap_or_default();
            let sample_rate = mf
                .get("sampleRate")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default();
            let channels = mf
                .get("channels")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default();
            if encoding != ASSUMED_ENCODING
                || sample_rate != ASSUMED_SAMPLE_RATE_HZ
                || channels != ASSUMED_CHANNELS
            {
                return Err(TwilioError::UnsupportedMediaFormat);
            }
            Ok(TwilioEvent::Start {
                stream_sid,
                call_sid,
                encoding,
                sample_rate,
                channels,
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

// ── standard base64 (RFC 4648), a LOCAL copy of the workspace's one decoder contract ─────────────
//
// The workspace's one base64 implementation is `busbar_substrate_values::media`; every other reader
// (`busbar_voice_codec::topology::twilio` and `ir::codec` among them) imports it and carries no
// algorithm of its own. It is in this crate's closure (through `busbar-voice-codec`), but a plane
// names no substrate crate (`tests/purity.rs`, `the_plane_names_no_kernel_side_crate`), so this copy
// stands in for it. It is NOT a second algorithm: its decode contract must match that one byte for
// byte, because the byte count it returns is billed — `crate::plane` derives a call's audio duration
// from it. The contract, all of it:
// whitespace is ignored; `=` padding is TERMINAL (only whitespace or more `=` may follow it — data
// resuming after padding, `QQ==QQ==`, is malformed, never one longer payload); a lone trailing
// sextet, or any byte outside the alphabet, refuses the payload. `tests::twilio` pins each clause.

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
    let mut sextets: Vec<u8> = Vec::with_capacity(s.len());
    // Padding is TERMINAL: once `=` is seen, encoded data resuming is a malformed payload, refused.
    let mut padded = false;
    for b in s.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'=' {
            padded = true;
            continue;
        }
        if padded {
            return None;
        }
        sextets.push(b);
    }
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

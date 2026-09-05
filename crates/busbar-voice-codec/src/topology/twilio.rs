// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWILIO MEDIA STREAMS ENVELOPE for the telephony topology (behind the `runtime` feature).
//!
//! Twilio speaks a JSON-over-WS protocol on its Media Streams leg: lifecycle events (`connected`,
//! `start`, `mark`, `dtmf`, `stop` — the whole set Twilio sends TO the socket, because an event
//! this codec does not model is a decode REFUSAL to everything downstream) plus per-frame `media`
//! events whose `payload` is base64 8 kHz µ-law. The
//! generic [`crate::topology::telephony::TelephonyProxy`] bridge already carries raw `Vec<u8>` on its
//! `client_in`/`client_out` halves, so the only carrier-specific work is this thin, stateless codec
//! that:
//!
//! * DECODES an inbound Twilio WS frame into a [`TwilioEvent`], base64-decoding a `media` payload to
//!   the raw µ-law bytes the proxy's `client_in` stream consumes.
//! * ENCODES raw µ-law bytes back into the Twilio outbound `media` envelope for the proxy's
//!   `client_out` sink.
//! * Renders the inbound-webhook TwiML that tells Twilio which WS URL to dial.
//! * REFUSES a `start` whose negotiated media format is not `g711_ulaw` / 8000 Hz — a silent format
//!   mismatch would corrupt the barge-in truncate arithmetic without erroring, so it fails closed.
//! * Guards a WS connection's `streamSid` against the value bound at admission, so a forged or replayed
//!   connection cannot inject audio into a session it does not own before any byte is admitted.

use serde::Serialize;

// The crate's ONE base64 implementation. This module used to carry its own copy, justified as
// keeping the envelope free of a new dependency — a justification the crate split retired:
// `busbar-substrate-values` is already an unconditional dependency and `ir/codec` already decodes
// audio through it. Two implementations of one wire primitive in one crate is a drift hazard with
// nothing bought for it, and this is the primitive that turns bytes on a phone call into audio.
use busbar_substrate_values::media::{base64_decode, base64_encode};

/// Twilio's negotiated µ-law encoding string on the `start` event's media format.
pub const TWILIO_MULAW_ENCODING: &str = "audio/x-mulaw";
/// The only sample rate the 8 kHz passthrough carrier accepts.
pub const TWILIO_SAMPLE_RATE: u64 = 8000;
/// The only channel count the mono barge-in arithmetic accepts.
pub const TWILIO_CHANNELS: u64 = 1;

/// A REFUSAL on the Twilio envelope boundary — every variant fails closed rather than admitting a
/// frame the session engine would then trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwilioError {
    /// The WS frame was not the expected Twilio JSON shape (unparseable, or a required field missing).
    Malformed,
    /// A well-formed frame carried an `event` the envelope does not model.
    UnknownEvent(String),
    /// A `media` payload was not valid base64.
    BadPayload,
    /// The `start` event's negotiated media format is not `g711_ulaw` / 8000 Hz / mono — refused so the
    /// wrong-format bytes never reach the barge-in truncate math.
    FormatMismatch {
        /// The encoding Twilio actually negotiated.
        encoding: String,
        /// The sample rate Twilio actually negotiated.
        sample_rate: u64,
        /// The channel count Twilio actually negotiated.
        channels: u64,
    },
    /// The connection presented a `streamSid` that does not match the one bound at admission — a forged
    /// or replayed connection, refused before any byte is admitted.
    Forged {
        /// The `streamSid` bound to this call at admission.
        expected: String,
        /// The `streamSid` the inbound frame actually presented.
        actual: String,
    },
}

impl std::fmt::Display for TwilioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TwilioError::Malformed => write!(f, "malformed Twilio Media Streams frame"),
            TwilioError::UnknownEvent(e) => write!(f, "unknown Twilio event: {e}"),
            TwilioError::BadPayload => write!(f, "Twilio media payload is not valid base64"),
            TwilioError::FormatMismatch {
                encoding,
                sample_rate,
                channels,
            } => write!(
                f,
                "Twilio media format refused: {encoding} {sample_rate}Hz {channels}ch is not g711_ulaw/8000Hz/mono"
            ),
            TwilioError::Forged { expected, actual } => {
                write!(f, "Twilio streamSid mismatch: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for TwilioError {}

/// The negotiated media format Twilio declares on its `start` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaFormat {
    /// The wire encoding (`audio/x-mulaw` for the passthrough carrier).
    pub encoding: String,
    /// The sample rate in Hz (8000 for the passthrough carrier).
    pub sample_rate: u64,
    /// The channel count (1 for the passthrough carrier).
    pub channels: u64,
}

/// The `start` event's carried identity + format — the one place the call's `streamSid`, Twilio's
/// `callSid`, and the negotiated format arrive together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwilioStart {
    /// The `streamSid` Twilio minted for this Media Streams connection, repeated on every later frame.
    pub stream_sid: String,
    /// Twilio's `callSid` for the underlying PSTN call.
    pub call_sid: String,
    /// The negotiated media format to validate against the locked `g711_ulaw` config.
    pub media_format: MediaFormat,
}

/// One decoded Twilio Media Streams event. Only [`TwilioEvent::Media`] carries session audio; the
/// lifecycle variants drive the adapter, not the session pump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwilioEvent {
    /// The one-time handshake event, first on the socket.
    Connected,
    /// The stream opened; carries identity + the negotiated media format.
    Start(TwilioStart),
    /// A ~20 ms audio frame — `payload` is the raw µ-law bytes for `client_in`.
    Media {
        /// The connection's `streamSid`, to check against the admitted value.
        stream_sid: String,
        /// The base64-decoded raw µ-law audio bytes.
        payload: Vec<u8>,
    },
    /// A playback-position ack — corroborates the session's own barge-in clock, never load-bearing.
    Mark {
        /// The connection's `streamSid`.
        stream_sid: String,
        /// The mark name the outbound side chose.
        name: String,
    },
    /// A touch-tone keypress heard on the inbound track — sent only when the stream has DTMF
    /// enabled. It carries no session audio: the adapter discards it exactly like [`Self::Mark`].
    /// It is modelled rather than left unknown because an unmodelled event is a decode ERROR, and a
    /// caller pressing a key must not be handled as a garbled or forged frame.
    Dtmf {
        /// The connection's `streamSid`.
        stream_sid: String,
        /// The key that was pressed (`0`-`9`, `*`, `#`, `A`-`D`), or empty when Twilio omits it.
        digit: String,
    },
    /// The terminal event; the adapter closes `client_in` on it.
    Stop,
}

/// THE TWILIO ENVELOPE CODEC — stateless decode/encode between Twilio's JSON Media Streams frames and
/// the raw µ-law `Vec<u8>` the telephony proxy carries.
pub struct TwilioEnvelope;

impl TwilioEnvelope {
    /// DECODE one inbound Twilio WS frame into a [`TwilioEvent`]. A `media` event's base64 payload is
    /// decoded to raw µ-law bytes. Fails closed on any frame that is not well-formed Twilio JSON.
    pub fn decode(frame: &[u8]) -> Result<TwilioEvent, TwilioError> {
        let v: serde_json::Value =
            serde_json::from_slice(frame).map_err(|_| TwilioError::Malformed)?;
        let event = v
            .get("event")
            .and_then(serde_json::Value::as_str)
            .ok_or(TwilioError::Malformed)?;
        match event {
            "connected" => Ok(TwilioEvent::Connected),
            "start" => {
                let start = v.get("start").ok_or(TwilioError::Malformed)?;
                let stream_sid = start
                    .get("streamSid")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| v.get("streamSid").and_then(serde_json::Value::as_str))
                    .ok_or(TwilioError::Malformed)?
                    .to_string();
                let call_sid = start
                    .get("callSid")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let mf = start.get("mediaFormat").ok_or(TwilioError::Malformed)?;
                let media_format = MediaFormat {
                    encoding: mf
                        .get("encoding")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    sample_rate: mf
                        .get("sampleRate")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or_default(),
                    channels: mf
                        .get("channels")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or_default(),
                };
                Ok(TwilioEvent::Start(TwilioStart {
                    stream_sid,
                    call_sid,
                    media_format,
                }))
            }
            "media" => {
                let stream_sid = v
                    .get("streamSid")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let payload_b64 = v
                    .get("media")
                    .and_then(|m| m.get("payload"))
                    .and_then(serde_json::Value::as_str)
                    .ok_or(TwilioError::Malformed)?;
                let payload = base64_decode(payload_b64)
                    .ok_or(TwilioError::BadPayload)?
                    .to_vec();
                Ok(TwilioEvent::Media {
                    stream_sid,
                    payload,
                })
            }
            "mark" => {
                let stream_sid = v
                    .get("streamSid")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let name = v
                    .get("mark")
                    .and_then(|m| m.get("name"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                Ok(TwilioEvent::Mark { stream_sid, name })
            }
            "dtmf" => {
                let stream_sid = v
                    .get("streamSid")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let digit = v
                    .get("dtmf")
                    .and_then(|d| d.get("digit"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                Ok(TwilioEvent::Dtmf { stream_sid, digit })
            }
            "stop" => Ok(TwilioEvent::Stop),
            other => Err(TwilioError::UnknownEvent(other.to_string())),
        }
    }

    /// ENCODE raw µ-law bytes into a Twilio outbound `media` envelope for a given `stream_sid`. The
    /// field order is fixed so the serialization is deterministic and byte-stable.
    #[must_use]
    pub fn encode_media(stream_sid: &str, mulaw: &[u8]) -> Vec<u8> {
        let out = OutboundMedia {
            event: "media",
            stream_sid,
            media: OutboundPayload {
                payload: base64_encode(mulaw),
            },
        };
        serde_json::to_vec(&out).expect("the outbound media envelope always serializes")
    }
}

#[derive(Serialize)]
struct OutboundMedia<'a> {
    event: &'static str,
    #[serde(rename = "streamSid")]
    stream_sid: &'a str,
    media: OutboundPayload,
}

#[derive(Serialize)]
struct OutboundPayload {
    payload: String,
}

/// ASSERT the negotiated media format is the locked `g711_ulaw` / 8000 Hz / mono carrier, refusing
/// anything else. A mismatch corrupts the 8-bytes-per-ms barge-in arithmetic silently, so it is refused
/// outright rather than reformatted or warned about.
pub fn assert_g711_ulaw(fmt: &MediaFormat) -> Result<(), TwilioError> {
    if fmt.encoding == TWILIO_MULAW_ENCODING
        && fmt.sample_rate == TWILIO_SAMPLE_RATE
        && fmt.channels == TWILIO_CHANNELS
    {
        Ok(())
    } else {
        Err(TwilioError::FormatMismatch {
            encoding: fmt.encoding.clone(),
            sample_rate: fmt.sample_rate,
            channels: fmt.channels,
        })
    }
}

/// THE PRE-ADMISSION FORGERY GUARD — the binding a Twilio Media Streams connection is checked against
/// before any of its bytes are admitted into the session. `call_id` is minted at the TwiML webhook and
/// embedded in the `<Stream>` URL; `stream_sid` is the value Twilio declares at `start` and repeats on
/// every later frame. The proxy/session engine do not authenticate the caller — this guard does, so a
/// replayed or forged WS connection cannot inject audio into a call it does not own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionGuard {
    call_id: String,
    stream_sid: String,
}

impl AdmissionGuard {
    /// Bind the guard from the webhook-minted `call_id` and the `stream_sid` the `start` event
    /// declared. The route calls this once, after [`assert_g711_ulaw`] clears the `start` format.
    #[must_use]
    pub fn bind(call_id: impl Into<String>, stream_sid: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            stream_sid: stream_sid.into(),
        }
    }

    /// The webhook-minted call id this guard is bound to.
    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// The `streamSid` bound at admission.
    #[must_use]
    pub fn stream_sid(&self) -> &str {
        &self.stream_sid
    }

    /// ADMIT an inbound frame's `stream_sid`. A mismatch is a forged/replayed connection and is REFUSED
    /// — the caller must not hand the frame's bytes to `client_in`.
    pub fn admit(&self, stream_sid: &str) -> Result<(), TwilioError> {
        if stream_sid == self.stream_sid {
            Ok(())
        } else {
            Err(TwilioError::Forged {
                expected: self.stream_sid.clone(),
                actual: stream_sid.to_string(),
            })
        }
    }
}

/// Build the `wss://…/twilio/{call_id}` URL Twilio dials, from a WS base and the webhook-minted
/// `call_id`. Kept next to the TwiML renderer so the URL the webhook advertises and the route the WS
/// accepts are derived the one way.
#[must_use]
pub fn stream_url(ws_base: &str, call_id: &str) -> String {
    format!("{}/twilio/{}", ws_base.trim_end_matches('/'), call_id)
}

/// Render the inbound-webhook TwiML that tells Twilio to open a Media Streams WS to `ws_url`. Pure: it
/// carries no audio and no provider secret, exactly one variable (the URL, XML-escaped).
#[must_use]
pub fn render_connect_stream(ws_url: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response><Connect><Stream url=\"{}\"/></Connect></Response>",
        xml_escape(ws_url)
    )
}

/// Render the webhook TwiML directly from a WS base and the minted `call_id` — the composition the
/// webhook handler uses.
#[must_use]
pub fn render_twiml_for_call(ws_base: &str, call_id: &str) -> String {
    render_connect_stream(&stream_url(ws_base, call_id))
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/twilio_tests.rs"]
mod twilio_tests;

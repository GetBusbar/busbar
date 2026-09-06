// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAYER 3 — MEDIA / AUDIO-FRAME (VERBATIM by default — an identity IR). Design `plane4-duplex-session.md`.
//!
//! Audio frames (`input_audio_buffer.append` up; `response.output_audio.delta` down) are byte-relayed
//! VERBATIM by default. Per `plane4-duplex-session.md` this is still an IR — the tap point for meter and audit, and the seam
//! where the OPTIONAL transcode (g711 ↔ pcm24k for telephony) would live, armed only when a lane
//! declares it. The transport primitive that carries it (`pipe_read`/`pipe_write`) moves RAW BYTES;
//! the plane frames on top.
//!
//! The wire encodes audio as base64 STRINGS inside JSON events; the codec (see [`crate::ir::codec`])
//! base64-decodes on the way in and re-encodes on the way out, storing the DECODED bytes in
//! [`IrAudioFrame::media`]. The identity IR is the decoded bytes, not the base64 text.

use bytes::Bytes;

/// DIRECTION OF TRAVEL for one framed audio message — the plane frames on top of a byte-duplex pipe,
/// so each frame carries which way it flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpDown {
    /// Client → server (`input_audio_buffer.append`).
    Up,
    /// Server → client (`response.output_audio.delta`).
    Down,
}

/// THE NEGOTIATED PCM WIRE FORMAT (`plane4-duplex-session.md` audio-format field). Two dialect-normalized shapes:
/// signed-16-bit little-endian PCM at 24 kHz (the Realtime default) and G.711 µ-law at 8 kHz (the
/// telephony format). The plane needs this to turn a byte count into a millisecond position — the
/// barge-in truncate math (`plane4-duplex-session.md`) — because raw PCM carries no timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioFormat {
    /// Signed 16-bit little-endian PCM, 24 kHz, mono — the Realtime default (`pcm16`).
    Pcm16,
    /// G.711 µ-law, 8 kHz, mono — the telephony format (`g711_ulaw`).
    G711Ulaw,
}

impl AudioFormat {
    /// The dialect wire token for this format (`pcm16` / `g711_ulaw`).
    #[must_use]
    pub fn wire_name(self) -> &'static str {
        match self {
            AudioFormat::Pcm16 => "pcm16",
            AudioFormat::G711Ulaw => "g711_ulaw",
        }
    }

    /// Parse a dialect wire token into a format, or `None` for an unrecognized one. `g711_alaw` is
    /// deliberately not modeled yet — the plane speaks only the two formats it negotiates today.
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "pcm16" => Some(AudioFormat::Pcm16),
            "g711_ulaw" => Some(AudioFormat::G711Ulaw),
            _ => None,
        }
    }

    /// Bytes of audio per millisecond of playback. pcm16 = 24 samples/ms × 2 bytes = 48; g711 µ-law =
    /// 8 samples/ms × 1 byte = 8. This is the constant the barge-in truncate math divides by.
    #[must_use]
    pub fn bytes_per_ms(self) -> u64 {
        match self {
            // 24_000 Hz × 2 bytes/sample / 1000 ms.
            AudioFormat::Pcm16 => 48,
            // 8_000 Hz × 1 byte/sample / 1000 ms.
            AudioFormat::G711Ulaw => 8,
        }
    }

    /// Convert a byte count of audio into its playback duration in whole milliseconds (truncating).
    #[must_use]
    pub fn bytes_to_ms(self, bytes: u64) -> u64 {
        bytes / self.bytes_per_ms()
    }

    /// Convert a playback duration in milliseconds into the byte count that carries it.
    #[must_use]
    pub fn ms_to_bytes(self, ms: u64) -> u64 {
        ms * self.bytes_per_ms()
    }
}

/// THE PURE BARGE-IN TRUNCATE HELPER (`plane4-duplex-session.md`). Given the total bytes of downlink audio the plane has
/// actually PLAYED OUT to the client for one item, compute the `audio_played_ms` truncate point — the
/// audio the user genuinely heard. On WebSocket the upstream emits audio faster than realtime, so this
/// count is the plane's own playback-position bookkeeping ([`crate::ir::codec::DecodeState`]), never a
/// field copied off the wire. The runtime that ACTS on this (cancel + truncate) is the next layer;
/// this function is the arithmetic only.
#[must_use]
pub fn truncate_point_ms(bytes_played: u64, fmt: AudioFormat) -> u64 {
    fmt.bytes_to_ms(bytes_played)
}

/// THE NEUTRAL AUDIO-FRAME IR (`plane4-duplex-session.md`). `media` is OPAQUE — the identity transform by default; the IR
/// exists for the meter/audit tap, not the reshape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrAudioFrame {
    /// Which direction this frame travels.
    pub dir: UpDown,
    /// Monotonic per-direction sequence number (audit ordering / gap detection).
    pub seq: u64,
    /// The audio payload — opaque bytes, relayed verbatim under the identity transform by default.
    pub media: Bytes,
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAYER 3 — MEDIA / AUDIO-FRAME (VERBATIM by default — an identity IR). Design §2.4.
//!
//! Audio frames (`input_audio_buffer.append` up; `response.output_audio.delta` down) are byte-relayed
//! VERBATIM by default. Per §2.1 this is still an IR — the tap point for meter and audit, and the seam
//! where the OPTIONAL transcode (g711 ↔ pcm24k for telephony) would live, armed only when a lane
//! declares it. The transport primitive that carries it (`pipe_read`/`pipe_write`) moves RAW BYTES;
//! the plane frames on top.

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

/// THE NEUTRAL AUDIO-FRAME IR (§2.4). `media` is OPAQUE — the identity transform by default; the IR
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

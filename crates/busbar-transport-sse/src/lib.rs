// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `sse` transport: one request, N response frames, composed over `http`.
//!
//! `sse` carries no session of its own; it inherits `http`'s per-frame `WireStatusClass` at the first
//! response frame, exactly as the design's composition rule states ("a composed transport
//! inherits the lower layer's status leg"). This crate does not open a socket itself: `dial`
//! delegates straight to an [`busbar_transport_http::HttpTransport`] it holds, and `frames`
//! re-segments the byte stream `http` already assembled at the SSE frame terminator (a blank
//! line), using the terminator scan [`proto`] carries — ported from `busbar_substrate::proto` per
//! the design's rule that a transport's own wire pieces live in the transport crate.
//!
//! The re-segmentation buffer is held to the design's per-connection reading budget
//! (`MAX_CURSOR_BYTES`). Upstream bytes are untrusted, and this is the one accumulator with no cap
//! a layer above it: the served door's request-body limit does not reach a streamed response body.
//! An upstream that opens an event stream and never writes a blank line ends it with `Framing`
//! rather than growing this buffer for the life of the connection.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;

use busbar_contract::{Kind, Plugin, TransportMeta};
use busbar_transport_http::HttpTransport;

pub(crate) mod proto;
pub mod reframe;

/// Carve every complete SSE frame sitting at the front of `buf`, resuming the terminator scan at
/// `scanned` (rewound by three, the most of a four-byte terminator a previous look can have left
/// straddling the boundary).
///
/// Returns the carved frames alongside how many bytes this call RELOCATED inside `buf` — the pair a
/// caller uses to pin the carve's own complexity class without a process-global counter racing every
/// other test in the binary, exactly as the scan reports the bytes it examined. Carving through a
/// read offset and compacting once at the end holds that figure to one buffer's worth however many
/// frames the buffer holds; removing each frame as it is found instead moves the whole remaining
/// tail once per frame, which is quadratic in the number of frames one buffer arrives holding — the
/// ordinary shape when an upstream flushes a batch of events in a single body.
fn carve_complete_frames(buf: &mut Vec<u8>, scanned: usize) -> (Vec<Vec<u8>>, usize) {
    let mut carved: Vec<Vec<u8>> = Vec::new();
    let mut moved = 0_usize;
    let mut resume = scanned;
    // How much of `buf` has been carved into a frame already. Nothing is removed inside the loop:
    // the scan simply resumes past what it has taken.
    let mut consumed = 0_usize;
    while let (Some((offset, term_len)), _) =
        proto::find_frame_terminator_from(&buf[consumed..], resume.saturating_sub(3))
    {
        let end = consumed + offset + term_len;
        carved.push(buf[consumed..end].to_vec());
        consumed = end;
        // What follows a carved frame is a fresh frame's worth of bytes, none of it yet proven.
        resume = 0;
    }
    if consumed > 0 {
        // The one compaction: whatever is left of the last, incomplete frame moves to the front,
        // once, no matter how many frames came off the front before it.
        moved += buf.len() - consumed;
        buf.drain(..consumed);
    }
    (carved, moved)
}

/// The `sse` transport.
pub struct SseTransport {
    http: Arc<HttpTransport>,
}

impl std::fmt::Debug for SseTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SseTransport").finish_non_exhaustive()
    }
}

impl SseTransport {
    /// Compose `sse` over an already-built `http` transport.
    #[must_use]
    pub fn new(http: Arc<HttpTransport>) -> Self {
        Self { http }
    }
}

impl Plugin for SseTransport {
    fn key(&self) -> &'static str {
        Self::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> busbar_contract_transport::AbiVersion {
        busbar_contract_transport::registry::TRANSPORT_ABI
    }
}

pub mod claims;
pub mod meta;
mod transport;

#[cfg(test)]
mod tests;

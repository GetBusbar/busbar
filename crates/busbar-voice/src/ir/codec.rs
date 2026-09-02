// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE READER / WRITER PAIR — the bidirectional analog of the LLM plane's
//! `ProtocolReader`/`ProtocolWriter`. Design §2.6.
//!
//! The single design delta vs the LLM `ProtocolReader` is that Plane 4 needs a client→server event
//! vocabulary, so the plane defines TWO DIRECTIONS over one wire schema (the MCP "one reader, one
//! writer, both directions" discipline). SKELETON: trait signatures only; the bodies are the P2 build.

use crate::ir::event::{IrClientEvent, IrServerEvent};

/// ONE WIRE EVENT — the opaque, dialect-shaped message a reader parses / a writer produces. SKELETON:
/// a newtype over raw bytes (the OpenAI Realtime dialect frames JSON; a future dialect frames its
/// own). Kept deliberately opaque so the reader/writer own all framing knowledge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireEvent(pub bytes::Bytes);

/// PER-SESSION DECODE STATE threaded through [`DuplexReader::read_down`] — the analog of the LLM
/// reader's `StreamDecodeState`. Holds what is per-session, not per-frame: barge-in playback-position
/// tracking (§2.3) and `CallRef` correlation (§2.2). SKELETON: an empty, non-exhaustive stub.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct DecodeState {}

/// WIRE → IR. Reads a dialect's wire events into the plane's neutral IR, in both directions.
///
/// One wire event maps to 0..n IR events (the `read_response_events` shape). `read_up` yields the NEW
/// client→server vocabulary; `read_down` threads per-session [`DecodeState`].
pub trait DuplexReader {
    /// Client→server events (the net-new vocabulary): audio uplink, config, tool results.
    fn read_up(&self, evt: WireEvent) -> Vec<IrClientEvent>;

    /// Server→client events, threading per-session decode state (barge-in position, `CallRef` map).
    fn read_down(&self, evt: WireEvent, st: &mut DecodeState) -> Vec<IrServerEvent>;
}

/// IR → WIRE. Re-frames the plane's neutral IR back onto a dialect's wire, in both directions.
pub trait DuplexWriter {
    /// Re-frame a client→server event onto the UPSTREAM dialect's wire.
    fn write_up(&self, ev: IrClientEvent) -> WireEvent;

    /// Re-frame a server→client event onto the CLIENT dialect's wire.
    fn write_down(&self, ev: IrServerEvent) -> WireEvent;
}

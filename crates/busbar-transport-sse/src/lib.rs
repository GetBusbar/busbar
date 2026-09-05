// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `sse` transport: one request, N response frames, composed over `http`.
//!
//! `sse` carries no session of its own; it inherits `http`'s per-frame `StatusClass` at the first
//! response frame, exactly as the design's composition rule states ("a composed transport
//! inherits the lower layer's status leg"). This crate does not open a socket itself: `dial`
//! delegates straight to an [`busbar_transport_http::HttpTransport`] it holds, and `frames`
//! re-segments the byte stream `http` already assembled at the SSE frame terminator (a blank
//! line), using the parser [`proto`] carries — ported from `busbar_substrate::proto` per the
//! design's rule that a transport's own wire pieces live in the transport crate.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;

use busbar_contract::{
    ArenaBytes, Frame, Fut, Kind, Plugin, Refusal, SlabBytes, StreamId, Transport,
    TransportConfigView, TransportKeyHandle, TransportMeta,
};
use busbar_contract_transport::wire::ArrivalRecord;
use busbar_contract_transport::wire::CloseReason;
use busbar_contract_transport::wire::Conn;
use busbar_contract_transport::wire::Direction;
use busbar_contract_transport::wire::FrameMeta;
use busbar_contract_transport::wire::Listener;
use busbar_contract_transport::wire::TransportError;
use busbar_transport_http::HttpTransport;
use futures::{Stream, StreamExt};

pub mod proto;

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
        busbar_contract_transport::AbiVersion(1)
    }
}

impl TransportMeta for SseTransport {
    const KEY: &'static str = "sse";
    const SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] = &[];
    const EGRESS_SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] = &[];
    const COMPOSES_OVER: &'static [&'static str] = &["http"];
    const HANDOFF: Option<busbar_contract_transport::wire::Handoff> = None;
    const FRAMING: busbar_contract_transport::wire::Framing =
        busbar_contract_transport::wire::Framing::Stream;
    const SESSION: bool = false;
    const SESSION_BOUND: bool = false;
    const UNIT0_TRIGGER: Option<busbar_contract_transport::wire::Unit0Trigger> = None;
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract_transport::wire::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[];
    const DECODES_PAYLOAD: bool = false;
    const STATUS_CLASS: Option<busbar_contract_transport::wire::StatusAt> =
        Some(busbar_contract_transport::wire::StatusAt::FirstFrame);
}

impl Transport for SseTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        let mut record = self.http.arrival(conn);
        record.transport_chain.push("sse");
        record
    }

    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        self.http.listen(cfg, keys)
    }

    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        self.http.accept(l)
    }

    fn dial<'a>(
        &'a self,
        dest: &'a busbar_contract::VerifiedDestination,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        self.http.dial(dest, keys)
    }

    fn frames(
        &self,
        conn: Conn,
    ) -> Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>> {
        let inner = self.http.frames(conn);
        // State: the underlying `http` frame stream, an accumulation buffer for bytes not yet at
        // a complete SSE terminator, the status class carried by `http`'s own first frame (the
        // inherited status leg), and whether that status has already been attached to an emitted
        // frame.
        type FrameStream =
            Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>>;
        struct State {
            inner: FrameStream,
            buf: Vec<u8>,
            pending: VecDeque<(
                Vec<u8>,
                Option<busbar_contract_transport::wire::StatusClass>,
            )>,
            status: Option<busbar_contract_transport::wire::StatusClass>,
            status_attached: bool,
            done: bool,
        }
        let state = State {
            inner,
            buf: Vec::new(),
            pending: VecDeque::new(),
            status: None,
            status_attached: false,
            done: false,
        };
        Box::pin(futures::stream::unfold(state, move |mut st| async move {
            loop {
                if let Some((raw, status)) = st.pending.pop_front() {
                    let len = raw.len() as u64;
                    let bytes: Arc<[u8]> = raw.into();
                    let frame = Frame {
                        direction: Direction::Inbound,
                        stream: StreamId(0),
                        bytes: SlabBytes::new(bytes),
                        meta: FrameMeta {
                            bytes: len,
                            transport_units: None,
                            status,
                        },
                    };
                    return Some((Ok((StreamId(0), frame)), st));
                }
                if st.done {
                    return None;
                }
                match st.inner.next().await {
                    Some(Ok((_s, http_frame))) => {
                        if let Some(status) = http_frame.meta.status {
                            // `http`'s HEAD frame: remember its status leg, do not emit it as an
                            // SSE frame of our own — it carries no SSE payload.
                            st.status = Some(status);
                            continue;
                        }
                        st.buf.extend_from_slice(http_frame.bytes.as_slice());
                        while let Some((offset, term_len)) = proto::find_frame_terminator(&st.buf) {
                            let end = offset + term_len;
                            let raw: Vec<u8> = st.buf.drain(..end).collect();
                            if proto::parse_sse_frame(&raw).is_some() {
                                let status = if st.status_attached {
                                    None
                                } else {
                                    st.status_attached = true;
                                    st.status
                                };
                                st.pending.push_back((raw, status));
                            }
                        }
                        if !st.pending.is_empty() {
                            continue;
                        }
                    }
                    Some(Err(e)) => {
                        st.done = true;
                        return Some((Err(e), st));
                    }
                    None => {
                        // A trailing frame with no terminator (a stream that ends mid-frame) is
                        // dropped rather than guessed complete — the design's own rule that a
                        // stream dying before its trailer posts the lower evidence.
                        return None;
                    }
                }
            }
        }))
    }

    fn write<'a>(
        &'a self,
        conn: &'a Conn,
        stream: StreamId,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, usize> {
        self.http.write(conn, stream, bytes)
    }

    fn encode_envelope<'a>(
        &self,
        fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn busbar_contract::Arena,
    ) -> Result<busbar_contract::ArenaBytes<'a>, busbar_contract_transport::wire::Encode> {
        // `sse` is a reading of an `http` response, and an outbound request on it is an HTTP one.
        self.http.encode_envelope(fields, body, arena)
    }

    fn adopt<'a>(
        &'a self,
        from: &'a dyn Transport,
        conn: Conn,
        keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        self.http.adopt(from, conn, keys)
    }

    fn detach(&self, conn: &Conn) -> Option<busbar_contract_transport::wire::RawStream> {
        self.http.detach(conn)
    }

    fn composed_over(&self) -> Option<&'static str> {
        // `sse` holds no socket of its own — `new` takes the `http` it is composed over, and that
        // is the only way one is ever built.
        Some(self.http.key())
    }

    fn close(&self, conn: Conn, reason: CloseReason) {
        self.http.close(conn, reason);
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        stream: Option<StreamId>,
        refusal: &'a Refusal,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, ()> {
        self.http.unit0_refusal(conn, stream, refusal, bytes)
    }
}

#[cfg(test)]
mod tests;

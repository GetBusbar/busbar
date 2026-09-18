// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The [`busbar_contract::Transport`] implementation itself.
//!
//! `sse` holds no socket: every method here delegates to the `http` transport it was composed
//! over, except `frames`, which re-segments `http`'s byte stream at the SSE frame terminator. The
//! struct, its constructor and the carve helper live in the crate root; this module carries only
//! the trait surface the kernel drives, so a sibling reader finds the same `transport.rs` in every
//! wire.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;

use busbar_contract::{
    ArenaBytes, Frame, Fut, Plugin, Refusal, SlabBytes, StreamId, Transport, TransportConfigView,
    TransportKeyHandle,
};
use busbar_contract_transport::wire::ArrivalRecord;
use busbar_contract_transport::wire::CloseReason;
use busbar_contract_transport::wire::Conn;
use busbar_contract_transport::wire::Direction;
use busbar_contract_transport::wire::FrameMeta;
use busbar_contract_transport::wire::Listener;
use busbar_contract_transport::wire::TransportError;
use futures::{Stream, StreamExt};

use crate::{carve_complete_frames, proto, SseTransport};

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
        /// The status leg `http` read off the response head, kept whole. Splitting the class from
        /// the number and the requested wait would let one of the three ride out on an SSE frame
        /// without the others — they describe one answer, so they move as one.
        #[derive(Clone, Copy, Default)]
        struct StatusLeg {
            class: Option<busbar_contract_transport::wire::WireStatusClass>,
            code: Option<busbar_contract_transport::wire::WireStatus>,
            retry_after_secs: Option<u64>,
        }
        struct State {
            inner: FrameStream,
            buf: Vec<u8>,
            /// How much of `buf` has already been proven not to hold a frame terminator. The scan
            /// resumes from here (rewound by three, the most of a four-byte terminator a previous
            /// look can have left straddling the boundary) instead of starting over on every
            /// arriving chunk, which for one large trickled frame is the difference between a pass
            /// over the frame and a pass per chunk.
            scanned: usize,
            pending: VecDeque<(Vec<u8>, StatusLeg)>,
            status: StatusLeg,
            status_attached: bool,
            done: bool,
        }
        let state = State {
            inner,
            buf: Vec::new(),
            scanned: 0,
            pending: VecDeque::new(),
            status: StatusLeg::default(),
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
                            status: status.class,
                            status_code: status.code,
                            retry_after_secs: status.retry_after_secs,
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
                            // SSE frame of our own — it carries no SSE payload. The whole leg is
                            // remembered, not just the class: the number and the requested wait
                            // are facts about the same answer and travel with it.
                            st.status = StatusLeg {
                                class: Some(status),
                                code: http_frame.meta.status_code,
                                retry_after_secs: http_frame.meta.retry_after_secs,
                            };
                            continue;
                        }
                        st.buf.extend_from_slice(http_frame.bytes.as_slice());
                        let (carved, _moved) = carve_complete_frames(&mut st.buf, st.scanned);
                        for raw in carved {
                            // Whether this frame carries an SSE field at all is the only question
                            // here; the payload itself travels on untouched, so a full parse would
                            // build one only to drop it. A comment frame — the ordinary `: ping`
                            // keepalive — carries none and is the one thing there is nothing to
                            // hand up for.
                            if proto::frame_carries_a_field(&raw) {
                                let status = if st.status_attached {
                                    StatusLeg::default()
                                } else {
                                    st.status_attached = true;
                                    st.status
                                };
                                st.pending.push_back((raw, status));
                            }
                        }
                        st.scanned = st.buf.len();
                        if st.buf.len() > busbar_contract::MAX_CURSOR_BYTES {
                            // What is left after every complete frame has been drained is ONE
                            // frame's prefix, and the design's per-connection reading budget is
                            // what one frame is allowed to be. Upstream bytes are untrusted and
                            // this buffer has no cap a layer up — a streamed response body is
                            // exactly what the served door's body limit does not reach — so an
                            // upstream that never ends a frame would grow it for the life of the
                            // connection. Ended here instead.
                            //
                            // Frames carved off the front of this same buffer are dropped with it.
                            // The error is the stream's last word, and a consumer that kept polling
                            // would otherwise be handed an event AFTER it — payload out of a body
                            // this transport has just refused to go on reading.
                            st.done = true;
                            st.pending.clear();
                            return Some((Err(TransportError::Framing), st));
                        }
                        if !st.pending.is_empty() {
                            continue;
                        }
                    }
                    Some(Err(e)) => {
                        // The same rule the cursor budget's own error follows: an error is
                        // terminal, so nothing queued behind it goes out after it.
                        st.done = true;
                        st.pending.clear();
                        return Some((Err(e), st));
                    }
                    None => {
                        st.done = true;
                        // An upstream that answered with an error status and then a body that is
                        // not an event stream — a rate limiter's JSON, say — carves into no frames
                        // at all, so the status leg `http` read off the response head has nothing
                        // to ride out on and the consumer sees a clean empty success. The upstream's
                        // own answer has to survive the composition: the buffered body goes out as
                        // one final frame wearing that leg. When there is no body to carry it, no
                        // frame is defensible and the framing error is what is left.
                        let failing = matches!(
                            st.status.class,
                            Some(busbar_contract_transport::wire::WireStatusClass::ClientError)
                                | Some(
                                    busbar_contract_transport::wire::WireStatusClass::ServerError
                                )
                                | Some(busbar_contract_transport::wire::WireStatusClass::Other)
                        );
                        if failing && !st.status_attached {
                            if st.buf.is_empty() {
                                return Some((Err(TransportError::Framing), st));
                            }
                            st.status_attached = true;
                            let raw = std::mem::take(&mut st.buf);
                            st.pending.push_back((raw, st.status));
                            continue;
                        }
                        // A stream that ends MID-FRAME. What is left in the buffer is one event's
                        // prefix: the upstream began an event and the body ended before it did.
                        //
                        // Guessing it complete is out — this transport does not invent a terminator
                        // the upstream never wrote. Ending clean is out too, and that is what 1.5.5
                        // decides: a body that failed part-way through was surfaced to the caller
                        // as an error, never delivered as a shorter answer that arrived
                        // (`docs/design/inventory/1.5.5-proxy-hooks.md:406-407` — the mid-stream and
                        // pre-first-byte rows, both of which end the body stream with an error). So
                        // it is a framing error, which is also the reading the sibling `stdio` crate
                        // gives a line the peer never finished.
                        //
                        // Only when the leftover is actually an event. The layer below hands up a
                        // trailer section as a frame of its own, and a header block is not a
                        // half-written event — it carries no SSE field, so it ends the stream
                        // cleanly, as it did before.
                        if proto::frame_carries_a_field(&st.buf) {
                            return Some((Err(TransportError::Framing), st));
                        }
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

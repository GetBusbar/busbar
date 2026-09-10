// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO ENDS OF A REAL SOCKET, as the generic mount's session loop wants them.
//!
//! [`crate::mount`] is written against [`crate::mount::FrameSource`] and
//! [`crate::mount::FrameSink`] rather than against a socket, so that the rules in it — ordering, the
//! backpressure posture, which end cut, one close per session — are exercisable at the seam instead
//! of only through a network. This module is the other half of that arrangement: the implementation
//! over the actual `tokio_tungstenite::WebSocketStream`, with nothing in it that decides anything.
//!
//! ## What lives here and not in the pump, and why the line is where it is
//!
//! Two of the three bounds a duplex session runs under are HERE rather than in the pump, and both
//! for the same reason: they are about this WIRE's own frames.
//!
//! * **The keepalive.** A Ping is a frame of the WebSocket protocol that carries no plane data, and
//!   `tokio-tungstenite` does not answer one on a split stream. So it is answered here, and the pump
//!   never sees it — a pump that answered a Ping would be a pump that knew what a Ping is, which is
//!   exactly the knowledge the generic mount is arranged not to have.
//!
//! * **The message ceiling.** It is the CARRIER's, because the carrier is what buffers a partial
//!   message before anything above it has been handed a byte; a check above would only refuse bytes
//!   already in this node's heap. It is set on the `WebSocketConfig` this transport builds every
//!   connection with, and an oversized message therefore ends the read rather than reaching the pump.
//!
//! The third — how long the whole session may run — is the pump's, because it is about the SESSION
//! rather than about a frame.
//!
//! ## The one thing the media type decides
//!
//! This wire has two frame kinds and the declaration is the only thing entitled to say which one a
//! plane's bytes are. A wire with one kind ignores the media type; this one reads it. Nothing else
//! about the bytes is looked at: the payload is the plane's, whole, in both directions.

use std::future::Future;
use std::sync::Arc;

use busbar_contract_transport::session::EgressLease;
use busbar_contract_transport::wire::TransportError;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use tokio::sync::Mutex as AsyncMutex;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;

use crate::conn::Sock;
use crate::mount::{FrameSink, FrameSource};
use crate::transport::{read_error, CLOSE_BUDGET, PONG_BUDGET};

/// Split one upgraded socket into the two ends a session runs over.
///
/// The write half is SHARED, behind one lock, and it has to be: the keepalive answer is a write the
/// read half makes, and two unsynchronised writers on one WebSocket produce interleaved frames,
/// which is a protocol error rather than a race that resolves itself.
#[must_use]
pub(crate) fn split(sock: Sock) -> (WsFrames, WsSink) {
    let (writer, reader) = sock.split();
    let writer = Arc::new(AsyncMutex::new(writer));
    (
        WsFrames {
            reader,
            writer: Arc::clone(&writer),
        },
        WsSink { writer },
    )
}

/// The inbound half of one upgraded socket.
pub(crate) struct WsFrames {
    reader: SplitStream<Sock>,
    writer: Arc<AsyncMutex<SplitSink<Sock, Message>>>,
}

impl FrameSource for WsFrames {
    async fn next_frame(&mut self) -> Option<Result<Vec<u8>, TransportError>> {
        loop {
            match self.reader.next().await {
                // The stream finished, or the peer closed. Both are the ORDERLY end the pump takes
                // as the client's cut, and a close frame is not a frame of the session: a plane that
                // was handed one would be handed a byte the peer never sent it.
                None | Some(Ok(Message::Close(_))) => return None,
                Some(Ok(Message::Binary(bytes))) => return Some(Ok(bytes.to_vec())),
                Some(Ok(Message::Text(text))) => return Some(Ok(text.as_bytes().to_vec())),
                // THE KEEPALIVE, answered here and never handed up. It is a protocol-blind,
                // byte-level obligation of this wire and carries no plane data at all.
                //
                // The answer is the one write in this crate that nothing above it can cancel: this
                // half is suspended INSIDE it, so a peer that pings and then stops reading would
                // park the session in the send for as long as it liked, holding the socket for the
                // life of the process. The budget is what ends that, and the failure is REPORTED
                // rather than swallowed — a session whose keepalive never landed is not a healthy
                // session, and returning to the read would tell the pump it was.
                Some(Ok(Message::Ping(payload))) => {
                    let answered = tokio::time::timeout(PONG_BUDGET, async {
                        let mut w = self.writer.lock().await;
                        w.send(Message::Pong(payload)).await
                    })
                    .await;
                    match answered {
                        Ok(Ok(())) => continue,
                        Ok(Err(e)) => return Some(Err(read_error(&e))),
                        Err(_) => return Some(Err(TransportError::Backpressure)),
                    }
                }
                // A Pong answers a Ping this side sent, and a raw Frame is a fragment the library
                // has not finished assembling. Neither is a frame of the session.
                Some(Ok(Message::Pong(_) | Message::Frame(_))) => continue,
                Some(Err(e)) => return Some(Err(read_error(&e))),
            }
        }
    }
}

/// The outbound half of one upgraded socket.
pub(crate) struct WsSink {
    writer: Arc<AsyncMutex<SplitSink<Sock, Message>>>,
}

/// Whether the declaration's media type names a TEXT frame on this wire.
///
/// This wire has two kinds and the declaration is the only thing entitled to choose. The rule is the
/// media type's own registry rule and not a list of protocols: the `text/` tree is text by
/// definition, and the `+json` structured-syntax suffix (and `application/json` itself) is a
/// character-encoded document whose consumers on this wire universally expect a text frame.
/// Everything else is bytes, which is the safe answer for a payload whose encoding is not stated:
/// a binary payload sent as text is a protocol error the moment it is not valid UTF-8.
#[must_use]
pub(crate) fn is_text_media(media: &str) -> bool {
    let media = media.split(';').next().unwrap_or(media).trim();
    media.starts_with("text/") || media == "application/json" || media.ends_with("+json")
}

impl FrameSink for WsSink {
    async fn write_frame(&mut self, frame: &[u8], media: &str) -> Result<(), TransportError> {
        // The bytes are the plane's, whole, and the only decision made about them is which of this
        // wire's two kinds carries them — which the DECLARATION made, not this function.
        let message = if is_text_media(media) {
            match std::str::from_utf8(frame) {
                Ok(text) => Message::Text(text.into()),
                // The declaration said text and the plane wrote something that is not. Sending it
                // as a text frame would put invalid UTF-8 in a frame whose kind promises otherwise,
                // which every conforming peer must fail the connection on; sending it as bytes
                // delivers what the plane actually wrote. The disagreement is the declaration's to
                // fix and neither answer is this function's to invent, so it delivers.
                Err(_) => Message::Binary(frame.to_vec().into()),
            }
        } else {
            Message::Binary(frame.to_vec().into())
        };
        let mut w = self.writer.lock().await;
        w.send(message).await.map_err(|e| read_error(&e))
    }

    async fn write_close(&mut self, code: u16) {
        // Best effort, bounded, and nothing reads the result — the session is over either way, and a
        // close that could fail the ending would let a peer that stopped reading decide how this
        // node records what happened. The budget is what keeps the write from outliving the session:
        // a peer whose receive window is full never accepts the frame.
        let _ = tokio::time::timeout(CLOSE_BUDGET, async {
            let mut w = self.writer.lock().await;
            let _ = w
                .send(Message::Close(Some(CloseFrame {
                    code: CloseCode::from(code),
                    reason: "".into(),
                })))
                .await;
            let _ = w.close().await;
        })
        .await;
    }
}

/// THE OFFERING END OF AN UPSTREAM LEG: a bounded queue, and refusal when it is full.
///
/// The whole of why it is a queue at all is that the driver seam it serves is SYNCHRONOUS — see
/// [`busbar_contract_transport::session::EgressLease`]'s own header — and a socket write is not. So
/// the hand-off is a `try_send` and never a wait: the sender is the session's one thread, and a wait
/// here would suspend the inbound pump behind an upstream that stopped reading.
///
/// `finish` drops the sender rather than sending a sentinel, because the channel already carries
/// "no more" in its own vocabulary and a sentinel is a value the drain would have to be trusted to
/// recognise. Dropping it is the same statement with nothing to get wrong, and it is idempotent
/// because a cell that is already empty stays empty.
pub(crate) struct ChannelLease {
    tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
}

impl EgressLease for ChannelLease {
    fn offer(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        let Some(tx) = self.tx.as_ref() else {
            return Err(TransportError::Closed);
        };
        match tx.try_send(frame.to_vec()) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                Err(TransportError::Backpressure)
            }
            // The far end is gone, so the lease is over and every later offer is over too. The cell
            // is cleared here rather than left holding a sender nothing reads, so a caller that
            // ignores this answer and offers again gets the same one for a reason that is now
            // local.
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.tx = None;
                Err(TransportError::Closed)
            }
        }
    }

    fn finish(&mut self) {
        self.tx = None;
    }
}

/// THE DRAINING END: everything offered, in order, onto the upstream socket, then the close.
///
/// RETURNED by the dial rather than spawned inside it, and that is the ownership statement the whole
/// arrangement rests on: a transport that spawned this would be a transport deciding what runtime
/// the composition's tasks live on and when they are cancelled. The root spawns it, beside the
/// session it belongs to, and drops it with the session.
///
/// A write that fails ends the drain rather than being retried: the leg is one socket, the frames
/// are a session's and in order, and a frame skipped over would be a hole in a stream whose reader
/// has no way to see one. The lease's next offer answers `Closed`, which is how the driver finds out.
pub(crate) async fn drain_egress(
    mut frames: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut sink: WsSink,
    media: String,
) {
    while let Some(frame) = frames.recv().await {
        if sink.write_frame(&frame, &media).await.is_err() {
            // Nothing left to close politely on: the write that just failed was the attempt.
            return;
        }
    }
    // Every ending that reaches here is orderly — the lease was finished, or the session that held
    // it was dropped — and an upstream this node opened is owed the close its protocol defines.
    sink.write_close(crate::mount::close_code(
        busbar_contract_transport::wire::CloseReason::Normal,
    ))
    .await;
}

/// Mint the pair one upstream leg is offered and drained through.
pub(crate) fn lease(
    depth: usize,
    sink: WsSink,
    media: &str,
) -> (ChannelLease, impl Future<Output = ()> + Send) {
    // A zero-depth channel is not a channel `try_send` can ever put anything into, so the floor is
    // one: a lease nothing can be offered to would refuse a healthy session's first frame.
    let (tx, rx) = tokio::sync::mpsc::channel(depth.max(1));
    (
        ChannelLease { tx: Some(tx) },
        drain_egress(rx, sink, media.to_string()),
    )
}

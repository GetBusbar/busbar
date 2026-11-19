// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MESSAGES ON A WEBSOCKET UPSTREAM: the write after the open, and the read's message ends.
//!
//! An HTTP exchange hands the connection its whole request at the open, so `Exchange::write`
//! refuses any later bytes. A WebSocket exchange is the opposite: its open is the handshake, and
//! everything after the 101 is messages, both ways, until one side closes. The states are
//! `crate::outbound::ws::Upstream`; this file is where the exchange and the connection use them.
//!
//! DECLARED by `native_conns.rs`: `Exchange::ws` is set by `open_native` for a WebSocket carrier,
//! `Exchange::write` and `Exchange::read` call the two functions below.

use std::task::{Context, Poll};

use busbar_contract::conn::{ConnError, Piece, PieceKind};
use busbar_contract::storage::StorageSource;

use super::{Exchange, State};

use crate::outbound::ws::{Kind, Message, Refusal, Upstream};

impl Exchange {
    /// CALLED by `Exchange::write` in place of its refusal of a non-empty write, when `self.ws`
    /// is set. `text` and `end` are the connection table's own write arguments: the message's
    /// kind (on its first piece) and whether this piece ends it. An empty write with `end` after
    /// a finished message is the engine's close.
    ///
    /// # Errors
    /// `Pending` until the 101 arrived or while the socket queue is full (the caller's ticket is
    /// woken); `Closed` after either side closed or when the handshake was refused; `Refused`
    /// for pieces out of order.
    pub(crate) fn write_message(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &[u8],
        (text, end): (bool, bool),
        storage: &StorageSource,
    ) -> Result<usize, ConnError> {
        // The handshake request goes first, exactly as an HTTP request does.
        let stream = match self.send(cx, storage) {
            Poll::Pending => return Err(ConnError::Pending),
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Ready(Ok(stream)) => stream,
        };
        let Some(upstream) = self.ws.as_mut() else {
            return Err(ConnError::Closed);
        };
        if matches!(upstream, Upstream::Handshaking) {
            // No message before the 101: the read that hands up the answer's head opens the
            // session and wakes this caller's ticket.
            return Err(ConnError::Pending);
        }
        let State::Dialled(conn) = &mut self.state else {
            return Err(ConnError::Closed);
        };
        if bytes.is_empty() && end && matches!(upstream, Upstream::Open { sending: false, .. }) {
            return match conn.poll_close_stream(cx, stream) {
                Poll::Pending => Err(ConnError::Pending),
                Poll::Ready(Err(failure)) => Err(self.attempt_failed(&failure)),
                Poll::Ready(Ok(())) => {
                    if let Some(upstream) = self.ws.as_mut() {
                        upstream.closing();
                    }
                    Ok(0)
                }
            };
        }
        let continuing = matches!(upstream, Upstream::Open { sending: true, .. });
        let message = Message {
            kind: match (continuing, text) {
                (true, _) => Kind::Continuation,
                (false, true) => Kind::Text,
                (false, false) => Kind::Binary,
            },
            fin: end,
        };
        // The state moves only when the piece is taken: a pended piece is offered again as it was.
        let mut next = *upstream;
        let flags = match next.send(message) {
            Ok(flags) => flags,
            Err(Refusal::NotOpen) => return Err(ConnError::Closed),
            Err(Refusal::Sequence | Refusal::Transport) => return Err(ConnError::Refused),
        };
        match conn.poll_send_message(cx, stream, bytes, flags) {
            Poll::Pending | Poll::Ready(Ok(0)) if !bytes.is_empty() => Err(ConnError::Pending),
            Poll::Pending => Err(ConnError::Pending),
            Poll::Ready(Err(failure)) => Err(self.attempt_failed(&failure)),
            Poll::Ready(Ok(taken)) => {
                if let Some(upstream) = self.ws.as_mut() {
                    *upstream = next;
                }
                Ok(taken)
            }
        }
    }

    /// CALLED by `Exchange::read` on every piece it is about to hand up, when `self.ws` is set:
    /// the answer's head opens (or refuses) the session, and the end closes it. A body piece's
    /// `end` already says whether it ends its message (the transport's `MSG_FIN`).
    pub(super) fn message_read(&mut self, piece: &Piece) {
        let Some(upstream) = self.ws.as_mut() else {
            return;
        };
        match piece.kind {
            PieceKind::Fields if matches!(upstream, Upstream::Handshaking) => {
                upstream.answered(piece.status_code.unwrap_or_default());
            }
            PieceKind::Completion => upstream.ended(),
            PieceKind::Fields | PieceKind::Body | PieceKind::HookReply => {}
        }
    }

    /// A WebSocket connection is never kept for another exchange: `release` answers `Err` for it.
    pub(super) fn never_kept(&self) -> bool {
        self.ws.is_some()
    }
}

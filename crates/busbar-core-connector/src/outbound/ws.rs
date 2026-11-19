// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A WEBSOCKET UPSTREAM ON THE DIAL (`ws://` and `wss://` destinations).
//!
//! Nothing "upgrades" in the engine. The scheme table names the WebSocket carrier; the dial runs
//! exactly as for HTTP (the guard, the proxy tunnel, the target's TLS, the sealed head), and the
//! WebSocket transport in its client role does its own HTTP/1.1 handshake on the dialled
//! connection: its handshake request is a head like any other (control parts, with a sealed mark
//! for each sealed header or query value), on the stream it opened. Messages after the 101 are
//! payload on that stream.
//!
//! What is the engine's, and is here:
//!
//! * the handshake's own lines never come from a plane's head ([`drop_handshake_lines`]);
//! * the exchange's states ([`Upstream`]): no message before the 101; an answer that is not 101
//!   is an ordinary answer (its status is classified, the walk may move on); after the 101 the
//!   connection carries this one session and is never kept or shared;
//! * a message's kind and end, to and from the transport's message flags ([`Message`]);
//! * the delivery verdict of the session: `whole` when the engine's close was accepted and
//!   flushed (the ledger's rule for any stream; nothing per message).

/// The lines of the WebSocket handshake (RFC 6455 section 4.1). The transport writes them itself;
/// the engine never sends them in a head, so they are outside every signed set.
pub(crate) const HANDSHAKE_LINES: [&str; 4] = [
    "upgrade",
    "connection",
    "sec-websocket-key",
    "sec-websocket-version",
];

/// The status that opens the session (RFC 6455 section 4.2.2).
pub(crate) const SWITCHING_PROTOCOLS: u32 = 101;

/// Transport message flags (`MSG_*`), as the transport kind numbers them.
pub(crate) const MSG_TEXT: u32 = 1;
/// A binary message.
pub(crate) const MSG_BINARY: u32 = 2;
/// The piece ends its message.
pub(crate) const MSG_FIN: u32 = 4;

/// Remove the handshake's own lines from a head a plane stated, in place (each value wiped).
/// `sec-websocket-protocol` and every other line stay, written as handed.
pub(crate) fn drop_handshake_lines(fields: &mut Vec<(String, Vec<u8>)>) {
    fields.retain_mut(|(name, value)| {
        let own = HANDSHAKE_LINES
            .iter()
            .any(|line| name.eq_ignore_ascii_case(line));
        if own {
            drop(busbar_contract::secure::SecureVec::from(std::mem::take(
                value,
            )));
        }
        !own
    });
}

/// What a message piece is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// UTF-8 text.
    Text,
    /// Bytes.
    Binary,
    /// More of the message the last piece began.
    Continuation,
}

/// One piece of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Message {
    /// Text, binary, or more of the last.
    pub(crate) kind: Kind,
    /// The piece ends its message.
    pub(crate) fin: bool,
}

impl Message {
    /// From the flags of a `STREAM_BODY`. `None` = flags no message has (both kinds at once).
    pub(crate) const fn of_flags(flags: u32) -> Option<Self> {
        let kind = match flags & (MSG_TEXT | MSG_BINARY) {
            MSG_TEXT => Kind::Text,
            MSG_BINARY => Kind::Binary,
            0 => Kind::Continuation,
            _ => return None,
        };
        Some(Self {
            kind,
            fin: flags & MSG_FIN != 0,
        })
    }

    /// The `arg` of `emit(stream, BODY)`.
    pub(crate) const fn flags(self) -> u32 {
        let kind = match self.kind {
            Kind::Text => MSG_TEXT,
            Kind::Binary => MSG_BINARY,
            Kind::Continuation => 0,
        };
        if self.fin {
            kind | MSG_FIN
        } else {
            kind
        }
    }
}

/// Where a WebSocket upstream exchange is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Upstream {
    /// The handshake request is out (or going); the answer's head has not arrived.
    Handshaking,
    /// 101: the session is open; messages flow both ways.
    Open {
        /// The engine is inside a message it has not ended (the next piece is a continuation).
        sending: bool,
        /// The far end is inside a message it has not ended.
        receiving: bool,
    },
    /// The far end answered another status: an ordinary answer, read to its end. No message is
    /// ever sent.
    Refused(u32),
    /// The engine emitted the end (its close); the far end's close is awaited.
    Closing,
    /// Over.
    Closed,
}

/// What the exchange may not do. Each is the engine's own misuse or the transport's breach; the
/// text says which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A message before the 101, or after the close: the engine's caller is told, nothing is
    /// emitted.
    NotOpen,
    /// A first piece that says "continuation", or a new kind inside an unfinished message.
    Sequence,
    /// The transport handed up a message before a 101 head, or flags no message has: FAULT
    /// BadRecords.
    Transport,
}

impl Upstream {
    /// A dialled WebSocket exchange, its handshake request emitted.
    pub(crate) const fn new() -> Self {
        Self::Handshaking
    }

    /// The answer's head arrived with `status`.
    pub(crate) fn answered(&mut self, status: u32) {
        if matches!(self, Self::Handshaking) {
            *self = if status == SWITCHING_PROTOCOLS {
                Self::Open {
                    sending: false,
                    receiving: false,
                }
            } else {
                Self::Refused(status)
            };
        }
    }

    /// The engine wants to send a piece: the flags to emit it with.
    ///
    /// # Errors
    /// [`Refusal::NotOpen`] or [`Refusal::Sequence`]; nothing is emitted.
    pub(crate) fn send(&mut self, message: Message) -> Result<u32, Refusal> {
        let Self::Open { sending, .. } = self else {
            return Err(Refusal::NotOpen);
        };
        match (message.kind, *sending) {
            (Kind::Continuation, false) | (Kind::Text | Kind::Binary, true) => {
                return Err(Refusal::Sequence)
            }
            _ => {}
        }
        *sending = !message.fin;
        Ok(message.flags())
    }

    /// The transport handed up a body piece with `flags`.
    ///
    /// # Errors
    /// [`Refusal::Transport`] for a message before the 101 or flags no message has. A body on a
    /// refused handshake is the refusal's own body and carries no message: `Ok(None)`.
    pub(crate) fn received(&mut self, flags: u32) -> Result<Option<Message>, Refusal> {
        match self {
            Self::Refused(_) => Ok(None),
            Self::Open { receiving, .. } => {
                let message = Message::of_flags(flags).ok_or(Refusal::Transport)?;
                if matches!(message.kind, Kind::Continuation) != *receiving {
                    return Err(Refusal::Transport);
                }
                *receiving = !message.fin;
                Ok(Some(message))
            }
            // After the engine's close the far end may still finish what it was sending.
            Self::Closing => Message::of_flags(flags).map(Some).ok_or(Refusal::Transport),
            Self::Handshaking | Self::Closed => Err(Refusal::Transport),
        }
    }

    /// The engine emitted the end (its close frame goes out).
    pub(crate) fn closing(&mut self) {
        if matches!(self, Self::Open { .. }) {
            *self = Self::Closing;
        }
    }

    /// The stream ended (the far end's close, a reset, or the refused answer's end).
    pub(crate) fn ended(&mut self) {
        *self = Self::Closed;
    }

    /// The handshake request may still be sent again by the evidence rules: only while the
    /// answer's head has not arrived. After the 101 nothing is ever sent again.
    pub(crate) const fn may_redial(&self) -> bool {
        matches!(self, Self::Handshaking)
    }

    /// A WebSocket connection is never kept for another exchange and never shared.
    pub(crate) const fn reusable(&self) -> bool {
        false
    }

    /// The status the walk classifies when the handshake was refused.
    pub(crate) const fn refused_status(&self) -> Option<u32> {
        match self {
            Self::Refused(status) => Some(*status),
            _ => None,
        }
    }
}

/// The scheme a WebSocket head states (`H_SCHEME`): the destination's own, not `http`.
pub(crate) const fn scheme(secure: bool) -> &'static str {
    if secure {
        "wss"
    } else {
        "ws"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(fin: bool) -> Message {
        Message {
            kind: Kind::Text,
            fin,
        }
    }

    fn more(fin: bool) -> Message {
        Message {
            kind: Kind::Continuation,
            fin,
        }
    }

    #[test]
    fn the_handshakes_own_lines_never_come_from_a_plane() {
        let mut fields = vec![
            ("Upgrade".to_owned(), b"websocket".to_vec()),
            ("authorization".to_owned(), b"Bearer t".to_vec()),
            ("Sec-WebSocket-Key".to_owned(), b"AAAA".to_vec()),
            ("sec-websocket-protocol".to_owned(), b"realtime".to_vec()),
            ("connection".to_owned(), b"Upgrade".to_vec()),
            ("sec-websocket-version".to_owned(), b"13".to_vec()),
        ];
        drop_handshake_lines(&mut fields);
        let names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["authorization", "sec-websocket-protocol"]);
    }

    #[test]
    fn no_message_is_sent_before_the_101() {
        let mut upstream = Upstream::new();
        assert_eq!(upstream.send(text(true)), Err(Refusal::NotOpen));
        assert!(upstream.may_redial());
        upstream.answered(101);
        assert_eq!(upstream.send(text(true)), Ok(MSG_TEXT | MSG_FIN));
        assert!(
            !upstream.may_redial(),
            "after the 101 nothing is sent again"
        );
        assert!(!upstream.reusable());
    }

    #[test]
    fn another_status_is_an_ordinary_answer_the_walk_classifies() {
        let mut upstream = Upstream::new();
        upstream.answered(429);
        assert_eq!(upstream.refused_status(), Some(429));
        assert_eq!(upstream.send(text(true)), Err(Refusal::NotOpen));
        assert_eq!(upstream.received(0), Ok(None), "the refusal's own body");
        upstream.ended();
        assert_eq!(upstream, Upstream::Closed);
    }

    #[test]
    fn a_message_in_pieces_keeps_its_order_both_ways() {
        let mut upstream = Upstream::new();
        upstream.answered(101);
        assert_eq!(upstream.send(more(false)), Err(Refusal::Sequence));
        assert_eq!(upstream.send(text(false)), Ok(MSG_TEXT));
        assert_eq!(upstream.send(text(true)), Err(Refusal::Sequence));
        assert_eq!(upstream.send(more(false)), Ok(0));
        assert_eq!(upstream.send(more(true)), Ok(MSG_FIN));
        assert_eq!(upstream.send(text(true)), Ok(MSG_TEXT | MSG_FIN));

        assert_eq!(
            upstream.received(MSG_BINARY),
            Ok(Some(Message {
                kind: Kind::Binary,
                fin: false
            }))
        );
        assert_eq!(upstream.received(MSG_TEXT), Err(Refusal::Transport));
    }

    #[test]
    fn a_message_from_the_transport_before_the_101_is_its_breach() {
        let mut upstream = Upstream::new();
        assert_eq!(
            upstream.received(MSG_TEXT | MSG_FIN),
            Err(Refusal::Transport)
        );
        let mut open = Upstream::new();
        open.answered(101);
        assert_eq!(
            open.received(MSG_TEXT | MSG_BINARY),
            Err(Refusal::Transport)
        );
        assert_eq!(open.received(MSG_FIN), Err(Refusal::Transport));
    }

    #[test]
    fn after_the_engines_close_messages_still_arrive_until_the_far_end_closes() {
        let mut upstream = Upstream::new();
        upstream.answered(101);
        upstream.closing();
        assert_eq!(upstream.send(text(true)), Err(Refusal::NotOpen));
        assert!(upstream.received(MSG_TEXT | MSG_FIN).is_ok());
        upstream.ended();
        assert_eq!(upstream, Upstream::Closed);
    }

    #[test]
    fn the_flags_round_trip() {
        for flags in [
            0,
            MSG_TEXT,
            MSG_BINARY,
            MSG_FIN,
            MSG_TEXT | MSG_FIN,
            MSG_BINARY | MSG_FIN,
        ] {
            assert_eq!(Message::of_flags(flags).map(Message::flags), Some(flags));
        }
        assert_eq!(Message::of_flags(MSG_TEXT | MSG_BINARY), None);
    }

    #[test]
    fn the_head_states_the_destinations_own_scheme() {
        assert_eq!((scheme(true), scheme(false)), ("wss", "ws"));
    }
}

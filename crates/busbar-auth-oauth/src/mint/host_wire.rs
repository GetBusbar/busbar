// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN'S OWN NEED, OVER THE HOST'S CONNECTOR (THE DESIGN §5, the connections section;
//! §6.5: the minting styles "mint through the plugin's own `open-web` need"): [`HostWire`] is the
//! [`Wire`] the token exchange runs over in production. The token request goes out on the framed
//! need its style names (`ESTABLISH`, then `WRITE_REQUEST` head, body, end: the framer writes its
//! own wire head and its client defaults), and the reply is read piece by piece (`READ_REPLY`: its
//! head's code, its body, its terminal piece).
//!
//! THE REPLAY RULE (`busbar_contract::abi::sdk::conn`): every service carries the next completion
//! handle of the op's ticket. The exchange runs on the instance's DRIVER ticket, inside `tick` and
//! the `drive`s between ticks, which are one cycle (a tick's start forgets what the last cycle
//! kept): the handle count is the instance's, reset at each tick and carried on through each
//! drive, so no service is ever answered from another's kept result.

use std::sync::atomic::{AtomicU32, Ordering};
use std::task::Poll;

use busbar_contract::abi::host::conn::connector::{
    ReplyPiece, RequestPiece, REPLY_ACK, REPLY_BODY, REPLY_END, REPLY_HEAD, REQUEST_BODY,
    REQUEST_END, REQUEST_HEAD,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::{ConnFailure, Connector, Host};
use busbar_contract::abi::transport::{fields, FrameSpan};
use busbar_contract::conn::{ConnError, ConnId, PieceKind};

use super::{Got, TokenRequest, Wire};

/// The connector for one entry of the driver ticket's cycle.
pub(crate) struct HostWire<'a> {
    host: &'a Host,
    ticket: Ticket,
    issued: &'a AtomicU32,
}

impl<'a> HostWire<'a> {
    /// The need's services over `host`, on `ticket`, the cycle's handle count in `issued`.
    pub(crate) fn new(host: &'a Host, ticket: Ticket, issued: &'a AtomicU32) -> Self {
        Self {
            host,
            ticket,
            issued,
        }
    }

    /// Run `f` over the connector, the cycle's handle count carried in and out.
    fn with<T>(&self, f: impl FnOnce(&mut Connector<'_>) -> T) -> T {
        let mut c = self
            .host
            .connector_from(self.ticket, self.issued.load(Ordering::Acquire));
        let answer = f(&mut c);
        self.issued.store(c.issued(), Ordering::Release);
        answer
    }
}

/// The connection error a host refusal names: its text is the table's own (`ConnError::text`).
fn error_of(f: &ConnFailure) -> ConnError {
    const ALL: [ConnError; 9] = [
        ConnError::Pending,
        ConnError::Timeout,
        ConnError::Closed,
        ConnError::NotOwner,
        ConnError::UndeclaredNeed,
        ConnError::Refused,
        ConnError::Fault,
        ConnError::Unarmed,
        ConnError::CredentialUnavailable,
    ];
    match f {
        ConnFailure::Unarmed => ConnError::Unarmed,
        ConnFailure::NoTicket => ConnError::Pending,
        ConnFailure::Fault => ConnError::Fault,
        ConnFailure::CredentialUnavailable => ConnError::CredentialUnavailable,
        ConnFailure::Failed(t) => ALL
            .into_iter()
            .find(|e| e.text() == t)
            .unwrap_or(ConnError::Fault),
        ConnFailure::Refused(t) => ALL
            .into_iter()
            .find(|e| e.text() == t)
            .unwrap_or(ConnError::Refused),
    }
}

/// A service answer that must not pend (a held framed request's pieces never do).
fn now<T>(a: Poll<Result<T, ConnFailure>>) -> Result<T, ConnError> {
    match a {
        Poll::Ready(Ok(v)) => Ok(v),
        Poll::Ready(Err(f)) => Err(error_of(&f)),
        Poll::Pending => Err(ConnError::Refused),
    }
}

const fn span(offset: usize, len: usize) -> FrameSpan {
    FrameSpan {
        offset: offset as u64,
        len: len as u64,
    }
}

/// The request's head words and field block, as `WRITE_REQUEST`'s head piece names them: the
/// method `POST`, the target's path and query (no fragment: a client never sends one), then each
/// field.
fn head(req: &TokenRequest, timeout_ms: u64) -> Result<(Vec<u8>, RequestPiece), ConnError> {
    let url = busbar_contract::net::parse_url(&req.target).map_err(|_| ConnError::Refused)?;
    let words = url.path.split('#').next().unwrap_or("/");
    let mut bytes = b"POST".to_vec();
    bytes.extend_from_slice(words.as_bytes());
    let block_at = bytes.len();
    for (name, value) in &req.fields {
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(fields::SEPARATOR);
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(fields::LINE_END);
    }
    let piece = RequestPiece {
        kind: REQUEST_HEAD,
        _reserved: 0,
        method: span(0, 4),
        target: span(4, words.len()),
        fields: span(block_at, bytes.len() - block_at),
        timeout_ms,
    };
    Ok((bytes, piece))
}

impl Wire for HostWire<'_> {
    fn open(&self, req: &TokenRequest, timeout_ms: u64) -> Result<ConnId, ConnError> {
        let (head, head_piece) = head(req, timeout_ms)?;
        let body = req.body.expose_secret().as_bytes();
        let body_piece = RequestPiece {
            kind: REQUEST_BODY,
            ..RequestPiece::default()
        };
        let end_piece = RequestPiece {
            kind: REQUEST_END,
            ..RequestPiece::default()
        };
        self.with(|c| {
            let stream = now(c.establish(req.need, Some(&req.target), ""))?;
            let sent = (|| {
                if now(c.write_request(stream, &head_piece, &head))? != head.len() {
                    return Err(ConnError::Refused);
                }
                let mut at = 0;
                while at < body.len() {
                    match now(c.write_request(stream, &body_piece, &body[at..]))? {
                        0 => return Err(ConnError::Refused),
                        n => at += n,
                    }
                }
                now(c.write_request(stream, &end_piece, &[])).map(|_| ())
            })();
            match sent {
                Ok(()) => Ok(ConnId(stream)),
                Err(e) => {
                    let _ = c.close(stream);
                    Err(e)
                }
            }
        })
    }

    fn read(&self, conn: ConnId, buf: &mut [u8]) -> Result<Got, ConnError> {
        let mut slot = ReplyPiece::default();
        let answer = self.with(|c| c.read_reply(conn.0, buf, &mut slot));
        match answer {
            Poll::Pending => Err(ConnError::Pending),
            Poll::Ready(Err(f)) => Err(error_of(&f)),
            Poll::Ready(Ok(got)) => match got.piece.kind {
                REPLY_HEAD => Ok(Got {
                    kind: PieceKind::Fields,
                    len: 0,
                    end: false,
                    status: Some(got.piece.code),
                }),
                REPLY_BODY => Ok(Got {
                    kind: PieceKind::Body,
                    len: got.len,
                    end: false,
                    status: None,
                }),
                REPLY_END | REPLY_ACK => Ok(Got {
                    kind: PieceKind::Completion,
                    len: 0,
                    end: true,
                    status: None,
                }),
                _ => Err(ConnError::Fault),
            },
        }
    }

    fn close(&self, conn: ConnId) {
        let _ = self.with(|c| c.close(conn.0));
    }
}

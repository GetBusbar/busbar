// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE REQUEST UNIT AS THE KERNEL'S ROUTE PUMP DRIVES IT (`BUSBAR-1.6.0.md` Part 3, section 12):
//! the pieces of a one-request door (the ephemeral-secret mint, the SDP offer, the metadata
//! document), in the order the pump pushes them, and what the plane answers each with.
//!
//! Per attempt the pump pushes an ATTEMPT piece first, then the caller's body (re-pushed on every
//! attempt), then the far end's answer. The plane answers:
//!
//! | piece | mint | SDP offer | metadata |
//! |---|---|---|---|
//! | ATTEMPT | the mint request, whole | the request head; its body follows | the document |
//! | the caller's body | nothing (the mint reads no caller body) | relayed to the far end as it arrived | the document, if not yet answered |
//! | the far end's answer | gathered; on its last piece, the caller's answer | the same | refused: it dials nothing |
//!
//! Every answer is plain data in the plane's own vocabulary; writing it into the host's buffers is
//! the door's job. A new ATTEMPT forgets what the previous attempt's far end said.

use crate::codec::ir::config::SessionConfig;
use crate::driven::{
    metadata_reply, mint_failed, mint_reply, sdp_reply, Attempt, Door, Reply, Steps, FIELD_LOCATION,
};

/// Who pushed a piece.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum From {
    /// The caller: the request body.
    Caller,
    /// The far end: its answer.
    FarEnd,
    /// The kernel: an ATTEMPT, numbered from `1`.
    Kernel(u32),
}

/// One piece, as the door read it off the crossing.
#[derive(Debug, Clone, Copy)]
pub struct Piece<'a> {
    /// Who pushed it.
    pub from: From,
    /// Its bytes.
    pub bytes: &'a [u8],
    /// On the far end's first piece: the status it answered.
    pub status: Option<u16>,
    /// No piece of this `from` follows.
    pub last: bool,
    /// On the far end's first piece: the response head fields the plane's need keeps, names
    /// lower-case.
    pub head: &'a [(&'a [u8], &'a [u8])],
}

/// The plane's answer to one piece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Nothing to emit yet.
    Nothing,
    /// The request this attempt sends the far end; a body that follows arrives as [`Answer::ToFarEnd`].
    Attempt(Attempt),
    /// More of the request's body, bound for the far end.
    ToFarEnd(Vec<u8>),
    /// The caller's whole answer: the unit is done.
    ToCaller(Reply),
    /// The piece is one this door never takes.
    Refused,
}

/// One unit on a one-request door.
#[derive(Debug, Clone)]
pub struct RequestUnit {
    door: Door,
    locked: SessionConfig,
    caller_ref: Option<String>,
    audience: String,
    status: Option<u16>,
    location: Option<String>,
    far: Vec<u8>,
    answered: bool,
}

impl RequestUnit {
    /// A unit on `door`, minting over the `locked` session params, naming the caller by
    /// `caller_ref` (the kernel's reference, never the principal) and answering the metadata
    /// document for `audience`. `None` for a door that opens a live session.
    #[must_use]
    pub fn new(
        door: Door,
        locked: SessionConfig,
        caller_ref: Option<String>,
        audience: String,
    ) -> Option<Self> {
        if door.is_session() {
            return None;
        }
        Some(Self {
            door,
            locked,
            caller_ref,
            audience,
            status: None,
            location: None,
            far: Vec::new(),
            answered: false,
        })
    }

    /// Its door.
    #[must_use]
    pub const fn door(&self) -> Door {
        self.door
    }

    /// `true` once the caller's answer has been given.
    #[must_use]
    pub const fn answered(&self) -> bool {
        self.answered
    }

    fn answer(&mut self, reply: Reply) -> Answer {
        self.answered = true;
        Answer::ToCaller(reply)
    }

    /// The plane's answer to `piece`.
    pub fn on_piece(&mut self, piece: Piece<'_>) -> Answer {
        if self.answered {
            return Answer::Nothing;
        }
        match (self.door, piece.from) {
            (Door::Metadata, From::Kernel(_) | From::Caller) => {
                let reply = metadata_reply(&self.audience);
                self.answer(reply)
            }
            (Door::Metadata, From::FarEnd) => Answer::Refused,
            (_, From::Kernel(0)) => Answer::Refused,
            (_, From::Kernel(_)) => {
                self.status = None;
                self.location = None;
                self.far.clear();
                match self
                    .door
                    .route(&self.locked, self.caller_ref.as_deref(), &[])
                {
                    Ok(Some(attempt)) => Answer::Attempt(attempt),
                    Ok(None) => Answer::Refused,
                    Err(reason) => {
                        let reply = mint_failed(&reason);
                        self.answer(reply)
                    }
                }
            }
            (Door::Sdp, From::Caller) => {
                if piece.bytes.is_empty() {
                    Answer::Nothing
                } else {
                    Answer::ToFarEnd(piece.bytes.to_vec())
                }
            }
            (_, From::Caller) => Answer::Nothing,
            (_, From::FarEnd) => self.far_end_piece(piece),
        }
    }

    fn far_end_piece(&mut self, piece: Piece<'_>) -> Answer {
        if let Some(status) = piece.status {
            self.status = Some(status);
            self.location = piece
                .head
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(FIELD_LOCATION.as_bytes()))
                .and_then(|(_, value)| std::str::from_utf8(value).ok())
                .map(str::to_owned);
        }
        self.far.extend_from_slice(piece.bytes);
        if !piece.last {
            return Answer::Nothing;
        }
        let Some(status) = self.status else {
            return Answer::Refused;
        };
        let reply = match self.door {
            Door::Mint => mint_reply(status, &self.far),
            _ => sdp_reply(status, self.location.as_deref(), &self.far),
        };
        self.answer(reply)
    }
}

#[cfg(test)]
#[path = "tests/request_unit_tests.rs"]
mod tests;

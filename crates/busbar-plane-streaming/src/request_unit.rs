// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE REQUEST UNIT AS THE KERNEL'S ROUTE PUMP DRIVES IT (`BUSBAR-1.6.0.md` Part 3, section 12):
//! the mint door's one request, and what the plane answers it with.
//!
//! The mint door is answered by the plane itself (`ROUTE_LOCAL`): it dials nothing, so the pump
//! pushes the caller's body alone, as one last piece. The plane answers it with a ticket busbar
//! mints (`ticket.mint`, row 132), its record the session config the ticket locks. The door makes the
//! host call; this unit says what to ask for and how the caller is answered.
//!
//! Every answer is plain data in the plane's own vocabulary; writing it into the host's buffers is
//! the door's job.

use crate::codec::ir::config::SessionConfig;
use crate::driven::{mint_failed, minted, Door, Reply};
use crate::ticket::{clamped_ttl_secs, ticket_record};

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
    /// Mint a ticket living `ttl_secs` with `record` stored beside it, then answer the caller
    /// through [`RequestUnit::minted`].
    Mint {
        /// The lifetime asked, in seconds.
        ttl_secs: u64,
        /// The ticket's record: the session config it locks.
        record: Vec<u8>,
    },
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
    asked: bool,
    answered: bool,
}

impl RequestUnit {
    /// Open the plane's state for one kernel unit on `door` (the unit's identity is the kernel's;
    /// the door keys this state by it), minting over the `locked` session params. `None` for a door
    /// that opens a live session.
    #[must_use]
    pub fn open(door: Door, locked: SessionConfig) -> Option<Self> {
        if door.is_session() {
            return None;
        }
        Some(Self {
            door,
            locked,
            asked: false,
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

    /// The plane's answer to `piece`. The caller's last piece asks for the ticket, once; a far
    /// end never answers a unit that dials nothing.
    pub fn on_piece(&mut self, piece: Piece<'_>) -> Answer {
        if self.answered || self.asked {
            return Answer::Nothing;
        }
        match piece.from {
            From::Caller if piece.last => match ticket_record(&self.locked) {
                Ok(record) => {
                    self.asked = true;
                    Answer::Mint {
                        ttl_secs: clamped_ttl_secs(None),
                        record,
                    }
                }
                Err(reason) => self.answer(mint_failed(&reason)),
            },
            From::Caller | From::Kernel(_) => Answer::Nothing,
            From::FarEnd => Answer::Refused,
        }
    }

    /// The host answered the mint: the caller's answer, the ticket and its expiry, or the served
    /// plane's 502 naming why.
    pub fn minted(&mut self, result: Result<(String, u64), String>) -> Answer {
        let reply = match result {
            Ok((ticket, expires_at_unix)) => minted(&ticket, expires_at_unix),
            Err(reason) => mint_failed(&reason),
        };
        self.answer(reply)
    }
}

#[cfg(test)]
#[path = "tests/request_unit_tests.rs"]
mod tests;

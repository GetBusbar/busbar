// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The bounded challenge: the one answer this unit can give that is neither a principal nor a
//! refusal.
//!
//! A scheme that cannot settle who is calling from the credential alone asks the client something.
//! That only happens inside a handshake unit — one the plane opened by saying so, or the transport
//! opened with its own native trigger — because a challenge needs a leg to be delivered on, and a
//! handshake unit is the shape that has one: the challenge goes out as the unit's delivery leg, and
//! the proof arrives as the next handshake frames.
//!
//! It is bounded in two dimensions, rounds and bytes, and running past either ends the unit rather
//! than continuing. An unbounded challenge is an unbounded conversation with an unauthenticated
//! party, which is a way of spending a connection slot for free.

/// The limits an exchange may not exceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeBounds {
    /// The most rounds the exchange may take.
    pub max_rounds: u32,
    /// The most bytes it may take, across the whole exchange.
    pub max_bytes: u32,
}

/// One challenge to deliver, and what is left of its budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The bytes the client is asked to answer.
    pub bytes: Vec<u8>,
    /// The rounds left before the exchange is exhausted.
    pub rounds_left: u32,
    /// The bytes left before the exchange is exhausted.
    pub bytes_left: u32,
}

impl Challenge {
    /// Open an exchange against its bounds.
    pub fn open(bytes: Vec<u8>, bounds: ChallengeBounds) -> Self {
        let spent = bytes.len().min(u32::MAX as usize) as u32;
        Challenge {
            bytes,
            rounds_left: bounds.max_rounds.saturating_sub(1),
            bytes_left: bounds.max_bytes.saturating_sub(spent),
        }
    }

    /// Whether this exchange has run out of rounds or bytes. An exhausted exchange ends the unit.
    pub fn exhausted(&self) -> bool {
        self.rounds_left == 0 || self.bytes_left == 0
    }

    /// Account one more round of the given size, returning the exchange or `None` when the budget
    /// is gone.
    pub fn advance(mut self, next: Vec<u8>) -> Option<Self> {
        let spent = next.len().min(u32::MAX as usize) as u32;
        if self.rounds_left == 0 || spent > self.bytes_left {
            return None;
        }
        self.rounds_left -= 1;
        self.bytes_left -= spent;
        self.bytes = next;
        Some(self)
    }
}

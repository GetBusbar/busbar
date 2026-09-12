// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The PURE half of one arrival door: the value a session's ENDING is carried in.
//!
//! The door itself -- what it binds, what it spawns, what it awaits -- stays in
//! `busbar-substrate`. What crosses between the two halves of that door is a number, and a number
//! is a value, so it lives here and `busbar-substrate` re-exports it at the path it has always had.

/// THE CLOSE CODE ONE ENDING IS SPELLED WITH, on its way from whoever ended the session to the task
/// that owns the socket.
///
/// A session ends for a reason, and a client is entitled to the number for it: a money refusal, a
/// policy refusal and this node's own fault are three different endings and were, until this type,
/// one silence. The frame channel below hands out a stream and a sink and nothing else, so a caller
/// adapting a sink over it had nowhere to put the code and every ending arrived bare.
///
/// It is a SLOT rather than a second channel because the ordering has to be exact: the code is read
/// only after the outbound queue has drained, so a code stored while frames are still queued does
/// not preempt them. Dropping the sender is what ends that queue, and the store happens-before the
/// load on the one task that does both.
///
/// Zero is "no code": the ending is then the bare close this acceptor has always sent, byte for
/// byte, which is what keeps every existing caller unchanged.
#[derive(Clone, Debug, Default)]
pub struct CloseSlot(std::sync::Arc<std::sync::atomic::AtomicU16>);

impl CloseSlot {
    /// SPELL this session's ending. Last writer wins; a code stored after the queue has drained is
    /// a code that arrived too late and is not sent, which is the same race a second channel would
    /// have had and could not have resolved without holding the socket open for it.
    pub fn set(&self, code: u16) {
        self.0.store(code, std::sync::atomic::Ordering::Release);
    }

    /// The code this ending carries, or zero for the bare close.
    #[must_use]
    pub fn code(&self) -> u16 {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}

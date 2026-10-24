// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S I/O, AS THE HOST'S TWO HALVES SHARE IT (`abi::host::io`, `io.*`): the [`IoHost`] trait
//! the host's connector implements over the OS handles it owns, and the plugin loader's `io` slots
//! dispatch into. The loader names this, the connector names this, and neither names the other.
//! Nothing here crosses the plugin boundary: the ABI a carrier sees is `abi::host::io`.
//!
//! `owner` names the calling instance (the loader's identity for it): a handle belongs to the
//! instance whose call made it, and every call on a handle another instance owns is refused.
//! `ticket` is the calling op's ticket: the host reads what it admitted for the dial that ticket
//! runs. `waker` is the ticket's wake, registered by a call that answers `Pending`.

use std::task::{Poll, Waker};

use crate::abi::mechanism::ticket::Ticket;

/// Why an I/O call answered without its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoRefusal {
    /// The host's policy: not admitted, not the caller's handle, an unknown handle.
    Refused(String),
    /// The system's answer, with its text.
    Failed(String),
}

impl IoRefusal {
    /// A refusal for a handle the caller does not hold.
    #[must_use]
    pub fn unknown() -> Self {
        Self::Refused("no such handle".into())
    }
}

/// An I/O call's answer.
pub type IoResult<T> = Result<T, IoRefusal>;

/// A program to spawn, as a carrier states it: borrowed for the call.
#[derive(Debug, Clone, Copy)]
pub struct Spawn<'a> {
    /// Its absolute path.
    pub program: &'a str,
    /// Its arguments.
    pub args: &'a [&'a str],
    /// Its whole environment.
    pub env: &'a [(&'a str, &'a str)],
}

/// THE HOST'S I/O over the OS handles it owns (module docs). Every method answers at once; one that
/// may pend answers `Pending` only when nothing moved, `waker` registered for the direction.
pub trait IoHost: Send + Sync {
    /// Begin reaching `addr` for the dial `ticket` runs; the handle, the connect in flight.
    ///
    /// # Errors
    ///
    /// Not admitted for the dial, or the system refused at once.
    fn open(&self, owner: u64, ticket: Ticket, addr: &str) -> IoResult<u64>;

    /// Bind `bind` for the listen `ticket` runs; the handle and the address bound.
    ///
    /// # Errors
    ///
    /// Not admitted, or the system could not bind it.
    fn listen(&self, owner: u64, ticket: Ticket, bind: &str) -> IoResult<(u64, String)>;

    /// The next connection off `listener`, for the accept `ticket` runs: its handle and its far
    /// end's address.
    fn accept(
        &self,
        owner: u64,
        ticket: Ticket,
        listener: u64,
        waker: &Waker,
    ) -> Poll<IoResult<(u64, String)>>;

    /// Bytes into `buf`; `0` is the clean end.
    fn read(&self, owner: u64, handle: u64, buf: &mut [u8], waker: &Waker)
        -> Poll<IoResult<usize>>;

    /// How many of `bytes` the handle took.
    fn write(&self, owner: u64, handle: u64, bytes: &[u8], waker: &Waker) -> Poll<IoResult<usize>>;

    /// `Ready` once `handle` may make progress in `dir` (`abi::host::io::DIR_*`); for a stream
    /// still connecting, `DIR_WRITE` is its connect settling (FAILED with the system's text).
    fn ready(&self, owner: u64, handle: u64, dir: u32, waker: &Waker) -> Poll<IoResult<()>>;

    /// Shut `how` (`DIR_*`) of `handle` down.
    ///
    /// # Errors
    ///
    /// Not the caller's handle, or the system refused.
    fn shut(&self, owner: u64, handle: u64, how: u32) -> IoResult<()>;

    /// Release `handle`; a spawned program is killed with it.
    ///
    /// # Errors
    ///
    /// Not the caller's handle.
    fn close(&self, owner: u64, handle: u64) -> IoResult<()>;

    /// Start `spawn` for the dial `ticket` runs; the duplex handle over its input and output.
    ///
    /// # Errors
    ///
    /// Not admitted for the dial, or the system could not start it.
    fn spawn(&self, owner: u64, ticket: Ticket, spawn: &Spawn<'_>) -> IoResult<u64>;

    /// `handle`'s local port and its far end's address (empty = none).
    ///
    /// # Errors
    ///
    /// Not the caller's handle.
    fn ends(&self, owner: u64, handle: u64) -> IoResult<(u16, String)>;
}

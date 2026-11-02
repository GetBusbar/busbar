// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S I/O, AS THE HOST'S TWO HALVES SHARE IT (`abi::host::io`, `io.*`): the [`IoHost`] trait

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

/// What `io.ends` answers of a handle ([`IoHost::ends`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ends {
    /// The local port (`0` for a handle with none).
    pub port: u16,
    /// The far end's address (empty = none).
    pub peer: String,
    /// A spawned program's exit code once the program itself has exited; `None` while it runs,
    /// and for every handle that is not a program. A program ended by a signal answers `128` plus
    /// the signal's number, as a shell reports it.
    pub exit: Option<u32>,
}

/// THE HOST'S I/O over the OS handles it owns (module docs). Every method answers at once; one that

pub trait IoHost: Send + Sync {
    /// Begin reaching `addr` for the dial `ticket` runs; the handle, the connect in flight.

    fn open(&self, owner: u64, ticket: Ticket, addr: &str) -> IoResult<u64>;

    /// Bind `bind` for the listen `ticket` runs; the handle and the address bound.

    fn listen(&self, owner: u64, ticket: Ticket, bind: &str) -> IoResult<(u64, String)>;

    /// The next connection off `listener`, for the accept `ticket` runs: its handle and its far

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

    fn ready(&self, owner: u64, handle: u64, dir: u32, waker: &Waker) -> Poll<IoResult<()>>;

    /// Shut `how` (`DIR_*`) of `handle` down.

    fn shut(&self, owner: u64, handle: u64, how: u32) -> IoResult<()>;

    /// Release `handle`; a spawned program is killed with it.

    fn close(&self, owner: u64, handle: u64) -> IoResult<()>;

    /// Start `spawn` for the dial `ticket` runs; the duplex handle over its input and output.

    fn spawn(&self, owner: u64, ticket: Ticket, spawn: &Spawn<'_>) -> IoResult<u64>;

    /// `handle`'s ends: its local port and its far end's address (empty = none), and for a

    fn ends(&self, owner: u64, handle: u64) -> IoResult<Ends>;

    /// Release every handle `owner` still holds, each as [`IoHost::close`] releases it: the

    fn reap(&self, owner: u64) {
        let _ = owner;
    }
}

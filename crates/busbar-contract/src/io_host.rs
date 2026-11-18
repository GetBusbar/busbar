// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S I/O, AS THE HOST'S TWO HALVES SHARE IT (`abi::host::io`, `io.*`): the [`IoHost`] trait

use std::task::{Poll, Waker};

use crate::abi::mechanism::ticket::Ticket;

/// Why an I/O call answered without its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoRefusal {
    /// The host's policy: not admitted, not the caller's handle, an unknown handle. The words are
    /// fixed in the program, or shared with whoever made them (a held environment's own reason):
    /// a refusal copies no text.
    Refused(crate::kept::Text),
    /// The system's answer, with its text.
    Failed(String),
}

impl IoRefusal {
    /// A refusal for a handle the caller does not hold.
    #[must_use]
    pub const fn unknown() -> Self {
        Self::Refused(crate::kept::Text::fixed("no such handle"))
    }
}

/// An I/O call's answer.
pub type IoResult<T> = Result<T, IoRefusal>;

/// A program to spawn, as a carrier states it: borrowed for the call.
///
/// `Debug` names the program and says only the length of each argument and environment value: an
/// argument or a value routinely carries a credential, and none may reach a log line.
#[derive(Clone, Copy)]
pub struct Spawn<'a> {
    /// Its absolute path.
    pub program: &'a str,
    /// Its arguments.
    pub args: &'a [&'a str],
    /// Its whole environment.
    pub env: &'a [(&'a str, &'a str)],
}

/// A value `Debug` names only by its length, behind an optional name.
struct Redacted<'a> {
    name: &'a str,
    len: usize,
}

impl std::fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.name.is_empty() {
            write!(f, "<{} bytes>", self.len)
        } else {
            write!(f, "{}=<{} bytes>", self.name, self.len)
        }
    }
}

/// Argument lengths, as `Debug` may say them.
struct ArgLengths<'a>(&'a [&'a str]);

impl std::fmt::Debug for ArgLengths<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|a| Redacted {
                name: "",
                len: a.len(),
            }))
            .finish()
    }
}

/// An environment as `Debug` may say it: every name, with the length of its value beside it.
struct EnvLengths<'a>(&'a [(&'a str, &'a str)]);

impl std::fmt::Debug for EnvLengths<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(name, value)| Redacted {
                name,
                len: value.len(),
            }))
            .finish()
    }
}

impl std::fmt::Debug for Spawn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spawn")
            .field("program", &self.program)
            .field("args", &ArgLengths(self.args))
            .field("env", &EnvLengths(self.env))
            .finish()
    }
}

/// A socket address as text, held in place: `ip:port` exactly as `std` spells a
/// [`SocketAddr`](std::net::SocketAddr) (`[v6]:port` for IPv6), or empty for none. It is a value,
/// not an allocation: the host answers a bound or far address without building a string.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AddrText {
    len: u8,
    bytes: [u8; AddrText::CAP],
}

impl AddrText {
    /// The longest text a socket address spells is 58 bytes
    /// (`[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535`).
    pub const CAP: usize = 64;

    /// No address.
    pub const EMPTY: Self = Self {
        len: 0,
        bytes: [0; Self::CAP],
    };

    /// `addr` as `std` spells it.
    #[must_use]
    pub fn of(addr: &std::net::SocketAddr) -> Self {
        let mut text = Self::EMPTY;
        // A socket address never spells more than `CAP` bytes, so the write cannot fail.
        let _ = std::fmt::Write::write_fmt(&mut text, format_args!("{addr}"));
        text
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Only whole `str`s are ever written (`write_str` below), so the bytes are UTF-8.
        std::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or_default()
    }
}

impl std::fmt::Write for AddrText {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let at = usize::from(self.len);
        let end = at.checked_add(s.len()).ok_or(std::fmt::Error)?;
        let dst = self.bytes.get_mut(at..end).ok_or(std::fmt::Error)?;
        dst.copy_from_slice(s.as_bytes());
        self.len = u8::try_from(end).map_err(|_| std::fmt::Error)?;
        Ok(())
    }
}

impl Default for AddrText {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl std::ops::Deref for AddrText {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Debug for AddrText {
    /// As the text's own `str` shows.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl std::fmt::Display for AddrText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<str> for AddrText {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for AddrText {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for AddrText {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}

/// What `io.ends` answers of a handle ([`IoHost::ends`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ends {
    /// The local port (`0` for a handle with none).
    pub port: u16,
    /// The far end's address (empty = none).
    pub peer: AddrText,
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
    fn listen(&self, owner: u64, ticket: Ticket, bind: &str) -> IoResult<(u64, AddrText)>;

    /// The next connection off `listener`, for the accept `ticket` runs: its handle and its far
    fn accept(
        &self,
        owner: u64,
        ticket: Ticket,
        listener: u64,
        waker: &Waker,
    ) -> Poll<IoResult<(u64, AddrText)>>;

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

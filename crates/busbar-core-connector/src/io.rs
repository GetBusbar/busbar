// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `io.*` — READINESS ON THE PER-WORKER REACTOR (`BUSBAR-1.6.0.md` THE DESIGN, §5 and §11.2).
//!
//! The host owns every socket, and a socket's readiness comes from the reactor of the worker that
//! registered it: `register`, `poll_ready`, `clear_ready`, `deregister`. Nothing here starts a
//! thread or runs a runtime of its own. A socket registered outside a worker is refused
//! ([`NOT_ON_A_WORKER`]) rather than handed a reactor thread to hide behind, and every wait answers
//! not-ready with the caller's waker registered, never a block.
//!
//! * [`register`] puts a non-blocking descriptor on the calling worker's reactor, for both
//!   directions;
//! * [`Registered::poll_ready`] answers Ready once the direction may make progress, or Pending
//!   with the waker registered;
//! * [`Ready::clear_ready`] says the direction answered `WouldBlock` after all, so the next
//!   `poll_ready` waits for a fresh edge (the readiness token is what makes a missed edge
//!   impossible: it clears exactly the readiness it observed);
//! * [`Registered::deregister`] takes the descriptor back off the reactor.

use std::io;
use std::os::fd::AsRawFd;
use std::task::{Context, Poll};

use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::io::Interest;

/// What [`register`] answers off a worker: the descriptor was not registered.
pub const NOT_ON_A_WORKER: &str = "io.register: not on a worker's reactor";

/// A direction of a registered descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Bytes can be read (or a connection accepted).
    Read,
    /// Bytes can be written (or a connect completed).
    Write,
}

/// A descriptor registered on the calling worker's reactor.
#[derive(Debug)]
pub struct Registered<T: AsRawFd>(AsyncFd<T>);

/// One direction's observed readiness, from [`Registered::poll_ready`]. Dropping it keeps the
/// readiness; [`Ready::clear_ready`] clears exactly what was observed.
pub struct Ready<'a, T: AsRawFd>(AsyncFdReadyGuard<'a, T>);

impl<T: AsRawFd> Ready<'_, T> {
    /// The direction answered `WouldBlock`: wait for a fresh edge before the next attempt.
    pub fn clear_ready(mut self) {
        self.0.clear_ready();
    }
}

/// `io.register`: put the non-blocking `io` on the calling worker's reactor.
///
/// # Errors
///
/// [`NOT_ON_A_WORKER`] when the caller is not on a worker; the reactor's own refusal otherwise.
pub fn register<T: AsRawFd>(io: T) -> io::Result<Registered<T>> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(io::Error::other(NOT_ON_A_WORKER));
    }
    AsyncFd::with_interest(io, Interest::READABLE | Interest::WRITABLE).map(Registered)
}

impl<T: AsRawFd> Registered<T> {
    /// `io.poll_ready`: Ready once `dir` may make progress; Pending with `cx`'s waker registered.
    ///
    /// # Errors
    ///
    /// The reactor failed the registration.
    pub fn poll_ready(
        &self,
        dir: Direction,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Ready<'_, T>>> {
        match dir {
            Direction::Read => self.0.poll_read_ready(cx),
            Direction::Write => self.0.poll_write_ready(cx),
        }
        .map_ok(Ready)
    }

    /// `io.deregister`: take the descriptor back off the reactor.
    #[must_use]
    pub fn deregister(self) -> T {
        self.0.into_inner()
    }

    /// The descriptor.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        self.0.get_ref()
    }

    /// One non-blocking attempt of `op` in `dir`, repeated across fresh edges: `WouldBlock` clears
    /// the observed readiness and waits again; anything else is the answer.
    ///
    /// # Errors
    ///
    /// What `op` answered, or the reactor's failure.
    pub fn poll_io<R>(
        &self,
        dir: Direction,
        cx: &mut Context<'_>,
        mut op: impl FnMut(&T) -> io::Result<R>,
    ) -> Poll<io::Result<R>> {
        loop {
            let ready = std::task::ready!(self.poll_ready(dir, cx))?;
            match op(self.get_ref()) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => ready.clear_ready(),
                other => return Poll::Ready(other),
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/io_tests.rs"]
mod tests;

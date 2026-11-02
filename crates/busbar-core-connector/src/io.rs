// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `io.*` — READINESS ON THE PER-WORKER REACTOR (`BUSBAR-1.6.0.md` THE DESIGN, §5 and §11.2).

use std::io;
use std::os::fd::{AsFd, AsRawFd, RawFd};
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
pub struct Registered<T: AsFd>(AsyncFd<Owned<T>>);

/// The value [`register`] took, with the descriptor it lent at registration: the one descriptor the
/// reactor is told about for the registration's whole life, whatever the value would lend later.
#[derive(Debug)]
struct Owned<T: AsFd> {
    io: T,
    fd: RawFd,
}

impl<T: AsFd> AsRawFd for Owned<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// One direction's observed readiness, from [`Registered::poll_ready`]. Dropping it keeps the

pub struct Ready<'a, T: AsFd>(AsyncFdReadyGuard<'a, Owned<T>>);

impl<T: AsFd> Ready<'_, T> {
    /// The direction answered `WouldBlock`: wait for a fresh edge before the next attempt.
    pub fn clear_ready(mut self) {
        self.0.clear_ready();
    }
}

/// `io.register`: put the non-blocking `io` on the calling worker's reactor.

pub fn register<T: AsFd>(io: T) -> io::Result<Registered<T>> {
    let _entered = enter_process_runtime();
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(io::Error::other(NOT_ON_A_WORKER));
    }
    let fd = io.as_fd().as_raw_fd();
    let owned = Owned { io, fd };
    // SAFETY: tokio's contract for `register_with_interest` (RUSTSEC-2026-0386) is that the
    // descriptor `as_raw_fd` answers is valid and open, stays open on the same file description
    // for the `AsyncFd`'s whole life, and is the same on every call. `fd` is what `io.as_fd()`
    // lent: by I/O safety it is open and belongs to `io`, which cannot close it through a shared
    // borrow. `Owned::as_raw_fd` answers that one `fd` on every call. `io` is moved into the
    // `AsyncFd` and never handed out mutably (`Registered` lends only `&T`, never `get_mut`), so it
    // is neither dropped nor changed while registered: it leaves only through `into_inner`
    // ([`Registered::deregister`]) or the `AsyncFd`'s drop, and both take the descriptor off the
    // reactor before `io` is returned or dropped.
    #[allow(unsafe_code)]
    let registered =
        unsafe { AsyncFd::register_with_interest(owned, Interest::READABLE | Interest::WRITABLE) };
    registered.map(Registered).map_err(io::Error::from)
}

/// The process's one runtime, as the root installed it at boot.
static PROCESS_REACTOR: std::sync::OnceLock<tokio::runtime::Handle> = std::sync::OnceLock::new();

/// Install the process's one runtime: a socket registered off a runtime thread goes on its

pub fn install_process_reactor(handle: tokio::runtime::Handle) {
    let _ = PROCESS_REACTOR.set(handle);
}

/// Off a runtime's task, the process's one runtime entered for the guard's life — its reactor for a

pub(crate) fn enter_process_runtime() -> Option<tokio::runtime::EnterGuard<'static>> {
    if tokio::runtime::Handle::try_current().is_ok() && tokio::task::try_id().is_some() {
        return None;
    }
    PROCESS_REACTOR.get().map(tokio::runtime::Handle::enter)
}

impl<T: AsFd> Registered<T> {
    /// `io.poll_ready`: Ready once `dir` may make progress; Pending with `cx`'s waker registered.

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
        self.0.into_inner().io
    }

    /// The descriptor.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.0.get_ref().io
    }

    /// One non-blocking attempt of `op` in `dir`, repeated across fresh edges: `WouldBlock` clears

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

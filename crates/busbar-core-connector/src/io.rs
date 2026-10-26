// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `io.*` — READINESS ON THE PER-WORKER REACTOR (`BUSBAR-1.6.0.md` THE DESIGN, §5 and §11.2).
//!
//! The host owns every socket, and a socket's readiness comes from the reactor of the worker that
//! registered it: `register`, `poll_ready`, `clear_ready`, `deregister`. Nothing here starts a
//! thread or runs a runtime of its own. A socket registered off a runtime's task (a dispatcher
//! worker driving a plugin's connection, whatever runtime context it entered) goes on the process's
//! one runtime the root installed ([`install_process_reactor`]); with none installed it goes on the
//! runtime the caller is inside, and with none at all it is refused ([`NOT_ON_A_WORKER`]). Every
//! wait answers not-ready with the caller's waker registered, never a block.
//!
//! * [`register`] puts a non-blocking descriptor on the calling worker's reactor, for both
//!   directions. It takes only a value that OWNS its descriptor (`T: AsFd`, by value; a bare
//!   `RawFd` is not one), and the [`Registered`] holds that value until [`Registered::deregister`]
//!   hands it back, so the descriptor the reactor watches stays open and unchanged for the whole
//!   registration (RUSTSEC-2026-0386: tokio's safe `AsyncFd` constructors accepted any raw fd);
//! * [`Registered::poll_ready`] answers Ready once the direction may make progress, or Pending
//!   with the waker registered;
//! * [`Ready::clear_ready`] says the direction answered `WouldBlock` after all, so the next
//!   `poll_ready` waits for a fresh edge (the readiness token is what makes a missed edge
//!   impossible: it clears exactly the readiness it observed);
//! * [`Registered::deregister`] takes the descriptor back off the reactor.

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
/// readiness; [`Ready::clear_ready`] clears exactly what was observed.
pub struct Ready<'a, T: AsFd>(AsyncFdReadyGuard<'a, Owned<T>>);

impl<T: AsFd> Ready<'_, T> {
    /// The direction answered `WouldBlock`: wait for a fresh edge before the next attempt.
    pub fn clear_ready(mut self) {
        self.0.clear_ready();
    }
}

/// `io.register`: put the non-blocking `io` on the calling worker's reactor.
///
/// `io` is taken by value and must own its descriptor (`AsFd`): the registration holds it until
/// [`Registered::deregister`] hands it back, so the descriptor cannot be closed or reused under the
/// reactor.
///
/// # Errors
///
/// [`NOT_ON_A_WORKER`] when the caller is not on a worker; the reactor's own refusal otherwise.
pub fn register<T: AsFd>(io: T) -> io::Result<Registered<T>> {
    // A plugin driving its connection from a dispatcher worker (an export sink delivering a batch,
    // an auth plugin's `ready` fetching its key set) runs on no task: its socket goes on the
    // reactor of the process's one runtime, the one the root installed at boot
    // ([`install_process_reactor`]), even where the worker has ENTERED another runtime's context.
    // Never a reactor of its own.
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
/// reactor. Set once; a second install is ignored.
pub fn install_process_reactor(handle: tokio::runtime::Handle) {
    let _ = PROCESS_REACTOR.set(handle);
}

/// Off a runtime's task, the process's one runtime entered for the guard's life — its reactor for a
/// socket, its timer for a deadline. `None` inside a task (the runtime polling it drives its own
/// reactor and timer), or before the root installed it.
///
/// A thread that merely ENTERED a runtime is not driving it: a dispatcher worker runs inside the
/// control runtime's context while the control thread waits synchronously on that worker's op (the
/// boot's `ready`, a governance store's reply). A socket or a timer put on that runtime then waits
/// for a thread that is blocked on it, and its waker never fires; on the process reactor (the
/// connector's own I/O thread) it is always driven.
pub(crate) fn enter_process_runtime() -> Option<tokio::runtime::EnterGuard<'static>> {
    if tokio::runtime::Handle::try_current().is_ok() && tokio::task::try_id().is_some() {
        return None;
    }
    PROCESS_REACTOR.get().map(tokio::runtime::Handle::enter)
}

impl<T: AsFd> Registered<T> {
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
        self.0.into_inner().io
    }

    /// The descriptor.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.0.get_ref().io
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

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S I/O, PLUGIN SIDE (`abi::host::io`, `io.*`): safe calls into the [`IoSlots`] table
//! the host handed an instance at `open`, for ONE entry of one op on one ticket. What a carrier
//! moves bytes with: it never holds a descriptor, only the host's opaque handles. The `unsafe` of a
//! call through the table stays here, so a carrier crate stays `#![forbid(unsafe_code)]`.
//!
//! A slot that MAY PEND answers [`Poll::Pending`] when nothing moved: the host wakes the ticket
//! once the handle may make progress, and the op, re-entered, simply calls again. Nothing here
//! allocates: every result is a scalar or a count of the caller's own buffer.

use std::task::Poll;

use crate::abi::host::io::{
    op, AddrIn, HandleIn, IoSlots, ListenIn, OpenIn, ReadIn, ReadyIn, ShutIn, SpawnIn, WriteIn,
};
use crate::abi::host::service::{ServiceFn, ServiceHead, ServiceOut};
use crate::abi::mechanism::call::{AbiStr, Field, Outcome, RawOutcome};
use crate::abi::mechanism::ticket::{CompletionHandle, HostCtx, Ticket};
use crate::abi::sdk::lent::HostBuf;

pub use crate::abi::host::io::{DIR_BOTH, DIR_READ, DIR_WRITE, MAX_ADDR};

/// Why an I/O call answered without its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoFailure {
    /// The instance was handed no I/O table, or the host offers no such slot.
    Unarmed,
    /// The call may pend and the op runs on no ticket.
    NoTicket,
    /// The host refused the call (not admitted, not the caller's handle), with its text.
    Refused(String),
    /// The system failed the call, with its text.
    Failed(String),
    /// The host faulted.
    Fault,
}

impl IoFailure {
    /// The failure's text (empty = none).
    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Self::Refused(t) | Self::Failed(t) => t,
            Self::Unarmed => "the instance was handed no host I/O",
            Self::NoTicket => "the call runs on no ticket and cannot pend",
            Self::Fault => "the host I/O faulted",
        }
    }
}

impl std::fmt::Display for IoFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.text())
    }
}

impl std::error::Error for IoFailure {}

/// An I/O call's answer.
pub type IoAnswer<T> = Result<T, IoFailure>;

/// The host's I/O for one entry of one op on one ticket.
#[derive(Debug)]
pub struct Io<'h> {
    ctx: HostCtx,
    slots: *const IoSlots,
    ticket: Ticket,
    issued: u32,
    _host: std::marker::PhantomData<&'h ()>,
}

/// An I/O `in`: every one leads with a [`ServiceHead`].
trait IoIn {
    fn head(&mut self) -> &mut ServiceHead;
}
macro_rules! io_in {
    ($($t:ty),*) => {$(impl IoIn for $t {
        fn head(&mut self) -> &mut ServiceHead { &mut self.head }
    })*};
}
io_in!(OpenIn, ListenIn, AddrIn, ReadIn, WriteIn, ReadyIn, ShutIn, HandleIn, SpawnIn);

const fn head() -> ServiceHead {
    ServiceHead {
        size: 0,
        op: 0,
        handle: CompletionHandle {
            ticket: Ticket::NONE,
            seq: 0,
            _reserved: 0,
        },
    }
}

const fn text(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// The host's error text, copied.
fn host_text(s: AbiStr) -> String {
    if s.ptr.is_null() || s.len == 0 {
        return String::new();
    }
    // SAFETY: the host's text, `len` bytes, valid for the process's life (the service rule).
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

impl<'h> Io<'h> {
    pub(crate) const fn new(ctx: HostCtx, slots: *const IoSlots, ticket: Ticket) -> Self {
        Self {
            ctx,
            slots,
            ticket,
            issued: 0,
            _host: std::marker::PhantomData,
        }
    }

    /// Whether the host lent the instance its I/O table.
    #[must_use]
    pub fn armed(&self) -> bool {
        !self.slots.is_null()
    }

    fn slot(&self, pick: impl FnOnce(&IoSlots) -> Option<ServiceFn>) -> Option<ServiceFn> {
        // SAFETY: NULL, or the host's I/O table, valid for the instance's life.
        unsafe { self.slots.as_ref() }.and_then(pick)
    }

    /// Cross into slot `op` with `input`: its `out` when READY, `Pending` when nothing moved.
    fn call<I: IoIn>(
        &mut self,
        op: u32,
        pick: impl FnOnce(&IoSlots) -> Option<ServiceFn>,
        mut input: I,
    ) -> Poll<IoAnswer<ServiceOut>> {
        let Some(f) = self.slot(pick) else {
            return Poll::Ready(Err(IoFailure::Unarmed));
        };
        if self.ticket.is_none() && crate::abi::host::io::may_pend(op) {
            return Poll::Ready(Err(IoFailure::NoTicket));
        }
        let seq = self.issued;
        self.issued = self.issued.wrapping_add(1);
        *input.head() = ServiceHead {
            size: std::mem::size_of::<I>() as u32,
            op,
            handle: CompletionHandle {
                ticket: self.ticket,
                seq,
                _reserved: 0,
            },
        };
        let mut out = ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(Outcome::Fault),
            _reserved: [0; 3],
            value: 0,
            len: 0,
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            error: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
        };
        match f(self.ctx, std::ptr::from_ref(&input).cast(), &mut out).outcome() {
            Outcome::Ready => Poll::Ready(Ok(out)),
            Outcome::Pending => Poll::Pending,
            Outcome::Failed => Poll::Ready(Err(IoFailure::Failed(host_text(out.error)))),
            Outcome::Refused => Poll::Ready(Err(IoFailure::Refused(host_text(out.error)))),
            Outcome::Fault => Poll::Ready(Err(IoFailure::Fault)),
        }
    }

    /// A slot that never pends: its answer.
    fn now<I: IoIn>(
        &mut self,
        op: u32,
        pick: impl FnOnce(&IoSlots) -> Option<ServiceFn>,
        input: I,
    ) -> IoAnswer<ServiceOut> {
        match self.call(op, pick, input) {
            Poll::Ready(r) => r,
            // A slot that may not pend answered PENDING: the host broke the table's rule.
            Poll::Pending => Err(IoFailure::Fault),
        }
    }

    /// `io.open`: begin reaching `addr` (`ip:port`, or `unix:` and an absolute path); its handle,
    /// the connect in flight (it settles under [`Io::ready`] for [`DIR_WRITE`]).
    ///
    /// # Errors
    ///
    /// The host did not admit `addr` for this dial, or the system refused at once.
    pub fn open(&mut self, addr: &str) -> IoAnswer<u64> {
        let i = OpenIn {
            head: head(),
            addr: text(addr),
        };
        self.now(op::OPEN, |s| s.open, i).map(|o| o.value)
    }

    /// `io.listen`: bind `bind` (`ip:port`); the listener's handle and how many bytes of `addr`
    /// (at least [`MAX_ADDR`]) the address bound took.
    ///
    /// # Errors
    ///
    /// The host did not admit the bind, or the system could not bind it.
    pub fn listen(&mut self, bind: &str, addr: &mut [u8]) -> IoAnswer<(u64, usize)> {
        let i = ListenIn {
            head: head(),
            bind: text(bind),
            addr_buf: addr.as_mut_ptr(),
            addr_cap: addr.len(),
        };
        let o = self.now(op::LISTEN, |s| s.listen, i)?;
        written(o.value, o.len, addr.len())
    }

    /// `io.accept`: the next connection off `listener` — its handle and how many bytes of `peer`
    /// (at least [`MAX_ADDR`]) its far end's address took; `Pending` when none is waiting.
    pub fn accept(&mut self, listener: u64, peer: &mut [u8]) -> Poll<IoAnswer<(u64, usize)>> {
        let i = AddrIn {
            head: head(),
            handle: listener,
            addr_buf: peer.as_mut_ptr(),
            addr_cap: peer.len(),
        };
        let cap = peer.len();
        self.call(op::ACCEPT, |s| s.accept, i)
            .map(|r| r.and_then(|o| written(o.value, o.len, cap)))
    }

    /// `io.read`: bytes into `buf` (`0` = the clean end); `Pending` when none is ready.
    pub fn read(&mut self, handle: u64, buf: &mut [u8]) -> Poll<IoAnswer<usize>> {
        let cap = buf.len();
        let i = ReadIn {
            head: head(),
            handle,
            buf: buf.as_mut_ptr(),
            cap,
        };
        self.call(op::READ, |s| s.read, i)
            .map(|r| r.and_then(|o| count(o.len, cap)))
    }

    /// `io.read` STRAIGHT INTO THE HOST'S BUFFER (a carrier's `read` answering the host's own
    /// `buf`): the bytes land at `buf`'s next free place and are counted there; how many (`0` =
    /// the clean end, or no room left). `Pending` when none is ready.
    pub fn read_host(&mut self, handle: u64, buf: &mut HostBuf<'_, u8>) -> Poll<IoAnswer<usize>> {
        let (ptr, cap) = buf.room();
        let i = ReadIn {
            head: head(),
            handle,
            buf: ptr,
            cap,
        };
        let r = self
            .call(op::READ, |s| s.read, i)
            .map(|r| r.and_then(|o| count(o.len, cap)));
        if let Poll::Ready(Ok(n)) = r {
            buf.advance(n);
        }
        r
    }

    /// The address-writing slots, into a HOST buffer (a carrier's `listen`/`accept`/`arrival`
    /// answering the host's own address buffer): the address lands at `addr`'s next free place.
    fn addr_in(handle: u64, addr: &mut HostBuf<'_, u8>) -> (AddrIn, usize) {
        let (ptr, cap) = addr.room();
        (
            AddrIn {
                head: head(),
                handle,
                addr_buf: ptr,
                addr_cap: cap,
            },
            cap,
        )
    }

    /// [`Io::listen`], the address bound written into the host's buffer `addr`; the handle.
    ///
    /// # Errors
    ///
    /// As [`Io::listen`].
    pub fn listen_host(&mut self, bind: &str, addr: &mut HostBuf<'_, u8>) -> IoAnswer<u64> {
        let (ptr, cap) = addr.room();
        let i = ListenIn {
            head: head(),
            bind: text(bind),
            addr_buf: ptr,
            addr_cap: cap,
        };
        let o = self.now(op::LISTEN, |s| s.listen, i)?;
        addr.advance(count(o.len, cap)?);
        Ok(o.value)
    }

    /// [`Io::accept`], the far end's address written into the host's buffer `peer`; the handle.
    pub fn accept_host(&mut self, listener: u64, peer: &mut HostBuf<'_, u8>) -> Poll<IoAnswer<u64>> {
        let (i, cap) = Self::addr_in(listener, peer);
        match self.call(op::ACCEPT, |s| s.accept, i) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(o)) => Poll::Ready(count(o.len, cap).map(|n| {
                peer.advance(n);
                o.value
            })),
        }
    }

    /// `io.write`: how many of `bytes` the handle took; `Pending` when it took none.
    pub fn write(&mut self, handle: u64, bytes: &[u8]) -> Poll<IoAnswer<usize>> {
        let i = WriteIn {
            head: head(),
            handle,
            bytes: bytes.as_ptr(),
            len: bytes.len(),
        };
        let len = bytes.len();
        self.call(op::WRITE, |s| s.write, i)
            .map(|r| r.and_then(|o| count(o.len, len)))
    }

    /// `io.ready`: `Ready` once `handle` may make progress in `dir` ([`DIR_READ`] | [`DIR_WRITE`];
    /// for a stream still connecting, [`DIR_WRITE`] is its connect settling).
    pub fn ready(&mut self, handle: u64, dir: u32) -> Poll<IoAnswer<()>> {
        let i = ReadyIn {
            head: head(),
            handle,
            dir,
            _reserved: 0,
        };
        self.call(op::READY, |s| s.ready, i).map(|r| r.map(|_| ()))
    }

    /// `io.shut`: shut `how` ([`DIR_READ`] | [`DIR_WRITE`] | [`DIR_BOTH`]) of `handle` down.
    ///
    /// # Errors
    ///
    /// Not the caller's handle, or the system refused.
    pub fn shut(&mut self, handle: u64, how: u32) -> IoAnswer<()> {
        let i = ShutIn {
            head: head(),
            handle,
            how,
            _reserved: 0,
        };
        self.now(op::SHUT, |s| s.shut, i).map(|_| ())
    }

    /// `io.close`: release `handle` (a spawned program is killed with it).
    ///
    /// # Errors
    ///
    /// Not the caller's handle.
    pub fn close(&mut self, handle: u64) -> IoAnswer<()> {
        let i = HandleIn {
            head: head(),
            handle,
        };
        self.now(op::CLOSE, |s| s.close, i).map(|_| ())
    }

    /// `io.spawn`: start `program` (an absolute path) with `args` and exactly the environment
    /// `env`, no shell; the duplex handle over its input and output.
    ///
    /// # Errors
    ///
    /// The host did not admit the program for this dial, or the system could not start it.
    pub fn spawn(&mut self, program: AbiStr, args: &[AbiStr], env: &[Field]) -> IoAnswer<u64> {
        let i = SpawnIn {
            head: head(),
            program,
            args: args.as_ptr(),
            args_len: args.len(),
            env: env.as_ptr(),
            env_len: env.len(),
        };
        self.now(op::SPAWN, |s| s.spawn, i).map(|o| o.value)
    }

    /// [`Io::spawn`] of the program a carrier's `dial` was lent (`abi::transport::Destination`,
    /// `DEST_PROGRAM`), passed through as the host lent it: its path, arguments and environment.
    ///
    /// # Errors
    ///
    /// As [`Io::spawn`].
    pub fn spawn_dest(
        &mut self,
        dest: crate::abi::sdk::Lent<'_, crate::abi::transport::Destination>,
    ) -> IoAnswer<u64> {
        let d = dest.get();
        let i = SpawnIn {
            head: head(),
            program: d.program,
            args: d.args,
            args_len: d.args_len,
            env: d.env,
            env_len: d.env_len,
        };
        self.now(op::SPAWN, |s| s.spawn, i).map(|o| o.value)
    }

    /// `io.ends`: `handle`'s local port and how many bytes of `peer` (at least [`MAX_ADDR`]) its
    /// far end's address took (`0` = it has none).
    ///
    /// # Errors
    ///
    /// Not the caller's handle.
    pub fn ends(&mut self, handle: u64, peer: &mut [u8]) -> IoAnswer<(u32, usize)> {
        let i = AddrIn {
            head: head(),
            handle,
            addr_buf: peer.as_mut_ptr(),
            addr_cap: peer.len(),
        };
        let cap = peer.len();
        let o = self.now(op::ENDS, |s| s.ends, i)?;
        let port = u32::try_from(o.value).map_err(|_| IoFailure::Fault)?;
        Ok((port, count(o.len, cap)?))
    }
}

/// A count the host wrote: at most `cap`, else the host broke the rule.
fn count(n: u64, cap: usize) -> IoAnswer<usize> {
    usize::try_from(n)
        .ok()
        .filter(|n| *n <= cap)
        .ok_or(IoFailure::Fault)
}

/// A handle and the bytes written beside it.
fn written(handle: u64, n: u64, cap: usize) -> IoAnswer<(u64, usize)> {
    Ok((handle, count(n, cap)?))
}

#[cfg(test)]
#[path = "tests/io_tests.rs"]
mod tests;

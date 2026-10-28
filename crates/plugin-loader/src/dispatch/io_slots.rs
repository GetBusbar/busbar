// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S I/O SLOTS, HOST SIDE (`abi::host::io`, `io.*`): the [`IoSlots`] table every instance
//! is handed ([`IO_SLOTS`]), each slot a thin frame over the [`IoHost`] its dispatcher serves
//! ([`super::Dispatcher::install_io`]), called under the instance's own identity: a handle another
//! instance made is refused there, never here.
//!
//! * The frame checks the head (its op and its size), a slot that may pend has a ticket (REFUSED
//!   otherwise, never run), and an address buffer is at least `MAX_ADDR`.
//! * A slot that may pend hands the host the ticket's WAKER: an inline ticket's (`super::inline`)
//!   is its task's own; any other ticket's wakes it through the dispatcher's route, as the host's
//!   `wake` does.
//! * Every error text is interned: a `ServiceOut::error` is valid for the process's life, and the
//!   distinct texts the system answers are few.
//!
//! A panic answers FAULT; the `out` is written as far as the caller stated it, and one stated below
//! the first is REFUSED.

use std::ffi::c_void;
use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::task::{Poll, Wake, Waker};

use busbar_contract::abi::host::io::{
    check_addr_buf, check_dir, check_how, check_spawn_in, may_pend, op, AddrIn, HandleIn, IoSlots,
    ListenIn, OpenIn, ReadIn, ReadyIn, ShutIn, SpawnIn, WriteIn, SLOTS,
};
use busbar_contract::abi::host::service::{check_head, ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Field, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};
use busbar_contract::io_host::{Ends, IoHost, IoRefusal, IoResult, Spawn};

use super::services::{stated_out, write_out, Answered};
use super::ticket::Waking;

/// The table every instance is handed.
pub static IO_SLOTS: IoSlots = IoSlots {
    size: size_of::<IoSlots>() as u32,
    slots: SLOTS,
    open: Some(open),
    listen: Some(listen),
    accept: Some(accept),
    read: Some(read),
    write: Some(write),
    ready: Some(ready),
    shut: Some(shut),
    close: Some(close),
    spawn: Some(spawn),
    ends: Some(ends),
};

/// The refusal of an instance whose dispatcher serves no host I/O.
pub const NO_IO: &str = "no host I/O is bound";
/// The refusal of a slot that may pend, made on no ticket.
pub const UNTICKETED: &str = "an io slot that may pend is callable only inside a ticketed op";
/// The refusal of an address buffer below `MAX_ADDR`.
pub const SHORT_ADDR: &str = "an address buffer holds at least MAX_ADDR bytes";

/// The host's I/O refusal, as the plugin reads it.
fn refusal(e: IoRefusal) -> Answered {
    match e {
        IoRefusal::Refused(t) => Answered::bare(Outcome::Refused, crate::intern_name(&t)),
        IoRefusal::Failed(t) => Answered::bare(Outcome::Failed, crate::intern_name(&t)),
    }
}

/// A polled I/O's answer: PENDING, `ok`'s, or its refusal.
fn polled<T>(p: Poll<Result<T, IoRefusal>>, ok: impl FnOnce(T) -> Answered) -> Answered {
    match p {
        Poll::Pending => Answered::bare(Outcome::Pending, ""),
        Poll::Ready(Ok(v)) => ok(v),
        Poll::Ready(Err(e)) => refusal(e),
    }
}

/// The calling instance as the host knows it: its identity, its route, and the I/O it is served.
struct Caller {
    owner: u64,
    /// The route, and the instance as the supplier of every ticket it hands the I/O (#74).
    waking: Waking,
    io: Arc<dyn IoHost>,
}

impl Caller {
    /// The waker of `ticket`'s op: a held inline ticket's task, or the dispatcher's route, which
    /// judges any other ticket when the wake fires (#74: a generation never minted, inline or not,
    /// quarantines this caller, the supplier the waker carries).
    fn waker(&self, ticket: Ticket) -> Waker {
        if let Some(w) = self
            .waking
            .route
            .upgrade()
            .and_then(|r| r.inline_waker(ticket))
        {
            return w;
        }
        Waker::from(Arc::new(Routed {
            waking: self.waking.clone(),
            ticket,
        }))
    }
}

/// A wake through the dispatcher's route, as the host's own `wake` makes it.
struct Routed {
    waking: Waking,
    ticket: Ticket,
}

impl Wake for Routed {
    fn wake(self: Arc<Self>) {
        self.waking.wake(self.ticket);
    }
}

fn caller(ctx: HostCtx) -> Option<Caller> {
    let waking = Waking::of(super::handle::resolve(ctx)?)?;
    let io = waking.route.upgrade()?.io()?;
    Some(Caller {
        owner: ctx.handle,
        waking,
        io,
    })
}

/// ONE SLOT'S FRAME (module docs).
fn slot<I: Copy>(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
    service: u32,
    body: impl FnOnce(&I, &Caller, Ticket) -> Answered,
) -> RawOutcome {
    // SAFETY: a non-NULL `out` is the caller's, its leading `size` readable.
    let Some(lent) = (unsafe { stated_out(out) }) else {
        return RawOutcome::of(Outcome::Refused);
    };
    let a = catch_unwind(AssertUnwindSafe(|| {
        if input.is_null() || out.is_null() {
            return Answered::fault();
        }
        // SAFETY: a non-NULL `in` leads with its head (the call shape).
        let head = unsafe { input.cast::<ServiceHead>().read_unaligned() };
        if check_head(&head, service, size_of::<I>()).is_err() {
            return Answered::fault();
        }
        let ticket = head.handle.ticket;
        if may_pend(service) && ticket.is_none() {
            return Answered::bare(Outcome::Refused, UNTICKETED);
        }
        let Some(c) = caller(ctx) else {
            return Answered::bare(Outcome::Refused, NO_IO);
        };
        // SAFETY: the head covered an `I`.
        let i = unsafe { input.cast::<I>().read_unaligned() };
        body(&i, &c, ticket)
    }))
    .unwrap_or(Answered::fault());
    // SAFETY: the caller's `out`, as the call shape lends it, writable for the `lent` bytes it
    // stated.
    unsafe { write_out(out, lent, &a) }
}

/// A caller's string, checked: `None` for NULL with a length or bad UTF-8.
///
/// # Safety
/// `s` is the caller's, live for the call.
unsafe fn text<'a>(s: AbiStr) -> Option<&'a str> {
    // SAFETY: the caller's range, live for the call; its length capped before the slice is formed.
    std::str::from_utf8(unsafe { super::validate::lent_str(s) }?).ok()
}

/// A caller's list, checked: `None` for NULL with a count, or a count over the hard byte maximum
/// (refused before the slice is formed, THE DESIGN §11.13 M1).
///
/// # Safety
/// `ptr` names `len` of the caller's `T`s, live for the call.
unsafe fn list<'a, T>(ptr: *const T, len: usize) -> Option<&'a [T]> {
    // SAFETY: the caller's list, live for the call.
    unsafe { super::validate::lent(ptr, len) }
}

/// Write `addr` into the caller's address buffer (checked at least `MAX_ADDR`); its length.
///
/// # Safety
/// `buf` is the caller's, writable for `cap` bytes.
unsafe fn put(buf: *mut u8, cap: usize, addr: &str) -> u64 {
    let n = addr.len().min(cap);
    // SAFETY: the caller's buffer, `n <= cap`.
    unsafe { std::ptr::copy_nonoverlapping(addr.as_ptr(), buf, n) };
    n as u64
}

c_entry! {
    fn open(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        slot::<OpenIn>(ctx, input, out, op::OPEN, |i, c, ticket| {
            // SAFETY: the caller's string, live for the call.
            let Some(addr) = (unsafe { text(i.addr) }) else {
                return Answered::fault();
            };
            match c.io.open(c.owner, ticket, addr) {
                Ok(h) => Answered::ready(h, 0),
                Err(e) => refusal(e),
            }
        })
    }

    fn listen(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        slot::<ListenIn>(ctx, input, out, op::LISTEN, |i, c, ticket| {
            if check_addr_buf(i.addr_buf, i.addr_cap, "io.listen.addr").is_err() {
                return Answered::bare(Outcome::Refused, SHORT_ADDR);
            }
            // SAFETY: the caller's string, live for the call.
            let Some(bind) = (unsafe { text(i.bind) }) else {
                return Answered::fault();
            };
            match c.io.listen(c.owner, ticket, bind) {
                // SAFETY: the caller's buffer, checked at least `MAX_ADDR`.
                Ok((h, addr)) => Answered::ready(h, unsafe { put(i.addr_buf, i.addr_cap, &addr) }),
                Err(e) => refusal(e),
            }
        })
    }

    fn accept(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        slot::<AddrIn>(ctx, input, out, op::ACCEPT, |i, c, ticket| {
            if check_addr_buf(i.addr_buf, i.addr_cap, "io.accept.addr").is_err() {
                return Answered::bare(Outcome::Refused, SHORT_ADDR);
            }
            let p = c.io.accept(c.owner, ticket, i.handle, &c.waker(ticket));
            // SAFETY: the caller's buffer, checked at least `MAX_ADDR`.
            polled(p, |(h, peer)| {
                Answered::ready(h, unsafe { put(i.addr_buf, i.addr_cap, &peer) })
            })
        })
    }

    fn read(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        slot::<ReadIn>(ctx, input, out, op::READ, |i, c, ticket| {
            // SAFETY: the caller's buffer, writable for `cap` bytes for the call; NULL with a
            // capacity, or a capacity over the hard byte maximum, is refused before it is formed.
            let Some(buf) = (unsafe { super::validate::lent_mut(i.buf, i.cap) }) else {
                return Answered::fault();
            };
            let p = c.io.read(c.owner, i.handle, buf, &c.waker(ticket));
            polled(p, |n| Answered::ready(0, n as u64))
        })
    }

    fn write(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        slot::<WriteIn>(ctx, input, out, op::WRITE, |i, c, ticket| {
            // SAFETY: the caller's bytes, live for the call.
            let Some(bytes) = (unsafe { list(i.bytes, i.len) }) else {
                return Answered::fault();
            };
            let p = c.io.write(c.owner, i.handle, bytes, &c.waker(ticket));
            polled(p, |n| Answered::ready(0, n as u64))
        })
    }

    fn ready(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        slot::<ReadyIn>(ctx, input, out, op::READY, |i, c, ticket| {
            if check_dir(i.dir).is_err() {
                return Answered::fault();
            }
            let p = c.io.ready(c.owner, i.handle, i.dir, &c.waker(ticket));
            polled(p, |()| Answered::ready(0, 0))
        })
    }

    fn shut(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        slot::<ShutIn>(ctx, input, out, op::SHUT, |i, c, _| {
            if check_how(i.how).is_err() {
                return Answered::fault();
            }
            match c.io.shut(c.owner, i.handle, i.how) {
                Ok(()) => Answered::ready(0, 0),
                Err(e) => refusal(e),
            }
        })
    }

    fn close(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        slot::<HandleIn>(ctx, input, out, op::CLOSE, |i, c, _| {
            match c.io.close(c.owner, i.handle) {
                Ok(()) => Answered::ready(0, 0),
                Err(e) => refusal(e),
            }
        })
    }

    fn spawn(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        slot::<SpawnIn>(ctx, input, out, op::SPAWN, |i, c, ticket| {
            if check_spawn_in(i).is_err() {
                return Answered::fault();
            }
            // SAFETY: the caller's strings and lists, live for the call.
            let parsed = unsafe {
                let program = text(i.program);
                let args = list::<AbiStr>(i.args, i.args_len)
                    .and_then(|a| a.iter().map(|s| text(*s)).collect::<Option<Vec<_>>>());
                let env = list::<Field>(i.env, i.env_len).and_then(|e| {
                    e.iter()
                        .map(|f| Some((text(f.name)?, text(f.value)?)))
                        .collect::<Option<Vec<_>>>()
                });
                program.zip(args).zip(env)
            };
            let Some(((program, args), env)) = parsed else {
                return Answered::fault();
            };
            let spawn = Spawn {
                program,
                args: &args,
                env: &env,
            };
            match c.io.spawn(c.owner, ticket, &spawn) {
                Ok(h) => Answered::ready(h, 0),
                Err(e) => refusal(e),
            }
        })
    }

    fn ends(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        slot::<AddrIn>(ctx, input, out, op::ENDS, |i, c, _| {
            if check_addr_buf(i.addr_buf, i.addr_cap, "io.ends.addr").is_err() {
                return Answered::bare(Outcome::Refused, SHORT_ADDR);
            }
            // SAFETY: the caller's buffer, checked at least `MAX_ADDR`.
            unsafe { ends_answer(c.io.ends(c.owner, i.handle), i.addr_buf, i.addr_cap) }
        })
    }
}

/// `io.ends`' answer of what the host's I/O reported: a program that has exited answers its exit
/// code in `value` with `exited` set and writes no far address; any other handle its local port and
/// its far end's address.
///
/// # Safety
/// `buf` is the caller's, writable for `cap` bytes.
unsafe fn ends_answer(ends: IoResult<Ends>, buf: *mut u8, cap: usize) -> Answered {
    match ends {
        Ok(Ends {
            exit: Some(code), ..
        }) => Answered {
            exited: 1,
            ..Answered::ready(u64::from(code), 0)
        },
        // SAFETY: the caller's buffer (the contract above).
        Ok(Ends { port, peer, .. }) => {
            Answered::ready(u64::from(port), unsafe { put(buf, cap, &peer) })
        }
        Err(e) => refusal(e),
    }
}

#[cfg(test)]
#[path = "../tests/io_slots_tests.rs"]
mod tests;

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
//! A panic answers FAULT; the whole `out` is written.

use std::ffi::c_void;
use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Weak};
use std::task::{Poll, Wake, Waker};

use busbar_contract::abi::host::io::{
    check_addr_buf, check_dir, check_how, check_spawn_in, may_pend, op, AddrIn, HandleIn, IoSlots,
    ListenIn, OpenIn, ReadIn, ReadyIn, ShutIn, SpawnIn, WriteIn, SLOTS,
};
use busbar_contract::abi::host::service::{check_head, ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Field, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};
use busbar_contract::io_host::{IoHost, IoRefusal, Spawn};

use super::ticket::{InstanceWake, WakeRoute};

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

/// One slot's answer, before it is written into the caller's `out`.
struct Answer {
    outcome: Outcome,
    value: u64,
    len: u64,
    error: &'static str,
}

impl Answer {
    const fn ready(value: u64, len: u64) -> Self {
        Self {
            outcome: Outcome::Ready,
            value,
            len,
            error: "",
        }
    }

    const fn with(outcome: Outcome, error: &'static str) -> Self {
        Self {
            outcome,
            value: 0,
            len: 0,
            error,
        }
    }

    fn of(e: IoRefusal) -> Self {
        match e {
            IoRefusal::Refused(t) => Self::with(Outcome::Refused, crate::intern_name(&t)),
            IoRefusal::Failed(t) => Self::with(Outcome::Failed, crate::intern_name(&t)),
        }
    }

    fn polled<T>(p: Poll<Result<T, IoRefusal>>, ok: impl FnOnce(T) -> Self) -> Self {
        match p {
            Poll::Pending => Self::with(Outcome::Pending, ""),
            Poll::Ready(Ok(v)) => ok(v),
            Poll::Ready(Err(e)) => Self::of(e),
        }
    }
}

/// The calling instance as the host knows it: its identity, its route, and the I/O it is served.
struct Caller {
    owner: u64,
    route: Weak<dyn WakeRoute>,
    io: Arc<dyn IoHost>,
}

impl Caller {
    /// The waker of `ticket`'s op: an inline ticket's task, or the dispatcher's route.
    fn waker(&self, ticket: Ticket) -> Waker {
        if let Some(w) = self.route.upgrade().and_then(|r| r.inline_waker(ticket)) {
            return w;
        }
        Waker::from(Arc::new(Routed {
            route: self.route.clone(),
            ticket,
        }))
    }
}

/// A wake through the dispatcher's route, as the host's own `wake` makes it.
struct Routed {
    route: Weak<dyn WakeRoute>,
    ticket: Ticket,
}

impl Wake for Routed {
    fn wake(self: Arc<Self>) {
        if let Some(r) = self.route.upgrade() {
            r.wake(self.ticket);
        }
    }
}

fn caller(ctx: HostCtx) -> Option<Caller> {
    if ctx.ptr.is_null() {
        return None;
    }
    // SAFETY: every `HostCtx` the host hands out points to a leaked `InstanceWake`.
    let wake = unsafe { &*ctx.ptr.cast_const().cast::<InstanceWake>() };
    let route = wake.route.get()?.clone();
    let io = route.upgrade()?.io()?;
    Some(Caller {
        owner: ctx.ptr as usize as u64,
        route,
        io,
    })
}

/// ONE SLOT'S FRAME (module docs).
fn slot<I: Copy>(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
    service: u32,
    body: impl FnOnce(&I, &Caller, Ticket) -> Answer,
) -> RawOutcome {
    let a = catch_unwind(AssertUnwindSafe(|| {
        if input.is_null() || out.is_null() {
            return Answer::with(Outcome::Fault, "");
        }
        // SAFETY: a non-NULL `in` leads with its head (the call shape).
        let head = unsafe { input.cast::<ServiceHead>().read_unaligned() };
        if check_head(&head, service, size_of::<I>()).is_err() {
            return Answer::with(Outcome::Fault, "");
        }
        let ticket = head.handle.ticket;
        if may_pend(service) && ticket.is_none() {
            return Answer::with(Outcome::Refused, UNTICKETED);
        }
        let Some(c) = caller(ctx) else {
            return Answer::with(Outcome::Refused, NO_IO);
        };
        // SAFETY: the head covered an `I`.
        let i = unsafe { input.cast::<I>().read_unaligned() };
        body(&i, &c, ticket)
    }))
    .unwrap_or(Answer::with(Outcome::Fault, ""));
    if !out.is_null() {
        let o = ServiceOut {
            size: size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(a.outcome),
            _reserved: [0; 3],
            value: a.value,
            len: a.len,
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            error: AbiStr {
                ptr: if a.error.is_empty() {
                    std::ptr::null()
                } else {
                    a.error.as_ptr()
                },
                len: a.error.len(),
            },
        };
        // SAFETY: the caller's `out`, checked non-NULL.
        unsafe { out.write_unaligned(o) };
    }
    RawOutcome::of(a.outcome)
}

/// A caller's string, checked: `None` for NULL with a length or bad UTF-8.
///
/// # Safety
/// `s` is the caller's, live for the call.
unsafe fn text<'a>(s: AbiStr) -> Option<&'a str> {
    if s.len == 0 {
        return Some("");
    }
    if s.ptr.is_null() {
        return None;
    }
    // SAFETY: the caller's range, live for the call.
    std::str::from_utf8(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).ok()
}

/// A caller's list, checked: `None` for NULL with a count.
///
/// # Safety
/// `ptr` names `len` of the caller's `T`s, live for the call.
unsafe fn list<'a, T>(ptr: *const T, len: usize) -> Option<&'a [T]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller's list, live for the call.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
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

extern "C" fn open(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot::<OpenIn>(ctx, input, out, op::OPEN, |i, c, ticket| {
        // SAFETY: the caller's string, live for the call.
        let Some(addr) = (unsafe { text(i.addr) }) else {
            return Answer::with(Outcome::Fault, "");
        };
        match c.io.open(c.owner, ticket, addr) {
            Ok(h) => Answer::ready(h, 0),
            Err(e) => Answer::of(e),
        }
    })
}

extern "C" fn listen(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot::<ListenIn>(ctx, input, out, op::LISTEN, |i, c, ticket| {
        if check_addr_buf(i.addr_buf, i.addr_cap, "io.listen.addr").is_err() {
            return Answer::with(Outcome::Refused, SHORT_ADDR);
        }
        // SAFETY: the caller's string, live for the call.
        let Some(bind) = (unsafe { text(i.bind) }) else {
            return Answer::with(Outcome::Fault, "");
        };
        match c.io.listen(c.owner, ticket, bind) {
            // SAFETY: the caller's buffer, checked at least `MAX_ADDR`.
            Ok((h, addr)) => Answer::ready(h, unsafe { put(i.addr_buf, i.addr_cap, &addr) }),
            Err(e) => Answer::of(e),
        }
    })
}

extern "C" fn accept(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot::<AddrIn>(ctx, input, out, op::ACCEPT, |i, c, ticket| {
        if check_addr_buf(i.addr_buf, i.addr_cap, "io.accept.addr").is_err() {
            return Answer::with(Outcome::Refused, SHORT_ADDR);
        }
        let p = c.io.accept(c.owner, ticket, i.handle, &c.waker(ticket));
        // SAFETY: the caller's buffer, checked at least `MAX_ADDR`.
        Answer::polled(p, |(h, peer)| {
            Answer::ready(h, unsafe { put(i.addr_buf, i.addr_cap, &peer) })
        })
    })
}

extern "C" fn read(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot::<ReadIn>(ctx, input, out, op::READ, |i, c, ticket| {
        if i.cap > 0 && i.buf.is_null() {
            return Answer::with(Outcome::Fault, "");
        }
        let buf: &mut [u8] = if i.cap == 0 {
            &mut []
        } else {
            // SAFETY: the caller's buffer, writable for `cap` bytes for the call.
            unsafe { std::slice::from_raw_parts_mut(i.buf, i.cap) }
        };
        let p = c.io.read(c.owner, i.handle, buf, &c.waker(ticket));
        Answer::polled(p, |n| Answer::ready(0, n as u64))
    })
}

extern "C" fn write(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot::<WriteIn>(ctx, input, out, op::WRITE, |i, c, ticket| {
        // SAFETY: the caller's bytes, live for the call.
        let Some(bytes) = (unsafe { list(i.bytes, i.len) }) else {
            return Answer::with(Outcome::Fault, "");
        };
        let p = c.io.write(c.owner, i.handle, bytes, &c.waker(ticket));
        Answer::polled(p, |n| Answer::ready(0, n as u64))
    })
}

extern "C" fn ready(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot::<ReadyIn>(ctx, input, out, op::READY, |i, c, ticket| {
        if check_dir(i.dir).is_err() {
            return Answer::with(Outcome::Fault, "");
        }
        let p = c.io.ready(c.owner, i.handle, i.dir, &c.waker(ticket));
        Answer::polled(p, |()| Answer::ready(0, 0))
    })
}

extern "C" fn shut(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot::<ShutIn>(ctx, input, out, op::SHUT, |i, c, _| {
        if check_how(i.how).is_err() {
            return Answer::with(Outcome::Fault, "");
        }
        match c.io.shut(c.owner, i.handle, i.how) {
            Ok(()) => Answer::ready(0, 0),
            Err(e) => Answer::of(e),
        }
    })
}

extern "C" fn close(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot::<HandleIn>(ctx, input, out, op::CLOSE, |i, c, _| {
        match c.io.close(c.owner, i.handle) {
            Ok(()) => Answer::ready(0, 0),
            Err(e) => Answer::of(e),
        }
    })
}

extern "C" fn spawn(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot::<SpawnIn>(ctx, input, out, op::SPAWN, |i, c, ticket| {
        if check_spawn_in(i).is_err() {
            return Answer::with(Outcome::Fault, "");
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
            return Answer::with(Outcome::Fault, "");
        };
        let spawn = Spawn {
            program,
            args: &args,
            env: &env,
        };
        match c.io.spawn(c.owner, ticket, &spawn) {
            Ok(h) => Answer::ready(h, 0),
            Err(e) => Answer::of(e),
        }
    })
}

extern "C" fn ends(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot::<AddrIn>(ctx, input, out, op::ENDS, |i, c, _| {
        if check_addr_buf(i.addr_buf, i.addr_cap, "io.ends.addr").is_err() {
            return Answer::with(Outcome::Refused, SHORT_ADDR);
        }
        match c.io.ends(c.owner, i.handle) {
            // SAFETY: the caller's buffer, checked at least `MAX_ADDR`.
            Ok((port, peer)) => Answer::ready(u64::from(port), unsafe {
                put(i.addr_buf, i.addr_cap, &peer)
            }),
            Err(e) => Answer::of(e),
        }
    })
}

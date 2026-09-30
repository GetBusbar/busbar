// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR SLOTS, HOST SIDE (`BUSBAR-1.6.0.md` §11.12, the connections section): the
//! [`ConnectorSlots`] table ([`CONN_SLOTS`]) an instance whose Statement declares a need is handed
//! at bind, each slot a thin frame over the host's ONE connection table
//! ([`busbar_contract::conn::Conns`]), called under the instance's own identity.
//!
//! * `ESTABLISH` opens the need (its Statement index) at the target the plugin names.
//! * `READ` answers the next piece's bytes; nothing ready is PENDING on the caller's ticket (the
//!   table wakes it), and never PENDING without one. A closed stream reads as its end (`len` 0).
//! * `WRITE` offers bytes; `CLOSE` closes.
//! * `RANDOM` fills the buffer from the OS; `IDENTITY` names the process.
//! * A slot this host does not offer is NULL: a plugin that needs it refuses to open.

use std::mem::size_of;
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, OnceLock};

use busbar_contract::abi::host::conn::connector::{
    service, ConnectorSlots, EstablishIn, IdentityIn, IoIn, ProcessIdentity, RandomIn, StreamIn,
    SERVICES,
};
use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};
use busbar_contract::conn::{ConnError, ConnId, Conns, InstanceId, NeedId, OpenDesc};

use super::ticket::InstanceWake;

/// The table an instance with a declared need is handed.
pub static CONN_SLOTS: ConnectorSlots = ConnectorSlots {
    size: size_of::<ConnectorSlots>() as u32,
    slots: SERVICES,
    establish: Some(establish),
    reject_endpoint: None,
    side_stream: None,
    read: Some(read),
    write: Some(write),
    upgrade_secure: None,
    facts: None,
    checkout: None,
    checkin: None,
    close: Some(close),
    random: Some(random),
    identity: Some(identity),
};

/// A mechanism ticket as the connection table's wake number ([`busbar_contract::conn::Ticket`]):
/// [`Ticket::NONE`] is `0`, which registers nothing.
#[must_use]
pub const fn conn_ticket(t: Ticket) -> u64 {
    ((t.slot as u64) << 32) | t.generation as u64
}

/// The mechanism ticket a connection table's wake number names ([`conn_ticket`]'s inverse).
#[must_use]
pub const fn ticket_of(n: u64) -> Ticket {
    Ticket {
        slot: (n >> 32) as u32,
        generation: n as u32,
    }
}

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

    /// A connection table's refusal, as the plugin reads it.
    const fn of(e: ConnError) -> Self {
        let outcome = match e {
            ConnError::Pending => Outcome::Pending,
            ConnError::Timeout | ConnError::Closed | ConnError::Fault => Outcome::Failed,
            ConnError::NotOwner
            | ConnError::UndeclaredNeed
            | ConnError::Refused
            | ConnError::Unarmed => Outcome::Refused,
        };
        Self::with(outcome, e.text())
    }
}

/// The instance a context names, and its connection table.
fn armed(ctx: HostCtx) -> Option<&'static (InstanceId, Arc<dyn Conns>)> {
    if ctx.ptr.is_null() {
        return None;
    }
    // SAFETY: every `HostCtx` the host hands out points to a leaked `InstanceWake`.
    let wake: &'static InstanceWake = unsafe { &*ctx.ptr.cast_const().cast::<InstanceWake>() };
    wake.conn.get()
}

/// ONE SLOT'S FRAME: the `in` and `out` are there and the head is this service's and covers its
/// `in`, then `body` with the caller's identity and table. A panic answers FAULT; the whole `out`
/// is written.
fn slot(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
    service: u32,
    in_size: usize,
    body: impl FnOnce(InstanceId, &Arc<dyn Conns>, ServiceHead) -> Answer,
) -> RawOutcome {
    let a = catch_unwind(AssertUnwindSafe(|| {
        if input.is_null() || out.is_null() {
            return Answer::with(Outcome::Fault, "");
        }
        // SAFETY: a non-NULL `in` leads with its head (the call shape).
        let head = unsafe { input.cast::<ServiceHead>().read_unaligned() };
        if head.op != service || (head.size as usize) < in_size {
            return Answer::with(Outcome::Fault, "");
        }
        match armed(ctx) {
            Some((id, table)) => body(*id, table, head),
            None => Answer::of(ConnError::Unarmed),
        }
    }))
    .unwrap_or_else(|_| Answer::with(Outcome::Fault, ""));
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

/// The caller's bytes (`len` of them at `ptr`), or `None` for a length behind NULL.
///
/// # Safety
/// A non-NULL `ptr` names `len` live bytes for the call.
unsafe fn bytes<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    match (ptr.is_null(), len) {
        (_, 0) => Some(&mut []),
        (true, _) => None,
        // SAFETY: the caller's contract.
        (false, n) => Some(unsafe { std::slice::from_raw_parts_mut(ptr, n) }),
    }
}

extern "C" fn establish(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::ESTABLISH,
        size_of::<EstablishIn>(),
        |id, table, _| {
            // SAFETY: the head covered an `EstablishIn`.
            let i = unsafe { input.cast::<EstablishIn>().read_unaligned() };
            // SAFETY: a checked range of the caller's, live for the call.
            let Some(target) = (unsafe { bytes(i.target.ptr.cast_mut(), i.target.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            let target = String::from_utf8_lossy(target);
            let desc = OpenDesc {
                target: &target,
                ..OpenDesc::default()
            };
            match table.open(id, NeedId(i.need), &desc) {
                Ok(ConnId(stream)) => Answer::ready(stream, 0),
                Err(e) => Answer::of(e),
            }
        },
    )
}

extern "C" fn read(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::READ,
        size_of::<IoIn>(),
        |id, table, head| {
            // SAFETY: the head covered an `IoIn`.
            let i = unsafe { input.cast::<IoIn>().read_unaligned() };
            // SAFETY: the caller's buffer, live until the service completes.
            let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            let ticket = conn_ticket(head.handle.ticket);
            match table.read(id, ConnId(i.stream), ticket, buf) {
                Ok(piece) => Answer::ready(0, piece.len as u64),
                Err(ConnError::Closed) => Answer::ready(0, 0),
                Err(ConnError::Pending) if head.handle.ticket.is_none() => Answer::with(
                    Outcome::Refused,
                    "a read that would pend is callable only inside a ticketed op",
                ),
                Err(e) => Answer::of(e),
            }
        },
    )
}

extern "C" fn write(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::WRITE,
        size_of::<IoIn>(),
        |id, table, _| {
            // SAFETY: the head covered an `IoIn`.
            let i = unsafe { input.cast::<IoIn>().read_unaligned() };
            // SAFETY: the caller's bytes, live until the service completes.
            let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            match table.write(id, ConnId(i.stream), buf, false) {
                Ok(n) => Answer::ready(0, n as u64),
                Err(e) => Answer::of(e),
            }
        },
    )
}

extern "C" fn close(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::CLOSE,
        size_of::<StreamIn>(),
        |id, table, _| {
            // SAFETY: the head covered a `StreamIn`.
            let i = unsafe { input.cast::<StreamIn>().read_unaligned() };
            match table.close(id, ConnId(i.stream)) {
                Ok(()) => Answer::ready(0, 0),
                Err(e) => Answer::of(e),
            }
        },
    )
}

extern "C" fn random(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::RANDOM,
        size_of::<RandomIn>(),
        |_, _, _| {
            // SAFETY: the head covered a `RandomIn`.
            let i = unsafe { input.cast::<RandomIn>().read_unaligned() };
            // SAFETY: the caller's buffer, live for the call.
            let Some(buf) = (unsafe { bytes(i.buf, i.len) }) else {
                return Answer::with(Outcome::Fault, "");
            };
            match getrandom::fill(buf) {
                Ok(()) => Answer::ready(0, i.len as u64),
                Err(_) => Answer::with(Outcome::Failed, "the host has no randomness"),
            }
        },
    )
}

/// The process's OS user and program name, read once and held for the process's life.
fn process() -> &'static (String, String) {
    static ONE: OnceLock<(String, String)> = OnceLock::new();
    ONE.get_or_init(|| {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_default();
        let program = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default();
        (user, program)
    })
}

fn abi(s: &'static str) -> AbiStr {
    AbiStr {
        ptr: if s.is_empty() {
            std::ptr::null()
        } else {
            s.as_ptr()
        },
        len: s.len(),
    }
}

extern "C" fn identity(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    slot(
        ctx,
        input,
        out,
        service::IDENTITY,
        size_of::<IdentityIn>(),
        |_, _, _| {
            // SAFETY: the head covered an `IdentityIn`.
            let i = unsafe { input.cast::<IdentityIn>().read_unaligned() };
            if i.identity.is_null() {
                return Answer::with(Outcome::Fault, "");
            }
            let (user, program) = process();
            // SAFETY: the caller's identity slot, checked non-NULL.
            unsafe {
                i.identity.write_unaligned(ProcessIdentity {
                    size: size_of::<ProcessIdentity>() as u32,
                    _reserved: 0,
                    pid: u64::from(std::process::id()),
                    os_user: abi(user),
                    program: abi(program),
                });
            }
            Answer::ready(0, 0)
        },
    )
}

#[cfg(test)]
#[path = "../tests/conn_services_tests.rs"]
mod tests;

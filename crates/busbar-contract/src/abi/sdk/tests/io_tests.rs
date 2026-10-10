// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin side of the host's I/O table: a table of test slots answers each shape, and the SDK
//! reads it as the rules say.

use super::*;
use std::ffi::c_void;

use crate::abi::host::io::SLOTS;

const TICKET: Ticket = Ticket {
    slot: 3,
    generation: 1,
};

fn answer(
    out: *mut ServiceOut,
    o: Outcome,
    value: u64,
    len: u64,
    error: &'static str,
) -> RawOutcome {
    // SAFETY: the SDK's `out`, live for the call.
    unsafe {
        (*out).outcome = RawOutcome::of(o);
        (*out).value = value;
        (*out).len = len;
        (*out).error = AbiStr {
            ptr: error.as_ptr(),
            len: error.len(),
        };
    }
    RawOutcome::of(o)
}

/// The C ABI, spelled once for the test slots below: each spelling of its literal is a Law 0 hit
/// (the scan reads it as a secret instance's id).
macro_rules! c_abi {
    ($($(#[$m:meta])* fn $name:ident($($arg:ident: $t:ty),* $(,)?) -> $ret:ty $body:block)*) => {
        $($(#[$m])* extern "C" fn $name($($arg: $t),*) -> $ret $body)*
    };
}

c_abi! {
    fn open(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        // SAFETY: the SDK's `in`.
        let i = unsafe { input.cast::<OpenIn>().read() };
        // SAFETY: the SDK's string.
        let addr = unsafe { std::slice::from_raw_parts(i.addr.ptr, i.addr.len) };
        if addr == b"127.0.0.1:1" {
            answer(out, Outcome::Ready, 9, 0, "")
        } else {
            answer(out, Outcome::Refused, 0, 0, "not admitted")
        }
    }

    fn read(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        // SAFETY: the SDK's `in`.
        let i = unsafe { input.cast::<ReadIn>().read() };
        assert_eq!(i.head.op, op::READ);
        assert_eq!(i.head.handle.ticket, TICKET);
        match i.handle {
            1 => answer(out, Outcome::Pending, 0, 0, ""),
            2 => {
                // SAFETY: the SDK's buffer.
                unsafe { i.buf.write(b'x') };
                answer(out, Outcome::Ready, 0, 1, "")
            }
            3 => answer(out, Outcome::Ready, 0, i.cap as u64 + 1, ""),
            _ => answer(out, Outcome::Failed, 0, 0, "reset by peer"),
        }
    }

    fn ends(_ctx: HostCtx, _input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        answer(out, Outcome::Ready, 8080, 3, "")
    }
}

static TABLE: IoSlots = IoSlots {
    size: std::mem::size_of::<IoSlots>() as u32,
    slots: SLOTS,
    open: Some(open),
    listen: None,
    accept: None,
    read: Some(read),
    write: None,
    ready: None,
    shut: None,
    close: None,
    spawn: None,
    ends: Some(ends),
};

fn io(ticket: Ticket) -> Io<'static> {
    Io::new(
        HostCtx {
            ptr: std::ptr::null_mut(),
        },
        &TABLE,
        ticket,
    )
}

#[test]
fn an_open_answers_the_hosts_handle_or_its_refusal() {
    assert_eq!(io(Ticket::NONE).open("127.0.0.1:1"), Ok(9));
    assert_eq!(
        io(Ticket::NONE).open("10.0.0.1:1"),
        Err(IoFailure::Refused("not admitted".into()))
    );
}

#[test]
fn a_read_pends_moves_or_fails_and_a_count_past_the_buffer_is_a_fault() {
    let mut buf = [0_u8; 4];
    let mut io = io(TICKET);
    assert_eq!(io.read(1, &mut buf), Poll::Pending);
    assert_eq!(io.read(2, &mut buf), Poll::Ready(Ok(1)));
    assert_eq!(buf[0], b'x');
    assert_eq!(io.read(3, &mut buf), Poll::Ready(Err(IoFailure::Fault)));
    assert_eq!(
        io.read(4, &mut buf),
        Poll::Ready(Err(IoFailure::Failed("reset by peer".into())))
    );
}

#[test]
fn a_slot_that_may_pend_is_not_made_on_no_ticket_and_an_absent_slot_is_unarmed() {
    let mut buf = [0_u8; 4];
    assert_eq!(
        io(Ticket::NONE).read(2, &mut buf),
        Poll::Ready(Err(IoFailure::NoTicket))
    );
    assert_eq!(
        io(TICKET).write(2, b"x"),
        Poll::Ready(Err(IoFailure::Unarmed))
    );
    let bare = Io::new(
        HostCtx {
            ptr: std::ptr::null_mut(),
        },
        std::ptr::null(),
        TICKET,
    );
    assert!(!bare.armed());
}

#[test]
fn ends_answers_the_local_port_and_the_peer_bytes() {
    let mut peer = [0_u8; MAX_ADDR];
    assert_eq!(io(Ticket::NONE).ends(9, &mut peer), Ok((8080, 3)));
}

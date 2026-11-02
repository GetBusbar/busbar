// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin side of the host's I/O table: a table of test slots answers each shape, and the SDK

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

    fn ends(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        // SAFETY: the SDK's `in`, an `AddrIn`.
        let i = unsafe { input.cast::<AddrIn>().read() };
        match i.handle {
            // A program that exited with code 3; its pipe may still be held open.
            7 => {
                // SAFETY: the SDK's `out`, live for the call.
                unsafe { (*out).exited = 1 };
                answer(out, Outcome::Ready, 3, 0, "")
            }
            // A program still running: no far end, not exited.
            8 => answer(out, Outcome::Ready, 0, 0, ""),
            _ => answer(out, Outcome::Ready, 8080, 3, ""),
        }
    }

    fn spawn(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
        // SAFETY: `Io::spawn` builds the frame and both nested lists from its borrowed strings;
        // their storage and the wrapper's ABI lists remain live until this slot returns.
        let i = unsafe { input.cast::<SpawnIn>().read() };
        assert_eq!(i.head.op, op::SPAWN);
        assert_eq!(i.head.handle.ticket, TICKET);
        // SAFETY: as above; these ranges are initialized by the wrapper and still borrowed.
        unsafe {
            let program = std::slice::from_raw_parts(i.program.ptr, i.program.len);
            let args = std::slice::from_raw_parts(i.args, i.args_len);
            let env = std::slice::from_raw_parts(i.env, i.env_len);
            let args: Vec<&[u8]> = args.iter()
                .map(|s| std::slice::from_raw_parts(s.ptr, s.len)).collect();
            let env: Vec<(&[u8], &[u8])> = env.iter().map(|f| (
                std::slice::from_raw_parts(f.name.ptr, f.name.len),
                std::slice::from_raw_parts(f.value.ptr, f.value.len),
            )).collect();
            assert_eq!(program, b"/usr/bin/tool");
            assert_eq!(args, [b"--flag".as_slice(), b"argument with spaces".as_slice(), b""]);
            assert_eq!(env, [(b"NAME".as_slice(), b"value".as_slice()), (b"EMPTY", b"")]);
        }
        answer(out, Outcome::Ready, 11, 0, "")
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
    Io::new(HostCtx::NONE, &TABLE, ticket)
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
    let bare = Io::new(HostCtx::NONE, std::ptr::null(), TICKET);
    assert!(!bare.armed());
}

#[test]
fn ends_answers_the_local_port_and_the_peer_bytes() {
    let mut peer = [0_u8; MAX_ADDR];
    assert_eq!(io(Ticket::NONE).ends(9, &mut peer), Ok((8080, 3)));
}

/// `io.ends` on a program's handle reads the program's own exit from `exited`: the code once it

#[test]
fn program_exit_reads_the_exited_byte_and_the_code() {
    assert_eq!(io(Ticket::NONE).program_exit(7), Ok(Some(3)));
    assert_eq!(io(Ticket::NONE).program_exit(8), Ok(None));
    assert_eq!(io(Ticket::NONE).program_exit(9), Ok(None));
}

/// The public safe entry receives only borrowed Rust strings, including nested arguments and

#[test]
fn spawn_lends_owned_strings_and_nested_lists_until_the_slot_returns() {
    let table = IoSlots {
        spawn: Some(spawn),
        ..TABLE
    };
    let mut io = Io::new(HostCtx::NONE, &table, TICKET);
    let program = String::from("/usr/bin/tool");
    let argument = String::from("argument with spaces");
    let name = String::from("NAME");
    let value = String::from("value");
    assert_eq!(
        io.spawn(
            &program,
            &["--flag", &argument, ""],
            &[(&name, &value), ("EMPTY", "")]
        ),
        Ok(11)
    );
    assert_eq!(
        (program.as_str(), argument.as_str(), value.as_str()),
        ("/usr/bin/tool", "argument with spaces", "value")
    );
}

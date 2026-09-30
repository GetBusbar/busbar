// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The connector through a scripted host: every service pends once and completes on the host's
//! side, the op's re-entry re-issues each handle and reads the stored result, and no service ever
//! runs twice.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;

use super::*;

/// What the scripted host stored per handle `seq`, and how many times it ran each.
#[derive(Default)]
struct Script {
    stored: HashMap<u32, (Outcome, u64, u64)>,
    runs: HashMap<u32, u32>,
    reads: usize,
}

static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);
const CHUNKS: [&[u8]; 3] = [b"hello ", b"world", b""];

fn answer(out: *mut ServiceOut, o: Outcome, value: u64, len: u64) -> RawOutcome {
    // SAFETY: the SDK's `out`, live for the call.
    let out = unsafe { &mut *out };
    out.outcome = RawOutcome::of(o);
    out.value = value;
    out.len = len;
    RawOutcome::of(o)
}

/// One scripted service: the first issue of a handle runs it (and pends); a re-issue answers the
/// stored result.
fn serve(op: u32, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: every service `in` leads with a `ServiceHead`.
    let head = unsafe { *input.cast::<ServiceHead>() };
    assert_eq!(head.op, op);
    let seq = head.handle.seq;
    let mut g = SCRIPT.lock().unwrap();
    let s = g.as_mut().expect("a script");
    if let Some(&(o, v, l)) = s.stored.get(&seq) {
        return answer(out, o, v, l);
    }
    *s.runs.entry(seq).or_default() += 1;
    let (value, len) = match op {
        service::ESTABLISH => (7, 0),
        service::WRITE => {
            // SAFETY: an `IoIn`.
            let io = unsafe { *input.cast::<IoIn>() };
            (0, io.len as u64)
        }
        service::READ => {
            // SAFETY: an `IoIn`, its buffer the SDK's parked one.
            let io = unsafe { *input.cast::<IoIn>() };
            let chunk = CHUNKS[s.reads.min(2)];
            s.reads += 1;
            // SAFETY: `io.buf` holds `io.len` writable bytes until the read completes.
            unsafe { std::ptr::copy_nonoverlapping(chunk.as_ptr(), io.buf, chunk.len()) };
            (0, chunk.len() as u64)
        }
        _ => (0, 0),
    };
    s.stored.insert(seq, (Outcome::Ready, value, len));
    answer(out, Outcome::Pending, 0, 0)
}

extern "C" fn establish(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    serve(service::ESTABLISH, i, o)
}
extern "C" fn write(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    serve(service::WRITE, i, o)
}
extern "C" fn read(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    serve(service::READ, i, o)
}
extern "C" fn close(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    serve(service::CLOSE, i, o)
}

static SLOTS: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: crate::abi::host::conn::connector::SERVICES,
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
    random: None,
    identity: None,
};

fn host(conns: *const ConnectorSlots) -> Host {
    Host::of(&HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx {
            ptr: std::ptr::null_mut(),
        },
        wake: None,
        conns,
        services: std::ptr::null(),
    })
}

const TICKET: Ticket = Ticket {
    slot: 3,
    generation: 1,
};

#[test]
fn an_exchange_pends_until_complete_and_no_service_runs_twice() {
    *SCRIPT.lock().unwrap() = Some(Script::default());
    let h = host(&SLOTS);
    let mut state = Exchange::new(b"ping".to_vec());
    let mut entries = 0;
    let response = loop {
        entries += 1;
        assert!(entries < 20, "the exchange never completed");
        // One entry of the op: a fresh connector, the same parked state.
        let mut c = h.connector(TICKET);
        match exchange(&mut c, &mut state, 0, Some("far")) {
            Poll::Pending => continue,
            Poll::Ready(r) => break r.expect("the exchange completes"),
        }
    };
    assert_eq!(response, b"hello world");
    let g = SCRIPT.lock().unwrap();
    let s = g.as_ref().unwrap();
    // establish, write, three reads, close: six services, each run once.
    assert_eq!(s.runs.len(), 6);
    assert!(s.runs.values().all(|&n| n == 1), "{:?}", s.runs);
    // Every service pended once, so the op entered once more than it made services.
    assert_eq!(entries, 7);
}

#[test]
fn an_instance_handed_no_connector_is_unarmed_and_no_ticket_cannot_pend() {
    let unarmed = host(std::ptr::null());
    let mut c = unarmed.connector(TICKET);
    assert_eq!(c.establish(0, None), Poll::Ready(Err(ConnFailure::Unarmed)));
    let h = host(&SLOTS);
    let mut c = h.connector(Ticket::NONE);
    assert_eq!(
        c.establish(0, None),
        Poll::Ready(Err(ConnFailure::NoTicket))
    );
}

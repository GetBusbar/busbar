// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The connector's own rules: an instance handed no connector is Unarmed, a NONE ticket cannot
//! pend, and a connector resumed from a parked count issues its handles on from it. (The scripted
//! host that pends every service is `exchange_tests`.)

use std::ffi::c_void;
use std::sync::Mutex;

use super::*;

/// The handles `establish` was issued with.
static SEEN: Mutex<Vec<u32>> = Mutex::new(Vec::new());
/// One SEEN-reading test at a time.
static SERIAL: Mutex<()> = Mutex::new(());

/// The `within` set each `establish` handed the host.
static WITHIN: Mutex<Vec<String>> = Mutex::new(Vec::new());

extern "C" fn establish(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    // SAFETY: an `EstablishIn`, leading with its `ServiceHead`.
    let input = unsafe { *i.cast::<EstablishIn>() };
    SEEN.lock().unwrap().push(input.head.handle.seq);
    // SAFETY: the SDK's text, live for the call.
    let within = unsafe { std::slice::from_raw_parts(input.within.ptr, input.within.len) };
    WITHIN
        .lock()
        .unwrap()
        .push(String::from_utf8_lossy(within).into_owned());
    // SAFETY: the SDK's `out`, live for the call.
    unsafe { (*o).value = 7 };
    RawOutcome::of(Outcome::Ready)
}

static SLOTS: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: crate::abi::host::conn::connector::SERVICES,
    establish: Some(establish),
    reject_endpoint: None,
    side_stream: None,
    read: None,
    write: None,
    upgrade_secure: None,
    facts: None,
    checkout: None,
    checkin: None,
    close: None,
    random: None,
    identity: None,
    read_reply: None,
    write_request: None,
};

/// The host clock the tests set.
static MONO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `clock.now`: the tests' monotonic reading.
extern "C" fn clock_now(_: HostCtx, i: *const c_void, _: *mut ServiceOut) -> RawOutcome {
    use crate::abi::host::service::ClockNowIn;
    // SAFETY: a `ClockNowIn`; its reading the SDK's, live for the call.
    unsafe {
        let input = *i.cast::<ClockNowIn>();
        (*input.reading).mono_ns = MONO.load(std::sync::atomic::Ordering::SeqCst);
    }
    RawOutcome::of(Outcome::Ready)
}

/// The host's admission text for need 1 (a trust anchor that does not parse).
const NOT_ADMITTED: &str = "need 1: its trust anchors do not parse";

/// `need.admit`: need 0 admitted, need 1 refused with the host's text; always on no ticket.
extern "C" fn need_admit(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    use crate::abi::host::service::NeedAdmitIn;
    // SAFETY: a `NeedAdmitIn`; the SDK's `out`, live for the call.
    let (input, out) = unsafe { (*i.cast::<NeedAdmitIn>(), &mut *o) };
    assert!(
        input.head.handle.ticket.is_none(),
        "a never-pending service rides no ticket"
    );
    let verdict = if input.need == 1 {
        out.error = AbiStr {
            ptr: NOT_ADMITTED.as_ptr(),
            len: NOT_ADMITTED.len(),
        };
        Outcome::Refused
    } else {
        Outcome::Ready
    };
    out.outcome = RawOutcome::of(verdict);
    RawOutcome::of(verdict)
}

fn services() -> &'static crate::abi::host::service::HostSlots {
    use crate::abi::host::service::HostSlots;
    static SERVICES: std::sync::OnceLock<HostSlots> = std::sync::OnceLock::new();
    SERVICES.get_or_init(|| {
        // SAFETY: every slot is an `Option<fn>` and the head two integers: all-zero is a table
        // offering nothing.
        let mut t: HostSlots = unsafe { std::mem::zeroed() };
        t.size = std::mem::size_of::<HostSlots>() as u32;
        t.slots = crate::abi::host::service::SERVICES;
        t.clock_now = Some(clock_now);
        t.need_admit = Some(need_admit);
        t
    })
}

fn host(conns: *const ConnectorSlots) -> Host {
    Host::of(&HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx {
            ptr: std::ptr::null_mut(),
        },
        wake: None,
        conns,
        services: services(),
    })
}

const TICKET: Ticket = Ticket {
    slot: 3,
    generation: 1,
};

#[test]
fn an_instance_handed_no_connector_is_unarmed_and_no_ticket_cannot_pend() {
    let unarmed = host(std::ptr::null());
    let mut c = unarmed.connector(TICKET);
    assert_eq!(c.establish(0, None, ""), Poll::Ready(Err(ConnFailure::Unarmed)));
    let h = host(&SLOTS);
    let mut c = h.connector(Ticket::NONE);
    assert_eq!(
        c.establish(0, None, ""),
        Poll::Ready(Err(ConnFailure::NoTicket))
    );
    let mut c = h.connector(TICKET);
    assert_eq!(
        c.write(7, b"x"),
        Poll::Ready(Err(ConnFailure::Unarmed)),
        "a service the host does not offer"
    );
}

#[test]
fn a_connector_resumed_from_a_parked_count_issues_on_from_it() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    SEEN.lock().unwrap().clear();
    let h = host(&SLOTS);
    let mut c = h.connector(TICKET);
    assert_eq!(c.establish(0, None, ""), Poll::Ready(Ok(7)));
    assert_eq!(c.establish(0, None, ""), Poll::Ready(Ok(7)));
    let parked = c.issued();
    assert_eq!(parked, 2);
    let mut resumed = h.connector_from(TICKET, parked);
    assert_eq!(resumed.establish(0, None, ""), Poll::Ready(Ok(7)));
    assert_eq!(*SEEN.lock().unwrap(), vec![0, 1, 2]);
    assert_eq!(h.connector(TICKET).within(5).budget_ms(), Some(5));
}

/// RED: a backoff pends until the host's clock reaches its instant — asking for no resume before
/// it (the op's wake_at_ns), and a resume that comes sooner pends again with the same instant. (That
/// the host's timer never resumes before wake_at_ns is the dispatcher's own RED: dispatch_tests'
/// `pend timer -> ... early=0`.)
#[test]
fn a_backoff_pends_until_the_host_clock_reaches_it() {
    use crate::abi::mechanism::lifecycle::CancelOut;
    use crate::abi::sdk::out::Out;
    use std::sync::atomic::Ordering;
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let h = host(&SLOTS);
    let until = 5_000_000_000;
    for early in [1_000, until - 1] {
        MONO.store(early, Ordering::SeqCst);
        // SAFETY: plain data; all-zero is valid.
        let mut o: CancelOut = unsafe { std::mem::zeroed() };
        let mut out = Out::new(&mut o);
        let mut c = h.connector(TICKET);
        assert_eq!(
            not_before(&mut c, &mut out, until),
            Poll::Pending,
            "at {early}"
        );
        assert_eq!(
            o.head.wake_at_ns, until,
            "resume no earlier than the instant"
        );
        assert_eq!(
            c.issued(),
            0,
            "the clock is read on no ticket: no handle drawn, so a replay never reads a stored time"
        );
    }
    MONO.store(until, Ordering::SeqCst);
    // SAFETY: as above.
    let mut o: CancelOut = unsafe { std::mem::zeroed() };
    let mut c = h.connector(TICKET);
    assert_eq!(
        not_before(&mut c, &mut Out::new(&mut o), until),
        Poll::Ready(Ok(()))
    );
    assert_eq!(o.head.wake_at_ns, 0, "a ready answer asks for no timer");
}

/// `open` learns the host's verdict on its needs: admitted, or refused with the host's text
/// verbatim (so the plugin answers its own 1.5.5 words); on no ticket, drawing no handle.
#[test]
fn open_learns_the_hosts_verdict_on_a_need() {
    let h = host(&SLOTS);
    let mut c = h.connector(TICKET);
    assert_eq!(c.admit(0), Ok(()));
    assert_eq!(
        c.admit(1),
        Err(ConnFailure::Refused(NOT_ADMITTED.to_string()))
    );
    assert_eq!(c.issued(), 0, "no handle drawn");
    // An instance handed no services table cannot ask.
    let bare = Host::of(&HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx {
            ptr: std::ptr::null_mut(),
        },
        wake: None,
        conns: &SLOTS,
        services: std::ptr::null(),
    });
    assert_eq!(bare.connector(TICKET).admit(0), Err(ConnFailure::Unarmed));
}

/// THE LANDING SET (ARCHITECT DEST-PIN 2026-10-01): `establish` hands the host the address set its
/// dial must land on, verbatim, and `""` for none.
#[test]
fn establish_hands_the_host_the_set_its_dial_lands_within() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    WITHIN.lock().unwrap().clear();
    let h = host(&SLOTS);
    let mut c = h.connector(TICKET);
    assert_eq!(
        c.establish(0, None, "203.0.113.5,2001:db8::1"),
        Poll::Ready(Ok(7))
    );
    assert_eq!(c.establish(0, None, ""), Poll::Ready(Ok(7)));
    assert_eq!(
        *WITHIN.lock().unwrap(),
        vec!["203.0.113.5,2001:db8::1".to_owned(), String::new()]
    );
}

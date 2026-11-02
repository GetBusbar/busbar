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
    let within = if input.within.ptr.is_null() {
        "<absent>".to_owned()
    } else {
        // SAFETY: the SDK's text, live for the call.
        let b = unsafe { std::slice::from_raw_parts(input.within.ptr, input.within.len) };
        String::from_utf8_lossy(b).into_owned()
    };
    WITHIN.lock().unwrap().push(within);
    // SAFETY: the SDK's `out`, live for the call.
    unsafe { (*o).value = 7 };
    RawOutcome::of(Outcome::Ready)
}

/// The streams `close` was handed, with whether the call rode a ticket.
static CLOSED: Mutex<Vec<(u64, bool)>> = Mutex::new(Vec::new());

extern "C" fn close(_: HostCtx, i: *const c_void, _: *mut ServiceOut) -> RawOutcome {
    // SAFETY: a `StreamIn`, leading with its `ServiceHead`.
    let input = unsafe { *i.cast::<crate::abi::host::conn::connector::StreamIn>() };
    CLOSED
        .lock()
        .unwrap()
        .push((input.stream, !input.head.handle.ticket.is_none()));
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
    close: Some(close),
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
    /* SAFETY: these harness tables and callbacks are live for the snapshot. */
    unsafe {
        Host::from_raw(&HostTables {
            size: std::mem::size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: HostCtx::NONE,
            wake: None,
            conns,
            services: services(),
            io: std::ptr::null(),
        })
    }
}

const TICKET: Ticket = Ticket {
    slot: 3,
    generation: 1,
};

#[test]
fn an_instance_handed_no_connector_is_unarmed_and_no_ticket_cannot_pend() {
    let unarmed = host(std::ptr::null());
    let mut c = unarmed.connector(TICKET);
    assert_eq!(
        c.establish(0, None, ""),
        Poll::Ready(Err(ConnFailure::Unarmed))
    );
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
    let bare = /* SAFETY: these harness tables and callbacks are live for the snapshot. */ unsafe { Host::from_raw(&HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: &SLOTS,
        services: std::ptr::null(),
        io: std::ptr::null(),
    }) };
    assert_eq!(bare.connector(TICKET).admit(0), Err(ConnFailure::Unarmed));
}

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

/// `close` never pends, so it is made on no ticket (an instance closing its kept connections as it
/// goes); every other service still refuses NONE.
#[test]
fn close_is_made_on_no_ticket() {
    let h = host(&SLOTS);
    let mut c = h.connector(Ticket::NONE);
    assert_eq!(c.close(9), Poll::Ready(Ok(())));
    assert!(CLOSED.lock().unwrap().contains(&(9, false)));
    assert_eq!(
        c.establish(0, None, ""),
        Poll::Ready(Err(ConnFailure::NoTicket))
    );
}

/// The cause `read_reply` names: `value` of the refused ack the scripted host answers.
static REFUSED_CAUSE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The host's text on that refusal.
const REFUSED_TEXT: &str = "the connection was refused";

/// `read_reply`: the refused ack, naming [`REFUSED_CAUSE`] with [`REFUSED_TEXT`].
extern "C" fn refused_reply(_: HostCtx, _: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK's `out`, live for the call.
    let out = unsafe { &mut *o };
    out.value = REFUSED_CAUSE.load(std::sync::atomic::Ordering::SeqCst);
    out.error = AbiStr {
        ptr: REFUSED_TEXT.as_ptr(),
        len: REFUSED_TEXT.len(),
    };
    out.outcome = RawOutcome::of(Outcome::Refused);
    RawOutcome::of(Outcome::Refused)
}

static REFUSING: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: crate::abi::host::conn::connector::SERVICES,
    establish: None,
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
    read_reply: Some(refused_reply),
    write_request: None,
};

/// A refusal naming `CAUSE_CREDENTIAL_UNAVAILABLE` reads as [`ConnFailure::CredentialUnavailable`]:
/// the plugin tells a vanished credential from any other refusal. RED arm: the same refusal naming
/// no cause is the host's plain refusal, with its text.
#[test]
fn a_refusal_naming_an_unavailable_credential_reads_as_its_own_failure() {
    use crate::abi::host::conn::connector::{CAUSE_CREDENTIAL_UNAVAILABLE, CAUSE_NONE};
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let h = host(&REFUSING);
    let mut buf = [0_u8; 8];
    let mut slot = ReplyPiece::default();
    REFUSED_CAUSE.store(
        CAUSE_CREDENTIAL_UNAVAILABLE,
        std::sync::atomic::Ordering::SeqCst,
    );
    let mut c = h.connector(TICKET);
    assert_eq!(
        c.read_reply(1, &mut buf, &mut slot),
        Poll::Ready(Err(ConnFailure::CredentialUnavailable))
    );
    assert_eq!(c.cause(), CAUSE_CREDENTIAL_UNAVAILABLE);
    REFUSED_CAUSE.store(CAUSE_NONE, std::sync::atomic::Ordering::SeqCst);
    let mut c = h.connector(TICKET);
    assert_eq!(
        c.read_reply(1, &mut buf, &mut slot),
        Poll::Ready(Err(ConnFailure::Refused(REFUSED_TEXT.to_string())))
    );
}

static REQUEST_SECURITY: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static SEALED_REQUESTS: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

extern "C" fn request_security(_: HostCtx, input: *const c_void, _: *mut ServiceOut) -> RawOutcome {
    use crate::abi::host::conn::connector::{FactsIn, StreamFacts};
    let security = REQUEST_SECURITY.load(std::sync::atomic::Ordering::SeqCst);
    if security == 2 {
        return RawOutcome::of(Outcome::Pending);
    }
    // SAFETY: the connector lends FactsIn and its writable facts slot for this call.
    unsafe {
        let input = &*input.cast::<FactsIn>();
        (*input.facts).size = std::mem::size_of::<StreamFacts>() as u32;
        (*input.facts).secure = security;
    }
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn sealed_request(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    use crate::abi::host::conn::connector::RequestIn;
    // SAFETY: the connector lends RequestIn, its bytes, and the writable reply for this call.
    unsafe {
        let input = &*input.cast::<RequestIn>();
        SEALED_REQUESTS
            .lock()
            .unwrap()
            .push(std::slice::from_raw_parts(input.buf, input.len).to_vec());
        (*out).len = input.len as u64;
    }
    RawOutcome::of(Outcome::Ready)
}

#[test]
fn a_sealed_framed_body_checks_security_before_sending_any_credential_bytes() {
    use crate::abi::host::conn::connector::REQUEST_BODY;
    use crate::abi::sdk::cred::{Cred, SealedWrite, NOT_SECURE};
    use std::sync::atomic::Ordering;

    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    SEALED_REQUESTS.lock().unwrap().clear();
    let slots = ConnectorSlots {
        facts: Some(request_security),
        write_request: Some(sealed_request),
        ..SLOTS
    };
    let h = host(&slots);
    let body = RequestPiece {
        kind: REQUEST_BODY,
        ..RequestPiece::ZERO
    };
    let required = Cred::captured(zeroize::Zeroizing::new(b"CANARY-request-body".to_vec()))
        .secure_for("https://token.example/");
    let refused = Poll::Ready(Err(ConnFailure::Refused(NOT_SECURE.into())));

    REQUEST_SECURITY.store(0, Ordering::SeqCst);
    let mut clear = SealedWrite::message(required.field());
    assert_eq!(clear.request(&mut h.connector(TICKET), 7, &body), refused);
    assert!(SEALED_REQUESTS.lock().unwrap().is_empty());
    REQUEST_SECURITY.store(1, Ordering::SeqCst);
    assert_eq!(
        clear.request(&mut h.connector(TICKET), 7, &body),
        refused,
        "a refused write stays refused after re-entry"
    );
    assert!(SEALED_REQUESTS.lock().unwrap().is_empty());

    let mut waiting = SealedWrite::message(required.field());
    REQUEST_SECURITY.store(2, Ordering::SeqCst);
    assert_eq!(
        waiting.request(&mut h.connector(TICKET), 7, &body),
        Poll::Pending
    );
    assert!(SEALED_REQUESTS.lock().unwrap().is_empty());
    REQUEST_SECURITY.store(1, Ordering::SeqCst);
    assert_eq!(
        waiting.request(&mut h.connector(TICKET), 7, &body),
        Poll::Ready(Ok(required.len()))
    );
    assert_eq!(
        *SEALED_REQUESTS.lock().unwrap(),
        vec![b"CANARY-request-body".to_vec()]
    );

    SEALED_REQUESTS.lock().unwrap().clear();
    let no_facts = ConnectorSlots {
        facts: None,
        ..slots
    };
    let missing = host(&no_facts);
    let mut required_write = SealedWrite::message(required.field());
    assert_eq!(
        required_write.request(&mut missing.connector(TICKET), 7, &body),
        refused
    );
    assert!(SEALED_REQUESTS.lock().unwrap().is_empty());
    let free = Cred::captured(zeroize::Zeroizing::new(b"allowed-in-clear".to_vec()));
    assert_eq!(
        SealedWrite::message(free.field()).request(&mut missing.connector(TICKET), 7, &body),
        Poll::Ready(Ok(free.len()))
    );
    assert_eq!(
        *SEALED_REQUESTS.lock().unwrap(),
        vec![b"allowed-in-clear".to_vec()]
    );
}

#[test]
fn snapshots_read_only_complete_advertised_function_fields() {
    #[repr(C)]
    struct Prefix {
        size: u32,
        slots: u32,
        first: Option<ServiceFn>,
    }
    let mut prefix = Prefix {
        size: std::mem::size_of::<Prefix>() as u32,
        slots: u32::MAX,
        first: Some(establish),
    };
    // SAFETY: only this complete prefix is advertised; its function obeys the service ABI.
    let conn = unsafe { snapshot_connector(std::ptr::from_ref(&prefix).cast()) }.unwrap();
    assert!(conn.establish.is_some());
    assert!(conn.reject_endpoint.is_none());
    assert_eq!(conn.slots, crate::abi::host::conn::connector::SERVICES);
    // SAFETY: the same function representation occupies the first slot of all three tables.
    let services = unsafe { snapshot_services(std::ptr::from_ref(&prefix).cast()) }.unwrap();
    assert!(services.clock_now.is_some());
    assert!(services.records_get.is_none());
    // SAFETY: as above; these snapshots are inspected, never called as a different service.
    let io = unsafe { snapshot_io(std::ptr::from_ref(&prefix).cast()) }.unwrap();
    assert!(io.open.is_some());
    assert!(io.listen.is_none());

    prefix.size -= 1;
    // SAFETY: the advertised prefix is still readable, but its final slot is incomplete.
    let partial = unsafe { snapshot_connector(std::ptr::from_ref(&prefix).cast()) }.unwrap();
    assert!(partial.establish.is_none());
    prefix.size = std::mem::size_of::<Prefix>() as u32;
    prefix.slots = 0;
    // SAFETY: a complete allocation with an advertised zero slot count.
    let absent = unsafe { snapshot_connector(std::ptr::from_ref(&prefix).cast()) }.unwrap();
    assert!(absent.establish.is_none());

    // A header-only allocation has no function-pointer storage to read.
    let head = [8u32, u32::MAX];
    // SAFETY: exactly the two advertised u32 words are allocated and readable.
    let empty = unsafe { snapshot_services(head.as_ptr().cast()) }.unwrap();
    assert!(empty.clock_now.is_none());
    let too_short = 4u32;
    // SAFETY: just the advertised size word is allocated; no slots word is read.
    assert!(unsafe { snapshot_io(std::ptr::from_ref(&too_short).cast()) }.is_none());
}

#[test]
fn a_safe_wake_only_host_preserves_the_opaque_context_and_absent_tables() {
    static WOKEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    extern "C" fn wake(ctx: HostCtx, _: Ticket) {
        WOKEN.store(ctx.handle, std::sync::atomic::Ordering::SeqCst);
    }
    let empty = Host::NONE;
    assert!(!empty.lends_connector());
    assert!(empty.services().is_none());
    assert!(!empty.io(TICKET).armed());
    empty.wake(TICKET);
    assert_eq!(WOKEN.load(std::sync::atomic::Ordering::SeqCst), 0);
    let host = Host::wake_only(HostCtx { handle: 73 }, wake);
    assert!(!host.lends_connector());
    assert!(host.services().is_none());
    assert!(!host.io(TICKET).armed());
    host.wake(TICKET);
    assert_eq!(WOKEN.load(std::sync::atomic::Ordering::SeqCst), 73);
}

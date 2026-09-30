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

extern "C" fn establish(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    // SAFETY: an `EstablishIn`, leading with its `ServiceHead`.
    let head = unsafe { *i.cast::<ServiceHead>() };
    SEEN.lock().unwrap().push(head.handle.seq);
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
    let mut c = h.connector(TICKET);
    assert_eq!(
        c.write(7, b"x"),
        Poll::Ready(Err(ConnFailure::Unarmed)),
        "a service the host does not offer"
    );
}

#[test]
fn a_connector_resumed_from_a_parked_count_issues_on_from_it() {
    SEEN.lock().unwrap().clear();
    let h = host(&SLOTS);
    let mut c = h.connector(TICKET);
    assert_eq!(c.establish(0, None), Poll::Ready(Ok(7)));
    assert_eq!(c.establish(0, None), Poll::Ready(Ok(7)));
    let parked = c.issued();
    assert_eq!(parked, 2);
    let mut resumed = h.connector_from(TICKET, parked);
    assert_eq!(resumed.establish(0, None), Poll::Ready(Ok(7)));
    assert_eq!(*SEEN.lock().unwrap(), vec![0, 1, 2]);
    assert_eq!(h.connector(TICKET).within(5).budget_ms(), Some(5));
}

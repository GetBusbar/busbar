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

/// The host services: only `disk.append`, which records its handle and lands every byte.
extern "C" fn disk_append(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    use crate::abi::host::service::{DiskAppendIn, DiskWritten, DISK_ROTATED};
    // SAFETY: a `DiskAppendIn`.
    let input = unsafe { *i.cast::<DiskAppendIn>() };
    SEEN.lock().unwrap().push(input.head.handle.seq);
    // SAFETY: the SDK's parked result, live until the append completes.
    unsafe {
        input.result.write(DiskWritten {
            size: std::mem::size_of::<DiskWritten>() as u32,
            rotated: DISK_ROTATED,
            _reserved: [0; 3],
            written: input.bytes.len as u64,
        });
    }
    RawOutcome::of(Outcome::Ready)
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
        t.disk_append = Some(disk_append);
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
    let _g = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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

/// One op making a connector service and a host service: both draw on ONE handle count, so a
/// replay never confuses them; `disk.append` answers what the host wrote.
#[test]
fn connector_and_host_services_share_one_handle_count() {
    let _g = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    use crate::abi::host::service::{DiskWritten, DISK_ROTATED};
    SEEN.lock().unwrap().clear();
    let h = host(&SLOTS);
    let mut c = h.connector(TICKET);
    assert_eq!(c.establish(0, None), Poll::Ready(Ok(7)));
    let bytes = b"{\"line\":1}\n".to_vec();
    // SAFETY: plain integers; all-zero is valid.
    let mut result: DiskWritten = unsafe { std::mem::zeroed() };
    let Poll::Ready(Ok(w)) = c.disk_append("requests", &bytes, &mut result) else {
        panic!("the append lands");
    };
    assert_eq!((w.written, w.rotated), (bytes.len() as u64, DISK_ROTATED));
    assert_eq!(*SEEN.lock().unwrap(), vec![0, 1]);
}

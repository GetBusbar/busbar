// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin side's host-service wrappers (`services.rs`), over a hand-built table.

use super::*;
use crate::abi::host::service::{ServiceFn, NOT_ENTITLED, SERVICES};
use crate::abi::mechanism::ticket::Ticket;

/// A host that entitles exactly `item:one`.
extern "C" fn entitles_one(
    _ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: the wrapper hands an `EntitlementCheckIn` and a live `out`.
    unsafe {
        let i = input.cast::<EntitlementCheckIn>().read_unaligned();
        let target = std::slice::from_raw_parts(i.target.ptr, i.target.len);
        (*out).value = if target == b"item:one" {
            ENTITLED
        } else {
            NOT_ENTITLED
        };
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

/// A host that answers FAILED.
extern "C" fn fails(_ctx: HostCtx, _input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: a live `out`.
    unsafe { (*out).outcome = RawOutcome::of(Outcome::Failed) };
    RawOutcome::of(Outcome::Failed)
}

/// A host that answers a verdict the service does not have.
extern "C" fn breaks(_ctx: HostCtx, _input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: a live `out`.
    unsafe {
        (*out).value = 7;
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

fn table(slot: Option<ServiceFn>) -> HostSlots {
    HostSlots {
        size: size_of::<HostSlots>() as u32,
        slots: SERVICES,
        clock_now: None,
        records_get: None,
        records_list: None,
        records_claim: None,
        dest_judge: None,
        sign: None,
        unit_nest: None,
        work_open: None,
        work_find: None,
        work_settle: None,
        work_resume: None,
        trust_sight: None,
        trust_due: None,
        verify_lookup: None,
        verify_store: None,
        entitlement_check: slot,
        content_scan: None,
        hook_call: None,
    }
}

fn services(t: &HostSlots) -> Services {
    let tables = HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx {
            ptr: std::ptr::null_mut(),
        },
        wake: None,
        conns: std::ptr::null(),
        services: t,
    };
    Services::of(&tables).expect("a table was handed")
}

fn handle() -> CompletionHandle {
    CompletionHandle {
        ticket: Ticket::NONE,
        seq: 0,
        _reserved: 0,
    }
}

#[test]
fn entitled_answers_the_hosts_verdict_and_every_failure_is_an_error() {
    let t = table(Some(entitles_one));
    let s = services(&t);
    assert_eq!(s.entitled(handle(), "item:one"), Ok(true));
    assert_eq!(s.entitled(handle(), "item:two"), Ok(false));
    let none = table(None);
    assert_eq!(
        services(&none).entitled(handle(), "item:one"),
        Err(ServiceError::Unserved)
    );
    let failing = table(Some(fails));
    let refused = services(&failing).entitled(handle(), "item:one");
    assert_eq!(refused, Err(ServiceError::Declined(Outcome::Failed)));
    let broken = table(Some(breaks));
    assert_eq!(
        services(&broken).entitled(handle(), "item:one"),
        Err(ServiceError::Broken)
    );
}

#[test]
fn no_table_is_no_services() {
    let tables = HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx {
            ptr: std::ptr::null_mut(),
        },
        wake: None,
        conns: std::ptr::null(),
        services: std::ptr::null(),
    };
    assert!(Services::of(&tables).is_none());
}

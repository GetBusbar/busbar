// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Old-public-API witness: write_all's owned output must be wiped at actual deallocation.
//! The fake host registers only its first WRITE loan, whose bytes start at the output allocation
//! base. Subsequent partial loans may be interior slices and are never registered.

use std::ffi::c_void;
use std::sync::{Mutex, OnceLock, PoisonError};

use super::drive;
use crate::abi::host::conn::connector::{ConnectorSlots, IoIn};
use crate::abi::host::service::ServiceOut;
use crate::abi::mechanism::call::{Outcome, RawOutcome};
use crate::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use crate::abi::sdk::conn::{ConnFailure, Host};
use crate::abi::sdk::store::op::Parked;
use crate::abi::sdk::store::{Op, Step};
use crate::alloc_counter::{
    watch_initialized_payload, InitializedPayloadProbe, PayloadObservations,
};

const PAYLOAD: &[u8] = b"write-all-initialized-CREDENTIAL-canary";
const TICKET: Ticket = Ticket {
    slot: 9,
    generation: 4,
};

#[derive(Clone, Copy)]
enum End {
    Cancel,
    Success,
    Error,
}

struct Script {
    end: End,
    calls: usize,
    accepted: usize,
    loans_match: bool,
    closed: usize,
}

static SERIAL: Mutex<()> = Mutex::new(());
static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);

fn script<R>(f: impl FnOnce(&mut Script) -> R) -> R {
    f(SCRIPT.lock().unwrap().as_mut().unwrap())
}

extern "C" fn establish(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the connector lends this writable output for the current service call.
    unsafe { (*out).value = 17 };
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn write(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the connector lends an IoIn and its initialized byte slice for this call only.
    let bytes = unsafe {
        let input = &*input.cast::<IoIn>();
        std::slice::from_raw_parts(input.buf, input.len)
    };
    script(|s| {
        if s.calls == 0 {
            // SAFETY: write_all's first loan starts at its owned allocation base. The op retains
            // exclusive ownership on this thread until completion/cancellation below. Registration
            // retains address/length metadata only; the observer reads at deallocation before free.
            unsafe { watch_initialized_payload(bytes) };
        }
        s.calls += 1;
        s.loans_match &= bytes == &PAYLOAD[s.accepted..];
        match s.end {
            End::Cancel => RawOutcome::of(Outcome::Pending),
            End::Success | End::Error if s.calls == 1 => {
                s.accepted += 3;
                // SAFETY: the connector lends a writable ServiceOut for this call.
                unsafe { (*out).len = 3 };
                RawOutcome::of(Outcome::Ready)
            }
            End::Success => {
                s.accepted += bytes.len();
                // SAFETY: the connector lends a writable ServiceOut for this call.
                unsafe { (*out).len = bytes.len() as u64 };
                RawOutcome::of(Outcome::Ready)
            }
            End::Error => RawOutcome::of(Outcome::Failed),
        }
    })
}

extern "C" fn close(_: HostCtx, _: *const c_void, _: *mut ServiceOut) -> RawOutcome {
    script(|s| s.closed += 1);
    RawOutcome::of(Outcome::Ready)
}

fn host(end: End) -> Host {
    static CONNS: OnceLock<ConnectorSlots> = OnceLock::new();
    let conns = CONNS.get_or_init(|| {
        // SAFETY: the table contains integers and optional function pointers only.
        let mut slots: ConnectorSlots = unsafe { std::mem::zeroed() };
        slots.size = std::mem::size_of::<ConnectorSlots>() as u32;
        slots.slots = crate::abi::host::conn::connector::SERVICES;
        slots.establish = Some(establish);
        slots.write = Some(write);
        slots.close = Some(close);
        slots
    });
    *SCRIPT.lock().unwrap() = Some(Script {
        end,
        calls: 0,
        accepted: 0,
        loans_match: true,
        closed: 0,
    });
    Host::of(&HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns,
        services: std::ptr::null(),
        io: std::ptr::null(),
    })
}

fn run(host: &Host) -> (Step<Result<(), ConnFailure>>, Parked) {
    let mut op = Op::enter(TICKET, Some(host), None, None);
    let step = drive(&mut op, |wire| {
        Box::pin(async move {
            wire.connect(0, None).await?;
            wire.write_all(PAYLOAD).await
        })
    });
    (step, op.into_parked())
}

fn complete_observation(probe: InitializedPayloadProbe, count: usize) -> PayloadObservations {
    let observations = probe.finish();
    assert!(
        !observations.reentered,
        "memory reader reentered the allocator"
    );
    assert_eq!(
        observations.payloads.len(),
        count,
        "registered owners were observed"
    );
    for payload in &observations.payloads {
        assert_eq!(payload.len, PAYLOAD.len());
        assert!(payload.freed, "the registered owner was actually destroyed");
        assert!(
            !payload.reallocated,
            "this scenario performs no output growth"
        );
        #[cfg(target_os = "linux")]
        {
            assert_eq!(payload.read_error, None, "OS memory reader failed");
            assert!(
                payload.complete_read,
                "OS memory reader returned a partial span"
            );
            assert_eq!(payload.bytes_read, PAYLOAD.len());
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(payload.read_error, Some(std::io::ErrorKind::Unsupported));
            assert!(!payload.complete_read);
        }
    }
    observations
}

fn calibrate_observer() {
    use zeroize::Zeroize;
    // SAFETY: both registered initialized Vec prefixes stay exclusively owned and are freed on
    // this thread within this scope. No legacy marker/scanner API is called or armed.
    let probe =
        unsafe { InitializedPayloadProbe::start().expect("open initialized-payload observer") };
    let plain = PAYLOAD.to_vec();
    let mut wiped = PAYLOAD.to_vec();
    // SAFETY: these are owned allocation bases and remain initialized through deallocation below.
    unsafe {
        watch_initialized_payload(&plain);
        watch_initialized_payload(&wiped);
    }
    wiped.as_mut_slice().zeroize();
    drop(plain);
    drop(wiped);
    let observations = complete_observation(probe, 2);
    #[cfg(target_os = "linux")]
    {
        assert!(
            !observations.payloads[0].wiped,
            "observer must detect unwiped control"
        );
        assert!(
            observations.payloads[1].wiped,
            "observer must accept wiped control"
        );
    }
    #[cfg(not(target_os = "linux"))]
    let _ = observations;
}

fn assert_wire_output_wiped(probe: InitializedPayloadProbe) {
    let observations = complete_observation(probe, 1);
    #[cfg(target_os = "linux")]
    assert!(
        observations.payloads[0].wiped,
        "write_all output reached deallocation unwiped"
    );
    #[cfg(not(target_os = "linux"))]
    let _ = observations;
}

#[test]
fn cancelled_write_all_wipes_the_output_loan_it_parked() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    calibrate_observer();
    let host = host(End::Cancel);
    // SAFETY: the registered write_all output remains owned by this thread until Parked drops.
    let probe =
        unsafe { InitializedPayloadProbe::start().expect("open initialized-payload observer") };
    let (step, parked) = run(&host);
    assert!(matches!(step, Step::Pending { .. }));
    assert_eq!(script(|s| s.calls), 1);
    assert!(script(|s| s.loans_match));
    assert_eq!(script(|s| s.accepted), 0);
    drop(parked);
    assert_eq!(script(|s| s.closed), 1);
    assert_wire_output_wiped(probe);
}

#[test]
fn partial_write_all_wipes_its_whole_initialized_output_on_success_or_error() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    calibrate_observer();
    for end in [End::Success, End::Error] {
        let host = host(end);
        // SAFETY: the first WRITE loan's owned allocation is destroyed on this thread below.
        let probe =
            unsafe { InitializedPayloadProbe::start().expect("open initialized-payload observer") };
        let (step, parked) = run(&host);
        match end {
            End::Success => assert_eq!(step, Step::Ready(Ok(()))),
            End::Error => assert!(matches!(step, Step::Ready(Err(ConnFailure::Failed(_))))),
            End::Cancel => unreachable!(),
        }
        assert_eq!(script(|s| s.calls), 2);
        assert!(
            script(|s| s.loans_match),
            "partial writes lent exactly the remaining bytes"
        );
        assert_eq!(
            script(|s| s.accepted),
            if matches!(end, End::Success) {
                PAYLOAD.len()
            } else {
                3
            }
        );
        drop(parked);
        assert_eq!(script(|s| s.closed), 1);
        assert_wire_output_wiped(probe);
    }
}

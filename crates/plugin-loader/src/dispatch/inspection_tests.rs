// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::dispatch::{
    in_head, out_head, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, Kind, LinkedRow, NoSink,
    Plugin, NO_BLOB,
};
use busbar_contract::abi::mechanism::{
    call::{DeadlineClass, RawOutcome, FLAG_RESUME},
    door::Door,
    inspection::{InspectionError, InspectionQuery, InspectionRequest},
    lifecycle::{OpenIn, OpenOut, OpsHead, TickIn, TickOut},
    KindCode,
};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct State {
    leases: Mutex<std::collections::HashMap<u64, Vec<u8>>>,
    released: std::sync::atomic::AtomicUsize,
    observed: Mutex<Vec<(u32, bool, InspectionReceipt)>>,
    shorted: std::sync::atomic::AtomicBool,
    snapshot: Option<Box<busbar_contract::abi::plane::PlaneSnapshot>>,
    tick_entered: std::sync::atomic::AtomicBool,
    tick_continue: std::sync::atomic::AtomicBool,
}
struct InspectionKind;
impl Kind for InspectionKind {
    const CODE: KindCode = KindCode::Export;
    type Ops = OpsHead;
    const TIMEOUT: Outcome = Outcome::Failed;
    fn short(answer: &crate::dispatch::Answer) -> bool {
        answer.slot == slot::TICK && answer.out::<TickOut>().is_ok_and(|o| o.next_tick_ns == 9)
    }
}

crate::dispatch_tests::c_abi! {
    fn opened(_: *mut std::ffi::c_void, _: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        // SAFETY: the loader supplies this operation's actual OpenOut.
        let out = unsafe { &mut *out.cast::<OpenOut>() };
        out.instance = Box::into_raw(Box::<State>::default()).cast();
        out.head.outcome = RawOutcome::of(Outcome::Ready);
        RawOutcome::of(Outcome::Ready)
    }
    fn closed(instance: *mut std::ffi::c_void, _: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        // SAFETY: open allocated this box, and close is called once.
        unsafe { drop(Box::from_raw(instance.cast::<State>())); (*out.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Ready); }
        RawOutcome::of(Outcome::Ready)
    }
    fn cancelled(_: *mut std::ffi::c_void, _: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        // SAFETY: every cancel output starts with OutHead.
        unsafe { (*out.cast::<OutHead>()).outcome = RawOutcome::of(Outcome::Ready); }
        RawOutcome::of(Outcome::Ready)
    }
    fn released(instance: *mut std::ffi::c_void, input: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        // SAFETY: release's instance and frame are the host's validated fixture values.
        let (state, lease) = unsafe { (&*instance.cast::<State>(), (*input.cast::<busbar_contract::abi::mechanism::lifecycle::ReleaseIn>()).lease) };
        let outcome = match state.leases.lock().unwrap().remove(&lease) {
            Some(mut bytes) => {
                bytes.fill(0xA5);
                state.released.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Outcome::Ready
            }
            None => Outcome::Refused,
        };
        unsafe { (*out.cast::<OutHead>()).outcome = RawOutcome::of(outcome); }
        RawOutcome::of(outcome)
    }
    fn crossed(instance: *mut std::ffi::c_void, input: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        // SAFETY: all fixture slots use the mechanism head and open allocated this state.
        let (state, input, out_head) = unsafe { (&*instance.cast::<State>(), &*input.cast::<InHead>(), &mut *out.cast::<OutHead>()) };
        let outcome = (|| {
            if input.op == slot::TICK && unsafe { (*std::ptr::from_ref(input).cast::<TickIn>()).now_ns == 3 } {
                state.tick_entered.store(true, std::sync::atomic::Ordering::SeqCst);
                let start = std::time::Instant::now();
                while !state.tick_continue.load(std::sync::atomic::Ordering::SeqCst) {
                    if start.elapsed() > WAIT { return Err(()); }
                    std::thread::yield_now();
                }
            }
            // SAFETY: input extension memory is the host's loan for this crossing.
            let bytes = unsafe { super::super::validate::lent(input.extensions.ptr, input.extensions.len) }.ok_or(())?;
            let capability = inspection::read_capability(bytes).map_err(|_| ())?.ok_or(())?;
            if let Some(receipt) = inspection::read_receipt(bytes).map_err(|_| ())? {
                if receipt.request.ticket != input.ticket || receipt.request.epoch != capability.epoch { return Err(()); }
                // Ordinary PENDING's request allocation was poisoned and freed by release.
                // The host must own the complete request and reply independently.
                state.observed.lock().unwrap().push((input.op, input.flags & FLAG_RESUME != 0, receipt));
                if input.op == slot::TICK {
                    // SAFETY: tick's host frame contains TickIn and TickOut.
                    let short = unsafe { (*std::ptr::from_ref(input).cast::<TickIn>()).now_ns == 2 };
                    if short && !state.shorted.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        unsafe { (*out.cast::<TickOut>()).next_tick_ns = 9; }
                        return Ok(Outcome::Failed);
                    }
                }
                return Ok(Outcome::Ready);
            }
            let request = InspectionRequest {
                ticket: input.ticket, epoch: capability.epoch, id: 1,
                query: InspectionQuery::CarrierSessions { sessions: vec![7, 9] },
            };
            let bytes = inspection::append_request(&[], &request).map_err(|_| ())?;
            out_head.extensions = Blob { ptr: bytes.as_ptr(), len: bytes.len(), fmt: BLOB_OCTETS, flags: 0 };
            let mut leases = state.leases.lock().unwrap();
            let lease = leases.keys().copied().max().unwrap_or(0) + 1;
            leases.insert(lease, bytes);
            out_head.lease = lease;
            Ok(Outcome::Pending)
        })().unwrap_or(Outcome::Fault);
        out_head.outcome = RawOutcome::of(outcome);
        RawOutcome::of(outcome)
    }
    fn door() -> &'static Door {
        static ADDRESS: OnceLock<usize> = OnceLock::new();
        let ptr = *ADDRESS.get_or_init(|| {
            let real = crate::dispatch_test_plugin::door().parts();
            // SAFETY: the original test door's table is an OpsHead, copied then restated with
            // matching fixture slot signatures. Every table and door allocation is static.
            let mut ops = unsafe { *real.ops };
            ops.open = Some(opened); ops.close = Some(closed);
            ops.tick = Some(crossed); ops.drive = Some(crossed); ops.cancel = Some(cancelled); ops.release = Some(released);
            let ops = Box::leak(Box::new(ops));
            let door = unsafe { Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts { ops, ..real }) };
            Box::into_raw(Box::new(door)) as usize
        });
        // SAFETY: initialized once above and leaked for the process lifetime.
        unsafe { &*(ptr as *const Door) }
    }
}

fn rig() -> (Dispatcher, Plugin<InspectionKind>, *const State) {
    let provider = Arc::new(InspectionOnlyHost);
    let d = Dispatcher::with_services(DispatchConfig::default(), provider);
    let row = LinkedRow::of(door).expect("fixture door");
    let p = crate::dispatch::load_linked::<InspectionKind>(
        &row,
        Bind {
            instance: Arc::from("inspection"),
            max_inflight_cap: 2,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("fixture loads");
    let mut frame = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: NO_BLOB,
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    assert_eq!(p.call(slot::OPEN, &mut frame).outcome, Outcome::Ready);
    let state = frame.out.instance.cast::<State>();
    (d, p, state)
}

fn tick(now_ns: u64) -> Frame<TickIn, TickOut> {
    Frame::new(
        TickIn {
            head: in_head(),
            now_ns,
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 0,
        },
    )
}

#[test]
fn ordinary_pending_resumes_with_a_copied_receipt_and_short_recall_keeps_it() {
    let (d, p, state) = rig();
    let ticket = d.mint(0).unwrap();
    let done = d
        .submit(&p, ticket, slot::TICK, tick(2), DeadlineClass::Call, 0)
        .wait(WAIT)
        .unwrap();
    assert_eq!(done.outcome, Outcome::Failed);
    assert!(done.short);
    let done = d
        .submit(&p, ticket, slot::TICK, tick(2), DeadlineClass::Call, 0)
        .wait(WAIT)
        .unwrap();
    assert_eq!(done.outcome, Outcome::Ready);
    // SAFETY: the plugin remains opened while this test borrows its state.
    let seen = unsafe { &*state }.observed.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(
        unsafe { &*state }
            .released
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the unhanded PENDING request lease is released before RESUME"
    );
    assert_eq!(seen[0].0, slot::TICK);
    assert!(seen[0].1, "ordinary PENDING must re-enter with RESUME");
    assert_eq!(
        seen[0].2, seen[1].2,
        "short recall must retain the immutable receipt"
    );
    assert_eq!(seen[0].2.result, Err(InspectionError::Unsupported));
    drop(seen);
    d.recycle(ticket);
}

#[test]
fn tick_pending_ends_its_frame_and_drive_receives_the_same_inspection() {
    let (d, p, state) = rig();
    let driver = d.driver(&p, 0).unwrap();
    let done = d.tick(&p, driver, 1).wait(WAIT).unwrap();
    assert_eq!(done.outcome, Outcome::Pending);
    assert_ne!(done.lease, 0, "the driver TICK lease belongs to its caller");
    let mut release = Frame::new(
        busbar_contract::abi::mechanism::lifecycle::ReleaseIn {
            head: in_head(),
            lease: done.lease,
        },
        out_head(),
    );
    assert_eq!(p.call(slot::RELEASE, &mut release).outcome, Outcome::Ready);
    assert_eq!(
        unsafe { &*state }
            .released
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    drop(done);
    let start = std::time::Instant::now();
    loop {
        // SAFETY: the plugin remains open, and its observation list has its own lock.
        let seen = unsafe { &*state }.observed.lock().unwrap();
        if !seen.is_empty() {
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].0, slot::DRIVE);
            assert_eq!(seen[0].2.request.ticket, driver);
            assert_eq!(seen[0].2.result, Err(InspectionError::Unsupported));
            break;
        }
        drop(seen);
        assert!(start.elapsed() < WAIT, "inspection did not wake DRIVE");
        std::thread::yield_now();
    }
    d.recycle(driver);
}

#[test]
fn one_copied_request_commits_and_wakes_once_even_if_the_plugin_repeats_it() {
    use super::super::services::{Caller, Served, ServiceStore};
    use super::super::ticket::WakeRoute;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Route {
        store: Arc<ServiceStore>,
        provider: InspectionOnlyHost,
        wakes: AtomicUsize,
    }
    impl WakeRoute for Route {
        fn wake(&self, _: Ticket, _: Option<&'static InstanceWake>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
        fn services(&self) -> Option<Served<'_>> {
            Some(Served {
                store: &self.store,
                provider: &self.provider,
            })
        }
    }
    let route = Arc::new(Route {
        store: Arc::default(),
        provider: InspectionOnlyHost,
        wakes: AtomicUsize::new(0),
    });
    let dyn_route: Arc<dyn WakeRoute> = route.clone();
    let wake: &'static InstanceWake = Box::leak(Box::default());
    assert!(wake.route.set(Arc::downgrade(&dyn_route)).is_ok());
    assert!(wake
        .caller
        .set(Caller {
            instance: Arc::from("actual-bound-instance"),
            plugin: Arc::from("fixture"),
            kind: KindCode::Plane
        })
        .is_ok());
    let mut input = in_head();
    input.ticket = Ticket {
        slot: 1,
        generation: 8,
    };
    let loan = unsafe { prepare(wake, slot::TICK, &mut input, Some(17)) }.unwrap();
    let capability =
        unsafe { super::super::validate::lent(input.extensions.ptr, input.extensions.len) }
            .unwrap();
    let request = InspectionRequest {
        ticket: input.ticket,
        epoch: inspection::read_capability(capability)
            .unwrap()
            .unwrap()
            .epoch,
        id: 1,
        query: InspectionQuery::CarrierSessions { sessions: vec![7] },
    };
    drop(loan);
    let mut bytes = inspection::append_request(&[], &request).unwrap();
    let mut output = out_head();
    output.extensions = Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    for _ in 0..2 {
        assert!(unsafe {
            answer(
                wake,
                slot::TICK,
                input.ticket,
                Some(17),
                Outcome::Pending,
                &output,
            )
        }
        .is_ok());
    }
    assert_eq!(route.wakes.load(Ordering::SeqCst), 1);
    bytes.fill(0xA5);
    drop(bytes);
    let loan = unsafe { prepare(wake, slot::DRIVE, &mut input, Some(17)) }.unwrap();
    let bytes = unsafe { super::super::validate::lent(input.extensions.ptr, input.extensions.len) }
        .unwrap();
    assert_eq!(
        inspection::read_receipt(bytes).unwrap().unwrap(),
        InspectionReceipt {
            request,
            result: Err(InspectionError::Unsupported),
        }
    );
    drop(loan);
    assert!(
        input.extensions.len == 0,
        "the frame's original extensions were restored"
    );
}

#[test]
fn ticketless_cancel_invalidates_the_ticket_named_in_its_body() {
    use busbar_contract::abi::mechanism::lifecycle::{CancelIn, CancelOut};
    let (d, p, state) = rig();
    let ticket = d.mint(0).unwrap();
    let done = d
        .submit(&p, ticket, slot::TICK, tick(1), DeadlineClass::Call, 0)
        .wait(WAIT)
        .unwrap();
    assert_eq!(done.outcome, Outcome::Ready);
    // SAFETY: the opened plugin owns this state until close.
    let request = unsafe { &*state }.observed.lock().unwrap()[0]
        .2
        .request
        .clone();
    let caller = caller_key(p.inner.wake);
    assert!(d
        .services()
        .inspection_input(caller, ticket, None)
        .unwrap()
        .1
        .is_some());
    let mut cancel = Frame::new(
        CancelIn {
            head: in_head(),
            ticket,
        },
        CancelOut {
            head: out_head(),
            disposition: 0,
            _reserved: 0,
        },
    );
    assert_eq!(p.call(slot::CANCEL, &mut cancel).outcome, Outcome::Ready);
    assert!(cancel.input.head.ticket.is_none());
    assert!(d
        .services()
        .inspection_input(caller, ticket, None)
        .unwrap()
        .1
        .is_none());
    assert!(!d
        .services()
        .inspection_complete(caller, None, &request, Arc::from(&b"late"[..])));
    d.recycle(ticket);
}

#[path = "../../../busbar-contract/src/tests/allocation_observer.rs"]
mod alloc_counter;

#[global_allocator]
static INSPECTION_ALLOCATOR: alloc_counter::Counting = alloc_counter::Counting::new();

struct InspectionRoute {
    store: Arc<super::super::services::ServiceStore>,
    provider: InspectionOnlyHost,
}
impl super::super::ticket::WakeRoute for InspectionRoute {
    fn wake(&self, _: Ticket, _: Option<&'static InstanceWake>) {}
    fn services(&self) -> Option<super::super::services::Served<'_>> {
        Some(super::super::services::Served {
            store: &self.store,
            provider: &self.provider,
        })
    }
}
fn input_route() -> (Arc<InspectionRoute>, &'static InstanceWake, InHead) {
    let route = Arc::new(InspectionRoute {
        store: Arc::default(),
        provider: InspectionOnlyHost,
    });
    let dynamic: Arc<dyn super::super::ticket::WakeRoute> = route.clone();
    let wake = Box::leak(Box::<InstanceWake>::default());
    assert!(wake.route.set(Arc::downgrade(&dynamic)).is_ok());
    assert!(wake
        .caller
        .set(super::super::services::Caller {
            instance: Arc::from("inspection-secret"),
            plugin: Arc::from("fixture"),
            kind: KindCode::Plane
        })
        .is_ok());
    let mut input = in_head();
    input.ticket = Ticket {
        slot: 1,
        generation: 8,
    };
    (route, wake, input)
}

#[test]
fn secret_input_flags_survive_pending_resume_short_replay_and_cancel() {
    use busbar_contract::abi::mechanism::{call::BLOB_SECRET, extensions};
    let (route, wake, mut input) = input_route();
    let prior = zeroize::Zeroizing::new(extensions::encode(&[(
        "unrelated",
        b"protected-extension-value",
    )]));
    input.extensions = Blob {
        ptr: prior.as_ptr(),
        len: prior.len(),
        fmt: BLOB_OCTETS,
        flags: BLOB_SECRET,
    };
    let original = input.extensions;
    let first = unsafe { prepare(wake, slot::TICK, &mut input, None) }
        .unwrap()
        .unwrap();
    assert_eq!(input.extensions.flags, BLOB_SECRET);
    let bytes = unsafe { super::super::validate::lent(input.extensions.ptr, input.extensions.len) }
        .unwrap();
    assert_eq!(
        extensions::get(bytes, "unrelated"),
        Some(&b"protected-extension-value"[..])
    );
    let request = InspectionRequest {
        ticket: input.ticket,
        epoch: inspection::read_capability(bytes).unwrap().unwrap().epoch,
        id: 1,
        query: InspectionQuery::CarrierSessions { sessions: vec![7] },
    };
    let output_bytes = inspection::append_request(&[], &request).unwrap();
    let mut output = out_head();
    output.extensions = Blob {
        ptr: output_bytes.as_ptr(),
        len: output_bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    assert_eq!(
        unsafe {
            answer(
                wake,
                slot::TICK,
                input.ticket,
                None,
                Outcome::Pending,
                &output,
            )
        },
        Ok(true)
    );
    drop(first);
    assert_eq!(input.extensions.ptr, original.ptr);

    let mut seen = None;
    for flags in [FLAG_RESUME, FLAG_RESUME, 0] {
        input.flags = flags;
        let loan = unsafe { prepare(wake, slot::DRIVE, &mut input, None) }
            .unwrap()
            .unwrap();
        assert_eq!(input.extensions.flags, BLOB_SECRET);
        let bytes =
            unsafe { super::super::validate::lent(input.extensions.ptr, input.extensions.len) }
                .unwrap();
        let receipt = inspection::read_receipt(bytes).unwrap().unwrap();
        if let Some(prior) = &seen {
            assert_eq!(&receipt, prior);
        } else {
            seen = Some(receipt);
        }
        drop(loan);
    }
    route
        .store
        .inspection_cancel(caller_key(wake), input.ticket);
    assert!(route
        .store
        .inspection_input(caller_key(wake), input.ticket, None)
        .unwrap()
        .1
        .is_none());
    route.store.forget(input.ticket);
}

#[test]
fn every_secret_input_copy_is_wiped_on_cancel_epoch_end_and_owner_drop() {
    use alloc_counter::{watch_initialized_payload, InitializedPayloadProbe};
    use busbar_contract::abi::mechanism::{call::BLOB_SECRET, extensions};
    let secret = [0xA7; 32];
    for end in 0..3 {
        // SAFETY: every registered input allocation remains on this thread until destruction.
        let probe = unsafe { InitializedPayloadProbe::start().expect("open the memory observer") };
        let (route, wake, mut input) = input_route();
        let prior = zeroize::Zeroizing::new(extensions::encode(&[("unrelated", &secret)]));
        // SAFETY: the owned Vec's initialized slice begins at its allocation base.
        unsafe { watch_initialized_payload(&prior) };
        let mut expected_lengths = vec![prior.len()];
        input.extensions = Blob {
            ptr: prior.as_ptr(),
            len: prior.len(),
            fmt: BLOB_OCTETS,
            flags: BLOB_SECRET,
        };
        for _ in 0..3 {
            let loan = unsafe { prepare(wake, slot::TICK, &mut input, None) }.unwrap();
            assert!(loan.is_some(), "the crossing must copy the secret input");
            expected_lengths.push(input.extensions.len);
            drop(loan);
        }
        match end {
            0 => route
                .store
                .inspection_cancel(caller_key(wake), input.ticket),
            1 => {
                route.store.forget(input.ticket);
            }
            _ => (),
        }
        drop(route);
        drop(prior);
        let observations = probe.finish();
        assert!(
            !observations.reentered,
            "OS memory reader reentered the allocator"
        );
        assert_eq!(
            observations
                .payloads
                .iter()
                .map(|record| record.len)
                .collect::<Vec<_>>(),
            expected_lengths,
            "observe the original input and every prepared copy, including temporary allocations"
        );
        for record in &observations.payloads {
            assert!(record.freed, "secret allocation was not freed: {record:?}");
            #[cfg(target_os = "linux")]
            {
                assert_eq!(record.read_error, None, "OS memory read failed: {record:?}");
                assert!(
                    record.complete_read,
                    "OS memory read was incomplete: {record:?}"
                );
                assert_eq!(record.bytes_read, record.len);
                assert!(
                    record.wiped,
                    "every copied secret allocation must be wiped: {record:?}"
                );
            }
            #[cfg(not(target_os = "linux"))]
            {
                assert_eq!(record.read_error, Some(std::io::ErrorKind::Unsupported));
                assert!(!record.complete_read);
                assert_eq!(record.bytes_read, 0);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    eprintln!("Input copies and frees checked; memory proof requires Linux /proc/self/mem");
}

pub(super) fn watch_input_copy(bytes: &[u8]) {
    // SAFETY: prepare passes only the base initialized prefix of its owned Vec. An active probe
    // requires that input loan to stay on its thread through destruction; outside one this is a no-op.
    unsafe { alloc_counter::watch_initialized_payload(bytes) }
}

#[test]
fn unrelated_truncated_extensions_and_full_input_keep_old_call_behavior() {
    use busbar_contract::abi::mechanism::extensions;
    let (_route, wake, mut input) = input_route();
    let mut old = extensions::encode(&[("unrelated", b"first"), ("unrelated", b"second")]);
    old.push(0xFF);
    let mut output = out_head();
    output.extensions = Blob {
        ptr: old.as_ptr(),
        len: old.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    assert_eq!(
        unsafe {
            answer(
                wake,
                slot::TICK,
                input.ticket,
                None,
                Outcome::Ready,
                &output,
            )
        },
        Ok(false)
    );
    input.extensions = output.extensions;
    let loan = unsafe { prepare(wake, slot::TICK, &mut input, None) }.unwrap();
    assert!(loan.is_none());
    assert_eq!(input.extensions.ptr, old.as_ptr());
    let full = extensions::encode(&[(
        "full",
        &vec![0; inspection::MAX_BYTES - extensions::entry_len("full", &[])],
    )]);
    assert_eq!(full.len(), inspection::MAX_BYTES);
    input.extensions = Blob {
        ptr: full.as_ptr(),
        len: full.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let loan = unsafe { prepare(wake, slot::TICK, &mut input, None) }.unwrap();
    assert!(
        loan.is_none(),
        "optional capability cannot fault an otherwise valid full input"
    );
    assert_eq!(input.extensions.ptr, full.as_ptr());
}

crate::dispatch_tests::c_abi! {
    fn plane_opened(_: *mut std::ffi::c_void, input: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        // SAFETY: the actual plane open frames are live, and an empty snapshot is valid.
        let (input, out) = unsafe { (&*input.cast::<busbar_contract::abi::plane::PlaneOpenIn>(), &mut *out.cast::<busbar_contract::abi::plane::PlaneOpenOut>()) };
        let mut state = Box::<State>::default();
        let mut snapshot: Box<busbar_contract::abi::plane::PlaneSnapshot> = Box::new(unsafe { std::mem::zeroed() });
        snapshot.size = std::mem::size_of_val(&*snapshot) as u32;
        snapshot.generation = input.open.generation;
        out.snapshot = &*snapshot;
        state.snapshot = Some(snapshot);
        out.open.instance = Box::into_raw(state).cast();
        out.open.head.outcome = RawOutcome::of(Outcome::Ready);
        RawOutcome::of(Outcome::Ready)
    }
    fn inspection_plane_door() -> &'static Door {
        static ADDRESS: OnceLock<usize> = OnceLock::new();
        let ptr = *ADDRESS.get_or_init(|| {
            let real = crate::plane_door_plugin::door().parts();
            // SAFETY: clone the actual plane table, replacing every slot used by this fixture.
            let mut ops = unsafe { *real.ops.cast::<busbar_contract::abi::plane::Ops>() };
            ops.head.open = Some(plane_opened); ops.head.close = Some(closed);
            ops.head.retire = Some(cancelled);
            ops.head.tick = Some(crossed); ops.head.drive = Some(crossed); ops.head.cancel = Some(cancelled); ops.head.release = Some(released);
            let ops = Box::leak(Box::new(ops));
            let door = unsafe { Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts { ops: std::ptr::from_ref(ops).cast(), ..real }) };
            Box::into_raw(Box::new(door)) as usize
        });
        unsafe { &*(ptr as *const Door) }
    }
}

fn plane_rig() -> (crate::dispatch::plane_calls::PlaneInstance, *const State) {
    use crate::dispatch::{kinds::plane::Plane, plane_calls::PlaneInstance};
    use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};
    let d = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(InspectionOnlyHost),
    ));
    let row = LinkedRow::of(inspection_plane_door).unwrap();
    let p = crate::dispatch::load_linked::<Plane>(
        &row,
        Bind {
            instance: Arc::from("inspection-plane"),
            max_inflight_cap: 2,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            // This boundary control crosses no destination but the real MCP
            // descriptor still declares HTTP and stdio needs.
            conns: ConnTable::Probe,
        },
    )
    .unwrap();
    // SAFETY: zero is valid for these C-layout input/output data structs; heads are set below.
    let mut input: PlaneOpenIn = unsafe { std::mem::zeroed() };
    let mut output: PlaneOpenOut = unsafe { std::mem::zeroed() };
    input.open.head = in_head();
    input.open.generation = 1;
    output.open.head = out_head();
    let mut open = Frame::new(input, output);
    assert_eq!(p.call(slot::OPEN, &mut open).outcome, Outcome::Ready);
    let state = open.out.open.instance.cast::<State>();
    let instance = PlaneInstance::new(p, d.clone(), 0);
    (instance, state)
}

#[test]
fn actual_plane_calls_tick_releases_the_pending_lease_before_returning() {
    use busbar_contract::plane_calls::PlaneCalls;
    let (instance, state) = plane_rig();
    let driver = instance.driver().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    assert_eq!(
        rt.block_on(async { tokio::time::timeout(WAIT, instance.tick(driver, 1)).await })
            .unwrap(),
        Some(0)
    );
    // SAFETY: instance still owns its open fixture state. No manual RELEASE is used here.
    let state = unsafe { &*state };
    assert_eq!(state.released.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(state.leases.lock().unwrap().is_empty());
    let start = std::time::Instant::now();
    loop {
        let seen = state.observed.lock().unwrap();
        if let Some((op, _, receipt)) = seen.first() {
            assert_eq!(*op, slot::DRIVE);
            assert_eq!(receipt.request.ticket, driver);
            assert_eq!(receipt.result, Err(InspectionError::Unsupported));
            break;
        }
        drop(seen);
        assert!(start.elapsed() < WAIT);
        std::thread::yield_now();
    }
    instance.recycle(driver);
}

#[test]
fn composed_loans_end_each_crossing_while_a_driver_keeps_its_epoch() {
    let (route, wake, mut input) = input_route();
    route.store.keep(input.ticket, 41);
    let caller = caller_key(wake);
    let (epoch, _) = route
        .store
        .inspection_input(caller, input.ticket, None)
        .unwrap();
    for id in 1..=32 {
        let request = InspectionRequest {
            ticket: input.ticket,
            epoch,
            id,
            query: InspectionQuery::CarrierSessions { sessions: vec![id] },
        };
        let bytes = inspection::append_request(&[], &request).unwrap();
        let mut output = out_head();
        output.extensions = Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        assert_eq!(
            unsafe {
                answer(
                    wake,
                    slot::TICK,
                    input.ticket,
                    None,
                    Outcome::Pending,
                    &output,
                )
            },
            Ok(true)
        );
        let loan = unsafe { prepare(wake, slot::DRIVE, &mut input, None) }
            .unwrap()
            .unwrap();
        let weak = Arc::downgrade(&loan._bytes);
        let bytes =
            unsafe { super::super::validate::lent(input.extensions.ptr, input.extensions.len) }
                .unwrap();
        assert_eq!(
            inspection::read_receipt(bytes).unwrap().unwrap().request,
            request
        );
        drop(loan);
        assert!(
            weak.upgrade().is_none(),
            "no historical composed allocation survives this crossing"
        );
        assert_eq!(
            route
                .store
                .inspection_input(caller, input.ticket, None)
                .unwrap()
                .0,
            epoch
        );
    }
    route.store.forget(input.ticket);
}

#[test]
fn malformed_owned_inspection_entries_still_fail_closed() {
    use busbar_contract::abi::mechanism::extensions;
    let (_route, wake, mut input) = input_route();
    let loan = unsafe { prepare(wake, slot::TICK, &mut input, None) }
        .unwrap()
        .unwrap();
    let bytes = unsafe { super::super::validate::lent(input.extensions.ptr, input.extensions.len) }
        .unwrap();
    let request = InspectionRequest {
        ticket: input.ticket,
        epoch: inspection::read_capability(bytes).unwrap().unwrap().epoch,
        id: 1,
        query: InspectionQuery::CarrierSessions { sessions: vec![7] },
    };
    drop(loan);
    let good = inspection::append_request(&[], &request).unwrap();
    let mut duplicate = good.clone();
    duplicate.extend_from_slice(&good);
    let truncated = good[..good.len() - 1].to_vec();
    let mut trailing = good.clone();
    trailing.push(0xFF);
    for bytes in [&duplicate, &truncated, &trailing] {
        let mut output = out_head();
        output.extensions = Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        assert_eq!(
            unsafe {
                answer(
                    wake,
                    slot::TICK,
                    input.ticket,
                    None,
                    Outcome::Pending,
                    &output,
                )
            },
            Err(())
        );
    }
    let cap = inspection::encode_capability(request.epoch).unwrap();
    let duplicate_cap = extensions::encode(&[
        (inspection::EXT_CAPABILITY, &cap),
        (inspection::EXT_CAPABILITY, &cap),
    ]);
    input.extensions = Blob {
        ptr: duplicate_cap.as_ptr(),
        len: duplicate_cap.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    assert!(unsafe { prepare(wake, slot::TICK, &mut input, None) }.is_err());
}

#[test]
fn plane_tick_lease_is_released_if_settled_reply_is_never_polled() {
    use busbar_contract::plane_calls::PlaneCalls;
    let (instance, state) = plane_rig();
    let driver = instance.driver().unwrap();
    let future = instance.tick(driver, 1);

    let start = std::time::Instant::now();
    let state = unsafe { &*state };
    while state.observed.lock().unwrap().is_empty() {
        assert!(start.elapsed() < WAIT);
        std::thread::yield_now();
    }
    drop(future);
    assert_eq!(state.released.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(state.leases.lock().unwrap().is_empty());
    instance.recycle(driver);
}

#[test]
fn plane_tick_lease_is_released_when_future_drops_before_crossing_returns() {
    use busbar_contract::plane_calls::PlaneCalls;
    use std::sync::atomic::Ordering;
    let (instance, state) = plane_rig();
    let driver = instance.driver().unwrap();
    let future = instance.tick(driver, 3);
    let state = unsafe { &*state };
    let start = std::time::Instant::now();
    while !state.tick_entered.load(Ordering::SeqCst) {
        assert!(start.elapsed() < WAIT);
        std::thread::yield_now();
    }
    drop(future);
    state.tick_continue.store(true, Ordering::SeqCst);
    while state.observed.lock().unwrap().is_empty() {
        assert!(start.elapsed() < WAIT);
        std::thread::yield_now();
    }
    assert_eq!(state.released.load(Ordering::SeqCst), 1);
    assert!(state.leases.lock().unwrap().is_empty());
    instance.recycle(driver);
}

#[test]
fn oversized_optional_blobs_are_not_sliced_and_active_inspection_fails_closed() {
    let (route, wake, mut input) = input_route();
    let oversized = Blob {
        ptr: std::ptr::NonNull::<u8>::dangling().as_ptr(),
        len: inspection::MAX_BYTES + 1,
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    input.extensions = oversized;
    // SAFETY: the input head is valid; its fabricated oversized blob must not be dereferenced.
    assert!(unsafe { prepare(wake, slot::TICK, &mut input, None) }
        .unwrap()
        .is_none());
    let mut output = out_head();
    output.extensions = oversized;
    assert_eq!(
        unsafe {
            answer(
                wake,
                slot::TICK,
                input.ticket,
                None,
                Outcome::Pending,
                &output,
            )
        },
        Ok(false)
    );
    let (epoch, _) = route
        .store
        .inspection_input(caller_key(wake), input.ticket, None)
        .unwrap();
    let request = InspectionRequest {
        ticket: input.ticket,
        epoch,
        id: 1,
        query: InspectionQuery::CarrierSessions { sessions: vec![7] },
    };
    assert_eq!(
        route
            .store
            .inspection_begin(caller_key(wake), None, &request),
        Ok(true)
    );
    assert!(unsafe { prepare(wake, slot::TICK, &mut input, None) }.is_err());
    assert_eq!(
        unsafe {
            answer(
                wake,
                slot::TICK,
                input.ticket,
                None,
                Outcome::Pending,
                &output,
            )
        },
        Err(())
    );
    route
        .store
        .inspection_cancel(caller_key(wake), input.ticket);
    assert_eq!(
        unsafe {
            answer(
                wake,
                slot::TICK,
                input.ticket,
                None,
                Outcome::Pending,
                &output,
            )
        },
        Ok(false)
    );
}

// No business service is part of these inspection custody assertions.
struct InspectionOnlyHost;
impl busbar_contract::services::HostServices for InspectionOnlyHost {
    fn now(&self) -> busbar_contract::services::Reading {
        panic!("unexpected host service now in inspection/conditional boundary control")
    }
    fn dest_judge(
        &self,
        _dest: &str,
        _class: u32,
        _flags: u32,
        _later: Option<busbar_contract::services::Later>,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service dest_judge in inspection/conditional boundary control")
    }
    fn records_get(
        &self,
        _caller: &busbar_contract::services::Caller,
        _kind: &str,
        _key: &[u8],
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service records_get in inspection/conditional boundary control")
    }
    fn records_list(
        &self,
        _caller: &busbar_contract::services::Caller,
        _list: busbar_contract::services::RecordsList,
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service records_list in inspection/conditional boundary control")
    }
    fn records_claim(
        &self,
        _caller: &busbar_contract::services::Caller,
        _kind: &str,
        _key: &[u8],
        _ttl_ms: u64,
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service records_claim in inspection/conditional boundary control")
    }
    fn sign(
        &self,
        _caller: &busbar_contract::services::Caller,
        _data: &[u8],
    ) -> busbar_contract::services::Stored {
        panic!("unexpected host service sign in inspection/conditional boundary control")
    }
    fn trust_sight(
        &self,
        _caller: &busbar_contract::services::Caller,
        _counterparty: &str,
        _hash: &str,
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service trust_sight in inspection/conditional boundary control")
    }
    fn trust_unreached(
        &self,
        _caller: &busbar_contract::services::Caller,
        _counterparty: &str,
    ) -> busbar_contract::services::Stored {
        panic!("unexpected host service trust_unreached in inspection/conditional boundary control")
    }
    fn trust_sight_item(
        &self,
        _caller: &busbar_contract::services::Caller,
        _counterparty: &str,
        _item: &str,
        _digest: &str,
    ) -> busbar_contract::services::Stored {
        panic!(
            "unexpected host service trust_sight_item in inspection/conditional boundary control"
        )
    }
    fn trust_decide(
        &self,
        _caller: &busbar_contract::services::Caller,
        _key: busbar_contract::services::TrustKeyRef<'_>,
        _expected: Option<&str>,
        _approve: bool,
    ) -> busbar_contract::services::Stored {
        panic!("unexpected host service trust_decide in inspection/conditional boundary control")
    }
    fn trust_state(
        &self,
        _caller: &busbar_contract::services::Caller,
        _counterparty: &str,
    ) -> busbar_contract::services::Stored {
        panic!("unexpected host service trust_state in inspection/conditional boundary control")
    }
    fn trust_serves(
        &self,
        _caller: &busbar_contract::services::Caller,
        _counterparty: &str,
        _item: Option<&str>,
        _digest: Option<&str>,
    ) -> busbar_contract::services::Stored {
        panic!("unexpected host service trust_serves in inspection/conditional boundary control")
    }
    fn trust_due(
        &self,
        _caller: &busbar_contract::services::Caller,
    ) -> busbar_contract::services::Stored {
        panic!("unexpected host service trust_due in inspection/conditional boundary control")
    }
    fn trust_verify(
        &self,
        _caller: &busbar_contract::services::Caller,
        _counterparty: &str,
        _payload: &[u8],
        _signatures: &[u8],
    ) -> busbar_contract::services::Stored {
        panic!("unexpected host service trust_verify in inspection/conditional boundary control")
    }
    fn entitlement_check(
        &self,
        _caller: &busbar_contract::services::Caller,
        _unit: Option<u64>,
        _target: &str,
    ) -> busbar_contract::services::Stored {
        panic!(
            "unexpected host service entitlement_check in inspection/conditional boundary control"
        )
    }
    fn session_emit(
        &self,
        _caller: &busbar_contract::services::Caller,
        _session: u64,
        _bytes: &[u8],
    ) -> busbar_contract::services::Stored {
        panic!("unexpected host service session_emit in inspection/conditional boundary control")
    }
    fn ticket_mint(
        &self,
        _caller: &busbar_contract::services::Caller,
        _unit: Option<u64>,
        _ttl_secs: u64,
        _record: &[u8],
    ) -> busbar_contract::services::Stored {
        panic!("unexpected host service ticket_mint in inspection/conditional boundary control")
    }
    fn ticket_take(
        &self,
        _caller: &busbar_contract::services::Caller,
        _unit: Option<u64>,
    ) -> busbar_contract::services::Stored {
        panic!("unexpected host service ticket_take in inspection/conditional boundary control")
    }
    fn random_fill(&self, _len: u64) -> busbar_contract::services::Stored {
        panic!("unexpected host service random_fill in inspection/conditional boundary control")
    }
    fn records_secret(
        &self,
        _kind: &str,
        _id: &str,
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service records_secret in inspection/conditional boundary control")
    }
    fn unit_nest(
        &self,
        _caller: &busbar_contract::services::Caller,
        _unit: Option<u64>,
        _ask: busbar_contract::services::NestAsk,
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service unit_nest in inspection/conditional boundary control")
    }
    fn work_open(
        &self,
        _caller: &busbar_contract::services::Caller,
        _unit: Option<u64>,
        _kind: &str,
        _record: &[u8],
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service work_open in inspection/conditional boundary control")
    }
    fn work_find(
        &self,
        _caller: &busbar_contract::services::Caller,
        _unit: Option<u64>,
        _reference: &[u8],
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service work_find in inspection/conditional boundary control")
    }
    fn work_settle(
        &self,
        _caller: &busbar_contract::services::Caller,
        _unit: Option<u64>,
        _handle: u64,
        _record: &[u8],
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service work_settle in inspection/conditional boundary control")
    }
    fn work_resume(
        &self,
        _caller: &busbar_contract::services::Caller,
        _unit: Option<u64>,
        _handle: u64,
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service work_resume in inspection/conditional boundary control")
    }
    fn disk_append(
        &self,
        _dest: &busbar_contract::services::DiskDest,
        _bytes: Vec<u8>,
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service disk_append in inspection/conditional boundary control")
    }
    fn verify_lookup(
        &self,
        _caller: &busbar_contract::services::Caller,
        _key: &[u8],
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service verify_lookup in inspection/conditional boundary control")
    }
    fn verify_store(
        &self,
        _caller: &busbar_contract::services::Caller,
        _key: &[u8],
        _entry: &[u8],
        _ttl_ms: u64,
    ) -> busbar_contract::services::Stored {
        panic!("unexpected host service verify_store in inspection/conditional boundary control")
    }
    fn content_scan(
        &self,
        _caller: &busbar_contract::services::Caller,
        _unit: Option<u64>,
        _content: &[u8],
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service content_scan in inspection/conditional boundary control")
    }
    fn hook_call(
        &self,
        _caller: &busbar_contract::services::Caller,
        _unit: Option<u64>,
        _ask: busbar_contract::services::HookAsk,
        _later: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        panic!("unexpected host service hook_call in inspection/conditional boundary control")
    }
    fn snapshot_read(
        &self,
        _caller: &busbar_contract::services::Caller,
        _scope: u32,
    ) -> busbar_contract::services::Snapshot {
        panic!("unexpected host service snapshot_read in inspection/conditional boundary control")
    }
}

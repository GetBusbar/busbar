// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `Safe` slots through the real trampoline: the SDK mints the instance on a READY `open`, types it
//! for every later call, and drops it on a READY `close` — never on anything else.

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::abi::mechanism::call::{
    Blob, InHead, Op, OutHead, Outcome, RawOutcome, BLOB_ABSENT, FLAG_RESUME,
};
use crate::abi::mechanism::lifecycle::{
    slot, CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, RefreshIn, ReleaseIn,
    TickIn, TickOut, ValidateIn,
};
use crate::abi::mechanism::ticket::{HostCtx, Ticket};
use crate::abi::mechanism::KindCode;
use crate::abi::sdk::door::KindOps;
use crate::abi::sdk::lent::Lent;

use super::{Instance, SafeSlot};
use crate::abi::sdk::out::Out;

#[repr(C)]
#[derive(Clone, Copy)]
struct LifecycleOnly {
    head: OpsHead,
}

// SAFETY: `#[repr(C)]`, `head: OpsHead` first, nothing after it; the lifecycle's `open` out is
// `OpenOut`.
unsafe impl KindOps for LifecycleOnly {
    const KIND: KindCode = KindCode::Secret;
    type Lifecycle = crate::abi::sdk::door::Lifecycle;
}

/// The instance state: counts its drops into the test's counter.
pub struct Probe {
    pub drops: &'static AtomicUsize,
    pub value: u64,
    /// Its `Drop` panics after counting (plugin code the SDK runs at `close`).
    pub panics_on_drop: bool,
    /// The leases its answers hold.
    pub leases: crate::abi::sdk::life::Leases,
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panics_on_drop, "the state's Drop panics");
    }
}

/// `open`'s behaviour, by the settings length.
const OPEN_READY: usize = 1;
const OPEN_FAILED: usize = 2;
const OPEN_PANICS: usize = 3;
const OPEN_FORGES: usize = 4;
const OPEN_INSTALLS_NOTHING: usize = 5;
const OPEN_DROP_PANICS: usize = 6;
/// `close` with these `in.flags` answers FAILED.
const CLOSE_FAILS: u32 = 7;
/// `close` with these `in.flags` answers READY naming a reason leased from the state's own table
/// (memory the box that goes at this `close` owns).
const CLOSE_LEASES_ERROR: u32 = 8;
/// `drive` with these `in.flags` answers FAILED with a reason leased from a table the body made
/// for itself.
const DRIVE_LOCAL_LEASE: u32 = 0x100;
/// `drive` with these `in.flags` answers FAILED with a reason leased from the instance's table.
const DRIVE_STATE_LEASE: u32 = 0x200;
/// What a ticketed `release` parks across its PENDING.
const PARKED: u64 = 0x5afe;
/// A `release` ticket in this slot takes its continuation back by value in its RESUME.
const RESUME_TAKES: u32 = 7;
/// A `release` ticket in this slot takes its continuation back boxed in its RESUME.
const RESUME_BOXES: u32 = 9;

mod plugin {
    use super::*;

    macro_rules! safe_slot {
        ($name:ident, $state:ty, $in:ty, $out:ty, |$inst:ident, $input:ident, $o:ident| $body:expr) => {
            pub struct $name;
            impl SafeSlot for $name {
                type In = $in;
                type Out = $out;
                type State = $state;
                fn call(
                    $inst: Instance<'_, $state>,
                    $input: Lent<'_, $in>,
                    #[allow(unused_mut)] mut $o: Out<'_, $out>,
                ) -> Outcome {
                    $body
                }
            }
        };
    }

    safe_slot!(Validate, Probe, ValidateIn, OutHead, |i, _input, _o| {
        // No instance before `open`.
        if i.get().is_none() {
            Outcome::Ready
        } else {
            Outcome::Refused
        }
    });
    safe_slot!(Open, Probe, OpenIn, OpenOut, |i, input, o| {
        let s = input.field(|x| &x.settings);
        // The test lends its counter's address as the settings pointer.
        // SAFETY: the test's leaked, `'static` counter.
        let drops = unsafe { &*s.ptr.cast::<AtomicUsize>() };
        if s.len != OPEN_INSTALLS_NOTHING {
            i.open(Probe {
                drops,
                value: 41,
                panics_on_drop: s.len == OPEN_DROP_PANICS,
                leases: Default::default(),
            });
        }
        match s.len {
            OPEN_FAILED => Outcome::Failed,
            OPEN_PANICS => panic!("open panics after installing"),
            OPEN_FORGES => {
                // Only the SDK's own code can reach the raw `out` (`Out::raw`): a forged instance.
                o.raw().instance = 0x10 as *mut c_void;
                Outcome::Ready
            }
            _ => Outcome::Ready,
        }
    });
    // Another state type than `open` installed: reads no instance.
    safe_slot!(Refresh, u32, RefreshIn, OutHead, |i, _input, _o| {
        if i.get().is_none() {
            Outcome::Refused
        } else {
            Outcome::Ready
        }
    });
    // Installing outside `open` panics: FAULT.
    safe_slot!(Retire, Probe, GenIn, OutHead, |i, _input, _o| {
        let drops = i.get().expect("open installed a probe").drops;
        i.open(Probe {
            drops,
            value: 0,
            panics_on_drop: false,
            leases: Default::default(),
        });
        Outcome::Ready
    });
    safe_slot!(Tick, Probe, TickIn, TickOut, |i, _input, o| {
        o.set(|o| &o.next_tick_ns, i.get().map_or(0, |p| p.value + 1));
        Outcome::Ready
    });
    safe_slot!(Drive, Probe, DriveIn, OutHead, |i, input, o| {
        match input.head.flags {
            DRIVE_LOCAL_LEASE => {
                let local = crate::abi::sdk::life::Leases::default();
                o.lease_str(|o| &o.error, &local, "a reason".to_string());
                Outcome::Failed
            }
            DRIVE_STATE_LEASE => {
                let p = i.get().expect("open installed a probe");
                o.lease_str(|o| &o.error, &p.leases, "a reason".to_string());
                Outcome::Failed
            }
            _ => Outcome::Ready,
        }
    });
    safe_slot!(Cancel, Probe, CancelIn, CancelOut, |_i, _input, _o| {
        Outcome::Ready
    });
    // A ticketed fresh entry parks [`PARKED`] and answers PENDING; its RESUME answers READY
    // having found it, or FAILED.
    safe_slot!(Release, Probe, ReleaseIn, OutHead, |i, _input, _o| {
        if i.ticket().is_none() {
            Outcome::Ready
        } else if !i.resuming() {
            i.park(PARKED);
            Outcome::Pending
        } else {
            let found = match i.ticket().slot {
                RESUME_TAKES => i.resume_value::<u64>(),
                RESUME_BOXES => i.resume::<u64>().map(|b| *b),
                // It takes nothing back: the SDK drops what was parked on the way out.
                _ => return Outcome::Ready,
            };
            if found == Some(PARKED) {
                Outcome::Ready
            } else {
                Outcome::Failed
            }
        }
    });
    safe_slot!(Close, Probe, InHead, OutHead, |i, input, o| {
        if input.flags == CLOSE_FAILS {
            Outcome::Failed
        } else {
            if input.flags == CLOSE_LEASES_ERROR {
                let p = i.get().expect("open installed a probe");
                o.lease_str(|o| &o.error, &p.leases, "closing".to_string());
            }
            Outcome::Ready
        }
    });

    crate::plugin_door! {
        ops: LifecycleOnly,
        statement: crate::abi::sdk::door::statement("safe-probe", "0", 4),
        lifecycle: {
            validate: crate::abi::sdk::Safe<Validate>,
            open: crate::abi::sdk::Safe<Open>,
            refresh: crate::abi::sdk::Safe<Refresh>,
            retire: crate::abi::sdk::Safe<Retire>,
            tick: crate::abi::sdk::Safe<Tick>,
            drive: crate::abi::sdk::Safe<Drive>,
            cancel: crate::abi::sdk::Safe<Cancel>,
            release: crate::abi::sdk::Safe<Release>,
            close: crate::abi::sdk::Safe<Close>,
        },
    }
}

fn table() -> &'static LifecycleOnly {
    // SAFETY: the macro's `'static` door and table.
    unsafe { &*(*plugin::door()).ops.cast::<LifecycleOnly>() }
}

fn in_head<T>(op: u32) -> InHead {
    InHead {
        size: size_of::<T>() as u32,
        op,
        flags: 0,
        deadline_class: 0,
        _reserved: [0; 3],
        host: HostCtx::NONE,
        ticket: Ticket::NONE,
        deadline_ns: 0,
        trace_id: [0; 16],
        parent_span_id: 0,
        extensions: Blob {
            ptr: ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        },
    }
}

fn zeroed<T>() -> T {
    // SAFETY: every `in`/`out` here is plain data; all-zero is valid.
    unsafe { std::mem::zeroed() }
}

fn out_head<T>() -> OutHead {
    let mut h: OutHead = zeroed();
    h.size = size_of::<T>() as u32;
    h.outcome = RawOutcome::of(Outcome::Fault);
    h
}

fn call<I, O>(op: Option<Op>, instance: *mut c_void, input: &I, out: &mut O) -> Outcome {
    op.expect("every slot is filled")(
        instance,
        ptr::from_ref(input).cast(),
        ptr::from_mut(out).cast(),
    )
    .outcome()
}

/// `open` with `mode`, counting drops into a fresh counter: `(outcome, instance, counter)`.
fn open(mode: usize) -> (Outcome, *mut c_void, &'static AtomicUsize) {
    let drops: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    let mut input: OpenIn = zeroed();
    input.head = in_head::<OpenIn>(slot::OPEN);
    input.settings = Blob {
        ptr: ptr::from_ref(drops).cast(),
        len: mode,
        fmt: BLOB_ABSENT,
        flags: 0,
    };
    let mut out: OpenOut = zeroed();
    out.head = out_head::<OpenOut>();
    let o = call(table().head.open, ptr::null_mut(), &input, &mut out);
    (o, out.instance, drops)
}

fn tick(instance: *mut c_void) -> (Outcome, u64) {
    let mut input: TickIn = zeroed();
    input.head = in_head::<TickIn>(slot::TICK);
    let mut out: TickOut = zeroed();
    out.head = out_head::<TickOut>();
    let o = call(table().head.tick, instance, &input, &mut out);
    (o, out.next_tick_ns)
}

fn close(instance: *mut c_void, flags: u32) -> Outcome {
    close_out(instance, flags).0
}

/// `close` with `flags`: its outcome and the `out` the host reads after it.
fn close_out(instance: *mut c_void, flags: u32) -> (Outcome, OutHead) {
    let mut input = in_head::<InHead>(slot::CLOSE);
    input.flags = flags;
    let mut out = out_head::<OutHead>();
    let o = call(table().head.close, instance, &input, &mut out);
    (o, out)
}

#[test]
fn a_ready_open_mints_the_instance_every_later_slot_reads_typed() {
    let (o, inst, drops) = open(OPEN_READY);
    assert_eq!(o, Outcome::Ready);
    assert!(!inst.is_null());
    assert_eq!(tick(inst), (Outcome::Ready, 42), "tick reads open's state");
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(close(inst, 0), Outcome::Ready);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "a READY close drops the state"
    );
}

#[test]
fn validate_before_open_reads_no_instance() {
    let mut input: ValidateIn = zeroed();
    input.head = in_head::<ValidateIn>(slot::VALIDATE);
    let mut out = out_head::<OutHead>();
    let o = call(table().head.validate, ptr::null_mut(), &input, &mut out);
    assert_eq!(o, Outcome::Ready);
}

#[test]
fn a_slot_naming_another_state_type_reads_none() {
    let (_, inst, _) = open(OPEN_READY);
    let mut input: RefreshIn = zeroed();
    input.head = in_head::<RefreshIn>(slot::REFRESH);
    let mut out = out_head::<OutHead>();
    assert_eq!(
        call(table().head.refresh, inst, &input, &mut out),
        Outcome::Refused
    );
    assert_eq!(close(inst, 0), Outcome::Ready);
}

#[test]
fn an_open_that_is_not_ready_hands_back_no_instance_and_drops_the_state() {
    let (o, inst, drops) = open(OPEN_FAILED);
    assert_eq!(o, Outcome::Failed);
    assert!(inst.is_null());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn an_open_that_panics_after_installing_is_fault_and_drops_the_state() {
    let (o, inst, drops) = open(OPEN_PANICS);
    assert_eq!(o, Outcome::Fault);
    assert!(inst.is_null());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn a_pointer_the_body_forges_is_overwritten_by_the_minted_one() {
    // RED: `out.instance = 0x10` in a safe body never reaches the host.
    let (o, inst, _) = open(OPEN_FORGES);
    assert_eq!(o, Outcome::Ready);
    assert_ne!(inst, 0x10 as *mut c_void);
    assert_eq!(tick(inst), (Outcome::Ready, 42));
    assert_eq!(close(inst, 0), Outcome::Ready);
}

#[test]
fn a_ready_open_that_installs_nothing_hands_back_null() {
    // The host judges a READY `open` with a NULL instance FAULT.
    let (o, inst, _) = open(OPEN_INSTALLS_NOTHING);
    assert_eq!(o, Outcome::Ready);
    assert!(inst.is_null());
}

#[test]
fn a_close_that_is_not_ready_keeps_the_state() {
    let (_, inst, drops) = open(OPEN_READY);
    assert_eq!(close(inst, CLOSE_FAILS), Outcome::Failed);
    assert_eq!(drops.load(Ordering::SeqCst), 0, "the host still calls it");
    assert_eq!(tick(inst), (Outcome::Ready, 42));
    assert_eq!(close(inst, 0), Outcome::Ready);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn installing_outside_open_is_fault() {
    let (_, inst, drops) = open(OPEN_READY);
    let mut input: GenIn = zeroed();
    input.head = in_head::<GenIn>(slot::RETIRE);
    let mut out = out_head::<OutHead>();
    assert_eq!(
        call(table().head.retire, inst, &input, &mut out),
        Outcome::Fault
    );
    // Only the refused probe drops; the instance is untouched.
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(tick(inst), (Outcome::Ready, 42));
    assert_eq!(close(inst, 0), Outcome::Ready);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}

#[test]
fn a_state_whose_drop_panics_still_closes_ready() {
    // RED (C1 M5 c): the box is freed during the unwind, so a FAULT here would leave the host
    // holding a freed instance it believes is open. The close answers READY.
    let (o, inst, drops) = open(OPEN_DROP_PANICS);
    assert_eq!(o, Outcome::Ready);
    assert_eq!(close(inst, 0), Outcome::Ready);
    assert_eq!(drops.load(Ordering::SeqCst), 1, "the state dropped once");
}

fn drive(instance: *mut c_void, flags: u32) -> Outcome {
    let mut input: DriveIn = zeroed();
    input.head = in_head::<DriveIn>(slot::DRIVE);
    input.head.flags = flags;
    let mut out = out_head::<OutHead>();
    call(table().head.drive, instance, &input, &mut out)
}

#[test]
fn red_an_answer_leased_from_a_table_the_body_dropped_is_fault() {
    // C1 M5 (b): the body's own `Leases` is dropped when it returns, freeing the reason the head
    // names before the host copies it. The SDK answers FAULT, so the host reads nothing.
    let (_, inst, _) = open(OPEN_READY);
    assert_eq!(drive(inst, DRIVE_LOCAL_LEASE), Outcome::Fault);
    // The GREEN twin: leased from the instance's table, the answer stands.
    assert_eq!(drive(inst, DRIVE_STATE_LEASE), Outcome::Failed);
    assert_eq!(close(inst, 0), Outcome::Ready);
}

/// THE REQUEST PATH TAKES NO SHARED LOCK WHEN NOTHING IS PARKED (THE DESIGN, the plugin ABI: "no allocation
/// and no blocking on the hot path"). Every worker on an instance enters through the same `Head`;
/// an entry on an instance with nothing parked must not touch the parked table's mutex, so it
/// cannot wait on another worker holding it.
#[test]
fn an_entry_with_nothing_parked_takes_no_parked_lock() {
    let (o, inst, _drops) = open(OPEN_READY);
    assert_eq!(o, Outcome::Ready);
    // SAFETY: the instance the SDK minted above, alive until the `close` below.
    let h = unsafe { super::head(inst) }.expect("an open instance has a head");
    let held = h.parked();
    let at = inst as usize;
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(tick(at as *mut c_void));
    });
    let answered = rx.recv_timeout(std::time::Duration::from_secs(5));
    drop(held);
    worker.join().expect("the worker returns");
    assert_eq!(
        answered.ok(),
        Some((Outcome::Ready, 42)),
        "an entry with nothing parked waited on the parked table's lock"
    );
    assert_eq!(close(inst, 0), Outcome::Ready);
}

/// A CROSSING ALLOCATES NOTHING, ITS PER-CALL LOG SCOPE INCLUDED (THE DESIGN, the plugin ABI: "no
/// allocation and no blocking on the hot path"; the per-call scoped capture is kept). The
/// thread's capture dispatcher is built once, on the worker's first crossing; every later crossing
/// scopes the body under it with a reference-count clone and a thread-local swap, and allocates
/// nothing.
#[test]
fn a_crossing_with_its_scoped_capture_allocates_nothing() {
    let (o, inst, _drops) = open(OPEN_READY);
    assert_eq!(o, Outcome::Ready);
    // The worker's first crossings build its capture slot.
    assert_eq!(tick(inst), (Outcome::Ready, 42));
    assert_eq!(tick(inst), (Outcome::Ready, 42));
    crate::alloc_counter::reset();
    let answered = tick(inst);
    let allocations = crate::alloc_counter::allocations();
    assert_eq!(answered, (Outcome::Ready, 42));
    assert_eq!(allocations, 0, "a warm crossing allocated");
    assert_eq!(close(inst, 0), Outcome::Ready);
}

#[test]
fn red_a_ready_close_names_no_memory_its_freed_state_owned() {
    // RED before the fix: the reason `close` leased from the state's table named the box the
    // trampoline then freed, and the host read freed memory. The `out` the host reads now names
    // none of it: its error is absent, the state gone, the answer READY.
    let (o, instance, drops) = open(OPEN_READY);
    assert_eq!(o, Outcome::Ready);
    let (closed, out) = close_out(instance, CLOSE_LEASES_ERROR);
    assert_eq!(closed, Outcome::Ready);
    assert_eq!(drops.load(Ordering::SeqCst), 1, "the state is gone");
    assert!(
        out.error.ptr.is_null() && out.error.len == 0,
        "no reason names the freed box"
    );
    assert!(out.extensions.ptr.is_null(), "nor does any payload");
}

/// `release` on `ticket` with `flags`: a fresh entry parks and pends, a RESUME answers READY.
fn release(instance: *mut c_void, ticket: Ticket, flags: u32) -> Outcome {
    let mut input: ReleaseIn = zeroed();
    input.head = in_head::<ReleaseIn>(slot::RELEASE);
    input.head.ticket = ticket;
    input.head.flags = flags;
    let mut out = out_head::<OutHead>();
    call(table().head.release, instance, &input, &mut out)
}

/// A NOT-READY CONTINUATION COMES FROM A RECYCLED POOL (BUSBAR-1.6.0.md A.8, decision #30: "no
/// allocation and no blocking on the hot path"). Once an instance has parked on a ticket, a later
/// PENDING, RESUME, READY cycle on a recycled ticket reuses the continuation's allocation: the
/// crossing pair allocates nothing.
#[test]
fn red_a_warm_pending_resume_ready_cycle_on_a_recycled_ticket_allocates_nothing() {
    let (o, inst, _drops) = open(OPEN_READY);
    assert_eq!(o, Outcome::Ready);
    for generation in 1..=2 {
        let t = Ticket {
            slot: 3,
            generation,
        };
        assert_eq!(release(inst, t, 0), Outcome::Pending);
        assert_eq!(release(inst, t, FLAG_RESUME), Outcome::Ready);
    }
    // The ticket's slot, recycled: a new generation.
    let recycled = Ticket {
        slot: 3,
        generation: 3,
    };
    crate::alloc_counter::reset();
    let parked = release(inst, recycled, 0);
    let resumed = release(inst, recycled, FLAG_RESUME);
    let allocations = crate::alloc_counter::allocations();
    assert_eq!((parked, resumed), (Outcome::Pending, Outcome::Ready));
    assert_eq!(
        allocations, 0,
        "a warm PENDING, RESUME, READY cycle allocated"
    );
    assert_eq!(close(inst, 0), Outcome::Ready);
}

/// A CROSSING ON ONE TICKET NEVER WAITS ON ANOTHER TICKET'S CONTINUATION (decision #30: no
/// blocking on the hot path; A.8: zero contended atomics). With ticket A parked and its table held,
/// a READY crossing on ticket B still completes.
#[test]
fn red_a_ready_crossing_completes_while_another_ticket_is_parked_and_held() {
    let (o, inst, _drops) = open(OPEN_READY);
    assert_eq!(o, Outcome::Ready);
    let a = Ticket {
        slot: 5,
        generation: 1,
    };
    assert_eq!(release(inst, a, 0), Outcome::Pending);
    // SAFETY: the instance the SDK minted above, alive until the `close` below.
    let h = unsafe { super::head(inst) }.expect("an open instance has a head");
    let held = h.parked();
    let at = inst as usize;
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let b = Ticket {
            slot: 6,
            generation: 1,
        };
        let _ = tx.send(release(at as *mut c_void, b, FLAG_RESUME));
    });
    let answered = rx.recv_timeout(std::time::Duration::from_secs(5));
    drop(held);
    worker.join().expect("the worker returns");
    assert_eq!(
        answered.ok(),
        Some(Outcome::Ready),
        "a READY crossing on ticket B waited on ticket A's parked continuation"
    );
    assert_eq!(release(inst, a, FLAG_RESUME), Outcome::Ready);
    assert_eq!(close(inst, 0), Outcome::Ready);
}

/// One warm PENDING, RESUME, READY cycle on `slot`'s recycled ticket: the allocations it made.
fn warm_cycle_allocations(instance: *mut c_void, slot: u32) -> u64 {
    for generation in 1..=2 {
        let t = Ticket { slot, generation };
        assert_eq!(release(instance, t, 0), Outcome::Pending);
        assert_eq!(release(instance, t, FLAG_RESUME), Outcome::Ready);
    }
    let recycled = Ticket {
        slot,
        generation: 3,
    };
    crate::alloc_counter::reset();
    let parked = release(instance, recycled, 0);
    let resumed = release(instance, recycled, FLAG_RESUME);
    let allocations = crate::alloc_counter::allocations();
    assert_eq!((parked, resumed), (Outcome::Pending, Outcome::Ready));
    allocations
}

/// The GREEN twin: a RESUME that takes its continuation back by value leaves its allocation in the
/// instance's pool, so the warm cycle allocates nothing either.
#[test]
fn a_warm_cycle_that_takes_its_continuation_back_allocates_nothing() {
    let (o, inst, _drops) = open(OPEN_READY);
    assert_eq!(o, Outcome::Ready);
    assert_eq!(warm_cycle_allocations(inst, RESUME_TAKES), 0);
    assert_eq!(close(inst, 0), Outcome::Ready);
}

/// The control: the counter sees an allocation when one happens. A RESUME that takes its
/// continuation back boxed makes exactly the one fresh box.
#[test]
fn the_counter_sees_the_box_a_boxed_resume_hands_back() {
    let (o, inst, _drops) = open(OPEN_READY);
    assert_eq!(o, Outcome::Ready);
    assert_eq!(warm_cycle_allocations(inst, RESUME_BOXES), 1);
    assert_eq!(close(inst, 0), Outcome::Ready);
}

/// More tickets parked at once than one segment holds: the table grows, and every ticket resumes
/// its own continuation and frees its slot.
#[test]
fn the_parked_table_grows_past_a_segment_and_every_ticket_resumes_its_own() {
    let (o, inst, _drops) = open(OPEN_READY);
    assert_eq!(o, Outcome::Ready);
    // SAFETY: the instance the SDK minted above, alive until the `close` below.
    let h = unsafe { super::head(inst) }.expect("an open instance has a head");
    let many = 3 * super::SEGMENT as u32 + 1;
    let ticket = |generation| Ticket {
        slot: RESUME_TAKES,
        generation,
    };
    for g in 1..=many {
        assert_eq!(release(inst, ticket(g), 0), Outcome::Pending);
    }
    assert_eq!(h.count(), many as usize, "every ticket holds its own slot");
    for g in 1..=many {
        assert_eq!(release(inst, ticket(g), FLAG_RESUME), Outcome::Ready);
    }
    assert_eq!(h.count(), 0, "every slot is free again");
    assert_eq!(close(inst, 0), Outcome::Ready);
}

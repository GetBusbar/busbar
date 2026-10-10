// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `Safe` slots through the real trampoline: the SDK mints the instance on a READY `open`, types it
//! for every later call, and drops it on a READY `close` — never on anything else.

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::abi::mechanism::call::{Blob, InHead, Op, OutHead, Outcome, RawOutcome, BLOB_ABSENT};
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
/// `drive` with these `in.flags` answers FAILED with a reason leased from a table the body made
/// for itself.
const DRIVE_LOCAL_LEASE: u32 = 0x100;
/// `drive` with these `in.flags` answers FAILED with a reason leased from the instance's table.
const DRIVE_STATE_LEASE: u32 = 0x200;

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
    safe_slot!(Release, Probe, ReleaseIn, OutHead, |_i, _input, _o| {
        Outcome::Ready
    });
    safe_slot!(Close, Probe, InHead, OutHead, |_i, input, _o| {
        if input.flags == CLOSE_FAILS {
            Outcome::Failed
        } else {
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
        host: HostCtx {
            ptr: ptr::null_mut(),
        },
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
    let mut input = in_head::<InHead>(slot::CLOSE);
    input.flags = flags;
    let mut out = out_head::<OutHead>();
    call(table().head.close, instance, &input, &mut out)
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

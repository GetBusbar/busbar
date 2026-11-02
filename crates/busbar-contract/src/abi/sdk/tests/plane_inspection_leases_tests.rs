// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Optional plane answer leases through the real OPEN/TICK/RELEASE/CLOSE trampolines.
use super::*;
use crate::abi::mechanism::call::{Blob, Op, BLOB_JSON};
use crate::abi::mechanism::lifecycle::slot;
use crate::abi::sdk::life::Leases;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

static DROPPED: AtomicUsize = AtomicUsize::new(0);
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
struct Owned(std::sync::Weak<Leases>);
impl Drop for Owned {
    fn drop(&mut self) {
        // A kept destructor can reenter its lease owner: RELEASE must detach and unlock first.
        if let Some(leases) = self.0.upgrade() {
            let _ = leases.held();
        }
        DROPPED.fetch_add(1, Ordering::SeqCst);
    }
}
#[derive(Default)]
struct Leasing {
    generations: Generations<PlaneSnapshot, ()>,
    leases: Arc<Leases>,
}
impl PlaneLife for Leasing {
    type Held = ();
    fn generations(&self) -> &Generations<PlaneSnapshot, ()> {
        &self.generations
    }
    fn leases(&self) -> Option<&Leases> {
        Some(&self.leases)
    }
    fn open(_: &Lent<'_, PlaneOpenIn>) -> Result<Opened<Self>, Refusal> {
        Ok(Opened {
            plane: Self::default(),
            first: Published {
                spec: SnapshotSpec::default(),
                held: (),
            },
        })
    }
    fn refresh(&self, _: &[u8], _: u64) -> Result<Published<()>, Refusal> {
        Ok(Published {
            spec: SnapshotSpec::default(),
            held: (),
        })
    }
    fn cancel(
        _: Instance<'_, Self>,
        _: Lent<'_, PlaneCancelIn>,
        mut out: Out<'_, PlaneCancelOut>,
    ) -> Outcome {
        out.set(|o| &o.cancel.disposition, crate::abi::plane::CANCEL_ABORTED);
        Outcome::Ready
    }
    fn tick(
        instance: Instance<'_, Self>,
        _: Lent<'_, TickIn>,
        mut out: Out<'_, TickOut>,
    ) -> Outcome {
        let plane = instance.get().expect("opened plane");
        out.keep(&plane.leases, Owned(Arc::downgrade(&plane.leases)));
        Outcome::Ready
    }
}
mod plugin {
    use super::*;
    crate::plugin_door! {
        ops: crate::abi::plane::Ops,
        statement: crate::abi::sdk::door::statement("inspection-plane-leases", "0", 1),
        lifecycle: plane_life(Leasing),
    }
}
fn table() -> &'static crate::abi::plane::Ops {
    // SAFETY: this test's static door was built with the plane Ops table.
    unsafe { &*plugin::door().ops.cast::<crate::abi::plane::Ops>() }
}
fn zero<T>() -> T {
    // SAFETY: every ABI input/output used here is explicitly plain all-zero-valid data.
    unsafe { std::mem::zeroed() }
}
fn head<T>(op: u32) -> InHead {
    InHead {
        size: size_of::<T>() as u32,
        op,
        ..zero()
    }
}
fn out_head<T>() -> OutHead {
    OutHead {
        size: size_of::<T>() as u32,
        ..zero()
    }
}
fn call<I, O>(op: Option<Op>, instance: *mut c_void, input: &I, out: &mut O) -> Outcome {
    // SAFETY: this private fixture supplies matching initialized plane frames and live nested
    // input ranges, with NULL for OPEN or its still-live SDK instance.
    unsafe {
        op.unwrap()(
            instance,
            ptr::from_ref(input).cast(),
            ptr::from_mut(out).cast(),
        )
    }
    .outcome()
}
fn open() -> *mut c_void {
    let settings = b"{}";
    let mut input: PlaneOpenIn = zero();
    input.open.head = head::<PlaneOpenIn>(slot::OPEN);
    input.open.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    input.open.generation = 1;
    let mut out: PlaneOpenOut = zero();
    out.open.head = out_head::<PlaneOpenOut>();
    assert_eq!(
        call(table().head.open, ptr::null_mut(), &input, &mut out),
        Outcome::Ready
    );
    assert!(!out.open.instance.is_null());
    out.open.instance
}
fn tick(instance: *mut c_void) -> u64 {
    let mut input: TickIn = zero();
    input.head = head::<TickIn>(slot::TICK);
    let mut out: TickOut = zero();
    out.head = out_head::<TickOut>();
    assert_eq!(
        call(table().head.tick, instance, &input, &mut out),
        Outcome::Ready
    );
    assert_ne!(out.head.lease, 0);
    out.head.lease
}
fn release(instance: *mut c_void, lease: u64) -> Outcome {
    let mut input: ReleaseIn = zero();
    input.head = head::<ReleaseIn>(slot::RELEASE);
    input.lease = lease;
    let mut out = out_head::<OutHead>();
    call(table().head.release, instance, &input, &mut out)
}
fn close(instance: *mut c_void) {
    assert_eq!(
        call(
            table().head.close,
            instance,
            &head::<InHead>(slot::CLOSE),
            &mut out_head::<OutHead>()
        ),
        Outcome::Ready
    );
}
#[test]
fn raw_release_drops_once_duplicate_is_refused_and_close_drops_unreleased_answers() {
    let _serial = SERIAL.lock().unwrap();
    DROPPED.store(0, Ordering::SeqCst);
    let instance = open();
    let first = tick(instance);
    assert_eq!(DROPPED.load(Ordering::SeqCst), 0);
    assert_eq!(release(instance, first), Outcome::Ready);
    assert_eq!(DROPPED.load(Ordering::SeqCst), 1);
    assert_eq!(release(instance, first), Outcome::Refused);
    assert_eq!(DROPPED.load(Ordering::SeqCst), 1);
    let second = tick(instance);
    assert_ne!(first, second);
    let mut cancel: PlaneCancelIn = zero();
    cancel.cancel.head = head::<PlaneCancelIn>(slot::CANCEL);
    let mut cancelled: PlaneCancelOut = zero();
    cancelled.cancel.head = out_head::<PlaneCancelOut>();
    assert_eq!(
        call(table().head.cancel, instance, &cancel, &mut cancelled),
        Outcome::Ready
    );
    assert_eq!(
        DROPPED.load(Ordering::SeqCst),
        1,
        "cancel cannot free bytes the host still copies"
    );
    assert_eq!(release(instance, second), Outcome::Ready);
    assert_eq!(DROPPED.load(Ordering::SeqCst), 2);
    let third = tick(instance);
    assert_ne!(second, third);
    close(instance);
    assert_eq!(DROPPED.load(Ordering::SeqCst), 3);
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observe all arbitrary RawWaker callbacks, including destruction of a replaced registration.

use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{RawWaker, RawWakerVTable, Waker};

pub(crate) struct Probe {
    locked: Box<dyn Fn() -> bool + Send + Sync>,
    pub(crate) clones: AtomicUsize,
    pub(crate) drops: AtomicUsize,
    pub(crate) wakes: AtomicUsize,
    pub(crate) under_lock: AtomicUsize,
}

impl Probe {
    pub(crate) fn new(locked: impl Fn() -> bool + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            locked: Box::new(locked),
            clones: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
            wakes: AtomicUsize::new(0),
            under_lock: AtomicUsize::new(0),
        })
    }

    fn observe(&self, counter: &AtomicUsize) {
        counter.fetch_add(1, Ordering::SeqCst);
        if (self.locked)() {
            self.under_lock.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub(crate) fn waker(self: &Arc<Self>) -> Waker {
        let raw = RawWaker::new(Arc::into_raw(Arc::clone(self)).cast(), &VTABLE);
        // SAFETY: each handle owns one Arc, and every callback below preserves that ownership.
        unsafe { Waker::from_raw(raw) }
    }

    pub(crate) fn assert_unlocked(&self) {
        assert_eq!(self.under_lock.load(Ordering::SeqCst), 0);
    }
}

unsafe fn clone(data: *const ()) -> RawWaker {
    // SAFETY: a borrowed callback retains the handle's Arc while creating its new owned handle.
    let probe = ManuallyDrop::new(unsafe { Arc::<Probe>::from_raw(data.cast()) });
    let retained = Arc::clone(&probe);
    probe.observe(&probe.clones);
    RawWaker::new(Arc::into_raw(retained).cast(), &VTABLE)
}

unsafe fn wake(data: *const ()) {
    // SAFETY: consuming wake releases exactly this handle's Arc after observing it.
    let probe = unsafe { Arc::<Probe>::from_raw(data.cast()) };
    probe.observe(&probe.wakes);
}

unsafe fn wake_by_ref(data: *const ()) {
    // SAFETY: a borrowed wake leaves the handle's Arc owned by the RawWaker.
    let probe = ManuallyDrop::new(unsafe { Arc::<Probe>::from_raw(data.cast()) });
    probe.observe(&probe.wakes);
}

unsafe fn drop_handle(data: *const ()) {
    // SAFETY: destruction consumes exactly the Arc reference belonging to this handle.
    let probe = unsafe { Arc::<Probe>::from_raw(data.cast()) };
    probe.observe(&probe.drops);
}

static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_handle);

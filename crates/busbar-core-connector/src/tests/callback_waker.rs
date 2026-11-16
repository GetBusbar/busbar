// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observe wake callbacks and the lifetime of registrations through safe `Wake` ownership.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Wake, Waker};

pub(crate) struct Probe {
    locked: Box<dyn Fn() -> bool + Send + Sync>,
    pub(crate) live: AtomicUsize,
    pub(crate) drops: AtomicUsize,
    pub(crate) wakes: AtomicUsize,
    pub(crate) under_lock: AtomicUsize,
}

impl Probe {
    pub(crate) fn new(locked: impl Fn() -> bool + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            locked: Box::new(locked),
            live: AtomicUsize::new(0),
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
        self.live.fetch_add(1, Ordering::SeqCst);
        Waker::from(Arc::new(Registration(Arc::clone(self))))
    }

    pub(crate) fn assert_unlocked(&self) {
        assert_eq!(self.under_lock.load(Ordering::SeqCst), 0);
    }
}

struct Registration(Arc<Probe>);

impl Wake for Registration {
    fn wake(self: Arc<Self>) {
        self.0.observe(&self.0.wakes);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.observe(&self.0.wakes);
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
        self.0.observe(&self.0.drops);
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Task waiters on a request's deadline and accepts waiting on a listener are woken in the order
//! they registered (first registered, first woken), each once however often it registered.

use super::*;
use std::task::Wake;

const WAITERS: usize = 16;

struct Recording {
    n: usize,
    woken: Arc<Mutex<Vec<usize>>>,
}

impl Wake for Recording {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.lock().unwrap().push(self.n);
    }
}

fn wakers(woken: &Arc<Mutex<Vec<usize>>>) -> Vec<Waker> {
    (0..WAITERS)
        .map(|n| {
            Waker::from(Arc::new(Recording {
                n,
                woken: woken.clone(),
            }))
        })
        .collect()
}

#[test]
fn deadline_task_waiters_wake_in_registration_order_once_each() {
    let woken = Arc::new(Mutex::new(Vec::new()));
    let wakers = wakers(&woken);
    let wake = Arc::new(DeadlineWake::default());
    for waker in wakers.iter().chain(wakers.iter()) {
        wake.register(DeadlineInterest::Task, waker);
    }
    wake.wake_by_ref();
    assert_eq!(*woken.lock().unwrap(), (0..WAITERS).collect::<Vec<_>>());
}

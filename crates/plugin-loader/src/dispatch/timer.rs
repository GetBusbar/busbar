// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CALL PATH'S CLOCK: one thread that wakes a task at an instant, needing no async runtime, so
//! a call waits on its op's `wake_at_ns` and its deadline the same way under tokio, under
//! `futures::executor::block_on` and on a plain thread. A sleep that ends early (its op answered)
//! takes its entry back, so the clock holds only the sleeps still waiting.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Condvar, Mutex, OnceLock, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

#[derive(Default)]
struct Due {
    wakers: BTreeMap<(Instant, u64), Waker>,
    seq: u64,
}

struct Clock {
    due: Mutex<Due>,
    changed: Condvar,
}

fn clock() -> &'static Clock {
    static CLOCK: OnceLock<&'static Clock> = OnceLock::new();
    CLOCK.get_or_init(|| {
        let c: &'static Clock = Box::leak(Box::new(Clock {
            due: Mutex::new(Due::default()),
            changed: Condvar::new(),
        }));
        std::thread::Builder::new()
            .name("busbar-plugin-clock".to_string())
            .spawn(move || run(c))
            .expect("spawn the plugin call clock");
        c
    })
}

fn run(c: &'static Clock) {
    let mut due = c.due.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        let now = Instant::now();
        let mut fire = Vec::new();
        while let Some(entry) = due.wakers.first_entry() {
            if entry.key().0 > now {
                break;
            }
            fire.push(entry.remove());
        }
        if !fire.is_empty() {
            drop(due);
            fire.into_iter().for_each(Waker::wake);
            due = c.due.lock().unwrap_or_else(PoisonError::into_inner);
            continue;
        }
        due = match due.wakers.first_key_value().map(|(k, _)| k.0) {
            Some(at) => {
                c.changed
                    .wait_timeout(due, at.saturating_duration_since(now))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0
            }
            None => c.changed.wait(due).unwrap_or_else(PoisonError::into_inner),
        };
    }
}

/// Ready at `at`.
#[derive(Debug)]
pub(crate) struct Sleep {
    at: Instant,
    /// The clock's entry for this sleep and the waker it holds.
    armed: Option<(u64, Waker)>,
}

/// A future ready at `at`.
pub(crate) fn sleep_until(at: Instant) -> Sleep {
    Sleep { at, armed: None }
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if Instant::now() >= self.at {
            return Poll::Ready(());
        }
        if self
            .armed
            .as_ref()
            .is_some_and(|(_, w)| w.will_wake(cx.waker()))
        {
            return Poll::Pending;
        }
        let c = clock();
        let mut due = c.due.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((seq, _)) = self.armed.take() {
            due.wakers.remove(&(self.at, seq));
        }
        due.seq += 1;
        let seq = due.seq;
        due.wakers.insert((self.at, seq), cx.waker().clone());
        drop(due);
        c.changed.notify_one();
        self.armed = Some((seq, cx.waker().clone()));
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some((seq, _)) = self.armed.take() {
            clock()
                .due
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .wakers
                .remove(&(self.at, seq));
        }
    }
}

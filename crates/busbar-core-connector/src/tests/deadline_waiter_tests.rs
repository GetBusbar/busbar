// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::{DeadlineInterest, DeadlineWake, Held};
use std::sync::Weak;
use std::task::{Context, Wake, Waker};

fn open_pending(c: &Connector, request_ms: u64) -> ConnId {
    c.open_request(
        OWNER,
        NeedId(0),
        &OpenDesc {
            target: "pending.test:443",
            timeout_ms: request_ms,
            ..Default::default()
        },
        false,
        0,
    )
    .unwrap()
}

#[test]
fn waiters_survive_write_no_ticket_and_repeated_polls_until_the_original_deadline() {
    worker().block_on(async {
        for (dial_ms, request_ms) in [(100, 0), (700, 100)] {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let changed = Arc::new(tokio::sync::Notify::new());
            let recording = seen.clone();
            let signal = changed.clone();
            let (c, carrier, _) = pending_waking(
                dial_ms,
                Arc::new(move |owner, ticket| {
                    assert_eq!(owner, OWNER);
                    recording.lock().unwrap().push(ticket);
                    signal.notify_one();
                }),
            );
            let id = open_pending(&c, request_ms);
            let held = c.slab.get(OWNER, id).unwrap().1;
            let due = if request_ms == 0 {
                held.dial_due.lock().unwrap().clone().unwrap()
            } else {
                held.due.lock().unwrap().clone().unwrap()
            };
            let original = due.at;
            for _ in 0..8 {
                assert_eq!(c.wait(OWNER, &[id], 41), Err(ConnError::Pending));
            }
            assert_eq!(c.write(OWNER, id, b"accepted", true, true), Ok(8));
            assert_eq!(c.wait(OWNER, &[id], 42), Err(ConnError::Pending));
            assert_eq!(
                c.read(OWNER, id, NO_TICKET, &mut [0; 8]),
                Err(ConnError::Pending)
            );
            assert_eq!(c.landed(OWNER, id, NO_TICKET), Err(ConnError::Pending));
            assert_eq!(c.wait(OWNER, &[id], NO_TICKET), Err(ConnError::Pending));
            let current = if request_ms == 0 {
                held.dial_due.lock().unwrap().clone().unwrap()
            } else {
                held.due.lock().unwrap().clone().unwrap()
            };
            assert_eq!(current.at, original);
            assert!(Arc::ptr_eq(&current.timer, &due.timer));
            {
                let waiters = due.wake.waiters.lock().unwrap();
                assert_eq!(
                    waiters.tickets.len(),
                    2,
                    "repeated tickets are deduplicated"
                );
                assert!(waiters.tasks.is_empty());
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let both = {
                        let seen = seen.lock().unwrap();
                        seen.contains(&41) && seen.contains(&42)
                    };
                    if both {
                        break;
                    }
                    changed.notified().await;
                }
            })
            .await
            .expect("both tickets must be woken by their original deadline");
            assert!(!seen.lock().unwrap().contains(&NO_TICKET));
            for _ in 0..3 {
                assert_eq!(c.wait(OWNER, &[id], 41), Ok(0));
                assert_eq!(c.read(OWNER, id, 42, &mut [0; 8]), Err(ConnError::Timeout));
                if request_ms == 0 {
                    assert_eq!(
                        c.write(OWNER, id, b"later", false, true),
                        Err(ConnError::Timeout)
                    );
                }
            }
            assert_eq!(carrier.1.load(Ordering::SeqCst), 0);
            c.close(OWNER, id).unwrap();
            assert!(due.wake.waiters.lock().unwrap().tickets.is_empty());
            assert!(due.timer.get().unwrap().lock().unwrap().is_none());
        }
    });
}

#[test]
fn closing_or_forgetting_cancels_a_registered_timer_even_while_a_poll_holds_its_clone() {
    worker().block_on(async {
        for forget in [false, true] {
            let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counting = wakes.clone();
            let (c, _, pending) = pending_waking(
                40,
                Arc::new(move |_, _| {
                    counting.fetch_add(1, Ordering::SeqCst);
                }),
            );
            let id = open_pending(&c, 0);
            assert_eq!(c.wait(OWNER, &[id], 51), Err(ConnError::Pending));
            let held = c.slab.get(OWNER, id).unwrap().1;
            let due = held.dial_due.lock().unwrap().clone().unwrap();
            if forget {
                c.forget(OWNER);
            } else {
                c.close(OWNER, id).unwrap();
            }
            assert!(due.wake.cancelled.load(Ordering::Acquire));
            assert!(due.wake.waiters.lock().unwrap().tickets.is_empty());
            assert!(due.timer.get().unwrap().lock().unwrap().is_none());

            due.wake
                .register(DeadlineInterest::Ticket(52), &c.waker(OWNER, 52));
            assert!(due.wake.waiters.lock().unwrap().tickets.is_empty());
            tokio::time::sleep(Duration::from_millis(70)).await;
            assert_eq!(wakes.load(Ordering::SeqCst), 0);
            assert_eq!(c.read(OWNER, id, 51, &mut [0; 8]), Err(ConnError::Closed));
            drop(pending.lock().unwrap().take());
        }
    });
}

#[test]
fn deadline_wake_can_reenter_the_same_connection_and_close_it() {
    worker().block_on(async {
        let home = Arc::new(Mutex::new(None::<(Weak<Connector>, ConnId)>));
        let visiting = home.clone();
        let finished = Arc::new(tokio::sync::Notify::new());
        let signal = finished.clone();
        let (c, _, _) = pending_waking(
            40,
            Arc::new(move |_, ticket| {
                assert_eq!(ticket, 61);
                let (c, id) = visiting.lock().unwrap().clone().unwrap();
                let c = c.upgrade().unwrap();
                assert_eq!(c.wait(OWNER, &[id], NO_TICKET), Ok(0));
                assert_eq!(
                    c.read(OWNER, id, NO_TICKET, &mut [0; 8]),
                    Err(ConnError::Timeout)
                );
                c.close(OWNER, id).unwrap();
                signal.notify_one();
            }),
        );
        let c = Arc::new(c);
        let id = open_pending(&c, 0);
        *home.lock().unwrap() = Some((Arc::downgrade(&c), id));
        assert_eq!(c.wait(OWNER, &[id], 61), Err(ConnError::Pending));
        tokio::time::timeout(Duration::from_secs(2), finished.notified())
            .await
            .unwrap();
        assert_eq!(c.wait(OWNER, &[id], 61), Err(ConnError::Closed));
    });
}

struct DropProbe {
    held: Weak<Held>,
    wake: Weak<DeadlineWake>,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
}

#[allow(clippy::manual_noop_waker)]
impl Wake for DropProbe {
    fn wake(self: Arc<Self>) {}
}

impl Drop for DropProbe {
    fn drop(&mut self) {
        if let Some(held) = self.held.upgrade() {
            assert!(held.due.try_lock().is_ok());
            assert!(held.dial_due.try_lock().is_ok());
        }
        if let Some(wake) = self.wake.upgrade() {
            assert!(wake.waiters.try_lock().is_ok());
        }
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn host_task_waiters_deduplicate_and_drop_outside_connection_and_waiter_guards() {
    worker().block_on(async {
        let (c, _, pending) = pending(700);
        let id = open_pending(&c, 0);
        let held = c.slab.get(OWNER, id).unwrap().1;
        let due = held.dial_due.lock().unwrap().clone().unwrap();
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first = Waker::from(Arc::new(DropProbe {
            held: Arc::downgrade(&held),
            wake: Arc::downgrade(&due.wake),
            dropped: dropped.clone(),
        }));
        let second = Waker::from(Arc::new(DropProbe {
            held: Arc::downgrade(&held),
            wake: Arc::downgrade(&due.wake),
            dropped: dropped.clone(),
        }));
        for waker in [&first, &first, &second, &second] {
            assert_eq!(
                c.poll_read(OWNER, id, &mut Context::from_waker(waker), &mut [0; 8]),
                Poll::Pending
            );
        }
        assert_eq!(due.wake.waiters.lock().unwrap().tasks.len(), 2);
        drop(first);
        drop(second);
        c.close(OWNER, id).unwrap();
        assert!(
            dropped.load(Ordering::SeqCst) >= 1,
            "the superseded task has only its deadline hold"
        );
        assert!(due.wake.waiters.lock().unwrap().tasks.is_empty());

        let callback = pending.lock().unwrap().take();
        drop(callback);
        drop(held);
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    });
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercise both carrier broadcast and piece publication through the real public connection.

use super::*;
use crate::carrier::{Carry, Side};
use crate::framer::{Call, Crossed, DoorFacts};
use std::mem::ManuallyDrop;
use std::sync::atomic::AtomicUsize;
use std::task::{RawWaker, RawWakerVTable};
use tokio::io::AsyncWriteExt;

struct Callbacks {
    timely: AtomicBool,
    clones: AtomicUsize,
    wakes: AtomicUsize,
    calls: Mutex<Vec<std::thread::JoinHandle<Result<usize, ConnError>>>>,
}

impl Default for Callbacks {
    fn default() -> Self {
        Self {
            timely: AtomicBool::new(true),
            clones: AtomicUsize::new(0),
            wakes: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
        }
    }
}

struct Callback {
    connector: Weak<Connector>,
    conn: ConnId,
    runtime: tokio::runtime::Handle,
    armed: AtomicBool,
    observed: Arc<Callbacks>,
}

impl Callback {
    fn observe(&self, cloning: bool) {
        if cloning {
            self.observed.clones.fetch_add(1, Ordering::SeqCst);
        } else {
            self.observed.wakes.fetch_add(1, Ordering::SeqCst);
        }
        let connector = self.connector.upgrade().unwrap();
        let conn = self.conn;
        let runtime = self.runtime.clone();
        let (done_tx, done) = std::sync::mpsc::channel();
        let call = std::thread::spawn(move || {
            let _entered = runtime.enter();
            let result = connector.wait(OWNER, &[conn], NO_TICKET);
            let _ = done_tx.send(());
            result
        });
        self.observed
            .timely
            .fetch_and(done.recv_timeout(CALLBACK_WAIT).is_ok(), Ordering::SeqCst);
        self.observed.calls.lock().unwrap().push(call);
    }

    fn cloned(&self) {
        if self.armed.load(Ordering::SeqCst) {
            self.observe(true);
        }
    }

    fn notified(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.observe(false);
        }
    }
}

impl Wake for Callback {
    fn wake(self: Arc<Self>) {
        self.notified();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notified();
    }
}

// Each raw handle owns exactly one Arc reference. Cloning retains a new reference before
// running caller code; borrowed operations use ManuallyDrop and consuming ones release it.
unsafe fn clone_callback(data: *const ()) -> RawWaker {
    // SAFETY: all vtable data pointers originate from Arc::into_raw in raw_waker or this clone.
    let callback = ManuallyDrop::new(unsafe { Arc::<Callback>::from_raw(data.cast()) });
    let retained = Arc::clone(&callback);
    callback.cloned();
    RawWaker::new(Arc::into_raw(retained).cast(), &CALLBACK_VTABLE)
}

unsafe fn wake_callback(data: *const ()) {
    // SAFETY: wake consumes the single Arc reference belonging to this raw handle.
    let callback = unsafe { Arc::<Callback>::from_raw(data.cast()) };
    callback.notified();
}

unsafe fn wake_callback_by_ref(data: *const ()) {
    // SAFETY: this raw handle retains its Arc reference for the duration of the borrow.
    let callback = ManuallyDrop::new(unsafe { Arc::<Callback>::from_raw(data.cast()) });
    callback.notified();
}

unsafe fn drop_callback(data: *const ()) {
    // SAFETY: drop consumes the single Arc reference belonging to this raw handle.
    drop(unsafe { Arc::<Callback>::from_raw(data.cast()) });
}

static CALLBACK_VTABLE: RawWakerVTable = RawWakerVTable::new(
    clone_callback,
    wake_callback,
    wake_callback_by_ref,
    drop_callback,
);

fn raw_waker(callback: Arc<Callback>) -> Waker {
    let raw = RawWaker::new(Arc::into_raw(callback).cast(), &CALLBACK_VTABLE);
    // SAFETY: the vtable above maintains the owned Arc references and Callback is Send + Sync.
    unsafe { Waker::from_raw(raw) }
}

struct CapturedSide {
    inner: Box<dyn Side>,
    wake: Arc<Mutex<Option<Waker>>>,
}

impl Side for CapturedSide {
    fn ticket(&self) -> busbar_contract::abi::mechanism::ticket::Ticket {
        self.inner.ticket()
    }

    fn register(&self, waker: &Waker) {
        // Capture the real carrier wake instead of delivering reactor notifications during
        // setup. Each test chooses the exact broadcast or sibling publication that delivers it.
        let incoming = waker.clone();
        let previous = self.wake.lock().unwrap().replace(incoming);
        drop(previous);
    }
}

struct CapturedCarrier {
    inner: TestDoor,
    wake: Arc<Mutex<Option<Waker>>>,
}

impl FramerDoor for CapturedCarrier {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }

    fn side(&self) -> Option<Box<dyn Side>> {
        self.inner.side().map(|inner| {
            Box::new(CapturedSide {
                inner,
                wake: Arc::clone(&self.wake),
            }) as Box<dyn Side>
        })
    }

    fn carry(&self, side: &dyn Side, resume: bool, call: Carry<'_>) -> Crossed {
        self.inner.carry(side, resume, call)
    }
}

#[test]
fn a_carrier_wake_runs_public_waker_callbacks_outside_the_fan_lock() {
    worker().block_on(async {
        let (listener, far) = far_end().await;
        let captured = Arc::new(Mutex::new(None));
        let c = Arc::new(Connector::serving(
            Transports::new(vec![Entry {
                door: Arc::new(CapturedCarrier {
                    inner: TestDoor::identity(CARRIER_CLAIM),
                    wake: Arc::clone(&captured),
                }),
                alpn: Vec::new(),
            }])
            .unwrap(),
            loopback_literals(),
            None,
            Arc::new(|_, _| {}),
        ));
        c.declare_over(OWNER, NEED, CARRIER_CLAIM).unwrap();
        let conn = c
            .open(
                OWNER,
                NEED,
                &OpenDesc {
                    target: &far,
                    ..Default::default()
                },
            )
            .unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let observed = Arc::new(Callbacks::default());
        let callback = Arc::new(Callback {
            connector: Arc::downgrade(&c),
            conn,
            runtime: tokio::runtime::Handle::current(),
            armed: AtomicBool::new(false),
            observed: Arc::clone(&observed),
        });
        let waker = raw_waker(Arc::clone(&callback));
        let initial = c.poll_read(OWNER, conn, &mut Context::from_waker(&waker), &mut [0; 1]);
        callback.armed.store(true, Ordering::SeqCst);
        let carrier_wake = captured
            .lock()
            .unwrap()
            .take()
            .expect("carrier registered its wake");
        carrier_wake.wake();
        let timely = observed.timely.load(Ordering::SeqCst);
        let wakes = observed.wakes.load(Ordering::SeqCst);
        let calls = std::mem::take(&mut *observed.calls.lock().unwrap());
        let answers: Vec<_> = calls.into_iter().map(|call| call.join().unwrap()).collect();
        c.close(OWNER, conn).unwrap();
        drop((socket, waker, callback));

        assert!(initial.is_pending());
        assert!(
            wakes > 0,
            "the actual carrier wake reached the registered caller"
        );
        assert!(timely, "a clone or wake callback reentered a locked fan");
        assert!(answers
            .iter()
            .all(|answer| *answer == Err(ConnError::Pending)));
    });
}

#[test]
fn a_piece_wakes_its_public_reader_after_the_line_is_unlocked() {
    worker().block_on(async {
        let (listener, far) = far_end().await;
        let c = Arc::new(
            Connector::serving(
                Transports::new(vec![
                    Entry {
                        door: Arc::new(TestDoor::new(
                            FRAMER_CLAIM,
                            &[FRAMER_CLAIM],
                            &[],
                            crate::support::Knobs {
                                offer: Some(H2_OFFER),
                                messages: Some(crate::compose::EXCHANGE_STREAM),
                                ..Default::default()
                            },
                        )),
                        alpn: Vec::new(),
                    },
                    Entry {
                        door: Arc::new(CapturedCarrier {
                            inner: TestDoor::identity(CARRIER_CLAIM),
                            wake: Arc::default(),
                        }),
                        alpn: Vec::new(),
                    },
                ])
                .unwrap(),
                loopback_literals(),
                None,
                Arc::new(|_, _| {}),
            )
            .pooling(SHARED_LINE_POOL),
        );
        c.declare_over(OWNER, NEED, FRAMER_CLAIM).unwrap();
        let desc = OpenDesc {
            target: &far,
            ..Default::default()
        };
        let first = c.open(OWNER, NEED, &desc).unwrap();
        let (mut socket, _) = listener.accept().await.unwrap();
        let second = c.open(OWNER, NEED, &desc).unwrap();
        let observed = Arc::new(Callbacks::default());
        let callback = Arc::new(Callback {
            connector: Arc::downgrade(&c),
            conn: first,
            runtime: tokio::runtime::Handle::current(),
            armed: AtomicBool::new(false),
            observed: Arc::clone(&observed),
        });
        let waker = Waker::from(Arc::clone(&callback));
        let initial = c.poll_read(OWNER, first, &mut Context::from_waker(&waker), &mut [0; 1]);
        callback.armed.store(true, Ordering::SeqCst);
        socket.write_all(b"x").await.unwrap();
        let notified = tokio::time::timeout(CALLBACK_WAIT, async {
            loop {
                let _ = c.wait(OWNER, &[second], NO_TICKET);
                if observed.wakes.load(Ordering::SeqCst) > 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok();
        let timely = observed.timely.load(Ordering::SeqCst);
        let calls = std::mem::take(&mut *observed.calls.lock().unwrap());
        let answers: Vec<_> = calls.into_iter().map(|call| call.join().unwrap()).collect();
        c.close(OWNER, first).unwrap();
        c.close(OWNER, second).unwrap();
        drop((socket, waker, callback));

        assert!(initial.is_pending());
        assert!(
            notified,
            "the sibling drive published a piece for the first reader"
        );
        assert!(
            timely,
            "piece publication invoked the caller under the line guard"
        );
        assert_eq!(answers, vec![Ok(0)]);
    });
}

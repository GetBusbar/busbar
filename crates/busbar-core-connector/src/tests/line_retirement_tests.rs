// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT A LINE RETIRES, and when, on the two paths that hand a connection back without the plain

use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock, TryLockError, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::conn::Bytes;
use tokio::net::{TcpListener, TcpStream};

use super::super::Line;
use super::dial;
use crate::carrier::{Carry, Side};
use crate::compose::{Failure, Planned, Via, EXCHANGE_STREAM};
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor};
use crate::support::{via, worker};

const LONG: Duration = Duration::from_secs(10);

/// Whether the line's lock is held by someone right now (this thread included).
fn lock_held(line: &Line) -> bool {
    matches!(line.state.try_lock(), Err(TryLockError::WouldBlock))
}

type Gate = (mpsc::Sender<()>, mpsc::Receiver<()>);

/// THE TEST CARRIER, with a read and a write that each park once when armed: the crossing says it
struct Gated {
    inner: Arc<dyn FramerDoor>,
    line: OnceLock<Weak<Line>>,
    read: Mutex<Option<Gate>>,
    write: Mutex<Option<Gate>>,
    shut: AtomicUsize,
    under_lock: AtomicUsize,
}

impl FramerDoor for Gated {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }

    fn side(&self) -> Option<Box<dyn Side>> {
        self.inner.side()
    }

    fn carry(&self, side: &dyn Side, resume: bool, call: Carry<'_>) -> Crossed {
        if self
            .line
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|line| lock_held(&line))
        {
            self.under_lock.fetch_add(1, Ordering::SeqCst);
        }
        match &call {
            Carry::Shut(..) => {
                self.shut.fetch_add(1, Ordering::SeqCst);
            }
            Carry::Read(..) => {
                let gate = self.read.lock().unwrap().take();
                if let Some((entered, release)) = gate {
                    entered.send(()).unwrap();
                    release.recv().unwrap();
                }
            }
            Carry::Write(..) => {
                let gate = self.write.lock().unwrap().take();
                if let Some((entered, release)) = gate {
                    entered.send(()).unwrap();
                    release.recv().unwrap();
                    return Crossed {
                        outcome: Outcome::Failed,
                        error: Some(b"the carrier's write failed".to_vec()),
                    };
                }
            }
            _ => {}
        }
        self.inner.carry(side, resume, call)
    }
}

/// A dialled, landed line over the gated carrier, its far end accepted.
async fn connected() -> (Arc<Line>, Arc<Gated>, TcpStream) {
    let far = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = far.local_addr().unwrap();
    let carrier = via();
    let door = Arc::new(Gated {
        inner: Arc::clone(&carrier.door),
        line: OnceLock::new(),
        read: Mutex::new(None),
        write: Mutex::new(None),
        shut: AtomicUsize::new(0),
        under_lock: AtomicUsize::new(0),
    });
    let entry: Arc<dyn FramerDoor> = Arc::clone(&door) as Arc<dyn FramerDoor>;
    let conn = Planned::carried(
        Via {
            door: entry,
            io: carrier.io,
        },
        dial(&at.to_string()),
    )
    .and_then(|p| p.dial_at(at))
    .expect("dials");
    let (peer, _) = far.accept().await.unwrap();
    let line = Line::new(conn);
    door.line.set(Arc::downgrade(&line)).unwrap();
    futures::future::poll_fn(|cx| line.poll_landed(EXCHANGE_STREAM, cx))
        .await
        .expect("the dial lands");
    (line, door, peer)
}

/// A waker that counts itself, and whether the line's lock was held when it ran.
struct Probe {
    line: Weak<Line>,
    woken: AtomicUsize,
    under_lock: AtomicUsize,
}

impl Probe {
    fn new(line: &Arc<Line>) -> Arc<Self> {
        Arc::new(Self {
            line: Arc::downgrade(line),
            woken: AtomicUsize::new(0),
            under_lock: AtomicUsize::new(0),
        })
    }
}

impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.line.upgrade().is_some_and(|line| lock_held(&line)) {
            self.under_lock.fetch_add(1, Ordering::SeqCst);
        }
        self.woken.fetch_add(1, Ordering::SeqCst);
    }
}

/// What a queued opening's payload saw of its own destruction.
#[derive(Default)]
struct Witness {
    dropped: AtomicUsize,
    under_lock: AtomicUsize,
}

/// An opening body's owner: it counts its own drop, and whether the line's lock was held then.
struct Owned {
    bytes: [u8; 6],
    witness: Arc<Witness>,
    line: Weak<Line>,
}

impl AsRef<[u8]> for Owned {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if self.line.upgrade().is_some_and(|line| lock_held(&line)) {
            self.witness.under_lock.fetch_add(1, Ordering::SeqCst);
        }
        self.witness.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

/// RED before the unwind path retired what the closing path does: `Taken::drop` closed the line
#[test]
fn an_unwound_driver_wakes_the_second_holder_and_abandons_the_queued_opening_outside_the_lock() {
    let rt = worker();
    rt.block_on(async {
        let (line, door, _peer) = connected().await;

        let (entered_tx, entered) = mpsc::channel();
        let (release, held_back) = mpsc::channel::<()>();
        let driver = {
            let line = Arc::clone(&line);
            thread::spawn(move || {
                let unwound = catch_unwind(AssertUnwindSafe(|| {
                    let s = line.state();
                    line.turn::<u8>(
                        s,
                        None,
                        |_conn| {
                            entered_tx.send(()).unwrap();
                            held_back.recv().unwrap();
                            resume_unwind(Box::new("the drive unwound"))
                        },
                        |_, _| {},
                    );
                }));
                unwound.is_err()
            })
        };
        entered
            .recv_timeout(LONG)
            .expect("the driver has the connection out");

        let probe = Probe::new(&line);
        let waker = Waker::from(Arc::clone(&probe));
        let mut cx = Context::from_waker(&waker);
        assert!(
            line.poll_ready(EXCHANGE_STREAM, &mut cx).is_pending(),
            "the connection is out with the driver: the second holder waits for it"
        );
        assert_eq!(probe.woken.load(Ordering::SeqCst), 0);

        let witness = Arc::new(Witness::default());
        let body = Bytes::from_owner(Owned {
            bytes: *b"queued",
            witness: Arc::clone(&witness),
            line: Arc::downgrade(&line),
        });
        line.lend();
        line.attach(Some((Vec::new(), body)), Default::default())
            .unwrap_or_else(|_| panic!("the open is handed to the owner"));
        assert_eq!(line.state().opening.len(), 1);
        assert_eq!(witness.dropped.load(Ordering::SeqCst), 0);

        release.send(()).unwrap();
        assert!(driver.join().unwrap(), "the drive unwound");

        assert_eq!(
            probe.woken.load(Ordering::SeqCst),
            1,
            "the second holder that found the connection out is woken once, not left asleep"
        );
        assert_eq!(
            probe.under_lock.load(Ordering::SeqCst),
            0,
            "its waker ran under the line's lock"
        );
        assert_eq!(
            witness.dropped.load(Ordering::SeqCst),
            1,
            "the queued opening is abandoned now, not at the line's final drop"
        );
        assert_eq!(
            witness.under_lock.load(Ordering::SeqCst),
            0,
            "the queued opening was dropped under the line's lock"
        );
        {
            let s = line.state();
            assert!(s.closing, "the line is closed");
            assert!(s.conn.is_some(), "the connection was put back");
            assert!(s.opening.is_empty());
            assert!(s.missed.is_empty());
        }
        assert_eq!(
            door.shut.load(Ordering::SeqCst),
            0,
            "the unwind crossed no plugin to close the connection: that is its holder's"
        );

        assert!(line.poll_ready(EXCHANGE_STREAM, &mut cx).is_ready());

        line.close();
        assert!(door.shut.load(Ordering::SeqCst) >= 1);
        assert_eq!(door.under_lock.load(Ordering::SeqCst), 0);
    });
}

/// RED before a handed-over open's failure was filed only for a holder still on the line:
#[test]
fn a_handed_over_open_that_fails_after_its_holder_left_files_no_refusal_and_the_sibling_is_told() {
    let rt = worker();
    let handle = rt.handle().clone();
    rt.block_on(async {
        let (line, door, _peer) = connected().await;

        let (read_in, read_entered) = mpsc::channel();
        let (read_release, read_held) = mpsc::channel();
        *door.read.lock().unwrap() = Some((read_in, read_held));
        let holder = {
            let line = Arc::clone(&line);
            let on = handle.clone();
            thread::spawn(move || {
                let _rt = on.enter();
                let _ = line.poll_ready(EXCHANGE_STREAM, &mut Context::from_waker(Waker::noop()));
            })
        };
        read_entered
            .recv_timeout(LONG)
            .expect("the holder's read reaches the carrier");

        line.lend();
        line.lend();
        let body = |bytes: &'static [u8]| Some((Vec::new(), Bytes::from_static(bytes)));
        let cancelled = line
            .attach(body(b"cancelled"), Default::default())
            .unwrap_or_else(|_| panic!("the first open is handed to the owner"));
        let live = line
            .attach(body(b"live"), Default::default())
            .unwrap_or_else(|_| panic!("the second open is handed to the owner"));
        assert_ne!(cancelled, live);
        assert_eq!(line.state().opening.len(), 2);

        let (write_in, write_entered) = mpsc::channel();
        let (write_release, write_held) = mpsc::channel();
        *door.write.lock().unwrap() = Some((write_in, write_held));
        read_release.send(()).unwrap();
        write_entered
            .recv_timeout(LONG)
            .expect("the owner opens the first handed-over exchange outside the lock");

        assert_eq!(line.leave(cancelled, false), 2);
        write_release.send(()).unwrap();
        holder.join().unwrap();

        {
            let s = line.state();
            let mut filed: Vec<u64> = s.refused.keys().copied().collect();
            filed.sort_unstable();
            assert_eq!(
                filed,
                vec![live],
                "a failure was filed for an exchange nobody holds any more"
            );
            assert!(!s.held.contains(&cancelled));
            assert!(s.held.contains(&live));
        }

        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            matches!(
                line.poll_piece(live, &mut cx),
                Poll::Ready(Err(Failure::Failed(_)))
            ),
            "the live holder's own open failure is its first read"
        );
        assert!(line.state().refused.is_empty());
        assert_eq!(
            door.under_lock.load(Ordering::SeqCst),
            0,
            "a carrier crossing ran under the line's lock"
        );
        assert_eq!(line.leave(live, false), 1);
        line.close();
    });
}

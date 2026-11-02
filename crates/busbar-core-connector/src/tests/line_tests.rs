// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO PLUGIN CODE RUNS UNDER A HOST LOCK (`BUSBAR-1.6.0.md` §11, M1 DISPATCH RULINGS), on a line:

use std::sync::{mpsc, Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Waker};
use std::thread::{self, ThreadId};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use super::Line;
use crate::carrier::{Carry, Side};
use crate::compose::{Dial, Planned, Via, EXCHANGE_STREAM};
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor};
use crate::support::{via, worker};

#[path = "line_retirement_tests.rs"]
mod retirement_tests;

#[path = "line_cancelled_opening_tests.rs"]
mod cancelled_opening_tests;

/// One carrier crossing as the stub saw it: the op, the thread it ran on, and whether the line's
type Crossing = (&'static str, ThreadId, bool);

/// THE TEST CARRIER, with a read that HANGS once armed: it says it is inside the crossing, then
struct Hanging {
    inner: Arc<dyn FramerDoor>,
    line: OnceLock<Weak<Line>>,
    gate: Mutex<Option<(mpsc::Sender<ThreadId>, mpsc::Receiver<()>)>>,
    crossings: Mutex<Vec<Crossing>>,
}

fn op(call: &Carry<'_>) -> &'static str {
    match call {
        Carry::Listen(..) => "listen",
        Carry::Accept(..) => "accept",
        Carry::Dial(..) => "dial",
        Carry::Read(..) => "read",
        Carry::Write(..) => "write",
        Carry::Flush(..) => "flush",
        Carry::Shut(..) => "shut",
        Carry::Cancel(..) => "cancel",
    }
}

impl FramerDoor for Hanging {
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
        let name = op(&call);
        let locked = self
            .line
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|line| line.state.try_lock().is_err());
        self.crossings
            .lock()
            .unwrap()
            .push((name, thread::current().id(), locked));
        if name == "read" {
            let gate = self.gate.lock().unwrap().take();
            if let Some((entered, release)) = gate {
                entered.send(thread::current().id()).unwrap();
                release.recv().unwrap();
            }
        }
        self.inner.carry(side, resume, call)
    }
}

fn dial(target: &str) -> Dial {
    Dial {
        target: target.to_owned(),
        tls: None,
        alpn: Vec::new(),
        open_timeout: Duration::from_secs(5),
        opening: None,
        head_words: Default::default(),
        anchors: None,
    }
}

fn line_with_connection_held_out(closing: bool) -> Line {
    Line {
        state: Mutex::new(super::State {
            conn: None,
            closing,
            seen: super::Seen::default(),
            opening: Default::default(),
            refused: Default::default(),
            missed: Vec::new(),
            parked: Default::default(),
            held: Default::default(),
            next: 3,
        }),
        fan: Arc::default(),
        dialled: true,
        users: std::sync::atomic::AtomicUsize::new(1),
        tainted: std::sync::atomic::AtomicBool::new(false),
    }
}

#[test]
fn abandoned_pooled_openings_wipe_query_storage_on_rejection_close_and_return() {
    #[derive(Debug, Clone, Copy)]
    enum Abandonment {
        Rejected,
        Closed,
        Returned,
    }
    for mode in [
        Abandonment::Rejected,
        Abandonment::Closed,
        Abandonment::Returned,
    ] {
        for watch_target in [false, true] {
            let line = line_with_connection_held_out(matches!(mode, Abandonment::Rejected));
            let value = b"key=pooled-secret".to_vec();
            let target = b"/path?caller=target-secret".to_vec();
            let watched = if watch_target { &target } else { &value };
            let pointer = watched.as_ptr();
            let len = watched.len();
            let (_, wiped, _) = crate::support::observe_wipe(pointer, len, || {
                let answer = line.attach(
                    Some((
                        vec![("busbar-sealed-query".into(), value)],
                        Vec::new().into(),
                    )),
                    (b"POST".to_vec(), target),
                );
                assert_eq!(answer.is_err(), matches!(mode, Abandonment::Rejected));
                if matches!(mode, Abandonment::Closed) {
                    line.close();
                }
                if matches!(mode, Abandonment::Returned) {
                    line.state().closing = true;
                    let mut taken = super::Taken {
                        line: &line,
                        conn: None,
                    };
                    line.bring_back(&mut taken, |_| {});
                }
                drop(line);
            });
            assert_eq!(wiped, Some(true), "mode={mode:?}, target={watch_target}");
        }
    }
}

/// RED before the connection had one owner: the line's lock was held across every crossing of a
#[test]
fn a_hung_carrier_crossing_holds_no_lock_and_a_close_beside_it_never_waits() {
    let rt = worker();
    let handle = rt.handle().clone();
    rt.block_on(async {
        let far = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = far.local_addr().unwrap();
        let carrier = via();
        let door = Arc::new(Hanging {
            inner: Arc::clone(&carrier.door),
            line: OnceLock::new(),
            gate: Mutex::new(None),
            crossings: Mutex::new(Vec::new()),
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
        let (mut peer, _) = far.accept().await.unwrap();
        let line = Line::new(conn);
        door.line.set(Arc::downgrade(&line)).unwrap();
        futures::future::poll_fn(|cx| line.poll_landed(EXCHANGE_STREAM, cx))
            .await
            .expect("the dial lands");

        let (entered_tx, entered) = mpsc::channel();
        let (release, held_back) = mpsc::channel();
        *door.gate.lock().unwrap() = Some((entered_tx, held_back));
        let reading = Arc::clone(&line);
        let on = handle.clone();
        let holder = thread::spawn(move || {
            let _rt = on.enter();
            let _ = reading.poll_ready(EXCHANGE_STREAM, &mut Context::from_waker(Waker::noop()));
        });
        let owner = entered
            .recv_timeout(Duration::from_secs(10))
            .expect("the holder's read reaches the carrier");

        let (done_tx, done) = mpsc::channel();
        let closing = Arc::clone(&line);
        let closer = thread::spawn(move || {
            let mut cx = Context::from_waker(Waker::noop());
            let before = closing.poll_ready(EXCHANGE_STREAM, &mut cx);
            let empty_write = closing.emit(EXCHANGE_STREAM, b"", true, true);
            closing.close();
            let after = closing.poll_ready(EXCHANGE_STREAM, &mut cx);
            done_tx.send((before, after, empty_write)).unwrap();
        });
        let (before, after, empty_write) = done.recv_timeout(Duration::from_secs(5)).expect(
            "a poll and a close beside a hung carrier crossing returned while it still hangs",
        );
        assert!(
            before.is_pending(),
            "the connection is out with its owner: another holder's poll waits for it, unblocked"
        );
        assert!(after.is_ready(), "once closed, the line is ready: its end");
        let shut_early = door
            .crossings
            .lock()
            .unwrap()
            .iter()
            .any(|(op, ..)| *op == "shut");
        assert!(
            !shut_early,
            "the close was handed to the connection's owner: nothing crossed beside its hung read"
        );

        release.send(()).unwrap();
        holder.join().unwrap();
        closer.join().unwrap();
        assert_eq!(
            empty_write.map_err(|f| crate::map(&f)),
            Err(busbar_contract::conn::ConnError::Pending),
            "an empty frame is not accepted while the connection is out"
        );
        let crossings = door.crossings.lock().unwrap().clone();
        assert!(
            crossings.iter().all(|(.., locked)| !locked),
            "a carrier crossing ran under the line's lock: {crossings:?}"
        );
        let hung = crossings
            .iter()
            .rposition(|(op, ..)| *op == "read")
            .expect("the hung read crossed");
        assert_eq!(crossings[hung].1, owner);
        let after_read: Vec<(&str, ThreadId)> = crossings[hung + 1..]
            .iter()
            .map(|(op, on, _)| (*op, *on))
            .collect();
        assert_eq!(
            after_read,
            vec![("cancel", owner), ("shut", owner)],
            "the owner closed the connection as it brought it back, on its own thread: the read \
             that pended cancelled, then the carrier's shut"
        );
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), peer.read_to_end(&mut rest))
            .await
            .expect("the far end sees the close")
            .unwrap();
        assert!(rest.is_empty());
    });
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cancellation remains possible until the owner selects this opening, including while an
//! earlier opening crosses. Selection and cancellation share the line's lock; plugin crossings,
//! secret wiping and payload retirement do not.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Waker};
use std::thread;
use std::time::Duration;

use busbar_contract::abi::transport::ROLE_FRAMER;
use busbar_contract::conn::Bytes;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use super::{dial, Hanging};
use crate::compose::{Planned, Via, EXCHANGE_STREAM};
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor};
use crate::line::Line;
use crate::support::{observe_wipe, via, worker, Knobs, TestDoor};

const LONG: Duration = Duration::from_secs(10);
type Gate = (mpsc::Sender<()>, mpsc::Receiver<()>);

/// Observe real encode/emit crossings and park the first selected opening inside its encode.
struct Observed {
    inner: TestDoor,
    line: OnceLock<Weak<Line>>,
    encode: Mutex<Option<Gate>>,
    bodies: Mutex<Vec<Vec<u8>>>,
    streams: Mutex<Vec<u64>>,
    under_lock: AtomicUsize,
}

impl FramerDoor for Observed {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        if self
            .line
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|line| line.state.try_lock().is_err())
        {
            self.under_lock.fetch_add(1, Ordering::SeqCst);
        }
        match &call {
            Call::Encode(input, _) => {
                let body = crate::support::lent(input.body, input.body_len);
                self.bodies.lock().unwrap().push(body);
                let gate = self.encode.lock().unwrap().take();
                if let Some((entered, release)) = gate {
                    entered.send(()).unwrap();
                    release.recv_timeout(LONG).unwrap();
                }
            }
            Call::Emit(input, _) => self.streams.lock().unwrap().push(input.stream),
            _ => {}
        }
        self.inner.cross(call)
    }
}

#[derive(Default)]
struct Witness {
    dropped: AtomicUsize,
    under_lock: AtomicUsize,
}

/// The opening's actual body owner, whose destruction can reenter the host.
struct Owned {
    bytes: &'static [u8],
    line: Weak<Line>,
    witness: Arc<Witness>,
}

impl AsRef<[u8]> for Owned {
    fn as_ref(&self) -> &[u8] {
        self.bytes
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if self
            .line
            .upgrade()
            .is_some_and(|line| line.state.try_lock().is_err())
        {
            self.witness.under_lock.fetch_add(1, Ordering::SeqCst);
        }
        self.witness.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

/// Queue a real opening, retaining only an allocator observation address and a body witness.
fn queued(
    line: &Arc<Line>,
    body: &'static [u8],
    watch_target: bool,
) -> (u64, Arc<Witness>, *const u8, usize) {
    let field = b"key=cancelled-secret".to_vec();
    let target = b"/path?caller=cancelled-secret".to_vec();
    let watched = if watch_target { &target } else { &field };
    let pointer = watched.as_ptr();
    let len = watched.len();
    let witness = Arc::new(Witness::default());
    let body = Bytes::from_owner(Owned {
        bytes: body,
        line: Arc::downgrade(line),
        witness: Arc::clone(&witness),
    });
    line.lend();
    let stream = line
        .attach(
            Some((vec![("busbar-sealed-query".into(), field)], body)),
            (b"POST".to_vec(), target),
        )
        .unwrap_or_else(|_| panic!("the real opening queues behind the owner"));
    (stream, witness, pointer, len)
}

fn cancel(line: &Line, queued: (u64, Arc<Witness>, *const u8, usize), left: usize) {
    let (stream, witness, pointer, len) = queued;
    let (remaining, wiped, _) = observe_wipe(pointer, len, || line.leave(stream, false));
    assert_eq!(remaining, left);
    assert_eq!(wiped, Some(true), "cancelled secret storage is wiped now");
    assert_eq!(witness.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(witness.under_lock.load(Ordering::SeqCst), 0);
}

#[test]
fn cancelled_queued_openings_never_cross_and_live_neighbors_open_once_in_fifo_order() {
    let rt = worker();
    let handle = rt.handle().clone();
    rt.block_on(async {
        for watch_target in [false, true] {
            let far = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = far.local_addr().unwrap();
            let carrier = via();
            let carrying = Arc::new(Hanging {
                inner: Arc::clone(&carrier.door),
                line: OnceLock::new(),
                gate: Mutex::new(None),
                crossings: Mutex::new(Vec::new()),
            });
            let framing = Arc::new(Observed {
                inner: TestDoor::new("queued", &["queued"], &[], Knobs::default())
                    .with_role(ROLE_FRAMER),
                line: OnceLock::new(),
                encode: Mutex::new(None),
                bodies: Mutex::new(Vec::new()),
                streams: Mutex::new(Vec::new()),
                under_lock: AtomicUsize::new(0),
            });
            let conn = Planned::locate(
                framing.clone(),
                Via {
                    door: carrying.clone(),
                    io: carrier.io,
                },
                dial(&at.to_string()),
            )
            .and_then(|plan| plan.dial_at(at))
            .expect("the real framed connection dials");
            let (mut peer, _) = far.accept().await.unwrap();
            let line = Line::new(conn);
            carrying.line.set(Arc::downgrade(&line)).unwrap();
            framing.line.set(Arc::downgrade(&line)).unwrap();
            futures::future::poll_fn(|cx| line.poll_landed(EXCHANGE_STREAM, cx))
                .await
                .unwrap();

            // The original holder owns the real connection inside a carrier read.
            let (read_in, read_entered) = mpsc::channel();
            let (read_release, read_held) = mpsc::channel();
            *carrying.gate.lock().unwrap() = Some((read_in, read_held));
            let owner = {
                let line = Arc::clone(&line);
                let on = handle.clone();
                thread::spawn(move || {
                    let _rt = on.enter();
                    line.poll_ready(EXCHANGE_STREAM, &mut Context::from_waker(Waker::noop()))
                })
            };
            read_entered.recv_timeout(LONG).unwrap();

            let before_return = queued(&line, b"cancel-before", watch_target);
            let live = |bytes: &'static [u8]| {
                line.lend();
                line.attach(
                    Some((Vec::new(), Bytes::from_static(bytes))),
                    Default::default(),
                )
                .unwrap_or_else(|_| panic!("the live opening queues"))
            };
            let selected = live(b"selected");
            let during_open = queued(&line, b"cancel-during", watch_target);
            let first = live(b"live-first");
            let second = live(b"live-second");
            assert_eq!(line.users(), 6);
            cancel(&line, before_return, 5);
            assert!(framing.bodies.lock().unwrap().is_empty());

            // The next opening is selected and crosses. Its later neighbors remain cancellable.
            let (encode_in, encode_entered) = mpsc::channel();
            let (encode_release, encode_held) = mpsc::channel();
            *framing.encode.lock().unwrap() = Some((encode_in, encode_held));
            read_release.send(()).unwrap();
            encode_entered.recv_timeout(LONG).unwrap();
            assert_eq!(line.leave(selected, false), 4);
            cancel(&line, during_open, 3);
            encode_release.send(()).unwrap();
            assert!(owner.join().unwrap().is_pending());

            assert_eq!(
                *framing.bodies.lock().unwrap(),
                vec![
                    b"selected".to_vec(),
                    b"live-first".to_vec(),
                    b"live-second".to_vec()
                ]
            );
            assert_eq!(
                *framing.streams.lock().unwrap(),
                vec![selected, first, second]
            );
            assert!(line.state().opening.is_empty());
            assert!(line.state().refused.is_empty());

            // The far end received only the selected request and the two live neighbors.
            let expected = b"selectedlive-firstlive-second";
            let mut received = vec![0; expected.len()];
            tokio::time::timeout(LONG, peer.read_exact(&mut received))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, expected);
            assert_eq!(line.leave(first, true), 2);
            assert_eq!(line.leave(second, true), 1);
            assert_eq!(line.leave(EXCHANGE_STREAM, true), 0);
            line.close();
            line.close();
            let mut rest = Vec::new();
            tokio::time::timeout(LONG, peer.read_to_end(&mut rest))
                .await
                .unwrap()
                .unwrap();
            assert!(rest.is_empty(), "no cancelled body reached the wire");
            assert_eq!(framing.under_lock.load(Ordering::SeqCst), 0);
            let crossings = carrying.crossings.lock().unwrap();
            assert!(crossings.iter().all(|(.., locked)| !locked));
            assert_eq!(crossings.iter().filter(|(op, ..)| *op == "shut").count(), 1);
        }
    });
}

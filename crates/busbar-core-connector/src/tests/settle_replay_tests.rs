// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::io_host::{IoHost, IoRefusal};

type Gate = Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>;

struct ReplayRecordingDoor {
    inner: TestDoor,
    emits: Mutex<Vec<(usize, bool, bool)>>,
}

impl FramerDoor for ReplayRecordingDoor {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        if let Call::Emit(i, _) = &call {
            let text = i.flags & EMIT_TEXT != 0;
            let end = i.end_of_frame != 0;

            if text || (i.len == 0 && end) {
                self.emits.lock().unwrap().push((i.len, end, text));
            }
        }
        self.inner.cross(call)
    }
}

struct ReplayCarrier {
    inner: GatedWrites,
    dial: Gate,
    write: Gate,
    made: AtomicU64,
}

impl ReplayCarrier {
    fn pause(gate: &Gate) {
        let gate = gate.lock().unwrap().take();
        if let Some((entered, release)) = gate {
            entered.send(()).unwrap();
            release.recv().unwrap();
        }
    }
}

impl FramerDoor for ReplayCarrier {
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
        match call {
            Carry::Dial(i, o) => {
                Self::pause(&self.dial);
                let result = self.inner.carry(side, resume, Carry::Dial(i, o));
                self.made.store(o.conn, Ordering::SeqCst);
                result
            }
            Carry::Write(i, o) => {
                Self::pause(&self.write);
                self.inner.carry(side, resume, Carry::Write(i, o))
            }

            Carry::Flush(..) => Crossed {
                outcome: Outcome::Ready,
                error: None,
            },
            other => self.inner.carry(side, resume, other),
        }
    }
}

fn pending_connector(
    carrier: Arc<ReplayCarrier>,
    answer: Arc<Mutex<Option<crate::Judged>>>,
    wakes: Arc<Mutex<Vec<Ticket>>>,
    pooled: bool,
) -> (Arc<Connector>, Arc<ReplayRecordingDoor>) {
    let framing = Arc::new(ReplayRecordingDoor {
        inner: TestDoor::new("frames", &["frames"], &["bytes"], Default::default()),
        emits: Mutex::new(Vec::new()),
    });
    let c = Connector::serving(
        Transports::new(vec![
            Entry {
                door: framing.clone(),
                alpn: Vec::new(),
            },
            Entry {
                door: carrier,
                alpn: Vec::new(),
            },
        ])
        .unwrap(),
        Arc::new(move |_: &str, _: u32, done: crate::Judged| {
            *answer.lock().unwrap() = Some(done);
            None
        }),
        None,
        Arc::new(move |_, ticket| wakes.lock().unwrap().push(ticket)),
    )
    .pooling(crate::pool::PoolPosture {
        max_idle_per_host: if pooled { 8 } else { 0 },
        idle_timeout: Duration::from_secs(60),
    });
    c.declare_over(OWNER, NeedId(0), "frames").unwrap();
    (Arc::new(c), framing)
}

fn carrier() -> Arc<ReplayCarrier> {
    Arc::new(ReplayCarrier {
        inner: GatedWrites {
            inner: TestDoor::identity("bytes"),
            gate: Arc::default(),
            accepted: Mutex::new(Vec::new()),
        },
        dial: Mutex::new(None),
        write: Mutex::new(None),
        made: AtomicU64::new(0),
    })
}

#[test]
fn a_pending_dial_completed_after_close_never_publishes_a_live_line() {
    for forget in [false, true] {
        let runtime = worker();
        let on = runtime.handle().clone();
        runtime.block_on(async {
            let (far, address) = far_end().await;
            let carrier = carrier();
            let answer = Arc::new(Mutex::new(None));
            let (c, _) = pending_connector(carrier.clone(), answer.clone(), Arc::default(), true);
            let id = c
                .open(
                    OWNER,
                    NeedId(0),
                    &OpenDesc {
                        target: &address,
                        ..Default::default()
                    },
                )
                .unwrap();
            answer.lock().unwrap().take().unwrap()(Ok(address.parse().unwrap()));
            let (entered_tx, entered) = std::sync::mpsc::channel();
            let (release, held_back) = std::sync::mpsc::channel();
            *carrier.dial.lock().unwrap() = Some((entered_tx, held_back));
            let reading = Arc::clone(&c);
            let reader = std::thread::spawn(move || {
                let _entered = on.enter();
                reading.read(OWNER, id, 71, &mut [0; 1])
            });
            entered.recv().unwrap();
            if forget {
                c.forget(OWNER);
            } else {
                c.close(OWNER, id).unwrap();
            }
            release.send(()).unwrap();
            let result = reader.join().unwrap();
            let handle = carrier.made.load(Ordering::SeqCst);
            let io = crate::hostio::process();
            let retired = matches!(
                io.ends(crate::support::OWNER, handle),
                Err(IoRefusal::Refused(_))
            );

            c.pools.forget(OWNER);
            let _ = io.close(crate::support::OWNER, handle);
            drop(far);
            assert_eq!(result, Err(ConnError::Closed));
            assert!(
                handle != 0 && retired,
                "a retired dial left a pooled line or socket"
            );
        });
    }
}

#[test]
fn replay_keeps_a_short_suffix_and_empty_flags_across_zero_and_busy_retries() {
    let runtime = worker();
    let on = runtime.handle().clone();
    runtime.block_on(async {
        let (listener, address) = far_end().await;
        let carrier = carrier();
        let answer = Arc::new(Mutex::new(None));
        let wakes = Arc::new(Mutex::new(Vec::new()));
        let (c, framing) = pending_connector(carrier.clone(), answer.clone(), wakes.clone(), false);
        let opening = vec![b'o'; crate::compose::WRITE_BUFFER_BYTES - 4];
        let id = c
            .open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: &address,
                    body: busbar_contract::conn::Bytes::copy_from_slice(&opening),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(c.write(OWNER, id, b"accepted", true, true), Ok(8));
        assert_eq!(c.write(OWNER, id, b"", true, false), Ok(0));
        answer.lock().unwrap().take().unwrap()(Ok(address.parse().unwrap()));
        let first = c.wait(OWNER, &[id], 72);
        let first_frames = framing.emits.lock().unwrap().clone();
        let (mut socket, _) = listener.accept().await.unwrap();

        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release, held_back) = std::sync::mpsc::channel();
        *carrier.write.lock().unwrap() = Some((entered_tx, held_back));
        let held = c.slab.get(OWNER, id).unwrap().1;
        let (line, stream) = held.line().unwrap();
        let busy = std::thread::spawn(move || {
            let _entered = on.enter();
            let waker = Waker::noop();
            let _ = line.poll_ready(stream, &mut Context::from_waker(waker));
        });
        entered.recv().unwrap();
        let while_busy = c.wait(OWNER, &[id], 73);
        release.send(()).unwrap();
        busy.join().unwrap();
        wakes.lock().unwrap().clear();
        carrier.inner.gate.release();
        let woken = wakes.lock().unwrap().clone();
        let was_woken = woken.contains(&73);

        let mut expected = opening;
        expected.extend_from_slice(b"accepted");
        let got = tokio::time::timeout(Duration::from_secs(5), async {
            let mut got = Vec::new();
            while got.len() < expected.len() {
                let _ = c.wait(OWNER, &[id], 74);
                let mut bytes = vec![0; expected.len() - got.len()];
                tokio::select! {
                    read = socket.read(&mut bytes) => {
                        let n = read.unwrap();
                        if n == 0 { break; }
                        got.extend_from_slice(&bytes[..n]);
                    }
                    _ = tokio::time::sleep(Duration::from_millis(1)) => {}
                }
            }
            let _ = c.wait(OWNER, &[id], 74);
            got
        })
        .await;
        let frames = framing.emits.lock().unwrap().clone();
        c.close(OWNER, id).unwrap();
        drop((socket, held));
        assert_eq!(first, Err(ConnError::Pending));
        assert_eq!(first_frames, vec![(4, false, true)]);
        assert_eq!(while_busy, Err(ConnError::Pending));
        assert!(
            was_woken,
            "a retained replay registered its caller with the line"
        );
        assert_eq!(got.unwrap(), expected);
        assert_eq!(
            frames,
            vec![(4, false, true), (4, true, true), (0, true, false)]
        );
    });
}

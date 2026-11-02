// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct Reentry {
    target: Mutex<Option<(std::sync::Weak<Connector>, ConnId)>>,
    timely: AtomicBool,
    calls: Mutex<Vec<std::thread::JoinHandle<Result<usize, ConnError>>>>,
}

impl Reentry {
    fn observe(&self) {
        let (connector, conn) = self.target.lock().unwrap().clone().unwrap();
        let connector = connector.upgrade().unwrap();
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (done_tx, done) = std::sync::mpsc::channel();
        let call = std::thread::spawn(move || {
            entered_tx.send(()).unwrap();
            let answer = connector.wait(OWNER, &[conn], 92);
            let _ = done_tx.send(());
            answer
        });
        entered.recv().unwrap();

        self.timely.store(
            done.recv_timeout(Duration::from_secs(5)).is_ok(),
            Ordering::SeqCst,
        );
        self.calls.lock().unwrap().push(call);
    }

    fn join(&self) -> Vec<Result<usize, ConnError>> {
        std::mem::take(&mut *self.calls.lock().unwrap())
            .into_iter()
            .map(|call| call.join().unwrap())
            .collect()
    }
}

#[derive(Default)]
struct WriteGate {
    released: AtomicBool,
    waker: futures::task::AtomicWaker,
}

struct WriteSide {
    inner: Box<dyn crate::carrier::Side>,
    gate: Arc<WriteGate>,
}

impl crate::carrier::Side for WriteSide {
    fn ticket(&self) -> busbar_contract::abi::mechanism::ticket::Ticket {
        self.inner.ticket()
    }
    fn register(&self, waker: &Waker) {
        self.inner.register(waker);
        self.gate.waker.register(waker);
    }
}

struct HeldProxyWrite {
    inner: TestDoor,
    gate: Arc<WriteGate>,
}

impl FramerDoor for HeldProxyWrite {
    fn facts(&self) -> &crate::framer::DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: crate::framer::Call<'_>) -> crate::framer::Crossed {
        self.inner.cross(call)
    }
    fn side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        self.inner.side().map(|inner| {
            Box::new(WriteSide {
                inner,
                gate: self.gate.clone(),
            }) as Box<dyn crate::carrier::Side>
        })
    }
    fn carry(
        &self,
        side: &dyn crate::carrier::Side,
        resume: bool,
        call: crate::carrier::Carry<'_>,
    ) -> crate::framer::Crossed {
        use crate::carrier::Carry;
        use busbar_contract::abi::mechanism::call::Outcome;
        let outcome = match &call {
            Carry::Flush(..) => Some(Outcome::Ready),
            Carry::Write(..) if !self.gate.released.load(Ordering::SeqCst) => {
                Some(Outcome::Pending)
            }
            _ => None,
        };
        match outcome {
            Some(outcome) => crate::framer::Crossed {
                outcome,
                error: None,
            },
            None => self.inner.carry(side, resume, call),
        }
    }
}

struct DropWait(Arc<Reentry>);

#[allow(clippy::manual_noop_waker)]
impl Wake for DropWait {
    fn wake(self: Arc<Self>) {}
}

impl Drop for DropWait {
    fn drop(&mut self) {
        self.0.observe();
    }
}

#[test]
fn completing_a_later_replay_drops_the_earlier_public_waker_outside_guards() {
    worker().block_on(async {
        let (listener, proxy) = far_end().await;
        let proxy_addr: SocketAddr = proxy.parse().unwrap();
        let answer = Arc::new(Mutex::new(None::<crate::Judged>));
        let answering = Arc::clone(&answer);
        let gate = Arc::new(WriteGate::default());
        let reentry = Arc::new(Reentry::default());
        let c = Arc::new(
            Connector::serving(
                Transports::new(vec![
                    Entry {
                        door: Arc::new(TestDoor::new(
                            "frames",
                            &["frames"],
                            &["bytes"],
                            Default::default(),
                        )),
                        alpn: Vec::new(),
                    },
                    Entry {
                        door: Arc::new(HeldProxyWrite {
                            inner: TestDoor::identity("bytes"),
                            gate: gate.clone(),
                        }),
                        alpn: Vec::new(),
                    },
                ])
                .unwrap(),
                Arc::new(move |dest: &str, _: u32, done: crate::Judged| {
                    if dest == proxy_addr.to_string() {
                        Some(Ok(proxy_addr))
                    } else {
                        *answering.lock().unwrap() = Some(done);
                        None
                    }
                }),
                None,
                Arc::new(|_, _| {}),
            )
            .proxying(Some(crate::proxy::test_config(
                "127.0.0.1",
                proxy_addr.port(),
                None,
                "",
            ))),
        );
        c.declare_need(OWNER, NeedId(0), "frames", EGRESS_OPERATOR_INFRASTRUCTURE)
            .unwrap();
        let id = c
            .open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: "far.test:80",
                    ..Default::default()
                },
            )
            .unwrap();
        *reentry.target.lock().unwrap() = Some((Arc::downgrade(&c), id));
        let bytes = vec![b'x'; crate::compose::WRITE_BUFFER_BYTES];
        assert_eq!(c.write(OWNER, id, &bytes, true, false), Ok(bytes.len()));
        answer.lock().unwrap().take().unwrap()(Ok("127.0.0.1:80".parse().unwrap()));
        let first = {
            let waker = Waker::from(Arc::new(DropWait(reentry.clone())));
            let mut cx = Context::from_waker(&waker);
            c.poll_read(OWNER, id, &mut cx, &mut [0; 1])
        };
        let (mut socket, _) = listener.accept().await.unwrap();
        let proxy = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                assert!(request.len() <= 8192, "CONNECT request stayed bounded");
            }
            assert!(request.starts_with(b"CONNECT far.test:80 HTTP/1.1\r\n"));
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();

            socket
        });

        gate.released.store(true, Ordering::SeqCst);
        gate.waker.wake();
        let dropped = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let mut cx = Context::from_waker(Waker::noop());
                let _ = c.poll_read(OWNER, id, &mut cx, &mut [0; 1]);
                if !reentry.calls.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok();
        let timely = reentry.timely.load(Ordering::SeqCst);
        let socket = tokio::time::timeout(Duration::from_secs(5), proxy)
            .await
            .unwrap()
            .unwrap();
        c.close(OWNER, id).unwrap();
        drop(socket);
        let calls = reentry.join();
        assert!(first.is_pending());
        assert!(
            dropped,
            "the retained old caller Waker was exercised before close"
        );
        assert!(
            timely,
            "replay dropped the old caller Waker under a host guard"
        );
        assert_eq!(calls, vec![Err(ConnError::Pending)]);
    });
}

#[test]
fn a_judgement_completion_wakes_a_public_wait_without_holding_its_answer() {
    let answer = Arc::new(Mutex::new(None::<crate::Judged>));
    let answering = Arc::clone(&answer);
    let reentry = Arc::new(Reentry::default());
    let waking = Arc::clone(&reentry);
    let c = Arc::new(Connector::serving(
        Transports::new(vec![Entry {
            door: Arc::new(TestDoor::identity("bytes")),
            alpn: Vec::new(),
        }])
        .unwrap(),
        Arc::new(move |_: &str, _: u32, done: crate::Judged| {
            *answering.lock().unwrap() = Some(done);
            None
        }),
        None,
        Arc::new(move |_, _| waking.observe()),
    ));
    c.declare_over(OWNER, NeedId(0), "bytes").unwrap();
    let id = c
        .open(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: "far.test:80",
                ..Default::default()
            },
        )
        .unwrap();
    *reentry.target.lock().unwrap() = Some((Arc::downgrade(&c), id));
    assert_eq!(c.wait(OWNER, &[id], 91), Err(ConnError::Pending));
    answer.lock().unwrap().take().unwrap()(Err(DEST_UNRESOLVABLE));
    let results = reentry.join();
    c.close(OWNER, id).unwrap();
    assert!(
        reentry.timely.load(Ordering::SeqCst),
        "completion called its wake under a host guard"
    );
    assert_eq!(results, vec![Ok(0)]);
}

#[test]
fn a_proxy_judgement_can_reenter_the_same_connections_public_wait() {
    let answer = Arc::new(Mutex::new(None::<crate::Judged>));
    let answering = Arc::clone(&answer);
    let reentry = Arc::new(Reentry::default());
    let judging = Arc::clone(&reentry);
    let c = Arc::new(
        Connector::serving(
            Transports::new(vec![
                Entry {
                    door: Arc::new(TestDoor::new(
                        "frames",
                        &["frames"],
                        &["bytes"],
                        Default::default(),
                    )),
                    alpn: Vec::new(),
                },
                Entry {
                    door: Arc::new(TestDoor::identity("bytes")),
                    alpn: Vec::new(),
                },
            ])
            .unwrap(),
            Arc::new(move |dest: &str, _: u32, done: crate::Judged| {
                if dest == "proxy.test:9090" {
                    judging.observe();
                    Some(Err(DEST_UNRESOLVABLE))
                } else {
                    *answering.lock().unwrap() = Some(done);
                    None
                }
            }),
            None,
            Arc::new(|_, _| {}),
        )
        .proxying(Some(crate::proxy::test_config(
            "proxy.test",
            9090,
            None,
            "",
        ))),
    );
    c.declare_need(OWNER, NeedId(0), "frames", EGRESS_OPERATOR_INFRASTRUCTURE)
        .unwrap();
    let id = c
        .open(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: "far.test:80",
                ..Default::default()
            },
        )
        .unwrap();
    *reentry.target.lock().unwrap() = Some((Arc::downgrade(&c), id));
    answer.lock().unwrap().take().unwrap()(Ok("127.0.0.1:80".parse().unwrap()));
    let result = c.wait(OWNER, &[id], 93);
    let callbacks = reentry.join();
    c.close(OWNER, id).unwrap();
    assert_eq!(result, Ok(0), "the refused proxy judgement is ready");
    assert!(
        reentry.timely.load(Ordering::SeqCst),
        "the public judge callback crossed under a host guard"
    );
    assert_eq!(callbacks, vec![Err(ConnError::Pending)]);
}

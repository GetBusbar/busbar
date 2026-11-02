// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A wait reports interest readiness; the following read must still see a spent dial's error.

use super::*;
use crate::carrier::{Carry, Side};
use crate::framer::{Call, Crossed, DoorFacts};
use crate::registry::Entry;
use crate::support::{worker, TestDoor};
use busbar_contract::abi::host::service::DEST_PLAINTEXT;
use busbar_contract::abi::mechanism::call::Outcome;
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const OWNER: InstanceId = InstanceId(1);
const NEED: NeedId = NeedId(0);
const TARGET: &str = "target.test:443";
const PROXY: &str = "proxy.test:3128";

#[derive(Default)]
struct PendedJudge {
    pending: Mutex<VecDeque<(String, Judged)>>,
    immediate: HashMap<String, Result<SocketAddr, Verdict>>,
}

impl PendedJudge {
    fn answer(&self, authority: &str, answer: Result<SocketAddr, Verdict>) {
        let done = {
            let mut pending = self.pending.lock().unwrap();
            let at = pending
                .iter()
                .position(|(name, _)| name == authority)
                .unwrap();
            pending.remove(at).unwrap().1
        };
        done(answer);
    }
}

impl DialJudge for PendedJudge {
    fn judge_dial(
        &self,
        authority: &str,
        _: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, Verdict>> {
        if let Some(answer) = self.immediate.get(authority) {
            return Some(*answer);
        }
        self.pending
            .lock()
            .unwrap()
            .push_back((authority.to_owned(), done));
        None
    }
}

struct CountedCarrier {
    inner: TestDoor,
    answers: Mutex<VecDeque<Outcome>>,
    on_dial: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    dials: AtomicUsize,
    cancels: AtomicUsize,
}

impl FramerDoor for CountedCarrier {
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
        if matches!(&call, Carry::Dial(..)) {
            self.dials.fetch_add(1, Ordering::SeqCst);
            let on_dial = self.on_dial.lock().unwrap().take();
            if let Some(on_dial) = on_dial {
                on_dial();
            }
            let outcome = self
                .answers
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Outcome::Ready);
            if outcome != Outcome::Ready {
                return Crossed {
                    outcome,
                    error: None,
                };
            }
        }
        if matches!(&call, Carry::Cancel(..)) {
            self.cancels.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.carry(side, resume, call)
    }
}

struct Rig {
    c: Connector,
    judge: Arc<PendedJudge>,
    carrier: Arc<CountedCarrier>,
    framing: Arc<TestDoor>,
    wakes: Arc<Mutex<Vec<Ticket>>>,
}

impl Rig {
    fn new(
        outcomes: Vec<Outcome>,
        proxied: bool,
        immediate: &[(&str, Result<SocketAddr, Verdict>)],
    ) -> Self {
        let judge = Arc::new(PendedJudge {
            immediate: immediate
                .iter()
                .map(|(name, answer)| ((*name).to_owned(), *answer))
                .collect(),
            ..Default::default()
        });
        let carrier = Arc::new(CountedCarrier {
            inner: TestDoor::identity("bytes"),
            answers: Mutex::new(outcomes.into()),
            on_dial: Mutex::new(None),
            dials: AtomicUsize::new(0),
            cancels: AtomicUsize::new(0),
        });

        let framing = Arc::new(TestDoor::new(
            "frames",
            &["frames"],
            &["bytes"],
            Default::default(),
        ));
        let wakes = Arc::new(Mutex::new(Vec::new()));
        let waking = Arc::clone(&wakes);
        let c = Connector::serving(
            Transports::new(vec![
                Entry {
                    door: framing.clone(),
                    alpn: Vec::new(),
                },
                Entry {
                    door: carrier.clone(),
                    alpn: Vec::new(),
                },
            ])
            .unwrap(),
            judge.clone(),
            None,
            Arc::new(move |_, ticket| waking.lock().unwrap().push(ticket)),
        )
        .proxying(if proxied {
            proxy::resolve_config(&proxy::ProxyEnvValues {
                http: Some(format!("http://{PROXY}")),
                ..Default::default()
            })
            .unwrap()
        } else {
            None
        });
        c.declare_over(OWNER, NEED, "frames").unwrap();
        Self {
            c,
            judge,
            carrier,
            framing,
            wakes,
        }
    }

    fn open(&self, target: &str) -> ConnId {
        self.c
            .open(
                OWNER,
                NEED,
                &OpenDesc {
                    target,
                    ..Default::default()
                },
            )
            .unwrap()
    }

    fn pending(&self, id: ConnId) {
        assert_eq!(
            self.c.read(OWNER, id, 41, &mut [0; 8]),
            Err(ConnError::Pending)
        );
        assert_eq!(self.c.write(OWNER, id, b"accepted", true, true), Ok(8));
        assert_eq!(self.c.write(OWNER, id, b"", true, false), Ok(0));
        assert_eq!(self.c.wait(OWNER, &[id], 42), Err(ConnError::Pending));
        assert_eq!(self.carrier.dials.load(Ordering::SeqCst), 0);
    }

    fn terminal(&self, id: ConnId, error: ConnError, dials: usize) {
        for _ in 0..3 {
            assert_eq!(self.c.wait(OWNER, &[id], 43), Ok(0));
            assert_eq!(self.c.read(OWNER, id, 44, &mut [0; 8]), Err(error));
            assert_eq!(
                self.c.poll_read(
                    OWNER,
                    id,
                    &mut Context::from_waker(Waker::noop()),
                    &mut [0; 8]
                ),
                Poll::Ready(Err(error))
            );
            assert_eq!(self.c.write(OWNER, id, b"later", true, false), Err(error));
            assert_eq!(self.c.facts(OWNER, id), Err(error));
            assert_eq!(self.c.landed(OWNER, id, 44), Err(error));
        }
        assert_eq!(self.carrier.dials.load(Ordering::SeqCst), dials);
        assert!(
            self.framing.handed.lock().unwrap().is_empty(),
            "accepted bytes never reach a failed dial"
        );
        self.c.close(OWNER, id).unwrap();
        assert_eq!(
            self.c.read(OWNER, id, 45, &mut [0; 8]),
            Err(ConnError::Closed)
        );
        assert_eq!(self.c.wait(OWNER, &[id], 46), Err(ConnError::Closed));
    }
}

fn pinned() -> SocketAddr {
    "127.0.0.1:9".parse().unwrap()
}

#[test]
fn a_spent_direct_dial_keeps_its_error_after_wait_and_after_the_first_read() {
    for (outcome, error) in [
        (Outcome::Fault, ConnError::Fault),
        (Outcome::Failed, ConnError::Fault),
        (Outcome::Refused, ConnError::Refused),
        (Outcome::Pending, ConnError::Fault),
    ] {
        for wait_first in [true, false] {
            let rig = Rig::new(vec![outcome], false, &[]);
            let id = rig.open(TARGET);
            rig.pending(id);
            rig.judge.answer(TARGET, Ok(pinned()));
            assert!(rig.wakes.lock().unwrap().contains(&42));
            if wait_first {
                assert_eq!(rig.c.wait(OWNER, &[id], 47), Ok(0));
            } else {
                assert_eq!(rig.c.read(OWNER, id, 47, &mut [0; 8]), Err(error));
            }
            rig.terminal(id, error, 1);
            assert_eq!(
                rig.carrier.cancels.load(Ordering::SeqCst),
                usize::from(outcome == Outcome::Pending)
            );
        }
    }
}

#[test]
fn a_pended_judgement_keeps_resolution_faults_distinct_from_refusals() {
    for (verdict, error) in [
        (DEST_UNRESOLVABLE, ConnError::Fault),
        (DEST_NO_ADDRESSES, ConnError::Fault),
        (DEST_PLAINTEXT, ConnError::Refused),
    ] {
        let rig = Rig::new(Vec::new(), false, &[]);
        let id = rig.open(TARGET);
        rig.pending(id);
        rig.judge.answer(TARGET, Err(verdict));
        rig.terminal(id, error, 0);
    }
}

#[test]
fn a_terminal_dial_spends_a_deadline_that_expires_during_its_crossing() {
    for wait_first in [true, false] {
        let rig = Rig::new(vec![Outcome::Fault], false, &[]);
        let id = rig
            .c
            .open(
                OWNER,
                NEED,
                &OpenDesc {
                    target: TARGET,
                    timeout_ms: 60_000,
                    ..Default::default()
                },
            )
            .unwrap();
        rig.pending(id);
        let held = rig.c.slab.get(OWNER, id).unwrap().1;
        let expiring = Arc::clone(&held);
        *rig.carrier.on_dial.lock().unwrap() = Some(Box::new(move || {
            expiring.due.lock().unwrap().as_mut().unwrap().at = std::time::Instant::now();
        }));
        rig.judge.answer(TARGET, Ok(pinned()));
        if wait_first {
            assert_eq!(rig.c.wait(OWNER, &[id], 47), Ok(0));
        } else {
            assert_eq!(
                rig.c.read(OWNER, id, 47, &mut [0; 8]),
                Err(ConnError::Fault)
            );
        }
        assert!(
            held.due.lock().unwrap().is_none(),
            "terminal completion retires the original bound"
        );
        rig.terminal(id, ConnError::Fault, 1);
    }
}

#[test]
fn a_spent_proxy_dial_keeps_its_error_for_each_pending_judgement_route() {
    for (target_pending, proxy_pending) in [(true, false), (true, true), (false, true)] {
        for (outcome, error) in [
            (Outcome::Fault, ConnError::Fault),
            (Outcome::Refused, ConnError::Refused),
        ] {
            let mut immediate = Vec::new();
            if !target_pending {
                immediate.push((TARGET, Ok(pinned())));
            }
            if !proxy_pending {
                immediate.push((PROXY, Ok(pinned())));
            }
            let rig = Rig::new(vec![outcome], true, &immediate);
            let id = rig.open(TARGET);
            rig.pending(id);
            if target_pending {
                rig.judge.answer(TARGET, Ok(pinned()));
                if proxy_pending {
                    assert_eq!(rig.c.wait(OWNER, &[id], 48), Err(ConnError::Pending));
                }
            }
            if proxy_pending {
                rig.judge.answer(PROXY, Ok(pinned()));
            }
            rig.terminal(id, error, 1);
        }
    }
}

#[test]
fn a_proxy_judgement_refusal_keeps_its_typed_answer() {
    for proxy_pending in [false, true] {
        for (verdict, error) in [
            (DEST_UNRESOLVABLE, ConnError::Fault),
            (DEST_PLAINTEXT, ConnError::Refused),
        ] {
            let immediate = if proxy_pending {
                Vec::new()
            } else {
                vec![(PROXY, Err(verdict))]
            };
            let rig = Rig::new(Vec::new(), true, &immediate);
            let id = rig.open(TARGET);
            rig.pending(id);
            rig.judge.answer(TARGET, Ok(pinned()));
            if proxy_pending {
                assert_eq!(rig.c.wait(OWNER, &[id], 49), Err(ConnError::Pending));
                rig.judge.answer(PROXY, Err(verdict));
            }
            rig.terminal(id, error, 0);
        }
    }
}

#[test]
fn a_failed_pending_dial_leaves_a_parallel_successful_exchange_intact() {
    worker().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let rig = Rig::new(vec![Outcome::Fault, Outcome::Ready], false, &[]);
        let failed = rig.open(TARGET);
        let succeeded = rig.open("success.test:443");
        assert_eq!(rig.c.write(OWNER, succeeded, b"ping", true, false), Ok(4));
        rig.judge.answer(TARGET, Ok(pinned()));
        assert_eq!(rig.c.wait(OWNER, &[failed], 50), Ok(0));
        rig.judge.answer("success.test:443", Ok(at));
        let (finish, finished) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4];
            socket.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            socket.write_all(b"pong").await.unwrap();
            finished.await.unwrap();
        });
        let got = tokio::time::timeout(Duration::from_secs(5), async {
            let mut got = Vec::new();
            while got.len() < 4 {
                assert_eq!(
                    rig.c.read(OWNER, failed, 51, &mut [0; 8]),
                    Err(ConnError::Fault)
                );
                let mut bytes = [0; 4];
                let piece =
                    std::future::poll_fn(|cx| rig.c.poll_read(OWNER, succeeded, cx, &mut bytes))
                        .await
                        .unwrap();
                assert!(piece.len > 0);
                got.extend_from_slice(&bytes[..piece.len]);
            }
            got
        })
        .await
        .unwrap();
        assert_eq!(got, b"pong");
        assert_eq!(rig.carrier.dials.load(Ordering::SeqCst), 2);
        assert_eq!(*rig.framing.handed.lock().unwrap(), b"ping");
        rig.c.close(OWNER, failed).unwrap();
        rig.c.close(OWNER, succeeded).unwrap();
        finish.send(()).unwrap();
        peer.await.unwrap();
    });
}

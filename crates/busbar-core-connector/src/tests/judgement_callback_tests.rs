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
                        alpn: Arc::default(),
                    },
                    Entry {
                        door: Arc::new(HeldProxyWrite {
                            inner: TestDoor::identity("bytes"),
                            gate: gate.clone(),
                        }),
                        alpn: Arc::default(),
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
        // The test owner carries `insecure_transport.accept: plaintext` (SEC-2, #297 model A).
        crate::tests::accept_plaintext(&c, &[OWNER]);
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
            // `advanced.proxy_resolution: local` (the default): the CONNECT names the address the
            // judgement answered for `far.test:80`.
            assert!(request.starts_with(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n"));
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
            alpn: Arc::default(),
        }])
        .unwrap(),
        Arc::new(move |_: &str, _: u32, done: crate::Judged| {
            *answering.lock().unwrap() = Some(done);
            None
        }),
        None,
        Arc::new(move |_, _| waking.observe()),
    ));
    // The test owner carries `insecure_transport.accept: plaintext` (SEC-2, #297 model A).
    crate::tests::accept_plaintext(&c, &[OWNER]);
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
                    alpn: Arc::default(),
                },
                Entry {
                    door: Arc::new(TestDoor::identity("bytes")),
                    alpn: Arc::default(),
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
    // The test owner carries `insecure_transport.accept: plaintext` (SEC-2, #297 model A).
    crate::tests::accept_plaintext(&c, &[OWNER]);
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

/// A connector framing `frames` over `bytes` (`knobs` on the framer), its dials judged by `judge`
/// and taken through `proxy`, with `OWNER`'s need `0` declared through the host's table.
fn refusal_connector(
    judge: impl Fn(&str, u32, crate::Judged) -> Option<Result<SocketAddr, u64>> + Send + Sync + 'static,
    knobs: crate::support::Knobs,
    proxy: Option<Arc<crate::proxy::ProxyChoice>>,
) -> Arc<Connector> {
    let c = Arc::new(
        Connector::serving(
            Transports::new(vec![
                Entry {
                    door: Arc::new(TestDoor::new("frames", &["frames"], &["bytes"], knobs)),
                    alpn: Arc::default(),
                },
                Entry {
                    door: Arc::new(TestDoor::identity("bytes")),
                    alpn: Arc::default(),
                },
            ])
            .unwrap(),
            Arc::new(judge),
            None,
            Arc::new(|_, _| {}),
        )
        .proxying(proxy),
    );
    // The default class: a framed operator-infrastructure need declared without `target_from` is
    // the retired shape BUSBAR-6017 refuses at declaration, and these needs name no config target.
    let spec = ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: busbar_contract::conn::codes::EGRESS_DEFAULT,
        transport: "frames".to_owned(),
        auth: String::new(),
        target_from: String::new(),
        trust_from: String::new(),
        details: busbar_contract::rendering::ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
        keep_mode: busbar_contract::conn::codes::KEEP_NAMED,
        keep_response_headers: Vec::new(),
        deny_response_headers: Vec::new(),
    };
    DeclaredConns::declare(&*c, OWNER, NeedId(0), &spec, None, None).unwrap();
    c
}

/// Read `id` until it fails (at most five seconds).
fn read_until_failed(c: &Connector, id: ConnId) -> ConnError {
    let until = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut cx = Context::from_waker(Waker::noop());
        if let Poll::Ready(Err(e)) = c.poll_read(OWNER, id, &mut cx, &mut [0; 64]) {
            return e;
        }
        assert!(std::time::Instant::now() < until, "the connection failed");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn shown(why: &busbar_contract::conn::NeedRefusal) -> String {
    why.render(str::to_owned)
}

/// RED (F-013): THE PROXY HOP IS NAMED, NOT THE REGISTRY. (a) The operator's egress proxy's NAME
/// does not resolve (a pended verdict): the egress proxy could not be reached. (b) The guard
/// refuses the proxy at open: busbar refused the egress proxy. (c) With no proxy, a registry name
/// that does not resolve is the path, never busbar's policy.
#[test]
fn a_refusal_names_the_hop_that_failed() {
    let proxy = || {
        Some(crate::proxy::test_config(
            "proxy.corp.invalid",
            3128,
            None,
            "",
        ))
    };
    let open = |c: &Connector| {
        c.open(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: "far.test:80",
                ..Default::default()
            },
        )
    };

    let a = refusal_connector(
        |dest: &str, _: u32, done: crate::Judged| {
            if dest == "far.test:80" {
                return Some(Err(DEST_UNRESOLVABLE));
            }
            std::thread::spawn(move || done(Err(DEST_UNRESOLVABLE)));
            None
        },
        Default::default(),
        proxy(),
    );
    // `far.test` resolves only at the proxy: `proxy_resolution: proxy` (the default, `local`,
    // refuses a target that does not resolve here before the proxy hop is reached).
    a.set_proxy_by_address(false);
    let id = open(&a).expect("the proxy's judgement pends");
    read_until_failed(&a, id);
    let why = a.conn_refusal(OWNER, id).expect("the reason is held");
    assert_eq!(
        why,
        busbar_contract::conn::NeedRefusal::ProxyUnreached("the name did not resolve".into())
    );
    assert_eq!(
        shown(&why),
        "could not connect to the egress proxy: the name did not resolve"
    );

    let b = refusal_connector(
        |dest: &str, _: u32, _: crate::Judged| {
            if dest == "far.test:80" {
                return Some(Err(DEST_UNRESOLVABLE));
            }
            Some(Err(busbar_contract::services::codes::DEST_INTERNAL))
        },
        Default::default(),
        proxy(),
    );
    b.set_proxy_by_address(false);
    assert!(open(&b).is_err());
    assert_eq!(
        b.refusal(OWNER, NeedId(0)).as_ref().map(shown).as_deref(),
        Some(
            "busbar refused the egress proxy: the destination guard refuses an internal or \
             loopback address (enable allow_private on its upstream registration to allow it)"
        )
    );

    let c = refusal_connector(
        |_: &str, _: u32, _: crate::Judged| Some(Err(DEST_UNRESOLVABLE)),
        Default::default(),
        None,
    );
    assert!(open(&c).is_err());
    let why = c.refusal(OWNER, NeedId(0)).expect("the reason is held");
    assert_eq!(
        why,
        busbar_contract::conn::NeedRefusal::Unreached("the name did not resolve".into())
    );
    assert_eq!(
        shown(&why),
        "could not connect to the registry: the name did not resolve"
    );
}

/// The reason `id` (opened on need `0`) failed, wherever the connector recorded it: per conn (read
/// on the worker until the connection fails, at most five seconds), or per need when the kernel
/// failed the connect synchronously.
async fn reason_of(c: &Connector, opened: Result<ConnId, ConnError>) -> String {
    match opened {
        Ok(id) => {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let mut cx = Context::from_waker(Waker::noop());
                    if let Poll::Ready(Err(_)) = c.poll_read(OWNER, id, &mut cx, &mut [0; 64]) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the connection failed");
            shown(
                &c.conn_refusal(OWNER, id)
                    .expect("the conn's reason is held"),
            )
        }
        Err(_) => shown(
            &c.refusal(OWNER, NeedId(0))
                .expect("the need's reason is held"),
        ),
    }
}

/// A proxy that reads one CONNECT head and answers `answer`: its address.
fn answering_proxy(answer: &'static [u8]) -> SocketAddr {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let at = l.local_addr().unwrap();
    std::thread::spawn(move || {
        let Ok((mut s, _)) = l.accept() else { return };
        let mut head = Vec::new();
        let mut byte = [0];
        while !head.ends_with(b"\r\n\r\n") && s.read_exact(&mut byte).is_ok() {
            head.push(byte[0]);
        }
        let _ = s.write_all(answer);
        std::thread::sleep(Duration::from_secs(2));
    });
    at
}

/// RED (F-013): AN ASYNCHRONOUS PROXY-HOP FAILURE NAMES THE PROXY. (a) Nothing listens at the
/// proxy. (b) The proxy answers CONNECT 407. (c) The registry asks for connection security and
/// none is set: the target hop failed, never the proxy.
#[test]
fn an_asynchronous_proxy_hop_failure_names_the_proxy() {
    let opened = |proxy_addr: SocketAddr, knobs: crate::support::Knobs, target| {
        let c = refusal_connector(
            move |dest: &str, _: u32, _: crate::Judged| {
                if dest == proxy_addr.to_string() {
                    Some(Ok(proxy_addr))
                } else {
                    Some(Ok("127.0.0.1:80".parse().unwrap()))
                }
            },
            knobs,
            Some(crate::proxy::test_config(
                "127.0.0.1",
                proxy_addr.port(),
                None,
                "",
            )),
        );
        // The test owner carries `insecure_transport.accept: plaintext` (SEC-2, #297 model A): the
        // plaintext proxy hop is admitted, so the hop's own failure is what is named.
        crate::tests::accept_plaintext(&c, &[OWNER]);
        let id = c.open(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target,
                ..Default::default()
            },
        );
        if let Ok(id) = id {
            let _ = c.write(OWNER, id, b"x", true, false);
        }
        (c, id)
    };

    worker().block_on(async {
        let dead: SocketAddr = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let (c, id) = opened(dead, Default::default(), "far.test:80");
        let a = reason_of(&c, id).await;
        let os = a
            .strip_prefix("could not connect to the egress proxy: ")
            .unwrap_or_else(|| panic!("the proxy is named: {a}"));
        assert!(!os.is_empty(), "{a}");
        assert!(!a.contains("registry"), "{a}");
        assert!(!a.contains("reactor"), "the dial ran on a worker: {a}");

        let proxy = answering_proxy(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
        let (c, id) = opened(proxy, Default::default(), "far.test:80");
        assert_eq!(
            reason_of(&c, id).await,
            "could not connect to the egress proxy: proxy refused CONNECT far.test:80: HTTP/1.1 \
             407 Proxy Authentication Required"
        );

        let proxy = answering_proxy(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
        let secured = crate::support::Knobs {
            secure_name: Some("far.test"),
            ..Default::default()
        };
        let (c, id) = opened(proxy, secured, "far.test:443");
        assert!(id.is_err(), "the dial fails before any connect");
        assert_eq!(
            reason_of(&c, id).await,
            "could not connect to the registry: the target asks for connection security and none \
             is set"
        );
    });
}

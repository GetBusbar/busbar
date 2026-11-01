// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::carrier::{Carry, Side};
use crate::framer::{Call, Crossed, DoorFacts};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket as SideTicket;
use busbar_contract::abi::transport::EMIT_TEXT;
use futures::task::AtomicWaker;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "settle_replay_tests.rs"]
mod settle_replay_tests;

struct RecordingDoor {
    inner: TestDoor,
    emits: Mutex<Vec<(usize, bool, bool)>>,
}

impl FramerDoor for RecordingDoor {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        if let Call::Emit(i, _) = &call {
            self.emits
                .lock()
                .unwrap()
                .push((i.len, i.end_of_frame != 0, i.flags & EMIT_TEXT != 0));
        }
        self.inner.cross(call)
    }
}

#[derive(Default)]
struct ConnectGate {
    released: AtomicBool,
    waker: AtomicWaker,
}

impl ConnectGate {
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.waker.wake();
    }
}

struct GatedSide {
    inner: Box<dyn Side>,
    gate: Arc<ConnectGate>,
}

impl Side for GatedSide {
    fn ticket(&self) -> SideTicket {
        self.inner.ticket()
    }

    fn register(&self, waker: &Waker) {
        self.inner.register(waker);
        self.gate.waker.register(waker);
    }
}

struct GatedCarrier {
    inner: TestDoor,
    gate: Arc<ConnectGate>,
}

impl FramerDoor for GatedCarrier {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }

    fn side(&self) -> Option<Box<dyn Side>> {
        self.inner.side().map(|inner| {
            Box::new(GatedSide {
                inner,
                gate: Arc::clone(&self.gate),
            }) as Box<dyn Side>
        })
    }

    fn carry(&self, side: &dyn Side, resume: bool, call: Carry<'_>) -> Crossed {
        if matches!(call, Carry::Flush(..)) && !self.gate.released.load(Ordering::SeqCst) {
            return Crossed {
                outcome: Outcome::Pending,
                error: None,
            };
        }
        self.inner.carry(side, resume, call)
    }
}

fn connector(
    gate: Arc<ConnectGate>,
    secure: bool,
    tls: Option<Arc<rustls::ClientConfig>>,
    wakes: Arc<Mutex<Vec<Ticket>>>,
) -> (Connector, Arc<RecordingDoor>) {
    let door = Arc::new(RecordingDoor {
        inner: TestDoor::new(
            "frames",
            &["frames"],
            &["bytes"],
            crate::support::Knobs {
                secure_name: secure.then_some("localhost"),
                ..Default::default()
            },
        ),
        emits: Mutex::new(Vec::new()),
    });
    let view = Transports::new(vec![
        Entry {
            door: door.clone(),
            alpn: Vec::new(),
        },
        Entry {
            door: Arc::new(GatedCarrier {
                inner: TestDoor::identity("bytes"),
                gate,
            }),
            alpn: Vec::new(),
        },
    ])
    .unwrap();
    let c = Connector::serving(
        view,
        loopback_literals(),
        tls,
        Arc::new(move |_, ticket| {
            wakes.lock().unwrap().push(ticket);
        }),
    );
    c.declare_over(OWNER, NeedId(0), "frames").unwrap();
    (c, door)
}

async fn reply(c: &Connector, id: ConnId) {
    let got = tokio::time::timeout(Duration::from_secs(5), async {
        let mut got = Vec::new();
        while got.len() < 2 {
            let mut bytes = [0; 2];
            let piece = std::future::poll_fn(|cx| c.poll_read(OWNER, id, cx, &mut bytes))
                .await
                .unwrap();
            assert!(piece.len > 0);
            got.extend_from_slice(&bytes[..piece.len]);
        }
        got
    })
    .await
    .unwrap();
    assert_eq!(got, b"ok");
}

#[test]
fn connecting_empty_frames_backpressure_wake_and_retry_without_loss() {
    worker().block_on(async {
        for (end, text) in [(false, false), (false, true), (true, false), (true, true)] {
            let (listener, far) = far_end().await;
            let gate = Arc::new(ConnectGate::default());
            let wakes = Arc::new(Mutex::new(Vec::new()));
            let (c, door) = connector(Arc::clone(&gate), false, None, Arc::clone(&wakes));
            let id = c
                .open(
                    OWNER,
                    NeedId(0),
                    &OpenDesc {
                        target: &far,
                        ..Default::default()
                    },
                )
                .unwrap();
            let (mut socket, _) = listener.accept().await.unwrap();
            let (finish, finished) = tokio::sync::oneshot::channel();
            let peer = tokio::spawn(async move {
                let mut bytes = [0; 4];
                socket.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"head");
                socket.write_all(b"ok").await.unwrap();
                finished.await.unwrap();
            });
            assert_eq!(c.write(OWNER, id, b"head", false, false), Ok(4));
            assert_eq!(c.write(OWNER, id, b"", end, text), Ok(0));
            assert_eq!(
                c.write(OWNER, id, b"", !end, !text),
                Err(ConnError::Pending)
            );
            assert_eq!(
                c.write(OWNER, id, b"unaccepted", true, true),
                Err(ConnError::Pending)
            );
            assert_eq!(c.wait(OWNER, &[id], 51), Err(ConnError::Pending));
            wakes.lock().unwrap().clear();
            gate.release();
            assert!(
                wakes.lock().unwrap().contains(&51),
                "the connecting writer is woken"
            );
            reply(&c, id).await;
            assert_eq!(c.write(OWNER, id, b"", !end, !text), Ok(0));
            assert_eq!(
                *door.emits.lock().unwrap(),
                vec![(4, false, false), (0, end, text), (0, !end, !text)]
            );
            assert_eq!(*door.inner.handed.lock().unwrap(), b"head");
            c.close(OWNER, id).unwrap();
            finish.send(()).unwrap();
            peer.await.unwrap();
        }
    });
}

#[test]
fn handshaking_empty_frames_backpressure_and_retry_after_the_handshake() {
    crate::tls::install_crypto_provider();
    let ca = crate::test_support::private_ca();
    let trust = busbar_contract::transport::trust::EgressTrust {
        extra_anchors: crate::test_support::certs_from_pem(&ca.ca_pem),
        ..Default::default()
    };
    let tls = Arc::new(crate::tls::client::build_client_config(&trust).unwrap());
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![ca.leaf_der.into()],
            rustls_pki_types::PrivateKeyDer::try_from(ca.key_der).unwrap(),
        )
        .unwrap();
    worker().block_on(async {
        let (listener, far) = far_end().await;
        let gate = Arc::new(ConnectGate::default());
        gate.release();
        let (c, door) = connector(gate, true, Some(tls), Arc::default());
        let id = c.open(OWNER, NeedId(0), &OpenDesc { target: &far, ..Default::default() }).unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let (hello, seen_hello) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let (finish, finished) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut byte = [0; 1];
            assert_eq!(socket.peek(&mut byte).await.unwrap(), 1);
            hello.send(()).unwrap();
            released.await.unwrap();
            let mut socket = tokio_rustls::TlsAcceptor::from(Arc::new(server)).accept(socket).await.unwrap();
            let mut bytes = [0; 4];
            socket.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"head");
            socket.write_all(b"ok").await.unwrap();
            socket.flush().await.unwrap();
            finished.await.unwrap();
        });
        let mut bytes = [0; 1];
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = seen_hello => result.unwrap(),
                got = std::future::poll_fn(|cx| c.poll_read(OWNER, id, cx, &mut bytes)) => panic!("handshake has no peer answer yet: {got:?}"),
            }
        }).await.unwrap();
        assert_eq!(c.write(OWNER, id, b"head", false, false), Ok(4));
        assert_eq!(c.write(OWNER, id, b"", true, true), Ok(0));
        assert_eq!(c.emit(OWNER, id, crate::compose::EXCHANGE_STREAM, b"", false, false), Err(ConnError::Pending));
        release.send(()).unwrap();
        reply(&c, id).await;
        assert_eq!(c.emit(OWNER, id, crate::compose::EXCHANGE_STREAM, b"", false, false), Ok(0));
        assert_eq!(*door.emits.lock().unwrap(), vec![(4, false, false), (0, true, true), (0, false, false)]);
        c.close(OWNER, id).unwrap();
        finish.send(()).unwrap();
        peer.await.unwrap();
    });
}

struct GatedWrites {
    inner: TestDoor,
    gate: Arc<ConnectGate>,
    accepted: Mutex<Vec<(usize, bool)>>,
}

impl FramerDoor for GatedWrites {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }

    fn side(&self) -> Option<Box<dyn Side>> {
        self.inner.side().map(|inner| {
            Box::new(GatedSide {
                inner,
                gate: Arc::clone(&self.gate),
            }) as Box<dyn Side>
        })
    }

    fn carry(&self, side: &dyn Side, resume: bool, call: Carry<'_>) -> Crossed {
        if let Carry::Write(i, o) = call {
            if !self.gate.released.load(Ordering::SeqCst) {
                return Crossed {
                    outcome: Outcome::Pending,
                    error: None,
                };
            }
            let crossed = self
                .inner
                .carry(side, resume, Carry::Write(&mut *i, &mut *o));
            if crossed.outcome == Outcome::Ready {
                self.accepted.lock().unwrap().push((
                    o.len as usize,
                    o.len as usize == i.len
                        && i.flags & busbar_contract::abi::transport::WRITE_END_OF_FRAME != 0,
                ));
            }
            crossed
        } else {
            self.inner.carry(side, resume, call)
        }
    }
}

async fn connected_carrier(
    wakes: Arc<Mutex<Vec<Ticket>>>,
) -> (Connector, Arc<GatedWrites>, ConnId, tokio::net::TcpStream) {
    let (listener, far) = far_end().await;
    let door = Arc::new(GatedWrites {
        inner: TestDoor::identity("bytes"),
        gate: Arc::default(),
        accepted: Mutex::new(Vec::new()),
    });
    let view = Transports::new(vec![Entry {
        door: door.clone(),
        alpn: Vec::new(),
    }])
    .unwrap();
    let c = Connector::serving(
        view,
        loopback_literals(),
        None,
        Arc::new(move |_, ticket| {
            wakes.lock().unwrap().push(ticket);
        }),
    );
    c.declare_over(OWNER, NeedId(0), "bytes").unwrap();
    let id = c
        .open(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: &far,
                ..Default::default()
            },
        )
        .unwrap();
    let (mut socket, _) = listener.accept().await.unwrap();
    socket.write_all(b"ok").await.unwrap();
    reply(&c, id).await;
    (c, door, id, socket)
}

#[test]
fn a_raw_carriers_empty_end_is_delivered_once_and_backpressures_until_taken() {
    worker().block_on(async {
        let wakes = Arc::new(Mutex::new(Vec::new()));
        let (c, door, id, mut socket) = connected_carrier(Arc::clone(&wakes)).await;
        assert_eq!(c.write(OWNER, id, b"", true, false), Ok(0));
        assert!(door.accepted.lock().unwrap().is_empty());
        assert_eq!(
            c.write(OWNER, id, b"", true, false),
            Err(ConnError::Pending)
        );
        assert_eq!(
            c.write(OWNER, id, b"tail", true, false),
            Err(ConnError::Pending)
        );
        assert_eq!(c.wait(OWNER, &[id], 61), Err(ConnError::Pending));
        wakes.lock().unwrap().clear();
        door.gate.release();
        assert!(wakes.lock().unwrap().contains(&61));
        assert_eq!(c.write(OWNER, id, b"tail", true, false), Ok(4));
        assert_eq!(c.write(OWNER, id, b"", true, false), Ok(0));
        assert_eq!(
            *door.accepted.lock().unwrap(),
            vec![(0, true), (4, true), (0, true)]
        );
        assert_eq!(c.write(OWNER, id, b"", false, false), Ok(0));
        assert_eq!(
            *door.accepted.lock().unwrap(),
            vec![(0, true), (4, true), (0, true)]
        );
        let mut bytes = [0; 4];
        tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"tail");
        c.close(OWNER, id).unwrap();
    });
}

#[test]
fn a_raw_carriers_full_payload_still_accepts_one_empty_end() {
    worker().block_on(async {
        let (c, door, id, _socket) = connected_carrier(Arc::default()).await;
        let bytes = vec![1; crate::compose::WRITE_BUFFER_BYTES + 10];
        assert_eq!(
            c.write(OWNER, id, &bytes, true, false),
            Ok(crate::compose::WRITE_BUFFER_BYTES)
        );
        assert_eq!(c.write(OWNER, id, b"", true, false), Ok(0));
        assert_eq!(
            c.write(OWNER, id, b"", true, false),
            Err(ConnError::Pending)
        );
        assert!(door.accepted.lock().unwrap().is_empty());
        c.close(OWNER, id).unwrap();
    });
}

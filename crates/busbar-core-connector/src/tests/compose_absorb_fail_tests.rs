// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WASTE-EGRESS W1, steps 9 and 10 at the `Connection` level: a lost opening wire fails the
//! connection (step 9), and a failed connection keeps its wire only when its carrier could still
//! deliver bytes it held (step 10, decided in `fail()`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use futures::task::AtomicWaker;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use crate::carrier::{Carry, Side};
use crate::compose::{Connection, Dial, Failure, HeadWords, Opening, Via};
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor};
use crate::support::{worker, Knobs, TestDoor};

/// THE REPEATING DOOR: the test framer `inner`, whose emit on any stream from `from` on yields its
/// wire twice over, so a sealed field's filler appears twice and `seals.splice` refuses it with
/// `SEAL_BROKEN` after the framer took the emit.
struct Repeating {
    inner: TestDoor,
    from: u64,
}

impl FramerDoor for Repeating {
    fn io_owner(&self) -> Option<u64> {
        self.inner.io_owner()
    }
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn seals_values(&self) -> bool {
        self.inner.seals_values()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Emit(i, o) if i.stream >= self.from => {
                let crossed = self.inner.cross(Call::Emit(&mut *i, &mut *o));
                if crossed.outcome == Outcome::Ready {
                    let len = usize::try_from(o.yielded.wire_len).unwrap();
                    if len > 0 && len.saturating_mul(2) <= i.sink.wire_cap {
                        // SAFETY: this READY output initialized the sink's first `len` bytes, and
                        // the sink holds `wire_cap >= 2 * len` bytes.
                        unsafe {
                            std::ptr::copy_nonoverlapping(i.sink.wire, i.sink.wire.add(len), len);
                        }
                        o.yielded.wire_len = (2 * len) as u64;
                    }
                }
                crossed
            }
            other => self.inner.cross(other),
        }
    }
}

/// A test framer whose DIALLED emit on stream `on` yields its wire together with an `agreed`
/// position no offer holds (a dialled connection's offer is empty), so `absorb` queues the wire and
/// then fails in `check_agreed_position`. `TestDoor` states `agreed` only on the accepting side.
struct Agreeing {
    inner: TestDoor,
    on: u64,
    agreed: u32,
}

impl FramerDoor for Agreeing {
    fn io_owner(&self) -> Option<u64> {
        self.inner.io_owner()
    }
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Emit(i, o) if i.stream == self.on => {
                let crossed = self.inner.cross(Call::Emit(&mut *i, &mut *o));
                if crossed.outcome == Outcome::Ready {
                    assert!(o.yielded.wire_len > 0, "the bad agreed comes with wire");
                    o.yielded.agreed = self.agreed;
                }
                crossed
            }
            other => self.inner.cross(other),
        }
    }
}

/// The write gate: while `armed`, the carrier's `write` takes nothing and pends; once `broken`, it
/// fails. `release` disarms it and wakes the task its pending write registered.
#[derive(Default)]
struct Gate {
    armed: AtomicBool,
    broken: AtomicBool,
    waker: AtomicWaker,
}

impl Gate {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
    fn break_writes(&self) {
        self.broken.store(true, Ordering::SeqCst);
        self.waker.wake();
    }
    fn release(&self) {
        self.armed.store(false, Ordering::SeqCst);
        self.waker.wake();
    }
}

struct GatedSide {
    inner: Box<dyn Side>,
    gate: Arc<Gate>,
}

impl Side for GatedSide {
    fn ticket(&self) -> Ticket {
        self.inner.ticket()
    }
    fn register(&self, waker: &Waker) {
        self.inner.register(waker);
        self.gate.waker.register(waker);
    }
}

/// THE WRITE-GATED CARRIER: the test carrier, its `write` held by [`Gate`].
struct GatedCarrier {
    inner: TestDoor,
    gate: Arc<Gate>,
}

impl FramerDoor for GatedCarrier {
    fn io_owner(&self) -> Option<u64> {
        self.inner.io_owner()
    }
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
        if matches!(call, Carry::Write(..)) {
            if self.gate.broken.load(Ordering::SeqCst) {
                return Crossed {
                    outcome: Outcome::Failed,
                    error: Some(b"the test carrier's connection was reset".to_vec()),
                };
            }
            if self.gate.armed.load(Ordering::SeqCst) {
                return Crossed {
                    outcome: Outcome::Pending,
                    error: None,
                };
            }
        }
        self.inner.carry(side, resume, call)
    }
}

fn gated_via(gate: &Arc<Gate>) -> Via {
    Via {
        door: Arc::new(GatedCarrier {
            inner: TestDoor::identity("test-carrier"),
            gate: Arc::clone(gate),
        }),
        io: crate::hostio::process(),
    }
}

fn dial(target: &str) -> Dial {
    Dial {
        plaintext_accepted: false,
        target: target.to_owned(),
        tls: None,
        alpn: Vec::new(),
        open_timeout: Duration::from_secs(5),
        opening: None,
        head_words: HeadWords::default(),
        anchors: None,
    }
}

/// A far end that accepts and reads whatever comes, saying nothing.
async fn plain_far() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let far = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s);
        }
    });
    far
}

/// A TLS far end offering `h2`, reading whatever comes; and the dial that reaches it, offering
/// `h2`, with the plain opening `first` on the exchange stream.
async fn tls_far() -> Dial {
    let ca = crate::test_support::private_ca();
    let anchor = crate::test_support::certs_from_pem(&ca.ca_pem).remove(0);
    let mut server = std::sync::Arc::unwrap_or_clone(
        busbar_contract::crypto::tls::server_config(|b| {
            b.with_no_client_auth().with_single_cert(
                vec![ca.leaf_der.into()],
                rustls_pki_types::PrivateKeyDer::try_from(ca.key_der).unwrap(),
            )
        })
        .unwrap(),
    );
    server.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let far = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (s, _) = l.accept().await.unwrap();
        let Ok(mut s) = acceptor.accept(s).await else {
            return;
        };
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut got)).await;
    });
    let trust = busbar_contract::transport::trust::EgressTrust {
        extra_anchors: vec![anchor],
        ..Default::default()
    };
    let mut d = dial(&far);
    d.tls = Some(Arc::new(
        crate::tls::client::build_client_config(&trust).unwrap(),
    ));
    d.alpn = vec![b"h2".to_vec()];
    d.opening = Some((Vec::new(), b"first".to_vec().into()));
    d
}

/// The sealing test framer over TLS, its emits from stream `3` on repeated.
fn repeating_door() -> Arc<Repeating> {
    Arc::new(Repeating {
        inner: TestDoor::new(
            "sec",
            &["sec"],
            &[],
            Knobs {
                secure_name: Some("localhost"),
                seals: true,
                render_fields: true,
                ..Knobs::default()
            },
        ),
        from: 3,
    })
}

/// An opening with one sealed field.
fn sealed_opening() -> Option<Opening> {
    Some((
        vec![
            ("x-api-key".into(), b"sealed-credential-value".to_vec()),
            (
                busbar_contract::conn::SEALED_FIELDS_FIELD.into(),
                b"x-api-key".to_vec(),
            ),
        ],
        b"second".to_vec().into(),
    ))
}

/// An unsealed opening.
fn plain_opening(body: &[u8]) -> Option<Opening> {
    Some((Vec::new(), body.to_vec().into()))
}

fn words(target: &[u8]) -> HeadWords {
    (b"POST".to_vec(), target.to_vec())
}

/// Drive `c` until it is open with every byte of protocol output gone to the carrier and flushed
/// (`poll_prepared`'s readiness), bounded.
async fn settled(c: &mut Connection) {
    tokio::time::timeout(
        Duration::from_secs(10),
        futures::future::poll_fn(|cx| c.poll_prepared(cx)),
    )
    .await
    .expect("the connection opens and flushes in time")
    .expect("the connection opens");
}

fn noop() -> Context<'static> {
    Context::from_waker(Waker::noop())
}

fn seal_broken() -> Failure {
    Failure::Refused(crate::seal::SEAL_BROKEN.to_owned())
}

/// (r12) A lost opening wire fails the connection: `open_exchange` on a second, sealed stream
/// whose framer wire repeats the filler is refused `SEAL_BROKEN` by the splice after the framer
/// took the emit, and the connection is no longer live, multiplexing or reusable. RED without
/// step 9's `fail()` in `put_opening_marked` (`live()` stays true).
#[test]
fn open_exchange_absorb_failure_fails_connection() {
    worker().block_on(async {
        let d = tls_far().await;
        let mut c = Connection::dial(repeating_door(), &crate::support::via(), d).unwrap();
        settled(&mut c).await;
        assert_eq!(
            c.established().agreed_protocol.as_deref(),
            Some(&b"h2"[..]),
            "the connection agreed h2"
        );
        assert!(c.live() && c.multiplexes() && c.reusable());
        assert!(c.cause().is_none());

        let refused = c.open_exchange(3, sealed_opening(), words(b"/second"), &mut noop());
        assert_eq!(refused, Err(seal_broken()));
        assert!(!c.live(), "the lost opening wire failed the connection");
        assert!(!c.multiplexes());
        assert!(!c.reusable());
        assert!(c.cause().is_some(), "the failure states its cause");
        c.close();
    });
}

/// (r17) Step 10's condition, decided in `fail()`: a failed connection keeps its wire only when
/// its carrier could still deliver bytes it held.
mod fail_keeps_wire_only_with_unsent_bytes {
    use super::*;

    /// (i) Gate armed, a stream's frames queued, then an out-of-range `agreed` fails the
    /// connection after its wire was queued: the wire is kept. RED against r16's per-arm rule
    /// (the agreed arm set nothing).
    #[test]
    fn i_agreed_out_of_range_with_frames_queued() {
        worker().block_on(async {
            let far = plain_far().await;
            let gate = Arc::new(Gate::default());
            let door = Arc::new(Agreeing {
                inner: TestDoor::identity("bytes"),
                on: 5,
                agreed: 9,
            });
            let mut c = Connection::dial(door, &gated_via(&gate), dial(&far)).unwrap();
            settled(&mut c).await;
            let before = c.flushed();

            gate.arm();
            c.open_exchange(
                3,
                plain_opening(b"queued-on-three"),
                words(b"/three"),
                &mut noop(),
            )
            .expect("stream 3's frames are queued");
            assert!(c.live());
            assert_eq!(c.flushed(), before, "the gated carrier took nothing");

            let failed = c.open_exchange(
                5,
                plain_opening(b"agreed-out-of-range"),
                words(b"/five"),
                &mut noop(),
            );
            assert!(
                matches!(failed, Err(Failure::Failed(_))),
                "the agreed position fails: {failed:?}"
            );
            assert!(!c.live());
            assert!(
                c.wire_kept(),
                "failed with frames queued on a healthy carrier, the wire is kept"
            );
            gate.release();
            c.close();
        });
    }

    /// (ii) Gate armed, frames queued, then the carrier's write fails: the carrier is lost, so
    /// nothing it held can still reach the peer and the wire is not kept.
    #[test]
    fn ii_carrier_write_error_with_frames_queued() {
        worker().block_on(async {
            let far = plain_far().await;
            let gate = Arc::new(Gate::default());
            let door = Arc::new(TestDoor::identity("bytes"));
            let mut c = Connection::dial(door, &gated_via(&gate), dial(&far)).unwrap();
            settled(&mut c).await;
            let before = c.flushed();

            gate.arm();
            c.open_exchange(
                3,
                plain_opening(b"queued-on-three"),
                words(b"/three"),
                &mut noop(),
            )
            .expect("stream 3's frames are queued");
            assert!(c.live());
            assert_eq!(c.flushed(), before, "the gated carrier took nothing");

            gate.break_writes();
            let polled = c.poll_piece(&mut noop());
            assert!(
                matches!(polled, Poll::Ready(Err(_))),
                "the carrier's write error fails the connection: {polled:?}"
            );
            assert!(!c.live());
            assert!(
                !c.wire_kept(),
                "a lost carrier delivers nothing it held: the wire is not kept"
            );
            c.close();
        });
    }

    /// (iii) Gate unarmed, everything flushed, then a splice `SEAL_BROKEN`: its wire was zeroized
    /// unqueued, nothing else is held, so the wire is not kept.
    #[test]
    fn iii_splice_seal_broken_with_everything_flushed() {
        worker().block_on(async {
            let d = tls_far().await;
            let gate = Arc::new(Gate::default());
            let mut c = Connection::dial(repeating_door(), &gated_via(&gate), d).unwrap();
            settled(&mut c).await;
            assert!(c.live());

            let refused = c.open_exchange(3, sealed_opening(), words(b"/second"), &mut noop());
            assert_eq!(refused, Err(seal_broken()));
            assert!(!c.live());
            assert!(
                !c.wire_kept(),
                "the refused wire was never queued and nothing else is held: not kept"
            );
            c.close();
        });
    }
}

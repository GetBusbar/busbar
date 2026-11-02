// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A real upstream socket and checked raw-framer batch, with publication explicitly polled.

use std::future::Future as _;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use crate::datagram::{Across, DatagramFraming, Leg, LegSink, LineStep, Pairing, PublicationTask};
use crate::dialled::{Dialled, Phase, READS_PER_DRIVE};
use crate::framer::{Call, Crossed, DoorFacts, FramerDoor, Refused};
use crate::udp::{self, ReadyPort, UdpPort};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{
    FramePiece, FrameSpan, RendezvousTerms, HANDSHAKE_ANSWERS, LANE_CLEAR, LANE_RENDEZVOUS,
    PIECE_END_OF_FRAME, ROLE_FRAMER,
};
use busbar_contract::conn::ConnError;

#[derive(Default)]
struct ReaderWake {
    count: AtomicUsize,
    changed: tokio::sync::Notify,
}

impl Wake for ReaderWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_one();
    }
}

impl ReaderWake {
    fn clear(&self) {
        self.count.store(0, Ordering::SeqCst);
    }

    async fn notified(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.count.load(Ordering::SeqCst) == 0 {
                self.changed.notified().await;
            }
        })
        .await
        .expect("a real progress owner must wake the upstream reader");
    }
}

#[derive(Default)]
struct Caller {
    pending: AtomicBool,
    frames: Mutex<Vec<Across>>,
    task: Mutex<Option<PublicationTask>>,
}

impl LegSink for Caller {
    fn line(&self, across: Across, _: Instant) {
        self.frames.lock().unwrap().push(across);
    }

    fn poll_line(
        &self,
        _: &mut Context<'_>,
        input: Option<&Across>,
        _: bool,
        now: Instant,
    ) -> Poll<Result<LineStep, Refused>> {
        if self.pending.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        if let Some(input) = input {
            self.line(input.clone(), now);
            return Poll::Ready(Ok(LineStep::Batch {
                yielded: crate::framer::Yielded::default(),
                accepted: true,
            }));
        }
        Poll::Ready(Ok(LineStep::Complete))
    }

    fn schedule(&self, task: PublicationTask) -> bool {
        assert!(self.task.lock().unwrap().replace(task).is_none());
        true
    }

    fn close(&self) {}
}

impl Caller {
    fn poll_publication(&self) -> Poll<()> {
        // The future is outside the caller lock while it calls back into the real pairing.
        let mut task = self.task.lock().unwrap().take().expect("scheduled actor");
        let result = task.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        if result.is_pending() {
            *self.task.lock().unwrap() = Some(task);
        }
        result
    }
}

struct RawFramer {
    facts: DoorFacts,
    inputs: Mutex<Vec<Vec<u8>>>,
    fingerprint: [u8; 32],
    bind: bool,
}

#[allow(unsafe_code)]
impl FramerDoor for RawFramer {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Begin(_, out) => out.framing = 1,
            Call::Ingest(input, out) => {
                // SAFETY: the host lends this initialized lane and byte span for the crossing.
                let lane = unsafe { &*input.lane };
                let bytes = if input.len == 0 {
                    &[][..]
                } else {
                    unsafe { std::slice::from_raw_parts(input.bytes, input.len) }
                };
                if lane.lane == LANE_RENDEZVOUS {
                    let mut frame = Vec::new();
                    let mut span = |bytes: &[u8]| {
                        let span = FrameSpan {
                            offset: frame.len() as u64,
                            len: bytes.len() as u64,
                        };
                        frame.extend_from_slice(bytes);
                        span
                    };
                    out.datagram.terms = RendezvousTerms {
                        role: HANDSHAKE_ANSWERS,
                        local_user: span(b"host"),
                        local_secret: span(b"host-password-0123456789"),
                        remote_user: span(b"far"),
                        remote_secret: span(b"far-password-0123456789"),
                        peer_fingerprint: span(&self.fingerprint),
                        ..RendezvousTerms::ZERO
                    };
                    assert!(frame.len() <= input.sink.frame_cap);
                    // SAFETY: the initialized terms fit the host's checked frame loan.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            frame.as_ptr(),
                            input.sink.frame,
                            frame.len(),
                        );
                    }
                    out.yielded.frame_len = frame.len() as u64;
                } else if lane.lane == LANE_CLEAR && bytes.first() == Some(&0x80) {
                    self.inputs.lock().unwrap().push(bytes.to_vec());
                    assert!(
                        bytes.len() >= 2
                            && bytes.len() <= input.sink.frame_cap
                            && input.sink.pieces_cap > 0
                    );
                    // D1 and D2 yield only caller-bound LINE; D3 yields channel output.
                    let stream = if bytes[1] == 3 { 3 } else { 20 };
                    // SAFETY: both output loans are checked above, and the piece names only
                    // initialized bytes copied before this crossing returns.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            input.sink.frame,
                            bytes.len(),
                        );
                        input.sink.pieces.write(FramePiece {
                            stream,
                            len: bytes.len() as u64,
                            flags: PIECE_END_OF_FRAME,
                            ..FramePiece::ZERO
                        });
                    }
                    out.yielded.frame_len = bytes.len() as u64;
                    out.yielded.pieces_len = 1;
                } else if self.bind
                    && lane.lane == LANE_CLEAR
                    && lane.bound == 0
                    && bytes.starts_with(&[0, 1])
                {
                    out.datagram.request = busbar_contract::abi::transport::PATH_REQUEST_BIND;
                    out.datagram.request_to = lane.path;
                }
            }
            _ => {}
        }
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }
}

fn binding_answer(request: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut answer = vec![1, 1, 0, 24, 0x21, 0x12, 0xa4, 0x42];
    answer.extend_from_slice(&request[8..20]);
    let key = ::ring::hmac::Key::new(::ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let signature = ::ring::hmac::sign(&key, &answer);
    answer.extend_from_slice(&[0, 8, 0, 20]);
    answer.extend_from_slice(signature.as_ref());
    answer
}

/// Drive the real host and peer DTLS associations, answering their integrity-checked probes.
fn establish_keying(
    host: &mut DatagramFraming,
    host_cert: Arc<crate::dtls::SessionCert>,
    far_cert: Arc<crate::dtls::SessionCert>,
    host_addr: std::net::SocketAddr,
    far_addr: std::net::SocketAddr,
) {
    use crate::dtls::{Association, IceCredentials, Role, Verdict};
    let mut far = Association::new(
        far_cert,
        Role::Client,
        &IceCredentials {
            ufrag: "far".into(),
            pwd: "far-password-0123456789".into(),
        },
        &IceCredentials {
            ufrag: "host".into(),
            pwd: "host-password-0123456789".into(),
        },
        host_cert.fingerprint(),
    );
    let mut now = Instant::now();
    // Match the existing datagram handshake fixtures' finite clock pump; no sleeps or socket
    // timings establish the presented state used by the readiness control below.
    for _ in 0..200 {
        while let Some((to, packet)) = host.poll_send() {
            assert_eq!(to, far_addr);
            if far.ingest(host_addr, &packet, now) == Verdict::Raw && packet.starts_with(&[0, 1]) {
                host.datagram(
                    far_addr,
                    &binding_answer(&packet, b"far-password-0123456789"),
                    now,
                )
                .unwrap();
            }
        }
        let _ = far.bind_path(host_addr, now);
        while let Some((to, packet)) = far.poll_wire() {
            assert_eq!(to, host_addr);
            host.datagram(far_addr, &packet, now).unwrap();
            if packet.starts_with(&[0, 1]) {
                far.ingest(
                    host_addr,
                    &binding_answer(&packet, b"host-password-0123456789"),
                    now,
                );
            }
        }
        if host.presented() && far.peer_verified() {
            return;
        }
        now += Duration::from_millis(10);
        far.handle_timeout(now);
        host.timeout(now).unwrap();
    }
    panic!("the real handshake must present its verified keying material");
}

struct Rig {
    dialled: Dialled,
    door: Arc<RawFramer>,
    caller: Arc<Caller>,
    far: UdpPort,
    socket: UdpSocket,
    woke: Arc<ReaderWake>,
    waker: Waker,
}

impl Rig {
    fn new(limit: Option<usize>) -> Self {
        Self::settings(limit, false)
    }

    fn settings(limit: Option<usize>, keyed: bool) -> Self {
        let host_cert = Arc::new(crate::dtls::SessionCert::mint().unwrap());
        let far_cert = keyed.then(|| Arc::new(crate::dtls::SessionCert::mint().unwrap()));
        let port = udp::bind("127.0.0.1:0").unwrap();
        let socket = port.get_ref().try_clone().unwrap();
        let far = udp::bind("127.0.0.1:0").unwrap();
        let door = Arc::new(RawFramer {
            facts: DoorFacts {
                name: "upstream-read-wake".into(),
                claims: vec!["upstream-read-wake"],
                role: ROLE_FRAMER,
                composes_over: Vec::new(),
                ported: false,
                status_rows: Vec::new(),
                duplex: Vec::new(),
                datagram: true,
            },
            inputs: Mutex::default(),
            fingerprint: far_cert.as_ref().map_or([0; 32], |cert| cert.fingerprint()),
            bind: keyed,
        });
        let (mut framing, _) =
            DatagramFraming::accept(door.clone(), host_cert.clone(), port.local_addr()).unwrap();
        framing.rendezvous(b"terms", Instant::now()).unwrap();
        // Admit the real sender through an integrity-checked STUN request. The ordinary raw
        // fixture requests no bind and has no deadline; the keyed control completes DTLS below.
        let username = b"host:far";
        let mut check = vec![0, 1, 0, 36, 0x21, 0x12, 0xa4, 0x42];
        check.extend_from_slice(&[7; 12]);
        check.extend_from_slice(&[0, 6, 0, 8]);
        check.extend_from_slice(username);
        let key = ::ring::hmac::Key::new(
            ::ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            b"host-password-0123456789",
        );
        let signature = ::ring::hmac::sign(&key, &check);
        check.extend_from_slice(&[0, 8, 0, 20]);
        check.extend_from_slice(signature.as_ref());
        framing
            .datagram(far.local_addr(), &check, Instant::now())
            .unwrap();
        if let Some(cert) = far_cert {
            establish_keying(
                &mut framing,
                host_cert,
                cert,
                port.local_addr(),
                far.local_addr(),
            );
        }
        while framing.poll_send().is_some() {}
        if !keyed {
            assert!(framing.deadline().is_none());
        }
        let caller = Arc::new(Caller::default());
        let pairing = Pairing::with_memory_limit(caller.clone(), port.local_addr(), limit);
        for (leg, stream) in [(Leg::Caller, 10), (Leg::Upstream, 20)] {
            let mut head = super::message(b"kind: opaque\r\n");
            head.stream = stream;
            head.fields = true;
            pairing.sort(leg, vec![head], Instant::now());
        }
        let dialled = Dialled::new(framing, ReadyPort::open(port).unwrap(), pairing, None);
        dialled.pairing.attach(dialled.leg.clone()).unwrap();
        *dialled.phase.lock().unwrap() = Phase::Running;
        let woke = Arc::new(ReaderWake::default());
        let waker = Waker::from(woke.clone());
        Self {
            dialled,
            door,
            caller,
            far,
            socket,
            woke,
            waker,
        }
    }

    fn send(&self, bytes: &[u8]) {
        self.far
            .try_send_to(bytes, self.dialled.leg.port.local_addr())
            .unwrap()
            .unwrap();
    }

    fn pending(&self, read: bool) {
        if read {
            assert_eq!(
                self.dialled.read(&self.waker, &mut [0; 16]),
                Err(ConnError::Pending)
            );
        } else {
            assert!(!self.dialled.ready(&self.waker));
        }
    }

    async fn first_batch(&self, read: bool) {
        loop {
            self.woke.clear();
            self.pending(read);
            if !self.door.inputs.lock().unwrap().is_empty() {
                break;
            }
            self.woke.notified().await;
        }
        assert!(self.dialled.leg.ready.lock().unwrap().is_empty());
        assert!(self.dialled.leg.timer.lock().unwrap().is_none());
        self.woke.clear();
    }
}

#[test]
fn line_only_socket_batches_rearm_reads_after_their_actual_continuation() {
    for read in [false, true] {
        crate::support::worker().block_on(async {
            let rig = Rig::new(None);
            rig.send(&[0x80, 1]);
            rig.send(&[0x80, 2]);
            rig.first_batch(read).await;
            assert_eq!(*rig.door.inputs.lock().unwrap(), vec![vec![0x80, 1]]);
            assert_eq!(
                rig.woke.count.load(Ordering::SeqCst),
                0,
                "actor is unpolled"
            );
            rig.caller.pending.store(true, Ordering::SeqCst);
            assert!(rig.caller.poll_publication().is_pending());
            assert_eq!(rig.woke.count.load(Ordering::SeqCst), 0, "LINE is pending");
            assert_eq!(rig.door.inputs.lock().unwrap().len(), 1);
            rig.caller.pending.store(false, Ordering::SeqCst);
            assert!(rig.caller.poll_publication().is_ready());
            assert_eq!(rig.woke.count.load(Ordering::SeqCst), 1);
            rig.woke.clear();
            rig.pending(read);
            assert_eq!(rig.door.inputs.lock().unwrap().len(), 2);
            assert_eq!(rig.woke.count.load(Ordering::SeqCst), 0);
            // An extra poll while this continuation is unpolled must leave the actor owning
            // progress, without waking the reader into a busy loop.
            rig.pending(read);
            assert_eq!(rig.woke.count.load(Ordering::SeqCst), 0);
            assert_eq!(rig.door.inputs.lock().unwrap().len(), 2);
            assert!(rig.caller.poll_publication().is_ready());
            assert_eq!(rig.woke.count.load(Ordering::SeqCst), 1);
            assert_eq!(rig.caller.frames.lock().unwrap().len(), 2);
            rig.woke.clear();
            // The completion wake gets the reader back to a real Pending receive. Only then
            // send D3: the port's registered interest must drive its channel message.
            rig.pending(read);
            assert_eq!(rig.woke.count.load(Ordering::SeqCst), 0);
            rig.send(&[0x80, 3]);
            rig.woke.notified().await;
            assert!(rig.dialled.ready(&rig.waker));
            let mut buf = [0; 16];
            let piece = rig.dialled.read(&rig.waker, &mut buf).unwrap();
            assert_eq!(&buf[..piece.len], &[0x80, 3]);
            assert!(piece.end);
            assert!(rig.caller.poll_publication().is_ready());
            rig.dialled.close();
        });
    }
}

#[test]
fn the_existing_datagram_drive_bound_wakes_once_with_an_unread_packet_remaining() {
    crate::support::worker().block_on(async {
        let rig = Rig::new(None);
        for _ in 0..READS_PER_DRIVE {
            rig.send(&[0xff]); // Security drops these: every step is Complete, no output batch.
        }
        rig.send(&[0xff, 1]); // One more Complete packet remains after the existing drive bound.
        rig.send(&[0x80, 3]);
        loop {
            rig.woke.clear();
            rig.pending(false);
            let mut next = [0; 2];
            if rig.socket.peek_from(&mut next).unwrap().0 == 2 {
                assert_eq!(next, [0xff, 1]);
                break;
            }
            rig.woke.notified().await;
        }
        assert!(rig.door.inputs.lock().unwrap().is_empty());
        assert_eq!(rig.woke.count.load(Ordering::SeqCst), 1);
        assert!(rig.dialled.ready(&rig.waker));
        assert_eq!(*rig.door.inputs.lock().unwrap(), vec![vec![0x80, 3]]);
        assert!(rig.caller.poll_publication().is_ready());
        rig.dialled.close();
    });
}

#[test]
fn storage_pending_and_a_full_channel_queue_do_not_schedule_retry_spins() {
    crate::support::worker().block_on(async {
        let rig = Rig::new(Some(usize::MAX));
        let memory = rig.dialled.pairing.memory_account();
        let overhead = crate::publication::Memory::reservation_size(0).unwrap();
        let held = memory
            .reserve(usize::MAX - memory.used() - overhead)
            .unwrap();
        let transferring = held.publishing();
        for _ in 0..3 {
            rig.pending(false);
            assert_eq!(rig.woke.count.load(Ordering::SeqCst), 0);
        }
        drop(transferring);
        drop(held);
        assert!(
            rig.woke.count.load(Ordering::SeqCst) > 0,
            "actual retirement wakes"
        );
        *rig.dialled.leg.ready.lock().unwrap() =
            super::ready_messages(&vec![(&b"queued"[..], true); crate::dialled::MAX_READY]);
        rig.woke.clear();
        for _ in 0..3 {
            rig.dialled.leg.wait_ready(&rig.waker);
            rig.dialled
                .leg
                .drive(
                    &rig.dialled.pairing,
                    &mut Context::from_waker(&rig.waker),
                    None,
                )
                .unwrap();
            assert_eq!(rig.woke.count.load(Ordering::SeqCst), 0);
        }
        rig.dialled.close();
    });
}

#[test]
fn cancellation_before_actor_poll_and_terminal_storage_failure_do_not_rewake() {
    crate::support::worker().block_on(async {
        let rig = Rig::new(None);
        rig.send(&[0x80, 1]);
        rig.first_batch(false).await;
        // Dropping a never-polled scheduled future runs its real publication cancellation guard.
        let task = rig.caller.task.lock().unwrap().take().unwrap();
        drop(task);
        assert!(rig.dialled.pairing.publication_outcome().failure.is_some());
        assert!(rig.woke.count.load(Ordering::SeqCst) > 0);
        rig.woke.clear();
        for _ in 0..3 {
            assert!(rig.dialled.ready(&rig.waker));
            assert_eq!(
                rig.dialled.read(&rig.waker, &mut [0; 8]),
                Err(ConnError::Fault)
            );
            assert_eq!(rig.woke.count.load(Ordering::SeqCst), 0);
        }
        let exhausted = Rig::new(Some(1));
        assert!(exhausted.dialled.ready(&exhausted.waker));
        exhausted.woke.clear();
        for _ in 0..3 {
            assert!(exhausted.dialled.ready(&exhausted.waker));
            assert_eq!(
                exhausted.dialled.read(&exhausted.waker, &mut [0; 8]),
                Err(ConnError::Fault)
            );
            assert_eq!(exhausted.woke.count.load(Ordering::SeqCst), 0);
        }
    });
}

#[test]
fn an_expired_unkeyed_leg_is_ready_for_timeout_without_rearming_the_past_timer() {
    crate::support::worker().block_on(async {
        let mut rig = Rig::new(None);
        rig.dialled.due = Some(Instant::now() - Duration::from_nanos(1));
        assert!(!rig.dialled.leg.presented());
        *rig.dialled.leg.ready.lock().unwrap() = super::ready_messages(&[(b"queued", true)]);
        assert!(rig.dialled.ready(&rig.waker));
        let mut queued = [0; 8];
        let piece = rig.dialled.read(&rig.waker, &mut queued).unwrap();
        assert_eq!(&queued[..piece.len], b"queued");
        assert!(piece.end);
        for _ in 0..3 {
            assert!(rig.dialled.ready(&rig.waker));
            assert_eq!(
                rig.dialled.read(&rig.waker, &mut [0; 8]),
                Err(ConnError::Timeout)
            );
            assert_eq!(rig.woke.count.load(Ordering::SeqCst), 0);
            assert!(rig.dialled.leg.timer.lock().unwrap().is_none());
        }
        assert!(rig.door.inputs.lock().unwrap().is_empty());
        rig.dialled.close();
        rig.woke.clear();
        assert!(rig.dialled.ready(&rig.waker));
        assert_eq!(
            rig.dialled.read(&rig.waker, &mut [0; 8]),
            Err(ConnError::Closed)
        );
        assert_eq!(rig.woke.count.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn conn_wait_reports_the_keying_timeout_after_the_exchange_spent_the_outer_deadline() {
    use busbar_contract::conn::{Conns as _, InstanceId, NeedId};
    crate::support::worker().block_on(async {
        let mut rig = Rig::new(None);
        rig.dialled.due = Some(Instant::now() - Duration::from_nanos(1));
        let wake_count = Arc::new(AtomicUsize::new(0));
        let counted = wake_count.clone();
        let connector = crate::Connector {
            wake: Arc::new(move |_, _| {
                counted.fetch_add(1, Ordering::SeqCst);
            }),
            ..crate::Connector::default()
        };
        let owner = InstanceId(17);
        let need = NeedId(23);
        let held = crate::Held::over(None, None, None)
            .bounded(1)
            .dialling(rig.dialled);
        // The exchange head already began the answer: Conns::wait must now use the leg's
        // keying readiness instead of being rescued by Held::within_due's initial-head bound.
        held.answered();
        assert!(held.due.lock().unwrap().is_none());
        connector.slab.declare(owner, need);
        let conn = connector.slab.insert(owner, need, held).unwrap();
        for _ in 0..3 {
            assert_eq!(connector.wait(owner, &[conn], 7), Ok(0));
            assert_eq!(
                connector.read(owner, conn, 7, &mut [0; 8]),
                Err(ConnError::Timeout)
            );
            assert_eq!(wake_count.load(Ordering::SeqCst), 0);
        }
        connector.close(owner, conn).unwrap();
    });
}

#[test]
fn an_unexpired_or_successfully_keyed_leg_stays_pending_without_a_timeout_spin() {
    for keyed in [false, true] {
        crate::support::worker().block_on(async {
            let mut rig = Rig::settings(None, keyed);
            rig.dialled.due = Some(if keyed {
                Instant::now() - Duration::from_nanos(1)
            } else {
                Instant::now() + Duration::from_secs(60)
            });
            assert_eq!(rig.dialled.leg.presented(), keyed);
            for _ in 0..3 {
                assert!(!rig.dialled.ready(&rig.waker));
                assert_eq!(
                    rig.dialled.read(&rig.waker, &mut [0; 8]),
                    Err(ConnError::Pending)
                );
                assert_eq!(rig.woke.count.load(Ordering::SeqCst), 0);
            }
            rig.dialled.close();
        });
    }
}

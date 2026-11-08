// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(feature = "transport-webrtc")]

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Wake, Waker};

use busbar_contract::transport::TransportSettings;
use busbar_core_connector::datagram::Pairing;
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};
use busbar_core_connector::publication::{Memory, Messages};
use busbar_core_connector::udp::{bind, ReadyPort};
use busbar_core_connector::Connector;
use busbar_kernel::config::limits::{BuildScope, LimitsResolved};
use busbar_kernel::plane_driver::{CallerEnd, SessionCaller};

use super::{lock, CallerLeg, ClaimDoor, Joining, Opened};

type Callback = Arc<dyn Fn() + Send + Sync>;

pub(crate) struct OpeningFramer {
    inner: Arc<dyn FramerDoor>,
    fault: AtomicU8,
    self_retired: AtomicBool,
    finish_attempts: AtomicUsize,
    pub(crate) finishes: AtomicUsize,
    pub(crate) on_finish: Mutex<Option<Callback>>,
}

impl OpeningFramer {
    pub(crate) fn new() -> Arc<Self> {
        let plugin = crate::root::test_plugins::linked_transport(
            busbar_transport_webrtc::door,
            crate::root::doors::bind(),
        );
        Arc::new(Self {
            inner: Arc::new(
                crate::root::doors::Dispatched::open(plugin, &TransportSettings::default())
                    .expect("real WebRTC door opens"),
            ),
            fault: AtomicU8::new(0),
            self_retired: AtomicBool::new(false),
            finish_attempts: AtomicUsize::new(0),
            finishes: AtomicUsize::new(0),
            on_finish: Mutex::new(None),
        })
    }
}

impl FramerDoor for OpeningFramer {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        if let Call::Finish(input, out) = call {
            self.finish_attempts.fetch_add(1, Ordering::SeqCst);
            let callback = self.on_finish.lock().unwrap().clone();
            if let Some(callback) = callback {
                callback();
            }
            let crossed = self.inner.cross(Call::Finish(input, out));
            if self.self_retired.load(Ordering::SeqCst) {
                assert_eq!(
                    crossed.outcome,
                    busbar_contract::abi::mechanism::call::Outcome::Failed
                );
                assert_eq!(
                    crossed.error.as_deref(),
                    Some(b"finish: no such framing".as_slice()),
                    "a malformed SDP was already retired by the actual product"
                );
            } else {
                assert_eq!(
                    crossed.outcome,
                    busbar_contract::abi::mechanism::call::Outcome::Ready,
                    "the actual WebRTC product completed Finish"
                );
                self.finishes.fetch_add(1, Ordering::SeqCst);
            }
            return crossed;
        }
        if let Call::Ingest(input, out) = call {
            let crossed = self.inner.cross(Call::Ingest(input, out));
            if crossed.outcome == busbar_contract::abi::mechanism::call::Outcome::Failed {
                self.self_retired.store(true, Ordering::SeqCst);
            }

            match self.fault.swap(0, Ordering::SeqCst) {
                1 => out.yielded.pieces_len = 0,
                2 => {
                    return Crossed {
                        outcome: busbar_contract::abi::mechanism::call::Outcome::Refused,
                        error: None,
                    };
                }
                3 => panic!("host cleanup probe after actual WebRTC preparation"),
                4 => out.datagram.terms.local_user = out.datagram.terms.remote_user,
                _ => {}
            }
            crossed
        } else {
            self.inner.cross(call)
        }
    }
}

pub(crate) fn offer() -> zeroize::Zeroizing<Vec<u8>> {
    crate::root::serve::serve_datagram::peer::offer_description()
}

pub(crate) fn assert_description(bytes: &[u8]) {
    let sdp = std::str::from_utf8(bytes).expect("SDP answer is text");
    assert!(sdp.starts_with("v=0\r\n"), "{sdp}");
    for field in [
        "a=ice-ufrag:",
        "a=ice-pwd:",
        "a=fingerprint:",
        "a=candidate:",
        "m=application",
    ] {
        assert!(sdp.contains(field), "missing {field}: {sdp}");
    }
}

fn door() -> Arc<ClaimDoor> {
    ClaimDoor::serve(ReadyPort::open(bind("127.0.0.1:0").unwrap()).unwrap())
}

fn open(door: &Arc<ClaimDoor>, framer: &Arc<OpeningFramer>) -> Result<Opened, String> {
    let limits = LimitsResolved {
        datagram_line_memory_bytes: Some(
            4 * busbar_core_connector::test_support::datagram_output_reservation_bytes(),
        ),
        ..LimitsResolved::default()
    };
    let _scope = BuildScope::enter(&limits);
    Opened::open(door, Arc::clone(framer) as Arc<dyn FramerDoor>, &offer())
}

fn only_joining(opened: Opened) -> Joining {
    let Opened {
        description,
        caller,
        head,
        joining,
    } = opened;
    drop((description, caller, head));
    joining
}

struct Observed {
    leg: Weak<CallerLeg>,
    pairing: Weak<Pairing>,
    messages: Weak<Messages>,
    memory: Arc<Memory>,
}

impl Observed {
    fn new(opened: &Opened) -> Self {
        let pairing = lock(&opened.caller.leg.pairing).clone().unwrap();
        let memory = pairing.memory_account();
        assert!(memory.used() > 0, "the actual opening has charged custody");
        assert_description(&opened.description.bytes);
        Self {
            leg: Arc::downgrade(&opened.caller.leg),
            pairing: Arc::downgrade(&pairing),
            messages: Arc::downgrade(&opened.caller.from),
            memory,
        }
    }

    fn retired(&self, framer: &OpeningFramer) {
        assert!(self.leg.upgrade().is_none(), "the caller cycle retired");
        assert!(self.pairing.upgrade().is_none(), "the pairing retired");
        assert!(
            self.messages.upgrade().is_none(),
            "the opening queue retired"
        );
        assert_eq!(self.memory.used(), 0, "all opening custody retired");
        assert_eq!(framer.finishes.load(Ordering::SeqCst), 1);
    }
}

fn assert_host_unlocked(door: &ClaimDoor, leg: &CallerLeg) {
    assert!(door.legs.try_lock().is_ok());
    assert!(leg.id.try_lock().is_ok());
    assert!(leg.pairing.try_lock().is_ok());
    assert!(leg.outbound.try_lock().is_ok());
    assert!(leg.to_session.try_lock().is_ok());
}

#[tokio::test]
async fn dropping_an_accepted_opening_retires_its_cycle_queue_and_custody_once() {
    let door = door();
    let framer = OpeningFramer::new();
    let opened = open(&door, &framer).unwrap();
    let observed = Observed::new(&opened);
    drop(opened);
    observed.retired(&framer);
    assert!(lock(&door.legs).is_empty());
    assert!(door.assocs.is_empty());
    door.close();
    assert_eq!(framer.finishes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn refusal_retires_the_opening_when_the_last_admission_holder_drops() {
    let door = door();
    let framer = OpeningFramer::new();
    let opened = open(&door, &framer).unwrap();
    let observed = Observed::new(&opened);
    let joining = only_joining(opened);
    let opening = Arc::new(Mutex::new(Some(joining)));
    let admitted = Arc::clone(&opening);
    let refused = move || drop(admitted);
    drop(opening);
    assert!(observed.pairing.upgrade().is_some());
    refused();
    observed.retired(&framer);
    assert!(lock(&door.legs).is_empty());
    assert!(door.assocs.is_empty());
    door.close();
}

#[tokio::test]
async fn cancelling_before_or_after_first_poll_retires_the_accepted_opening() {
    for first_poll in [false, true] {
        let door = door();
        let framer = OpeningFramer::new();
        let opened = open(&door, &framer).unwrap();
        let observed = Observed::new(&opened);
        let mut cancelled = Box::pin(async move {
            let opening = opened;
            std::future::pending::<()>().await;
            drop(opening);
        });
        if first_poll {
            let wake = Waker::noop();
            assert!(cancelled
                .as_mut()
                .poll(&mut Context::from_waker(wake))
                .is_pending());
        }
        drop(cancelled);
        observed.retired(&framer);
        door.close();
    }
}

#[tokio::test]
async fn missing_description_refusal_and_unwinding_retire_the_actual_product_once() {
    for fault in [1, 2, 3] {
        let door = door();
        let framer = OpeningFramer::new();
        framer.fault.store(fault, Ordering::SeqCst);
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open(&door, &framer)));
        if fault == 3 {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        assert_eq!(framer.finishes.load(Ordering::SeqCst), 1);
        assert!(lock(&door.legs).is_empty());
        assert!(door.assocs.is_empty());
        door.close();
    }
}

#[tokio::test]
async fn malformed_real_sdp_retires_the_actual_framing_once() {
    for description in [b"not SDP".as_slice(), b"v=0\r\n", b"\xff"] {
        let door = door();
        let framer = OpeningFramer::new();
        assert!(Opened::open(&door, framer.clone(), description).is_err());
        assert!(framer.self_retired.load(Ordering::SeqCst));
        assert_eq!(framer.finishes.load(Ordering::SeqCst), 0);
        assert_eq!(framer.finish_attempts.load(Ordering::SeqCst), 1);
        assert!(lock(&door.legs).is_empty());
        assert!(door.assocs.is_empty());
        door.close();
    }
}

#[tokio::test]
async fn a_book_refusal_retires_the_already_joined_association_outside_host_locks() {
    let door = door();
    let framer = OpeningFramer::new();
    let opened = open(&door, &framer).unwrap();
    let observed = Observed::new(&opened);
    let weak_door = Arc::downgrade(&door);
    let weak_leg = observed.leg.clone();
    let weak_pairing = observed.pairing.clone();
    *lock(&framer.on_finish) = Some(Arc::new(move || {
        let door = weak_door.upgrade().unwrap();
        let leg = weak_leg.upgrade().unwrap();
        assert_host_unlocked(&door, &leg);
        let pairing = weak_pairing.upgrade().unwrap();
        assert!(pairing.closed());
        pairing.close();
    }));
    let joining = only_joining(opened);
    let connector = Connector::new();
    let refusal = joining.admit_into(0, &connector).unwrap_err();
    assert!(refusal.starts_with("the session book refused"));
    observed.retired(&framer);
    assert!(lock(&door.legs).is_empty());
    assert!(door.assocs.is_empty());
    door.close();
}

#[tokio::test]
async fn a_duplicate_book_key_retires_only_the_second_joined_opening() {
    let connector = Connector::new();
    let first_door = door();
    let first_framer = OpeningFramer::new();
    let first = open(&first_door, &first_framer).unwrap();
    let first_observed = Observed::new(&first);
    only_joining(first).admit_into(1, &connector).unwrap();

    let second_door = door();
    let second_framer = OpeningFramer::new();
    let second = open(&second_door, &second_framer).unwrap();
    let second_observed = Observed::new(&second);
    let refused = only_joining(second).admit_into(1, &connector).unwrap_err();
    assert!(refused.starts_with("the session book refused"));
    second_observed.retired(&second_framer);
    assert!(lock(&second_door.legs).is_empty());
    assert!(second_door.assocs.is_empty());
    assert!(!first_observed.pairing.upgrade().unwrap().closed());
    assert_eq!(first_framer.finishes.load(Ordering::SeqCst), 0);
    connector.unpair(1);
    first_observed.retired(&first_framer);
    first_door.close();
    second_door.close();
}

#[tokio::test]
async fn a_duplicate_local_user_refuses_only_the_second_real_opening() {
    let door = door();
    let connector = Connector::new();
    let first_framer = OpeningFramer::new();
    let first = open(&door, &first_framer).unwrap();
    let first_observed = Observed::new(&first);
    let first_user = zeroize::Zeroizing::new(
        std::str::from_utf8(&first.description.bytes)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("a=ice-ufrag:"))
            .unwrap()
            .to_owned(),
    );
    only_joining(first).admit_into(1, &connector).unwrap();

    let second_framer = OpeningFramer::new();
    second_framer.fault.store(4, Ordering::SeqCst);
    let offered = offer();
    let offered = std::str::from_utf8(&offered).unwrap();
    let mut rewritten =
        zeroize::Zeroizing::new(String::with_capacity(offered.len() + first_user.len()));
    for line in offered.split_inclusive("\r\n") {
        if line.starts_with("a=ice-ufrag:") {
            rewritten.push_str("a=ice-ufrag:");
            rewritten.push_str(&first_user);
            rewritten.push_str("\r\n");
        } else {
            rewritten.push_str(line);
        }
    }
    let limits = LimitsResolved {
        datagram_line_memory_bytes: Some(
            4 * busbar_core_connector::test_support::datagram_output_reservation_bytes(),
        ),
        ..Default::default()
    };
    let second = {
        let _scope = BuildScope::enter(&limits);
        Opened::open(&door, second_framer.clone(), rewritten.as_bytes()).unwrap()
    };
    let second_observed = Observed::new(&second);
    let refusal = only_joining(second).admit_into(2, &connector).unwrap_err();
    assert!(refusal.starts_with("the claim door refused"), "{refusal}");
    second_observed.retired(&second_framer);
    assert!(!first_observed.pairing.upgrade().unwrap().closed());
    assert_eq!(first_framer.finishes.load(Ordering::SeqCst), 0);
    connector.unpair(1);
    first_observed.retired(&first_framer);
    door.close();
}

struct ReentrantWake(Callback);

impl Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
        (self.0)();
    }
}

#[tokio::test]
async fn successful_admission_keeps_serving_until_explicit_retirement_and_wakes_without_locks() {
    let door = door();
    let framer = OpeningFramer::new();
    let mut pair = super::tests::real::Pair::with_framer(door.clone(), framer.clone()).await;
    let connector = pair.connector.clone();
    let observed = Observed {
        leg: Arc::downgrade(&pair.caller.leg),
        pairing: Arc::downgrade(&pair.pairing),
        messages: Arc::downgrade(&pair.caller.from),
        memory: pair.pairing.memory_account(),
    };
    assert!(!pair.pairing.closed());
    assert_eq!(framer.finishes.load(Ordering::SeqCst), 0);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        assert_eq!(pair.caller.read().await, Some(Vec::new()));
        pair.send(b"peer opening").await;
        assert_eq!(pair.caller.read().await, Some(b"peer opening".to_vec()));
        assert!(pair.caller.write(b"served").await);
        assert_eq!(pair.received().await, b"served");
        pair.send(b"later data").await;
        assert_eq!(pair.caller.read().await, Some(b"later data".to_vec()));
    })
    .await
    .expect("the actual admitted root association serves opening and later peer data");
    let caller = &pair.caller;

    let weak_door = Arc::downgrade(&door);
    let weak_leg = observed.leg.clone();
    let weak_pairing = observed.pairing.clone();
    let weak_connector = Arc::downgrade(&connector);
    let wakes = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&wakes);
    let wake = Waker::from(Arc::new(ReentrantWake(Arc::new(move || {
        assert_host_unlocked(&weak_door.upgrade().unwrap(), &weak_leg.upgrade().unwrap());
        let pairing = weak_pairing.upgrade().unwrap();
        assert!(pairing.closed());
        pairing.close();
        weak_connector.upgrade().unwrap().unpair(1);
        count.fetch_add(1, Ordering::SeqCst);
    }))));
    assert!(matches!(
        caller.from.poll_recv(&mut Context::from_waker(&wake)),
        Poll::Pending
    ));
    connector.unpair(1);
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    assert_eq!(framer.finishes.load(Ordering::SeqCst), 1);
    assert_eq!(caller.read().await, None);
    assert!(!caller.write(b"retired").await);
    drop(pair);
    observed.retired(&framer);
    connector.unpair(1);
    assert!(lock(&door.legs).is_empty());
    assert!(door.assocs.is_empty());
    door.close();
}

/// Leave the actual product's offer queued, then fail the host's opening continuation. FINISH
/// must drain that real partial SDP through a small sink before the product forgets its token.
struct RetiringDial {
    inner: Arc<OpeningFramer>,
    probed: AtomicBool,
}

impl FramerDoor for RetiringDial {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        use busbar_contract::abi::mechanism::call::Outcome;
        use busbar_contract::abi::sdk::door::{blank_in, blank_out};
        use busbar_contract::abi::transport::{FinishIn, FramerOut, YIELD_MORE};
        match call {
            Call::Begin(input, out) => {
                let sink = input.sink;
                input.sink.frame_cap = 0;
                input.sink.pieces_cap = 0;
                let crossed = self.inner.cross(Call::Begin(input, out));
                input.sink = sink;
                assert_eq!(crossed.outcome, Outcome::Ready);
                assert_ne!(out.yielded.flags & YIELD_MORE, 0);
                crossed
            }
            Call::Timer(..) => Crossed {
                outcome: Outcome::Failed,
                error: Some(b"host cancels before the queued offer is published".to_vec()),
            },
            Call::Finish(input, out) => {
                let sink = input.sink;
                input.sink.frame_cap = 32;
                input.sink.pieces_cap = 1;
                let crossed = self.inner.cross(Call::Finish(input, out));
                if crossed.outcome == Outcome::Ready && out.yielded.flags & YIELD_MORE == 0 {
                    let mut probe: FinishIn = blank_in();
                    probe.framing = input.framing;
                    probe.lane = input.lane;
                    probe.sink = input.sink;
                    let mut result: FramerOut = blank_out();
                    let gone = self
                        .inner
                        .inner
                        .cross(Call::Finish(&mut probe, &mut result));
                    assert_eq!(gone.outcome, Outcome::Failed);
                    assert_eq!(
                        gone.error.as_deref(),
                        Some(b"finish: no such framing".as_slice()),
                        "the actual WebRTC framing table released its token after all batches"
                    );
                    self.probed.store(true, Ordering::SeqCst);
                }
                input.sink = sink;
                crossed
            }
            call => self.inner.cross(call),
        }
    }
}

#[tokio::test]
async fn actual_webrtc_finish_drains_multiple_partial_sdp_batches_and_releases_its_token() {
    let inner = OpeningFramer::new();
    let framer = Arc::new(RetiringDial {
        inner: inner.clone(),
        probed: AtomicBool::new(false),
    });
    let cert = Arc::new(busbar_core_connector::dtls::SessionCert::mint().unwrap());
    let judge: Arc<dyn busbar_core_connector::DialJudge> =
        Arc::new(|_: &str, _: u32, _: busbar_core_connector::Judged| None);
    let error = busbar_core_connector::datagram::DatagramFraming::dial(
        framer.clone(),
        cert,
        "127.0.0.1:40000".parse().unwrap(),
        &[("channel".to_owned(), b"events".to_vec())],
        judge,
        0,
    )
    .unwrap_err();
    assert_eq!(
        error.outcome,
        busbar_contract::abi::mechanism::call::Outcome::Failed
    );
    assert!(inner.finish_attempts.load(Ordering::SeqCst) > 1);
    assert_eq!(
        inner.finishes.load(Ordering::SeqCst),
        inner.finish_attempts.load(Ordering::SeqCst)
    );
    assert!(framer.probed.load(Ordering::SeqCst));
}
